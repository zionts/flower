//! SQL-only, quota-first raw invocation preflight. Not registered in any router.
//!
//! Borrow the ingress-owned/precharged body; do not run RequestJson<Value> first.
//! This module never captures a root or authorizes an alias. Only a
//! parent-owned atomic sealed-registry lookup can decide ordinary versus native
//! SQL and issue the native operation witness. In particular, caller JSON never
//! selects cancel/query/explain/catalog, a phase, or an authority purpose.
//!
//! Anonymous mappings are charged, owned and completely pre-touched BEFORE any
//! input decoding. The scanner uses no Value/String/Vec/map, recursive descent,
//! serde rejection formatter, or raw-text Debug implementation. This is a local
//! buffer/work proof, not a process-wide physical-memory or serving-launch proof.

#[path = "sql_ingress/owned.rs"]
mod owned;
#[path = "sql_ingress/registry.rs"]
mod registry;
#[path = "sql_ingress/scanner.rs"]
mod scanner;
#[path = "sql_ingress/storage.rs"]
mod storage;

pub(crate) use owned::{NativeInput, NativeParameter, NativeQuery, OwnedLimits};
pub(crate) use registry::{
    CancelResultShape, ClassifiedRegistry, Operation, RegistryClassifier, TerminalHeader,
};
use scanner::{Key, Level, Scanner};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use storage::{Mapping, rounded};

pub(crate) const MAX_BODY_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_NAME_BYTES: usize = 256;
pub(crate) const MAX_SQL_BYTES: usize = 64 * 1024;
pub(crate) const MAX_PARAMETERS: usize = 256;
pub(crate) const MAX_ROWS: u64 = 1000;
pub(crate) const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_DEPTH: usize = 64;
// Pinned serde_json starts its countdown at128 and rejects when it reaches0:
// 127 containers including the public object. Discovery preserves that cap.
const MAX_LOOKUP_DEPTH: usize = 127;
const MAX_KEYS: usize = 4096;
const MAX_NODES: usize = 65_536;
const KEY_SLOTS: usize = MAX_KEYS * 2;
// Finite local controls, scanner/string decoding temporaries, header, mapping
// owners and result descriptors. This is NOT the Tokio/native thread stack.
const CONTROL_BYTES: usize = 16 * 1024;
const CHECK_QUANTUM: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Invalid,
    Duplicate,
    UnknownField,
    Capacity,
    WorkLimit,
    Cancelled,
    Deadline,
    Unsupported,
}
impl Error {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::Invalid => "SQL_INPUT_INVALID",
            Self::Duplicate => "SQL_INPUT_DUPLICATE",
            Self::UnknownField => "SQL_INPUT_FIELD",
            Self::Capacity => "SQL_INPUT_CAPACITY",
            Self::WorkLimit => "SQL_INPUT_WORK_LIMIT",
            Self::Cancelled => "SQL_CANCELLED",
            Self::Deadline => "SQL_DEADLINE",
            Self::Unsupported => "SQL_UNSUPPORTED",
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for Error {}

/// Caller supplies the SAME absolute native deadline from node SQL admission,
/// before capture. A preflight ticket uses its separate finite absolute deadline
/// (bounded by the raw transport deadline). Neither type can reset a phase clock.
/// Implementations must be primitive native stop/deadline checks only: no
/// allocation, formatting, source/database callbacks or authority decisions.
/// Sync permits a borrowed job checker to survive a Send request/worker future.
pub(crate) trait Check: Send + Sync {
    fn check(&self) -> Result<(), Error>;
}
pub(crate) struct Control<'a> {
    deadline: Instant,
    cancelled: &'a AtomicBool,
}
impl<'a> Control<'a> {
    pub(crate) fn new(deadline: Instant, cancelled: &'a AtomicBool) -> Self {
        Self {
            deadline,
            cancelled,
        }
    }
}
impl Check for Control<'_> {
    fn check(&self) -> Result<(), Error> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(Error::Cancelled)
        } else if Instant::now() >= self.deadline {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}

/// No allocation/queue on overload. Initialize once at node startup. The parent
/// must back BOTH bytes and concurrency with the actual approved node budget;
/// constructing this pool is not authorization to increase that budget.
pub(crate) struct Pool {
    bytes: AtomicUsize,
    jobs: AtomicUsize,
    byte_limit: usize,
    job_limit: usize,
}
impl Pool {
    pub(crate) const fn new(byte_limit: usize, job_limit: usize) -> Self {
        Self {
            bytes: AtomicUsize::new(0),
            jobs: AtomicUsize::new(0),
            byte_limit,
            job_limit,
        }
    }
    fn reserve(&self, bytes: usize, check: &dyn Check) -> Result<Ticket<'_>, Error> {
        let mut failure = None;
        self.jobs
            .try_update(Ordering::AcqRel, Ordering::Acquire, |jobs| {
                if let Err(error) = check.check() {
                    failure = Some(error);
                    return None;
                }
                jobs.checked_add(1).filter(|v| *v <= self.job_limit)
            })
            .map_err(|_| failure.unwrap_or(Error::Capacity))?;
        // RAII also returns the slot if a trusted checker unexpectedly unwinds.
        // Check every CAS retry: quota contention is not an unbounded preflight
        // worker whose deadline is checked only after admission returns.
        let mut ticket = Ticket {
            pool: self,
            bytes: 0,
        };
        failure = None;
        self.bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                if let Err(error) = check.check() {
                    failure = Some(error);
                    return None;
                }
                used.checked_add(bytes).filter(|v| *v <= self.byte_limit)
            })
            .map_err(|_| failure.unwrap_or(Error::Capacity))?;
        ticket.bytes = bytes;
        Ok(ticket)
    }
    #[cfg(test)]
    fn retained(&self) -> (usize, usize) {
        (
            self.bytes.load(Ordering::Acquire),
            self.jobs.load(Ordering::Acquire),
        )
    }
}
struct Ticket<'a> {
    pool: &'a Pool,
    bytes: usize,
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        self.pool.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.pool.jobs.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub body_bytes: usize,
    pub nodes: usize,
    pub keys: usize,
    pub depth: usize,
    pub number_bytes: usize,
    pub work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            body_bytes: MAX_BODY_BYTES,
            nodes: MAX_NODES,
            keys: MAX_KEYS,
            depth: MAX_DEPTH,
            number_bytes: 1024,
            work: 64 * 1024 * 1024,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<Self, Error> {
        if self.body_bytes == 0
            || self.body_bytes > MAX_BODY_BYTES
            || self.nodes == 0
            || self.nodes > MAX_NODES
            || self.keys > MAX_KEYS
            || self.depth == 0
            || self.depth > MAX_DEPTH
            || self.number_bytes == 0
            || self.number_bytes > 1024
            || self.work == 0
            || self.work > 64 * 1024 * 1024
        {
            return Err(Error::Capacity);
        }
        Ok(self)
    }
}

/// Trusted HTTP route kind only, never a caller-controlled SQL operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Transport {
    Query,
    Call,
}

#[derive(Clone, Copy, Default)]
struct Span {
    start: usize,
    end: usize,
}
impl Span {
    fn slice(self, bytes: &[u8]) -> &[u8] {
        &bytes[self.start..self.end]
    }
}

/// Fixed native lookup name and borrowed validated JSON spans. No Debug/Display:
/// args and credentials must never enter logs, error strings or source reports.
/// Holding this keeps a BORROW of the original retained Bytes; the caller must
/// keep the actual ingress byte lease alive. This owns no decoded argument tree.
pub(crate) struct Header<'body> {
    body: &'body [u8],
    name: [u8; MAX_NAME_BYTES],
    name_len: usize,
    args: Option<Span>,
    credentials: Option<Span>,
    request_id: Option<Span>,
    expected_revision: Option<u64>,
}
impl Header<'_> {
    pub(crate) fn name(&self) -> &str {
        // Written solely by the strict Unicode decoder.
        unsafe { std::str::from_utf8_unchecked(&self.name[..self.name_len]) }
    }
    pub(crate) fn args_json(&self) -> &[u8] {
        self.args.map_or(b"null", |s| s.slice(self.body))
    }
    pub(crate) fn credentials_json(&self) -> Option<&[u8]> {
        self.credentials.map(|s| s.slice(self.body))
    }
    pub(crate) fn request_id_json(&self) -> Option<&[u8]> {
        self.request_id.map(|s| s.slice(self.body))
    }
    pub(crate) fn expected_revision(&self) -> Option<u64> {
        self.expected_revision
    }
    pub(crate) fn body_len(&self) -> usize {
        self.body.len()
    }
}

/// Complete, syntax-checked name discovery only. It preserves ordinary JSON
/// duplicate-key last-wins semantics for routing, but confers no authority.
/// Keeping this alive also keeps the source borrowed through native preflight.
/// No Debug/Display. A fully decoded overlong name is opaque, not ordinary.
/// Only a complete healthy registry can prove that name is not a native alias.
pub(crate) struct NameLookup<'body> {
    body: &'body [u8],
    name: [u8; MAX_NAME_BYTES],
    name_len: usize,
}
impl NameLookup<'_> {
    pub(crate) fn decoded_len(&self) -> usize {
        self.name_len
    }
    pub(crate) fn bounded_name(&self) -> Option<&str> {
        (self.name_len <= MAX_NAME_BYTES).then(|| {
            // Only a complete strict Unicode decoder writes this inline name.
            unsafe { std::str::from_utf8_unchecked(&self.name[..self.name_len]) }
        })
    }
    /// Compatibility accessor for the supported inline path. Never truncates,
    /// panics, invents an empty name, or silently selects ordinary dispatch.
    pub(crate) fn name(&self) -> Result<&str, Error> {
        self.bounded_name().ok_or(Error::Unsupported)
    }
}

/// Scratch never holds copied body bytes. A failed scan poisons the owner;
/// name discovery then native preflight share ONE cumulative work allowance.
/// The owner accepts at most one discovery and one full native envelope.
pub(crate) struct Preflight<'pool> {
    levels: Mapping<Level>,
    keys: Mapping<Key>,
    limits: Limits,
    remaining: usize,
    failed: Option<Error>,
    discovered: bool,
    discovery_body: Option<(usize, usize)>,
    check: &'pool dyn Check,
    keys_dirty: bool,
    used: bool,
    _ticket: Ticket<'pool>,
}
impl<'pool> Preflight<'pool> {
    pub(crate) fn admission_bytes() -> Result<usize, Error> {
        rounded::<Level>(MAX_LOOKUP_DEPTH)?
            .checked_add(rounded::<Key>(KEY_SLOTS)?)
            .and_then(|n| n.checked_add(CONTROL_BYTES))
            .ok_or(Error::Capacity)
    }
    pub(crate) fn new(
        pool: &'pool Pool,
        limits: Limits,
        check: &'pool dyn Check,
    ) -> Result<Self, Error> {
        let limits = limits.validate()?;
        check.check()?;
        let ticket = pool.reserve(Self::admission_bytes()?, check)?;
        let levels = Mapping::new(MAX_LOOKUP_DEPTH, check)?;
        let keys = Mapping::new(KEY_SLOTS, check)?;
        Ok(Self {
            levels,
            keys,
            limits,
            remaining: limits.work,
            failed: None,
            discovered: false,
            discovery_body: None,
            check,
            keys_dirty: false,
            used: false,
            _ticket: ticket,
        })
    }
    fn same_check(&mut self, provided: &dyn Check) -> Result<(), Error> {
        let result = self.check.check().and_then(|()| {
            // Trait vtables may be duplicated across optimized codegen units.
            // Check the data address only; execution ALWAYS uses the retained
            // original checker, even if a same-address/ZST argument aliases it.
            if std::ptr::addr_eq(self.check, provided) {
                Ok(())
            } else {
                Err(Error::Invalid)
            }
        });
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
    /// Call before Value allocation, then give ONLY the complete witness to the
    /// parent's concrete classifier under its actual atomic Published guard. Ordinary aliases can retain their original
    /// JSON decoder: discovery does not apply native SQL duplicate/key/node or
    /// mantissa caps to their argument trees. Unsupported is never a fallback.
    pub(crate) fn lookup_name<'body>(
        &mut self,
        body: &'body [u8],
        check: &dyn Check,
    ) -> Result<NameLookup<'body>, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.used || self.discovered {
            self.failed = Some(Error::Invalid);
            return Err(Error::Invalid);
        }
        self.same_check(check)?;
        let check = self.check;
        self.discovered = true;
        let result = (|| {
            check.check()?;
            if body.len() > self.limits.body_bytes {
                return Err(Error::Capacity);
            }
            let mut scanner = Scanner::new(
                body,
                &mut self.levels,
                &mut self.keys,
                self.limits,
                &mut self.remaining,
                check,
            );
            scanner.lookup_name()
        })();
        match &result {
            Ok(lookup) => {
                self.discovery_body = Some((lookup.body.as_ptr() as usize, lookup.body.len()))
            }
            Err(error) => self.failed = Some(*error),
        }
        result
    }
    /// Borrow the actual complete discovery, scratch and cumulative work ledger.
    /// This creates no source/publication/authority witness and accepts no flags.
    pub(crate) fn registry_classifier<'borrow, 'body>(
        &'borrow mut self,
        lookup: &'borrow NameLookup<'body>,
        check: &'borrow dyn Check,
    ) -> Result<RegistryClassifier<'borrow, 'pool, 'body>, Error> {
        let result = (|| {
            if let Some(error) = self.failed {
                return Err(error);
            }
            self.same_check(check)?;
            if self.used
                || self.discovery_body != Some((lookup.body.as_ptr() as usize, lookup.body.len()))
            {
                return Err(Error::Invalid);
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.failed = Some(error);
            return Err(error);
        }
        let original_check = self.check;
        Ok(RegistryClassifier::new(self, lookup, original_check))
    }
    /// The raw body is attached to discovery, not an independent caller object.
    /// The returned header still does NOT carry a sealed-registry witness.
    pub(crate) fn parse_lookup<'body>(
        &mut self,
        lookup: &NameLookup<'body>,
        transport: Transport,
        check: &dyn Check,
    ) -> Result<Header<'body>, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        self.same_check(check)?;
        if self.discovery_body != Some((lookup.body.as_ptr() as usize, lookup.body.len())) {
            self.failed = Some(Error::Invalid);
            return Err(Error::Invalid);
        }
        if lookup.bounded_name().is_none() {
            self.failed = Some(Error::Unsupported);
            return Err(Error::Unsupported);
        }
        let header = self.parse(lookup.body, transport, check)?;
        if Some(header.name()) != lookup.bounded_name() {
            self.failed = Some(Error::Invalid);
            return Err(Error::Invalid);
        }
        Ok(header)
    }
    pub(crate) fn parse<'body>(
        &mut self,
        body: &'body [u8],
        transport: Transport,
        check: &dyn Check,
    ) -> Result<Header<'body>, Error> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.used {
            self.failed = Some(Error::Invalid);
            return Err(Error::Invalid);
        }
        self.same_check(check)?;
        let check = self.check;
        self.used = true;
        let result = (|| {
            check.check()?;
            if body.len() > self.limits.body_bytes.min(MAX_INPUT_BYTES) {
                return Err(Error::Capacity);
            }
            // New mappings are fully initialized to default keys already.
            // Discovery inserts no keys. Only actual reused registry scratch
            // needs another metered clear before interpreting invocation spans.
            let keys_dirty = self.keys_dirty;
            self.keys_dirty = true;
            let mut scanner = Scanner::new(
                body,
                &mut self.levels,
                &mut self.keys,
                self.limits,
                &mut self.remaining,
                check,
            );
            if keys_dirty {
                scanner.clear_keys()?;
            }
            scanner.envelope(transport)
        })();
        if let Err(error) = result {
            self.failed = Some(error);
        }
        result
    }
}

#[cfg(test)]
#[path = "sql_ingress/lookup_tests.rs"]
mod lookup_tests;
#[cfg(test)]
#[path = "sql_ingress/owned_tests.rs"]
mod owned_tests;
#[cfg(test)]
#[path = "sql_ingress/source_tests.rs"]
mod source_tests;
#[cfg(test)]
#[path = "sql_ingress/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "sql_ingress/registry_tests.rs"]
mod registry_tests;
