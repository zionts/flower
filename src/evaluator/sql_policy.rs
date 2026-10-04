//! Root-free native collection reads for terminal SQL, NOT a serving activation.
//!
//! All inputs borrow already-owned, trusted capture. No provider, Records, App,
//! guest principal/definer assertion, key capability or mutable source is accepted.
//! Controllers must discard a job on any error, insert only approved/redacted
//! candidates, carry temporal validity into freshness/publication, and destroy
//! capture before SQLite. Ordinary SQL's retention gate remains HOLD.
#[path = "sql_policy/compare.rs"]
mod compare;
#[path = "sql_policy/redact.rs"]
mod redact;
#[path = "sql_policy/rule.rs"]
mod rule;
#[path = "sql_policy/typed.rs"]
mod typed;
pub(crate) use typed::{NativeDecodedKey, NativeKeyRow};

use super::sql_control::JobControl;
use super::sql_frame::{ArenaEntry, ArenaIter, ArenaKind, ArenaValue, FrameError};
use super::sqlite::SqlError;
use std::cell::Cell;

pub(crate) const MAX_RULE_NODES: usize = 256;
pub(crate) const MAX_RULE_DEPTH: usize = 32;
pub(crate) const MAX_POLICY_WORK: usize = 64 * 1024 * 1024;
const MAX_COLLECTIONS: usize = 64;
const MAX_SUPPORT_ROWS: usize = 20_000;

/// Deliberately carries no row contents, names, keys, provenance or security IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PolicyError {
    Unsupported,
    NeedCapture,
    UncertifiedTemporal,
    RuleLimit,
    Capacity,
    WorkLimit,
    Cancelled,
    Deadline,
}
impl std::fmt::Display for PolicyError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Unsupported => "unsupported terminal policy semantics",
            Self::NeedCapture => "terminal policy support was not captured",
            Self::UncertifiedTemporal => "uncertified terminal policy time dependence",
            Self::RuleLimit => "terminal policy rule limit exceeded",
            Self::Capacity => "terminal policy capacity exceeded",
            Self::WorkLimit => "terminal policy work limit exceeded",
            Self::Cancelled => "terminal policy cancelled",
            Self::Deadline => "terminal policy deadline exceeded",
        })
    }
}
impl std::error::Error for PolicyError {}
impl From<FrameError> for PolicyError {
    fn from(error: FrameError) -> Self {
        match error {
            FrameError::Capacity => Self::Capacity,
            FrameError::Invalid | FrameError::Unsupported => Self::Unsupported,
            FrameError::WorkLimit => Self::WorkLimit,
            FrameError::Cancelled => Self::Cancelled,
            FrameError::Deadline => Self::Deadline,
        }
    }
}

/// No-dependence and mathematically proved no future flip are distinct.
/// `Until(t)` is exclusive: publication/reuse at t must reauthorize, even with
/// no write. Native wall-clock selection and final freshness belong to caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Validity {
    Independent,
    ClockInvariant,
    Until(u64),
}
impl Validity {
    pub(crate) fn intersect(self, other: Self) -> Self {
        match (self, other) {
            (Self::Until(a), Self::Until(b)) => Self::Until(a.min(b)),
            (value @ Self::Until(_), _) | (_, value @ Self::Until(_)) => value,
            (Self::ClockInvariant, _) | (_, Self::ClockInvariant) => Self::ClockInvariant,
            _ => Self::Independent,
        }
    }
    pub(crate) fn permits(self, native_now: u64) -> bool {
        match self {
            Self::Until(at) => native_now < at,
            Self::Independent | Self::ClockInvariant => true,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Decision {
    pub allowed: bool,
    pub validity: Validity,
}

/// Single cumulative policy work account for the WHOLE admitted job, including
/// every row, field, support lookup, validation, serialization and replay.
/// Caller may lower, never raise, the cap. No error can be caught and resumed.
pub(crate) struct PolicyBudget {
    remaining: Cell<usize>,
    failed: Cell<Option<PolicyError>>,
    validity: Cell<Validity>,
    not_before: Cell<Option<u64>>,
}
impl PolicyBudget {
    pub(crate) fn new(work: usize) -> Result<Self, PolicyError> {
        if work > MAX_POLICY_WORK {
            return Err(PolicyError::Capacity);
        }
        Ok(Self {
            remaining: Cell::new(work),
            failed: Cell::new(None),
            validity: Cell::new(Validity::Independent),
            not_before: Cell::new(None),
        })
    }
    pub(crate) fn failure(&self) -> Option<PolicyError> {
        self.failed.get()
    }
    pub(crate) fn remaining_work(&self) -> usize {
        self.remaining.get()
    }
    /// Mandatory before seal AND final publication: a caught policy error or
    /// a clock-only change cannot turn earlier approved rows into a result.
    /// Supplied time is native, never guest ctx.clock or a claimed stable proof.
    pub(crate) fn finish(
        &self,
        job: &mut JobControl,
        native_now: u64,
    ) -> Result<Validity, PolicyError> {
        let work = self.operation(job)?;
        let validity = self.validity.get();
        if self
            .not_before
            .get()
            .is_some_and(|start| native_now < start)
            || !validity.permits(native_now)
        {
            return work.keep(Err(PolicyError::UncertifiedTemporal));
        }
        Ok(validity)
    }
    fn note(&self, validity: Validity, native_now: u64) {
        self.validity.set(self.validity.get().intersect(validity));
        if validity != Validity::Independent {
            self.not_before.set(Some(
                self.not_before
                    .get()
                    .map_or(native_now, |old| old.max(native_now)),
            ));
        }
    }
    fn fail(&self, error: PolicyError) -> PolicyError {
        let error = self.failed.get().unwrap_or(error);
        self.failed.set(Some(error));
        error
    }
    fn operation<'b>(&'b self, job: &'b mut JobControl) -> Result<Work<'b>, PolicyError> {
        let mut work = Work { budget: self, job };
        work.debit(0)?;
        Ok(work)
    }
}
struct Work<'a> {
    budget: &'a PolicyBudget,
    job: &'a mut JobControl,
}
impl Work<'_> {
    fn debit(&mut self, units: usize) -> Result<(), PolicyError> {
        if let Some(error) = self.budget.failure() {
            return Err(error);
        }
        self.job.check().map_err(|error| {
            self.budget.fail(match error {
                SqlError::Cancelled => PolicyError::Cancelled,
                SqlError::Deadline => PolicyError::Deadline,
                _ => PolicyError::Unsupported,
            })
        })?;
        let left = self
            .budget
            .remaining
            .get()
            .checked_sub(units)
            .ok_or_else(|| self.budget.fail(PolicyError::WorkLimit))?;
        self.budget.remaining.set(left);
        Ok(())
    }
    fn keep<T>(&self, result: Result<T, PolicyError>) -> Result<T, PolicyError> {
        result.map_err(|error| self.budget.fail(error))
    }
    fn frame<T>(&self, result: Result<T, FrameError>) -> Result<T, PolicyError> {
        self.keep(result.map_err(PolicyError::from))
    }
    fn next<'a>(
        &mut self,
        iter: &mut ArenaIter<'a>,
    ) -> Result<Option<ArenaEntry<'a>>, PolicyError> {
        self.debit(1)?;
        iter.next().map(|result| self.frame(result)).transpose()
    }
    /// O(1) fallible arena boundary even when no policy/field/traversal exists.
    /// as_f64 only reads cached classification; it does not coerce or reparse.
    fn touch(&mut self, value: ArenaValue<'_>) -> Result<(), PolicyError> {
        self.debit(1)?;
        self.frame(value.as_f64())?;
        Ok(())
    }
    fn get<'a>(
        &mut self,
        value: ArenaValue<'a>,
        name: &str,
    ) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        self.debit(1)?;
        // Arena hashing/probes/comparisons are separately sticky and metered.
        self.frame(value.get(name))
    }
    fn text_order(&mut self, left: &str, right: &str) -> Result<std::cmp::Ordering, PolicyError> {
        use std::cmp::Ordering;
        let len = left.len().min(right.len());
        let mut offset = 0;
        while offset < len {
            let end = (offset + 1024).min(len);
            self.debit(end - offset)?;
            let order = left.as_bytes()[offset..end].cmp(&right.as_bytes()[offset..end]);
            if order != Ordering::Equal {
                return Ok(order);
            }
            offset = end;
        }
        self.debit(1)?;
        Ok(left.len().cmp(&right.len()))
    }
    fn text_same(&mut self, left: &str, right: &str) -> Result<bool, PolicyError> {
        self.debit(1)?;
        if left.len() != right.len() {
            return Ok(false);
        }
        Ok(self.text_order(left, right)? == std::cmp::Ordering::Equal)
    }
}

/// These rows and policies MUST be supplied by the native controller from an
/// already-owned capture, not from a guest-constructed manifest or assertion.
#[derive(Clone, Copy)]
pub(crate) struct CapturedCollection<'a> {
    pub name: &'a str,
    /// None is authoritative absence of an access policy (ordinary open read).
    pub policy: Option<ArenaValue<'a>>,
}
#[derive(Clone, Copy)]
pub(crate) struct CapturedSupportRow<'a> {
    pub collection: &'a str,
    pub key: &'a str,
    /// None is authoritative captured row absence. Missing slice entry is NOT.
    pub row: Option<ArenaValue<'a>>,
}
#[derive(Clone, Copy)]
pub(crate) struct CapturedSupport<'a> {
    collections: &'a [CapturedCollection<'a>],
    rows: &'a [CapturedSupportRow<'a>],
    native_rows: Option<&'a [NativeKeyRow<'a>]>,
}
impl<'a> CapturedSupport<'a> {
    pub(crate) fn from_owned_capture(
        collections: &'a [CapturedCollection<'a>],
        rows: &'a [CapturedSupportRow<'a>],
    ) -> Result<Self, PolicyError> {
        if collections.len() > MAX_COLLECTIONS || rows.len() > MAX_SUPPORT_ROWS {
            return Err(PolicyError::Capacity);
        }
        Ok(Self {
            collections,
            rows,
            native_rows: None,
        })
    }
    fn collection(
        self,
        name: &str,
        work: &mut Work<'_>,
    ) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        let mut found = None;
        for item in self.collections {
            work.debit(1)?;
            if work.text_same(item.name, name)? {
                if found.is_some() {
                    return Err(PolicyError::Unsupported);
                }
                found = Some(item.policy);
            }
        }
        found.ok_or(PolicyError::NeedCapture)
    }
    fn row(
        self,
        collection: &str,
        key: &str,
        work: &mut Work<'_>,
    ) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        let mut found = None;
        for item in self.rows {
            work.debit(1)?;
            if work.text_same(item.collection, collection)? && work.text_same(item.key, key)? {
                if found.is_some() {
                    return Err(PolicyError::Unsupported);
                }
                found = Some(item.row);
            }
        }
        found.ok_or(PolicyError::NeedCapture)
    }
}

/// No privilege mode/bool: only a verified principal from the separate native
/// authentication phase. `$anonymous` normalization exactly matches access.rs.
#[derive(Clone, Copy)]
pub(crate) struct VerifiedPrincipal<'a> {
    value: ArenaValue<'a>,
    anonymous: bool,
    object: bool,
}
impl<'a> VerifiedPrincipal<'a> {
    pub(crate) fn from_native_auth(
        value: ArenaValue<'a>,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Self, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            work.touch(value)?;
            let object = value.kind() == ArenaKind::Object;
            let anonymous = object
                && work.get(value, "subject")?.and_then(ArenaValue::as_str) == Some("$anonymous");
            Ok(Self {
                value,
                anonymous,
                object,
            })
        })();
        work.keep(result)
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PolicyEngine<'a> {
    support: CapturedSupport<'a>,
    principal: VerifiedPrincipal<'a>,
    now: u64,
}
impl<'a> PolicyEngine<'a> {
    pub(crate) fn new(
        support: CapturedSupport<'a>,
        verified_principal: VerifiedPrincipal<'a>,
        native_now: u64,
    ) -> Self {
        Self {
            support,
            principal: verified_principal,
            now: native_now,
        }
    }
    /// Use on EVERY get/read/scan/range row, BEFORE projection, SQLite insertion,
    /// aggregation, limit, offset or cursor formation. Index/selecting fields
    /// must be visible too; omitting them is not a policy-authorized range API.
    pub(crate) fn authorize(
        &self,
        collection: &str,
        key: &'a str,
        row: ArenaValue<'a>,
        selecting_fields: &[&str],
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<ReadAuthorization<'a>, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            work.touch(row)?;
            let policy = self.support.collection(collection, &mut work)?;
            let parts = rule::policy_parts(policy, &mut work)?;
            // Validate EVERY read rule, even a hidden row/absent field/branch.
            rule::validate_policy_reads(parts, self.support, false, &mut work)?;
            let subject = rule::Subject {
                engine: *self,
                key,
                parts: None,
                native: false,
                row,
            };
            let mut decision = rule::evaluate_optional(parts.read, false, subject, &mut work)?;
            if policy.is_none() {
                decision.allowed = true;
            }
            if decision.allowed {
                for field in selecting_fields {
                    let shown = rule::field_decision(parts.fields, field, subject, &mut work)?;
                    decision.allowed &= shown.allowed;
                    decision.validity = decision.validity.intersect(shown.validity);
                }
            }
            // Field redaction must be certified before a candidate is exposed.
            if decision.allowed
                && let Some(fields) = parts.fields
            {
                let mut iter = fields.children();
                while let Some(entry) = work.next(&mut iter)? {
                    let name = entry.key.ok_or(PolicyError::Unsupported)?;
                    if work.get(row, name)?.is_some() {
                        let shown = rule::field_decision(parts.fields, name, subject, &mut work)?;
                        decision.validity = decision.validity.intersect(shown.validity);
                    }
                }
            }
            budget.note(decision.validity, self.now);
            Ok(ReadAuthorization {
                decision,
                candidate: decision.allowed.then_some(RedactedRow {
                    subject,
                    fields: parts.fields,
                    validity: decision.validity,
                }),
            })
        })();
        work.keep(result)
    }
}
pub(crate) struct ReadAuthorization<'a> {
    pub decision: Decision,
    pub candidate: Option<RedactedRow<'a>>,
}
/// Private raw-row state; no raw-source/override accessor. All visible access
/// passes through the same verified-principal field predicate.
pub(crate) struct RedactedRow<'a> {
    subject: rule::Subject<'a>,
    fields: Option<ArenaValue<'a>>,
    validity: Validity,
}

#[cfg(test)]
#[path = "sql_policy/tests.rs"]
mod tests;
