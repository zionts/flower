//! Raw protected-lifetime range existence over the actual Records overlay.
//!
//! Always-built key-only source primitive, independent of SQL serving. It uses
//! the actual borrowed Backing view and generic bounded im/redb read features.
//! Native destructive control is NOT wired by this module import: its caller
//! must provide sticky roster authority, ONE original work/resident scope and
//! publication exclusion plus genuinely prepaid native scratch/stack backing.
//!
//! Bounds come exclusively from the parent's sticky native roster. This module
//! checks their byte shape, NOT their authority or canonical namespace spelling.
//! No schema declaration, value, version, body, metadata validator, ordinary I/O,
//! cache, memo, Records/Backing/Value clone, or escaping root/guard participates.

use super::Records;
use crate::consensus::backing::{PairTable, PlainTable};
use std::ops::Bound;

/// Initial supported representation, NOT a permanent limit on ordinary names.
/// Overlong selectors/namespaces/encountered keys HOLD through a typed fault.
pub(crate) const LIFETIME_KEY_CAPACITY: usize = 4096;

/// A scalar answer only. Found is a semantic lifetime refusal for the parent;
/// faults are source fail-stop/HOLD, and must never be rewritten to Absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimePresence {
    Found,
    Absent,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimeUnsupported {
    Selector,
    Namespace,
    Candidate,
    RunBacking,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifetimePresenceFault {
    Work,
    Unsupported(LifetimeUnsupported),
    InvalidBounds,
    NamespaceChanged,
    InvalidUtf8,
    CorruptOverlay,
    /// Preserves cold/quota/contention/inactive/depth/corruption as faults.
    Native(redb::ResidentReadFault),
    Storage,
}

/// ONE preprovided cumulative logical work meter. Exhaustion is sticky; no
/// selector or internal phase refreshes it. Tokens count calls/end probes,
/// candidates/tombstones, and initialized/copied/checked scratch bytes. They are
/// NOT an instruction, deadline, retained-memory, physical-page, or RSS bound.
/// Vendor traversal separately fixes depth at 128. The ONE outer resident scope
/// meters cumulative native extent bytes; the parent must not renew that scope.
pub(crate) struct LifetimeWork {
    remaining: usize,
    used: usize,
    exhausted: bool,
}
impl LifetimeWork {
    pub(crate) fn new(preprovided: usize) -> Self {
        Self {
            remaining: preprovided,
            used: 0,
            exhausted: false,
        }
    }
    pub(crate) fn used(&self) -> usize {
        self.used
    }
    fn charge(&mut self, amount: usize) -> Result<(), LifetimePresenceFault> {
        if self.exhausted || amount > self.remaining {
            self.exhausted = true;
            return Err(LifetimePresenceFault::Work);
        }
        self.remaining -= amount;
        // used + remaining never exceeds the original preprovided usize.
        self.used += amount;
        Ok(())
    }
}

/// Parent hook's ONLY result: borrowing the already-held backing, without
/// cloning a table/Arc or opening a transaction. No view may leave the call.
/// Implement the match inside backing.rs, where Table is private:
/// Empty => Empty, Plain(t) => Plain(t), Pair(t,p) => Pair(t,p), Run(_) => Run.
pub(crate) enum LifetimeBackingView<'a> {
    Empty,
    Plain(&'a PlainTable),
    Pair(&'a PairTable, &'a str),
    Run,
}

/// Root-free, fixed-capacity scratch. Construct/admit/write-touch BEFORE taking
/// the root/exclusion; constructor work uses the SAME meter as execution.
/// size_of::<Self>() reports only this object, not a physical/native allowance.
/// redb's range scratch has exactly 128 parent slots and one leaf. Returned page
/// guards remain local to the resident/excluded call and are dropped on fault.
pub(crate) struct LifetimePresenceScratch {
    bounds: redb::ResidentRangeBounds,
    range: redb::ResidentRangeScratch,
    lower: [u8; LIFETIME_KEY_CAPACITY],
    upper: [u8; LIFETIME_KEY_CAPACITY],
    bound_len: usize,
    query: [u8; LIFETIME_KEY_CAPACITY + 1],
    namespace: [u8; LIFETIME_KEY_CAPACITY],
    namespace_len: Option<usize>,
}
impl LifetimePresenceScratch {
    /// Exact source-prefix interval [P, P-with-final-comma-replaced-by-minus).
    /// Collection-marker keys do not belong in this interval. The parent alone
    /// derives canonical P from sticky nativeRoster, never a schema name list.
    pub(crate) fn prepare(
        lower: &str,
        upper: &str,
        namespace: Option<&str>,
        work: &mut LifetimeWork,
    ) -> Result<Self, LifetimePresenceFault> {
        work.charge(1)?; // attempted constructor, including every refusal
        if lower.len() > LIFETIME_KEY_CAPACITY || upper.len() > LIFETIME_KEY_CAPACITY {
            return Err(LifetimePresenceFault::Unsupported(
                LifetimeUnsupported::Selector,
            ));
        }
        if namespace.is_some_and(|name| name.len() > LIFETIME_KEY_CAPACITY) {
            return Err(LifetimePresenceFault::Unsupported(
                LifetimeUnsupported::Namespace,
            ));
        }
        work.charge(lower.len() + upper.len() + namespace.map_or(0, str::len))?;
        let Some((&last, prefix)) = lower.as_bytes().split_last() else {
            return Err(LifetimePresenceFault::InvalidBounds);
        };
        if last != b','
            || upper.len() != lower.len()
            || upper.as_bytes().last() != Some(&b'-')
            || &upper.as_bytes()[..prefix.len()] != prefix
        {
            return Err(LifetimePresenceFault::InvalidBounds);
        }
        // Fixed initialization/touch plus copies are charged before construction.
        work.charge(
            std::mem::size_of::<Self>() + lower.len() + upper.len() + namespace.map_or(0, str::len),
        )?;
        let lower_bound = Bound::Included(lower.as_bytes());
        let upper_bound = Bound::Excluded(upper.as_bytes());
        let mut bounds = match namespace {
            Some(name) => {
                redb::ResidentRangeBounds::partition(name.as_bytes(), lower_bound, upper_bound)
            }
            None => redb::ResidentRangeBounds::plain(lower_bound, upper_bound),
        }
        .map_err(native_fault)?;
        let mut range = redb::ResidentRangeScratch::new();
        bounds.pre_touch();
        range.pre_touch();
        let mut scratch = Self {
            bounds,
            range,
            lower: [0; LIFETIME_KEY_CAPACITY],
            upper: [0; LIFETIME_KEY_CAPACITY],
            bound_len: lower.len(),
            query: [0; LIFETIME_KEY_CAPACITY + 1],
            namespace: [0; LIFETIME_KEY_CAPACITY],
            namespace_len: namespace.map(str::len),
        };
        scratch.lower[..lower.len()].copy_from_slice(lower.as_bytes());
        scratch.upper[..upper.len()].copy_from_slice(upper.as_bytes());
        if let Some(name) = namespace {
            scratch.namespace[..name.len()].copy_from_slice(name.as_bytes());
        }
        // Do not infer physical residency from initialization or these touches.
        for byte in scratch
            .lower
            .iter_mut()
            .chain(scratch.upper.iter_mut())
            .chain(scratch.query.iter_mut())
            .chain(scratch.namespace.iter_mut())
        {
            unsafe {
                std::ptr::write_volatile(byte, *byte);
            }
        }
        Ok(scratch)
    }
}

fn native_fault(error: redb::StorageError) -> LifetimePresenceFault {
    match redb::resident_read_fault(&error) {
        Some(reason) => LifetimePresenceFault::Native(reason),
        None => LifetimePresenceFault::Storage,
    }
}
fn overlay_fault(error: im::BoundedReadError) -> LifetimePresenceFault {
    match error {
        im::BoundedReadError::Depth => LifetimePresenceFault::Work,
        im::BoundedReadError::InvalidNode => LifetimePresenceFault::CorruptOverlay,
    }
}
fn checked_key<'a>(
    bytes: &'a [u8],
    work: &mut LifetimeWork,
) -> Result<&'a str, LifetimePresenceFault> {
    work.charge(1)?; // candidate, even overlong/malformed or a tombstone
    if bytes.len() > LIFETIME_KEY_CAPACITY {
        return Err(LifetimePresenceFault::Unsupported(
            LifetimeUnsupported::Candidate,
        ));
    }
    work.charge(bytes.len())?; // UTF-8 check/maximum bounded key comparison bytes
    std::str::from_utf8(bytes).map_err(|_| LifetimePresenceFault::InvalidUtf8)
}

/// Visit the complete disk interval, unless a live unshadowed raw key proves
/// Found earlier. No value access (including version/header) is needed. A body
/// may be empty, malformed packed JSON, Null, scalar, or arbitrarily large.
fn disk_presence<'a, K: redb::Key + 'static>(
    records: &Records,
    range: &mut redb::ResidentRange<'a, K>,
    key_bytes: impl for<'guard> Fn(&'guard redb::AccessGuard<'a, K>) -> &'guard [u8],
    work: &mut LifetimeWork,
) -> Result<LifetimePresence, LifetimePresenceFault> {
    loop {
        work.charge(1)?; // next call, including final end probe and native fault
        let Some(entry) = range.next() else {
            return Ok(LifetimePresence::Absent);
        };
        let (raw_key, raw_body) = entry.map_err(native_fault)?;
        let key = checked_key(key_bytes(&raw_key), work)?;
        work.charge(1)?; // bounded exact-shadow lookup; misses/end probes count
        match records.map.get_next_bounded(key).map_err(overlay_fault)? {
            Some((overlay_key, entry)) => {
                let overlay_key = checked_key(overlay_key.as_bytes(), work)?;
                if overlay_key == key {
                    // This candidate is already charged; tombstone work is extra.
                    work.charge(1)?;
                    if entry.value.is_some() {
                        return Ok(LifetimePresence::Found);
                    }
                } else {
                    return Ok(LifetimePresence::Found);
                }
            }
            None => return Ok(LifetimePresence::Found),
        }
        // Page references do not accumulate in a key queue or escape this call.
        drop(raw_body);
        drop(raw_key);
    }
}

impl Records {
    /// Presence in the exact relevant merged range, using key identity ONLY.
    /// Borrow from ONE actual current publication inside its mutation exclusion
    /// and outer resident scope. Scratch/meter must already have been admitted.
    /// The parent interprets Found as deterministic semantic refusal and every
    /// fault as source fail-stop; no fault authorizes deletion or release.
    pub(crate) fn lifetime_presence(
        &self,
        scratch: &mut LifetimePresenceScratch,
        work: &mut LifetimeWork,
    ) -> Result<LifetimePresence, LifetimePresenceFault> {
        work.charge(1)?; // backing/view lookup, never a root/Arc clone
        let backing = match self.backing.as_deref() {
            None => LifetimeBackingView::Empty,
            Some(backing) => backing.lifetime_presence_view(),
        };
        match &backing {
            LifetimeBackingView::Pair(_, namespace) => {
                if namespace.len() > LIFETIME_KEY_CAPACITY {
                    return Err(LifetimePresenceFault::Unsupported(
                        LifetimeUnsupported::Namespace,
                    ));
                }
                work.charge(namespace.len() + 1)?;
                if scratch.namespace_len != Some(namespace.len())
                    || scratch.namespace[..namespace.len()] != *namespace.as_bytes()
                {
                    return Err(LifetimePresenceFault::NamespaceChanged);
                }
            }
            LifetimeBackingView::Plain(_) if scratch.namespace_len.is_some() => {
                return Err(LifetimePresenceFault::NamespaceChanged);
            }
            _ => {}
        }
        work.charge(scratch.bound_len)?;
        scratch.query[..scratch.bound_len].copy_from_slice(&scratch.lower[..scratch.bound_len]);
        let mut query_len = scratch.bound_len;
        let upper = std::str::from_utf8(&scratch.upper[..scratch.bound_len])
            .map_err(|_| LifetimePresenceFault::InvalidUtf8)?;
        // Overlay first: a later live overlay entry may prove presence while the
        // backing's first child page is cold. Tombstones still consume work.
        loop {
            work.charge(1)?; // lookup/prefetch, including empty/out-of-range end
            let query = std::str::from_utf8(&scratch.query[..query_len])
                .map_err(|_| LifetimePresenceFault::InvalidUtf8)?;
            let Some((key, entry)) = self.map.get_next_bounded(query).map_err(overlay_fault)?
            else {
                break;
            };
            let key = checked_key(key.as_bytes(), work)?;
            if key >= upper {
                break;
            }
            if entry.value.is_some() {
                return Ok(LifetimePresence::Found);
            }
            work.charge(1 + key.len() + 1)?; // tombstone + successor copy + NUL
            scratch.query[..key.len()].copy_from_slice(key.as_bytes());
            scratch.query[key.len()] = 0; // strict successor even for embedded NUL
            query_len = key.len() + 1;
        }
        work.charge(1)?; // cursor construction/backing dispatch, including refusals
        match backing {
            LifetimeBackingView::Empty => {
                work.charge(1)?; // complete empty-backing end probe
                Ok(LifetimePresence::Absent)
            }
            LifetimeBackingView::Run => Err(LifetimePresenceFault::Unsupported(
                LifetimeUnsupported::RunBacking,
            )),
            LifetimeBackingView::Plain(table) => {
                let mut range = table
                    .resident_range(&scratch.bounds, &mut scratch.range)
                    .map_err(native_fault)?;
                disk_presence(self, &mut range, |key| key.value(), work)
            }
            LifetimeBackingView::Pair(table, _) => {
                let mut range = table
                    .resident_partition_range(&scratch.bounds, &mut scratch.range)
                    .map_err(native_fault)?;
                disk_presence(self, &mut range, |key| key.value().1, work)
            }
        }
    }
}

#[cfg(test)]
mod tests;
