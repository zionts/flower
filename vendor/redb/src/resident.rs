//! Flower's synchronous, quota-first resident reads. No cache fill or file I/O.
use crate::{StorageError, io};
use std::cell::Cell;

#[derive(Clone, Copy)]
struct Budget {
    maximum: usize,
    used: usize,
}
thread_local! { static BUDGET: Cell<Option<Budget>> = const { Cell::new(None) }; }

/// Why a resident-only read could not proceed. These are not backend failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentReadFault {
    /// The required extent is not already in a resident cache/buffer.
    ColdPage { offset: u64, length: usize },
    /// A cache lock is held by another operation; this scope never waits.
    Contended,
    /// The cumulative extent-byte allowance was exhausted before a read.
    Budget,
}
impl std::fmt::Display for ResidentReadFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "resident-only read: {self:?}")
    }
}
impl std::error::Error for ResidentReadFault {}

/// Run synchronous read-only operations without allocating/filling page buffers,
/// flushing buffered writes, or reaching the storage backend. Cache locks are
/// tried, never waited on. The allowance charges each requested extent before
/// looking it up, including repeat reads and misses; it is not the cache size.
/// Nested scopes share the outer allowance and cannot renew it. The closure
/// must not perform writes, spawn work, or return database/page/table guards.
pub fn with_resident_reads<T>(maximum_extent_bytes: usize, read: impl FnOnce() -> T) -> T {
    struct Reset(Option<Budget>);
    impl Drop for Reset {
        fn drop(&mut self) {
            BUDGET.with(|budget| budget.set(self.0));
        }
    }
    let previous = BUDGET.with(Cell::get);
    if previous.is_some() {
        return read();
    }
    BUDGET.with(|budget| {
        budget.set(Some(Budget {
            maximum: maximum_extent_bytes,
            used: 0,
        }))
    });
    let _reset = Reset(previous);
    read()
}

pub(crate) fn charge(length: usize) -> Option<Result<(), StorageError>> {
    BUDGET.with(|cell| {
        let mut budget = cell.get()?;
        let Some(used) = budget
            .used
            .checked_add(length)
            .filter(|used| *used <= budget.maximum)
        else {
            budget.used = budget.maximum;
            cell.set(Some(budget));
            return Some(Err(fault(ResidentReadFault::Budget)));
        };
        budget.used = used;
        cell.set(Some(budget));
        Some(Ok(()))
    })
}
pub(crate) fn fault(reason: ResidentReadFault) -> StorageError {
    // This error is created above CheckedBackend, so it cannot latch io_failed.
    StorageError::Io(io::Error::new(std::io::ErrorKind::WouldBlock, reason))
}
/// Extract a resident-only refusal without classifying real backend errors as
/// cache misses. This preserves the ordinary I/O failure semantics.
pub fn resident_read_fault(error: &StorageError) -> Option<ResidentReadFault> {
    let StorageError::Io(error) = error else {
        return None;
    };
    error
        .get_ref()?
        .downcast_ref::<ResidentReadFault>()
        .copied()
}

// Only Flower's scoped, mutation-excluded reads use release-equivalent PageImpl
// tracking in debug builds. They must drop every page before leaving the scope.
pub(crate) fn active() -> bool {
    BUDGET.with(|budget| budget.get().is_some())
}
