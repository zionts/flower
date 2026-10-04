//! Flower's synchronous, quota-first resident reads. No cache fill or file I/O.
use crate::StorageError;
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
    /// No synchronous resident scope is active on this thread.
    Inactive,
    /// The fixed native traversal path limit was reached.
    Depth,
    /// A node header, offset, encoded key or page address is malformed.
    Corrupt,
    /// A request exceeds the fixed key capacity or uses the wrong bounds kind.
    InvalidRequest,
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
        }));
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
    // Created above CheckedBackend: no boxing/allocation and no io_failed latch.
    StorageError::Resident(reason)
}
/// Extract a resident-only refusal without reclassifying real backend failures.
pub fn resident_read_fault(error: &StorageError) -> Option<ResidentReadFault> {
    match error {
        StorageError::Resident(reason) => Some(*reason),
        _ => None,
    }
}

pub(crate) fn require_active() -> Result<(), StorageError> {
    if active() {
        Ok(())
    } else {
        Err(fault(ResidentReadFault::Inactive))
    }
}

// Only Flower's scoped, mutation-excluded reads use release-equivalent PageImpl
// tracking in debug builds. They must drop every page before leaving the scope.
pub(crate) fn active() -> bool {
    BUDGET.with(|budget| budget.get().is_some())
}

// Isolated vendor test instrumentation only. No production allocator interception.
#[cfg(test)]
pub(crate) mod test_support {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! {
        static PROBE: Cell<Option<[usize; 3]>> = const { Cell::new(None) };
    }
    fn record(index: usize) {
        let _ = PROBE.try_with(|probe| {
            if let Some(mut count) = probe.get() {
                count[index] += 1;
                probe.set(Some(count));
            }
        });
    }
    struct ProbeAllocator;
    #[global_allocator]
    static ALLOCATOR: ProbeAllocator = ProbeAllocator;
    unsafe impl GlobalAlloc for ProbeAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            record(0);
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            record(1);
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            record(2);
            unsafe { System.realloc(ptr, layout, new_size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
    pub(crate) fn probe<T>(run: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                PROBE.with(|probe| probe.set(None));
            }
        }
        PROBE.with(|probe| {
            assert!(probe.get().is_none());
            probe.set(Some([0; 3]));
        });
        let reset = Reset;
        let result = run();
        let count = PROBE.with(|probe| probe.replace(None).unwrap());
        drop(reset);
        assert_eq!(count, [0; 3], "native alloc/alloc_zeroed/realloc");
        result
    }
}

/// Inspect only whether the calling thread is in an actual resident page-read
/// scope. For allocator instrumentation; this is not an admission capability.
pub fn resident_scope_active() -> bool {
    BUDGET.try_with(|budget| budget.get().is_some()).unwrap_or(false)
}
