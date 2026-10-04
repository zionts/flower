//! Capture instrumentation filters the ONE crate test allocator by REAL scope.
pub(crate) use crate::allocation_probe::Counts;
pub(crate) fn run<T>(operation: impl FnOnce() -> T) -> (T, Counts) {
    crate::allocation_probe::run_filtered(operation, redb::resident_scope_active)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout};
    #[test]
    fn allocation_probe_positive_control_counts_all_native_heap_operations_only_in_real_scope() {
        let ((), counts) = run(|| {
            redb::with_resident_reads(1, || unsafe {
                let layout = Layout::from_size_align(32, 8).unwrap();
                let ptr = crate::allocation_probe::Allocator.alloc(layout);
                assert!(!ptr.is_null());
                let ptr = crate::allocation_probe::Allocator.realloc(ptr, layout, 64);
                assert!(!ptr.is_null());
                crate::allocation_probe::Allocator
                    .dealloc(ptr, Layout::from_size_align(64, 8).unwrap());
                let ptr = crate::allocation_probe::Allocator.alloc_zeroed(layout);
                assert!(!ptr.is_null());
                crate::allocation_probe::Allocator.dealloc(ptr, layout);
            })
        });
        assert_eq!(
            counts,
            Counts {
                alloc: 1,
                zeroed: 1,
                realloc: 1,
                bytes: 128
            }
        );
        let (_, counts) = run(|| std::hint::black_box(vec![0u8; 128]));
        assert_eq!(counts, Counts::default());
    }
}
