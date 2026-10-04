//! Test-only System allocator evidence. Never used by production or binaries.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Counts {
    pub alloc: usize,
    pub zeroed: usize,
    pub realloc: usize,
    pub bytes: usize,
}
#[derive(Clone, Copy)]
struct State {
    counts: Counts,
    enabled: fn() -> bool,
}
thread_local! {static PROBE:Cell<Option<State>>=const {Cell::new(None)};}
pub(crate) struct Allocator;
fn record(kind: u8, bytes: usize) {
    // Neither inspection nor Cell updates allocate, borrow recursively, lock,
    // panic during TLS teardown, format, or call the tested allocator again.
    let _ = PROBE.try_with(|probe| {
        if let Some(mut state) = probe.get() {
            if !(state.enabled)() {
                return;
            }
            let counts = &mut state.counts;
            match kind {
                0 => counts.alloc = counts.alloc.saturating_add(1),
                1 => counts.zeroed = counts.zeroed.saturating_add(1),
                _ => counts.realloc = counts.realloc.saturating_add(1),
            }
            counts.bytes = counts.bytes.saturating_add(bytes);
            probe.set(Some(state));
        }
    });
}
unsafe impl GlobalAlloc for Allocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(0, layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(1, layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(2, new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
pub(crate) fn run_filtered<T>(operation: impl FnOnce() -> T, enabled: fn() -> bool) -> (T, Counts) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            let _ = PROBE.try_with(|probe| probe.set(None));
        }
    }
    PROBE.with(|probe| {
        assert!(probe.get().is_none());
        probe.set(Some(State {
            counts: Counts::default(),
            enabled,
        }));
    });
    let reset = Reset;
    let result = operation();
    let counts = PROBE.with(|probe| probe.get().unwrap().counts);
    drop(reset);
    (result, counts)
}

/// Explicit TLS guard used by test-only crypto/runtime allocator probes. No
/// production limit or interception; returns allocation operations/request bytes.
pub(crate) fn measure<T>(operation: impl FnOnce() -> T) -> (T, usize, usize) {
    let (result, counts) = run_filtered(operation, || true);
    (
        result,
        counts
            .alloc
            .saturating_add(counts.zeroed)
            .saturating_add(counts.realloc),
        counts.bytes,
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocation_probe_general_positive_control_and_unwind_reset() {
        let (_, count, bytes) = measure(|| unsafe {
            let layout = Layout::from_size_align(32, 8).unwrap();
            let ptr = Allocator.alloc(layout);
            assert!(!ptr.is_null());
            let ptr = Allocator.realloc(ptr, layout, 64);
            assert!(!ptr.is_null());
            Allocator.dealloc(ptr, Layout::from_size_align(64, 8).unwrap());
            let ptr = Allocator.alloc_zeroed(layout);
            assert!(!ptr.is_null());
            Allocator.dealloc(ptr, layout);
        });
        assert_eq!((count, bytes), (3, 128));
        let (_, counts) = run_filtered(|| std::hint::black_box(vec![0u8; 128]), || false);
        assert_eq!(counts, Counts::default());
        let _ = std::panic::catch_unwind(|| measure(|| panic!("expected test guard unwind")));
        assert_eq!(measure(|| ()).1, 0);
    }
}
