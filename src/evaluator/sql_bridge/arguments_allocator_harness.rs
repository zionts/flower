//! Standalone concatenated-argument allocation observer after arena admission.
//! Run run-arguments-tests.sh; dependencies use the parent's existing rlibs.
#![allow(dead_code)]
#[path = "../sql_bridge.rs"]
pub(crate) mod sql_bridge;
#[allow(clippy::chunks_exact_to_as_chunks)] // Reference module is parent-owned.
#[path = "../wire.rs"]
pub(crate) mod wire;
mod evaluator {
    pub(crate) use crate::{sql_bridge, wire};
}

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
thread_local! { static COUNTING: Cell<bool> = const { Cell::new(false) }; static ALLOCATIONS: Cell<usize> = const { Cell::new(0) }; }
struct Tracking;
unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|c| {
            if c.get() {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
        });
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        COUNTING.with(|c| {
            if c.get() {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
        });
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        COUNTING.with(|c| {
            if c.get() {
                ALLOCATIONS.with(|a| a.set(a.get() + 1));
            }
        });
        unsafe { System.realloc(ptr, layout, size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: Tracking = Tracking;
fn allocation_count<T>(f: impl FnOnce() -> T) -> (T, usize) {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            COUNTING.with(|c| c.set(false));
        }
    }
    ALLOCATIONS.with(|a| a.set(0));
    COUNTING.with(|c| c.set(true));
    let guard = Guard;
    let result = f();
    drop(guard);
    (result, ALLOCATIONS.with(Cell::get))
}

#[test]
fn concatenated_arguments_never_allocate_after_admission() {
    use evaluator::sql_bridge::{WireArena, WireError, WireLimits};
    use evaluator::wire::{KEY, LATIN1, MAP, NULL};
    let input = [
        MAP, 1, 0, 0, 0, LATIN1, 1, 0, 0, 0, b'x', NULL, MAP, 1, 0, 0, 0, KEY, 0, 0, 0, 0, NULL,
    ];
    let mut arena = WireArena::new(WireLimits::default()).unwrap();
    let mut short = WireArena::new(WireLimits {
        nodes: 1,
        ..WireLimits::default()
    })
    .unwrap();
    let mut capped = WireArena::new(WireLimits {
        message_bytes: 1,
        ..WireLimits::default()
    })
    .unwrap();
    let mut work = WireArena::new(WireLimits {
        job_work: 1,
        ..WireLimits::default()
    })
    .unwrap();
    let before = arena.work_remaining();
    let retained = arena.allocation_bytes();
    let (result, count) = allocation_count(|| -> Result<(), WireError> {
        let root = arena.decode_arguments_checked(&input, &mut || Ok(()))?;
        arena.encode_checked(root, &mut || Ok(()))?;
        arena.json_checked(root, &mut || Ok(()))?;
        arena.reset_checked(&mut || Ok(()))?;
        let root = arena.decode_arguments(&[])?;
        if arena.value(root)?.len() != Some(0) {
            return Err(WireError::Invalid("empty arguments"));
        }
        arena.reset()?;
        if arena.decode_arguments(&[NULL; 9]) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("arity quota"));
        }
        arena.reset()?;
        if arena.decode_arguments(&input[12..]) != Err(WireError::Invalid("unknown key reference"))
        {
            return Err(WireError::Invalid("key table survived reset"));
        }
        arena.reset()?;
        if arena.decode_arguments_checked(&input, &mut || Err(WireError::Cancelled))
            != Err(WireError::Cancelled)
        {
            return Err(WireError::Invalid("cancel quota"));
        }
        if short.decode_arguments(&[NULL]) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("node quota"));
        }
        if capped.decode_arguments(&input) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("message quota"));
        }
        if work.decode_arguments(&[NULL]) != Err(WireError::WorkLimit) {
            return Err(WireError::Invalid("work quota"));
        }
        Ok(())
    });
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(count, 0, "arguments decoder called the Rust allocator");
    assert_eq!(arena.allocation_bytes(), retained);
    assert!(
        arena.work_remaining() < before,
        "resets replenished job work"
    );
}
