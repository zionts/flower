//! Standalone native tests without changing the parent's module list or Cargo.
//! Run run-tests.sh from the repository root; dependencies use existing rlibs.
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
fn no_rust_allocations_after_admission_success_or_failure() {
    use evaluator::sql_bridge::WireError;
    use evaluator::wire::ARRAY;
    use serde_json::json;
    let input = evaluator::wire::encode(
        &json!({"𐀀": [{"common": "é😀"}, {"common": "\u{0}"}], "\u{e000}": [false, 1.5]}),
    )
    .unwrap();
    let mut arena =
        evaluator::sql_bridge::WireArena::new(evaluator::sql_bridge::WireLimits::default())
            .unwrap();
    let retained = arena.allocation_bytes();
    let (result, allocations) = crate::allocation_count(|| -> Result<(), WireError> {
        let id = arena.decode(&input)?;
        arena.encode(id)?;
        arena.json(id)?;
        arena.reset()?;
        let root = arena.object()?;
        let child = arena.text("new 😀")?;
        arena.insert(root, "a", child)?;
        let n = arena.real(4.25)?;
        arena.insert(root, "b", n)?;
        arena.encode(root)?;
        arena.json(root)?;
        arena.reset()?;
        if arena.decode(&[ARRAY, 255, 255, 255, 255]).is_ok() {
            return Err(WireError::Invalid("bad accepted"));
        }
        arena.reset()?;
        let root = arena.text("\0\0\0\0")?;
        arena.json(root)?;
        Ok(())
    });
    assert!(result.is_ok());
    assert_eq!(allocations, 0);
    assert_eq!(arena.allocation_bytes(), retained);
}

#[test]
fn rejection_paths_never_allocate_after_admission() {
    use evaluator::sql_bridge::{WireArena, WireError, WireLimits};
    let mut output = WireArena::new(WireLimits {
        output_bytes: 5,
        ..WireLimits::default()
    })
    .unwrap();
    let mut nodes = WireArena::new(WireLimits {
        nodes: 1,
        ..WireLimits::default()
    })
    .unwrap();
    let mut work = WireArena::new(WireLimits {
        job_work: 2,
        ..WireLimits::default()
    })
    .unwrap();
    let mut cancel = WireArena::new(WireLimits::default()).unwrap();
    let (result, count) = allocation_count(|| -> Result<(), WireError> {
        let root = output.text("output longer than five")?;
        if output.encode(root) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("output quota"));
        }
        output.reset()?;
        let root = output.text("\0")?;
        if output.json(root) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("JSON quota"));
        }
        if nodes.decode(&[8, 1, 0, 0, 0, 0]) != Err(WireError::Capacity) {
            return Err(WireError::Invalid("node quota"));
        }
        let root = work.decode(&[0])?;
        if work.encode(root) != Err(WireError::WorkLimit) {
            return Err(WireError::Invalid("work quota"));
        }
        if cancel.decode_checked(&[0], &mut || Err(WireError::Cancelled))
            != Err(WireError::Cancelled)
        {
            return Err(WireError::Invalid("cancel quota"));
        }
        Ok(())
    });
    assert!(result.is_ok());
    assert_eq!(count, 0);
}
