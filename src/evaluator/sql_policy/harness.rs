#![allow(dead_code, unexpected_cfgs, unused_imports)]
//! Independent test entry only; does not wire policy into Flower serving.
#[path = "../sql_control.rs"]
mod sql_control;
#[path = "../sql_frame.rs"]
mod sql_frame;
#[path = "../sql_policy.rs"]
mod sql_policy;
#[path = "../sqlite/mod.rs"]
mod sqlite;
#[cfg(test)]
mod reference {
    include!(concat!(env!("OUT_DIR"), "/ordinary_access.rs"));
}
#[cfg(test)]
mod allocation_probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! {
        static ACTIVE: Cell<bool> = const { Cell::new(false) };
        static COUNT: Cell<usize> = const { Cell::new(0) };
        static BYTES: Cell<usize> = const { Cell::new(0) };
    }
    pub struct Probe;
    unsafe impl GlobalAlloc for Probe {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            note(layout.size());
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new: usize) -> *mut u8 {
            note(new);
            unsafe { System.realloc(pointer, old, new) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) }
        }
    }
    fn note(bytes: usize) {
        ACTIVE.with(|active| {
            if active.get() {
                COUNT.with(|count| count.set(count.get() + 1));
                BYTES.with(|count| count.set(count.get() + bytes));
            }
        });
    }
    #[global_allocator]
    static ALLOCATOR: Probe = Probe;
    pub fn measure<T>(function: impl FnOnce() -> T) -> (T, usize, usize) {
        COUNT.with(|count| count.set(0));
        BYTES.with(|bytes| bytes.set(0));
        ACTIVE.with(|active| assert!(!active.replace(true)));
        let result = function();
        ACTIVE.with(|active| active.set(false));
        (result, COUNT.with(Cell::get), BYTES.with(Cell::get))
    }
}
