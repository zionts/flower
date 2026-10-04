#![allow(dead_code, unexpected_cfgs, unused_imports)]
#[path = "../sql_frame.rs"]
mod sql_frame;
#[path = "../sqlite/mod.rs"]
mod sqlite;

// Independent harness only: counting allocator proves no Rust heap allocation
// after frame pre-touch for capture/scanner/insertion/sealing and records ABI
// output allocation Layout bytes. TLS selection avoids other test threads.
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
            ACTIVE.with(|active| {
                if active.get() {
                    COUNT.with(|count| count.set(count.get() + 1));
                    BYTES.with(|bytes| bytes.set(bytes.get() + layout.size()));
                }
            });
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            ACTIVE.with(|active| {
                if active.get() {
                    COUNT.with(|count| count.set(count.get() + 1));
                    BYTES.with(|bytes| bytes.set(bytes.get() + layout.size()));
                }
            });
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, pointer: *mut u8, old: Layout, new: usize) -> *mut u8 {
            ACTIVE.with(|active| {
                if active.get() {
                    COUNT.with(|count| count.set(count.get() + 1));
                    BYTES.with(|bytes| bytes.set(bytes.get() + new));
                }
            });
            unsafe { System.realloc(pointer, old, new) }
        }
        unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
            unsafe { System.dealloc(pointer, layout) }
        }
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

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod allocation_tests;
