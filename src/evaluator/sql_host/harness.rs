#![allow(dead_code, unexpected_cfgs, unused_imports)]
//! Independent allocation observer; imports the CURRENT actual bridge/frame/ACL
//! and SQLite engine. Does not wire this host into Flower serving or fake ACL.
#[path = "../sql.rs"]
mod sql;
#[path = "../sql_bridge.rs"]
mod sql_bridge;
#[path = "../sql_control.rs"]
mod sql_control;
#[path = "../sql_frame.rs"]
mod sql_frame;
#[path = "../sql_host.rs"]
mod sql_host;
#[path = "../sql_policy.rs"]
mod sql_policy;
#[path = "../sqlite/mod.rs"]
mod sqlite;
#[allow(clippy::chunks_exact_to_as_chunks)] // Parent-owned reference ABI module.
#[path = "../wire.rs"]
mod wire;
mod evaluator {
    pub(crate) use crate::{
        sql, sql_bridge, sql_control, sql_frame, sql_host, sql_policy, sqlite, wire,
    };
}
mod crypto {
    #[path = "/workspace/flower/src/crypto/sql_managed.rs"]
    pub(crate) mod sql_managed;
}
#[cfg(test)]
mod reference {
    include!(concat!(env!("OUT_DIR"), "/ordinary_access.rs"));
}
#[cfg(test)]
mod allocation_probe {
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;
    thread_local! { static ACTIVE: Cell<bool> = const {Cell::new(false)}; static COUNT: Cell<usize> = const {Cell::new(0)}; static BYTES: Cell<usize> = const {Cell::new(0)}; }
    struct Probe;
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
    fn note(size: usize) {
        ACTIVE.with(|active| {
            if active.get() {
                COUNT.with(|c| c.set(c.get() + 1));
                BYTES.with(|c| c.set(c.get() + size));
            }
        });
    }
    #[global_allocator]
    static ALLOCATOR: Probe = Probe;
    pub(crate) fn measure<T>(run: impl FnOnce() -> T) -> (T, usize, usize) {
        struct Guard;
        impl Drop for Guard {
            fn drop(&mut self) {
                ACTIVE.with(|a| a.set(false));
            }
        }
        COUNT.with(|c| c.set(0));
        BYTES.with(|c| c.set(0));
        ACTIVE.with(|a| assert!(!a.replace(true)));
        let guard = Guard;
        let result = run();
        drop(guard);
        (result, COUNT.with(Cell::get), BYTES.with(Cell::get))
    }
}
