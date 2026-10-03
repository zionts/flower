//! All SQLite allocations carry the quota that originally paid for them.
//!
//! SQLite can free an allocation after its allocating TLS scope has disappeared or
//! on another thread. Neither free nor realloc is allowed to infer its owner from
//! the current thread. The header (including alignment/payload overhead) is charged
//! before the system allocator is called. No process-wide heap limit is used.
use std::alloc::{Layout, alloc, dealloc, realloc};
use std::cell::RefCell;
use std::ffi::{c_int, c_void};
use std::ptr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use libsqlite3_sys as ffi;

#[derive(Debug)]
pub(super) struct Quota {
    limit: usize,
    used: AtomicUsize,
    peak: AtomicUsize,
    failed: AtomicBool,
}

impl Quota {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
            peak: AtomicUsize::new(0),
            failed: AtomicBool::new(false),
        })
    }

    pub(super) fn charge(&self, bytes: usize) -> bool {
        if self.failed() {
            return false;
        }
        let mut used = self.used.load(Ordering::Acquire);
        loop {
            let Some(total) = used.checked_add(bytes).filter(|total| *total <= self.limit) else {
                self.fail();
                return false;
            };
            match self
                .used
                .compare_exchange_weak(used, total, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    self.peak.fetch_max(total, Ordering::Relaxed);
                    return true;
                }
                Err(actual) => used = actual,
            }
        }
    }

    pub(super) fn release(&self, bytes: usize) {
        self.used.fetch_sub(bytes, Ordering::AcqRel);
    }

    pub(super) fn remaining(&self) -> usize {
        self.limit.saturating_sub(self.used.load(Ordering::Acquire))
    }

    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    pub(super) fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    #[cfg(test)]
    pub(super) fn peak(&self) -> usize {
        self.peak.load(Ordering::Acquire)
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Arc<Quota>>> = const { RefCell::new(None) };
}

/// Reentry is rejected: provider/check callbacks cannot silently replace the
/// active query's attribution. Dropping the scope never frees outstanding native
/// allocations; their header Arc still owns the quota.
pub(super) struct Scope(std::marker::PhantomData<std::rc::Rc<()>>);
impl Scope {
    pub(super) fn enter(quota: Arc<Quota>) -> Option<Self> {
        CURRENT
            .try_with(|slot| {
                let mut slot = slot.try_borrow_mut().ok()?;
                if slot.is_some() {
                    return None;
                }
                *slot = Some(quota);
                Some(Self(std::marker::PhantomData))
            })
            .ok()
            .flatten()
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        let _ = CURRENT.try_with(|slot| {
            if let Ok(mut slot) = slot.try_borrow_mut() {
                *slot = None;
            }
        });
    }
}

fn current() -> Option<Arc<Quota>> {
    CURRENT
        .try_with(|slot| slot.try_borrow().ok().and_then(|q| q.clone()))
        .ok()
        .flatten()
}

#[repr(C, align(16))]
struct Header {
    owner: Arc<Quota>,
    size: usize,
}
const HEADER: usize = size_of::<Header>();
const ALIGN: usize = align_of::<Header>();

fn layout(size: usize) -> Option<Layout> {
    Layout::from_size_align(size.checked_add(HEADER)?, ALIGN).ok()
}

unsafe extern "C" fn malloc(size: c_int) -> *mut c_void {
    if size <= 0 {
        return ptr::null_mut();
    }
    let Some(owner) = current() else {
        return ptr::null_mut();
    };
    let size = size as usize;
    let Some(layout) = layout(size) else {
        owner.fail();
        return ptr::null_mut();
    };
    if !owner.charge(layout.size()) {
        return ptr::null_mut();
    }
    // SAFETY: layout has nonzero size and the resulting allocation is aligned for
    // Header and SQLite (at least 8-byte). The payload starts after a full Header.
    let base = unsafe { alloc(layout) };
    if base.is_null() {
        owner.release(layout.size());
        owner.fail();
        return ptr::null_mut();
    }
    unsafe {
        base.cast::<Header>().write(Header { owner, size });
        base.add(HEADER).cast()
    }
}

unsafe extern "C" fn free(data: *mut c_void) {
    if data.is_null() {
        return;
    }
    // SAFETY: SQLite only frees pointers returned by this allocator. Move the
    // Arc out before deallocating; free never consults TLS, including cross-thread.
    unsafe {
        let base = data.cast::<u8>().sub(HEADER);
        let header = base.cast::<Header>().read();
        header.owner.release(HEADER + header.size);
        dealloc(base, layout(header.size).expect("valid allocation layout"));
        drop(header);
    }
}

unsafe extern "C" fn resize(data: *mut c_void, size: c_int) -> *mut c_void {
    if data.is_null() {
        return unsafe { malloc(size) };
    }
    if size <= 0 {
        unsafe { free(data) };
        return ptr::null_mut();
    }
    // No allocations/reallocations outside a bounded initialization/query scope.
    if current().is_none() {
        return ptr::null_mut();
    }
    unsafe {
        let base = data.cast::<u8>().sub(HEADER);
        let header = &*base.cast::<Header>();
        let old_size = header.size;
        let new_size = size as usize;
        let Some(new_layout) = layout(new_size) else {
            header.owner.fail();
            return ptr::null_mut();
        };
        let growth = new_size.saturating_sub(old_size);
        if !header.owner.charge(growth) {
            return ptr::null_mut();
        }
        let next = realloc(
            base,
            layout(old_size).expect("valid allocation layout"),
            new_layout.size(),
        );
        if next.is_null() {
            // Failed realloc leaves the original allocation/header untouched.
            header.owner.release(growth);
            header.owner.fail();
            return ptr::null_mut();
        }
        let header = &mut *next.cast::<Header>();
        header.size = new_size;
        header.owner.release(old_size.saturating_sub(new_size));
        next.add(HEADER).cast()
    }
}

unsafe extern "C" fn allocation_size(data: *mut c_void) -> c_int {
    if data.is_null() {
        return 0;
    }
    unsafe { (*data.cast::<u8>().sub(HEADER).cast::<Header>()).size as c_int }
}

unsafe extern "C" fn roundup(size: c_int) -> c_int {
    if size <= 0 {
        return 0;
    }
    match size.checked_add(15) {
        Some(n) => n & !15,
        None => {
            if let Some(quota) = current() {
                quota.fail();
            }
            0
        }
    }
}
unsafe extern "C" fn init(_: *mut c_void) -> c_int {
    ffi::SQLITE_OK
}
unsafe extern "C" fn shutdown(_: *mut c_void) {}

pub(super) fn methods() -> ffi::sqlite3_mem_methods {
    ffi::sqlite3_mem_methods {
        xMalloc: Some(malloc),
        xFree: Some(free),
        xRealloc: Some(resize),
        xSize: Some(allocation_size),
        xRoundup: Some(roundup),
        xInit: Some(init),
        xShutdown: Some(shutdown),
        pAppData: ptr::null_mut(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_owner_survives_tls_and_cross_thread_free() {
        let quota = Quota::new(4096);
        let pointer;
        {
            let _scope = Scope::enter(quota.clone()).unwrap();
            pointer = unsafe { malloc(128) };
            assert!(!pointer.is_null());
            assert_eq!(quota.used(), HEADER + 128);
        }
        let address = pointer as usize;
        std::thread::spawn(move || unsafe { free(address as *mut c_void) })
            .join()
            .unwrap();
        assert_eq!(quota.used(), 0);
    }

    #[test]
    fn realloc_keeps_original_owner_and_failure_is_sticky() {
        let first = Quota::new(HEADER + 160);
        let second = Quota::new(4096);
        let mut p;
        {
            let _scope = Scope::enter(first.clone()).unwrap();
            p = unsafe { malloc(64) };
        }
        {
            let _scope = Scope::enter(second.clone()).unwrap();
            p = unsafe { resize(p, 128) };
            assert!(!p.is_null());
            assert_eq!(first.used(), HEADER + 128);
            assert_eq!(second.used(), 0);
            assert!(unsafe { resize(p, 256) }.is_null());
            assert!(first.failed());
            assert!(unsafe { resize(p, 144) }.is_null());
        }
        unsafe { free(p) };
        assert_eq!(first.used(), 0);
        assert!(first.peak() <= HEADER + 160);
        assert!(unsafe { malloc(16) }.is_null());
    }
}
