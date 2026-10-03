//! One-time fail-closed SQLite initialization and a VFS with no filesystem,
//! dynamic-library, clock or entropy access. Never call sqlite3_shutdown: another
//! subsystem may retain SQLite pointers, and the allocator must remain installed.
use std::cell::UnsafeCell;
use std::ffi::{c_char, c_int, c_void};
use std::ptr;
use std::sync::OnceLock;

use libsqlite3_sys as ffi;

use super::SqlError;
use super::allocator::{self, Quota, Scope};

pub(super) const VFS_NAME: &std::ffi::CStr = c"flower_bounded_sql_memory";
const INIT_BYTES: usize = 1024 * 1024;
static INITIALIZED: OnceLock<Result<(), SqlError>> = OnceLock::new();

// sqlite3_vfs_register mutates pNext under SQLite's own mutex. All other fields
// are set once, before registration; the object has process lifetime.
struct StaticVfs(UnsafeCell<ffi::sqlite3_vfs>);
unsafe impl Sync for StaticVfs {}
static VFS: StaticVfs = StaticVfs(UnsafeCell::new(unsafe { std::mem::zeroed() }));

pub(super) fn initialize() -> Result<(), SqlError> {
    *INITIALIZED.get_or_init(|| {
        let quota = Quota::new(INIT_BYTES);
        let _scope = Scope::enter(quota.clone()).ok_or(SqlError::Unavailable)?;
        // SQL_CONFIG_MALLOC returns MISUSE if SQLite was initialized elsewhere.
        // Do not shut it down to bypass this safety gate.
        unsafe {
            let methods = allocator::methods();
            if ffi::sqlite3_config(ffi::SQLITE_CONFIG_MALLOC, &methods) != ffi::SQLITE_OK
                || ffi::sqlite3_config(ffi::SQLITE_CONFIG_SERIALIZED) != ffi::SQLITE_OK
                || ffi::sqlite3_config(ffi::SQLITE_CONFIG_MEMSTATUS, 0 as c_int) != ffi::SQLITE_OK
                || ffi::sqlite3_config(ffi::SQLITE_CONFIG_LOOKASIDE, 0 as c_int, 0 as c_int)
                    != ffi::SQLITE_OK
                || ffi::sqlite3_initialize() != ffi::SQLITE_OK
            {
                return Err(SqlError::Unavailable);
            }
            let vfs = VFS.0.get();
            *vfs = ffi::sqlite3_vfs {
                iVersion: 2,
                szOsFile: size_of::<ffi::sqlite3_file>() as c_int,
                mxPathname: 1024,
                zName: VFS_NAME.as_ptr(),
                xOpen: Some(open),
                xDelete: Some(delete),
                xAccess: Some(access),
                xFullPathname: Some(full_path),
                xDlOpen: Some(dl_open),
                xDlError: Some(dl_error),
                xDlSym: None,
                xDlClose: Some(dl_close),
                xRandomness: Some(randomness),
                xSleep: Some(sleep),
                xCurrentTime: Some(time),
                xGetLastError: Some(last_error),
                xCurrentTimeInt64: Some(time64),
                ..std::mem::zeroed()
            };
            // Default too: SQLite's global PRNG must not fall back to the OS VFS.
            if ffi::sqlite3_vfs_register(vfs, 1) != ffi::SQLITE_OK || quota.failed() {
                return Err(SqlError::Unavailable);
            }
        }
        Ok(())
    })
}

#[cfg(test)]
static OPEN_ATTEMPTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
pub(super) fn open_attempts() -> usize {
    OPEN_ATTEMPTS.load(std::sync::atomic::Ordering::Relaxed)
}

unsafe extern "C" fn open(
    _: *mut ffi::sqlite3_vfs,
    _: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    _: c_int,
    _: *mut c_int,
) -> c_int {
    #[cfg(test)]
    OPEN_ATTEMPTS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if !file.is_null() {
        unsafe { (*file).pMethods = ptr::null() };
    }
    ffi::SQLITE_CANTOPEN
}
unsafe extern "C" fn delete(_: *mut ffi::sqlite3_vfs, _: *const c_char, _: c_int) -> c_int {
    ffi::SQLITE_IOERR_DELETE
}
unsafe extern "C" fn access(
    _: *mut ffi::sqlite3_vfs,
    _: *const c_char,
    _: c_int,
    out: *mut c_int,
) -> c_int {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn full_path(
    _: *mut ffi::sqlite3_vfs,
    _: *const c_char,
    size: c_int,
    out: *mut c_char,
) -> c_int {
    if size > 0 && !out.is_null() {
        unsafe { *out = 0 };
    }
    ffi::SQLITE_CANTOPEN
}
unsafe extern "C" fn dl_open(_: *mut ffi::sqlite3_vfs, _: *const c_char) -> *mut c_void {
    ptr::null_mut()
}
unsafe extern "C" fn dl_error(_: *mut ffi::sqlite3_vfs, size: c_int, out: *mut c_char) {
    if size > 0 && !out.is_null() {
        unsafe { *out = 0 };
    }
}
unsafe extern "C" fn dl_close(_: *mut ffi::sqlite3_vfs, _: *mut c_void) {}
unsafe extern "C" fn randomness(_: *mut ffi::sqlite3_vfs, size: c_int, out: *mut c_char) -> c_int {
    if size > 0 && !out.is_null() {
        unsafe { ptr::write_bytes(out, 0, size as usize) };
    }
    0
}
unsafe extern "C" fn sleep(_: *mut ffi::sqlite3_vfs, _: c_int) -> c_int {
    0
}
unsafe extern "C" fn time(_: *mut ffi::sqlite3_vfs, out: *mut f64) -> c_int {
    if !out.is_null() {
        unsafe { *out = 0.0 };
    }
    ffi::SQLITE_ERROR
}
unsafe extern "C" fn time64(_: *mut ffi::sqlite3_vfs, out: *mut ffi::sqlite3_int64) -> c_int {
    if !out.is_null() {
        unsafe { *out = 0 };
    }
    ffi::SQLITE_ERROR
}
unsafe extern "C" fn last_error(_: *mut ffi::sqlite3_vfs, size: c_int, out: *mut c_char) -> c_int {
    if size > 0 && !out.is_null() {
        unsafe { *out = 0 };
    }
    0
}
