//! Exact finite mappings for capture; exact-capacity native ABI output buffers.
//!
//! Anonymous mappings avoid allocator rounding/metadata for arena slabs. The
//! admission pass counts system-page-rounded mappings, not estimates of a JSON
//! Value tree. Every mapped byte is written before captured input is accepted.
//! Output is the existing Vec/String ABI; allocation Layout/capacities are exact
//! and preflighted against the caller's separately reserved native buffer quota.
use std::alloc::{Layout, alloc};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

use super::{FrameControl, FrameError};

pub(super) fn mapped_bytes<T>(len: usize) -> Result<usize, FrameError> {
    if len == 0 {
        return Ok(0);
    }
    if size_of::<T>() == 0 {
        return Err(FrameError::Unsupported);
    }
    let layout = Layout::array::<T>(len).map_err(|_| FrameError::Capacity)?;
    let page = page_size()?;
    if layout.align() > page {
        return Err(FrameError::Unsupported);
    }
    layout
        .size()
        .checked_add(page - 1)
        .map(|bytes| bytes / page * page)
        .ok_or(FrameError::Capacity)
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn page_size() -> Result<usize, FrameError> {
    // sysconf does not allocate a Rust-owned buffer and the result is process
    // constant. No lazy cache/map/mutex is initialized during capture.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || !(page as usize).is_power_of_two() {
        return Err(FrameError::Unsupported);
    }
    Ok(page as usize)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn page_size() -> Result<usize, FrameError> {
    Err(FrameError::Unsupported)
}

pub(super) struct Slab<T: Copy> {
    data: NonNull<T>,
    len: usize,
    bytes: usize,
}
impl<T: Copy + Default> Slab<T> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn new(len: usize, control: &FrameControl<'_>) -> Result<Self, FrameError> {
        control.check()?;
        let bytes = mapped_bytes::<T>(len)?;
        if bytes == 0 {
            return Ok(Self {
                data: NonNull::dangling(),
                len,
                bytes,
            });
        }
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            return Err(FrameError::Capacity);
        }
        let Some(data) = NonNull::new(mapped.cast::<T>()) else {
            // A successful address-zero mapping cannot back a Rust NonNull.
            // Do not leak it on platforms where such a mapping is permitted.
            unsafe { libc::munmap(mapped, bytes) };
            return Err(FrameError::Capacity);
        };
        let slab = Self { data, len, bytes };
        // Own the mapping before initialization, so a cancellation error really
        // unmaps the partially initialized region through Copy-only Drop.
        // Explicit volatile writes force all pages (including padding/tail) to
        // become resident now rather than allocating backing on later capture.
        // No zero bit-pattern assumption is made for enum/descriptor values.
        for offset in 0..bytes {
            if offset.is_multiple_of(super::MAX_CAPTURE_SLICE) {
                control.check()?;
            }
            unsafe { mapped.cast::<u8>().add(offset).write_volatile(0) };
        }
        let quantum = (super::MAX_CAPTURE_SLICE / size_of::<T>()).max(1);
        for offset in 0..len {
            if offset.is_multiple_of(quantum) {
                control.check()?;
            }
            unsafe { data.as_ptr().add(offset).write(T::default()) };
        }
        Ok(slab)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn new(_len: usize, _control: &FrameControl<'_>) -> Result<Self, FrameError> {
        Err(FrameError::Unsupported)
    }
}
impl<T: Copy> Slab<T> {
    pub(super) fn mapped_bytes(&self) -> usize {
        self.bytes
    }
}
impl<T: Copy> Deref for Slab<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        // Mapping initialized completely in new; dangling is allowed for len0.
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}
impl<T: Copy> DerefMut for Slab<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }
}
impl<T: Copy> Drop for Slab<T> {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.bytes != 0 {
            // T:Copy cannot have a destructor. This mapping uniquely belongs to
            // this slab; no borrowed slice can outlive its owner.
            unsafe { libc::munmap(self.data.as_ptr().cast(), self.bytes) };
        }
    }
}
// Exclusive mapping ownership follows the element's normal thread bounds.
unsafe impl<T: Copy + Send> Send for Slab<T> {}
unsafe impl<T: Copy + Sync> Sync for Slab<T> {}

pub(super) fn exact_vec<T>(capacity: usize) -> Result<Vec<T>, FrameError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    if size_of::<T>() == 0 {
        return Err(FrameError::Unsupported);
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| FrameError::Capacity)?;
    let pointer = unsafe { alloc(layout) };
    if pointer.is_null() {
        return Err(FrameError::Capacity);
    }
    // Use the same global allocator and Layout as Vec's destructor. No element
    // is initialized yet. Every caller preflights and pushes <=capacity values.
    Ok(unsafe { Vec::from_raw_parts(pointer.cast::<T>(), 0, capacity) })
}
pub(super) fn exact_string(value: &str) -> Result<String, FrameError> {
    let mut bytes = exact_vec::<u8>(value.len())?;
    bytes.extend_from_slice(value.as_bytes());
    Ok(unsafe { String::from_utf8_unchecked(bytes) })
}
