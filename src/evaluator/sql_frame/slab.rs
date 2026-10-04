//! Exact finite mappings for capture; exact-capacity native ABI output buffers.
//!
//! Anonymous capture maps and prepared shared typed memfd maps avoid Rust
//! allocator rounding/metadata for arena slabs. The
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

/// # Safety
/// Every bit pattern is a valid T; repr(C) with no implicit padding or pointers,
/// and all bytes are initialized. Only typed ABI PODs implement this trait.
pub(super) unsafe trait MappedPod: Copy {}
unsafe impl MappedPod for u8 {}
unsafe impl MappedPod for u32 {}

pub(super) struct Slab<T: Copy> {
    data: NonNull<T>,
    len: usize,
    bytes: usize,
    writable: bool,
    #[cfg(target_os = "linux")]
    file: Option<super::transport::FrameFile>,
    #[cfg(test)]
    mapping_id: u64,
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
                writable: true,
                #[cfg(target_os = "linux")]
                file: None,
                #[cfg(test)]
                mapping_id: 0,
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
            if unsafe { libc::munmap(mapped, bytes) } != 0 {
                std::process::abort();
            }
            return Err(FrameError::Capacity);
        };
        let slab = Self {
            data,
            len,
            bytes,
            writable: true,
            #[cfg(target_os = "linux")]
            file: None,
            #[cfg(test)]
            mapping_id: super::mapping_tests::next_id(),
        };
        slab.initialize(control)?;
        Ok(slab)
    }
    fn initialize(&self, control: &FrameControl<'_>) -> Result<(), FrameError> {
        // Pre-touch all pages AND tail bytes, then create valid native elements.
        for offset in 0..self.bytes {
            if offset.is_multiple_of(super::MAX_CAPTURE_SLICE) {
                control.check()?;
            }
            unsafe {
                self.data
                    .as_ptr()
                    .cast::<u8>()
                    .add(offset)
                    .write_volatile(0)
            };
        }
        let quantum = (super::MAX_CAPTURE_SLICE / size_of::<T>()).max(1);
        for offset in 0..self.len {
            if offset.is_multiple_of(quantum) {
                control.check()?;
            }
            unsafe { self.data.as_ptr().add(offset).write(T::default()) };
        }
        Ok(())
    }
    pub(super) fn new_typed(
        len: usize,
        control: &FrameControl<'_>,
        transport: bool,
    ) -> Result<Self, FrameError>
    where
        T: MappedPod,
    {
        if !transport {
            return Self::new(len, control);
        }
        #[cfg(target_os = "linux")]
        {
            control.check()?;
            let bytes = mapped_bytes::<T>(len)?;
            let file = super::transport::FrameFile::create(bytes)?;
            let mut slab = Self::map_file(file, len, true, control)?;
            slab.initialize(control)?;
            // Keep explicit mutability at the owning constructor, never adopted RO.
            slab.writable = true;
            Ok(slab)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(FrameError::Unsupported)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn new(_len: usize, _control: &FrameControl<'_>) -> Result<Self, FrameError> {
        Err(FrameError::Unsupported)
    }
}
impl<T: Copy> Slab<T> {
    #[cfg(target_os = "linux")]
    pub(super) fn map_file(
        file: super::transport::FrameFile,
        len: usize,
        writable: bool,
        control: &FrameControl<'_>,
    ) -> Result<Self, FrameError>
    where
        T: MappedPod,
    {
        control.check()?;
        let bytes = mapped_bytes::<T>(len)?;
        let data = if bytes == 0 {
            NonNull::dangling()
        } else {
            let mapped = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    bytes,
                    libc::PROT_READ | if writable { libc::PROT_WRITE } else { 0 },
                    libc::MAP_SHARED,
                    file.as_raw_fd(),
                    0,
                )
            };
            if mapped == libc::MAP_FAILED {
                return Err(FrameError::Capacity);
            }
            let Some(data) = NonNull::new(mapped.cast::<T>()) else {
                if unsafe { libc::munmap(mapped, bytes) } != 0 {
                    std::process::abort();
                }
                return Err(FrameError::Capacity);
            };
            data
        };
        Ok(Self {
            data,
            len,
            bytes,
            writable,
            file: Some(file),
            #[cfg(test)]
            mapping_id: if bytes == 0 {
                0
            } else {
                super::mapping_tests::next_id()
            },
        })
    }
    #[cfg(target_os = "linux")]
    pub(super) fn into_unmapped_file(
        mut self,
        budget: &super::control::Budget,
        control: &FrameControl<'_>,
    ) -> Result<super::transport::FrameFile, FrameError> {
        budget.debit(1, control)?;
        if !self.writable || self.file.is_none() {
            return Err(FrameError::Invalid);
        }
        self.unmap(); // ACTUAL owning RW mapping is gone, not merely a borrow.
        self.len = 0;
        self.bytes = 0;
        self.writable = false;
        let file = self.file.take().ok_or(FrameError::Invalid)?;
        Ok(file)
    }
    fn unmap(&self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.bytes != 0 {
            let result = unsafe { libc::munmap(self.data.as_ptr().cast(), self.bytes) };
            #[cfg(test)]
            super::mapping_tests::released(self.region(), result);
            // Continuing unwinding would drop/refund the strong preparation
            // lease while its map might still exist. Fail-stop before that.
            if result != 0 {
                std::process::abort();
            }
        }
    }
    pub(super) fn mapped_bytes(&self) -> usize {
        self.bytes
    }
    #[cfg(test)]
    pub(super) fn region(&self) -> super::mapping_tests::Region {
        super::mapping_tests::Region {
            id: self.mapping_id,
            address: self.data.as_ptr() as usize,
            bytes: self.bytes,
        }
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
        assert!(self.writable, "immutable frame mapping");
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }
}
impl<T: Copy> Drop for Slab<T> {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        if self.writable && self.file.is_some() {
            // Before sealing a failed/prepared owner can really overwrite its
            // writable backing. Immutable RO files cannot honestly be wiped.
            for offset in 0..self.bytes {
                unsafe {
                    self.data
                        .as_ptr()
                        .cast::<u8>()
                        .add(offset)
                        .write_volatile(0)
                };
            }
        }
        self.unmap();
        // file is closed after this map is gone; wrappers drop the lease LAST.
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
