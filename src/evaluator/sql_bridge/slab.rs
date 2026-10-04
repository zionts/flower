//! Exact page-rounded Unix mappings. Admission is done by WireArena first.
use super::WireError;
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

pub(super) fn page_size() -> Result<usize, WireError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if page > 0 && (page as usize).is_power_of_two() {
            return Ok(page as usize);
        }
    }
    Err(WireError::Unsupported)
}
pub(super) fn mapped_bytes<T>(len: usize, page: usize) -> Result<usize, WireError> {
    if size_of::<T>() == 0 || align_of::<T>() > page {
        return Err(WireError::Unsupported);
    }
    if len == 0 {
        return Ok(0);
    }
    let size = len.checked_mul(size_of::<T>()).ok_or(WireError::Capacity)?;
    size.checked_add(page - 1)
        .map(|n| n / page * page)
        .ok_or(WireError::Capacity)
}
pub(super) struct Slab<T: Copy> {
    pointer: NonNull<T>,
    len: usize,
    bytes: usize,
}
impl<T: Copy + Default> Slab<T> {
    pub(super) fn new(len: usize, page: usize) -> Result<Self, WireError> {
        let bytes = mapped_bytes::<T>(len, page)?;
        if bytes == 0 {
            return Ok(Self {
                pointer: NonNull::dangling(),
                len,
                bytes,
            });
        }
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
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
                return Err(WireError::Capacity);
            }
            let Some(pointer) = NonNull::new(mapped.cast::<T>()) else {
                unsafe { libc::munmap(mapped, bytes) };
                return Err(WireError::Capacity);
            };
            // Force backing of every mapped page including tail padding before
            // admitting input. OS/PTE/physical retention proof remains HOLD.
            for offset in 0..bytes {
                unsafe { pointer.as_ptr().cast::<u8>().add(offset).write_volatile(0) };
            }
            for offset in 0..len {
                unsafe { pointer.as_ptr().add(offset).write(T::default()) };
            }
            Ok(Self {
                pointer,
                len,
                bytes,
            })
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        Err(WireError::Unsupported)
    }
}
impl<T: Copy> Deref for Slab<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.len) }
    }
}
impl<T: Copy> DerefMut for Slab<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) }
    }
}
impl<T: Copy> Drop for Slab<T> {
    fn drop(&mut self) {
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if self.bytes != 0 {
            unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) };
        }
    }
}
unsafe impl<T: Copy + Send> Send for Slab<T> {}
unsafe impl<T: Copy + Sync> Sync for Slab<T> {}
