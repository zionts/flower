//! Exact finite native mappings. No heap owner allocation, late growth or RSS
//! estimate. Full volatile pre-touch and full volatile scrub include page tails.
use super::{CHECK_QUANTUM, Check, Error};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
))]
fn page() -> Result<usize, Error> {
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if n <= 0 || !(n as usize).is_power_of_two() {
        return Err(Error::Unsupported);
    }
    Ok(n as usize)
}
#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64"
)))]
fn page() -> Result<usize, Error> {
    Err(Error::Unsupported)
}

pub(super) fn rounded<T>(len: usize) -> Result<usize, Error> {
    let page = page()?;
    if size_of::<T>() == 0 || align_of::<T>() > page {
        return Err(Error::Unsupported);
    }
    let n = size_of::<T>().checked_mul(len).ok_or(Error::Capacity)?;
    n.checked_add(page - 1)
        .map(|n| n / page * page)
        .ok_or(Error::Capacity)
}

pub(super) struct Mapping<T: Copy> {
    data: NonNull<T>,
    len: usize,
    bytes: usize,
}
impl<T: Copy + Default> Mapping<T> {
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    ))]
    pub(super) fn new(len: usize, check: &dyn Check) -> Result<Self, Error> {
        check.check()?;
        let bytes = rounded::<T>(len)?;
        if bytes == 0 {
            return Ok(Self {
                data: NonNull::dangling(),
                len,
                bytes,
            });
        }
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(Error::Capacity);
        }
        let Some(data) = NonNull::new(pointer.cast::<T>()) else {
            unsafe {
                libc::munmap(pointer, bytes);
            }
            return Err(Error::Capacity);
        };
        let mapped = Self { data, len, bytes };
        // Own first: cancellation during initialization unmaps and scrubs through
        // Drop without reading uninitialized descriptors.
        for i in 0..bytes {
            if i.is_multiple_of(CHECK_QUANTUM) {
                check.check()?;
            }
            unsafe {
                pointer.cast::<u8>().add(i).write_volatile(0);
            }
        }
        for i in 0..len {
            if i.is_multiple_of(CHECK_QUANTUM) {
                check.check()?;
            }
            unsafe {
                data.as_ptr().add(i).write(T::default());
            }
        }
        check.check()?;
        Ok(mapped)
    }
    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64"
    )))]
    pub(super) fn new(_: usize, _: &dyn Check) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }
}
impl<T: Copy> Mapping<T> {
    #[cfg(test)]
    pub(super) fn mapped_bytes(&self) -> usize {
        self.bytes
    }
}
impl<T: Copy> Deref for Mapping<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.data.as_ptr(), self.len) }
    }
}
impl<T: Copy> DerefMut for Mapping<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { std::slice::from_raw_parts_mut(self.data.as_ptr(), self.len) }
    }
}
impl<T: Copy> Drop for Mapping<T> {
    fn drop(&mut self) {
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_pointer_width = "64"
        ))]
        if self.bytes != 0 {
            // Never read T (initialization may have stopped). Covers credentials
            // and partial copies, including mapped tails; cannot be elided.
            for i in 0..self.bytes {
                unsafe {
                    self.data.as_ptr().cast::<u8>().add(i).write_volatile(0);
                }
            }
            unsafe {
                libc::munmap(self.data.as_ptr().cast(), self.bytes);
            }
        }
    }
}
unsafe impl<T: Copy + Send> Send for Mapping<T> {}
unsafe impl<T: Copy + Sync> Sync for Mapping<T> {}
