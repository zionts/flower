//! Exactly page-rounded pre-touched mappings; mandatory locked byte storage.
//! This accounts user mappings, not kernel page tables or allocator/stack state.
use super::{Control, Error, SlotTicket, profile::MappingLease};
use std::ops::{Deref, DerefMut};
use std::ptr::NonNull;
use zeroize::Zeroize;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) fn page_size() -> Result<usize, Error> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || !(page as usize).is_power_of_two() {
        return Err(Error::Unsupported);
    }
    Ok(page as usize)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn page_size() -> Result<usize, Error> {
    Err(Error::Unsupported)
}
pub(super) fn mapped_bytes(len: usize) -> Result<usize, Error> {
    let page = page_size()?;
    len.checked_add(page - 1)
        .map(|len| len / page * page)
        .ok_or(Error::Capacity)
}
pub(super) struct Slab {
    pointer: NonNull<u8>,
    len: usize,
    bytes: usize,
    locked: bool,
    lease: Option<MappingLease>,
    #[cfg(test)]
    id: u64,
}
impl Slab {
    #[cfg(test)]
    pub(super) fn is_erased(&self) -> bool {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.bytes) }
            .iter()
            .all(|byte| *byte == 0)
    }
    #[cfg(test)]
    pub(super) fn is_locked(&self) -> bool {
        self.locked
    }
    #[cfg(test)]
    pub(super) fn new(len: usize, lock: bool, control: &Control<'_>) -> Result<Self, Error> {
        if !lock {
            return Err(Error::Unsupported);
        }
        Self::allocate(len, None, control)
    }
    pub(super) fn new_ticket(
        len: usize,
        ticket: &SlotTicket,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        Self::allocate(len, Some(ticket), control)
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub(super) fn allocate(
        len: usize,
        ticket: Option<&SlotTicket>,
        control: &Control<'_>,
    ) -> Result<Self, Error> {
        control.check()?;
        if let Some(ticket) = ticket {
            ticket.check_control(control)?;
        }
        let bytes = mapped_bytes(len)?;
        if bytes == 0 {
            return Err(Error::Capacity);
        }
        let mut lease = ticket.map(SlotTicket::mapping);
        #[cfg(test)]
        observer::mapping_attempt();
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
            return Err(Error::Capacity);
        }
        if let Some(lease) = lease.as_mut() {
            lease.mapped();
        }
        let Some(pointer) = NonNull::new(mapped.cast::<u8>()) else {
            if unsafe { libc::munmap(mapped, bytes) } == 0
                && let Some(lease) = lease.as_mut()
            {
                lease.unmapped();
            }
            return Err(Error::Capacity);
        };
        let mut slab = Self {
            pointer,
            len,
            bytes,
            locked: false,
            lease,
            #[cfg(test)]
            id: observer::next_id(),
        };
        {
            // No pageable-secret fallback. Locking happens before captured input.
            if unsafe { libc::mlock(mapped, bytes) } != 0 {
                return Err(Error::Capacity);
            }
            slab.locked = true;
            #[cfg(target_os = "linux")]
            if unsafe { libc::madvise(mapped, bytes, libc::MADV_DONTDUMP) } != 0 {
                return Err(Error::Unsupported);
            }
        }
        for i in 0..bytes {
            if i.is_multiple_of(1024) {
                control.debit((bytes - i).min(1024))?;
            }
            unsafe { pointer.as_ptr().add(i).write_volatile(0) };
        }
        control.check()?;
        Ok(slab)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub(super) fn allocate(
        _len: usize,
        _ticket: Option<&SlotTicket>,
        _control: &Control<'_>,
    ) -> Result<Self, Error> {
        Err(Error::Unsupported)
    }
}
impl Deref for Slab {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.pointer.as_ptr(), self.len) }
    }
}
impl DerefMut for Slab {
    fn deref_mut(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.len) }
    }
}
impl Zeroize for Slab {
    fn zeroize(&mut self) {
        // Erase every rounded byte, not only the exposed logical length.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.bytes) }.zeroize();
    }
}
impl Drop for Slab {
    fn drop(&mut self) {
        self.zeroize();
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            // munmap automatically releases the OS lock. Do NOT munlock first:
            // a failed unmap must retain a locked, erased owner and its credit.
            #[cfg(test)]
            let erased = self.is_erased();
            #[cfg(test)]
            let result = if observer::fail_unmap() {
                unsafe { libc::munmap(self.pointer.as_ptr().add(1).cast(), self.bytes) }
            } else {
                unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) }
            };
            #[cfg(not(test))]
            let result = unsafe { libc::munmap(self.pointer.as_ptr().cast(), self.bytes) };
            #[cfg(test)]
            observer::released(observer::Release {
                id: self.id,
                address: self.pointer.as_ptr() as usize,
                bytes: self.bytes,
                erased,
                result,
            });
            if result == 0
                && let Some(lease) = self.lease.as_mut()
            {
                lease.unmapped();
            }
            // A still-mapped lease Drop permanently holds slot+strong owner.
        }
    }
}
unsafe impl Send for Slab {}
// Not Sync: workspace/private-material state remains owned by one operation.

#[cfg(test)]
#[path = "mapping_observer.rs"]
pub(super) mod observer;
