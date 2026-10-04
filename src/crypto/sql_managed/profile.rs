//! Immutable startup-only node-wide key-lock admission. No key authority.
//! Unsafe startup evidence is an integration attestation, NOT its verifier.
use super::{Admission, Control, Error, NativeAllowance, Workspace};
use std::alloc::{Layout, alloc, dealloc};
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering, fence};

// Never reset after a successful production startup, even when handles die.
static STARTUP: AtomicU8 = AtomicU8::new(0);
const CAS_ATTEMPTS: usize = 64;
const HOLD: usize = 1usize << (usize::BITS - 1);

/// All remaining process locked owners, including their future hard bound.
/// None means unknown and MUST refuse, not a zero default.
pub(crate) struct NodeStartup {
    native_job_ceiling: usize,
    approved_software_bytes: usize,
    approved_locked_bytes: usize,
    other_locked_bytes: usize,
}
impl NodeStartup {
    /// # Safety
    /// The actual node controller must establish BEFORE any key/private input:
    /// * the approved original-job concurrency ceiling and exclusive crypto
    ///   software/locked budgets (NOT borrowed from the public control baseline);
    /// * a complete source audit of ALL other existing/future locked owners;
    /// * startup quiescence, no competing mlock/profile initializer, and use of
    ///   this one profile by every Store/replica/job in the process thereafter.
    ///
    /// This issuer does not perform that audit/approval or authenticate a node.
    pub(crate) unsafe fn from_trusted_node_startup(
        native_job_ceiling: usize,
        approved_software_bytes: usize,
        approved_locked_bytes: usize,
        all_other_locked_owner_bound: Option<usize>,
    ) -> Result<Self, Error> {
        let other_locked_bytes = all_other_locked_owner_bound.ok_or(Error::NativeAdmission)?;
        if native_job_ceiling == 0 || approved_software_bytes == 0 || approved_locked_bytes == 0 {
            return Err(Error::NativeAdmission);
        }
        Ok(Self {
            native_job_ceiling,
            approved_software_bytes,
            approved_locked_bytes,
            other_locked_bytes,
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct LockProfileCaps {
    pub slots: usize,
    /// Capsule locked maps ONLY. Other audited owners are charged separately.
    pub locked_bytes: usize,
    /// Actual profile control allocation/handle plus full per-loan admission.
    pub software_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockProfileLayout {
    pub control_allocation_bytes: usize,
    pub profile_handle_bytes: usize,
    pub global_control_bytes: usize,
    pub control_bytes: usize,
    pub slot_state_bytes: usize,
    pub capsule_locked_bytes: usize,
    pub capsule_software_bytes: usize,
    pub total_locked_bytes: usize,
    pub total_software_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LockProfileStatus {
    pub slots: usize,
    pub active_slots: usize,
    pub held_slots: usize,
    pub charged_software_bytes: usize,
    pub charged_locked_bytes: usize,
    pub soft_memlock_bytes: usize,
    pub hard_memlock_bytes: usize,
    pub startup_vmlck_bytes: usize,
    pub other_locked_bytes: usize,
}
// Exact allocator layout is declared here, rather than guessing Arc internals.
// Allocator metadata/kernel ownership remain additional driver ledger terms.
#[repr(C)]
struct Inner {
    references: AtomicUsize,
    active: AtomicUsize,
    held: AtomicUsize,
    slots: usize,
    slot_offset: usize,
    allocation: Layout,
    layout: LockProfileLayout,
    caps: LockProfileCaps,
    admission: Admission,
    soft: usize,
    hard: usize,
    diagnostic: usize,
    other: usize,
}
#[repr(C)]
struct Slot {
    // 0 free; bit0 ticket; other low bits count mappings in units of2.
    // HOLD is sticky and never returns capacity. One atomic prevents a lost
    // final-map versus final-ticket release race across threads.
    ownership: AtomicUsize,
}
struct Strong(NonNull<Inner>);
impl Strong {
    fn inner(&self) -> &Inner {
        unsafe { self.0.as_ref() }
    }
    fn retain(&self) -> Self {
        // Startup checks the representation bound. Only one profile, one ticket
        // and at most five mapping owners per slot exist; no public Clone.
        self.inner().references.fetch_add(1, Ordering::Relaxed);
        Self(self.0)
    }
    fn slot(&self, index: usize) -> &Slot {
        debug_assert!(index < self.inner().slots);
        unsafe {
            &*self
                .0
                .as_ptr()
                .cast::<u8>()
                .add(self.inner().slot_offset)
                .cast::<Slot>()
                .add(index)
        }
    }
    fn release_active(&self) {
        self.inner().active.fetch_sub(1, Ordering::AcqRel);
    }
    fn status(&self) -> LockProfileStatus {
        let inner = self.inner();
        let active = inner.active.load(Ordering::Acquire);
        LockProfileStatus {
            slots: inner.slots,
            active_slots: active,
            held_slots: inner.held.load(Ordering::Acquire),
            charged_software_bytes: inner.layout.control_bytes + active * inner.admission.bytes(),
            charged_locked_bytes: inner.other + active * inner.admission.pinned_bytes,
            soft_memlock_bytes: inner.soft,
            hard_memlock_bytes: inner.hard,
            startup_vmlck_bytes: inner.diagnostic,
            other_locked_bytes: inner.other,
        }
    }
}
impl Drop for Strong {
    fn drop(&mut self) {
        if self.inner().references.fetch_sub(1, Ordering::Release) == 1 {
            fence(Ordering::Acquire);
            let layout = self.inner().allocation;
            unsafe {
                std::ptr::drop_in_place(self.0.as_ptr());
                dealloc(self.0.as_ptr().cast(), layout);
            }
            #[cfg(test)]
            DESTROYED.fetch_add(1, Ordering::Relaxed);
        }
    }
}
unsafe impl Send for Strong {}
unsafe impl Sync for Strong {}
#[cfg(test)]
pub(super) static DESTROYED: AtomicUsize = AtomicUsize::new(0);

/// Noncloneable strong owner. Parent may share one handle by borrowing it from
/// its node owner. Tickets/mappings retain it across thread/outer-handle drops.
pub(crate) struct NodeLockProfile {
    owner: Strong,
}
impl NodeLockProfile {
    pub(crate) fn required_layout(
        slots: usize,
        native: NativeAllowance,
    ) -> Result<LockProfileLayout, Error> {
        if slots == 0 || slots > (isize::MAX as usize - 1) / 6 {
            return Err(Error::Capacity);
        }
        let admission = Workspace::required_admission(native)?;
        let (allocation, _) = Layout::new::<Inner>()
            .extend(Layout::array::<Slot>(slots).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        let allocation = allocation.pad_to_align();
        let global_control_bytes = size_of::<AtomicU8>() + size_of::<super::AtomicU64>();
        let control_bytes = allocation
            .size()
            .checked_add(size_of::<Self>())
            .and_then(|bytes| bytes.checked_add(global_control_bytes))
            .ok_or(Error::Capacity)?;
        let locked = admission
            .pinned_bytes
            .checked_mul(slots)
            .ok_or(Error::Capacity)?;
        let software = admission
            .bytes()
            .checked_mul(slots)
            .and_then(|bytes| bytes.checked_add(control_bytes))
            .ok_or(Error::Capacity)?;
        Ok(LockProfileLayout {
            control_allocation_bytes: allocation.size(),
            profile_handle_bytes: size_of::<Self>(),
            global_control_bytes,
            control_bytes,
            slot_state_bytes: size_of::<Slot>(),
            capsule_locked_bytes: admission.pinned_bytes,
            capsule_software_bytes: admission.bytes(),
            total_locked_bytes: locked,
            total_software_bytes: software,
        })
    }
    /// Safe consumer of an unsafe, node-startup-only attestation. Reads actual
    /// finite soft AND hard RLIMIT_MEMLOCK and a fixed-storage VmLck diagnostic.
    /// No setrlimit, privilege, fallback, environment or runtime reconfiguration.
    pub(crate) fn new(
        evidence: NodeStartup,
        caps: LockProfileCaps,
        native: NativeAllowance,
    ) -> Result<Self, Error> {
        STARTUP
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| Error::NativeAdmission)?;
        let result = Self::construct(evidence, caps, native);
        STARTUP.store(if result.is_ok() { 2 } else { 0 }, Ordering::Release);
        result
    }
    fn construct(
        evidence: NodeStartup,
        caps: LockProfileCaps,
        native: NativeAllowance,
    ) -> Result<Self, Error> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(Error::Unsupported);
        }
        if caps.slots == 0
            || caps.slots > evidence.native_job_ceiling
            || caps.locked_bytes > evidence.approved_locked_bytes
            || caps.software_bytes > evidence.approved_software_bytes
        {
            return Err(Error::NativeAdmission);
        }
        let layout = Self::required_layout(caps.slots, native)?;
        if layout.total_locked_bytes > caps.locked_bytes
            || layout.total_software_bytes > caps.software_bytes
        {
            return Err(Error::NativeAdmission);
        }
        let total_locked = caps
            .locked_bytes
            .checked_add(evidence.other_locked_bytes)
            .ok_or(Error::Capacity)?;
        let (soft, hard) = actual_memlock()?;
        validate_memlock(soft, hard, total_locked)?;
        let soft = usize::try_from(soft).map_err(|_| Error::Capacity)?;
        let hard = usize::try_from(hard).map_err(|_| Error::Capacity)?;
        reject_lock_limit_privileges()?;
        let diagnostic = locked_diagnostic()?;
        if diagnostic > evidence.other_locked_bytes {
            return Err(Error::NativeAdmission);
        }
        let admission = Workspace::required_admission(native)?;
        let (allocation, slot_offset) = Layout::new::<Inner>()
            .extend(Layout::array::<Slot>(caps.slots).map_err(|_| Error::Capacity)?)
            .map_err(|_| Error::Capacity)?;
        let allocation = allocation.pad_to_align();
        let pointer =
            NonNull::new(unsafe { alloc(allocation) }.cast::<Inner>()).ok_or(Error::Capacity)?;
        unsafe {
            pointer.as_ptr().write(Inner {
                references: AtomicUsize::new(1),
                active: AtomicUsize::new(0),
                held: AtomicUsize::new(0),
                slots: caps.slots,
                slot_offset,
                allocation,
                layout,
                caps,
                admission,
                soft,
                hard,
                diagnostic,
                other: evidence.other_locked_bytes,
            });
            for index in 0..caps.slots {
                pointer
                    .as_ptr()
                    .cast::<u8>()
                    .add(slot_offset)
                    .cast::<Slot>()
                    .add(index)
                    .write(Slot {
                        ownership: AtomicUsize::new(0),
                    });
            }
        }
        Ok(Self {
            owner: Strong(pointer),
        })
    }
    pub(crate) fn layout(&self) -> LockProfileLayout {
        self.owner.inner().layout
    }
    pub(crate) fn status(&self) -> LockProfileStatus {
        self.owner.status()
    }
    pub(crate) fn claim(&self, control: &Control<'_>) -> Result<SlotTicket, Error> {
        let inner = self.owner.inner();
        control.check()?;
        if inner.held.load(Ordering::Acquire) != 0 {
            return Err(Error::NativeAdmission);
        }
        let mut active = inner.active.load(Ordering::Acquire);
        let mut reserved = false;
        for _ in 0..CAS_ATTEMPTS {
            control.debit(1)?;
            let next = active.checked_add(1).ok_or(Error::Capacity)?;
            let bytes = next
                .checked_mul(inner.admission.bytes())
                .and_then(|n| n.checked_add(inner.layout.control_bytes))
                .ok_or(Error::Capacity)?;
            let locked = next
                .checked_mul(inner.admission.pinned_bytes)
                .ok_or(Error::Capacity)?;
            if next > inner.slots
                || bytes > inner.caps.software_bytes
                || locked > inner.caps.locked_bytes
            {
                return Err(Error::NativeAdmission);
            }
            match inner.active.compare_exchange_weak(
                active,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    reserved = true;
                    break;
                }
                Err(current) => active = current,
            }
        }
        if !reserved {
            return Err(Error::NativeAdmission);
        }
        for index in 0..inner.slots {
            if let Err(error) = control.debit(1) {
                self.owner.release_active();
                return Err(error);
            }
            if self
                .owner
                .slot(index)
                .ownership
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                let ticket = SlotTicket {
                    owner: self.owner.retain(),
                    index,
                    control_identity: control.identity,
                };
                ticket.check_control(control)?; // Drop ticket rolls back stop/fatal-HOLD races.
                return Ok(ticket);
            }
        }
        self.owner.release_active();
        Err(Error::NativeAdmission)
    }
    // Independent fixtures only; no per-query/per-Store production constructor.
    #[cfg(test)]
    pub(super) fn fixture(
        evidence: NodeStartup,
        caps: LockProfileCaps,
        native: NativeAllowance,
    ) -> Result<Self, Error> {
        Self::construct(evidence, caps, native)
    }
}

/// Consumed once; cannot be minted from a numeric byte allowance or a bool.
pub(crate) struct SlotTicket {
    owner: Strong,
    index: usize,
    control_identity: u64,
}
impl SlotTicket {
    pub(super) fn check_control(&self, control: &Control<'_>) -> Result<(), Error> {
        control.check()?;
        if self.control_identity != control.identity
            || self.owner.inner().held.load(Ordering::Acquire) != 0
        {
            return Err(Error::NativeAdmission);
        }
        Ok(())
    }
    pub(super) fn validate(
        &self,
        native: NativeAllowance,
        control: &Control<'_>,
    ) -> Result<Admission, Error> {
        self.check_control(control)?;
        if self
            .owner
            .slot(self.index)
            .ownership
            .load(Ordering::Acquire)
            != 1
        {
            return Err(Error::NativeAdmission);
        }
        let actual = Workspace::required_admission(native)?;
        if actual != self.owner.inner().admission {
            return Err(Error::NativeAdmission);
        }
        Ok(actual)
    }
    pub(super) fn mapping(&self) -> MappingLease {
        self.owner
            .slot(self.index)
            .ownership
            .fetch_add(2, Ordering::AcqRel);
        MappingLease {
            owner: Some(self.owner.retain()),
            index: self.index,
            mapped: false,
        }
    }
    #[cfg(test)]
    pub(super) fn status(&self) -> LockProfileStatus {
        self.owner.status()
    }
}
impl Drop for SlotTicket {
    fn drop(&mut self) {
        if self
            .owner
            .slot(self.index)
            .ownership
            .fetch_sub(1, Ordering::AcqRel)
            == 1
        {
            self.owner.release_active();
        }
    }
}
/// One strong owner per mapping, including partially constructed workspaces.
/// A failed actual munmap permanently holds the slot AND control allocation.
pub(super) struct MappingLease {
    owner: Option<Strong>,
    index: usize,
    mapped: bool,
}
impl MappingLease {
    pub(super) fn mapped(&mut self) {
        self.mapped = true;
    }
    pub(super) fn unmapped(&mut self) {
        self.mapped = false;
    }
}
impl Drop for MappingLease {
    fn drop(&mut self) {
        let owner = self.owner.take().unwrap();
        if self.mapped {
            let old = owner
                .slot(self.index)
                .ownership
                .fetch_or(HOLD, Ordering::AcqRel);
            if old & HOLD == 0 {
                owner.inner().held.fetch_add(1, Ordering::AcqRel);
            }
            // Intentional fatal HOLD: losing the outer node/workspace handle
            // cannot silently free/recreate capacity while this map still lives.
            std::mem::forget(owner);
        } else if owner
            .slot(self.index)
            .ownership
            .fetch_sub(2, Ordering::AcqRel)
            == 2
        {
            owner.release_active();
        }
    }
}

fn validate_memlock(soft: libc::rlim_t, hard: libc::rlim_t, required: usize) -> Result<(), Error> {
    if soft == libc::RLIM_INFINITY || hard == libc::RLIM_INFINITY || soft > hard {
        return Err(Error::NativeAdmission);
    }
    let page = super::slab::page_size()?;
    // Linux enforces the limit rounded down to whole pages.
    let soft = usize::try_from(soft).map_err(|_| Error::Capacity)? / page * page;
    let hard = usize::try_from(hard).map_err(|_| Error::Capacity)? / page * page;
    if required > soft || required > hard {
        return Err(Error::NativeAdmission);
    }
    Ok(())
}
fn actual_memlock() -> Result<(libc::rlim_t, libc::rlim_t), Error> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limits) } != 0 {
        return Err(Error::NativeAdmission);
    }
    Ok((limits.rlim_cur, limits.rlim_max))
}
/// Diagnostic only. Does not prove backing, all owners, future locks or source
/// nonretention. The native source-audit attestation is independently mandatory.
fn locked_diagnostic() -> Result<usize, Error> {
    #[cfg(target_os = "linux")]
    {
        let fd = unsafe {
            libc::open(
                c"/proc/self/status".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(Error::NativeAdmission);
        }
        let mut buffer = [0u8; 8192];
        let read = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        let closed = unsafe { libc::close(fd) };
        if read <= 0 || read as usize == buffer.len() || closed != 0 {
            return Err(Error::NativeAdmission);
        }
        for line in buffer[..read as usize].split(|byte| *byte == b'\n') {
            if let Some(field) = line.strip_prefix(b"VmLck:") {
                let mut pieces = field
                    .split(|byte| byte.is_ascii_whitespace())
                    .filter(|part| !part.is_empty());
                let digits = pieces.next().ok_or(Error::NativeAdmission)?;
                if pieces.next() != Some(b"kB".as_slice())
                    || pieces.next().is_some()
                    || digits.is_empty()
                {
                    return Err(Error::NativeAdmission);
                }
                let mut number = 0usize;
                for byte in digits {
                    if !byte.is_ascii_digit() {
                        return Err(Error::NativeAdmission);
                    }
                    number = number
                        .checked_mul(10)
                        .and_then(|n| n.checked_add((byte - b'0') as usize))
                        .ok_or(Error::Capacity)?;
                }
                return number.checked_mul(1024).ok_or(Error::Capacity);
            }
        }
        Err(Error::NativeAdmission)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Unsupported)
    }
}
#[cfg(test)]
#[path = "profile_tests.rs"]
mod tests;

// Finite RLIMIT enforcement must not be waived by Linux lock/resource caps.
fn reject_lock_limit_privileges() -> Result<(), Error> {
    #[cfg(target_os = "linux")]
    {
        #[repr(C)]
        struct Header {
            version: u32,
            pid: i32,
        }
        #[repr(C)]
        #[derive(Clone, Copy)]
        struct Data {
            effective: u32,
            permitted: u32,
            inheritable: u32,
        }
        let mut header = Header {
            version: 0x2008_0522,
            pid: 0,
        };
        let mut data = [Data {
            effective: 0,
            permitted: 0,
            inheritable: 0,
        }; 2];
        if unsafe {
            libc::syscall(
                libc::SYS_capget,
                &mut header as *mut Header,
                data.as_mut_ptr(),
            )
        } != 0
        {
            return Err(Error::NativeAdmission);
        }
        // Linux CAP_IPC_LOCK=14, CAP_SYS_RESOURCE=24, both in the low word.
        if (data[0].effective | data[0].permitted | data[0].inheritable) & ((1 << 14) | (1 << 24))
            != 0
        {
            return Err(Error::NativeAdmission);
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(Error::Unsupported)
    }
}
