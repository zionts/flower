//! One finite, pre-touched mapped arena. No per-cell malloc/Arc/Box or mappings.
//!
//! A slot is private while staged and immutable while any cell/witness owns it.
//! Slot references and pool lifetime are intrusive, in the admitted mapping.
//! The associated native lease is stored inline in the same exact layout and
//! released only AFTER munmap on the last pool-or-cell owner. Ordinary source
//! Snapshots, Records, Backings and transactions never enter this module.
use super::{MAX_REGISTRY_BYTES, RegistryError, RegistryIdentity, RegistryNamespace};
use std::alloc::Layout;
use std::cell::UnsafeCell;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const STAGING: usize = usize::MAX;
const MAX_REFERENCES: usize = isize::MAX as usize;
pub(crate) const HARD_REGISTRY_POOL_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const HARD_REGISTRY_POOL_CELLS: usize = 256;

/// This trait does not prove node-wide backing. The native caller must provide
/// ONE process-global owner, not manufacture a budget for each Store. Its
/// lease must cover the exact supplied mapping bytes and retained cell limit,
/// plus separately accounted caller/owner metadata outside this mapping. The
/// Lease value's actual inline size/alignment IS included in our layout; any
/// resources it owns indirectly require the native owner's own exact contract.
/// There is no Box<dyn Lease>, cloned Arc metadata or implicit default owner.
pub(crate) trait RegistryAdmission {
    type Lease: Send + Sync + 'static;
    fn try_reserve(
        &self,
        actual_mapped_bytes: usize,
        cells: usize,
    ) -> Result<Self::Lease, RegistryError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryPoolLimits {
    pub(crate) bytes: usize,
    pub(crate) cells: usize,
}
impl RegistryPoolLimits {
    pub(crate) const HARD: Self = Self {
        bytes: HARD_REGISTRY_POOL_BYTES,
        cells: HARD_REGISTRY_POOL_CELLS,
    };
    fn valid(self) -> bool {
        self.bytes > 0
            && self.bytes <= HARD_REGISTRY_POOL_BYTES
            && self.cells > 0
            && self.cells <= HARD_REGISTRY_POOL_CELLS
    }
}

/// Exact object layout and actual system-page-rounded extent. A lower byte
/// limit can reduce usable cells; requested cells are never reported as usable
/// unless their control+inline lease+fixed slots fit that mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RegistryPoolLayout {
    pub(crate) mapped_bytes: usize,
    pub(crate) cells: usize,
    pub(crate) control_bytes: usize,
    pub(crate) lease_bytes: usize,
    pub(crate) slot_bytes: usize,
    pub(crate) slot_header_bytes: usize,
    pub(crate) payload_bytes: usize,
    pub(crate) page_bytes: usize,
    lease_offset: usize,
    slots_offset: usize,
}
impl RegistryPoolLayout {
    fn for_lease<L>(limits: RegistryPoolLimits) -> Result<Self, RegistryError> {
        if !limits.valid() {
            return Err(RegistryError::Invalid);
        }
        let page = page_size()?;
        for cells in (1..=limits.cells).rev() {
            let (control, lease_offset) = Layout::new::<PoolControl>()
                .extend(Layout::new::<L>())
                .map_err(|_| RegistryError::Capacity)?;
            let (layout, slots_offset) = control
                .extend(Layout::array::<RegistrySlot>(cells).map_err(|_| RegistryError::Capacity)?)
                .map_err(|_| RegistryError::Capacity)?;
            if layout.align() > page {
                return Err(RegistryError::Unsupported);
            }
            let mapped_bytes = layout
                .size()
                .checked_add(page - 1)
                .map(|bytes| bytes / page * page)
                .ok_or(RegistryError::Capacity)?;
            if mapped_bytes <= limits.bytes {
                return Ok(Self {
                    mapped_bytes,
                    cells,
                    control_bytes: std::mem::size_of::<PoolControl>(),
                    lease_bytes: std::mem::size_of::<L>(),
                    slot_bytes: std::mem::size_of::<RegistrySlot>(),
                    slot_header_bytes: std::mem::size_of::<RegistrySlot>() - MAX_REGISTRY_BYTES,
                    payload_bytes: MAX_REGISTRY_BYTES,
                    page_bytes: page,
                    lease_offset,
                    slots_offset,
                });
            }
        }
        Err(RegistryError::Capacity)
    }
}

#[repr(C)]
struct PoolControl {
    owners: AtomicUsize,
    next_slot: AtomicUsize,
    next_namespace: AtomicU64,
    stage_gate: AtomicBool,
    live_slots: AtomicUsize,
    cells: usize,
    slots_offset: usize,
    lease_offset: usize,
    mapped_bytes: usize,
    release: unsafe fn(NonNull<PoolControl>),
}

// Every SlotData bit pattern is valid: integers and byte arrays only. The mmap
// is zeroed/pre-touched before publication; slot data is then accessed through
// UnsafeCell ONLY by its unique staging owner or immutable published readers.
#[repr(C)]
struct SlotData {
    identity: StoredIdentity,
    body_len: u32,
    body: [u8; MAX_REGISTRY_BYTES],
}
#[repr(C)]
#[derive(Clone, Copy)]
struct StoredIdentity {
    store: u64,
    installation: u64,
    registry: u64,
    bundle: u64,
    schema: u64,
    namespace_uid: u64,
    namespace_epoch: u64,
}
impl From<RegistryIdentity> for StoredIdentity {
    fn from(value: RegistryIdentity) -> Self {
        Self {
            store: value.store,
            installation: value.installation,
            registry: value.registry,
            bundle: value.bundle,
            schema: value.schema,
            namespace_uid: value.namespace.uid,
            namespace_epoch: value.namespace.epoch,
        }
    }
}
impl From<StoredIdentity> for RegistryIdentity {
    fn from(value: StoredIdentity) -> Self {
        Self {
            store: value.store,
            installation: value.installation,
            registry: value.registry,
            bundle: value.bundle,
            schema: value.schema,
            namespace: RegistryNamespace {
                uid: value.namespace_uid,
                epoch: value.namespace_epoch,
            },
        }
    }
}
#[repr(C)]
struct RegistrySlot {
    references: AtomicUsize,
    data: UnsafeCell<SlotData>,
}

/// Pointer-only owner of the actual bounded mapping. Caller-held handles and
/// their native stacks/control storage are additional admission obligations.
pub(crate) struct RegistryPool {
    control: NonNull<PoolControl>,
}
/// A unique slot, admitted BEFORE serialization or source capture. Its private
/// mutable staging state cannot be registered as a native witness or read by
/// another cell. Cancellation/error drops return exactly this slot.
pub(in crate::consensus) struct RegistryStaging {
    control: NonNull<PoolControl>,
    slot: NonNull<RegistrySlot>,
}
/// Immutable root-free registry bytes. A clone adds no allocation; the slot
/// remains charged and nonreusable until its LAST cell/witness owner drops.
pub(in crate::consensus) struct RegistryCell {
    control: NonNull<PoolControl>,
    slot: NonNull<RegistrySlot>,
}

impl RegistryPool {
    pub(crate) fn reservation_layout<A: RegistryAdmission>(
        limits: RegistryPoolLimits,
    ) -> Result<RegistryPoolLayout, RegistryError> {
        RegistryPoolLayout::for_lease::<A::Lease>(limits)
    }

    /// No Store or source reference is accepted. Construction/pretouch must
    /// finish at node startup BEFORE any source publication can use this pool.
    /// A cancellation/check error unmaps BEFORE releasing the provided lease.
    pub(crate) fn admit<A: RegistryAdmission>(
        admission: &A,
        limits: RegistryPoolLimits,
        mut check: impl FnMut() -> Result<(), RegistryError>,
    ) -> Result<Self, RegistryError> {
        check()?;
        let layout = Self::reservation_layout::<A>(limits)?;
        let lease = admission.try_reserve(layout.mapped_bytes, layout.cells)?;
        // Declaration order matters on early return/unwind: mapping before
        // lease, including a partially pre-touched cancellation failure.
        let mapping = Mapping::new(layout.mapped_bytes)?;
        mapping.touch(&mut check)?;
        let control = mapping.pointer.cast::<PoolControl>();
        unsafe {
            control.as_ptr().write(PoolControl {
                owners: AtomicUsize::new(1),
                next_slot: AtomicUsize::new(0),
                next_namespace: AtomicU64::new(1),
                stage_gate: AtomicBool::new(false),
                live_slots: AtomicUsize::new(0),
                cells: layout.cells,
                slots_offset: layout.slots_offset,
                lease_offset: layout.lease_offset,
                mapped_bytes: layout.mapped_bytes,
                release: release_mapping::<A::Lease>,
            });
            mapping
                .pointer
                .as_ptr()
                .add(layout.lease_offset)
                .cast::<A::Lease>()
                .write(lease);
            for index in 0..layout.cells {
                let slot = mapping
                    .pointer
                    .as_ptr()
                    .add(layout.slots_offset)
                    .cast::<RegistrySlot>()
                    .add(index);
                // SlotData and UnsafeCell's zero bit patterns are valid. Only
                // the atomic needs explicit initialization; no 37KiB temporary
                // SlotData/array object is constructed on the native stack.
                std::ptr::addr_of_mut!((*slot).references).write(AtomicUsize::new(0));
            }
        }
        std::mem::forget(mapping);
        Ok(Self { control })
    }

    pub(crate) fn try_clone(&self) -> Result<Self, RegistryError> {
        retain_pool(self.control)?;
        Ok(Self {
            control: self.control,
        })
    }
    pub(crate) fn mapped_bytes(&self) -> usize {
        self.header().mapped_bytes
    }
    pub(crate) fn capacity(&self) -> usize {
        self.header().cells
    }
    pub(crate) fn live_cells(&self) -> usize {
        self.header().live_slots.load(Ordering::Acquire)
    }
    fn header(&self) -> &PoolControl {
        // This handle owns one intrusive pool reference.
        unsafe { self.control.as_ref() }
    }

    /// Private native source issuance. A Store must retain this UID in its
    /// actual current-publication namespace adjunct; this operation does not
    /// register/validate a caller name or prove that adjunct is wired. The
    /// checked nonwrapping counter itself lives in the admitted pool mapping.
    pub(in crate::consensus) fn issue_namespace(
        &self,
        epoch: Option<u64>,
    ) -> Result<RegistryNamespace, RegistryError> {
        if epoch.is_some_and(|epoch| epoch == 0 || epoch > 9_007_199_254_740_991) {
            return Err(RegistryError::Invalid);
        }
        let uid = next_namespace(&self.header().next_namespace)?;
        Ok(RegistryNamespace {
            uid,
            epoch: epoch.unwrap_or(0),
        })
    }

    pub(in crate::consensus) fn stage(&self) -> Result<RegistryStaging, RegistryError> {
        let guard = StageGuard::try_acquire(&self.header().stage_gate)?;
        self.stage_locked(&guard)
    }

    fn stage_locked(&self, _guard: &StageGuard<'_>) -> Result<RegistryStaging, RegistryError> {
        let header = self.header();
        // No other producer can claim a slot while this nonwaiting gate is
        // owned. Drops may ONLY add free slots, so a vacancy cannot move behind
        // this bounded scan. Capacity can linearize at gate acquisition; gate
        // contention is explicitly Busy, never falsely reported as fullness.
        let mut index = header.next_slot.fetch_add(1, Ordering::Relaxed) % header.cells;
        for _ in 0..header.cells {
            let slot = unsafe {
                NonNull::new_unchecked(
                    self.control
                        .as_ptr()
                        .cast::<u8>()
                        .add(header.slots_offset)
                        .cast::<RegistrySlot>()
                        .add(index),
                )
            };
            let references = unsafe { &slot.as_ref().references };
            if references
                .compare_exchange(0, STAGING, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                if let Err(error) = retain_pool(self.control) {
                    references.store(0, Ordering::Release);
                    return Err(error);
                }
                header.live_slots.fetch_add(1, Ordering::AcqRel);
                return Ok(RegistryStaging {
                    control: self.control,
                    slot,
                });
            }
            index = if index + 1 == header.cells {
                0
            } else {
                index + 1
            };
        }
        Err(RegistryError::Capacity)
    }
}
impl Drop for RegistryPool {
    fn drop(&mut self) {
        release_pool(self.control);
    }
}

impl RegistryStaging {
    /// Internal source-owned constructor. This is not a parser/guest claim
    /// about ordinary dispatch; the future opaque native Envelope must also
    /// validate these stamps against its actual current publication atomically.
    pub(in crate::consensus) fn seal(
        self,
        identity: RegistryIdentity,
        raw_json: &[u8],
    ) -> Result<RegistryCell, RegistryError> {
        if !identity.valid()
            || raw_json.is_empty()
            || raw_json.len() > MAX_REGISTRY_BYTES
            || std::str::from_utf8(raw_json).is_err()
        {
            return Err(RegistryError::Invalid);
        }
        // Unique STAGING ownership excludes readers/reuse of this slot. All
        // bytes that accessors can expose are overwritten before Release.
        let data = unsafe { &mut *self.slot.as_ref().data.get() };
        data.identity = identity.into();
        data.body_len = raw_json.len() as u32;
        data.body[..raw_json.len()].copy_from_slice(raw_json);
        unsafe { self.slot.as_ref().references.store(1, Ordering::Release) };
        let cell = RegistryCell {
            control: self.control,
            slot: self.slot,
        };
        // Transfer exactly this slot's one pool owner; staging Drop must not
        // free a slot now visible to immutable readers.
        std::mem::forget(self);
        Ok(cell)
    }
}
impl Drop for RegistryStaging {
    fn drop(&mut self) {
        // No published reader ever owned this unique STAGING slot.
        free_slot(self.control, self.slot);
    }
}

impl RegistryCell {
    pub(in crate::consensus) fn try_clone(&self) -> Result<Self, RegistryError> {
        let references = unsafe { &self.slot.as_ref().references };
        references
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count > 0 && count < MAX_REFERENCES).then(|| count + 1)
            })
            .map_err(|_| RegistryError::Capacity)?;
        Ok(Self {
            control: self.control,
            slot: self.slot,
        })
    }
    pub(crate) fn raw_json(&self) -> &[u8] {
        let data = self.data();
        &data.body[..data.body_len as usize]
    }
    pub(in crate::consensus) fn identity(&self) -> RegistryIdentity {
        self.data().identity.into()
    }
    pub(in crate::consensus) fn matches_namespace(&self, namespace: RegistryNamespace) -> bool {
        let data = self.data();
        data.identity.namespace_uid == namespace.uid
            && data.identity.namespace_epoch == namespace.epoch
    }
    fn data(&self) -> &SlotData {
        // Sealing publishes all data with Release. Any handle owns a positive
        // reference; no writer can modify/reuse the slot until every reader and
        // borrowed slice has ended. try_clone acts only on already owned data.
        unsafe { &*self.slot.as_ref().data.get() }
    }
}
impl Drop for RegistryCell {
    fn drop(&mut self) {
        let references = unsafe { &self.slot.as_ref().references };
        let mut count = references.load(Ordering::Acquire);
        loop {
            if count == 0 || count == STAGING {
                // Violated private lifetime invariant; do not reuse a mapping
                // with a potentially live reader or release a false lease.
                std::process::abort();
            }
            let next = if count == 1 { STAGING } else { count - 1 };
            match references.compare_exchange_weak(count, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    if count == 1 {
                        // Lock LAST-release before exposing a free slot, so
                        // counter/accounting cannot temporarily exceed capacity
                        // when another producer reuses it concurrently.
                        free_slot(self.control, self.slot);
                    }
                    return;
                }
                Err(actual) => count = actual,
            }
        }
    }
}

struct StageGuard<'a> {
    gate: &'a AtomicBool,
}
impl<'a> StageGuard<'a> {
    fn try_acquire(gate: &'a AtomicBool) -> Result<Self, RegistryError> {
        gate.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| RegistryError::Busy)?;
        Ok(Self { gate })
    }
}
impl Drop for StageGuard<'_> {
    fn drop(&mut self) {
        self.gate.store(false, Ordering::Release);
    }
}

fn next_namespace(counter: &AtomicU64) -> Result<u64, RegistryError> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| RegistryError::Capacity)
}
fn retain_pool(control: NonNull<PoolControl>) -> Result<(), RegistryError> {
    unsafe { &control.as_ref().owners }
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            (count > 0 && count < MAX_REFERENCES).then(|| count + 1)
        })
        .map(|_| ())
        .map_err(|_| RegistryError::Capacity)
}
fn release_pool(control: NonNull<PoolControl>) {
    let header = unsafe { control.as_ref() };
    let count = header.owners.fetch_sub(1, Ordering::AcqRel);
    if count == 0 {
        std::process::abort();
    }
    if count == 1 {
        // No operation can retain through an owner that no longer exists.
        // All slots must be released; no source/table/transaction is stored.
        if header.live_slots.load(Ordering::Acquire) != 0 {
            std::process::abort();
        }
        unsafe { (header.release)(control) };
    }
}
fn free_slot(control: NonNull<PoolControl>, slot: NonNull<RegistrySlot>) {
    let header = unsafe { control.as_ref() };
    let previous = header.live_slots.fetch_sub(1, Ordering::AcqRel);
    if previous == 0 {
        std::process::abort();
    }
    // No writes follow publication of FREE. New unique staging owners may
    // now overwrite data; old shorter tails are never exposed by accessors.
    unsafe { slot.as_ref().references.store(0, Ordering::Release) };
    release_pool(control);
}

unsafe fn release_mapping<L>(control: NonNull<PoolControl>) {
    let header = unsafe { control.as_ref() };
    let mapped_bytes = header.mapped_bytes;
    let lease_offset = header.lease_offset;
    // Move the concrete INLINE lease onto this admitted native caller's stack.
    // Its destructor cannot run while the actual backing is still mapped.
    let lease = unsafe {
        control
            .as_ptr()
            .cast::<u8>()
            .add(lease_offset)
            .cast::<L>()
            .read()
    };
    unmap(control.cast(), mapped_bytes);
    drop(lease);
}

struct Mapping {
    pointer: NonNull<u8>,
    bytes: usize,
}
impl Mapping {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn new(bytes: usize) -> Result<Self, RegistryError> {
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
            return Err(RegistryError::Capacity);
        }
        let Some(pointer) = NonNull::new(mapped.cast::<u8>()) else {
            // A successful null mapping cannot be represented by our pointers.
            if unsafe { libc::munmap(mapped, bytes) } != 0 {
                std::process::abort();
            }
            return Err(RegistryError::Unsupported);
        };
        Ok(Self { pointer, bytes })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn new(_bytes: usize) -> Result<Self, RegistryError> {
        Err(RegistryError::Unsupported)
    }
    fn touch(
        &self,
        check: &mut impl FnMut() -> Result<(), RegistryError>,
    ) -> Result<(), RegistryError> {
        for offset in 0..self.bytes {
            if offset.is_multiple_of(64 * 1024) {
                check()?;
            }
            // Explicit writes include ALL control/header/lease/padding bytes;
            // first source use never commits backing pages under exclusion.
            unsafe { self.pointer.as_ptr().add(offset).write_volatile(0) };
        }
        check()
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        unmap(self.pointer, self.bytes);
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn unmap(pointer: NonNull<u8>, bytes: usize) {
    if unsafe { libc::munmap(pointer.as_ptr().cast(), bytes) } != 0 {
        // A live backing must NEVER release its admission lease on unmap
        // failure. This is an internal native invariant, not a guest error.
        std::process::abort();
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn unmap(_pointer: NonNull<u8>, _bytes: usize) {
    std::process::abort();
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn page_size() -> Result<usize, RegistryError> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || !(page as usize).is_power_of_two() {
        return Err(RegistryError::Unsupported);
    }
    Ok(page as usize)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn page_size() -> Result<usize, RegistryError> {
    Err(RegistryError::Unsupported)
}

// RegistryAdmission requires the inline lease to be Send+Sync. Pool ownership
// is atomic; slot data is unique mutable STAGING or shared immutable SEALED.
// The mapping outlives every handle/slice and its Drop uses the original layout.
unsafe impl Send for RegistryPool {}
unsafe impl Sync for RegistryPool {}
unsafe impl Send for RegistryStaging {}
unsafe impl Send for RegistryCell {}
unsafe impl Sync for RegistryCell {}

#[cfg(test)]
#[path = "pool/tests.rs"]
mod tests;
