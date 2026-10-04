//! Finite CURRENT-only native name/UID metadata and OWNED registry cells.
//!
//! Real immutable cells are moved into an exactly laid-out in-region owner
//! array, never copied as bytes or resurrected from weak/raw slots. Selection
//! clones only a validated CURRENT owner under the same metadata/key gate.
//! This is NOT source validation, a native node admission owner, persistence,
//! routing or SQL authority. Parent must admit ONE actual combined mapping.
use super::pool::{RegistryCell, RegistryPool};
use super::{RegistryError, RegistryIdentity};
use std::alloc::Layout;
use std::cell::UnsafeCell;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_HEADS: usize = 256;
// An upper bound on this component, NOT an additional node allowance. Parent
// must count it, cell slots, inline lease, cancellation/control and rounding
// together within the SAME 16 MiB before any Store opens.
const MAX_COMPONENT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) enum DirectoryError {
    Busy,
    Capacity,
    Invalid,
    Missing,
    Stale,
    AlreadyCurrent,
    CurrentUnavailable,
}

/// Exact UTF-8 bytes, not a hash, pointer, sentinel name or fixed 4 KiB buffer.
/// Root and Scoped("") remain different even at the same fixture epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) enum NativeKey<'a> {
    Root,
    Scoped(&'a str),
}

/// Native-only SOURCE input. These scalars do not prove their own provenance.
/// Store/install/epoch must come from the actual guarded source publication.
/// The directory deliberately does not invent new Snapshot/PartitionState UIDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct NativeOrigin<'a> {
    pub(in crate::consensus) store: u64,
    pub(in crate::consensus) installation: u64,
    pub(in crate::consensus) epoch: u64,
    pub(in crate::consensus) key: NativeKey<'a>,
}
impl<'a> NativeOrigin<'a> {
    fn valid(self) -> bool {
        // Actual root-vs-scoped epoch rules belong to private native issuance.
        // Zero installation is supported by the existing pool identity.
        self.store != 0 && self.epoch <= 9_007_199_254_740_991
    }
    fn kind(self) -> u64 {
        match self.key {
            NativeKey::Root => 0,
            NativeKey::Scoped(_) => 1,
        }
    }
    fn bytes(self) -> &'a [u8] {
        match self.key {
            NativeKey::Root => &[],
            NativeKey::Scoped(name) => name.as_bytes(),
        }
    }
}

/// Actual native current registry/bundle/schema stamps, not global high water.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct NativeCode {
    pub(in crate::consensus) registry: u64,
    pub(in crate::consensus) bundle: u64,
    pub(in crate::consensus) schema: u64,
}
impl NativeCode {
    fn valid(self) -> bool {
        self.registry != 0 && self.bundle != 0 && self.schema != 0
    }
}

/// Opaque scalar correlation only. Not a weak slot, cell reference or authority
/// to dereference any body. The source retains this only in its current adjunct.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct NativeHeadToken {
    store: u64,
    installation: u64,
    epoch: u64,
    kind: u64,
    uid: u64,
}
impl NativeHeadToken {
    pub(in crate::consensus) fn uid(self) -> u64 {
        self.uid
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct HeadMetadata {
    pub(in crate::consensus) token: NativeHeadToken,
    pub(in crate::consensus) code: NativeCode,
}

/// Complete object extent for Control + fixed heads + REAL cell owners + key bytes +
/// alignment padding. No page rounding here: parent must extend its combined
/// pool Layout with object_layout(), THEN round/admit the one actual mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct DirectoryLayout {
    pub(in crate::consensus) bytes: usize,
    pub(in crate::consensus) alignment: usize,
    pub(in crate::consensus) control_bytes: usize,
    pub(in crate::consensus) head_bytes: usize,
    pub(in crate::consensus) owner_bytes: usize,
    pub(in crate::consensus) heads: usize,
    pub(in crate::consensus) key_bytes: usize,
    heads_offset: usize,
    owners_offset: usize,
    keys_offset: usize,
}
impl DirectoryLayout {
    /// Explicit startup lower-only dimensions, no default/growth/per-Store map.
    pub(in crate::consensus) fn new(
        max_heads: usize,
        key_bytes: usize,
    ) -> Result<Self, DirectoryError> {
        if max_heads == 0 || max_heads > MAX_HEADS {
            return Err(DirectoryError::Invalid);
        }
        let heads =
            Layout::array::<UnsafeCell<Head>>(max_heads).map_err(|_| DirectoryError::Capacity)?;
        let (layout, heads_offset) = Layout::new::<Control>()
            .extend(heads)
            .map_err(|_| DirectoryError::Capacity)?;
        let owners = Layout::array::<UnsafeCell<Option<RegistryCell>>>(max_heads)
            .map_err(|_| DirectoryError::Capacity)?;
        let (layout, owners_offset) = layout
            .extend(owners)
            .map_err(|_| DirectoryError::Capacity)?;
        let keys = Layout::array::<u8>(key_bytes).map_err(|_| DirectoryError::Capacity)?;
        let (layout, keys_offset) = layout.extend(keys).map_err(|_| DirectoryError::Capacity)?;
        let layout = layout.pad_to_align();
        if layout.size() > MAX_COMPONENT_BYTES {
            return Err(DirectoryError::Capacity);
        }
        Ok(Self {
            bytes: layout.size(),
            alignment: layout.align(),
            control_bytes: std::mem::size_of::<Control>(),
            head_bytes: std::mem::size_of::<Head>(),
            owner_bytes: std::mem::size_of::<Option<RegistryCell>>(),
            heads: max_heads,
            key_bytes,
            heads_offset,
            owners_offset,
            keys_offset,
        })
    }
    pub(in crate::consensus) fn object_layout(self) -> Layout {
        // Fields determining validity are private; constructed by checked new.
        Layout::from_size_align(self.bytes, self.alignment).expect("checked directory layout")
    }
}

#[repr(C)]
struct Control {
    gate: AtomicBool,
    counts: UnsafeCell<Counts>,
    heads: usize,
    key_bytes: usize,
    heads_offset: usize,
    owners_offset: usize,
    keys_offset: usize,
}
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Counts {
    heads: usize,
    key_bytes: usize,
}
// Every head bit pattern is valid. uid == 0 means free. Only one CURRENT head
// descriptor per origin; no descriptor/extent/free-list history is retained.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct Head {
    store: u64,
    installation: u64,
    epoch: u64,
    kind: u64,
    uid: u64,
    registry: u64,
    bundle: u64,
    schema: u64,
    offset: usize,
    len: usize,
}
impl Head {
    fn token(self) -> NativeHeadToken {
        NativeHeadToken {
            store: self.store,
            installation: self.installation,
            epoch: self.epoch,
            kind: self.kind,
            uid: self.uid,
        }
    }
    fn matches(self, identity: RegistryIdentity) -> bool {
        self.store == identity.store
            && self.installation == identity.installation
            && self.uid == identity.namespace.uid
            && self.epoch == identity.namespace.epoch
            && self.registry == identity.registry
            && self.bundle == identity.bundle
            && self.schema == identity.schema
    }
    fn metadata(self) -> HeadMetadata {
        HeadMetadata {
            token: self.token(),
            code: NativeCode {
                registry: self.registry,
                bundle: self.bundle,
                schema: self.schema,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct DirectoryUsage {
    pub(in crate::consensus) heads: usize,
    pub(in crate::consensus) key_bytes: usize,
}

/// Non-clone handle to an initialized region. Standalone initialization owns an
/// exclusive region borrow and clears on Drop. A PRIVATE unsafe pool wrapper
/// may instead borrow a persistent region from a live RegistryPool handle;
/// these shared views never clear on Drop or permit safe teardown. In both
/// modes every metadata/key/owner access uses the SAME nonwaiting gate.
pub(in crate::consensus) struct Directory<'region> {
    control: NonNull<Control>,
    clear_on_drop: bool,
    pool: Option<&'region RegistryPool>,
    region: PhantomData<&'region mut [u8]>,
}
impl<'region> Directory<'region> {
    /// Region must already be admitted/initialized by the actual native owner;
    /// this safe borrow proves lifetime/exclusivity, NOT admission or same-pool
    /// placement. Parent alone must prove the exact combined mapping contract.
    pub(in crate::consensus) fn initialize(
        region: &'region mut [u8],
        layout: DirectoryLayout,
    ) -> Result<Self, DirectoryError> {
        // Public accounting fields are convenient for parent integration, but
        // cannot be trusted as safe pointer arithmetic if a caller mutates them.
        if DirectoryLayout::new(layout.heads, layout.key_bytes)? != layout
            || region.len() != layout.bytes
            || !(region.as_ptr() as usize).is_multiple_of(layout.alignment)
        {
            return Err(DirectoryError::Invalid);
        }
        region.fill(0);
        let control =
            NonNull::new(region.as_mut_ptr().cast::<Control>()).ok_or(DirectoryError::Invalid)?;
        unsafe {
            control.as_ptr().write(Control {
                gate: AtomicBool::new(false),
                counts: UnsafeCell::new(Counts::default()),
                heads: layout.heads,
                key_bytes: layout.key_bytes,
                heads_offset: layout.heads_offset,
                owners_offset: layout.owners_offset,
                keys_offset: layout.keys_offset,
            });
            for index in 0..layout.heads {
                region
                    .as_mut_ptr()
                    .add(layout.heads_offset)
                    .cast::<UnsafeCell<Head>>()
                    .add(index)
                    .write(UnsafeCell::new(Head::default()));
                // Option<RegistryCell> is NOT assumed to have a zero/Copy bit
                // pattern. Initialize every actual owner explicitly to None.
                region
                    .as_mut_ptr()
                    .add(layout.owners_offset)
                    .cast::<UnsafeCell<Option<RegistryCell>>>()
                    .add(index)
                    .write(UnsafeCell::new(None));
            }
        }
        Ok(Self {
            control,
            clear_on_drop: true,
            pool: None,
            region: PhantomData,
        })
    }

    /// Persistent pool view: lifetime is tied to this actual external pool
    /// handle, NOT to a Cell/raw slot. No public raw constructor exists.
    ///
    /// # Safety
    /// Parent must prove region is the admitted initialized directory tail of
    /// `pool`, with exactly this checked layout/alignment/extent, and remains
    /// live/unreinitialized until every view ends. Pool teardown must run ONLY
    /// after the last external handle has excluded all live views.
    pub(super) unsafe fn borrow_from_pool(
        pool: &'region RegistryPool,
        region: NonNull<u8>,
        layout: DirectoryLayout,
    ) -> Self {
        debug_assert_eq!(
            DirectoryLayout::new(layout.heads, layout.key_bytes),
            Ok(layout)
        );
        debug_assert!((region.as_ptr() as usize).is_multiple_of(layout.alignment));
        let directory = Self {
            control: region.cast(),
            clear_on_drop: false,
            pool: Some(pool),
            region: PhantomData,
        };
        debug_assert_eq!(directory.header().heads, layout.heads);
        debug_assert_eq!(directory.header().key_bytes, layout.key_bytes);
        debug_assert_eq!(directory.header().heads_offset, layout.heads_offset);
        debug_assert_eq!(directory.header().owners_offset, layout.owners_offset);
        debug_assert_eq!(directory.header().keys_offset, layout.keys_offset);
        directory
    }

    /// Private last-external-pool-handle teardown, BEFORE releasing its base
    /// pool reference. This removes the current-cell self-mapping ownership
    /// cycle while an independent pool owner still keeps the map initialized.
    ///
    /// # Safety
    /// All Directory views/operations must have ended and none may be created
    /// concurrently. `pool` must retain an independent live pool reference
    /// through this call; region/layout must meet borrow_from_pool's contract.
    pub(super) unsafe fn clear_from_pool_exclusive(
        pool: &'region RegistryPool,
        region: NonNull<u8>,
        layout: DirectoryLayout,
    ) {
        let mut directory = unsafe { Self::borrow_from_pool(pool, region, layout) };
        directory.clear_exclusive();
    }

    /// Native source ONLY. Callback must be a private nonwaiting/no-allocation
    /// issuance from the same pool counter (e.g. pool.issue_namespace(epoch)),
    /// never a guest/caller UID/hash/pointer or a separate counter. We invoke it
    /// ONCE, ONLY after a fixed head AND exact contiguous extent are admitted
    /// under this gate. Failure/panic leaves directory/key bytes unchanged.
    /// A successfully spent UID is never recycled, including on invalid output.
    pub(in crate::consensus) fn register_native(
        &self,
        origin: NativeOrigin<'_>,
        code: NativeCode,
        issue_private_uid: impl FnOnce() -> Result<u64, DirectoryError>,
    ) -> Result<NativeHeadToken, DirectoryError> {
        if !origin.valid() || !code.valid() {
            return Err(DirectoryError::Invalid);
        }
        let guard = self.lock()?;
        if self.find_key(&guard, origin).index.is_some() {
            // A replacement install/epoch must retire the old current adjunct
            // first. Never accumulate older descriptor history for one name.
            return Err(DirectoryError::AlreadyCurrent);
        }
        let index = (0..self.header().heads)
            .find(|&index| self.head(&guard, index).uid == 0)
            .ok_or(DirectoryError::Capacity)?;
        let extent = self.first_fit(&guard, origin.bytes().len());
        let offset = extent.offset.ok_or(DirectoryError::Capacity)?;
        let uid = issue_private_uid()?;
        if uid == 0 || (0..self.header().heads).any(|index| self.head(&guard, index).uid == uid) {
            return Err(DirectoryError::Invalid);
        }
        let head = Head {
            store: origin.store,
            installation: origin.installation,
            epoch: origin.epoch,
            kind: origin.kind(),
            uid,
            registry: code.registry,
            bundle: code.bundle,
            schema: code.schema,
            offset,
            len: origin.bytes().len(),
        };
        // All possible refusal/callback work is finished before key mutation.
        unsafe {
            std::ptr::copy_nonoverlapping(
                origin.bytes().as_ptr(),
                self.keys().add(offset),
                head.len,
            );
        }
        self.write_head(&guard, index, head);
        let mut counts = self.counts(&guard);
        counts.heads += 1;
        counts.key_bytes += head.len;
        self.write_counts(&guard, counts);
        Ok(head.token())
    }

    /// Exact source origin + optional previously issued UID correlation. No
    /// borrowed key escapes: returned metadata consists exclusively of scalars.
    pub(in crate::consensus) fn lookup_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: Option<NativeHeadToken>,
    ) -> Result<HeadMetadata, DirectoryError> {
        if !origin.valid() {
            return Err(DirectoryError::Invalid);
        }
        let guard = self.lock()?;
        Ok(self.correlate(&guard, origin, expected)?.1.metadata())
    }

    /// Changed registry/code pair immediately replaces current metadata. There
    /// is no old body alias, and no attachment/weak-slot fallback. Parent must
    /// atomically attach a matching real owned Cell before body selection works.
    pub(in crate::consensus) fn update_code_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: NativeHeadToken,
        code: NativeCode,
    ) -> Result<HeadMetadata, DirectoryError> {
        if !origin.valid() || !code.valid() {
            return Err(DirectoryError::Invalid);
        }
        let guard = self.lock()?;
        let (index, mut head) = self.correlate(&guard, origin, Some(expected))?;
        head.registry = code.registry;
        head.bundle = code.bundle;
        head.schema = code.schema;
        self.write_head(&guard, index, head);
        // Conservative even for equal code: an explicit validated attachment
        // is required again. No old witness can become current by aliasing.
        let previous = self.take_owner(&guard, index);
        drop(guard);
        drop(previous);
        Ok(head.metadata())
    }

    /// Attach one REAL immutable owner to the exact CURRENT origin/token/code.
    /// Caller scalars are correlation, not native source authority. Mismatches
    /// refuse; even on refusal the input cell is dropped AFTER releasing the
    /// gate. Success moves ownership and detaches the prior cell under it.
    pub(in crate::consensus) fn attach_current_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: NativeHeadToken,
        actual_code: NativeCode,
        cell: RegistryCell,
    ) -> Result<(), DirectoryError> {
        if !origin.valid() || !actual_code.valid() {
            return Err(DirectoryError::Invalid);
        }
        // A production pool view must not attach a foreign allocation merely
        // because another pool issued numerically equal UID/code scalars.
        // Standalone provided-region fixtures have no same-map owner proof;
        // their component API is not a native NodeResources construction.
        if self.pool.is_some_and(|pool| !pool.owns_cell(&cell)) {
            return Err(DirectoryError::CurrentUnavailable);
        }
        let guard = self.lock()?;
        let (index, head) = self.correlate(&guard, origin, Some(expected))?;
        if head.metadata().code != actual_code || !head.matches(cell.identity()) {
            // Locals (the gate) drop before the owned function parameter.
            drop(guard);
            drop(cell);
            return Err(DirectoryError::CurrentUnavailable);
        }
        let previous = self.replace_owner(&guard, index, cell);
        drop(guard);
        drop(previous);
        Ok(())
    }

    /// Clone only the REAL current owner, under the SAME gate as full exact
    /// origin/token/code/identity validation. Never use a weak/raw slot or an
    /// old detached witness as fallback. Missing head/body, stale correlation
    /// or mismatched code/identity => CurrentUnavailable, never an old alias.
    pub(in crate::consensus) fn select_current_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: NativeHeadToken,
        code: NativeCode,
    ) -> Result<RegistryCell, DirectoryError> {
        if !origin.valid() || !code.valid() {
            return Err(DirectoryError::Invalid);
        }
        let guard = self.lock()?;
        let (index, head) = self
            .correlate(&guard, origin, Some(expected))
            .map_err(|error| match error {
                DirectoryError::Missing | DirectoryError::Stale => {
                    DirectoryError::CurrentUnavailable
                }
                other => other,
            })?;
        if head.metadata().code != code {
            return Err(DirectoryError::CurrentUnavailable);
        }
        // This reference is strictly lexical, gate-protected, and never
        // escapes. Only the successfully retained owned Cell is returned.
        let owner = unsafe { &*self.owner_pointer(&guard, index) };
        let cell = owner.as_ref().ok_or(DirectoryError::CurrentUnavailable)?;
        if !head.matches(cell.identity()) || self.pool.is_some_and(|pool| !pool.owns_cell(cell)) {
            return Err(DirectoryError::CurrentUnavailable);
        }
        cell.try_clone().map_err(|error| match error {
            RegistryError::Capacity => DirectoryError::Capacity,
            RegistryError::Busy => DirectoryError::Busy,
            RegistryError::Invalid | RegistryError::Unsupported | RegistryError::Cancelled => {
                DirectoryError::CurrentUnavailable
            }
        })
    }

    pub(in crate::consensus) fn retire_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: NativeHeadToken,
    ) -> Result<(), DirectoryError> {
        self.remove_native(origin, expected)
    }

    /// Removes only a correlated current head, not another incarnation. Key
    /// bytes may be reused immediately: no key borrows or historical names can
    /// escape. Detach the owner under the gate, destroy it only AFTER release.
    pub(in crate::consensus) fn remove_native(
        &self,
        origin: NativeOrigin<'_>,
        expected: NativeHeadToken,
    ) -> Result<(), DirectoryError> {
        if !origin.valid() {
            return Err(DirectoryError::Invalid);
        }
        let guard = self.lock()?;
        let (index, head) = self.correlate(&guard, origin, Some(expected))?;
        unsafe { self.keys().add(head.offset).write_bytes(0, head.len) };
        self.write_head(&guard, index, Head::default());
        let mut counts = self.counts(&guard);
        counts.heads -= 1;
        counts.key_bytes -= head.len;
        self.write_counts(&guard, counts);
        let previous = self.take_owner(&guard, index);
        drop(guard);
        drop(previous);
        Ok(())
    }

    pub(in crate::consensus) fn usage(&self) -> Result<DirectoryUsage, DirectoryError> {
        let guard = self.lock()?;
        let counts = self.counts(&guard);
        Ok(DirectoryUsage {
            heads: counts.heads,
            key_bytes: counts.key_bytes,
        })
    }

    /// Only the standalone exclusive region owner may clear safely. &mut on
    /// one pool view does NOT exclude other views, so borrowed mode refuses.
    pub(in crate::consensus) fn clear(&mut self) -> Result<(), DirectoryError> {
        if !self.clear_on_drop {
            return Err(DirectoryError::Invalid);
        }
        self.clear_exclusive();
        Ok(())
    }

    // Exclusive standalone borrow or private last-pool-handle contract. One
    // cell-sized stack temporary, not an uncharged heap/staged owner array.
    // Release the live gate before EVERY destructor, including the last cell
    // that may unmap its backing and invoke the concrete lease destructor.
    fn clear_exclusive(&mut self) {
        debug_assert!(!self.header().gate.load(Ordering::Relaxed));
        for index in 0..self.header().heads {
            let guard = self.lock().expect("exclusive directory clear");
            self.write_head(&guard, index, Head::default());
            let previous = self.take_owner(&guard, index);
            drop(guard);
            drop(previous);
        }
        let guard = self.lock().expect("exclusive directory clear");
        unsafe { self.keys().write_bytes(0, self.header().key_bytes) };
        self.write_counts(&guard, Counts::default());
    }

    fn header(&self) -> &Control {
        // Either the exclusive region or borrowed pool handle lifetime keeps
        // the initialized control live through every operation and its gate.
        unsafe { self.control.as_ref() }
    }
    fn lock(&self) -> Result<Guard<'_>, DirectoryError> {
        Guard::acquire(&self.header().gate)
    }
    fn head(&self, _guard: &Guard<'_>, index: usize) -> Head {
        debug_assert!(index < self.header().heads);
        unsafe {
            *(*self
                .control
                .as_ptr()
                .cast::<u8>()
                .add(self.header().heads_offset)
                .cast::<UnsafeCell<Head>>()
                .add(index))
            .get()
        }
    }
    fn write_head(&self, _guard: &Guard<'_>, index: usize, head: Head) {
        debug_assert!(index < self.header().heads);
        unsafe {
            (*self
                .control
                .as_ptr()
                .cast::<u8>()
                .add(self.header().heads_offset)
                .cast::<UnsafeCell<Head>>()
                .add(index))
            .get()
            .write(head);
        }
    }
    fn owner_pointer(&self, _guard: &Guard<'_>, index: usize) -> *mut Option<RegistryCell> {
        debug_assert!(index < self.header().heads);
        unsafe {
            (*self
                .control
                .as_ptr()
                .cast::<u8>()
                .add(self.header().owners_offset)
                .cast::<UnsafeCell<Option<RegistryCell>>>()
                .add(index))
            .get()
        }
    }
    fn take_owner(&self, guard: &Guard<'_>, index: usize) -> Option<RegistryCell> {
        // Move, never Copy/byte-clone, the one owner; preserve initialized None.
        unsafe { (&mut *self.owner_pointer(guard, index)).take() }
    }
    fn replace_owner(
        &self,
        guard: &Guard<'_>,
        index: usize,
        cell: RegistryCell,
    ) -> Option<RegistryCell> {
        unsafe { (&mut *self.owner_pointer(guard, index)).replace(cell) }
    }
    fn counts(&self, _guard: &Guard<'_>) -> Counts {
        unsafe { *self.header().counts.get() }
    }
    fn write_counts(&self, _guard: &Guard<'_>, counts: Counts) {
        unsafe { self.header().counts.get().write(counts) };
    }
    fn keys(&self) -> *mut u8 {
        unsafe {
            self.control
                .as_ptr()
                .cast::<u8>()
                .add(self.header().keys_offset)
        }
    }
    fn correlate(
        &self,
        guard: &Guard<'_>,
        origin: NativeOrigin<'_>,
        expected: Option<NativeHeadToken>,
    ) -> Result<(usize, Head), DirectoryError> {
        // Checking source scalar correlation first prevents accepting another
        // Store/install/epoch/key-kind by presenting a valid old token.
        if expected.is_some_and(|token| {
            token.store != origin.store
                || token.installation != origin.installation
                || token.epoch != origin.epoch
                || token.kind != origin.kind()
        }) {
            return Err(DirectoryError::Stale);
        }
        let index = self
            .find(guard, origin)
            .index
            .ok_or(DirectoryError::Missing)?;
        let head = self.head(guard, index);
        if expected.is_some_and(|token| token != head.token()) {
            return Err(DirectoryError::Stale);
        }
        Ok((index, head))
    }

    fn find_key(&self, guard: &Guard<'_>, origin: NativeOrigin<'_>) -> Search {
        self.find_with(guard, origin, false)
    }
    fn find(&self, guard: &Guard<'_>, origin: NativeOrigin<'_>) -> Search {
        self.find_with(guard, origin, true)
    }
    fn find_with(&self, guard: &Guard<'_>, origin: NativeOrigin<'_>, exact: bool) -> Search {
        let mut result = Search::default();
        for index in 0..self.header().heads {
            result.head_visits += 1;
            let head = self.head(guard, index);
            if head.uid == 0
                || head.store != origin.store
                || (exact && head.installation != origin.installation)
                || (exact && head.epoch != origin.epoch)
                || head.kind != origin.kind()
                || head.len != origin.bytes().len()
            {
                continue;
            }
            // Each disjoint stored extent is compared at most once. Total
            // comparison bytes <= CURRENT used key bytes, never name history.
            result.comparison_bytes += head.len;
            let bytes =
                unsafe { std::slice::from_raw_parts(self.keys().add(head.offset), head.len) };
            if bytes == origin.bytes() {
                result.index = Some(index);
                break;
            }
        }
        result
    }

    fn first_fit(&self, guard: &Guard<'_>, len: usize) -> ExtentSearch {
        let mut result = ExtentSearch::default();
        if len > self.header().key_bytes {
            return result;
        }
        if len == 0 {
            result.offset = Some(0);
            return result;
        }
        let mut candidate = 0;
        // At most H occupied intervals plus the trailing gap. No dynamic free
        // list, compaction, sort scratch or historical descriptor is needed.
        for _ in 0..=self.header().heads {
            let mut nearest: Option<Head> = None;
            for index in 0..self.header().heads {
                result.head_visits += 1;
                let head = self.head(guard, index);
                if head.uid != 0
                    && head.len != 0
                    && head.offset >= candidate
                    && nearest.is_none_or(|old| head.offset < old.offset)
                {
                    nearest = Some(head);
                }
            }
            let end = nearest.map_or(self.header().key_bytes, |head| head.offset);
            if len <= end - candidate {
                result.offset = Some(candidate);
                return result;
            }
            match nearest {
                Some(head) => candidate = head.offset + head.len,
                None => return result,
            }
        }
        result
    }
}
impl Drop for Directory<'_> {
    fn drop(&mut self) {
        if self.clear_on_drop {
            self.clear_exclusive();
        }
    }
}

#[derive(Default)]
struct Search {
    index: Option<usize>,
    head_visits: usize,
    comparison_bytes: usize,
}
#[derive(Default)]
struct ExtentSearch {
    offset: Option<usize>,
    head_visits: usize,
}
struct Guard<'a> {
    gate: &'a AtomicBool,
}
impl<'a> Guard<'a> {
    fn acquire(gate: &'a AtomicBool) -> Result<Self, DirectoryError> {
        gate.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| DirectoryError::Busy)?;
        Ok(Self { gate })
    }
}
impl Drop for Guard<'_> {
    fn drop(&mut self) {
        self.gate.store(false, Ordering::Release);
    }
}
// Standalone region or actual borrowed pool handle keeps backing initialized.
// Only SAME-gate access mutates heads/counts/keys/current owner slots. No raw
// pointers, guards, owner references or key borrows can escape safe operations.
unsafe impl Send for Directory<'_> {}
unsafe impl Sync for Directory<'_> {}

#[cfg(test)]
#[path = "directory/tests.rs"]
mod tests;
