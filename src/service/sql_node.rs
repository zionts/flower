//! The independently constructible admission/baseline part of node resources.
//!
//! This is NOT a native-ready `NodeResources` constructor. The actual source
//! RegistryPool, Store/Consensus constructors and cancellation static-region
//! owner must be coupled before startup can use it. No serving path calls this
//! module yet. A byte reservation is not an RSS/mlock/allocator-backing proof.
//!
//! The approved 16 MiB baseline is permanently carved from USER preparation
//! capacity, not added to it. Every native allocation must acquire a strong
//! baseline lease before allocation and retain it until AFTER its final unmap /
//! owner cleanup. A single source mapping can be admitted, never a replacement
//! pool or a per-router pool. Source cells, staging and replacement witnesses
//! must all use that one source-owned mapping.
use super::admission::Pool;
use std::{
    alloc::Layout,
    fmt,
    ptr::NonNull,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

pub(crate) const NODE_BASELINE_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_REGISTRY_CELLS: usize = 256;
pub(crate) const MAX_CANCEL_SLOTS: usize = 128;

/// Immutable startup limits. Operators may only lower the approved ceilings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeLimits {
    pub(crate) registry_bytes: usize,
    pub(crate) registry_cells: usize,
    pub(crate) cancel_slots: usize,
}
impl Default for NodeLimits {
    fn default() -> Self {
        Self {
            registry_bytes: NODE_BASELINE_BYTES,
            registry_cells: MAX_REGISTRY_CELLS,
            cancel_slots: MAX_CANCEL_SLOTS,
        }
    }
}
impl NodeLimits {
    /// Parse only at startup; never reload or increase an existing owner. Error
    /// text names settings but deliberately never echoes environment values.
    pub(crate) fn from_env() -> Result<Self, NodeResourceError> {
        fn lower(name: &str, maximum: usize) -> Result<usize, NodeResourceError> {
            match std::env::var(name) {
                Ok(value) => value
                    .parse::<usize>()
                    .ok()
                    .filter(|value| *value > 0 && *value <= maximum)
                    .ok_or(NodeResourceError::InvalidLimits),
                Err(std::env::VarError::NotPresent) => Ok(maximum),
                Err(std::env::VarError::NotUnicode(_)) => Err(NodeResourceError::InvalidLimits),
            }
        }
        Self {
            registry_bytes: lower("FLOWER_SQL_REGISTRY_BYTES", NODE_BASELINE_BYTES)?,
            registry_cells: lower("FLOWER_SQL_REGISTRY_CELLS", MAX_REGISTRY_CELLS)?,
            cancel_slots: lower("FLOWER_SQL_CANCELLATION_SLOTS", MAX_CANCEL_SLOTS)?,
        }
        .validate()
    }
    pub(crate) fn validate(self) -> Result<Self, NodeResourceError> {
        if self.registry_bytes == 0
            || self.registry_bytes > NODE_BASELINE_BYTES
            || self.registry_cells == 0
            || self.registry_cells > MAX_REGISTRY_CELLS
            || self.cancel_slots == 0
            || self.cancel_slots > MAX_CANCEL_SLOTS
        {
            return Err(NodeResourceError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Existing preparation classes, copied once by the eventual startup owner.
/// `per_job` is the existing whole evaluation reservation (including enabled
/// native SQL); this component never removes its legacy blanket allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AdmissionConfig {
    pub(crate) workers: [usize; 3],
    pub(crate) memory: [usize; 3],
    pub(crate) input: [usize; 3],
    pub(crate) per_job: usize,
}
impl AdmissionConfig {
    pub(crate) fn configured() -> anyhow::Result<Self> {
        let settings = super::tuning::settings()?;
        let evaluator = crate::evaluator::config::settings()?;
        Ok(Self {
            workers: [
                settings.preparation_workers,
                settings.control_workers,
                settings.deployment_workers,
            ],
            memory: [
                settings.preparation_memory_bytes,
                settings.control_memory_bytes,
                settings.deployment_memory_bytes,
            ],
            input: [
                settings.queued_bytes,
                settings.control_queued_bytes,
                settings.control_queued_bytes,
            ],
            per_job: super::tuning::evaluation_memory_bytes(
                evaluator.guest_memory_bytes,
                evaluator.rust_memory_bytes,
            )?,
        })
    }
    fn carved(self) -> Result<Self, NodeResourceError> {
        if self.per_job == 0 || self.workers.contains(&0) || self.input.contains(&0) {
            return Err(NodeResourceError::InvalidAdmission);
        }
        let Some(remaining) = self.memory[0].checked_sub(NODE_BASELINE_BYTES) else {
            return Err(NodeResourceError::InsufficientUserMemory {
                configured: self.memory[0],
                per_job: self.per_job,
            });
        };
        if remaining < self.per_job {
            return Err(NodeResourceError::InsufficientUserMemory {
                configured: self.memory[0],
                per_job: self.per_job,
            });
        }
        if self.memory[1..].iter().any(|bytes| *bytes < self.per_job) {
            return Err(NodeResourceError::InsufficientReservedClassMemory);
        }
        Ok(Self {
            memory: [remaining, self.memory[1], self.memory[2]],
            ..self
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NodeResourceError {
    InvalidLimits,
    InvalidAdmission,
    InsufficientUserMemory { configured: usize, per_job: usize },
    InsufficientReservedClassMemory,
    UnsupportedPlatform,
    LayoutOverflow,
    BaselineExhausted,
    RegistryAlreadyIssued,
    InvalidRegistryReservation,
    MappingFailed,
    Poisoned,
    OwnerCounterExhausted,
}
impl fmt::Display for NodeResourceError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientUserMemory { configured, per_job } => write!(
                out,
                "FLOWER_PREPARATION_MEMORY_BYTES={configured} cannot fit the immutable {NODE_BASELINE_BYTES}-byte node registry/control baseline plus one {per_job}-byte existing evaluation reservation; the remaining USER budget must fit one job (a one-worker default is insufficient); explicitly configure enough memory or refuse SQL startup, never auto-increase it"
            ),
            Self::InvalidLimits => out.write_str("SQL node limits must be positive and may only lower the hard 16 MiB / 256 registry cells / 128 cancellation slots ceilings"),
            Self::InvalidAdmission => out.write_str("node admission requires positive workers, queued-input budgets and per-job bytes"),
            Self::InsufficientReservedClassMemory => out.write_str("existing CONTROL and DEPLOYMENT budgets must each fit one existing evaluation reservation"),
            Self::UnsupportedPlatform => out.write_str("SQL node baseline mapping requires Linux x86-64 and a valid native page size"),
            Self::LayoutOverflow => out.write_str("SQL node native allocation layout overflow"),
            Self::BaselineExhausted => out.write_str("SQL node registry/control baseline exhausted; no extra pool or capacity increase is allowed"),
            Self::RegistryAlreadyIssued => out.write_str("the node's one source registry mapping was already issued; it cannot be recreated or reset"),
            Self::InvalidRegistryReservation => out.write_str("source registry reservation must fit its actual mapped bytes and immutable cell ceiling"),
            Self::MappingFailed => out.write_str("SQL node baseline control mapping failed before native source construction"),
            Self::Poisoned => out.write_str("SQL node baseline ledger poisoned"),
            Self::OwnerCounterExhausted => out.write_str("SQL node baseline strong owner counter exhausted"),
        }
    }
}
impl std::error::Error for NodeResourceError {}

/// Exact requested Arc allocation layout, not a claim about malloc's retained
/// arenas/pages. ArcInner is repr(C), two AtomicUsize counters followed by data
/// in the pinned native toolchain. A native allocator probe must check this
/// against the real Arc<Pool> request; wider allocator backing remains HOLD.
#[repr(C)]
struct ArcAllocation<T> {
    strong: AtomicUsize,
    weak: AtomicUsize,
    value: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocationLayout {
    pub(crate) control_layout: Layout,
    pub(crate) control_mapped_bytes: usize,
    pub(crate) admission_arc_requested_layout: Layout,
    pub(crate) associated_lease_layout: Layout,
    pub(crate) page_bytes: usize,
}
impl AllocationLayout {
    pub(crate) fn native() -> Result<Self, NodeResourceError> {
        if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            return Err(NodeResourceError::UnsupportedPlatform);
        }
        #[cfg(target_os = "linux")]
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        #[cfg(not(target_os = "linux"))]
        let page = -1;
        let page_bytes = usize::try_from(page)
            .ok()
            .filter(|page| page.is_power_of_two() && *page >= Layout::new::<Control>().align())
            .ok_or(NodeResourceError::UnsupportedPlatform)?;
        Ok(Self {
            control_layout: Layout::new::<Control>(),
            control_mapped_bytes: round_pages(Layout::new::<Control>().size(), page_bytes)?,
            admission_arc_requested_layout: Layout::new::<ArcAllocation<Pool>>(),
            associated_lease_layout: Layout::new::<BaselineLease>(),
            page_bytes,
        })
    }
}

/// Exact page span of a REAL region, including its actual starting-page offset.
/// Native owners must provide their actual static/mapped address and extent.
/// A sizeof-only cancellation constant cannot prove this value.
pub(crate) fn region_page_bytes(
    address: usize,
    bytes: usize,
    page: usize,
) -> Result<usize, NodeResourceError> {
    if bytes == 0 || !page.is_power_of_two() {
        return Err(NodeResourceError::LayoutOverflow);
    }
    address
        .checked_add(bytes)
        .ok_or(NodeResourceError::LayoutOverflow)?;
    let span = (address & (page - 1))
        .checked_add(bytes)
        .ok_or(NodeResourceError::LayoutOverflow)?;
    round_pages(span, page)
}
fn round_pages(bytes: usize, page: usize) -> Result<usize, NodeResourceError> {
    if bytes == 0 || !page.is_power_of_two() {
        return Err(NodeResourceError::LayoutOverflow);
    }
    bytes
        .checked_add(page - 1)
        .map(|bytes| bytes & !(page - 1))
        .ok_or(NodeResourceError::LayoutOverflow)
}

struct Accounting {
    native_constant_bytes: usize,
    registry_bytes: usize,
    registry_cells: usize,
    registry_ever_issued: bool,
}
struct Control {
    owners: AtomicUsize,
    accounting: Mutex<Accounting>,
    limits: NodeLimits,
    page_bytes: usize,
    control_mapped_bytes: usize,
    admission_arc_requested_bytes: usize,
}
struct StrongOwner(NonNull<Control>);
// The mapping contains only immutable limits, a mutex and atomic owner count.
// Every pointer handle owns a counted reference; no weak pointer can survive it.
unsafe impl Send for StrongOwner {}
unsafe impl Sync for StrongOwner {}
impl StrongOwner {
    fn control(&self) -> &Control {
        unsafe { self.0.as_ref() }
    }
    fn try_clone(&self) -> Result<Self, NodeResourceError> {
        let mut count = self.control().owners.load(Ordering::Relaxed);
        loop {
            let next = count
                .checked_add(1)
                .filter(|count| *count <= isize::MAX as usize)
                .ok_or(NodeResourceError::OwnerCounterExhausted)?;
            match self.control().owners.compare_exchange_weak(
                count,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(Self(self.0)),
                Err(current) => count = current,
            }
        }
    }
}
impl Drop for StrongOwner {
    fn drop(&mut self) {
        if self.control().owners.fetch_sub(1, Ordering::Release) == 1 {
            std::sync::atomic::fence(Ordering::Acquire);
            let bytes = self.control().control_mapped_bytes;
            unsafe {
                std::ptr::drop_in_place(self.0.as_ptr());
                // Leak rather than mint capacity if a native unmap fails. There
                // is no retry/new registry mapping and no baseline credit path.
                let _ = libc::munmap(self.0.as_ptr().cast(), bytes);
            }
        }
    }
}

/// Finished shared-admission component, deliberately not the complete node.
/// Clone handles through `try_clone`; they share BOTH the ledger and real Pool.
/// The eventual native NodeResources owns this before opening any Store.
pub(crate) struct NodeAdmission {
    // Field drop order: the real Pool owner is cleaned up before the last node
    // mapping, not after the baseline owner disappears.
    admission: Arc<Pool>,
    owner: StrongOwner,
    configured_user_bytes: usize,
    remaining_user_bytes: usize,
    per_job: usize,
}
impl NodeAdmission {
    pub(crate) fn prepare(
        config: AdmissionConfig,
        limits: NodeLimits,
    ) -> Result<Self, NodeResourceError> {
        // Complete numeric/layout preflight BEFORE mmap, Pool construction, any
        // Store open, listener bind or liveness publication. No defaults change.
        let limits = limits.validate()?;
        let carved = config.carved()?;
        let layout = AllocationLayout::native()?;
        let initial = layout
            .control_mapped_bytes
            .checked_add(layout.admission_arc_requested_layout.size())
            .filter(|bytes| *bytes < limits.registry_bytes)
            .ok_or(NodeResourceError::BaselineExhausted)?;
        let _ = initial;
        #[cfg(target_os = "linux")]
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                layout.control_mapped_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let pointer = libc::MAP_FAILED;
        if pointer == libc::MAP_FAILED {
            return Err(NodeResourceError::MappingFailed);
        }
        let Some(pointer) = NonNull::new(pointer.cast::<Control>()) else {
            unsafe {
                libc::munmap(pointer, layout.control_mapped_bytes);
            }
            return Err(NodeResourceError::MappingFailed);
        };
        unsafe {
            // Every mapped page is written before publishing any owner. This
            // is physical pre-touch, not an mlock/RSS/kernel entitlement claim.
            for offset in (0..layout.control_mapped_bytes).step_by(layout.page_bytes) {
                std::ptr::write_volatile(pointer.as_ptr().cast::<u8>().add(offset), 0);
            }
            pointer.as_ptr().write(Control {
                owners: AtomicUsize::new(1),
                accounting: Mutex::new(Accounting {
                    native_constant_bytes: 0,
                    registry_bytes: 0,
                    registry_cells: 0,
                    registry_ever_issued: false,
                }),
                limits,
                page_bytes: layout.page_bytes,
                control_mapped_bytes: layout.control_mapped_bytes,
                admission_arc_requested_bytes: layout.admission_arc_requested_layout.size(),
            });
        }
        let owner = StrongOwner(pointer);
        let admission =
            Pool::with_deployment(carved.workers, carved.memory, carved.input, carved.per_job);
        Ok(Self {
            admission,
            owner,
            configured_user_bytes: config.memory[0],
            remaining_user_bytes: carved.memory[0],
            per_job: config.per_job,
        })
    }
    pub(crate) fn try_clone(&self) -> Result<Self, NodeResourceError> {
        let owner = self.owner.try_clone()?;
        Ok(Self {
            admission: self.admission.clone(),
            owner,
            configured_user_bytes: self.configured_user_bytes,
            remaining_user_bytes: self.remaining_user_bytes,
            per_job: self.per_job,
        })
    }
    pub(super) fn admission(&self) -> Arc<Pool> {
        self.admission.clone()
    }

    /// Prepay an actual native constant/control allocation. This ticket must be
    /// installed in its real owner BEFORE a numeric unsafe native initializer is
    /// called; the number itself is NOT proof. Exact static page spans and token
    /// Arc/owner allocation layouts still need the cancellation owner's API.
    pub(crate) fn reserve_native_constant(
        &self,
        bytes: usize,
    ) -> Result<BaselineLease, NodeResourceError> {
        self.reserve(bytes, 0, false)
    }
    /// Inherent budget seam only: NOT an assumed RegistryAdmission trait impl.
    /// The real RegistryPool must supply its exact page-rounded mapping bytes,
    /// including its own control + this associated INLINE lease's real Layout.
    /// Its final munmap MUST precede dropping the returned non-cloneable lease.
    pub(crate) fn reserve_registry_mapping(
        &self,
        bytes: usize,
        cells: usize,
    ) -> Result<BaselineLease, NodeResourceError> {
        self.reserve(bytes, cells, true)
    }
    fn reserve(
        &self,
        bytes: usize,
        cells: usize,
        registry: bool,
    ) -> Result<BaselineLease, NodeResourceError> {
        let control = self.owner.control();
        if bytes == 0
            || (registry
                && (cells == 0
                    || cells > control.limits.registry_cells
                    || !bytes.is_multiple_of(control.page_bytes)))
        {
            return Err(NodeResourceError::InvalidRegistryReservation);
        }
        // Clone strong ownership before changing accounting; failure never
        // leaves a booked allocation with no owner.
        let owner = self.owner.try_clone()?;
        let mut state = control
            .accounting
            .lock()
            .map_err(|_| NodeResourceError::Poisoned)?;
        if registry && state.registry_ever_issued {
            return Err(NodeResourceError::RegistryAlreadyIssued);
        }
        let constants = state
            .native_constant_bytes
            .checked_add(if registry { 0 } else { bytes })
            .ok_or(NodeResourceError::LayoutOverflow)?;
        let registry_bytes = if registry {
            bytes
        } else {
            state.registry_bytes
        };
        control
            .control_mapped_bytes
            .checked_add(control.admission_arc_requested_bytes)
            .and_then(|total| total.checked_add(constants))
            .and_then(|total| total.checked_add(registry_bytes))
            .filter(|total| *total <= control.limits.registry_bytes)
            .ok_or(NodeResourceError::BaselineExhausted)?;
        state.native_constant_bytes = constants;
        if registry {
            state.registry_bytes = bytes;
            state.registry_cells = cells;
            state.registry_ever_issued = true;
        }
        drop(state);
        Ok(BaselineLease {
            admission: self.admission.clone(),
            owner,
            bytes,
            cells,
            registry,
        })
    }
    /// Budget available for the source's layout calculation AFTER all actual
    /// other constant/control/page reservations. Not a layout or readiness proof.
    pub(crate) fn remaining_registry_limits(&self) -> Result<(usize, usize), NodeResourceError> {
        let control = self.owner.control();
        let state = control
            .accounting
            .lock()
            .map_err(|_| NodeResourceError::Poisoned)?;
        if state.registry_ever_issued {
            return Err(NodeResourceError::RegistryAlreadyIssued);
        }
        let used = control
            .control_mapped_bytes
            .checked_add(control.admission_arc_requested_bytes)
            .and_then(|bytes| bytes.checked_add(state.native_constant_bytes))
            .ok_or(NodeResourceError::LayoutOverflow)?;
        Ok((
            control
                .limits
                .registry_bytes
                .checked_sub(used)
                .ok_or(NodeResourceError::BaselineExhausted)?,
            control.limits.registry_cells,
        ))
    }
    pub(crate) fn metrics(&self) -> serde_json::Value {
        let control = self.owner.control();
        let state = control.accounting.lock().ok();
        serde_json::json!({
            "construction": "ADMISSION_ONLY_NATIVE_SOURCE_AND_CANCELLATION_HOLD",
            "configuredUserMemoryBytes": self.configured_user_bytes,
            "baselineReservedBytes": NODE_BASELINE_BYTES,
            "remainingUserMemoryBytes": self.remaining_user_bytes,
            "perJobReservationBytes": self.per_job,
            "controlMappedBytes": control.control_mapped_bytes,
            "admissionArcRequestedBytes": control.admission_arc_requested_bytes,
            "nativeConstantReservedBytes": state.as_ref().map(|state| state.native_constant_bytes),
            "registryMappedReservedBytes": state.as_ref().filter(|state| state.registry_ever_issued).map(|state| state.registry_bytes),
            "registryReservedCells": state.as_ref().filter(|state| state.registry_ever_issued).map(|state| state.registry_cells),
            "registryByteCeiling": control.limits.registry_bytes,
            "registryCellCeiling": control.limits.registry_cells,
            "cancellationSlotCeiling": control.limits.cancel_slots,
            "cancellationStaticPageBytes": Option::<usize>::None,
            "allocatorBacking": "HOLD"
        })
    }
}

/// Strong prepaid baseline ownership, including the REAL shared admission pool.
/// No Weak, per-lease Box/Arc allocation, capacity reset, or independent pool.
/// It is intentionally non-cloneable: source stores ONE lease inline in its ONE
/// mapped PoolControl; the source primitive controls all pointer handle clones.
pub(crate) struct BaselineLease {
    admission: Arc<Pool>,
    owner: StrongOwner,
    bytes: usize,
    cells: usize,
    registry: bool,
}
impl BaselineLease {
    pub(crate) fn reserved_bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn reserved_cells(&self) -> usize {
        self.cells
    }
}
impl Drop for BaselineLease {
    fn drop(&mut self) {
        // Native memory cleanup must already have happened in the owning
        // component. On poison leave accounting charged; never invent credits.
        if let Ok(mut state) = self.owner.control().accounting.lock() {
            if self.registry {
                state.registry_bytes -= self.bytes;
                state.registry_cells -= self.cells;
                // registry_ever_issued stays true: no second mapping/new cap.
            } else {
                state.native_constant_bytes -= self.bytes;
            }
        }
        // Strong Pool/ledger fields drop only after this typed ticket's Drop.
        // The immutable USER carve is NEVER returned while a Pool exists.
        let _ = &self.admission;
    }
}

#[cfg(test)]
#[path = "sql_node/tests.rs"]
mod tests;
