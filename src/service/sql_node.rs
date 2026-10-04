//! Permanent mapped admission/baseline bootstrap, NOT a native-ready node.
//!
//! ONE process-global startup attempt publishes ONE page-rounded, pre-touched
//! mmap containing the actual admission::Pool BY VALUE and its native ledger.
//! No native Arc/Box allocator backing, deallocation, reset or per-router pool.
//! Startup/source/Store/cancellation wiring remains HOLD until the parent couples
//! their real owner APIs, BEFORE ANY Store open or listener/liveness publication.
//! The existing 16 MiB USER carve and 432 MiB job reservation remain unchanged.
use super::admission::{Owner, Pool, StrongInput};
use std::{
    alloc::Layout,
    fmt,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
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
    BootstrapMissing,
    BootstrapFailed,
    BootstrapMismatch,
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
            Self::MappingFailed => out.write_str("SQL node admission/ledger mapping failed before native source construction"),
            Self::Poisoned => out.write_str("SQL node baseline ledger poisoned"),
            Self::BootstrapMissing => out.write_str("SQL node admission bootstrap is missing; native construction is HOLD"),
            Self::BootstrapFailed => out.write_str("SQL node admission bootstrap already failed or unwound; no retry/reset is allowed"),
            Self::BootstrapMismatch => out.write_str("SQL node admission bootstrap is immutable; a different configuration/limits cannot create another pool"),
        }
    }
}
impl std::error::Error for NodeResourceError {}

/// Report actual caller-inline layouts. These are not invented page spans:
/// a source/caller must include its inline owner/lease in its REAL owned mapping
/// or stack allowance. The source mapping reservation includes its inline lease.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AllocationLayout {
    pub(crate) pool_layout: Layout,
    pub(crate) control_layout: Layout,
    pub(crate) mapping_layout: Layout,
    pub(crate) mapped_bytes: usize,
    pub(crate) node_handle_layout: Layout,
    pub(crate) admission_handle_layout: Layout,
    pub(crate) strong_input_layout: Layout,
    pub(crate) associated_lease_layout: Layout,
    pub(crate) bootstrap_region: StaticRegion,
    pub(crate) page_bytes: usize,
}
/// Actual address, sizeof/alignment and page span of the live GLOBAL object.
/// Parent must union overlapping source-bootstrap/cancellation static pages with
/// this span, not charge sizeof-aligned fiction or silently grow the baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StaticRegion {
    pub(crate) address: usize,
    pub(crate) layout: Layout,
    pub(crate) page_start: usize,
    pub(crate) page_end: usize,
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
            .filter(|page| {
                page.is_power_of_two() && *page >= Layout::new::<NativeMapping>().align()
            })
            .ok_or(NodeResourceError::UnsupportedPlatform)?;
        let address = std::ptr::from_ref(&GLOBAL).addr();
        let layout = Layout::new::<Bootstrap>();
        let page_start = address & !(page_bytes - 1);
        let span_bytes = region_page_bytes(address, layout.size(), page_bytes)?;
        let bootstrap_region = StaticRegion {
            address,
            layout,
            page_start,
            page_end: page_start
                .checked_add(span_bytes)
                .ok_or(NodeResourceError::LayoutOverflow)?,
            page_bytes: span_bytes,
        };
        Ok(Self {
            pool_layout: Layout::new::<Pool>(),
            control_layout: Layout::new::<Control>(),
            mapping_layout: Layout::new::<NativeMapping>(),
            mapped_bytes: round_pages(Layout::new::<NativeMapping>().size(), page_bytes)?,
            node_handle_layout: Layout::new::<NodeAdmission>(),
            admission_handle_layout: Layout::new::<Owner>(),
            strong_input_layout: Layout::new::<StrongInput>(),
            associated_lease_layout: Layout::new::<BaselineLease>(),
            bootstrap_region,
            page_bytes,
        })
    }
}

/// Exact page span of a REAL region, including its starting-page offset.
/// Arithmetic only, NOT an unsafe numeric native-readiness verifier.
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
    accounting: Mutex<Accounting>,
    limits: NodeLimits,
    config: AdmissionConfig,
    layout: AllocationLayout,
}
#[repr(C)]
struct NativeMapping {
    admission: Pool,
    control: Control,
}
struct Bootstrap {
    // OnceLock normally retries after an initializer unwinds. The attempt flag
    // forbids such a retry from mmap'ing/minting another admission owner.
    attempted: AtomicBool,
    result: OnceLock<Result<NodeAdmission, NodeResourceError>>,
}
static GLOBAL: Bootstrap = Bootstrap {
    attempted: AtomicBool::new(false),
    result: OnceLock::new(),
};

/// Native handle to the permanent mapping. The GLOBAL holds the original handle
/// for process life; all clones/leases borrow the SAME actual mapped Pool.
/// Deliberately no Drop/unmap, refactory, reset or native-ready constructor.
#[derive(Clone, Copy)]
pub(crate) struct NodeAdmission {
    owner: &'static NativeMapping,
}
impl NodeAdmission {
    /// Startup-only attempt. Repeated matching calls borrow the published owner;
    /// failure is latched, mismatches refuse, and no path creates another Pool.
    /// Parent must call this BEFORE ANY Store. No serving path is wired here.
    pub(crate) fn prepare(
        config: AdmissionConfig,
        limits: NodeLimits,
    ) -> Result<&'static Self, NodeResourceError> {
        let result = GLOBAL.result.get_or_init(|| {
            if GLOBAL.attempted.swap(true, Ordering::AcqRel) {
                return Err(NodeResourceError::BootstrapFailed);
            }
            Self::prepare_once(config, limits)
        });
        let node = result.as_ref().map_err(|error| *error)?;
        if node.owner.control.config != config || node.owner.control.limits != limits {
            return Err(NodeResourceError::BootstrapMismatch);
        }
        Ok(node)
    }
    /// Never lazily creates an owner. Missing/bad bootstrap is native HOLD.
    pub(crate) fn global() -> Result<&'static Self, NodeResourceError> {
        GLOBAL
            .result
            .get()
            .ok_or(NodeResourceError::BootstrapMissing)?
            .as_ref()
            .map_err(|error| *error)
    }
    fn prepare_once(
        config: AdmissionConfig,
        limits: NodeLimits,
    ) -> Result<Self, NodeResourceError> {
        // Complete preflight BEFORE any mmap, Store open, bind or publication.
        let limits = limits.validate()?;
        let carved = config.carved()?;
        let layout = AllocationLayout::native()?;
        layout
            .mapped_bytes
            .checked_add(layout.bootstrap_region.page_bytes)
            .filter(|bytes| *bytes < limits.registry_bytes)
            .ok_or(NodeResourceError::BaselineExhausted)?;
        #[cfg(target_os = "linux")]
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                layout.mapped_bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let pointer = libc::MAP_FAILED;
        if pointer == libc::MAP_FAILED || pointer.is_null() {
            // Never retry or invent capacity. Even a bizarre successful null
            // mapping is conservatively retained, not deallocated/recreated.
            return Err(NodeResourceError::MappingFailed);
        }
        let pointer = pointer.cast::<NativeMapping>();
        unsafe {
            for offset in (0..layout.mapped_bytes).step_by(layout.page_bytes) {
                std::ptr::write_volatile(pointer.cast::<u8>().add(offset), 0);
            }
            pointer.write(NativeMapping {
                // Actual constructor is BY VALUE; no Arc::new then hidden heap.
                admission: Pool::value(carved.workers, carved.memory, carved.input, carved.per_job),
                control: Control {
                    accounting: Mutex::new(Accounting {
                        native_constant_bytes: 0,
                        registry_bytes: 0,
                        registry_cells: 0,
                        registry_ever_issued: false,
                    }),
                    limits,
                    config,
                    layout,
                },
            });
            // The sole successful mapping is never dropped or unmapped. This
            // reference is valid for process life, including after all callers
            // disappear. GLOBAL publication supplies synchronized visibility.
            Ok(Self { owner: &*pointer })
        }
    }
    pub(crate) fn try_clone(&self) -> Result<Self, NodeResourceError> {
        Ok(*self)
    }
    pub(super) fn admission(&self) -> Owner {
        Owner::NativeStatic(&self.owner.admission)
    }
    pub(crate) fn allocation_layout(&self) -> AllocationLayout {
        self.owner.control.layout
    }

    /// Numeric bookkeeping seam only, NOT native readiness. Parent supplies
    /// real owner-linked constant/page reservations before allocation and unions
    /// their actual static spans. All charges remain permanent even if a ticket
    /// is dropped: uncertain cleanup cannot mint credit or a replacement pool.
    pub(crate) fn reserve_native_constant(
        &self,
        bytes: usize,
    ) -> Result<BaselineLease, NodeResourceError> {
        self.reserve(bytes, 0, false)
    }
    /// The actual source must include its own control + this INLINE lease's real
    /// Layout in its page-rounded mapping bytes. Exactly one mapping, ever.
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
        let control = &self.owner.control;
        if bytes == 0
            || (registry
                && (cells == 0
                    || cells > control.limits.registry_cells
                    || !bytes.is_multiple_of(control.layout.page_bytes)))
        {
            return Err(NodeResourceError::InvalidRegistryReservation);
        }
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
            .layout
            .mapped_bytes
            .checked_add(control.layout.bootstrap_region.page_bytes)
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
        Ok(BaselineLease {
            admission: self.admission(),
            owner: self.owner,
            bytes,
            cells,
            registry,
        })
    }
    /// Remaining same-16-MiB source budget, AFTER real mapping/GLOBAL span and
    /// prior actual constants. Not a physical/native/ready claim.
    pub(crate) fn remaining_registry_limits(&self) -> Result<(usize, usize), NodeResourceError> {
        let control = &self.owner.control;
        let state = control
            .accounting
            .lock()
            .map_err(|_| NodeResourceError::Poisoned)?;
        if state.registry_ever_issued {
            return Err(NodeResourceError::RegistryAlreadyIssued);
        }
        let used = control
            .layout
            .mapped_bytes
            .checked_add(control.layout.bootstrap_region.page_bytes)
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
        let control = &self.owner.control;
        let layout = control.layout;
        let state = control.accounting.lock().ok();
        serde_json::json!({
            "construction": "MAPPED_ADMISSION_ONLY_SOURCE_CANCELLATION_STARTUP_HOLD",
            "configuredUserMemoryBytes": control.config.memory[0],
            "baselineReservedBytes": NODE_BASELINE_BYTES,
            "remainingUserMemoryBytes": control.config.memory[0] - NODE_BASELINE_BYTES,
            "perJobReservationBytes": control.config.per_job,
            "admissionPoolBytes": layout.pool_layout.size(),
            "admissionPoolAlign": layout.pool_layout.align(),
            "controlBytes": layout.control_layout.size(),
            "controlAlign": layout.control_layout.align(),
            "ownedMappingBytes": layout.mapped_bytes,
            "ownedMappingAddress": std::ptr::from_ref(self.owner).addr(),
            "globalStaticAddress": layout.bootstrap_region.address,
            "globalStaticBytes": layout.bootstrap_region.layout.size(),
            "globalStaticAlign": layout.bootstrap_region.layout.align(),
            "globalStaticPageStart": layout.bootstrap_region.page_start,
            "globalStaticPageEnd": layout.bootstrap_region.page_end,
            "globalStaticPageBytes": layout.bootstrap_region.page_bytes,
            "callerNodeHandleBytes": layout.node_handle_layout.size(),
            "callerAdmissionHandleBytes": layout.admission_handle_layout.size(),
            "callerStrongInputBytes": layout.strong_input_layout.size(),
            "sourceInlineLeaseBytes": layout.associated_lease_layout.size(),
            "nativeConstantReservedBytes": state.as_ref().map(|state| state.native_constant_bytes),
            "registryMappedReservedBytes": state.as_ref().filter(|state| state.registry_ever_issued).map(|state| state.registry_bytes),
            "registryReservedCells": state.as_ref().filter(|state| state.registry_ever_issued).map(|state| state.registry_cells),
            "registryByteCeiling": control.limits.registry_bytes,
            "registryCellCeiling": control.limits.registry_cells,
            "cancellationSlotCeiling": control.limits.cancel_slots,
            "cancellationStaticPageBytes": Option::<usize>::None,
            "poolOwnership": "PROCESS_LIFETIME_ACTUAL_MMAP",
            "nativePhysicalAggregate": "HOLD"
        })
    }
}

/// Strong actual permanent Pool + ledger ownership. No heap allocation or Weak;
/// source places ONE non-cloneable lease inline in its REAL mapped control.
/// NO refund on Drop: cleanup/unmap uncertainty never produces fake credit.
pub(crate) struct BaselineLease {
    admission: Owner,
    owner: &'static NativeMapping,
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
    pub(crate) fn is_registry_mapping(&self) -> bool {
        self.registry
    }
    pub(crate) fn admission(&self) -> Owner {
        self.admission.clone()
    }
    pub(crate) fn allocation_layout(&self) -> AllocationLayout {
        self.owner.control.layout
    }
}

#[cfg(test)]
#[path = "sql_node/tests.rs"]
mod tests;
