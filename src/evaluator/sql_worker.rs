//! Fixed native HOST source-worker stack foundation; deliberately unintegrated.
//!
//! `StackExtentReady` certifies only the owned, page-rounded pthread stack and
//! guards. It is NOT a TLS/allocator/kernel/async/source-callgraph certificate.
//! No production NativeOwner implementation is supplied. Unknown admission
//! fails before mmap, pthread_create, source enrollment or a first read fence.
#![allow(dead_code)]

use super::{sql_control::JobControl, sqlite::SqlError};
use std::{alloc::Layout, marker::PhantomData, sync::Arc, sync::atomic::AtomicBool};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
))]
#[path = "sql_worker/linux.rs"]
mod linux;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
))]
#[allow(unused_imports)]
pub(crate) use linux::{NativeThread, WorkerFactory};

pub(crate) const APPROVED_WORKER_CEILING: usize = 1;

pub(crate) fn platform_gate() -> Result<(), WorkerError> {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_pointer_width = "64",
        target_env = "gnu"
    )) {
        Ok(())
    } else {
        Err(WorkerError::UnsupportedPlatform)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Hold {
    NativeOwnerNotInstalled,
    NativeTlsDtv,
    AllocatorBacking,
    KernelThread,
    AsyncFenceRuntime,
    SourceCallgraph,
    WholeHostPhysical,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkerError {
    Hold(Hold),
    UnsupportedPlatform,
    InvalidLayout,
    Overflow,
    Busy,
    MappingFailed,
    ProtectionFailed,
    Attributes(i32),
    AttributeCleanup(i32),
    Create(i32),
    StackMismatch,
    Wait(i32),
    Join(i32),
    Unmap(i32),
    NativePanic,
    InvalidState,
    Job(SqlError),
}
impl From<SqlError> for WorkerError {
    fn from(value: SqlError) -> Self {
        Self::Job(value)
    }
}

/// Caller supplies the already selected native stack size. No crypto estimate,
/// RUST_MIN_STACK, RLIMIT increase, fallback stack or unapproved extra budget.
#[derive(Clone, Copy, Debug)]
pub(crate) struct StackSpec {
    pub(crate) usable_bytes: usize,
}

/// Exact inline/native mapping layouts; malloc backing and kernel costs are NOT
/// encoded as guessed headers. The real owner must refuse those unknown terms.
#[derive(Clone, Copy, Debug)]
pub(crate) struct WorkerLayout {
    pub(crate) page_bytes: usize,
    pub(crate) stack_bytes: usize,
    pub(crate) guard_bytes_each: usize,
    pub(crate) stack_mapping_bytes: usize,
    pub(crate) control_layout: Layout,
    pub(crate) control_mapping_bytes: usize,
    pub(crate) task_layout: Layout,
    pub(crate) lease_layout: Layout,
    pub(crate) caller_handle_layout: Layout,
    pub(crate) explicit_mapping_bytes: usize,
}
impl WorkerLayout {
    pub(crate) fn round_pages(bytes: usize, page: usize) -> Result<usize, WorkerError> {
        if bytes == 0 || !page.is_power_of_two() {
            return Err(WorkerError::InvalidLayout);
        }
        bytes
            .checked_add(page - 1)
            .map(|n| n & !(page - 1))
            .ok_or(WorkerError::Overflow)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MapKind {
    StackAndGuards,
    ControlAndTask,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NativeEvent {
    Mapped {
        id: u64,
        kind: MapKind,
        address: usize,
        bytes: usize,
    },
    StackReady {
        stack_id: u64,
    },
    CallbackStarted,
    CallbackCleaned,
    Joined,
    Unmapped {
        id: u64,
        kind: MapKind,
        address: usize,
        bytes: usize,
    },
    CleanupUncertain,
}

/// Strong, non-cloneable lease for the ORIGINAL job plus actual node slot and
/// native allocation backing. Its Drop returns capacity only after both actual
/// munmaps. No boxed trait object, channel node, detached reaper or hidden pool.
///
/// # Safety
/// The lease must retain the real node/per-job owners; observing an event must
/// not panic, allocate unadmitted memory, create source refs or return credit.
/// IDs must be unique for this owner's actual mapping lifetimes (not VA alone).
pub(crate) unsafe trait NativeLease: Send + Sync + 'static {
    fn mapping_ids(&self) -> [u64; 2];
    fn observe(&self, _event: NativeEvent) {}
}

/// Must be provided by the one immutable process-node owner, never per Store.
/// This unsafe admission boundary is an ATTESTATION, not a resource verifier.
/// There is deliberately no serving implementation or positive default.
///
/// # Safety
/// `admit` must acquire the original job ticket and immutable ONE-worker slot
/// before any allocation, and include the exact layouts plus current libc's
/// native TLS/DTV/TCB/startup/attribute/destructor allocations, allocator backing,
/// signal/caller stacks, task/control moves, kernel clone/VMA/page-table/task
/// costs, physical/cgroup policy and any async-runtime machinery. Unknown =>
/// Hold, never zero or a margin. No new capacity may be fabricated. It must also
/// certify the complete trusted source callgraph (including depth128 code/cert/
/// JSON and paired8KiB keys) fits the actual usable stack AFTER native TLS/TCB.
/// `admit` and all its error paths are source-free, finite and already prepaid.
pub(crate) unsafe trait NativeOwner {
    type Lease: NativeLease;
    fn immutable_worker_ceiling(&self) -> usize;
    fn native_gate(&self, _layout: &WorkerLayout) -> Result<(), Hold> {
        Err(Hold::NativeOwnerNotInstalled)
    }
    fn admit(
        &self,
        layout: &WorkerLayout,
        original: &JobControl,
    ) -> Result<Self::Lease, WorkerError>;
}

/// The only bootstrap is closed, source-free native stack inspection. No fn
/// pointer, arbitrary closure, guest Wasm/code, credentials or source payload.
#[derive(Clone, Copy, Debug)]
pub(crate) enum WorkerBootstrap {
    InspectOwnedStack,
}

/// Observed by pthread_getattr_np on the ACTUAL worker before Ready. Native
/// custom stacks report libc guardsize0; our two PROT_NONE guards are owned
/// separately. `stack_bytes` includes glibc's in-stack TLS/TCB reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct StackExtentReady {
    pub(crate) stack_mapping_id: u64,
    pub(crate) stack_address: usize,
    pub(crate) stack_bytes: usize,
    pub(crate) native_reported_guard_bytes: usize,
    pub(crate) owned_guard_bytes_each: usize,
    pub(crate) stack_mapping_bytes: usize,
    pub(crate) control_mapping_id: u64,
}

/// Only issued after native owner admission AND real stack Ready AND an original
/// job-control check. Borrow prevents overlapping source-enrollment/control use.
/// This token does not certify source-root GC or dynamic source retention.
pub(crate) struct SourceEnrollment<'a> {
    pub(crate) extent: StackExtentReady,
    pub(crate) original: &'a mut JobControl,
    pub(super) _private: PhantomData<&'a mut ()>,
}

/// Closed trusted native capture task, inline in prepaid storage, never a guest
/// selected function or Box<dyn Fn>. Controller/source owners supply concrete
/// typed implementations only AFTER obtaining SourceEnrollment.
///
/// # Safety
/// No source ref/fence may be created before enrollment. All source/certificate/
/// identity/copy/controller paths use this SAME `original` (including work
/// counters stored in the concrete task), never renew time/work on retry.
/// All data/drop/panic/async machinery must fit the admitted native profile and
/// callgraph; Send+'static requires genuinely owned references, not transmuted
/// borrowed lifetimes. Cleanup must release all source refs before returning.
pub(crate) unsafe trait TrustedCaptureTask: Send + 'static {
    fn run(self, original: &mut JobControl, extent: StackExtentReady) -> Result<(), WorkerError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub(crate) callback: Result<(), WorkerError>,
    pub(crate) extent: StackExtentReady,
}

/// Kept separate from worker storage: this is the original preadmitted Arc, not
/// a freshly allocated cancellation channel or independent retry control.
fn original_cancellation(original: &JobControl) -> Arc<AtomicBool> {
    Arc::clone(original.cancellation())
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_pointer_width = "64",
    target_env = "gnu"
))]
#[path = "sql_worker/tests.rs"]
mod tests;
