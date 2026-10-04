//! Detached, root-free SQL callback host. Never connected to serving APIs here.
//!
//! Guest bytes cannot select a phase, invoker, privilege mode or source owner.
//! Exactly two caller-admitted WireArena mappings hold arguments and outcomes;
//! all source/metadata/policy values borrow an already-owned FrameBuilder.
//! Native controller certification, capture replay and physical admission remain
//! separate gates. See sql_host/API.md, including the fatal-error adapter gate.
#[path = "sql_host/authority.rs"]
mod authority;
#[path = "sql_host/capture.rs"]
mod capture;
pub(crate) use capture::{NativeCapture, NativeCaptureCollection, NativeCaptureRow};
#[path = "sql_host/copy.rs"]
mod copy;
#[path = "sql_host/provider.rs"]
mod provider;
#[path = "sql_host/read.rs"]
mod read;
#[path = "sql_host/temporal.rs"]
pub(crate) mod temporal;
pub(crate) use authority::{ClosedAuthorityPermit, NativeAuthorityExecution};
use temporal::{
    CallbackCompletion, CallbackOutcome, FinishPermission, GlobalTemporalLedger, NativeBoundary,
    NativeTimePoint, PermissionStamp, TemporalError,
};

#[cfg(test)]
use super::sql_bridge::WireLimits;
use super::sql_bridge::{WireArena, WireError, WireId, WireKind, WireOutcome, WireValue};
use super::sql_control::JobControl;
use super::sql_frame::{ArenaValue, FrameBuilder, FrameControl, FrameError, JsonId, KeyId};
use super::sql_policy::{
    CapturedSupport, PolicyBudget, PolicyEngine, PolicyError, Validity, VerifiedPrincipal,
};
use super::sqlite::SqlError;
use std::sync::{Arc, atomic::AtomicBool};

pub(crate) const MAX_HOST_WORK: usize = 64 * 1024 * 1024;
pub(crate) const MAX_RELATIONS: usize = 64;
pub(crate) const MAX_CAPTURED_ROWS: usize = 20_000;
const HOST_CONTROL_BYTES: usize = 64 * 1024;
const MAX_WIRE_PAIR_BYTES: usize = 32 * 1024 * 1024;

/// Trusted native callback selection, never decoded from callback arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativePhase {
    InitialAuth,
    FreshAuth,
    ReadlessPlan,
    Authority,
    Provider,
    ReadlessFinalizer,
}
impl NativePhase {
    fn readless(self) -> bool {
        matches!(self, Self::ReadlessPlan | Self::ReadlessFinalizer)
    }
    fn authentication(self) -> bool {
        matches!(self, Self::InitialAuth | Self::FreshAuth)
    }
}

/// Concrete downcastable fatal demand, containing no private identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeNeedCapture;
impl std::fmt::Display for NativeNeedCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SQL_NATIVE_NEED_CAPTURE")
    }
}
impl std::error::Error for NativeNeedCapture {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HostError {
    Forbidden,
    Unsupported,
    Invalid,
    Capacity,
    WorkLimit,
    Cancelled,
    Deadline,
    NeedCapture(NativeNeedCapture),
    Finished,
    Wire(WireError),
    Temporal(TemporalError),
}
impl std::fmt::Display for HostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Self::Temporal(error) = self {
            return error.fmt(f);
        }
        f.write_str(match self {
            Self::Temporal(_) => "SQL_HOST_TEMPORAL",
            Self::Forbidden => "SQL_HOST_FORBIDDEN",
            Self::Unsupported => "SQL_HOST_UNSUPPORTED",
            Self::Invalid => "SQL_HOST_INVALID",
            Self::Capacity => "SQL_HOST_CAPACITY",
            Self::WorkLimit => "SQL_HOST_WORK_LIMIT",
            Self::Cancelled => "SQL_HOST_CANCELLED",
            Self::Deadline => "SQL_HOST_DEADLINE",
            Self::NeedCapture(_) => "SQL_NATIVE_NEED_CAPTURE",
            Self::Finished => "SQL_HOST_FINISHED",
            Self::Wire(_) => "SQL_HOST_WIRE_INVALID",
        })
    }
}
impl std::error::Error for HostError {}
impl From<TemporalError> for HostError {
    fn from(error: TemporalError) -> Self {
        Self::Temporal(error)
    }
}
impl From<WireError> for HostError {
    fn from(e: WireError) -> Self {
        match e {
            WireError::Capacity => Self::Capacity,
            WireError::WorkLimit => Self::WorkLimit,
            WireError::Cancelled => Self::Cancelled,
            e => Self::Wire(e),
        }
    }
}
impl From<FrameError> for HostError {
    fn from(e: FrameError) -> Self {
        match e {
            FrameError::Capacity => Self::Capacity,
            FrameError::WorkLimit => Self::WorkLimit,
            FrameError::Cancelled => Self::Cancelled,
            FrameError::Deadline => Self::Deadline,
            FrameError::Unsupported => Self::Unsupported,
            FrameError::Invalid => Self::Invalid,
        }
    }
}
impl From<PolicyError> for HostError {
    fn from(e: PolicyError) -> Self {
        match e {
            PolicyError::NeedCapture => Self::NeedCapture(NativeNeedCapture),
            PolicyError::Capacity => Self::Capacity,
            PolicyError::WorkLimit => Self::WorkLimit,
            PolicyError::Cancelled => Self::Cancelled,
            PolicyError::Deadline => Self::Deadline,
            _ => Self::Unsupported,
        }
    }
}

/// Trusted absence is not the same as an uncaptured lookup. Complete describes
/// the whole native relation, not a LIMIT/prefix/guest assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureCoverage {
    Complete,
    KeysOnly,
}
#[derive(Clone, Copy)]
pub(crate) struct OwnedRow {
    pub key: KeyId,
    pub value: Option<JsonId>,
}
#[derive(Clone, Copy)]
pub(crate) struct OwnedRelation<'a> {
    pub name: &'a str,
    pub coverage: CaptureCoverage,
    pub rows: &'a [OwnedRow],
}

/// Only controller-issued FrameBuilder offsets, never guest wire IDs or purpose.
/// Fields are private so a callback cannot amend the binding through host calls.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct NativeBinding<'a> {
    invoker: JsonId,
    principal: JsonId,
    history: JsonId,
    authority_context: JsonId,
    partition: JsonId,
    clock: u64,
    source_revision: u64,
    permission_revision: u64,
    code_version: &'a str,
    catalog_version: &'a str,
}
impl<'a> NativeBinding<'a> {
    /// Preserve original capture Rseal while checking a later permission point.
    /// Native issuance/correlation only; NOT a source/certificate verifier.
    pub(crate) fn at_permission_point(mut self, point: NativeTimePoint) -> Result<Self, HostError> {
        let (clock, revision) = point.issued_clock_revision();
        if revision < self.source_revision {
            return Err(HostError::Invalid);
        }
        self.clock = clock;
        self.permission_revision = revision;
        Ok(self)
    }
    #[allow(clippy::too_many_arguments)] // Explicit native-issued binding, not a guest map.
    pub(crate) fn from_controller(
        invoker: JsonId,
        principal: JsonId,
        history: JsonId,
        authority_context: JsonId,
        partition: JsonId,
        clock: u64,
        source_revision: u64,
        code_version: &'a str,
        catalog_version: &'a str,
    ) -> Result<Self, HostError> {
        if clock > (1u64 << 53) - 1
            || source_revision > (1u64 << 53) - 1
            || code_version.is_empty()
            || code_version.len() > 4096
            || catalog_version.is_empty()
            || catalog_version.len() > 128
        {
            return Err(HostError::Invalid);
        }
        Ok(Self {
            invoker,
            principal,
            history,
            authority_context,
            partition,
            clock,
            source_revision,
            permission_revision: source_revision,
            code_version,
            catalog_version,
        })
    }
}

/// Parent's aggregate reservation includes the source frame, borrowed relation
/// descriptor owners and both exact page-rounded arenas, not two separate caps.
#[derive(Clone, Copy)]
pub(crate) struct ExternalReservation {
    pub total_bytes: usize,
    /// Exact page/layout/capacity bytes of ALL borrowed descriptor/name owners,
    /// not just the initialized slice lengths. Native admission supplies this.
    pub borrowed_owner_bytes: usize,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DemandKind {
    Get,
    CompleteScan,
    PolicySupport,
}
#[derive(Clone, Copy)]
struct Demand {
    kind: DemandKind,
    collection: Option<WireId>,
    key: Option<WireId>,
}
pub(crate) struct CaptureDemand<'a> {
    pub kind: DemandKind,
    pub collection: Option<&'a str>,
    pub key: Option<&'a str>,
}

/// Admit once for a WHOLE native job. Callbacks, phases and capture retries must
/// borrow this same account; resetting arenas never resets cumulative work.
pub(crate) struct HostAdmission {
    input: WireArena,
    output: WireArena,
    budget: HostBudget,
    exact_bytes: usize,
    reserved_bytes: usize,
    borrowed_owner_bytes: usize,
    job_stamp: JobStamp,
    policy_work_ceiling: Option<usize>,
    policy_identity: Option<usize>,
}
impl HostAdmission {
    /// TEST-ONLY fixture convenience, not a production aggregate allocator.
    /// Maps before observing exact bytes; production passes two arenas already
    /// covered by its native aggregate admission to from_admitted instead.
    #[cfg(test)]
    pub(crate) fn new(
        limits: WireLimits,
        frame: &FrameBuilder,
        relations: &[OwnedRelation<'_>],
        reservation: ExternalReservation,
        work: usize,
        original_job: &JobControl,
    ) -> Result<Self, HostError> {
        let input = WireArena::new(limits)?;
        let output = WireArena::new(limits)?;
        Self::from_admitted(
            input,
            output,
            frame,
            relations,
            reservation,
            work,
            original_job,
        )
    }
    pub(crate) fn from_admitted(
        input: WireArena,
        output: WireArena,
        frame: &FrameBuilder,
        relations: &[OwnedRelation<'_>],
        reservation: ExternalReservation,
        work: usize,
        original_job: &JobControl,
    ) -> Result<Self, HostError> {
        if work > MAX_HOST_WORK || relations.len() > MAX_RELATIONS {
            return Err(HostError::Capacity);
        }
        let pair = input
            .allocation_bytes()
            .checked_add(output.allocation_bytes())
            .filter(|n| *n <= MAX_WIRE_PAIR_BYTES)
            .ok_or(HostError::Capacity)?;
        let mut owners = std::mem::size_of_val(relations);
        let mut count = 0usize;
        for relation in relations {
            count = count
                .checked_add(relation.rows.len())
                .filter(|n| *n <= MAX_CAPTURED_ROWS)
                .ok_or(HostError::Capacity)?;
            owners = owners
                .checked_add(std::mem::size_of_val(relation.rows))
                .and_then(|n| n.checked_add(relation.name.len()))
                .ok_or(HostError::Capacity)?;
        }
        if owners > reservation.borrowed_owner_bytes {
            return Err(HostError::Capacity);
        }
        let exact_bytes = pair
            .checked_add(frame.allocation_bytes())
            .and_then(|n| n.checked_add(reservation.borrowed_owner_bytes))
            .and_then(|n| n.checked_add(HOST_CONTROL_BYTES))
            .filter(|n| *n <= reservation.total_bytes)
            .ok_or(HostError::Capacity)?;
        Ok(Self {
            input,
            output,
            budget: HostBudget {
                remaining: work,
                failed: None,
                demand: None,
                rejected: false,
                temporal: GlobalTemporalLedger::new(original_job),
            },
            exact_bytes,
            reserved_bytes: reservation.total_bytes,
            borrowed_owner_bytes: reservation.borrowed_owner_bytes,
            job_stamp: JobStamp {
                admitted: original_job.admitted(),
                deadline: original_job.deadline(),
                cancellation: original_job.cancellation().clone(),
            },
            policy_work_ceiling: None,
            policy_identity: None,
        })
    }
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.exact_bytes
    }
    pub(crate) fn remaining_work(&self) -> usize {
        self.budget.remaining
    }
    pub(crate) fn failure(&self) -> Option<HostError> {
        self.budget.failed
    }
    pub(crate) fn validity(&self) -> Validity {
        self.budget.temporal.validity()
    }
    pub(crate) fn demand(&self) -> Result<Option<CaptureDemand<'_>>, HostError> {
        self.budget
            .demand
            .map(|d| {
                Ok(CaptureDemand {
                    kind: d.kind,
                    collection: d
                        .collection
                        .map(|id| self.input.value(id)?.as_str().ok_or(HostError::Invalid))
                        .transpose()?,
                    key: d
                        .key
                        .map(|id| self.input.value(id)?.as_str().ok_or(HostError::Invalid))
                        .transpose()?,
                })
            })
            .transpose()
    }
    /// Only NeedCapture is replayable. Native caller must destroy the prior VM,
    /// capture/certify this demand, then explicitly acknowledge it. No arena,
    /// policy, job, deadline or work account is recreated/refilled by this step.
    /// # Safety
    /// Controller observed the actual NativeNeedCapture cause, destroyed the
    /// abandoned VM, and completed/certified exactly this pending capture.
    /// No guest flag or dropped host alone is evidence of VM destruction.
    pub(crate) unsafe fn acknowledge_native_capture(
        &mut self,
        original_job: &mut JobControl,
    ) -> Result<(), HostError> {
        if self.budget.failed != Some(HostError::NeedCapture(NativeNeedCapture))
            || self.budget.demand.is_none()
        {
            return Err(self.budget.failed.unwrap_or(HostError::Invalid));
        }
        if !self.job_stamp.matches(original_job) {
            self.budget.failed = Some(HostError::Temporal(TemporalError::WrongOriginalJob));
            return Err(self.budget.failed.unwrap());
        }
        if let Err(error) = original_job.check() {
            let error = match error {
                SqlError::Cancelled => HostError::Cancelled,
                SqlError::Deadline => HostError::Deadline,
                _ => HostError::Invalid,
            };
            self.budget.failed = Some(error);
            return Err(error);
        }
        // PolicySupport poisons its separate cumulative account; no reset API.
        if self
            .budget
            .demand
            .is_some_and(|d| d.kind == DemandKind::PolicySupport)
        {
            return Err(HostError::Unsupported);
        }
        let result = self
            .budget
            .temporal
            .abandon_for_native_capture(original_job);
        if let Err(error) = result {
            self.budget.failed = Some(error.into());
            return Err(error.into());
        }
        self.budget.failed = None;
        self.budget.demand = None;
        Ok(())
    }
    /// Mandatory controller-supplied fresh native time before/after traversal,
    /// seal and publication. This does not replace a source/auth certificate.
    pub(crate) fn check_native_clock(
        &mut self,
        job: &mut JobControl,
        clock: u64,
    ) -> Result<(), HostError> {
        let mut work = Work {
            budget: &mut self.budget,
            job,
        };
        work.debit(0)?;
        let result = work.budget.temporal.check_native_clock(work.job, clock);
        work.keep(result)
    }
    pub(crate) fn permission_stamp(
        &mut self,
        job: &mut JobControl,
        clock: u64,
    ) -> Result<PermissionStamp, HostError> {
        let mut work = Work {
            budget: &mut self.budget,
            job,
        };
        work.debit(0)?;
        let result = work.budget.temporal.permission_stamp(work.job, clock);
        work.keep(result)
    }
    pub(crate) fn validate_finish_permission(
        &mut self,
        job: &mut JobControl,
        permission: FinishPermission,
        fresh_native_clock: u64,
    ) -> Result<Option<u64>, HostError> {
        let mut work = Work {
            budget: &mut self.budget,
            job,
        };
        work.debit(0)?;
        let result = work.budget.temporal.validate_finalizer_permission(
            work.job,
            permission,
            fresh_native_clock,
            true,
        );
        work.keep(result)
    }
    pub(crate) fn validate_permission_stamp(
        &mut self,
        job: &mut JobControl,
        stamp: PermissionStamp,
        clock: u64,
    ) -> Result<(), HostError> {
        let mut work = Work {
            budget: &mut self.budget,
            job,
        };
        work.debit(0)?;
        let result = work
            .budget
            .temporal
            .validate_permission_stamp(work.job, stamp, clock);
        work.keep(result)
    }
}
struct JobStamp {
    admitted: std::time::Instant,
    deadline: std::time::Instant,
    cancellation: Arc<AtomicBool>,
}
impl JobStamp {
    fn matches(&self, job: &JobControl) -> bool {
        self.admitted == job.admitted()
            && self.deadline == job.deadline()
            && Arc::ptr_eq(&self.cancellation, job.cancellation())
    }
}
struct HostBudget {
    remaining: usize,
    failed: Option<HostError>,
    demand: Option<Demand>,
    rejected: bool,
    temporal: GlobalTemporalLedger,
}
struct Work<'a> {
    budget: &'a mut HostBudget,
    job: &'a mut JobControl,
}
impl Work<'_> {
    fn fail(&mut self, error: HostError) -> HostError {
        let e = self.budget.failed.unwrap_or(error);
        self.budget.failed = Some(e);
        e
    }
    fn keep<T, E: Into<HostError>>(&mut self, result: Result<T, E>) -> Result<T, HostError> {
        result.map_err(|e| self.fail(e.into()))
    }
    fn debit(&mut self, units: usize) -> Result<(), HostError> {
        if let Some(e) = self.budget.failed {
            return Err(e);
        }
        if self.budget.rejected {
            return Err(self.fail(HostError::Temporal(TemporalError::AuthorizationDenied)));
        }
        if let Err(e) = self.job.check() {
            return Err(self.fail(match e {
                SqlError::Cancelled => HostError::Cancelled,
                SqlError::Deadline => HostError::Deadline,
                _ => HostError::Invalid,
            }));
        }
        self.budget.remaining = self
            .budget
            .remaining
            .checked_sub(units)
            .ok_or_else(|| self.fail(HostError::WorkLimit))?;
        Ok(())
    }
    fn bytes(&mut self, bytes: usize) -> Result<(), HostError> {
        for _ in 0..bytes / 1024 {
            self.debit(1024)?;
        }
        self.debit(bytes % 1024)
    }
    fn checker(&mut self) -> Result<(), WireError> {
        self.debit(0).map_err(|e| match e {
            HostError::WorkLimit => WireError::WorkLimit,
            _ => WireError::Cancelled,
        })
    }
    fn same(&mut self, a: &str, b: &str) -> Result<bool, HostError> {
        self.debit(1)?;
        if a.len() != b.len() {
            return Ok(false);
        }
        for (a, b) in a.as_bytes().chunks(1024).zip(b.as_bytes().chunks(1024)) {
            self.debit(a.len())?;
            if a != b {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Unlike WireValue::member/index, this scan debits EACH visited key/entry.
    fn member<'a>(
        &mut self,
        value: WireValue<'a>,
        key: &str,
    ) -> Result<Option<WireValue<'a>>, HostError> {
        self.debit(1)?;
        for entry in value.iter()? {
            self.debit(1)?;
            if self.same(entry.key.ok_or(HostError::Invalid)?, key)? {
                return Ok(Some(entry.value));
            }
        }
        Ok(None)
    }
    fn need(
        &mut self,
        kind: DemandKind,
        collection: Option<WireId>,
        key: Option<WireId>,
    ) -> HostError {
        if self.budget.demand.is_none() {
            self.budget.demand = Some(Demand {
                kind,
                collection,
                key,
            });
        }
        self.fail(HostError::NeedCapture(NativeNeedCapture))
    }
}

/// A borrow scoped to exactly one VM callback. Contains no serving root, App,
/// cache, source/provider closure, key resolver or mutable source capability.
pub(crate) struct SqlHost<'a> {
    admission: &'a mut HostAdmission,
    frame: &'a FrameBuilder,
    relations: &'a [OwnedRelation<'a>],
    binding: NativeBinding<'a>,
    native_capture: Option<NativeCapture<'a>>,
    finish_permission: Option<temporal::FinishPermission>,
    phase: NativePhase,
    authority: Option<ClosedAuthorityPermit<'a>>,
    completion: Option<CallbackCompletion>,
    support: Option<CapturedSupport<'a>>,
    policy_budget: &'a PolicyBudget,
    job: &'a mut JobControl,
    cancellation: Arc<AtomicBool>,
    completed: Option<WireOutcome>,
    provider_rows: Option<usize>,
}
impl<'a> SqlHost<'a> {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_native(
        phase: NativePhase,
        admission: &'a mut HostAdmission,
        capture: NativeCapture<'a>,
        binding: NativeBinding<'a>,
        policy_budget: &'a PolicyBudget,
        point: NativeTimePoint,
        job: &'a mut JobControl,
    ) -> Result<Self, HostError> {
        if phase == NativePhase::ReadlessFinalizer {
            return Err(HostError::Forbidden);
        }
        let mut required = std::mem::size_of_val(capture.relations)
            .checked_add(capture.owner_bytes)
            .ok_or(HostError::Capacity)?;
        for relation in capture.relations {
            required = required
                .checked_add(std::mem::size_of_val(relation.rows))
                .and_then(|n| n.checked_add(relation.name.len()))
                .ok_or(HostError::Capacity)?;
        }
        if required > admission.borrowed_owner_bytes {
            return Err(HostError::Capacity);
        }
        let mut host = Self::construct(
            phase,
            admission,
            capture.frame,
            capture.relations,
            binding,
            Some(capture.support.captured),
            policy_budget,
            job,
            point,
            None,
        )?;
        host.native_capture = Some(capture);
        Ok(host)
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        phase: NativePhase,
        admission: &'a mut HostAdmission,
        frame: &'a FrameBuilder,
        relations: &'a [OwnedRelation<'a>],
        binding: NativeBinding<'a>,
        support: Option<CapturedSupport<'a>>,
        policy_budget: &'a PolicyBudget,
        point: NativeTimePoint,
        job: &'a mut JobControl,
    ) -> Result<Self, HostError> {
        Self::construct(
            phase,
            admission,
            frame,
            relations,
            binding,
            support,
            policy_budget,
            job,
            point,
            None,
        )
    }
    /// Stamp must be obtained from this ledger BEFORE constructing finalizer.
    /// The exact issued permission point may be newer than captured Rseal.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_qualified_finalizer(
        admission: &'a mut HostAdmission,
        frame: &'a FrameBuilder,
        binding: NativeBinding<'a>,
        policy_budget: &'a PolicyBudget,
        stamp: PermissionStamp,
        point: NativeTimePoint,
        job: &'a mut JobControl,
    ) -> Result<Self, HostError> {
        let permission = {
            let mut work = Work {
                budget: &mut admission.budget,
                job,
            };
            work.debit(0)?;
            let result = work
                .budget
                .temporal
                .qualify_finalizer(work.job, stamp, point);
            work.keep(result)?
        };
        let mut host = Self::construct(
            NativePhase::ReadlessFinalizer,
            admission,
            frame,
            &[],
            binding,
            None,
            policy_budget,
            job,
            point,
            None,
        )?;
        host.finish_permission = Some(permission);
        Ok(host)
    }
    pub(crate) fn finish_permission(&self) -> Result<FinishPermission, HostError> {
        if self.completed.is_none()
            || self.completion != Some(CallbackCompletion::MetadataOnly)
            || self.failure().is_some()
        {
            return Err(self.failure().unwrap_or(HostError::Finished));
        }
        self.finish_permission.ok_or(HostError::Forbidden)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_native_registered_authority(
        admission: &'a mut HostAdmission,
        capture: NativeCapture<'a>,
        binding: NativeBinding<'a>,
        policy_budget: &'a PolicyBudget,
        job: &'a mut JobControl,
        point: NativeTimePoint,
        permit: ClosedAuthorityPermit<'a>,
        execution: NativeAuthorityExecution<'a>,
    ) -> Result<Self, HostError> {
        let mut required = std::mem::size_of_val(capture.relations)
            .checked_add(capture.owner_bytes)
            .ok_or(HostError::Capacity)?;
        for relation in capture.relations {
            required = required
                .checked_add(std::mem::size_of_val(relation.rows))
                .and_then(|n| n.checked_add(relation.name.len()))
                .ok_or(HostError::Capacity)?;
        }
        if required > admission.borrowed_owner_bytes {
            return Err(HostError::Capacity);
        }
        {
            let mut work = Work {
                budget: &mut admission.budget,
                job,
            };
            work.debit(0)?;
            let result = permit.validate(capture.frame, binding, point, execution);
            work.keep(result)?;
        }
        let mut host = Self::construct(
            NativePhase::Authority,
            admission,
            capture.frame,
            capture.relations,
            binding,
            None,
            policy_budget,
            job,
            point,
            Some(permit),
        )?;
        host.native_capture = Some(capture);
        Ok(host)
    }
    /// Only this closed native permit enables Authority SYSTEM reads. It never
    /// flows into a provider, operator, finalizer, SQL engine or publication.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn new_registered_authority(
        admission: &'a mut HostAdmission,
        frame: &'a FrameBuilder,
        relations: &'a [OwnedRelation<'a>],
        binding: NativeBinding<'a>,
        policy_budget: &'a PolicyBudget,
        job: &'a mut JobControl,
        point: NativeTimePoint,
        permit: ClosedAuthorityPermit<'a>,
        execution: NativeAuthorityExecution<'a>,
    ) -> Result<Self, HostError> {
        let mut work = Work {
            budget: &mut admission.budget,
            job,
        };
        work.debit(0)?;
        let result = permit.validate(frame, binding, point, execution);
        work.keep(result)?;
        Self::construct(
            NativePhase::Authority,
            admission,
            frame,
            relations,
            binding,
            None,
            policy_budget,
            job,
            point,
            Some(permit),
        )
    }
    #[allow(clippy::too_many_arguments)]
    fn construct(
        phase: NativePhase,
        admission: &'a mut HostAdmission,
        frame: &'a FrameBuilder,
        relations: &'a [OwnedRelation<'a>],
        binding: NativeBinding<'a>,
        support: Option<CapturedSupport<'a>>,
        policy_budget: &'a PolicyBudget,
        job: &'a mut JobControl,
        point: NativeTimePoint,
        authority: Option<ClosedAuthorityPermit<'a>>,
    ) -> Result<Self, HostError> {
        {
            let mut work = Work {
                budget: &mut admission.budget,
                job,
            };
            work.debit(0)?;
            if (phase == NativePhase::Authority && authority.is_none())
                || (phase != NativePhase::Authority && authority.is_some())
                || (phase == NativePhase::Provider && support.is_none())
            {
                return Err(work.fail(HostError::Forbidden));
            }
            let result =
                point.validate_callback_binding(phase, binding.clock, binding.permission_revision);
            work.keep(result)?;
        }
        // Revalidate aggregate ownership against the SAME external reservation
        // when a trusted caller replaces captured descriptors between phases.
        let pair = admission
            .input
            .allocation_bytes()
            .checked_add(admission.output.allocation_bytes())
            .ok_or(HostError::Capacity)?;
        let mut owners = std::mem::size_of_val(relations);
        let mut row_count = 0usize;
        if relations.len() > MAX_RELATIONS {
            return Err(HostError::Capacity);
        }
        for relation in relations {
            row_count = row_count
                .checked_add(relation.rows.len())
                .filter(|n| *n <= MAX_CAPTURED_ROWS)
                .ok_or(HostError::Capacity)?;
            owners = owners
                .checked_add(std::mem::size_of_val(relation.rows))
                .and_then(|n| n.checked_add(relation.name.len()))
                .ok_or(HostError::Capacity)?;
        }
        if owners > admission.borrowed_owner_bytes {
            return Err(HostError::Capacity);
        }
        let exact = pair
            .checked_add(frame.allocation_bytes())
            .and_then(|n| n.checked_add(admission.borrowed_owner_bytes))
            .and_then(|n| n.checked_add(HOST_CONTROL_BYTES))
            .filter(|n| *n <= admission.reserved_bytes)
            .ok_or(HostError::Capacity)?;
        admission.exact_bytes = exact;
        if !admission.job_stamp.matches(job) {
            admission.budget.failed = Some(HostError::Temporal(TemporalError::WrongOriginalJob));
            return Err(admission.budget.failed.unwrap());
        }
        let identity = std::ptr::from_ref(policy_budget) as usize;
        if admission
            .policy_identity
            .is_some_and(|original| original != identity)
        {
            admission.budget.failed = Some(HostError::Forbidden);
            return Err(HostError::Forbidden);
        }
        admission.policy_identity = Some(identity);
        if let Some(error) = policy_budget.failure() {
            admission.budget.failed = Some(error.into());
            return Err(error.into());
        }
        let policy_remaining = policy_budget.remaining_work();
        if admission
            .policy_work_ceiling
            .is_some_and(|ceiling| policy_remaining > ceiling)
        {
            admission.budget.failed = Some(HostError::Forbidden);
            return Err(HostError::Forbidden);
        }
        admission.policy_work_ceiling = Some(policy_remaining);
        let mut work = Work {
            budget: &mut admission.budget,
            job,
        };
        work.debit(0)?;
        // Capture/binding IDs are builder-local and never supplied by the guest.
        let cancellation = work.job.cancellation().clone();
        let control = FrameControl::new(&cancellation, work.job.deadline());
        for id in [
            binding.invoker,
            binding.principal,
            binding.history,
            binding.authority_context,
            binding.partition,
        ] {
            work.keep(frame.json(id, &control))?;
        }
        for (i, relation) in relations.iter().enumerate() {
            work.bytes(relation.name.len())?;
            if !plain_collection(relation.name) {
                return Err(work.fail(HostError::Unsupported));
            }
            for prior in &relations[..i] {
                if work.same(prior.name, relation.name)? {
                    return Err(work.fail(HostError::Invalid));
                }
            }
        }
        let result = work.budget.temporal.begin_callback(point, work.job);
        work.keep(result)?;
        Ok(Self {
            admission,
            frame,
            relations,
            binding,
            native_capture: None,
            finish_permission: None,
            phase,
            authority,
            completion: None,
            support,
            policy_budget,
            cancellation,
            job,
            completed: None,
            provider_rows: None,
        })
    }
    pub(crate) fn phase(&self) -> NativePhase {
        self.phase
    }
    pub(crate) fn failure(&self) -> Option<HostError> {
        self.admission.failure()
    }
    pub(crate) fn finished(&self) -> Option<WireOutcome> {
        if self.failure().is_some() {
            None
        } else {
            self.completed
        }
    }
    pub(crate) fn finished_value(&self, id: WireId) -> Result<WireValue<'_>, HostError> {
        if let Some(error) = self.failure() {
            return Err(error);
        }
        if self.completed.is_none() {
            return Err(HostError::Finished);
        }
        self.admission.output.value(id).map_err(Into::into)
    }

    pub(crate) fn call_checked<'b>(
        &'b mut self,
        operation: &str,
        input: &[u8],
    ) -> Result<&'b [u8], HostError> {
        let Self {
            admission,
            frame,
            relations,
            binding,
            phase,
            support,
            native_capture,
            policy_budget,
            job,
            cancellation,
            completed,
            ..
        } = self;
        let HostAdmission {
            input: arguments,
            output,
            budget,
            ..
        } = &mut **admission;
        let mut work = Work { budget, job };
        work.debit(0)?;
        if completed.is_some() {
            return Err(work.fail(HostError::Finished));
        }
        // Capability denial precedes guest parsing, so malicious captured writers
        // cannot turn a forbidden operation into a catchable decode failure.
        if !permitted(*phase, operation) {
            return Err(work.fail(HostError::Forbidden));
        }
        work.bytes(input.len())?;
        let result = arguments.reset_checked(&mut || work.checker());
        work.keep(result)?;
        let result = output.reset_checked(&mut || work.checker());
        work.keep(result)?;
        let result = arguments.decode_arguments_checked(input, &mut || work.checker());
        let root = work.keep(result)?;
        let result = dispatch(
            operation,
            arguments.value(root)?,
            output,
            frame,
            relations,
            *binding,
            *phase,
            *support,
            *native_capture,
            policy_budget,
            cancellation,
            &mut work,
        );
        let result = work.keep(result)?;
        let result =
            output.encode_outcome_checked(WireOutcome::Success(result), &mut || work.checker());
        work.keep(result)
    }
    pub(crate) fn register_native_boundary(
        &mut self,
        boundary: NativeBoundary,
    ) -> Result<(), HostError> {
        let mut work = Work {
            budget: &mut self.admission.budget,
            job: self.job,
        };
        work.debit(0)?;
        let result = work
            .budget
            .temporal
            .register_native_boundary(boundary, work.job);
        work.keep(result)
    }
    pub(crate) fn completion(&self) -> Option<CallbackCompletion> {
        self.completion
    }
    pub(crate) fn authority_target(&self) -> Option<&str> {
        self.authority.as_ref().map(ClosedAuthorityPermit::target)
    }
    /// Copies the complete callback result into the fixed OUTPUT arena while
    /// guest memory is suspended; no guest slice/pointer is retained afterwards.
    pub(crate) fn finish_checked(&mut self, bytes: &[u8]) -> Result<(), HostError> {
        // Raw VM finish is at the native ISSUED point, not a wall-clock freshness
        // claim. Controller MUST check/stamp fresh native time before seal and
        // publication; the completed value alone is never a permission stamp.
        self.finish_checked_at(bytes, self.binding.clock)
    }
    pub(crate) fn finish_checked_at(
        &mut self,
        bytes: &[u8],
        fresh_native_clock: u64,
    ) -> Result<(), HostError> {
        let HostAdmission {
            input,
            output,
            budget,
            ..
        } = &mut *self.admission;
        let mut work = Work {
            budget,
            job: self.job,
        };
        work.debit(0)?;
        if self.completed.is_some() {
            return Err(work.fail(HostError::Finished));
        }
        work.bytes(bytes.len())?;
        let result = input.reset_checked(&mut || work.checker());
        work.keep(result)?;
        let result = output.reset_checked(&mut || work.checker());
        work.keep(result)?;
        let result = input.decode_outcome_checked(bytes, &mut || work.checker());
        let outcome = work.keep(result)?;
        let result = (|| {
            match outcome {
                WireOutcome::Success(id) => {
                    copy::wire(input.value(id)?, output, &mut work).map(WireOutcome::Success)
                }
                WireOutcome::Failure {
                    code,
                    message,
                    details,
                } => {
                    let code = input.value(code)?.as_str().ok_or(HostError::Invalid)?;
                    let message = input.value(message)?.as_str().ok_or(HostError::Invalid)?;
                    let details = details
                        .map(|id| copy::wire(input.value(id)?, output, &mut work))
                        .transpose()?;
                    work.bytes(code.len())?;
                    work.bytes(message.len())?;
                    // failure() uses no heap; text processing in it has no external
                    // checker, so build the transport via checked text/insert below.
                    copy::failure(code, message, details, output, &mut work)
                }
            }
        })();
        let outcome = work.keep(result)?;
        let result = output.encode_outcome_checked(outcome, &mut || work.checker());
        work.keep(result)?;
        work.debit(0)?;
        // Decode/copy native outcome first. Native poison cannot be substituted
        // with a guest BusinessFailure; denied jobs cannot later run SQL/sign.
        let result = work.budget.temporal.finish_callback(
            work.job,
            if matches!(outcome, WireOutcome::Success(_)) {
                CallbackOutcome::Success
            } else {
                CallbackOutcome::Failure
            },
            fresh_native_clock,
        );
        let completion = work.keep(result)?;
        if let Some(permission) = self.finish_permission {
            let result = work.budget.temporal.validate_finalizer_permission(
                work.job,
                permission,
                fresh_native_clock,
                true,
            );
            work.keep(result)?;
        }
        work.budget.rejected = completion == CallbackCompletion::RejectedUncacheable;
        self.completion = Some(completion);
        self.completed = Some(outcome);
        Ok(())
    }
    /// One native SqlFinishInput value; the SDK adapts this to the established
    /// finalize(ctx, execution, metadata) THREE arguments. No source method.
    pub(crate) fn prepare_finish_input(
        &mut self,
        request: JsonId,
        result: JsonId,
        provenance: JsonId,
    ) -> Result<&[u8], HostError> {
        let HostAdmission { output, budget, .. } = &mut *self.admission;
        let mut work = Work {
            budget,
            job: self.job,
        };
        work.debit(0)?;
        if self.phase != NativePhase::ReadlessFinalizer || self.completed.is_some() {
            return Err(work.fail(HostError::Forbidden));
        }
        let permission = self
            .finish_permission
            .ok_or_else(|| work.fail(HostError::Temporal(TemporalError::NoPermission)))?;
        let checked = work.budget.temporal.validate_finalizer_permission(
            work.job,
            permission,
            self.binding.clock,
            false,
        );
        let valid_until = work.keep(checked)?;
        let control = FrameControl::new(&self.cancellation, work.job.deadline());
        let r = output.reset_checked(&mut || work.checker());
        work.keep(r)?;
        let r = (|| {
            let root = output.object()?;
            for (name, id) in [
                ("request", request),
                ("result", result),
                ("provenance", provenance),
            ] {
                let value = copy::arena(self.frame.json(id, &control)?, output, &mut work)?;
                copy::insert(output, root, name, value, &mut work)?;
            }
            let binding = copy::binding(
                self.binding,
                valid_until,
                self.frame,
                &control,
                output,
                &mut work,
            )?;
            copy::insert(output, root, "binding", binding, &mut work)?;
            Ok::<_, HostError>(root)
        })();
        let root = work.keep(r)?;
        let r = output.encode_checked(root, &mut || work.checker());
        work.keep(r)
    }
}

impl Drop for SqlHost<'_> {
    fn drop(&mut self) {
        // A caller cannot accidentally replenish policy work by constructing a
        // fresh policy account between callbacks. Only its remaining scalar is
        // kept; no policy/source/VM owner or token survives this callback borrow.
        let remaining = self.policy_budget.remaining_work();
        self.admission.policy_work_ceiling = Some(
            self.admission
                .policy_work_ceiling
                .map_or(remaining, |ceiling| ceiling.min(remaining)),
        );
    }
}

fn permitted(phase: NativePhase, operation: &str) -> bool {
    match operation {
        "principal" | "clock" | "history" | "codeVersion" => true,
        "get" | "scan" | "now" | "changesAt" | "range" | "query" => !phase.readless(),
        // Recursive SQL, writers, definer and unknown operations
        // never enter a detached closed read-only host in ANY phase.
        _ => false,
    }
}
fn plain_collection(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 4096
        && !name.starts_with('_')
        && !name.starts_with('$')
        && !name.contains([':', '\0'])
        && !matches!(name, "sql_tables" | "sql_columns" | "sql_relationships")
}
#[allow(clippy::too_many_arguments)]
fn dispatch(
    operation: &str,
    args: WireValue<'_>,
    output: &mut WireArena,
    frame: &FrameBuilder,
    relations: &[OwnedRelation<'_>],
    binding: NativeBinding<'_>,
    phase: NativePhase,
    support: Option<CapturedSupport<'_>>,
    native_capture: Option<NativeCapture<'_>>,
    policy_budget: &PolicyBudget,
    cancellation: &AtomicBool,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    let mut iter = args.iter()?;
    let mut values: [Option<WireValue<'_>>; 8] = [None; 8];
    let mut count = 0;
    for entry in &mut iter {
        work.debit(1)?;
        if count == values.len() {
            return Err(HostError::Invalid);
        }
        values[count] = Some(entry.value);
        count += 1;
    }
    let control = FrameControl::new(cancellation, work.job.deadline());
    match operation {
        "principal" | "history" | "clock" | "now" | "codeVersion" => {
            if count != 0 {
                return Err(HostError::Invalid);
            }
            match operation {
                "clock" => {
                    work.debit(1)?;
                    let result = work.budget.temporal.read_clock(work.job);
                    let clock = work.keep(result)?;
                    Ok(output.real(clock as f64)?)
                }
                "now" => {
                    work.debit(1)?;
                    let result = work.budget.temporal.poll_now(work.job);
                    work.keep(result)?;
                    Err(work.fail(HostError::Temporal(TemporalError::Uncertified)))
                }
                "codeVersion" => copy::text(output, binding.code_version, work),
                "principal" => copy::arena(
                    frame.json(
                        if matches!(phase, NativePhase::Authority | NativePhase::ReadlessPlan) {
                            binding.invoker
                        } else {
                            binding.principal
                        },
                        &control,
                    )?,
                    output,
                    work,
                ),
                _ => copy::arena(frame.json(binding.history, &control)?, output, work),
            }
        }
        "changesAt" => {
            if count != 1 {
                return Err(HostError::Invalid);
            }
            let value = values[0].ok_or(HostError::Invalid)?;
            let result = work.budget.temporal.declare_changes_at(work.job, value);
            work.keep(result)?;
            Ok(output.null()?)
        }
        "get" | "scan" => read::read(
            operation,
            &values[..count],
            output,
            frame,
            relations,
            binding,
            phase,
            support,
            native_capture,
            policy_budget,
            &control,
            work,
        ),
        "range" | "query" => Err(HostError::Unsupported),
        _ => Err(HostError::Forbidden),
    }
}

// Native Err is never encoded as FAILURE. anyhow's boxed fatal-error wrapper
// currently allocates: this detached adapter is NOT a physical/no-heap native
// admission proof. Typed call_checked/finish_checked paths allocate zero heap.
// Parent must admit/prebuild fatal wrappers or revise the transport error ABI
// before activation. NativeNeedCapture is the concrete top-level anyhow cause.
#[cfg(feature = "sql")]
impl super::wasm::EncodedHost for SqlHost<'_> {
    fn call<'a>(&'a mut self, operation: &str, input: &[u8]) -> anyhow::Result<&'a [u8]> {
        self.call_checked(operation, input).map_err(native_error)
    }
    fn finish(&mut self, outcome: &[u8]) -> anyhow::Result<()> {
        self.finish_checked(outcome).map_err(native_error)
    }
}
#[cfg(feature = "sql")]
fn native_error(e: HostError) -> anyhow::Error {
    match e {
        HostError::NeedCapture(demand) => anyhow::Error::new(demand),
        e => anyhow::Error::new(e),
    }
}

#[cfg(test)]
#[path = "sql_host/tests.rs"]
mod tests;
