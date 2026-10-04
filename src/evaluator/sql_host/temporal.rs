//! Native callback temporal accounting; detached, fixed-size, no wall-clock read.
//! No job deadline, guest flag, public claim, signer or result-proof lifetime is
//! authorization provenance. Native point/boundary constructors are explicit
//! trust boundaries, NOT verifiers. Store ONE ledger in original HostBudget.
use super::NativePhase;
use crate::crypto::sql_managed::{Error as JwtError, TimeDependency};
use crate::evaluator::{
    sql_bridge::WireValue, sql_control::JobControl, sql_policy::Validity, sqlite::SqlError,
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
static NEXT_LEDGER: AtomicU64 = AtomicU64::new(1);

pub(crate) const MAX_EXACT_CLOCK: u64 = (1u64 << 53) - 1;

/// Fixed failures without private identifiers/text. Raw host must poison its
/// fatal account on Err BEFORE exposing any exception to a guest catch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TemporalError {
    InvalidClock,
    InvalidBoundary,
    ForbiddenPhase,
    Uncertified,
    ProvenanceMismatch,
    WrongOriginalJob,
    BackwardsClock,
    Expired,
    CallbackPending,
    NoCallback,
    AuthorizationDenied,
    NoPermission,
    Cancelled,
    Deadline,
}
impl std::fmt::Display for TemporalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidClock => "SQL_TIME_INVALID_CLOCK",
            Self::InvalidBoundary => "SQL_TIME_INVALID_BOUNDARY",
            Self::ForbiddenPhase => "SQL_TIME_FORBIDDEN_PHASE",
            Self::Uncertified => "SQL_TIME_UNCERTIFIED",
            Self::ProvenanceMismatch => "SQL_TIME_PROVENANCE_MISMATCH",
            Self::WrongOriginalJob => "SQL_TIME_WRONG_ORIGINAL_JOB",
            Self::BackwardsClock => "SQL_TIME_BACKWARDS_CLOCK",
            Self::Expired => "SQL_TIME_EXPIRED",
            Self::CallbackPending => "SQL_TIME_CALLBACK_PENDING",
            Self::NoCallback => "SQL_TIME_NO_CALLBACK",
            Self::AuthorizationDenied => "SQL_TIME_AUTHORIZATION_DENIED",
            Self::NoPermission => "SQL_TIME_NO_PERMISSION",
            Self::Cancelled => "SQL_TIME_CANCELLED",
            Self::Deadline => "SQL_TIME_DEADLINE",
        })
    }
}
impl std::error::Error for TemporalError {}

fn permission_phase(phase: NativePhase) -> bool {
    matches!(
        phase,
        NativePhase::InitialAuth
            | NativePhase::FreshAuth
            | NativePhase::Authority
            | NativePhase::Provider
    )
}

fn authentication_phase(phase: NativePhase) -> bool {
    matches!(phase, NativePhase::InitialAuth | NativePhase::FreshAuth)
}

/// Exact native certificate/deployment identity, never wire-constructed.
/// Source revision can advance at a fresh point. Deployment/catalog epochs
/// must remain fixed for one original job. This does NOT verify a certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeTimePoint {
    original_job: OriginalJobStamp,
    phase: NativePhase,
    checked_at_ms: u64,
    source_revision: u64,
    deployment_epoch: u64,
    catalog_epoch: u64,
}
impl NativeTimePoint {
    /// # Safety
    /// Actual native controller verified captured source point and exact
    /// immutable deployed callback/catalog. Epochs are native-issued identities
    /// bound to those versions, NOT flags, signer IDs, claims or guessed hashes.
    /// checked_at_ms is the real native clock issued to THIS exact callback.
    /// This constructor establishes no authorization/source validity itself.
    pub(crate) unsafe fn from_certified_native_point(
        original_job: &JobControl,
        phase: NativePhase,
        checked_at_ms: u64,
        source_revision: u64,
        deployment_epoch: u64,
        catalog_epoch: u64,
    ) -> Result<Self, TemporalError> {
        if checked_at_ms > MAX_EXACT_CLOCK {
            return Err(TemporalError::InvalidClock);
        }
        if source_revision > MAX_EXACT_CLOCK || deployment_epoch == 0 || catalog_epoch == 0 {
            return Err(TemporalError::ProvenanceMismatch);
        }
        Ok(Self {
            original_job: OriginalJobStamp::of(original_job),
            phase,
            checked_at_ms,
            source_revision,
            deployment_epoch,
            catalog_epoch,
        })
    }
    pub(super) fn issued_clock_revision(self) -> (u64, u64) {
        (self.checked_at_ms, self.source_revision)
    }
    /// Equality against native host binding only, NOT certificate verification.
    /// Must pass before starting a callback with this point. The original job
    /// and deployment/catalog identities are additionally checked by ledger.
    pub(crate) fn validate_callback_binding(
        self,
        phase: NativePhase,
        issued_clock: u64,
        source_revision: u64,
    ) -> Result<(), TemporalError> {
        if self.phase != phase
            || self.checked_at_ms != issued_clock
            || self.source_revision != source_revision
        {
            return Err(TemporalError::ProvenanceMismatch);
        }
        Ok(())
    }
}

/// Actual evaluated permission dependency. Include hidden/filtered/failed rows.
/// Private fields exclude arbitrary public claims/guest "timeProven" flags.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeBoundary {
    point: NativeTimePoint,
    validity: Validity,
    not_before_ms: u64,
    denied: bool,
    callback_clock_covered: bool,
}
impl NativeBoundary {
    /// # Safety
    /// validity is actual sql_policy output at point.checked_at_ms (prefer
    /// cumulative original-job PolicyBudget::finish). ClockInvariant is that
    /// evaluator's specific mathematical proof, NOT a stable/null declaration.
    /// To discharge a raw callback clock read, native audited dependency/code
    /// coverage must prove this bounds ALL its clock-dependent permission
    /// decisions. An unrelated row's validity does not prove arbitrary JS.
    pub(crate) unsafe fn from_native_policy(
        point: NativeTimePoint,
        validity: Validity,
    ) -> Result<Self, TemporalError> {
        if !permission_phase(point.phase) {
            return Err(TemporalError::ForbiddenPhase);
        }
        if matches!(validity, Validity::Until(at) if at <= point.checked_at_ms || at > MAX_EXACT_CLOCK)
        {
            return Err(TemporalError::InvalidBoundary);
        }
        Ok(Self {
            point,
            validity,
            not_before_ms: point.checked_at_ms,
            denied: false,
            callback_clock_covered: false,
        })
    }
    /// # Safety
    /// dependency is UNMODIFIED actual managed JWT verification output after
    /// signature/options/claim checks at this exact native point, never a
    /// manually populated TimeDependency/public claims object. To discharge
    /// raw clock reads, native audited callback coverage must ALSO prove its
    /// clock comparisons are fully covered; token verification alone cannot.
    pub(crate) unsafe fn from_verified_jwt(
        point: NativeTimePoint,
        dependency: TimeDependency,
    ) -> Result<Self, TemporalError> {
        if !authentication_phase(point.phase) {
            return Err(TemporalError::ForbiddenPhase);
        }
        if dependency.checked_at_ms != point.checked_at_ms
            || dependency
                .valid_from_ms
                .is_some_and(|at| at > point.checked_at_ms)
        {
            return Err(TemporalError::ProvenanceMismatch);
        }
        if dependency.expires_at_ms <= point.checked_at_ms
            || dependency.expires_at_ms > MAX_EXACT_CLOCK
        {
            return Err(TemporalError::InvalidBoundary);
        }
        Ok(Self {
            point,
            validity: Validity::Until(dependency.expires_at_ms),
            not_before_ms: dependency
                .valid_from_ms
                .unwrap_or(0)
                .max(dependency.checked_at_ms),
            denied: false,
            callback_clock_covered: false,
        })
    }
    /// # Safety
    /// error is the exact actual verifier outcome after authenticated temporal
    /// claim checking at point. NotActive already contains min(nbf, exp).
    /// Signature/Claims/options failures have NO authenticated time provenance.
    /// Authenticated failure still cannot create a permission/future deny cache.
    pub(crate) unsafe fn from_verified_jwt_failure(
        point: NativeTimePoint,
        error: JwtError,
    ) -> Result<Self, TemporalError> {
        if !authentication_phase(point.phase) {
            return Err(TemporalError::ForbiddenPhase);
        }
        let validity = match error {
            JwtError::NotActive { changes_at_ms }
                if changes_at_ms > point.checked_at_ms && changes_at_ms <= MAX_EXACT_CLOCK =>
            {
                Validity::Until(changes_at_ms)
            }
            JwtError::Expired { at_ms } if at_ms <= point.checked_at_ms => {
                // Already-expired negative has no future time-only wake.
                // NOT a positive clock proof: denied stays sticky below.
                Validity::ClockInvariant
            }
            _ => return Err(TemporalError::ProvenanceMismatch),
        };
        Ok(Self {
            point,
            validity,
            not_before_ms: point.checked_at_ms,
            denied: true,
            callback_clock_covered: false,
        })
    }
    /// Explicit whole-callback native coverage trust boundary; dependency
    /// bookkeeping alone NEVER proves an arbitrary raw callback clock read.
    ///
    /// # Safety
    /// Actual native audited callback/code certificate at self.point proves
    /// EVERY clock-dependent decision of THIS callback is covered by this
    /// actual authenticated/evaluated witness, including hidden/failing paths.
    /// This is NOT a verifier, stable assertion, guest flag or signer claim.
    /// Independent policy output and negative JWT outcomes cannot provide it.
    pub(crate) unsafe fn with_native_callback_clock_coverage(
        mut self,
    ) -> Result<Self, TemporalError> {
        if self.denied || self.validity == Validity::Independent {
            return Err(TemporalError::Uncertified);
        }
        self.callback_clock_covered = true;
        Ok(self)
    }
    pub(crate) fn from_trusted_lease(boundary: NativeTrustedLeaseBoundary) -> Self {
        Self {
            point: boundary.point,
            validity: Validity::Until(boundary.expires_at_ms),
            not_before_ms: boundary.point.checked_at_ms,
            denied: false,
            callback_clock_covered: false,
        }
    }
}

/// Actual native lease/grant/oversight expiry; never an execution timeout.
#[derive(Clone, Copy, Debug)]
pub(crate) struct NativeTrustedLeaseBoundary {
    point: NativeTimePoint,
    expires_at_ms: u64,
}
impl NativeTrustedLeaseBoundary {
    /// # Safety
    /// Native validation authenticated the actual lease/grant row, scope,
    /// revocation/freshness and explicit expiration at this exact certified
    /// phase/checked-clock point. Complete dependency coverage is required if
    /// used to discharge callback clock reads. JobControl's 10s deadline,
    /// guest flags/signers/claims and clock+120s result-proof bound are NEVER
    /// permission provenance. This type is NOT a lease/certificate verifier.
    pub(crate) unsafe fn from_native_validation(
        point: NativeTimePoint,
        expires_at_ms: u64,
    ) -> Result<Self, TemporalError> {
        if !permission_phase(point.phase) {
            return Err(TemporalError::ForbiddenPhase);
        }
        if expires_at_ms <= point.checked_at_ms || expires_at_ms > MAX_EXACT_CLOCK {
            return Err(TemporalError::InvalidBoundary);
        }
        Ok(Self {
            point,
            expires_at_ms,
        })
    }
}

/// One callback's pending time declaration. Production owns it INSIDE the
/// original-job ledger, so abandoning a VM never abandons native poison.
/// Fixed scalar state: no source handles, dynamic owner, or Arc clone.
#[derive(Debug)]
pub(crate) struct CallbackTime {
    phase: NativePhase,
    issued_clock: u64,
    point: Option<NativeTimePoint>,
    clock_read: bool,
    declared_changes_at: bool,
    native_clock_covered: bool,
    validity: Validity,
    denied: bool,
    failure: Option<TemporalError>,
}
impl CallbackTime {
    /// Native selection/issued time only, NEVER phase/time flags from wire.
    pub(crate) fn new(native_phase: NativePhase, issued_clock: u64) -> Result<Self, TemporalError> {
        if issued_clock > MAX_EXACT_CLOCK {
            return Err(TemporalError::InvalidClock);
        }
        Ok(Self {
            phase: native_phase,
            issued_clock,
            point: None,
            clock_read: false,
            declared_changes_at: false,
            native_clock_covered: false,
            validity: Validity::Independent,
            denied: false,
            failure: None,
        })
    }
    fn fail(&mut self, error: TemporalError) -> TemporalError {
        let error = self.failure.unwrap_or(error);
        self.failure = Some(error);
        error
    }
    fn check(&self) -> Result<(), TemporalError> {
        self.failure.map_or(Ok(()), Err)
    }
    /// Permission CLOCK is pending until finish. Readless CLOCK is issued
    /// metadata only, NEVER a permission-cache proof.
    pub(crate) fn read_clock(&mut self) -> Result<u64, TemporalError> {
        self.check()?;
        if permission_phase(self.phase) {
            self.clock_read = true;
        }
        Ok(self.issued_clock)
    }
    /// First now() call is fatal even if caught/substituted with clock later.
    pub(crate) fn poll_now(&mut self) -> Result<u64, TemporalError> {
        self.check()?;
        Err(self.fail(if permission_phase(self.phase) {
            TemporalError::Uncertified
        } else {
            TemporalError::ForbiddenPhase
        }))
    }
    /// Trusted deployed callback's actual earliest semantic flip. Borrowed
    /// numeric scalar only: no coercion/stringification/heap/stable null claim.
    pub(crate) fn declare_changes_at(&mut self, value: WireValue<'_>) -> Result<(), TemporalError> {
        self.check()?;
        if !permission_phase(self.phase) {
            return Err(self.fail(TemporalError::ForbiddenPhase));
        }
        let Some(value) = value.as_f64() else {
            return Err(self.fail(TemporalError::InvalidBoundary));
        };
        if !value.is_finite()
            || value.fract() != 0.0
            || value <= self.issued_clock as f64
            || value > MAX_EXACT_CLOCK as f64
        {
            return Err(self.fail(TemporalError::InvalidBoundary));
        }
        self.validity = self.validity.intersect(Validity::Until(value as u64));
        self.declared_changes_at = true;
        Ok(())
    }
    pub(crate) fn register_native_boundary(
        &mut self,
        boundary: NativeBoundary,
    ) -> Result<(), TemporalError> {
        self.check()?;
        if !permission_phase(self.phase) {
            return Err(self.fail(TemporalError::ForbiddenPhase));
        }
        if self.point != Some(boundary.point) {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        self.validity = self.validity.intersect(boundary.validity);
        self.denied |= boundary.denied;
        self.native_clock_covered |= boundary.callback_clock_covered;
        Ok(())
    }
    fn finish_success(&mut self) -> Result<Validity, TemporalError> {
        self.check()?;
        if self.denied {
            return Err(self.fail(TemporalError::AuthorizationDenied));
        }
        if self.clock_read && !self.declared_changes_at && !self.native_clock_covered {
            return Err(self.fail(TemporalError::Uncertified));
        }
        Ok(self.validity)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OriginalJobStamp {
    admitted: Instant,
    deadline: Instant,
    cancellation_identity: usize,
}
impl OriginalJobStamp {
    fn of(job: &JobControl) -> Self {
        Self {
            admitted: job.admitted(),
            deadline: job.deadline(),
            cancellation_identity: Arc::as_ptr(job.cancellation()) as usize,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallbackOutcome {
    Success,
    Failure,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CallbackCompletion {
    PermissionEvaluated,
    MetadataOnly,
    /// No positive temporal cert needed for denial delivery; NEVER cache.
    /// No SQL/operator/result/signing may follow this original-job rejection.
    RejectedUncacheable,
}
/// Temporal sub-certificate only, NOT authentication/source/cache admission.
/// Revalidate against the SAME ledger/job at publication; later evaluated
/// boundaries/callbacks make an earlier stamp stale.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PermissionStamp {
    job: OriginalJobStamp,
    ledger: u64,
    sequence: u64,
    validity: Validity,
    not_before_ms: Option<u64>,
}
impl PermissionStamp {
    pub(crate) fn validity(self) -> Validity {
        self.validity
    }
    pub(crate) fn not_before_ms(self) -> Option<u64> {
        self.not_before_ms
    }
}
/// Opaque qualification of one real pre-finalizer permission stamp. It is
/// ledger/job/sequence/native-point correlated, NOT a controller verifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FinishPermission {
    stamp: PermissionStamp,
    point: NativeTimePoint,
    finalizer_sequence: u64,
}
impl FinishPermission {
    pub(crate) fn valid_until(self) -> Option<u64> {
        match self.stamp.validity {
            Validity::Until(at) => Some(at),
            Validity::Independent | Validity::ClockInvariant => None,
        }
    }
}
/// ONE admitted account for the WHOLE original job including auth/fresh-auth,
/// authority/providers/hidden rows/capture replays. All boundaries intersect.
/// No source owner, provider, key, root, callback closure or heap is retained.
pub(crate) struct GlobalTemporalLedger {
    original_job: OriginalJobStamp,
    ledger: u64,
    latest_clock: Option<u64>,
    completed_finalizer: Option<u64>,
    deployment: Option<(u64, u64)>,
    active: Option<CallbackTime>,
    replay: Option<(NativePhase, bool)>,
    validity: Validity,
    not_before_ms: Option<u64>,
    failure: Option<TemporalError>,
    denied: bool,
    sequence: u64,
    permissions: u64,
}
impl GlobalTemporalLedger {
    pub(crate) fn new(original_job: &JobControl) -> Self {
        Self {
            original_job: OriginalJobStamp::of(original_job),
            ledger: NEXT_LEDGER
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                .expect("native temporal ledger identity exhausted"),
            latest_clock: None,
            completed_finalizer: None,
            deployment: None,
            active: None,
            replay: None,
            validity: Validity::Independent,
            not_before_ms: None,
            failure: None,
            denied: false,
            sequence: 0,
            permissions: 0,
        }
    }
    pub(crate) fn failure(&self) -> Option<TemporalError> {
        self.failure
    }
    pub(crate) fn validity(&self) -> Validity {
        self.validity
    }
    pub(crate) fn not_before_ms(&self) -> Option<u64> {
        self.not_before_ms
    }
    fn fail(&mut self, error: TemporalError) -> TemporalError {
        let error = self.failure.unwrap_or(error);
        self.failure = Some(error);
        error
    }
    fn check_job(&mut self, job: &mut JobControl) -> Result<(), TemporalError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.original_job != OriginalJobStamp::of(job) {
            return Err(self.fail(TemporalError::WrongOriginalJob));
        }
        job.check().map_err(|error| {
            self.fail(match error {
                SqlError::Cancelled => TemporalError::Cancelled,
                SqlError::Deadline => TemporalError::Deadline,
                _ => TemporalError::WrongOriginalJob,
            })
        })
    }
    fn check_clock(&mut self, native_now: u64, expiry: bool) -> Result<(), TemporalError> {
        if native_now > MAX_EXACT_CLOCK {
            return Err(self.fail(TemporalError::InvalidClock));
        }
        if self.not_before_ms.is_some_and(|at| native_now < at)
            || self.latest_clock.is_some_and(|at| native_now < at)
        {
            return Err(self.fail(TemporalError::BackwardsClock));
        }
        if expiry && !self.validity.permits(native_now) {
            return Err(self.fail(TemporalError::Expired));
        }
        self.latest_clock = Some(native_now);
        Ok(())
    }
    fn absorb_active(&mut self) {
        if let Some(callback) = &self.active {
            self.validity = self.validity.intersect(callback.validity);
            if callback.clock_read || callback.validity != Validity::Independent {
                self.not_before_ms = Some(
                    self.not_before_ms
                        .map_or(callback.issued_clock, |old| old.max(callback.issued_clock)),
                );
            }
        }
    }
    pub(crate) fn begin_callback(
        &mut self,
        point: NativeTimePoint,
        job: &mut JobControl,
    ) -> Result<(), TemporalError> {
        self.check_job(job)?;
        if point.original_job != self.original_job {
            return Err(self.fail(TemporalError::WrongOriginalJob));
        }
        if self.denied {
            return Err(self.fail(TemporalError::AuthorizationDenied));
        }
        if self.active.is_some() {
            return Err(self.fail(TemporalError::CallbackPending));
        }
        if self.replay.is_some_and(|(phase, _)| phase != point.phase) {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        self.check_clock(point.checked_at_ms, true)?;
        let deployment = (point.deployment_epoch, point.catalog_epoch);
        if self.deployment.is_some_and(|old| old != deployment) {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        self.deployment = Some(deployment);
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| self.fail(TemporalError::ProvenanceMismatch))?;
        let mut callback = CallbackTime::new(point.phase, point.checked_at_ms)?;
        callback.point = Some(point);
        callback.clock_read = self.replay.is_some_and(|(_, read)| read);
        self.completed_finalizer = None;
        self.active = Some(callback);
        Ok(())
    }
    fn apply<T>(
        &mut self,
        job: &mut JobControl,
        call: impl FnOnce(&mut CallbackTime) -> Result<T, TemporalError>,
    ) -> Result<T, TemporalError> {
        self.check_job(job)?;
        let result = self
            .active
            .as_mut()
            .ok_or(TemporalError::NoCallback)
            .and_then(call);
        self.absorb_active();
        result.map_err(|error| self.fail(error))
    }
    /// Exact already-controller-issued point of the active callback. Root read
    /// helpers use this instead of reconstructing any point from binding/phase.
    pub(crate) fn active_point(
        &mut self,
        job: &mut JobControl,
    ) -> Result<NativeTimePoint, TemporalError> {
        self.apply(job, |callback| {
            callback.point.ok_or(TemporalError::ProvenanceMismatch)
        })
    }
    pub(crate) fn read_clock(&mut self, job: &mut JobControl) -> Result<u64, TemporalError> {
        self.apply(job, CallbackTime::read_clock)
    }
    pub(crate) fn poll_now(&mut self, job: &mut JobControl) -> Result<u64, TemporalError> {
        self.apply(job, CallbackTime::poll_now)
    }
    pub(crate) fn declare_changes_at(
        &mut self,
        job: &mut JobControl,
        value: WireValue<'_>,
    ) -> Result<(), TemporalError> {
        self.apply(job, |callback| callback.declare_changes_at(value))
    }
    pub(crate) fn register_native_boundary(
        &mut self,
        boundary: NativeBoundary,
        job: &mut JobControl,
    ) -> Result<(), TemporalError> {
        self.apply(job, |callback| callback.register_native_boundary(boundary))?;
        if boundary.validity != Validity::Independent {
            self.not_before_ms = Some(self.not_before_ms.map_or(boundary.not_before_ms, |old| {
                old.max(boundary.not_before_ms)
            }));
        }
        Ok(())
    }
    /// Fresh native check before/after traversal/seal/publication. Allowed
    /// during pending declaration: returning CLOCK need not prematurely fail.
    /// Only success finish/permission stamp requires completed clock coverage.
    pub(crate) fn check_native_clock(
        &mut self,
        job: &mut JobControl,
        fresh_native_clock: u64,
    ) -> Result<(), TemporalError> {
        self.check_job(job)?;
        if self.denied {
            return Err(self.fail(TemporalError::AuthorizationDenied));
        }
        self.check_clock(fresh_native_clock, true)
    }
    pub(crate) fn finish_callback(
        &mut self,
        job: &mut JobControl,
        outcome: CallbackOutcome,
        fresh_native_clock: u64,
    ) -> Result<CallbackCompletion, TemporalError> {
        self.check_job(job)?;
        if self.active.is_none() {
            return Err(self.fail(TemporalError::NoCallback));
        }
        if outcome == CallbackOutcome::Failure {
            // Plain clock/crossed expiry need no positive cert for negative
            // delivery. poll_now/capability/invalid failures remain fatal.
            self.check_clock(fresh_native_clock, false)?;
            self.active = None;
            self.denied = true;
            return Ok(CallbackCompletion::RejectedUncacheable);
        }
        let validity = self.apply(job, CallbackTime::finish_success)?;
        self.check_clock(fresh_native_clock, true)?;
        let callback = self.active.take().ok_or(TemporalError::NoCallback)?;
        self.replay = None;
        if permission_phase(callback.phase) {
            self.permissions = self
                .permissions
                .checked_add(1)
                .ok_or_else(|| self.fail(TemporalError::ProvenanceMismatch))?;
            self.validity = self.validity.intersect(validity);
            Ok(CallbackCompletion::PermissionEvaluated)
        } else {
            if callback.phase == NativePhase::ReadlessFinalizer {
                self.completed_finalizer = Some(self.sequence);
            }
            Ok(CallbackCompletion::MetadataOnly)
        }
    }
    /// ONLY for actual native NeedCapture after destroying abandoned VM.
    /// No result/permission is produced; all boundaries/clock floors survive.
    /// Pending clock coverage may be supplied by full replay, never now poison.
    /// This is not a general error reset and cannot retry native denial.
    pub(crate) fn abandon_for_native_capture(
        &mut self,
        job: &mut JobControl,
    ) -> Result<(), TemporalError> {
        self.check_job(job)?;
        let Some(callback) = &self.active else {
            return Err(self.fail(TemporalError::NoCallback));
        };
        if callback.denied {
            return Err(self.fail(TemporalError::AuthorizationDenied));
        }
        self.replay = Some((callback.phase, callback.clock_read));
        self.absorb_active();
        self.active = None;
        Ok(())
    }
    pub(crate) fn permission_stamp(
        &mut self,
        job: &mut JobControl,
        fresh_native_clock: u64,
    ) -> Result<PermissionStamp, TemporalError> {
        self.check_native_clock(job, fresh_native_clock)?;
        if self.active.is_some() || self.replay.is_some() {
            return Err(self.fail(TemporalError::CallbackPending));
        }
        if self.permissions == 0 {
            return Err(self.fail(TemporalError::NoPermission));
        }
        Ok(PermissionStamp {
            job: self.original_job,
            ledger: self.ledger,
            sequence: self.sequence,
            validity: self.validity,
            not_before_ms: self.not_before_ms,
        })
    }
    pub(crate) fn qualify_finalizer(
        &mut self,
        job: &mut JobControl,
        stamp: PermissionStamp,
        point: NativeTimePoint,
    ) -> Result<FinishPermission, TemporalError> {
        self.validate_permission_stamp(job, stamp, point.checked_at_ms)?;
        if point.original_job != self.original_job
            || point.phase != NativePhase::ReadlessFinalizer
            || self.deployment != Some((point.deployment_epoch, point.catalog_epoch))
        {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        let finalizer_sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| self.fail(TemporalError::ProvenanceMismatch))?;
        Ok(FinishPermission {
            stamp,
            point,
            finalizer_sequence,
        })
    }
    pub(crate) fn validate_finalizer_permission(
        &mut self,
        job: &mut JobControl,
        permission: FinishPermission,
        fresh_native_clock: u64,
        publishing: bool,
    ) -> Result<Option<u64>, TemporalError> {
        self.check_native_clock(job, fresh_native_clock)?;
        let stamp = permission.stamp;
        let active_matches = self
            .active
            .as_ref()
            .is_some_and(|callback| callback.point == Some(permission.point));
        if stamp.job != self.original_job
            || stamp.ledger != self.ledger
            || permission.finalizer_sequence != self.sequence
            || stamp.sequence.checked_add(1) != Some(self.sequence)
            || stamp.validity != self.validity
            || stamp.not_before_ms != self.not_before_ms
            || self.replay.is_some()
            || (publishing
                && (self.active.is_some() || self.completed_finalizer != Some(self.sequence)))
            || (!publishing && !active_matches)
        {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        Ok(permission.valid_until())
    }
    pub(crate) fn validate_permission_stamp(
        &mut self,
        job: &mut JobControl,
        stamp: PermissionStamp,
        fresh_native_clock: u64,
    ) -> Result<(), TemporalError> {
        let current = self.permission_stamp(job, fresh_native_clock)?;
        if current != stamp {
            return Err(self.fail(TemporalError::ProvenanceMismatch));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "temporal_tests.rs"]
mod tests;
