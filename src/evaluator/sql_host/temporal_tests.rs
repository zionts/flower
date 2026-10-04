#![allow(unexpected_cfgs)] // Standalone actual-source reference, not serving activation.
use super::*;
use crate::evaluator::{
    sql_bridge::{WireArena, WireError, WireLimits},
    sql_frame::{FrameBuilder, FrameControl, FrameLimits, JsonBank, JsonId},
    sql_policy::{
        CapturedCollection, CapturedSupport, MAX_POLICY_WORK, PolicyBudget, PolicyEngine,
        VerifiedPrincipal,
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

fn job() -> JobControl {
    JobControl::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
}
// Synthetic native certificate fixture ONLY; not a certificate verifier or a
// claim that these unit tests prove serving freshness/source admission.
fn point(job: &JobControl, phase: NativePhase, now: u64) -> NativeTimePoint {
    unsafe { NativeTimePoint::from_certified_native_point(job, phase, now, 17, 3, 5) }.unwrap()
}
fn wire() -> WireArena {
    WireArena::new(WireLimits {
        message_bytes: 4096,
        text_bytes: 4096,
        nodes: 128,
        keys: 128,
        logical_key_bytes: 4096,
        output_bytes: 4096,
        depth: 16,
        job_work: 64 * 1024,
    })
    .unwrap()
}
fn begin(phase: NativePhase, now: u64) -> (JobControl, GlobalTemporalLedger) {
    let mut job = job();
    let mut ledger = GlobalTemporalLedger::new(&job);
    ledger
        .begin_callback(point(&job, phase, now), &mut job)
        .unwrap();
    (job, ledger)
}
fn declare(ledger: &mut GlobalTemporalLedger, job: &mut JobControl, at: u64) {
    let mut arena = wire();
    let id = arena.real(at as f64).unwrap();
    ledger
        .declare_changes_at(job, arena.value(id).unwrap())
        .unwrap();
}
fn finish(ledger: &mut GlobalTemporalLedger, job: &mut JobControl, now: u64) {
    assert_eq!(
        ledger.finish_callback(job, CallbackOutcome::Success, now),
        Ok(CallbackCompletion::PermissionEvaluated)
    );
}
fn lease(point: NativeTimePoint, expiry: u64) -> NativeBoundary {
    // Test-only native lease fixture, NOT validation of a deployed lease.
    NativeBoundary::from_trusted_lease(
        unsafe { NativeTrustedLeaseBoundary::from_native_validation(point, expiry) }.unwrap(),
    )
}

#[test]
fn static_callbacks_without_clock_are_independent_in_all_permission_phases() {
    for phase in [
        NativePhase::InitialAuth,
        NativePhase::FreshAuth,
        NativePhase::Authority,
        NativePhase::Provider,
    ] {
        let (mut job, mut ledger) = begin(phase, 100);
        finish(&mut ledger, &mut job, 101);
        let stamp = ledger.permission_stamp(&mut job, 102).unwrap();
        assert_eq!(stamp.validity(), Validity::Independent);
        assert_eq!(stamp.not_before_ms(), None);
        ledger
            .validate_permission_stamp(&mut job, stamp, 103)
            .unwrap();
    }
}
#[test]
fn clock_can_return_before_declaration_but_clock_only_success_is_fatal() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    assert_eq!(ledger.read_clock(&mut job), Ok(100));
    ledger.check_native_clock(&mut job, 100).unwrap(); // pre/post traversal okay
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 100),
        Err(TemporalError::Uncertified)
    );
    assert_eq!(ledger.failure(), Some(TemporalError::Uncertified));
    assert_eq!(
        ledger.permission_stamp(&mut job, 100),
        Err(TemporalError::Uncertified)
    );
}
#[test]
fn caught_now_then_clock_and_changes_at_cannot_rescue_any_permission_phase() {
    let mut arena = wire();
    let id = arena.integer(101).unwrap();
    for phase in [
        NativePhase::InitialAuth,
        NativePhase::FreshAuth,
        NativePhase::Authority,
        NativePhase::Provider,
    ] {
        let (mut job, mut ledger) = begin(phase, 100);
        let _caught_by_guest = ledger.poll_now(&mut job);
        assert_eq!(ledger.read_clock(&mut job), Err(TemporalError::Uncertified));
        assert_eq!(
            ledger.declare_changes_at(&mut job, arena.value(id).unwrap()),
            Err(TemporalError::Uncertified)
        );
        assert_eq!(
            ledger.register_native_boundary(lease(point(&job, phase, 100), 101), &mut job),
            Err(TemporalError::Uncertified)
        );
        assert_eq!(
            ledger.finish_callback(&mut job, CallbackOutcome::Failure, 100),
            Err(TemporalError::Uncertified)
        );
        assert_eq!(
            ledger.abandon_for_native_capture(&mut job),
            Err(TemporalError::Uncertified)
        );
    }
}
#[test]
fn exact_first_before_at_after_boundary_is_not_a_row_write() {
    for check in [100, 101, 102, 103] {
        let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
        assert_eq!(ledger.read_clock(&mut job), Ok(100));
        declare(&mut ledger, &mut job, 102);
        finish(&mut ledger, &mut job, 100);
        let stamp = ledger.permission_stamp(&mut job, 100).unwrap();
        let result = ledger.validate_permission_stamp(&mut job, stamp, check);
        assert_eq!(
            result,
            if check < 102 {
                Ok(())
            } else {
                Err(TemporalError::Expired)
            }
        );
        assert_eq!(stamp.validity(), Validity::Until(102));
    }
}
#[test]
fn future_safe_integer_declarations_intersect_instead_of_extending() {
    let mut job = job();
    let mut ledger = GlobalTemporalLedger::new(&job);
    for (phase, now, expiry) in [
        (NativePhase::InitialAuth, 100, 120),
        (NativePhase::Authority, 101, 130),
        (NativePhase::Provider, 102, 110),
        (NativePhase::FreshAuth, 103, 140),
    ] {
        ledger
            .begin_callback(point(&job, phase, now), &mut job)
            .unwrap();
        ledger.read_clock(&mut job).unwrap();
        declare(&mut ledger, &mut job, expiry);
        declare(&mut ledger, &mut job, expiry + 100);
        finish(&mut ledger, &mut job, now);
    }
    assert_eq!(ledger.validity(), Validity::Until(110));
    assert_eq!(ledger.not_before_ms(), Some(103));
    let stamp = ledger.permission_stamp(&mut job, 109).unwrap();
    assert_eq!(
        ledger.validate_permission_stamp(&mut job, stamp, 110),
        Err(TemporalError::Expired)
    );
}
#[test]
fn changes_at_accepts_i32_and_real_exact_integer_representations() {
    for real in [false, true] {
        let mut arena = wire();
        let id = if real {
            arena.real(101.0)
        } else {
            arena.integer(101)
        }
        .unwrap();
        let (mut job, mut ledger) = begin(NativePhase::Provider, 100);
        ledger.read_clock(&mut job).unwrap();
        ledger
            .declare_changes_at(&mut job, arena.value(id).unwrap())
            .unwrap();
        finish(&mut ledger, &mut job, 100);
        assert_eq!(ledger.validity(), Validity::Until(101));
    }
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, MAX_EXACT_CLOCK - 1);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, MAX_EXACT_CLOCK);
    finish(&mut ledger, &mut job, MAX_EXACT_CLOCK - 1);
    assert_eq!(
        ledger.permission_stamp(&mut job, MAX_EXACT_CLOCK),
        Err(TemporalError::Expired)
    );
}
#[test]
fn null_fraction_past_equal_negative_text_bool_object_array_and_unsafe_integer_refuse() {
    let mut arena = wire();
    let ids = [
        arena.null().unwrap(),
        arena.real(100.5).unwrap(),
        arena.integer(99).unwrap(),
        arena.integer(100).unwrap(),
        arena.integer(-1).unwrap(),
        arena.real(-0.0).unwrap(),
        arena.real((1u64 << 53) as f64).unwrap(),
        arena.text("101").unwrap(),
        arena.boolean(true).unwrap(),
        arena.object().unwrap(),
        arena.array().unwrap(),
    ];
    for id in ids {
        let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
        ledger.read_clock(&mut job).unwrap();
        assert_eq!(
            ledger.declare_changes_at(&mut job, arena.value(id).unwrap()),
            Err(TemporalError::InvalidBoundary)
        );
        assert_eq!(
            ledger.finish_callback(&mut job, CallbackOutcome::Failure, 100),
            Err(TemporalError::InvalidBoundary)
        );
    }
}
#[test]
fn actual_wire_refuses_nan_and_infinite_before_borrowed_time_scalar() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut arena = wire();
        assert!(matches!(arena.real(value), Err(WireError::Invalid(_))));
        let mut arena = wire();
        let mut encoded = [0; 9];
        encoded[0] = crate::evaluator::wire::FLOAT;
        encoded[1..].copy_from_slice(&value.to_le_bytes());
        assert!(matches!(arena.decode(&encoded), Err(WireError::Invalid(_))));
    }
}
#[test]
fn readless_clock_is_metadata_only_and_no_permission_stamp() {
    for phase in [NativePhase::ReadlessPlan, NativePhase::ReadlessFinalizer] {
        let (mut job, mut ledger) = begin(phase, 100);
        assert_eq!(ledger.read_clock(&mut job), Ok(100));
        assert_eq!(
            ledger.finish_callback(&mut job, CallbackOutcome::Success, 100),
            Ok(CallbackCompletion::MetadataOnly)
        );
        assert_eq!(ledger.not_before_ms(), None);
        assert_eq!(
            ledger.permission_stamp(&mut job, 100),
            Err(TemporalError::NoPermission)
        );
    }
}
#[test]
fn readless_now_and_changes_at_are_native_fatal_not_catchable_metadata() {
    let mut arena = wire();
    let id = arena.integer(120_100).unwrap();
    for phase in [NativePhase::ReadlessPlan, NativePhase::ReadlessFinalizer] {
        let (mut job, mut ledger) = begin(phase, 100);
        assert_eq!(
            ledger.poll_now(&mut job),
            Err(TemporalError::ForbiddenPhase)
        );
        assert_eq!(
            ledger.read_clock(&mut job),
            Err(TemporalError::ForbiddenPhase)
        );
        let (mut job, mut ledger) = begin(phase, 100);
        assert_eq!(
            ledger.declare_changes_at(&mut job, arena.value(id).unwrap()),
            Err(TemporalError::ForbiddenPhase)
        );
        assert_eq!(
            unsafe {
                NativeTrustedLeaseBoundary::from_native_validation(point(&job, phase, 100), 120_100)
            }
            .unwrap_err(),
            TemporalError::ForbiddenPhase
        );
    }
}
#[test]
fn finalizer_clock_plus_120s_never_extends_authorization_cache_boundary() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 103);
    finish(&mut ledger, &mut job, 100);
    ledger
        .begin_callback(point(&job, NativePhase::ReadlessFinalizer, 102), &mut job)
        .unwrap();
    let result_proof_expiry = ledger.read_clock(&mut job).unwrap() + 120_000;
    assert_eq!(result_proof_expiry, 120_102);
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 102),
        Ok(CallbackCompletion::MetadataOnly)
    );
    assert_eq!(ledger.validity(), Validity::Until(103));
    assert_eq!(
        ledger.permission_stamp(&mut job, 103),
        Err(TemporalError::Expired)
    );
}
#[test]
fn backward_native_clock_is_sticky_even_if_future_clock_returns() {
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 120);
    finish(&mut ledger, &mut job, 100);
    assert_eq!(
        ledger.check_native_clock(&mut job, 99),
        Err(TemporalError::BackwardsClock)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 101),
        Err(TemporalError::BackwardsClock)
    );
}
#[test]
fn job_execution_deadline_is_not_permission_expiry_and_original_job_cannot_be_replaced() {
    let mut job =
        JobControl::new(Duration::from_secs(1), Arc::new(AtomicBool::new(false))).unwrap();
    let mut ledger = GlobalTemporalLedger::new(&job);
    ledger
        .begin_callback(point(&job, NativePhase::InitialAuth, 100), &mut job)
        .unwrap();
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 1_000_000);
    finish(&mut ledger, &mut job, 100);
    assert_eq!(ledger.validity(), Validity::Until(1_000_000));
    let mut replacement =
        JobControl::new(Duration::from_secs(1), job.cancellation().clone()).unwrap();
    assert_eq!(
        ledger.begin_callback(point(&job, NativePhase::FreshAuth, 101), &mut replacement),
        Err(TemporalError::WrongOriginalJob)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 101),
        Err(TemporalError::WrongOriginalJob)
    );
}
#[test]
fn cancellation_and_original_deadline_are_sticky_and_not_time_certificates() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    job.cancellation().store(true, Ordering::Release);
    assert_eq!(ledger.read_clock(&mut job), Err(TemporalError::Cancelled));
    job.cancellation().store(false, Ordering::Release);
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Failure, 100),
        Err(TemporalError::Cancelled)
    );
    let mut job =
        JobControl::new(Duration::from_nanos(1), Arc::new(AtomicBool::new(false))).unwrap();
    let mut ledger = GlobalTemporalLedger::new(&job);
    std::thread::sleep(Duration::from_millis(1)); // exact expiry test, not polling
    assert_eq!(
        ledger.begin_callback(point(&job, NativePhase::InitialAuth, 100), &mut job),
        Err(TemporalError::Deadline)
    );
    assert_eq!(ledger.validity(), Validity::Independent);
}
#[test]
fn native_point_phase_clock_revision_code_and_catalog_must_match_exactly() {
    for change in 0..5 {
        let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
        let expected = point(&job, NativePhase::Authority, 100);
        let mut other = expected;
        match change {
            0 => other.phase = NativePhase::Provider,
            1 => other.checked_at_ms = 101,
            2 => other.source_revision = 18,
            3 => other.deployment_epoch = 4,
            _ => other.catalog_epoch = 6,
        }
        assert_eq!(
            ledger.register_native_boundary(lease(other, 120), &mut job),
            Err(TemporalError::ProvenanceMismatch)
        );
        assert_eq!(
            ledger.read_clock(&mut job),
            Err(TemporalError::ProvenanceMismatch)
        );
    }
    for change_catalog in [false, true] {
        let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
        finish(&mut ledger, &mut job, 100);
        let mut next = point(&job, NativePhase::FreshAuth, 101);
        if change_catalog {
            next.catalog_epoch += 1;
        } else {
            next.deployment_epoch += 1;
        }
        assert_eq!(
            ledger.begin_callback(next, &mut job),
            Err(TemporalError::ProvenanceMismatch)
        );
    }
}
#[test]
fn native_invalid_claims_do_not_gain_temporal_provenance() {
    let job = job();
    let point = point(&job, NativePhase::InitialAuth, 100);
    assert_eq!(
        unsafe {
            NativeBoundary::from_verified_jwt(
                point,
                TimeDependency {
                    checked_at_ms: 99,
                    valid_from_ms: None,
                    expires_at_ms: 120,
                },
            )
        }
        .unwrap_err(),
        TemporalError::ProvenanceMismatch
    );
    assert_eq!(
        unsafe {
            NativeBoundary::from_verified_jwt(
                point,
                TimeDependency {
                    checked_at_ms: 100,
                    valid_from_ms: Some(101),
                    expires_at_ms: 120,
                },
            )
        }
        .unwrap_err(),
        TemporalError::ProvenanceMismatch
    );
    for expiry in [99, 100, MAX_EXACT_CLOCK + 1] {
        assert_eq!(
            unsafe {
                NativeBoundary::from_verified_jwt(
                    point,
                    TimeDependency {
                        checked_at_ms: 100,
                        valid_from_ms: None,
                        expires_at_ms: expiry,
                    },
                )
            }
            .unwrap_err(),
            TemporalError::InvalidBoundary
        );
        assert_eq!(
            unsafe { NativeTrustedLeaseBoundary::from_native_validation(point, expiry) }
                .unwrap_err(),
            TemporalError::InvalidBoundary
        );
    }
    for error in [
        JwtError::Signature,
        JwtError::Claims,
        JwtError::Invalid,
        JwtError::Authority,
        JwtError::NotActive { changes_at_ms: 100 },
        JwtError::Expired { at_ms: 101 },
    ] {
        assert_eq!(
            unsafe { NativeBoundary::from_verified_jwt_failure(point, error) }.unwrap_err(),
            TemporalError::ProvenanceMismatch
        );
    }
    assert!(matches!(
        CallbackTime::new(NativePhase::InitialAuth, MAX_EXACT_CLOCK + 1),
        Err(TemporalError::InvalidClock)
    ));
    assert_eq!(
        unsafe {
            NativeTimePoint::from_certified_native_point(
                &job,
                NativePhase::InitialAuth,
                100,
                17,
                0,
                5,
            )
        },
        Err(TemporalError::ProvenanceMismatch)
    );
}
#[test]
fn native_independent_policy_does_not_rescue_raw_clock() {
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    ledger.read_clock(&mut job).unwrap();
    ledger
        .register_native_boundary(
            unsafe {
                NativeBoundary::from_native_policy(
                    point(&job, NativePhase::Authority, 100),
                    Validity::Independent,
                )
            }
            .unwrap(),
            &mut job,
        )
        .unwrap();
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 100),
        Err(TemporalError::Uncertified)
    );
}
#[test]
fn plain_clock_business_failure_needs_no_positive_cert_but_stops_every_later_phase() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.read_clock(&mut job).unwrap();
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Failure, 101),
        Ok(CallbackCompletion::RejectedUncacheable)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 101),
        Err(TemporalError::AuthorizationDenied)
    );
    for phase in [
        NativePhase::Authority,
        NativePhase::Provider,
        NativePhase::FreshAuth,
        NativePhase::ReadlessFinalizer,
    ] {
        assert_eq!(
            ledger.begin_callback(point(&job, phase, 101), &mut job),
            Err(TemporalError::AuthorizationDenied)
        );
    }
}
#[test]
fn failed_outcome_after_crossed_expiry_is_uncacheable_not_a_grant() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    declare(&mut ledger, &mut job, 101);
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Failure, 102),
        Ok(CallbackCompletion::RejectedUncacheable)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 102),
        Err(TemporalError::AuthorizationDenied)
    );
}
#[test]
fn pending_callback_cannot_publish_or_begin_new_callback() {
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    assert_eq!(
        ledger.permission_stamp(&mut job, 100),
        Err(TemporalError::CallbackPending)
    );
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    assert_eq!(
        ledger.begin_callback(point(&job, NativePhase::Provider, 100), &mut job),
        Err(TemporalError::CallbackPending)
    );
}
#[test]
fn capture_replay_preserves_earliest_boundary_floor_phase_and_unfinished_clock() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 105);
    ledger.abandon_for_native_capture(&mut job).unwrap();
    ledger
        .begin_callback(point(&job, NativePhase::InitialAuth, 101), &mut job)
        .unwrap();
    declare(&mut ledger, &mut job, 120);
    finish(&mut ledger, &mut job, 101);
    assert_eq!(ledger.validity(), Validity::Until(105));
    assert_eq!(ledger.not_before_ms(), Some(101));
    assert_eq!(
        ledger.permission_stamp(&mut job, 105),
        Err(TemporalError::Expired)
    );
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.read_clock(&mut job).unwrap();
    ledger.abandon_for_native_capture(&mut job).unwrap();
    ledger
        .begin_callback(point(&job, NativePhase::InitialAuth, 101), &mut job)
        .unwrap();
    // Clock omission on replay cannot manufacture Independent.
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 101),
        Err(TemporalError::Uncertified)
    );
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.abandon_for_native_capture(&mut job).unwrap();
    assert_eq!(
        ledger.begin_callback(point(&job, NativePhase::Authority, 101), &mut job),
        Err(TemporalError::ProvenanceMismatch)
    );
}
#[test]
fn abandoned_provider_cannot_publish_earlier_auth_permission() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    finish(&mut ledger, &mut job, 100);
    ledger
        .begin_callback(point(&job, NativePhase::Provider, 101), &mut job)
        .unwrap();
    ledger.abandon_for_native_capture(&mut job).unwrap();
    assert_eq!(
        ledger.permission_stamp(&mut job, 101),
        Err(TemporalError::CallbackPending)
    );
}
#[test]
fn subsequent_callbacks_make_prior_stamp_stale_even_without_new_boundary() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    finish(&mut ledger, &mut job, 100);
    let stamp = ledger.permission_stamp(&mut job, 100).unwrap();
    ledger
        .begin_callback(point(&job, NativePhase::Provider, 101), &mut job)
        .unwrap();
    finish(&mut ledger, &mut job, 101);
    assert_eq!(
        ledger.validate_permission_stamp(&mut job, stamp, 101),
        Err(TemporalError::ProvenanceMismatch)
    );
}

fn frame_limits() -> FrameLimits {
    FrameLimits {
        raw_bytes: 0,
        support_bytes: 128 * 1024,
        decoded_bytes: 128 * 1024,
        nodes: 4096,
        documents: 64,
        keys: 0,
        key_bytes: 0,
        tables: 0,
        columns: 0,
        rows: 0,
        cells: 0,
        text_bytes: 0,
        provenance_bytes: 0,
        parse_work: 8 * 1024 * 1024,
    }
}
fn capture(frame: &mut FrameBuilder, text: &str, control: &FrameControl<'_>) -> JsonId {
    let id = frame.reserve_json(JsonBank::Support, text.len()).unwrap();
    frame.append_json_chunk(id, text.as_bytes()).unwrap();
    frame.finish_json(id, control).unwrap();
    id
}
fn with_policy<T>(
    policy: &str,
    rows: &[&str],
    now: u64,
    run: impl for<'a> FnOnce(
        PolicyEngine<'a>,
        &[crate::evaluator::sql_frame::ArenaValue<'a>],
        &PolicyBudget,
        &mut JobControl,
    ) -> T,
) -> T {
    let mut job = job();
    with_policy_on_job(&mut job, policy, rows, now, run)
}
fn with_policy_on_job<T>(
    job: &mut JobControl,
    policy: &str,
    rows: &[&str],
    now: u64,
    run: impl for<'a> FnOnce(
        PolicyEngine<'a>,
        &[crate::evaluator::sql_frame::ArenaValue<'a>],
        &PolicyBudget,
        &mut JobControl,
    ) -> T,
) -> T {
    let cancellation = job.cancellation().clone();
    let control = FrameControl::new(&cancellation, job.deadline());
    let mut frame = FrameBuilder::new(frame_limits(), &control).unwrap();
    let policy_id = capture(&mut frame, policy, &control);
    let principal_id = capture(&mut frame, "{}", &control);
    let row_ids: Vec<_> = rows
        .iter()
        .map(|row| capture(&mut frame, row, &control))
        .collect();
    let collections = [CapturedCollection {
        name: "root",
        policy: Some(frame.json(policy_id, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let principal = VerifiedPrincipal::from_native_auth(
        frame.json(principal_id, &control).unwrap(),
        &budget,
        job,
    )
    .unwrap();
    let rows: Vec<_> = row_ids
        .iter()
        .map(|id| frame.json(*id, &control).unwrap())
        .collect();
    run(
        PolicyEngine::new(support, principal, now),
        &rows,
        &budget,
        job,
    )
}
#[test]
fn actual_native_policy_clock_flip_first_before_at_after_without_any_write() {
    let policy = r#"{"read":{"gt":[{"ref":["row","oversight"]},{"ref":["now"]}]}}"#;
    for checked in [100, 101, 102, 103] {
        with_policy(
            policy,
            &[r#"{"oversight":102}"#],
            checked,
            |engine, rows, budget, job| {
                let decision = engine
                    .authorize("root", "key", rows[0], &[], budget, job)
                    .unwrap()
                    .decision;
                assert_eq!(decision.allowed, checked < 102);
                assert_eq!(
                    decision.validity,
                    if checked < 102 {
                        Validity::Until(102)
                    } else {
                        Validity::ClockInvariant
                    }
                );
                #[cfg(sql_policy_harness)]
                {
                    let actual_native = crate::reference::run(
                        &serde_json::from_str(policy).unwrap(),
                        &serde_json::json!({}),
                        &serde_json::json!({"oversight":102}),
                        "key",
                        &[],
                        checked,
                        &[],
                        &[],
                    );
                    assert_eq!(decision.allowed, actual_native.0);
                }
                let mut ledger = GlobalTemporalLedger::new(job);
                let point = point(job, NativePhase::Authority, checked);
                ledger.begin_callback(point, job).unwrap();
                ledger.read_clock(job).unwrap();
                let validity = budget.finish(job, checked).unwrap();
                ledger
                    .register_native_boundary(
                        unsafe {
                            NativeBoundary::from_native_policy(point, validity)
                                .unwrap()
                                .with_native_callback_clock_coverage()
                        }
                        .unwrap(),
                        job,
                    )
                    .unwrap();
                if decision.allowed {
                    finish(&mut ledger, job, checked);
                    let stamp = ledger.permission_stamp(job, checked).unwrap();
                    assert_eq!(
                        ledger.validate_permission_stamp(job, stamp, 102),
                        Err(TemporalError::Expired)
                    );
                } else {
                    assert_eq!(
                        ledger.finish_callback(job, CallbackOutcome::Failure, checked),
                        Ok(CallbackCompletion::RejectedUncacheable)
                    );
                    assert_eq!(
                        ledger.permission_stamp(job, checked),
                        Err(TemporalError::AuthorizationDenied)
                    );
                }
            },
        );
    }
}
#[test]
fn actual_hidden_row_boundary_participates_even_when_guest_never_sees_row() {
    // First hidden row becomes readable at 101; visible row expires at 120.
    let policy = r#"{"read":{"lt":[{"ref":["row","opens"]},{"ref":["now"]}]}}"#;
    with_policy(
        policy,
        &[r#"{"opens":100}"#, r#"{"opens":50}"#],
        100,
        |engine, rows, budget, job| {
            let hidden = engine
                .authorize("root", "hidden", rows[0], &[], budget, job)
                .unwrap();
            assert!(!hidden.decision.allowed);
            assert!(hidden.candidate.is_none());
            let visible = engine
                .authorize("root", "visible", rows[1], &[], budget, job)
                .unwrap();
            assert!(visible.decision.allowed);
            let point = point(job, NativePhase::Provider, 100);
            let mut ledger = GlobalTemporalLedger::new(job);
            ledger.begin_callback(point, job).unwrap();
            ledger
                .register_native_boundary(
                    unsafe {
                        NativeBoundary::from_native_policy(point, budget.finish(job, 100).unwrap())
                    }
                    .unwrap(),
                    job,
                )
                .unwrap();
            finish(&mut ledger, job, 100);
            assert_eq!(ledger.validity(), Validity::Until(101));
            assert_eq!(
                ledger.permission_stamp(job, 101),
                Err(TemporalError::Expired)
            );
        },
    );
}
#[test]
fn actual_field_policy_boundary_accumulates_before_projection() {
    let policy = r#"{"read":{"const":true},"fields":{"hidden":{"read":{"gt":[{"ref":["row","lease"]},{"ref":["now"]}]}}}}"#;
    with_policy(
        policy,
        &[r#"{"hidden":"private","lease":102}"#],
        100,
        |engine, rows, budget, job| {
            let result = engine
                .authorize("root", "key", rows[0], &[], budget, job)
                .unwrap();
            assert!(
                result
                    .candidate
                    .unwrap()
                    .field("hidden", budget, job)
                    .unwrap()
                    .is_some()
            );
            let point = point(job, NativePhase::Provider, 100);
            let mut ledger = GlobalTemporalLedger::new(job);
            ledger.begin_callback(point, job).unwrap();
            ledger
                .register_native_boundary(
                    unsafe {
                        NativeBoundary::from_native_policy(point, budget.finish(job, 100).unwrap())
                    }
                    .unwrap(),
                    job,
                )
                .unwrap();
            finish(&mut ledger, job, 100);
            assert_eq!(
                ledger.permission_stamp(job, 102),
                Err(TemporalError::Expired)
            );
        },
    );
}
#[test]
fn actual_native_policy_specific_invariant_can_cover_clock_but_null_declaration_cannot() {
    // Exact native comparison proof: no future integer time equals 100.5.
    let policy = r#"{"read":{"ne":[{"ref":["now"]},{"value":100.5}]}}"#;
    with_policy(policy, &["{}"], 100, |engine, rows, budget, job| {
        let decision = engine
            .authorize("root", "key", rows[0], &[], budget, job)
            .unwrap()
            .decision;
        assert!(decision.allowed);
        assert_eq!(decision.validity, Validity::ClockInvariant);
        let point = point(job, NativePhase::Authority, 100);
        let mut ledger = GlobalTemporalLedger::new(job);
        ledger.begin_callback(point, job).unwrap();
        ledger.read_clock(job).unwrap();
        ledger
            .register_native_boundary(
                unsafe {
                    NativeBoundary::from_native_policy(point, budget.finish(job, 100).unwrap())
                        .unwrap()
                        .with_native_callback_clock_coverage()
                }
                .unwrap(),
                job,
            )
            .unwrap();
        finish(&mut ledger, job, 100);
        let stamp = ledger.permission_stamp(job, 200).unwrap();
        assert_eq!(stamp.validity(), Validity::ClockInvariant);
        assert_eq!(stamp.not_before_ms(), Some(100));
    });
}

// Test fixture uses REAL production mounted loader + real Ed25519 verification.
// Key bytes, points and row grants are synthetic test fixtures, not a serving
// certificate proof. No mock TimeDependency substitutes for this verifier.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn actual_jwt(job: &mut JobControl, claims: &[u8], now: u64) -> Result<TimeDependency, JwtError> {
    use crate::crypto::sql_managed as jwt;
    use aes_gcm::{Aes256Gcm, KeyInit, aead::AeadInPlace};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ed25519_dalek::{Signer, SigningKey};
    use sha2::{Digest, Sha256};
    let seed = [7u8; 32];
    let wrapping = [9u8; 32];
    let dek = [11u8; 32];
    fn seal(key: &[u8; 32], nonce: [u8; 12], purpose: &str, payload: &[u8; 32]) -> String {
        let aad = serde_json::to_vec(&serde_json::json!([
            "flower-key-v1",
            "domain",
            "id",
            1,
            "Ed25519",
            purpose
        ]))
        .unwrap();
        let mut encrypted = payload.to_vec();
        let tag = Aes256Gcm::new_from_slice(key)
            .unwrap()
            .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), &aad, &mut encrypted)
            .unwrap();
        encrypted.extend_from_slice(&tag);
        URL_SAFE_NO_PAD.encode(encrypted)
    }
    let wrapping_id = URL_SAFE_NO_PAD.encode(Sha256::digest(wrapping));
    let wrapped_dek = seal(&wrapping, [1; 12], "dek", &dek);
    let ciphertext = seal(&dek, [2; 12], "material", &seed);
    let wrapping_nonce = URL_SAFE_NO_PAD.encode([1u8; 12]);
    let nonce = URL_SAFE_NO_PAD.encode([2u8; 12]);
    let message = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","kid":"flower.id.1","typ":"JWT"}"#),
        URL_SAFE_NO_PAD.encode(claims)
    );
    let signature = SigningKey::from_bytes(&seed).sign(message.as_bytes());
    let token = format!(
        "{}.{}",
        message,
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    );
    let cancellation = job.cancellation().clone();
    let control = jwt::Control::new(&cancellation, job.deadline(), 8 * 1024 * 1024).unwrap();
    let mut parser = FrameBuilder::new(frame_limits(), control.frame()).unwrap();
    let mut attr = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
    let mut stack = std::ptr::null_mut();
    let mut stack_bytes = 0;
    unsafe {
        assert_eq!(
            libc::pthread_getattr_np(libc::pthread_self(), attr.as_mut_ptr()),
            0
        );
        assert_eq!(
            libc::pthread_attr_getstack(attr.as_ptr(), &mut stack, &mut stack_bytes),
            0
        );
        assert_eq!(libc::pthread_attr_destroy(attr.as_mut_ptr()), 0);
    }
    // Exact currently enforced native thread extent, not an estimated bound.
    let native = unsafe { jwt::NativeAllowance::from_trusted_launch(stack_bytes, 0) }.unwrap();
    let mut workspace = jwt::Workspace::new(
        jwt::Workspace::required_admission(native).unwrap().bytes(),
        native,
        &control,
    )
    .unwrap();
    let key_point = jwt::FreshPoint {
        job: 1,
        snapshot: 17,
        certificate: [3; 32],
    };
    let grant = unsafe {
        jwt::Grant::from_trusted_capture(
            jwt::KeyFields {
                domain: "domain",
                id: "id",
                name: "tokens",
                algorithm: "Ed25519",
                declaration_algorithm: "Ed25519",
                binding_usages: &["verify"],
                declaration_usages: &["verify"],
                version: 1,
                active_version: 1,
                revoked: false,
                retired: false,
                envelope: Some(jwt::EnvelopeFields {
                    provider: "mounted",
                    wrapping_id: &wrapping_id,
                    wrapped_dek: &wrapped_dek,
                    wrapping_nonce: &wrapping_nonce,
                    ciphertext: &ciphertext,
                    nonce: &nonce,
                }),
            },
            jwt::Attenuation {
                phase: jwt::Phase::InitialAuthentication,
                definition: "$flower.authorize",
                authentication_key: Some("tokens"),
                signing_keys: &[],
            },
            key_point,
            &control,
        )
    }
    .unwrap();
    // Prepaid locked fixture input page, no serving provider/key source retained.
    struct Input(*mut u8, usize);
    impl Drop for Input {
        fn drop(&mut self) {
            unsafe {
                std::ptr::write_bytes(self.0, 0, self.1);
                libc::munlock(self.0.cast(), self.1);
                libc::munmap(self.0.cast(), self.1);
            }
        }
    }
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let input = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(input, libc::MAP_FAILED);
    let input = Input(input.cast(), page);
    unsafe {
        assert_eq!(libc::mlock(input.0.cast(), page), 0);
        assert_eq!(libc::madvise(input.0.cast(), page, libc::MADV_DONTDUMP), 0);
        std::ptr::write_bytes(input.0, 0, page);
    }
    let input_bytes = unsafe { &mut *input.0.cast::<[u8; 32]>() };
    input_bytes.copy_from_slice(&wrapping);
    // Fixture is configured known test material; no production mount-acquisition
    // certificate is claimed by this test's unsafe trust-boundary construction.
    workspace
        .prepare_mounted(
            &grant,
            key_point,
            unsafe { jwt::MountedWrapping::from_trusted_mount(input_bytes) },
            &control,
        )
        .unwrap();
    job.check().unwrap();
    workspace
        .verify(
            grant,
            key_point,
            token.as_bytes(),
            b"{}",
            now,
            &mut parser,
            &control,
        )
        .map(|verified| verified.dependency)
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn actual_jwt_expiration_is_earliest_before_lease_grant_oversight_table_and_hidden_row() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 15_000);
    let dependency = actual_jwt(&mut job, br#"{"exp":20,"nbf":10}"#, 15_000).unwrap();
    assert_eq!(
        dependency,
        TimeDependency {
            checked_at_ms: 15_000,
            valid_from_ms: Some(10_000),
            expires_at_ms: 20_000
        }
    );
    let point0 = point(&job, NativePhase::InitialAuth, 15_000);
    ledger.read_clock(&mut job).unwrap();
    ledger
        .register_native_boundary(
            unsafe {
                NativeBoundary::from_verified_jwt(point0, dependency)
                    .unwrap()
                    .with_native_callback_clock_coverage()
            }
            .unwrap(),
            &mut job,
        )
        .unwrap();
    declare(&mut ledger, &mut job, 200_000);
    finish(&mut ledger, &mut job, 15_000);
    for (phase, at, expiry) in [
        (NativePhase::Authority, 15_001, 25_000),
        (NativePhase::Provider, 15_002, 30_000),
        (NativePhase::FreshAuth, 15_003, 40_000),
    ] {
        ledger
            .begin_callback(point(&job, phase, at), &mut job)
            .unwrap();
        ledger
            .register_native_boundary(lease(point(&job, phase, at), expiry), &mut job)
            .unwrap();
        finish(&mut ledger, &mut job, at);
    }
    for (policy, rows, checked) in [
        (
            r#"{"read":{"gt":[{"ref":["row","oversight"]},{"ref":["now"]}]}}"#,
            &[r#"{"oversight":35000}"#][..],
            15_004,
        ),
        (
            r#"{"read":{"const":true},"fields":{"hidden":{"read":{"gt":[{"ref":["row","tableExpires"]},{"ref":["now"]}]}}}}"#,
            &[r#"{"hidden":"value","tableExpires":40000}"#][..],
            15_005,
        ),
        (
            r#"{"read":{"lt":[{"ref":["row","opens"]},{"ref":["now"]}]}}"#,
            &[r#"{"opens":44999}"#, r#"{"opens":10000}"#][..],
            15_006,
        ),
    ] {
        with_policy_on_job(
            &mut job,
            policy,
            rows,
            checked,
            |engine, rows, budget, job| {
                for row in rows {
                    let candidate = engine
                        .authorize("root", "key", *row, &[], budget, job)
                        .unwrap()
                        .candidate;
                    if let Some(candidate) = candidate {
                        candidate.field("hidden", budget, job).unwrap();
                    }
                }
                let validity = budget.finish(job, checked).unwrap();
                let native = point(job, NativePhase::Provider, checked);
                ledger.begin_callback(native, job).unwrap();
                ledger
                    .register_native_boundary(
                        unsafe { NativeBoundary::from_native_policy(native, validity) }.unwrap(),
                        job,
                    )
                    .unwrap();
                finish(&mut ledger, job, checked);
            },
        );
    }
    assert_eq!(ledger.validity(), Validity::Until(20_000));
    let stamp = ledger.permission_stamp(&mut job, 19_999).unwrap();
    assert_eq!(
        ledger.validate_permission_stamp(&mut job, stamp, 20_000),
        Err(TemporalError::Expired)
    );
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn actual_jwt_nbf_first_before_at_after_requires_new_auth_not_future_deny_cache() {
    for checked in [9_999, 10_000, 10_001] {
        let (mut job, mut ledger) = begin(NativePhase::InitialAuth, checked);
        let result = actual_jwt(&mut job, br#"{"exp":20,"nbf":10}"#, checked);
        let native = point(&job, NativePhase::InitialAuth, checked);
        match result {
            Ok(dependency) => {
                ledger
                    .register_native_boundary(
                        unsafe { NativeBoundary::from_verified_jwt(native, dependency) }.unwrap(),
                        &mut job,
                    )
                    .unwrap();
                finish(&mut ledger, &mut job, checked);
                assert_eq!(
                    ledger
                        .permission_stamp(&mut job, checked)
                        .unwrap()
                        .validity(),
                    Validity::Until(20_000)
                );
            }
            Err(error) => {
                assert_eq!(
                    error,
                    JwtError::NotActive {
                        changes_at_ms: 10_000
                    }
                );
                ledger
                    .register_native_boundary(
                        unsafe { NativeBoundary::from_verified_jwt_failure(native, error) }
                            .unwrap(),
                        &mut job,
                    )
                    .unwrap();
                assert_eq!(
                    ledger.finish_callback(&mut job, CallbackOutcome::Failure, checked),
                    Ok(CallbackCompletion::RejectedUncacheable)
                );
                assert_eq!(
                    ledger.permission_stamp(&mut job, 10_000),
                    Err(TemporalError::AuthorizationDenied)
                );
            }
        }
    }
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn actual_jwt_not_active_reports_earlier_expiry_when_nbf_is_later() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 15_000);
    let error = actual_jwt(&mut job, br#"{"exp":20,"nbf":30}"#, 15_000).unwrap_err();
    assert_eq!(
        error,
        JwtError::NotActive {
            changes_at_ms: 20_000
        }
    );
    ledger
        .register_native_boundary(
            unsafe {
                NativeBoundary::from_verified_jwt_failure(
                    point(&job, NativePhase::InitialAuth, 15_000),
                    error,
                )
            }
            .unwrap(),
            &mut job,
        )
        .unwrap();
    assert_eq!(ledger.validity(), Validity::Until(20_000));
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 15_000),
        Err(TemporalError::AuthorizationDenied)
    );
    assert_eq!(
        actual_jwt(&mut job, br#"{"exp":20,"nbf":30}"#, 20_000),
        Err(JwtError::Expired { at_ms: 20_000 })
    );
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn actual_jwt_expired_business_failure_is_uncacheable_even_after_late_declaration() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 20_000);
    let error = actual_jwt(&mut job, br#"{"exp":20,"nbf":10}"#, 20_000).unwrap_err();
    ledger
        .register_native_boundary(
            unsafe {
                NativeBoundary::from_verified_jwt_failure(
                    point(&job, NativePhase::InitialAuth, 20_000),
                    error,
                )
            }
            .unwrap(),
            &mut job,
        )
        .unwrap();
    declare(&mut ledger, &mut job, 999_999);
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Failure, 20_001),
        Ok(CallbackCompletion::RejectedUncacheable)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 20_001),
        Err(TemporalError::AuthorizationDenied)
    );
}
#[test]
fn full_postadmission_scalar_phases_and_refusals_allocate_zero_rust_heap() {
    let mut arena = wire();
    let expiry = arena.integer(102).unwrap();
    let late = arena.real(10_000.0).unwrap();
    let invalid = arena.null().unwrap();
    let mut job = job();
    let mut ledger = GlobalTemporalLedger::new(&job);
    let p0 = point(&job, NativePhase::InitialAuth, 100);
    let p1 = point(&job, NativePhase::Provider, 101);
    let ((stamp, stop), allocations, bytes) = crate::allocation_probe::measure(|| {
        ledger.begin_callback(p0, &mut job).unwrap();
        ledger.read_clock(&mut job).unwrap();
        ledger
            .declare_changes_at(&mut job, arena.value(expiry).unwrap())
            .unwrap();
        finish(&mut ledger, &mut job, 100);
        ledger.begin_callback(p1, &mut job).unwrap();
        ledger
            .declare_changes_at(&mut job, arena.value(late).unwrap())
            .unwrap();
        ledger
            .register_native_boundary(lease(p1, 500), &mut job)
            .unwrap();
        finish(&mut ledger, &mut job, 101);
        let stamp = ledger.permission_stamp(&mut job, 101).unwrap();
        let stop = ledger.validate_permission_stamp(&mut job, stamp, 102);
        (stamp, stop)
    });
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(stamp.validity(), Validity::Until(102));
    assert_eq!(stop, Err(TemporalError::Expired));
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    let (error, allocations, bytes) = crate::allocation_probe::measure(|| {
        ledger.declare_changes_at(&mut job, arena.value(invalid).unwrap())
    });
    assert_eq!(
        (error, allocations, bytes),
        (Err(TemporalError::InvalidBoundary), 0, 0)
    );
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    let (error, allocations, bytes) = crate::allocation_probe::measure(|| {
        let _caught = ledger.poll_now(&mut job);
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 100)
    });
    assert_eq!(
        (error, allocations, bytes),
        (Err(TemporalError::Uncertified), 0, 0)
    );
}
#[test]
fn actual_policy_and_temporal_ledger_postadmission_allocate_zero_rust_heap() {
    with_policy(
        r#"{"read":{"gt":[{"ref":["row","oversight"]},{"ref":["now"]}]}}"#,
        &[r#"{"oversight":102}"#],
        100,
        |engine, rows, budget, job| {
            let mut ledger = GlobalTemporalLedger::new(job);
            let point = point(job, NativePhase::Provider, 100);
            let (stop, allocations, bytes) = crate::allocation_probe::measure(|| {
                ledger.begin_callback(point, job).unwrap();
                ledger.read_clock(job).unwrap();
                engine
                    .authorize("root", "key", rows[0], &[], budget, job)
                    .unwrap();
                ledger
                    .register_native_boundary(
                        unsafe {
                            NativeBoundary::from_native_policy(
                                point,
                                budget.finish(job, 100).unwrap(),
                            )
                            .unwrap()
                            .with_native_callback_clock_coverage()
                        }
                        .unwrap(),
                        job,
                    )
                    .unwrap();
                finish(&mut ledger, job, 100);
                ledger.permission_stamp(job, 102)
            });
            assert_eq!(
                (stop, allocations, bytes),
                (Err(TemporalError::Expired), 0, 0)
            );
        },
    );
}
#[test]
fn fixed_account_has_no_drop_or_dynamic_owner_and_probe_positive_control_works() {
    assert!(!std::mem::needs_drop::<CallbackTime>());
    assert!(!std::mem::needs_drop::<GlobalTemporalLedger>());
    assert!(std::mem::size_of::<GlobalTemporalLedger>() <= 512);
    let (value, allocations, bytes) =
        crate::allocation_probe::measure(|| std::hint::black_box(vec![0u8; 64]));
    assert!(allocations >= 1);
    assert!(bytes >= 64);
    drop(value);
}

#[test]
fn unrelated_native_boundary_does_not_certify_raw_clock_without_explicit_native_coverage() {
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    let native = point(&job, NativePhase::Authority, 100);
    ledger.read_clock(&mut job).unwrap();
    ledger
        .register_native_boundary(lease(native, 120), &mut job)
        .unwrap();
    assert_eq!(ledger.validity(), Validity::Until(120));
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 100),
        Err(TemporalError::Uncertified)
    );
    let (mut job, mut ledger) = begin(NativePhase::Authority, 100);
    let native = point(&job, NativePhase::Authority, 100);
    ledger.read_clock(&mut job).unwrap();
    // Synthetic audited callback fixture: this callback does ONLY this exact
    // validated lease-time comparison. No arbitrary guest stable flag exists.
    let witness = unsafe { lease(native, 120).with_native_callback_clock_coverage() }.unwrap();
    ledger.register_native_boundary(witness, &mut job).unwrap();
    finish(&mut ledger, &mut job, 100);
    assert_eq!(
        ledger.permission_stamp(&mut job, 119).unwrap().validity(),
        Validity::Until(120)
    );
}
#[test]
fn native_clock_coverage_cannot_be_independent_or_negative_or_change_point() {
    let job = job();
    let native = point(&job, NativePhase::InitialAuth, 100);
    let independent =
        unsafe { NativeBoundary::from_native_policy(native, Validity::Independent) }.unwrap();
    assert_eq!(
        unsafe { independent.with_native_callback_clock_coverage() }.unwrap_err(),
        TemporalError::Uncertified
    );
    let denial = unsafe {
        NativeBoundary::from_verified_jwt_failure(
            native,
            JwtError::NotActive { changes_at_ms: 120 },
        )
    }
    .unwrap();
    assert_eq!(
        unsafe { denial.with_native_callback_clock_coverage() }.unwrap_err(),
        TemporalError::Uncertified
    );
    for phase in [
        NativePhase::Authority,
        NativePhase::Provider,
        NativePhase::ReadlessPlan,
        NativePhase::ReadlessFinalizer,
    ] {
        let native = point(&job, phase, 100);
        assert_eq!(
            unsafe {
                NativeBoundary::from_verified_jwt(
                    native,
                    TimeDependency {
                        checked_at_ms: 100,
                        valid_from_ms: None,
                        expires_at_ms: 120,
                    },
                )
            }
            .unwrap_err(),
            TemporalError::ForbiddenPhase
        );
        assert_eq!(
            unsafe {
                NativeBoundary::from_verified_jwt_failure(
                    native,
                    JwtError::NotActive { changes_at_ms: 120 },
                )
            }
            .unwrap_err(),
            TemporalError::ForbiddenPhase
        );
    }
}
#[test]
fn native_callback_binding_and_original_point_job_are_checked_not_just_public_numbers() {
    let job = job();
    let native = point(&job, NativePhase::InitialAuth, 100);
    assert_eq!(
        native.validate_callback_binding(NativePhase::InitialAuth, 100, 17),
        Ok(())
    );
    for (phase, clock, revision) in [
        (NativePhase::FreshAuth, 100, 17),
        (NativePhase::InitialAuth, 101, 17),
        (NativePhase::InitialAuth, 100, 18),
    ] {
        assert_eq!(
            native.validate_callback_binding(phase, clock, revision),
            Err(TemporalError::ProvenanceMismatch)
        );
    }
    let mut other = JobControl::new(Duration::from_secs(10), job.cancellation().clone()).unwrap();
    let mut ledger = GlobalTemporalLedger::new(&other);
    assert_eq!(
        ledger.begin_callback(native, &mut other),
        Err(TemporalError::WrongOriginalJob)
    );
    assert_eq!(
        ledger.permission_stamp(&mut other, 100),
        Err(TemporalError::WrongOriginalJob)
    );
}
#[test]
fn first_before_at_after_fresh_native_clocks_and_fresh_auth_keep_one_original_job() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 100);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 102);
    finish(&mut ledger, &mut job, 100);
    ledger.check_native_clock(&mut job, 100).unwrap();
    ledger
        .begin_callback(point(&job, NativePhase::FreshAuth, 101), &mut job)
        .unwrap();
    declare(&mut ledger, &mut job, 110); // Cannot extend original auth expiration.
    finish(&mut ledger, &mut job, 101);
    let stamp = ledger.permission_stamp(&mut job, 101).unwrap();
    assert_eq!(stamp.validity(), Validity::Until(102));
    assert_eq!(
        ledger.validate_permission_stamp(&mut job, stamp, 102),
        Err(TemporalError::Expired)
    );
    assert_eq!(
        ledger.validate_permission_stamp(&mut job, stamp, 103),
        Err(TemporalError::Expired)
    );
    assert_eq!(
        ledger.begin_callback(point(&job, NativePhase::FreshAuth, 103), &mut job),
        Err(TemporalError::Expired)
    );
}
#[test]
fn clock_boundary_crossing_before_callback_finish_blocks_success_without_any_write() {
    let (mut job, mut ledger) = begin(NativePhase::Provider, 100);
    ledger.read_clock(&mut job).unwrap();
    declare(&mut ledger, &mut job, 101);
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 101),
        Err(TemporalError::Expired)
    );
    assert_eq!(
        ledger.permission_stamp(&mut job, 102),
        Err(TemporalError::Expired)
    );
}
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[test]
fn actual_verified_jwt_is_dependency_not_unrelated_raw_callback_clock_proof() {
    let (mut job, mut ledger) = begin(NativePhase::InitialAuth, 15_000);
    let dependency = actual_jwt(&mut job, br#"{"exp":20,"nbf":10}"#, 15_000).unwrap();
    ledger.read_clock(&mut job).unwrap();
    let boundary = unsafe {
        NativeBoundary::from_verified_jwt(point(&job, NativePhase::InitialAuth, 15_000), dependency)
    }
    .unwrap();
    ledger.register_native_boundary(boundary, &mut job).unwrap();
    assert_eq!(
        ledger.finish_callback(&mut job, CallbackOutcome::Success, 15_000),
        Err(TemporalError::Uncertified)
    );
}
