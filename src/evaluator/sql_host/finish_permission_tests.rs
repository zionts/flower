//! Actual original-job ledger -> qualified native encoder -> publication checks.
//! Unsafe points below are component fixtures, NOT source/controller proof.
use super::*;
fn permission(
    f: &mut Fixture,
    admitted: &mut HostAdmission,
    budget: &PolicyBudget,
    until: Option<u64>,
) {
    let point = native_point(&f.job, NativePhase::InitialAuth, f.binding);
    let mut host = SqlHost::new(
        NativePhase::InitialAuth,
        admitted,
        &f.frame,
        &[],
        f.binding,
        None,
        budget,
        point,
        &mut f.job,
    )
    .unwrap();
    if let Some(until) = until {
        host.call_checked("clock", &[]).unwrap();
        host.call_checked("changesAt", &args(&[json!(until)]))
            .unwrap();
    }
    host.finish_checked_at(&[wire::SUCCESS, wire::NULL], f.binding.clock)
        .unwrap();
}
#[test]
fn actual_stamp_encodes_exclusive_bound_and_original_rseal_at_fresh_permission_revision() {
    for until in [None, Some(200)] {
        let mut f = Fixture::new("null");
        f.binding.clock = 100;
        let mut admitted = admission(&f, &[], MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        permission(&mut f, &mut admitted, &budget, until);
        let stamp = admitted.permission_stamp(&mut f.job, 105).unwrap();
        f.binding.clock = 105;
        let point = unsafe {
            NativeTimePoint::from_certified_native_point(
                &f.job,
                NativePhase::ReadlessFinalizer,
                105,
                23,
                1,
                1,
            )
        }
        .unwrap();
        f.binding = f.binding.at_permission_point(point).unwrap();
        let mut host = SqlHost::new_qualified_finalizer(
            &mut admitted,
            &f.frame,
            f.binding,
            &budget,
            stamp,
            point,
            &mut f.job,
        )
        .unwrap();
        let bytes = host
            .prepare_finish_input(f.request, f.result, f.provenance)
            .unwrap();
        let mut reader = WireArena::new(wire_limits()).unwrap();
        let id = reader.decode(bytes).unwrap();
        let binding = reader.value(id).unwrap().member("binding").unwrap();
        assert_eq!(
            binding.member("sourceRevision").unwrap().as_f64(),
            Some(17.0)
        );
        match until {
            Some(at) => assert_eq!(
                binding.member("validUntil").unwrap().as_f64(),
                Some(at as f64)
            ),
            None => assert_eq!(binding.member("validUntil").unwrap().kind(), WireKind::Null),
        }
        // Readless clock does not add a permission callback or change expiry.
        host.call_checked("clock", &[]).unwrap();
        host.finish_checked_at(&[wire::SUCCESS, wire::NULL], 106)
            .unwrap();
        let qualified = host.finish_permission().unwrap();
        drop(host);
        assert_eq!(
            admitted
                .validate_finish_permission(&mut f.job, qualified, 107)
                .unwrap(),
            until
        );
        if until.is_some() {
            assert_eq!(
                admitted.validate_finish_permission(&mut f.job, qualified, 200),
                Err(HostError::Temporal(TemporalError::Expired))
            );
        }
    }
}
#[test]
fn absent_permission_never_becomes_null_and_unqualified_encoder_refuses() {
    let mut f = Fixture::new("null");
    let mut admitted = admission(&f, &[], MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let point = native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding);
    let mut host = SqlHost::new(
        NativePhase::ReadlessFinalizer,
        &mut admitted,
        &f.frame,
        &[],
        f.binding,
        None,
        &budget,
        point,
        &mut f.job,
    )
    .unwrap();
    assert_eq!(
        host.prepare_finish_input(f.request, f.result, f.provenance),
        Err(HostError::Temporal(TemporalError::NoPermission))
    );
    assert_eq!(host.finished(), None);
}
#[test]
fn old_sequence_another_ledger_and_wrong_permission_revision_refuse_finalizer() {
    for variant in 0..3 {
        let mut f = Fixture::new("null");
        let mut admitted = admission(&f, &[], MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        permission(&mut f, &mut admitted, &budget, None);
        let stamp = admitted
            .permission_stamp(&mut f.job, f.binding.clock)
            .unwrap();
        if variant == 0 {
            permission(&mut f, &mut admitted, &budget, None);
        }
        if variant == 1 {
            admitted = admission(&f, &[], MAX_HOST_WORK);
            permission(&mut f, &mut admitted, &budget, None);
        }
        let point = native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding);
        if variant == 2 {
            let other = unsafe {
                NativeTimePoint::from_certified_native_point(
                    &f.job,
                    NativePhase::ReadlessFinalizer,
                    f.binding.clock,
                    18,
                    1,
                    1,
                )
            }
            .unwrap();
            f.binding = f.binding.at_permission_point(other).unwrap();
        }
        let result = SqlHost::new_qualified_finalizer(
            &mut admitted,
            &f.frame,
            f.binding,
            &budget,
            stamp,
            point,
            &mut f.job,
        );
        assert!(matches!(
            result,
            Err(HostError::Temporal(TemporalError::ProvenanceMismatch))
        ));
    }
}
#[test]
fn qualified_permission_cannot_publish_before_finish_or_after_new_callback() {
    let mut f = Fixture::new("null");
    let mut admitted = admission(&f, &[], MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    permission(&mut f, &mut admitted, &budget, None);
    let stamp = admitted
        .permission_stamp(&mut f.job, f.binding.clock)
        .unwrap();
    let point = native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding);
    let mut host = SqlHost::new_qualified_finalizer(
        &mut admitted,
        &f.frame,
        f.binding,
        &budget,
        stamp,
        point,
        &mut f.job,
    )
    .unwrap();
    assert_eq!(host.finish_permission(), Err(HostError::Finished));
    host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
    let qualified = host.finish_permission().unwrap();
    drop(host);
    permission(&mut f, &mut admitted, &budget, None);
    assert_eq!(
        admitted.validate_finish_permission(&mut f.job, qualified, f.binding.clock),
        Err(HostError::Temporal(TemporalError::ProvenanceMismatch))
    );
}
#[cfg(sql_host_harness)]
#[test]
fn actual_qualified_finish_encoder_and_expiry_refusal_allocate_zero_rust_heap() {
    let mut f = Fixture::new("null");
    f.binding.clock = 100;
    let mut admitted = admission(&f, &[], MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    permission(&mut f, &mut admitted, &budget, Some(200));
    let point = native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding);
    let (result, count, bytes) =
        crate::allocation_probe::measure(|| -> Result<FinishPermission, HostError> {
            let stamp = admitted.permission_stamp(&mut f.job, 100)?;
            let mut host = SqlHost::new_qualified_finalizer(
                &mut admitted,
                &f.frame,
                f.binding,
                &budget,
                stamp,
                point,
                &mut f.job,
            )?;
            host.prepare_finish_input(f.request, f.result, f.provenance)?;
            host.finish_checked_at(&[wire::SUCCESS, wire::NULL], 199)?;
            host.finish_permission()
        });
    assert_eq!((count, bytes), (0, 0));
    let qualified = result.unwrap();
    let (result, count, bytes) = crate::allocation_probe::measure(|| {
        admitted.validate_finish_permission(&mut f.job, qualified, 200)
    });
    assert_eq!(result, Err(HostError::Temporal(TemporalError::Expired)));
    assert_eq!((count, bytes), (0, 0));
    let (_, count, bytes) =
        crate::allocation_probe::measure(|| std::hint::black_box(vec![1u8; 32]));
    assert!(count > 0 && bytes >= 32);
}

#[test]
fn exact_native_host_layouts_fit_the_original_fixed_control_reservation() {
    let control = std::mem::size_of::<HostAdmission>()
        + std::mem::size_of::<SqlHost<'_>>()
        + std::mem::size_of::<PolicyBudget>();
    assert!(control <= HOST_CONTROL_BYTES);
    eprintln!(
        "native_layout_admission={} host={} ledger={} stamp={} finish_permission={} capture={} capture_collection={} capture_row={} native_key_row={} policy={} identity_global=8",
        std::mem::size_of::<HostAdmission>(),
        std::mem::size_of::<SqlHost<'_>>(),
        std::mem::size_of::<GlobalTemporalLedger>(),
        std::mem::size_of::<PermissionStamp>(),
        std::mem::size_of::<FinishPermission>(),
        std::mem::size_of::<NativeCapture<'_>>(),
        std::mem::size_of::<NativeCaptureCollection>(),
        std::mem::size_of::<NativeCaptureRow>(),
        std::mem::size_of::<super::super::super::sql_policy::NativeKeyRow<'_>>(),
        std::mem::size_of::<PolicyBudget>()
    );
}
#[test]
fn lower_work_new_policy_account_cannot_replace_the_original_native_account() {
    let mut f = Fixture::new("null");
    let mut admitted = admission(&f, &[], MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    permission(&mut f, &mut admitted, &budget, None);
    let replacement = PolicyBudget::new(budget.remaining_work().saturating_sub(1)).unwrap();
    let point = native_point(&f.job, NativePhase::InitialAuth, f.binding);
    assert!(matches!(
        SqlHost::new(
            NativePhase::InitialAuth,
            &mut admitted,
            &f.frame,
            &[],
            f.binding,
            None,
            &replacement,
            point,
            &mut f.job
        ),
        Err(HostError::Forbidden)
    ));
}
