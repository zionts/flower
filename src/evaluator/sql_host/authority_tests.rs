use super::*;
use crate::evaluator::sql::{Operation, TerminalMethod};

#[test]
fn authority_operation_is_from_native_descriptor_not_raw_plan_or_purpose() {
    for operation in [
        Operation::Query,
        Operation::Explain,
        Operation::Catalog,
        Operation::Cancel,
    ] {
        let mut f = Fixture::new("null");
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let purpose = capture(
            &mut f.frame,
            r#"{"operation":"cancel","principal":{"subject":"caller-chosen"}}"#,
            &control,
        );
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let terminal = TerminalMethod {
            catalog: "native_catalog".into(),
            operation,
            cancel_result: None,
            finalizer: "run.$sql.finalize".into(),
            signing_keys: vec![],
        };
        let mut decode = WireArena::new(wire_limits()).unwrap();
        let mut host = registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            native_point(&f.job, NativePhase::Authority, f.binding),
            &mut f.job,
            f.authority_catalog,
        )
        .unwrap();
        let (encoded, count, bytes) =
            crate::allocation_probe::measure(|| host.prepare_authority_input(&terminal, purpose));
        assert_eq!((count, bytes), (0, 0));
        let root = decode.decode(encoded.unwrap()).unwrap();
        let request = decode.value(root).unwrap();
        let expected = match operation {
            Operation::Query => "query",
            Operation::Explain => "explain",
            Operation::Catalog => "catalog",
            Operation::Cancel => "cancel",
        };
        assert_eq!(
            request.member("operation").unwrap().as_str(),
            Some(expected)
        );
        assert_eq!(
            request.member("catalog").unwrap().as_str(),
            Some("native_catalog")
        );
        assert_eq!(
            request
                .member("invoker")
                .unwrap()
                .member("subject")
                .unwrap()
                .as_str(),
            Some("caller")
        );
        assert_eq!(
            request
                .member("purpose")
                .unwrap()
                .member("operation")
                .unwrap()
                .as_str(),
            Some("cancel")
        );
        assert_eq!(
            request
                .member("purpose")
                .unwrap()
                .member("principal")
                .unwrap()
                .member("subject")
                .unwrap()
                .as_str(),
            Some("caller-chosen")
        );
    }
}

#[test]
fn authority_builder_refuses_wrong_phase_and_cancel_signer_before_callback() {
    for phase in [NativePhase::ReadlessPlan, NativePhase::Authority] {
        let mut f = Fixture::new("null");
        let relations = [];
        let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let terminal = TerminalMethod {
            catalog: "native_catalog".into(),
            operation: Operation::Cancel,
            cancel_result: None,
            finalizer: "run.$sql.finalize".into(),
            signing_keys: vec![serde_json::json!({"name":"signer","usages":["sign"]})],
        };
        let point = native_point(&f.job, phase, f.binding);
        let mut host = if phase == NativePhase::Authority {
            registered_authority_host(
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                &budget,
                point,
                &mut f.job,
                f.authority_catalog,
            )
        } else {
            SqlHost::new(
                phase,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                Some(support),
                &budget,
                point,
                &mut f.job,
            )
        }
        .unwrap();
        let result = host.prepare_authority_input(&terminal, f.request);
        assert!(matches!(
            result,
            Err(HostError::Forbidden | HostError::Invalid)
        ));
        assert!(host.finished().is_none());
    }
}

#[test]
fn generic_authority_enum_is_not_a_system_capability() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
    let point = native_point(&f.job, NativePhase::Authority, f.binding);
    assert!(matches!(
        SqlHost::new(
            NativePhase::Authority,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            point,
            &mut f.job
        ),
        Err(HostError::Forbidden)
    ));
    assert_eq!(admitted.failure(), Some(HostError::Forbidden));
    assert!(matches!(
        registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            point,
            &mut f.job,
            f.authority_catalog
        ),
        Err(HostError::Forbidden)
    ));
}

#[test]
fn registered_authority_reads_full_security_metadata_but_keeps_invoker_identity() {
    let mut f = Fixture::new(
        r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"fields":{"hidden":{"read":{"const":false}}}}"#,
    );
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
        let mut host = registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            native_point(&f.job, NativePhase::Authority, f.binding),
            &mut f.job,
            f.authority_catalog,
        )
        .unwrap();
        assert_eq!(host.authority_target(), Some("test"));
        assert_eq!(
            json_response(host.call_checked("principal", &[]).unwrap())["subject"],
            "caller"
        );
        // Invoker is caller, effective principal is attenuated/different. Full
        // security rows/fields are visible ONLY in this closed private phase.
        assert_eq!(
            json_response(host.call_checked("get", &get("b")).unwrap())["hidden"],
            "private"
        );
        assert_eq!(
            json_response(host.call_checked("scan", &scan()).unwrap())
                .as_array()
                .unwrap()
                .len(),
            2
        );
        host.finish_checked(&outcome(&json!(true))).unwrap();
    }
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    // A following provider gets NO inherited privilege. Native effective
    // identity applies, so even the caller-owned row is hidden under attenuation.
    let mut host = SqlHost::new(
        NativePhase::Provider,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        Some(support),
        &budget,
        native_point(&f.job, NativePhase::Provider, f.binding),
        &mut f.job,
    )
    .unwrap();
    assert_eq!(host.authority_target(), None);
    assert_eq!(
        json_response(host.call_checked("get", &get("a🌸")).unwrap()),
        Value::Null
    );
}

#[test]
fn closed_authority_witness_rejects_target_code_certificate_source_job_and_binding_mismatch() {
    for wrong in 0..10 {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let point = native_point(&f.job, NativePhase::Authority, f.binding);
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let permit = unsafe {
            ClosedAuthorityPermit::from_certified_native_registration(
                &f.frame,
                f.authority_catalog,
                point,
                f.binding,
                [1; 32],
                [2; 32],
                &control,
            )
        }
        .unwrap();
        let mut binding = f.binding;
        if wrong == 3 {
            binding.source_revision += 1;
        }
        if wrong == 4 {
            binding.principal = binding.invoker;
        }
        if wrong == 5 {
            binding.clock += 1;
        }
        let replacement = JobControl::new(Duration::from_secs(10), f.cancel.clone()).unwrap();
        let execution_point = if wrong == 6 {
            native_point(&replacement, NativePhase::Authority, f.binding)
        } else if wrong == 7 {
            unsafe {
                NativeTimePoint::from_certified_native_point(
                    &f.job,
                    NativePhase::Authority,
                    f.binding.clock,
                    f.binding.source_revision,
                    2,
                    1,
                )
            }
            .unwrap()
        } else {
            point
        };
        let execution = unsafe {
            NativeAuthorityExecution::from_certified_native_execution(
                execution_point,
                if wrong == 0 { "other" } else { "test" },
                if wrong == 8 {
                    "wrong-code"
                } else {
                    f.binding.code_version
                },
                if wrong == 9 {
                    "wrong-catalog"
                } else {
                    f.binding.catalog_version
                },
                if wrong == 1 { [3; 32] } else { [1; 32] },
                if wrong == 2 { [4; 32] } else { [2; 32] },
            )
        }
        .unwrap();
        assert!(
            matches!(
                SqlHost::new_registered_authority(
                    &mut admitted,
                    &f.frame,
                    &relations,
                    binding,
                    &budget,
                    &mut f.job,
                    point,
                    permit,
                    execution
                ),
                Err(HostError::Temporal(TemporalError::ProvenanceMismatch))
            ),
            "case {wrong}"
        );
        assert!(admitted.failure().is_some());
    }
}

#[test]
fn authority_target_is_native_bounded_unicode_not_sql_identifier_or_guest_fallback() {
    let mut f = Fixture::new("null");
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    for target in ["🌸registered.私有", "", "$flower.authorize"] {
        let catalog = capture(
            &mut f.frame,
            &json!({"name":"native_catalog","version":"catalog-v1","authority":target,"tables":[]})
                .to_string(),
            &control,
        );
        let point = native_point(&f.job, NativePhase::Authority, f.binding);
        let result = unsafe {
            ClosedAuthorityPermit::from_certified_native_registration(
                &f.frame, catalog, point, f.binding, [1; 32], [2; 32], &control,
            )
        };
        assert_eq!(result.is_ok(), target == "🌸registered.私有");
    }
    for length in [384, 385] {
        let target = "a".repeat(length);
        let catalog = capture(
            &mut f.frame,
            &json!({"name":"native_catalog","version":"catalog-v1","authority":target,"tables":[]})
                .to_string(),
            &control,
        );
        let point = native_point(&f.job, NativePhase::Authority, f.binding);
        assert_eq!(
            unsafe {
                ClosedAuthorityPermit::from_certified_native_registration(
                    &f.frame, catalog, point, f.binding, [1; 32], [2; 32], &control,
                )
            }
            .is_ok(),
            length == 384
        );
    }
}

#[test]
fn registered_authority_closed_permit_never_allows_hostile_writers_or_derived_reads() {
    for operation in [
        "set",
        "delete",
        "materialize",
        "unmaterialize",
        "definer",
        "sql",
        "derive",
        "key",
        "unknown",
    ] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            native_point(&f.job, NativePhase::Authority, f.binding),
            &mut f.job,
            f.authority_catalog,
        )
        .unwrap();
        assert_eq!(
            host.call_checked(operation, &[255]),
            Err(HostError::Forbidden)
        );
        assert_eq!(
            host.finish_checked(&outcome(&json!(false))),
            Err(HostError::Forbidden)
        );
        assert!(host.finished().is_none());
    }
}

#[test]
fn registered_private_phase_reads_hidden_jobs_and_grants_not_public_provider_fields() {
    let mut f = Fixture::new(
        r#"{"read":{"const":false},"fields":{"sqlAuthority":{"read":{"const":false}},"lease":{"read":{"const":false}}}}"#,
    );
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let job_key = f.frame.retain_key("private-job").unwrap();
    let grant_key = f.frame.retain_key("private-grant").unwrap();
    let job = capture(
        &mut f.frame,
        r#"{"sqlAuthority":{"subject":"caller"},"lease":{"expiresAt":1002},"oversightExpiresAt":1001}"#,
        &control,
    );
    let grant = capture(
        &mut f.frame,
        r#"{"subject":"other","scope":"private","expiresAt":1003}"#,
        &control,
    );
    let jobs = [OwnedRow {
        key: job_key,
        value: Some(job),
    }];
    let grants = [OwnedRow {
        key: grant_key,
        value: Some(grant),
    }];
    let relations = [
        OwnedRelation {
            name: "jobs",
            coverage: CaptureCoverage::Complete,
            rows: &jobs,
        },
        OwnedRelation {
            name: "accountSessionGrants",
            coverage: CaptureCoverage::Complete,
            rows: &grants,
        },
    ];
    let job_get = args(&[
        json!({"kind":"collection","name":"jobs"}),
        json!("private-job"),
    ]);
    let grant_get = args(&[
        json!({"kind":"collection","name":"accountSessionGrants"}),
        json!("private-grant"),
    ]);
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
        let mut host = registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            native_point(&f.job, NativePhase::Authority, f.binding),
            &mut f.job,
            f.authority_catalog,
        )
        .unwrap();
        assert_eq!(
            json_response(host.call_checked("get", &job_get).unwrap())["lease"]["expiresAt"],
            1002
        );
        assert_eq!(
            json_response(host.call_checked("get", &grant_get).unwrap())["scope"],
            "private"
        );
        assert_eq!(
            json_response(host.call_checked("principal", &[]).unwrap())["subject"],
            "caller"
        );
        // Reading rows alone is bookkeeping/source work, NOT arbitrary guest
        // clock coverage or registration of lease validation that did not run.
        host.finish_checked(&outcome(&json!(true))).unwrap();
    }
    let policies = [
        CapturedCollection {
            name: "jobs",
            policy: Some(f.frame.json(f.policy, &control).unwrap()),
        },
        CapturedCollection {
            name: "accountSessionGrants",
            policy: Some(f.frame.json(f.policy, &control).unwrap()),
        },
    ];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let mut host = SqlHost::new(
        NativePhase::Provider,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        Some(support),
        &budget,
        native_point(&f.job, NativePhase::Provider, f.binding),
        &mut f.job,
    )
    .unwrap();
    assert_eq!(
        json_response(host.call_checked("get", &job_get).unwrap()),
        Value::Null
    );
    assert_eq!(
        json_response(host.call_checked("get", &grant_get).unwrap()),
        Value::Null
    );
}

#[test]
fn closed_authority_catalog_capture_cannot_be_transplanted_to_another_owned_frame() {
    let mut f = Fixture::new("null");
    let other = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let point = native_point(&f.job, NativePhase::Authority, f.binding);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let permit = unsafe {
        ClosedAuthorityPermit::from_certified_native_registration(
            &f.frame,
            f.authority_catalog,
            point,
            f.binding,
            [1; 32],
            [2; 32],
            &control,
        )
    }
    .unwrap();
    let execution = unsafe {
        NativeAuthorityExecution::from_certified_native_execution(
            point,
            "test",
            f.binding.code_version,
            f.binding.catalog_version,
            [1; 32],
            [2; 32],
        )
    }
    .unwrap();
    assert!(matches!(
        SqlHost::new_registered_authority(
            &mut admitted,
            &other.frame,
            &relations,
            f.binding,
            &budget,
            &mut f.job,
            point,
            permit,
            execution
        ),
        Err(HostError::Temporal(TemporalError::ProvenanceMismatch))
    ));
}
