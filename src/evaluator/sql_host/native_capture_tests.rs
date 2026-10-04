//! Real native binder -> actual host -> encoded SDK-facing keys -> same-frame SQL.
//! Captured input is a fixture, not a serving/controller/grant verifier.
use super::super::super::sql_frame::{ColumnKind, FrameCell, FrameColumn};
use super::super::super::sqlite::{self, QueryOptions, SqlCell};
use super::*;
fn actual_policy(name: &str) -> String {
    let manifest: Value =
        serde_json::from_str(include_str!("../sql_policy/typed_manifest.json")).unwrap();
    manifest
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap()["access"]
        .to_string()
}
pub(super) struct Captured {
    pub(super) f: Fixture,
    pub(super) declaration: JsonId,
    pub(super) collections: [NativeCaptureCollection; 2],
    pub(super) descriptors: [NativeCaptureRow; 4],
}
pub(super) fn captured_members() -> Captured {
    let mut f = Fixture::new(&actual_policy("members"));
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let principal = capture(
        &mut f.frame,
        r#"{"subject":"alice","claims":{"role":"user"}}"#,
        &control,
    );
    f.binding.invoker = principal;
    f.binding.principal = principal;
    let declaration = capture(
        &mut f.frame,
        r#"{"name":"members","jsonKey":true}"#,
        &control,
    );
    let target = capture(&mut f.frame, r#"{"name":"superadmins"}"#, &control);
    let target_policy = capture(&mut f.frame, &actual_policy("superadmins"), &control);
    let mut descriptors =
        [NativeCaptureRow::from_owned_offsets(declaration, declaration, f.rows[0].key, None, None);
            4];
    for (index, (key, row)) in [
        (r#"["acme","alice"]"#, r#"{"amount":3}"#),
        (r#"["another","alice"]"#, r#"{"amount":4}"#),
        (r#"["other","bob"]"#, r#"{"amount":1000}"#),
    ]
    .into_iter()
    .enumerate()
    {
        let retained = f.frame.retain_key(key).unwrap();
        let decoded = capture(&mut f.frame, key, &control);
        let pair = capture(
            &mut f.frame,
            &serde_json::to_string(&json!(["members", key])).unwrap(),
            &control,
        );
        let row = capture(&mut f.frame, row, &control);
        f.rows[index] = OwnedRow {
            key: retained,
            value: Some(row),
        };
        descriptors[index] = NativeCaptureRow::from_owned_offsets(
            declaration,
            pair,
            retained,
            Some(decoded),
            Some(row),
        );
    }
    let retained = f.frame.retain_key("alice").unwrap();
    let pair = capture(&mut f.frame, r#"["superadmins","alice"]"#, &control);
    descriptors[3] = NativeCaptureRow::from_owned_offsets(target, pair, retained, None, None);
    let collections = [
        NativeCaptureCollection::from_owned_offsets(declaration, Some(f.policy)),
        NativeCaptureCollection::from_owned_offsets(target, Some(target_policy)),
    ];
    Captured {
        f,
        declaration,
        collections,
        descriptors,
    }
}
#[test]
fn actual_first_human_typed_get_scan_provider_and_whole_same_frame_count_sum() {
    // Prewarm SQLite BEFORE creating the original <=10s job.
    let warm_cancel = AtomicBool::new(false);
    let warm_control = FrameControl::new(&warm_cancel, Instant::now() + Duration::from_secs(10));
    let mut warm_frame = FrameBuilder::new(frame_limits(), &warm_control)
        .unwrap()
        .seal(&warm_control)
        .unwrap();
    sqlite::execute(
        "SELECT 1",
        &[],
        &[],
        &mut warm_frame,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    drop(warm_frame);
    let Captured {
        mut f,
        declaration,
        collections,
        descriptors,
    } = captured_members();
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let table = f
        .frame
        .add_table(
            "visible",
            &[FrameColumn {
                name: "amount",
                kind: ColumnKind::Integer,
                nullable: false,
                logical_type: None,
                unit: None,
                equality: false,
            }],
        )
        .unwrap();
    let relations = [OwnedRelation {
        name: "members",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let first = descriptors[0];
    // Caller-prepaid fixed witness bank seed. The capture constructor overwrites
    // EVERY entry by the exact binder; seed is never an authorization assertion.
    let seed = first.bind(&f.frame, &control, &budget, &mut f.job).unwrap();
    let mut witnesses = [seed; 4];
    let mut policies = [CapturedCollection {
        name: "",
        policy: None,
    }; 2];
    let native = NativeCapture::from_owned_native_capture(
        &mut admitted,
        &f.frame,
        &relations,
        &collections,
        &descriptors,
        &mut policies,
        &mut witnesses,
        &control,
        &budget,
        &mut f.job,
    )
    .unwrap();
    let point = native_point(&f.job, NativePhase::Provider, f.binding);
    let mut reader = WireArena::new(wire_limits()).unwrap();
    let batch_id;
    {
        let mut host = SqlHost::new_native(
            NativePhase::Provider,
            &mut admitted,
            native,
            f.binding,
            &budget,
            point,
            &mut f.job,
        )
        .unwrap();
        let get = args(&[
            json!({"kind":"collection","name":"members"}),
            json!(r#"["acme","alice"]"#),
        ]);
        assert_eq!(
            json_response(host.call_checked("get", &get).unwrap())["amount"],
            3
        );
        let get_hidden = args(&[
            json!({"kind":"collection","name":"members"}),
            json!(r#"["other","bob"]"#),
        ]);
        assert!(json_response(host.call_checked("get", &get_hidden).unwrap()).is_null());
        let scan = args(&[json!({"kind":"collection","name":"members"})]);
        let scanned = json_response(host.call_checked("scan", &scan).unwrap());
        assert_eq!(scanned.as_array().unwrap().len(), 2);
        assert!(
            scanned
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["key"].is_string())
        );
        batch_id = reader
            .decode(
                host.prepare_provider_input_from_native_catalog(declaration)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            reader
                .value(batch_id)
                .unwrap()
                .member("rows")
                .unwrap()
                .len(),
            Some(2)
        );
        host.finish_checked(&outcome(&json!({"rows":[],"provenance":[]})))
            .unwrap();
        host.validated_provider_rows(1).unwrap();
    }
    // Source frame ownership is ended before sealing/SQLite. Only actual
    // authorized values from the complete prefiltered batch become typed cells.
    budget.finish(&mut f.job, f.binding.clock).unwrap();
    drop(admitted);
    let rows = reader.value(batch_id).unwrap().member("rows").unwrap();
    for entry in rows.iter().unwrap() {
        let amount = entry
            .value
            .member("value")
            .unwrap()
            .member("amount")
            .unwrap()
            .as_f64()
            .unwrap();
        assert!(amount.fract() == 0.0 && (0.0..1000.0).contains(&amount));
        f.frame
            .insert_row(table, &[FrameCell::Integer(amount as i64)], &control)
            .unwrap();
    }
    let mut sealed = f.frame.seal(&control).unwrap();
    let tables = sealed.native_tables(1024 * 1024).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*),SUM(amount) FROM visible",
        &[],
        &tables,
        &mut sealed,
        QueryOptions::default(),
        &mut || f.job.check(),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![SqlCell::Integer(2), SqlCell::Integer(7)]]
    );
}

#[test]
fn native_whole_capture_duplicate_missing_negative_work_and_cancel_refuse_before_provider() {
    for variant in 0..5 {
        let Captured {
            mut f,
            declaration: _,
            collections,
            mut descriptors,
        } = captured_members();
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let relations = [OwnedRelation {
            name: "members",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let seed = descriptors[0]
            .bind(&f.frame, &control, &budget, &mut f.job)
            .unwrap();
        let mut witnesses = [seed; 4];
        let mut policies = [CapturedCollection {
            name: "",
            policy: None,
        }; 2];
        if variant == 0 {
            descriptors[1] = descriptors[0];
        }
        if variant == 1 {
            descriptors[3] = descriptors[2];
        }
        if variant == 2 {
            admitted.budget.remaining = 0;
        }
        if variant == 3 {
            f.cancel.store(true, Ordering::Release);
        }
        if variant == 4 {
            admitted.borrowed_owner_bytes = 1;
        }
        let result = NativeCapture::from_owned_native_capture(
            &mut admitted,
            &f.frame,
            &relations,
            &collections,
            &descriptors,
            &mut policies,
            &mut witnesses,
            &control,
            &budget,
            &mut f.job,
        );
        assert!(result.is_err());
        assert!(admitted.failure().is_some());
        assert!(
            admitted
                .permission_stamp(&mut f.job, f.binding.clock)
                .is_err()
        );
    }
}
#[test]
fn native_missing_readable_negative_is_need_capture_not_false_or_independent() {
    let Captured {
        mut f,
        declaration,
        collections,
        descriptors,
    } = captured_members();
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let relations = [OwnedRelation {
        name: "members",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let seed = descriptors[0]
        .bind(&f.frame, &control, &budget, &mut f.job)
        .unwrap();
    let mut witnesses = [seed; 3];
    let mut policies = [CapturedCollection {
        name: "",
        policy: None,
    }; 2];
    let native = NativeCapture::from_owned_native_capture(
        &mut admitted,
        &f.frame,
        &relations,
        &collections,
        &descriptors[..3],
        &mut policies,
        &mut witnesses,
        &control,
        &budget,
        &mut f.job,
    )
    .unwrap();
    let point = native_point(&f.job, NativePhase::Provider, f.binding);
    let mut host = SqlHost::new_native(
        NativePhase::Provider,
        &mut admitted,
        native,
        f.binding,
        &budget,
        point,
        &mut f.job,
    )
    .unwrap();
    assert_eq!(
        host.prepare_provider_input_from_native_catalog(declaration),
        Err(HostError::NeedCapture(NativeNeedCapture))
    );
    assert_eq!(host.finished(), None);
    drop(host);
    assert_eq!(
        unsafe { admitted.acknowledge_native_capture(&mut f.job) },
        Err(HostError::Unsupported)
    );
    assert_eq!(budget.failure(), Some(PolicyError::NeedCapture));
}
#[cfg(sql_host_harness)]
#[test]
fn actual_typed_native_capture_filtering_and_error_paths_have_zero_rust_allocations() {
    let Captured {
        mut f,
        declaration,
        collections,
        descriptors,
    } = captured_members();
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let relations = [OwnedRelation {
        name: "members",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let seed = descriptors[0]
        .bind(&f.frame, &control, &budget, &mut f.job)
        .unwrap();
    let mut witnesses = [seed; 4];
    let mut policies = [CapturedCollection {
        name: "",
        policy: None,
    }; 2];
    let point = native_point(&f.job, NativePhase::Provider, f.binding);
    let (result, count, bytes) = crate::allocation_probe::measure(|| -> Result<(), HostError> {
        let native = NativeCapture::from_owned_native_capture(
            &mut admitted,
            &f.frame,
            &relations,
            &collections,
            &descriptors,
            &mut policies,
            &mut witnesses,
            &control,
            &budget,
            &mut f.job,
        )?;
        let mut host = SqlHost::new_native(
            NativePhase::Provider,
            &mut admitted,
            native,
            f.binding,
            &budget,
            point,
            &mut f.job,
        )?;
        host.prepare_provider_input_from_native_catalog(declaration)?;
        host.finish_checked(&[wire::SUCCESS, wire::NULL])?;
        Ok(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!((count, bytes), (0, 0));
    f.cancel.store(true, Ordering::Release);
    let (result, count, bytes) = crate::allocation_probe::measure(|| {
        admitted.check_native_clock(&mut f.job, f.binding.clock)
    });
    assert_eq!(result, Err(HostError::Cancelled));
    assert_eq!((count, bytes), (0, 0));
}

#[test]
fn actual_hidden_native_rows_keep_expiry_and_clock_invariant_stamp_bound() {
    for (policy, validity) in [
        (
            r#"{"read":{"gte":[{"ref":["now"]},{"value":200}]}}"#,
            Validity::Until(200),
        ),
        (
            r#"{"read":{"eq":[{"ref":["now"]},{"value":100.5}]}}"#,
            Validity::ClockInvariant,
        ),
    ] {
        let Captured {
            mut f,
            declaration,
            mut collections,
            descriptors,
        } = captured_members();
        f.binding.clock = 100;
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let policy = capture(&mut f.frame, policy, &control);
        collections[0] = NativeCaptureCollection::from_owned_offsets(declaration, Some(policy));
        let relations = [OwnedRelation {
            name: "members",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let seed = descriptors[0]
            .bind(&f.frame, &control, &budget, &mut f.job)
            .unwrap();
        let mut witnesses = [seed; 4];
        let mut policies = [CapturedCollection {
            name: "",
            policy: None,
        }; 2];
        let native = NativeCapture::from_owned_native_capture(
            &mut admitted,
            &f.frame,
            &relations,
            &collections,
            &descriptors,
            &mut policies,
            &mut witnesses,
            &control,
            &budget,
            &mut f.job,
        )
        .unwrap();
        let point = native_point(&f.job, NativePhase::Provider, f.binding);
        let mut reader = WireArena::new(wire_limits()).unwrap();
        {
            let mut host = SqlHost::new_native(
                NativePhase::Provider,
                &mut admitted,
                native,
                f.binding,
                &budget,
                point,
                &mut f.job,
            )
            .unwrap();
            let id = reader
                .decode(
                    host.prepare_provider_input_from_native_catalog(declaration)
                        .unwrap(),
                )
                .unwrap();
            assert_eq!(
                reader.value(id).unwrap().member("rows").unwrap().len(),
                Some(0)
            );
            host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
        }
        assert_eq!(admitted.validity(), validity);
        let stamp = admitted.permission_stamp(&mut f.job, 101).unwrap();
        assert_eq!(stamp.validity(), validity);
        f.binding.clock = 101;
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
        reader.reset().unwrap();
        let id = reader
            .decode(
                host.prepare_finish_input(f.request, f.result, f.provenance)
                    .unwrap(),
            )
            .unwrap();
        let expiry = reader
            .value(id)
            .unwrap()
            .member("binding")
            .unwrap()
            .member("validUntil")
            .unwrap();
        match validity {
            Validity::Until(at) => assert_eq!(expiry.as_f64(), Some(at as f64)),
            Validity::ClockInvariant => assert_eq!(expiry.kind(), WireKind::Null),
            _ => panic!("specific evaluated fixture"),
        }
        host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
        let permission = host.finish_permission().unwrap();
        drop(host);
        let until = admitted
            .validate_finish_permission(&mut f.job, permission, 102)
            .unwrap();
        assert_eq!(
            until,
            match validity {
                Validity::Until(at) => Some(at),
                _ => None,
            }
        );
    }
}
