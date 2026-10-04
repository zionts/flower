//! Parent imports sql_host + sql_policy in evaluator.rs. These tests then run
//! the CURRENT real Wasmtime/QuickJS transport, not a Node SQL mock database.
use super::*;
use crate::evaluator::wasm::{self, Limits};
fn native_limits() -> Arc<Limits> {
    Limits::new(Instant::now() + Duration::from_secs(180), 128 * 1024 * 1024)
}
fn invocation_limits(f: &Fixture) -> Arc<Limits> {
    Limits::new_cancellable(f.job.deadline(), 128 * 1024 * 1024, f.cancel.clone())
}
fn native_source(kind: &str, compute: &str) -> String {
    let definition = if kind == "sqlPlan" {
        "queryMethod"
    } else {
        kind
    };
    let terminal = if kind == "sqlPlan" {
        "terminal:{},"
    } else {
        ""
    };
    format!(
        "{}var __flowerBundle={{default:{{definitions:{{test:{{name:'test',kind:'{definition}',{terminal}compute:{compute}}}}},http:{{}}}}}};",
        wasm::STATIC_INIT_MARKER
    )
}
#[test]
fn detached_native_real_wasm_readless_metadata_and_recycled_vm() {
    let code = native_source(
        "sqlPlan",
        "ctx=>{globalThis.calls=(globalThis.calls||0)+1;return [ctx.principal(),ctx.clock(),ctx.history(),ctx.codeVersion(),typeof ctx.get,globalThis.calls]}",
    );
    let prepared = wasm::prepare(&code, native_limits()).unwrap();
    for clock in [1000, 1001] {
        let mut f = Fixture::new("null");
        f.binding.clock = clock;
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let execution = invocation_limits(&f);
        let mut host = SqlHost::new(
            NativePhase::ReadlessPlan,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessPlan, f.binding),
            &mut f.job,
        )
        .unwrap();
        wasm::execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlPlan",
            &mut host,
            execution,
        )
        .unwrap();
        let WireOutcome::Success(id) = host.finished().unwrap() else {
            panic!("success")
        };
        let value = host.finished_value(id).unwrap();
        assert_eq!(
            value.index(0).unwrap().member("subject").unwrap().as_str(),
            Some("caller")
        );
        assert_eq!(value.index(1).unwrap().as_f64(), Some(clock as f64));
        assert_eq!(value.index(4).unwrap().as_str(), Some("undefined"));
        assert_eq!(value.index(5).unwrap().as_i32(), Some(1));
        assert_eq!(host.completion(), Some(CallbackCompletion::MetadataOnly));
        drop(host);
        assert_eq!(
            admitted.permission_stamp(&mut f.job, clock),
            Err(HostError::Temporal(TemporalError::NoPermission))
        );
    }
}
#[test]
fn detached_native_real_wasm_captured_write_is_uncatchable() {
    let code = format!(
        "{}var __flowerBundle={{default:{{definitions:{{'$flower.authorize':{{name:'$flower.authorize',kind:'queryMethod',compute:()=>{{try{{__flowerContexts[1].set({{kind:'collection',name:'rows'}},'key',1)}}catch(_){{return 'caught'}}return 'write'}}}}}},http:{{}}}}}};",
        wasm::STATIC_INIT_MARKER
    );
    let prepared = wasm::prepare(&code, native_limits()).unwrap();
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let execution = invocation_limits(&f);
    let mut host = SqlHost::new(
        NativePhase::InitialAuth,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        None,
        &budget,
        native_point(&f.job, NativePhase::InitialAuth, f.binding),
        &mut f.job,
    )
    .unwrap();
    let error = wasm::execute_sql_authorization(&prepared, &[wire::NULL], &mut host, execution)
        .unwrap_err();
    assert!(
        error
            .chain()
            .any(|e| e.downcast_ref::<HostError>() == Some(&HostError::Forbidden)),
        "typed native denial was lost"
    );
    assert_eq!(host.failure(), Some(HostError::Forbidden));
    assert!(host.finished().is_none());
}
#[test]
fn detached_native_real_wasm_need_capture_type_survives_anyhow_wasmtime() {
    let code = native_source(
        "sqlAuthority",
        "ctx=>{try{return ctx.get({kind:'collection',name:'rows'},'uncaptured')}catch(_){return null}}",
    );
    let prepared = wasm::prepare(&code, native_limits()).unwrap();
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::KeysOnly,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
        let execution = invocation_limits(&f);
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
        let error = wasm::execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlAuthority",
            &mut host,
            execution,
        )
        .unwrap_err();
        assert!(
            error.chain().any(|e| e.is::<NativeNeedCapture>()),
            "typed native demand was lost"
        );
        assert!(host.finished().is_none());
    }
    assert_eq!(admitted.demand().unwrap().unwrap().key, Some("uncaptured"));
}
#[test]
fn detached_native_real_wasm_raw_crypto_remains_forbidden() {
    for compute in [
        "()=>{try{return __flowerCrypto(15,0,new Uint8Array([1]))}catch(_){return 'caught'}}",
        "()=>{try{return __flowerCrypto(101,0,'invalid','key','{}')}catch(_){return 'caught'}}",
    ] {
        let prepared = wasm::prepare(&native_source("sqlPlan", compute), native_limits()).unwrap();
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let execution = invocation_limits(&f);
        let mut host = SqlHost::new(
            NativePhase::ReadlessPlan,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessPlan, f.binding),
            &mut f.job,
        )
        .unwrap();
        let error = wasm::execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlPlan",
            &mut host,
            execution,
        )
        .unwrap_err();
        assert!(error.to_string().contains("SQL_CRYPTO_FORBIDDEN"));
        assert!(host.finished().is_none());
    }
}

#[test]
fn detached_real_wasm_provider_observes_only_complete_redacted_logical_key_batch() {
    let code = native_source(
        "sqlProvider",
        "(ctx,input)=>{const rows=input.rows;let sum=0,hidden=0;for(const row of rows){sum+=row.value.amount;if(Object.hasOwn(row.value,'sqlAuthority'))hidden++}return {rows:[{sourceRow:0,cells:[{text:rows[0].key},{integer:String(rows.length)},{integer:String(sum)},{integer:String(hidden)}]}]}}",
    );
    let prepared = wasm::prepare(&code, native_limits()).unwrap();
    let mut f = Fixture::new(super::native_key_tests::METADATA_POLICY);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let principal = capture(&mut f.frame, super::native_key_tests::ALICE, &control);
    f.binding.invoker = principal;
    f.binding.principal = principal;
    let a = f.frame.retain_key("a").unwrap();
    let b = f.frame.retain_key("b").unwrap();
    let av = capture(
        &mut f.frame,
        r#"{"amount":3,"sqlAuthority":7,"sqlSources":["private-a"]}"#,
        &control,
    );
    let bv = capture(
        &mut f.frame,
        r#"{"amount":4,"sqlAuthority":900,"sqlSources":["private-b"]}"#,
        &control,
    );
    let declaration = capture(
        &mut f.frame,
        r#"{"name":"metadata","jsonKey":false}"#,
        &control,
    );
    let rows = [
        OwnedRow {
            key: a,
            value: Some(av),
        },
        OwnedRow {
            key: b,
            value: Some(bv),
        },
    ];
    let relations = [OwnedRelation {
        name: "metadata",
        coverage: CaptureCoverage::Complete,
        rows: &rows,
    }];
    let policies = [CapturedCollection {
        name: "metadata",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let execution = invocation_limits(&f);
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
    // Fixed admitted scratch, not guest-owned bytes; original job deadline is
    // retained. This is transport evidence, NOT whole native allocation proof.
    let mut input = [0; 64 * 1024];
    let bytes = host
        .prepare_provider_input_from_native_catalog(declaration)
        .unwrap();
    let length = bytes.len();
    input[..length].copy_from_slice(bytes);
    wasm::execute_prepared_encoded(
        &prepared,
        "test",
        &input[..length],
        "sqlProvider",
        &mut host,
        execution,
    )
    .unwrap();
    let rows = host.validated_provider_rows(4).unwrap();
    let cells = rows.index(0).unwrap().member("cells").unwrap();
    assert_eq!(
        cells.index(0).unwrap().member("text").unwrap().as_str(),
        Some("a")
    );
    assert_eq!(
        cells.index(1).unwrap().member("integer").unwrap().as_str(),
        Some("2")
    );
    assert_eq!(
        cells.index(2).unwrap().member("integer").unwrap().as_str(),
        Some("7")
    );
    assert_eq!(
        cells.index(3).unwrap().member("integer").unwrap().as_str(),
        Some("0")
    );
}

#[test]
fn detached_real_wasm_cannot_catch_or_wire_a_misplaced_physical_source_id() {
    let prepared = wasm::prepare(
        &native_source(
            "sqlAuthority",
            "ctx=>{try{return ctx.scan({kind:'collection',name:'rows'})}catch(_){return 'caught'}}",
        ),
        native_limits(),
    )
    .unwrap();
    let mut f = Fixture::new("null");
    f.rows[0].key = f.frame.retain_key(r#"source:["rows","private"]"#).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let execution = invocation_limits(&f);
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
    let error = wasm::execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        execution,
    )
    .unwrap_err();
    assert!(
        error
            .chain()
            .any(|error| error.downcast_ref::<HostError>() == Some(&HostError::Forbidden))
    );
    assert!(host.finished().is_none());
    assert_eq!(host.failure(), Some(HostError::Forbidden));
}

fn authorization_source(compute: &str) -> String {
    format!(
        "{}var __flowerBundle={{default:{{definitions:{{'$flower.authorize':{{name:'$flower.authorize',kind:'queryMethod',compute:{compute}}}}},http:{{}}}}}};",
        wasm::STATIC_INIT_MARKER
    )
}
fn assert_native_temporal(error: &anyhow::Error, expected: TemporalError) {
    assert!(
        error
            .chain()
            .any(|cause| cause.downcast_ref::<HostError>() == Some(&HostError::Temporal(expected))),
        "typed native temporal cause was lost"
    );
}

#[test]
fn detached_real_wasm_temporal_clock_only_authorization_is_native_uncertified() {
    let prepared = wasm::prepare(
        &authorization_source("ctx=>ctx.clock()<102"),
        native_limits(),
    )
    .unwrap();
    let mut f = Fixture::new("null");
    f.binding.clock = 100;
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let execution = invocation_limits(&f);
    let mut host = SqlHost::new(
        NativePhase::InitialAuth,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        None,
        &budget,
        native_point(&f.job, NativePhase::InitialAuth, f.binding),
        &mut f.job,
    )
    .unwrap();
    let error = wasm::execute_sql_authorization(&prepared, &[wire::NULL], &mut host, execution)
        .unwrap_err();
    assert_native_temporal(&error, TemporalError::Uncertified);
    assert_eq!(
        host.failure(),
        Some(HostError::Temporal(TemporalError::Uncertified))
    );
    assert!(host.finished().is_none());
    assert_eq!(host.completion(), None);
}

#[test]
fn detached_real_wasm_temporal_caught_now_cannot_be_replaced_or_replayed() {
    let prepared = wasm::prepare(
        &authorization_source(
            "ctx=>{try{ctx.now()}catch(_){};ctx.changesAt(102);return ctx.clock()<102}",
        ),
        native_limits(),
    )
    .unwrap();
    let mut f = Fixture::new("null");
    f.binding.clock = 100;
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
        let execution = invocation_limits(&f);
        let mut host = SqlHost::new(
            NativePhase::InitialAuth,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::InitialAuth, f.binding),
            &mut f.job,
        )
        .unwrap();
        let error = wasm::execute_sql_authorization(&prepared, &[wire::NULL], &mut host, execution)
            .unwrap_err();
        assert_native_temporal(&error, TemporalError::Uncertified);
        assert_eq!(
            host.finish_checked(&outcome(&json!(true))),
            Err(HostError::Temporal(TemporalError::Uncertified))
        );
        assert!(host.finished().is_none());
    }
    // Recycled/destroyed VM does NOT own this ledger. Exact same original job
    // cannot start a substitute fresh auth/provider or acknowledge no demand.
    for phase in [NativePhase::FreshAuth, NativePhase::Provider] {
        assert!(matches!(
            SqlHost::new(
                phase,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                None,
                &budget,
                native_point(&f.job, phase, f.binding),
                &mut f.job
            ),
            Err(HostError::Temporal(TemporalError::Uncertified))
        ));
    }
    assert_eq!(
        unsafe { admitted.acknowledge_native_capture(&mut f.job) },
        Err(HostError::Temporal(TemporalError::Uncertified))
    );
    assert_eq!(
        admitted.permission_stamp(&mut f.job, 100),
        Err(HostError::Temporal(TemporalError::Uncertified))
    );
}

#[test]
fn detached_real_wasm_temporal_earliest_expiry_survives_every_permission_phase_without_write() {
    // ALL native preparation/prewarm precedes admission. None renew the original
    // 10s (or lower operator) job/deadline/cancellation for these callbacks.
    let auth = wasm::prepare(
        &authorization_source("ctx=>{const t=ctx.clock();ctx.changesAt(102);return t<102}"),
        native_limits(),
    )
    .unwrap();
    let fresh = wasm::prepare(
        &authorization_source("ctx=>{const t=ctx.clock();ctx.changesAt(110);return t<110}"),
        native_limits(),
    )
    .unwrap();
    let authority = wasm::prepare(
        &native_source(
            "sqlAuthority",
            "ctx=>{const t=ctx.clock();ctx.changesAt(102);return t<102}",
        ),
        native_limits(),
    )
    .unwrap();
    let provider = wasm::prepare(
        &native_source(
            "sqlProvider",
            "ctx=>{const t=ctx.clock();ctx.changesAt(102);return t<102}",
        ),
        native_limits(),
    )
    .unwrap();
    for publication_clock in [101, 102, 103] {
        let mut f = Fixture::new("null");
        f.binding.clock = 100;
        let original_deadline = f.job.deadline();
        let relations = [];
        let support = CapturedSupport::from_owned_capture(&[], &[]).unwrap();
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        for phase in [
            NativePhase::InitialAuth,
            NativePhase::Authority,
            NativePhase::Provider,
            NativePhase::FreshAuth,
        ] {
            f.binding.clock = if phase == NativePhase::FreshAuth {
                101
            } else {
                100
            };
            admitted
                .check_native_clock(&mut f.job, f.binding.clock)
                .unwrap();
            let execution = invocation_limits(&f);
            let point = native_point(&f.job, phase, f.binding);
            {
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
                    .unwrap()
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
                    .unwrap()
                };
                match phase {
                    NativePhase::InitialAuth => {
                        wasm::execute_sql_authorization(&auth, &[wire::NULL], &mut host, execution)
                    }
                    NativePhase::FreshAuth => {
                        wasm::execute_sql_authorization(&fresh, &[wire::NULL], &mut host, execution)
                    }
                    NativePhase::Authority => wasm::execute_prepared_encoded(
                        &authority,
                        "test",
                        &[wire::NULL],
                        "sqlAuthority",
                        &mut host,
                        execution,
                    ),
                    NativePhase::Provider => wasm::execute_prepared_encoded(
                        &provider,
                        "test",
                        &[wire::NULL],
                        "sqlProvider",
                        &mut host,
                        execution,
                    ),
                    _ => unreachable!(),
                }
                .unwrap();
                assert_eq!(
                    host.completion(),
                    Some(CallbackCompletion::PermissionEvaluated)
                );
                assert!(host.finished().is_some());
            }
            admitted
                .check_native_clock(&mut f.job, f.binding.clock)
                .unwrap();
            assert_eq!(f.job.deadline(), original_deadline);
        }
        let stamp = admitted.permission_stamp(&mut f.job, 101).unwrap();
        assert_eq!(stamp.validity(), Validity::Until(102));
        assert_eq!(stamp.not_before_ms(), Some(101));
        assert_eq!(
            admitted.validate_permission_stamp(&mut f.job, stamp, publication_clock),
            if publication_clock < 102 {
                Ok(())
            } else {
                Err(HostError::Temporal(TemporalError::Expired))
            }
        );
    }
}

#[test]
fn detached_real_wasm_temporal_readless_metadata_never_extends_auth_expiry() {
    let auth = wasm::prepare(
        &authorization_source("ctx=>{ctx.changesAt(102);return true}"),
        native_limits(),
    )
    .unwrap();
    let plan = wasm::prepare(
        &native_source(
            "sqlPlan",
            "ctx=>[ctx.clock(),typeof ctx.now,typeof ctx.changesAt,typeof ctx.get]",
        ),
        native_limits(),
    )
    .unwrap();
    // This unsigned result-bound metadata is NOT a managed signature or auth
    // expiry. Actual signing remains forbidden/HOLD; do not claim otherwise.
    let finalizer = wasm::prepare(
        &native_source(
            "sqlFinalizer",
            "ctx=>({issued:ctx.clock(),resultBound:ctx.clock()+120000})",
        ),
        native_limits(),
    )
    .unwrap();
    let mut f = Fixture::new("null");
    f.binding.clock = 100;
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    for (phase, prepared, kind) in [
        (NativePhase::InitialAuth, &auth, "query"),
        (NativePhase::ReadlessPlan, &plan, "sqlPlan"),
        (NativePhase::ReadlessFinalizer, &finalizer, "sqlFinalizer"),
    ] {
        f.binding.clock = if phase == NativePhase::ReadlessFinalizer {
            101
        } else {
            100
        };
        let execution = invocation_limits(&f);
        let mut host = SqlHost::new(
            phase,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, phase, f.binding),
            &mut f.job,
        )
        .unwrap();
        if phase == NativePhase::InitialAuth {
            wasm::execute_sql_authorization(prepared, &[wire::NULL], &mut host, execution).unwrap();
        } else {
            wasm::execute_prepared_encoded(
                prepared,
                "test",
                &[wire::NULL],
                kind,
                &mut host,
                execution,
            )
            .unwrap();
            assert_eq!(host.completion(), Some(CallbackCompletion::MetadataOnly));
        }
        let WireOutcome::Success(id) = host.finished().unwrap() else {
            panic!("success")
        };
        let value = host.finished_value(id).unwrap();
        if phase == NativePhase::ReadlessPlan {
            assert_eq!(value.index(0).unwrap().as_i32(), Some(100));
            for index in 1..4 {
                assert_eq!(value.index(index).unwrap().as_str(), Some("undefined"));
            }
        } else if phase == NativePhase::ReadlessFinalizer {
            assert_eq!(value.member("issued").unwrap().as_i32(), Some(101));
            assert_eq!(value.member("resultBound").unwrap().as_i32(), Some(120101));
        }
    }
    let stamp = admitted.permission_stamp(&mut f.job, 101).unwrap();
    assert_eq!(stamp.validity(), Validity::Until(102));
    assert_eq!(
        admitted.validate_permission_stamp(&mut f.job, stamp, 102),
        Err(HostError::Temporal(TemporalError::Expired))
    );
}

#[test]
fn detached_real_wasm_registered_authority_sees_private_guard_metadata_not_effective_identity() {
    let prepared = wasm::prepare(&native_source("sqlAuthority", "ctx=>[ctx.principal(),ctx.get({kind:'collection',name:'rows'},'b').hidden,ctx.scan({kind:'collection',name:'rows'}).length]"), native_limits()).unwrap();
    let mut f =
        Fixture::new(r#"{"read":{"const":false},"fields":{"hidden":{"read":{"const":false}}}}"#);
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let execution = invocation_limits(&f);
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
    wasm::execute_prepared_encoded(
        &prepared,
        "test",
        &[wire::NULL],
        "sqlAuthority",
        &mut host,
        execution,
    )
    .unwrap();
    let WireOutcome::Success(id) = host.finished().unwrap() else {
        panic!("success")
    };
    let value = host.finished_value(id).unwrap();
    assert_eq!(
        value.index(0).unwrap().member("subject").unwrap().as_str(),
        Some("caller")
    );
    assert_eq!(value.index(1).unwrap().as_str(), Some("private"));
    assert_eq!(value.index(2).unwrap().as_i32(), Some(2));
}

#[test]
fn detached_real_wasm_closed_authority_captured_raw_hostile_operations_remain_fatal() {
    for expression in [
        "__flowerContexts[1].set({kind:'collection',name:'rows'},'a',1)",
        "__flowerContexts[1].delete({kind:'collection',name:'rows'},'a')",
        "__flowerContexts[1].materialize({kind:'derived',name:'other'},null)",
        "__flowerContexts[1].unmaterialize({kind:'derived',name:'other'},null)",
        "__flowerContexts[1].get({kind:'derived',name:'other'},null)",
        "__flowerCrypto(101,0,'invalid','key','{}')",
    ] {
        let compute = format!("()=>{{try{{{expression};}}catch(_){{return 'caught'}}return true}}");
        let prepared =
            wasm::prepare(&native_source("sqlAuthority", &compute), native_limits()).unwrap();
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let execution = invocation_limits(&f);
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
        let error = wasm::execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlAuthority",
            &mut host,
            execution,
        )
        .unwrap_err();
        if expression.starts_with("__flowerCrypto") {
            assert!(error.to_string().contains("SQL_CRYPTO_FORBIDDEN"));
        } else {
            assert!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<HostError>() == Some(&HostError::Forbidden))
            );
        }
        assert!(host.finished().is_none());
    }
}

#[test]
fn detached_real_wasm_readless_captured_now_changes_at_and_reads_are_fatal() {
    for kind in ["sqlPlan", "sqlFinalizer"] {
        for expression in [
            "__flowerContexts[1].now()",
            "__flowerContexts[1].changesAt(102)",
            "__flowerContexts[1].get({kind:'collection',name:'rows'},'a')",
        ] {
            let prepared = wasm::prepare(
                &native_source(
                    kind,
                    &format!("()=>{{try{{{expression}}}catch(_){{return 'caught'}}return true}}"),
                ),
                native_limits(),
            )
            .unwrap();
            let mut f = Fixture::new("null");
            f.binding.clock = 100;
            let relations = [];
            let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
            let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
            let execution = invocation_limits(&f);
            let phase = if kind == "sqlPlan" {
                NativePhase::ReadlessPlan
            } else {
                NativePhase::ReadlessFinalizer
            };
            let mut host = SqlHost::new(
                phase,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                None,
                &budget,
                native_point(&f.job, phase, f.binding),
                &mut f.job,
            )
            .unwrap();
            let error = wasm::execute_prepared_encoded(
                &prepared,
                "test",
                &[wire::NULL],
                kind,
                &mut host,
                execution,
            )
            .unwrap_err();
            assert!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<HostError>() == Some(&HostError::Forbidden))
            );
            assert!(host.finished().is_none());
        }
    }
}

/// Actual raw Wasm import, deliberately bypassing every SDK/QuickJS context
/// surface. Compilation is setup before the fixture ORIGINAL job is admitted.
fn raw_host_opcode(opcode: i32) -> Arc<wasm::Prepared> {
    use base64::Engine as _;
    use wasm_encoder::*;
    let mut module = Module::new();
    let mut types = TypeSection::new();
    types.ty().function([ValType::I32; 3], [ValType::I64]);
    types.ty().function([ValType::I32], [ValType::I32]);
    types.ty().function([ValType::I32; 5], [ValType::I64]);
    types.ty().function([], [ValType::I64]);
    module.section(&types);
    let mut imports = ImportSection::new();
    imports.import("flower", "host_call", EntityType::Function(0));
    module.section(&imports);
    let mut functions = FunctionSection::new();
    functions.function(1).function(2).function(3);
    module.section(&functions);
    let mut memory = MemorySection::new();
    memory.memory(MemoryType {
        minimum: 1,
        maximum: Some(2),
        memory64: false,
        shared: false,
        page_size_log2: None,
    });
    module.section(&memory);
    let mut globals = GlobalSection::new();
    globals.global(
        GlobalType {
            val_type: ValType::I32,
            mutable: true,
            shared: false,
        },
        &ConstExpr::i32_const(8192),
    );
    module.section(&globals);
    let mut exports = ExportSection::new();
    exports
        .export("memory", ExportKind::Memory, 0)
        .export("flower_alloc", ExportKind::Func, 1)
        .export("flower_invoke", ExportKind::Func, 2)
        .export("flower_manifest", ExportKind::Func, 3);
    module.section(&exports);
    let mut code = CodeSection::new();
    let mut alloc = Function::new([]);
    alloc
        .instruction(&Instruction::GlobalGet(0))
        .instruction(&Instruction::GlobalGet(0))
        .instruction(&Instruction::LocalGet(0))
        .instruction(&Instruction::I32Add)
        .instruction(&Instruction::GlobalSet(0))
        .instruction(&Instruction::End);
    code.function(&alloc);
    let mut invoke = Function::new([]);
    invoke
        .instruction(&Instruction::I32Const(opcode))
        .instruction(&Instruction::I32Const(32))
        .instruction(&Instruction::I32Const(0))
        .instruction(&Instruction::Call(0))
        .instruction(&Instruction::End);
    code.function(&invoke);
    let mut manifest = Function::new([]);
    manifest
        .instruction(&Instruction::I64Const((6i64 << 32) | 64))
        .instruction(&Instruction::End);
    code.function(&manifest);
    module.section(&code);
    let mut data = DataSection::new();
    data.active(
        0,
        &ConstExpr::i32_const(64),
        [wire::SUCCESS, wire::MAP, 0, 0, 0, 0],
    );
    module.section(&data);
    let bytes = module.finish();
    wasm::prepare_bundle(
        &json!({"hash":crate::evaluator::hash(&bytes),
        "wasm":base64::engine::general_purpose::STANDARD.encode(&bytes)}),
        native_limits(),
    )
    .unwrap()
}

#[test]
fn detached_real_raw_wasm_opcodes_8_9_10_11_14_15_and_unknown_cannot_publish() {
    for opcode in [8, 9, 10, 11, 14, 15, 999] {
        let prepared = raw_host_opcode(opcode);
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let execution = invocation_limits(&f);
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
        let error = wasm::execute_prepared_encoded(
            &prepared,
            "test",
            &[wire::NULL],
            "sqlAuthority",
            &mut host,
            execution,
        )
        .unwrap_err();
        if opcode == 999 {
            assert!(
                error
                    .chain()
                    .any(|cause| cause.to_string().contains("unknown host operation 999"))
            );
        } else {
            assert!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<HostError>() == Some(&HostError::Forbidden))
            );
        }
        assert!(host.finished().is_none());
        assert_eq!(host.completion(), None);
    }
}

#[test]
fn actual_sdk_typed_provider_adapter_parses_each_encoded_native_key_once_in_real_wasmtime() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let generated = std::process::Command::new("node")
        .arg(root.join("src/evaluator/sql_host/sdk_provider_fixture.mjs"))
        .arg(root)
        .output()
        .expect("native SDK fixture builder");
    assert!(generated.status.success(), "SQL_FIXTURE_BUILD_FAILED");
    let code = std::str::from_utf8(&generated.stdout).unwrap();
    let prepared = wasm::prepare(code, native_limits()).unwrap();
    let code_version = crate::evaluator::hash(code.as_bytes());
    // Both actual SDK compilation and actual native prepare finish BEFORE the
    // original JobControl. No 180s warm allowance becomes execution permission.
    let super::native_capture_tests::Captured {
        mut f,
        declaration,
        collections,
        descriptors,
    } = super::native_capture_tests::captured_members();
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
    let execution = invocation_limits(&f);
    let binding = NativeBinding::from_controller(
        f.binding.invoker,
        f.binding.principal,
        f.binding.history,
        f.binding.authority_context,
        f.binding.partition,
        f.binding.clock,
        f.binding.source_revision,
        &code_version,
        f.binding.catalog_version,
    )
    .unwrap();
    let point = native_point(&f.job, NativePhase::Provider, binding);
    let mut host = SqlHost::new_native(
        NativePhase::Provider,
        &mut admitted,
        native,
        binding,
        &budget,
        point,
        &mut f.job,
    )
    .unwrap();
    // Fixed fixture transport scratch, not a post-admission growing Vec. This
    // is a component invocation, NOT a whole runtime/native-stack admission.
    let mut arguments = [0u8; 64 * 1024];
    let input = host
        .prepare_provider_input_from_native_catalog(declaration)
        .unwrap();
    let length = input.len();
    arguments[..length].copy_from_slice(input);
    wasm::execute_prepared_encoded(
        &prepared,
        "capture.$sql.provider.members",
        &arguments[..length],
        "sqlProvider",
        &mut host,
        execution,
    )
    .unwrap();
    let rows = host.validated_provider_rows(1).unwrap();
    assert_eq!(rows.len(), Some(2));
    let sum: i64 = rows
        .iter()
        .unwrap()
        .map(|entry| {
            entry
                .value
                .member("cells")
                .unwrap()
                .index(0)
                .unwrap()
                .member("integer")
                .unwrap()
                .as_str()
                .unwrap()
                .parse::<i64>()
                .unwrap()
        })
        .sum();
    assert_eq!(sum, 7);
    let WireOutcome::Success(id) = host.finished().unwrap() else {
        panic!("native provider success")
    };
    assert_eq!(
        host.finished_value(id)
            .unwrap()
            .member("provenance")
            .unwrap()
            .index(0)
            .unwrap()
            .member("parsed")
            .unwrap()
            .as_i32(),
        Some(2)
    );
    assert_eq!(
        host.completion(),
        Some(CallbackCompletion::PermissionEvaluated)
    );
}

#[test]
fn actual_sdk_finalizer_consumes_native_qualified_expiry_and_original_rseal_in_real_wasmtime() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let generated = std::process::Command::new("node")
        .arg(root.join("src/evaluator/sql_host/sdk_provider_fixture.mjs"))
        .arg(root)
        .output()
        .unwrap();
    assert!(generated.status.success(), "SQL_FIXTURE_BUILD_FAILED");
    let code = std::str::from_utf8(&generated.stdout).unwrap();
    let prepared = wasm::prepare(code, native_limits()).unwrap();
    let code_version = crate::evaluator::hash(code.as_bytes());
    let mut f = Fixture::new("null");
    f.binding.clock = 100;
    let mut admitted = admission(&f, &[], MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let original_binding = NativeBinding::from_controller(
        f.binding.invoker,
        f.binding.principal,
        f.binding.history,
        f.binding.authority_context,
        f.binding.partition,
        100,
        17,
        &code_version,
        f.binding.catalog_version,
    )
    .unwrap();
    {
        let point = native_point(&f.job, NativePhase::InitialAuth, original_binding);
        let mut host = SqlHost::new(
            NativePhase::InitialAuth,
            &mut admitted,
            &f.frame,
            &[],
            original_binding,
            None,
            &budget,
            point,
            &mut f.job,
        )
        .unwrap();
        host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
    }
    // Actual deployed declaration callback records its exclusive permission
    // boundary in the ORIGINAL ledger; no app finalizer metadata invents it.
    {
        let point = native_point(&f.job, NativePhase::FreshAuth, original_binding);
        let mut host = SqlHost::new(
            NativePhase::FreshAuth,
            &mut admitted,
            &f.frame,
            &[],
            original_binding,
            None,
            &budget,
            point,
            &mut f.job,
        )
        .unwrap();
        host.call_checked("clock", &[]).unwrap();
        host.call_checked("changesAt", &args(&[json!(200)]))
            .unwrap();
        host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
    }
    let stamp = admitted.permission_stamp(&mut f.job, 105).unwrap();
    // Unsafe COMPONENT native issuance only, not actual source verification.
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
    let binding = original_binding.at_permission_point(point).unwrap();
    let execution = invocation_limits(&f);
    let mut host = SqlHost::new_qualified_finalizer(
        &mut admitted,
        &f.frame,
        binding,
        &budget,
        stamp,
        point,
        &mut f.job,
    )
    .unwrap();
    let mut arguments = [0u8; 64 * 1024];
    let input = host
        .prepare_finish_input(f.request, f.result, f.provenance)
        .unwrap();
    let length = input.len();
    arguments[..length].copy_from_slice(input);
    wasm::execute_prepared_encoded(
        &prepared,
        "capture.run.$sql.finalize",
        &arguments[..length],
        "sqlFinalizer",
        &mut host,
        execution,
    )
    .unwrap();
    let WireOutcome::Success(id) = host.finished().unwrap() else {
        panic!("native finalizer success")
    };
    let value = host.finished_value(id).unwrap();
    assert_eq!(value.member("until").unwrap().as_i32(), Some(200));
    assert_eq!(value.member("sourceRevision").unwrap().as_i32(), Some(17));
    assert_eq!(value.member("clock").unwrap().as_i32(), Some(105));
    assert_eq!(value.member("invoker").unwrap().as_str(), Some("caller"));
    assert_eq!(
        value.member("principal").unwrap().as_str(),
        Some("effective")
    );
    assert_eq!(value.member("get").unwrap().as_str(), Some("undefined"));
    let permission = host.finish_permission().unwrap();
    drop(host);
    assert_eq!(
        admitted
            .validate_finish_permission(&mut f.job, permission, 106)
            .unwrap(),
        Some(200)
    );
    assert_eq!(
        admitted.validate_finish_permission(&mut f.job, permission, 200),
        Err(HostError::Temporal(TemporalError::Expired))
    );
}
