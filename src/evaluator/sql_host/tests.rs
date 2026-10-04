#![allow(unexpected_cfgs)] // External-only allocator observer; not a production feature.
use super::super::{
    sql_frame::{FrameLimits, JsonBank},
    sql_policy::{CapturedCollection, Validity},
    wire,
};
use super::*;
#[path = "authority_tests.rs"]
mod authority_tests;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

fn wire_limits() -> WireLimits {
    WireLimits {
        message_bytes: 64 * 1024,
        text_bytes: 128 * 1024,
        nodes: 4096,
        keys: 4096,
        logical_key_bytes: 256 * 1024,
        output_bytes: 64 * 1024,
        depth: 64,
        job_work: 8 * 1024 * 1024,
    }
}
fn frame_limits() -> FrameLimits {
    FrameLimits {
        raw_bytes: 128 * 1024,
        support_bytes: 128 * 1024,
        decoded_bytes: 128 * 1024,
        nodes: 8192,
        documents: 64,
        keys: 64,
        key_bytes: 8192,
        tables: 4,
        columns: 16,
        rows: 128,
        cells: 512,
        text_bytes: 64 * 1024,
        provenance_bytes: 1024,
        parse_work: 8 * 1024 * 1024,
    }
}
fn capture(frame: &mut FrameBuilder, text: &str, control: &FrameControl<'_>) -> JsonId {
    let id = frame.reserve_json(JsonBank::Support, text.len()).unwrap();
    for chunk in text.as_bytes().chunks(64 * 1024) {
        frame.append_json_chunk(id, chunk).unwrap();
    }
    frame.finish_json(id, control).unwrap();
    id
}
fn args(values: &[Value]) -> Vec<u8> {
    let mut encoder = wire::Encoder::default();
    for value in values {
        encoder.value(value).unwrap();
    }
    encoder.out
}
fn get(key: &str) -> Vec<u8> {
    args(&[json!({"kind":"collection","name":"rows"}), json!(key)])
}
fn scan() -> Vec<u8> {
    args(&[json!({"kind":"collection","name":"rows"})])
}
fn outcome(value: &Value) -> Vec<u8> {
    let mut bytes = vec![wire::SUCCESS];
    bytes.extend(wire::encode(value).unwrap());
    bytes
}
struct Fixture {
    frame: FrameBuilder,
    binding: NativeBinding<'static>,
    rows: [OwnedRow; 3],
    policy: JsonId,
    authority_catalog: JsonId,
    request: JsonId,
    result: JsonId,
    provenance: JsonId,
    cancel: Arc<AtomicBool>,
    job: JobControl,
}
impl Fixture {
    fn new(policy: &str) -> Self {
        let cancel = Arc::new(AtomicBool::new(false));
        let job = JobControl::new(Duration::from_secs(10), cancel.clone()).unwrap();
        let control = FrameControl::new(&cancel, job.deadline());
        let mut frame = FrameBuilder::new(frame_limits(), &control).unwrap();
        let invoker = capture(
            &mut frame,
            r#"{"subject":"caller","claims":{"role":"ordinary"}}"#,
            &control,
        );
        let principal = capture(&mut frame, r#"{"subject":"effective"}"#, &control);
        let history = capture(
            &mut frame,
            r#"{"database":"logical","incarnation":"stable"}"#,
            &control,
        );
        let authority = capture(&mut frame, r#"{"verified":true}"#, &control);
        let partition = capture(&mut frame, "null", &control);
        let policy = capture(&mut frame, policy, &control);
        let authority_catalog = capture(
            &mut frame,
            r#"{"name":"native_catalog","version":"catalog-v1","authority":"test","tables":[]}"#,
            &control,
        );
        let a = frame.retain_key("a🌸").unwrap();
        let b = frame.retain_key("b").unwrap();
        let absent = frame.retain_key("gone").unwrap();
        let av = capture(
            &mut frame,
            r#"{"owner":"caller","public":"🌸字","hidden":"private"}"#,
            &control,
        );
        let bv = capture(
            &mut frame,
            r#"{"owner":"other","public":2,"hidden":"private"}"#,
            &control,
        );
        let request = capture(
            &mut frame,
            r#"{"input":{"sql":"SELECT 1"},"purpose":{"untrusted":true}}"#,
            &control,
        );
        let result = capture(&mut frame, r#"{"rows":[]}"#, &control);
        let provenance = capture(&mut frame, "[]", &control);
        let binding = NativeBinding::from_controller(
            invoker,
            principal,
            history,
            authority,
            partition,
            1000,
            17,
            "code-generation",
            "catalog-v1",
        )
        .unwrap();
        Self {
            frame,
            binding,
            rows: [
                OwnedRow {
                    key: a,
                    value: Some(av),
                },
                OwnedRow {
                    key: b,
                    value: Some(bv),
                },
                OwnedRow {
                    key: absent,
                    value: None,
                },
            ],
            policy,
            authority_catalog,
            request,
            result,
            provenance,
            cancel,
            job,
        }
    }
}
/// Test controller attestation ONLY. It is not the missing production source/
/// deployed-code/catalog verifier; callers explicitly pass phase/binding/job.
fn native_point(
    job: &JobControl,
    phase: NativePhase,
    binding: NativeBinding<'_>,
) -> NativeTimePoint {
    unsafe {
        NativeTimePoint::from_certified_native_point(
            job,
            phase,
            binding.clock,
            binding.permission_revision,
            1,
            1,
        )
    }
    .unwrap()
}
#[allow(clippy::too_many_arguments)]
fn registered_authority_host<'a>(
    admitted: &'a mut HostAdmission,
    frame: &'a FrameBuilder,
    relations: &'a [OwnedRelation<'a>],
    binding: NativeBinding<'a>,
    budget: &'a PolicyBudget,
    point: NativeTimePoint,
    job: &'a mut JobControl,
    registration: JsonId,
) -> Result<SqlHost<'a>, HostError> {
    let control = FrameControl::new(job.cancellation(), job.deadline());
    let permit = unsafe {
        ClosedAuthorityPermit::from_certified_native_registration(
            frame,
            registration,
            point,
            binding,
            [1; 32],
            [2; 32],
            &control,
        )
    }?;
    let execution = unsafe {
        NativeAuthorityExecution::from_certified_native_execution(
            point,
            "test",
            binding.code_version,
            binding.catalog_version,
            [1; 32],
            [2; 32],
        )
    }?;
    SqlHost::new_registered_authority(
        admitted, frame, relations, binding, budget, job, point, permit, execution,
    )
}
fn complete_permission_fixture(
    f: &mut Fixture,
    admitted: &mut HostAdmission,
    budget: &PolicyBudget,
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
    host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
}
fn admission(f: &Fixture, relations: &[OwnedRelation<'_>], work: usize) -> HostAdmission {
    HostAdmission::new(
        wire_limits(),
        &f.frame,
        relations,
        ExternalReservation {
            total_bytes: 128 * 1024 * 1024,
            borrowed_owner_bytes: 16 * 1024,
        },
        work,
        &f.job,
    )
    .unwrap()
}
fn json_response(bytes: &[u8]) -> Value {
    let mut arena = WireArena::new(wire_limits()).unwrap();
    let WireOutcome::Success(id) = arena.decode_outcome(bytes).unwrap() else {
        panic!("expected native success")
    };
    serde_json::from_slice(arena.json(id).unwrap()).unwrap()
}

#[test]
fn native_phase_matrix_all_operations_and_unknowns() {
    let phases = [
        NativePhase::InitialAuth,
        NativePhase::FreshAuth,
        NativePhase::ReadlessPlan,
        NativePhase::Authority,
        NativePhase::Provider,
        NativePhase::ReadlessFinalizer,
    ];
    for phase in phases {
        for op in [
            "now",
            "principal",
            "history",
            "get",
            "scan",
            "range",
            "query",
            "set",
            "delete",
            "materialize",
            "unmaterialize",
            "clock",
            "changesAt",
            "definer",
            "sql",
            "codeVersion",
            "__flowerContexts",
            "system",
            "unknown",
        ] {
            let allowed = matches!(op, "principal" | "history" | "clock" | "codeVersion")
                || (!phase.readless()
                    && matches!(op, "now" | "changesAt" | "get" | "scan" | "range" | "query"));
            assert_eq!(permitted(phase, op), allowed, "{phase:?} {op}");
        }
    }
}
#[test]
fn captured_writers_and_spoofed_principal_are_fatal_before_decode() {
    for phase in [
        NativePhase::InitialAuth,
        NativePhase::FreshAuth,
        NativePhase::ReadlessPlan,
        NativePhase::Provider,
        NativePhase::ReadlessFinalizer,
    ] {
        for op in [
            "set",
            "delete",
            "materialize",
            "unmaterialize",
            "definer",
            "sql",
            "unknown",
        ] {
            let mut f = Fixture::new("null");
            let relations = [OwnedRelation {
                name: "rows",
                coverage: CaptureCoverage::Complete,
                rows: &f.rows,
            }];
            let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
            let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
            let mut host = SqlHost::new(
                phase,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                if matches!(phase, NativePhase::Authority | NativePhase::Provider) {
                    Some(CapturedSupport::from_owned_capture(&[], &[]).unwrap())
                } else {
                    None
                },
                &budget,
                native_point(&f.job, phase, f.binding),
                &mut f.job,
            )
            .unwrap();
            assert_eq!(
                host.call_checked(op, &[255]).unwrap_err(),
                HostError::Forbidden
            );
            assert_eq!(
                host.finish_checked(&outcome(&json!("escaped"))),
                Err(HostError::Forbidden)
            );
        }
    }
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    assert_eq!(
        json_response(host.call_checked("principal", &[]).unwrap())["subject"],
        "caller"
    );
    let spoof = args(&[json!({"subject":"system","read":true})]);
    assert_eq!(
        host.call_checked("principal", &spoof).unwrap_err(),
        HostError::Invalid
    );
}
#[test]
fn readless_sources_now_changes_and_metadata_arity_are_denied() {
    for phase in [NativePhase::ReadlessPlan, NativePhase::ReadlessFinalizer] {
        for op in ["get", "scan", "range", "query", "now", "changesAt"] {
            let mut f = Fixture::new("null");
            let relations = [];
            let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
            let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
            assert_eq!(
                host.call_checked(op, &[]).unwrap_err(),
                HostError::Forbidden
            );
        }
    }
}
#[test]
fn auth_owned_get_unicode_and_complete_scan_are_not_limit_prefixes() {
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    let input = get("a🌸");
    let guest = input.as_ptr() as usize..input.as_ptr() as usize + input.len();
    let response = host.call_checked("get", &input).unwrap();
    let native = response.as_ptr() as usize..response.as_ptr() as usize + response.len();
    assert!(guest.end <= native.start || native.end <= guest.start);
    assert_eq!(json_response(response)["public"], "🌸字");
    assert_eq!(
        json_response(host.call_checked("get", &get("missing")).unwrap()),
        Value::Null
    );
    let result = json_response(host.call_checked("scan", &scan()).unwrap());
    assert_eq!(result.as_array().unwrap().len(), 2);
    assert_eq!(result[0]["key"], "a🌸");
    let partial = args(&[
        json!({"kind":"collection","name":"rows"}),
        json!({"limit":1}),
    ]);
    assert_eq!(
        host.call_checked("scan", &partial).unwrap_err(),
        HostError::Unsupported
    );
}
#[test]
fn uncaptured_get_is_not_absent_and_demand_is_sticky() {
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::KeysOnly,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        assert_eq!(
            json_response(host.call_checked("get", &get("gone")).unwrap()),
            Value::Null
        );
        assert_eq!(
            host.call_checked("get", &get("uncaptured")).unwrap_err(),
            HostError::NeedCapture(NativeNeedCapture)
        );
        assert_eq!(
            host.call_checked("get", &get("gone")).unwrap_err(),
            HostError::NeedCapture(NativeNeedCapture)
        );
        assert_eq!(
            host.finish_checked(&outcome(&json!(null))),
            Err(HostError::NeedCapture(NativeNeedCapture))
        );
    }
    let demand = admitted.demand().unwrap().unwrap();
    assert_eq!(demand.kind, DemandKind::Get);
    assert_eq!(demand.collection, Some("rows"));
    assert_eq!(demand.key, Some("uncaptured"));
    let before = admitted.remaining_work();
    unsafe { admitted.acknowledge_native_capture(&mut f.job) }.unwrap();
    assert_eq!(admitted.remaining_work(), before);
}
#[test]
fn incomplete_scan_and_missing_relation_require_capture_not_empty_result() {
    for coverage in [CaptureCoverage::KeysOnly, CaptureCoverage::Complete] {
        let mut f = Fixture::new("null");
        let relations = if coverage == CaptureCoverage::KeysOnly {
            vec![OwnedRelation {
                name: "rows",
                coverage,
                rows: &f.rows,
            }]
        } else {
            vec![]
        };
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        {
            let mut host = SqlHost::new(
                NativePhase::FreshAuth,
                &mut admitted,
                &f.frame,
                &relations,
                f.binding,
                None,
                &budget,
                native_point(&f.job, NativePhase::FreshAuth, f.binding),
                &mut f.job,
            )
            .unwrap();
            assert_eq!(
                host.call_checked("scan", &scan()).unwrap_err(),
                HostError::NeedCapture(NativeNeedCapture)
            );
        }
        assert_eq!(
            admitted.demand().unwrap().unwrap().kind,
            DemandKind::CompleteScan
        );
    }
}
#[test]
fn derived_index_internal_and_raw_refs_cannot_read_owned_relations() {
    for reference in [
        json!("rows"),
        json!({"kind":"derived","name":"rows"}),
        json!({"kind":"collection","name":"rows","indexes":{}}),
        json!({"kind":"collection","name":"record:rows"}),
        json!({"kind":"collection","name":"$internal"}),
        json!({"kind":"collection","name":"__flowerContexts"}),
    ] {
        let mut f = Fixture::new("null");
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        assert_eq!(
            host.call_checked("get", &args(&[reference, json!("a🌸")]))
                .unwrap_err(),
            HostError::Forbidden
        );
    }
}
#[test]
fn native_acl_invoker_filter_and_field_redaction_before_guest_copy() {
    let mut f = Fixture::new(
        r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"fields":{"hidden":{"read":{"const":false}}}}"#,
    );
    f.binding.principal = f.binding.invoker;
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    let row = json_response(host.call_checked("get", &get("a🌸")).unwrap());
    assert_eq!(row["public"], "🌸字");
    assert!(row.get("hidden").is_none());
    assert_eq!(
        json_response(host.call_checked("get", &get("b")).unwrap()),
        Value::Null
    );
    let scan = json_response(host.call_checked("scan", &scan()).unwrap());
    assert_eq!(scan, json!([{"key":"a🌸","value":row}]));
    assert!(!scan.to_string().contains("source:["));
}
#[test]
fn provider_uses_native_effective_principal_not_guest_role_or_read_flag() {
    let mut f = Fixture::new(
        r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}"#,
    );
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        json_response(host.call_checked("principal", &[]).unwrap())["subject"],
        "effective"
    );
    assert_eq!(
        json_response(host.call_checked("get", &get("a🌸")).unwrap()),
        Value::Null
    );
}
#[test]
fn authority_provider_cannot_construct_without_native_policy_support() {
    for phase in [NativePhase::Authority, NativePhase::Provider] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
            Err(HostError::Forbidden)
        ));
    }
}
#[test]
fn concat_repeated_keys_unicode_decode_and_finish_copy_are_host_owned() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    // The finish source is mutable guest-owned memory and immediately destroyed.
    let value = json!({"🌸":{"repeated":"字"},"next":{"repeated":"💐"}});
    let mut bytes = outcome(&value);
    host.finish_checked(&bytes).unwrap();
    bytes.fill(255);
    let WireOutcome::Success(id) = host.finished().unwrap() else {
        panic!("success")
    };
    assert_eq!(
        host.finished_value(id)
            .unwrap()
            .member("🌸")
            .unwrap()
            .member("repeated")
            .unwrap()
            .as_str(),
        Some("字")
    );
    assert_eq!(
        host.call_checked("clock", &[]).unwrap_err(),
        HostError::Finished
    );
}
#[test]
fn callback_business_failure_is_copied_but_host_denial_is_never_failure() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut host = SqlHost::new(
        NativePhase::ReadlessFinalizer,
        &mut admitted,
        &f.frame,
        &relations,
        f.binding,
        None,
        &budget,
        native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding),
        &mut f.job,
    )
    .unwrap();
    let mut bytes = vec![wire::FAILURE];
    bytes.extend(
        wire::encode(&json!({"code":"APPLICATION","message":"字🌸","details":{"bounded":true}}))
            .unwrap(),
    );
    host.finish_checked(&bytes).unwrap();
    bytes.fill(0);
    let WireOutcome::Failure {
        code,
        message,
        details,
    } = host.finished().unwrap()
    else {
        panic!("failure")
    };
    assert_eq!(
        host.finished_value(code).unwrap().as_str(),
        Some("APPLICATION")
    );
    assert_eq!(host.finished_value(message).unwrap().as_str(), Some("字🌸"));
    assert!(details.is_some());
}
#[test]
fn immutable_native_finish_binding_cannot_be_substituted_by_raw_purpose() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    complete_permission_fixture(&mut f, &mut admitted, &budget);
    let stamp = admitted
        .permission_stamp(&mut f.job, f.binding.clock)
        .unwrap();
    let mut host = SqlHost::new_qualified_finalizer(
        &mut admitted,
        &f.frame,
        f.binding,
        &budget,
        stamp,
        native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding),
        &mut f.job,
    )
    .unwrap();
    let bytes = host
        .prepare_finish_input(f.request, f.result, f.provenance)
        .unwrap();
    let mut reader = WireArena::new(wire_limits()).unwrap();
    let id = reader.decode(bytes).unwrap();
    let input = reader.value(id).unwrap();
    let binding = input.member("binding").unwrap();
    assert_eq!(
        binding.member("sourceRevision").unwrap().as_f64(),
        Some(17.0)
    );
    assert_eq!(
        binding.member("codeVersion").unwrap().as_str(),
        Some("code-generation")
    );
    assert_eq!(
        binding.member("catalogVersion").unwrap().as_str(),
        Some("catalog-v1")
    );
    assert_eq!(
        binding
            .member("authorityContext")
            .unwrap()
            .member("verified")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    assert!(
        binding
            .member("authorityContext")
            .unwrap()
            .member("untrusted")
            .is_none()
    );
    assert_eq!(
        json_response(host.call_checked("principal", &[]).unwrap())["subject"],
        "effective"
    );
}
#[test]
fn cancellation_deadline_and_work_failure_are_sticky_across_callbacks() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let cancel = f.cancel.clone();
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
    cancel.store(true, Ordering::Release);
    assert_eq!(
        host.call_checked("clock", &[]).unwrap_err(),
        HostError::Cancelled
    );
    cancel.store(false, Ordering::Release);
    assert_eq!(
        host.call_checked("clock", &[]).unwrap_err(),
        HostError::Cancelled
    );
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, 4);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    for _ in 0..4 {
        host.call_checked("clock", &[]).unwrap();
    }
    assert_eq!(
        host.call_checked("clock", &[]).unwrap_err(),
        HostError::WorkLimit
    );
    let mut f = Fixture::new("null");
    f.job = JobControl::new(Duration::from_millis(1), f.cancel.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(3));
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    assert!(matches!(
        SqlHost::new(
            NativePhase::ReadlessPlan,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessPlan, f.binding),
            &mut f.job
        ),
        Err(HostError::Deadline)
    ));
}
#[test]
fn repeated_wire_lookups_are_explicitly_metered_and_untrusted_depth_text_fail() {
    let mut arena = WireArena::new(wire_limits()).unwrap();
    let input = json!({"first":0,"last":1});
    let encoded = wire::encode(&input).unwrap();
    let id = arena.decode(&encoded).unwrap();
    let mut f = Fixture::new("null");
    let mut budget = HostBudget {
        remaining: 20,
        failed: None,
        demand: None,
        rejected: false,
        temporal: GlobalTemporalLedger::new(&f.job),
    };
    let mut work = Work {
        budget: &mut budget,
        job: &mut f.job,
    };
    let mut successes = 0;
    loop {
        match work.member(arena.value(id).unwrap(), "last") {
            Ok(Some(_)) => successes += 1,
            Err(HostError::WorkLimit) => break,
            _ => panic!("lookup"),
        }
    }
    assert!(successes > 0 && successes < 5);
    for input in [vec![wire::NULL; 9], vec![255]] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        assert!(host.call_checked("clock", &input).is_err());
        assert!(host.failure().is_some());
    }
}
#[test]
fn exact_two_arena_and_combined_source_owner_quota_is_required() {
    let f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let admitted = admission(&f, &relations, MAX_HOST_WORK);
    let bytes = admitted.allocation_bytes();
    assert!(bytes > f.frame.allocation_bytes());
    assert!(matches!(
        HostAdmission::new(
            wire_limits(),
            &f.frame,
            &relations,
            ExternalReservation {
                total_bytes: bytes - 1,
                borrowed_owner_bytes: 16 * 1024,
            },
            MAX_HOST_WORK,
            &f.job
        ),
        Err(HostError::Capacity)
    ));
    let input = WireArena::new(WireLimits {
        nodes: 131072,
        keys: 65536,
        ..WireLimits::default()
    })
    .unwrap();
    let output = WireArena::new(WireLimits::default()).unwrap();
    assert!(input.allocation_bytes() + output.allocation_bytes() > MAX_WIRE_PAIR_BYTES);
    assert!(matches!(
        HostAdmission::from_admitted(
            input,
            output,
            &f.frame,
            &relations,
            ExternalReservation {
                total_bytes: usize::MAX,
                borrowed_owner_bytes: 16 * 1024
            },
            MAX_HOST_WORK,
            &f.job
        ),
        Err(HostError::Capacity)
    ));
}

#[cfg(sql_host_harness)]
#[test]
fn post_admission_typed_host_success_and_errors_allocate_zero_heap() {
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::KeysOnly,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let get_known = get("a🌸");
    let get_unknown = get("uncaptured");
    let finish = outcome(&json!({"🌸":{"x":1},"next":{"x":2}}));
    let (result, allocations, bytes) =
        crate::allocation_probe::measure(|| -> Result<(), HostError> {
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
            )?;
            host.call_checked("get", &get_known)?;
            host.call_checked("get", &get_known)?;
            host.call_checked("principal", &[])?;
            host.call_checked("history", &[])?;
            host.call_checked("codeVersion", &[])?;
            if host.call_checked("get", &get_unknown).unwrap_err()
                != HostError::NeedCapture(NativeNeedCapture)
            {
                return Err(HostError::Invalid);
            }
            Ok(())
        });
    assert_eq!(result, Ok(()));
    assert_eq!((allocations, bytes), (0, 0));
    unsafe { admitted.acknowledge_native_capture(&mut f.job) }.unwrap();
    // Complete SAME phase replay before any readless finalizer is permitted.
    {
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
        host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
    }
    let (result, allocations, bytes) =
        crate::allocation_probe::measure(|| -> Result<(), HostError> {
            let stamp = admitted.permission_stamp(&mut f.job, f.binding.clock)?;
            let mut host = SqlHost::new_qualified_finalizer(
                &mut admitted,
                &f.frame,
                f.binding,
                &budget,
                stamp,
                native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding),
                &mut f.job,
            )?;
            host.prepare_finish_input(f.request, f.result, f.provenance)?;
            host.finish_checked(&finish)?;
            Ok(())
        });
    assert_eq!(result, Ok(()));
    assert_eq!((allocations, bytes), (0, 0));
}
#[cfg(sql_host_harness)]
#[test]
fn post_admission_actual_acl_field_filtering_allocates_zero_heap() {
    let mut f =
        Fixture::new(r#"{"read":{"const":true},"fields":{"hidden":{"read":{"const":false}}}}"#);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let input = get("a🌸");
    let (result, allocations, bytes) =
        crate::allocation_probe::measure(|| -> Result<(), HostError> {
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
            )?;
            for _ in 0..8 {
                host.call_checked("get", &input)?;
            }
            Ok(())
        });
    assert_eq!(result, Ok(()));
    assert_eq!((allocations, bytes), (0, 0));
}

#[cfg(feature = "sql")]
#[path = "wasm_tests.rs"]
mod wasm_tests;

#[test]
fn captured_temporal_policy_validity_survives_hidden_row_and_field_copy() {
    let mut f = Fixture::new(r#"{"read":{"lt":[{"ref":["now"]},{"value":1002}]}}"#);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        host.call_checked("get", &get("a🌸")).unwrap();
    }
    assert_eq!(admitted.validity(), Validity::Until(1002));
    assert!(!admitted.validity().permits(1002));
}
#[test]
fn phase_replay_cannot_replace_original_job_clock_or_cancellation() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        host.call_checked("clock", &[]).unwrap();
        host.call_checked("changesAt", &args(&[json!(1002)]))
            .unwrap();
        host.finish_checked(&outcome(&json!(true))).unwrap();
    }
    let mut replacement = JobControl::new(Duration::from_secs(10), f.cancel.clone()).unwrap();
    assert!(matches!(
        SqlHost::new(
            NativePhase::FreshAuth,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&replacement, NativePhase::FreshAuth, f.binding),
            &mut replacement
        ),
        Err(HostError::Temporal(TemporalError::WrongOriginalJob))
    ));
    assert!(matches!(
        SqlHost::new(
            NativePhase::FreshAuth,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::FreshAuth, f.binding),
            &mut f.job
        ),
        Err(HostError::Temporal(TemporalError::WrongOriginalJob))
    ));
}

#[test]
fn provider_native_input_filters_before_projector_and_source_row_is_batch_local() {
    let mut f = Fixture::new(r#"{"read":{"eq":[{"ref":["row","owner"]},{"value":"caller"}]}}"#);
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
    let bytes = host.prepare_provider_input("rows").unwrap();
    let mut input = WireArena::new(wire_limits()).unwrap();
    let id = input.decode(bytes).unwrap();
    let root = input.value(id).unwrap();
    assert_eq!(root.member("rows").unwrap().len(), Some(1));
    assert_eq!(
        root.member("rows")
            .unwrap()
            .index(0)
            .unwrap()
            .member("value")
            .unwrap()
            .member("owner")
            .unwrap()
            .as_str(),
        Some("caller")
    );
    assert_eq!(
        root.member("purpose")
            .unwrap()
            .member("verified")
            .unwrap()
            .as_bool(),
        Some(true)
    );
    assert!(
        root.member("purpose")
            .unwrap()
            .member("untrusted")
            .is_none()
    );
    let result = outcome(
        &json!({"rows":[{"sourceRow":0,"cells":[{"integer":"-9223372036854775808"},{"text":"🌸"}]},{"sourceRow":0,"cells":[{"integer":"9223372036854775807"},null]}],"provenance":[]}),
    );
    host.finish_checked(&result).unwrap();
    assert_eq!(host.validated_provider_rows(2).unwrap().len(), Some(2));
}
#[test]
fn provider_rejects_foreign_ordinal_and_unproved_or_noncanonical_cells() {
    for row in [
        json!({"sourceRow":2,"cells":[null]}),
        json!({"sourceRow":-1,"cells":[null]}),
        json!({"sourceRow":0.5,"cells":[null]}),
        json!({"sourceRow":0,"cells":[true]}),
        json!({"sourceRow":0,"cells":[{"integer":"01"}]}),
        json!({"sourceRow":0,"cells":[{"integer":"-0"}]}),
        json!({"sourceRow":0,"cells":[{"integer":"9223372036854775808"}]}),
        json!({"sourceRow":0,"cells":[{"real":"1"}]}),
        json!({"sourceRow":0,"cells":[{"text":1}]}),
        json!({"sourceRow":0,"cells":[null],"key":"raw"}),
    ] {
        let mut f = Fixture::new("null");
        let policies = [CapturedCollection {
            name: "rows",
            policy: None,
        }];
        let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        host.prepare_provider_input("rows").unwrap();
        host.finish_checked(&outcome(&json!({"rows":[row]})))
            .unwrap();
        assert!(matches!(
            host.validated_provider_rows(1),
            Err(HostError::Invalid)
        ));
        assert_eq!(host.failure(), Some(HostError::Invalid));
    }
}
#[test]
fn wire_depth_text_capacity_and_failed_finish_are_fatal_sticky() {
    let mut nested = vec![wire::SUCCESS];
    for _ in 0..65 {
        nested.extend([wire::ARRAY, 1, 0, 0, 0]);
    }
    nested.push(wire::NULL);
    let long = outcome(&json!("x".repeat(65536)));
    let mut invalid = vec![wire::FAILURE];
    invalid.extend(wire::encode(&json!({"code":true,"message":"bad"})).unwrap());
    for bytes in [nested, long, invalid] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let mut host = SqlHost::new(
            NativePhase::ReadlessFinalizer,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding),
            &mut f.job,
        )
        .unwrap();
        assert!(host.finish_checked(&bytes).is_err());
        assert!(host.failure().is_some());
        assert!(host.finish_checked(&outcome(&json!(null))).is_err());
        assert!(host.finished().is_none());
    }
}
#[cfg(sql_host_harness)]
#[test]
fn provider_preparation_full_result_validation_and_all_fatal_paths_are_heap_free() {
    let mut f = Fixture::new("null");
    let policies = [CapturedCollection {
        name: "rows",
        policy: None,
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let result =
        outcome(&json!({"rows":[{"sourceRow":0,"cells":[{"integer":"-9223372036854775808"}]}]}));
    let (r, count, bytes) = crate::allocation_probe::measure(|| -> Result<(), HostError> {
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
        )?;
        host.prepare_provider_input("rows")?;
        host.finish_checked(&result)?;
        host.validated_provider_rows(1)?;
        Ok(())
    });
    assert_eq!(r, Ok(()));
    assert_eq!((count, bytes), (0, 0));
    for input in [vec![255], vec![wire::NULL; 9]] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        let (r, count, bytes) = crate::allocation_probe::measure(|| -> Result<(), HostError> {
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
            )?;
            if host.call_checked("clock", &input).is_ok() {
                return Err(HostError::Invalid);
            }
            if host.finish_checked(&[wire::SUCCESS, wire::NULL]).is_ok() {
                return Err(HostError::Invalid);
            }
            Ok(())
        });
        assert_eq!(r, Ok(()));
        assert_eq!((count, bytes), (0, 0));
    }
}

#[test]
fn uncaptured_policy_support_is_fatal_typed_not_authoritative_absence() {
    for absent in [false, true] {
        let mut f = Fixture::new(r#"{"read":{"readable":["target",{"value":"missing"}]}}"#);
        let control = FrameControl::new(&f.cancel, f.job.deadline());
        let target_policy = capture(&mut f.frame, r#"{"read":{"const":true}}"#, &control);
        let policies = [
            CapturedCollection {
                name: "rows",
                policy: Some(f.frame.json(f.policy, &control).unwrap()),
            },
            CapturedCollection {
                name: "target",
                policy: Some(f.frame.json(target_policy, &control).unwrap()),
            },
        ];
        let support_rows = [super::super::sql_policy::CapturedSupportRow {
            collection: "target",
            key: "missing",
            row: None,
        }];
        let support = CapturedSupport::from_owned_capture(
            &policies,
            if absent { &support_rows } else { &[] },
        )
        .unwrap();
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::Complete,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        {
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
            if absent {
                assert_eq!(
                    json_response(host.call_checked("get", &get("a🌸")).unwrap()),
                    Value::Null
                );
            } else {
                assert_eq!(
                    host.call_checked("get", &get("a🌸")).unwrap_err(),
                    HostError::NeedCapture(NativeNeedCapture)
                );
                assert!(host.finished().is_none());
            }
        }
        if !absent {
            assert_eq!(
                admitted.demand().unwrap().unwrap().kind,
                DemandKind::PolicySupport
            );
            assert_eq!(
                unsafe { admitted.acknowledge_native_capture(&mut f.job) },
                Err(HostError::Unsupported)
            );
            assert_eq!(budget.failure(), Some(PolicyError::NeedCapture));
        }
    }
}
#[test]
fn native_capture_acknowledgement_cannot_clear_original_stop() {
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::KeysOnly,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        assert_eq!(
            host.call_checked("get", &get("uncaptured")).unwrap_err(),
            HostError::NeedCapture(NativeNeedCapture)
        );
    }
    let remaining = admitted.remaining_work();
    f.cancel.store(true, Ordering::Release);
    assert_eq!(
        unsafe { admitted.acknowledge_native_capture(&mut f.job) },
        Err(HostError::Cancelled)
    );
    assert_eq!(admitted.remaining_work(), remaining);
    f.cancel.store(false, Ordering::Release);
    assert_eq!(
        unsafe { admitted.acknowledge_native_capture(&mut f.job) },
        Err(HostError::Cancelled)
    );
    assert!(matches!(
        SqlHost::new(
            NativePhase::InitialAuth,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::InitialAuth, f.binding),
            &mut f.job
        ),
        Err(HostError::Cancelled)
    ));
}

#[test]
fn native_phases_cannot_replenish_policy_work_with_a_fresh_budget() {
    let mut f = Fixture::new("null");
    let policies = [CapturedCollection {
        name: "rows",
        policy: None,
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        host.call_checked("get", &get("a🌸")).unwrap();
        host.finish_checked(&[wire::SUCCESS, wire::NULL]).unwrap();
    }
    assert!(budget.remaining_work() < MAX_HOST_WORK);
    let renewed = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    assert!(matches!(
        SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &renewed,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job
        ),
        Err(HostError::Forbidden)
    ));
    assert!(matches!(
        SqlHost::new(
            NativePhase::Provider,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            Some(support),
            &budget,
            native_point(&f.job, NativePhase::Provider, f.binding),
            &mut f.job
        ),
        Err(HostError::Forbidden)
    ));
}

#[path = "native_key_tests.rs"]
mod native_key_tests;

#[test]
fn temporal_original_job_is_bound_at_admission_not_the_first_callback() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut replacement = JobControl::new(Duration::from_secs(10), f.cancel.clone()).unwrap();
    let point = native_point(&replacement, NativePhase::ReadlessPlan, f.binding);
    assert!(matches!(
        SqlHost::new(
            NativePhase::ReadlessPlan,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            point,
            &mut replacement
        ),
        Err(HostError::Temporal(TemporalError::WrongOriginalJob))
    ));
    assert!(matches!(
        SqlHost::new(
            NativePhase::ReadlessPlan,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessPlan, f.binding),
            &mut f.job
        ),
        Err(HostError::Temporal(TemporalError::WrongOriginalJob))
    ));
}

#[test]
fn temporal_clock_now_changes_at_exact_accounting_and_native_substitution_refusal() {
    for operation in ["clock", "now"] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        let result = host.call_checked(operation, &[]);
        if operation == "clock" {
            assert_eq!(json_response(result.unwrap()), json!(1000));
        } else {
            assert_eq!(result, Err(HostError::Temporal(TemporalError::Uncertified)));
        }
        assert_eq!(
            host.finish_checked(&outcome(&json!(true))),
            Err(HostError::Temporal(TemporalError::Uncertified))
        );
        assert!(host.finished().is_none());
    }
    for boundary in [
        json!(null),
        json!("1002"),
        json!(1000),
        json!(1000.5),
        json!(9007199254740992u64),
    ] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
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
        assert_eq!(
            host.call_checked("changesAt", &args(&[boundary])),
            Err(HostError::Temporal(TemporalError::InvalidBoundary))
        );
        assert_eq!(
            host.finish_checked(&outcome(&json!(false))),
            Err(HostError::Temporal(TemporalError::InvalidBoundary))
        );
        assert!(host.finished().is_none());
    }
}

#[test]
fn actual_policy_dependency_does_not_certify_arbitrary_guest_clock() {
    let mut f = Fixture::new(
        r#"{"read":{"lt":[{"ref":["now"]},{"value":1002}]},"fields":{"hidden":{"read":{"lt":[{"ref":["now"]},{"value":1001}]}}}}"#,
    );
    let control = FrameControl::new(&f.cancel, f.job.deadline());
    let policies = [CapturedCollection {
        name: "rows",
        policy: Some(f.frame.json(f.policy, &control).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&policies, &[]).unwrap();
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    {
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
        host.call_checked("scan", &scan()).unwrap();
        host.call_checked("clock", &[]).unwrap();
        assert_eq!(
            host.finish_checked(&outcome(&json!(true))),
            Err(HostError::Temporal(TemporalError::Uncertified))
        );
        assert!(host.finished().is_none());
    }
    assert_eq!(admitted.validity(), Validity::Until(1001));
}

#[test]
fn temporal_business_failure_is_uncacheable_and_stops_later_permission_or_result_work() {
    let mut f = Fixture::new("null");
    let relations = [];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let mut denied = vec![wire::FAILURE];
    denied.extend(wire::encode(&json!({"code":"DENIED","message":"denied"})).unwrap());
    {
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
        host.call_checked("clock", &[]).unwrap();
        host.finish_checked_at(&denied, 1001).unwrap();
        assert_eq!(
            host.completion(),
            Some(CallbackCompletion::RejectedUncacheable)
        );
        assert!(matches!(host.finished(), Some(WireOutcome::Failure { .. })));
    }
    assert!(matches!(
        SqlHost::new(
            NativePhase::ReadlessFinalizer,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            native_point(&f.job, NativePhase::ReadlessFinalizer, f.binding),
            &mut f.job
        ),
        Err(HostError::Temporal(TemporalError::AuthorizationDenied))
    ));
    assert_eq!(
        admitted.permission_stamp(&mut f.job, 1001),
        Err(HostError::Temporal(TemporalError::AuthorizationDenied))
    );
}

#[test]
fn temporal_capture_replay_preserves_earliest_expiry_and_requires_same_phase() {
    for replay_phase in [NativePhase::InitialAuth, NativePhase::FreshAuth] {
        let mut f = Fixture::new("null");
        let relations = [OwnedRelation {
            name: "rows",
            coverage: CaptureCoverage::KeysOnly,
            rows: &f.rows,
        }];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        {
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
            host.call_checked("clock", &[]).unwrap();
            host.call_checked("changesAt", &args(&[json!(1002)]))
                .unwrap();
            assert_eq!(
                host.call_checked("get", &get("uncaptured")),
                Err(HostError::NeedCapture(NativeNeedCapture))
            );
        }
        let work = admitted.remaining_work();
        unsafe { admitted.acknowledge_native_capture(&mut f.job) }.unwrap();
        assert_eq!(admitted.remaining_work(), work);
        let point = native_point(&f.job, replay_phase, f.binding);
        let result = SqlHost::new(
            replay_phase,
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            None,
            &budget,
            point,
            &mut f.job,
        );
        if replay_phase != NativePhase::InitialAuth {
            assert!(matches!(
                result,
                Err(HostError::Temporal(TemporalError::ProvenanceMismatch))
            ));
        } else {
            let mut host = result.unwrap();
            host.call_checked("changesAt", &args(&[json!(1010)]))
                .unwrap();
            host.finish_checked(&outcome(&json!(true))).unwrap();
            drop(host);
            let stamp = admitted.permission_stamp(&mut f.job, 1001).unwrap();
            assert_eq!(stamp.validity(), Validity::Until(1002));
            assert_eq!(
                admitted.validate_permission_stamp(&mut f.job, stamp, 1002),
                Err(HostError::Temporal(TemporalError::Expired))
            );
        }
    }
}

#[test]
fn unfinished_callback_drop_never_completes_temporal_permission_or_metadata_only_grant() {
    for completed in [false, true] {
        let mut f = Fixture::new("null");
        let relations = [];
        let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
        let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
        {
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
            host.call_checked("clock", &[]).unwrap();
            if completed {
                host.finish_checked(&outcome(&json!(1000))).unwrap();
                assert_eq!(host.completion(), Some(CallbackCompletion::MetadataOnly));
            }
        }
        assert_eq!(
            admitted.permission_stamp(&mut f.job, 1001),
            Err(HostError::Temporal(if completed {
                TemporalError::NoPermission
            } else {
                TemporalError::CallbackPending
            }))
        );
    }
}

#[cfg(sql_host_harness)]
#[test]
fn post_admission_typed_temporal_and_registered_authority_allocate_zero_rust_heap() {
    let mut f = Fixture::new("null");
    let relations = [OwnedRelation {
        name: "rows",
        coverage: CaptureCoverage::Complete,
        rows: &f.rows,
    }];
    let mut admitted = admission(&f, &relations, MAX_HOST_WORK);
    let budget = PolicyBudget::new(MAX_HOST_WORK).unwrap();
    let changes = args(&[json!(1002)]);
    let result = outcome(&json!(true));
    let point = native_point(&f.job, NativePhase::Authority, f.binding);
    let (result, count, bytes) = crate::allocation_probe::measure(|| -> Result<(), HostError> {
        let mut host = registered_authority_host(
            &mut admitted,
            &f.frame,
            &relations,
            f.binding,
            &budget,
            point,
            &mut f.job,
            f.authority_catalog,
        )?;
        host.call_checked("clock", &[])?;
        host.call_checked("changesAt", &changes)?;
        host.finish_checked(&result)?;
        drop(host);
        let stamp = admitted.permission_stamp(&mut f.job, 1001)?;
        admitted.validate_permission_stamp(&mut f.job, stamp, 1001)?;
        Ok(())
    });
    assert_eq!(result, Ok(()));
    assert_eq!((count, bytes), (0, 0));
    // Typed expired path measured separately; actual anyhow::Error::new and
    // Wasmtime fatal owners remain outside this observer / explicit HOLD.
    let (error, count, bytes) =
        crate::allocation_probe::measure(|| admitted.permission_stamp(&mut f.job, 1002));
    assert_eq!(error, Err(HostError::Temporal(TemporalError::Expired)));
    assert_eq!((count, bytes), (0, 0));
}

#[path = "finish_permission_tests.rs"]
mod finish_permission_tests;
#[path = "native_capture_tests.rs"]
mod native_capture_tests;
