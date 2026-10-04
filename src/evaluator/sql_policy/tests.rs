#![allow(unexpected_cfgs)]
// sql_policy_harness enables external-only allocator and actual-native reference tests.
use super::super::sql_frame::{
    ColumnKind, FrameBuilder, FrameCell, FrameControl, FrameLimits, JsonBank, JsonId,
};
use super::*;
use std::{
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};

fn control() -> &'static FrameControl<'static> {
    static FLAG: AtomicBool = AtomicBool::new(false);
    static CONTROL: std::sync::OnceLock<FrameControl<'static>> = std::sync::OnceLock::new();
    CONTROL.get_or_init(|| FrameControl::new(&FLAG, Instant::now() + Duration::from_secs(86400)))
}
fn job() -> JobControl {
    JobControl::new(Duration::from_secs(10), Arc::new(AtomicBool::new(false))).unwrap()
}
fn limits() -> FrameLimits {
    FrameLimits {
        raw_bytes: 256 * 1024,
        support_bytes: 256 * 1024,
        decoded_bytes: 256 * 1024,
        nodes: 8192,
        documents: 512,
        keys: 128,
        key_bytes: 1024,
        tables: 4,
        columns: 16,
        rows: 128,
        cells: 512,
        text_bytes: 64 * 1024,
        provenance_bytes: 1024,
        parse_work: 8 * 1024 * 1024,
    }
}
fn capture(builder: &mut FrameBuilder, text: &str) -> JsonId {
    let id = builder.reserve_json(JsonBank::Support, text.len()).unwrap();
    for chunk in text.as_bytes().chunks(64 * 1024) {
        builder.append_json_chunk(id, chunk).unwrap();
    }
    builder.finish_json(id, control()).unwrap();
    id
}
fn with_case<T>(
    policy: &str,
    principal: &str,
    row: &str,
    run: impl for<'a> FnOnce(
        PolicyEngine<'a>,
        ArenaValue<'a>,
        &'a [CapturedCollection<'a>],
        &PolicyBudget,
        &mut JobControl,
    ) -> T,
) -> T {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let policy = capture(&mut builder, policy);
    let principal = capture(&mut builder, principal);
    let row = capture(&mut builder, row);
    let collections = [CapturedCollection {
        name: "root",
        policy: Some(builder.json(policy, control()).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let mut job = job();
    let principal = VerifiedPrincipal::from_native_auth(
        builder.json(principal, control()).unwrap(),
        &budget,
        &mut job,
    )
    .unwrap();
    let engine = PolicyEngine::new(support, principal, 100);
    run(
        engine,
        builder.json(row, control()).unwrap(),
        &collections,
        &budget,
        &mut job,
    )
}

#[test]
fn hidden_row_and_field_never_reach_candidate_or_raw_mapped_override() {
    let policy = r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"fields":{"secret":{"read":{"const":false}},"public":{"write":{"const":false}}}}"#;
    with_case(
        policy,
        r#"{"subject":"user","claims":{"role":"admin"}}"#,
        r#"{"owner":"someone","secret":"private","public":7}"#,
        |engine, row, _, budget, job| {
            let result = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap();
            assert!(!result.decision.allowed);
            assert!(result.candidate.is_none());
        },
    );
    with_case(
        policy,
        r#"{"subject":"user"}"#,
        r#"{"owner":"user","secret":"private","public":7}"#,
        |engine, row, _, budget, job| {
            let result = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap();
            let candidate = result.candidate.unwrap();
            assert!(candidate.field("secret", budget, job).unwrap().is_none());
            assert!(matches!(
                candidate
                    .mapped_cell("secret", ColumnKind::Text, budget, job)
                    .unwrap(),
                FrameCell::Null
            ));
            assert!(matches!(
                candidate
                    .mapped_cell("public", ColumnKind::Integer, budget, job)
                    .unwrap(),
                FrameCell::Integer(7)
            ));
            let mut output = [0; 128];
            let length = candidate.encode_json(&mut output, budget, job).unwrap();
            let redacted: serde_json::Value = serde_json::from_slice(&output[..length]).unwrap();
            assert!(redacted.get("secret").is_none());
            assert_eq!(redacted["public"], 7);
            let selected = engine
                .authorize("root", "key", row, &["secret"], budget, job)
                .unwrap();
            assert!(!selected.decision.allowed);
            assert!(selected.candidate.is_none());
        },
    );
}

#[cfg(sql_policy_harness)]
fn differential(policy: &str, principal: &str, row: &str, selecting: &[&str]) {
    let expected = crate::reference::run(
        &serde_json::from_str(policy).unwrap(),
        &serde_json::from_str(principal).unwrap(),
        &serde_json::from_str(row).unwrap(),
        "key",
        selecting,
        100,
        &[],
        &[],
    );
    with_case(policy, principal, row, |engine, row, _, budget, job| {
        let actual = engine
            .authorize("root", "key", row, selecting, budget, job)
            .unwrap();
        assert_eq!(
            actual.decision.allowed, expected.0,
            "native read decision differs"
        );
        if let Some(candidate) = actual.candidate {
            let mut output = [0; 4096];
            let len = candidate.encode_json(&mut output, budget, job).unwrap();
            let redacted: serde_json::Value = serde_json::from_slice(&output[..len]).unwrap();
            assert_eq!(redacted, expected.1, "native redaction differs");
        }
    });
}
#[cfg(sql_policy_harness)]
#[test]
fn differential_actual_native_comparison_numeric_and_deep_value_matrix() {
    let pairs = [
        ("null", "null"),
        ("true", "false"),
        ("false", "0"),
        ("1", "1.0"),
        ("-0", "0"),
        ("9007199254740992", "9007199254740993"),
        ("9223372036854775807", "9223372036854775806"),
        ("18446744073709551615", "18446744073709551614"),
        ("-9223372036854775808", "9223372036854775808"),
        ("18446744073709551615", "18446744073709551616"),
        ("1e-999", "0"),
        ("0.1", "0.1000000000000000055511151231257827"),
        ("1e100", "9e99"),
        ("9007199254740990.5", "9007199254740991"),
        (r#""𐀀""#, r#""\uE000""#),
        (r#""ab\u0000c""#, r#""ab\u0000""#),
        (
            "[null,1,{\"a\":[true,null]}]",
            "[null,1.0,{\"a\":[true,null]}]",
        ),
        ("{\"a\":1,\"b\":2}", "{\"b\":2.0,\"a\":1.0}"),
        ("{\"a\":1,\"b\":2}", "{\"a\":1,\"c\":2}"),
        ("[1,2]", "[2,1]"),
        ("[]", "{}"),
        ("[null]", "[null,null]"),
    ];
    for (left, right) in pairs {
        for op in ["eq", "ne", "lt", "lte", "gt", "gte", "startsWith", "in"] {
            let policy = format!(
                r#"{{"read":{{"{op}":[{{"ref":["row","left"]}},{{"ref":["row","right"]}}]}}}}"#
            );
            let row = format!(r#"{{"left":{left},"right":{right}}}"#);
            differential(&policy, "{}", &row, &[]);
        }
        let policy = r#"{"read":{"in":[{"ref":["row","left"]},{"ref":["row","right"]}]}}"#;
        let row = format!(r#"{{"left":{left},"right":[null,{right}]}}"#);
        differential(policy, "{}", &row, &[]);
    }
}
#[cfg(sql_policy_harness)]
#[test]
fn differential_actual_native_boolean_path_anonymous_field_and_selecting_rules() {
    for rule in [
        r#"{"all":[]}"#,
        r#"{"any":[]}"#,
        r#"{"not":{"const":false}}"#,
        r#"{"all":[{"const":true},{"any":[{"const":false},{"exists":{"ref":["row","value"]}}]}]}"#,
        r#"{"eq":[{"ref":["row","array","+01","value"]},{"value":"ok"}]}"#,
        r#"{"exists":{"ref":["row","absent"]}}"#,
        r#"{"ne":[{"ref":["row","absent"]},{"value":1}]}"#,
        r#"{"eq":[{"ref":["principal","claims","roles","00"]},{"value":"admin"}]}"#,
        r#"{"eq":[{"ref":["key"]},{"value":"key"}]}"#,
        r#"{"exists":{"ref":["principal","subject"]}}"#,
        r#"{"exists":{"ref":["principal","claims"]}}"#,
        r#"{"eq":[{"ref":["principal","tenant"]},{"value":"partition"}]}"#,
    ] {
        let policy = format!(
            r#"{{"read":{rule},"fields":{{"secret":{{"read":{{"const":false}}}},"value":{{"write":{{"const":false}}}}}}}}"#
        );
        for principal in [
            r#"{"subject":"user","tenant":"partition","claims":{"roles":["admin"]}}"#,
            r#"{"subject":"$anonymous","tenant":"partition","claims":{"roles":["admin"]}}"#,
            "null",
            "[]",
        ] {
            for selecting in [&[][..], &["secret"][..], &["value"][..]] {
                differential(
                    &policy,
                    principal,
                    r#"{"value":true,"secret":"hidden","array":[null,{"value":"ok"}]}"#,
                    selecting,
                );
            }
        }
    }
    differential(
        r#"{"read":{"const":true},"fields":{"hidden":{"read":{"const":false}}}}"#,
        "{}",
        r#"{"hidden":"not output","string":"\u0000\n\"\\😀","array":[null,true,1.0,{"a":3}]}"#,
        &[],
    );
}

#[test]
fn guest_row_claims_or_definer_fields_cannot_spoof_verified_principal() {
    let policy = r#"{"read":{"eq":[{"ref":["principal","claims","role"]},{"value":"admin"}]}}"#;
    with_case(
        policy,
        r#"{"subject":"user","claims":{"role":"member"}}"#,
        r#"{"principal":{"claims":{"role":"admin"}},"definer":true,"system":true}"#,
        |engine, row, _, budget, job| {
            assert!(
                !engine
                    .authorize("root", "key", row, &[], budget, job)
                    .unwrap()
                    .decision
                    .allowed
            );
        },
    );
    with_case(
        policy,
        r#"{"subject":"$anonymous","claims":{"role":"admin"}}"#,
        "{}",
        |engine, row, _, budget, job| {
            assert!(
                !engine
                    .authorize("root", "key", row, &[], budget, job)
                    .unwrap()
                    .decision
                    .allowed
            );
        },
    );
}

#[test]
fn malformed_unknown_and_unsupported_paths_fail_closed_even_unreached() {
    for policy in [
        r#"{"unknown":{"const":true},"read":{"const":true}}"#,
        r#"{"read":{"unknown":true}}"#,
        r#"{"read":{"const":1}}"#,
        r#"{"read":{"const":true,"eq":[]}}"#,
        r#"{"read":{"all":[{"const":false},{"unknown":true}]}}"#,
        r#"{"read":{"eq":[{"value":1}]}}"#,
        r#"{"read":{"exists":{"ref":[]}}}"#,
        r#"{"read":{"exists":{"ref":["principal"]}}}"#,
        r#"{"read":{"exists":{"ref":["principal","subject","bad"]}}}"#,
        r#"{"read":{"exists":{"ref":["row",""]}}}"#,
        r#"{"read":{"exists":{"ref":["key","0"]}}}"#,
        r#"{"read":{"exists":{"ref":["next","field"]}}}"#,
        r#"{"read":{"exists":{"value":1,"ref":["now"]}}}"#,
        r#"{"read":{"const":true},"fields":{"bad":{"read":{"unknown":1}}}}"#,
        r#"{"read":{"const":true},"fields":{"bad":{"other":{"const":true}}}}"#,
        r#"{"read":{"const":true},"fields":{"bad":{}}}"#,
        r#"{"read":{"const":true},"fields":{"bad":{"read":null}}}"#,
        r#"{"read":{"const":true},"insert":{"unknown":true}}"#,
        r#"{"read":{"const":true},"fields":{"field":{"write":{"unknown":true}}}}"#,
    ] {
        with_case(policy, "{}", "{}", |engine, row, _, budget, job| {
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::Unsupported)
            ));
            assert_eq!(budget.failure(), Some(PolicyError::Unsupported));
        });
    }
}

#[test]
fn exact_rule_node_and_depth_limits() {
    for (nodes, accepted) in [(256, true), (257, false)] {
        let children = vec![r#"{"const":true}"#; nodes - 1].join(",");
        let policy = format!(r#"{{"read":{{"all":[{children}]}}}}"#);
        with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
            let result = engine.authorize("root", "key", row, &[], budget, job);
            if accepted {
                assert!(result.unwrap().decision.allowed);
            } else {
                assert!(matches!(result, Err(PolicyError::RuleLimit)));
            }
        });
    }
    for (depth, accepted) in [(32, true), (33, false)] {
        let mut rule = r#"{"const":true}"#.to_owned();
        for _ in 1..depth {
            rule = format!(r#"{{"not":{rule}}}"#);
        }
        let policy = format!(r#"{{"read":{rule}}}"#);
        with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
            let result = engine.authorize("root", "key", row, &[], budget, job);
            if accepted {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(PolicyError::RuleLimit)));
            }
        });
    }
}

#[test]
fn caught_work_refusal_is_sticky_and_cumulative_across_rows() {
    assert!(matches!(
        PolicyBudget::new(MAX_POLICY_WORK + 1),
        Err(PolicyError::Capacity)
    ));
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        "{}",
        |engine, row, _, _, job| {
            let budget = PolicyBudget::new(200).unwrap();
            let first = engine
                .authorize("root", "key", row, &[], &budget, job)
                .unwrap();
            assert!(first.decision.allowed);
            let left = budget.remaining_work();
            assert!(left < 200);
            let mut exhausted = false;
            for _ in 0..100 {
                if matches!(
                    engine.authorize("root", "key", row, &[], &budget, job),
                    Err(PolicyError::WorkLimit)
                ) {
                    exhausted = true;
                    break;
                }
            }
            assert!(exhausted);
            assert!(budget.remaining_work() < left);
            assert!(matches!(
                engine.authorize("root", "key", row, &[], &budget, job),
                Err(PolicyError::WorkLimit)
            ));
        },
    );
}

#[test]
fn native_job_cancellation_and_deadline_are_sticky_not_new_per_operation() {
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        "{}",
        |engine, row, _, budget, job| {
            job.cancellation()
                .store(true, std::sync::atomic::Ordering::Release);
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::Cancelled)
            ));
            job.cancellation()
                .store(false, std::sync::atomic::Ordering::Release);
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::Cancelled)
            ));
        },
    );
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        "{}",
        |engine, row, _, budget, _| {
            let mut job =
                JobControl::new(Duration::from_nanos(1), Arc::new(AtomicBool::new(false))).unwrap();
            std::thread::sleep(Duration::from_millis(1));
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, &mut job),
                Err(PolicyError::Deadline)
            ));
            assert_eq!(budget.failure(), Some(PolicyError::Deadline));
        },
    );
}

#[test]
fn readable_distinguishes_uncaptured_authoritative_absent_hidden_and_visible() {
    for mode in 0..4 {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let root = capture(
            &mut builder,
            r#"{"read":{"readable":["target",{"ref":["row","link"]}]}}"#,
        );
        let target = capture(
            &mut builder,
            r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}"#,
        );
        let principal = capture(&mut builder, r#"{"subject":"user"}"#);
        let row = capture(&mut builder, r#"{"link":"key"}"#);
        let target_row = capture(
            &mut builder,
            if mode == 3 {
                r#"{"owner":"user"}"#
            } else {
                r#"{"owner":"other"}"#
            },
        );
        let collections = [
            CapturedCollection {
                name: "root",
                policy: Some(builder.json(root, control()).unwrap()),
            },
            CapturedCollection {
                name: "target",
                policy: Some(builder.json(target, control()).unwrap()),
            },
        ];
        let rows = [CapturedSupportRow {
            collection: "target",
            key: "key",
            row: if mode == 1 {
                None
            } else {
                Some(builder.json(target_row, control()).unwrap())
            },
        }];
        let support =
            CapturedSupport::from_owned_capture(&collections, if mode == 0 { &[] } else { &rows })
                .unwrap();
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let mut job = job();
        let principal = VerifiedPrincipal::from_native_auth(
            builder.json(principal, control()).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, principal, 100);
        let result = engine.authorize(
            "root",
            "key",
            builder.json(row, control()).unwrap(),
            &[],
            &budget,
            &mut job,
        );
        if mode == 0 {
            assert!(matches!(result, Err(PolicyError::NeedCapture)));
            assert_eq!(budget.failure(), Some(PolicyError::NeedCapture));
        } else {
            let allowed = result.unwrap().decision.allowed;
            assert_eq!(allowed, mode == 3);
            #[cfg(sql_policy_harness)]
            {
                let root: serde_json::Value = serde_json::from_str(
                    r#"{"read":{"readable":["target",{"ref":["row","link"]}]}}"#,
                )
                .unwrap();
                let target: serde_json::Value = serde_json::from_str(
                    r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}"#,
                )
                .unwrap();
                let target_row = if mode == 1 {
                    None
                } else {
                    Some(serde_json::json!({"owner":if mode == 3 {"user"} else {"other"}}))
                };
                let native = crate::reference::run(
                    &root,
                    &serde_json::json!({"subject":"user"}),
                    &serde_json::json!({"link":"key"}),
                    "key",
                    &[],
                    100,
                    &[("target".into(), target)],
                    &[("target".into(), "key".into(), target_row)],
                );
                assert_eq!(allowed, native.0);
            }
        }
    }
}
#[test]
fn readable_target_itself_cannot_readable_and_no_policy_or_capture_is_not_authority() {
    for (target, expected) in [
        (
            Some(r#"{"read":{"readable":["target",{"value":"key"}]}}"#),
            PolicyError::Unsupported,
        ),
        (None, PolicyError::Unsupported),
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let root = capture(
            &mut builder,
            r#"{"read":{"readable":["target",{"value":"key"}]}}"#,
        );
        let target = target.map(|text| capture(&mut builder, text));
        let empty = capture(&mut builder, "{}");
        let collections = [
            CapturedCollection {
                name: "root",
                policy: Some(builder.json(root, control()).unwrap()),
            },
            CapturedCollection {
                name: "target",
                policy: target.map(|id| builder.json(id, control()).unwrap()),
            },
        ];
        let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let mut job = job();
        let principal = VerifiedPrincipal::from_native_auth(
            builder.json(empty, control()).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        let result = PolicyEngine::new(support, principal, 100).authorize(
            "root",
            "key",
            builder.json(empty, control()).unwrap(),
            &[],
            &budget,
            &mut job,
        );
        assert!(matches!(result, Err(error) if error == expected));
    }
    with_case(
        r#"{"read":{"readable":["missing",{"value":"key"}]}}"#,
        "{}",
        "{}",
        |engine, row, _, budget, job| {
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::NeedCapture)
            ));
        },
    );
    with_case("{}", "{}", "{}", |engine, row, _, budget, job| {
        assert!(
            !engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap()
                .decision
                .allowed
        );
        let collections = [CapturedCollection {
            name: "open",
            policy: None,
        }];
        let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
        let open = PolicyEngine::new(support, engine.principal, 100);
        assert!(
            open.authorize("open", "key", row, &[], budget, job)
                .unwrap()
                .decision
                .allowed
        );
        assert!(matches!(
            open.authorize("notcaptured", "key", row, &[], budget, job),
            Err(PolicyError::NeedCapture)
        ));
    });
}
#[test]
fn readable_only_accepts_proved_string_key_canonicalization_and_duplicate_support_refuses() {
    for raw_key in ["[1,2]", "{\"a\":1}"] {
        let policy = format!(r#"{{"read":{{"readable":["root",{{"value":{raw_key}}}]}}}}"#);
        // A self-readable read rule is rejected during validation, before key
        // resolution; use a separate guarded nonrecursive target below.
        with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::Unsupported)
            ));
        });
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let root = capture(
            &mut builder,
            &format!(r#"{{"read":{{"readable":["target",{{"value":{raw_key}}}]}}}}"#),
        );
        let target = capture(&mut builder, r#"{"read":{"const":true}}"#);
        let empty = capture(&mut builder, "{}");
        let collections = [
            CapturedCollection {
                name: "root",
                policy: Some(builder.json(root, control()).unwrap()),
            },
            CapturedCollection {
                name: "target",
                policy: Some(builder.json(target, control()).unwrap()),
            },
        ];
        let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let mut job = job();
        let principal = VerifiedPrincipal::from_native_auth(
            builder.json(empty, control()).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        assert!(matches!(
            PolicyEngine::new(support, principal, 100).authorize(
                "root",
                "key",
                builder.json(empty, control()).unwrap(),
                &[],
                &budget,
                &mut job
            ),
            Err(PolicyError::Unsupported)
        ));
    }
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        "{}",
        |engine, row, collections, budget, job| {
            let duplicates = [collections[0], collections[0]];
            let support = CapturedSupport::from_owned_capture(&duplicates, &[]).unwrap();
            assert!(matches!(
                PolicyEngine::new(support, engine.principal, 100).authorize(
                    "root",
                    "key",
                    row,
                    &[],
                    budget,
                    job
                ),
                Err(PolicyError::Unsupported)
            ));
        },
    );
}

#[cfg(sql_policy_harness)]
#[test]
fn exact_scalar_clock_flip_boundaries_match_native_decisions_without_a_write() {
    for value in [99.0, 100.0, 101.0, 101.5, 102.0, 102.5, -1.0] {
        for op in ["eq", "ne", "lt", "lte", "gt", "gte"] {
            for reverse in [false, true] {
                let (left, right) = if reverse {
                    (
                        format!(r#"{{"value":{value}}}"#),
                        r#"{"ref":["now"]}"#.to_owned(),
                    )
                } else {
                    (
                        r#"{"ref":["now"]}"#.to_owned(),
                        format!(r#"{{"value":{value}}}"#),
                    )
                };
                let policy = format!(r#"{{"read":{{"{op}":[{left},{right}]}}}}"#);
                let parsed: serde_json::Value = serde_json::from_str(&policy).unwrap();
                with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
                    let result = engine
                        .authorize("root", "key", row, &[], budget, job)
                        .unwrap();
                    let native = |now| {
                        crate::reference::run(
                            &parsed,
                            &serde_json::json!({}),
                            &serde_json::json!({}),
                            "key",
                            &[],
                            now,
                            &[],
                            &[],
                        )
                        .0
                    };
                    assert_eq!(result.decision.allowed, native(100));
                    let future = (101..110).find(|now| native(*now) != native(100));
                    assert_eq!(
                        result.decision.validity,
                        future.map_or(Validity::ClockInvariant, Validity::Until)
                    );
                    if let Some(at) = future {
                        assert!(result.decision.validity.permits(at - 1));
                        assert!(!result.decision.validity.permits(at));
                        let changed = PolicyEngine::new(engine.support, engine.principal, at)
                            .authorize("root", "key", row, &[], budget, job)
                            .unwrap();
                        assert_ne!(result.decision.allowed, changed.decision.allowed);
                    }
                });
            }
        }
    }
}
#[test]
fn field_time_boundary_is_carried_before_projection_and_unknown_temporal_refuses() {
    with_case(
        r#"{"read":{"const":true},"fields":{"timed":{"read":{"gte":[{"ref":["now"]},{"value":102}]}}}}"#,
        "{}",
        r#"{"timed":"value"}"#,
        |engine, row, _, budget, job| {
            let result = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap();
            assert_eq!(result.decision.validity, Validity::Until(102));
            let candidate = result.candidate.unwrap();
            assert!(candidate.field("timed", budget, job).unwrap().is_none());
            assert_eq!(candidate.validity(), Validity::Until(102));
            let later = PolicyEngine::new(engine.support, engine.principal, 102)
                .authorize("root", "key", row, &[], budget, job)
                .unwrap()
                .candidate
                .unwrap();
            assert!(later.field("timed", budget, job).unwrap().is_some());
        },
    );
    for policy in [
        r#"{"read":{"all":[{"lt":[{"ref":["now"]},{"value":102}]}]}}"#,
        r#"{"read":{"not":{"lt":[{"ref":["now"]},{"value":102}]}}}"#,
        r#"{"read":{"in":[{"ref":["now"]},{"value":[102]}]}}"#,
        r#"{"read":{"lt":[{"ref":["now"]},{"value":1e100}]}}"#,
        r#"{"read":{"startsWith":[{"ref":["now"]},{"value":"x"}]}}"#,
    ] {
        with_case(policy, "{}", "{}", |engine, row, _, budget, job| {
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::UncertifiedTemporal)
            ));
        });
    }
}

#[test]
fn oversized_path_scalar_coercions_and_fixed_output_fail_closed() {
    with_case(
        r#"{"read":{"exists":{"ref":["row","items","000000000000000000000000000000"]}}}"#,
        "{}",
        r#"{"items":[true]}"#,
        |engine, row, _, budget, job| {
            assert!(matches!(
                engine.authorize("root", "key", row, &[], budget, job),
                Err(PolicyError::Unsupported)
            ));
        },
    );
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        r#"{"v":"9007199254740993","huge":9223372036854775807}"#,
        |engine, row, _, budget, job| {
            let candidate = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap()
                .candidate
                .unwrap();
            assert!(matches!(
                candidate
                    .mapped_cell("v", ColumnKind::Text, budget, job)
                    .unwrap(),
                FrameCell::Text(_)
            ));
            assert!(matches!(
                candidate.mapped_cell("huge", ColumnKind::Integer, budget, job),
                Err(PolicyError::Unsupported)
            ));
        },
    );
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        r#"{"value":"text"}"#,
        |engine, row, _, budget, job| {
            let candidate = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap()
                .candidate
                .unwrap();
            assert_eq!(
                candidate.encode_json(&mut [0; 1], budget, job),
                Err(PolicyError::Capacity)
            );
            assert_eq!(
                candidate.encode_json(&mut [0; 128], budget, job),
                Err(PolicyError::Capacity)
            );
        },
    );
}

#[test]
fn native_policy_precedes_real_sqlite_aggregate_hidden_fields_stay_null() {
    use super::super::sql_frame::FrameColumn;
    use super::super::sqlite::{self, QueryOptions, SqlCell};
    let mut capture_frame = FrameBuilder::new(limits(), control()).unwrap();
    let policy = capture(
        &mut capture_frame,
        r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"fields":{"secret":{"read":{"const":false}}}}"#,
    );
    let principal = capture(&mut capture_frame, r#"{"subject":"user"}"#);
    let rows = capture(
        &mut capture_frame,
        r#"[{"owner":"user","amount":3,"secret":7},{"owner":"other","amount":1000,"secret":900},{"owner":"user","amount":4,"secret":8}]"#,
    );
    let collections = [CapturedCollection {
        name: "root",
        policy: Some(capture_frame.json(policy, control()).unwrap()),
    }];
    let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let mut job = job();
    let principal = VerifiedPrincipal::from_native_auth(
        capture_frame.json(principal, control()).unwrap(),
        &budget,
        &mut job,
    )
    .unwrap();
    let engine = PolicyEngine::new(support, principal, 100);
    let mut typed_frame = FrameBuilder::new(limits(), control()).unwrap();
    let columns = ["amount", "secret"].map(|name| FrameColumn {
        name,
        kind: ColumnKind::Integer,
        nullable: true,
        logical_type: None,
        unit: None,
        equality: false,
    });
    let table = typed_frame.add_table("visible", &columns).unwrap();
    let array = capture_frame.json(rows, control()).unwrap();
    for entry in array.children() {
        let row = entry.unwrap().value;
        let read = engine
            .authorize("root", "key", row, &[], &budget, &mut job)
            .unwrap();
        if let Some(candidate) = read.candidate {
            let cells = [
                candidate
                    .mapped_cell("amount", ColumnKind::Integer, &budget, &mut job)
                    .unwrap(),
                candidate
                    .mapped_cell("secret", ColumnKind::Integer, &budget, &mut job)
                    .unwrap(),
            ];
            typed_frame.insert_row(table, &cells, control()).unwrap();
        }
    }
    drop(capture_frame); // no raw/policy/support capability enters SQLite
    let mut sealed = typed_frame.seal(control()).unwrap();
    let tables = sealed.native_tables(1024 * 1024).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*),SUM(amount),COUNT(secret),SUM(secret) FROM visible",
        &[],
        &tables,
        &mut sealed,
        QueryOptions {
            batch_rows: 1,
            max_rows: 1,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![
            SqlCell::Integer(2),
            SqlCell::Integer(7),
            SqlCell::Integer(0),
            SqlCell::Null
        ]]
    );
}

#[test]
fn large_redaction_checks_cancellation_and_deadline_inside_operation() {
    let row = format!(r#"{{"text":"{}"}}"#, "x".repeat(180_000));
    for cancel in [false, true] {
        let mut output = vec![0; 200_000];
        with_case(
            r#"{"read":{"const":true}}"#,
            "{}",
            &row,
            |engine, row, _, budget, initial_job| {
                let candidate = engine
                    .authorize("root", "key", row, &[], budget, initial_job)
                    .unwrap()
                    .candidate
                    .unwrap();
                let flag = Arc::new(AtomicBool::new(false));
                let mut job = JobControl::new(
                    if cancel {
                        Duration::from_secs(10)
                    } else {
                        Duration::from_millis(1)
                    },
                    flag.clone(),
                )
                .unwrap();
                if cancel {
                    std::thread::scope(|scope| {
                        scope.spawn(|| {
                            std::thread::sleep(Duration::from_millis(1));
                            flag.store(true, std::sync::atomic::Ordering::Release);
                        });
                        assert_eq!(
                            candidate.encode_json(&mut output, budget, &mut job),
                            Err(PolicyError::Cancelled)
                        );
                    });
                    flag.store(false, std::sync::atomic::Ordering::Release);
                    assert_eq!(
                        candidate.encode_json(&mut output, budget, &mut job),
                        Err(PolicyError::Cancelled)
                    );
                } else {
                    assert_eq!(
                        candidate.encode_json(&mut output, budget, &mut job),
                        Err(PolicyError::Deadline)
                    );
                }
            },
        );
    }
}

#[cfg(sql_policy_harness)]
#[test]
fn post_admission_policy_validation_support_compare_projection_and_redaction_allocate_zero() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let root = capture(
        &mut builder,
        r#"{"read":{"all":[{"exists":{"ref":["principal","subject"]}},{"eq":[{"ref":["row","array"]},{"value":[null,1.0,{"a":1.25}]}]},{"readable":["target",{"ref":["row","link"]}]}]},"fields":{"secret":{"read":{"const":false}},"float":{"read":{"gte":[{"ref":["now"]},{"value":101}]}}}}"#,
    );
    let target = capture(
        &mut builder,
        r#"{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}"#,
    );
    let principal = capture(&mut builder, r#"{"subject":"user"}"#);
    let row = capture(
        &mut builder,
        r#"{"link":"key","array":[null,1,{"a":1.25}],"secret":"not emitted","float":1.25,"integer":7,"text":"\u0000\n😀"}"#,
    );
    let target_row = capture(&mut builder, r#"{"owner":"user"}"#);
    let collections = [
        CapturedCollection {
            name: "root",
            policy: Some(builder.json(root, control()).unwrap()),
        },
        CapturedCollection {
            name: "target",
            policy: Some(builder.json(target, control()).unwrap()),
        },
    ];
    let rows = [CapturedSupportRow {
        collection: "target",
        key: "key",
        row: Some(builder.json(target_row, control()).unwrap()),
    }];
    let mut job = job();
    let mut output = [0; 2048];
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let (result, allocations, bytes) =
        crate::allocation_probe::measure(|| -> Result<_, PolicyError> {
            let support = CapturedSupport::from_owned_capture(&collections, &rows)?;
            let principal = VerifiedPrincipal::from_native_auth(
                builder.json(principal, control())?,
                &budget,
                &mut job,
            )?;
            let engine = PolicyEngine::new(support, principal, 100);
            let auth = engine.authorize(
                "root",
                "key",
                builder.json(row, control())?,
                &[],
                &budget,
                &mut job,
            )?;
            let candidate = auth.candidate.ok_or(PolicyError::Unsupported)?;
            let integer =
                candidate.mapped_cell("integer", ColumnKind::Integer, &budget, &mut job)?;
            let text = candidate.mapped_cell("text", ColumnKind::Text, &budget, &mut job)?;
            let hidden = candidate.mapped_cell("secret", ColumnKind::Text, &budget, &mut job)?;
            let timed = candidate.mapped_cell("float", ColumnKind::Real, &budget, &mut job)?;
            let length = candidate.encode_json(&mut output, &budget, &mut job)?;
            Ok((auth.decision, length, integer, text, hidden, timed))
        });
    assert_eq!((allocations, bytes), (0, 0));
    let (decision, _, integer, text, hidden, timed) = result.unwrap();
    assert_eq!(decision.validity, Validity::Until(101));
    assert!(matches!(integer, FrameCell::Integer(7)));
    assert!(matches!(text, FrameCell::Text(_)));
    assert!(matches!(
        (hidden, timed),
        (FrameCell::Null, FrameCell::Null)
    ));
}
#[cfg(sql_policy_harness)]
#[test]
fn post_admission_temporal_numeric_and_error_paths_allocate_zero() {
    for policy in [
        r#"{"read":{"lt":[{"ref":["now"]},{"value":102.5}]}}"#,
        r#"{"read":{"eq":[{"value":0.1000000000000000055511151231257827},{"value":0.1}]}}"#,
        r#"{"read":{"eq":[{"value":18446744073709551615},{"value":18446744073709551614}]}}"#,
        r#"{"read":{"eq":[{"value":1e-999},{"value":0}]}}"#,
        r#"{"read":{"lt":[{"ref":["now"]},{"value":1e100}]}}"#,
        r#"{"read":{"exists":{"ref":["key","0"]}}}"#,
        r#"{"read":{"readable":["missing",{"value":"key"}]}}"#,
    ] {
        with_case(policy, "{}", "{}", |engine, row, _, budget, job| {
            let (_, allocations, bytes) = crate::allocation_probe::measure(|| {
                engine.authorize("root", "key", row, &[], budget, job)
            });
            assert_eq!((allocations, bytes), (0, 0));
        });
    }
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        r#"{"value":"text"}"#,
        |engine, row, _, budget, job| {
            let candidate = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap()
                .candidate
                .unwrap();
            let (result, allocations, bytes) = crate::allocation_probe::measure(|| {
                candidate.encode_json(&mut [0; 1], budget, job)
            });
            assert_eq!(result, Err(PolicyError::Capacity));
            assert_eq!((allocations, bytes), (0, 0));
        },
    );
}

#[test]
fn finish_blocks_caught_failures_and_hidden_row_time_flips_without_writes() {
    with_case(
        r#"{"read":{"gte":[{"ref":["now"]},{"value":102}]}}"#,
        "{}",
        "{}",
        |engine, row, _, budget, job| {
            let auth = engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap();
            assert!(!auth.decision.allowed);
            assert!(auth.candidate.is_none());
            assert_eq!(budget.finish(job, 101), Ok(Validity::Until(102)));
            assert_eq!(
                budget.finish(job, 102),
                Err(PolicyError::UncertifiedTemporal)
            );
            assert_eq!(
                budget.finish(job, 101),
                Err(PolicyError::UncertifiedTemporal)
            );
        },
    );
    with_case(
        r#"{"read":{"lt":[{"ref":["now"]},{"value":102}]}}"#,
        "{}",
        "{}",
        |engine, row, _, budget, job| {
            engine
                .authorize("root", "key", row, &[], budget, job)
                .unwrap();
            assert_eq!(
                budget.finish(job, 99),
                Err(PolicyError::UncertifiedTemporal)
            );
        },
    );
    with_case(
        r#"{"read":{"const":true}}"#,
        "{}",
        "{}",
        |engine, row, _, _, job| {
            let budget = PolicyBudget::new(1).unwrap();
            assert!(
                engine
                    .authorize("root", "key", row, &[], &budget, job)
                    .is_err()
            );
            assert_eq!(budget.finish(job, 100), Err(PolicyError::WorkLimit));
        },
    );
}
#[cfg(sql_policy_harness)]
#[test]
fn unproved_native_number_error_domain_refuses_without_allocating_boxed_serde_errors() {
    for value in [
        "1.7976931348623157e308",
        "1.7976931348623158e308",
        "1e301",
        "0e0000000001",
        "0e9999999999",
        "1e-9999999999",
    ] {
        let policy = format!(r#"{{"read":{{"eq":[{{"value":{value}}},{{"value":0}}]}}}}"#);
        with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
            let (result, allocations, bytes) = crate::allocation_probe::measure(|| {
                engine.authorize("root", "key", row, &[], budget, job)
            });
            assert!(matches!(result, Err(PolicyError::Unsupported)));
            assert_eq!((allocations, bytes), (0, 0));
        });
    }
    for value in ["1e300", "1e-300", "0e999999999", "1e-999999999"] {
        let policy = format!(r#"{{"read":{{"eq":[{{"value":{value}}},{{"value":0}}]}}}}"#);
        with_case(&policy, "{}", "{}", |engine, row, _, budget, job| {
            let (result, allocations, bytes) = crate::allocation_probe::measure(|| {
                engine.authorize("root", "key", row, &[], budget, job)
            });
            assert!(result.is_ok());
            assert_eq!((allocations, bytes), (0, 0));
        });
    }
}

#[test]
fn empty_open_reads_and_redaction_still_obey_borrowed_frame_control() {
    for operation in 0..4 {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let empty = capture(&mut builder, "{}");
        let flag = AtomicBool::new(false);
        let frame_control = FrameControl::new(&flag, Instant::now() + Duration::from_secs(10));
        let row = builder.json(empty, &frame_control).unwrap();
        let collections = [CapturedCollection {
            name: "open",
            policy: None,
        }];
        let support = CapturedSupport::from_owned_capture(&collections, &[]).unwrap();
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let mut job = job();
        let principal = VerifiedPrincipal::from_native_auth(row, &budget, &mut job).unwrap();
        let engine = PolicyEngine::new(support, principal, 100);
        let candidate = engine
            .authorize("open", "key", row, &[], &budget, &mut job)
            .unwrap()
            .candidate
            .unwrap();
        flag.store(true, std::sync::atomic::Ordering::Release);
        let refused = match operation {
            0 => matches!(
                engine.authorize("open", "key", row, &[], &budget, &mut job),
                Err(PolicyError::Cancelled)
            ),
            1 => matches!(
                candidate.field_visible("missing", &budget, &mut job),
                Err(PolicyError::Cancelled)
            ),
            2 => matches!(
                candidate.mapped_cell("missing", ColumnKind::Text, &budget, &mut job),
                Err(PolicyError::Cancelled)
            ),
            _ => {
                candidate.encode_json(&mut [0; 16], &budget, &mut job)
                    == Err(PolicyError::Cancelled)
            }
        };
        assert!(refused);
        assert_eq!(budget.finish(&mut job, 100), Err(PolicyError::Cancelled));
    }
}

// Other owners' existing native-reference harnesses lack the new physical
// helper extraction; keep this extension confined to its own updated harness.
#[cfg(all(sql_policy_harness, sql_policy_typed_harness))]
#[path = "typed_tests.rs"]
mod typed_tests;
