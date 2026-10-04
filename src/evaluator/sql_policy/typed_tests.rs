//! Frozen actual ACLs plus unmodified-current-native reference differential tests.
//! Owned serde/Vec/String fixture/reference work is OUTSIDE allocator probes.
use super::*;
use serde_json::{Value, json};
use std::sync::atomic::Ordering as AtomicOrdering;

const MANIFEST: &str = include_str!("typed_manifest.json");
const ALICE: &str = r#"{"subject":"alice","claims":{"role":"user","org":"acme"}}"#;
#[derive(Clone, Copy)]
struct Prepared {
    declaration: JsonId,
    pair: JsonId,
    key: super::super::super::sql_frame::KeyId,
    decoded: Option<JsonId>,
    row: Option<JsonId>,
}
fn put(frame: &mut FrameBuilder, text: &str, control: &FrameControl<'_>) -> JsonId {
    let id = frame.reserve_json(JsonBank::Support, text.len()).unwrap();
    for chunk in text.as_bytes().chunks(64 * 1024) {
        frame.append_json_chunk(id, chunk).unwrap();
    }
    frame.finish_json(id, control).unwrap();
    id
}
fn prepare(
    frame: &mut FrameBuilder,
    name: &str,
    encoded: &str,
    decoded: Option<&str>,
    row: Option<&str>,
    control: &FrameControl<'_>,
) -> Prepared {
    let declaration = put(
        frame,
        &json!({"name":name,"jsonKey":decoded.is_some()}).to_string(),
        control,
    );
    let physical = crate::reference::source_id(name, encoded);
    assert_eq!(
        crate::reference::source_pair(&physical).unwrap(),
        (name.to_owned(), encoded.to_owned())
    );
    let pair = put(frame, physical.strip_prefix("source:").unwrap(), control);
    let key = frame.retain_key(encoded).unwrap();
    let decoded = decoded.map(|text| put(frame, text, control));
    let row = row.map(|text| put(frame, text, control));
    Prepared {
        declaration,
        pair,
        key,
        decoded,
        row,
    }
}
fn bind<'a>(
    frame: &'a FrameBuilder,
    prepared: Prepared,
    control: &'a FrameControl<'a>,
    budget: &PolicyBudget,
    job: &mut JobControl,
) -> Result<NativeKeyRow<'a>, PolicyError> {
    NativeKeyRow::bind_owned_native_capture(
        frame,
        prepared.declaration,
        prepared.pair,
        prepared.key,
        prepared.decoded,
        prepared.row,
        control,
        budget,
        job,
    )
}
fn collect_targets(value: &Value, names: &mut std::collections::BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if key == "readable" {
                    names.insert(value[0].as_str().unwrap().to_owned());
                } else if key != "value" {
                    collect_targets(value, names);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_targets(item, names);
            }
        }
        _ => {}
    }
}
fn key_parts(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            key == "ref" && value[0] == "key" && value.as_array().unwrap().len() > 1
                || key != "value" && key_parts(value)
        }),
        Value::Array(items) => items.iter().any(key_parts),
        _ => false,
    }
}
fn actual_policy(name: &str) -> Value {
    serde_json::from_str::<Value>(MANIFEST)
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == name)
        .unwrap()["access"]
        .clone()
}

/// One same-frame native pipeline with exact captured support/absence. Returns
/// actual native and borrowed-policy decisions/redactions. No mock classifier.
#[allow(clippy::too_many_arguments)]
fn differential(
    name: &str,
    policy: &Value,
    principal: &Value,
    encoded: &str,
    decoded: Option<&str>,
    row: &Value,
    targets: &[(String, Value)],
    rows: &[(String, String, Option<Value>)],
    selecting: &[&str],
) -> (bool, Value) {
    let expected = crate::reference::run(
        policy, principal, row, encoded, selecting, 100, targets, rows,
    );
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    // Explicit smaller quota for these bounded individual ACL fixtures. No
    // production limit/default changes or secondary owner are introduced.
    let mut shape = limits();
    shape.raw_bytes = 64 * 1024;
    shape.support_bytes = 64 * 1024;
    shape.decoded_bytes = 64 * 1024;
    shape.nodes = 4096;
    shape.documents = 64;
    shape.keys = 32;
    shape.key_bytes = 2048;
    shape.rows = 8;
    shape.cells = 32;
    shape.text_bytes = 1024;
    let mut frame = FrameBuilder::new(shape, &control).unwrap();
    let policy_id = put(&mut frame, &policy.to_string(), &control);
    let principal_id = put(&mut frame, &principal.to_string(), &control);
    let ids: Vec<_> = targets
        .iter()
        .map(|(_, policy)| put(&mut frame, &policy.to_string(), &control))
        .collect();
    let root = prepare(
        &mut frame,
        name,
        encoded,
        decoded,
        Some(&row.to_string()),
        &control,
    );
    let prepared: Vec<_> = rows
        .iter()
        .map(|(collection, key, row)| {
            let parsed: Option<Value> = serde_json::from_str::<Value>(key)
                .ok()
                .filter(|v| v.is_array() || v.is_object());
            let decoded = parsed.as_ref().map(|_| key.as_str());
            prepare(
                &mut frame,
                collection,
                key,
                decoded,
                row.as_ref().map(Value::to_string).as_deref(),
                &control,
            )
        })
        .collect();
    let mut collections = vec![CapturedCollection {
        name,
        policy: Some(frame.json(policy_id, &control).unwrap()),
    }];
    collections.extend(
        targets
            .iter()
            .zip(ids)
            .map(|((name, _), id)| CapturedCollection {
                name,
                policy: Some(frame.json(id, &control).unwrap()),
            }),
    );
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let root = bind(&frame, root, &control, &budget, &mut job).unwrap();
    let bound: Vec<_> = prepared
        .into_iter()
        .map(|prepared| bind(&frame, prepared, &control, &budget, &mut job).unwrap())
        .collect();
    let support =
        CapturedSupport::from_owned_native_capture(&collections, &bound, &budget, &mut job)
            .unwrap();
    let principal = VerifiedPrincipal::from_native_auth(
        frame.json(principal_id, &control).unwrap(),
        &budget,
        &mut job,
    )
    .unwrap();
    let engine = PolicyEngine::new(support, principal, 100);
    let actual = engine
        .authorize_native(root, selecting, &budget, &mut job)
        .unwrap_or_else(|error| panic!("policy {name}: {error:?}"));
    assert_eq!(
        actual.decision.allowed, expected.0,
        "native decision {name}"
    );
    let mut redacted = Value::Null;
    if let Some(candidate) = actual.candidate {
        let mut bytes = [0; 8192];
        let n = candidate
            .encode_json(&mut bytes, &budget, &mut job)
            .unwrap();
        redacted = serde_json::from_slice(&bytes[..n]).unwrap();
        assert_eq!(redacted, expected.1, "native redaction {name}");
    }
    assert_eq!(budget.finish(&mut job, 100).unwrap(), Validity::Independent);
    (actual.decision.allowed, redacted)
}

#[test]
fn native_key_part_whole_key_and_missing_semantics_match_actual_access() {
    let keys = [
        ("opaque", false, false),
        (
            "[\"acme\",\"alice\",null,9007199254740993,-0,1e-999,{\"nested\":[true,\"é\"]}]",
            false,
            true,
        ),
        ("{\"0\":\"acme\",\"object\":{\"k\":[null,7]}}", false, true),
        ("null", true, true),
        ("true", true, true),
        ("7", true, true),
        ("\"alice\"", true, true),
        (" \n[ 1, { \"a\": 2 } ] \t", false, true),
    ];
    let paths = [
        vec!["key"],
        vec!["key", "0"],
        vec!["key", "+00000000000000000000000000000000000000000001"],
        vec!["key", "2"],
        vec!["key", "3"],
        vec!["key", "4"],
        vec!["key", "5"],
        vec!["key", "6", "nested", "1"],
        vec!["key", "object", "k", "0"],
        vec!["key", "absent"],
        vec!["key", "18446744073709551616"],
        vec!["key", "-0"],
    ];
    let literals = [
        json!("acme"),
        json!("alice"),
        json!(null),
        json!(true),
        json!(0),
        json!(9007199254740992u64),
        json!(9007199254740993u64),
        json!([null, 7]),
        json!({"k":[null,7]}),
    ];
    for (encoded, json_key, decoded) in keys {
        let mut rules = Vec::new();
        for path in &paths {
            for literal in &literals {
                for op in ["eq", "ne", "lt", "lte", "gt", "gte", "startsWith", "in"] {
                    rules.push(json!({op:[{"ref":path},{"value":literal}]}));
                }
            }
            rules.push(json!({"exists":{"ref":path}}));
        }
        // Batch independent comparison rules as actual field-read predicates.
        // One finite admitted frame per128 rules, not thousands of re-mappings.
        // Each predicate is compared to actual Access::redact, never a boolean
        // permission fixture or an enabled SQL positive endpoint.
        for rules in rules.chunks(128) {
            key_part_batch(encoded, json_key, decoded, rules);
        }
    }
}
fn key_part_batch(encoded: &str, json_key: bool, decoded: bool, rules: &[Value]) {
    let mut fields = serde_json::Map::new();
    let mut values = serde_json::Map::new();
    for (index, rule) in rules.iter().enumerate() {
        let name = format!("f{index}");
        fields.insert(name.clone(), json!({"read":rule}));
        values.insert(name, json!(1));
    }
    let policy = json!({"read":{"const":true},"fields":fields});
    let row = Value::Object(values);
    let principal = json!({});
    let expected = crate::reference::run(&policy, &principal, &row, encoded, &[], 100, &[], &[]).1;
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    let mut frame = FrameBuilder::new(limits(), &control).unwrap();
    let policy_id = put(&mut frame, &policy.to_string(), &control);
    let principal_id = put(&mut frame, "{}", &control);
    let mut prepared = prepare(
        &mut frame,
        "root",
        encoded,
        decoded.then_some(encoded),
        Some(&row.to_string()),
        &control,
    );
    prepared.declaration = put(
        &mut frame,
        &json!({"name":"root","jsonKey":json_key}).to_string(),
        &control,
    );
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let root = bind(&frame, prepared, &control, &budget, &mut job).unwrap();
    assert_eq!(root.encoded_key(), encoded);
    if !json_key {
        assert!(matches!(root.logical_key(),NativeDecodedKey::String(key) if key==encoded));
    }
    let collections = [CapturedCollection {
        name: "root",
        policy: Some(frame.json(policy_id, &control).unwrap()),
    }];
    let support =
        CapturedSupport::from_owned_native_capture(&collections, &[], &budget, &mut job).unwrap();
    let verified = VerifiedPrincipal::from_native_auth(
        frame.json(principal_id, &control).unwrap(),
        &budget,
        &mut job,
    )
    .unwrap();
    let engine = PolicyEngine::new(support, verified, 100);
    let candidate = engine
        .authorize_native(root, &[], &budget, &mut job)
        .unwrap()
        .candidate
        .unwrap();
    for index in 0..rules.len() {
        let name = format!("f{index}");
        assert_eq!(
            candidate
                .field_visible(&name, &budget, &mut job)
                .unwrap()
                .allowed,
            expected.get(&name).is_some(),
            "actual native key-part comparison"
        );
    }
    let mut output = [0; 4096];
    let n = candidate
        .encode_json(&mut output, &budget, &mut job)
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&output[..n]).unwrap(),
        expected
    );
    budget.finish(&mut job, 100).unwrap();
}

#[test]
fn canonical_composite_readable_matches_actual_utf16_and_number_identity() {
    let values = [
        json!(["acme", "alice"]),
        json!({"z":null,"a":[7,true,"q\n\"\\"]}),
        json!({"\u{e000}":1,"\u{10000}":2,"10":3,"2":4}),
        json!([9007199254740993u64, 1e-7, 1e21, -0.0]),
        json!([]),
        json!({}),
    ];
    for value in values {
        let encoded = crate::reference::canonical_json(&value);
        for (exists, visible) in [(true, true), (true, false), (false, false)] {
            let policy = json!({"read":{"readable":["members",{"value":value}]}});
            let target = json!({"read":{"eq":[{"ref":["row","shown"]},{"value":true}]}});
            let rows = [(
                "members".to_owned(),
                encoded.clone(),
                exists.then_some(json!({"shown":visible})),
            )];
            let actual = differential(
                "root",
                &policy,
                &json!({}),
                "root-key",
                None,
                &json!({}),
                &[("members".to_owned(), target)],
                &rows,
                &[],
            );
            assert_eq!(actual.0, visible);
        }
    }
    // The target's own key-part ACL must resolve from its ENCODED identity, not
    // the original operand's rounded or differently ordered object tokens.
    let policy = json!({"read":{"readable":["members",{"value":["acme","alice"]}]}});
    let target = json!({"read":{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}});
    for subject in ["alice", "bob"] {
        assert_eq!(
            differential(
                "root",
                &policy,
                &json!({"subject":subject}),
                "root-key",
                None,
                &json!({}),
                &[("members".to_owned(), target.clone())],
                &[(
                    "members".to_owned(),
                    r#"["acme","alice"]"#.to_owned(),
                    Some(json!({}))
                )],
                &[]
            )
            .0,
            subject == "alice"
        );
    }
}

#[test]
fn frozen_all_189_policies_native_typed_matrix_is_supported_not_allowlisted() {
    let manifest: Value = serde_json::from_str(MANIFEST).unwrap();
    let entries = manifest.as_array().unwrap();
    assert_eq!(entries.len(), 189);
    let mut previously_typed = 0;
    let mut total = 0;
    // Human, hidden human, computer, process, anonymous are native principals,
    // not an "allowed" flag. Plain and typed root keys each exercise every AST.
    for entry in entries {
        let name = entry["name"].as_str().unwrap();
        let policy = &entry["access"];
        let mut names = std::collections::BTreeSet::new();
        collect_targets(policy, &mut names);
        let targets: Vec<_> = names
            .iter()
            .map(|name| {
                (
                    name.clone(),
                    entries.iter().find(|entry| entry["name"] == *name).unwrap()["access"].clone(),
                )
            })
            .collect();
        previously_typed += usize::from(
            key_parts(policy) || targets.iter().any(|(_, policy)| key_parts(&policy["read"])),
        );
        let rows: Vec<_> = names
            .iter()
            .flat_map(|name| {
                ["alice", "bob", "acme", "k", "s", r#"["acme","alice"]"#]
                    .map(|key| (name.clone(), key.to_owned(), None))
            })
            .collect();
        for principal in [
            serde_json::from_str(ALICE).unwrap(),
            json!({"subject":"bob","claims":{"role":"user","org":"other"}}),
            json!({"subject":"alice","claims":{"role":"computer","org":"acme"}}),
            json!({"subject":"worker","claims":{"role":"service"}}),
            json!({"subject":"$anonymous"}),
        ] {
            for (encoded, decoded) in [
                ("k", None),
                (r#"["acme","alice"]"#, Some(r#"["acme","alice"]"#)),
            ] {
                differential(
                    name,
                    policy,
                    &principal,
                    encoded,
                    decoded,
                    &json!({}),
                    &targets,
                    &rows,
                    &[],
                );
            }
        }
        total += 1;
    }
    assert_eq!((total, previously_typed), (189, 89));
}

#[test]
fn actual_members_scopes_roles_labels_reports_jobs_grants_fences_integrations_and_oversight() {
    let principal: Value = serde_json::from_str(ALICE).unwrap();
    let cases = [
        (
            "members",
            r#"["acme","alice"]"#,
            Some(r#"["acme","alice"]"#),
            json!({"org":"acme","subject":"alice","amount":3}),
            r#"["other","bob"]"#,
            Some(r#"["other","bob"]"#),
            json!({"org":"other","subject":"bob","amount":1000}),
        ),
        (
            "scopes",
            r#"["acme","scope"]"#,
            Some(r#"["acme","scope"]"#),
            json!({"org":"acme","amount":4}),
            r#"["other","scope"]"#,
            Some(r#"["other","scope"]"#),
            json!({"org":"other","amount":1000}),
        ),
        (
            "usage",
            r#"["acme","2026-10","s",7]"#,
            Some(r#"["acme","2026-10","s",7]"#),
            json!({"org":"acme","month":"2026-10","session":"s","step":7,"costNanos":3}),
            r#"["other","2026-10","s",7]"#,
            Some(r#"["other","2026-10","s",7]"#),
            json!({"org":"other","costNanos":1000}),
        ),
        (
            "dependencies",
            r#"["acme","dependent","blocker"]"#,
            Some(r#"["acme","dependent","blocker"]"#),
            json!({"org":"acme","dependent":"dependent","blocker":"blocker"}),
            r#"["other","dependent","blocker"]"#,
            Some(r#"["other","dependent","blocker"]"#),
            json!({"org":"other"}),
        ),
        (
            "roleHolders",
            "role:role",
            None,
            json!({"org":"acme","members":["alice"]}),
            "role:other",
            None,
            json!({"org":"other","members":["bob"]}),
        ),
        (
            "labels",
            r#"["acme","l"]"#,
            Some(r#"["acme","l"]"#),
            json!({"owner":"org"}),
            r#"["other","l"]"#,
            Some(r#"["other","l"]"#),
            json!({"owner":"org"}),
        ),
        (
            "reports",
            "r",
            None,
            json!({"org":"acme","private":true,"reach":["alice"]}),
            "hidden",
            None,
            json!({"org":"acme","private":true,"createdBy":"bob","reach":[]}),
        ),
        (
            "toolJobs",
            "j",
            None,
            json!({"payload":{"owner":"alice","org":"acme"}}),
            "hidden",
            None,
            json!({"payload":{"owner":"bob","org":"other"}}),
        ),
        (
            "accountSessionGrants",
            "g",
            None,
            json!({"subject":"alice","generation":3}),
            "hidden",
            None,
            json!({"subject":"bob","generation":3}),
        ),
        (
            "accountFences",
            "alice",
            None,
            json!({"generation":3}),
            "bob",
            None,
            json!({"generation":3}),
        ),
        (
            "sessions",
            "s",
            None,
            json!({"org":"acme","owner":"bob","private":true,"createdBy":"bob","overseers":["alice"],"oversight":{"alice":1}}),
            "hidden",
            None,
            json!({"org":"acme","owner":"bob","private":true,"createdBy":"bob","overseers":[]}),
        ),
    ];
    for (name, key, decoded, row, hidden_key, hidden_decoded, hidden_row) in cases {
        let policy = actual_policy(name);
        let mut names = std::collections::BTreeSet::new();
        collect_targets(&policy, &mut names);
        let targets: Vec<_> = names
            .iter()
            .map(|name| (name.clone(), actual_policy(name)))
            .collect();
        let rows: Vec<_> = names
            .iter()
            .flat_map(|name| {
                ["alice", "bob", "acme", "s"].map(|key| (name.clone(), key.to_owned(), None))
            })
            .collect();
        assert!(
            differential(
                name,
                &policy,
                &principal,
                key,
                decoded,
                &row,
                &targets,
                &rows,
                &[]
            )
            .0,
            "actual positive {name}"
        );
        assert!(
            !differential(
                name,
                &policy,
                &principal,
                hidden_key,
                hidden_decoded,
                &hidden_row,
                &targets,
                &rows,
                &[]
            )
            .0,
            "actual hidden {name}"
        );
    }
    // Additional actual integration/grants/roles fixtures are checked below;
    // product-level refreshed rights and oversight expiry are NOT collection ACL.
    for name in ["grants", "roles", "integrationSettings"] {
        let policy = actual_policy(name);
        let mut names = std::collections::BTreeSet::new();
        collect_targets(&policy, &mut names);
        let targets: Vec<_> = names
            .iter()
            .map(|name| (name.clone(), actual_policy(name)))
            .collect();
        let rows: Vec<_> = names
            .iter()
            .flat_map(|name| ["alice", "acme", "s"].map(|key| (name.clone(), key.to_owned(), None)))
            .collect();
        for (key, decoded, row) in [
            (
                r#"["acme","i"]"#,
                Some(r#"["acme","i"]"#),
                json!({"org":"acme","owner":"alice","subject":"alice","members":["alice"]}),
            ),
            (
                r#"["other","i"]"#,
                Some(r#"["other","i"]"#),
                json!({"org":"other","owner":"bob","subject":"bob","members":["bob"]}),
            ),
        ] {
            let allowed = differential(
                name,
                &policy,
                &principal,
                key,
                decoded,
                &row,
                &targets,
                &rows,
                &[],
            )
            .0;
            assert_eq!(
                allowed,
                key.starts_with("[\"acme\""),
                "actual integration rights {name}"
            );
        }
    }
}

#[test]
fn typed_membership_rows_are_authorized_before_same_frame_real_count_sum() {
    use super::super::super::sql_frame::FrameColumn;
    use super::super::super::sqlite::{self, QueryOptions, SqlCell};
    let policy = actual_policy("members");
    let superadmin = actual_policy("superadmins");
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    let mut frame = FrameBuilder::new(limits(), &control).unwrap();
    let policy_id = put(&mut frame, &policy.to_string(), &control);
    let target_id = put(&mut frame, &superadmin.to_string(), &control);
    let principal_id = put(&mut frame, ALICE, &control);
    let prepared = [
        prepare(
            &mut frame,
            "members",
            r#"["acme","alice"]"#,
            Some(r#"["acme","alice"]"#),
            Some(r#"{"amount":3}"#),
            &control,
        ),
        prepare(
            &mut frame,
            "members",
            r#"["other","bob"]"#,
            Some(r#"["other","bob"]"#),
            Some(r#"{"amount":1000}"#),
            &control,
        ),
        prepare(
            &mut frame,
            "members",
            r#"["acme","bob"]"#,
            Some(r#"["acme","bob"]"#),
            Some(r#"{"amount":4}"#),
            &control,
        ),
    ];
    let absent = prepare(&mut frame, "superadmins", "alice", None, None, &control);
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    // Borrow during policy, collect only scalar approved cells, then end views
    // and insert into the SAME builder. No second default 128MiB owner.
    let mut cells = [None; 3];
    {
        let collections = [
            CapturedCollection {
                name: "members",
                policy: Some(frame.json(policy_id, &control).unwrap()),
            },
            CapturedCollection {
                name: "superadmins",
                policy: Some(frame.json(target_id, &control).unwrap()),
            },
        ];
        let absent = [bind(&frame, absent, &control, &budget, &mut job).unwrap()];
        let support =
            CapturedSupport::from_owned_native_capture(&collections, &absent, &budget, &mut job)
                .unwrap();
        let principal = VerifiedPrincipal::from_native_auth(
            frame.json(principal_id, &control).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, principal, 100);
        for (index, prepared) in prepared.into_iter().enumerate() {
            let row = bind(&frame, prepared, &control, &budget, &mut job).unwrap();
            assert_eq!(row.retained_key(), prepared.key);
            assert!(
                matches!(row.logical_key(),NativeDecodedKey::Json(value) if value.kind()==ArenaKind::Array)
            );
            if let Some(candidate) = engine
                .authorize_native(row, &[], &budget, &mut job)
                .unwrap()
                .candidate
            {
                let cell = candidate
                    .mapped_cell("amount", ColumnKind::Integer, &budget, &mut job)
                    .unwrap();
                cells[index] = Some(match cell {
                    FrameCell::Integer(value) => value,
                    _ => panic!("integer fixture"),
                });
            }
        }
    }
    assert_eq!(cells, [Some(3), None, Some(4)]);
    budget.finish(&mut job, 100).unwrap();
    let columns = [FrameColumn {
        name: "amount",
        kind: ColumnKind::Integer,
        nullable: false,
        logical_type: None,
        unit: None,
        equality: false,
    }];
    let table = frame.add_table("people", &columns).unwrap();
    for cell in cells.into_iter().flatten() {
        frame
            .insert_row(table, &[FrameCell::Integer(cell)], &control)
            .unwrap();
    }
    let mut sealed = frame.seal(&control).unwrap();
    let tables = sealed.native_tables(1024 * 1024).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*),SUM(amount) FROM people",
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
        [vec![SqlCell::Integer(2), SqlCell::Integer(7)]]
    );
}

#[test]
fn typed_key_binding_and_refusals_have_zero_postadmission_rust_heap() {
    let mut job = job();
    let cancel = job.cancellation().clone();
    let control = FrameControl::new(&cancel, job.deadline());
    let mut frame = FrameBuilder::new(limits(), &control).unwrap();
    let policy = put(
        &mut frame,
        r#"{"read":{"eq":[{"ref":["key","1"]},{"ref":["principal","subject"]}]}}"#,
        &control,
    );
    let principal = put(&mut frame, ALICE, &control);
    let good = prepare(
        &mut frame,
        "members",
        r#"["acme","alice"]"#,
        Some(r#"["acme","alice"]"#),
        Some("{}"),
        &control,
    );
    let malformed_declarations = [
        r#"{"name":"members","jsonKey":"true"}"#,
        r#"{"name":"members","json_key":true}"#,
        r#"{"name":"members","jsonKey":true,"allowed":true}"#,
        r#"{"name":"source:[x]","jsonKey":true}"#,
    ];
    let declarations: Vec<_> = malformed_declarations
        .iter()
        .map(|text| put(&mut frame, text, &control))
        .collect();
    let wrong_pair = put(&mut frame, r#"["other","[\"acme\",\"alice\"]"]"#, &control);
    let whitespace_pair = put(
        &mut frame,
        r#"[ "members", "[\"acme\",\"alice\"]" ]"#,
        &control,
    );
    let wrong_decoded = put(&mut frame, r#"["other","bob"]"#, &control);
    let physical = prepare(
        &mut frame,
        "members",
        "source:[x]",
        None,
        Some("{}"),
        &control,
    );
    let rounded = prepare(
        &mut frame,
        "members",
        "[9007199254740992]",
        Some("[9007199254740993]"),
        Some("{}"),
        &control,
    );
    let noncanonical = prepare(
        &mut frame,
        "members",
        r#"{"z":1,"a":2}"#,
        Some(r#"{"z":1,"a":2}"#),
        Some("{}"),
        &control,
    );
    let collections = [CapturedCollection {
        name: "members",
        policy: Some(frame.json(policy, &control).unwrap()),
    }];
    let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
    let mut output = [0; 128];
    let ((allowed, used), allocations, bytes) = crate::allocation_probe::measure(|| {
        let root = bind(&frame, good, &control, &budget, &mut job).unwrap();
        let support =
            CapturedSupport::from_owned_native_capture(&collections, &[], &budget, &mut job)
                .unwrap();
        let verified = VerifiedPrincipal::from_native_auth(
            frame.json(principal, &control).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, verified, 100);
        let read = engine
            .authorize_native(root, &[], &budget, &mut job)
            .unwrap();
        let n = read
            .candidate
            .unwrap()
            .encode_json(&mut output, &budget, &mut job)
            .unwrap();
        budget.finish(&mut job, 100).unwrap();
        (read.decision.allowed, n)
    });
    assert_eq!((allowed, used, allocations, bytes), (true, 2, 0, 0));
    let mut refusals = vec![
        Prepared {
            pair: wrong_pair,
            ..good
        },
        Prepared {
            pair: whitespace_pair,
            ..good
        },
        Prepared {
            decoded: Some(wrong_decoded),
            ..good
        },
        Prepared {
            decoded: None,
            ..good
        },
        physical,
        rounded,
        noncanonical,
    ];
    refusals.extend(declarations.into_iter().map(|declaration| Prepared {
        declaration,
        ..good
    }));
    for prepared in refusals {
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let (result, n, bytes) = crate::allocation_probe::measure(|| {
            bind(&frame, prepared, &control, &budget, &mut job)
        });
        assert!(matches!(
            result,
            Err(PolicyError::Unsupported | PolicyError::NeedCapture)
        ));
        assert_eq!((n, bytes), (0, 0));
        assert_eq!(budget.finish(&mut job, 100).err(), budget.failure());
    }
}

#[test]
fn typed_support_uncaptured_absent_duplicate_and_recursive_target_fail_before_output() {
    for state in [0, 1, 2, 3] {
        let mut job = job();
        let cancel = job.cancellation().clone();
        let control = FrameControl::new(&cancel, job.deadline());
        let mut frame = FrameBuilder::new(limits(), &control).unwrap();
        let policy = put(
            &mut frame,
            r#"{"read":{"readable":["members",{"value":["acme","alice"]}]}}"#,
            &control,
        );
        let target = put(
            &mut frame,
            if state == 3 {
                r#"{"read":{"readable":["root",{"value":"k"}]}}"#
            } else {
                r#"{"read":{"const":true}}"#
            },
            &control,
        );
        let principal = put(&mut frame, "{}", &control);
        let root = prepare(&mut frame, "root", "k", None, Some("{}"), &control);
        let absent = prepare(
            &mut frame,
            "members",
            r#"["acme","alice"]"#,
            Some(r#"["acme","alice"]"#),
            None,
            &control,
        );
        let collections = [
            CapturedCollection {
                name: "root",
                policy: Some(frame.json(policy, &control).unwrap()),
            },
            CapturedCollection {
                name: "members",
                policy: Some(frame.json(target, &control).unwrap()),
            },
        ];
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let root = bind(&frame, root, &control, &budget, &mut job).unwrap();
        let absent = bind(&frame, absent, &control, &budget, &mut job).unwrap();
        let rows = match state {
            0 => vec![],
            2 => vec![absent, absent],
            _ => vec![absent],
        };
        let (result, n, bytes) = crate::allocation_probe::measure(|| {
            let support =
                CapturedSupport::from_owned_native_capture(&collections, &rows, &budget, &mut job)?;
            let verified = VerifiedPrincipal::from_native_auth(
                frame.json(principal, &control).unwrap(),
                &budget,
                &mut job,
            )?;
            let engine = PolicyEngine::new(support, verified, 100);
            engine
                .authorize_native(root, &[], &budget, &mut job)
                .map(|read| read.decision.allowed)
        });
        assert_eq!((n, bytes), (0, 0));
        match state {
            0 => assert_eq!(result, Err(PolicyError::NeedCapture)),
            1 => assert_eq!(result, Ok(false)),
            _ => assert_eq!(result, Err(PolicyError::Unsupported)),
        };
    }
}

#[test]
fn typed_original_work_cancel_deadline_and_temporal_fences_remain_sticky() {
    for mode in [0, 1, 2, 3] {
        // Preserve one original job even for the deadline test: setup remains
        // within the normal admitted bound, then block until THAT deadline.
        let mut job = job();
        let cancel = job.cancellation().clone();
        let control = FrameControl::new(&cancel, job.deadline());
        let mut frame = FrameBuilder::new(limits(), &control).unwrap();
        let policy = put(
            &mut frame,
            if mode == 3 {
                r#"{"read":{"all":[{"exists":{"ref":["key","0"]}},{"lt":[{"ref":["now"]},{"value":101}]}]}}"#
            } else {
                r#"{"read":{"const":true}}"#
            },
            &control,
        );
        let principal = put(&mut frame, "{}", &control);
        let prepared = prepare(&mut frame, "root", "[7]", Some("[7]"), Some("{}"), &control);
        let collections = [CapturedCollection {
            name: "root",
            policy: Some(frame.json(policy, &control).unwrap()),
        }];
        let budget = PolicyBudget::new(MAX_POLICY_WORK).unwrap();
        let root = bind(&frame, prepared, &control, &budget, &mut job).unwrap();
        let support =
            CapturedSupport::from_owned_native_capture(&collections, &[], &budget, &mut job)
                .unwrap();
        let verified = VerifiedPrincipal::from_native_auth(
            frame.json(principal, &control).unwrap(),
            &budget,
            &mut job,
        )
        .unwrap();
        let engine = PolicyEngine::new(support, verified, 100);
        if mode == 0 {
            budget.remaining.set(0);
        }
        if mode == 1 {
            cancel.store(true, AtomicOrdering::Release);
        }
        if mode == 2 {
            std::thread::sleep(
                job.deadline().saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            );
        }
        let (result, n, bytes) = crate::allocation_probe::measure(|| {
            engine
                .authorize_native(root, &[], &budget, &mut job)
                .map(|read| read.decision.allowed)
        });
        assert_eq!((n, bytes), (0, 0));
        let expected = [
            PolicyError::WorkLimit,
            PolicyError::Cancelled,
            PolicyError::Deadline,
            PolicyError::UncertifiedTemporal,
        ][mode];
        assert_eq!(result, Err(expected));
        cancel.store(false, AtomicOrdering::Release);
        assert_eq!(budget.finish(&mut job, 100), Err(expected));
    }
}

#[test]
fn actual_org_visibility_and_typed_scope_field_redaction_selecting_match_native() {
    let alice: Value = serde_json::from_str(ALICE).unwrap();
    let target = actual_policy("superadmins");
    let absent = [("superadmins".to_owned(), "alice".to_owned(), None)];
    let orgs = actual_policy("orgs");
    let row = json!({"settings":{"secret":"not-public"},"name":"Other org"});
    let read = differential(
        "orgs",
        &orgs,
        &alice,
        "other",
        None,
        &row,
        &[("superadmins".to_owned(), target.clone())],
        &absent,
        &[],
    );
    assert!(read.0);
    assert!(read.1.get("settings").is_none());
    assert!(
        !differential(
            "orgs",
            &orgs,
            &alice,
            "other",
            None,
            &row,
            &[("superadmins".to_owned(), target.clone())],
            &absent,
            &["settings"]
        )
        .0
    );
    for key in ["acme", "other"] {
        let computer = json!({"subject":"computer","claims":{"role":"computer","org":"acme"}});
        let rows = [("superadmins".to_owned(), "computer".to_owned(), None)];
        assert_eq!(
            differential(
                "orgs",
                &orgs,
                &computer,
                key,
                None,
                &row,
                &[("superadmins".to_owned(), target.clone())],
                &rows,
                &[]
            )
            .0,
            key == "acme"
        );
    }
    let scopes = actual_policy("scopes");
    let rows = [(
        "superadmins".to_owned(),
        "alice".to_owned(),
        Some(json!({})),
    )];
    let row = json!({"org":"other","instructions":"not-public","amount":7});
    let key = r#"["other","scope"]"#;
    let read = differential(
        "scopes",
        &scopes,
        &alice,
        key,
        Some(key),
        &row,
        &[("superadmins".to_owned(), target.clone())],
        &rows,
        &[],
    );
    assert!(read.0);
    assert!(read.1.get("instructions").is_none());
    assert_eq!(read.1["amount"], 7);
    assert!(
        !differential(
            "scopes",
            &scopes,
            &alice,
            key,
            Some(key),
            &row,
            &[("superadmins".to_owned(), target)],
            &rows,
            &["instructions"]
        )
        .0
    );
}

#[path = "typed_probe_tests.rs"]
mod typed_probe_tests;
