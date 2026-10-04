//! Differential fixtures use ACTUAL private native types/build/decoders. All
//! fixture serde/allocation happens OUTSIDE the measured component window.
use super::*;
use crate::evaluator::{HttpMethod, sql_registry};
use serde_json::json;

// Test allowance only, NOT a new native admission or production work ledger.
const TEST_WORK: usize = 10_000_000;
fn raw_terminal() -> Value {
    json!({"name":"run","kind":"query","cache":false,"watch":false,
        "terminal":{"catalog":"app","operation":"query", "finalizer":"run.$sql.finalize","signingKeys":[]}})
}
fn actual(raw: Value) -> HttpMethod {
    serde::Deserialize::deserialize(&raw).unwrap()
}
fn produced(http: BTreeMap<String, HttpMethod>) -> (Value, Value) {
    (
        sql_registry::build(&http).unwrap(),
        serde_json::to_value(http).unwrap(),
    )
}
fn terminal_pair() -> (Value, Value) {
    produced(BTreeMap::from([("public".into(), actual(raw_terminal()))]))
}
fn empty_pair() -> (Value, Value) {
    produced(BTreeMap::from([(
        "plain".into(),
        actual(json!({"name":"plain","kind":"query"})),
    )]))
}
fn puts(registry: Value, http: Value) -> BTreeMap<String, Value> {
    BTreeMap::from([
        ("terminalMethods".into(), registry),
        ("httpMethods".into(), http),
    ])
}
fn check(entries: &BTreeMap<String, Value>) -> Result<Pairing, WorkFault> {
    effect(entries, &[], &mut { TEST_WORK })
}
fn changed(mut descriptor: Value, change: impl FnOnce(&mut Value)) -> BTreeMap<String, Value> {
    change(&mut descriptor);
    puts(
        json!({"format":1,"methods":{"public":descriptor.clone()}}),
        json!({"public":descriptor}),
    )
}

/// Oracle allocates intentionally OUTSIDE probes. Decode actual HttpMethod,
/// validate actual TerminalMethod, build actual native registry and compare it.
/// It is only applied to genuine/candidate terminal descriptors, not arbitrary
/// huge ordinary maps (the production component makes the narrower claim).
fn native_oracle(entries: &BTreeMap<String, Value>) -> bool {
    let Some(http) = entries.get("httpMethods").and_then(Value::as_object) else {
        return false;
    };
    let Some(registry) = entries.get(RECORD) else {
        return false;
    };
    let mut typed = BTreeMap::new();
    for (alias, value) in http {
        if !value.is_object() {
            return false;
        }
        let Ok(method) = HttpMethod::deserialize(value) else {
            return false;
        };
        if method
            .terminal
            .as_ref()
            .is_some_and(|terminal| terminal.validate().is_err())
        {
            return false;
        }
        typed.insert(alias.clone(), method);
    }
    sql_registry::build(&typed).is_ok_and(|built| {
        serde_json::to_vec(&built).unwrap() == serde_json::to_vec(registry).unwrap()
    })
}
use serde::Deserialize as _;

#[test]
fn sql_pairing_actual_producer_query_flags_default_omission_and_known_empty() {
    for (registry, http) in [terminal_pair(), empty_pair(), produced(BTreeMap::new())] {
        let entries = puts(registry, http);
        assert!(native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Paired));
    }
    let (registry, _) = terminal_pair();
    let method = &registry["methods"]["public"];
    assert_eq!(method["cache"], false);
    assert_eq!(method["watch"], false);
    assert!(method.get("receipt").is_none());
    assert!(method.get("consistency").is_none());
    assert_eq!(method["terminal"]["signingKeys"], json!([]));
    assert!(method["terminal"].get("cancelResult").is_none());
}

#[test]
fn sql_pairing_header_only_all_unpaired_code_changes_and_bundle_tombstone() {
    let (registry, http) = empty_pair();
    assert_eq!(
        check(&BTreeMap::from([(RECORD.into(), registry.clone())])),
        Ok(Pairing::Invalidate)
    );
    for key in ["bundle", "schema", "httpMethods", RECORD] {
        assert_eq!(
            check(&BTreeMap::from([(key.into(), json!(null))])),
            Ok(Pairing::Invalidate)
        );
        assert_eq!(
            effect(&BTreeMap::new(), &[key.into()], &mut { TEST_WORK }),
            Ok(Pairing::Invalidate)
        );
        let entries = puts(registry.clone(), http.clone());
        assert_eq!(
            effect(&entries, &[key.into()], &mut { TEST_WORK }),
            Ok(if key == "bundle" {
                Pairing::Invalidate
            } else {
                Pairing::Paired
            })
        );
    }
    let mut entries = puts(registry, http);
    entries.insert("bundle".into(), json!("accepted bundle"));
    entries.insert("schema".into(), json!({}));
    assert_eq!(
        effect(&entries, &["bundle".into()], &mut { TEST_WORK }),
        Ok(Pairing::Paired)
    );
    assert_eq!(
        check(&BTreeMap::from([("ordinary".into(), json!(null))])),
        Ok(Pairing::Keep)
    );
    assert_eq!(
        effect(&BTreeMap::new(), &["ordinary".into()], &mut { TEST_WORK }),
        Ok(Pairing::Keep)
    );
}

#[test]
fn sql_pairing_alias_fold_is_exact_not_method_name_lookup() {
    let method = actual(raw_terminal());
    let (registry, http) = produced(BTreeMap::from([
        ("a".into(), method.clone()),
        ("z".into(), method),
        (
            "ordinary".into(),
            actual(json!({"name":"plain","kind":"query"})),
        ),
    ]));
    let entries = puts(registry.clone(), http.clone());
    assert!(native_oracle(&entries));
    assert_eq!(check(&entries), Ok(Pairing::Paired));
    let mut missing = registry.clone();
    missing["methods"].as_object_mut().unwrap().remove("z");
    assert_eq!(check(&puts(missing, http.clone())), Ok(Pairing::Invalidate));
    let mut renamed = registry;
    let a = renamed["methods"]
        .as_object_mut()
        .unwrap()
        .remove("a")
        .unwrap();
    renamed["methods"]["run"] = a;
    assert_eq!(check(&puts(renamed, http)), Ok(Pairing::Invalidate));
}

#[test]
fn sql_pairing_empty_cannot_hide_later_terminal_and_ordinary_arrays_never_bypass() {
    let (empty, ordinary) = empty_pair();
    let (_, http) = terminal_pair();
    assert_eq!(check(&puts(empty.clone(), http)), Ok(Pairing::Invalidate));
    assert_eq!(
        check(&puts(empty.clone(), json!({"plain":["plain","query"]}))),
        Ok(Pairing::Invalidate)
    );
    assert_eq!(
        check(&puts(empty.clone(), json!({"plain":null}))),
        Ok(Pairing::Invalidate)
    );
    assert_eq!(check(&puts(empty, ordinary)), Ok(Pairing::Paired));
}

#[test]
fn sql_pairing_actual_native_positional_terminal_array_bypass_control() {
    let array = json!(["run","query",{"catalog":"app","operation":"query","finalizer":"run.$sql.finalize","signingKeys":[]},"linearizable",null,false,false]);
    let decoded = HttpMethod::deserialize(&array).unwrap();
    assert!(
        decoded.terminal.is_some(),
        "actual decoder accepts positional RawHttpMethod"
    );
    let (empty, _) = empty_pair();
    assert_eq!(
        check(&puts(empty, json!({"public":array}))),
        Ok(Pairing::Invalidate)
    );
    let (registry, _) = produced(BTreeMap::from([("public".into(), decoded)]));
    assert_eq!(
        check(&puts(registry, json!({"public":array}))),
        Ok(Pairing::Invalidate)
    );
}

#[test]
fn sql_pairing_http_canonical_defaults_types_and_unknown_fields_match_actual_oracle() {
    let (_, http) = terminal_pair();
    let canonical = http["public"].clone();
    let cases = [
        changed(canonical.clone(), |m| {
            m["consistency"] = json!("linearizable")
        }),
        changed(canonical.clone(), |m| {
            m["consistency"] = json!("replica-local")
        }),
        changed(canonical.clone(), |m| m["receipt"] = json!(true)),
        changed(canonical.clone(), |m| m["receipt"] = json!(false)),
        changed(canonical.clone(), |m| m["cache"] = json!(true)),
        changed(canonical.clone(), |m| m["watch"] = json!(true)),
        changed(canonical.clone(), |m| m["cache"] = json!(null)),
        changed(canonical.clone(), |m| m["kind"] = json!("mutation")),
        changed(canonical.clone(), |m| m["kind"] = json!("transaction")),
        changed(canonical.clone(), |m| m["kind"] = json!("unknown")),
        changed(canonical.clone(), |m| m["name"] = json!(123)),
        changed(canonical.clone(), |m| {
            m.as_object_mut().unwrap().remove("watch");
        }),
        changed(canonical.clone(), |m| m["terminal"] = json!(null)),
        changed(canonical.clone(), |m| m["unknown"] = json!(true)),
        changed(canonical, |m| m["name"] = json!("x".repeat(257))),
    ];
    for entries in cases {
        assert!(!native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Invalidate));
    }
}

#[test]
fn sql_pairing_terminal_canonical_required_fields_and_default_vec_omission() {
    let (_, http) = terminal_pair();
    let canonical = http["public"].clone();
    for key in ["catalog", "operation", "finalizer", "signingKeys"] {
        let entries = changed(canonical.clone(), |m| {
            m["terminal"].as_object_mut().unwrap().remove(key);
        });
        assert!(!native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Invalidate));
    }
    for entries in [
        changed(canonical.clone(), |m| {
            m["terminal"]["cancelResult"] = json!(null)
        }),
        changed(canonical.clone(), |m| {
            m["terminal"]["unknown"] = json!(true)
        }),
        changed(canonical.clone(), |m| {
            m["terminal"]["operation"] = json!("QUERY")
        }),
        changed(canonical.clone(), |m| {
            m["terminal"]["signingKeys"] = json!({})
        }),
        changed(canonical.clone(), |m| {
            m["terminal"]["finalizer"] = json!("")
        }),
        changed(canonical.clone(), |m| {
            m["terminal"]["finalizer"] = json!("x".repeat(385))
        }),
        changed(canonical, |m| m["terminal"]["catalog"] = json!(null)),
    ] {
        assert!(!native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Invalidate));
    }
    // Actual decoder accepts the default vec omission, but actual build adds it.
    let raw = json!({"name":"run","kind":"query","cache":false,"watch":false,
        "terminal":{"catalog":"app","operation":"query","finalizer":"f"}});
    assert!(HttpMethod::deserialize(&raw).is_ok());
    assert_eq!(check(&changed(raw, |_| {})), Ok(Pairing::Invalidate));
}

#[test]
fn sql_pairing_identifier_limits_reserved_names_and_native_empty_name_parity() {
    let (_, http) = terminal_pair();
    let canonical = http["public"].clone();
    for name in [
        "",
        "App",
        "1app",
        "a-b",
        "é",
        "sql_tables",
        "sql_columns",
        "sql_relationships",
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
    ] {
        let entries = changed(canonical.clone(), |m| {
            m["terminal"]["catalog"] = json!(name)
        });
        assert!(!native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Invalidate));
    }
    for (len, expected) in [(63, Pairing::Paired), (64, Pairing::Invalidate)] {
        let entries = changed(canonical.clone(), |m| {
            m["terminal"]["catalog"] = json!("a".repeat(len))
        });
        assert_eq!(native_oracle(&entries), expected == Pairing::Paired);
        assert_eq!(check(&entries), Ok(expected));
    }
    for (alias, name) in [
        ("".to_owned(), "".to_owned()),
        ("x".repeat(256), "y".repeat(256)),
    ] {
        let mut raw = raw_terminal();
        raw["name"] = json!(name);
        let (registry, http) = produced(BTreeMap::from([(alias, actual(raw))]));
        let entries = puts(registry, http);
        assert!(native_oracle(&entries));
        assert_eq!(check(&entries), Ok(Pairing::Paired));
    }
    let method = actual(raw_terminal());
    assert!(sql_registry::build(&BTreeMap::from([("x".repeat(257), method)])).is_err());
}

#[test]
fn sql_pairing_actual_operations_cancel_result_and_signer_rules_differential() {
    for operation in ["query", "explain", "catalog", "cancel"] {
        for result in [None, Some("boolean"), Some("cancelled"), Some("other")] {
            let mut raw = raw_terminal();
            raw["terminal"]["operation"] = json!(operation);
            if let Some(result) = result {
                raw["terminal"]["cancelResult"] = json!(result);
            }
            let entries = changed(raw, |_| {});
            assert_eq!(
                check(&entries),
                Ok(if native_oracle(&entries) {
                    Pairing::Paired
                } else {
                    Pairing::Invalidate
                })
            );
        }
    }
    let cases = [
        json!([]),
        json!([{"usages":["verify","sign"]}]),
        json!([{"name":"","usages":["sign"]}]),
        json!([{"name":1,"usages":["sign"]},{"name":1,"usages":["sign"]}]),
        json!([{"name":"one","usages":["sign"]},{"name":"two","usages":["sign"]}]),
        json!([{"name":"dup","usages":["sign"]},{"name":"dup","usages":["sign"]}]),
        json!([{"name":"one","usages":["verify"]}]),
        json!([{"name":"one","usages":"sign"}]),
        json!([{"usages":[null,1,{"a":"sign"},"sign"],"arbitrary":{"array":[1,true,null]}}]),
        json!([null]),
        json!([["sign"]]),
        json!(
            (0..9)
                .map(|_| json!({"usages":["sign"]}))
                .collect::<Vec<_>>()
        ),
    ];
    let (_, http) = terminal_pair();
    for operation in ["query", "cancel"] {
        for signers in &cases {
            let entries = changed(http["public"].clone(), |m| {
                m["terminal"]["operation"] = json!(operation);
                m["terminal"]["signingKeys"] = signers.clone();
            });
            let expected = native_oracle(&entries);
            assert_eq!(
                check(&entries),
                Ok(if expected {
                    Pairing::Paired
                } else {
                    Pairing::Invalidate
                })
            );
        }
    }
}

#[test]
fn sql_pairing_signed_zero_value_equality_is_not_exact_native_producer_equality() {
    let mut raw = raw_terminal();
    raw["terminal"]["signingKeys"] = json!([{"usages":["sign"],"numeric":-0.0}]);
    let (mut registry, http) = produced(BTreeMap::from([("public".into(), actual(raw))]));
    assert_eq!(
        check(&puts(registry.clone(), http.clone())),
        Ok(Pairing::Paired)
    );
    registry["methods"]["public"]["terminal"]["signingKeys"][0]["numeric"] = json!(0.0);
    assert_eq!(
        registry["methods"]["public"], http["public"],
        "old tree PartialEq misses signed-zero producer drift"
    );
    let entries = puts(registry, http);
    assert!(!native_oracle(&entries));
    assert_eq!(check(&entries), Ok(Pairing::Invalidate));
}

#[test]
fn sql_pairing_actual_finalizer_and_eight_distinct_signer_boundaries() {
    let (_, http) = terminal_pair();
    let canonical = http["public"].clone();
    let entries = changed(canonical.clone(), |m| {
        m["terminal"]["finalizer"] = json!("f".repeat(384));
        m["terminal"]["signingKeys"] = json!(
            (0..8)
                .map(|index| json!({"name":format!("key{index}"),"usages":["sign"]}))
                .collect::<Vec<_>>()
        );
    });
    assert!(native_oracle(&entries));
    assert_eq!(check(&entries), Ok(Pairing::Paired));
    let entries = changed(canonical, |m| {
        m["terminal"]["signingKeys"] = json!(
            (0..9)
                .map(|index| json!({"name":format!("key{index}"),"usages":["sign"]}))
                .collect::<Vec<_>>()
        );
    });
    assert!(!native_oracle(&entries));
    assert_eq!(check(&entries), Ok(Pairing::Invalidate));
}

#[test]
fn sql_pairing_finite_component_layout_is_not_native_stack_admission() {
    // Observed type sizes only. Caller still owns actual stack/controller and
    // the single cumulative source ledger; these are NOT backing allowances.
    println!(
        "actual Walk={} Frame={} NumberBuffer={} depth={} aliases={} registry={}",
        std::mem::size_of::<Walk<'_>>(),
        std::mem::size_of::<Frame<'_>>(),
        std::mem::size_of::<NumberBuffer>(),
        MAX_DEPTH,
        MAX_ALIASES,
        MAX_BYTES
    );
    assert_eq!(MAX_DEPTH, 128);
    assert_eq!(std::mem::size_of::<NumberBuffer>(), 40);
}

#[test]
fn sql_pairing_public_key_metadata_is_not_authentication_or_finalizer_provenance() {
    let mut raw = raw_terminal();
    raw["terminal"]["finalizer"] = json!("not-a-verified-callback");
    raw["terminal"]["signingKeys"] =
        json!([{"usages":["sign"],"kind":"not-a-key","algorithm":"not-authenticated"}]);
    let entries = changed(raw, |_| {});
    assert!(
        native_oracle(&entries),
        "native validation checks metadata, NOT actual authority"
    );
    assert_eq!(check(&entries), Ok(Pairing::Paired));
}

#[test]
fn sql_pairing_exact_32_alias_bound_and_http_only_extras() {
    let method = actual(raw_terminal());
    let mut methods = BTreeMap::new();
    for index in 0..32 {
        methods.insert(format!("alias{index:02}"), method.clone());
    }
    let (registry, mut http) = produced(methods.clone());
    http["plain"] = json!({"name":"plain","kind":"query"});
    assert_eq!(
        check(&puts(registry.clone(), http.clone())),
        Ok(Pairing::Paired)
    );
    methods.insert("alias32".into(), method);
    assert!(sql_registry::build(&methods).is_err());
    let mut extra = registry;
    extra["methods"]["alias32"] = http["alias00"].clone();
    http["alias32"] = http["alias00"].clone();
    assert_eq!(check(&puts(extra, http)), Ok(Pairing::Invalidate));
}

#[test]
fn sql_pairing_registry_top_level_native_canonical_shape() {
    let (_, http) = empty_pair();
    for bad in [
        json!(null),
        json!([]),
        json!({}),
        json!({"format":1}),
        json!({"format":1,"methods":{},"extra":true}),
        json!({"format":1,"methods":[]}),
        json!({"format":1.0,"methods":{}}),
        json!({"format":2,"methods":{}}),
        json!({"format":"1","methods":{}}),
    ] {
        assert_eq!(check(&puts(bad, http.clone())), Ok(Pairing::Invalidate));
    }
}

#[test]
fn sql_pairing_exact_json_counter_matches_actual_serde_strings_numbers_and_structure() {
    let controls: String = (0..=31).map(char::from).collect();
    let cases = [
        json!(null),
        json!(true),
        json!(false),
        json!([]),
        json!({}),
        json!([1,2,{"a":[null,"é😀/\\\""]}]),
        json!({"control":controls,"string":"\u{2028}\u{2029}"}),
        json!({"z":false,"a":true,"é":"/"}),
        json!("x".repeat(MAX_BYTES - 2)),
        json!("\0".repeat(100)),
    ];
    for value in cases {
        assert_eq!(
            encoded_bytes(&value, &mut { TEST_WORK }),
            Ok(Some(serde_json::to_vec(&value).unwrap().len()))
        );
    }
    let mut numbers = vec![
        json!(i64::MIN),
        json!(i64::MAX),
        json!(u64::MAX),
        json!(0),
        json!(-0.0),
        json!(0.0),
        json!(f64::MIN),
        json!(f64::MAX),
        json!(f64::MIN_POSITIVE),
        json!(f64::from_bits(1)),
    ];
    let mut state = 0x91ab_97ce_55f0_71a1u64;
    for _ in 0..4096 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let value = f64::from_bits(state);
        if value.is_finite() {
            numbers.push(json!(value));
        }
    }
    for value in numbers {
        let expected = serde_json::to_vec(&value).unwrap();
        assert!(expected.len() <= 32);
        assert_eq!(
            encoded_bytes(&value, &mut { TEST_WORK }),
            Ok(Some(expected.len()))
        );
        let buffer = number_bytes(value.as_number().unwrap(), &mut { TEST_WORK })
            .unwrap()
            .unwrap();
        assert_eq!(&buffer.bytes[..buffer.len], expected.as_slice());
    }
}

fn nested(mut value: Value, depth: usize) -> Value {
    for _ in 0..depth {
        value = Value::Array(vec![value]);
    }
    value
}
#[test]
fn sql_pairing_explicit_fixed_walk_depth_128_and_finite_deep_refusal() {
    let value = nested(json!(null), 128);
    assert_eq!(
        encoded_bytes(&value, &mut { TEST_WORK }),
        Ok(Some(serde_json::to_vec(&value).unwrap().len()))
    );
    let value = nested(json!(null), 129);
    assert_eq!(encoded_bytes(&value, &mut { TEST_WORK }), Ok(None));
    assert_eq!(same_json(&value, &value, &mut { TEST_WORK }), Ok(false));
    // Empty array itself at depth 128 is accepted, not just scalars there.
    let value = nested(json!([]), 128);
    assert!(encoded_bytes(&value, &mut { TEST_WORK }).unwrap().is_some());
    let value = nested(json!(null), 1024);
    let mut work = TEST_WORK;
    assert_eq!(encoded_bytes(&value, &mut work), Ok(None));
    assert!(
        TEST_WORK - work < 2048,
        "walk cannot traverse the deep tail"
    );
}

#[test]
fn sql_pairing_exact_native_build_registry_byte_limit_and_escape_overflow() {
    let mut raw = raw_terminal();
    raw["terminal"]["signingKeys"] = json!([{"usages":["sign"],"payload":""}]);
    let (base, _) = produced(BTreeMap::from([("public".into(), actual(raw.clone()))]));
    let baseline = serde_json::to_vec(&base).unwrap().len();
    raw["terminal"]["signingKeys"][0]["payload"] = json!("x".repeat(MAX_BYTES - baseline));
    let (registry, http) = produced(BTreeMap::from([("public".into(), actual(raw.clone()))]));
    assert_eq!(serde_json::to_vec(&registry).unwrap().len(), MAX_BYTES);
    assert_eq!(check(&puts(registry, http)), Ok(Pairing::Paired));
    raw["terminal"]["signingKeys"][0]["payload"] = json!("x".repeat(MAX_BYTES - baseline + 1));
    assert!(sql_registry::build(&BTreeMap::from([("public".into(), actual(raw))])).is_err());
    assert_eq!(
        encoded_bytes(&json!("x".repeat(MAX_BYTES - 1)), &mut { TEST_WORK }),
        Ok(None)
    );
    let escaped = json!("\0".repeat(MAX_BYTES / 6 + 1));
    assert!(serde_json::to_vec(&escaped).unwrap().len() > MAX_BYTES);
    assert_eq!(encoded_bytes(&escaped, &mut { TEST_WORK }), Ok(None));
}

#[test]
fn sql_pairing_huge_http_is_not_cloned_or_recursively_compared() {
    let (registry, mut http) = empty_pair();
    http["plain"]["ignoredOrdinaryPayload"] = json!("x".repeat(2 * 1024 * 1024));
    // Ordinary producer/auth/type provenance is intentionally NOT claimed.
    assert_eq!(check(&puts(registry, http)), Ok(Pairing::Paired));
    let (registry, mut http) = terminal_pair();
    http["public"]["terminal"]["signingKeys"] =
        json!([{"usages":["sign"],"large":"x".repeat(2*1024*1024)}]);
    let mut remaining = 20_000;
    assert_eq!(
        effect(&puts(registry, http), &[], &mut remaining),
        Ok(Pairing::Invalidate)
    );
    assert!(remaining > 0);
}

#[test]
fn sql_pairing_all_repeated_traversals_share_one_cumulative_ledger() {
    let (registry, http) = terminal_pair();
    let entries = puts(registry, http);
    let mut first = TEST_WORK;
    assert_eq!(effect(&entries, &[], &mut first), Ok(Pairing::Paired));
    let cost = TEST_WORK - first;
    let mut exact = cost;
    assert_eq!(effect(&entries, &[], &mut exact), Ok(Pairing::Paired));
    assert_eq!(exact, 0);
    assert_eq!(effect(&entries, &[], &mut exact), Err(WorkFault::Work));
    let mut twice = 2 * cost;
    assert_eq!(effect(&entries, &[], &mut twice), Ok(Pairing::Paired));
    assert_eq!(effect(&entries, &[], &mut twice), Ok(Pairing::Paired));
    assert_eq!(twice, 0);
    for budget in 0..cost {
        let mut work = budget;
        assert_eq!(effect(&entries, &[], &mut work), Err(WorkFault::Work));
        assert!(work <= budget);
    }
    let text = "not-a-short-key";
    assert_eq!(text_eq(text, text, &mut 1), Err(WorkFault::Work));
    assert_eq!(
        field(json!({"a":1,"b":2}).as_object().unwrap(), "b", &mut 1),
        Err(WorkFault::Work)
    );
}

#[test]
fn sql_pairing_metered_tree_equality_matches_actual_canonical_serde_bytes() {
    let cases = [
        json!(null),
        json!(false),
        json!(true),
        json!(1),
        json!(1.0),
        json!(-0.0),
        json!(0.0),
        json!("é"),
        json!("e"),
        json!([]),
        json!({}),
        json!([1, "x", {}]),
        json!({"a":[1,"x"],"b":null}),
    ];
    for a in &cases {
        for b in &cases {
            assert_eq!(
                same_json(a, b, &mut { TEST_WORK }),
                Ok(serde_json::to_vec(a).unwrap() == serde_json::to_vec(b).unwrap())
            );
        }
    }
    let value = json!({"a":"x".repeat(4000),"b":[1,2,3]});
    assert_eq!(same_json(&value, &value, &mut 300), Err(WorkFault::Work));
}

#[test]
fn sql_pairing_actual_global_allocator_probe_all_three_positive_controls() {
    use std::alloc::{Layout, alloc, alloc_zeroed, dealloc, realloc};
    let (_, counts) = crate::allocation_probe::run_filtered(
        || unsafe {
            let layout = Layout::from_size_align(32, 8).unwrap();
            let pointer = alloc(layout);
            assert!(!pointer.is_null());
            let pointer = realloc(pointer, layout, 64);
            assert!(!pointer.is_null());
            dealloc(pointer, Layout::from_size_align(64, 8).unwrap());
            let pointer = alloc_zeroed(layout);
            assert!(!pointer.is_null());
            dealloc(pointer, layout);
        },
        || true,
    );
    assert_eq!(
        (counts.alloc, counts.zeroed, counts.realloc, counts.bytes),
        (1, 1, 1, 128)
    );
}

#[test]
fn sql_pairing_zero_rust_heap_actual_effect_success_refusals_depth_arrays_32_and_tiny_work() {
    let (registry, http) = terminal_pair();
    let canonical = http["public"].clone();
    let mut fixtures = vec![
        (puts(registry, http), Pairing::Paired),
        {
            let (r, h) = empty_pair();
            (puts(r, h), Pairing::Paired)
        },
        {
            let (r, h) = produced(BTreeMap::new());
            (puts(r, h), Pairing::Paired)
        },
        (
            BTreeMap::from([("ordinary".into(), json!(null))]),
            Pairing::Keep,
        ),
        (
            BTreeMap::from([(RECORD.into(), json!({"format":1,"methods":{}}))]),
            Pairing::Invalidate,
        ),
        (
            changed(canonical.clone(), |m| {
                m["terminal"].as_object_mut().unwrap().remove("signingKeys");
            }),
            Pairing::Invalidate,
        ),
        (
            changed(canonical.clone(), |m| {
                m["terminal"]["unknown"] = json!(true)
            }),
            Pairing::Invalidate,
        ),
        (
            changed(
                canonical.clone(),
                |m| {
                    m["terminal"]["signingKeys"] =
                        json!([{"name":"dup","usages":["sign"]},{"name":"dup","usages":["sign"]}])
                },
            ),
            Pairing::Invalidate,
        ),
        (
            changed(canonical.clone(), |m| {
                m["terminal"]["signingKeys"] =
                    json!([{"usages":["sign"],"deep":nested(json!(null),129)}])
            }),
            Pairing::Invalidate,
        ),
        (
            changed(canonical.clone(), |m| {
                m["terminal"]["signingKeys"] =
                    json!([{"usages":["sign"],"overflow":"\0".repeat(6000)}])
            }),
            Pairing::Invalidate,
        ),
        (
            puts(
                json!({"format":1,"methods":{}}),
                json!({"public":["run","query",{"catalog":"app","operation":"query","finalizer":"f","signingKeys":[]},"linearizable",null,false,false]}),
            ),
            Pairing::Invalidate,
        ),
        (
            changed(
                canonical,
                |m| m["terminal"]["signingKeys"] = json!([{"name":"key","usages":["sign"],"numbers":[i64::MIN,u64::MAX,f64::MAX,-0.0]}]),
            ),
            Pairing::Paired,
        ),
    ];
    let method = actual(raw_terminal());
    let methods = (0..32)
        .map(|index| (format!("alias{index:02}"), method.clone()))
        .collect();
    let (registry, http) = produced(methods);
    fixtures.push((puts(registry, http), Pairing::Paired));
    let (registry, mut http) = empty_pair();
    http["plain"]["huge"] = json!("x".repeat(2 * 1024 * 1024));
    fixtures.push((puts(registry, http), Pairing::Paired));
    let mut raw = raw_terminal();
    raw["terminal"]["signingKeys"] = json!([{"usages":["sign"],"numeric":-0.0}]);
    let (mut registry, http) = produced(BTreeMap::from([("public".into(), actual(raw))]));
    registry["methods"]["public"]["terminal"]["signingKeys"][0]["numeric"] = json!(0.0);
    fixtures.push((puts(registry, http), Pairing::Invalidate));
    for (entries, expected) in fixtures {
        let mut remaining = TEST_WORK;
        let (result, counts) = crate::allocation_probe::run_filtered(
            || effect(&entries, &[], &mut remaining),
            || true,
        );
        assert_eq!(result, Ok(expected));
        assert_eq!(counts, crate::allocation_probe::Counts::default());
        let mut remaining = 0;
        let (result, counts) = crate::allocation_probe::run_filtered(
            || effect(&entries, &[], &mut remaining),
            || true,
        );
        assert_eq!(result, Err(WorkFault::Work));
        assert_eq!(counts, crate::allocation_probe::Counts::default());
    }
    for key in ["bundle", "schema", "httpMethods", RECORD] {
        let entries = BTreeMap::new();
        let deletes = [key.to_owned()];
        let mut remaining = TEST_WORK;
        let (result, counts) = crate::allocation_probe::run_filtered(
            || effect(&entries, &deletes, &mut remaining),
            || true,
        );
        assert_eq!(result, Ok(Pairing::Invalidate));
        assert_eq!(counts, crate::allocation_probe::Counts::default());
    }
}
