//! Tests use the exact current evaluator serde/validate/build before observation.
use super::*;
use crate::{allocation_probe, metadata_reference as reference};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::time::Duration;
static NEVER: AtomicBool = AtomicBool::new(false);
fn control() -> Control<'static> {
    Control::new(Instant::now() + Duration::from_secs(30), &NEVER)
}
fn pool() -> Pool {
    Pool::new(16 * 1024 * 1024, 8)
}
fn method(operation: &str) -> Value {
    json!({"name":"private.run", "kind":"query", "cache":false, "watch":false,
        "terminal":{"catalog":"app", "operation":operation, "finalizer":"private.run.$sql.finalize", "signingKeys":[]}})
}
fn real_registry(method: Value, alias: &str) -> Vec<u8> {
    let actual: reference::HttpMethod = serde_json::from_value(method).unwrap();
    let registry = reference::registry(&BTreeMap::from([(alias.to_owned(), actual)])).unwrap();
    serde_json::to_vec(&registry).unwrap()
}
fn encoded_registry(method: Value, alias: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({"format":1,"methods":{alias:method}})).unwrap()
}
fn classified(raw: &[u8], name: &str) -> Result<bool, Error> {
    let body = serde_json::to_vec(&json!({"name":name})).unwrap();
    let pool = pool();
    let check = control();
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight.lookup_name(&body, &check).unwrap();
    let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
    classifier.classify(raw).map(|r| r.is_ordinary())
}

#[test]
fn actual_build_all_four_operations_match_header_and_borrowed_offsets_zero_rust() {
    let pool = pool();
    let check = control();
    for (op, expected) in [
        ("query", Operation::Query),
        ("explain", Operation::Explain),
        ("catalog", Operation::Catalog),
        ("cancel", Operation::Cancel),
    ] {
        let raw = real_registry(method(op), "public.sql");
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = flight
            .lookup_name(br#"{"name":"public.sql"}"#, &check)
            .unwrap();
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
        assert_eq!((n, bytes), (0, 0));
        let result = result.unwrap();
        assert!(!result.is_ordinary());
        let header = result.terminal().unwrap();
        assert_eq!(header.operation(), expected);
        assert_eq!(header.name(), "private.run");
        assert_eq!(header.alias(), "public.sql");
        assert_eq!(header.catalog(), "app");
        assert_eq!(header.finalizer(), "private.run.$sql.finalize");
        assert_eq!(header.cancel_result(), None);
        assert_eq!(header.signing_keys_json(), b"[]");
        let encoded: Value = serde_json::from_slice(header.encoded_method_json()).unwrap();
        assert_eq!(encoded, method(op));
        assert_eq!(
            serde_json::from_slice::<Value>(header.encoded_terminal_json()).unwrap(),
            method(op)["terminal"]
        );
        let base = raw.as_ptr() as usize;
        for slice in [
            header.encoded_method_json(),
            header.encoded_terminal_json(),
            header.signing_keys_json(),
        ] {
            assert!(
                slice.as_ptr() as usize >= base
                    && (slice.as_ptr() as usize) + slice.len() <= base + raw.len()
            );
        }
        assert_eq!(classified(&raw, "private.run"), Ok(true));
        assert_eq!(classified(&raw, "private.run.$sql.finalize"), Ok(true));
    }
}

#[test]
fn opaque_overlong_names_decode_every_byte_and_only_complete_registry_proves_ordinary() {
    let pool = pool();
    let check = control();
    let empty = serde_json::to_vec(&reference::registry(&BTreeMap::new()).unwrap()).unwrap();
    for name in [
        "a".repeat(257),
        "é".repeat(129),
        format!("{}\0😃", "a".repeat(254)),
        "z".repeat(65536),
    ] {
        let body = serde_json::to_vec(&json!({"name":name})).unwrap();
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let (lookup, n, bytes) = allocation_probe::measure(|| flight.lookup_name(&body, &check));
        assert_eq!((n, bytes), (0, 0));
        let lookup = lookup.unwrap();
        assert_eq!(lookup.decoded_len(), name.len());
        assert_eq!(lookup.bounded_name(), None);
        assert_eq!(lookup.name(), Err(Error::Unsupported));
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&empty));
        assert_eq!((n, bytes), (0, 0));
        assert!(result.unwrap().is_ordinary());
    }
    let long = "a".repeat(257);
    let raw = encoded_registry(method("query"), &long);
    assert_eq!(classified(&raw, &long).err(), Some(Error::Capacity));
    for raw in [
        b"".as_slice(),
        b"{}",
        b"null",
        b"{\"format\":1,\"methods\":{}}junk",
        b"{\"format\":2,\"methods\":{}}",
        b"{\"format\":1}",
        b"{\"format\":1,\"methods\":null}",
    ] {
        assert!(classified(raw, &long).is_err());
    }
}

#[test]
fn last_name_wins_long_short_short_long_and_complete_unicode_nul_utf8_validation() {
    let pool = pool();
    let check = control();
    let long = "é".repeat(129);
    for (body, expected) in [
        (
            format!(r#"{{"name":"{long}","na\u006de":"short\u0000\ud83d\ude03"}}"#),
            "short\0😃".to_owned(),
        ),
        (
            format!(r#"{{"name":"short","na\u006de":"{long}"}}"#),
            long.clone(),
        ),
    ] {
        let actual: Value = serde_json::from_slice(body.as_bytes()).unwrap();
        assert_eq!(actual["name"].as_str(), Some(expected.as_str()));
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = flight.lookup_name(body.as_bytes(), &check).unwrap();
        assert_eq!(lookup.decoded_len(), expected.len());
        assert_eq!(
            lookup.bounded_name(),
            if expected.len() <= 256 {
                Some(expected.as_str())
            } else {
                None
            }
        );
    }
    let malformed = [
        format!(r#"{{"name":"{long}\ud800"}}"#).into_bytes(),
        format!(r#"{{"name":"{long}\udfff"}}"#).into_bytes(),
        format!(r#"{{"name":"{long}\z"}}"#).into_bytes(),
        format!(r#"{{"name":"{long}"}}junk"#).into_bytes(),
        [format!(r#"{{"name":"{long}"#).as_bytes(), b"\xff\"}"].concat(),
        [format!(r#"{{"name":"{long}"#).as_bytes(), b"\x00\"}"].concat(),
    ];
    for body in malformed {
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        assert!(flight.lookup_name(&body, &check).is_err());
        let error = flight.failed.unwrap();
        assert_eq!(
            flight.lookup_name(br#"{"name":"good"}"#, &check).err(),
            Some(error)
        );
    }
}

#[test]
fn unicode_aliases_have_decoded_256_byte_limit_and_duplicate_escaped_keys_refuse() {
    for name in ["é".repeat(128), format!("{}\0😃", "a".repeat(251))] {
        let raw = real_registry(method("query"), &name);
        assert_eq!(classified(&raw, &name), Ok(false));
    }
    let entry = serde_json::to_string(&method("query")).unwrap();
    for raw in [
        format!(r#"{{"format":1,"methods":{{"sql":{entry},"s\u0071l":{entry}}}}}"#),
        format!(r#"{{"format":1,"for\u006dat":1,"methods":{{"sql":{entry}}}}}"#),
        format!(r#"{{"format":1,"methods":{{"sql":{entry}}},"methods":{{}}}}"#),
        r#"{"format":1,"methods":{"sql":{"name":"x","na\u006de":"x"}}}"#.to_owned(),
    ] {
        assert_eq!(
            classified(raw.as_bytes(), "sql").err(),
            Some(Error::Duplicate)
        );
    }
}

#[test]
fn full_registry_is_validated_before_any_matched_alias_or_ordinary_result() {
    let good = serde_json::to_string(&method("query")).unwrap();
    for raw in [
        format!(r#"{{"format":1,"methods":{{"sql":{good},"tail":null}}}}"#),
        format!(
            r#"{{"format":1,"methods":{{"sql":{good},"tail":{{"name":"x","kind":"query"}}}}}}"#
        ),
        format!(r#"{{"format":1,"methods":{{"sql":{good},"tail":{good}}}}}junk"#),
        format!(r#"{{"format":1,"methods":{{"sql":{good},"tail":{good},}}}}"#),
    ] {
        for name in ["sql", "unmatched"] {
            assert!(classified(raw.as_bytes(), name).is_err());
        }
    }
}

#[test]
fn actual_serde_and_validation_differential_covers_flags_null_defaults_operations_and_unknown() {
    let mut fixtures = vec![method("query")];
    for field in ["name", "kind", "cache", "watch", "terminal"] {
        let mut value = method("query");
        value.as_object_mut().unwrap().remove(field);
        fixtures.push(value);
        let mut value = method("query");
        value[field] = Value::Null;
        fixtures.push(value);
    }
    for (field, values) in [
        (
            "kind",
            vec![json!("mutation"), json!("transaction"), json!("unknown")],
        ),
        (
            "consistency",
            vec![
                json!("linearizable"),
                json!("replica-local"),
                Value::Null,
                json!(false),
            ],
        ),
        ("cache", vec![json!(true), json!(0), json!("false")]),
        ("watch", vec![json!(true), json!(0), json!("false")]),
        ("receipt", vec![json!(true), json!(false)]),
        ("access", vec![json!({"kind":"public"})]),
    ] {
        for v in values {
            let mut value = method("query");
            value[field] = v;
            fixtures.push(value);
        }
    }
    for (field, values) in [
        (
            "catalog",
            vec![
                json!(""),
                json!("A"),
                json!("sql_tables"),
                json!("sqlite_schema"),
                json!("a".repeat(64)),
                json!("a".repeat(63)),
                json!("app_12"),
            ],
        ),
        (
            "operation",
            vec![
                json!("query"),
                json!("explain"),
                json!("catalog"),
                json!("cancel"),
                json!("QUERY"),
                Value::Null,
                json!(1),
            ],
        ),
        (
            "finalizer",
            vec![
                json!(""),
                json!("x".repeat(384)),
                json!("x".repeat(385)),
                Value::Null,
            ],
        ),
        (
            "cancelResult",
            vec![
                Value::Null,
                json!("boolean"),
                json!("cancelled"),
                json!("callback"),
                json!(true),
            ],
        ),
        ("unknown", vec![json!(true)]),
    ] {
        for v in values {
            let mut value = method("query");
            value["terminal"][field] = v;
            fixtures.push(value);
        }
    }
    for value in fixtures {
        let reference = serde_json::from_value::<reference::HttpMethod>(value.clone())
            .ok()
            .is_some_and(|m| m.terminal.as_ref().is_some_and(|t| t.validate().is_ok()));
        let raw = encoded_registry(value.clone(), "sql");
        let native = classified(&raw, "sql");
        assert_eq!(native.is_ok(), reference, "fixture {value}");
        if native.is_ok() {
            assert_eq!(native, Ok(false));
        }
    }
    // Query receipt:null is tolerated by RawHttpMethod's Option<bool>, but never
    // emitted by real build. The frozen terminal-record ingress rejects EVERY
    // receipt property, as required, not silently guessing null means absent.
    let mut value = method("query");
    value["receipt"] = Value::Null;
    assert!(serde_json::from_value::<reference::HttpMethod>(value.clone()).is_ok());
    assert_eq!(
        classified(&encoded_registry(value, "sql"), "sql").err(),
        Some(Error::Invalid)
    );
}

#[test]
fn real_cancel_shapes_signers_and_arbitrary_bounded_signing_value_semantics() {
    for shape in [Value::Null, json!("boolean"), json!("cancelled")] {
        let mut value = method("cancel");
        value["terminal"]["cancelResult"] = shape.clone();
        let raw = real_registry(value, "sql");
        assert_eq!(classified(&raw, "sql"), Ok(false));
        let pool = pool();
        let check = control();
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        let result = classifier.classify(&raw).unwrap();
        assert_eq!(
            result.terminal().unwrap().cancel_result(),
            if shape.is_null() {
                None
            } else if shape == "boolean" {
                Some(CancelResultShape::Boolean)
            } else {
                Some(CancelResultShape::Cancelled)
            }
        );
    }
    let signer_fixtures = vec![
        json!([]),
        json!([{"usages":["sign"]}]),
        json!([{"name":null,"usages":["read","sign",{},null,7]}]),
        json!([{"name":"x","kind":"not-a-real-key","algorithm":null,"arbitrary":[{},[],1],"usages":["sign"]}]),
        json!([{"name":"x","usages":["sign"]},{"name":"x","usages":["sign"]}]),
        json!([{"name":"é\0","usages":["sign"]},{"name":"é\0","usages":["sign"]}]),
        json!([{"name":17,"usages":["sign"]},{"name":17,"usages":["sign"]}]),
        json!([{"usages":[]}]),
        json!([{"usages":"sign"}]),
        json!([{"usages":["SIGN"]}]),
        json!([null]),
        json!(vec![json!({"usages":["sign"]}); 8]),
        json!(vec![json!({"usages":["sign"]}); 9]),
        Value::Null,
    ];
    for operation in ["query", "cancel"] {
        for signers in &signer_fixtures {
            let mut value = method(operation);
            value["terminal"]["signingKeys"] = signers.clone();
            let reference = serde_json::from_value::<reference::HttpMethod>(value.clone())
                .ok()
                .is_some_and(|m| m.terminal.unwrap().validate().is_ok());
            let result = classified(&encoded_registry(value.clone(), "sql"), "sql");
            assert_eq!(result.is_ok(), reference, "signer fixture {value}");
        }
    }
    let mut value = method("query");
    value["terminal"]
        .as_object_mut()
        .unwrap()
        .remove("signingKeys");
    assert_eq!(
        classified(&encoded_registry(value, "sql"), "sql"),
        Ok(false)
    );
}

#[test]
fn exact_metadata_byte_alias_count_depth_caps_and_all_descriptors() {
    let entries = (0..32)
        .map(|n| {
            (
                format!("sql{n}"),
                serde_json::from_value::<reference::HttpMethod>(method("query")).unwrap(),
            )
        })
        .collect();
    let raw = serde_json::to_vec(&reference::registry(&entries).unwrap()).unwrap();
    assert_eq!(classified(&raw, "sql31"), Ok(false));
    let entries = (0..33)
        .map(|n| (format!("sql{n}"), method("query")))
        .collect::<serde_json::Map<_, _>>();
    let raw = serde_json::to_vec(&json!({"format":1,"methods":entries})).unwrap();
    assert_eq!(classified(&raw, "sql0").err(), Some(Error::Capacity));
    let mut raw = b"{\"format\":1,\"methods\":{}}".to_vec();
    raw.resize(32768, b' ');
    assert_eq!(classified(&raw, "ordinary"), Ok(true));
    raw.push(b' ');
    assert_eq!(classified(&raw, "ordinary").err(), Some(Error::Capacity));
    for nested in [57, 58, 59, 60, 61, 62, 63, 64, 65] {
        let entry = serde_json::to_string(&method("query")).unwrap();
        let signers = format!(
            r#"[{{"usages":["sign"],"extra":{}0{}}}]"#,
            "[".repeat(nested),
            "]".repeat(nested)
        );
        let raw = format!(
            r#"{{"format":1,"methods":{{"sql":{}}}}}"#,
            entry.replace("\"signingKeys\":[]", &format!("\"signingKeys\":{signers}"))
        );
        // Root/methods/method/terminal/signers/signer/extra account for 6+nested.
        assert_eq!(
            classified(raw.as_bytes(), "sql").is_ok(),
            nested + 6 <= 64,
            "depth {nested}"
        );
    }
}

struct Fault(AtomicUsize);
impl Check for Fault {
    fn check(&self) -> Result<(), Error> {
        match self.0.load(Ordering::Acquire) {
            0 => Ok(()),
            1 => Err(Error::Cancelled),
            _ => Err(Error::Deadline),
        }
    }
}
#[test]
fn cancellation_deadline_malformed_and_work_failures_poison_same_cumulative_preflight() {
    let pool = pool();
    let check = control();
    for malformed in [
        b"null".as_slice(),
        b"{\"format\":1,\"methods\":{}}junk",
        b"{\"format\":9,\"methods\":{}}",
    ] {
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = flight
            .lookup_name(br#"{"name":"ordinary"}"#, &check)
            .unwrap();
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        let first = classifier.classify(malformed).err().unwrap();
        assert_eq!(
            classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
            Some(first)
        );
        assert_eq!(
            flight.parse_lookup(&lookup, Transport::Query, &check).err(),
            Some(first)
        );
    }
    for state in [1, 2] {
        let fault = Fault(AtomicUsize::new(0));
        let mut flight = Preflight::new(&pool, Limits::default(), &fault).unwrap();
        let lookup = flight
            .lookup_name(br#"{"name":"ordinary"}"#, &fault)
            .unwrap();
        let mut classifier = flight.registry_classifier(&lookup, &fault).unwrap();
        fault.0.store(state, Ordering::Release);
        let (result, n, bytes) =
            allocation_probe::measure(|| classifier.classify(b"{\"format\":1,\"methods\":{}}"));
        assert_eq!((n, bytes), (0, 0));
        let first = result.err().unwrap();
        fault.0.store(0, Ordering::Release);
        assert_eq!(
            classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
            Some(first)
        );
        assert_eq!(
            flight.parse_lookup(&lookup, Transport::Query, &fault).err(),
            Some(first)
        );
    }
    let mut flight = Preflight::new(
        &pool,
        Limits {
            work: 540000,
            ..Limits::default()
        },
        &check,
    )
    .unwrap();
    let lookup = flight
        .lookup_name(br#"{"name":"ordinary"}"#, &check)
        .unwrap();
    let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
    assert!(
        classifier
            .classify(b"{\"format\":1,\"methods\":{}}")
            .unwrap()
            .is_ordinary()
    );
    assert!(
        classifier
            .classify(b"{\"format\":1,\"methods\":{}}")
            .unwrap()
            .is_ordinary()
    );
    assert_eq!(
        classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
        Some(Error::WorkLimit)
    );
    assert_eq!(
        classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
        Some(Error::WorkLimit)
    );
    assert_eq!(
        flight.parse_lookup(&lookup, Transport::Query, &check).err(),
        Some(Error::WorkLimit)
    );
}

#[test]
fn classifier_creation_rejects_foreign_body_witness_and_layout_stays_in_existing_control() {
    let pool = pool();
    let check = control();
    let mut first = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let mut second = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let a = first.lookup_name(br#"{"name":"a"}"#, &check).unwrap();
    let b = second.lookup_name(br#"{"name":"b"}"#, &check).unwrap();
    assert_eq!(
        first.registry_classifier(&b, &check).err(),
        Some(Error::Invalid)
    );
    assert_eq!(
        first.registry_classifier(&a, &check).err(),
        Some(Error::Invalid)
    );
    assert_eq!(Preflight::admission_bytes().unwrap(), 282624);
    assert!(registry::control_layout_bytes() <= CONTROL_BYTES);
    fn send_sync<T: Send + Sync>() {}
    send_sync::<NameLookup<'static>>();
    send_sync::<RegistryClassifier<'static, 'static, 'static>>();
    send_sync::<ClassifiedRegistry<'static>>();
    send_sync::<TerminalHeader<'static>>();
    println!(
        "control_layout_bytes={} control_allowance_bytes={} preflight_bytes={} terminal_header_bytes={} classifier_bytes={} classified_bytes={}",
        registry::control_layout_bytes(),
        CONTROL_BYTES,
        Preflight::admission_bytes().unwrap(),
        size_of::<TerminalHeader>(),
        size_of::<RegistryClassifier>(),
        size_of::<ClassifiedRegistry>()
    );
}

#[test]
fn healthy_classification_reuses_scratch_for_native_envelope_not_registry_offset_keys() {
    let raw = real_registry(method("query"), "sql");
    let pool = pool();
    let check = control();
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight
        .lookup_name(br#"{"name":"sql","args":{"sql":"select 1"}}"#, &check)
        .unwrap();
    let before = flight.remaining;
    {
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        assert!(classifier.classify(&raw).unwrap().terminal().is_some());
    }
    let after = flight.remaining;
    assert!(after < before);
    let (header, n, bytes) =
        allocation_probe::measure(|| flight.parse_lookup(&lookup, Transport::Query, &check));
    assert_eq!((n, bytes), (0, 0));
    assert_eq!(header.unwrap().name(), "sql");
    assert!(flight.remaining < after);
}

#[test]
fn classifier_errors_are_zero_rust_and_no_replacement_checker_or_second_lookup_can_recover() {
    let pool = pool();
    let check = control();
    let good = real_registry(method("query"), "sql");
    let bad = [
        b"null".to_vec(),
        b"{\"format\":1,\"methods\":{}}junk".to_vec(),
        b"{\"format\":1,\"methods\":{},\"unknown\":0}".to_vec(),
        b"{\"format\":1,\"methods\":{},\"methods\":{}}".to_vec(),
        b"{\"format\":3,\"methods\":{}}".to_vec(),
        encoded_registry(method("query"), &"x".repeat(257)),
        encoded_registry(json!({"name":"x","kind":"query"}), "sql"),
        {
            let mut method = method("query");
            method["terminal"]["signingKeys"] = json!([{"usages":["read"]}]);
            encoded_registry(method, "sql")
        },
    ];
    for raw in bad {
        let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
        assert_eq!((n, bytes), (0, 0));
        let error = result.err().unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&good));
        assert_eq!((n, bytes), (0, 0));
        assert_eq!(result.err(), Some(error));
    }
    let other = control();
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
    assert_eq!(
        flight.registry_classifier(&lookup, &other).err(),
        Some(Error::Invalid)
    );
    assert_eq!(
        flight.registry_classifier(&lookup, &check).err(),
        Some(Error::Invalid)
    );
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
    assert_eq!(
        flight.lookup_name(br#"{"name":"sql"}"#, &check).err(),
        Some(Error::Invalid)
    );
    assert_eq!(
        flight.registry_classifier(&lookup, &check).err(),
        Some(Error::Invalid)
    );
}

struct Trip {
    calls: AtomicUsize,
    at: AtomicUsize,
    deadline: bool,
}
impl Check for Trip {
    fn check(&self) -> Result<(), Error> {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        if n >= self.at.load(Ordering::Relaxed) {
            Err(if self.deadline {
                Error::Deadline
            } else {
                Error::Cancelled
            })
        } else {
            Ok(())
        }
    }
}
#[test]
fn stops_inside_key_clear_unicode_hash_whole_validation_semantics_and_signer_comparisons_are_sticky()
 {
    let mut value = method("query");
    value["terminal"]["signingKeys"] = json!([
        {"name":"é".repeat(2500),"usages":["sign"],"arbitrary":"é".repeat(2500)},
        {"name":format!("{}x","é".repeat(2500)),"usages":[null,{},1,"read","sign"]}
    ]);
    let raw = real_registry(value, "sql");
    let pool = pool();
    let trip = Trip {
        calls: AtomicUsize::new(0),
        at: AtomicUsize::new(usize::MAX),
        deadline: false,
    };
    let mut flight = Preflight::new(&pool, Limits::default(), &trip).unwrap();
    let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &trip).unwrap();
    let mut classifier = flight.registry_classifier(&lookup, &trip).unwrap();
    trip.calls.store(0, Ordering::Relaxed);
    let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
    assert_eq!((n, bytes), (0, 0));
    assert!(result.unwrap().terminal().is_some());
    let total = trip.calls.load(Ordering::Relaxed);
    assert!(total > 1024);
    for deadline in [false, true] {
        for at in [1, 64, 1023, 1025, total / 2, total - 1] {
            let trip = Trip {
                calls: AtomicUsize::new(0),
                at: AtomicUsize::new(usize::MAX),
                deadline,
            };
            let mut flight = Preflight::new(&pool, Limits::default(), &trip).unwrap();
            let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &trip).unwrap();
            let mut classifier = flight.registry_classifier(&lookup, &trip).unwrap();
            trip.calls.store(0, Ordering::Relaxed);
            trip.at.store(at, Ordering::Relaxed);
            let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
            assert_eq!((n, bytes), (0, 0));
            let expected = if deadline {
                Error::Deadline
            } else {
                Error::Cancelled
            };
            assert_eq!(result.err(), Some(expected));
            trip.at.store(usize::MAX, Ordering::Relaxed);
            assert_eq!(
                classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
                Some(expected)
            );
        }
    }
}

#[test]
fn actual_large_arbitrary_value_and_full_signing_array_metadata_are_not_key_authority() {
    let mut value = method("query");
    value["terminal"]["signingKeys"] = json!([{"usages":["sign"],"extra":vec![0;13000]}]);
    let raw = real_registry(value.clone(), "sql");
    assert!(raw.len() < 32768);
    let pool = pool();
    let check = control();
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
    let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
    let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
    assert_eq!((n, bytes), (0, 0));
    let header = result.unwrap().into_terminal().unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(header.signing_keys_json()).unwrap(),
        value["terminal"]["signingKeys"]
    );
    // No key-name/algorithm/access selection accessor or authority verifier was
    // used; the original immutable full descriptor is just borrowed metadata.
}

#[test]
fn stored_value_numeric_semantics_refuse_nonfinite_or_unsupported_metadata_without_fallback() {
    for number in ["1e400", "-1e400", "1e9999999999999999999999999999"] {
        let raw = format!(
            r#"{{"format":1,"methods":{{"sql":{{"name":"x","kind":"query","cache":false,"watch":false,"terminal":{{"catalog":"app","operation":"query","finalizer":"f","signingKeys":[{{"usages":["sign"],"extra":{number}}}]}}}}}}}}"#
        );
        assert!(serde_json::from_slice::<Value>(raw.as_bytes()).is_err());
        assert_eq!(
            classified(raw.as_bytes(), "sql").err(),
            Some(Error::Unsupported)
        );
        assert_eq!(
            classified(raw.as_bytes(), "unmatched").err(),
            Some(Error::Unsupported)
        );
    }
    let mut value = method("query");
    value["terminal"]["signingKeys"] = json!([{"usages":["sign"],"extra":[f64::MAX,f64::MIN,f64::MIN_POSITIVE,5e-324,u64::MAX,i64::MIN]}]);
    let raw = real_registry(value, "sql");
    assert_eq!(classified(&raw, "sql"), Ok(false));
}

#[test]
fn all_real_identifier_reserved_names_empty_public_names_and_missing_signer_defaults_match() {
    for name in [
        "sql_tables",
        "sql_columns",
        "sql_relationships",
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
        "app",
        "a_012",
        "_app",
        "App",
        "a-pp",
        "é",
        "a\0",
    ] {
        let mut value = method("query");
        value["terminal"]["catalog"] = json!(name);
        let actual: reference::HttpMethod = serde_json::from_value(value.clone()).unwrap();
        let valid = actual.terminal.unwrap().validate().is_ok();
        assert_eq!(
            classified(&encoded_registry(value, "sql"), "sql").is_ok(),
            valid
        );
    }
    for name in ["", &"a".repeat(256)] {
        let mut value = method("query");
        value["name"] = json!(name);
        let raw = real_registry(value, "sql");
        assert_eq!(classified(&raw, "sql"), Ok(false));
    }
    let raw = real_registry(method("query"), "");
    assert_eq!(classified(&raw, "ordinary"), Ok(true));
}

#[test]
fn all_existing_key_slots_support_real_bounded_signer_values_above_native_request_key_cap() {
    let mut value = method("query");
    value["terminal"]["signingKeys"] =
        json!([{"usages":["sign"],"extra":vec![json!({"":0});4200]}]);
    let raw = real_registry(value, "sql");
    assert!(raw.len() <= 32768);
    let pool = pool();
    let check = control();
    let mut flight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = flight.lookup_name(br#"{"name":"sql"}"#, &check).unwrap();
    let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
    let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(&raw));
    assert_eq!((n, bytes), (0, 0));
    assert!(result.unwrap().terminal().is_some());
}

#[test]
fn malformed_signer_tail_decoded_duplicates_and_overlong_method_finalizer_always_deny() {
    for (field, len) in [("name", 257), ("finalizer", 385)] {
        let mut value = method("query");
        if field == "name" {
            value[field] = json!("x".repeat(len));
        } else {
            value["terminal"][field] = json!("x".repeat(len));
        }
        assert_eq!(
            classified(&encoded_registry(value, "sql"), "sql").err(),
            Some(Error::Capacity)
        );
    }
    let entry = serde_json::to_string(&method("query")).unwrap();
    for keys in [
        r#"[{"usages":["sign"],"u\u0073ages":["sign"]}]"#,
        r#"[{"usages":["sign"],"extra":{"x":1,"\u0078":2}}]"#,
        r#"[{"usages":["sign"]},{"usages":["read"]}]"#,
        r#"[{"name":"é","usages":["sign"]},{"name":"\u00e9","usages":["sign"]}]"#,
        r#"[{"usages":["sign","\ud800"]}]"#,
    ] {
        let raw = format!(
            r#"{{"format":1,"methods":{{"sql":{}}}}}"#,
            entry.replace("\"signingKeys\":[]", &format!("\"signingKeys\":{keys}"))
        );
        for name in ["sql", "ordinary"] {
            assert!(classified(raw.as_bytes(), name).is_err());
        }
    }
}

#[test]
fn dropping_and_recreating_classifier_cannot_reset_cumulative_work_or_failure() {
    let pool = pool();
    let check = control();
    let mut flight = Preflight::new(
        &pool,
        Limits {
            work: 540000,
            ..Limits::default()
        },
        &check,
    )
    .unwrap();
    let lookup = flight
        .lookup_name(br#"{"name":"ordinary"}"#, &check)
        .unwrap();
    let empty = b"{\"format\":1,\"methods\":{}}";
    for _ in 0..2 {
        let before = flight.remaining;
        {
            let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
            let (result, n, bytes) = allocation_probe::measure(|| classifier.classify(empty));
            assert_eq!((n, bytes), (0, 0));
            assert!(result.unwrap().is_ordinary());
        }
        assert!(flight.remaining < before);
    }
    {
        let mut classifier = flight.registry_classifier(&lookup, &check).unwrap();
        assert_eq!(classifier.classify(empty).err(), Some(Error::WorkLimit));
    }
    assert_eq!(
        flight.registry_classifier(&lookup, &check).err(),
        Some(Error::WorkLimit)
    );
    assert_eq!(
        flight.parse_lookup(&lookup, Transport::Query, &check).err(),
        Some(Error::WorkLimit)
    );
}

struct Permissive(AtomicUsize);
impl Check for Permissive {
    fn check(&self) -> Result<(), Error> {
        self.0.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
#[repr(C)]
struct SameAddressCheck {
    alternative: Permissive,
    calls: AtomicUsize,
    at: AtomicUsize,
}
impl Check for SameAddressCheck {
    fn check(&self) -> Result<(), Error> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= self.at.load(Ordering::Relaxed) {
            Err(Error::Deadline)
        } else {
            Ok(())
        }
    }
}
#[test]
fn same_address_compatibility_argument_never_changes_actual_retained_checker_execution() {
    let original = SameAddressCheck {
        alternative: Permissive(AtomicUsize::new(0)),
        calls: AtomicUsize::new(0),
        at: AtomicUsize::new(usize::MAX),
    };
    assert_eq!(
        (&original as *const SameAddressCheck).cast::<u8>(),
        (&original.alternative as *const Permissive).cast::<u8>()
    );
    let pool = pool();
    let mut flight = Preflight::new(&pool, Limits::default(), &original).unwrap();
    let lookup = flight
        .lookup_name(br#"{"name":"ordinary"}"#, &original.alternative)
        .unwrap();
    let mut classifier = flight
        .registry_classifier(&lookup, &original.alternative)
        .unwrap();
    original.calls.store(0, Ordering::Relaxed);
    original.at.store(20, Ordering::Relaxed);
    let (result, n, bytes) =
        allocation_probe::measure(|| classifier.classify(b"{\"format\":1,\"methods\":{}}"));
    assert_eq!((n, bytes), (0, 0));
    assert_eq!(result.err(), Some(Error::Deadline));
    assert_eq!(original.alternative.0.load(Ordering::Relaxed), 0);
    original.at.store(usize::MAX, Ordering::Relaxed);
    assert_eq!(
        classifier.classify(b"{\"format\":1,\"methods\":{}}").err(),
        Some(Error::Deadline)
    );
}
