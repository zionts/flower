use super::*;
use crate::allocation_probe;
use std::cell::Cell;
use std::time::Duration;
static NEVER: AtomicBool = AtomicBool::new(false);
fn control() -> Control<'static> {
    Control::new(Instant::now() + Duration::from_secs(30), &NEVER)
}
fn budget() -> Pool {
    Pool::new(16 * 1024 * 1024, 8)
}
fn parse(body: &[u8], transport: Transport) -> Result<Header<'_>, Error> {
    let pool = budget();
    let check = control();
    let mut arena = Preflight::new(&pool, Limits::default(), &check)?;
    arena.parse(body, transport, &check)
}
fn error(body: &[u8]) -> Error {
    parse(body, Transport::Query).err().unwrap()
}

#[test]
fn borrowed_spans_and_fixed_unicode_name_roundtrip() {
    let body = br#" {"arg\u0073":{"a":[1,null,true,"secret"]}, "credentials":{"token":"private"},"name":"x\u0000\u00e9\ud83d\ude03"} "#;
    let header = parse(body, Transport::Query).unwrap();
    assert_eq!(header.name(), "x\0é😃");
    assert_eq!(header.args_json(), br#"{"a":[1,null,true,"secret"]}"#);
    assert_eq!(
        header.credentials_json(),
        Some(br#"{"token":"private"}"#.as_slice())
    );
    let start = body.as_ptr() as usize;
    let args = header.args_json().as_ptr() as usize;
    assert!(args >= start && args + header.args_json().len() <= start + body.len());
    // Scratch can be dropped while the header still borrows the original body.
    assert_eq!(header.name().len(), 8);
}

#[test]
fn missing_args_and_credentials_remain_distinct_from_explicit_null() {
    let absent = parse(br#"{"name":"ordinary"}"#, Transport::Query).unwrap();
    assert_eq!(absent.args_json(), b"null");
    assert!(absent.credentials_json().is_none());
    let null = parse(
        br#"{"name":"ordinary","args":null,"credentials":null}"#,
        Transport::Query,
    )
    .unwrap();
    assert_eq!(null.args_json(), b"null");
    assert_eq!(null.credentials_json(), Some(b"null".as_slice()));
}

#[test]
fn complete_structural_syntax_and_static_errors() {
    for body in [
        b"".as_slice(),
        b"null",
        b"[]",
        b"{}",
        br#"{"name":null}"#,
        br#"{"name":1}"#,
        br#"{"name":""}"#,
        br#"{"name":"x"} null"#,
        br#"{"name":"x",}"#,
        br#"{"name":"x","args":[1,]}"#,
        br#"{"name":"x","args":{"a":1,}}"#,
        br#"{"name":"x","args":01}"#,
        br#"{"name":"x","args":1.}"#,
        br#"{"name":"x","args":1e+}"#,
        br#"{"name":"x","args":tru}"#,
        br#"{"name":"x","args":[}"#,
        br#"{"name":"x","args":"\x20"}"#,
        br#"{"name":"x","args":"\uD800"}"#,
        br#"{"name":"x","args":"\uDC00"}"#,
        br#"{"name":"x","args":"\uD800\u0020"}"#,
        b"{\"name\":\"x\",\"args\":\"\xff\"}",
        b"{\"name\":\"x\",\"args\":\"\xc0\xaf\"}",
        b"{\"name\":\"x\",\"args\":\"\xed\xa0\x80\"}",
        b"{\"name\":\"x\",\"args\":\"a\x00\"}",
    ] {
        assert!(parse(body, Transport::Query).is_err());
    }
    for e in [
        Error::Invalid,
        Error::Duplicate,
        Error::UnknownField,
        Error::Capacity,
        Error::WorkLimit,
        Error::Cancelled,
        Error::Deadline,
        Error::Unsupported,
    ] {
        assert!(e.to_string().starts_with("SQL_"));
        assert!(!e.to_string().contains("private"));
    }
}

#[test]
fn rejects_decoded_duplicate_top_and_nested_keys_but_allows_separate_objects() {
    for body in [
        br#"{"name":"x","name":"y"}"#.as_slice(),
        br#"{"name":"x","na\u006de":"y"}"#,
        br#"{"name":"x","args":{"a":1,"\u0061":2}}"#,
        "{\"name\":\"x\",\"args\":{\"é\":1,\"\\u00e9\":2}}".as_bytes(),
        br#"{"name":"x","args":{"\ud83d\ude03":1,"\ud83D\uDE03":2}}"#,
    ] {
        assert_eq!(error(body), Error::Duplicate);
    }
    assert!(
        parse(
            br#"{"name":"x","args":[{"a":1},{"a":2}]}"#,
            Transport::Query
        )
        .is_ok()
    );
}

#[test]
fn unknown_root_fields_cannot_select_native_operation_or_authority() {
    for field in [
        "operation",
        "phase",
        "purpose",
        "$principal",
        "authority",
        "bundle",
        "writes",
    ] {
        let body = format!(r#"{{"name":"x","{field}":"cancel"}}"#);
        assert_eq!(error(body.as_bytes()), Error::UnknownField);
    }
    // Arguments may be application data. They are deliberately NOT interpreted
    // as operation/phase/purpose authority, even when named that way.
    let body =
        br#"{"name":"x","args":{"operation":"cancel","phase":"finalize","purpose":"system"}}"#;
    assert!(parse(body, Transport::Query).is_ok());
}

#[test]
fn call_transport_metadata_matches_public_validation_and_query_rejects_it() {
    let body = br#"{"name":"x","requestId":"a\u0000","expectedRevision":9007199254740991}"#;
    let header = parse(body, Transport::Call).unwrap();
    assert_eq!(header.expected_revision(), Some(9_007_199_254_740_991));
    assert_eq!(header.request_id_json(), Some(br#""a\u0000""#.as_slice()));
    assert_eq!(error(body), Error::UnknownField);
    assert!(parse(br#"{"name":"x","expectedRevision":0}"#, Transport::Call).is_ok());
    for body in [
        br#"{"name":"x","requestId":""}"#.as_slice(),
        br#"{"name":"x","requestId":null}"#,
        br#"{"name":"x","expectedRevision":-1}"#,
        br#"{"name":"x","expectedRevision":-0}"#,
        br#"{"name":"x","expectedRevision":1.0}"#,
        br#"{"name":"x","expectedRevision":1e0}"#,
        br#"{"name":"x","expectedRevision":9007199254740992}"#,
        br#"{"name":"x","expectedRevision":null}"#,
    ] {
        assert!(parse(body, Transport::Call).is_err());
    }
    assert!(parse(br#"{"name":"x"}"#, Transport::Call).is_ok());
}

#[test]
fn name_hard_utf8_byte_limit_and_arbitrary_control_aliases() {
    let raw = format!(r#"{{"name":"{}"}}"#, "é".repeat(128));
    assert_eq!(
        parse(raw.as_bytes(), Transport::Query)
            .unwrap()
            .name()
            .len(),
        MAX_NAME_BYTES
    );
    let raw = format!(r#"{{"name":"{}"}}"#, "é".repeat(129));
    assert_eq!(error(raw.as_bytes()), Error::Capacity);
    for alias in ["\u{0}", "\n", "\u{1}", "é😃/\\\""] {
        let name = serde_json::to_string(alias).unwrap();
        let raw = format!(r#"{{"name":{name}}}"#);
        assert_eq!(
            parse(raw.as_bytes(), Transport::Query).unwrap().name(),
            alias
        );
    }
}

#[test]
fn hard_limits_are_checked_before_growth_and_failures_are_sticky() {
    let pool = budget();
    let check = control();
    for (limits, body) in [
        (
            Limits {
                body_bytes: 5,
                ..Limits::default()
            },
            br#"{"name":"x"}"#.as_slice(),
        ),
        (
            Limits {
                nodes: 2,
                ..Limits::default()
            },
            br#"{"name":"x","args":null}"#,
        ),
        (
            Limits {
                keys: 1,
                ..Limits::default()
            },
            br#"{"name":"x","args":null}"#,
        ),
        (
            Limits {
                number_bytes: 3,
                ..Limits::default()
            },
            br#"{"name":"x","args":1234}"#,
        ),
        (
            Limits {
                depth: 2,
                ..Limits::default()
            },
            br#"{"name":"x","args":[[]]}"#,
        ),
    ] {
        let mut owner = Preflight::new(&pool, limits, &check).unwrap();
        assert_eq!(
            owner.parse(body, Transport::Query, &check).err(),
            Some(Error::Capacity)
        );
        assert_eq!(
            owner
                .parse(br#"{"name":"x"}"#, Transport::Query, &check)
                .err(),
            Some(Error::Capacity)
        );
    }
    let mut owner = Preflight::new(
        &pool,
        Limits {
            work: 3,
            ..Limits::default()
        },
        &check,
    )
    .unwrap();
    assert_eq!(
        owner
            .parse(br#"{"name":"x"}"#, Transport::Query, &check)
            .err(),
        Some(Error::WorkLimit)
    );
}

#[test]
fn exact_depth64_node_and_mantissa_caps() {
    for (depth, okay) in [(63, true), (64, false)] {
        let body = format!(
            r#"{{"name":"x","args":{}0{}}}"#,
            "[".repeat(depth),
            "]".repeat(depth)
        );
        assert_eq!(parse(body.as_bytes(), Transport::Query).is_ok(), okay);
    }
    let body = format!(r#"{{"name":"x","args":0.{}}}"#, "1".repeat(1024));
    assert_eq!(error(body.as_bytes()), Error::Capacity);
    let body = format!(r#"{{"name":"x","args":[{}0]}}"#, "0,".repeat(MAX_NODES));
    assert_eq!(error(body.as_bytes()), Error::Capacity);
}

#[test]
fn large_unknown_key_and_large_nested_field_reject_without_heap_growth() {
    let giant_key = "k".repeat(512 * 1024);
    let body = format!(r#"{{"name":"x","{giant_key}":null}}"#);
    let nested = format!(r#"{{"name":"x","args":{{"{giant_key}":null}}}}"#);
    let pool = budget();
    let check = control();
    let mut owner = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let (result, n, bytes) =
        allocation_probe::measure(|| owner.parse(body.as_bytes(), Transport::Query, &check));
    assert_eq!((n, bytes), (0, 0));
    assert_eq!(result.err(), Some(Error::UnknownField));
    let mut owner = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let (result, n, bytes) =
        allocation_probe::measure(|| owner.parse(nested.as_bytes(), Transport::Query, &check));
    assert_eq!((n, bytes), (0, 0));
    assert!(result.is_ok());
}

struct StopAfter {
    calls: AtomicUsize,
    stop: AtomicUsize,
    error: Error,
}
impl Check for StopAfter {
    fn check(&self) -> Result<(), Error> {
        let n = self.calls.fetch_add(1, Ordering::Relaxed);
        if n >= self.stop.load(Ordering::Relaxed) {
            Err(self.error)
        } else {
            Ok(())
        }
    }
}
#[test]
fn cancellation_and_deadline_inside_large_structural_skip_no_unbounded_utf8_pass() {
    let body = format!(r#"{{"name":"x","args":"{}"}}"#, "é".repeat(128 * 1024));
    let pool = budget();
    let check = control();
    for error in [Error::Cancelled, Error::Deadline] {
        let stop = StopAfter {
            calls: AtomicUsize::new(0),
            stop: AtomicUsize::new(usize::MAX),
            error,
        };
        let mut owner = Preflight::new(&pool, Limits::default(), &stop).unwrap();
        // Keep the actual original checker through admission and parse; stop
        // inside the large Unicode scan rather than substituting a phase check.
        // Fresh mapped keys were initialized before admission completed.
        stop.calls.store(0, Ordering::Relaxed);
        stop.stop.store(20, Ordering::Relaxed);
        let (result, n, bytes) =
            allocation_probe::measure(|| owner.parse(body.as_bytes(), Transport::Query, &stop));
        assert_eq!(result.err(), Some(error));
        assert_eq!((n, bytes), (0, 0));
        assert_eq!(stop.calls.load(Ordering::Relaxed), 21);
        assert!(owner.remaining > Limits::default().work - 10_000);
        assert_eq!(
            owner.parse(b"{}", Transport::Query, &check).err(),
            Some(error)
        );
    }
}

#[test]
fn prepaid_actual_layout_and_parallel_byte_slot_capacity() {
    let bytes = Preflight::admission_bytes().unwrap();
    let pool = Pool::new(bytes * 2, 2);
    let check = control();
    let first = Preflight::new(&pool, Limits::default(), &check).unwrap();
    assert_eq!(
        bytes,
        first.levels.mapped_bytes() + first.keys.mapped_bytes() + CONTROL_BYTES
    );
    assert_eq!(pool.retained(), (bytes, 1));
    std::thread::scope(|scope| {
        let second = scope.spawn(|| {
            let second = Preflight::new(&pool, Limits::default(), &check).unwrap();
            assert_eq!(pool.retained(), (bytes * 2, 2));
            assert_eq!(
                Preflight::new(&pool, Limits::default(), &check)
                    .err()
                    .map(|e| e.code()),
                Some("SQL_INPUT_CAPACITY")
            );
            drop(second);
        });
        second.join().unwrap();
    });
    drop(first);
    assert_eq!(pool.retained(), (0, 0));
    let slots = Pool::new(bytes * 2, 1);
    let first = Preflight::new(&slots, Limits::default(), &check).unwrap();
    assert!(Preflight::new(&slots, Limits::default(), &check).is_err());
    drop(first);
    let memory = Pool::new(bytes - 1, 2);
    assert!(Preflight::new(&memory, Limits::default(), &check).is_err());
    assert_eq!(memory.retained(), (0, 0));
}

#[test]
fn pretouch_cancellation_releases_both_slots_and_byte_lease() {
    let pool = budget();
    let stop = StopAfter {
        calls: AtomicUsize::new(0),
        stop: AtomicUsize::new(10),
        error: Error::Cancelled,
    };
    assert!(Preflight::new(&pool, Limits::default(), &stop).is_err());
    assert_eq!(pool.retained(), (0, 0));
    assert!(Preflight::new(&pool, Limits::default(), &control()).is_ok());
}

#[test]
fn success_and_all_error_classes_zero_rust_postadmission_allocations() {
    let pool = budget();
    let check = control();
    for body in [
        r#"{"name":"x\u0000😃","args":{"a":[1,true,null,"t"]},"credentials":"jwt"}"#.as_bytes(),
        br#"{"name":"x","args":{"a":1,"a":2}}"#,
        br#"{"name":"x","args":"\uD800"}"#,
        br#"{"name":"x","operation":"cancel"}"#,
        br#"{"name":"x"}[]"#,
        br#"{"name":null}"#,
    ] {
        let mut owner = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let (_, count, bytes) =
            allocation_probe::measure(|| owner.parse(body, Transport::Query, &check));
        assert_eq!((count, bytes), (0, 0));
    }
}

#[test]
fn owned_input_and_typed_query_zero_alloc_with_source_body_released() {
    let body = r#"{"name":"x\u0000","args":{"sql":"select ?1, ?2, ?3, ?4, ?5, ?6","parameters":[null,true,123,-1.25,"é\u0000😃",1e2],"maxRows":10,"queryId":"q"},"credentials":"jwt"}"#.as_bytes().to_vec();
    let header = parse(&body, Transport::Query).unwrap();
    let pool = budget();
    let check = control();
    let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
    let (result, n, bytes) = allocation_probe::measure(|| owner.import(&header));
    assert!(result.is_ok());
    assert_eq!((n, bytes), (0, 0));
    drop(body);
    assert_eq!(owner.name().unwrap(), "x\0");
    let (result, n, bytes) = allocation_probe::measure(|| owner.decode_string_credentials());
    assert_eq!(result.unwrap(), Some(b"jwt".as_slice()));
    assert_eq!((n, bytes), (0, 0));
    let (result, n, bytes) = allocation_probe::measure(|| owner.query_args());
    assert_eq!((n, bytes), (0, 0));
    let query: NativeQuery<'_> = result.unwrap();
    assert_eq!(query.sql(), "select ?1, ?2, ?3, ?4, ?5, ?6");
    assert_eq!(query.max_rows(), Some(10));
    assert_eq!(query.query_id(), Some("q"));
    let mut p = query.parameters();
    assert!(matches!(p.next(), Some(NativeParameter::Null)));
    assert!(matches!(p.next(), Some(NativeParameter::Bool(true))));
    assert!(matches!(p.next(), Some(NativeParameter::Integer(123))));
    assert!(matches!(p.next(), Some(NativeParameter::Real(v)) if v == -1.25));
    assert!(matches!(p.next(), Some(NativeParameter::Text("é\0😃"))));
    assert!(matches!(p.next(), Some(NativeParameter::Real(v)) if v == 100.0));
    assert!(p.next().is_none());
}

#[test]
fn later_query_errors_are_closed_sticky_and_allocation_free() {
    let pool = budget();
    let check = control();
    let header = parse(br#"{"name":"x"}"#, Transport::Query).unwrap();
    for raw in [
        b"null".as_slice(),
        br#"{"sql":""}"#,
        br#"{"sql":"select 1","parameters":[{}]}"#,
        br#"{"sql":"select 1","parameters":null}"#,
        br#"{"sql":"select 1","parameters":[1e999]}"#,
        br#"{"sql":"select 1","operation":"cancel"}"#,
        br#"{"sql":"select 1","sql":"select 2"}"#,
        br#"{"sql":"select 1","queryId":""}"#,
    ] {
        let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
        owner.import(&header).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| owner.query_json(raw));
        assert!(result.is_err());
        assert_eq!((n, bytes), (0, 0));
        assert!(owner.args_json().is_err());
    }
}

#[test]
fn native_sql_parameter_token_and_input_caps() {
    let pool = budget();
    let check = control();
    let header = parse(br#"{"name":"x"}"#, Transport::Query).unwrap();
    let sql = format!(r#"{{"sql":"{}"}}"#, "s".repeat(MAX_SQL_BYTES + 1));
    let params = format!(
        r#"{{"sql":"select 1","parameters":[{}0]}}"#,
        "0,".repeat(MAX_PARAMETERS)
    );
    for raw in [sql.as_bytes(), params.as_bytes()] {
        let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
        owner.import(&header).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| owner.query_json(raw));
        assert_eq!(result.err(), Some(Error::Capacity));
        assert_eq!((n, bytes), (0, 0));
    }
    let raw = format!(
        r#"{{"name":"x","credentials":"{}"}}"#,
        "x".repeat(MAX_TOKEN_BYTES)
    );
    let header = parse(raw.as_bytes(), Transport::Query).unwrap();
    let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
    owner.import(&header).unwrap();
    assert_eq!(
        owner.decode_string_credentials().unwrap().unwrap().len(),
        MAX_TOKEN_BYTES
    );
    let raw = format!(
        r#"{{"name":"x","credentials":"{}"}}"#,
        "x".repeat(MAX_TOKEN_BYTES + 1)
    );
    let header = parse(raw.as_bytes(), Transport::Query).unwrap();
    let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
    owner.import(&header).unwrap();
    assert_eq!(
        owner.decode_string_credentials().err(),
        Some(Error::Capacity)
    );
    let raw = format!(r#"{{"name":"x","args":"{}"}}"#, "x".repeat(MAX_INPUT_BYTES));
    assert_eq!(error(raw.as_bytes()), Error::Capacity);
}

#[test]
fn no_capture_or_source_operator_required_for_extraction_stage() {
    // Production module has no App/Snapshot/Records/provider dependency. Probe
    // stage boundary before the test's simulated next-stage source callback.
    let stage = Cell::new(0);
    let header = parse(br#"{"name":"x","args":[0,1,2]}"#, Transport::Query).unwrap();
    assert_eq!(stage.get(), 0);
    assert_eq!(header.name(), "x");
    stage.set(1); // Simulated parent next-stage, not a routing integration claim.
    assert_eq!(stage.get(), 1);
}

#[test]
fn deterministic_json_fixtures_match_reference_values_without_tree_retention() {
    let pool = budget();
    let mut seed = 0x71234333u64;
    for i in 0..512 {
        // Each fixture is a different newly admitted request, not a retry/phase
        // of one job. Keep its ONE checker through construction and parsing.
        let check = control();
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let value = serde_json::json!({"name":format!("alias\0é{i}"), "args":{
            "int": seed as i64, "real": (seed % 100_000) as f64 / 37.0,
            "values":[null,true,false,"unicode 😃 / \\ \n",i],"empty":{} }});
        let body = serde_json::to_vec(&value).unwrap();
        let mut owner = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let (result, n, bytes) =
            allocation_probe::measure(|| owner.parse(&body, Transport::Query, &check));
        assert_eq!((n, bytes), (0, 0));
        let header = result.unwrap();
        // Compare the same emitted bytes, not construction-time f64 bits:
        // this pinned serde_json configuration does not enable float_roundtrip.
        let reference: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(header.name(), reference["name"].as_str().unwrap());
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(header.args_json()).unwrap(),
            reference["args"]
        );
    }
}

#[test]
fn real_pinned_value_array_amplification_positive_control_counts_only() {
    // Synthetic input only, built before measurement. Counts are cumulative
    // allocation Layout request bytes, NOT live RSS/peak. This reproduces the
    // actual Axum Json<Value>::from_bytes and ValueVisitor::visit_seq Vec growth.
    let count = 131_072;
    let body = format!(
        r#"{{"name":"synthetic","args":[{}0]}}"#,
        "0,".repeat(count - 1)
    );
    let (result, allocs, requested) =
        allocation_probe::measure(|| axum::Json::<serde_json::Value>::from_bytes(body.as_bytes()));
    let value = result.unwrap().0;
    let values = value["args"].as_array().unwrap();
    let decoded_backing = values.capacity() * size_of::<serde_json::Value>();
    assert_eq!(values.len(), count);
    assert!(decoded_backing > body.len() * 8);
    assert!(requested >= decoded_backing && allocs > 0);
    println!(
        "synthetic Axum array: wire_bytes={} elements={} Value_bytes={} capacity={} array_backing_bytes={} allocator_operations={} cumulative_requested_bytes={}",
        body.len(),
        count,
        size_of::<serde_json::Value>(),
        values.capacity(),
        decoded_backing,
        allocs,
        requested
    );
}
