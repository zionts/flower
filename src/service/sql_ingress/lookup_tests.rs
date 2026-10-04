use super::*;
use crate::allocation_probe;
use std::time::Duration;
static NEVER: AtomicBool = AtomicBool::new(false);
fn control() -> Control<'static> {
    Control::new(Instant::now() + Duration::from_secs(30), &NEVER)
}
fn budget() -> Pool {
    Pool::new(16 * 1024 * 1024, 8)
}

#[test]
fn discovery_preserves_ordinary_large_arrays_keys_mantissas_and_depth() {
    let pool = budget();
    let check = control();
    let many_keys = (0..5000)
        .map(|i| format!(r#""k{i}":0"#))
        .collect::<Vec<_>>()
        .join(",");
    let fixtures = [
        format!(r#"{{"args":[{}0],"name":"ordinary"}}"#, "0,".repeat(70_000)),
        format!(r#"{{"args":{{{many_keys}}},"name":"ordinary"}}"#),
        format!(r#"{{"args":0.{},"name":"ordinary"}}"#, "1".repeat(2048)),
        format!(
            r#"{{"args":{}0{},"name":"ordinary"}}"#,
            "[".repeat(100),
            "]".repeat(100)
        ),
        r#"{"args":{"a":1,"a":2},"name":"ignored","na\u006de":"ordinary"}"#.to_owned(),
    ];
    for body in fixtures {
        let reference: serde_json::Value = serde_json::from_slice(body.as_bytes()).unwrap();
        let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let (result, n, bytes) =
            allocation_probe::measure(|| preflight.lookup_name(body.as_bytes(), &check));
        assert_eq!((n, bytes), (0, 0));
        let lookup = result.unwrap();
        assert_eq!(lookup.name().unwrap(), reference["name"].as_str().unwrap());
        // An actual parent registry would now prove ordinary and keep its
        // original route; do not apply the closed native envelope to that tree.
        assert!(
            preflight
                .parse_lookup(&lookup, Transport::Query, &check)
                .is_err()
        );
    }
}

#[test]
fn discovery_matches_pinned_ordinary_recursion_boundary() {
    let pool = budget();
    let check = control();
    for nested in [125, 126, 127, 128] {
        let body = format!(
            r#"{{"args":{}0{},"name":"ordinary"}}"#,
            "[".repeat(nested),
            "]".repeat(nested)
        );
        let reference = serde_json::from_slice::<serde_json::Value>(body.as_bytes()).is_ok();
        let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let native = preflight.lookup_name(body.as_bytes(), &check).is_ok();
        assert_eq!(native, reference, "depth fixture {nested}");
    }
}

#[test]
fn last_name_controls_lookup_but_native_duplicate_envelope_fails_closed() {
    let pool = budget();
    let check = control();
    for body in [
        br#"{"name":"ordinary","name":"native"}"#.as_slice(),
        br#"{"name":null,"na\u006de":"native"}"#,
        br#"{"name":"ordinary","na\u006de":"native","args":{"operation":"cancel"}}"#,
    ] {
        let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        let lookup = preflight.lookup_name(body, &check).unwrap();
        assert_eq!(lookup.name().unwrap(), "native");
        assert_eq!(
            preflight
                .parse_lookup(&lookup, Transport::Query, &check)
                .err(),
            Some(Error::Duplicate)
        );
    }
    for body in [
        br#"{"name":"native","name":null}"#.as_slice(),
        br#"{"name":"native","name":false}"#,
        br#"{"name":"native"} null"#,
    ] {
        let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
        assert!(preflight.lookup_name(body, &check).is_err());
    }
}

#[test]
fn complete_discovery_then_borrowed_native_header_no_tree_allocation_or_work_reset() {
    let pool = budget();
    let check = control();
    let body = br#"{"credentials":{"token":"sensitive"},"args":{"sql":"select 1"},"na\u006de":"native\u0000\ud83d\ude03"}"#;
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let (lookup, n, bytes) = allocation_probe::measure(|| preflight.lookup_name(body, &check));
    assert_eq!((n, bytes), (0, 0));
    let lookup = lookup.unwrap();
    assert_eq!(lookup.name().unwrap(), "native\0😃");
    let remaining = preflight.remaining;
    let (header, n, bytes) =
        allocation_probe::measure(|| preflight.parse_lookup(&lookup, Transport::Query, &check));
    assert_eq!((n, bytes), (0, 0));
    let header = header.unwrap();
    assert_eq!(header.name(), lookup.name().unwrap());
    assert!(preflight.remaining < remaining);
    assert_eq!(header.args_json(), br#"{"sql":"select 1"}"#);
    assert!(preflight.lookup_name(body, &check).is_err());
    assert!(
        preflight
            .parse_lookup(&lookup, Transport::Query, &check)
            .is_err()
    );
}

#[test]
fn oversized_name_is_opaque_not_ordinary_fallback_or_alias_truncation() {
    let pool = budget();
    let check = control();
    let oversized = "a".repeat(257);
    let body = format!(r#"{{"name":"{oversized}"}}"#);
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let lookup = preflight.lookup_name(body.as_bytes(), &check).unwrap();
    assert_eq!(lookup.decoded_len(), 257);
    assert_eq!(lookup.bounded_name(), None);
    assert_eq!(lookup.name(), Err(Error::Unsupported));
    assert_eq!(
        preflight
            .parse_lookup(&lookup, Transport::Query, &check)
            .err(),
        Some(Error::Unsupported)
    );
    // Earlier overlong aliases cannot hide a last native alias; complete syntax
    // discovery picks the final decoded name exactly as the actual Value parser.
    let body = format!(r#"{{"name":"{oversized}","name":"native"}}"#);
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    assert_eq!(
        preflight
            .lookup_name(body.as_bytes(), &check)
            .unwrap()
            .name()
            .unwrap(),
        "native"
    );
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
fn one_native_checker_reused_for_all_owned_phases_and_stop_is_sticky() {
    let pool = budget();
    let check = control();
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let header = preflight
        .parse(
            br#"{"name":"native","args":{"sql":"select 1"}}"#,
            Transport::Query,
            &check,
        )
        .unwrap();
    for error in [Error::Cancelled, Error::Deadline] {
        let fault = Fault(AtomicUsize::new(0));
        let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &fault).unwrap();
        owner.import(&header).unwrap();
        fault.0.store(
            if error == Error::Cancelled { 1 } else { 2 },
            Ordering::Release,
        );
        let (result, n, bytes) = allocation_probe::measure(|| owner.query_args());
        assert_eq!(result.err(), Some(error));
        assert_eq!((n, bytes), (0, 0));
        fault.0.store(0, Ordering::Release); // No reset through a later phase/same checker.
        assert_eq!(owner.args_json().err(), Some(error));
    }
}

#[test]
fn mapping_owner_initialization_and_quota_denial_have_zero_rust_allocations() {
    let pool = budget();
    let check = control();
    let (preflight, n, bytes) =
        allocation_probe::measure(|| Preflight::new(&pool, Limits::default(), &check));
    assert_eq!((n, bytes), (0, 0));
    drop(preflight.unwrap());
    let (owned, n, bytes) =
        allocation_probe::measure(|| NativeInput::new(&pool, OwnedLimits::default(), &check));
    assert_eq!((n, bytes), (0, 0));
    let owned = owned.unwrap();
    let exact = owned.mapped_charge_actual();
    assert_eq!(
        exact,
        NativeInput::admission_bytes(OwnedLimits::default()).unwrap()
    );
    drop(owned);
    assert_eq!(pool.retained(), (0, 0));
    let deny = Pool::new(1, 1);
    let (result, n, bytes) =
        allocation_probe::measure(|| Preflight::new(&deny, Limits::default(), &check));
    assert!(result.is_err());
    assert_eq!((n, bytes), (0, 0));
    let (result, n, bytes) =
        allocation_probe::measure(|| NativeInput::new(&deny, OwnedLimits::default(), &check));
    assert!(result.is_err());
    assert_eq!((n, bytes), (0, 0));
    println!(
        "preflight_charge_bytes={} native_input_charge_bytes={} combined_charge_bytes={}",
        Preflight::admission_bytes().unwrap(),
        exact,
        Preflight::admission_bytes().unwrap() + exact
    );
}

#[test]
fn fully_escaped_maximum_jwt_decodes_under_exact_native_limit() {
    let body = format!(
        r#"{{"name":"native","credentials":"{}"}}"#,
        "\\u0061".repeat(MAX_TOKEN_BYTES)
    );
    let pool = budget();
    let check = control();
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let header = preflight
        .parse(body.as_bytes(), Transport::Query, &check)
        .unwrap();
    let mut owner = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
    owner.import(&header).unwrap();
    let (result, n, bytes) = allocation_probe::measure(|| owner.decode_string_credentials());
    assert_eq!((n, bytes), (0, 0));
    let decoded = result.unwrap().unwrap();
    assert_eq!(decoded.len(), MAX_TOKEN_BYTES);
    assert!(decoded.iter().all(|b| *b == b'a'));
}
