use super::*;
use crate::allocation_probe;
use std::time::Duration;
static NEVER: AtomicBool = AtomicBool::new(false);

#[test]
fn large_valid_parameter_does_not_pay_raw_and_decoded_bytes_against_one_cap() {
    // The raw <=1MiB and decoded <=1MiB owners are distinct, precisely admitted
    // mappings, not a guessed multiplier or a post-decode memory reservation.
    let body = format!(
        r#"{{"name":"native","args":{{"sql":"select ?1","parameters":["{}"]}}}}"#,
        "x".repeat(900 * 1024)
    );
    let pool = Pool::new(8 * 1024 * 1024, 4);
    let check = Control::new(Instant::now() + Duration::from_secs(30), &NEVER);
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let header = preflight
        .parse(body.as_bytes(), Transport::Query, &check)
        .unwrap();
    let mut owned = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
    owned.import(&header).unwrap();
    let (query, n, bytes) = allocation_probe::measure(|| owned.query_args());
    assert_eq!((n, bytes), (0, 0));
    let query = query.unwrap();
    assert_eq!(query.sql(), "select ?1");
    assert!(
        matches!(query.parameters().next(), Some(NativeParameter::Text(value)) if value.len() == 900 * 1024)
    );
    assert_eq!(owned.args_json().unwrap(), header.args_json());
}

#[test]
fn owned_reduced_decoded_capacity_fails_before_output_growth() {
    let pool = Pool::new(8 * 1024 * 1024, 4);
    let check = Control::new(Instant::now() + Duration::from_secs(30), &NEVER);
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let header = preflight
        .parse(
            br#"{"name":"native","args":{"sql":"select 1"}}"#,
            Transport::Query,
            &check,
        )
        .unwrap();
    let mut owned = NativeInput::new(
        &pool,
        OwnedLimits {
            decoded_bytes: 4,
            ..OwnedLimits::default()
        },
        &check,
    )
    .unwrap();
    owned.import(&header).unwrap();
    let (result, n, bytes) = allocation_probe::measure(|| owned.query_args());
    assert_eq!(result.err(), Some(Error::Capacity));
    assert_eq!((n, bytes), (0, 0));
    assert_eq!(owned.args_json().err(), Some(Error::Capacity));
}

#[test]
fn row_limit_matches_current_sqlite_maximum_and_is_static_on_overflow() {
    let pool = Pool::new(8 * 1024 * 1024, 4);
    let check = Control::new(Instant::now() + Duration::from_secs(30), &NEVER);
    let mut preflight = Preflight::new(&pool, Limits::default(), &check).unwrap();
    let header = preflight
        .parse(br#"{"name":"native"}"#, Transport::Query, &check)
        .unwrap();
    for (raw, okay) in [
        (br#"{"sql":"select 1","maxRows":1000}"#.as_slice(), true),
        (br#"{"sql":"select 1","maxRows":1001}"#.as_slice(), false),
    ] {
        let mut owned = NativeInput::new(&pool, OwnedLimits::default(), &check).unwrap();
        owned.import(&header).unwrap();
        let (result, n, bytes) = allocation_probe::measure(|| owned.query_json(raw));
        assert_eq!((n, bytes), (0, 0));
        assert_eq!(result.is_ok(), okay);
    }
}

#[test]
fn all_native_owners_are_send_and_sync_without_unchecked_control_sharing() {
    fn check<T: Send + Sync>() {}
    check::<Preflight<'static>>();
    check::<NativeInput<'static>>();
    check::<NativeQuery<'static>>();
    check::<Header<'static>>();
    check::<NameLookup<'static>>();
}
