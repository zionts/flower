use super::*;

fn config() -> Config {
    Config::parse(
        "org.spend,org.dailySpend,hourTotals,scopeSpend,chargeTotals",
        None,
        None,
    )
    .unwrap()
}
fn records_certificate(data: &Records, keys: &[&str]) -> MutationCertificate {
    MutationCertificate::new(
        DependencyCertificate {
            checks: keys
                .iter()
                .map(|id| (id.to_string(), Stamp::Record(data.version(id))))
                .collect(),
            bytes: 0,
        },
        data,
        2000,
    )
}
fn cell(value: i64) -> Value {
    json!({"name":"org.spend","args":null,"deps":[],"outcome":{"ok":true,"value":value}})
}
const CELL: &str = "cell:[\"org.spend\",null]";
const SOURCE: &str = "source:[\"org.dailySpend\",\"private-session-id\"]";

#[test]
fn all_failed_dependencies_are_counted_not_only_first_sorted_cell() {
    let mut data = Records::from([(CELL.into(), cell(1)), (SOURCE.into(), json!(1))]);
    let certificate = records_certificate(&data, &[CELL, SOURCE, "bundle"]);
    assert!(certificate.valid(&data));
    data.insert(CELL.into(), cell(2));
    data.insert(SOURCE.into(), json!(2));
    data.insert("bundle".into(), json!("private code"));
    assert!(!certificate.valid(&data));
    let config = config();
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.cell_record, 1);
    assert_eq!(report.mismatches.source_record, 1);
    assert_eq!(report.mismatches.other_record, 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
    assert!(!report.truncated);
    assert_eq!(report.names[0].cell_record, 1);
    assert_eq!(report.names[1].source_record, 1);

    // Specifically exercise the historical bias with cell as the FIRST key.
    let certificate =
        records_certificate(&Records::from([(CELL.into(), cell(0))]), &[CELL, SOURCE]);
    assert_eq!(certificate.reads.checks.keys().next().unwrap(), CELL);
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.cell_record, 1);
    assert_eq!(report.mismatches.source_record, 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
}

#[test]
fn cell_only_is_an_unsafe_counterfactual_not_a_repair_claim() {
    let mut data = Records::from([(CELL.into(), cell(1))]);
    let certificate = records_certificate(&data, &[CELL]);
    data.insert(CELL.into(), cell(2));
    let config = config();
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.cell_record, 1);
    assert_eq!(report.mismatches.non_cell(), 0);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "yes");
    assert_eq!(report.claim, "not_safe_repairability");
    assert!(!certificate.valid(&data));
}

fn window(data: &Records, marker: &str, lower: &str, upper: &str) -> Stamp {
    Stamp::Window {
        index: marker.into(),
        marker: Mutex::new(data.generation(marker)),
        lower: lower.into(),
        upper: upper.into(),
        entries: data
            .range_versions::<(Bound<&str>, Bound<&str>)>((
                Bound::Included(lower),
                Bound::Excluded(upper),
            ))
            .collect(),
    }
}
#[test]
fn changed_marker_unchanged_window_is_not_a_conflict_and_diagnostic_never_adopts() {
    let first = "ordered-entry:[\"hourTotals\",[\"score\"]]:a";
    let outside = "ordered-entry:[\"hourTotals\",[\"score\"]]:z";
    let marker = "index-range:[\"hourTotals\",[\"score\"]]";
    let mut data = Records::from([(first.into(), json!(1))]);
    let stamp = window(&data, marker, first, outside);
    let old_marker = data.generation(marker);
    let certificate = MutationCertificate::new(
        DependencyCertificate {
            checks: [("window:private-query-args".into(), stamp)].into(),
            bytes: 0,
        },
        &data,
        2000,
    );
    data.insert(outside.into(), json!(2));
    assert_ne!(data.generation(marker), old_marker);
    let config = config();
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.window, 0);
    assert!(!report.truncated);
    let Stamp::Window { marker: saved, .. } = certificate.reads.checks.values().next().unwrap()
    else {
        panic!()
    };
    assert_eq!(
        *saved.lock().unwrap(),
        old_marker,
        "diagnostics must not adopt"
    );
    assert!(certificate.valid(&data));
    assert_eq!(
        *saved.lock().unwrap(),
        data.generation(marker),
        "ordinary validation still adopts"
    );
    data.insert(first.into(), json!(3));
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.window, 1);
    assert_eq!(report.names[2].window, 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
    assert!(!certificate.valid(&data));
}

#[test]
fn marker_and_all_structural_clock_checks_are_independent() {
    let mut data = Records::from([(CELL.into(), cell(1)), (SOURCE.into(), json!(1))]);
    let marker = "collection:\"org.dailySpend\"";
    let certificate = MutationCertificate::new(
        DependencyCertificate {
            checks: [(marker.into(), Stamp::Marker(data.generation(marker)))].into(),
            bytes: 0,
        },
        &data,
        2000,
    );
    data.insert(SOURCE.into(), json!(2));
    data.insert("clock".into(), json!(2001));
    data.insert("source:malformed-private-id".into(), Value::Null);
    data.insert("reactive:active".into(), json!("invalid"));
    data.insert(CELL.into(), json!({"malformed":"private-value"}));
    data.insert(
        "deep".into(),
        (0..128).fold(Value::Null, |value, _| json!([value])),
    );
    let config = config();
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.marker, 1);
    assert_eq!(report.mismatches.invalid_depth, 1);
    assert_eq!(report.mismatches.invalid_source_ids, 1);
    assert_eq!(report.mismatches.invalid_graph_pointer, 1);
    assert_eq!(report.mismatches.invalid_reactive_index, 1);
    assert_eq!(report.mismatches.graph_shape, 1);
    assert_eq!(report.mismatches.invalid_clock, 0);
    assert_eq!(report.mismatches.clock_bound, 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
    assert!(!certificate.valid(&data));
    data.insert("clock".into(), json!("private invalid clock"));
    let report = certificate.conflicts(&data, &config, 1);
    assert_eq!(report.mismatches.invalid_clock, 1);
    assert_eq!(report.mismatches.clock_bound, 1);
}

#[test]
fn truncation_never_claims_cell_only_even_if_later_source_was_not_reached() {
    let mut data = Records::from([(CELL.into(), cell(1)), (SOURCE.into(), json!(1))]);
    let certificate = records_certificate(&data, &[CELL, SOURCE]);
    data.insert(CELL.into(), cell(2));
    data.insert(SOURCE.into(), json!(2));
    for limit in [1, 7, 8] {
        let mut config = config();
        config.max_checks = limit;
        let report = certificate.conflicts(&data, &config, 1);
        assert_eq!(report.checks_inspected, limit);
        assert!(report.truncated);
        assert_eq!(report.ignoring_all_cell_versions_upper_bound, "unknown");
        if limit == 8 {
            assert_eq!(report.mismatches.cell_record, 1);
            assert_eq!(report.mismatches.source_record, 0);
        }
    }
    let mut config = config();
    config.max_checks = 9;
    let report = certificate.conflicts(&data, &config, 1);
    assert!(!report.truncated, "exact budget is complete, not truncated");
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
}

#[test]
fn window_entry_walk_and_final_absence_check_share_the_inspection_budget() {
    let a = "ordered-entry:[\"hourTotals\",[\"score\"]]:a";
    let z = "ordered-entry:[\"hourTotals\",[\"score\"]]:z";
    let marker = "index-range:[\"hourTotals\",[\"score\"]]";
    let mut data = Records::from([(a.into(), json!(1))]);
    let certificate = MutationCertificate::new(
        DependencyCertificate {
            checks: [("window:private".into(), window(&data, marker, a, z))].into(),
            bytes: 0,
        },
        &data,
        2000,
    );
    // Unchanged marker needs only the 7 state predicates + stamp.
    let mut config = config();
    config.max_checks = 8;
    assert!(!certificate.conflicts(&data, &config, 1).truncated);
    data.insert(z.into(), json!(2));
    for limit in [8, 9] {
        config.max_checks = limit;
        let report = certificate.conflicts(&data, &config, 1);
        assert!(report.truncated);
        assert_eq!(report.checks_inspected, limit);
        assert_eq!(report.ignoring_all_cell_versions_upper_bound, "unknown");
    }
    config.max_checks = 10;
    let report = certificate.conflicts(&data, &config, 1);
    assert!(!report.truncated);
    assert_eq!(report.mismatches.window, 0);
    assert!(certificate.valid(&data));
}

#[test]
fn configuration_and_event_count_are_strictly_bounded() {
    assert!(Config::parse("", None, None).unwrap().names.is_empty());
    for names in [
        "secret\nvalue",
        "a,a",
        "a,",
        "*",
        "name:session",
        "with space",
        "é",
    ] {
        assert!(Config::parse(names, None, None).is_none());
    }
    assert!(Config::parse(&"a".repeat(65), None, None).is_none());
    let names = (0..17)
        .map(|n| format!("name{n}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(Config::parse(&names, None, None).is_none());
    for checks in ["0", "65537", "-1", "invalid"] {
        assert!(Config::parse("", Some(checks), None).is_none());
    }
    assert!(Config::parse("", None, Some("10001")).is_none());
    let config = Config::parse("", None, Some("2")).unwrap();
    assert_eq!(config.reserve_event(), Some(1));
    assert_eq!(config.reserve_event(), Some(2));
    assert_eq!(config.reserve_event(), None);
    assert_eq!(config.events.load(Ordering::Relaxed), 2);
}

#[derive(Clone)]
struct Output(std::sync::Arc<Mutex<Vec<u8>>>);
impl std::io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
#[test]
fn emitted_fields_contain_only_fixed_counters_and_explicit_configured_names() {
    let secret = "secret-org-session-args-value-principal-credential";
    let hidden = format!("source:[\"{secret}\",\"{secret}\"]");
    let lookalike = "source:[\"org.spend.suffix\",\"secret\"]";
    let data = Records::new();
    let certificate = records_certificate(&data, &[SOURCE, &hidden, lookalike]);
    let mut changed = data.clone();
    for key in [SOURCE, &hidden, lookalike] {
        changed.insert(key.into(), json!(secret));
    }
    let config = config();
    let report = certificate.conflicts(&changed, &config, 1);
    assert_eq!(report.mismatches.source_record, 3);
    assert_eq!(
        report.names[0].source_record, 0,
        "prefix names must not match"
    );
    assert_eq!(report.names[1].source_record, 1);
    let output = Output(Default::default());
    let writer = output.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(move || writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("untrusted", credential = secret);
        let _entered = span.enter();
        report.emit();
    });
    let text = String::from_utf8(output.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("flower_conflict_diagnostic "));
    for forbidden in [
        secret,
        "private-session-id",
        "org.spend.suffix",
        "source:",
        "credential=",
    ] {
        assert!(!text.contains(forbidden), "must not emit {forbidden}");
    }
    assert!(text.contains("org.dailySpend"));
    assert!(text.contains("not_safe_repairability"));
    assert!(text.len() < 8192);
    let payload = text
        .split_once("flower_conflict_diagnostic ")
        .unwrap()
        .1
        .trim();
    let parsed: Value = serde_json::from_str(payload).unwrap();
    assert_eq!(parsed.as_object().unwrap().len(), 15);
    assert_eq!(parsed["mismatches"].as_object().unwrap().len(), 12);
}

#[test]
fn diagnostic_scan_does_not_change_existing_validation_results() {
    let base = Records::from([(CELL.into(), cell(1)), (SOURCE.into(), json!(1))]);
    let certificate = records_certificate(&base, &[CELL, SOURCE]);
    let mut variants = vec![base.clone()];
    for (key, value) in [
        (CELL, cell(2)),
        (SOURCE, json!(2)),
        ("clock", json!(2001)),
        ("clock", json!("bad")),
        ("source:bad", json!(0)),
        ("reactive:active", Value::Null),
    ] {
        let mut data = base.clone();
        data.insert(key.into(), value);
        variants.push(data);
    }
    for data in variants {
        let expected = certificate.valid(&data);
        for max_checks in [1, 8, 4096] {
            let mut config = config();
            config.max_checks = max_checks;
            let _report = certificate.conflicts(&data, &config, 1);
            assert_eq!(certificate.valid(&data), expected);
        }
    }
}

#[test]
fn graph_shape_and_clock_bound_each_exclude_the_cell_counterfactual() {
    let base = Records::new();
    let certificate = records_certificate(&base, &[]);
    let config = config();
    let mut graph = base.clone();
    graph.insert(
        "root:[\"definition\",null]".into(),
        json!({"name":"definition","args":null}),
    );
    assert!(!certificate.valid(&graph));
    let report = certificate.conflicts(&graph, &config, 1);
    assert_eq!(report.mismatches.graph_shape, 1);
    assert_eq!(report.mismatches.non_cell(), 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
    let mut clock = base.clone();
    clock.insert("clock".into(), json!(2001));
    assert!(!certificate.valid(&clock));
    let report = certificate.conflicts(&clock, &config, 1);
    assert_eq!(report.mismatches.clock_bound, 1);
    assert_eq!(report.mismatches.non_cell(), 1);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "no");
}

#[test]
fn unavailable_window_marker_is_unknown_without_waiting_or_poison_panic() {
    let data = Records::new();
    let certificate = MutationCertificate::new(
        DependencyCertificate {
            checks: [("window:private".into(), window(&data, "missing", "a", "z"))].into(),
            bytes: 0,
        },
        &data,
        2000,
    );
    let Stamp::Window { marker, .. } = certificate.reads.checks.values().next().unwrap() else {
        panic!()
    };
    let config = config();
    {
        let _locked = marker.lock().unwrap();
        let report = certificate.conflicts(&data, &config, 1);
        assert!(report.truncated);
        assert!(report.window_marker_unavailable);
        assert_eq!(report.ignoring_all_cell_versions_upper_bound, "unknown");
    }
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _locked = marker.lock().unwrap();
        panic!("poison fixture");
    }));
    let report = certificate.conflicts(&data, &config, 1);
    assert!(report.window_marker_unavailable);
    assert_eq!(report.ignoring_all_cell_versions_upper_bound, "unknown");
}
