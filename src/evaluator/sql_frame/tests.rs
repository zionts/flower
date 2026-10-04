use super::sqlite::{Equality, QueryOptions};
use super::*;

fn control() -> &'static FrameControl<'static> {
    static CANCELLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static CONTROL: std::sync::OnceLock<FrameControl<'static>> = std::sync::OnceLock::new();
    CONTROL.get_or_init(|| {
        FrameControl::new(
            &CANCELLED,
            std::time::Instant::now() + std::time::Duration::from_secs(86400),
        )
    })
}

fn limits() -> FrameLimits {
    FrameLimits {
        raw_bytes: 128 * 1024,
        support_bytes: 128 * 1024,
        decoded_bytes: 256 * 1024,
        nodes: 8192,
        documents: 512,
        keys: 512,
        key_bytes: 64 * 1024,
        tables: 67,
        columns: 128,
        rows: 256,
        cells: 4096,
        text_bytes: 256 * 1024,
        provenance_bytes: 1024,
        parse_work: 4 * 1024 * 1024,
    }
}
fn column(name: &str, kind: ColumnKind) -> FrameColumn<'_> {
    FrameColumn {
        name,
        kind,
        nullable: true,
        logical_type: None,
        unit: None,
        equality: true,
    }
}
fn capture(builder: &mut FrameBuilder, text: &str) -> Result<JsonId, FrameError> {
    let id = builder.reserve_json(JsonBank::Raw, text.len())?;
    for chunk in text.as_bytes().chunks(MAX_CAPTURE_SLICE) {
        builder.append_json_chunk(id, chunk)?;
    }
    builder.finish_json(id, control())?;
    Ok(id)
}
fn batch_bytes(batch: &Batch) -> usize {
    batch.rows.capacity() * size_of::<Vec<SqlCell>>()
        + batch
            .rows
            .iter()
            .map(|row| {
                row.capacity() * size_of::<SqlCell>()
                    + row
                        .iter()
                        .map(|cell| match cell {
                            SqlCell::Text(text) => text.capacity(),
                            _ => 0,
                        })
                        .sum::<usize>()
            })
            .sum::<usize>()
        + batch.next.as_ref().map_or(0, String::capacity)
}

#[test]
fn hard_limits_and_default_arena_are_admitted_before_capture() {
    let defaults = FrameLimits::default();
    assert!(
        FrameBuilder::new(
            FrameLimits {
                raw_bytes: MAX_TEXT_BYTES + 1,
                ..defaults
            },
            control()
        )
        .is_err()
    );
    assert!(
        FrameBuilder::new(
            FrameLimits {
                cells: usize::MAX,
                ..defaults
            },
            control()
        )
        .is_err()
    );
    assert!(
        FrameBuilder::new(
            FrameLimits {
                nodes: MAX_NODES + 1,
                ..defaults
            },
            control()
        )
        .is_err()
    );
    let builder = FrameBuilder::new(defaults, control()).unwrap();
    assert!(builder.allocation_bytes() <= MAX_FRAME_BYTES);
    assert!(builder.allocation_bytes() > 64 * 1024 * 1024);
    let before = builder.allocation_bytes();
    let frame = builder.seal(control()).unwrap();
    assert!(frame.allocation_bytes() < before);
    assert!(frame.allocation_bytes() < 64 * 1024 * 1024);
    assert!(size_of::<FrameBuilder>() < CONTROL_BYTES / 4);
    assert!(size_of::<json::ArenaValue<'_>>() <= 32);
}

#[test]
fn raw_support_chunks_and_capture_reservation_are_strict() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = builder.reserve_json(JsonBank::Support, 4).unwrap();
    assert!(builder.json(id, control()).is_err());
    assert!(builder.raw_json(id).is_err());
    builder.append_json_chunk(id, b"nu").unwrap();
    builder.append_json_chunk(id, b"ll").unwrap();
    builder.finish_json(id, control()).unwrap();
    assert!(builder.json(id, control()).unwrap().is_null());
    assert_eq!(builder.raw_json(id).unwrap(), "null");
    builder.seal(control()).unwrap();

    let builder = {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        builder.reserve_json(JsonBank::Raw, 4).unwrap();
        builder
    };
    assert!(matches!(builder.seal(control()), Err(FrameError::Invalid)));

    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    assert_eq!(
        builder.reserve_json(JsonBank::Raw, limits().raw_bytes + 1),
        Err(FrameError::Capacity)
    );
    assert_eq!(
        builder.reserve_json(JsonBank::Raw, 1),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));

    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = builder
        .reserve_json(JsonBank::Raw, MAX_CAPTURE_SLICE + 1)
        .unwrap();
    let bytes = vec![b' '; MAX_CAPTURE_SLICE + 1];
    assert_eq!(
        builder.append_json_chunk(id, &bytes),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
}

#[test]
fn exact_capacity_thresholds_poison_entire_frame() {
    for (raw, documents, decoded, nodes, expected) in [
        (4, 1, 0, 1, "null"),
        (3, 1, 0, 1, "null"),
        (4, 0, 0, 1, "null"),
        (4, 1, 0, 0, "null"),
        (5, 1, 2, 1, "\"abc\""),
    ] {
        let mut builder = FrameBuilder::new(
            FrameLimits {
                raw_bytes: raw,
                documents,
                decoded_bytes: decoded,
                nodes,
                ..limits()
            },
            control(),
        )
        .unwrap();
        let result = capture(&mut builder, expected);
        if raw == 4 && documents == 1 && nodes == 1 {
            assert!(result.is_ok());
            assert!(builder.seal(control()).is_ok());
        } else {
            assert_eq!(result, Err(FrameError::Capacity));
            assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
        }
    }
}

#[test]
fn compact_arena_preserves_raw_json_and_decodes_strings_paths_and_bools() {
    let text = r#" {"obj":{"x":"a\n\u0000\uD83D\uDE00","flag":true},"array":[null,false,12.50e+1],"\u006b":7} "#;
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = capture(&mut builder, text).unwrap();
    assert_eq!(builder.raw_json(id).unwrap(), text);
    let root = builder.json(id, control()).unwrap();
    assert_eq!(root.kind(), ArenaKind::Object);
    assert_eq!(
        root.get_path(&["obj", "x"]).unwrap().unwrap().as_str(),
        Some("a\n\0😀")
    );
    assert_eq!(
        root.get_path(&["obj", "flag"])
            .unwrap()
            .unwrap()
            .source_integer(),
        Ok(Some(1))
    );
    let array = root.get("array").unwrap().unwrap();
    assert!(array.at(0).unwrap().unwrap().is_null());
    assert_eq!(array.at(1).unwrap().unwrap().as_bool(), Some(false));
    assert_eq!(
        array.at(2).unwrap().unwrap().number_text(),
        Some("12.50e+1")
    );
    assert_eq!(array.at(2).unwrap().unwrap().as_f64().unwrap(), Some(125.0));
    assert_eq!(
        array.at(2).unwrap().unwrap().source_integer(),
        Ok(Some(125))
    );
    assert_eq!(
        root.get("k").unwrap().unwrap().source_integer(),
        Ok(Some(7))
    );
    let keys: Vec<_> = root
        .children()
        .map(|entry| entry.unwrap().key.unwrap())
        .collect();
    assert_eq!(keys, ["obj", "array", "k"]);
    assert!(root.get_path(&["obj", "missing"]).unwrap().is_none());
    assert!(root.at(0).unwrap().is_none());
}

#[test]
fn malformed_json_duplicate_keys_invalid_unicode_and_nonfinite_are_rejected() {
    for text in [
        "",
        " ",
        "nul",
        "null null",
        "null,",
        "[",
        "{",
        "[1,]",
        "{\"x\":1,}",
        "{\"x\" 1}",
        "{x:1}",
        "[1 2]",
        "01",
        "+1",
        "--1",
        "1.",
        "1e",
        "1e+",
        "NaN",
        "Infinity",
        "\"\\x00\"",
        "\"\\u0g00\"",
        "\"\\uD800\"",
        "\"\\uDC00\"",
        "\"\\uD800\\u0041\"",
        "\"a\nb\"",
        "{\"x\":1,\"x\":2}",
        "{\"x\":1,\"\\u0078\":2}",
        "{\"😀\":1,\"\\ud83d\\ude00\":2}",
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        assert_eq!(
            capture(&mut builder, text),
            Err(FrameError::Invalid),
            "{text:?}"
        );
        assert!(matches!(builder.seal(control()), Err(FrameError::Invalid)));
    }
    for text in ["1e309", "-1e9999999999999999999999999"] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        assert_eq!(capture(&mut builder, text), Err(FrameError::Unsupported));
        assert!(matches!(
            builder.seal(control()),
            Err(FrameError::Unsupported)
        ));
    }
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = builder.reserve_json(JsonBank::Raw, 3).unwrap();
    builder.append_json_chunk(id, &[b'"', 0xff, b'"']).unwrap();
    assert_eq!(builder.finish_json(id, control()), Err(FrameError::Invalid));
}

#[test]
fn explicit_depth_node_and_work_caps_prevent_growing_parser_scratch() {
    for depth in [64, 65] {
        let text = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let result = capture(&mut builder, &text);
        if depth == 64 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result, Err(FrameError::Capacity));
            assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
        }
    }
    let mut builder = FrameBuilder::new(
        FrameLimits {
            nodes: 3,
            ..limits()
        },
        control(),
    )
    .unwrap();
    assert_eq!(capture(&mut builder, "[1,2]"), Ok(JsonId(0)));
    assert_eq!(capture(&mut builder, "null"), Err(FrameError::Capacity));
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));

    let mut builder = FrameBuilder::new(
        FrameLimits {
            parse_work: 4,
            ..limits()
        },
        control(),
    )
    .unwrap();
    assert_eq!(
        capture(&mut builder, " [1,2,3] "),
        Err(FrameError::WorkLimit)
    );
    assert!(matches!(
        builder.seal(control()),
        Err(FrameError::WorkLimit)
    ));
}

#[test]
fn retained_key_offsets_and_provenance_are_bounded_and_internal() {
    let mut builder = FrameBuilder::new(
        FrameLimits {
            keys: 2,
            key_bytes: 5,
            provenance_bytes: 4,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let first = builder.retain_key("α").unwrap();
    let second = builder.retain_key("xyz").unwrap();
    assert_eq!(builder.key(first).unwrap(), "α");
    assert_eq!(builder.key(second).unwrap(), "xyz");
    builder.append_provenance(b"abcd").unwrap();
    let frame = builder.seal(control()).unwrap();
    assert_eq!(frame.provenance(), b"abcd");
    assert_eq!(frame.table_count(), 0);
    assert!(frame.native_tables(0).unwrap().is_empty());

    let mut builder = FrameBuilder::new(
        FrameLimits {
            keys: 0,
            ..limits()
        },
        control(),
    )
    .unwrap();
    assert_eq!(builder.retain_key("x"), Err(FrameError::Capacity));
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
    let mut builder = FrameBuilder::new(
        FrameLimits {
            provenance_bytes: 4,
            ..limits()
        },
        control(),
    )
    .unwrap();
    builder.append_provenance(b"abcd").unwrap();
    assert_eq!(builder.append_provenance(b"e"), Err(FrameError::Capacity));
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
}

#[test]
fn table_row_cell_text_and_type_limits_are_sticky() {
    let mut builder = FrameBuilder::new(
        FrameLimits {
            rows: 1,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let table = builder
        .add_table("visible", &[column("id", ColumnKind::Integer)])
        .unwrap();
    builder
        .insert_row(table, &[FrameCell::Integer(1)], control())
        .unwrap();
    assert_eq!(
        builder.insert_row(table, &[FrameCell::Integer(2)], control()),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));

    let mut builder = FrameBuilder::new(
        FrameLimits {
            cells: 1,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let table = builder
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("name", ColumnKind::Text),
            ],
        )
        .unwrap();
    assert_eq!(
        builder.insert_row(
            table,
            &[FrameCell::Integer(1), FrameCell::Text("x")],
            control()
        ),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));

    let mut builder = FrameBuilder::new(
        FrameLimits {
            text_bytes: 12,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let table = builder
        .add_table("visible", &[column("name", ColumnKind::Text)])
        .unwrap();
    builder
        .insert_row(table, &[FrameCell::Text("x")], control())
        .unwrap();
    assert_eq!(
        builder.insert_row(table, &[FrameCell::Text("y")], control()),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));

    for cell in [
        FrameCell::Text("1"),
        FrameCell::Real(1.0),
        FrameCell::Real(f64::INFINITY),
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let table = builder
            .add_table("visible", &[column("id", ColumnKind::Integer)])
            .unwrap();
        assert_eq!(
            builder.insert_row(table, &[cell], control()),
            Err(FrameError::Unsupported)
        );
        assert!(matches!(
            builder.seal(control()),
            Err(FrameError::Unsupported)
        ));
    }
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let mut required = column("id", ColumnKind::Integer);
    required.nullable = false;
    let table = builder.add_table("visible", &[required]).unwrap();
    assert_eq!(
        builder.insert_row(table, &[FrameCell::Null], control()),
        Err(FrameError::Unsupported)
    );
}

#[test]
fn tagged_cells_preserve_signed_i64_null_real_and_exact_text() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("amount", ColumnKind::Real),
                column("name", ColumnKind::Text),
            ],
        )
        .unwrap();
    let raw = r#"[[{"integer":"9223372036854775807"},{"real":1.25},{"text":"😀\u0000"}],[{"integer":"-9223372036854775808"},null,null]]"#;
    let id = capture(&mut builder, raw).unwrap();
    builder.insert_tagged_rows(table, id, control()).unwrap();
    let mut frame = builder.seal(control()).unwrap();
    let batch = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 64,
            max_bytes: 4096,
        })
        .unwrap();
    assert_eq!(
        batch.rows,
        [
            vec![
                SqlCell::Integer(i64::MAX),
                SqlCell::Real(1.25),
                SqlCell::Text("😀\0".to_owned())
            ],
            vec![SqlCell::Integer(i64::MIN), SqlCell::Null, SqlCell::Null],
        ]
    );
    assert!(batch.next.is_none());
}

#[test]
fn tagged_integer_invalid_noncanonical_and_boolean_are_not_coerced() {
    for cell in [
        r#"{"integer":"9223372036854775808"}"#,
        r#"{"integer":"-9223372036854775809"}"#,
        r#"{"integer":"01"}"#,
        r#"{"integer":"-0"}"#,
        r#"{"integer":"+1"}"#,
        r#"{"integer":"1.0"}"#,
        r#"{"integer":1}"#,
        r#"{"integer":"1","text":"x"}"#,
        "true",
        "false",
        "1",
        r#"{"real":true}"#,
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let table = builder
            .add_table("visible", &[column("id", ColumnKind::Integer)])
            .unwrap();
        let row = format!("[{cell}]");
        let id = capture(&mut builder, &row).unwrap();
        assert_eq!(
            builder.insert_tagged_row(table, id, control()),
            Err(FrameError::Unsupported),
            "{row}"
        );
        assert!(matches!(
            builder.seal(control()),
            Err(FrameError::Unsupported)
        ));
    }
}

#[test]
fn scalar_integer_conversion_is_exact_not_float_rounding() {
    for (text, expected) in [
        ("true", Ok(Some(1))),
        ("false", Ok(Some(0))),
        ("null", Ok(None)),
        ("-0", Ok(Some(0))),
        ("1.0", Ok(Some(1))),
        ("12.50e1", Ok(Some(125))),
        ("9007199254740991", Ok(Some(9_007_199_254_740_991))),
        ("9007199254740992", Err(FrameError::Unsupported)),
        ("9007199254740990.5", Err(FrameError::Unsupported)),
        ("1.00000000000000000000001", Err(FrameError::Unsupported)),
        ("1e-999", Err(FrameError::Unsupported)),
        (r#""9223372036854775807""#, Ok(Some(i64::MAX))),
        (r#""-9223372036854775808""#, Ok(Some(i64::MIN))),
        (r#""-0""#, Err(FrameError::Unsupported)),
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let id = capture(&mut builder, text).unwrap();
        assert_eq!(
            builder.json(id, control()).unwrap().source_integer(),
            expected,
            "{text}"
        );
    }
}

#[test]
fn sealing_copies_typed_values_and_discards_capture_witnesses() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table("visible", &[column("name", ColumnKind::Text)])
        .unwrap();
    let id = capture(&mut builder, r#"[{"text":"only typed bytes"}]"#).unwrap();
    let key = builder.retain_key("physical-secret-key").unwrap();
    assert_eq!(builder.key(key).unwrap(), "physical-secret-key");
    builder.insert_tagged_row(table, id, control()).unwrap();
    builder.append_provenance(b"trusted").unwrap();
    let before = builder.allocation_bytes();
    let mut frame = builder.seal(control()).unwrap();
    assert!(frame.allocation_bytes() < before);
    assert_eq!(frame.table(0).unwrap().name, "visible");
    assert_eq!(frame.table(0).unwrap().rows, 1);
    assert_eq!(frame.provenance(), b"trusted");
    let batch = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 1,
            max_bytes: 4096,
        })
        .unwrap();
    assert_eq!(
        batch.rows[0],
        [SqlCell::Text("only typed bytes".to_owned())]
    );
    // There is intentionally no frame.raw_json/json/key method and no source
    // field. Its exhaustive struct fields are TypedArena and a byte count.
}

#[test]
fn source_batch_capacity_is_exact_and_checked_before_allocations() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table("visible", &[column("name", ColumnKind::Text)])
        .unwrap();
    for _ in 0..3 {
        builder
            .insert_row(table, &[FrameCell::Text("hello")], control())
            .unwrap();
    }
    let mut frame = builder.seal(control()).unwrap();
    let allowance = size_of::<Vec<SqlCell>>() + size_of::<SqlCell>() + 5 + 3;
    let first = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 3,
            max_bytes: allowance,
        })
        .unwrap();
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.next.as_deref(), Some("0:1"));
    assert_eq!(batch_bytes(&first), allowance);
    assert_eq!(first.rows.capacity(), 1);
    assert_eq!(first.rows[0].capacity(), 1);
    match &first.rows[0][0] {
        SqlCell::Text(text) => assert_eq!(text.capacity(), 5),
        _ => panic!(),
    }
    assert_eq!(
        frame
            .scan(ScanRequest {
                table: 0,
                constraints: &[],
                after: None,
                limit: 3,
                max_bytes: allowance - 1
            })
            .unwrap_err(),
        SqlError::MemoryLimit
    );
    let second = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: first.next.as_deref(),
            limit: 3,
            max_bytes: allowance,
        })
        .unwrap();
    assert_eq!(second.next.as_deref(), Some("0:2"));
    let last = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: second.next.as_deref(),
            limit: 3,
            max_bytes: allowance - 3,
        })
        .unwrap();
    assert_eq!(last.rows.len(), 1);
    assert!(last.next.is_none());
    assert_eq!(batch_bytes(&last), allowance - 3);
    for token in [
        "0:0",
        "00:1",
        "0:01",
        "1:1",
        "0:4",
        "0:-1",
        "0:99999999999999999999999",
    ] {
        assert_eq!(
            frame
                .scan(ScanRequest {
                    table: 0,
                    constraints: &[],
                    after: Some(token),
                    limit: 1,
                    max_bytes: 4096
                })
                .unwrap_err(),
            SqlError::Provider,
            "{token}"
        );
    }
}

#[test]
fn logical_metadata_has_no_physical_names_and_export_is_bounded() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let mut amount = column("amount", ColumnKind::Integer);
    amount.logical_type = Some("money");
    amount.unit = Some("usd_micros");
    amount.nullable = false;
    builder.add_table("monthly_totals", &[amount]).unwrap();
    let frame = builder.seal(control()).unwrap();
    let view = frame.column(0, 0).unwrap();
    assert_eq!(view.name, "amount");
    assert_eq!(view.kind, ColumnKind::Integer);
    assert!(!view.nullable);
    assert_eq!(view.logical_type, Some("money"));
    assert_eq!(view.unit, Some("usd_micros"));
    let exact = size_of::<VirtualTable>()
        + "monthly_totals".len()
        + size_of::<String>()
        + "amount".len()
        + size_of::<usize>();
    assert!(matches!(
        frame.native_tables(exact - 1),
        Err(FrameError::Capacity)
    ));
    let tables = frame.native_tables(exact).unwrap();
    assert_eq!(tables.capacity(), 1);
    assert_eq!(tables[0].name, "monthly_totals");
    assert_eq!(tables[0].columns, ["amount"]);
    assert_eq!(tables[0].equality_columns, [0]);
}

#[test]
fn only_sixty_four_user_tables_plus_three_named_metadata_tables_are_allowed() {
    let mut builder = FrameBuilder::new(
        FrameLimits {
            columns: 67,
            ..limits()
        },
        control(),
    )
    .unwrap();
    for index in 0..64 {
        builder
            .add_table(
                &format!("visible_{index}"),
                &[column("id", ColumnKind::Integer)],
            )
            .unwrap();
    }
    for name in ["sql_tables", "sql_columns", "sql_relationships"] {
        builder
            .add_table(name, &[column("id", ColumnKind::Integer)])
            .unwrap();
    }
    assert_eq!(builder.seal(control()).unwrap().table_count(), 67);
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    for index in 0..64 {
        builder
            .add_table(
                &format!("visible_{index}"),
                &[column("id", ColumnKind::Integer)],
            )
            .unwrap();
    }
    assert_eq!(
        builder.add_table("visible_64", &[column("id", ColumnKind::Integer)]),
        Err(FrameError::Capacity)
    );
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
    for name in [
        "sqlite_master",
        "sqlite_schema",
        "physical.dot",
        "../physical",
        "Uppercase",
    ] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        assert_eq!(
            builder.add_table(name, &[column("id", ColumnKind::Integer)]),
            Err(FrameError::Invalid)
        );
    }
}

fn owned_fixture() -> (SealedSqlFrame, Vec<VirtualTable>) {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let visible = builder
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("amount", ColumnKind::Integer),
                column("name", ColumnKind::Text),
            ],
        )
        .unwrap();
    let relations = builder
        .add_table(
            "visible_links",
            &[
                column("left_id", ColumnKind::Integer),
                column("right_id", ColumnKind::Integer),
            ],
        )
        .unwrap();
    // Policy-selected rows only. No hidden record/database/provider exists in
    // the frame. Interleaving tables exercises seal's bounded row-order index.
    builder
        .insert_row(
            visible,
            &[
                FrameCell::Integer(1),
                FrameCell::Integer(9_007_199_254_740_993),
                FrameCell::Text("alice"),
            ],
            control(),
        )
        .unwrap();
    builder
        .insert_row(
            relations,
            &[FrameCell::Integer(1), FrameCell::Integer(2)],
            control(),
        )
        .unwrap();
    builder
        .insert_row(
            visible,
            &[
                FrameCell::Integer(2),
                FrameCell::Integer(7),
                FrameCell::Text("bob"),
            ],
            control(),
        )
        .unwrap();
    builder
        .insert_row(
            relations,
            &[FrameCell::Integer(2), FrameCell::Integer(1)],
            control(),
        )
        .unwrap();
    builder
        .insert_row(
            visible,
            &[
                FrameCell::Integer(3),
                FrameCell::Null,
                FrameCell::Text("null"),
            ],
            control(),
        )
        .unwrap();
    let frame = builder.seal(control()).unwrap();
    let tables = frame.native_tables(8192).unwrap();
    (frame, tables)
}

#[test]
fn real_sqlite_indexed_join_residual_equality_and_duplicate_aliases() {
    let (mut frame, tables) = owned_fixture();
    let result = sqlite::execute(
        "SELECT a.name AS same, b.name AS same, a.amount FROM visible_links l JOIN visible a ON a.id=l.left_id JOIN visible b ON b.id=l.right_id WHERE a.id=? ORDER BY b.name",
        &[SqlCell::Integer(1)], &tables, &mut frame,
        QueryOptions { batch_rows: 1, ..QueryOptions::default() }, &mut || Ok(()),
    ).unwrap();
    assert_eq!(result.columns, ["same", "same", "amount"]);
    assert_eq!(
        result.rows,
        [vec![
            SqlCell::Text("alice".to_owned()),
            SqlCell::Text("bob".to_owned()),
            SqlCell::Integer(9_007_199_254_740_993)
        ]]
    );
    assert!(!result.truncated);
    let constraints = [Equality {
        column: 0,
        value: SqlCell::Integer(99),
    }];
    let batch = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &constraints,
            after: None,
            limit: 10,
            max_bytes: 8192,
        })
        .unwrap();
    assert_eq!(batch.rows.len(), 3); // Intentional residual-only restriction.
}

#[test]
fn real_sqlite_aggregate_uses_all_owned_visible_rows_not_result_row_cap() {
    let (mut frame, tables) = owned_fixture();
    let result = sqlite::execute(
        "SELECT COUNT(*), SUM(amount), COUNT(amount) FROM visible",
        &[],
        &tables,
        &mut frame,
        QueryOptions {
            max_rows: 1,
            batch_rows: 1,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        result.rows,
        [vec![
            SqlCell::Integer(3),
            SqlCell::Integer(9_007_199_254_741_000),
            SqlCell::Integer(2)
        ]]
    );
    assert!(!result.truncated);
    let result = sqlite::execute(
        "SELECT name FROM visible ORDER BY id",
        &[],
        &tables,
        &mut frame,
        QueryOptions {
            max_rows: 1,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(result.rows, [vec![SqlCell::Text("alice".to_owned())]]);
    assert!(result.truncated);
}

#[test]
fn real_sqlite_source_capacity_failure_aborts_without_partial_aggregate() {
    let mut builder = FrameBuilder::new(
        FrameLimits {
            text_bytes: 2 * 1024 * 1024,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let table = builder
        .add_table("visible", &[column("name", ColumnKind::Text)])
        .unwrap();
    builder
        .insert_row(table, &[FrameCell::Text("small")], control())
        .unwrap();
    let huge = "x".repeat(sqlite::MAX_CELL_BYTES);
    builder
        .insert_row(table, &[FrameCell::Text(&huge)], control())
        .unwrap();
    let mut frame = builder.seal(control()).unwrap();
    let tables = frame.native_tables(8192).unwrap();
    let result = sqlite::execute(
        "SELECT COUNT(*) FROM visible",
        &[],
        &tables,
        &mut frame,
        QueryOptions {
            batch_rows: 1,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    );
    assert_eq!(result.unwrap_err(), SqlError::MemoryLimit);
}

#[test]
fn approved_source_projection_uses_arena_scalars_and_copies_key_text_without_value() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("enabled", ColumnKind::Integer),
                column("amount", ColumnKind::Real),
                column("name", ColumnKind::Text),
                column("source_key", ColumnKind::Text),
                column("optional", ColumnKind::Text),
            ],
        )
        .unwrap();
    let id = capture(&mut builder, r#"{"internal_id":"9223372036854775807","internal_bool":true,"internal_real":1.25,"internal_text":"hi\u0000😀"}"#).unwrap();
    let key = builder.retain_key("opaque-key").unwrap();
    builder
        .insert_source_row(
            table,
            id,
            &[
                SourceColumn::Field("internal_id"),
                SourceColumn::Field("internal_bool"),
                SourceColumn::Field("internal_real"),
                SourceColumn::Field("internal_text"),
                SourceColumn::Key(key),
                SourceColumn::Field("missing"),
            ],
            control(),
        )
        .unwrap();
    let mut frame = builder.seal(control()).unwrap();
    let tables = frame.native_tables(8192).unwrap();
    assert_eq!(
        tables[0].columns,
        ["id", "enabled", "amount", "name", "source_key", "optional"]
    );
    let batch = frame
        .scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 1,
            max_bytes: 8192,
        })
        .unwrap();
    assert_eq!(
        batch.rows,
        [vec![
            SqlCell::Integer(i64::MAX),
            SqlCell::Integer(1),
            SqlCell::Real(1.25),
            SqlCell::Text("hi\0😀".to_owned()),
            SqlCell::Text("opaque-key".to_owned()),
            SqlCell::Null,
        ]]
    );
}

#[test]
fn syntax_mutations_match_established_json_ignored_any_validation() {
    // A reference syntax-only serde visitor, NOT an owned Value parse. These
    // seeds contain no duplicate keys or lone surrogates (our stricter policy).
    let seeds = ["null", "false", "[true,null,12.5,-2e3]", r#""a\n\u0041😀""#];
    let replacements = *b" ,:0-\"\\[]{}x";
    for seed in seeds {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let mut tested = 0usize;
        for position in 0..seed.len() {
            for replacement in replacements {
                let mut input = seed.as_bytes().to_vec();
                input[position] = replacement;
                let text = std::str::from_utf8(&input);
                // IgnoredAny deliberately skips string UTF-8 validation; our
                // arena requires UTF-8 before exposing &str, as capture does.
                let reference =
                    text.is_ok() && serde_json::from_slice::<serde::de::IgnoredAny>(&input).is_ok();
                let valid = if let Ok(text) = text {
                    capture(&mut builder, text).is_ok()
                } else {
                    false
                };
                assert_eq!(valid, reference, "{input:?}");
                tested += 1;
                // A failed builder is deliberately unusable; reset in the test,
                // never in production or by bypassing a Records admission gate.
                if !valid || tested.is_multiple_of(64) {
                    builder = FrameBuilder::new(limits(), control()).unwrap();
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn seal_really_unmaps_all_raw_support_parser_key_witness_slabs() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = capture(&mut builder, r#"[{"text":"visible"}]"#).unwrap();
    builder.retain_key("not-a-sealed-key").unwrap();
    let table = builder
        .add_table("visible", &[column("name", ColumnKind::Text)])
        .unwrap();
    builder.insert_tagged_row(table, id, control()).unwrap();
    let regions = builder.capture.mapped_regions();
    for region in regions {
        if region.bytes != 0 {
            let mut residency = 0u8;
            assert_eq!(
                unsafe { libc::mincore(region.address as *mut libc::c_void, 1, &mut residency) },
                0
            );
            assert_ne!(residency & 1, 0, "capture mapping was pre-touched");
            assert_ne!(region.id, 0);
        }
    }
    let observation = mapping_tests::Observation::begin();
    let frame = builder.seal(control()).unwrap();
    let (releases, count) = observation.releases();
    assert_eq!(
        count,
        regions.iter().filter(|region| region.bytes != 0).count()
    );
    for region in regions.into_iter().filter(|region| region.bytes != 0) {
        let matching = releases[..count]
            .iter()
            .filter(|release| release.region.id == region.id)
            .collect::<Vec<_>>();
        assert_eq!(
            matching.len(),
            1,
            "each original mapping owner releases once"
        );
        assert_eq!(matching[0].region, region);
        assert_eq!(
            matching[0].result, 0,
            "the actual original munmap must succeed"
        );
        assert_eq!(matching[0].errno, 0);
    }
    // mincore after seal cannot identify the former owner: another parallel
    // test can already have reused that address. Owner-specific syscall
    // evidence above proves release independently of that race.
    assert_eq!(frame.table(0).unwrap().rows, 1);
}

#[cfg(target_os = "linux")]
#[test]
fn original_mapping_release_evidence_survives_immediate_virtual_address_reuse() {
    let owned = slab::Slab::<u8>::new(4096, control()).unwrap();
    let original = owned.region();
    let observation = mapping_tests::Observation::begin();
    drop(owned);
    let (releases, count) = observation.releases();
    assert_eq!(count, 1);
    assert_eq!(releases[0].region, original);
    assert_eq!(releases[0].result, 0);
    // Never MAP_FIXED: it could destroy a mapping created by another test.
    // NOREPLACE either creates our new distinct owner at the former address,
    // or proves a concurrent owner already occupies that released address.
    let replacement = unsafe {
        libc::mmap(
            original.address as *mut _,
            original.bytes,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if replacement == libc::MAP_FAILED {
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EEXIST)
        );
    } else {
        assert_eq!(replacement as usize, original.address);
        let mut residency = 0;
        assert_eq!(
            unsafe { libc::mincore(replacement, 1, &mut residency) },
            0,
            "mincore sees the NEW owner despite the proved original release"
        );
        assert_eq!(unsafe { libc::munmap(replacement, original.bytes) }, 0);
    }
    let (after, after_count) = observation.releases();
    assert_eq!(after_count, 1);
    assert_eq!(after[0].region.id, original.id);
}

#[test]
fn cached_number_projection_work_does_not_scale_with_reused_mantissa_length() {
    let labels: [String; 64] = std::array::from_fn(|index| format!("col_{index}"));
    let columns: [FrameColumn<'_>; 64] =
        std::array::from_fn(|index| column(&labels[index], ColumnKind::Integer));
    let projection = [SourceColumn::Field("n"); 64];
    let mut costs = [0usize; 2];
    for (index, numeric) in ["1".to_owned(), format!("1.{}", "0".repeat(990))]
        .into_iter()
        .enumerate()
    {
        let raw = format!("{{\"n\":{numeric}}}");
        let mut builder = FrameBuilder::new(
            FrameLimits {
                cells: 8192,
                parse_work: 64 * 1024,
                ..limits()
            },
            control(),
        )
        .unwrap();
        let table = builder.add_table("visible", &columns).unwrap();
        let id = capture(&mut builder, &raw).unwrap();
        let before = builder.capture.remaining_work();
        for _ in 0..64 {
            builder
                .insert_source_row(table, id, &projection, control())
                .unwrap();
        }
        costs[index] = before - builder.capture.remaining_work();
        assert_eq!(builder.seal(control()).unwrap().table(0).unwrap().rows, 64);
    }
    assert_eq!(
        costs[0], costs[1],
        "numeric conversion must be cached, not a raw-lexeme walk"
    );
    assert!(
        costs[0] < 32 * 1024,
        "all64x64 projected cells have finite cumulative debits"
    );
}

#[test]
fn repeated_lookup_iteration_and_conversion_exhaust_shared_work_and_poison_seal() {
    // Ignoring a view's error cannot make a partial/zero-valued result sealable.
    let mut builder = FrameBuilder::new(
        FrameLimits {
            parse_work: 256,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let id = capture(&mut builder, "{\"n\":1}").unwrap();
    let root = builder.json(id, control()).unwrap();
    let mut exhausted = false;
    for _ in 0..256 {
        match root
            .get("n")
            .and_then(|value| value.unwrap().source_integer())
        {
            Err(FrameError::WorkLimit) => {
                exhausted = true;
                break;
            }
            Ok(Some(1)) => {}
            _ => panic!("unexpected projection"),
        }
    }
    assert!(exhausted);
    assert!(matches!(
        builder.seal(control()),
        Err(FrameError::WorkLimit)
    ));

    let mut builder = FrameBuilder::new(
        FrameLimits {
            parse_work: 128,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let id = capture(&mut builder, "[null,null]").unwrap();
    let array = builder.json(id, control()).unwrap();
    let mut exhausted = false;
    for _ in 0..128 {
        for entry in array.children() {
            if matches!(entry, Err(FrameError::WorkLimit)) {
                exhausted = true;
                break;
            }
        }
        if exhausted {
            break;
        }
    }
    assert!(exhausted);
    assert!(matches!(
        builder.seal(control()),
        Err(FrameError::WorkLimit)
    ));
}

#[test]
fn numeric_tokens_above_finite_core_scratch_bound_fail_before_conversion() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let raw = format!("1.{}", "0".repeat(1023)); //1025 bytes, cap1024.
    assert_eq!(capture(&mut builder, &raw), Err(FrameError::Capacity));
    assert!(matches!(builder.seal(control()), Err(FrameError::Capacity)));
}

#[test]
fn primitive_cancellation_and_deadline_apply_at_every_compute_boundary() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let cancelled = AtomicBool::new(true);
    let stop = FrameControl::new(&cancelled, Instant::now() + Duration::from_secs(60));
    assert!(matches!(
        FrameBuilder::new(limits(), &stop),
        Err(FrameError::Cancelled)
    ));
    cancelled.store(false, Ordering::Release);
    let expired = FrameControl::new(&cancelled, Instant::now() - Duration::from_millis(1));
    assert!(matches!(
        FrameBuilder::new(limits(), &expired),
        Err(FrameError::Deadline)
    ));

    let mut builder = FrameBuilder::new(limits(), &stop).unwrap();
    let id = capture(&mut builder, "{\"n\":1}").unwrap();
    let root = builder.json(id, &stop).unwrap();
    let number = root.get("n").unwrap().unwrap();
    cancelled.store(true, Ordering::Release);
    assert_eq!(number.source_integer(), Err(FrameError::Cancelled));
    assert!(matches!(root.get("n"), Err(FrameError::Cancelled)));
    cancelled.store(false, Ordering::Release); // Poison is sticky, not resettable.
    assert!(matches!(builder.seal(&stop), Err(FrameError::Cancelled)));

    let mut builder = FrameBuilder::new(limits(), &stop).unwrap();
    let table = builder
        .add_table("visible", &[column("id", ColumnKind::Integer)])
        .unwrap();
    let id = capture(&mut builder, "{\"n\":1}").unwrap();
    assert_eq!(
        builder.insert_source_row(table, id, &[SourceColumn::Field("n")], &expired),
        Err(FrameError::Deadline)
    );
    assert!(matches!(builder.seal(&stop), Err(FrameError::Deadline)));
}

#[test]
fn cancellation_is_checked_within_large_scanner_work_not_only_between_calls() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};
    let cancelled = AtomicBool::new(false);
    let active = FrameControl::new(&cancelled, Instant::now() + Duration::from_secs(60));
    let mut builder = FrameBuilder::new(
        FrameLimits {
            raw_bytes: 8 * 1024 * 1024,
            decoded_bytes: 8 * 1024 * 1024,
            parse_work: 32 * 1024 * 1024,
            ..limits()
        },
        &active,
    )
    .unwrap();
    let raw = format!("\"{}\"", "x".repeat(4 * 1024 * 1024));
    let id = builder.reserve_json(JsonBank::Raw, raw.len()).unwrap();
    for chunk in raw.as_bytes().chunks(MAX_CAPTURE_SLICE) {
        builder.append_json_chunk(id, chunk).unwrap();
    }
    std::thread::scope(|scope| {
        scope.spawn(|| {
            std::thread::sleep(Duration::from_millis(1));
            cancelled.store(true, Ordering::Release);
        });
        assert_eq!(builder.finish_json(id, &active), Err(FrameError::Cancelled));
    });
    assert!(matches!(builder.seal(&active), Err(FrameError::Cancelled)));
}

#[test]
fn utf8_validation_handles_codepoints_split_at_capture_quantum_without_scratch_allocations() {
    // The leading quote plus65534ASCII bytes makes a4byte scalar straddle the
    // internal64KiB validation boundary. Capture chunks also split its bytes.
    let raw = format!("\"{}😀\"", "x".repeat(MAX_CAPTURE_SLICE - 2));
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let id = capture(&mut builder, &raw).unwrap();
    let view = builder.json(id, control()).unwrap();
    let text = view.as_str().unwrap();
    assert!(text.ends_with('😀'));
    assert_eq!(text.len(), MAX_CAPTURE_SLICE - 2 + 4);
}

#[test]
fn captured_but_not_authorized_rows_and_keys_never_become_sql_sources() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table(
            "visible",
            &[
                column("id", ColumnKind::Integer),
                column("name", ColumnKind::Text),
            ],
        )
        .unwrap();
    let mut policy_calls = 0usize;
    for raw in [
        r#"{"id":1,"name":"alice","readable":true}"#,
        r#"{"id":2,"name":"hidden sentinel","readable":false}"#,
        r#"{"id":3,"name":"bob","readable":true}"#,
    ] {
        let id = capture(&mut builder, raw).unwrap();
        policy_calls += 1;
        let readable = builder
            .json(id, control())
            .unwrap()
            .get("readable")
            .unwrap()
            .unwrap()
            .as_bool()
            .unwrap();
        // Caller policy precedes insertion. No policy/closure can be installed
        // in SealedSqlFrame, and no Records admission gate is exercised here.
        if readable {
            builder
                .insert_source_row(
                    table,
                    id,
                    &[SourceColumn::Field("id"), SourceColumn::Field("name")],
                    control(),
                )
                .unwrap();
        }
    }
    builder.retain_key("private physical witness").unwrap();
    let mut frame = builder.seal(control()).unwrap();
    let tables = frame.native_tables(8192).unwrap();
    let count = sqlite::execute(
        "SELECT COUNT(*) FROM visible",
        &[],
        &tables,
        &mut frame,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(count.rows, [vec![SqlCell::Integer(2)]]);
    let rows = sqlite::execute(
        "SELECT name FROM visible ORDER BY id",
        &[],
        &tables,
        &mut frame,
        QueryOptions::default(),
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(
        rows.rows,
        [
            vec![SqlCell::Text("alice".to_owned())],
            vec![SqlCell::Text("bob".to_owned())]
        ]
    );
    assert_eq!(
        policy_calls, 3,
        "SQLite cannot invoke source/policy callbacks"
    );
}
