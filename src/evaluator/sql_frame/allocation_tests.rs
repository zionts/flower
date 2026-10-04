use super::{
    allocation_probe::measure,
    sql_frame::*,
    sqlite::{ScanRequest, Source, SqlCell, VirtualTable},
};

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
        raw_bytes: 64 * 1024,
        support_bytes: 4096,
        decoded_bytes: 64 * 1024,
        nodes: 2048,
        documents: 64,
        keys: 64,
        key_bytes: 4096,
        tables: 4,
        columns: 16,
        rows: 64,
        cells: 256,
        text_bytes: 64 * 1024,
        provenance_bytes: 4096,
        parse_work: 1024 * 1024,
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
fn capture(builder: &mut FrameBuilder, raw: &str) -> Result<JsonId, FrameError> {
    let id = builder.reserve_json(JsonBank::Raw, raw.len())?;
    for chunk in raw.as_bytes().chunks(MAX_CAPTURE_SLICE) {
        builder.append_json_chunk(id, chunk)?;
    }
    builder.finish_json(id, control())?;
    Ok(id)
}

#[test]
fn preallocation_capture_parse_path_conversion_insert_and_seal_allocate_zero_heap_bytes() {
    let (builder, allocations, bytes) = measure(|| FrameBuilder::new(limits(), control()));
    assert_eq!((allocations, bytes), (0, 0));
    let mut builder = builder.unwrap();
    let columns = [
        column("id", ColumnKind::Integer),
        column("text", ColumnKind::Text),
        column("real", ColumnKind::Real),
    ];
    let raw = r#"[{"integer":"9223372036854775807"},{"text":"a\u0000\uD83D\uDE00"},{"real":1.25}]"#;
    let (result, allocations, bytes) = measure(|| -> Result<_, FrameError> {
        let table = builder.add_table("visible", &columns)?;
        let id = capture(&mut builder, raw)?;
        let arena = builder.json(id, control())?;
        let value = arena
            .at(0)
            .unwrap()
            .unwrap()
            .get("integer")
            .unwrap()
            .unwrap()
            .source_integer()?;
        let text = arena
            .at(1)
            .unwrap()
            .unwrap()
            .get_path(&["text"])
            .unwrap()
            .unwrap()
            .as_str()
            .unwrap();
        let content_valid = text == "a\0😀";
        let key = builder.retain_key("source-opaque-key")?;
        let key_valid = builder.key(key)? == "source-opaque-key";
        builder.append_provenance(b"trusted provenance")?;
        builder.insert_tagged_row(table, id, control())?;
        let frame = builder.seal(control())?;
        Ok((frame, value, content_valid, key_valid))
    });
    assert_eq!((allocations, bytes), (0, 0));
    let (frame, value, text_valid, key_valid) = result.unwrap();
    assert_eq!(value, Some(i64::MAX));
    assert!(text_valid && key_valid);
    assert_eq!(frame.table(0).unwrap().rows, 1);
}

#[test]
fn scanner_error_and_preflight_capacity_failure_allocate_zero_heap_bytes() {
    for raw in [r#"{"x":1,"\u0078":2}"#, "[1,]", r#""\uD800""#, "1e999"] {
        let mut builder = FrameBuilder::new(limits(), control()).unwrap();
        let (result, allocations, bytes) = measure(|| capture(&mut builder, raw));
        assert!(result.is_err());
        assert_eq!((allocations, bytes), (0, 0));
        let (result, allocations, bytes) = measure(|| builder.seal(control()));
        assert!(result.is_err());
        assert_eq!((allocations, bytes), (0, 0));
    }
    let (result, allocations, bytes) = measure(|| {
        FrameBuilder::new(
            FrameLimits {
                raw_bytes: usize::MAX,
                ..limits()
            },
            control(),
        )
    });
    assert!(matches!(result, Err(FrameError::Capacity)));
    assert_eq!((allocations, bytes), (0, 0));
}

#[test]
fn source_exact_layouts_match_max_bytes_and_failure_happens_before_heap_allocation() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let table = builder
        .add_table("visible", &[column("text", ColumnKind::Text)])
        .unwrap();
    for _ in 0..3 {
        builder
            .insert_row(table, &[FrameCell::Text("hello")], control())
            .unwrap();
    }
    let mut frame = builder.seal(control()).unwrap();
    let allowance = size_of::<Vec<SqlCell>>() + size_of::<SqlCell>() + 5 + 3;
    let (result, allocations, bytes) = measure(|| {
        frame.scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 3,
            max_bytes: allowance - 1,
        })
    });
    assert!(result.is_err());
    assert_eq!((allocations, bytes), (0, 0));
    let (result, allocations, bytes) = measure(|| {
        frame.scan(ScanRequest {
            table: 0,
            constraints: &[],
            after: None,
            limit: 3,
            max_bytes: allowance,
        })
    });
    let batch = result.unwrap();
    assert_eq!(batch.rows.len(), 1);
    assert_eq!(allocations, 4); // outer Vec, row Vec, text String, ordinal String.
    assert_eq!(bytes, allowance);
}

#[test]
fn logical_descriptor_capacity_failure_allocates_nothing_and_exact_success_is_admitted() {
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    builder
        .add_table("visible", &[column("text", ColumnKind::Text)])
        .unwrap();
    let frame = builder.seal(control()).unwrap();
    let allowance = size_of::<VirtualTable>() + 7 + size_of::<String>() + 4 + size_of::<usize>();
    let (result, allocations, bytes) = measure(|| frame.native_tables(allowance - 1));
    assert!(result.is_err());
    assert_eq!((allocations, bytes), (0, 0));
    let (result, _, bytes) = measure(|| frame.native_tables(allowance));
    assert!(result.is_ok());
    assert_eq!(bytes, allowance);
}

#[test]
fn difficult_core_float_paths_and_native_source_projection_allocate_no_heap() {
    let numeric = format!("0.{}1e-1", "123456789".repeat(80));
    let raw = format!(
        "{{\"private_amount\":{numeric},\"private_id\":true,\"private_name\":\"zero heap\"}}"
    );
    let mut builder = FrameBuilder::new(limits(), control()).unwrap();
    let columns = [
        column("amount", ColumnKind::Real),
        column("id", ColumnKind::Integer),
        column("name", ColumnKind::Text),
    ];
    let (result, allocations, bytes) = measure(|| -> Result<_, FrameError> {
        let table = builder.add_table("visible", &columns)?;
        let id = capture(&mut builder, &raw)?;
        builder.insert_source_row(
            table,
            id,
            &[
                SourceColumn::Field("private_amount"),
                SourceColumn::Field("private_id"),
                SourceColumn::Field("private_name"),
            ],
            control(),
        )?;
        builder.seal(control())
    });
    assert!(result.is_ok());
    assert_eq!((allocations, bytes), (0, 0));
}

#[test]
fn default_mapping_sizes_are_finite_and_capture_maps_are_released_on_seal() {
    let mut builder = FrameBuilder::new(FrameLimits::default(), control()).unwrap();
    let before = builder.allocation_bytes();
    let table = builder
        .add_table("visible", &[column("id", ColumnKind::Integer)])
        .unwrap();
    builder
        .insert_row(table, &[FrameCell::Integer(1)], control())
        .unwrap();
    let (result, allocations, bytes) = measure(|| builder.seal(control()));
    let frame = result.unwrap();
    assert_eq!((allocations, bytes), (0, 0));
    println!(
        "default mapped/control bytes: builder={before}; sealed={}",
        frame.allocation_bytes()
    );
    assert!(before <= MAX_FRAME_BYTES);
    assert!(frame.allocation_bytes() < before);
}

#[test]
fn cancellation_deadline_and_sticky_work_failures_allocate_zero_heap_bytes() {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};
    let cancelled = AtomicBool::new(true);
    let stopped = FrameControl::new(&cancelled, Instant::now() + Duration::from_secs(60));
    let (result, allocations, bytes) = measure(|| FrameBuilder::new(limits(), &stopped));
    assert!(matches!(result, Err(FrameError::Cancelled)));
    assert_eq!((allocations, bytes), (0, 0));
    let cancelled = AtomicBool::new(false);
    let expired = FrameControl::new(&cancelled, Instant::now() - Duration::from_millis(1));
    let (result, allocations, bytes) = measure(|| FrameBuilder::new(limits(), &expired));
    assert!(matches!(result, Err(FrameError::Deadline)));
    assert_eq!((allocations, bytes), (0, 0));
    let mut builder = FrameBuilder::new(
        FrameLimits {
            parse_work: 128,
            ..limits()
        },
        control(),
    )
    .unwrap();
    let id = capture(&mut builder, "{\"n\":1}").unwrap();
    let (error, allocations, bytes) = measure(|| {
        let root = builder.json(id, control()).unwrap();
        loop {
            if let Err(error) = root.get("n") {
                break error;
            }
        }
    });
    assert_eq!(error, FrameError::WorkLimit);
    assert_eq!((allocations, bytes), (0, 0));
    let (result, allocations, bytes) = measure(|| builder.seal(control()));
    assert!(matches!(result, Err(FrameError::WorkLimit)));
    assert_eq!((allocations, bytes), (0, 0));
}
