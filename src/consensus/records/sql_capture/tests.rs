use super::*;
use redb::{Database, ReadableDatabase, StorageBackend, TableDefinition};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug)]
struct Counted {
    file: redb::backends::FileBackend,
    reads: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}
impl StorageBackend for Counted {
    fn len(&self) -> io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.file.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.file.write(offset, data)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}
const PAIR: TableDefinition<(&[u8], &[u8]), &[u8]> = TableDefinition::new("capture-rows");
fn database(
    cache: usize,
) -> (
    Database,
    tempfile::TempDir,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let directory = tempfile::tempdir().unwrap();
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(directory.path().join("db.redb"))
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let db = Database::builder()
        .set_cache_size(cache)
        .create_with_backend(Counted {
            file: redb::backends::FileBackend::new(file).unwrap(),
            reads: reads.clone(),
            writes: writes.clone(),
        })
        .unwrap();
    (db, directory, reads, writes)
}
fn output() -> SqlCaptureBuffer {
    SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
}
fn keys<'a>(keys: &'a [&'a str]) -> SqlCaptureRequest<'a> {
    SqlCaptureRequest {
        selection: SqlCaptureSelection::Keys(keys),
        max_records: 32,
        max_examined: 128,
    }
}

#[test]
fn sql_capture_resident_cold_and_budget_refusals_do_not_read_or_poison_backend() {
    let (db, _directory, reads, writes) = database(0);
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"a".as_slice(), b"key".as_slice()),
            super::super::super::backing::encode(1, br#"{"ok":true}"#).as_slice(),
        )
        .unwrap();
    // ReadOnlyTable keeps its root page resident even with cache size zero.
    // Force a branch and cold child leaves to test the actual cold-read path.
    for n in 0..128 {
        tx.open_table(PAIR)
            .unwrap()
            .insert(
                (b"a".as_slice(), format!("extra-{n:03}").as_bytes()),
                vec![7u8; 512].as_slice(),
            )
            .unwrap();
    }
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = reader.open_table(PAIR).unwrap();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    let error = redb::with_resident_reads(32 * 1024 * 1024, || {
        table.get((b"a".as_slice(), b"key".as_slice()))
    })
    .err()
    .expect("resident read refused");
    assert!(matches!(
        redb::resident_read_fault(&error),
        Some(redb::ResidentReadFault::ColdPage { .. })
    ));
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    let error = redb::with_resident_reads(1, || table.get((b"a".as_slice(), b"key".as_slice())))
        .err()
        .expect("resident read refused");
    assert_eq!(
        redb::resident_read_fault(&error),
        Some(redb::ResidentReadFault::Budget)
    );
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    assert!(
        table
            .get((b"a".as_slice(), b"key".as_slice()))
            .unwrap()
            .is_some()
    );
    assert!(reads.load(Ordering::Relaxed) > before.0);
    drop(table);
    reader.close().unwrap();
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"a".as_slice(), b"next".as_slice()),
            b"still usable".as_slice(),
        )
        .unwrap();
    tx.commit().unwrap();
}

#[test]
fn sql_capture_paired_disk_copy_is_positive_without_memo_parse_or_escaping_read_pin() {
    let (db, _directory, reads, writes) = database(8 * 1024 * 1024);
    let key = r#"source:["rows","k"]"#;
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"sql".as_slice(), key.as_bytes()),
            super::super::super::backing::encode(41, br#"{"n":"9007199254740993","visible":true}"#)
                .as_slice(),
        )
        .unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"other".as_slice(), b"row".as_slice()),
            super::super::super::backing::encode(42, br#"{"other":true}"#).as_slice(),
        )
        .unwrap();
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = Arc::new(reader.open_table(PAIR).unwrap());
    // Warm only as baseline fixture setup, not as an SQL prefetch with a pin.
    drop(table.get((b"sql".as_slice(), key.as_bytes())).unwrap());
    let backing = Arc::new(Backing::pair(table.clone(), "sql".into()));
    let witness = Arc::downgrade(&backing);
    let records = Records::backed(backing);
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
        crate::consensus::cache::parses(41),
    );
    let mut input = output();
    redb::with_resident_reads(32 * 1024 * 1024, || {
        records.sql_capture_raw(&keys(&[key, "missing"]), &mut input)
    })
    .unwrap();
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed),
            crate::consensus::cache::parses(41)
        )
    );
    assert!(records.memo.0.lock().unwrap().is_empty());
    let rows: Vec<_> = input.records().collect();
    assert_eq!(rows[0].version, Some(41));
    assert!(rows[1].body.is_none());
    assert_eq!(
        super::super::super::packed::unpack(&input.bytes()[rows[0].body.clone().unwrap()])
            .unwrap()
            .as_ref(),
        br#"{"n":"9007199254740993","visible":true}"#
    );
    drop(records);
    assert!(witness.upgrade().is_none());
    drop(table);
    reader.close().unwrap();
    // Retain copied SQL input while another partition churns. Closing the old
    // transaction above is the pin witness; file/RSS observations are not caps.
    for round in 0..64 {
        let tx = db.begin_write().unwrap();
        tx.open_table(PAIR)
            .unwrap()
            .insert(
                (b"other".as_slice(), b"row".as_slice()),
                vec![round as u8; 4096].as_slice(),
            )
            .unwrap();
        tx.commit().unwrap();
    }
    assert_eq!(rows[0].version, Some(41));
    drop(rows);
    drop(input);
}

#[test]
fn sql_capture_overlay_has_no_shared_values_after_copy_and_counts_tombstones() {
    let value = Arc::new(serde_json::json!({"old":"kept only in copied bytes"}));
    let witness = Arc::downgrade(&value);
    let mut records = Records::new();
    records.insert_shared("key".into(), value.clone());
    drop(value);
    let mut input = output();
    records
        .sql_capture_raw(&keys(&["key"]), &mut input)
        .unwrap();
    drop(records);
    assert!(witness.upgrade().is_none());
    assert_eq!(input.records().len(), 1);
    let mut records = Records::new();
    for n in 0..100 {
        records.insert(format!("k{n:03}"), serde_json::json!({"n":n}));
    }
    let mut input = output();
    records
        .sql_capture_raw(
            &SqlCaptureRequest {
                selection: SqlCaptureSelection::Range {
                    lower: "k",
                    upper: Some("l"),
                    after: None,
                },
                max_records: 2,
                max_examined: 4,
            },
            &mut input,
        )
        .unwrap();
    assert_eq!(input.records().len(), 2);
    assert!(!input.complete());
    assert_eq!(input.continuation(), Some("k001"));
    assert!(input.examined() <= 4);
}

#[test]
fn sql_capture_metadata_chunks_preserve_version_size_and_do_not_decode() {
    let (db, _directory, reads, _) = database(8 * 1024 * 1024);
    let text = "x".repeat(150_000);
    let json = serde_json::to_vec(&serde_json::json!({"javascript":text})).unwrap();
    // A poorly-compressible metadata body makes actual multi-slice copying
    // independent of compressed/decompressed length accounting.
    let mut encoded = 17u64.to_le_bytes().to_vec();
    encoded.extend_from_slice(&json);
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"sql".as_slice(), b"bundle".as_slice()),
            encoded.as_slice(),
        )
        .unwrap();
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = Arc::new(reader.open_table(PAIR).unwrap());
    drop(
        table
            .get((b"sql".as_slice(), b"bundle".as_slice()))
            .unwrap(),
    );
    let records = Records::backed(Arc::new(Backing::pair(table.clone(), "sql".into())));
    let before = reads.load(Ordering::Relaxed);
    let mut joined = Vec::new();
    let mut offset = 0;
    while offset < json.len() {
        let mut input = output();
        redb::with_resident_reads(32 * 1024 * 1024, || {
            records.sql_capture_raw(
                &SqlCaptureRequest {
                    selection: SqlCaptureSelection::KeyChunk {
                        key: "bundle",
                        offset,
                    },
                    max_records: 1,
                    max_examined: 1,
                },
                &mut input,
            )
        })
        .unwrap();
        let row = input.records().next().unwrap();
        assert_eq!(row.version, Some(17));
        assert_eq!(row.json_bytes, json.len());
        assert_eq!(row.body_offset, offset);
        assert_eq!(row.total_body_bytes, json.len());
        let body = &input.bytes()[row.body.clone().unwrap()];
        joined.extend_from_slice(body);
        offset += body.len();
        assert_eq!(input.complete(), offset == json.len());
    }
    assert_eq!(reads.load(Ordering::Relaxed), before);
    assert_eq!(joined, json);
    assert!(records.memo.0.lock().unwrap().is_empty());
    drop(records);
    drop(table);
    reader.close().unwrap();
}

#[test]
fn sql_capture_one_examined_backing_row_advances_and_empty_key_continuation_is_present() {
    let (db, _directory, _, _) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert(
            (b"sql".as_slice(), b"".as_slice()),
            crate::consensus::backing::encode(1, b"null").as_slice(),
        )
        .unwrap();
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = Arc::new(reader.open_table(PAIR).unwrap());
    let records = Records::backed(Arc::new(Backing::pair(table.clone(), "sql".into())));
    let mut input = output();
    redb::with_resident_reads(32 * 1024 * 1024, || {
        records.sql_capture_raw(
            &SqlCaptureRequest {
                selection: SqlCaptureSelection::Range {
                    lower: "",
                    upper: None,
                    after: None,
                },
                max_records: 1,
                max_examined: 1,
            },
            &mut input,
        )
    })
    .unwrap();
    assert_eq!(input.records().len(), 1);
    assert_eq!(input.examined(), 1);
    assert_eq!(input.continuation(), Some(""));
    assert!(!input.complete());
    let mut tail = output();
    redb::with_resident_reads(32 * 1024 * 1024, || {
        records.sql_capture_raw(
            &SqlCaptureRequest {
                selection: SqlCaptureSelection::Range {
                    lower: "",
                    upper: None,
                    after: Some(""),
                },
                max_records: 1,
                max_examined: 1,
            },
            &mut tail,
        )
    })
    .unwrap();
    assert!(tail.complete());
    assert_eq!(tail.records().len(), 0);
    drop(records);
    drop(table);
    reader.close().unwrap();
}

#[test]
fn sql_capture_resident_nested_scopes_cannot_renew_quota_and_panic_resets_it() {
    let (db, _directory, reads, _) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert((b"a".as_slice(), b"key".as_slice()), b"data".as_slice())
        .unwrap();
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = reader.open_table(PAIR).unwrap();
    let before = reads.load(Ordering::Relaxed);
    redb::with_resident_reads(4096, || {
        drop(table.get((b"a".as_slice(), b"key".as_slice())).unwrap());
        let result = redb::with_resident_reads(32 * 1024 * 1024, || {
            table.get((b"a".as_slice(), b"key".as_slice()))
        });
        assert_eq!(
            redb::resident_read_fault(&result.err().expect("cumulative quota")),
            Some(redb::ResidentReadFault::Budget)
        );
    });
    assert_eq!(reads.load(Ordering::Relaxed), before);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| redb::with_resident_reads(
            1,
            || panic!("test scope unwind")
        )))
        .is_err()
    );
    assert!(
        table
            .get((b"a".as_slice(), b"key".as_slice()))
            .unwrap()
            .is_some()
    );
    drop(table);
    reader.close().unwrap();
}

#[test]
fn sql_capture_version_identity_exhaustion_never_wraps_or_renews_old_blocks() {
    let counter = AtomicU64::new(u64::MAX - 1024);
    assert_eq!(
        reserve_version_block(&counter, 1024),
        Some((u64::MAX - 1024, u64::MAX))
    );
    assert_eq!(reserve_version_block(&counter, 1024), None);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(reserve_version_block(&counter, 1), None);
}

#[test]
fn sql_capture_combined_native_scope_has_zero_heap_for_paired_overlay_range_and_faults() {
    use crate::consensus::sql_capture::allocation_probe::{self, Counts};
    let (db, _dir, reads, writes) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    for n in 0..96 {
        let key = format!("source:[\"rows\",\"{n:03}\"]");
        tx.open_table(PAIR)
            .unwrap()
            .insert(
                (b"scope".as_slice(), key.as_bytes()),
                super::super::super::backing::encode(100 + n, format!("{{\"n\":{n}}}").as_bytes())
                    .as_slice(),
            )
            .unwrap();
    }
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = Arc::new(reader.open_table(PAIR).unwrap());
    for row in table
        .range((b"scope".as_slice(), b"".as_slice())..)
        .unwrap()
    {
        drop(row.unwrap());
    }
    let mut records = Records::backed(Arc::new(Backing::pair(table.clone(), "scope".into())));
    records.insert(
        "source:[\"rows\",\"020-overlay\"]".into(),
        serde_json::json!({"n":1.0,"text":"東京🌸\n\u{0000}\\\""}),
    );
    records.remove("source:[\"rows\",\"010\"]");
    let request = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: "source:[\"rows\",",
            upper: Some("source:[\"rows\"-"),
            after: None,
        },
        max_records: 32,
        max_examined: 128,
    };
    let mut scratch = SqlCaptureScratch::for_partition(Some("scope"), &request).unwrap();
    let mut output = output();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    let (result, counts) = allocation_probe::run(|| {
        redb::with_resident_reads(32 * 1024 * 1024, || {
            records.sql_capture_prepared(&request, &mut output, &mut scratch)
        })
    });
    result.unwrap();
    assert_eq!(counts, Counts::default());
    assert_eq!(output.records().len(), 32);
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    let (version, counts) = allocation_probe::run(|| {
        redb::with_resident_reads(32 * 1024 * 1024, || {
            records.sql_capture_version("source:[\"rows\",\"095\"]")
        })
    });
    assert!(version.unwrap().is_some());
    assert_eq!(counts, Counts::default());
    let (error, counts) = allocation_probe::run(|| {
        redb::with_resident_reads(1, || {
            records.sql_capture_version("source:[\"rows\",\"095\"]")
        })
    });
    assert_eq!(error.unwrap_err(), SqlCaptureError::WorkLimit);
    assert_eq!(counts, Counts::default());
    drop(records);
    drop(table);
    reader.close().unwrap();
}

#[test]
fn sql_capture_combined_native_scope_has_zero_heap_for_plain_copy_and_cold_refusal() {
    use crate::consensus::sql_capture::allocation_probe::{self, Counts};
    const PLAIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("plain-probe");
    for cache in [0, 8 * 1024 * 1024] {
        let (db, _dir, reads, writes) = database(cache);
        let tx = db.begin_write().unwrap();
        for n in 0..128 {
            tx.open_table(PLAIN)
                .unwrap()
                .insert(
                    format!("key-{n:03}").as_bytes(),
                    super::super::super::backing::encode(
                        1000 + n,
                        format!("{{\"n\":{n},\"pad\":\"{}\"}}", "x".repeat(512)).as_bytes(),
                    )
                    .as_slice(),
                )
                .unwrap();
        }
        tx.commit().unwrap();
        let reader = db.begin_read().unwrap();
        let table = reader.open_table(PLAIN).unwrap();
        if cache > 0 {
            drop(table.get(b"key-000".as_slice()).unwrap());
        }
        let records = Records::backed(Arc::new(Backing::plain(table)));
        let mut output = output();
        let request = keys(&["key-000"]);
        let mut scratch = SqlCaptureScratch::for_partition(None, &request).unwrap();
        let before = (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed),
        );
        let (result, counts) = allocation_probe::run(|| {
            redb::with_resident_reads(32 * 1024 * 1024, || {
                records.sql_capture_prepared(&request, &mut output, &mut scratch)
            })
        });
        if cache == 0 {
            assert_eq!(result.unwrap_err(), SqlCaptureError::ColdPage);
        } else {
            result.unwrap();
            assert_eq!(output.records().len(), 1);
        }
        assert_eq!(counts, Counts::default());
        assert_eq!(
            before,
            (
                reads.load(Ordering::Relaxed),
                writes.load(Ordering::Relaxed)
            )
        );
        drop(records);
        reader.close().unwrap();
    }
}

#[test]
fn sql_capture_row_and_work_caps_stop_before_unneeded_successor_inspection() {
    // Oversized successor must not turn a completed permitted row into error.
    let mut records = Records::new();
    records.insert("a".into(), serde_json::json!(1));
    records.insert(
        "b".into(),
        serde_json::json!("x".repeat(SQL_CAPTURE_MAX_BYTES)),
    );
    let request = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: "",
            upper: None,
            after: None,
        },
        max_records: 1,
        max_examined: 128,
    };
    let mut output = output();
    records.sql_capture_raw(&request, &mut output).unwrap();
    assert_eq!(output.records().len(), 1);
    assert_eq!(output.continuation(), Some("a"));
    assert_eq!(output.examined(), 1);
    assert!(!output.complete());
    // 129 overlay tombstones: exactly 128 charged lookups, not a 129th Peek.
    let mut records = Records::new();
    records.keep_deletions();
    for n in 0..129 {
        let key = format!("k{n:03}");
        records.insert(key.clone(), serde_json::json!(1));
        records.remove(&key);
    }
    let mut output = super::tests::output();
    let request = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: "",
            upper: None,
            after: None,
        },
        max_records: 32,
        max_examined: 128,
    };
    records.sql_capture_raw(&request, &mut output).unwrap();
    assert_eq!(output.examined(), 128);
    assert_eq!(output.continuation(), Some("k127"));
    assert_eq!(output.records().len(), 0);
    assert!(!output.complete());
}

#[test]
fn sql_capture_resident_generic_scope_escape_is_immutable_pinned_data_not_mutable_aliasing() {
    let (db, _dir, _reads, _writes) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert((b"a".as_slice(), b"key".as_slice()), b"old".as_slice())
        .unwrap();
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = reader.open_table(PAIR).unwrap();
    drop(table.get((b"a".as_slice(), b"key".as_slice())).unwrap());
    let escaped = redb::with_resident_reads(32 * 1024 * 1024, || {
        table.resident_get_pair(b"a", b"key").unwrap().unwrap()
    });
    assert!(!redb::resident_scope_active());
    let tx = db.begin_write().unwrap();
    tx.open_table(PAIR)
        .unwrap()
        .insert((b"a".as_slice(), b"key".as_slice()), b"new".as_slice())
        .unwrap();
    tx.commit().unwrap();
    assert_eq!(escaped.value(), b"old");
    drop(escaped);
    drop(table);
    reader.close().unwrap();
    let reader = db.begin_read().unwrap();
    assert_eq!(
        reader
            .open_table(PAIR)
            .unwrap()
            .get((b"a".as_slice(), b"key".as_slice()))
            .unwrap()
            .unwrap()
            .value(),
        b"new"
    );
    reader.close().unwrap();
}

#[test]
fn sql_capture_full_row_slice_does_not_probe_a_cold_native_successor() {
    const PLAIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("cold-successor");
    let (db, _dir, reads, writes) = database(8192);
    let tx = db.begin_write().unwrap();
    for n in 0u64..128 {
        // Uncompressed native JSON body, not packed repetitive text, to force
        // numerous actual leaves. Version header is the normal storage format.
        let json = format!("{{\"n\":{n},\"pad\":\"{}\"}}", "x".repeat(1024));
        let mut body = n.to_le_bytes().to_vec();
        body.extend_from_slice(json.as_bytes());
        tx.open_table(PLAIN)
            .unwrap()
            .insert(format!("k{n:04}").as_bytes(), body.as_slice())
            .unwrap();
    }
    tx.commit().unwrap();
    // Reopen to remove unrelated commit-cache occupancy: setup warms only
    // the root path and first leaf, while subsequent leaves remain truly cold.
    drop(db);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(_dir.path().join("db.redb"))
        .unwrap();
    let db = Database::builder()
        .set_cache_size(64 * 1024)
        .create_with_backend(Counted {
            file: redb::backends::FileBackend::new(file).unwrap(),
            reads: reads.clone(),
            writes: writes.clone(),
        })
        .unwrap();
    let reader = db.begin_read().unwrap();
    let table = reader.open_table(PLAIN).unwrap();
    // Warm one leaf near the first child. Find the last key of that warmed
    // resident leaf using resident lookups only; the next key must be cold.
    drop(table.get(b"k0000".as_slice()).unwrap());
    let mut last = None;
    let mut cold = None;
    for n in 0..128 {
        let key = format!("k{n:04}");
        match redb::with_resident_reads(32 * 1024 * 1024, || table.resident_get(key.as_bytes())) {
            Ok(Some(_)) => last = Some(key),
            Err(error)
                if matches!(
                    redb::resident_read_fault(&error),
                    Some(redb::ResidentReadFault::ColdPage { .. })
                ) =>
            {
                cold = Some(key);
                break;
            }
            _ => {
                panic!("unexpected native fixture result (neither resident key nor cold successor)")
            }
        }
    }
    let last = last.expect("warmed leaf has key");
    let cold = cold.expect("fixture has actually cold successor");
    assert!(cold > last);
    let records = Records::backed(Arc::new(Backing::plain(table)));
    let request = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: &last,
            upper: None,
            after: None,
        },
        max_records: 1,
        max_examined: 128,
    };
    let mut scratch = SqlCaptureScratch::for_partition(None, &request).unwrap();
    let mut out = output();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    redb::with_resident_reads(32 * 1024 * 1024, || {
        records.sql_capture_prepared(&request, &mut out, &mut scratch)
    })
    .unwrap();
    assert_eq!(out.records().len(), 1);
    assert_eq!(out.continuation(), Some(last.as_str()));
    assert!(!out.complete());
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    drop(records);
    reader.close().unwrap();
}

#[test]
fn sql_capture_prepared_partition_mismatch_refuses_before_reading_another_namespace() {
    let (db, _dir, reads, writes) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    for (partition, value) in [("A", 1), ("B", 2)] {
        tx.open_table(PAIR)
            .unwrap()
            .insert(
                (partition.as_bytes(), b"sentinel".as_slice()),
                super::super::super::backing::encode(
                    value,
                    format!("{{\"namespace\":{value}}}").as_bytes(),
                )
                .as_slice(),
            )
            .unwrap();
    }
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = Arc::new(reader.open_table(PAIR).unwrap());
    for p in ["A", "B"] {
        drop(table.get((p.as_bytes(), b"sentinel".as_slice())).unwrap());
    }
    let records = Records::backed(Arc::new(Backing::pair(table.clone(), "A".into())));
    let request = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: "",
            upper: None,
            after: None,
        },
        max_records: 32,
        max_examined: 128,
    };
    let mut wrong = SqlCaptureScratch::for_partition(Some("B"), &request).unwrap();
    let mut out = output();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    let (result, counts) = crate::consensus::sql_capture::allocation_probe::run(|| {
        redb::with_resident_reads(32 * 1024 * 1024, || {
            records.sql_capture_prepared(&request, &mut out, &mut wrong)
        })
    });
    assert_eq!(result.unwrap_err(), SqlCaptureError::SnapshotChanged);
    assert_eq!(counts, crate::allocation_probe::Counts::default());
    assert_eq!(out.records().len(), 0);
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    let mut right = SqlCaptureScratch::for_partition(Some("A"), &request).unwrap();
    let mut out = output();
    redb::with_resident_reads(32 * 1024 * 1024, || {
        records.sql_capture_prepared(&request, &mut out, &mut right)
    })
    .unwrap();
    let row = out.records().next().unwrap();
    let json =
        super::super::super::packed::unpack(&out.bytes()[row.body.clone().unwrap()]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&json).unwrap()["namespace"],
        1
    );
    drop(records);
    drop(table);
    reader.close().unwrap();
}

#[test]
fn sql_capture_merged_pagination_matches_independent_oracle_with_replacements_and_tombstones() {
    const PLAIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("merge-oracle");
    let (db, _dir, _reads, _writes) = database(8 * 1024 * 1024);
    let tx = db.begin_write().unwrap();
    let mut oracle = std::collections::BTreeMap::<String, Value>::new();
    for n in 0..300 {
        let key = format!("k{n:04}");
        let value = serde_json::json!({"n":n,"source":"disk"});
        tx.open_table(PLAIN)
            .unwrap()
            .insert(
                key.as_bytes(),
                super::super::super::backing::encode(
                    n + 5000,
                    serde_json::to_vec(&value).unwrap().as_slice(),
                )
                .as_slice(),
            )
            .unwrap();
        oracle.insert(key, value);
    }
    for key in ["", "\u{0}", "k0001\u{0}", "東京🌸"] {
        let value = serde_json::json!({"special":key});
        tx.open_table(PLAIN)
            .unwrap()
            .insert(
                key.as_bytes(),
                super::super::super::backing::encode(
                    9000,
                    serde_json::to_vec(&value).unwrap().as_slice(),
                )
                .as_slice(),
            )
            .unwrap();
        oracle.insert(key.into(), value);
    }
    tx.commit().unwrap();
    let reader = db.begin_read().unwrap();
    let table = reader.open_table(PLAIN).unwrap();
    for row in table.range::<&[u8]>(..).unwrap() {
        drop(row.unwrap());
    }
    let mut records = Records::backed(Arc::new(Backing::plain(table)));
    for n in 0..300 {
        let key = format!("k{n:04}");
        if n % 3 == 0 {
            records.remove(&key);
            oracle.remove(&key);
        } else if n % 5 == 0 {
            let value = serde_json::json!({"n":n,"source":"overlay"});
            records.insert(key.clone(), value.clone());
            oracle.insert(key, value);
        }
    }
    for n in 0..140 {
        let key = format!("k{n:04}-overlay");
        let value = serde_json::json!({"insert":n});
        records.insert(key.clone(), value.clone());
        oracle.insert(key, value);
    }
    let expected: Vec<_> = oracle.into_iter().collect();
    for (max_records, max_examined, capacity) in [
        (1, 4, SQL_CAPTURE_MAX_BYTES),
        (7, 16, 512),
        (32, 128, SQL_CAPTURE_MAX_BYTES),
    ] {
        let mut actual = Vec::new();
        let mut after = None::<String>;
        for slice in 0..2000 {
            let request = SqlCaptureRequest {
                selection: SqlCaptureSelection::Range {
                    lower: "",
                    upper: None,
                    after: after.as_deref(),
                },
                max_records,
                max_examined,
            };
            let mut scratch = SqlCaptureScratch::for_partition(None, &request).unwrap();
            let mut out =
                SqlCaptureBuffer::from_reserved(vec![0; capacity].into_boxed_slice()).unwrap();
            redb::with_resident_reads(32 * 1024 * 1024, || {
                records.sql_capture_prepared(&request, &mut out, &mut scratch)
            })
            .unwrap();
            assert!(out.examined() <= max_examined);
            assert!(out.records().len() <= max_records);
            for row in out.records() {
                let key = std::str::from_utf8(&out.bytes()[row.key.clone()])
                    .unwrap()
                    .to_owned();
                let raw =
                    super::super::super::packed::unpack(&out.bytes()[row.body.clone().unwrap()])
                        .unwrap();
                let value = serde_json::from_slice::<Value>(&raw).unwrap();
                actual.push((key, value));
            }
            if out.complete() {
                break;
            }
            let continuation = out
                .continuation()
                .expect("partial slice consumed a key")
                .to_owned();
            assert!(after.as_ref().is_none_or(|after| continuation > *after));
            after = Some(continuation);
            assert!(
                slice < 1999,
                "merged copier failed to make bounded progress"
            );
        }
        assert_eq!(
            actual, expected,
            "rows={max_records},work={max_examined},capacity={capacity}"
        );
    }
    drop(records);
    reader.close().unwrap();
}
