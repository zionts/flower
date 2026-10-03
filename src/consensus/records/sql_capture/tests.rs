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
