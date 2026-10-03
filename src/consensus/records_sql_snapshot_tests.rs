//! Evidence tests for the intentionally closed SQL snapshot-retention gate.

use super::*;
use redb::{ReadableDatabase, StorageBackend, TableDefinition};
use serde_json::json;
use std::io;
use std::sync::atomic::AtomicUsize;

#[test]
fn sql_snapshot_unproved_memory_roots_fail_closed() {
    assert_eq!(Records::new().sql_snapshot_reservation_bytes(), None);
    let mut records = Records::from([("plain".to_owned(), json!({"old": true}))]);
    let snapshot = records.clone();
    let old = Arc::downgrade(records.get_shared("plain").unwrap());
    records.insert("plain".to_owned(), json!({"new": true}));
    records.remove("plain");
    assert!(old.upgrade().is_some(), "the old root retains its value");
    assert_eq!(snapshot.sql_snapshot_reservation_bytes(), None);
    assert_eq!(records.sql_snapshot_reservation_bytes(), None);
    drop(snapshot);
    assert!(old.upgrade().is_none());

    records.extend([("bulk".to_owned(), json!([1, 2]))]);
    records.insert_shared("shared".to_owned(), Arc::new(json!("shared")));
    let reconstructed: Records =
        serde_json::from_str(&serde_json::to_string(&records).unwrap()).unwrap();
    let from_map = Records::from(BTreeMap::from([("map".to_owned(), Value::Null)]));
    let from_iter: Records = [("iter".to_owned(), Value::Null)].into_iter().collect();
    for root in [records, reconstructed, from_map, from_iter] {
        assert_eq!(root.sql_snapshot_reservation_bytes(), None);
        assert_eq!(root.graph_view(None).sql_snapshot_reservation_bytes(), None);
    }
}

#[test]
fn sql_snapshot_empty_map_does_not_bound_historical_metadata() {
    let mut records = Records::new();
    for n in 0..64 {
        let key = format!("source:{}", json!([format!("collection-{n}"), "row"]));
        records.insert(key.clone(), Value::Null);
        records.remove(&key);
    }
    assert!(records.map.is_empty());
    assert!(records.memberships.len() >= 64);
    assert_eq!(records.sql_snapshot_reservation_bytes(), None);
    assert_eq!(records.clone().sql_snapshot_reservation_bytes(), None);
}

#[derive(Debug)]
struct CountedBackend {
    file: redb::backends::FileBackend,
    reads: Arc<AtomicUsize>,
}

impl StorageBackend for CountedBackend {
    fn len(&self) -> io::Result<u64> {
        self.file.len()
    }

    fn read(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.file.read(offset, output)
    }

    fn set_len(&self, length: u64) -> io::Result<()> {
        self.file.set_len(length)
    }

    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.file.write(offset, data)
    }

    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}

#[test]
fn sql_snapshot_backing_gate_performs_no_reads_or_decodes_under_churn() {
    const TABLE: TableDefinition<(&[u8], &[u8]), &[u8]> = TableDefinition::new("rows");
    const PARTITION: &[u8] = b"sql-org";
    const ROW: &[u8] = br#"source:["rows","row"]"#;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("snapshot.redb");
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let database = redb::Database::builder()
        .set_cache_size(0)
        .create_with_backend(CountedBackend {
            file: redb::backends::FileBackend::new(file).unwrap(),
            reads: reads.clone(),
        })
        .unwrap();
    let initial_version = next_version();
    let transaction = database.begin_write().unwrap();
    transaction
        .open_table(TABLE)
        .unwrap()
        .insert(
            (PARTITION, ROW),
            super::super::backing::encode(initial_version, br#"{"old":true}"#).as_slice(),
        )
        .unwrap();
    transaction.commit().unwrap();
    let backing = Arc::new(Backing::pair(
        Arc::new(database.begin_read().unwrap().open_table(TABLE).unwrap()),
        "sql-org".to_owned(),
    ));
    let mut current = Records::backed(backing);
    let retained = current.clone();
    let before = std::fs::metadata(&path).unwrap().len();

    let reject_without_reading = |records: &Records| {
        let before = reads.load(Ordering::Relaxed);
        assert_eq!(records.sql_snapshot_reservation_bytes(), None);
        assert_eq!(reads.load(Ordering::Relaxed), before);
        assert!(records.memo.0.lock().unwrap().is_empty());
        assert_eq!(super::super::cache::parses(initial_version), 0);
    };
    reject_without_reading(&current);
    reject_without_reading(&retained);

    // Raw JSON is a supported on-disk representation. Do not compress this
    // fixture: make page churn observable while one small partition is pinned.
    let mut encoded = vec![b'x'; (64 << 10) + 10];
    encoded[8] = b'"';
    *encoded.last_mut().unwrap() = b'"';
    for _ in 0..64 {
        let version = next_version();
        encoded[..8].copy_from_slice(&version.to_le_bytes());
        let transaction = database.begin_write().unwrap();
        {
            let mut table = transaction.open_table(TABLE).unwrap();
            table.insert((PARTITION, ROW), encoded.as_slice()).unwrap();
            table
                .insert((&b"other-org"[..], ROW), encoded.as_slice())
                .unwrap();
        }
        transaction.commit().unwrap();
        reject_without_reading(&retained);
        assert_eq!(super::super::cache::parses(version), 0);
    }
    assert!(std::fs::metadata(&path).unwrap().len() > before);
    let newer = Arc::new(Backing::pair(
        Arc::new(database.begin_read().unwrap().open_table(TABLE).unwrap()),
        "sql-org".to_owned(),
    ));
    current.rebase(newer, u64::MAX);
    reject_without_reading(&current);
    reject_without_reading(&retained);
    // Checking the gate never had to read even the original row. Read it now
    // to demonstrate that the old table remains pinned across the rebase.
    assert_eq!(
        retained.entries(..).next().unwrap().1.as_ref(),
        &json!({"old": true})
    );
    assert!(retained.memo.0.lock().unwrap().is_empty());
}

#[test]
fn sql_snapshot_spooled_and_empty_backings_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let spooled: Records = {
        let _spooling = Spool::activate(directory.path()).unwrap();
        serde_json::from_str(r#"{"plain":{"n":1}}"#).unwrap()
    };
    assert!(spooled.backing.is_some());
    assert_eq!(spooled.sql_snapshot_reservation_bytes(), None);
    assert!(spooled.memo.0.lock().unwrap().is_empty());
    let mut empty = Records::new();
    empty.keep_deletions();
    assert!(empty.is_settled());
    assert_eq!(empty.sql_snapshot_reservation_bytes(), None);
}
