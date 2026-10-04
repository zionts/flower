use super::*;
use crate::consensus::backing::{Backing, Spool};
use redb::{Database, ReadableDatabase, StorageBackend, TableDefinition};
use serde_json::{Value, json};
use std::io;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

const LOWER: &str = r#"source:["rows","#;
const UPPER: &str = r#"source:["rows"-"#;
const PLAIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("presence-plain");
const PAIR: TableDefinition<(&[u8], &[u8]), &[u8]> = TableDefinition::new("presence-pair");
const EXTENTS: usize = 64 * 1024 * 1024;
const WORK: usize = 64 * 1024 * 1024;

fn scratch(namespace: Option<&str>, meter: &mut LifetimeWork) -> LifetimePresenceScratch {
    LifetimePresenceScratch::prepare(LOWER, UPPER, namespace, meter).unwrap()
}
fn overlay(entries: impl IntoIterator<Item = (String, Option<Value>)>) -> Records {
    let mut records = Records::new();
    for (key, value) in entries {
        // Real Entry and OrdMap. Direct private fixtures permit deliberately
        // malformed source suffixes without metadata/body rebuilding.
        records.map.insert(
            key,
            super::super::Entry {
                value: value.map(Arc::new),
                version: 17,
                sequence: crate::consensus::backing::UNSEQUENCED,
            },
        );
    }
    records
}
fn attached(backing: Backing) -> Records {
    // Real Records with the real pinned backing. Avoid eager rebuild_metadata
    // in fixture setup, which is unrelated and would parse corrupt test bodies.
    Records {
        backing: Some(Arc::new(backing)),
        ..Records::new()
    }
}
fn answer(records: &Records) -> Result<LifetimePresence, LifetimePresenceFault> {
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    redb::with_resident_reads(EXTENTS, || {
        records.lifetime_presence(&mut scratch, &mut meter)
    })
}
fn raw_plain(entries: &[(&[u8], &[u8])]) -> (Database, Records) {
    let db = Database::builder()
        .set_cache_size(8 * 1024 * 1024)
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .unwrap();
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(PLAIN).unwrap();
        for (key, body) in entries {
            table.insert(*key, *body).unwrap();
        }
    }
    tx.commit().unwrap();
    let table = db.begin_read().unwrap().open_table(PLAIN).unwrap();
    for (key, _) in entries {
        drop(table.get(*key).unwrap());
    }
    (db, attached(Backing::plain(table)))
}
fn raw_pair(namespace: &str, entries: &[(&[u8], &[u8], &[u8])]) -> (Database, Records) {
    let db = Database::builder()
        .set_cache_size(8 * 1024 * 1024)
        .create_with_backend(redb::backends::InMemoryBackend::new())
        .unwrap();
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(PAIR).unwrap();
        for (partition, key, body) in entries {
            table.insert((*partition, *key), *body).unwrap();
        }
    }
    tx.commit().unwrap();
    let table = db.begin_read().unwrap().open_table(PAIR).unwrap();
    for (partition, key, _) in entries {
        drop(table.get((*partition, *key)).unwrap());
    }
    (
        db,
        attached(Backing::pair(Arc::new(table), namespace.to_owned())),
    )
}
fn paired_answer(
    records: &Records,
    namespace: &str,
) -> Result<LifetimePresence, LifetimePresenceFault> {
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(Some(namespace), &mut meter);
    redb::with_resident_reads(EXTENTS, || {
        records.lifetime_presence(&mut scratch, &mut meter)
    })
}
fn row(n: usize) -> String {
    format!(r#"source:["rows","{n:06}"]"#)
}
fn unsupported(reason: LifetimeUnsupported) -> LifetimePresenceFault {
    LifetimePresenceFault::Unsupported(reason)
}

#[test]
fn overlay_empty_complete_absence() {
    assert_eq!(answer(&Records::new()), Ok(LifetimePresence::Absent));
}
#[test]
fn overlay_null_is_presence() {
    let mut records = Records::new();
    records.insert(row(0), Value::Null);
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn overlay_every_scalar_and_unvalidated_malformed_suffix_is_presence() {
    for value in [json!(false), json!(0), json!(""), json!([]), json!({})] {
        let records = overlay([(
            format!("{LOWER}malformed-and-not-a-json-tuple"),
            Some(value),
        )]);
        assert!(!records.has_valid_source_ids() || records.invalid_sources.is_empty());
        assert_eq!(answer(&records), Ok(LifetimePresence::Found));
    }
}
#[test]
fn actual_invalid_source_metadata_does_not_gate_key_presence() {
    let mut records = Records::new();
    records.insert(format!("{LOWER}not-json"), Value::Null);
    assert!(!records.has_valid_source_ids());
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn actual_invalid_depth_metadata_does_not_gate_key_presence() {
    let mut value = Value::Null;
    for _ in 0..256 {
        value = Value::Array(vec![value]);
    }
    let mut records = Records::new();
    records.insert(row(0), value);
    assert!(!records.has_valid_depth());
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn overlay_tombstones_only_complete_absence() {
    assert_eq!(
        answer(&overlay([(row(0), None), (row(1), None)])),
        Ok(LifetimePresence::Absent)
    );
}
#[test]
fn overlay_tombstones_before_live_positive() {
    assert_eq!(
        answer(&overlay([(row(0), None), (row(1), Some(Value::Null))])),
        Ok(LifetimePresence::Found)
    );
}
#[test]
fn bounds_are_half_open_and_do_not_include_collection_marker() {
    let records = overlay([
        (r#"collection:rows"#.to_owned(), Some(Value::Null)),
        (r#"source:["rows"]"#.to_owned(), Some(Value::Null)),
        (UPPER.to_owned(), Some(Value::Null)),
        (r#"source:["rows-other","k"]"#.to_owned(), Some(Value::Null)),
        (r#"source:["row","k"]"#.to_owned(), Some(Value::Null)),
    ]);
    assert_eq!(answer(&records), Ok(LifetimePresence::Absent));
    assert_eq!(
        answer(&overlay([(LOWER.to_owned(), Some(Value::Null))])),
        Ok(LifetimePresence::Found)
    );
}
#[test]
fn utf8_nul_and_escaped_names_use_exact_native_bounds() {
    let name = "🌺\0\"\\\n";
    let encoded = serde_json::to_string(name).unwrap();
    let lower = format!("source:[{encoded},");
    let upper = format!("source:[{encoded}-");
    let key = format!("{lower}\"k\"]");
    let records = overlay([(key, Some(Value::Null))]);
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = LifetimePresenceScratch::prepare(&lower, &upper, None, &mut meter).unwrap();
    assert_eq!(
        records.lifetime_presence(&mut scratch, &mut meter),
        Ok(LifetimePresence::Found)
    );
    assert_eq!(answer(&records), Ok(LifetimePresence::Absent));
}
#[test]
fn raw_embedded_nul_strict_successors_do_not_skip_live_extension() {
    let key = format!("{LOWER}\0");
    let records = overlay([(key.clone(), None), (format!("{key}\0"), Some(Value::Null))]);
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn disk_warm_null_scalar_empty_and_malformed_backing_bodies_are_presence() {
    for body in [
        b"null".as_slice(),
        b"42",
        b"",
        b"\xff\x00badpacked",
        b"short",
    ] {
        let key = row(0);
        let (_db, records) = raw_plain(&[(key.as_bytes(), body)]);
        assert_eq!(answer(&records), Ok(LifetimePresence::Found));
        assert!(records.memo.0.lock().unwrap().is_empty());
    }
}
#[test]
fn disk_actual_encoded_null_and_scalar_are_presence_without_cache_parse() {
    for body in [b"null".as_slice(), b"true", b"17", br#""text""#] {
        let version = crate::consensus::records::next_version();
        let stored = crate::consensus::backing::encode(version, body);
        let key = row(0);
        let (_db, records) = raw_plain(&[(key.as_bytes(), &stored)]);
        let before = crate::consensus::cache::parses(version);
        assert_eq!(answer(&records), Ok(LifetimePresence::Found));
        assert_eq!(crate::consensus::cache::parses(version), before);
    }
}
#[test]
fn disk_malformed_matching_suffix_is_presence() {
    let key = format!("{LOWER}invalid-suffix");
    let (_db, records) = raw_plain(&[(key.as_bytes(), b"malformed")]);
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn disk_exact_bounds_and_collection_marker_are_absent() {
    let (_db, records) = raw_plain(&[
        (b"collection:rows", b""),
        (UPPER.as_bytes(), b""),
        (br#"source:["rows"]"#, b""),
        (br#"source:["rows2","x"]"#, b""),
    ]);
    assert_eq!(answer(&records), Ok(LifetimePresence::Absent));
}
#[test]
fn disk_tombstone_shadows_malformed_body() {
    let key = row(0);
    let (_db, mut records) = raw_plain(&[(key.as_bytes(), b"\xff")]);
    records.map = overlay([(key, None)]).map;
    assert_eq!(answer(&records), Ok(LifetimePresence::Absent));
}
#[test]
fn disk_live_overlay_replaces_body_without_reading_it() {
    let key = row(0);
    let (_db, mut records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    records.map = overlay([(key, Some(Value::Null))]).map;
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn disk_many_shadowed_rows_all_count_then_complete_absence() {
    let keys: Vec<_> = (0..512).map(row).collect();
    let entries: Vec<_> = keys
        .iter()
        .map(|key| (key.as_bytes(), b"broken".as_slice()))
        .collect();
    let (_db, mut records) = raw_plain(&entries);
    records.map = overlay(keys.iter().cloned().map(|key| (key, None))).map;
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    let prepared = meter.used();
    assert_eq!(
        redb::with_resident_reads(EXTENTS, || records
            .lifetime_presence(&mut scratch, &mut meter)),
        Ok(LifetimePresence::Absent)
    );
    assert!(meter.used() - prepared > 512 * 6);
}
#[test]
fn disk_shadowed_then_unshadowed_is_presence() {
    let first = row(0);
    let next = row(1);
    let (_db, mut records) = raw_plain(&[(first.as_bytes(), b""), (next.as_bytes(), b"bad")]);
    records.map = overlay([(first, None)]).map;
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn disk_pair_is_exact_namespace_and_source_range() {
    let key = row(0);
    let (_db, records) = raw_pair(
        "tenant\0🌺",
        &[
            (b"other", key.as_bytes(), b""),
            ("tenant\0🌺".as_bytes(), key.as_bytes(), b"bad"),
        ],
    );
    assert_eq!(
        paired_answer(&records, "tenant\0🌺"),
        Ok(LifetimePresence::Found)
    );
    assert_eq!(
        paired_answer(&records, "wrong"),
        Err(LifetimePresenceFault::NamespaceChanged)
    );
    let (_db, records) = raw_pair("tenant\0🌺", &[(b"other", key.as_bytes(), b"bad")]);
    assert_eq!(
        paired_answer(&records, "tenant\0🌺"),
        Ok(LifetimePresence::Absent)
    );
}
#[test]
fn disk_invalid_utf8_is_fault_not_absence_or_payload_validation() {
    let mut key = LOWER.as_bytes().to_vec();
    key.push(0xff);
    let (_db, records) = raw_plain(&[(&key, b"null")]);
    assert_eq!(answer(&records), Err(LifetimePresenceFault::InvalidUtf8));
}
#[test]
fn disk_pair_invalid_utf8_is_fault() {
    let mut key = LOWER.as_bytes().to_vec();
    key.push(0xff);
    let (_db, records) = raw_pair("p", &[(b"p", &key, b"null")]);
    assert_eq!(
        paired_answer(&records, "p"),
        Err(LifetimePresenceFault::InvalidUtf8)
    );
}
#[test]
fn overlong_selectors_and_namespace_are_explicit_typed_hold() {
    let lower = format!("{},", "x".repeat(LIFETIME_KEY_CAPACITY));
    let upper = format!("{}-", "x".repeat(LIFETIME_KEY_CAPACITY));
    let namespace = "p".repeat(LIFETIME_KEY_CAPACITY + 1);
    let mut meter = LifetimeWork::new(WORK);
    assert!(matches!(
        LifetimePresenceScratch::prepare(&lower, &upper, None, &mut meter),
        Err(LifetimePresenceFault::Unsupported(
            LifetimeUnsupported::Selector
        ))
    ));
    assert!(matches!(
        LifetimePresenceScratch::prepare(LOWER, UPPER, Some(&namespace), &mut meter),
        Err(LifetimePresenceFault::Unsupported(
            LifetimeUnsupported::Namespace
        ))
    ));
    let key = row(0);
    let (_db, records) = raw_pair(
        &namespace,
        &[(namespace.as_bytes(), key.as_bytes(), b"bad")],
    );
    assert_eq!(
        answer(&records),
        Err(unsupported(LifetimeUnsupported::Namespace))
    );
}
#[test]
fn overlong_overlay_live_and_tombstone_are_explicit_hold() {
    let key = format!("{LOWER}{}", "x".repeat(LIFETIME_KEY_CAPACITY));
    for value in [Some(Value::Null), None] {
        assert_eq!(
            answer(&overlay([(key.clone(), value)])),
            Err(unsupported(LifetimeUnsupported::Candidate))
        );
    }
}
#[test]
fn overlong_disk_live_and_shadowed_tombstone_are_explicit_hold() {
    let key = format!("{LOWER}{}", "x".repeat(LIFETIME_KEY_CAPACITY));
    let (_db, mut records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    assert_eq!(
        answer(&records),
        Err(unsupported(LifetimeUnsupported::Candidate))
    );
    records.map = overlay([(key, None)]).map;
    assert_eq!(
        answer(&records),
        Err(unsupported(LifetimeUnsupported::Candidate))
    );
}
#[test]
fn exactly_capacity_tombstone_successor_uses_4097_not_truncation() {
    let key = format!("{LOWER}{}", "x".repeat(LIFETIME_KEY_CAPACITY - LOWER.len()));
    assert_eq!(key.len(), LIFETIME_KEY_CAPACITY);
    let (_db, mut records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    records.map = overlay([(key, None)]).map;
    assert_eq!(answer(&records), Ok(LifetimePresence::Absent));
}
#[test]
fn invalid_bounds_cannot_claim_absence() {
    for (lower, upper) in [
        ("", ""),
        ("source:", "source;"),
        (LOWER, LOWER),
        (LOWER, "different-"),
        (LOWER, "source:[\"rows\"]"),
    ] {
        let mut meter = LifetimeWork::new(WORK);
        assert!(matches!(
            LifetimePresenceScratch::prepare(lower, upper, None, &mut meter),
            Err(LifetimePresenceFault::InvalidBounds)
        ));
    }
}
#[test]
fn work_exhaustion_is_sticky_and_precedes_constructor_work() {
    let mut meter = LifetimeWork::new(0);
    assert!(matches!(
        LifetimePresenceScratch::prepare(LOWER, UPPER, None, &mut meter),
        Err(LifetimePresenceFault::Work)
    ));
    assert_eq!(meter.used(), 0);
    assert_eq!(meter.charge(0), Err(LifetimePresenceFault::Work));
}
#[test]
fn work_is_cumulative_across_selectors_preparation_and_repeated_calls() {
    let records = Records::new();
    let mut measured = LifetimeWork::new(WORK);
    let mut first = scratch(None, &mut measured);
    assert_eq!(
        records.lifetime_presence(&mut first, &mut measured),
        Ok(LifetimePresence::Absent)
    );
    let first_work = measured.used();
    let mut exact = LifetimeWork::new(first_work);
    let mut first = scratch(None, &mut exact);
    assert_eq!(
        records.lifetime_presence(&mut first, &mut exact),
        Ok(LifetimePresence::Absent)
    );
    assert_eq!(
        records.lifetime_presence(&mut first, &mut exact),
        Err(LifetimePresenceFault::Work)
    );
    assert!(matches!(
        LifetimePresenceScratch::prepare(LOWER, UPPER, None, &mut exact),
        Err(LifetimePresenceFault::Work)
    ));
    assert_eq!(exact.used(), first_work);
}
#[test]
fn every_work_cutoff_before_full_shadowed_range_is_fault_not_absent() {
    let keys: Vec<_> = (0..4).map(row).collect();
    let entries: Vec<_> = keys
        .iter()
        .map(|key| (key.as_bytes(), b"bad".as_slice()))
        .collect();
    let (_db, mut records) = raw_plain(&entries);
    records.map = overlay(keys.into_iter().map(|key| (key, None))).map;
    let mut full = LifetimeWork::new(WORK);
    let mut complete = scratch(None, &mut full);
    let preparation = full.used();
    assert_eq!(
        redb::with_resident_reads(EXTENTS, || records
            .lifetime_presence(&mut complete, &mut full)),
        Ok(LifetimePresence::Absent)
    );
    let needed = full.used();
    for maximum in preparation..needed {
        let mut limited = LifetimeWork::new(maximum);
        let mut scratch = scratch(None, &mut limited);
        assert_eq!(
            redb::with_resident_reads(EXTENTS, || records
                .lifetime_presence(&mut scratch, &mut limited)),
            Err(LifetimePresenceFault::Work),
            "cutoff {maximum}/{needed}"
        );
    }
}
#[test]
fn native_extent_quota_and_inactive_are_not_empty() {
    let key = row(0);
    let (_db, records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    assert_eq!(
        records.lifetime_presence(&mut scratch, &mut meter),
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::Inactive
        ))
    );
    assert_eq!(
        redb::with_resident_reads(0, || records.lifetime_presence(&mut scratch, &mut meter)),
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::Budget
        ))
    );
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
}
#[test]
fn native_refusals_map_without_boxing_or_reclassification() {
    for reason in [
        redb::ResidentReadFault::Corrupt,
        redb::ResidentReadFault::Depth,
        redb::ResidentReadFault::Contended,
        redb::ResidentReadFault::InvalidRequest,
        redb::ResidentReadFault::Inactive,
        redb::ResidentReadFault::Budget,
        redb::ResidentReadFault::ColdPage {
            offset: 7,
            length: 8192,
        },
    ] {
        assert_eq!(
            native_fault(redb::StorageError::Resident(reason)),
            LifetimePresenceFault::Native(reason)
        );
    }
    assert_eq!(
        native_fault(redb::StorageError::Io(io::Error::other("fixture"))),
        LifetimePresenceFault::Storage
    );
    assert_eq!(
        overlay_fault(im::BoundedReadError::Depth),
        LifetimePresenceFault::Work
    );
    assert_eq!(
        overlay_fault(im::BoundedReadError::InvalidNode),
        LifetimePresenceFault::CorruptOverlay
    );
}
#[test]
fn run_backing_is_explicit_unsupported_without_spool_io() {
    let directory = tempfile::tempdir().unwrap();
    let _active = Spool::activate(directory.path()).unwrap();
    let mut writer = Spool::current().unwrap().writer();
    writer.insert(row(0), 23, b"null").unwrap();
    let records = attached(writer.finish().unwrap());
    assert_eq!(
        answer(&records),
        Err(unsupported(LifetimeUnsupported::RunBacking))
    );
}
#[test]
fn scratch_retains_no_records_backing_value_or_pin() {
    let key = row(0);
    let (_db, records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    let witness = Arc::downgrade(records.backing.as_ref().unwrap());
    let value = Arc::new(Value::Null);
    let mut records = records;
    records.map.insert(
        row(1),
        super::super::Entry {
            value: Some(value.clone()),
            version: 29,
            sequence: crate::consensus::backing::UNSEQUENCED,
        },
    );
    let before_backing = Arc::strong_count(records.backing.as_ref().unwrap());
    let before_value = Arc::strong_count(&value);
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    assert_eq!(answer(&records), Ok(LifetimePresence::Found));
    assert_eq!(
        Arc::strong_count(records.backing.as_ref().unwrap()),
        before_backing
    );
    assert_eq!(Arc::strong_count(&value), before_value);
    drop(records);
    assert!(witness.upgrade().is_none());
    assert_eq!(
        Records::new().lifetime_presence(&mut scratch, &mut meter),
        Ok(LifetimePresence::Absent)
    );
}

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
    fn read(&self, offset: u64, output: &mut [u8]) -> io::Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        self.file.read(offset, output)
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.file.write(offset, data)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.file.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.file.sync_data()
    }
}
fn cold() -> (
    Database,
    tempfile::TempDir,
    Records,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let dir = tempfile::tempdir().unwrap();
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.path().join("data.redb"))
        .unwrap();
    let reads = Arc::new(AtomicUsize::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let db = Database::builder()
        .set_cache_size(0)
        .create_with_backend(Counted {
            file: redb::backends::FileBackend::new(file).unwrap(),
            reads: reads.clone(),
            writes: writes.clone(),
        })
        .unwrap();
    let tx = db.begin_write().unwrap();
    {
        let mut table = tx.open_table(PLAIN).unwrap();
        for n in 0..512 {
            table
                .insert(row(n).as_bytes(), [7u8; 512].as_slice())
                .unwrap();
        }
    }
    tx.commit().unwrap();
    let table = db.begin_read().unwrap().open_table(PLAIN).unwrap();
    (db, dir, attached(Backing::plain(table)), reads, writes)
}
#[test]
fn cold_backing_is_fault_without_general_io_or_memo() {
    let (_db, _dir, records, reads, writes) = cold();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    assert!(matches!(
        answer(&records),
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::ColdPage { .. }
        ))
    ));
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
    assert!(records.memo.0.lock().unwrap().is_empty());
}
#[test]
fn live_overlay_proves_presence_before_cold_disk() {
    let (_db, _dir, mut records, reads, writes) = cold();
    records.map = overlay([(row(0), None), (row(999999), Some(Value::Null))]).map;
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    // Zero native extent allowance: no disk page or resident cursor constructor.
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    assert_eq!(
        redb::with_resident_reads(0, || records.lifetime_presence(&mut scratch, &mut meter)),
        Ok(LifetimePresence::Found)
    );
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
}
#[test]
fn every_disk_key_shadowed_but_cold_coverage_still_faults() {
    let (_db, _dir, mut records, reads, writes) = cold();
    records.map = overlay((0..512).map(|n| (row(n), None))).map;
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    assert!(matches!(
        answer(&records),
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::ColdPage { .. }
        ))
    ));
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
}
#[test]
fn many_shadowed_rows_work_limit_never_becomes_absent() {
    let keys: Vec<_> = (0..64).map(row).collect();
    let entries: Vec<_> = keys
        .iter()
        .map(|key| (key.as_bytes(), b"bad".as_slice()))
        .collect();
    let (_db, mut records) = raw_plain(&entries);
    records.map = overlay(keys.into_iter().map(|key| (key, None))).map;
    let mut measured = LifetimeWork::new(WORK);
    let _prepared = scratch(None, &mut measured);
    let mut meter = LifetimeWork::new(measured.used() + 10);
    let mut scratch = scratch(None, &mut meter);
    assert_eq!(
        redb::with_resident_reads(EXTENTS, || records
            .lifetime_presence(&mut scratch, &mut meter)),
        Err(LifetimePresenceFault::Work)
    );
}

#[test]
fn existing_root_probe_covers_preparation_overlay_disk_and_tombstone_absence() {
    let key = row(0);
    let (_db, mut records) = raw_plain(&[(key.as_bytes(), b"bad")]);
    records.map = overlay([(key, None)]).map;
    let ((mut scratch, mut meter), calls, bytes) = crate::allocation_probe::measure(|| {
        let mut meter = LifetimeWork::new(WORK);
        let scratch = scratch(None, &mut meter);
        (scratch, meter)
    });
    assert_eq!((calls, bytes), (0, 0));
    let (result, calls, bytes) = crate::allocation_probe::measure(|| {
        redb::with_resident_reads(EXTENTS, || {
            records.lifetime_presence(&mut scratch, &mut meter)
        })
    });
    assert_eq!(result, Ok(LifetimePresence::Absent));
    assert_eq!((calls, bytes), (0, 0));
    let records = overlay([(row(0), Some(Value::Null))]);
    let (result, calls, bytes) =
        crate::allocation_probe::measure(|| records.lifetime_presence(&mut scratch, &mut meter));
    assert_eq!(result, Ok(LifetimePresence::Found));
    assert_eq!((calls, bytes), (0, 0));
}
#[test]
fn existing_root_probe_covers_cold_and_native_quota_faults() {
    let (_db, _dir, records, reads, writes) = cold();
    let before = (
        reads.load(Ordering::Relaxed),
        writes.load(Ordering::Relaxed),
    );
    let mut meter = LifetimeWork::new(WORK);
    let mut scratch = scratch(None, &mut meter);
    let (result, calls, bytes) = crate::allocation_probe::measure(|| {
        redb::with_resident_reads(EXTENTS, || {
            records.lifetime_presence(&mut scratch, &mut meter)
        })
    });
    assert!(matches!(
        result,
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::ColdPage { .. }
        ))
    ));
    assert_eq!((calls, bytes), (0, 0));
    let (result, calls, bytes) = crate::allocation_probe::measure(|| {
        redb::with_resident_reads(0, || records.lifetime_presence(&mut scratch, &mut meter))
    });
    assert_eq!(
        result,
        Err(LifetimePresenceFault::Native(
            redb::ResidentReadFault::Budget
        ))
    );
    assert_eq!((calls, bytes), (0, 0));
    assert_eq!(
        before,
        (
            reads.load(Ordering::Relaxed),
            writes.load(Ordering::Relaxed)
        )
    );
}
