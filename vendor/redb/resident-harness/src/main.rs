//! Isolated, single-threaded native allocator probe. No Flower/SQL dependency.
//! Run with `cargo run --offline --manifest-path .../resident-harness/Cargo.toml`.
use redb::backends::InMemoryBackend;
use redb::{
    Database, ReadableDatabase, ReadableTableMetadata, ResidentKey, ResidentRangeBounds,
    ResidentRangeScratch, ResidentReadFault, StorageBackend, TableDefinition, Value,
    resident_read_fault, with_resident_reads,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::ops::Bound::{self, Excluded, Included, Unbounded};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

struct ProbeAllocator;
static PROBING: AtomicBool = AtomicBool::new(false);
static ALLOC: AtomicUsize = AtomicUsize::new(0);
static ZEROED: AtomicUsize = AtomicUsize::new(0);
static REALLOC: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for ProbeAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if PROBING.load(Ordering::Relaxed) {
            ALLOC.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if PROBING.load(Ordering::Relaxed) {
            ZEROED.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if PROBING.load(Ordering::Relaxed) {
            REALLOC.fetch_add(1, Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: ProbeAllocator = ProbeAllocator;

#[derive(Debug, Default)]
struct BackendCounts {
    reads: AtomicUsize,
    writes: AtomicUsize,
    syncs: AtomicUsize,
}
impl BackendCounts {
    fn snapshot(&self) -> (usize, usize, usize) {
        (
            self.reads.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
            self.syncs.load(Ordering::Relaxed),
        )
    }
}
#[derive(Debug)]
struct Backend {
    inner: InMemoryBackend,
    counts: Arc<BackendCounts>,
}
impl StorageBackend for Backend {
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn set_len(&self, length: u64) -> std::io::Result<()> {
        self.inner.set_len(length)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.counts.reads.fetch_add(1, Ordering::Relaxed);
        self.inner.read(offset, out)
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        self.counts.writes.fetch_add(1, Ordering::Relaxed);
        self.inner.write(offset, data)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.counts.syncs.fetch_add(1, Ordering::Relaxed);
        self.inner.sync_data()
    }
}
fn database(cache: usize) -> (Database, Arc<BackendCounts>) {
    let counts = Arc::new(BackendCounts::default());
    let mut builder = Database::builder();
    builder.set_cache_size(cache);
    let db = builder
        .create_with_backend(Backend {
            inner: InMemoryBackend::new(),
            counts: counts.clone(),
        })
        .unwrap();
    (db, counts)
}
fn probe<T>(counts: &BackendCounts, label: &str, run: impl FnOnce() -> T) -> T {
    let before = counts.snapshot();
    ALLOC.store(0, Ordering::Relaxed);
    ZEROED.store(0, Ordering::Relaxed);
    REALLOC.store(0, Ordering::Relaxed);
    PROBING.store(true, Ordering::SeqCst);
    let result = run();
    PROBING.store(false, Ordering::SeqCst);
    let allocation = (
        ALLOC.load(Ordering::Relaxed),
        ZEROED.load(Ordering::Relaxed),
        REALLOC.load(Ordering::Relaxed),
    );
    assert_eq!(allocation, (0, 0, 0), "{label}: native heap activity");
    assert_eq!(before, counts.snapshot(), "{label}: backend activity");
    result
}
const PLAIN: TableDefinition<&[u8], &[u8]> = TableDefinition::new("plain");
const PAIRS: TableDefinition<(&[u8], &[u8]), &[u8]> = TableDefinition::new("pairs");
const EMPTY: TableDefinition<&[u8], &[u8]> = TableDefinition::new("empty");
const RECORDS: usize = 11050;

fn key(index: usize) -> [u8; 8] {
    ((index as u64) * 2).to_be_bytes()
}
fn small_keys() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        vec![0, 0],
        b"a".to_vec(),
        b"a\0".to_vec(),
        b"ab".to_vec(),
        "é🎉".as_bytes().to_vec(),
        vec![255],
        vec![b'z'; 4096],
    ]
}
fn small_partitions() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0],
        b"p".to_vec(),
        b"p\0".to_vec(),
        b"prefix".to_vec(),
        b"prefix2".to_vec(),
        "分区🎉".as_bytes().to_vec(),
        vec![255],
        vec![b'z'; 4096],
    ]
}
fn main() {
    println!(
        "native storage: ResidentKey={} ResidentRangeBounds={} ResidentRangeScratch={} plain cursor={} paired cursor={} byte AccessGuard={} tuple AccessGuard={}",
        std::mem::size_of::<ResidentKey>(),
        std::mem::size_of::<ResidentRangeBounds>(),
        std::mem::size_of::<ResidentRangeScratch>(),
        std::mem::size_of::<redb::ResidentRange<'_, &[u8]>>(),
        std::mem::size_of::<redb::ResidentRange<'_, (&[u8], &[u8])>>(),
        std::mem::size_of::<redb::AccessGuard<'_, &[u8]>>(),
        std::mem::size_of::<redb::AccessGuard<'_, (&[u8], &[u8])>>()
    );
    // Byte equivalence against the actual upstream Value tuple encoder.
    for length in [0, 253, 254, 4096] {
        let partition = vec![42; length];
        let second = vec![13; 4096];
        let encoded = ResidentKey::pair(&partition, &second).unwrap();
        let ordinary =
            <(&[u8], &[u8]) as Value>::as_bytes(&(partition.as_slice(), second.as_slice()));
        assert_eq!(encoded.as_bytes(), ordinary.as_slice());
    }
    assert_eq!(
        ResidentKey::pair(&[0; 4096], &[0; 4096])
            .unwrap()
            .as_bytes()
            .len(),
        8195
    );

    let (db, counts) = database(128 * 1024 * 1024);
    let keys = small_keys();
    let partitions = small_partitions();
    let write = db.begin_write().unwrap();
    {
        let mut plain = write.open_table(PLAIN).unwrap();
        let mut pair = write.open_table(PAIRS).unwrap();
        write.open_table(EMPTY).unwrap();
        let value = [7; 4000];
        for index in 0..RECORDS {
            let key = key(index);
            plain.insert(key.as_slice(), value.as_slice()).unwrap();
            pair.insert((b"bulk".as_slice(), key.as_slice()), value.as_slice())
                .unwrap();
        }
        for key in &keys {
            plain.insert(key.as_slice(), key.as_slice()).unwrap();
            for partition in &partitions {
                pair.insert((partition.as_slice(), key.as_slice()), key.as_slice())
                    .unwrap();
            }
        }
    }
    write.commit().unwrap();
    let transaction = db.begin_read().unwrap();
    let plain = transaction.open_table(PLAIN).unwrap();
    let pair = transaction.open_table(PAIRS).unwrap();
    let empty = transaction.open_table(EMPTY).unwrap();
    let stats = plain.stats().unwrap();
    assert!(stats.leaf_pages() > 10000);
    assert!(pair.stats().unwrap().leaf_pages() > 10000);
    println!(
        "differential fixture: plain leaf pages={} branch pages={} height={}",
        stats.leaf_pages(),
        stats.branch_pages(),
        stats.tree_height()
    );
    // Ordinary fixtures and all warming occur OUTSIDE the probe and TLS scope.
    let ordinary_plain: Vec<_> = plain
        .range::<&[u8]>(..)
        .unwrap()
        .map(|r| {
            let (k, v) = r.unwrap();
            (k.value().to_vec(), v.value().to_vec())
        })
        .collect();
    let ordinary_pairs: Vec<_> = pair
        .range::<(&[u8], &[u8])>(..)
        .unwrap()
        .map(|r| {
            let (k, v) = r.unwrap();
            let (p, k) = k.value();
            (p.to_vec(), k.to_vec(), v.value().to_vec())
        })
        .collect();

    let bounds = ResidentRangeBounds::plain(Unbounded, Unbounded).unwrap();
    let mut scratch = ResidentRangeScratch::new();
    probe(&counts, "full plain forward >10k leaves", || {
        with_resident_reads(usize::MAX, || {
            let mut range = plain.resident_range(&bounds, &mut scratch).unwrap();
            for (key, value) in &ordinary_plain {
                let (k, v) = range.next().unwrap().unwrap();
                assert_eq!(k.value(), key.as_slice());
                assert_eq!(v.value(), value.as_slice());
            }
            assert!(range.next().is_none());
            assert!(range.next().is_none());
        })
    });
    let bulk = ResidentRangeBounds::partition(b"bulk", Unbounded, Unbounded).unwrap();
    probe(&counts, "full paired forward >10k leaves", || {
        with_resident_reads(usize::MAX, || {
            let mut range = pair.resident_partition_range(&bulk, &mut scratch).unwrap();
            for (partition, key, value) in ordinary_pairs.iter().filter(|(p, _, _)| p == b"bulk") {
                let (k, v) = range.next().unwrap().unwrap();
                assert_eq!(k.value(), (partition.as_slice(), key.as_slice()));
                assert_eq!(v.value(), value.as_slice());
            }
            assert!(range.next().is_none());
        })
    });

    // Exhaustive include/exclude/unbounded combinations, equal/inverted bounds,
    // empty keys/partitions, Unicode/NUL/prefix/max component lengths.
    let mut cases: Vec<Bound<&[u8]>> = vec![Unbounded];
    for key in &keys {
        cases.push(Included(key.as_slice()));
        cases.push(Excluded(key.as_slice()));
    }
    for lower in &cases {
        for upper in &cases {
            let expected: Vec<_> = plain
                .range::<&[u8]>((*lower, *upper))
                .unwrap()
                .map(|r| {
                    let (k, v) = r.unwrap();
                    (k.value().to_vec(), v.value().to_vec())
                })
                .collect();
            let bounds = ResidentRangeBounds::plain(*lower, *upper).unwrap();
            probe(&counts, "plain bound matrix", || {
                with_resident_reads(usize::MAX, || {
                    let mut range = plain.resident_range(&bounds, &mut scratch).unwrap();
                    for (key, value) in &expected {
                        let (k, v) = range.next().unwrap().unwrap();
                        assert_eq!(k.value(), key.as_slice());
                        assert_eq!(v.value(), value.as_slice());
                    }
                    assert!(range.next().is_none());
                })
            });
            for partition in &partitions {
                // Typed ordinary tuple range supplies the same second-key
                // bounds; filter the unbounded end to stay in this partition.
                let pair_bound = |bound| match bound {
                    Unbounded => Unbounded,
                    Included(key) => Included((partition.as_slice(), key)),
                    Excluded(key) => Excluded((partition.as_slice(), key)),
                };
                let expected: Vec<_> = pair
                    .range::<(&[u8], &[u8])>((pair_bound(*lower), pair_bound(*upper)))
                    .unwrap()
                    .filter_map(|r| {
                        let (k, v) = r.unwrap();
                        let (p, key) = k.value();
                        (p == partition.as_slice()).then(|| (key.to_vec(), v.value().to_vec()))
                    })
                    .collect();
                let bounds = ResidentRangeBounds::partition(partition, *lower, *upper).unwrap();
                probe(&counts, "paired bound matrix", || {
                    with_resident_reads(usize::MAX, || {
                        let mut range = pair
                            .resident_partition_range(&bounds, &mut scratch)
                            .unwrap();
                        for (key, value) in &expected {
                            let (k, v) = range.next().unwrap().unwrap();
                            assert_eq!(k.value(), (partition.as_slice(), key.as_slice()));
                            assert_eq!(v.value(), value.as_slice());
                        }
                        assert!(range.next().is_none());
                    })
                });
            }
        }
    }

    // Point equality and misses, plus seeks into leaf-end gaps at every bulk key.
    for index in 0..RECORDS {
        for query in [
            ((index as u64) * 2).to_be_bytes(),
            ((index as u64) * 2 + 1).to_be_bytes(),
        ] {
            let expected = plain
                .get(query.as_slice())
                .unwrap()
                .map(|v| v.value().to_vec());
            let expected_pair = pair
                .get((b"bulk".as_slice(), query.as_slice()))
                .unwrap()
                .map(|v| v.value().to_vec());
            let encoded = ResidentKey::pair(b"bulk", &query).unwrap();
            probe(&counts, "typed plain/paired point", || {
                with_resident_reads(usize::MAX, || {
                    assert_eq!(
                        plain
                            .resident_get(&query)
                            .unwrap()
                            .as_ref()
                            .map(|v| v.value()),
                        expected.as_deref()
                    );
                    assert_eq!(
                        pair.resident_get_pair(b"bulk", &query)
                            .unwrap()
                            .as_ref()
                            .map(|v| v.value()),
                        expected_pair.as_deref()
                    );
                    assert_eq!(
                        pair.resident_get_pair_encoded(&encoded)
                            .unwrap()
                            .as_ref()
                            .map(|v| v.value()),
                        expected_pair.as_deref()
                    );
                })
            });
        }
        let gap = ((index as u64) * 2 + 1).to_be_bytes();
        let bounds = ResidentRangeBounds::plain(Included(&gap), Unbounded).unwrap();
        let paired_bounds =
            ResidentRangeBounds::partition(b"bulk", Included(&gap), Unbounded).unwrap();
        let expected = plain
            .range::<&[u8]>((Included(gap.as_slice()), Unbounded))
            .unwrap()
            .next()
            .map(|r| r.unwrap().0.value().to_vec());
        probe(&counts, "leaf-end successor plain/paired", || {
            with_resident_reads(usize::MAX, || {
                let mut range = plain.resident_range(&bounds, &mut scratch).unwrap();
                assert_eq!(
                    range
                        .next()
                        .map(|r| r.unwrap())
                        .as_ref()
                        .map(|(k, _)| k.value()),
                    expected.as_deref()
                );
                drop(range);
                let mut range = pair
                    .resident_partition_range(&paired_bounds, &mut scratch)
                    .unwrap();
                if index + 1 < RECORDS {
                    assert_eq!(
                        range.next().unwrap().unwrap().0.value(),
                        (b"bulk".as_slice(), key(index + 1).as_slice())
                    );
                } else {
                    assert!(range.next().is_none());
                }
            })
        });
    }
    for key in &keys {
        let expected = plain.get(key.as_slice()).unwrap().unwrap().value().to_vec();
        probe(&counts, "special plain point", || {
            with_resident_reads(usize::MAX, || {
                assert_eq!(
                    plain.resident_get(key).unwrap().unwrap().value(),
                    expected.as_slice()
                );
            })
        });
        for partition in &partitions {
            let encoded = ResidentKey::pair(partition, key).unwrap();
            let expected = pair
                .get((partition.as_slice(), key.as_slice()))
                .unwrap()
                .unwrap()
                .value()
                .to_vec();
            probe(&counts, "special paired point", || {
                with_resident_reads(usize::MAX, || {
                    assert_eq!(
                        pair.resident_get_pair_encoded(&encoded)
                            .unwrap()
                            .unwrap()
                            .value(),
                        expected.as_slice()
                    );
                    assert_eq!(
                        pair.resident_get_pair(partition, key)
                            .unwrap()
                            .unwrap()
                            .value(),
                        expected.as_slice()
                    );
                })
            });
        }
    }

    probe(&counts, "inactive APIs", || {
        assert_eq!(
            resident_read_fault(&plain.resident_get(b"").err().unwrap()),
            Some(ResidentReadFault::Inactive)
        );
        assert_eq!(
            resident_read_fault(&pair.resident_get_pair(b"", b"").err().unwrap()),
            Some(ResidentReadFault::Inactive)
        );
        assert_eq!(
            resident_read_fault(&plain.resident_range(&bounds, &mut scratch).err().unwrap()),
            Some(ResidentReadFault::Inactive)
        );
    });
    probe(&counts, "zero quota + nested quota", || {
        with_resident_reads(0, || {
            assert_eq!(
                resident_read_fault(&plain.resident_get(b"").err().unwrap()),
                Some(ResidentReadFault::Budget)
            );
            with_resident_reads(usize::MAX, || {
                assert_eq!(
                    resident_read_fault(&pair.resident_get_pair(b"", b"").err().unwrap()),
                    Some(ResidentReadFault::Budget)
                );
            });
        })
    });
    let giant = [0; 4097];
    let plain_key = ResidentKey::plain(b"x").unwrap();
    probe(&counts, "fixed invalid request + Error conversion", || {
        with_resident_reads(usize::MAX, || {
            let error = plain.resident_get(&giant).err().unwrap();
            assert_eq!(
                resident_read_fault(&error),
                Some(ResidentReadFault::InvalidRequest)
            );
            assert!(matches!(
                redb::Error::from(error),
                redb::Error::Resident(ResidentReadFault::InvalidRequest)
            ));
            assert!(ResidentKey::pair(&giant, b"").is_err());
            assert!(pair.resident_get_pair_encoded(&plain_key).is_err());
            assert!(
                pair.resident_partition_range(&bounds, &mut scratch)
                    .is_err()
            );
            assert!(empty.resident_get(b"").unwrap().is_none());
            let mut range = empty.resident_range(&bounds, &mut scratch).unwrap();
            assert!(range.next().is_none());
        })
    });
    // First leaf/root descent uses a bounded quota, then a later child fails.
    // Latch emits exactly once; later next calls perform no reads/work.
    probe(&counts, "later quota error fused/nonpoison", || {
        with_resident_reads(65536, || {
            let mut range = plain.resident_range(&bounds, &mut scratch).unwrap();
            let mut saw_error = false;
            for entry in range.by_ref() {
                if let Err(error) = entry {
                    assert_eq!(resident_read_fault(&error), Some(ResidentReadFault::Budget));
                    saw_error = true;
                    break;
                }
            }
            assert!(saw_error);
            assert!(range.next().is_none());
            assert!(range.next().is_none());
        })
    });
    assert!(plain.get(b"a".as_slice()).unwrap().is_some());
    // TLS check at EVERY step even if a previously acquired leaf is resident.
    // This deliberately exercises a contract violation only to prove no fallback.
    // The production caller must never let a cursor escape its scope/exclusion.
    let mut escaped = with_resident_reads(usize::MAX, || {
        plain.resident_range(&bounds, &mut scratch).unwrap()
    });
    probe(&counts, "every-step scope check", || {
        assert_eq!(
            resident_read_fault(&escaped.next().unwrap().err().unwrap()),
            Some(ResidentReadFault::Inactive)
        );
        assert!(escaped.next().is_none());
    });
    drop(escaped);

    // Cold child requests refuse ABOVE CheckedBackend; no test backend I/O is
    // used under the scope as a fallback. Ordinary warm/read is allowed after.
    let (cold_db, cold_counts) = database(0);
    let write = cold_db.begin_write().unwrap();
    {
        let mut table = write.open_table(PLAIN).unwrap();
        for i in 0..1000 {
            table
                .insert(key(i).as_slice(), &[1; 4000].as_slice())
                .unwrap();
        }
    }
    write.commit().unwrap();
    let cold_transaction = cold_db.begin_read().unwrap();
    let cold_table = cold_transaction.open_table(PLAIN).unwrap();
    let bounds = ResidentRangeBounds::plain(Unbounded, Unbounded).unwrap();
    probe(
        &cold_counts,
        "cold point + range construction refusal",
        || {
            with_resident_reads(usize::MAX, || {
                assert!(matches!(
                    resident_read_fault(&cold_table.resident_get(&key(1)).err().unwrap()),
                    Some(ResidentReadFault::ColdPage { .. })
                ));
                assert!(matches!(
                    resident_read_fault(
                        &cold_table
                            .resident_range(&bounds, &mut scratch)
                            .err()
                            .unwrap()
                    ),
                    Some(ResidentReadFault::ColdPage { .. })
                ));
            })
        },
    );
    assert!(cold_table.get(key(1).as_slice()).unwrap().is_some());
    println!(
        "PASS: native differential bounds/points/successors, typed refusals, nested quota; alloc=0 alloc_zeroed=0 realloc=0 backend read/write/sync=0 in every probe."
    );
    println!(
        "NOT a Flower capture gate PASS: native stack/transients, physical exclusion, overlay/JSON admission and retained-frame proof remain the caller's responsibility."
    );
}
