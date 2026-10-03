# SQL snapshot retention: hard gate remains closed

**Decision, October 3, 2026:** `Records::sql_snapshot_reservation_bytes()`
returns `None` for every snapshot. This is an explicit unavailable bound, **not
zero bytes and not a measurement**. SQL admission must reject `None`; do not
substitute the 128 MiB allowance, the guest budget, or a row/serialized-byte count.
The method is feature-gated with `sql`, O(1), and performs no I/O, traversal,
JSON parsing, memo insertion, or cache population. Ordinary Records behavior is
unchanged. In-memory snapshots are also rejected: this change does not claim a
complete accounting proof for those roots.

## Why the proposed map/value counter is insufficient

`Records` retains more than its current rows (`src/consensus/records.rs`):

- `map` contains an `im::OrdMap` root, tree nodes, owned key allocations,
  tombstones, and shared `Arc<Value>` trees. Old clones retain these allocations
  even after the live revision replaces/removes entries or rebases.
- `invalid_depth` and `invalid_sources` are additional persistent ordered roots
  with their own key copies and nodes.
- `graph` and `graphs` retain `ReactiveIndex` structures. These include scan
  window treaps, nested persistent field-set maps/sets, validation errors and
  their strings. The `narrow` and `buckets` sets deliberately retain stale
  field sets after a cell is removed (`src/evaluator/rust_engine/metadata.rs`).
- `memberships` deliberately retains a token and owned marker for every
  collection/index once seen, even after all its source/index rows disappear.
  A zero-row Records can therefore retain growing historical metadata.
- `view` owns a generation string. A backing-reading instance's `memo` owns a
  hash table, key copies, boxes and shared decoded values. Clones start without
  memo entries, but that alone does not bound the other roots.

A real in-memory metric must account for all reachable nodes, capacities,
control blocks, retained JSON trees, and metadata, including stale metadata.
Counting serialized JSON or estimating the graph via its current record keys
is not such a proof. Insertion/removal, bulk load, deserialization,
`rebuild_metadata`, graph views, clones, stamp/path copies and rebases all need
explicit accounting invariants. An overflow/unsupported state must return
`None`. The SQL source's bounded, non-memoizing `entries` scans avoid one
retention path but do not remove these snapshot roots.

## A backed snapshot also causes future shared-database growth

Flower's `Backing::Pair` owns an `Arc<ReadOnlyTable>` and a partition prefix;
`serve_partitions` opens all the paired tables from **one database read
transaction** and shares those tables between partitions
(`src/consensus/backing.rs`, `src/consensus/store/partition_storage.rs`). The
partition's row count is not the read pin's retention scope. Furthermore,
`Backing::len` counts a paired partition by enumerating its range: it is not
an O(1) pre-admission size metric.

The locally resolved redb 4.3.0 implementation gives concrete evidence:

- `src/transaction_tracker.rs::oldest_local_referenced_transaction` returns the
  oldest retained read transaction.
- `src/transactions.rs::durable_commit` chooses its reclaim horizon from that
  oldest active transaction before processing freed pages. A small SQL
  partition's old read pin can delay reclamation of page churn in other
  partitions/tables in the same database.
- `src/tree_store/page_store/page_manager.rs::grow` expands the database layout
  and calls `Allocators::resize_to`.
- `src/tree_store/page_store/region.rs::Allocators` owns
  `Vec<BuddyAllocator>` plus the region tracker. `resize_to` grows those native
  structures with the layout.
- `src/tree_store/page_store/buddy_allocator.rs::BuddyAllocator` owns
  `Vec<BtreeBitmap>`. Bitmap size grows with region/page count. This is native
  allocator metadata, **not a cache of database row pages**. The cache limit
  set by `FLOWER_REDB_CACHE_BYTES` does not cap these structures.

Thus disk-page retention and native retention must be distinguished:

1. Old database pages/free-page records primarily consume **disk space**. It
   would be incorrect to charge every pinned disk byte as resident native
   memory, or to claim file growth directly measures RSS.
2. Growth also increases **native allocator metadata** (and can require
   transient write-side allocation). No snapshot-local bound on future
   database-wide writes or allocator growth is exposed/enforced here. The
   current root's size plus a constant redb cache allowance does not bound it.
3. `Backing::in_memory` test databases have another distinction: the backing
   storage bytes are themselves native memory. `Run` spooled backings retain
   an in-memory block index as well as a disk file. Neither can be treated as
   a constant-size generic backing.

The fixed snapshot allowance cannot bound arbitrary subsequent writes merely
because SQL has a time limit. Periodic metrics and post-growth cancellation
also discover overrun **after** allocations; they are not a hard reservation.
There is no proved <=128 MiB bound for all snapshot-induced retention with the
current pin. The redb format's much larger finite maximum is not that bound.

## Required admission integration

Before starting native SQL or cloning/pinning its input, the owner must obtain
`sql_snapshot_reservation_bytes()`. Reject unknown (`None`) and bounds above
the snapshot cap. Reserve the full configured snapshot allowance in node
admission in addition to guest, Rust, SQLite allocator and bridge budgets;
keep that permit until the actual job/snapshot is dropped, including cancelled
jobs. **With this implementation, every such call is rejected.** This is a
foundation safety gate, not an enabled SQL execution path. These Records-only
changes do not wire service admission themselves.

To open the gate without a scan merely to answer `LIMIT`:

- Prove and transactionally maintain the complete in-memory reachable-root
  accounting, or introduce a minimal SQL-specific root that omits unneeded
  metadata and has that proof. Account immutable old roots independently of
  later live writes. Do not use a current-map-only byte count.
- Either reject every backed snapshot, or add an enforceable database-wide
  retained-page/native-metadata growth allowance charged **before writes
  allocate**, coupled to the oldest SQL pins. An isolated bounded SQL copy or
  a backing implementation with explicit memory/pin limits is another design,
  but copying the whole organization just to answer `LIMIT` is not this design.
- Prove each supported backing variant separately, including database-owned
  storage/cache/native state and spooled-run indexes. Distinguish disk and
  native budgets.
- Add threshold/overflow and concurrent-write tests for the accounting proof,
  not only deadline or periodic-monitor tests.

## Focused evidence tests

`records_sql_snapshot_tests.rs` checks:

- Fail-closed behavior across new/from/extend/shared insert/deserialize/view
  paths, old cloned values retained through replacement/removal, and release
  after dropping that old root.
- A source-row-free map still retaining historical membership tokens.
- A counted **disk-backed paired table with its redb page cache disabled**:
  checking admission performs no backend reads, JSON decodes or memo insertion;
  other/current partition page churn grows the file while the old root remains
  pinned, and rebase does not invalidate that old root. File growth is evidence
  of retained disk pages, not a measured native-byte cap. Native metadata growth
  is established by the redb implementation above, not an RSS assertion.
- Spooled and empty backings remain rejected rather than assuming their
  unknown retained memory is zero.
