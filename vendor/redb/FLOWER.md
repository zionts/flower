# Flower's resident-only redb extension

Source: the exact `redb-4.3.0.crate` resolved by Flower's Cargo.lock. Both upstream MIT and Apache-2.0 notices are retained. No on-disk format, allocator, transaction, reclamation or ordinary cache behavior is changed.

Feature `flower-resident-reads` adds a synchronous scoped read allowance. `PagedCachedFile::read` checks it **before** `read_direct_into_arc`, cache insertion, eviction, buffered-write flushing or backend I/O. The resident branch uses try-locks and only clones already resident cache/write-buffer page references. Every requested extent, including repeated reads and misses, consumes the cumulative byte allowance before lookup. A cold page, contended lock or exhausted allowance is a typed, non-latched refusal above CheckedBackend; it does not poison the database as a backend I/O error would.

This is not a page-cache hard-size assertion. Ordinary redb cache counters remain ordinary redb behavior. Flower captures reserve their own raw arena and native scratch/reference allowance. They do not retain resident page references outside a short capture slice. Cold/oversized extents cannot allocate a new page buffer under the capture scope.

The caller must supply physical/logical mutation exclusion, preallocated output, bounded examined-entry/JSON-overlay work, a common logical/history/code/install epoch, and drop all range/page/table/source handles before the scope exits. The API is synchronous and thread-local: never spawn asynchronous work, write, or return source handles through it. Nested scopes share the original cumulative allowance. Flower's public capture API returns only owned bytes and scalar stamps.

There is deliberately **no prefetch/cache-insertion API** in this initial patch. A cold capture fails closed. A future prefetch must occur with no full Records/read-transaction pin and prove physical-epoch/page-reuse checks before insertion; an ordinary read with a pin is not an acceptable SQL prefetch. First-release acceptance still requires real stored-data positive captures and queries, not an always-cold implementation.

Changes from upstream:
- `src/resident.rs`: scoped budget, refusal payload and inspection helper.
- `src/tree_store/page_store/cached_file.rs`: quota-first resident-only read branch.
- `src/tree_store/btree.rs`: charge cached-root point reads before touching pages.
- `src/tree_store/page_store/{page_manager,base}.rs`: externally mutation-excluded resident scopes use untracked read-only debug pages/clones, avoiding blocking debug locks and unbounded alias-map growth. All such pages must drop before the resident scope/exclusion ends. Ordinary debug alias tracking is unchanged.
- `src/lib.rs`, `Cargo.toml`: feature/API wiring.
- Focused tests exercise resident cache/write-buffer hits, cold and oversized pre-read refusals, no backend reads/writes/flushes, scope reset/nested cumulative quota, and unchanged ordinary reads after refusal.

Flower keeps the old full `Records` SQL reservation gate returning None. This extension supports a separately proved terminal authorized frame; it does not make the old pinned snapshot safe.
