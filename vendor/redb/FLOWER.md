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


## Fixed native byte-key reader (2026-10-03)

The resident scope alone is **not** an allocation-free assertion about ordinary
`get`/`range`: tuple `Value::as_bytes` and ordinary bounds/cursor paths allocate.
Flower must use the following feature-gated APIs on tables opened **before** its
capture scope/exclusion; no new transaction/table or transaction-guard clone is
created by these readers:

- `ReadOnlyTable<&[u8], &[u8]>::resident_get(key: &[u8])`.
- `ReadOnlyTable<(&[u8], &[u8]), &[u8]>::resident_get_pair(partition, key)`.
- The preferred prebuilt point form is `ResidentKey::pair(partition, key)` then
  `resident_get_pair_encoded(&key)`. `ResidentKey::plain` is also available for
  inspecting/preparing byte-key requests; plain point reads already borrow the
  caller's byte slice directly.
- `ResidentRangeBounds::plain(lower: Bound<&[u8]>, upper: Bound<&[u8]>)`, or
  `ResidentRangeBounds::partition(partition, lower, upper)` for second-component
  bounds. Empty/equal/inverted bounds have ordinary redb range semantics.
- `ResidentRangeScratch::new()` holds one inline `[Option<Branch>; 128]` path
  and one leaf reference. Reuse it across sequential cursors, never clone paths.
- `table.resident_range(&bounds, &mut scratch)` / paired
  `table.resident_partition_range(&bounds, &mut scratch)` return a borrowed,
  forward-only `ResidentRange<'a, K>` yielding
  `Result<(AccessGuard<'a, K>, AccessGuard<'a, &[u8]>)>`.

Build bounds/keys/scratch and call their `pre_touch()` methods **before** taking
physical/logical exclusion. These methods only write-touch fixed inline storage;
they do not perform resource admission. Then, inside `with_resident_reads`,
borrow the already opened table. Consume/copy into previously admitted output,
drop yielded guards and cursor, and only then end the TLS scope/exclusion. The
scope/exclusion lifetime is a caller contract, not encoded into the Rust TLS API.
Do not return any cursor, page guard, or source handle through the closure.

```rust,ignore
let mut bounds = redb::ResidentRangeBounds::partition(
    partition, std::ops::Bound::Included(lower), std::ops::Bound::Excluded(upper),
)?;
let mut scratch = redb::ResidentRangeScratch::new();
bounds.pre_touch();
scratch.pre_touch();
// Admit native scratch/transient stack and acquire exclusion here.
redb::with_resident_reads(extent_allowance, || -> redb::Result<()> {
    let mut rows = table.resident_partition_range(&bounds, &mut scratch)?;
    for row in &mut rows {
        let (key, value) = row?;
        // Copy only admitted bytes to preallocated output; no Vec/JSON here.
        consume_preallocated(key.value(), value.value())?;
    }
    Ok(()) // rows and yielded page guards are already dropped
})?;
```

Both requested key components are limited to 4096 bytes. Inline buffers have
8202-byte capacity; exact tuple encoding is `varint(first.len()) || first || last`
(0..=253 one byte, 254 plus little-endian u16, 255 plus little-endian u32). A
maximum-sized supported pair encodes to 8195 bytes. Bounds/descent use the real
`Key::compare`, never tuple encoding byte order. Node offset/header areas and
paired-key prefixes are checked before raw accessor or tuple comparator calls.
The reader accepts the historical 255+u32 prefix safely. A seek into a leaf-end
gap ascends until the next parent child, then descends leftmost. Upper bounds and
same-partition checks occur **before** yielding any entry.

Native readers require active TLS at entry and every productive iterator step;
there is no ordinary-read fallback. Cursor errors are yielded once then fused,
with inline page-reference slots cleared on failure/end/drop. Point descent is
limited to **128 total pages**; a range holds at most **128 branches plus one
leaf**. A cycle/deeper path fails with a fixed refusal. Cached-root extents are
charged before cloning their page references; every fetched child goes through
the resident `PageResolver` hook. Guard/page clones in these excluded scopes use
the existing release-equivalent debug tracking; ordinary tracking is unchanged.

`StorageError::Resident(ResidentReadFault)` and `Error::Resident(...)` carry the
fixed enum directly, not an `io::Error` box. In addition to `ColdPage`,
`Contended`, and `Budget`, refusals include `Inactive`, `Depth`, `Corrupt`, and
`InvalidRequest`. New reader failures do not build `Corrupted(String)` or call
`format!`, and occur above `CheckedBackend`. Invalid resident page orders,
regional extents, and cache extent mismatches also return fixed `Corrupt`.
Genuine backend `Io`/`PreviousIo` behavior and its latch are unchanged.

### Native storage measurements and admission limitation

Measured by the exact vendored native harness on this x86-64 toolchain:

| `size_of` object | debug | release |
| --- | ---: | ---: |
| `ResidentKey` | 8,216 B | 8,216 B |
| `ResidentRangeBounds` (two key buffers) | 16,440 B | 16,440 B |
| `ResidentRangeScratch` | 6,200 B | 5,168 B |
| `ResidentRange` (plain or paired) | 32 B | 32 B |
| one byte/tuple `AccessGuard` | 104 B | 96 B |

These are **object sizes, not a total native stack high-water proof**. Admit all
simultaneously live scratch, bounds, request keys, cursor/guards and traversal
helper/transient native stack separately from copied raw output/overlay/JSON.
In particular, `resident_get_pair` builds an inline `ResidentKey` in its helper
stack, with compiler-dependent temporary/move storage; use the prebuilt encoded
form to avoid that large helper local inside exclusion. Bounds/scratch are
borrowed, not moved into the resident cursor. Resident page extent quota is a
separate cumulative allowance, not a charge for native stack storage or total
retained redb cache memory. There is no global allocator interception in the
production reader.

### Reproducible isolated native checks

Both harnesses have their own workspace/lock, add no production dependencies,
and run offline. `resident-unit-harness` compiles the exact `../src/lib.rs` and
uses upstream's already available rand/tempfile dev dependencies without the
uncached redb-2.6 compatibility-test dependency. Allocator probes are test-only.

```sh
cargo run --offline --manifest-path vendor/redb/resident-harness/Cargo.toml
cargo run --offline --release --manifest-path vendor/redb/resident-harness/Cargo.toml
cargo test --offline --manifest-path vendor/redb/resident-unit-harness/Cargo.toml --lib -- --test-threads=1
cargo fmt --manifest-path vendor/redb/resident-unit-harness/Cargo.toml -- --check
cargo fmt --manifest-path vendor/redb/resident-harness/Cargo.toml -- --check
```

The single-process differential harness compares typed ordinary redb points and
ranges, with all fixture warming done outside measurement/TLS. Its large plain
fixture has 11,051 leaves, 197 branches and height 4; both plain and paired full
forward scans exceed 10,000 leaves. It covers include/exclude/unbounded/equal/
inverted/empty bounds, missing points, every bulk leaf-gap successor, empty keys
and partitions, NUL, Unicode, prefixes, 4096-byte components and tuple encoder
byte equivalence at first lengths 0/253/254/4096. It counts `alloc`,
`alloc_zeroed`, and `realloc` around **only** native resident calls, plus backend
read/write/sync counters. Debug and release runs record zero in every probe,
including cold/budget/inactive/invalid-request refusals, cursor steps, late
quota fault/fusion, nested quotas, and ordinary reads after nonpoisoning refusal.

Exact-source unit probes additionally cover malformed headers/offsets/tuple
prefixes, corrupt page orders/addresses/cache extents, exact depth boundaries,
cycles, cold later-child errors, deterministic held-cache/write-buffer
contention, nested cumulative quota, and genuine backend I/O latching. All fixed
fault point/cursor/cache probes assert zero `alloc`/`alloc_zeroed`/`realloc`.

Rust 1.99's strict vendored clippy encounters upstream-only `assert_is_empty`
and `unnecessary_trailing_comma` denials; do not rewrite unrelated upstream
ordinary paths. The focused check keeps every other lint denied while forcing
only those two existing classes to warnings:

```sh
cargo clippy --offline --manifest-path vendor/redb/resident-unit-harness/Cargo.toml --lib -- \
  -D warnings --force-warn clippy::assert_is_empty --force-warn clippy::unnecessary_trailing_comma
cargo check --offline --manifest-path vendor/redb/resident-unit-harness/Cargo.toml --no-default-features --features std
RUSTFLAGS='-C panic=abort' cargo check --offline --manifest-path vendor/redb/resident-unit-harness/Cargo.toml \
  --no-default-features --features experimental-api-5
```

This evidence is **not** a Flower SQL capture/retention gate PASS. Flower's
mutation exclusion, preflight native/arena admission, output/overlay/JSON limits,
source-handle drop ordering and retained-frame proof remain separate obligations.
No parent Flower source is changed by this vendored extension.

## Public scope boundary and safe guard escape

`with_resident_reads<T>` constrains **page fetches**, not arbitrary closure heap
allocation, native stack usage or returned `T`. It is a safe generic API, not a
compiler-enforced SQL no-escape capability. Read-only resident methods borrow
`ReadOnlyTable`; its existing transaction guard pins MVCC pages. A `PageImpl`
owns immutable `Arc<[u8]>`; writable access remains `Arc::get_mut(...).unwrap()`
in `WritablePage::mem_mut`. Omitting debug alias tracking cannot create a mutable
alias through this API. An escaped read guard can nevertheless extend a pin or
obstruct normal writes; Flower's SQL facade must never permit it. The combined
scope-escape regression retains old immutable bytes while an ordinary writer
commits, then drops guards/table and successfully closes the old transaction.
No unsafe generalization or whole-closure no-heap theorem is claimed.

The new explicit byte-key readers and cached-root `get` charge page extents.
Ordinary `first`/`last` cached-root methods are not Flower capture APIs and are
not an admission/reference-budget certificate. Ordinary generic tuple/get/range
may allocate key/path memory even within this page-only scope. Flower does not
use them for capture or certificate validation.
