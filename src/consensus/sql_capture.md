# SQL bounded capture: storage proof and open gates

Source inspection of the `sql-bounded-capture` working tree, October 3, 2026
(base `4a240b6`; storage primitive handoff). Paths below are
repository-relative; function/type names are the source anchors.

**This is a storage-layer handoff, not SQL activation or a public/native SQL
PASS.** `Records::sql_snapshot_reservation_bytes()` still returns `None` for
all roots, and `Cargo.toml` keeps `sql` out of default features. The old full
snapshot route remains HOLD. The new API removes the additional long-lived SQL
source pin; it does not prove the whole node's baseline serving/cache memory.

## API and ownership invariant

```rust
Consensus::sql_capture_fence().await -> anyhow::Result<SqlCaptureFence>
Consensus::sql_capture_slice(
    &SqlCaptureFence,
    Option<&SqlCaptureEpoch>,
    SqlCaptureRequest<'_>,
    SqlCaptureBuffer,
) -> Result<SqlCapturedSlice, SqlCaptureError>

SqlCaptureBuffer::from_reserved(Box<[u8]>) -> Result<SqlCaptureBuffer, SqlCaptureError>
SqlCaptureBuffer::reservation_bytes(capacity: usize) -> Option<usize>
```

A capture borrows **the current publication**, under physical-database capture
exclusion and a publication `try_read`; it does not clone its `Records` root.
`Records::sql_capture_raw` borrows overlay values or obtains short-lived raw
backing guards. On success and every error/unwind, redb ranges, `AccessGuard`s,
page references and the publication borrow end before capture exclusion ends.
The returned slice owns only the supplied byte buffer, fixed slots,
continuation bytes and epoch metadata. No `Records`, `Backing`, `ReadOnlyTable`,
`Arc<Value>`, redb range or source guard escapes. Returned `Range<usize>` fields
are offsets into **owned bytes**, not storage iterators.

Thus SQL cannot retain an old read transaction while later physical writers
allocate/reclaim pages: writers are excluded during the borrow, and SQL owns no
source pin afterwards. This is not a claim that ordinary serving roots, backups
or other non-SQL snapshots never pin redb.

Anchors: `src/consensus/read.rs::{sql_capture_fence,sql_capture_slice}`;
`src/consensus/store/sql_capture.rs::Store::sql_capture_slice`;
`src/consensus/records/sql_capture.rs::Records::sql_capture_raw`;
`src/consensus/backing/sql_capture.rs::{RawRange,RawEntry,capture_raw_get}`.

## Fresh fence, logical epoch and representation

- The asynchronous fence uses the existing fresh replica/quorum cohort and
  no-clone `Store::has_applied_fence` readiness check. Its wrapper binds the
  proof to the **originating Store identity and partition binding**; a fence
  from another Store or namespace is rejected. Store identities use checked,
  nonwrapping allocation, not a caller-supplied Raft node ID.
- Under exclusion, capture checks the applied log identity/revision against the
  fence and resolves a scoped partition with `partitions::active`. A serving
  prefix newer than the fence is possible; the first slice reports its epoch.
  Subsequent slices compare the complete expected epoch: Store identity,
  installation generation, selected application revision **R**, and partition
  name/ownership epoch. Installation increments separately because it can
  replace state at the same R. A fence is not a reusable authorization lease.
- **Current validation is strict R.** Changes to R reject an attempted frame.
  Liveness under unrelated writes is **not proved**; an implementation that
  aborts every useful query during churn is not a successful safety gate.
  End-to-end fresh validation of history/code/authority/rows remains the
  terminal driver's responsibility, not an automatic final step of this API.
- **R does not prove raw-byte equivalence.** `Records::rebase` preserves logical
  records/versions/metadata but can move an overlay into packed backing storage
  without changing R. Every metadata chunk must agree on version, encoding,
  `json_bytes`, `total_body_bytes`, key and selected mode/field, with contiguous
  `body_offset`s. Never splice `StringChunk` and `KeyChunk`, or overlay and
  backed representations merely because their epochs match. The API has no
  separate overlay/backing representation-generation stamp; stable chunk
  representation or an additional identity/check must be proved before use.

Anchors: `read.rs::replica_fence`; `read/batch.rs`;
`store.rs::{has_applied_fence,install_snapshot}`;
`store/sql_capture.rs::{next_identity,sql_capture_bind_fence,sql_capture_slice}`;
`records.rs::rebase`; `sql_capture.rs::{SqlCaptureEpoch,SqlCapturedRecord}`.
(All anchors in this paragraph are under `src/consensus/`.)

## Quota-first output and bounded work

The admitted owner must reserve capacity **before allocation/capture**, allocate
and pass a **1..=64 KiB** boxed slice, and retain its admission lease until the
actual buffer/job is destroyed. `from_reserved` pre-touches it. The storage API
checks capacity but does not itself acquire a node admission lease.
`reservation_bytes` counts `size_of::<SqlCaptureBuffer>() + capacity`, including
32 inline record slots and the 4 KiB continuation array. Fence/epoch partition
strings, native scratch, the eventual frame and decoder allocations are
**additional**, not covered by this buffer number.

| Selection | Contract and refusal boundary |
| --- | --- |
| `Keys` | At most 32 keys/slots; every requested key has a checked present or absent slot. An uncaptured key is not absence. |
| `Range` | Physical `[lower, upper)` keys after `after`; at most 32 returned slots and 128 examined overlay/stored entries. Tombstones and shadowed backing entries consume work; the ordinary tombstone-skipping `Merge::next` is not used. |
| `KeyChunk` | Stored body and advertised JSON length each at most **16 MiB**, copied without unpacking. Small overlays serialize in one bounded pass; generic large overlay JSON refuses. |
| `StringChunk` | An overlay string field, notably `bundle.javascript`, copied as raw UTF-8 without scanning/serializing the whole string. Backed strings are unsupported here. Join bytes before UTF-8 decoding/compilation; a chunk may split a code point. |

Request keys/bounds/fields are at most 4 KiB. Continuation presence is separate
from its length, so `Some("")` is valid. A row/work/capacity stop is **not** proof
of range completeness: obey `complete` and the last consumed continuation,
including zero-row slices. Any whole-frame exhaustion must reject the query,
never produce COUNT/SUM over a silently truncated prefix.

For an overlay/native JSON value, `json_bound` preflights at most 4,096 nodes,
depth at most 128 and conservative escaping (`6 * UTF-8 length + 2`) before
`serde_json::to_writer` writes into the fixed slice. Large strings/nodes refuse
before serialization; this path does not clone values or fill the memo/cache.
For backed JSON, `stored_parts` reads the eight-byte version header and
`packed::json_len` **before decode**. Ordinary row copy additionally limits
advertised JSON to 64 KiB; metadata chunks permit the separate 16 MiB bound.
The caller must reserve joined raw bytes, decompression, nodes/text and scratch
before unpacking outside capture, and reject corrupt packed data.

Anchors: `src/consensus/sql_capture.rs::{validate,from_reserved,reservation_bytes,
record,chunk,value,json_bound,SliceWriter}`;
`src/consensus/records/sql_capture.rs::{stored_parts,sql_capture_raw}`;
`src/consensus/packed.rs::{json_len,unpack}`.

## Resident references are not native scratch

Capture enters `redb::with_resident_reads(32 * 1024 * 1024, ...)`. This is a
**cumulative requested extent-byte allowance**, not a cache-size or RSS claim.
Every requested extent, including repeats/misses, is charged before lookup,
new page-buffer allocation or backend I/O. Point reads of an already
`cached_root` are also charged; otherwise they would bypass the allowance.
Nested scopes cannot renew it, and RAII resets it on unwind.

The resident branch only clones already resident cache/write-buffer `Arc`s,
uses cache `try_read`/`try_lock`, and performs no insertion, eviction, buffered
write flush or backend read. Cold, contended and budget faults are typed,
non-latched refusals created above `CheckedBackend`; normal backend failures
retain their normal semantics. There is **no SQL prefetch/fill path** here.
Cold data therefore fails closed, not via an ordinary pinned fallback read.

In debug builds, `PageImpl` tracking is `Option<...>`. Newly read/cloned pages
inside the resident scope use `None`, avoiding shared debug HashMap growth and
blocking alias-tracking locks. This bypass is sound **only with external
physical/logical mutation exclusion and no escaped pages**. Existing tracked
pages retain their tracking; ordinary debug reads/clones/drops still use the
original checks. The generic redb scope's contract is not itself a
compiler-enforced no-escape or mutation-exclusion capability.

Anchors under `vendor/redb/`: `src/resident.rs::{with_resident_reads,charge,fault}`;
`src/tree_store/page_store/cached_file.rs::{read,read_resident}`;
`src/tree_store/btree.rs::{get,get_helper}`;
`src/tree_store/page_store/{page_manager.rs::get_page,base.rs::PageImpl}`;
`FLOWER.md` (extension contract and retained upstream notices).

### Native scratch ledger: source sizes, not an RSS estimate

Neither the 64 KiB output reservation nor the 32 MiB extent allowance charges
the allocations below. They must be covered **before** capture/admission and
before any proposed certificate validation; a complete enforced native scratch
quota is still unproved.

| Component | Source-grounded bound / remaining obligation |
| --- | --- |
| Paired point/range key encoding | `tuple_types.rs::serialize_tuple_elements_variable` reserves component bytes plus 5 bytes per variable component. With two 4 KiB components, its requested capacity is at most **8,202 bytes per bound/key**. `btree_iters.rs::encode_bounds` makes an additional `to_vec` copy per bounded endpoint: two owned endpoint vectors remain, plus the temporary tuple vector while encoding. Account for copies, not just the logical key length. Plain byte keys borrow for point get but range encoding still copies. |
| Flower strings | Overlay lower/upper range markers are cloned with `str::to_owned`, each at most 4 KiB. Paired range `backing.rs::upper` constructs a partition-plus-NUL string (at most 4,097 bytes). The bounded partition clone is made before the capture permit/root borrow, but still needs its own reservation. Fixed continuation copying does not allocate. |
| redb paths/guards | `btree_base.rs::MAX_BTREE_DEPTH = 128`; point get is an iterative bounded descent. `btree_cursor.rs::descend_to_position` caps each `Vec<Branch>` path at 128 branches. `BtreeCursorRange` can have front/back cursors, although this copier uses forward `next` only. Count vector capacity/reallocation peaks and guard/Arc metadata separately from referenced extent bytes. No raw record key/value is copied into a new heap body by these read-only guards. |
| `im` overlay iterator | Locked `im 15.1.0`, `src/ord/map.rs::range` and `src/nodes/btree.rs::Iter::{new,step_forward}` use **two Vec paths of borrowed node/index pairs**. The bounded range-marker clones are Flower's, not a clone of the map/value root. Path storage follows the live overlay tree's height, not the 128-entry examined cap; `im` does not enforce the redb depth limit. Derive/validate a supported-platform height/capacity allowance or use pre-reserved bounded traversal before claiming a hard scratch quota. |
| JSON preflight/serializer | Both passes are bounded by the preflight depth 128 (root depth 0) and 4,096 nodes, with `SliceWriter` reusing the output. Their call-stack frames, number/escape formatting temporaries and bounded error wrappers are separate native costs; depth is not a byte reservation for the thread stack. |
| Fault paths | `ResidentReadFault` is fixed-size; `io::Error::new` boxes the typed fault/error metadata rather than a payload proportional to an extent. Constant corruption/error messages and serializer error wrappers still have heap costs. Include their allocator overhead; they are not free because the successful copy is fixed-buffer. |

The ledger bounds logical/requested allocation inputs where shown. It is **not
an exact RSS figure, a mimalloc metadata proof, or a completed node quota**.
Allocator rounding/metadata, vector growth/old-new coexistence and stack
provisioning require explicit allowance/enforcement. Outside-capture
unpack/parse/compile/frame/cache memory requires its own admission proof too.

## Complete physical/logical exclusion inventory

One `SharedDatabase::capture_gate` serves every replica using the physical
file. Capture never queues and declines for active/waiting mutations or another
capture. Waiting writers have priority. Release wakes writers and charges one
shared cooldown: finish time plus `max(1 ns, 9 * measured hold time)`, including unwind
and release-lock delay. Ordinary mutations may coexist and do not wait for the
cooldown. This bounds aggregate capture occupancy, **not successful-query
liveness**. `Busy` is not permission to poll; `Paced(due)` permits one scheduled
wake followed by a new admission attempt. There is no fixed millisecond
floor; the async controller must yield or await that deadline between slices.

Production write-capable `Database` access outside `shared.rs` goes through
`database_under_mutation(&MutationPermit)`: it asserts the permit belongs to
the same gate and ties the reference lifetime to that live permit. Unguarded
`database()` is test-only; ordinary backup read-only access uses `begin_read`.
The current runtime inventory is:

| Path | Exclusion lifetime |
| --- | --- |
| `DatabaseWork::run`, `disk_profiled`, `read_disk` | Actual blocking job owns the permit, not its cancellable awaiting future. Direct votes, truncation, purge, checkpoint and backup/restore transactions remain covered through commit/abort/drop. Even runtime helpers receiving a raw `Database` for reads use this capability. |
| `Store::apply` | `DatabaseWork` covers rebase, logical application, complete publication and persistence submission; not just a later physical transaction. |
| `Store::install_snapshot` | Covered physical replacement plus installed backing construction, root publication and installation-generation update. Detached snapshot-file decode beforehand does not mutate the live database. |
| `SharedDatabase::commit` | Own permit spans begin, every staging callback, failed-stage abort/drop, restaging/retry, and final commit/drop. Cancelling a `Submitted` waiter cannot release the real job's permit. This covers batched appends/persistence/lazy flushes. |
| `Store::open` on an already shared database | Separate permit covers table creation, startup state/backing construction and recovery bookkeeping, while other replicas may already be live. |
| File compaction | `compact_when_doubled` runs before `SharedDatabase::with_database` publishes the new database; no live capture can observe it. There is no runtime compaction capability bypass. |

Keep this inventory true when adding a writer; a published-lock borrow alone
cannot exclude writes to another partition/table in the same redb file.

Anchors: `src/consensus/store/capture_gate.rs::{CaptureGate,MutationPermit,
CapturePermit}`; `src/consensus/store/shared.rs::{database_under_mutation,
begin_read,commit,open,compact_when_doubled}`;
`src/consensus/store.rs::{DatabaseWork,disk_profiled,read_disk,apply,
install_snapshot,open}`; `src/consensus/store/{persistence,lazy_flush,backup}.rs`.

## App/Consensus lifetime and namespace gates still open

`Consensus::partition` clones a handle and changes its binding: it uses the
**same mutable physical Store**, not a frozen partition Records root.
`PartitionCommand::Discard` resets snapshot data/receipts, base, last import
and chunks, and marks their physical replacements; this root release does not
depend on dropping an `Arc<App>`. In the currently supported static hosted
process, `main.rs` retains every group's `Consensus` in `hosted` throughout the
servers' lifetime, drains servers, then shuts down the groups.

**Arbitrary dynamic group removal is not supported/proved.** `Store::close`
only drains pending persistence/lazy/background work; it does not replace or
clear the publication held by remaining Store/Consensus handles.

Nor does removing a partition's registry entry prove an old `Arc<App>` was
freed: handlers can still own it, and `App` owns query caches whose encoded
results/certificates have heap allocations. The pending source controller
must use a weak controller with current reacquisition for each slice/validation
(or another proved lifecycle design), rather than an old source/App owner
across waits. Detached/cache-result memory surviving removal needs a
process-global lease until its last owner actually drops; a partition-local
budget reset cannot erase that retention. **That controller/accounting is not
implemented by this storage API.**

The storage API now provides `Consensus::check_availability()`: it shares the
exact startup-recovery cohort barrier with `snapshot_for`, then checks the
current publication's active partition metadata without a Snapshot/Records clone.
Foundation must replace namespace Runtime's `Registry::app` call to
`bound.snapshot_for(None)` with this helper before terminal routing. A temporary
full root clone before SQL admission is not a quota-first proof.

Anchors: `src/consensus/partitions.rs::{Consensus::partition,Discard}`;
`src/consensus/store.rs::{close,partition_snapshot}`;
`src/main.rs` (`hosted` server/drain/shutdown sequence);
`src/service.rs::App`; `src/service/query_cache.rs::{QueryCache,Entry}`;
`src/service/partitions/router.rs::Registry::{app,refresh}`.

## Primitive evidence and selective candidate history

The first positive stored-input witness is
`records/sql_capture/tests.rs::sql_capture_paired_disk_copy_is_positive_without_memo_parse_or_escaping_read_pin`:
a **real disk-backed paired redb table**, no capture backend reads/writes or
memo/parse fill, a checked absent slot, backing weak-reference release, then
explicit old `ReadTransaction::close` **before 64 other-partition writes** while
the owned input remains. Warming is fixture setup, not an approved SQL
prefetch. This is raw-storage evidence, **not SQLite/HTTP integration**.
Other capture/store tests exercise chunk bounds, nested cumulative allowance,
unwind reset, origin/epoch rejection, real writer exclusion and cancellation.
The installation test changes the generation directly; it is not a complete
network snapshot-install scenario.

Measured branch checks before final handoff:

- Capture/store tests **12 PASS**; shared/gate tests **14 PASS**.
- Records regression suite **25 PASS**; snapshot HOLD suite **5 PASS**;
  default-feature gate suite **14 PASS**. HOLD-test success means correct
  refusal, not admission or launch success.
- Library clippy exits **0**, with **21 baseline warnings**. All-target clippy
  fails on the untouched `3.14` fixture in
  `src/evaluator/wasm/tests/values.rs`; do not describe it as a full clean pass.

SQL/default library checks pass; npm check passed typecheck and 570 Node tests.
Full default workspace tests failed: Flower library 801 passed, 7 failed,
12 ignored. Failures include backup/recovery, normalization, Wasm numbered-op
and API fixtures, and three recycle-budget/timeout tests. They are not all
classified as baseline; no full-workspace green claim is made.

A candidate to replace strict-R aborts is a bounded selective certificate:
copy **value-change generation markers, not only membership-key markers**, and
point versions/checked absences; validate all dependencies at **one common fresh
revision**, with Store/install/partition/history/code/authority identity still
bound. `Records::generation` returns scalar tokens; `update_memberships`
changes the value marker on every member write but key markers only on
appearance/disappearance. `Records::rebase` preserves these membership tokens
and logical versions rather than rebuilding them, which is a source-grounded
reason the candidate may tolerate physical rebases.

The selective candidate was subsequently implemented in the followup below;
it does not make ordinary evaluator certificates an acceptable substitute.
The existing `DependencyCertificate::valid` is not a safe drop-in: its changed
window-marker branch walks `range_versions`, and other validation performs
ordinary Records reads. The new validator must have no fallback walk and no
root pin, stay quota-first/resident/work-bounded, and reject changed relevant
markers. Checking dependencies separately at different fresh revisions does
not establish one coherent frame. Chunk representation identity, controller/
namespace fixes, complete native/frame admission, detached authorization and
real positive terminal/native SQL integration remain hard launch gates.

Anchors: `src/consensus/records.rs::{generation,rebase,raw_version}`;
`src/evaluator/rust_engine/metadata.rs::update_memberships`;
`src/evaluator/rust_engine/dependencies.rs::DependencyCertificate::valid_records`;
`src/consensus/{sql_capture.rs,records/sql_capture/tests.rs,
store/sql_capture/tests.rs,store/capture_gate.rs,store/shared.rs}`.

## Selective dependency extension (followup, not activation)

The strict-R API is retained. A separate selective API permits unrelated
revision advances without weakening the current-publication/mutation barrier:

```rust
SqlCaptureCertificate::from_reserved(&fence, Box<[u8]>)
Consensus::sql_capture_certify(&fence, &mut certificate, &[dependencies])
Consensus::sql_capture_certified_slice(&fence, &certificate, request, buffer)
Consensus::sql_capture_validate(&fresh_fence, &certificate) -> SqlCaptureEpoch
```

The certificate owns at most 128 selectors and a caller-pre-admitted/pre-touched
key slab of at most 512 KiB. `reservation_bytes` includes the fixed slots; its
bounded binding clone and native scratch remain additional. No root, source
handle, callback, Value, iterator or database is retained. Private expected
stamps cannot be caller-forged/reset. Selector overflow refuses; changed
existing stamps are never adopted. Admission/retry failure is not permission
to discard dependencies and continue with the same partly captured input.

`Point(key)` refers to a physical key, including explicitly checked absence.
A new fallible resident-only getter reads an overlay scalar or a checked
8-byte backing version header, without ordinary `raw_version`, decoding,
memo/global-cache fill or spool fallback. `Collection(name)` takes a **raw,
unencoded logical collection name**; quota-first encoding before exclusion
constructs `collection:<canonical JSON string>` in the admitted slab. It is
the entire collection's VALUE generation, not `keys:` or a window marker.

Each certify call compares every previous expected dependency and stamps new
ones against ONE current publication under the same resident/exclusion scope.
Each certified slice again checks every accumulated dependency. Coverage is
mandatory: points/chunks must match a certified point or whole source
collection; ranges must lie inside one certified collection's canonical native
source-key prefix, with a bounded exclusive upper no later than that prefix's
comma-to-hyphen successor. Unbounded/arbitrary/index ranges are refused. This
is full-collection certification even for a narrower captured range, not a
claim of separately proved window/prefix change tracking.

The controller must finish complete logical relations/support, check chunk
representation/version/encoding/length/offset consistency, request a **fresh
fence**, and validate ALL accumulated selectors at ONE final publication.
That returned selected revision is **Rseal**, the common coexistence witness
for all copied inputs. Freeze it as sourceRevision; never substitute first-
slice R or a later delivery R. The storage certificate does not certify
controller completeness, row policy, omitted dependencies, temporal expiry,
or final authorization by itself. Delivery still requires fresh validation
and current authorization. Clock-polled permissions need an independently
proved future expiry; a marker alone cannot certify passage of wall time.

Physical rebase preserves logical versions/generations but not necessarily raw
encoding. Install/Store/partition-binding identity protects marker resets and
version reuse. A positive point version rejects rewrite ABA. A checked absent
point that was created and removed before the final publication can remain
valid: it certifies absence at Rseal, not “never existed.” Include full
collection VALUE generation to reject intervening published membership changes.
An insert/delete collapsed inside ONE atomic apply batch has no observable
intermediate publication and need not change an absent generation. The
process version generator now reserves blocks with checked atomic addition;
identity exhaustion is fatal/fail-closed rather than reusing old scalars.
Stored high-water exhaustion also prevents new blocks; no wrap is permitted.

### Measured selective storage evidence

All **22 capture tests passed** on the followup tree. The real native-backed
10,000-row fixtures pre-reserve their raw frame before capture; they decode
copied input outside the guard and require every distinct row, exact count and
sum. Actual same-selected-root/partition unrelated-collection writes,
persistence, blank control publication and persisted votes run on a background
executor between slices while copied input remains owned. Busy retry is allowed
only after an actual completed storage notification; Paced uses its supplied
wake deadline. No all-abort, zero-row or truncated aggregate counts as success.

| Fixture | Slices | Writes / votes | Exact count / sum | Elapsed | Common Rseal |
| --- | ---: | ---: | ---: | ---: | ---: |
| Root, native plain backing | 313 | 314 / 314 | 10,000 / 49,995,000 | 2.547 s | 317 (initial 3) |
| Scoped, native paired backing | 313 | 314 / 314 | 10,000 / 49,995,000 | 2.210 s | 317 (initial 3) |

Both retained exactly 99,063 raw body bytes. Cancellation fixtures abort a
waiting root/scoped capture controller while keeping 32 copied rows (sum 496),
then complete an actual selected-row rewrite, persistence, control and vote in
8.95 / 16.92 ms. These are observations, not hard timing or RSS caps.

Focused regressions reject presence-neutral relevant rewrites, insertion
phantoms, deletion, membership ABA across distinct serving publications,
uncovered points/ranges, excessive selector count/bytes, cross-Store reuse and
**real same-R snapshot installation**. They preserve final checked absence and
positive raw versions through actual rebase. Records regressions 28 PASS,
writer/gate regressions 14 PASS; SQL/default library checks and fmt/diff pass.
Library clippy exits zero with the same 21 preexisting warnings. The earlier
full-workspace failures remain unclassified/not green; this is not a full-suite
or terminal integration acceptance claim.

This extension does not complete the native scratch ledger above, establish
cold-source usability, or prove a terminal SQLite/HTTP success. Specifically,
paired scalar version checks still allocate redb tuple-key vectors; range bounds,
redb cursor paths and im overlay traversal allocate too. Their input bounds are
known but no enforced native scratch allocator capability is provided here.
Controller integration, hard native allocation accounting and real terminal
SQL admission/execution/authorization/delivery remain required separately.
