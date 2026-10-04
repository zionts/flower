# Current-only SQL registry arena — implementation contract

Status: **storage primitive only; source publication, warm startup, routing and the actual native node owner remain HOLD**. This is not a SQL launch proof.

Coordinator-approved limits (October 4, 2026, 00:57 UTC): at most **16 MiB total per process/node** for the shared registry + cancellation/control baseline and all actual new owner/control/header/rounding metadata; at most **256 simultaneously retained cells**. Operators may lower either at startup, never raise them. One shared NodeResources must exist before any Store opens. The native constructor must subtract actual cancellation/control/owner extents before passing the remaining lower-only registry byte limit; this is NOT a second independent 16 MiB allowance. A 32,768-byte JSON payload is permitted **plus a separately charged actual bounded header**; the entire envelope is not advertised as 32 KiB.

## Exact source API

`consensus::sql_registry` is enabled only by `sql`. There is no default owner or implicitly configured pool.

```rust
trait RegistryAdmission {
    type Lease: Send + Sync + 'static;
    fn try_reserve(&self, actual_mapped_bytes: usize, cells: usize)
        -> Result<Self::Lease, RegistryError>;
}

RegistryPoolLimits { bytes, cells } // lower-only; HARD = 16 MiB / 256
RegistryPool::reservation_layout::<A>(limits) -> RegistryPoolLayout
RegistryPool::admit(&owner, limits, check) -> RegistryPool // bare component only
RegistryDirectoryLimits { heads, key_bytes } // explicit dimensions, heads <= 256
RegistryPool::reservation_layout_with_directory::<A>(limits, directory) -> RegistryPoolLayout
RegistryPool::admit_with_directory(&owner, limits, directory, check) -> RegistryPool
pool.directory() -> lifetime-tied Directory // requires combined admission
pool.try_clone() -> RegistryPool
pool.capacity() -> usize
pool.mapped_bytes() -> usize
pool.live_cells() -> usize
pool.issue_namespace(actual_epoch) -> private RegistryNamespace // source-only
```

The associated lease is concrete and stored **inline**, with its actual `Layout` size/alignment included. No `Box<dyn Lease>`, per-cell `Arc`, growable table, queue or allocator-metadata estimate is used. The provided trait is an integration interface, **not proof** that an implementation has actual process-global backing. All resources the lease owns indirectly and all caller/global-owner storage outside this arena still need the concrete native owner's exact admission contract. Tests' `Arc<Owner>` is explicitly a fixture, not that contract.

## Actual arena layout

One anonymous mapping contains:

1. `PoolControl`, including distinct intrusive overall-owner and external-handle counts, checked namespace-UID counter, a nonwaiting atomic admission gate, fixed slot count, actual directory/lease/slot offsets/extent and concrete generic destruction callback.
2. The native `A::Lease` value, at its real alignment.
3. A fixed array of `RegistrySlot` objects.
4. When requested, the complete current-only `DirectoryLayout`: actual control, fixed scalar heads, explicitly initialized actual `Option<RegistryCell>` owners and exact variable UTF-8 key arena.
5. Checked system-page rounding of the complete combined `Layout`. No component is independently page-rounded or separately admitted.

`RegistryPoolLayout` reports `mapped_bytes`, effective `cells`, actual `control_bytes`, `lease_bytes`, `slot_bytes`, `slot_header_bytes`, `payload_bytes` and actual `page_bytes`, `directory_bytes`, `heads` and `key_bytes`. Lower byte limits reduce **effective** usable cells; a requested 256 is never reported unless it fits. If not even one cell fits, startup construction refuses before admission/mapping.

All mapped bytes—including lease/control/header/padding—are explicitly written before publication. No source is accepted during construction. Cancellation/check failure drops the mapping **before** its external lease. A final construction check runs after directory initialization and before moving the inline lease. On the last pool-or-cell owner, a monomorphized callback moves the inline lease to the caller's native stack, unmaps the original exact extent, then drops that lease. An unmap invariant failure aborts without falsely releasing a still-live allocation.

This is a mapped-byte/object-layout contract, **not a claim that these bytes alone equal all process RSS, native stack, loader/TLS, parser or kernel memory**.

## Cell ownership

Internal source-only operations:

```rust
pool.stage() -> RegistryStaging
stage.seal(actual_identity_including_native_namespace_uid_and_epoch, raw_json) -> RegistryCell
cell.try_clone() -> RegistryCell
cell.raw_json() -> &[u8]
```

A staging slot is admitted before copying and has one unique mutable owner. A sealed slot's bytes are immutable while any cell/witness owner remains. Current, replacement, staging and distinct old-envelope cells occupy simultaneous slots. Multiple witnesses of one cell share the same fixed mapping and refcount; they do not allocate payload copies. A detached copy must acquire a different slot first.

Slot claims serialize through one in-map atomic try gate. Contention is `Busy`, not a false `Capacity` result; there is no wait, retry loop or allocator waiter queue. While the gate is held, concurrent drops can only add vacancies, so an available slot cannot move behind the fixed bounded scan. A capacity refusal can linearize at gate acquisition.

Slot lifecycle is encoded in the in-map refcount: `0` free, `usize::MAX` exclusively staging/reclaiming, otherwise a checked positive immutable-reader count. Last drop first transitions to exclusive reclaiming, decrements live-slot accounting, then publishes free. It never publishes reusable zero before its own accounting/destruction work finishes. Refcount increments fail closed rather than wrapping. No raw/weak handle can resurrect a free slot.

The last **external pool handle** clears current directory cell owners while retaining its own independent overall mapping owner, then releases that owner. This breaks the directory/cell self-mapping reference cycle. Borrowed views are tied to external handles and their Drop is inert; detached cells/staging witnesses may retain the map after external handles reach zero but cannot access its directory. Failed external-handle increments roll back the preceding overall-owner increment.

Pool/cell handles are pointer-only but their *containing* futures, native parser data, arrays, stacks, etc. require separate caller admission. The arena is held until the final owner even if every ordinary Store handle has gone. Nothing in this module owns a Store, Database, Snapshot, Records, Backing, source value, table or transaction.

## Exactly located process-global bootstrap

`bootstrap_required_layout() -> StaticRegion` returns the actual `SOURCE_REGISTRY` object address, size/alignment and checked start/end system-page coverage. It is **not sizeof-only**, and does not assume its pages are disjoint from cancellation/control/native-owner statics. The native constructor must charge the unique union of all actual static page spans within the SAME approved node baseline.

`unsafe install_source_registry(pool, exact_charged_region)` installs exactly once into `OnceLock<RegistryPool>`. It verifies the exact current static region and initialized combined directory; bare component pools, wrong spans and duplicates refuse and return their actual rejected pool for explicit cleanup. Its unsafe caller contract requires real prepaid backing before **every production Store/Consensus opens**. The scalar attestation and admission trait are not verified backing evidence.

`source_registry()` returns only this process-lifetime owner, with missing bootstrap `Unsupported`, never inferred empty. No reset/default/per-Store construction exists. The accepted strong pool stays until process exit; no early baseline credit is claimed. Isolated child-process tests cover separate startups without resetting global counters or the OnceLock.

## Measured layouts, not portable allowance estimates

On the tested x86_64 platform, `PoolControl` was **192 bytes** before the lifecycle extension (now **224 bytes**); each cell slot is **32,840 bytes** (72 actual header + 32,768 payload). With the test fixture's actual **128-byte inline lease**, 256 cells + 256 directory heads + 10,000 key bytes map **8,445,952 bytes** on 4,096-byte pages. The native NodeAdmission lease is a different concrete type: recompute `reservation_layout_with_directory::<ActualAdmission>`, never adopt the fixture's lease layout or allocator estimates. Directory component details are in `DIRECTORY.md`.

## Deliberately unresolved source coupling

- Actual `terminalMethods`/bundle/schema versions must come from the same real root **and scoped** publication. The global version high-water mark is not that triple.
- Body/code sidecar persistence must belong to the exact queued projection and commit atomically with its application rows and state metadata. Never pair older persisted rows with later current-R sidecar metadata.
- Current-only ownership stays outside Snapshot/Records/PartitionState/copy bases/queued historical StoredState. Native envelopes alone may retain charged old metadata cells.
- Atomic classify-and-select must validate the actual Store/install/namespace/code triple under one continuous publication guard. An ordinary Snapshot is cloned only after dropping raw resident/source views and **before releasing that same guard**. Terminal selection returns no ordinary root.
- Missing/uninstalled registry is distinct from committed format-1 `methods:{}`. No legacy/schema fallback, no permanent cold-only ordinary dispatch.
- **Ordinary namespace length:** cells now retain only private source-issued namespace UID + epoch; no name or 4 KiB binding cap is imposed by this primitive. The checked UID counter is inside the admitted mapping. Source must still correlate the UID with the actual native Store/name/epoch under its current publication, using the combined exactly admitted current-only directory. Borrowed production views additionally reject cells from another pool using actual allocation/accounting identity; this is not Store/publication authority. Issuing a UID alone does not prove that correlation. No caller hash, guessed pointer, zero UID or sentinel serves as namespace authority.
- **Post-quorum capacity:** local sidecar capacity failure while applying an already-committed Raft command must not manufacture a different locally rejected command result. Native preproposal staging and follower/replay behavior need an explicit consistent contract; storage fail-stop/replay is distinct from typed admission refusal before proposal.
- Startup/crash/replay/install/import/freeze/retire/discard, late shared Store open, native global-owner/metrics/operator config, and every cache/hint/watch/fresh-fallback route still require source-grounded tests.

## Verification

An isolated harness compiles these exact production module files and the single shared test allocator probe. It compiles the exact pool module without a binding shim; it does **not** prove Store/binding/publication/routing semantics. Unit-test fixture origin scalars are not source-issued registry-envelope authority. Native pool tests cover exact page/layout/lease accounting, lower effective slots, hard bounds, required shared owner, old/current/staging peaks, last-owner unmap-before-release, bounded payload/private UID, deterministic moving-vacancy refusal distinction, failed/cancelled staging, parallel producers/readers, checked refcount exhaustion, unwind and zero Rust heap operations for slot/copy/clone/refusal/release.

Actual results and full Flower checks must be recorded separately; do not turn a unit/harness success into useful ordinary warm-start or SQL HTTP acceptance.

Latest frozen-stage evidence: the exact-source standalone harness passed **44/44 debug and 44/44 release** tests, with strict all-target Clippy (`-D warnings`). Actual Flower post-bootstrap results are recorded in the stage handoff; do not substitute the earlier pre-bootstrap 41-test run. Tests cover constructor cancellation/unwind, zero-sized leases, refcount rollback/concurrency, foreign-pool rejection, process-global isolated startup and the owned directory positives. Rust heap-operation counters do not prove native allocator/TLS/kernel/physical backing or finite source-worker stacks.

Post-bootstrap **actual Flower** checks (October 4): `cargo test --locked -p flower --features sql --lib sql_registry -- --test-threads=1 --nocapture`: **43 passed, zero failed/ignored** (the standalone allocator positive control is outside this filter); locked default library check, `cargo fmt --all --check` and `git diff --check` PASS. SQL library Clippy exited 0 with **95 Flower warnings**, largely inactive staged registry/directory/bootstrap APIs plus earlier source warnings; vendored im emitted 75 inherited warnings separately. This is not strict whole-library warning-clean status. No full workspace, JS suite, E2E or useful public SQL acceptance is newly claimed.

## Explicit schema presence follow-up

Actual empty-schema deployments remove the physical `schema` row (`rust_engine/indexes.rs`). `RegistryIdentity` and directory `NativeCode` now carry **`SourceStamp::KnownAbsent` or `Present(NonZeroU64)`**; failed/unknown source reads have no stamp and remain errors. Registry and bundle physical versions remain positive and mandatory for usable current metadata. Only the private initialized-map scalar encoding uses a zero word for the explicit KnownAbsent variant; no Envelope exposes a zero/guessed schema version or treats unknown as absent. Actual mapped Head/Slot layouts are unchanged; recompute concrete native layouts as always. Source issuance must establish checked absence at the SAME actual publication.

Follow-up checks: exact-source harness **47 debug /47 release PASS**, strict all-target Clippy PASS; actual Flower registry filter **46 PASS/0 failed/0 ignored**, default library check/fmt/diff PASS. SQL library Clippy exited0 with **97 Flower warnings** (staged inactive APIs and earlier source diagnostics); im75 separate. New tests exercise root/scoped absent→present→absent invalidation, exact current selection, old witness retention and zero Rust heap conversions/ownership. These component tests do not yet prove useful actual empty-schema ordinary Store/restart dispatch or full native serving.

## Lifecycle/atomic-ONE and actual source-stage follow-up

Current Directory adds same-mapping fixed Store lifecycle/fatal atomics and retired-owner scratch, documented in `directory/native-api.md`; no extra allowance or heap queue. Generic combined layout MUST be recomputed (PoolControl224 on measuredx64, Directory Control80/Head80/currentOwner16/status8/retiredOwner16;256heads+10000keys Directory40800). Source Store issuer now explicitly refuses outside `u64::MAX >> 2`, never resets/reuses. Prepared body owns an existingSTAGING slot; one-gate publication retains old owner until the caller releases Pubwrite. This is atomicONE, NOT grouped multi-namespace completion. Actual production startup/status/fatal/recovery/allroute wiring remains OPEN.

Coherent actual Flower v3: registry+META **91passed/0failed/0ignored**, actual cancelled-blocking-apply lifetime **1pass**, actual nonwrapping issuer-domain **1pass**; default library/fmt/diff PASS. Original weak-only source artifact FAILS the exact lifetime assertion; strongInner replacement native artifact PASS, with exact tested Store/test hashes equal to owned files. v3 verified14owned source files unchanged across all checks. SQL library Clippy exit0 with **146Flower warnings**, including staged APIs and earlier source diagnostics (not strict global); im75 separate. Exact component lifecycle harness **62debug/62release andstrictalltargetClippy PASS**. METAmodule now imported in real Store with fixed table recognition in SQL/nonSQL startup; parent corrected exact32768payloadPLUS8physicalheader and namespace-ranged invalidation. Queue projection, producerpairing, current source publication, startup warm recovery, fatal-on-partial wholePubguard and native concrete atomic classification are NOT wired yet.
