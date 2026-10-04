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
RegistryPool::admit(&owner, limits, check) -> RegistryPool
pool.try_clone() -> RegistryPool
pool.capacity() -> usize
pool.mapped_bytes() -> usize
pool.live_cells() -> usize
pool.issue_namespace(actual_epoch) -> private RegistryNamespace // source-only
```

The associated lease is concrete and stored **inline**, with its actual `Layout` size/alignment included. No `Box<dyn Lease>`, per-cell `Arc`, growable table, queue or allocator-metadata estimate is used. The provided trait is an integration interface, **not proof** that an implementation has actual process-global backing. All resources the lease owns indirectly and all caller/global-owner storage outside this arena still need the concrete native owner's exact admission contract. Tests' `Arc<Owner>` is explicitly a fixture, not that contract.

## Actual arena layout

One anonymous mapping contains:

1. `PoolControl`, including intrusive owner count, checked namespace-UID counter, a nonwaiting atomic admission gate, fixed slot count, actual offsets/extent and concrete generic destruction callback.
2. The native `A::Lease` value, at its real alignment.
3. A fixed array of `RegistrySlot` objects.
4. Checked system-page rounding of the complete combined `Layout`.

`RegistryPoolLayout` reports `mapped_bytes`, effective `cells`, actual `control_bytes`, `lease_bytes`, `slot_bytes`, `slot_header_bytes`, `payload_bytes` and actual `page_bytes`. Lower byte limits reduce **effective** usable cells; a requested 256 is never reported unless it fits. If not even one cell fits, startup construction refuses before admission/mapping.

All mapped bytes—including lease/control/header/padding—are explicitly written before publication. No source is accepted during construction. Cancellation/check failure drops the mapping **before** its external lease. On the last pool-or-cell owner, a monomorphized callback moves the inline lease to the caller's native stack, unmaps the original exact extent, then drops that lease. An unmap invariant failure aborts without falsely releasing a still-live allocation.

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

Pool/cell handles are pointer-only but their *containing* futures, native parser data, arrays, stacks, etc. require separate caller admission. The arena is held until the final owner even if every ordinary Store handle has gone. Nothing in this module owns a Store, Database, Snapshot, Records, Backing, source value, table or transaction.

## Deliberately unresolved source coupling

- Actual `terminalMethods`/bundle/schema versions must come from the same real root **and scoped** publication. The global version high-water mark is not that triple.
- Body/code sidecar persistence must belong to the exact queued projection and commit atomically with its application rows and state metadata. Never pair older persisted rows with later current-R sidecar metadata.
- Current-only ownership stays outside Snapshot/Records/PartitionState/copy bases/queued historical StoredState. Native envelopes alone may retain charged old metadata cells.
- Atomic classify-and-select must validate the actual Store/install/namespace/code triple under one continuous publication guard. An ordinary Snapshot is cloned only after dropping raw resident/source views and **before releasing that same guard**. Terminal selection returns no ordinary root.
- Missing/uninstalled registry is distinct from committed format-1 `methods:{}`. No legacy/schema fallback, no permanent cold-only ordinary dispatch.
- **Ordinary namespace length:** cells now retain only private source-issued namespace UID + epoch; no name or 4 KiB binding cap is imposed by this primitive. The checked UID counter is inside the admitted mapping. Source must still correlate the UID with the actual native Store/name/epoch under its current publication, using an exactly admitted current-only adjunct/directory. Issuing a UID alone does not prove that correlation. No caller hash, guessed pointer, zero UID or sentinel serves as namespace authority.
- **Post-quorum capacity:** local sidecar capacity failure while applying an already-committed Raft command must not manufacture a different locally rejected command result. Native preproposal staging and follower/replay behavior need an explicit consistent contract; storage fail-stop/replay is distinct from typed admission refusal before proposal.
- Startup/crash/replay/install/import/freeze/retire/discard, late shared Store open, native global-owner/metrics/operator config, and every cache/hint/watch/fresh-fallback route still require source-grounded tests.

## Verification

An isolated harness compiles these exact production module files and the single shared test allocator probe. It compiles the exact pool module without a binding shim; it does **not** prove Store/binding/publication/routing semantics. Unit-test fixture origin scalars are not source-issued registry-envelope authority. Native pool tests cover exact page/layout/lease accounting, lower effective slots, hard bounds, required shared owner, old/current/staging peaks, last-owner unmap-before-release, bounded payload/private UID, deterministic moving-vacancy refusal distinction, failed/cancelled staging, parallel producers/readers, checked refcount exhaustion, unwind and zero Rust heap operations for slot/copy/clone/refusal/release.

Actual results and full Flower checks must be recorded separately; do not turn a unit/harness success into useful ordinary warm-start or SQL HTTP acceptance.
