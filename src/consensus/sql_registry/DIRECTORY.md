# Current-only directory with real owned registry cells

Status (October 4, 2026): **component owner attachment/selection implemented; native source provenance, real node admission, Store startup/warm reconstruction, persistence, routing, Raft, and full SQL authority remain HOLD.** Fixture-origin scalars and `RegistryAdmission` implementations do not establish any of those gates.

## Scope

Production artifacts owned by this task:

- `src/consensus/sql_registry/directory.rs`
- `src/consensus/sql_registry/directory/tests.rs`
- `src/consensus/sql_registry/DIRECTORY.md`

The storage integration owns `pool.rs`, `sql_registry.rs`, `bootstrap.rs`, module declarations and their combined-mapping integration; all are part of this frozen stage. Foundation owns the actual native node adapter/main constructor. The directory is a sibling of `pool` inside `sql_registry`, so it consumes the **actual** `super::pool::RegistryCell`, `RegistryPool`, and source-parent registry identity/namespace definitions. There is no fake Cell representation or raw/weak-slot resurrection API.

A directory contains only CURRENT metadata, exact UTF-8 key extents, and one real `Option<RegistryCell>` owner per head. It stores no Snapshot, PartitionState, source Rows, Records, database/table/policy, or historical name/descriptor list. Existing detached witnesses may retain immutable cells in the pool; they never become a directory fallback.

## Exact API

Native operations/types are `pub(in crate::consensus)`; no guest/parser registration entry point exists:

```rust
DirectoryLayout::new(max_heads, key_bytes) -> Result<DirectoryLayout, DirectoryError>
layout.object_layout() -> std::alloc::Layout
Directory::initialize(&mut initialized_region[..], layout) -> Result<Directory, DirectoryError>

register_native(origin, actual_code, private_same_pool_uid_issuer) -> Result<NativeHeadToken, _>
lookup_native(origin, Option<expected_token>) -> Result<HeadMetadata, _>
update_code_native(origin, expected_token, actual_code) -> Result<HeadMetadata, _>
attach_current_native(origin, expected_token, actual_code, cell: RegistryCell) -> Result<(), _>
select_current_native(origin, expected_token, actual_code) -> Result<RegistryCell, _>
retire_native(origin, expected_token) -> Result<(), _>
remove_native(origin, expected_token) -> Result<(), _>
usage() -> Result<DirectoryUsage, _>
clear(&mut self) -> Result<(), DirectoryError>
```

`NativeHeadToken` is Copy scalar correlation `(Store, installation, epoch, root/scoped kind, issued UID)`, **not** a Cell owner, slot index, pointer, authority claim, or borrowed key. `HeadMetadata`/in-region `Head` remain Copy and contain no owner. Copies never duplicate cell ownership.

Private `pub(super)` unsafe pool-only bridge methods (accessible to the parent/sibling pool; not public raw constructors):

```rust
unsafe fn Directory::borrow_from_pool<'a>(
    pool: &'a RegistryPool,
    region: NonNull<u8>,
    layout: DirectoryLayout,
) -> Directory<'a>;

unsafe fn Directory::clear_from_pool_exclusive(
    pool: &RegistryPool,
    region: NonNull<u8>,
    layout: DirectoryLayout,
);
```

The actual implementation ties the teardown's pool borrow to its `Directory` impl lifetime too. Parent must prove pointer/offset/extent/alignment, initialized matching layout, and placement in that exact live pool mapping. Last-handle teardown must exclude **all** directory views/operations before calling the exclusive clear while retaining one independent pool reference. These unsafe obligations are not delegated to caller booleans or fixtures.

## Exact owner layout, same finite admission

Explicit immutable dimensions only: `1 <= max_heads <= 256`; arbitrary exact key capacity that fits the checked component arithmetic ceiling. No default, growth, per-Store map, independent mapping/reservation, heap keys, per-name 4 KiB cap, hash-only identity, free-list history, or `Box`/`Arc` per directory head.

The component `Layout` uses actual Rust types and alignment:

1. `Control`: nonwaiting atomic gate, protected live counters, dimensions, offsets.
2. `[UnsafeCell<Head>; max_heads]`: Copy scalar metadata.
3. **`[UnsafeCell<Option<RegistryCell>>; max_heads]`**, parallel to heads.
4. Exact `key_bytes` UTF-8 arena.
5. All offsets/inter-component padding and final alignment padding.

Every real owner slot is explicitly constructed as `UnsafeCell::new(None)` before publication. Zero-filled bytes are **not** assumed to construct a valid `Option<RegistryCell>`. Owners are only moved with `Option::replace`/`take`; they are never byte-copied, compacted, or duplicated. The public `owner_bytes` field is the actual `size_of::<Option<RegistryCell>>()`, not an estimated pointer count. Initialization rejects changed public accounting fields, bad alignment, and bad extent before any write.

Observed x86_64 layout, verified by independently extending exact actual-type layouts, for `new(256, 8193)`:

| Field | Bytes/value |
| --- | ---: |
| Control | 64 |
| Each Head | 80 |
| Each actual `Option<RegistryCell>` | 16 |
| Head/owner count | 256 each |
| Heads offset | 64 |
| Owners offset | 20,544 |
| Keys offset | 24,640 |
| Key arena | 8,193 |
| Alignment | 8 |
| Complete component object | 32,840 |

Do not reuse these platform-specific numbers as estimates. Parent must extend **one actual Layout** for pool Control + concrete inline lease + fixed Cell array + this DirectoryLayout, then page-round/admit/pre-touch one mapping. This component's arithmetic 16 MiB ceiling is **not another allowance**: actual total node registry + cancellation/control/owner storage stays within the **same 16 MiB**, with **at most 256 simultaneously retained cells**. Directory-held and detached witness-held cells consume the same pool slots, not separate quotas. Caller/owner stacks/control and any fixture/native admission-owner metadata remain additional concrete accounting obligations. `Directory` itself contains a pointer, optional borrowed-pool anchor, mode flag and lifetime marker; exclusive clear has only one cell-sized owner temporary, not a hidden 256-owner stack/heap array.

The parent supplies optional-directory pool admission and handle tracking. Passing a fixture owner proves only the component's exact reservation mechanics, not a real process-global NodeResources contract.

## Current body selection and invalidation

Borrowed production views retain an actual lifetime-tied pool anchor; attachment/selection reject foreign-pool cells even if their numeric UID/code/origin matches. `pool.owns_cell` compares the live control allocation identity, not caller hashes or numeric authority. Standalone provided-region fixtures have no such anchor and are not production node/provenance evidence.

Attachment takes ownership by value. Under the **same gate** used for metadata/keys, it correlates the full origin and expected token, compares the exact registry/bundle/schema triple, and verifies the actual cell identity's Store, installation, namespace UID/epoch, and all three code stamps. Kind/key matching is established by the head/token/origin correlation; the cell identity does not independently contain a name/kind. Refusal cannot replace a valid current owner. Success moves the incoming cell into that head's owner slot and moves the old owner out. The gate is released **before** either rejected or detached cell is destroyed.

Selection checks full origin/token/code under that same gate and clones **only** its live owned current cell via `RegistryCell::try_clone()`. No returned owner/key reference or raw slot escapes. Missing heads/bodies, stale origin/token correlation, and mismatched identity/code return `CurrentUnavailable`; invalid input and gate `Busy` remain distinct. Reference saturation maps to fixed typed `DirectoryError::Capacity`. Scalar lookup/update/remove still retain `Missing`/`Stale` diagnostics.

Every code update detaches the old body immediately, **even for equal code**. A new explicitly validated attachment is required before positive selection. Old independently owned witnesses remain readable/charged, never aliases for the new current code. Remove/retire zero their key extent, clear metadata, take the owner under the gate, and destroy it after release. Freed descriptor/key space can be reused, but a live old cell's namespace UID is not reused by the private nonwrapping pool issuer.

## Two lifetime modes, no self-mapping cycle

`initialize(&mut region, layout)` creates a non-clone standalone owner with `clear_on_drop = true`. Its exclusive region borrow excludes every operation during safe `clear(&mut self)`/Drop. It releases all owners outside the gate and resets keys/counters; the region's storage still belongs to its enclosing native/test owner.

`borrow_from_pool(&pool, pointer, layout)` creates a lifetime-tied shared view with `clear_on_drop = false`. View Drop is inert. Calling safe `clear(&mut view)` returns `Invalid`: mutable access to **one view** cannot bypass other shared views and clear the persistent directory.

Parent's separate external-handle counter must run `clear_from_pool_exclusive` on the **last external RegistryPool handle**, before releasing that handle's base pool reference. All views have ended then, while one independent mapping owner remains. Clear visits fixed slots, moves at most one owner onto the stack per iteration, releases the lexical gate, and drops that owner; only then may the parent release its pool reference. This breaks the current-head/cell self-mapping ownership cycle. Detached cells and staging owners may keep the map/lease alive after external handles reach zero, but cannot reach the directory. The concrete inline lease is released only by the pool after its mapping is unmapped.

## Exact keys and bounded work

Root and `Scoped("")` are distinct tagged keys; UTF-8 is exact, including NULs and distinct normalization forms. No key borrow escapes. Registration allows one current descriptor per `(Store, tagged exact key)`, not installation/epoch history. Reinstall/epoch replacement must first retire the old current descriptor.

The private UID issuer runs exactly once only after a head slot and contiguous key extent are admitted under the directory gate. It must be the same pool's private checked `issue_namespace` counter, with the guarded origin's exact epoch, nonwaiting/allocation-free/bounded. Busy/full/duplicate/invalid input never invokes it. Failure/panic/zero/live-duplicate UID leaves metadata/keys unchanged; spent UIDs are never recycled. This component cannot authenticate arbitrary callback/source scalars or actual source lifecycle.

Deterministic first-fit uses only current extents, no history/free-list/compaction. Fragmentation may refuse despite sufficient aggregate free bytes. Exact 10,000-byte UTF-8 names register, attach, select, and retire if the arena has room; one byte less refuses before issuance.

For `H <= 256`:

- Exact name search visits at most `H` heads; comparison bytes are at most current disjoint used key bytes.
- First-fit visits at most `H * (H + 1)` heads (full 256-head test: 65,792).
- Registration additionally performs bounded vacant-head/live-UID scans and copies only the admitted extent.
- Attach/select/update/remove have one bounded exact-key search and constant owner operations.
- Exclusive clear visits `H` heads/owners, zeroes the fixed arena, and uses `H + 1` one-shot gate acquisitions. Exclusivity excludes contention; it never waits/retries.

Ordinary operations use one strong atomic compare-exchange. Contention is `Busy`, not fake `Capacity`. No polling, waiter queue, retry acquisition loop, fallback allocator/map, or constructor on a source path exists. Destructors run after releasing the gate owned by their operation; a Busy refusal does not acquire another operation's gate.

## Executable component evidence

`/workspace/reports/sql-capture/directory-harness` compiles the **exact current production `sql_registry.rs`, `pool.rs`, and `directory.rs`**, not substitute Cell/identity types. It uses the existing single `allocation_probe::Allocator`, never a second allocator. Its standalone region and Arc-backed quota owner are explicitly fixtures, constructed before measurement. Parent pool changes are loaded from source on rebuild; fixtures do not depend on private pool/control/slot field layouts.

The original 14-test metadata harness remains (13 directory tests plus the shared allocator positive control). Ten added real-cell tests bring the owned directory suite to 23 tests and exercise:

- Root, scoped-empty, and 10,000-byte UTF-8 positive current body selection with same-pool issued namespaces.
- Exact code/Store/install/UID/epoch mismatch refusal and preservation of a valid current body.
- Changed/equal-code invalidation, old witness readability, missing current body until attachment, and retained slot exhaustion/reuse.
- Remove/retire while old/current witnesses live; stale UID never selects a replacement.
- Same-code owner replacement without slot reuse beneath live old witnesses.
- Inert borrowed-view Drop, rejection of borrowed safe clear, nonlast handle Drop, and last-handle cycle breaking.
- Last pool handle Drop while detached cell/staging owners retain the actual mapping/quota.
- One shared fixture owner's global byte/slot quota across pool admissions, refusals/rollback, and final release.
- Last-cell lease-destructor observation proving refusal/update/remove/retire/clear/Drop occur outside the directory gate.
- Cross-thread one-shot current selection and actual Cell cloning, allowing only success or `Busy` for gate contention.

Production register/attach/select/clone/drop/update/remove/retire/clear operations are measured as **zero Rust allocation operations and zero requested bytes**. General allocator positive-control/unwind-reset tests remain enabled. Fixture allocation, thread creation, assertions that fail, and mapping construction are not misrepresented as source-exclusion operations or native admission evidence.

Checks (standalone exact-source harness, October 4, 2026): debug and release **44/44 pass** (23 owned directory tests, 19 combined pool/bootstrap tests, one actual bootstrap-layout test and one shared allocator control); strict all-target clippy (`-D warnings`); rustfmt for the owned Rust sources/harness. Actual Flower post-bootstrap results are recorded separately in the checked stage handoff. Full source/native node/routing/public SQL acceptance is not claimed by these component tests. Pool reference-exhaustion tests exercise the actual cell saturation mechanics; driving the directory's clone-capacity path at artificial saturation additionally requires a parent-owned pool test hook/test with private reference-counter access—no raw-layout hack is added here.

## Remaining gates — do not overclaim

- Real global NodeResources/baseline/cancellation/control admission and immutable operator-lowered startup limits before any Store opens.
- Guarded current source publication/registry-envelope provenance, private callback issuance and exact origin/namespace-binding validation.
- Cold Store startup and persisted/warm reconstruction/retirement/publication sequencing.
- Node routing, Raft/publication/reinstall cross-source integration.
- Full native SQL authority/budget/root-free serving/cancellation integration.
- Parent full-repository tests/default and SQL builds, plus saturation-path integration testing if required.

Positive component body selection closes the prior **always-unavailable attachment placeholder only**. It is not a native-source validation or full SQL launch pass.

The combined pool and actual-address process-global bootstrap are documented in `POOL.md`. A native adapter must charge their complete actual concrete layouts plus the unique union of registry/cancellation/native-owner static pages before installation. No sizeof-only static allowance, fixture lease substitution, new per-Store owner or uncharged spare capacity closes that gate.

Post-bootstrap actual Flower `sql_registry` filter: **43/43 passed**, no ignored tests. Locked default library check, fmt/diff checks passed. SQL library Clippy exited 0 with 95 Flower warnings (staged inactive APIs and earlier diagnostics), not strict global Clippy. These results do not close Store/replay/atomic dispatch or native serving.
