# Native registry lifecycle and atomic ONE-body component API

This component note is **not** Store/source publication, node-budget, route activation,
confluence, persistence, recovery or whole-stack evidence. Production source wiring
and its actual publication/lifetime guards remain the parent task's responsibility.
The exact-production-file isolated harness includes a single allocation probe, not
an actual source producer or native admission owner.

## Exact Store identity/status domain

`directory::MAX_NATIVE_STORE_ID = u64::MAX >> 2` (4,611,686,018,427,387,903).
An actual native Store identity must be nonzero, within that domain, nonwrapping,
and **never reused**. The parent must update the real capture-identity issuer;
large fixture identities outside this domain explicitly fail rather than truncate,
hash, alias, use a pointer, or become an implicit namespace identity.

Each mapped atomic status word is `(exact_store_id << 2) | phase`:
Preparing=0, Ready=1, Fatal=2, Retiring=3. The complete zero word means Unregistered,
not Preparing Store 0 and never Ready. These are actual `AtomicU64` objects in the
admitted Directory mapping, separate from Copy heads. Copy-head writes cannot
clobber lifecycle/status atomics.

There are exactly `DirectoryLayout.heads` status slots, lower-only 1..=256, with no
separate growth/map/default or additional node allowance. Stores without a head
still occupy their registered lifecycle slot. Fatal Store slots cannot be reset by
a caller bool or by removal of an individual namespace. Their recovery requires
actual final lifetime retirement and a **new** never-reused Store identity. Once a
slot has been reclaimed, these finite primitives cannot remember an unbounded
history of old IDs: native issuer provenance/non-reuse is mandatory, not inferred.

## Parent startup and status obligations

All of these APIs are private to `crate::consensus`, not guest APIs:

- `Directory::prepare_store_native(store) -> Result<(), DirectoryError>`:
  reserve the actual mapped lifecycle slot **before exposing the Store**;
  initialized status is Preparing, never Ready by absence/default.
- `ready_store_native(store)`: one-way Preparing -> Ready startup seal. Repeating
  it on Ready/Fatal/Retiring is a refusal; no reset method or bool exists.
- `store_status_native(store) -> Result<SourceStatus, DirectoryError>` and
  `require_ready_native(store) -> Result<(), DirectoryError>`: bounded exact-ID
  scans. Preparing/Fatal/Retiring/Unregistered all refuse source use.
- `fatal_store_native(store) -> Result<SourceStatus, DirectoryError>`: bounded
  atomic exact-ID forward-only mark, **without acquiring the Directory gate**.
  Two fixed strong CAS attempts suffice for the acyclic Preparing -> Ready
  competitor. Already Fatal/Retiring or now Unregistered are fail-closed.
- `retire_store_native(store)`: actual **final InnerDrop**, not namespace removal
  or a caller-requested reset. One bounded status sweep, at most three strong CAS
  attempts per slot for the only forward phase progression, then one Directory
  try-gate/reclamation. It never waits, polls, queues, spawns, or hashes identities.
  A `Busy` result leaves the logical Retiring mark in place. An old delayed CAS
  compares the complete old identity/status word and cannot retire a different
  Store that reuses that bounded slot.

The parent must wire **every SQL source/capture/classifier/cache/final-fresh route**
to Ready under the real source publication/lifetime guards. `lookup_native` and
`select_current_native` now also require Ready; metadata or a real owned Cell
alone cannot implicitly register/authorize an unknown source. An old detached
witness may remain charged/readable, but is never a current fallback.

There is no production startup RAII guard in this component. Parent startup must
own the Preparing slot before exposure, clean it on errors/unwind before Store
construction completes, and hook final InnerDrop when it does complete. Mark
Fatal under the **same actual source publication write guard before unlocking**
when failure/panic can leave partially mutated source state. The fatal guard must
be structurally dropped before that guard releases, not armed after an error has
already escaped/unlocked. An actual registered valid-domain Store lifetime and
never-reused issuer make this mark bounded and independent of gate contention.
The parent must check a returned fail-closed status and prove all routes consult
it; process abort is only the approved last fail-closed fallback if that proof
cannot be maintained, not this component's ordinary failure policy.

## Prepared body and atomic ONE-body publication

`RegistryPool::prepare_body(raw_json) -> Result<RegistryReadyBody, RegistryError>`
checks nonempty UTF-8, at most 32,768 bytes, reclaims logical final retirement,
claims one existing STAGING cell slot, and copies the bytes **once**, before
identity/head/private-UID admission. It does not serialize, parse JSON, call a
source/signer callback, allocate Rust heap memory, create another mapping, or
publish an identity. The ready body privately owns the existing staging owner;
it is not Clone/Copy/readable as a published Cell. Dropping it returns that slot.
`directory::RegistryReadyBody` reexports the opaque type for source integration.

`Directory::publish_prepared_native(next_origin, expected_old_token, next_code,
ready_body) -> Result<NativePublication, DirectoryError>` is **atomic ONE namespace**:

1. Validate native domain/origin/code and actual same-pool prepared ownership.
2. Acquire one Directory gate, reclaim retired heads, require this Store Ready.
3. Find the exact Store + key kind + exact UTF-8 name. `expected_old_token` must
   correlate the old complete head, including old installation/epoch/private UID;
   new installation/epoch in `next_origin` is intentional replacement, not an
   excuse to accept a different Store/kind/name. Missing expected means actual
   new namespace only; existing-name conflict/stale expected refuse.
4. Preflight head/cell ownership, exact contiguous key extent/fragmentation,
   private UID exhaustion and Ready before live target mutation. Same
   installation/epoch retains the existing UID; new install/epoch or new key
   obtains a fresh UID from this exact pool's checked nonwrapping native counter.
5. Seal identity infallibly after all checks, with **no second body copy**, then
   move head/key/counts/current owner under the same gate. No fallible callback,
   parser, signer, serializer or allocation remains in this mutation suffix.
6. Return `NativePublication { metadata, detached }`. The detached old Cell
   belongs to the source caller; retain it until **after releasing Pubwrite**,
   then drop it. Rejected owners and reclamation owners are destroyed outside
   the Directory gate. A spent UID on a late status refusal is never recycled.

All refusals preserve the target's old complete metadata/body/key and existing
witnesses. Preparing a body may reclaim only logically retired heads from any
Store, never a useful Ready/Fatal head. `RegistryPool::stage()` also performs
reclamation before any cell-capacity scan. Native prepared-body access is only
through the external Pool handle; no Cell/raw-pointer-derived Directory view
can bypass that strong handle lifetime.

`register_native` / `update_code_native` / `attach_current_native` and the split
`RegistryStaging::seal` remain **fixture/component operations**, not production
source transactions. Do not build the source publication loop from these split
steps and do not treat them as an atomic grouped update.

## Multi-action boundary: explicitly NOT grouped atomicity

This extension provides the approved precise atomic-ONE fallback, not an atomic
<=256-action grouped transition. Repeating `publish_prepared_native`, removing
heads, or committing root/scoped source records in a loop is **not grouped
atomicity**. Every native Store writer must still own the same actual Pubwrite
across its complete source mutation and install a fail-closed RAII arm before
any partial mutation. On any partial failure/panic it must mark that affected
Store Fatal before unlocking; readers/cache/final-fresh routes must refuse it.
Unchanged other Stores remain useful. Parent admission must account for any
actual bounded multi-action plans/owners it introduces; this component does not
provide unadmitted heap maps or guessed caller-stack action arrays.

## Actual mapping and bounded reclamation

`DirectoryLayout::new` uses `Layout` of actual concrete Rust types and includes:
Control (including main/cleanup gate and every offset/count), fixed Copy heads,
real current `UnsafeCell<Option<RegistryCell>>` owners, exactly H `AtomicU64`
status slots, exactly H retired-owner `UnsafeCell<Option<RegistryCell>>` scratch
slots, exact key arena, and all alignment padding. All owners/scratch are
explicitly initialized to `None`, atomics to zero, and the whole supplied region
is initialized; the Pool pretouches its combined mapping before publication.
Observed x86_64 exact-source harness sizes (not portable/admission constants):
Control 80 bytes, Head 80, current owner 16, status atomic 8, retired scratch
owner 16, RegistryReadyBody 16, NativePublication 80. With H=256 and 8,193 key
bytes the Directory object is 39,000 bytes; with H=256 and 10,000 key bytes it is
40,800 bytes. The fixture combined pool with 256 cells and its actual 128-byte
inline lease maps 8,450,048 page-rounded bytes (PoolControl 224, slot 32,840).
These numbers describe that concrete fixture lease, not the parent's node lease.

The generic combined Pool layout extends this actual Directory layout
**automatically**, then page rounds/admission checks the same <=16 MiB mapping
and <=256 retained cells. There is no extra Directory/status allowance.

Every successful Directory gate performs bounded retirement reclamation
(H statuses x H current heads maximum), clearing exact head/key/count metadata
and moving real owners to mapped scratch. It CAS-clears only the exact Retiring
Store word. The main gate is released before draining scratch one Cell-sized
temporary at a time. A separate same-mapping cleanup gate prevents another
operation from racing scratch reuse during gate-free destruction: reentrant
or contending operations get Busy, never wait. The cleanup token releases even
on a standalone fixture lease-destructor unwind; any surviving initialized
scratch is drained before holding the main gate on the next operation. No heap
queue or uncharged
large stack array is involved. The last **external** Pool handle still performs
exclusive cycle-breaking clear while retaining its independent pool owner;
old witnesses/staging/prepared owners keep the map/lease charged until their
last drop, and lease release occurs only after unmap.

## Component checks and their limits

New fixtures cover actual type/layout initialization and zero Rust heap
operations, explicit bounded lifecycle/domain (including the maximum valid
Store ID and out-of-domain refusal), sticky Fatal and useful unaffected Store,
Present <-> KnownAbsent, fresh reinstall/epoch UID, all capacity/Busy/foreign
pool/stale/counter refusals preserving complete old state, concurrent reader
complete-old/new selection, gate-free retired destruction, Busy logical final
retirement reclaimed by next lookup AND preparation, old-witness charge/read
surviving head/key/status-slot reuse, delayed exact CAS without ABA, and strong
external handle/cycle teardown with a still-live prepared body.

These are exact-production-file fixture/component proofs only. Real source
publication guard ordering, actual startup failure cleanup/InnerDrop hooks,
issuer domain/non-reuse, all-route status consultation, multi-action fail-closed
confluence, native startup/node admission, and actual Flower integration remain
whole-source/parent verification gates.
