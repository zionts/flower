# Fixed native HOST source-worker stack foundation

**Serving, whole-native resource proof, actual source/controller integration: HOLD.**
New-only component; not imported by `evaluator.rs`. No main/Cargo/service/source/
consensus/SDK/writer/host/process integration, commit, push, PR or activation.

## ABI for the parent controller/node owner

The platform gate is **Linux + x86-64 + 64-bit + GNU libc only**. Unsupported
platforms return `UnsupportedPlatform`; the native implementation is cfg-gated.
This platform gate is not a libc/kernel/resource-profile certificate.

1. One immutable process-node owner implements the **unsafe** `NativeOwner`
   boundary. `immutable_worker_ceiling()` must be exactly **ONE**. Factory
   construction does not create a pool/counter, so another factory cannot mint a
   second allowance; the real owner must supply the global hard slot.
2. `WorkerFactory::layout::<ConcreteTask>(StackSpec)` reports actual `Layout`s
   for native control, inline task, associated inline lease and caller handle,
   actual native page size, rounded stack/guards/control mapping and sum.
3. `native_gate` defaults to `Hold(NativeOwnerNotInstalled)`. No production owner
   implementation exists here. It must remain HOLD until current native TLS/DTV,
   allocator backing, startup/control/destructors, kernel/physical profile,
   caller/signal stacks, source callgraph and any async machinery are proved and
   admitted. Returning Ok is an unsafe **caller attestation**, not verification
   performed by this module. Do not implement it by returning a guessed number.
4. `admit(layout, &ORIGINAL JobControl)` must acquire the **original real job
   ticket**, actual node ONE-worker slot and applicable existing-budget carve
   before any mapping/native constructor. The returned non-cloneable strong
   `NativeLease: Send + Sync + 'static` is inline in the control mapping. The
   lease supplies two unique mapping-lifetime IDs and an optional finite,
   nonallocating/no-panic source-free observer. No Boxed closure/lease/header or
   channel queue is allocated by the factory.
5. `start::<ConcreteTask>(spec, original_job, InspectOwnedStack)` takes the
   already-admitted original JobControl. Its time starts **before first fence**;
   all mapping/pre-touch/native startup cost remains inside that deadline and
   the same job reservation. Only the closed source-free bootstrap is accepted:
   no callback, source handle, function pointer, Wasm, JS, key or payload.
6. A `NativeThread` is returned only after the **actual** worker called
   `pthread_getattr_np(pthread_self())`, matched stack base/length and libc
   guardsize0 against the owned stack, and verified a real local stack address
   is inside it. `StackExtentReady` is **stack-extent readiness only**, never
   whole-native or source-GC/root-retention readiness.
7. `source_enrollment(&mut worker)` checks Ready + original control, then lends
   a nonconstructible `SourceEnrollment` with that SAME mutable JobControl.
   Create the real trusted typed task/source references only now. No source
   reference may be created earlier merely because some fixture gate is Ok.
8. `submit(concrete_task)` installs exactly one typed `TrustedCaptureTask` in
   prepaid inline storage. The unsafe task implementation must use this same
   original job in source/certificate/identity/copy/controller paths and retain
   original work counters across retries. No arbitrary guest-selected native
   callback/elevated query or unbounded pool is available. Only owned
   `Send + 'static` source references are accepted; never transmute borrowed
   source lifetimes to obtain this bound.
9. Original admitted/deadline/cancellation-Arc identity is captured in fixed
   control storage and checked before enrollment/submission/callback and after
   callback. Replacement is sticky refusal, not a new budget. Deep source/work
   machinery must still enforce its own sticky limits; this factory cannot
   verify a trusted implementation's internals or forcibly stop a blocking
   native callback.

The original cancellation Arc is **preexisting**, not allocated by the factory.
A clone retains the same allocation; it is dropped before lease credit. External
cancellation handles require their own strongly prepaid lifetime. Before calling
`start`, the caller must already retain the real original admission ticket
through control construction, layout/gate checks, refusal and JobControl drop.
`NativeOwner::admit` couples that existing ticket to the native lifetime; it must
not create an independent job/clock/work allowance.

## Actual stack and storage layout

No default stack-size guess is provided. The caller supplies the actually
selected native size, not a crypto estimate or `RUST_MIN_STACK` setting.
`layout` rounds it to the actual page size and rejects zero/small/overflow/
over-aligned control layouts. It maps **one extent** as PROT_NONE:

```
[one owned lower guard page][page-rounded RW native stack][one owned upper guard page]
```

Both guards remain PROT_NONE; every RW stack page and every control/task page is
written before `pthread_create`, Ready, source enrollment or a first fence.
`pthread_attr_setstack` uses the owned RW extent. Custom stack libc guard size is
explicitly set to0 and read back as0; that is **not** a zero-guard claim. The two
explicit owned guards are separate. `MAP_STACK` does not request growable memory
or a fallback stack, and no rlimit/capability is queried/raised by the factory.

The caller-selected2MiB fixture has on this4KiB-page native host:

| Extent | Actual bytes |
|---|---:|
| pthread-reported/custom stack (includes in-stack native TLS/TCB) | 2,097,152 |
| Lower + upper owned guards | 8,192 |
| Stack mapping total | 2,105,344 |
| Separate control + inline task/lease mapping (small fixture) | 4,096 |
| Simultaneous explicit maps | 2,109,440 |

These are actual extents, **not** whole-memory/RSS/backing or algorithm-usable
stack bytes. GNU libc reserves static TLS/TCB inside the stack and separately
allocates DTV/attribute storage. Real `ConcreteTask` and associated lease layouts
must be queried; a diagnostic zero-size lease/task is not a real node/job owner.
Large tasks may make the control mapping larger. Constructor/task/lease moves,
caller temporaries and cleanup frames are separate source-callgraph/native
admission obligations, not made free by using inline mapped task storage.

### SourceScratch and deep callgraph HOLD

This component does not import a fake source or assert that
`SqlCaptureScratch::reservation_bytes() == sizeof` proves total native resource
usage. The actual source/input owner must account its one fixed scratch instance
using the current source layout, placing it in the concrete admitted task/control
mapping or separately admitted mapping/actual stack extent without double-counting
or omitting copy/constructor frames. Exact code/certificate depth128, JSONdepth128,
paired8KiB-key scratch and their complete current callgraph have **not** been run
on this actual source worker. Those tests and caller-stack/backing verification
are required before `SourceCallgraph` can leave HOLD. The recursive guard fault
fixture is only an enforcement test, not an application stack-sufficiency proof.

Actual source async read fences may require an existing Tokio Handle. This
component neither enters Tokio nor supplies a reactor/Poll/heap proof. A future
integration must admit the actual handle/enter/future/poll/waker/state costs or
keep `AsyncFenceRuntime` HOLD. Main's2MiB stack setting and test16MiB setting are
not resource verifiers. A source-free clean-exec helper's512MiB AS/2MiB stack does
not contain or certify this HOST phase's malloc/native TLS/kernel/RSS or source
roots.

## Lifecycle and refusal

The strong original-job/native/node ticket stays in the mapping throughout
bootstrap, callback, source/task drop, panic cleanup, native TLS destruction and
thread exit. Result/VM completion alone returns no credit. `join()` or Drop
stops an unsubmitted worker using an atomic phase + blocking private futex;
submitted callbacks are not detached. No periodic sleep/status polling or
unbounded Rust/Tokio blocking pool exists.

```
callback/source cleanup -> actual pthread_join -> drop original control and
factory cancel handle -> actual stack+guards munmap -> actual control munmap
-> strong lease Drop / capacity credit
```

The worker catches normal Rust callback unwinding and reports a closed
`NativePanic` code after task cleanup; panic support/native hooks/TLS destructor
behavior are themselves part of the unknown admission profile. Native faults,
abort/double-panic or a blocking callback are not safely killable in-process.
Guard overflow tests therefore execute in isolated disposable children only.

Request-drop joins synchronously and preserves capacity while a callback or TLS
destructor blocks. The parent must keep this lifecycle inside an already admitted
native controller. Moving Drop to a newly spawned/unbounded reaper or
`spawn_blocking` would invalidate admission. Actual Tokio-abort/controller tests
remain HOLD; fixture requester-drop is not a claim about current HTTP handling.

Construction failures own and clean every partially mapped extent before dropping
its grant. Unknown native join/attribute-owner destruction or munmap failure
retains/leaks the strong grant rather than minting capacity. Actual map IDs,
base/length and successful munmap observer events prove the original ownership
release; post-VA `mincore` absence alone would not, because addresses can be reused.
Observer pointers/IDs are native internal test data, never source IDs/payload.

## Remaining activation blockers

- No actual immutable node-owner `NativeOwner` implementation, original job-ticket
  coupling or whole-native positive admission. The separate NodeAdmission
  component's numeric/mapped baseline is not enough by itself.
- No new resource room is requested/approved. These extents must be explicitly
  carved by the real owner from actual existing node/per-job reservations; no
  extra stack/TLS/kernel/concurrency margin beyond the approved budgets.
- Current libc exact requested sizes are observations, not simultaneous live
  backing/allocator metadata/page/slab/kernel/physical/cgroup bounds. Native
  startup/destruction can still allocate/fault/abort beyond explicit maps.
- Actual full source/store/controller/GC-clock/HostCtxSourceRoots lifetime and
  source scratch/deep-callgraph work are not integrated or verified here.
- Genuine original10s, async-fence, requester-abort, all-native-server/full HTTP/
  compiler/cert/SQL/crypto/controller integration is not tested by this harness.
- No serving activation, production artifact/profile installation or permission/
  capability/rlimit changes. Parent owns integration and publication.

See `OBSERVATIONS.md` for exact local libc audit and native evidence;
`harness/run-native.sh` for reproduction.
