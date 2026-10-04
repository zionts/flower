# SQL mapped node admission — owned ABI, startup integration HOLD

Owner adaptation: child `k7ypukoo2jiyhinp` of foundation `t4ovpycxalx27zea`, October 4, 2026. Published input base: `21ab176ae1bd3c9164b12eeaa68e2de3ff3eac99`.

## What changed; what did not

The earlier **400-byte requested Arc allocation was NOT backing proof**. It is removed from the new native path, rather than accompanied by allocator margins or a general mimalloc claim. One startup attempt constructs the real `admission::Pool` **by value** alongside the native ledger inside one explicitly page-rounded, pre-touched anonymous mmap. `GLOBAL` permanently retains that exact mapping. No native Arc/Box pool allocation, reference-counted last-drop unmap, deallocation, reset, second pool, per-Store/per-router factory or retry that mints capacity exists.

This is still **not `NativeReady`**. Actual source adapter/bootstrap, cancellation/current-token/history ownership, before-any-Store construction, main/all-route/global router use and serving activation belong to the parent and remain **HOLD**. Merely registering this module for root-library typechecking is not startup wiring. No unsafe numeric readiness verifier is provided.

The fixed **16,777,216-byte USER carve** is unchanged. Actual existing per-job reservation remains **432 MiB (452,984,832 bytes)**; minimum configured USER memory remains **448 MiB (469,762,048 bytes)**. CONTROL/DEPLOYMENT budgets, worker counts, queued-input bytes, FIFO partition/lane rotation, scheduler cancellation/delivery semantics and ordinary watches are preserved. Operators may only lower **16 MiB / 256 source cells / 128 cancellation slots** at startup. No deployment/default/resource configuration is edited or automatically raised.

## Actual owner / writer seam

- `pub(crate) mod admission;`
- `admission::Owner`: `Shared(Arc<Pool>)` preserves legacy/test/watch ownership; `NativeStatic(&'static Pool)` retains the **actual mapped Pool** for process life. `Clone`, `Deref<Target = Pool>` and `ptr_eq(&self, &Owner)` are available. Native clones allocate nothing.
- Internal `WeakOwner` preserves weak lifetime for `Shared`; the native case retains the permanent actual Pool reference, never a weak separately allocated object.
- `Pool::configured/new/with_deployment/watches` return `Owner`. `retain`, `acquire`, `schedule` move to `Owner`; the real algorithm and accounting are unchanged. `Pool::value(...) -> Pool` is the by-value constructor used by the native mmap.
- `Input` is `pub(crate)` with private fields.
- Opaque `pub(crate) struct StrongInput { _input: Input, _pool: Owner }`. **Input is declared FIRST and drops FIRST**, while the actual strong owner is alive. `Owner::retain_strong(&self, class: Class, bytes: usize) -> Result<StrongInput, ApiError>` retains input then clones that owner.
- Writer should keep its existing `Mutex<Option<StrongInput>>` attachment-before-evaluation and queued `Arc<Basis>` lifetime. No writer file is edited here. Parent resolves the frozen writer's old `Arc<Pool>` seam against this `Owner` ABI.

## Native bootstrap and reservation seam

```rust
NodeAdmission::prepare(config: AdmissionConfig, limits: NodeLimits)
    -> Result<&'static NodeAdmission, NodeResourceError>;
NodeAdmission::global()
    -> Result<&'static NodeAdmission, NodeResourceError>;
NodeAdmission::try_clone(&self) -> Result<NodeAdmission, NodeResourceError>;
NodeAdmission::admission(&self) -> admission::Owner;
NodeAdmission::allocation_layout(&self) -> AllocationLayout;
NodeAdmission::reserve_native_constant(&self, bytes: usize)
    -> Result<BaselineLease, NodeResourceError>;
NodeAdmission::reserve_registry_mapping(&self, bytes: usize, cells: usize)
    -> Result<BaselineLease, NodeResourceError>;
NodeAdmission::remaining_registry_limits(&self)
    -> Result<(usize, usize), NodeResourceError>;
```

`prepare` is process-global and immutable. Same config/limits borrows the published object. Different config/limits refuses. Any first validation/mmap failure is permanently latched. `OnceLock` is accompanied by a one-attempt flag so an initializer unwind cannot permit another mapping attempt. `global` never initializes lazily; missing/bad initialization is HOLD. Parent must call the startup attempt **before ANY Store**; that actual order is not claimed by this unwired component.

`BaselineLease` is non-cloneable and retains both the actual `Owner` and the permanent native mapping. Its real `Layout` is queried, never assumed to remain the old 40 bytes. Accessors: `reserved_bytes`, `reserved_cells`, `is_registry_mapping`, `admission`, `allocation_layout`. Source must recompute `reservation_layout::<ActualAdapter>()` using the real associated lease and place it inline in its actual owned mapping.

All baseline reservations are conservative **permanent charges**. A dropped ticket is not proof of native cleanup, so it returns no credit. Source mapping issuance remains one-shot even if a caller drops its ticket or initialization/cleanup fails. No reset/replacement witness creates a new cap.

## Exact accounting / page union obligation

`AllocationLayout::native()` and `allocation_layout()` report actual:

- `Layout::new::<Pool>()`, `Layout::new::<Control>()`, `Layout::new::<NativeMapping>()` and real page-rounded `mapped_bytes`;
- caller-inline `Layout::new::<NodeAdmission>()`, `Layout::new::<Owner>()`, `Layout::new::<StrongInput>()` and source-associated `Layout::new::<BaselineLease>()`;
- `bootstrap_region`: the **actual address of GLOBAL**, `Layout::new::<Bootstrap>()`, actual starting page and actual span including that address's page offset;
- native page size.

The mmap bytes **plus actual GLOBAL page span** are already reserved within the **same 16 MiB** before source reservation. The original `NodeAdmission` is physically inline inside GLOBAL's actual reported region. Native caller-inline handles are not hidden heap allocations: their actual embedding owner/mapping/stack must be prepaid; source's page-rounded reservation must include the exact associated inline lease. Parent must reserve any other actual caller/control regions within the same baseline and **union overlapping source-bootstrap/cancellation static pages with GLOBAL**, not add a fictitious `sizeof`-aligned span, margins, RSS, or new resource allowance. Address/page spans must be queried in the actual combined process; ASLR/build-dependent example addresses are not constants.

Reservations are bookkeeping, not a native initializer proof. No assertion about other mimalloc arenas, native stacks, pthread/kernel objects, process allowance, RSS/mlock, allocator backing or whole-controller physical aggregate is made.

## Check boundaries

Native tests use isolated OS children: ONE actual singleton/mapping per child, no global reset. They exercise actual mmap pre-touch/residency/process lifetime, zero Rust allocation in cold native construction and handles/lease retention, actual Pool FIFO/control/deployment/shared-handle behavior, immutable matching/mismatching startup, missing/failure HOLD and strong input charge retention. Ordinary Shared tests remain independent and explicitly are **not native-positive**. The legacy strong-input test observes retained bytes in the actual final `Pool::drop`, proving input-first cleanup at the last strong owner.

A small harness references frozen actual modules; its unused Consensus context methods are unreachable and are **never a positive fixture**. Actual full root-library checks must accompany it. The owner's root artifact is built from published whole-source HEAD plus only owned changes (and non-activating module registration); mutable unowned WIP is excluded. Native Store/Consensus/source, two physical replicas, router/all-route HTTP, current token and full SQL serving remain HOLD.
