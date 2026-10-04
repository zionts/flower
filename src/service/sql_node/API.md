# SQL node resources — admission component and integration HOLD

Owner: subagent `2lgji7vdotadzmy6`; parent `t4ovpycxalx27zea`. New files only: `src/service/sql_node.rs`, `sql_node/tests.rs`, this note. No main/service/admission/tuning/partition, Store/Consensus, source primitive, Cargo, SDK or runtime activation edits.

## Source-owner contact / constructor blocker

Subagents here have no `send_to_session` tool, and the sandbox has no `ultimator` CLI. The attempted CLI sends to source and parent both failed with command-not-found. **Contact has NOT occurred.** Parent must relay to `wax7bxo4iag6tgwo` before coupling and supply/import the frozen actual RegistryAdmission/RegistryPool plus mandatory shared-owner Store/Consensus APIs. No trait or Store constructor has been invented.

No `NodeResources` ready constructor or `router_with_resources` is exposed. Existing serving startup/router code is unchanged and therefore NOT repaired by this component alone. Do not activate SQL or claim global native construction success.

## Implemented real component

- `AdmissionConfig::configured()` copies current workers/memory/queued-input budgets and the real existing `evaluation_memory_bytes`, including its SQL blanket reservation. `NodeAdmission::prepare(config, limits)` checks everything before native mmap or Pool allocation, then creates exactly ONE real `admission::Pool` and one pre-touched mapped ledger.
- Fixed conservative **16,777,216-byte** baseline permanently carved from USER preparation memory. It is never added to the configured budget or credited back to the immutable Pool. At current 432 MiB/job, exact minimum USER configuration is **448 MiB (469,762,048 bytes)**; the 432 MiB one-worker default is explicitly refused. No defaults/worker counts/per-job allocation/fairness changes. CONTROL/DEPLOYMENT memory, workers and queues remain intact.
- `NodeLimits` is copied immutably into the ledger; hard ceilings 16 MiB / 256 source registry cells / 128 native cancellation slots. Optional startup-only proposed names: `FLOWER_SQL_REGISTRY_BYTES`, `FLOWER_SQL_REGISTRY_CELLS`, `FLOWER_SQL_CANCELLATION_SLOTS`. Values must be positive and may only lower the ceilings. Reduced source byte ceilings still use the conservative full 16 MiB USER carve, not extra capacity.
- `NodeAdmission::try_clone()` shares the SAME ledger and SAME actual Pool, with no allocation. `admission()` is service-visible only. No Weak baseline owner.
- `reserve_native_constant(actual_bytes)` and `reserve_registry_mapping(actual_page_rounded_bytes, actual_cells)` return non-cloneable `BaselineLease`: strong mapped ledger + strong actual Pool ownership, no new Arc allocation. Caller must put it in the real retained allocation owner BEFORE allocation/unsafe initializer and drop it AFTER final native cleanup/unmap. Only one source mapping ticket can ever be issued; its issued flag never resets, even after final ticket Drop. Failure rolls back strong ownership before returning.
- `remaining_registry_limits()` subtracts actual booked other constants, mapped ledger pages and exact requested Pool Arc layout before source layout calculation. It is a budget seam, NOT a RegistryAdmission impl, source layout proof, or native readiness proof. Cancellation must be actually reserved first by the full constructor.
- Metrics expose configured/reserved/remaining/per-job/control/capacity terms without source identities or private data. Missing source/cancellation layout and poisoned counters are null, not fabricated zero. Construction explicitly says `ADMISSION_ONLY_NATIVE_SOURCE_AND_CANCELLATION_HOLD`; allocator backing is HOLD.

## Exact native measurements already executed

Linux x86-64, native page 4096:

| Allocation | Exact measured/requested layout |
| --- | ---: |
| Ledger `Control` | 96 bytes, align 8 |
| Pre-touched ledger mapping | 4096 bytes |
| Actual `Arc<admission::Pool>` allocator request | 400 bytes, align 8, ONE real Rust allocation |
| Associated inline `BaselineLease` | **40 bytes, align 8**, Send + Sync + 'static |
| Source budget before any other native constants | 16,772,720 bytes |

The source owner must run its REAL `reservation_layout::<NodeAdapter>(limits)` with the actual 40-byte associated lease, not the earlier 128-byte fixture. No final source mapped size/cell capacity is asserted here.

The Arc layout is a pinned-toolchain requested-layout description, checked against the actual native allocation probe. It does NOT account/prove malloc/mimalloc arenas, resident backing or kernel storage. Exact requested layout vs actual resident backing must not be conflated; whole physical construction remains HOLD.

## Cancellation and other HOLDs

The actual cancellation API exposes a 38,944-byte static mutex/registry and hard 128 slots, but does not expose its actual static address/page extent or an owner-linked baseline ticket. Depending on real page offset its page span is 40,960 or 45,056 bytes. A sizeof-only number is not proof. No `NativeRegistry::from_prepaid_node_budget` call was made. Its handle, existing token Arc/control owners, scope lifetime, process-lifetime static ownership and cleanup must be reconciled with strong baseline ownership, with exact Layout or explicit HOLD; no guessed 8 KiB margin.

Frozen source API/Store constructors, actual source pool mapping/last-owner callback order, cancellation owner initialization/current token/source UID/history, required before-all-Stores/bind/liveness main wiring, real two-physical-replica/partition/router/HTTP tests, allocator/kernel/native stacks/backing, whole-node/global-singleton lifecycle, full default+SQL native checks and serving are HOLD. Ingress and its per-job overlapping reservations are untouched. Private-capsule/helper/resource profiles are untouched.

## Checks

Final coherent isolated native run: **26/26 PASS** (13 new node tests + 13 existing admission/ordinary ingress/tuning/allocator-probe tests), zero ignored; strict isolated Clippy **PASS** with `--locked --all-targets --offline -- -D warnings`, plus owned rustfmt/diff checks **PASS**. Hashes of all node and imported production modules matched before/after the final run. Tests imported the actual node module, actual tuning/ingress/probe, and an exact copy of admission with only an explicit ingress path attribute. Evaluator production config is copied unchanged excluding its unrelated full-Wasm test module. Application/telemetry glue is unconnected and fails if native Consensus methods are called: this is deliberately NOT a mocked positive Store/router/HTTP/native-SQL fixture.

The native tests measured real Arc request bytes, zero heap allocations for handle/ticket operations and pre-allocation refusals; real mmap + mincore pre-touch; strong ownership beyond NodeAdmission drop; actual native unmap before lease credit and final ledger drop; hard lower caps/overflow/poison; real shared cold/warm partition lanes and unchanged CONTROL/DEPLOYMENT positive capacity. They do not prove the unavailable source/cancellation integration.

Source mapping reservations must be positive native-page multiples; unrounded values refuse rather than masquerading as actual mappings. The harness permits only dead-code warnings for the deliberately unactivated context, no Clippy lint allowances. Parent later owns coherent full default+SQL native checks. No repository Cargo/lock edits or commits/push/PR, board completion, live process, or serving activation.

Final checked node file SHA-256: `f4654134f4e6ecaa2ae817277ecf5685ca457a356ef60e44795f912652db06a5`; tests: `c6237d2621169a0b7c2ac307101c48301af21a1fd143abac44982c70a7a1bfad`. Target `/workspace/sql-node-2lgji7vdotadzmy6-target` belongs only to this child and is removed after the completed checks; the reproducible small harness remains at `/workspace/sql-node-2lgji7vdotadzmy6-harness`. Shared native targets/cache are untouched.
