# Finite native key-lock profile — October 4, 2026

**Component seam only; serving/controller activation remains HOLD.** Owned files are only `src/crypto/sql_managed.rs` and its subtree. No deployment/configuration files, resource limits, capabilities, Cargo/shared imports, evaluator/service/node/SDK code, commits, pushes or PRs were changed here. This is specifically a **key-plaintext/cipher ownership** profile, not a demand to lock 91 MiB of business SQL rows, every guest byte or every native stack. No total compiler/register/transient-copy erasure theorem is claimed.

## Startup and authority are separate gates

```rust
unsafe NodeStartup::from_trusted_node_startup(
    actual_approved_native_job_ceiling,
    actual_approved_exclusive_profile_software_bytes,
    actual_approved_exclusive_capsule_locked_map_bytes,
    Some(audited_bound_of_ALL_other_existing_and_future_locked_owners),
) -> Result<NodeStartup>; // None => refusal, never assumed zero

NodeLockProfile::required_layout(operator_slots, NativeAllowance) -> Result<LockProfileLayout>;
NodeLockProfile::new(NodeStartup, LockProfileCaps, NativeAllowance) -> Result<NodeLockProfile>;
NodeLockProfile::claim(&original_Control) -> Result<SlotTicket>;
Workspace::required_admission(NativeAllowance) -> Result<Admission>;
Workspace::new(consumed_SlotTicket, NativeAllowance, &same_original_Control) -> Result<Workspace>;
unsafe Workspace::mount_destination(&trusted_Grant, exact_FreshPoint, &same_original_Control) -> Result<&mut [u8;32]>;
Workspace::prepare_owned_mounted(&trusted_Grant, exact_FreshPoint, &same_original_Control);
```

`new_with_ticket` is the same strict constructor and allows independent tests to invoke the production path despite the legacy `cfg(test)` helper. **Only `cfg(test)` retains `Workspace::new(numeric_bytes, NativeAllowance, Control)`.** No production bool/raw-byte overload, fresh per-Store pool or per-query profile constructor exists. Successful production startup is process-global and one-shot even after every outer handle drops. A failed initializer can retry only while its unsafe startup-before-keys contract remains true. The native node owner must provide/share the one immutable profile across every replica/job in the Flower node process; this module does not install that owner in a service. If a node boundary spans processes, a parent-enforced cross-process original-job ledger is additionally required: these process-local atomics do not prove a fleet/host-global ceiling.

**Unsafe issuers are not verifiers.** `NodeStartup` requires actual approval, startup quiescence before ANY key/private input, an exclusive software ledger term and a source audit of all other current/future lock owners. It does not authenticate that claim, infer approval from integers, certify all native memory or mint a key grant. `NativeAllowance` separately requires an already-admitted, actually enforced nonzero finite native stack extent and all supplied other-native extents before allocation/launch. Guard/signal stacks/TLS/native/allocator/kernel metadata and source/controller/capture certification remain additional parent terms/gates. `Grant` and `FreshPoint` retain their existing exact unsafe/equality meaning; they are NOT relabeled certificates.

The initial integration target is **one capsule**, bounded by the actual approved original-job crypto ceiling. The constructor accepts an explicitly operator-requested smaller/equal slot count only through that opaque trusted startup token. It does not invent a hard 128 ceiling, infer two-owner capacity from a successful single-owner test, or approve 2/8 slots. The 2/8 values below are arithmetic/layout regressions only. The parent public 16 MiB registry/cancellation/control baseline is not silently borrowed for key-private mappings, helpers or ingress. Budget provenance/carving remains the parent's real admission decision.

## OS and software checks, before any secret

Startup performs actual `getrlimit(RLIMIT_MEMLOCK)`. **Both soft and hard must be finite**, correctly ordered, and support capsule lock caps plus **ALL explicitly audited other locked owners**; Linux whole-page rounding is applied. Unknown other owners are refused. A fixed 8192-byte, fail-closed `/proc/self/status` parser captures actual startup `VmLck` and refuses if it exceeds the attested other-owner bound. **VmLck is a diagnostic, not a backing/source/future-lock proof.** Linux `capget` additionally refuses effective/permitted/inheritable `CAP_IPC_LOCK` or `CAP_SYS_RESOURCE`. No production `setrlimit`, host limit raise, privileged waiver, best-effort lock or pageable fallback is provided.

The exact control allocation is computed with `Layout::new::<Inner>().extend(Layout::array::<Slot>(slots)).pad_to_align()`, plus the actual node-handle size and explicit startup-gate/original-Control-identity atomic owners; no guessed Arc header, 16 KiB control estimate or unapproved room is used. Startup allocation is after cap/OS/diagnostic checks and is charged against the explicit software budget; allocator backing/metadata still need the native driver ledger. Slots are fixed scalars/atomics, with no per-loan allocation. Runtime CAS checks both original slot and full-software/locked byte ceilings, checks/debits the original cancellation/deadline/work owner, bounds CAS retries to64 and checks every finite slot scan iteration. Busy/contention returns a typed refusal, not an unbounded spin/retry loop. A ticket binds the exact original Control identity, not its address: moving it preserves the budget; reconstructing at a reused address does not. The private finite monotonic identity counter and its bounded CAS fail closed on exhaustion/contention, and it is NOT an authority/job/certificate issuer. Do not recreate/reset the original work/deadline owner for retries.

Admission is recalculated for actual page size and pinned AES/dalek type alignment before construction. A consumed ticket covers **all five maps**, actual Workspace + original Control owner layouts, and the exact driver-attested native extents. It is claimed **before the first mmap/mlock/pre-touch**. Every map locks and receives Linux `MADV_DONTDUMP` before a private byte can enter. The separate fixed32 mount page is now owned by Workspace rather than an untracked caller mount page.

### Exact Linux/x86_64 4096-byte-page map terms

| Owned map | Rounded locked bytes |
|---|---:|
| decoded/AAD/plaintext scratch | 65536 |
| JWT/output scratch | 65536 |
| seed/wrapping/DEK/ciphertext/nonce scratch (128 logical bytes) | 4096 |
| actual max(Aes256Gcm, dalek SigningKey) aligned crypto owner | 4096 |
| owned native mount input (32 logical bytes) | 4096 |
| **one capsule total** | **143360** |
| two-capsule arithmetic only | 286720 |
| eight-capsule arithmetic only | 1146880 |

**Measured production owner/control:** Workspace528 +original Control88 =616bytes; profile allocation232 +handle8 +global atomics9 =249bytes; each slot atomic8bytes. With the independently verified2MiB fixture stack and excluded other-native0, one capsule software2241128 and one profile total2241377. Test-only observer IDs add40Workspace bytes, producing test owner sum656/profile total2241417—not the production layout. Current checks are recorded in AUDIT.md. `required_layout` computes these from the current build, including production-vs-test owner differences; never reuse the historical 264-byte Workspace owner or old 87-test count as current evidence. The independently configured/pthread-verified 2097152-byte test-thread stack is a fixture extent, NOT a crypto-demand estimate or approval of whole kernel/thread ownership.

## Mount, erasure and credit lifetime

`mount_destination` supplies only an already-ticketed, locked, dump-excluded, zeroed fixed32 destination to the **future certified native mount loader**. Its unsafe contract requires the existing trusted captured declaration/Grant after the real native fresh verifier, plus the trusted configured source/regular file/permissions/exact length checks, complete32-byte write, no guest input/provider callback/retained source, and no plaintext read before the ticket/lock. Production code here opens NO secret file and does not certify that loader. The actual regular-file read in this subtree is test-only. Existing `MountedWrapping::from_trusted_mount` still documents its already-locked trusted-input contract; the borrowed loader wrapper is fixture-only, not a production admission bypass.

Preparation consumes/erases the owned input and uses the existing exact AES256GCM wrap-open/DEK-open + JWT implementation. No new seed setter/export, ordinary keyring/prepared handle, retained provider/source, raw guest native-auth crypto or fallback is introduced. All raw Wasm crypto families must remain sticky `SQL_CRYPTO_FORBIDDEN`; only a real trusted fresh captured declaration/grant permits the native component. Bad tags, stale grants/points, cancellation, deadline, reset, mismatch and unwind erase owned seed/DEK/cipher/plaintext/schedules/output/input. Successful JWT output remains intentionally borrowed until next use/reset/drop.

Each mapped owner has its own **strong** profile/mapping lease. The outer profile handle may die or Workspace may move/drop on another thread without losing control/credit. Exact atomic ticket/map ownership closes the last-map/last-ticket release race. Typed AES/dalek Drop + whole dead-owner zeroization occur before unmapping; the Workspace ticket is dropped last. **Only successful actual `munmap` returns mapping credit.** No `munlock` precedes it: successful unmap releases the OS lock automatically. Failure intentionally leaks/holds that strong owner and permanently retains slot/full-byte credit; status reports `held_slots`, all later loans/constructors and crypto publication checkpoints refuse, and the node must treat this as fatal HOLD. Dropping/recreating handles cannot reset it. `reset` erases but does NOT release a live mapping loan.

## Operator recipes — documentation only, no resource approval/config edits

For **one capsule only AND an independently audited zero other-lock bound**, the finite locked-map setting is143360 bytes. With other locked owners, use the checked sum `143360 * approved_slots + audited_other_locked_owner_bound`, independently approved and supported by actual runtime soft/hard limits. The global atomics are charged at their actual logical owner sizes; their actual backing/code/static pages still belong in the separate driver native ledger. These settings do not cover the software/native/stack/kernel ledger and do not activate SQL.

* Docker example: `docker run --ulimit memlock=143360:143360 ...`. Docker defaults may come from daemon `--default-ulimit` or daemon inheritance; there is no universal container64KiB assertion. Do not add `--privileged`, `CAP_IPC_LOCK` or `CAP_SYS_RESOURCE` to bypass a refusal.
* systemd example: `[Service]` with `LimitMEMLOCK=143360:143360` for that narrow zero-other-lock case. Manager/distribution defaults (which may already be adequate, e.g. an8MiB deployment) are not artifact proof; inspect the actual launched process. No unit/global manager setting was edited here.
* OCI `process.rlimits` example: `{"type":"RLIMIT_MEMLOCK","soft":143360,"hard":143360}`. Configure through the actual runtime/operator; never assume a manifest reaches the process.
* Kubernetes/Helm: no chart value/security-context label is proof of an actual process rlimit. Supply the finite immutable runtime profile through the real node startup path, configure the chosen OCI/runtime boundary outside this component, and fail startup if actual checks do not match. No Helm/OCI/Docker/systemd files were changed.

Verify the **actual started artifact**, before keys/capture/serving, not the build shell or a throwaway pod:

```sh
# PID is the real Flower process. Output only limit/diagnostic scalars.
awk '/Max locked memory/ {print $(NF-2), $(NF-1)}' /proc/"$PID"/limits
awk '/^VmLck:/ {print $2 * 1024}' /proc/"$PID"/status
```

The integrated native startup must also emit only scalar `status()/layout()` values (slots, approved cap terms, actual soft/hard, other-owner bound, diagnostic and HOLD counts), and prove the constructor ran in that exact artifact before ANY key/private input. `ulimit`, chart rendering, an8MiB manager default, build-shell values, VmLck alone or this component fixture cannot substitute. Missing/mismatched/unknown evidence => **HOLD/refuse**; never automatically raise limits or borrow a different admission pool.

## Verified primary references

Retrieved and checked October4,2026 (external reference files, no production edits):

* Linux man-pages `mlock(2)` — mandatory page locking, page rounding, `RLIMIT_MEMLOCK`, privilege caveat, and locks removed by `munmap`: https://man7.org/linux/man-pages/man2/mlock.2.html
* Linux kernel `/proc` documentation — meaning of the VmLck scalar: https://docs.kernel.org/filesystems/proc.html
* Docker daemon reference — `--default-ulimit`/daemon-limit inheritance: https://docs.docker.com/reference/cli/dockerd/
* systemd `systemd.exec` — byte-oriented `LimitMEMLOCK` and soft:hard form: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
* OCI runtime spec `config.md` — platform `RLIMIT_*` types with process `rlimits` soft/hard integer fields: https://github.com/opencontainers/runtime-spec/blob/main/config.md

These references explain mechanisms, not approval or proof for the actual deployed node. Parent source/baseline hooks, complete other-owner audit, native concurrency/control/admission enforcement, actual certified mount loader/capture/grant/freshness, exact started-artifact verification and serving remain **HOLD until integrated and independently checked**.
