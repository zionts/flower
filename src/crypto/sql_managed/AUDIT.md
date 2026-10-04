# Fixed-storage AES/JWT + finite native key-lock audit — October 4, 2026

**Current component normal113/113, forced-software33/33 and optimized-release33/33 PASS, including separate fresh-process cold filters in each variant. Serving/controller/native-whole-runtime activation remains HOLD.** This revision replaces the unsafe numerical production Workspace constructor with the externally provided startup-only node profile/consuming slot ticket, retains the numeric overload ONLY for independent cfg(test) fixtures, and owns the fifth fixed32 mount-input page. Read PROFILE.md for the exact API/operator/unsafe-issuance boundaries and REPRODUCE.md for commands.

Only `src/crypto/sql_managed.rs` and its subtree were edited. Starting shared checkout was `sql-interface-foundation` at `e29c104` + parent WIP; no Cargo/import/evaluator/host/policy/capture/process/node/service/SDK/backend/writer/source edits, configuration changes, limit raises, credentials, service, commit/push/PR or activation by this child. Harness outputs/manifests are unique/external (`/workspace/sql-managed-profile-yom3`); current actual frame/SQLite/root allocation-probe/ordinary reference inputs are read-only. Earlier87 counts and139528/2236680 owner totals are explicitly superseded, not current green.

## Current exact layout and admission evidence

Production (non-test), Linux/x86_64,4096-byte pages, actual selected/pthread-verified2097152-byte fixture stack:

| Term | Bytes |
|---|---:|
| five capsule mandatory locked/DONTDUMP maps | 143360 |
| actual Workspace owner | 528 |
| actual original Control owner | 88 |
| per-capsule owner sum | 616 |
| exact profile control allocation (Inner +one slot, Layout extension/padding) | 232 |
| profile handle | 8 |
| startup gate +unique-Control-identity global atomics | 9 |
| total profile control owner terms | 249 |
| one slot atomic | 8 |
| capsule software with exact2MiB fixture stack +zero EXCLUDED other-native field | 2241128 |
| one-profile software including its control owner terms | 2241377 |

Test-only mapping observer IDs add40Workspace bytes: test Workspace568 +Control88 =656owner sum; same profile control249; one fixture-profile total2241417. The production-only external layout entry point compiles `Workspace::new(profile.claim(original)?, native, original)` with cfg(not(test)), so these are not inferred from the numeric fixture overload. Fixed data maps65536+65536, private scratch4096, actual aligned AES/dalek owner4096, owned32-byte mount page4096. Arithmetic-only2/8 locked-map regressions286720/1146880 do not approve or demonstrate two/eight concurrent production jobs. Software/slot caps can only lower the native controller's actually approved exclusive budgets/ceiling.

These are logical requested-map/type/control/fixture-stack terms, **not allocator backing, RSS, VMA/page-table/kernel/TLS/guard/signal-stack/Grant/parser/guest/code/static/whole-native totals**. Startup global atomics are charged at actual owner sizes; their mapped backing remains a driver native term. `NativeAllowance`/`NodeStartup` are unsafe issuers of attestation boundaries, NOT verifiers or evidence of resource approval. Unknown other locked owners => refusal. Actual total node/original-job ledger and startup-before-ANY-keys/source audit remain parent hooks/HOLD; no hidden use of the16MiB public control baseline for key-private143360 maps/helpers/ingress.

## 1. Exact dependency identity and real feature tree

Actual primary source root used by the independent build:

```text
/usr/local/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/
```

Required parent dependency additions:

```toml
aes-gcm = { version = "=0.10.3", default-features = false, features = ["aes", "zeroize"] }
aes = { version = "=0.8.4", default-features = false, features = ["zeroize"] }
ghash = { version = "=0.5.1", default-features = false, features = ["zeroize"] }
polyval = { version = "=0.6.2", default-features = false, features = ["zeroize"] }
```

The actual external Cargo tree has aes-gcm only `aes`/`zeroize`; AES0.8.4 `zeroize`; GHASH0.5.1 `zeroize`; POLYVAL0.6.2 `zeroize`; cipher0.4.4, ctr0.9.2, aead0.5.2, crypto-common0.1.7, generic-array0.14.7, universal-hash0.5.1, subtle2.6.1, cpufeatures0.2.17. Transitive AES/POLYVAL default features appear but do not introduce AESGCM alloc/getrandom/std APIs. No AEAD allocating encrypt/decrypt, random key generation, error queue, provider cache or native FFI primitive is used in production. `Harness.Cargo.lock` preserves the complete actual resolution/checksums. This child did not edit the parent Cargo/lockfile; parent must inspect the integrated actual tree instead of extrapolating this one.

Primary GitHub API issue825 and PR827 were independently read: issue825 is closed; PR827 was merged June30,2026 and addresses feature propagation/ZeroizeOnDrop. **Closure does not prove the old pinned release contains the fix.** Actual0.10.3 source below proves it does not. Primary identifiers, not a secondary summary:

```text
https://github.com/RustCrypto/AEADs/issues/825
https://github.com/RustCrypto/AEADs/pull/827
```

`SOURCE-SHA256.txt` records the exact relevant local primary files. Original complete MIT/Apache notices from all four pinned packages are retained under `licenses/`; implementations were not vendored/reimplemented/patched. The only ordinary-code extraction is independent test-only code generated from the current actual first-party managed source.

## 2. Pinned expanded AES/GHASH cleanup: features alone are insufficient

- **aes-gcm0.10.3/src/lib.rs:** `AesGcm` owns inline AES and GHash. Its `zeroize` feature clears the temporary GHASH key during `From<Aes>`, but does not propagate all dependent zeroize features or add its own ZeroizeOnDrop implementation. Detached decrypt checks fixed limits, computes/constant-time-compares the tag **before** applying CTR to the caller buffer; bad tag returns fixed `aead::Error`, no malloc/native TLS error machinery.
- **aes0.8.4/src/autodetect.rs:** Drop dispatches `ManuallyDrop::drop` to the selected intrinsic/software owner. `ni.rs` encrypt/decrypt round-key owners zeroize schedules in Drop when zeroize is enabled. `soft.rs` clears its fixed key array; wrappers own/drop it. Production `CipherSlot::new` requires the actual `aes::Aes256: ZeroizeOnDrop` trait at compile time. This direct dependency/feature is not optional audit prose.
- **ghash0.5.1/src/lib.rs:** `GHash(Polyval)` has no independent Drop. Direct GHASH zeroize enables clearing local reversed `h` and transformed `h_polyval` construction buffers. It does NOT itself propagate POLYVAL zeroize; hence the separate exact direct POLYVAL dependency.
- **polyval0.6.2/src/backend/clmul.rs/soft64.rs/soft32.rs:** those backend Drop implementations clear fixed key/accumulator fields under zeroize. `autodetect.rs::finalize(self)` extracts the active backend with `ManuallyDrop::into_inner`; the finalized backend then drops. This covers the selected backend of the temporary finalized GHASH clone used for authentication.
- **Important additional caveat:** pinned `polyval0.6.2/src/backend/autodetect.rs` owns a `ManuallyDrop` union but has **NO Drop implementation**. Dropping AESGCM normally does not clear the original autodetect GHASH owner even with all four features. ARM PMULL additionally has an explicit TODO/no active zeroize Drop. Neither defect is silently inferred fixed from newer releases.

**Concrete mitigation for the owned state:** `CipherSlot` owns one aligned, pre-touched, mlocked/DONTDUMP mmap sized to the actual maximum of pinned `Aes256Gcm` and dalek `SigningKey` owners. It writes exactly one typed owner into that mapping. Clear/reinitialize/drop first run the typed Drop, then volatile-zeroize the **entire dead representation and every rounded page byte**. Thus the original GHASH state, inactive union representation/padding and any remaining expanded AES owner bytes are erased without relying on POLYVAL autodetect Drop. No byte scrubbing of a live cipher, type-layout reinterpretation, field offset guess or custom cipher is used. Wrapping schedule is scrubbed before DEK schedule initialization; DEK schedule is scrubbed before successful loader return. Exception guards scrub on error/unwind/reset/cancel/deadline as well.

**Actual tests:** mapped whole-state erased checks after real schedule initialization, reuse, reset and deliberate unwind; AES ZeroizeOnDrop compile assertion; normal and forced `aes_force_soft`/`polyval_force_soft` mounted tests pass. The **unchanged pinned AES0.8.4 upstream `tests::zeroize_works` test passed historically** from an isolated source copy: it directly tests software round-key objects and available x86 AES-NI round-key objects after Drop. Its old upstream manifest/cfg/deprecation warnings were observed, not hidden or attributed to this component; the independent component clippy-Dwarnings is clean.

Transient construction/primitive copies in compiler registers/stack still may remain, including returned/moved initial schedule construction and GHASH/CTR masks. No total zeroization claim is made. On the enabled x86 path the finalized backend cleanup and full mapped owner erasure above are explicit; ARM/other platform production loading returns Unsupported rather than widening the audit.

## 3. Real envelope and lifetime, not test seed-only success

Current actual ordinary reference source SHA256: `e745e980c9b1359182a21109dbfd8e5e9ba6a801759f345a4603c5e16d98d006` (`src/crypto/managed.rs`).

Read-only actual `src/crypto/managed.rs` establishes:

1. Mounted file must be regular, not group/other accessible, exactly32raw bytes; ID is canonical base64url SHA256(bytes).
2. `NativeKeys::envelope` wraps random DEK32 with mounted AES256GCM and AAD `['flower-key-v1',domain,id,version,algorithm,'dek']`, then seals key material using that DEK and the identical array with `material` purpose.
3. Existing wire stores ciphertext with appended16-byte tag, nonces12, URL_SAFE_NO_PAD; `NativeKeys::unwrap` opens wrapping then material in that order.

The production SQL loader accepts the Workspace-owned mount page only after a consuming native slot ticket and an existing trusted captured declaration/Grant/exact point following the real native fresh verifier. Its unsafe native destination is a provided fixed32 locked/DONTDUMP/pre-touched page, not a source loader or verifier. The borrowed input wrapper survives only as a cfg(test) compatibility fixture/private implementation detail. It derives/checks the real ID, constructs byte-identical AAD in a locked fixed slice, decodes canonical ciphertext/tag/nonces in a locked fixed page, opens DEK32 with RustCrypto detached AES256GCM, erases old wrapping input/schedule, opens seed32 with the authenticated DEK, and erases DEK/ciphertext/nonce/schedules. There is **no file/provider callback, old-root lookup, ordinary managed helper call, arbitrary private seed import/export or fallback in production**.

Standalone `build_harness.rs` extracts and compiles current actual ordinary `cipher`, `seal`, `open`, `aad`, `MountedKey`/read bodies into a test-only reference. Tests use those genuine ordinary AES ciphertexts for both layers, including an actual mode0600 mounted file read/wrap. Legacy caller mount-input fixtures retain a separate locked/DONTDUMP page outside Workspace; new strict-profile tests use the fifth Workspace-owned page and observe construction/drop too. The actual regular-file32 read into this owned page occurs only in the trusted test fixture, not production. Both AAD byte arrays, wrap-open and DEK-open are differentially checked; SQL loader then signs and verifies a real JWT from the recovered material. Bad wrap tag, bad material tag, wrong AAD at both layers, wrong wrapping key/ID, stale point, phase/definition/point/envelope rebind, one-operation reuse and reset all fail closed with owned-state cleanup.

Grant construction remains unsafe trusted capture: point/certificate equality is **not authenticity or whole-serving freshness**. The parent must validate exact native certificate/catalog/declaration/phase before constructing it and sever serving roots/capabilities. Mount source/regular-file/permissions/exact-length acquisition must occur in the future trusted native driver, after the actual captured Grant/fresh verifier and ticket+mandatory lock; this component does not claim to certify that source. After copying wrapping bytes into the admitted mapping it immediately drops/erases the borrowed input. Workspace retains no mount view/key-source/provider/callback/catalog cache. Only the point/envelope/phase-bound seed32 survives preparation for one operation; operation exit/disarm removes it.

## 4. Startup/profile/OS/lifetime and honest remanence boundary

Startup is immutable, process-global and one-shot even if the outer profile dies. The actual externally provided native node owner must share it across every Store/replica/job; cross-process/host-global original-job accounting is separately parent-owned. Actual `getrlimit` soft AND hard must be finite and support capsule map caps +all audited other current/future locked owners. Unknown owners/refused diagnostic/truncation/infinity/insufficient/overflow fail before maps/private input. Fixed `VmLck` is only a diagnostic; `capget` refuses startup calling-thread effective/permitted/inheritable CAP_IPC_LOCK/CAP_SYS_RESOURCE. The driver must enforce the same absence for participating threads. No production setrlimit/resource raise/privileged waiver/pageable fallback.

Full-byte/slot CAS checks use the original sticky cancellation/deadline/work owner, with64bounded CAS retries and metered finite slot scans. Unique original Control identity survives a move but rejects reconstructing at the same address/deadline/cancel flag to reset a budget; its private finite atomic identity is NOT a job/grant/certificate authority issuer. Tickets/mapping leases retain strong node control across thread/outer-handle drops. Original typed crypto Drop/full dead-owner scrub and all actual successful munmaps precede credit release. No munlock-before-munmap; a failed actual unmap leaks/retains the strong mapping/control owner and full slot credit in permanent fatal HOLD. Later loans/constructors/crypto publication refuse. Reset erases but never credits live maps.

The actual finite native stack/other-native allowance remains independently unsafe driver-attested BEFORE allocation/launch; the crypto library does not invent a demand estimate. Fresh threads select2MiB before spawn and verify pthread extent2097152. Zero fixture other-native bytes means the component observation EXCLUDES guard/signal/TLS/thread/kernel/allocator/other resources; not a production waiver or whole-memory proof. The exact current software/control layout table above replaces the historical four-map264-byte-owner values.

The owned dalek SigningKey is initialized in the same locked/dump-excluded crypto-owner mapping after AES owner cleanup; its Drop and full dead-owner mapping scrub run on operation exit. Dalek3.0.0 primitive construction still creates transient seed/derived scalar/hash stack copies; ExpandedSecretKey Drop clears its private fields, but Copy scalars/compiler temporaries are not thereby proven erased. This is documented remanence, not the previous overbroad all-private-stack HOLD. The exact native memory/stack extent and source nonretention remain real parent release gates. Native primitives remain non-preemptible internally, but their inputs are hard-bounded and cancellation/deadline are checked immediately before/after; no invented CPU-cycle bound is claimed.

## 5. C and Rust heap observations — cold success/error, no warm-up

Linux/glibc independent LD_PRELOAD probe covers malloc/calloc/realloc/reallocarray, aligned_alloc/posix_memalign/memalign/valloc/pvalloc with fixed C TLS counters and direct `__libc_*` forwarding. Symbol resolution/thread creation/output formatting happen outside observation. Rust GlobalAlloc separately counts requested layouts. Positive-control malloc/calloc/realloc/aligned_alloc/posix_memalign test measures5C calls and0Rust. The production path does not link this instrumentation.

Fresh-process filtered tests launch a fresh actual bounded-stack thread for each success/sign, success/verify, bad wrap tag, bad material tag and wrong-key case. Both first AES schedule constructions occur **inside observation**, no RustCrypto warm-up. CPU dispatch0.2.17 uses public AtomicU8/CPUID state, not key-dependent TLS or heap. Results on default selected x86 backend and forced software:

```text
Mounted wrap+DEK schedule init/open/sign/verify: native allocator calls=0, Rust calls=0, Rust bytes=0
Bad wrap tag:                              native allocator calls=0, Rust calls=0, Rust bytes=0
Bad material tag after DEK initialization: native allocator calls=0, Rust calls=0, Rust bytes=0
Wrong mounted key/identity:                native allocator calls=0, Rust calls=0, Rust bytes=0
```

Historical negative controls remain true for **ordinary AWS-LC**, not the new loader: pinned aws-lc-rs1.18.1 AeadCtx::build_context uses OPENSSL_malloc (observed1C/Rust0); pinned aws-lc-sys0.45.0 bad-tag error queue on a fresh thread initializes ERR_STATE/TLS (observed2C/Rust0). These are retained counter-validation/regression evidence, not used in the SQL production path. Pure native admitted JWT/SHA test also still measures0C/0Rust.

Current actual normal113/113 pass with selector/preload:47 managed,18 profile,29 current frame,18 SQLite,1 actual root allocator. This includes current frame-address-reuse release evidence, actual native64KiB/exact143360 child-process tests, original-control address-reuse refusal, partial map/lock unwind and actual EINVAL fatal unmap HOLD. Forced software mounted15/15 +profile18/18 pass; both strict-profile and legacy cold filters pass separately in fresh processes,0C/0Rust each of5fresh-thread cases. Optimized-release mounted15/15 +profile18/18 pass; both strict-profile and legacy cold filters also pass as separate fresh processes,0C/0Rust in all five cases each. Strict independent clippy-all-targets-Dwarnings and final owned rustfmt pass;11owned-Rust and15read-only-input hashes match before/after the final113-test run. Expected test-only unwinds are caught. Initial setup/cache build and later optimized compilation were interrupted by the tool worker; completed runs are reported separately, never inferred green from an interrupted command.

No full Flower/Ultimator checks, real started-serving artifact/profile/controller/source/certificate/membership/concurrency/native-whole-runtime/HTTP/SDK E2E, ARM/macOS/other-libc or complete physical/kernel/cycle proof is claimed. No novel total compiler/register/stack zeroization demand. Preserve sticky raw SQL_CRYPTO_FORBIDDEN across all families. Parent baseline/source/node/mount/controller hooks remain HOLD. No configuration/resource approval/activation was minted by this constructor. See PROFILE.md/API.md/REPRODUCE.md and current owned-source hashes.
