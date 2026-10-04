# SQL managed JWT seam — finite node key-lock profile, serving NOT activated

Owned files ONLY: `src/crypto/sql_managed.rs` and `src/crypto/sql_managed/**`. This revision implements a **real production mounted-envelope loader** on the narrow audited **Linux/x86_64** path. It performs both AES256GCM opens using the exact pinned RustCrypto implementation, never AWS-LC/ordinary managed/provider callbacks. **No shared Cargo/import/evaluator/service change, controller activation, commit, push or PR by this child.** Whole-serving certification/freshness/runtime admission remains parent-owned; raw SQL crypto must remain sticky `SQL_CRYPTO_FORBIDDEN`.

## Exact implemented API

```rust
Control::new(&AtomicBool, original_monotonic_deadline, work <= 64Mi) -> Result<Control>
Control::frame() -> &FrameControl

unsafe NativeAllowance::from_trusted_launch(actual_hard_stack_extent_bytes,
                                            other_actual_native_bytes) -> Result<NativeAllowance>
Workspace::required_admission(NativeAllowance) -> Result<Admission>
unsafe NodeStartup::from_trusted_node_startup(approved_native_job_ceiling,
    approved_exclusive_software_bytes, approved_locked_maps_bytes,
    Some(audited_all_other_locked_owner_bound)) -> Result<NodeStartup>
NodeLockProfile::required_layout(operator_slots, NativeAllowance) -> Result<LockProfileLayout>
NodeLockProfile::new(NodeStartup, LockProfileCaps, NativeAllowance) -> Result<NodeLockProfile>
NodeLockProfile::claim(&original_Control) -> Result<SlotTicket>
Workspace::new(consumed_SlotTicket, NativeAllowance, &same_original_Control) -> Result<Workspace>
// numerical Workspace::new exists ONLY under cfg(test); strict new_with_ticket is identical
unsafe Workspace::mount_destination(&trusted_Grant, exact_FreshPoint, &same_original_Control) -> Result<&mut [u8;32]>
Workspace::prepare_owned_mounted(&Grant, FreshPoint, &same_original_Control) -> Result<()>
Workspace::admission() -> Admission
Workspace::reset() // erase all mappings/schedules and disarm; does NOT reset Control

unsafe Grant::from_trusted_capture(KeyFields, Attenuation, FreshPoint, &Control) -> Result<Grant>
unsafe MountedWrapping::from_trusted_mount(&mut [u8;32]) -> MountedWrapping
// prepare_mounted(consumed_MountedWrapping) is now cfg(test) compatibility only

Workspace::untrusted_kid(token, &mut FrameBuilder, &Control) -> Result<UntrustedKid>
Workspace::verify(consumed_Grant, FreshPoint, token, options, native_now_ms,
                  &mut FrameBuilder, &Control) -> Result<Verified>
Workspace::sign(consumed_Grant, FreshPoint, claims, options,
                &mut FrameBuilder, &Control) -> Result<&str> // borrow JWT-result mapping

envelope_aad_into(&Grant, EnvelopePurpose::{Dek,Material}, admitted_output, &Control)
sha256(borrowed_bytes <= 1MiB, &Control) -> Result<[u8;32]>
sha512(borrowed_bytes <= 1MiB, &Control) -> Result<[u8;64]>
```

**These unsafe constructors are precise native trust boundaries, NOT certificate/resource verifiers.** The production numeric bypass is removed. Read **PROFILE.md** for the immutable startup-only/global slot and actual finite RLIMIT_MEMLOCK checks, unsafe source-audit/approved-concurrency requirements, owned mount page, exact control Layout and fatal munmap HOLD. Operator caps can only lower trusted startup bounds; unknown other locked owners/infinite OS limits are refused, not assumed zero. All production crypto calls bind the same unique original Control identity; moving it cannot reset its work/deadline, and reusing its address cannot impersonate it. Resource construction never grants key authority. `NativeAllowance` requires an actual nonzero finite hard stack extent already admitted BEFORE mapping allocation/thread launch. The driver must configure/enforce that same extent for all participating native threads and separate native signal stacks, and include guard pages, launch/TLS/OS ownership, code/static mappings and remaining native storage in its actual admission. Do not pass a guessed crypto stack-demand estimate, peak measurement, implicit growable-stack allowance or waiver. `Admission::bytes()` includes the supplied exact stack and other-native extents as well as the known workspace owner/mappings; overflow and a missing stack extent fail closed. This is not a proof that the driver's assertion is authentic or sufficient. Separate parser/control/grant/guest/OS resources must be charged in the same terminal ledger before use; no library-invented total native cap is supplied.

Workspace owns **an additional fixed32 native mount-input page**, **two 64KiB mappings**, a page-rounded **128-byte seed/wrapping-key/DEK/ciphertext/nonce mapping**, and a page-rounded **actual `max(size_of::<Aes256Gcm>(), size_of::<SigningKey>())` crypto-owner mapping**. **Every mapping** is pre-touched, mandatory `mlock`ed and Linux `MADV_DONTDUMP`; there is no pageable-secret fallback. Crypto-owner storage checks the actual pinned type alignment. The owned dalek SigningKey is also initialized in this same locked mapping, not retained as a pageable stack owner; it is dropped and wholly scrubbed on operation exit. No heap allocation occurs in the tested admitted native path, including first schedule initialization on a fresh thread and error paths.

Current Linux/x86_64, 4KiB-page capsule maps: **143360 mapped/locked bytes** (four original maps139264 + owned mount-input page4096). Workspace/original-Control/profile-control owners are computed from the actual current types; **the historical264-byte Workspace owner is no longer current**. Native stack/other-native extents remain additional exact driver-attested terms. See PROFILE.md/AUDIT.md for production-vs-test layouts and current independently measured checks; no whole-process/parser/Grant/guard/TLS/kernel/software/native/controller proof is implied. The old87-test evidence is historical, not a green run of this revision.

### One-use mount and secret ownership

`MountedWrapping` remains an unsafe consumed mutable borrowed view of **32 raw already-locked trusted mounted bytes**, now used by the independent compatibility fixture/private loader core only. Production receives its own already-ticketed/locked/DONTDUMP/pre-touched page through unsafe `mount_destination`, then uses `prepare_owned_mounted`; it does not accept an uncharged external input. The future native loader must validate the configured source/regular-file/permissions/exact length, write all32bytes, never read plaintext before the claimed ticket+lock, and never retain a provider/source/root. **This component does not implement/certify that acquisition controller or open a production secret file.** The actual file read in the new tests is only a trusted regular-file fixture. Input is erased on every preparation return/error/unwind/reset/drop; production offers no private seed import/export, arbitrary provider callback, ordinary prepared-key handle or fallback.

Loader checks exact fresh point and derives the ordinary wrapping identity `base64url(SHA256(wrapping_key32))` itself; an asserted ID cannot redirect a different key. It reconstructs byte-identical existing JSON-array AAD, strictly decodes canonical nonces/ciphertext/tag, authenticates the wrapped DEK32, erases the wrapping input and expanded wrapping schedule, constructs the DEK schedule, then authenticates the seed32. Tag failure at either layer exposes no seed and wipes/disarms all workspace state. Authenticated seed survives only for **one matching point/envelope/phase/declaration operation**. Everything else, including both expanded schedules, has already been erased before loader success. Sign/verify consume the Grant and erase/disarm material on success/error/unwind; successful sign intentionally retains only the authorized JWT result until next use/reset/drop. Failure, reset, cancellation, deadline and reuse erase all owned byte mappings and cipher state. `cfg(test)` seed injection remains only to preserve independent old vector tests, never a production path.

`aes-gcm0.10.3` does **not** inherit the newer issue825/PR827 cleanup fix. Mandatory direct AES/GHASH/POLYVAL zeroize feature unification is specified below and independently checked. Additional pinned-source caveat: POLYVAL0.6.2's autodetect owner has no `Drop`. The mapped `CipherSlot` therefore drops the typed AESGCM object, then volatile-zeroizes its **entire dead representation and rounded page**, including GHASH/unused union storage/padding. It never mutates a live cipher representation. Schedule construction and primitive code can still leave transient compiler/register/stack copies; this is explicitly **not total zeroization**. The parent October3 22:37 threat boundary does not require a novel proof erasing every such copy or a dedicated wholly locked/scrubbed worker stack solely for that purpose. It DOES require the actual hard finite native/stack allowance and locked/erased owned buffers/schedules described above. ARM PMULL and other platforms are not enabled by the production loader; no unsupported-platform fallback.

Caller must preadmit `FrameBuilder::allocation_bytes()` separately. Parser/node/document quotas are cumulative and fixed before inputs. No new serde Value/Vec/BTreeMap/JSON tree, ordinary managed/Wasm call, serving Records getter, prepared-key/catalog/auth cache, arbitrary definer or source provider exists in production code.

`untrusted_kid` carries **no authentication/authority**; it may only select a version of an independently prebound declaration. Complete verify requires exact canonical trusted kid. Grant is non-Clone/non-Debug/non-export, point/certificate/phase/native-definition/key/version/full-envelope-bound, and consumed once.

## Exact attenuation / borrowed typed capture boundary

`FreshPoint { job, snapshot, certificate:[u8;32] }` is an **equality token, not a certificate verifier**. `Grant::from_trusted_capture` is explicitly unsafe: caller must already have authenticated the exact native certificate/fresh point, captured catalog/binding/version/envelope and native declaration fields. Nonzero certificate checks are not presented as proof. No guest fields, unresolved serving root, arbitrary definer, mutable provider/source or caller-manufactured phase may satisfy this boundary.

- Initial/fresh authentication: exact native authenticate key name, empty signingKeys, verify usage only.
- Readless finalizer: no authenticate-key authority; exact native definition's declared signingKeys membership, sign usage only. Reject historical/retired signing.
- Binding and declaration usage intersection must authorize the operation. Ed25519 declaration and catalog algorithm must match. Revoked/destroyed/zero versions fail. Retired/historical versions are verify-only.
- Provider must be mounted, with exact canonical base64url lengths for wrapping hash32, wrapped DEK48, nonces12 and Ed25519 seed ciphertext48. Unsupported algorithms/providers/usages fail before primitive calls.
- v1 intentionally restricts key/domain/id symbols to nonempty ASCII alphanumeric/underscore/hyphen, <=128bytes. This is narrower than ordinary managed key names, not a compatibility fallback. **Trusted native definition identities use a separate nonempty UTF-8 <=384-byte bound**: actual `$flower.authorize`, generated `sql.query.$sql.finalize`, Unicode and embedded-NUL SDK names are complete length-delimited fingerprint identities, never key symbols/file paths/guest authorization selectors. Exact native captured declaration/phase matching remains required.

Parent must destroy serving roots/guest source capabilities before SQLite compute; borrowed arena metadata remains owned bounded storage, not an old source callback. The real fresh verifier and trusted captured declaration/Grant must precede mount loading/private use; preparation checks exact point/full grant binding again. Do not infer freshness from a catalog revision alone.

## JWT v1 subset and time behavior

- Compact JWT<=64KiB, decoded protected header<=1KiB, claims<=32KiB, options<=8KiB. Pure hash borrowed input<=1MiB. No padding/whitespace/noncanonical tail bits in base64url.
- Strict duplicate-key/UTF8/escape/surrogate/number/depth64/node/work quotas use the existing fixed arena scanner. Claims/header/options must be objects; empty option bytes mean `{}`.
- Header allows string alg/typ/kid only. Require EdDSA and exact grant kid. Unknown critical/external-key/other fields are refused.
- Sign options: only optional algorithm=EdDSA, exact kid, typ<=128bytes (default JWT). No keyFormat or asymmetric/ordinary fallback.
- Verify options: algorithms absent or exactly `["EdDSA"]`; issuer/subject/typ strings, audience array of<=16strings, integral clockToleranceSeconds0..3600, requireExpiration absent or true. All other fields/null/wrong shapes/requireExpiration=false/fractional tolerance fail closed.
- Nonnegative canonical integer NumericDate seconds<=2^53−1 for exp/nbf/iat. Fractional/exponent/signed dates are explicitly unsupported rather than rounded. Expiration required for **both sign and verify**. Issuer/subject/type match exactly when expected. Aud string or<=16string array requires explicit expected audience intersection; if token has aud and options omit audience, deny. Options/claim strings<=256bytes.
- Native caller supplies the invocation's real `now_ms`, never guest time or a new wall-clock read. Verification returns `TimeDependency { checked_at_ms, valid_from_ms: nbf−tolerance clamped0, expires_at_ms: exp+tolerance }`. NotActive contains the authenticated **earliest** next outcome boundary, including earlier expiration when nbf>exp. Expired contains the already-past expiration boundary and has no future time-only wake. Signature/options/claim-mismatch failures do not gain time authority. Parent must register these invocation dependencies, including NotActive, before caching/reactivity.
- exp strict: now>=exp+tolerance expires; nbf inclusive: now>=nbf−tolerance active, using exact integer milliseconds. iat has numeric shape validation, no extra future-time policy (matching existing verifier).
- Native strict dalek verification rejects scalar malleability/small-order identities. Fixed signature/public/seed sizes only; no PKCS8/PEM parse or export operation.

Control has a hard64crypto-call/selector-call cap and a sticky cumulative byte-work budget; operations reserve the actual page-rounded mapping sweep bytes before processing. Long codec/hash/capture/equality work checks original cancellation/deadline in<=1024-byte quanta. Native dalek primitive calls check before/after, operate on hard-bounded messages, and remain internally non-preemptible; no CPU-cycle/compiler-stack hard bound is invented. Parent must make work/cancel/deadline/capacity/HOLD fatal rather than guest-catchable/fallback-eligible.

## Parent Cargo hooks — exact narrow dependencies, not edited here

```toml
aes-gcm = { version = "=0.10.3", default-features = false, features = ["aes", "zeroize"] }
aes = { version = "=0.8.4", default-features = false, features = ["zeroize"] }
ghash = { version = "=0.5.1", default-features = false, features = ["zeroize"] }
polyval = { version = "=0.6.2", default-features = false, features = ["zeroize"] }
```

Existing pins used: `ed25519-dalek3.0.0` (fast/zeroize), `sha2 0.11.0`, `zeroize1.9.0`, `libc 0.2.189`. Parent must add/lock the four dependencies and review its **actual** feature tree; standalone `Harness.Cargo.lock` is the exact evidence manifest resolution, not a replacement for Flower's lockfile. `aes-gcm` alloc/getrandom/std/heapless features were not enabled. Source checksums and original MIT/Apache notices are retained under this subtree. Direct `aes::Aes256: ZeroizeOnDrop` is a production compile-time requirement, not only a test assertion.

No parent module/dispatch changes are made here. Parent must certify exact fresh point, attenuation and catalog capture, sever serving roots/source capabilities, provide actual native terminal admission, route only authorized managed jwt.sign/jwt.verify, register authenticated time dependencies, and preserve fatal raw denial/no fallback. Loader core PASS does not establish whole-serving launch PASS.

## Tested evidence and unclaimed integration

**Current113/113 native-interposed independent tests PASS**:47 managed,18 profile,30 current actual frame (including the new mapping-address-reuse observer),18 SQLite,1 actual root allocator. Forced software **15 mounted +18 profile =33/33 PASS**, and both legacy/strict-profile cold filters pass separately as fresh processes. Every five-case first-schedule/load/sign/verify/bad-wrap/bad-material/wrong-key thread reports0C/0Rust; the strict profile additionally observes ticket +all five mappings +typed Drop/unmap. C/aligned allocator positive control5C/0Rust; root Rust positive/unwind control3operations/128bytes. Actual ordinary mounted-file wrap and current source helper bodies are reference-only, never production reuse.

Actual64KiB/exact143360 fork/exec tests, unknown/nonzero other locks, finite/infinity/insufficient/overflow/slot/software caps, cross-thread/concurrent loan/outer-handle lifetime, original-Control address-reuse denial, cancel/deadline/partial map+lock/unwind/reset and actual injected munmap(EINVAL) permanent fatal HOLD are covered. Original AES/GHASH/dalek whole dead-owner/page scrub is retained. Non-test strict constructor signature and actual owner/control layout are measured independently; see AUDIT.md/PROFILE.md. Optimized mounted15/15 +profile18/18 and both separate fresh-process cold filters PASS. Historical87/11 counts and264-byte Workspace are superseded, not new green. Unchanged upstream AES round-key1/1 evidence is explicitly historical, not a new profile test.

Strict independent clippy-all-targets-Dwarnings passes; final owned rustfmt and11owned-Rust/15read-only-input hash comparisons PASS. Full Flower/Ultimator, real source/mount/verifier/controller/node/original-job admission/started artifact, HTTP/SDK E2E and unsupported platforms remain HOLD/not run. No shared edit/configuration/resource raise/commit/push/PR/activation by this child.
