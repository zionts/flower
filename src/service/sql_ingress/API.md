# Bounded raw SQL ingress — parent handoff

**Source-only component, October 4, 2026. Not serving-integrated.** Owned files are only `src/service/sql_ingress.rs` and this directory. No router, `service.rs`, ordinary ingress, telemetry, evaluator, SDK, Cargo, module list, consensus or shared-map edits; no commit/push/PR. Parent `t4ovpycxalx27zea` owns integration and publication.

## API and required order

```rust
Pool::new(byte_limit, job_limit); // initialize once, backed by actual approved node capacity
Preflight::admission_bytes() -> Result<usize, Error>;
Preflight::new(&pool, Limits, &preflight_check) -> Result<Preflight, Error>;
preflight.lookup_name(&retained_bytes, &preflight_check) -> Result<NameLookup, Error>;
lookup.decoded_len() -> usize;
lookup.bounded_name() -> Option<&str>; // None is opaque, NOT Ordinary
lookup.name() -> Result<&str, Error>; // inline compatibility path, explicit Unsupported if >256
let mut classifier = preflight.registry_classifier(&lookup, &preflight_check)?;
// SOURCE: invoke classifier.classify(actual_raw_terminalMethods) while holding
// the SAME actual validated Published guard. No Snapshot before classification.
// Only Ordinary may clone Snapshot UNDER THAT SAME publication.
// Terminal wraps private RegistryEnvelope/root-free cell + validated metadata;
// the descriptor alone is neither publication nor authority proof.
// Healthy retries require genuinely changed source publication; SAME work/check.
drop(classifier);
preflight.parse_lookup(&lookup, Transport::Query | Transport::Call, &preflight_check)
    -> Result<Header, Error>;
// Or parse(retained_bytes, trusted_transport, check) if the SQL route is already closed.

// Parent: actual native node SQL admission, then original absolute native deadline,
// BEFORE root capture/fence/source selection/authorization/plan/SQL operators.
NativeInput::admission_bytes(OwnedLimits) -> Result<usize, Error>;
NativeInput::new(&native_input_pool, OwnedLimits, &same_native_job_check)
    -> Result<NativeInput, Error>;
input.import(&header) -> Result<(), Error>;
input.name(); input.args_json(); input.credentials_json();
input.request_id_json(); input.expected_revision();
input.decode_string_credentials() -> Result<Option<&[u8]>, Error>; // optional primitive JWT string extraction
input.query_args() -> Result<NativeQuery, Error>; // default direct query input only
input.query_json(bounded_plan_input_json) -> Result<NativeQuery, Error>; // custom readless plan's input, not its whole request
query.sql(); query.parameters(); query.max_rows(); query.query_id();
```

`Check: Send + Sync` must be an allocation-free primitive native stop/deadline check, never a database/provider/authority callback. `Control::new(absolute_Instant, &AtomicBool)` is provided. Preflight and NativeInput borrow **one checker at construction** and use that exact checker for every later phase. Preflight's retained checker has the pool lifetime; compatibility method arguments must have the original data address and substitution fails sticky (vtable identity is not stable across optimized codegen). ALL actual execution uses the retained original checker even for same-address/ZST aliases. RegistryClassifier retains the same borrowed check and has no per-attempt check argument. Methods cannot supply a fresh phase deadline. The parent must adapt its actual original job clock/stop token without renewing time. Pool and checker borrows also keep them live; all native owners/views are compile-checked Send + Sync. This component does not start a worker or serialize an envelope outside admission.

### Raw body and ordinary dispatch

- Hook **before `RequestJson<Value>` or any partition/generic-call/forwarding Value extractor**, not inside an already-decoded handler. Borrow the precharged ingress `Bytes`; do not copy its whole body first. Header and NameLookup borrow that body; their only copied text is a fixed native alias array. Span getters borrow original input. The actual Bytes owner lifetime is covered by a test.
- Name discovery consumes the **complete JSON syntax and EOF**, accepts the final decoded root `name` exactly as existing Value last-key-wins routing would, and skips argument trees without constructing them. It deliberately does not apply SQL duplicate/key/node/mantissa caps to ordinary arguments. It preserves valid ordinary fixtures with 70,001 scalar elements, 5,000 object keys, 2,048 mantissa digits, nesting100 and duplicate keys. The pinned ordinary recursion boundary is tested exactly: serde starts at128 and rejects at0, hence127 containers including the invocation object.
- For a **sealed unmarked decision**, retain the existing ordinary decoder/functionality. Do not globally substitute the strict native envelope. A changed publication must never turn an ordinary Value into native dispatch: bind the ordinary decision to its exact alias/publication and reject/reclassify from retained raw bytes rather than fall back to ordinary SQL execution.
- Alias decoding supports escaped fields and arbitrary valid UTF-8 aliases, including Unicode/surrogate pairs and NUL. An overlong discovery succeeds as a **private opaque NameLookup** with its checked complete decoded byte length; it exposes no prefix/empty fallback through bounded_name. name() explicitly returns Unsupported instead of panicking; parse_lookup refuses it sticky. **Only full healthy registry verification proving every alias <=256 allows Ordinary for this case**. Long->short and short->long root duplicates retain ordinary last-name-wins semantics. Invalid UTF-8/escape/surrogate/NUL encoding, body/depth/work/EOF errors still fail sticky, including after the first256 decoded bytes.
- Discovery is capped by the current **8MiB transport maximum**, finite 64Mi work and the pinned ordinary recursion bound. Full native envelope prechecks **1MiB maximum body before its first decode**, depth64, cumulative65,536 nodes across all envelope fields, 4,096 object keys, a fixed8,192-slot duplicate-key index and1,024 bytes per number. Duplicate decoded keys are rejected throughout native input, including escaped equivalents. Hash collisions, key comparisons, UTF-8, escapes, numbers, structural skip, copying and decode all consume cumulative work and check stop/deadline at at most256 work units. One owner permits at most one discovery and one native parse plus cumulative healthy registry attempts; failed owners are sticky and cannot renew their work. The key index is metered-cleared before every whole registry attempt and any native parse that reuses registry keys (fresh mappings are already initialized), so captured offsets are never reused relative to a different input.

### Exact concrete classifier ABI (compiled freeze for source owner)

All symbols below are `pub(crate)` at `service::sql_ingress`, with private fields/constructors, no `Debug`/`Clone`, and no caller-selected verifier flag/phase/operation:

```rust
Preflight<'pool>::registry_classifier<'borrow, 'body>(
    &'borrow mut self, &'borrow NameLookup<'body>, &'borrow dyn Check,
) -> Result<RegistryClassifier<'borrow, 'pool, 'body>, Error>;
RegistryClassifier::classify<'registry>(&mut self, &'registry [u8])
    -> Result<ClassifiedRegistry<'registry>, Error>;
ClassifiedRegistry<'registry>::terminal(&self) -> Option<&TerminalHeader<'registry>>;
ClassifiedRegistry::is_ordinary(&self) -> bool; // informational ONLY, not a classifier input
ClassifiedRegistry<'registry>::into_terminal(self) -> Option<TerminalHeader<'registry>>;
TerminalHeader::alias/name/catalog/finalizer(&self) -> &str;
TerminalHeader::operation(&self) -> Operation; // Query | Explain | Catalog | Cancel
TerminalHeader::cancel_result(&self) -> Option<CancelResultShape>; // Boolean | Cancelled
TerminalHeader::encoded_method_json/encoded_terminal_json/signing_keys_json(&self) -> &[u8];
```

`NameLookup` is bound to the actual complete invocation body and classifier creation rejects a foreign-body witness. Classification first consumes **the entire 32KiB/depth64 registry**, syntax and EOF, rejecting duplicate decoded keys at all levels (including escaped aliases and arbitrary signer metadata), then verifies exact closed `{format:1,methods:{alias:HttpMethod}}` structure, at most32 aliases, and **all** descriptors before any result. Metadata reuses **all existing8192 key slots**, not an extra map or the4096-key eventual native request cap; real bounded signer values with4200 object entries pass. Structural whole-document node/number checks run once; semantic rereads spend the same cumulative work, not new per-attempt quotas. Canonical stored Value numbers are finite; nonfinite numeric JSON and unsupported noncanonical >64-byte numbers refuse explicitly without fallback.

Only healthy, explicit `{format:1,methods:{}}` is empty/Ordinary. Wrong/unknown/missing/null format/methods or descriptors refuse; stopped/malformed attempts poison Preflight permanently. Source **must reject missing/stale/unknown RegistryEnvelope** itself, never fabricate an empty record, and must only pass its actual provided immutable body. Repeated healthy calls do not replenish remaining work; source must additionally restrict retries to genuinely changed Published versions. This module does not verify source publication, registry stamps, schema absence, installed code or authorization.

Validation mirrors actual `evaluator.rs` HttpMethod/RawHttpMethod serde+TryFrom and `evaluator/sql.rs` TerminalMethod serde+validate/identifier, and actual `evaluator/sql_registry.rs::build` record. Terminal requires query, cache=false, watch=false, no replica-local, no receipt property; catalog is exact63-byte SQL identifier with actual reserved names; finalizer1..384 bytes, method/alias<=256 decoded UTF-8 bytes. Cancellation shapes only for Cancel, signers empty for Cancel; absent/null cancelResult preserves real Option default. At most8 signer Values: usages must be an array containing decoded string `sign`; string-name values are distinct, absent/nonstring name ignored exactly as actual validation. Other signer members/values are arbitrary bounded JSON, not an invented access/algorithm/key schema. `receipt:null` is tolerated by RawHttpMethod's Option, but never emitted by actual terminal serialization: this ingress explicitly rejects **any** receipt field per parent requirement.

Public lookup uses **only aliases**. Private callback method/finalizer names never become lookup aliases from metadata. Getters expose the actual decoded fixed fields, and original validated descriptor/full signingKeys array spans borrowing exactly the supplied immutable registry (absent signingKeys has actual empty-array default). No selected key or capability is returned. Consuming into_terminal permits a source-owned wrapper, but the source must keep its actual envelope body alive and bind the result to its private cell/install/store/scoped revision + bundle/schema/registry stamps + actual KnownAbsent schema proof. It cannot replace that correlation with a numeric verified flag or move/drop the borrowed body unsafely.

### Closed native envelope

Query accepts only `name`, optional `args`, optional `credentials`. Call additionally permits optional nonempty string `requestId` and nonnegative safe-integer `expectedRevision <= 9007199254740991`, matching public validation. Missing args is borrowed static `null`; absent credentials remains distinct from explicit null. Query rejects call-only metadata. `expectedRevision` is preserved only as public transport metadata: it never selects a historical root, operation, phase or authority. Parent retains the public mutation/transaction revision guard if write dispatch is actually selected by its sealed method metadata.

Unknown root fields, including `$principal`, `operation`, `phase`, `purpose`, `authority`, `writes` and `bundle`, fail closed. Those names can occur as ordinary **argument data** but are never interpreted here as native dispatch. No API accepts a caller `is_sql`, operation, purpose authority or a fabricated witness. **Cancellation must be selected from the parent's actual sealed alias descriptor**, not from these JSON bytes.

Header/NameLookup/RegistryClassifier/ClassifiedRegistry/TerminalHeader/NativeInput/NativeQuery/NativeParameter have no Debug/Display. Error is a fixed enum whose Display/code is only a constant `SQL_*` string. No source/SQL/token/parameters/key/error offset is formatted into failure payloads. Parent must encode those codes into its separately admitted bounded reply stage rather than route an arbitrary formatted serde/anyhow error through the native response.

## Later owned input and limits

All storage maps and controls are admitted **before mapping, pre-touch or copying**. NativeInput owns a <=1MiB raw span bank and a separate <=1MiB decoded bank, plus fixed parser/key/parameter descriptors. The distinct banks support a900KiB valid text parameter while retaining raw original args/credentials; there is no accidental requirement that raw+decoded bytes fit one1MiB input cap. Both banks' actual page-rounded physical charges are reserved, not a body-size multiplier. Limits can only decrease. All mapped bytes, including tails, are volatile-pre-touched; all are volatile-scrubbed before unmap and ticket release, including partial failures.

Only validated name/args/credentials/requestId spans are copied, not the complete transport envelope or any argument tree. After successful import the caller may release its own source borrow/body; **existing ingress's outer `_retained` reservation still lasts through `next.run(...).await`**, so its original raw-byte charge conservatively overlaps until response headers.

Optional query decoding accepts only `sql`, optional scalar `parameters`, optional `maxRows`, optional `queryId`; it does not choose a terminal operation. Bounds: SQL64KiB decoded UTF-8; at most256 parameters; decoded input and used typed parameter descriptor/text budget <=1MiB; maxRows <= current SQLite1000; nonempty queryId <=256 UTF-8 bytes (parent native registry must still validate its own ID contract); finite numeric scalar values. String credential extraction allows **64KiB decoded UTF-8 JWT bytes**, including the fully escaped boundary case; arbitrary credential objects remain raw bounded JSON for the native authorization path. It does not verify a JWT, choose a principal or find caller-named token fields.

Default-shaped query input can use query_args **only as a typed decoder after the parent's required deployed args/access/readless-plan processing**; it is not a shortcut around the actual code-owned callbacks. A custom native readless plan should use the parent's admitted native frame/wire value APIs; query_json is only for an **already bounded native JSON rendering of the plan's inner input**. Never materialize a serde Value/String/map to make that rendering. Actual SQLite grammar, scalar ABI conversion, cancel-ID validation, planning, authority, crypto, policy, table binding and source/result/output budgets remain parent-owned. HTTP method/content-type/body rejection semantics (including Axum's JSON MIME requirement) are also the integrating route's responsibility; this scanner consumes bytes, not an HTTP request.

## Exact ledger and unapproved resource proposal

Measured Linux/x86_64 with4KiB pages; methods recompute page rounding rather than assume it:

| Owner | Mapped storage | Finite local control allowance | Total charge |
| --- | ---: | ---: | ---: |
| Preflight | levels4,096 + key index262,144 |16,384 | **282,624 bytes** |
| NativeInput | raw1,048,576 + decoded1,048,576 + levels4,096 + key index262,144 + parameter descriptors8,192 |16,384 | **2,387,968 bytes** |
| One overlapping pair | | | **2,670,592 bytes** |

Classifier adds **no mapping, ticket, user carve, allowance or node resource change**. Linux x86_64 actual TerminalHeader/ClassifiedRegistry representations1072 bytes each; RegistryClassifier32. Compile-time explicitly enumerated fixed constructor/result/selected/scanner/cursor/field/decoder representations total **7747 <= existing16384** control bytes. This is a local representation bound, **not measured/compiler call-stack or physical backing approval**.

**Old proposal only, NOT approval or this child's change:** two preflight tickets cost565,248 bytes; two native input tickets cost4,775,936 bytes; combined local ceiling **5,341,184 bytes** plus separately charged ingress raw bodies and every other parent job owner. Pool independently bounds bytes and active owners with nonallocating atomics, has no unaccounted waiter queue, and releases failed reservations. Partial mapping/deadline failures release both dimensions; cross-thread capacity tests cover byte and slot exhaustion.

The existing ordinary default user queued-input pool is64MiB, control16MiB and body8MiB (`service/tuning.rs:202-205`). These local tickets **must be carved/backed by actual approved node admission**, not silently added beside that pool or treated as authorization for more concurrency. No node resource setting, serving pool or concurrency increase was changed or approved.16KiB is a declared finite allowance for these fixed local owners/decoder controls, **not proof of a whole Tokio/native thread stack, Wasmtime heap, allocator/kernel metadata or physical retention**. Mmap/pre-touch can still fail; swap/reclaim/overcommit/OOM, native/C allocation, actual stack/AS/cgroup backing, registry/controller/runtime and whole-node aggregate accounting remain release gates. Unsupported platforms fail `SQL_UNSUPPORTED`; no native ordinary-SQL fallback exists.

## Precise actual-source proof, not a whole-existing-API bug claim

At shared foundation baseline90c4dd3 + WIP:

1. `service/admission/ingress.rs:98-136` reserves512-byte overhead, grows the lease **before raw Vec requested capacity**, handles actual Vec capacity and stores the reservation in the Bytes owner. `:161-176` times **body receive only** and keeps the outer reservation until next.run completes. Raw bytes are therefore precharged; this is not an allegation that incoming bodies are entirely unbounded.
2. `service.rs:100-107` registers root query/call with `RequestJson` and `telemetry.rs:653-668` directly delegates `axum::Json<T>::from_request`. Axum0.8.9 `src/json.rs:99-114,170-202` obtains Bytes then runs `serde_json::Deserializer::from_slice`, `serde_path_to_error::deserialize` and end().
3. serde_json1.0.151 `src/value/de.rs:107-119` creates a **Vec<Value> and pushes every scalar**; `:121-145` builds its object map; `:73-81` copies strings. `src/de.rs:30-67` also has a growable scratch Vec. Existing handler validation/cache input admission (`service.rs:403-438`) and ordinary `admission::input_bytes` (`admission.rs:107-136`) operate **after** that owned Value exists. No SQL helper AS limit encompasses this parent-side parse.
4. Actual pinned **Axum Json<Value>::from_bytes**, synthetic compact scalar-array only: **262,173 wire bytes**, **131,072 elements**, `size_of<Value> =32`, Vec capacity131,072, **4,194,304 bytes final array backing** (~16x wire) before handler admission. Allocator observed **24 operations /8,389,145 cumulative requested Layout bytes**. Cumulative requested bytes are NOT simultaneous live bytes, RSS, allocator overhead or a process-wide peak. Diagnostics contain counts only, never request contents. No scaled whole-server OOM exploit or all-JSON amplification claim is made.
5. A borrowed RawValue is not an adequate replacement proof: pinned `de.rs:1285-1292` uses ignore_value; `:1102-1205` grows scratch for enclosing containers without the normal recursion check. Synthetic depth1024 borrowed RawValue succeeds with **8 operations /2,040 requested bytes**; malformed counterpart **9 /2,080**. Those are an **alternative-parser** positive control, not a claim that the actual Value route uses RawValue. The new custom scanner avoids serde on both success and failure.

Public shape source: `evaluator.rs:351-393`, safe mutation metadata `:245-280`; SDK `core.ts:25-27` permits any nonempty name and sqlMethod uses it; native SQL caps `evaluator/sqlite/mod.rs:23-33,386-407`; managed JWT `crypto/sql_managed.rs:31` is64KiB.

## Validation / remaining integration

The current isolated harness contains58 tests (the36 prior ingress/native-input tests preserved with opaque-name/same-check contract updates,20 classifier tests,2 actual producer tests). Final validation results are reported by the child checkpoint, not a serving claim. Run `bash src/service/sql_ingress/run-tests.sh` and `bash src/service/sql_ingress/run-clippy.sh`. Standalone harness imports the **one existing root allocation_probe**; the production module installs no allocator. It verifies exact root Cargo.lock versions/source dep-info and hashes the actual pinned rlibs (libc0.2.189, serde1.0.229, serde_json1.0.151, Axum0.8.9, anyhow1.0.104). reference.py extracts **verbatim actual current** HttpMethod/TerminalMethod serde/validation/identifier plus the real build module BEFORE allocator observations, rather than using a guessed schema. It hashes those source files and Cargo.lock on every run, uses an isolated unique `3dyrmki6` temporary output directory, CARGO_INCREMENTAL=0 and two test jobs, and removes only its own output. `SQL_INGRESS_OPT_LEVEL=2 bash .../run-tests.sh` additionally checks optimized module code with the same pinned artifacts. Changed-file rustfmt and git diff --check are also required.

Tests cover full malformed JSON/UTF-8/escapes/surrogates/numbers/trailing syntax, null/missing/nonobject/unknown fields, native duplicate keys, body/name/depth/node/key/mantissa/work capacity, cross-thread quota, cancellation/deadline inside long UTF-8 field skip, pre-touch cancellation and lease cleanup, escaped/NUL native alias lookup, ordinary-compatible discovery, actual Bytes source retention, fixed owner layout accounting, large valid parameter, SQL/parameter/JWT/row caps, sticky later errors, one original native checker, Send/Sync and512 reference fixtures. Rust allocation observers report **0 operations/0 bytes** for admitted scanner/copy/typed-query/JWT success and tested capacity/work/syntax/stop/deadline failures, plus owner construction/denial. This is not a C/kernel/full-runtime proof.

No actual service-hook/partition/generic-call integration, real HTTP closed-route test, full workspace Cargo/E2E, source-issued published envelope/binding witness, capture/fence/controller/native driver, final reply/result stage, resource approval or SQL-positive serving activation is claimed. The stage probe proves that extraction itself needs no Snapshot/Records/source/SQL operator dependency; it explicitly is **not** a fake routing integration test. All parent launch gates remain HOLD until those actual hooks and proofs exist.
