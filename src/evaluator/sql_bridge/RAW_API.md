# SQL-only encoded Wasm route — integration notes

The raw route is feature-gated and **not connected to the service**. The parent owns the evaluator/module/admission integration. Native activation remains **HOLD** until its broader runtime, physical-retention, snapshot, capability and job-budget gates are proved.

```rust
// In evaluator::wasm (same Prepared/Limits as ordinary execution):
execute_prepared_encoded(
    prepared: &Prepared,
    name: &str,
    args: &[u8],
    kind: &str,
    host: &mut dyn EncodedHost,
    shared: Arc<Limits>,
) -> anyhow::Result<()>;

trait EncodedHost {
    fn call<'a>(&'a mut self, operation: &str, input: &[u8]) -> anyhow::Result<&'a [u8]>;
    fn finish(&mut self, outcome: &[u8]) -> anyhow::Result<()>;
}

arena.decode_arguments(bytes) -> Result<WireId, WireError>;
arena.decode_arguments_checked(bytes, checker) -> Result<WireId, WireError>;
WireArena::MAX_ARGUMENTS == 8;
```

## Contract

- Only `sqlAuthority`, `sqlProvider`, `sqlPlan` and `sqlFinalizer` are accepted by the general encoded route. A **separate closed native entry** `execute_sql_authorization(prepared,args,host,limits)` invokes only the SDK's literal private `$flower.authorize` with query kind0; it takes no target name, admits no arbitrary query/alias and grants no system/key authority by itself. Controller must validate the captured authorization declaration/phase, certificate-covered read-only host and managed attenuation. Missing target never falls back to another query. The trusted QuickJS runner's method-kind/readless checks still run, but arbitrary native guests can ignore language surfaces and issue numbered imports directly. The byte transport does **not** make host policy decisions: the scoped host must enforce its exact callback kind/capabilities, including readless-plan imports and captured SDK writer/read capabilities.
- `args` is one **already admitted native value**, not JSON or a serde `Value`. The caller must build/encode it through its job's admitted arena. The route rejects `name.len() + args.len() > 1MiB` before checkout, and copies caller bytes immediately into guest linear memory. The resulting invocation keeps guest offsets only.
- `input` in `call` is the borrowed native **concatenated argument stream**: there is no ARRAY header. Call `decode_arguments_checked`, not `decode_checked`. The fixed parser creates an arena array root, admits at most eight arguments, consumes the complete stream and retains the native literal-key ordinal table across all argument roots. The synthetic root consumes one node/depth level. Reset before the next call; cumulative work is not renewed.
- The response is already **outcome encoded** (`SUCCESS + value` or `FAILURE + transport map`). Return the host output arena's `encode_outcome_checked` slice. The trait ties its lifetime to `&mut self`, never to `input`; the response cannot safely be the guest argument slice. It is copied into the guest before any subsequent host call.
- `finish` sees raw outcome bytes while the guest is suspended. Reset the input/result arena and `decode_outcome_checked` synchronously. It cannot safely retain the guest borrow. No ordinary wire Decoder/Encoder, serde Value or owned initialization-byte-result helper runs on this route.
- Input/output guest spans are checked for overflow, linear-memory bounds and independent 1MiB caps before parsing/copying. The parent must explicitly reserve the **aggregate** of its arena mappings, guest/runtime and frame memory; these helpers are not aggregate admission.
- Any native host `Err` terminates the raw invocation. Catchable application failures must be deliberately encoded as `WireOutcome::Failure` by the host, not formatted through the ordinary callback error serializer. Parent capability failures should return native `Err` or record a sticky context error according to its policy.

## Scoped token / recycle invariants

`Callback` discriminates ordinary owned-Value and encoded dispatch. Its raw token points only to the current execution's stack-local `&mut dyn EncodedHost` bridge. Dispatch borrows guest input only synchronously; returned response lifetime is attached to a local callback token/host, not the guest bytes. No token, caller input pointer, response slice or outcome slice is saved in a prepared image or recycled Store.

All Result paths detach the callback before reset/discard and before returning. Unwinding drops the owned Cell/Store instead of pooling it. Existing recycle `finish` replaces the **complete** Host with `Host::new(..., None)`, dropping managed shared-key/authorization caches and byte accounting. Checkout attaches another complete fresh Host. Raw crypto denial is invocation state and resets with this replacement.

## Crypto HOLD

**Every raw crypto operation currently fails closed**, including SHA-256 (17) and SHA-512 (15). There is no pure-hash exception yet, no ordinary managed-crypto fallback and no managed verify/sign/shared-handle support. The gate runs after cancellation checking but before settings, descriptor/arity processing, JSON/options/private-key parsing, clock callback or any managed cache access. It records `encoded_crypto_denied` in the invocation Host and fails the Wasm import; completion also checks this sticky context flag even if a guest runtime converts import failure into a catchable exception. The final native error is `SQL_CRYPTO_FORBIDDEN`, not a fabricated memory-budget failure.

A later pure-hash exception must use fixed stack digest/output, <=1MiB admitted input, bounded chunk cancellation checks and no Vec/serde fallback. Managed verification/signing needs the parent's bounded capability implementation before any exception can be enabled.

## Checks

- `cargo test --lib --features sql -j2 native_encoded -- --test-threads=1`: **11 real Wasmtime/QuickJS raw-route tests pass**. A combined filter run also passes **22 ordinary ABI/crypto/recycle/readless/Unicode regressions**.
- `bash src/evaluator/sql_bridge/run-tests.sh`: **29 pass** (25 prior bridge/reference/allocation tests plus four concatenated-root contracts).
- `bash src/evaluator/sql_bridge/run-arguments-tests.sh`: **28 pass**, including an isolated counting-allocator fixture covering concat success and arity/node/message/work/cancellation/key-reset failures with **zero Rust heap allocations after arena admission**. This observation is not a Wasmtime/compiler/native physical-memory proof.
- Default and SQL-feature library-only Cargo clippy exit 0 with existing lint warnings and intentionally unconnected foundation dead-code warnings. The isolated argument allocator harness passes strict `clippy-driver -D warnings`. Workspace `cargo fmt --all -- --check`, owned-file rustfmt and `git diff --check` pass.
- Current integrated stage also passed the actual library filters: raw-route11, frozen-context1, registry2, bridge21, frame28 and job-control2. Default library `cargo check`, SQL-feature **all-target** `cargo clippy`, whole `cargo fmt --all --check` and `git diff --check` exited0. Clippy is **not strict green**: existing warnings and staged unconnected API/dead-code warnings remain. The codec fixture's `3.14` has a function-scoped `approx_constant` annotation explaining it is arbitrary data, not pi; no broad lint waiver.
- The durable stage runner itself exited127 after all original commands returned0 because its script was edited while the shell was executing it. The added job-control filter was then run separately (2/2 PASS), followed by formatting/diff checks. Individual completed command evidence is valid; the runner is not claimed PASS. A broader all-Wasm test attempt was interrupted earlier and has no completed result. No full-suite/E2E/native-service activation PASS is claimed.
