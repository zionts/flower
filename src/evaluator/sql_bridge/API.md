# Bounded SQL guest wire bridge — integration API

Implemented in `src/evaluator/sql_bridge.rs` and `sql_bridge/{codec,slab}.rs`. This child changed **only new files under those paths**. The parent must add the module and raw Wasm callback route; ordinary `wire::Decoder/Encoder` must never run on that bounded route.

## Arena and typed views

```rust
WireArena::new(WireLimits) -> Result<WireArena, WireError>
arena.allocation_bytes() -> usize
arena.work_remaining() -> usize
arena.reset() -> Result<(), WireError>
arena.decode(&[u8]) -> Result<WireId, WireError>
arena.decode_outcome(&[u8]) -> Result<WireOutcome, WireError>
arena.value(WireId) -> Result<WireValue<'_>, WireError>
arena.encode(WireId) -> Result<&[u8], WireError>
arena.encode_outcome(WireOutcome) -> Result<&[u8], WireError>
arena.json(WireId) -> Result<&[u8], WireError>
```

Reset invalidates IDs/views and **does not replenish cumulative work**. `decode` requires a reset/empty arena and consumes exactly one native GUEST_ABI value. Outcomes consume the status byte and validate success/failure schemas. Failure, including capacity/work/cancellation errors, poisons the callback until reset. No partial output is returned.

`WireValue` has `id`, `kind`, `as_bool`, `as_i32`, `as_f64`, `as_str`, `len`, `member`, `index`, `iter`. `WireIter` is exact-size; each `WireEntry` has `key: Option<&str>` and `value: WireValue`. Objects include borrowed keys; arrays do not. Numbers preserve finite raw `i32` or `f64`, including incoming negative-zero bits. JSON output renders ECMAScript number text (negative zero -> zero) with stack-only ryu-js.

```rust
WireOutcome::Success(WireId)
WireOutcome::Failure { code: WireId, message: WireId, details: Option<WireId> }
```

Read-only typed accessors do not themselves mutate/charge the work balance. Parent traversal/provider code must charge/check its job budget, especially if repeatedly looking up/iterating untrusted data. Decoder, builders, encoder, sorting and JSON serialization are cumulatively charged. Borrowed views cannot coexist with mutable reset; stale/foreign IDs are rejected.

## Host replies

`null`, `boolean`, `integer(i32)`, `real(f64)`, `text(&str)`, `array`, `object`, `push(array,child)`, `insert(object,key,child)` operate directly in fixed slabs. A child attaches once; cycles and depth overflow are refused. Duplicate decoded keys are refused. `failure(code,message,details)` builds the transport object and returns a typed failure ready for `encode_outcome`. Failure outcomes manually constructed from IDs must refer to their common, correctly shaped transport object.

Both wire and raw JSON outputs use the same bounded output slab. Wire strings use ASCII Latin-1 or UTF-8; fixed-table key interning and admitted scratch heapsort produce the reference host encoder's canonical UTF-16 ordering. JSON can be copied to FrameBuilder in <=64KiB chunks without any owned JSON tree.

## Admission and cancellation

`WireLimits` fields: `message_bytes`, `text_bytes`, `nodes`, `keys`, `logical_key_bytes`, `output_bytes`, `depth`, `job_work`. Defaults/hard limits live in the source. Incoming/output caps cannot exceed 1MiB; depth cannot exceed 64. Keys includes **all key uses**, not just distinct literals; KEY references also consume logical decoded-byte quota and work. Counts are checked before node admission; Unicode uses a validation/exact-size pass before writing normalized text. Object duplicate and output intern tables never grow.

Every layout and page-rounded sum plus **64KiB finite header/control/stack allowance** is checked against 32MiB BEFORE any mmap. All mappings are pre-touched, including padding. No owned Value/BTreeMap/Vec/String or global-allocator call is needed by decode/build/encode/JSON/reset.

Checked variants accept `&mut dyn FnMut() -> Result<(), WireError>`:

- `reset_checked`, `decode_checked`, `decode_outcome_checked`
- `encode_checked`, `encode_outcome_checked`, `json_checked`
- `text_checked`, `insert_checked`

Use those on the production route. Checks run initially/finally where appropriate and at bounded work intervals; inner Unicode/hash/sort/copy loops also charge/check. Checker implementations must themselves meet the parent's no-allocation/cancellation contract. New arena means **new job admission**, not a callback; do not construct a new arena to renew callback work.

Native Linux 4096-byte-page measurement: one default arena admits **16,056,320 bytes** (15.3125MiB) including control. Two defaults admit **32,112,640 bytes**, below 32MiB; parent must reserve the aggregate explicitly if using separate argument/reply arenas. Decrease limits as needed rather than assigning each callback another independent 32MiB.

## Physical/native HOLD

This is a local bound on page-rounded **user-space mappings plus a reserved finite control allowance**, not a process-wide physical/native allocation proof. Kernel VM/PTE metadata, OS reclaim/swap/overcommit/OOM, Wasm engine/linear-memory allocations, parent frame/host/runtime, and caller/checker allocations are outside this local accounting. Volatile pre-touch cannot prove permanent physical retention. **Native route activation stays HOLD until the parent supplies these broader proofs and admission.** Unsupported platforms or mmap failure reject; there is no heap-tree fallback.

## Checks (October 3, 2026)

Run `bash src/evaluator/sql_bridge/run-tests.sh` after the parent's existing build provides dependency rlibs. It changes no Cargo/module files and removes its temporary executable.

**25 native tests pass:** 17 bridge tests, 6 existing reference-wire tests, 2 thread-local counting-allocator tests. Coverage includes 512 deterministic reference fixtures; all UTF encodings/key-literal ordinals/repeated refs; UTF-8 chunk boundaries; canonical UTF-16 key order; malformed/truncated values/outcomes; duplicate normalized keys; nonfinite values; depth/count/message/Unicode/key-byte/node/output/work exhaustion; cancellation; builder cycles/single ownership; stale/foreign IDs; cumulative work across resets; retained-byte admission. The allocation guard observes **zero Rust heap allocations** during both successful decode/build/encode/JSON/reset and quota/cancellation rejection paths. It is not a kernel/native physical-memory observer.

Standalone `clippy-driver -D warnings` passes; the harness allows only the existing parent-owned wire.rs `chunks_exact_to_as_chunks` lint. Changed Rust files pass rustfmt checking. Full Cargo/E2E/real Wasm route checks are parent integration work and were not claimed by this isolated child. No Cargo/shared-module edits, commit, push or PR was made.
