# Bounded native terminal collection policy — integration contract

New-only module; **not a serving activation**. Parent import, when ready:

```rust
#[cfg(feature = "sql")]
pub(crate) mod sql_policy;
```

No `Records`, serving getter, `App`, root, mutable source, key capability, provider trait/callback, owned `serde_json::Value`, dynamically growing row/map/rule tree, guest principal/definer switch, or auth-system privilege flag exists in production policy code. Inputs are borrowed `sql_frame::ArenaValue` views of an **already-owned trusted capture**. Captured descriptor slices must also be prepaid/resident/owned by the controller. Their allocator, acquisition/replay, authoritative absence proofs, full dependency/freshness certificates, separate native auth-system read-only metadata phase, terminal driver and whole native Wasm/storage lifetime proof are **not implemented here**. SQL remains **HOLD**.

## Exact API

All types/methods are crate-private. These are native-controller inputs, not guest claims:

```rust
PolicyBudget::new(work: usize) -> Result<PolicyBudget, PolicyError>
PolicyBudget::failure() -> Option<PolicyError>
PolicyBudget::remaining_work() -> usize
PolicyBudget::finish(&mut JobControl, native_now: u64) -> Result<Validity, PolicyError>

CapturedCollection { name: &str, policy: Option<ArenaValue> }
CapturedSupportRow { collection: &str, key: &str, row: Option<ArenaValue> }
CapturedSupport::from_owned_capture(&[CapturedCollection], &[CapturedSupportRow])
  -> Result<CapturedSupport, PolicyError>

VerifiedPrincipal::from_native_auth(ArenaValue, &PolicyBudget, &mut JobControl)
  -> Result<VerifiedPrincipal, PolicyError>
PolicyEngine::new(CapturedSupport, VerifiedPrincipal, native_now: u64) -> PolicyEngine
PolicyEngine::authorize(
  &self, collection: &str, key: &str, row: ArenaValue,
  selecting_fields: &[&str], &PolicyBudget, &mut JobControl,
) -> Result<ReadAuthorization, PolicyError>

ReadAuthorization { decision: Decision, candidate: Option<RedactedRow> }
Decision { allowed: bool, validity: Validity }
Validity = Independent | ClockInvariant | Until(u64)
Validity::intersect(other) -> Validity
Validity::permits(native_now: u64) -> bool // expiry only; use budget.finish too

RedactedRow::validity() -> Validity
RedactedRow::field_visible(name, &PolicyBudget, &mut JobControl) -> Result<Decision, PolicyError>
RedactedRow::field(name, &PolicyBudget, &mut JobControl) -> Result<Option<ArenaValue>, PolicyError>
RedactedRow::mapped_cell(name, ColumnKind, &PolicyBudget, &mut JobControl)
  -> Result<FrameCell, PolicyError>
RedactedRow::encode_json(&mut [u8], &PolicyBudget, &mut JobControl)
  -> Result<usize, PolicyError>

PolicyError = Unsupported | NeedCapture | UncertifiedTemporal | RuleLimit
  | Capacity | WorkLimit | Cancelled | Deadline
```

Errors carry **no row values, private names, keys, provenance or security IDs**. Every operational error is sticky in the one cumulative `PolicyBudget`: catching a guest error cannot resume evaluation or pass `finish`. Constructor capacity failures are fatal admission refusals.

### Captured versus authoritative absent

- Missing collection descriptor or support-row slice entry: **`NeedCapture`**, never `false`. It is fatal here; the module has no serving source it could consult. The controller owns any bounded capture/replay protocol.
- Present collection descriptor with `policy: None`: authoritative lack of collection access policy; ordinary reads are open. A present policy lacking `read` denies, matching native `Policy`'s default.
- Present support-row descriptor with `row: None`: authoritative captured absence, so `readable` is false.
- Present support row: evaluate its guarded collection's **read** rule, using the same verified principal/native time. A target must have a policy and its read rule must not contain `readable`, anywhere in its tree. Target schema/read-rule validation happens before any evaluation. An uncaptured target schema refuses even in a short-circuited branch.
- Duplicate matching catalog/support entries refuse. Lookup uses only the immutable bounded slice; no arbitrary provider/assertion fallback exists.

The evaluator conservatively requires captured readable support even when ordinary principal folding could establish a permanently denied target without a lookup. This can refuse an incomplete capture; it never manufactures authoritative absence.

## Required order and privacy boundary

1. Construct the **one native `JobControl` at admission, before capture**. Every arena must be inspected with a `FrameControl` from that job's original cancellation flag/deadline, not renewed per row/slice/replay. Each public policy boundary touches a fallible arena operation even for empty/open/hidden reads, so both controls apply.
2. Acquire the trusted schema/policy, verified principal and support closure into admitted resident-only ownership. Preserve the actual native JSON number lexemes/classification when capturing: do not route through guest JSON.stringify or a rounding canonicalizer before ACL evaluation. The auth-system full-read-only metadata phase is separate trusted native code; do not expose a boolean guest switch or use a guest-claimed principal. Anonymous normalization matches actual `access.rs`: `$anonymous` loses subject/claims and keeps tenant; non-object principal acts as an empty caller.
3. Use the unchanged string `authorize` API, or the separately checked `authorize_native` API after native key/source binding, for **every get/read/scan/range row before guest projection, typed SQL insertion, aggregate input, limits, offsets or cursors**. Pass all physical index/selecting fields; a row selected through an unreadable field must stay hidden.
4. `candidate: None` is a hidden row: do not pass it to the guest or insert it into SQL. The returned decision's temporal validity still matters. For approved rows, all present fields' read rules are certified before returning the candidate. Fields without a read rule inherit row visibility.
5. Only `RedactedRow` methods may feed projection. A mapped hidden/missing field is **Null**, before any coercion; there is no raw-field override parameter. Visible integer/real/text conversion delegates to the existing frame's bounded scalar conversion. This is separate from ACL comparison: numeric-looking text is **never** interpreted as a policy number.
6. The encoded helper writes only ACL-redacted JSON into **already-admitted caller scratch**, using a fixed depth-64 stack and checked writes. It removes top-level fields like ordinary native redaction; nested data in an approved field remains intact. Original object order/number lexemes are retained: it is not a canonical-key encoder or an ordinary guest serialization byte-conformance claim. A controller feeding a semantics-sensitive guest must prove its capture/encoding contract separately. No partial prefix from an error may be exposed.
7. For a same-builder pipeline, encode the candidate into admitted scratch, end all borrowed arena views, capture/reparse **that redacted JSON**, then use `insert_source_row` on the redacted document only. Calling it on the original raw document bypasses ACL and is forbidden. Alternatively copy approved `mapped_cell` output into a separately prepaid typed bank. Two default `FrameBuilder`s do **not** fit the global 128MiB allowance; this module does not admit such duplication. Account scratch, duplicated encoded/parsed redacted documents and descriptor banks explicitly, or refuse capacity.
8. **Call `PolicyBudget::finish` before seal and again at final publication**, using fresh trusted native time and the original job. It checks sticky failure, total deadline/cancellation, all accumulated validity (including hidden rows), expiry and backwards time. The caller still must validate the complete captured-source/schema/principal/authentication dependency certificate. `finish` is not such a certificate and does not poison a separate frame builder automatically.
9. Destroy capture/policy/support/guest/callback state before SQLite. Only approved typed cells in `SealedSqlFrame` may reach native aggregate computation. Full terminal/source retention/runtime admission/finalizer/publication gates remain the parent's HOLD work.

## Proven semantics and explicit refusal subset

Full read trees are validated with fixed stacks **before evaluation**: 256 rule nodes and depth32, per operation/field, exactly the ordinary limits. Fields are capped at256; catalog64 collections; support20000 rows; paths64 segments. No Vec/String/map growth occurs. Cumulative policy work is hard-capped at64Mi units and is never reset across rows/fields/replay. Arena work is additionally bounded/sticky by the frame. Rule/path/lookup/iterator steps debit; native text comparisons/copies check in <=1024-byte chunks, serialization scanning per byte; scalar parser tokens <=1024bytes. Fixed deep equality/JSON stacks are64 entries.

Supported operators: `const/all/any/not/eq/ne/in/exists/lt/lte/gt/gte/startsWith/readable`. Supported read operands: literal JSON; valid principal subject/tenant/claims paths, row paths, the entire string key, and exactly `now`. Object/array deep equality, nested nulls, numeric f64 equality, exact shared signed/unsigned integer ordering and mixed numeric fallback match actual ordinary native code. Top-level missing/null makes **both eq and ne false**; membership ignores null/missing matches. UTF8 byte comparison implements the native's string code-point ordering, not JavaScript UTF16 ordering. The native-only API's array index parsing preserves ordinary usize's leading zeros/`+` and overflow/invalid behavior with a charged streaming parser, including arbitrarily long leading-zero text within the original frame/job bounds. The legacy string-host API keeps its original20-byte array-index subset/refusal unchanged.

Explicit refusals:

- Unknown operators/fields/operand tags, extra tags, malformed types/arity, invalid reference roots/segments, malformed ignored write ASTs: `Unsupported`. Write-only AST shape/limits are checked, but no write is evaluated/granted. Trusted native schema scope validation remains mandatory.
- Read `next`/`args`, paths >64 segments: `Unsupported`, not guessed missing. The **legacy `authorize` API** still refuses key-part paths and composite-readable keys; it is not silently enabled for the unowned host.
- The **native-only API** supports key parts and composite-readable keys through the checked witness below. Unguarded/nested-readable target rules still refuse `Unsupported`; missing target/support capture remains `NeedCapture`.
- Numeric ACL comparisons use the **current native serde_json1.0.151 default scalar `Number` parser**, never a Value tree or frame/source integer coercion. Frame syntax is already validated. Tokens >1024bytes, cached absolute numeric magnitude >1e300 or exponent digit count >9 refuse **before** invoking serde's allocating overflow/error constructor. Supported finite numbers preserve native integer/float classification and rounding, including negative zero, underflow and integers beyond2^53. Arbitrary-precision `Number` or a non64-bit ABI fails a compile-time scalar-size/ABI assertion (only Linux/x86_64 was tested). Actual dependency features were inspected: default/std/raw_value/unbounded_depth, **no float_roundtrip/arbitrary_precision**. `float_roundtrip` long-number scratch, changed dependency parser/features, and native-error-domain expansion require a new allocator/semantic proof and remain HOLD; do not activate on an unproved feature closure.
- Time-dependent `all/any/not`, including a compound depending on a readable target's time rule, refuse `UncertifiedTemporal`. Temporal `in/startsWith` and a readable key depending on now refuse. Scalar clock comparisons require native now <=2^53-2 and numeric threshold within ±(2^53-2); wider temporal domains refuse. Missing/null/disjoint fixed types, `exists(now)` and two-now comparisons have explicit invariant proofs, not ctx.clock assertions.

### Exact future boundaries

For supported scalar `now < v` / `now >= v`, the next boundary is `ceil(v)`; for `now <= v` / `now > v`, `floor(v)+1`. Reversed comparisons swap operators. Eq/ne with an integral threshold flip at a future threshold or at `now+1` when currently equal; a nonintegral fixed threshold can never equal integral milliseconds and is certified invariant. Past thresholds can likewise have proved no future flip. `Until(t)` is **exclusive**; `ClockInvariant` is distinct from time-independent, and is never an invented expiry. The budget retains the earliest boundary across decisions and field visibility plus the latest evaluated clock lower bound. No absolute wall clock is read by this module.

## Native typed logical keys — separate checked API

`typed.rs` introduces a private-field `NativeKeyRow`; neither a guest `jsonKey`
boolean nor an opaque-looking entity ID chooses the encoding. The native caller
supplies the **actual owned `Source { name, jsonKey }` declaration** from the
captured schema/catalog (camel-case, absent `jsonKey` defaults false), actual
canonical physical-source suffix `[collection, encoded_logical_key]`, retained
`KeyId`, optional decoded-document `JsonId`, and row/authoritative absence
`JsonId`, all in the **same admitted FrameBuilder**. No new field is required on
existing `CapturedSupportRow` or host `OwnedRow`.

Binding checks declaration grammar/name, physical pair arity/string components,
canonical native serde escaping and exact retained key bytes, decoded raw token
identity, and typed-key native canonical identity. **Canonical-equivalent is not
sufficient** for decoded input: integers beyond2^53 can stringify to the same
bytes yet differ in native integer ordering. The decoded document must be parsed
from the exact retained encoded text. Scalar typed null/bool/number/string keys
are valid too; only arrays/objects supply key parts, exactly as native `Term`.
Physical/internal prefix-looking string keys/names refuse before output; the
physical pair has no public accessor and generic errors contain no IDs.

Every decoded key/document must be reserved/copied/parsed using the original
frame quotas and original job's FrameControl **before binding**. This component
adds no parser, Value tree, heap allocation, arena mapping or replay budget. The
caller must include raw physical-pair/declaration/decoded documents, their
parsed nodes/decoded strings, retained key bytes and witness descriptors in the
**original** admission; do not instantiate another default128MiB frame. Every
binding/lookup/canonical traversal/sort comparison/number parse/byte match is
charged to the original cumulative PolicyBudget and checks original JobControl.
FrameControl is not introspectable here: matching its flag/deadline during
capture remains the native controller obligation, not a claimed proof.

`from_owned_native_capture` validates **all** native collection names and
all duplicate `(collection, encoded_key)` support rows before a candidate can
be produced, even when unrelated to the selected row. Descriptor storage is
borrowed fixed/admitted metadata, not a new Vec allocation. Support witnesses
must share one frame. `authorize_native` accepts the bound witness instead of
independently substitutable collection/key/raw row inputs. Missing support
entry gives sticky `NeedCapture`; captured `row: None` is actual absence/false.
Readonly targets still cannot themselves use `readable`.

Whole `ref:["key"]` resolves to **encoded logical text**, never the decoded
JSON. Nonempty key paths walk only the already-owned array/object, matching
native object member/array index/missing/null semantics. Untyped string keys can
also contain valid noncanonical array/object JSON: pass a decoded document
whose raw bytes exactly equal the original string, keep `jsonKey:false`, and
native key-part lookup works without changing SDK string identity. Ordinary
opaque strings yield missing parts. A structure-looking untyped string without
a captured parse refuses `NeedCapture`; malformed JSON in that shape is outside
this bounded admitted subset (do not reinterpret a parser failure as absence).

Composite `readable` operands are canonicalized **by a streaming byte matcher**,
not an allocated String or scratch buffer. Arrays retain order; object member
selection is bounded O(n²) with **UTF-16** ordering from actual native
`json.rs::compare` (ACL string comparison remains UTF-8). Numbers use the same
pinned/native scalar parser and ryu-js formatter, including integer rounding
and negative-zero normalization; existing numeric refusal margins still apply.
The target then resolves its key parts from its own exact encoded key, not the
original operand's possibly rounded token stream.

### Exact SDK layering (do not double-decode)

Actual `sdk/define.ts` **application ctx.get** accepts a logical typed key,
validates the collection codec and sends `encodeKey()`'s canonical **string** to
raw host.get. Raw host.scan returns encoded strings; the application's ctx.scan
wrapper then `JSON.parse(row.key)` **once** for typed collections. Likewise the
actual generated provider in `sdk/sql.ts` already decodes incoming encoded row
keys once when its captured Source has `jsonKey:true`.

Therefore parent integration with those **unchanged actual SDK wrappers** must
keep raw host scan/provider-adapter input keys as `encoded_key()` strings while
using `authorize_native` internally. The resulting app ctx.scan/provider callback
keys are decoded arrays/objects/scalars, not opaque strings. Do not send
`NativeDecodedKey::Json` into an adapter that still calls JSON.parse: that would
be an incompatible double decode. `logical_key()` exposes the checked decoded
value for a direct native logical-key seam (or a separately proven adapter that
no longer decodes), not a license to alter the existing raw host protocol.

For declared mapped **sourceKey SQL columns**, deliberately retain
`encoded_key()` canonical text even though the application's logical key is
JSON. Native copies/transports must remain metered and admitted. Never put a
full `source:[...]` identity into schema/cells/errors or provenance. Host
read/provider integration is **not changed by this patch**; existing provider
`jsonKey:true` refusal remains until its owner imports these constructors and
performs complete native binding/coverage checks.

A private checked witness proves byte/offset correlation only. **Native
controller origin/catalog membership/absence/source freshness/root reservation,
full runtime/crypto/service/publication remain HOLD.** No guest constructor,
privilege flag, callback/source fallback, enabled SQL claim or public native
positive endpoint is added. Temporal proofs/refusals are unchanged; zero frozen
Ultimator read-tree `now` references do not waive method/provider expiry.

## Reproduction and measured evidence

Standalone `harness.rs` imports **current actual** sql_frame/sql_control/SQLite modules. `harness_build.rs` extracts and compiles the **unmodified current native** Policy/Rule parsing/validation, caller folding, `Check`, `Access::visible/redact`, equality and canonical JSON bodies from `rust_engine/access.rs` and `rust_engine/json.rs`, excluding serving Engine/Rows acquisition. Reference Rows use explicit test captured fixtures. This is stronger than an SDK-only mirror, but not a serving/controller authorization proof.

External `/workspace/sql-policy-harness/Cargo.toml` names:

```toml
[package]
name = "flower-sql-policy-harness"
version = "0.0.0"
edition = "2024"
build = "/workspace/flower/src/evaluator/sql_policy/harness_build.rs"
[lib]
path = "/workspace/flower/src/evaluator/sql_policy/harness.rs"
[dependencies]
libc = "=0.2.189"
libsqlite3-sys = { version = "0.38.2", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["raw_value", "unbounded_depth"] }
ryu-js = "1"
```

```sh
cd /workspace/sql-policy-harness
CARGO_TARGET_DIR=/workspace/SESSION-owned-target CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo test --offline -- --test-threads=1
CARGO_TARGET_DIR=/workspace/SESSION-owned-target CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo clippy --offline --all-targets -- -D warnings
rustfmt --edition 2024 --config skip_children=true --check \
  /workspace/flower/src/evaluator/sql_policy.rs \
  /workspace/flower/src/evaluator/sql_policy/*.rs
```

Final **69/69 PASS on actual shared HEAD866532061198183c2c873cdba78597b3dbb618eb**:21 policy tests,28 current-frame tests,18 current-native SQLite tests and2 current JobControl tests. Standalone `cargo clippy --all-targets -- -D warnings` and owned-file rustfmt check PASS. Counting-allocator guards report **0Rust allocations/0bytes post-admission** for all measured policy operations and supported/refused numeric/error cases. One earlier full run exceeded its120s command envelope under shared-host load; the final600s-envelope run completed normally in71.64s test time.

Fixtures cover hundreds of actual-native comparison/boolean/path/redaction/temporal decisions, readable visible/hidden/absent/uncaptured/recursive-target states, principal spoof rejection, exact rule limits, sticky work/time/cancellation, FrameControl even for open/empty reads, fixed output failure, real current SQLite COUNT/SUM privacy-before-aggregate, and isolated counting-allocator measurements for validation/lookup/comparison/redaction/projection plus supported numeric and refused/error paths. Test entry/build extraction never enter Flower production. No shared imports, Cargo/service/consensus/SDK files, commit, push, PR or deployment were performed by this child. Full Flower/Ultimator npm/Cargo/e2e checks were intentionally not run: this delegate is new-file-only, not wired into serving, and the parent owns integration/full checks.

### Typed-key extension evidence (October 4, 2026)

See `typed_matrix.md` and `typed_manifest.json` for the exact frozen189-policy
read/field-read inventory. The current-native extraction additionally compiles
unmodified `source_id/source_pair` helpers. Native fixture reference setup is
outside allocation probes; production inputs remain borrowed ArenaValue only.
The whole frozen matrix is **189 supported ASTs (including all89 previously
typed-key HOLDs), not189 allowed rows**. The old host/string API still has its
100/89 compatibility classification until separate host integration. Tests
include actual first-human `members[org,subject]` allowed and hidden rows before
one-frame real SQLite `COUNT=2,SUM=7`; full runtime/controller activation stays
HOLD. Final test/lint/allocation evidence is recorded with the matrix.

Typed-only external tests use the additional `sql_policy_typed_harness` cfg
emitted by this module's updated build script. Existing host harnesses that
emit only `sql_policy_harness` retain their old test surface and do not acquire
an unresolved new `reference::source_id/source_pair` dependency. To combine
the suites, use this updated extraction/build entry or add its unmodified
physical-helper sections and the new cfg in the host owner's harness.

Final typed extension validation: **81/81 isolated current-native tests PASS**
(2 controls,29 frame,32 policy including11 typed,18 SQLite), strict offline
clippy-Dwarnings and owned fmt PASS. Native post-admission typed success/refusal
regions report **0Rust allocations/0Layout bytes**. Whole189 AST matrix yields
1,890 differential decisions; exact key-part/comparison microcases cover7,008
predicates. See `typed_matrix.md` for frozen file hashes, corrected intermediate
checks, old external host-harness compile blocker and explicit remaining HOLDs.
