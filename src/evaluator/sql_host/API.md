# Current host closure: exact native capture + required finish expiry

Production constructors are now `new_native`, `new_native_registered_authority`
and `new_qualified_finalizer`; legacy `new` / unchecked registered-Authority
constructors are **test-only**. Historical evidence below is not current evidence.
Source/controller/certificate/runtime/signing/publication/serving still HOLD.

```rust
NativeCaptureCollection::from_owned_offsets(actual_source_declaration: JsonId, actual_policy: Option<JsonId>)
NativeCaptureRow::from_owned_offsets(actual_source_declaration: JsonId, canonical_source_pair: JsonId,
    retained_encoded_logical_key: KeyId, exact_decoded_key_document: Option<JsonId>, actual_row_or_absence: Option<JsonId>)
NativeCaptureRow::bind(frame, original_frame_control, original_policy_budget, original_job)
    -> Result<NativeKeyRow, HostError> // caller-prepaid bank initialization only
NativeCapture::from_owned_native_capture(original_admission, frame, relations,
    native_collection_descriptors, native_row_descriptors, prepaid_collection_bank,
    prepaid_native_key_bank, original_frame_control, original_policy_budget, original_job)
    -> Result<NativeCapture, HostError>
SqlHost::new_native(phase, original_admission, NativeCapture, binding,
    original_policy_budget, actual_native_point, original_job)
SqlHost::new_native_registered_authority(original_admission, NativeCapture,
    binding, original_policy_budget, original_job, actual_native_point, permit, execution)
NativeBinding::at_permission_point(actual_opaque_NativeTimePoint) -> Result<NativeBinding, HostError>
HostAdmission::permission_stamp(original_job, actual_fresh_clock) -> Result<PermissionStamp, HostError>
SqlHost::new_qualified_finalizer(original_admission, frame, binding,
    original_policy_budget, actual_permission_stamp, actual_finalizer_point, original_job)
SqlHost::prepare_finish_input(request, result, provenance) -> Result<&[u8], HostError>
SqlHost::finish_permission() -> Result<FinishPermission, HostError> // successful finalizer ONLY
HostAdmission::validate_finish_permission(original_job, FinishPermission,
    actual_fresh_publication_clock) -> Result<Option<u64>, HostError>
```

All native capture offsets resolve in ONE admitted frame. Every witness-bank
entry is overwritten by published `NativeKeyRow::bind_owned_native_capture`;
policies are obtained from this same frame. `CapturedSupport::from_owned_native_capture`
validates the entire native catalog/support set, and the private same-frame
support witness is retained in the checked capture. Every relation row matches
exact declaration/retained KeyId/row offset. Banks and descriptors are charged
BEFORE copying to the original aggregate reservation. No foreign ArenaValue,
string-only native proof, key-part-zero guess, JSON stringify/tree allocation,
source getter or guest jsonKey/privilege/verified flag is accepted. Descriptor
constructors alone confer nothing; malformed/duplicate/incomplete inputs poison
original admission before any candidate. Actual source-origin/completeness/
absence certificates remain the controller obligation, NOT a new verifier.

Actual get/scan/provider ACL uses `authorize_native` before projection, operators,
aggregate input and limits. The raw host and unchanged SDK provider adapter keep
**ENCODED STRING** keys; SDK decodes once. Native sourceKey columns remain encoded
text. Authority SYSTEM FULL READONLY retains original invoker and is bound to
actual captured registration/execution; its privilege never transfers to Provider.
The exact original PolicyBudget is retained (stable identity + cumulative work)
alongside the one original-job ledger. Sticky NeedCapture, policy-support replay
refusal, cancellation/deadline/work/clock poison cannot be reset by a phase/VM.

`binding.source_revision` is original **capture Rseal**. Separate private
`permission_revision` and issued clock come ONLY from actual opaque NativeTimePoint;
callback comparison uses that actual permission point while finish metadata
`sourceRevision` stays original Rseal. This is native issuance/correlation only,
NOT source/certificate/controller validation and not a guest-provided later number.

Before finalizer, take the latest healthy permission stamp with no active/pending
callback and at least one completed permission callback. The qualified constructor
correlates that exact ledger identity/original job/sequence/actual native point,
then admits exactly the finalizer phase. Encoder requires that opaque permission.
Required `binding.validUntil: number | null` is stamp Until(t) -> exclusive t;
completed evaluated Independent/ClockInvariant -> null. Unknown/absent/pending/
denied/refused proof cannot become null. No callback metadata/deadline/clock+120s
supplies this proof. Finish checks after callback, and the controller MUST recheck
`validate_finish_permission` immediately before publication; same earliest bound
only, no arbitrary refresh/extension/new callback/ledger reset. Readless clock is
metadata only. Guest BusinessFailure stops later providers/finalizer/signing;
native Err remains fatal and is not encoded as a catchable BusinessFailure.

Ledger reset/stale-stamp correlation adds one fixed native AtomicU64 identity
(8-byte global). Its process-global physical baseline/source-controller registration
is NOT proved by component tests and remains part of parent admission HOLD.
Caller-supplied resident descriptor banks, native runtime/stack/C/OS/crypto backing,
boxed anyhow fatal wrappers and actual source certificates remain separate HOLDs.

SDK keeps `{request,result,provenance,binding}` and finalize(ctx,execution,metadata)
THREE arguments. Missing/malformed/nonexclusive required native validUntil fails
constant `SQL_NATIVE_BINDING_INVALID` before app finalizer/signing; no default,
Date/Intl/DOM or fake JWT/source/runtime verification. Cancellation remains
closed `SQL_CANCEL_NATIVE_ONLY`, never a custom signing finalizer.

---

# October 4 root integration: original-job temporal + CLOSED registered authority

This continuation changes ONLY host root/read/authority/test/harness/API files.
No source/controller verifier, evaluator registry, Wasm ABI, SDK/service route,
crypto/process admission, serving activation, commit, push or PR is supplied.
**HOLD remains the serving result**, even when detached native tests pass.
The historical evidence below describes previous revisions, not this run.

## Exact current native construction API

- `HostAdmission::from_admitted(input, output, frame, relations, reservation,
  work, &original_job)` creates **one direct `GlobalTemporalLedger` inside the
  original HostBudget AT aggregate admission**, before any callback. Test-only
  `HostAdmission::new(..., work, &original_job)` has the same original-job input.
  No callback, fresh auth, replay or VM recycle constructs/replaces this ledger.
- `SqlHost::new(phase, admission, frame, relations, binding, support,
  policy_budget, NativeTimePoint, &mut original_job)` requires a CONTROLLER-issued
  point. It validates exact phase/issued clock/source revision against native
  binding; the ledger validates original admitted Instant/deadline/cancellation
  identity and stable native deployment/catalog epochs. A point is never
  reconstructed from guest arguments/binding numbers inside the host.
- `unsafe NativeTimePoint::from_certified_native_point(...)` remains the
  explicitly unsafe attestation seam, **NOT** the missing actual native source/
  deployed-code/catalog certificate verifier. Original job hard cap is 10s or
  the lower operator limit, unchanged; neither deadline is an epoch permission
  expiry and tests cannot refresh that allowance between callback phases.
- Generic `SqlHost::new(Authority, ...)` is sticky Forbidden, including with a
  valid CapturedSupport or native enum. Only
  `SqlHost::new_registered_authority(admission, frame, relations, binding,
  policy_budget, &mut original_job, point, permit, execution)` accepts Authority.
  Both opaque tokens have private scalar/fixed-text fields, never a Records,
  Consensus, Snapshot, provider, cache, closure or key owner.

## Closed Catalog.authority: private SYSTEM READONLY, principal remains invoker

`unsafe ClosedAuthorityPermit::from_certified_native_registration(frame,
actual_captured_catalog_id, point, binding, native_code_hash,
native_certificate_hash, control)` checks native captured Catalog name/version/
exact authority target and bounded shape, and stores only fixed native name/target UTF-8 buffers,
exact original binding/point and fixed native hash witnesses. Its target accepts
native Unicode names through 384 UTF-8 bytes, not a SQL-identifier guess.
`unsafe NativeAuthorityExecution::from_certified_native_execution(point,
actual_target, actual_code_version, actual_catalog_version, actual_code_hash,
actual_certificate_hash)` is the controller's separate actual deployed execution
witness. Constructor compares exact point, entire native binding, target, code/
catalog versions and both hashes. Wrong source, clock, phase, original job,
deployment/catalog, target, code/certificate or principal binding fail closed.
These unsafe constructors check **correlation, not authenticity**: actual source/
controller certificate verification is absent from serving and remains HOLD.
An enum, guest phase, stable/public claim, bool or bare new-with-Authority does
not confer privilege; an arbitrary normal query fallback is never provided.

Registered Authority, like closed InitialAuth/FreshAuth `$flower.authorize`, can
read **FULL bounded captured security metadata** without invoker row/field ACL.
Its `ctx.principal()` and request.invoker are still exactly `binding.invoker`,
even if effective `binding.principal` is attenuated/different. Tenant/history and
issued native clock are unchanged. This is not definer and cannot write or call
arbitrary derived/query/range/SQL/crypto/key APIs. Authority requires no policy
support **only behind this closed permit**. Provider ALWAYS applies actual native
effective-principal collection/row/field/hidden-selection ACL and never inherits
Authority privilege; neither do readless finalizer, operator, SQL or seal.
`prepare_authority_input` additionally requires the permit's exact catalog name
and native TerminalMethod operation. Guest purpose/plan cannot choose either.

## Temporal callback and publication contract

- `clock` in permission phases reads the issued native ledger clock and creates
  a pending proof obligation. A clock-only wire SUCCESS is fatal typed
  `HostError::Temporal(Uncertified)` with NO completed result. `now` is ALWAYS
  fatal in permission phases, even if guest catches/substitutes/recycles/replays.
  Readless clock is issued metadata only, never permission-cache provenance.
- Permission `changesAt` takes exactly ONE borrowed numeric WireValue, exact
  finite future JS-safe whole milliseconds. No parse/stringify/coercion/null
  stability flag. All declarations intersect the original earliest exclusive
  boundary; later phases/fresh auth cannot extend it. Readless now/changesAt/
  get/scan/query/range and every phase's writers/definer/derived/SQL/unknowns
  remain native fatal before decode. Crypto remains raw SQL_CRYPTO_FORBIDDEN.
- Every actual collection/hidden/field/support dependency is registered from
  cumulative actual PolicyBudget::finish BEFORE projection/copy. Actual native
  dependency bookkeeping does NOT certify arbitrary guest clock reads: no
  blanket `with_native_callback_clock_coverage` is called here. Controller may
  register exact actual JWT/lease/native-policy boundaries through
  `SqlHost::register_native_boundary`; managed verification/sign bridge still
  HOLD, never synthesized from public JWT claims or an execution timeout.
- `finish_checked_at(bytes, fresh_native_clock)` decodes/copies complete actual
  wire SUCCESS vs business FAILURE, then finishes temporal accounting BEFORE
  setting completed. Business Failure may deliver an uncacheable denial without
  positive temporal proof; RejectedUncacheable stops all later permission/
  provider/finalizer/result/sign work. Native poisoned Err cannot be turned into
  Failure. `completion()` exposes PermissionEvaluated/MetadataOnly/
  RejectedUncacheable to the controller; it is NOT a full resource/source proof.
- Real EncodedHost.finish uses `finish_checked(bytes)` at the **native issued
  point**, NOT an ambient fresh-time claim. The controller MUST request
  `admission.check_native_clock(&mut original_job, actual_fresh_clock)` before/
  after traversal and obtain `permission_stamp(job, actual_fresh_clock)` before
  seal, then reacquire/revalidate against the same ledger/job after subsequent
  callbacks and at publication using `validate_permission_stamp`. Completed
  output alone is NEVER a publication/cache certificate. A finalizer's unsigned
  clock+120s result-bound metadata does not extend the original authorization
  expiry. Actual signing/controller/publication integration remains HOLD.
- `unsafe acknowledge_native_capture(&mut original_job)` requires actual sticky
  NativeNeedCapture+demand, exact original job, real VM destruction and certified
  completion of that demand (unsafe controller contract, not a guest flag).
  It preserves all ledger/dependency/clock/work accounts and requires replay of
  the same phase. PolicySupport replay still refuses Unsupported rather than
  reset its poisoned policy budget. Dropping an unfinished SqlHost does NOT
  complete/reset the ledger; pending/replay blocks a stamp.

## Current validation scope and remaining HOLD

Typed post-admission Rust allocation observers exclude `anyhow::Error::new`,
Wasmtime trap/trace and C/runtime/kernel owners. A measured 0-Rust result must
NOT be promoted to total-native no-allocation or physical admission. Unsafe
fixture attestations use real raw Wasm/QuickJS execution but do not certify the
actual serving source/controller/deployed code. Managed JWT bridge, source/Rseal
controller, pre-mapping aggregate/runtime/allocator/stack/kernel admission,
signing/publication/cache/HTTP activation remain independent mandatory HOLDs.

The isolated `/workspace/sql-root-harness` copies current root solely to rewrite
module/test paths. Current unowned `native_key_tests.rs` needs parent migration
of old constructor calls to explicit NativeTimePoint and its one historical
Authority-ACL redaction fixture to Provider; external harness performs exactly
that test-only migration and leaves shared unowned source untouched. Production
root/read/authority bodies are the actual current shared source, not mocks.
Raw Wasm tests use actual `execute_sql_authorization`/`execute_prepared_encoded`
and ORIGINAL admitted JobControl/deadline/cancellation, prewarming beforehand.
No native test renews runtime allowance between phases.

## Final root evidence from this continuation

- **95/95 focused compact PASS**,0fail/ignored, including40 actual temporal/
  policy/JWT units,9 Authority units and ALL typed host/provider/temporal Rust
  allocation observers. One unrelated slow frozen entire-manifest inventory
  excluded explicitly (root compact registry96). Final rerun uses completed
  actual crypto-profile production/test module, no profile-test omissions.
- New temporal+closed-authority typed observer separately1/1 PASS: success and
  typed expiry/error0 Rust allocation/reallocation events and0 Layout bytes.
  Anyhow/Wasmtime/C/native physical owners remain excluded/HOLD.
- Strict isolated **clippy --all-targets -- -D warnings PASS**; owned fmt and
  shared diff-check PASS. No whole Flower/npm/HTTP/E2E PASS claimed.
- `wasm_tests.rs` registers **14** actual native tests, including the four
  required temporal recipes and tiny direct numeric Wasm host imports
  8/9/10/11/14/15/unknown. **Execution validation remains HOLD**: earlier external
  native workers stopped; latest refreshed actual manifest/lock/profile build
  timed out at600s while compiling the real library, before any test result.
  No native-Wasm pass is claimed. Parent's raw encoded14 file is untouched.
- Parent must migrate12 unowned native_key_tests constructors to explicit
  native_point before mutable job and its one historical Authority ACL scan
  fixture to Provider. Shared unowned file remains unchanged; external compact
  harness makes only that fixture migration. Complete commands/API/evidence are
  `/workspace/sql-root-harness/INTEGRATION.md` and scoped
  `flower/sql-root-integration.md`.

---

# Detached raw SQL host: exact boundary and integration HOLD

The detached-host foundation was initially new-only. The October4 continuation
owns only `read.rs`, `provider.rs`, `tests.rs`, `wasm_tests.rs`, this API document,
new `native_key_tests.rs` and `actual_acl_matrix.md`; the parent owns the root and
all other staged host/runtime/application work. This child changed no service,
SDK, Cargo, evaluator registry, raw Wasm, crypto, frame, capture, policy or shared
root file. The parent has staged the actual module imports in `evaluator.rs`:

```rust
#[cfg(feature = "sql")]
pub(crate) mod sql_policy;
#[cfg(feature = "sql")]
pub(crate) mod sql_host;
```

The host implements the **actual** `wasm::EncodedHost` trait. It is detached
foundation code, **not activated**, and is NOT a whole-native no-allocation or
physical admission PASS. The fatal `anyhow` wrapper gate below is especially
important; zero-allocation observations cover typed host machinery, not that
wrapper or Wasmtime traps.

## Native-only construction and ownership

- `HostAdmission::from_admitted(input: WireArena, output: WireArena,
  frame: &FrameBuilder, relations: &[OwnedRelation],
  ExternalReservation { total_bytes, borrowed_owner_bytes }, work)` consumes
  **exactly two** already-admitted arena owners. Their reported exact rounded
  allocation sum must be <=32MiB. The combined account is both arena reports +
  source frame's allocation report + native-provided exact borrowed owner
  capacities/layout/page bytes +64KiB finite host/control/stack reserve. The
  initialized slice/name footprint is also checked against the owner's account;
  slice length is NEVER claimed to prove the backing owner's allocation size.
- Production does not have a factory that allocates mappings before combined
  admission. `HostAdmission::new` is **test-only** fixture convenience. Parent
  must supply a real pre-mapping combined reservation/ownership proof; this
  module does not derive native allocator/kernel/runtime admission from mmap
  reports. Source/descriptor owner capacities must be supplied by native capture
  admission, not guessed from borrowed lengths.
- Relations are borrowed `OwnedRelation { name, coverage, rows }`; each
  `OwnedRow { key: KeyId, value: Option<JsonId> }` refers only to the SAME owned
  frame. Descriptor/name owners must themselves be root-free owned capture.
  There is no source trait, provider closure, serving `Records`, `App`, cache,
  `Arc<Value>`, root getter, I/O, key resolver or secret capability in the host.
- `NativeBinding::from_controller(invoker, principal, history,
  authority_context, partition, clock, source_revision, code_version,
  catalog_version)` accepts native frame offsets/owned metadata, NEVER guest
  wire IDs. Fields are private. Clock/revision must be JS-safe unsigned integers;
  version strings have finite caps. This issuance API does NOT prove actual
  freshness/code/history/authentication certification by itself.
- `SqlHost::new(phase, &mut admission, &frame, relations, binding,
  Option<CapturedSupport>, &PolicyBudget, &mut original_job)` creates one
  callback-scoped borrow. No guest phase or principal setter exists. The first
  host stamps the admitted Instant/deadline/cancellation Arc; subsequent phases
  and capture replay MUST use that same job, deadline and atomic owner.
- `CapturedSupport` is the concrete `sql_policy` owned-arena support view, NOT a
  trait's asserted grant or a user boolean. Authority/Provider construction
  without native policy support is refused. The host itself derives
  `VerifiedPrincipal` from its native binding's owned frame value before using
  `PolicyEngine::authorize`, not from guest options.

Caller must select the **closed** `$flower.authorize` target for Initial/FreshAuth
using the actual `execute_sql_authorization` entry; normal callbacks use
`execute_prepared_encoded` with a controller-verified kind/registered target.
Native phase selection, target/binding correlation and source certificates are
still controller gates. Do not accept a client "initial auth"/"system" flag.

## Historical detached-host phase/method matrix (superseded above)

`NativePhase = InitialAuth | FreshAuth | ReadlessPlan | Authority | Provider |
ReadlessFinalizer`.

- ReadlessPlan/ReadlessFinalizer: ONLY no-argument `principal`, `clock`, `history`,
  `codeVersion`. Captured contexts cannot obtain get/scan/query/range/sql/now/
  changesAt, writers or definer through these phases.
- InitialAuth/FreshAuth: those metadata primitives plus fixed captured `now`,
  plain-collection `get`, complete no-options `scan`. Full owned authentication
  metadata is readable only under the closed native auth callback selection.
- Authority/Provider: same bounded read methods, but native policy authorization
  and field filtering run BEFORE any guest/provider copy. Authority uses the
  verified native invoker; Provider uses the native effective principal.
- Nonreadless `query`/`range` are fatal Unsupported, not guessed equality/index/
  cursor semantics. Readless query/range are fatal Forbidden.
- EVERY phase fatally rejects set/delete/materialize/unmaterialize/definer/sql/
  changesAt and unknown operations. Capability denial precedes argument parsing.
  No host denial is encoded as a catchable business FAILURE.
- Crypto is NOT overridden here. Actual raw Wasm crypto remains
  `SQL_CRYPTO_FORBIDDEN`, including pure hashes and managed families.

`get` requires exactly `{kind:"collection",name:string}` and a string key;
extra ref fields, derived/index targets, bare references, raw/internal names and
typed guest JSON keys fail closed. The native key offset is encoded LOGICAL collection-key text, not a
`source:[collection,key]` physical identity. Raw physical/internal key prefixes
fail before capture demand or output; native captures with those prefixes also
fail. Whole string-key get semantics remain supported; actual typed key-part
ACLs are Unsupported, never translated into plain-key equality. The initial
production provider source subset is declared string keys only, as below.

`scan` is a COMPLETE relation only: coverage must be Complete, no options/LIMIT/
offset/index query is accepted, all captured keys must be strictly native UTF-16
ordered, and no prefix can stand in for complete SQL aggregate inputs. Capacity,
work, malformed capture/order or output failure aborts the entire callback.

Hidden rows become null/are omitted only AFTER native ACL. Object fields are
copied only through `RedactedRow::field`; nested copies are fixed-depth and
checked. An authorized ordinary scan/projector input preserves the LOGICAL
source key and returns the field-redacted value. Field redaction does not itself
hide the key: current native `Access::filter` and `scan_rows` prove that exact
contract, including the SDK/HTTP metadata fixture. Selecting/indexing an
unreadable field instead hides the WHOLE row through `authorize(selecting_fields)`.
The prior “any field redaction => Unsupported” branch was unproved and removed;
physical IDs remain forbidden. See `actual_acl_matrix.md` for precise sources,
full frozen application ACL inventory and unresolved actual typed-source gates.

## Capture and cumulative controls

- Coverage distinguishes KeysOnly (unknown key is Uncaptured) from Complete
  (unknown key is authoritative absence). Explicit `value: None` is certified
  absence even for KeysOnly. Missing relations/incomplete scans are NEVER [] or
  null. They issue sticky native NeedCapture.
- `NativeNeedCapture` is a concrete error with no names/keys in Display/Debug.
  The actual raw Wasm test proves it survives the anyhow/Wasmtime cause chain.
  `admission.demand()` exposes borrowed names/keys only to native capture replay;
  the error itself has no private contents. Demand references remain in the
  input arena until native acknowledgement; guest finish/catch cannot erase it.
- `acknowledge_native_capture` is native-only after destroying the old VM and
  completing certified capture. It does NOT refill any arena/host/job work,
  replace the job/atomic or extend the deadline; it also refuses cancellation/
  expiry. PolicySupport replay currently **HOLD**: `sql_policy` deliberately
  poisons its budget on NeedCapture and has no preserve-work replay API. This
  host refuses acknowledgement of that demand rather than reset policy work.
- Host work cap64Mi units, relations64, captured rows20000, provider columns64;
  callers may lower caps. Decoder/encoder arena work, frame access work and
  policy work are each cumulative and NEVER recreated/refilled by callbacks.
  Callback teardown retains only the policy account remaining scalar; a fresh
  larger policy budget cannot renew it in a later native phase.
- Every input-driven readonly WireValue member/entry traversal is explicitly
  debited/checks the original job; no repeated unmetered `member`/`index` loop.
  Text equality/copy accounting checks in<=1024-byte host chunks; bridge checked
  copies/scanner/sorter have their actual bounded polling. ArenaValue's own
  sticky access budget and native policy checks remain in force too.
- `admission.validity()` accumulates concrete policy temporal validity, including
  filtered-out candidates. Parent must carry this into fresh finish/publication.
  It is not an authorization/signature/publication certificate by itself.

## Real callback byte and projection flow

`call_checked` resets the existing arenas without refilling work, uses actual
`decode_arguments_checked` on the **concat stream** (no ARRAY header), then
returns output arena's actual `encode_outcome_checked(Success(..))`. The response
lifetime borrows HOST, never guest bytes. No Value/Vec/String tree, ordinary
wire encoder, allocating JSON serialization or post-copy size fallback runs.

`finish_checked` consumes actual SUCCESS/FAILURE native outcome encoding while
guest memory is suspended and iteratively copies into the fixed output arena.
Guest bytes can immediately disappear/change. `finished`/`finished_value` expose
only a healthy completed native result; errors/partial output are not published.
Guest business failure transport is preserved, but native host failures remain
native Err.

`prepare_provider_input_from_native_catalog(source_declaration_id)` loads the
actual native `Source{name,jsonKey}` from the owned frame, rejects malformed or
unknown properties/internal names, and refuses `jsonKey:true` rather than guess
SDK typed-key decoding. Missing jsonKey has exact native serde default false.
This is not a caller permission/key-mode flag. It produces the current SDK
`{source:{name}, rows:[{key,value}], purpose:nativeAuthorityContext}` only AFTER a
complete native ACL-filtered/redacted scan; its private source-row count is the actual
filtered batch length. Raw plan/caller purpose cannot substitute for context.
Name-only `prepare_provider_input(name)` is test-only, not a production API.

`bind_owned_native_string_row(source_declaration_id, source_pair_id, row)`
validates the owned actual Source, canonical native `[collection,logical_key]`
source-ID suffix, exact retained KeyId correlation and value offset. Its private
`NativeLogicalKey` exists only after validation; canonical native serde string
escaping/array shape is checked with fixed state under the same cumulative work
and original native job. No Value parser/stringifier, callback, resolver or guest
allowed flag runs. The controller must capture that suffix from an actual named
native source and use this constructor for each production row. The helper does
NOT prove native capture origin/current catalog certificate/coverage. Existing
native descriptor visibility remains a controller gate, not a forced opaque-row
issuance scheme. No shared root export or file change was needed.

`validated_provider_rows(native_column_count)` checks the ENTIRE finished batch,
only rows/provenance envelope fields, sourceRow integer range for that exact
filtered input, exact cells length, and native null/single-tag cells. Integer
text accepts canonical signed i64 including MIN/MAX; plus/leading-zero/-0/
overflow/boolean and unknown tags fail. A source can expand to several rows with
the same valid batch-local ordinal. Native sourceField/sourceKey mapping, declared
column-kind/nullability checks and insertion into `FrameBuilder` are parent
integration (frame insertion must succeed wholly before SQLite). This host does
not drop ACL before guest/native aggregation or silently forge physical IDs.

`prepare_finish_input(request_id,result_id,provenance_id)` is finalizer-only and
emits the current single native `SqlFinishInput` containing a freshly controller-
issued binding. The actual SDK adapts it to THREE application arguments:
`finalize(ctx,execution,metadata)`. SourceRevision/codeVersion/catalogVersion/
authorityContext come from private native binding, NOT request purpose. No source
method is added to `SqlFinishContext`.

## Explicit remaining HOLD gates

1. **Fatal raw adapter error allocation:** the actual EncodedHost signature
   returns `anyhow::Result`. Its terminal error wrapper uses `anyhow::Error::new`
   and allocates. Typed call_checked/finish_checked success and refusal machinery
   are zero-allocation; that does NOT make the complete raw runtime/fatal path
   zero-allocation. Parent must preadmit/prebuild a bounded fatal-error owner pool
   (including replay) or revise the transport error ABI, and prove Wasmtime trap/
   trace ownership. Do not activate by claiming the typed allocator tests cover
   this wrapper.
2. Native aggregate PRE-mapping source/frame/descriptor/arena reservation,
   allocator metadata, runtime/compiler/Store/snapshot/native stack/OS physical
   ownership are not proved here. ExternalReservation is a native input, not a
   proof recovered from a guest flag or slice length.
3. PolicySupport capture replay preserving sticky budget/work; native target/
   authentication/certificate/freshness correlation; actual managed verify/sign
   integration; source capture and retention; typed compute/result/publication
   controller and HTTP/service activation remain parent work/HOLD.
4. No general query/index/range/options or typed-key fallback. Supported ordinary
   string-row scans disclose only the native-authorized logical key. Actual typed
   membership/scopes/labels/usage and backend changesAt/support enumeration are
   incompatible until exact native extensions/controller integration are proved. No public
   controller, SDK/service entry, serving-root callback or ordinary ctx.sql
   Records-gate bypass was added.

## Reproduction and observed validation

The independent harness imports CURRENT actual bridge, frame, policy, ordinary
native ACL reference bodies and SQLite engine. It has its own isolated counting
allocator; setup-only fixture JSON/reference encoding is outside observed regions.
`/workspace/sql-host-harness/Cargo.toml` imports `sql_host/harness.rs`, matching
actual lockfile dependencies, jobs2, CARGO_INCREMENTAL=0.

```sh
cd /workspace/sql-host-harness
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo test -- --test-threads=1
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo clippy --all-targets -- -D warnings
rustfmt --edition 2024 --config skip_children=true --check \
  /workspace/flower/src/evaluator/sql_host.rs \
  /workspace/flower/src/evaluator/sql_host/*.rs
```

Observed: **123/123** imported actual-native tests PASS, including **27** host
tests and three isolated allocation observers with0Rust allocations/0Layout bytes for
post-admission typed success/refusal, actual ACL redaction, and provider input/
whole-result validation. The final strict independent clippy-Dwarnings exits0 too. Regressions also
cover policy-support uncaptured/absent distinction, stop-safe native capture
acknowledgement and nonrenewable policy work across phases. These numbers
are NOT allocator-global/Wasmtime/native physical-memory observations.

`sql_host/wasm_tests.rs` is compiled by the host tests when parent adds the two
actual imports. An external-only real crate integration at
`/workspace/sql-host-native-harness` copies the evaluator module declaration
file and external-only lib test-allocator hook needed by the concurrently staged
crypto test module, symlinks actual current source/vendor files and uses real Cargo deps;
no fake EncodedHost/NodeSQL database is substituted. Four real raw-Wasm tests PASS:
closed-auth captured writer cannot be caught; typed NativeNeedCapture survives
anyhow/Wasmtime; raw hash/managed crypto remain forbidden; readless primitive
metadata and recycled VM/host isolation work. Preparation is bounded separately
before fixture admission; invocations use the fixture ORIGINAL job deadline and
cancellation Arc, not a newly refreshed execution deadline.

Whole application/HTTP/E2E/native activation is NOT claimed. Parent should rerun
its shared-checkout import/integration checks; no commit/push/PR was made.

The real whole-library clippy check exits0 with existing and staged foundation
warnings (352 at the observed run); it is NOT strict green. No finished shared
parent build target is removed by this child.

Final real-Wasm rerun after native policy-work-pin/capture-stop hardening:
**4/4 PASS**, no ignored tests, against current shared source/dependencies.

## October4 actual-ACL/logical-key continuation

Frozen actual source revisions, complete222/189 declaration/ACL inventory,
14-table native Source/jsonKey mapping, exact supported/Unsupported operators,
real human/session-agent reproduction requirements and smallest exact remaining
extensions are in **`actual_acl_matrix.md`**. Main144c1a8d and published backendedcb1909
have identical collection ACLs, with100 supported read trees and89 key-part HOLDs.
There are zero `now` references in those frozen read/field-read trees, so temporal
compound refusal was NOT their actual blocker. Current membership uses typed
`members[org,subject]`; real backend also needs `changesAt` and support ranges/
options scans. No actual terminal/request/JWT/controller/launch PASS is claimed.

Current independent commands (own isolated targets, no main target):

```sh
cd /workspace/sql-acl-harness
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/workspace/sql-acl-harness-target cargo test -- --test-threads=1
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/workspace/sql-acl-harness-target cargo clippy --all-targets -- -D warnings
cd /workspace/sql-acl-native-harness
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR=/workspace/sql-acl-native-target \
  cargo test --features sql --lib evaluator::sql_host -- --test-threads=1
```

External harnesses import CURRENT actual policy/frame/bridge/SQLite and real
Wasmtime/QuickJS/native sources. Only module paths/test registration are copied;
production bodies and native authorization reference bodies remain unchanged.
The first shared-source compact harness failed on the unrelated parent-staged
`authority_tests.rs` calling `Option::is_err` on `host.finished()`. The independent
copy excludes only that unowned broken test module, explicitly; no shared source
was edited to make it pass, and this is not a full shared-checkout check result.
The root authority production code is still imported. Parent must fix/re-run its
actual integrated registry.

Initial current host run: **38/38 PASS**, including complete actual189-policy
native differential classification, real account/private-field logical-key
behavior, metadata hidden selecting-field refusal, actual session privacy/roles/
invites/oversight, complete redacted native batch -> sealed SQLite COUNT/SUM,
physical-key refusal and canonical source-pair constructor. Two additional
isolated zero-Rust-heap observers cover actual Source binding/redacted provider
input/refusals and concrete canonical/noncanonical native pair binding.
Full current isolated suite: **136/136 PASS**, zero failed/ignored, plus strict
`cargo clippy --all-targets -- -D warnings` **PASS**. This includes39 host tests,
all imported current frame/policy/bridge/SQLite/control/reference tests, and the
additional actual session ACL hidden-row -> provider -> sealed SQLite COUNT/SUM
regression. Typed measured actual redacted-provider/canonical-key issuance and
refusal paths remain **0Rust allocations/0Layout bytes**. All five owned Rust
files pass rustfmt check. Real current-native Wasmtime runtime rerun is recorded
separately after its isolated build completes.

No commit, push, PR, U checkout change, service activation or source policy waiver
was performed by this delegate. Frozen backend was fetched and archived/read only.

### Completed native transport and ordinary HTTP evidence

- NEW current real Wasmtime/QuickJS privacy regressions: **2/2 PASS**
  (`detached_real_wasm_provider_observes_only_complete_redacted_logical_key_batch`
  and `detached_real_wasm_cannot_catch_or_wire_a_misplaced_physical_source_id`).
  Provider receives the complete native field-redacted logical-key batch; its
  actual guest aggregate observes count2, visible SUM7, hidden-field count0.
  Physical source-ID denial is native/uncatchable and cannot finish a result.
- Actual SDK-generated/stored consensus/native HTTP metadata regressions:
  **8/8 PASS**, including ordinary scan/range logical keys with redacted values,
  hidden indexed selection suppression, SYSTEM read-only method authorization,
  private raw alias denial, spoof refusal, omitted-field preservation/protected
  write denial, process writes and current cache/receipt authorization revocation.
  These directly import current native service/evaluator bodies and embedded
  real SDK bundle; synthetic private session rows model already verified identity.
  They are NOT JWT/provisioned-key/terminal/signing/resource/launch positives.
- The first full-native host command spent17m40s compiling, then its overall20min
  command envelope expired partway through the old raw-crypto Wasm test. Its
  observed earlier typed/constructor/privacy tests and two old Wasm tests passed,
  but **no full-native suite PASS** is claimed for that timed-out command.
  The two new Wasm tests and eight ordinary service tests were separately rerun
  on the warmed native binary and completed with their original test invocation
  JobControl deadlines/cancellation owners, no production deadline increase.
- Direct current shared compact registry retry remains compile BLOCKED in
  unowned `authority_tests.rs`: missing new `TerminalMethod.cancel_result` in
  lines23/100 and `.is_err()` on Option from `host.finished()` at line122. No
  parent test or shared root was changed by this child to hide those errors.
- After adding actual jobs/grants/fences/roles/report support-row cases,
  **40/40 final host tests PASS**, strict isolated clippy-Dwarnings PASS again.
  The preceding complete isolated136-test checkpoint had39 host tests; the one
  added test is covered by this final40-test run, not retroactively part of136.

The subsequent warmed four-old-Wasm rerun was interrupted by the worker stopping
before it finished. No final4/4 rerun PASS or complete39-test native-host PASS is
claimed. The successful2-new-Wasm and8-native-HTTP runs above completed normally.
All full Flower/npm/SDK/e2e/whole-native resource checks remain parent integration,
not tests this delegate silently skipped as green. No own server/job was left
running; own isolated `sql-acl-{harness,native,shared}-target` build directories
were removed after the finished/interrupted commands. Other agents' targets and
all shared caches/source work were left alone.
