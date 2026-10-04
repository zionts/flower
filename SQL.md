# Flower SQL foundation (experimental, disabled by default)

SQL is an **explicit curated catalog over Flower**, not a second database or an export of every collection. Cargo's `default = []` remains unchanged. Build the experimental native foundation with `cargo build --features sql --bin flower`; an ordinary server build has SQL capability **OFF**.

**Launch status: HOLD. Two boundaries must not be confused:**

- **Legacy `ctx.sql` is permanently on HOLD.** Its original-snapshot retention gate is unproved: `Records::sql_snapshot_reservation_bytes()` returns `None` for every root. The feature-enabled path rejects with `SQL_SNAPSHOT_UNBOUNDED` before authority/provider execution; default builds reject native SQL with `SQL_UNAVAILABLE`. There is no test/public bypass, and the replacement terminal API must never fall back to this path. Read `src/consensus/records_sql_snapshot.md` for the root/backing/native allocator evidence.
- **`sqlMethod` declares the replacement detached terminal contract, but the native terminal lifecycle is not implemented or enabled yet.** The service refuses it with `SQL_TERMINAL_UNAVAILABLE`. SDK declarations/adapters, manifest callback numbers, owned-frame work, and SQLite allocator/operator tests do not establish capture/provider/finish conformance or enable serving.

Do not expose SQL aliases until the complete native storage/capture/frame/resource/callback/cancellation/authority/signing gates and application-specific disclosure tests pass. Bounded SQLite allocations alone do not bound a pinned Records snapshot under writes.

## Explicit opt-in packaging

The Nix flake exposes separate artifacts:

| Selection | Native build | Status |
| --- | --- | --- |
| `packages.<system>.flower` / `default`, `apps.<system>.flower` / `default`, overlay `pkgs.flower` | `--bin flower`, no `sql` feature | SQL capability OFF |
| `packages.<system>.flower-sql`, `apps.<system>.flower-sql`, overlay `pkgs.flower-sql` | `--bin flower --features sql` | Experimental foundation compiled; serving still HOLD |

Both packages participate in flake checks. The server source fileset includes the optional `vendor/redb` seam with `lib.fileset.maybeMissing`, so the storage child's vendored implementation is retained once present without making an intermediate checkout require that path. This packaging is not permission to remove either runtime gate. Source packaging tests do not substitute for Nix evaluation/build; those need a Nix-capable environment.

## Application declarations

This is a declaration example, **not a working server demo**. The authenticator deliberately refuses all credentials until real verification is configured.

```ts
import { collection, define, sqlCatalog, sqlMethod, sqlTable, v } from "@flower-js/sdk";

const notes = collection<{owner: string; text: string}>("notes")
  .index("owner", ["owner"]);
const visibleNotes = sqlTable({
  name: "notes",
  source: notes,
  description: "Notes the current caller may read",
  grain: "One source note",
  columns: [
    {name: "id", type: "text", sourceKey: true},
    {name: "text", type: "text", sourceField: "text"},
  ],
  // Candidates have already passed collection ACL filtering/redaction.
  // Add product policy; never restore a hidden source field.
  project(ctx, batch) {
    return {rows: batch.rows.flatMap((row, sourceRow) =>
      row.value.owner === ctx.principal()?.subject
        ? [{sourceRow, cells: [null, null]}] : [])};
  },
});
const catalog = sqlCatalog({
  name: "notes", version: "1", tables: [visibleNotes],
  authorize(_ctx, request) {
    if (!request.invoker) return null;
    // Real applications must also verify current membership, captured grants,
    // purpose/live call/lease and destination audience where relevant.
    return {principal: request.invoker, context: null, tables: ["notes"]};
  },
});
const queryArgs = v.object({sql: v.string()});
const app = define({
  // Register the exact catalog declaration explicitly; sqlMethod does not do it.
  sql: [catalog],
  auth: {authenticate: (_ctx, _credentials) => {
    throw new Error("Configure deployed credential verification");
  }},
  http: {
    "sql.query": sqlMethod("sql.query", {
      catalog, operation: "query", args: queryArgs, access: "authenticated",
      // Readless: actual verified invoker and validated args, no database ctx.
      plan(_invoker, args) { return {input: args, purpose: null}; },
      // Exactly THREE arguments. Native fresh-finish validation must precede it.
      finalize(_ctx, execution, _metadata) { return execution.result; },
    }),
    "sql.explain": sqlMethod("sql.explain", {
      catalog, operation: "explain", args: queryArgs, access: "authenticated",
    }),
    "sql.catalog": sqlMethod("sql.catalog", {
      catalog, operation: "catalog", access: "authenticated",
    }),
    "sql.cancel": sqlMethod("sql.cancel", {
      catalog, operation: "cancel", args: v.object({queryId: v.string()}),
      access: "authenticated",
    }),
  },
});
```

`sqlMethod(name,spec)` returns a `QueryMethod`, preserves argument schemas and compiled access policy, and forces `cache:false, watch:false`. It accepts only `catalog`, `operation`, `cancelResult`, `args`, `access`, `plan`, `finalize`, and `signingKeys`. These are ordinary authenticated named application aliases, never `$flower.sql` or a universal raw endpoint. Client input does not select arbitrary deployed callbacks. The SDK rejects an HTTP terminal method unless the same catalog declaration is present in `define({sql:[catalog]})`.

`plan(invoker,args)` has **no database context**. It receives the actual verified `Principal | null` and validated method arguments, and returns `SqlTerminalRequest = {input,purpose}`; both properties are required. `input` is `SqlQueryInput`, `{queryId:string}`, or `null`. Without a custom plan, the adapter returns `{input:args ?? null,purpose:null}`. Request purpose is untrusted data: only catalog authority validation can confer rights.

### Readless finalization and signing declarations

The application callback is exactly:

```ts
finalize(ctx, execution, metadata)
```

- `ctx: SqlFinishContext` exposes **only** `principal()`, `clock()`, `history()`, `codeVersion()`, and readonly `binding`. There is no source getter, recursive SQL, write/definer operation, ambient `now()`, or secret handle. The SDK adapter freezes the context using a trusted finish binding rather than binding a database host.
- `execution: SqlOperationResult<O>` is `{result,provenance}` (`SqlExecution`) for `query`. For `explain` and `catalog` it is respectively `SqlExplain` and `SqlCatalogInfo`, not that wrapper. Cancellation never invokes a guest finalizer; native output is a boolean or the exact `{cancelled:boolean}` shape declared below. Human query finalizers return `execution.result` only. Without a custom finalizer, the generated callback returns the public operation result and never query provenance.
- `metadata: SqlFinishMetadata` is the trusted `SqlFinishBinding` plus `request`. The binding contains `invoker`, effective `principal`, `clock`, `history: HistoryIdentity | null`, `codeVersion`, `catalogVersion`, validated `authorityContext`, original-capture `sourceRevision`, REQUIRED exclusive `validUntil: number | null`, and `partition:{name,epoch}|null`. These values must come from native fresh-finish validation, not client args or result fields.

`SqlFinishInput<O>` is internal trusted callback transport `{request,result,provenance,binding}`. The SDK adapts it to the three application arguments. Neither that adapter nor directly unit-testing it proves the native host has produced a valid binding.

Each declaration generates a dedicated `sqlFinalizer` callback named `${name}.$sql.finalize`, even when no custom callback is supplied. Both the query definition and HTTP manifest entry carry matching `SqlTerminalMetadata = {catalog,operation,cancelResult?,finalizer,signingKeys}`. Native callback kind **6** selects the readless `sqlPlan` profile for that terminal query definition; kind **7** selects its dedicated `sqlFinalizer` definition. These are callback kinds, not host-call opcodes.

Optional `signingKeys` contains at most eight declared `ManagedKey` descriptors. Every descriptor must include `sign` usage, and a nonempty list requires a custom finalizer. For example, `key("sql.proof", {algorithm:"HS256",usages:["sign"]})` may be listed in `signingKeys`; `define` adds it to the application key manifest. A declaration is not a loaded key or secret-byte capability. The native finish boundary must admit **only these keys and signing operations**, not general managed-key access. That boundary is a launch requirement, not a claim that finalizer signing currently runs.

## Required detached terminal lifecycle (not implemented yet)

The replacement must admit work quota-first and capture tiny bounded **owned** source/support slices. It must not retain the original Records root, read transaction, physical/logical storage guard, or provider/database capability across application callbacks or SQLite work. Cold/oversized resident reads must be refused before allocation/I/O inside a guard; any prefetch belongs outside those guards without an old transaction/root pin. Revision/epoch changes must invalidate the artifact, not silently weaken consistency.

Sealing must discard raw/support/managed/cache/provider references and leave only authorized typed logical rows for SQLite. Capture, provider reads, expanded rows, bridge buffers, provenance, native allocations and output must all share hard cumulative allowances; repeated slices/callbacks cannot reset them.

After execution, fresh bounded serving state must revalidate original/effective authority, captured grants/leases, source/policy certificates, temporal expiry, code/catalog generation and history. Only then may the readless three-argument finalizer use its bound metadata and admitted signing keys. A change or unknown dependency must discard the artifact instead of returning stale or partial results. A successful SELECT or signature still does not authorize a different audience: agent exposure/log append requires separate atomic current-recipient admission, including implicit forwarding destinations.

Cancellation must use one shared token across capture, VM progress, provider work and finish. Dropping a request or losing an agent lease must cancel it; worker/frame/storage reservations cannot be released while blocking work still owns them. Query IDs remain ephemeral names bound to freshly verified original/effective principal, validated purpose and partition, not authorization capabilities. Cancellation declarations reject every custom `finalize` and every signing key. `cancelResult?: "boolean" | "cancelled"` is accepted **only** on `operation:"cancel"`; the default is the literal boolean, while `cancelResult:"cancelled"` preserves an application API returning exactly `{cancelled:boolean}`. This is a closed native descriptor choice, never caller input or a JavaScript formatter. The controller bypasses the generated private finalizer and performs no SQL operator, source projection, result-proof signing or arbitrary wrapper on cancellation. The SDK's generated cancellation finalizer itself refuses invocation. The native terminal cancellation/finish lifecycle is still unavailable.

## Catalog and provider contract

`sqlTable` requires exactly one `source` or `sources` (1–8 registered collections). A union supports facts rooted in different collections—for example a scope board plus the organization's no-scope board even when there are zero scopes. It is not an arbitrary privileged provider.

Each projector gets `{source:{name},rows:[{key,value}],purpose}`. Keys are decoded by the SDK for JSON-key collections; `sourceKey` SQL columns intentionally contain the encoded key as text. Projected rows are `{sourceRow,cells}`. `sourceRow` is a validated batch-local ordinal; one candidate may emit many embedded task/goal rows. Native `sourceField`/`sourceKey` mappings must fill their cells from that referenced **redacted** row, overriding placeholder cells. All other cells are explicit tagged scalars. No implicit `row_json` exists.

A catalog requires a separate `sqlAuthority` callback receiving `{catalog,operation,invoker,purpose}` and returning `{principal,context,tables}` or null. `operation` comes from the validated deployed terminal descriptor, never a field in the untrusted plan/input/purpose. `tables` is an explicit logical-table allowlist, also applied to discovery/relationships. Only its validated `context` reaches provider `purpose`. Authority validation may read application authorization rows with trusted application rights; those rights end before provider execution. Ordinary SQL is rejected for system/definer invocations. Applications must deny raw process contexts unless their deployed authority callback proves a live captured grant/lease and expressly attenuates them; users cannot provide a SQL principal.

Providers use the dedicated `sqlProvider` callback, not a derived callback. They retain the effective invoker, dependencies and cumulative budgets bound to capture. Writes, definer elevation, derived reads, managed keys, recursive SQL, filesystem/network/entropy are unavailable. The legacy foundation limits callback scans/ranges to declared indexes and bounded pages (32); equality `ctx.query` requires a declared scalar index and fails if more than 32 visible rows are needed. These tested legacy constraints are not evidence of a completed terminal provider runtime. Use point reads or bounded range pages for policies, never a full collection dump.

Policy helpers must use `clock()` and declare every known future expiry with `changesAt()`. `SqlReadContext` retains `now()` in its source type, but polled/uncertified temporal dependencies fail closed. This authority/provider context is not the readless plan/finalizer context.

### Legacy declarations, permanently held

The legacy source surface remains `ctx.sql.query(catalog,input,purpose?)`, `catalog(catalog,purpose?)`, `explain(catalog,input,purpose?)`, and `cancel(catalog,queryId,purpose?)`. Its query type is `{result,provenance}`. These signatures are documented for source compatibility only, **not as a serving recipe or an eventual fallback**. Explicit one-shot/cache/watch flags cannot repair the unbounded original snapshot. New aliases must be terminal declarations, not ordinary `query` callbacks calling `ctx.sql`.

Provenance is bounded internal application evidence for independently reauthorized result/logging admission; do not expose physical source identifiers in human cells, catalog metadata, plans, errors, or failure logs. SQL evaluation itself does not mutate a conversation or authorize publication.

## Transport and receipt semantics

Input: `{sql,parameters?:JsonScalar[],maxRows?:number,queryId?:string}`. Scalars are null, boolean, finite JSON number or string. Use positional bindings, not interpolation. Integer source values beyond JavaScript's safe range must be exact signed-i64 decimal text mapped to an integer column, or tagged projector cells.

Canonical result:

```ts
type SqlCell = null | {integer:string} | {real:number} | {text:string};
type SqlResult = {
  columns: {name:string; logicalType?:string; unit?:string}[];
  rows: SqlCell[][];
  resultTruncated: boolean;
  warnings: string[];
  catalogVersion: string;
};
```

Rows are arrays, preserving duplicate SQL aliases and exact integer values. Nonfinite reals and blobs are rejected. Missing/redacted/null mapped properties become SQL NULL; unavailable values are not fabricated zeros. Metadata discovery describes logical columns and coverage, never physical collection/provider names. Built-in `sql_tables`, `sql_columns`, `sql_relationships` are metadata-only logical relations filtered by the same table allowlist.

The existing trusted one-shot service envelope keeps `{revision,value,duplicate:false}` and adds `history:{database,incarnation}|null` beside `value`, from native retention identity; clients keep history optional for an older binary. Application `value.history` is not a trusted receipt. Terminal completion must bind the actual capture's `sourceRevision` and `history` to its evidence and receipt, never an application-selected or later unrelated revision. This is not a durable cursor, and separate requests do not share a capture. No successful terminal receipt is currently available while serving is held.

## SQLite foundation and resource evidence

SQLite supplies the real parser and operators. The foundation accepts one read-only SELECT (including nonrecursive CTEs), joins, grouping, ordering and a default-deny deterministic function subset. It denies writes/DDL, transaction control, recursive evaluation, pragmas, attach/detach, schema/rowid escape, extension/file/network/random/ambient-time functions. SQLite NULL/no-affinity/BINARY comparison semantics apply. Integer SUM overflow fails; expressions SQLite represents as real are tagged real, not falsely promised as exact integers.

The legacy candidate virtual-table implementation pushes only native-mapped **BINARY text equality** and encoded-source-key equality initially. Native compound indexes may use a proven text equality prefix. SQLite retains the residual predicate (`omit=false`), and no ordering/limit/range is claimed consumed. Unicode string ranges, numeric affinities, NULL/missing behavior and protected fields deliberately fall back rather than change answers. Authorized aggregates never substitute all-source maintained aggregates. None of this permits SQLite to reenter Records in the replacement sealed-frame lifecycle.

Existing foundation ceilings (caller may only lower presentation limits): SQL 64 KiB; 256 parameters and 1 MiB parameter allowance; 1–1000 output rows (default 100); 1 MiB encoded response; 2-second cumulative SQL deadline; 10,000 source reads/8 MiB source allocations (including policy reads); 20,000 expanded rows; 256 KiB internal provenance; 64 source cursor states and 2 MiB retained source cursors. The legacy host permits only one query/explain invocation per method, so repeated host calls cannot reset work quotas. Source-budget failures are errors, never successful partial COUNT/SUM. The replacement terminal runtime uses one **total admitted-job deadline** of `min(FLOWER_EVALUATION_TIMEOUT_MS, 10 seconds)`, starting **before its first fence/capture** and continuing through encoding, code preparation, raw authentication/provider callbacks, SQLite, fresh finish validation, readless signing and native publication. Slices, retries, replay and callback resets never renew it. SQLite has an additional **2-second / 100,000-work-unit** sub-budget clipped to the original remaining total. An earlier actual grant/lease/policy/JWT expiry wins independently. Queue/admission wait is separately bounded. Every parser/copy/crypto stage must use the same cancellation and monotonic deadline; no source root or unbounded compilation may be hidden outside admission. These declared controls remain integration work, not a claim that the terminal serving gate is open.

SQLite's header-owner custom allocator charges before allocating/reallocating, including headers, and preserves ownership when freed on another thread/after TLS scope. Its sticky per-query cap is 16 MiB, not SQLite's global heap limit. Initialization has a separate fixed quota and fails closed if SQLite was already initialized elsewhere. The constrained VFS denies filesystem spill and dynamic-library/clock/entropy access. Provider/cursor/output bounds are separate: existing node admission reserves **16 MiB native + 32 MiB bridge + a conservative 128 MiB snapshot/frame allowance** in addition to shared guest/Rust allowances. A nominal allowance is not proof that retained roots are bounded. Guest stores share one cumulative invocation allowance.

## Checks and honest evidence

The Node `testDatabase` **does not execute SQL**. It refuses native SQL with `SQL_UNAVAILABLE` and must never simulate a different SQL parser/executor or expose a terminal plan as the result. SDK unit tests cover explicit catalog registration, callback/terminal metadata, schemas/access, readless three-argument adaptation, signing declarations, mapping/index validation, bounded unions and key decoding.

Native evaluator tests and the server-backed `bench/sql-conformance.mjs` exercise the foundation rather than a mock parser. The server harness must currently confirm hard-gate refusal, not claim positive end-to-end terminal/provider conformance. Run native foundation tests with `cargo test -p flower --lib --features sql`, not only `npm test`; allocator/operator unit success is not launch success. API coverage, docs rendering/type examples and source-only packaging checks likewise do not prove Nix evaluation/build or native serving.

Operational telemetry must never log SQL literals, parameters, results or raw provenance. Native errors are generic codes; hidden-row work counts belong only in privileged coarse telemetry.

## Native mutation commit-time fence (separate from SQL serving)

`MutationContext.requireCommitBefore(absoluteMs)` (Rust `Ctx::require_commit_before`;
host opcode 17) narrows an ordinary trusted mutation's authorization deadline.
It is present in default builds too: turning off query execution must not disable
checks on a previously issued artifact. This does **not** enable the held native
SQL query/capture/signing route or prove its resource/migration gates.

The application must verify actual signed proof, current authority and source
policy before declaring the earliest safe-integer absolute expiry. It must bind
**both** worker-result/early-held persistence and the later tool completion/log
append. For a live worker result, use the minimum of proof expiry, the current
worker-holding lease, actual grant/oversight/policy/JWT changes and applicable
original protocol deadlines. A guessed job deadline cannot replace an earlier
permission expiry. A later legitimate completion of an already-completed job
must not be refused merely because its historical, no-longer-live lease expired.
Required guard absence is a static refusal before effects, never a legacy shim.
Read-only policy wrappers may forward certified future changes to their trusted
mutation owner; they must not publish the mutation capability to SQL callbacks.

The native deadline is sticky/min-only and independent of read certification.
Known native access and authorization expiries narrow it; unknown required
witnesses refuse. A guarded authorization refresh cannot discard a tighter
same-principal validity. An expired/refused prepared artifact is not retried at
an old speculative wave clock. Serial and compact batches keep the guard; an
expired final batch discards its whole private overlay and invalidates successors
before rows, clocks, results, request receipts or sensitive Raft payloads persist.
A fresh application transaction emits exactly one static refusal, without the
rejected result, proof or error body.

**Exact temporal contract:** native freshness is checked after the writer's
commit barrier and again inside the exclusively ordered Raft core, after all
queuing, metadata and exact envelope-size validation, immediately before log-ID
assignment/append. A private no-root scalar basis was paired with the actual
initial snapshot selection and preserved through private overlays; it checks
native store/scope identity, installation/history, current expected revision,
original leader and the complete applied prior ordered prefix. The shared
service clock is sampled last, under the same publication guard. Replicas check
the logged native leader/time/position witness, not replica-local wall clocks.

A proposal authorized while valid may finish replication/fsync/application or
return its acknowledgement **after** expiry. This is not a physical durability
by-deadline promise. Later reads/consumption independently recheck current rights
and deny revoked/expired permission. Commit timeout/lost acknowledgement means
unknown outcome; replay preserves an earlier authorized receipt, not an invented
abort or renewed artifact. Nothing silently moves the admission point back to
earlier computation to evade a delayed pre-proposal expiry.

The native regressions retain the six original ordinary-mutation controls and
use the same real consensus/redb/QuickJS fixtures for guarded serial now/clock,
timed authorization, speculative and two-request inline compact expiry cases.
They cross a real 1.5-second expiry without editing its row, revision or stored
clock, and inspect the actual Raft log. Additional ordered-core queue,
post-valid-decision real storage delay, restart/replay and current native read
checks exercise the stated boundary. Node TestDatabase tests only model trusted
declarations; they are not native commit proof or a SQL-serving positive.

<!-- Native finish metadata safety contract -->

### Native finish permission expiry

`finalize(ctx, execution, metadata)` remains a three-argument, readless callback.
The native `{request,result,provenance,binding}` input requires
`binding.validUntil: number | null`, exposed as `metadata.validUntil`. A number
is the actual exclusive earliest permission expiry from the original job’s
healthy cumulative temporal ledger, rechecked before finalizer and publication.
`null` means a completed evaluated permission is native Independent or
ClockInvariant; missing, unknown, pending, denied or refused proof is never null.
The SDK refuses missing/malformed/expired bounds before application finalizer
code. It invents no default and does not verify JWT, source or runtime proofs.
`metadata.sourceRevision` is the original captured `Rseal`, even when fresh
permission validation uses a later revision. Neither a job deadline nor
`clock + 120000` is a permission proof or a substitute for `validUntil`.
Cancellation keeps closed native formatting (`SQL_CANCEL_NATIVE_ONLY`).
