# Flower SQL foundation (experimental, disabled by default)

SQL is an **explicit catalog over Flower's current snapshot**, not a second database or an export of every collection. Build the experimental native evaluator with `cargo build --features sql --bin flower`. A default server builds without it. Registering SDK descriptors is not a claim that an older/default binary can execute them: native query/explain/cancel fail with `SQL_UNAVAILABLE` there.

**Launch status: HOLD.** The complete snapshot retention hard gate is not proved; `Records::sql_snapshot_reservation_bytes()` returns None for every root. Native host operations reject this with `SQL_SNAPSHOT_UNBOUNDED` even in a feature-enabled build, before authority/provider execution. There is no public/test bypass. Read `src/consensus/records_sql_snapshot.md` for the root/backing/native allocator evidence. Source foundation in development. Do not enable public aliases until the native/provider/snapshot/cancellation/authority conformance gates and application-specific disclosure tests pass. In particular, bounded SQLite allocations alone do not bound pinned snapshot retention under writes.

## Application contract

```ts
import { collection, define, query, sqlCatalog, sqlTable } from "@flower-js/sdk";
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
  // This runs AFTER collection ACL filtering/redaction. It must add any
  // additional product policy, never restore a hidden source field.
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
const app = define({
  sql: [catalog],
  // Configure real authentication! No SQL principal comes from client args.
  auth: {authenticate: (_ctx, credentials) => {
    // Example only: replace with deployed credential verification.
    throw new Error("Configure an authenticator");
  }},
  http: {
    "sql.query": query("sql.query", {cache: false, watch: false},
      (ctx, input: {sql: string}) => ctx.sql.query(catalog, input).result),
  },
});
```

`sqlTable` requires exactly one `source` or `sources` (1–8 registered collections). Sources are walked lazily in bounded candidate batches. A union supports facts rooted in different collections—for example a scope board plus the organization's no-scope board even when there are zero scopes. It is not an arbitrary privileged provider.

Each projector gets `{source:{name},rows:[{key,value}],purpose}`. Keys are decoded by the SDK for JSON-key collections; `sourceKey` SQL columns intentionally contain the encoded key as text. Projected rows are `{sourceRow,cells}`. `sourceRow` is a validated batch-local ordinal; one candidate may emit many embedded task/goal rows. Native `sourceField`/`sourceKey` mappings fill their cells from that referenced **redacted** row, overriding placeholder cells. All other cells are explicit tagged scalars. No implicit `row_json` exists.

A catalog requires a separate `sqlAuthority` callback returning `{principal,context,tables}` or null. `tables` is an explicit logical-table allowlist, also applied to discovery/relationships. Only its validated `context` reaches provider `purpose`. Authority validation may read application authorization rows with trusted application rights; those rights end before provider execution. Ordinary SQL is rejected for system/definer invocations. Applications must deny raw process contexts unless their deployed authority callback proves a live captured grant/lease and expressly attenuates them; users cannot provide a SQL principal.

Providers run as `sqlProvider`, not as derived callbacks. They retain the effective invoker, same snapshot, dependency collector and cumulative budgets. Writes, definer elevation, derived reads, managed keys, recursive SQL, filesystem/network/entropy are unavailable. Callback scans/ranges need declared indexes and bounded pages (32); equality `ctx.query` is permitted only for a declared scalar index and fails if more than 32 visible rows are required. Use point reads or bounded range pages for policies, never a full collection dump.

`ctx.sql.query(catalog,input,purpose?)` returns **`{result,provenance}`**. Only `.result` belongs in a public human response. Provenance is bounded internal application evidence for independently reauthorized result/logging admission; do not expose physical source identifiers in cells, catalog metadata, plans, errors, or failure logs. The evaluator itself does not mutate a conversation or authorize publication.

Other methods: `ctx.sql.catalog(catalog,purpose?)`, `ctx.sql.explain(catalog,input,purpose?)`, `ctx.sql.cancel(catalog,queryId,purpose?)`. They are ordinary authenticated named application methods, never `$flower.sql` or a universal raw endpoint. Every SQL alias must declare `cache:false, watch:false`; the server bypasses lookup/coalescing/insertion and rejects watch creation before registration.

## Transport and snapshot semantics

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

Rows are arrays, preserving duplicate SQL aliases and exact integer values. Nonfinite reals and blobs are rejected. Missing/redacted/null mapped properties become SQL NULL; unavailable values are not fabricated zeros. Metadata discovery describes logical columns and coverage, never physical collection/provider names. Built-in `sql_tables`, `sql_columns`, `sql_relationships` are metadata-only virtual relations filtered by the same table allowlist.

The trusted service envelope keeps `{revision,value,duplicate:false}` and adds `history:{database,incarnation}|null` to explicitly one-shot reads, from that exact captured snapshot's retention state. Clients keep history optional for an older binary. It is not generated by the application and is not a durable cursor. Separate requests take separate snapshots.

Before delivering native SQL, the service acquires current serving authority, reauthorizes the original request and checks the complete source/policy certificate and temporal validity. A revocation, policy/data/code change or unknown temporal dependency discards the artifact rather than silently rerun or emit a partial aggregate. SQL policy helpers must use `clock()` and declare every known future expiry with `changesAt()`. A polled `now()`/uncertified dependency fails closed. Applications also reauthorize agent completion atomically with exposure/log append; a successful SELECT does not authorize a different audience.

## Dialect and resource boundary

SQLite supplies the real parser and operators. Accepted: one read-only SELECT (including nonrecursive CTEs), joins, grouping, ordering and a default-deny deterministic function subset. Denied: writes/DDL, transaction control, recursive evaluation, pragmas, attach/detach, schema/rowid escape, extension/file/network/random/ambient-time functions. SQLite NULL/no-affinity/BINARY comparison semantics apply. Integer SUM overflow fails; expressions that SQLite represents as real are tagged real, not falsely promised as exact integers.

Only native-mapped **BINARY text equality** and encoded-source-key equality are pushed initially. Native compound indexes may use a proven text equality prefix. SQLite retains the residual predicate (`omit=false`), and no ordering/limit/range is claimed consumed. Unicode string ranges, numeric affinities, NULL/missing behavior and protected fields deliberately fall back rather than change answers. Authorized aggregates never substitute all-source maintained aggregates.

Current hard ceilings (caller may only lower presentation limits): SQL 64 KiB; 256 parameters and 1 MiB parameter allowance; 1–1000 output rows (default 100); 1 MiB encoded response; 2-second cumulative SQL deadline; 10,000 source reads/8 MiB source allocations (including policy reads); 20,000 expanded rows; 256 KiB internal provenance; 64 source cursor states and 2 MiB retained source cursors. Only one query/explain evaluator invocation per method is allowed, so repeated host calls cannot reset work quotas. Source-budget failures are errors, never successful partial COUNT/SUM.

SQLite's header-owner custom allocator charges before allocating/reallocating, including headers, and preserves ownership when freed on another thread/after TLS scope. Its sticky per-query cap is 16 MiB, not SQLite's global heap limit. Initialization has a separate fixed quota and fails closed if SQLite was already initialized elsewhere. The constrained VFS denies filesystem spill and dynamic-library/clock/entropy access. Provider/cursor/output bridge bounds are separate: node admission reserves **16 MiB native + 32 MiB bridge + a conservative 128 MiB snapshot allowance** in addition to shared guest/Rust allowances. Guest stores share one cumulative invocation allowance.

Cancellation uses one shared token through VM progress, scans and callback work. Dropping an admitted request cancels but does not release its worker/snapshot permits before the blocking work exits. An authenticated native registry names queries ephemerally by original+effective principal, validated purpose, partition and query ID; cancel is reauthorized through the catalog and active IDs cannot be reused until the worker exits. A query ID is not a record ID or authority capability. The application must connect live agent lease loss/halt to this cancellation path; completion still revalidates.

## Tests

The existing Node `testDatabase` **does not execute SQL**. It refuses native SQL with `SQL_UNAVAILABLE`; it must never simulate a different SQL parser/executor. Declaration/SDK unit tests cover catalog opt-in, callback kind, mapping/index validation, bounded unions and key decoding. Real evaluator tests and the server-backed `bench/sql-conformance.mjs` exercise the same native engine as the server. The server harness must currently confirm the hard-gate refusal, not falsely claim end-to-end SQL queries pass. Run the native suite with `cargo test -p flower --lib --features sql`, not only `npm test`.

Operational telemetry must never log SQL literals, parameters, results or raw provenance. Native errors are generic codes; hidden-row work counts belong only in privileged coarse telemetry.
