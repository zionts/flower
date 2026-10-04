# Guest ABI v1

Application code runs as a WebAssembly *guest*. A JavaScript bundle is one kind
of guest: the pinned `quickjs.wasm` implements this ABI by running the bundle.
A Rust module built with the [`flower-sdk`](crates/flower-sdk) crate implements it
directly; [`examples/goblin-pizza-rs`](examples/goblin-pizza-rs) ports the benchmark
application that way. Rust owns everything else: the reactive graph, indexes, scans,
caching, dependency certificates, storage and replication. A guest only runs
one named callback per invocation and talks to the host through the imports
below.

Every call starts from a pristine image: the module's memory and mutable
globals as they were after initialization. Nothing a callback does survives
into another callback.

## Values

Values cross the boundary in a binary encoding designed to be cheap on both
sides: one tag byte, then little-endian fixed-width fields. Nothing is
variable-length except string bytes and container contents, so decoding never
loops over a length prefix. There is no JSON text at the boundary.

| Tag | Value | Payload |
| --- | --- | --- |
| `0x00` | null | none |
| `0x01` | false | none |
| `0x02` | true | none |
| `0x03` | integer | `i32` |
| `0x04` | number | `f64`, finite |
| `0x05` | string | `u32` byte count, UTF-8 |
| `0x06` | string | `u32` count, Latin-1 bytes (code points U+0000–U+00FF) |
| `0x07` | string | `u32` count, UTF-16 code units, well-formed |
| `0x08` | array | `u32` count, then that many values |
| `0x09` | map | `u32` count, then that many key/value pairs |
| `0x0a` | key reference | `u32` index (map keys only) |

- **Strings** travel in whichever representation the sender already holds.
  QuickJS copies its 8-bit and 16-bit strings verbatim; the host sends ASCII
  strings as Latin-1 and others as UTF-8. Lone surrogates are rejected.
- **Numbers** are JavaScript numbers. Senders may use either tag for integral
  values. The host keeps integral numbers below 2⁶⁴ (and above −2⁶³) as
  integers, exactly where parsing JavaScript's rendering of them would, and
  maps `-0` to `0`. NaN and infinities are rejected.
- **Map keys** are strings or key references. Each message numbers the key
  strings it contains in order of appearance, starting at zero; `0x0a n`
  repeats key `n`. A message may repeat a key string instead of referring to
  it. Keys are unique within a map. The host writes keys in JavaScript's
  canonical order (UTF-16 code units), which fixes their enumeration order.
- **Depth**: the root is at depth 1 and no value is deeper than 128.

## Module requirements

- A core WebAssembly module with exactly one memory, exported as `memory`:
  32-bit, not shared, not imported.
- Imports only the two functions below, from module `flower`.
- No start function. Features: MVP, SIMD, sign extension, saturating float
  conversion, multi-value and bulk memory. At most one private funcref table,
  which the module never mutates. Globals are numeric.
- Mutable globals need not be exported; the host exports them itself to reset
  them.

## Exports

```text
flower_alloc(size: i32) -> i32
flower_invoke(kind: i32, name_ptr: i32, name_len: i32, args_ptr: i32, args_len: i32) -> i64
flower_manifest() -> i64
flower_init() -> i32                        ; optional
```

- **`flower_alloc`** returns guest memory the host writes into: invocation
  inputs and host-call responses. It traps on exhaustion.
- **`flower_invoke`** runs one callback. `kind` is `0` query, `1` mutation,
  `2` transaction, `3` derived, `4` dedicated SQL authority validation,
  `5` dedicated invoker SQL provider, **`6` readless `sqlPlan`**, or
  **`7` readless `sqlFinalizer`**. Kind 6 invokes the terminal's existing query
  definition using a dedicated readless profile; `sqlPlan` is not a new
  serialized definition kind. Kind 7 invokes a dedicated `sqlFinalizer`
  definition. These SQL callback profiles are experimental internal entrypoints,
  not ordinary HTTP callback kinds or host-call operation numbers. Their native
  terminal lifecycle is not implemented/enabled yet. `name` is UTF-8 and `args`
  one value. It returns `ptr | len << 32` of an *outcome* that stays valid until
  the next reset.
- **`flower_manifest`** returns the module's manifest as a value (see below).
  The host calls it once per module, without host capabilities.
- **`flower_init`**, when present, runs once while the host prepares the
  module. The resulting memory and globals become the pristine image. It
  returns `0` on success.

An outcome is one status byte followed by a value:

- `0x00`: success; the value is the callback's result.
- `0x01`: failure; the value is a map with string `code` and `message` and an
  optional `details` value, itself a root value. Derived callbacks never carry
  `details`.

A malformed outcome is the callback's `INVALID_VALUE` failure.

## Imports

```text
flower.host_call(op: i32, payload_ptr: i32, payload_len: i32) -> i64
flower.crypto_call(op: i32, parameter: i32, spans_ptr: i32, span_count: i32, result_ptr: i32) -> i32
```

`host_call` takes the operation's arguments as consecutive root values and
returns `ptr | len << 32` of an outcome that the host allocated with
`flower_alloc`. The guest owns that buffer. A failure outcome carries a
business error the callback may catch, including `INVALID_VALUE` for
malformed arguments; unknown operations and resource failures trap instead.

| op | Name | Arguments | Result | Allowed in |
| --- | --- | --- | --- | --- |
| 1 | now | none | milliseconds | all |
| 2 | principal | none | principal or null | methods |
| 3 | history | none | `{database, incarnation}` or null | methods |
| 4 | get | target, key or args | record, derived value or null | all |
| 5 | scan | collection, options? | `[{key, value}]` | all |
| 6 | range | range | `{rows: [{key, value}], cursor}` | all |
| 7 | query | query | `[value]` | all |
| 8 | set | collection, key, value, options? | null | mutations |
| 9 | delete | collection, key | null | mutations |
| 10 | materialize | derived, args | null | mutations |
| 11 | unmaterialize | derived, args | null | mutations |
| 12 | clock | none | milliseconds | all |
| 13 | changesAt | milliseconds or null | null | all |
| 14 | definer | true or false | null | mutations |
| 15 | sql | operation, catalog name, input, purpose | typed result | legacy one-shot query only; permanently HOLD, not the terminal route |
| 16 | codeVersion | none | trusted code/schema SHA-256 or null | queries and mutations |
| 17 | requireCommitBefore | absolute safe-integer milliseconds | null | ordinary mutations only; attenuation, never a read/definer grant |

`requireCommitBefore` is an **ordinary mutation-only attenuation**, available
independently of the optional SQL artifact feature. Its single argument must be
an absolute, nonnegative safe-integer millisecond deadline. Repeated declarations
only narrow it. The trusted deployed application must first verify the signed
artifact, live lease and current policies; caller purpose/arguments cannot grant
or renew a capability through this operation. Queries, transaction planners,
SQL authority/provider/plan/finalizer callbacks and derived code cannot use it.
A missing host primitive has no compatibility fallback.

The native fence survives optional certificate loss, serial conversion and
atomic compaction. Known temporal policy/authorization flips narrow it; unknown
required authority refuses. Native candidate validation and the final ordered
Raft-core decision sample the real shared service clock. Original native scope,
installation/history/revision and leadership provenance plus the entire prior
ordered prefix must hold at that decision, before any sensitive log entry exists.
Replicas replay a scalar term/time/position witness deterministically, without
consulting their own clocks. This authorizes **ordered proposal**, not completion
of later quorum replication or fsync before expiry. A timeout remains an unknown
outcome, not an abort; already-authorized in-flight bytes are not clawed back.

The ordinary-profile labels "all"/"methods" do not grant source operations to
terminal callback kinds 6/7. Their readless contracts are described below;
finalizer getters use trusted finish metadata, not a Records host. The native
terminal lifecycle/capability boundary is still HOLD, not an enabled interpreter
for these profiles.

`definer(true)` and `definer(false)` bracket code that acts with the
application's rights, such as triggers: collection access policies and derived
access rules don't apply between them. They nest, and an unmatched
`definer(false)` fails with `INVALID_VALUE`. A mutation that returns with more
`definer(true)` than `definer(false)` calls fails with `DEFINER_UNBALANCED`,
and nothing it wrote commits. JavaScript bundles don't see this operation on
any context: the runner passes mutation and transaction computes a third
argument, `elevate(on)`, that calls it (the SDK keeps it to itself), and
queries and derived values get none.

A `target` is a collection name, `{"kind": "collection", "name": string}` or
`{"kind": "derived", "name": string}`. Scan options, range and query shapes are
described in [INDEXES.md](INDEXES.md). Transactions plan only: every host call
fails there.

`crypto_call` passes byte spans (`{u32 ptr, u32 len}` records) and writes a
`{u32 kind, u32 ptr, u32 length_or_integer}` result; the QuickJS guest's
[README](vendor/quickjs-ng/README.md#private-abi) describes the result kinds.
Entropy (opcode 0) is available only to mutations.

## Manifest

```json
{
  "definitions": {"name": {"kind": "derived|query|mutation|transaction|sqlAuthority|sqlProvider|sqlFinalizer",
                           "consistency": "replica-local", "receipt": false, "cache": false, "watch": false,
                           "terminal": {"catalog": "…", "operation": "query|explain|catalog|cancel",
                                        "finalizer": "….$sql.finalize", "signingKeys": [{…}]},
                           "aggregate": {…}, "access": {…}}},
  "http": {"alias": {"name": "definition", "kind": "query|mutation|transaction",
                     "consistency": "replica-local", "receipt": false, "cache": false, "watch": false,
                     "terminal": {"catalog": "…", "operation": "query|explain|catalog|cancel",
                                  "finalizer": "….$sql.finalize", "signingKeys": [{…}]}}},
  "maintenance": {"name": "…", "kind": "mutation", "onError": {…}} ,
  "authorize": {"name": "…", "result": "decision"},
  "collections": [{"name": "…", "indexes": {"index": ["field", …]}, "access": {…},
                   "references": [{"target": "…", "fields": ["field", …] | "key": true | 1-64,
                                   "json": true}]}],
  "keys": [{"kind": "key", "name": "…", "algorithm": "…", "usages": ["…"]}]
}
```

Optional members may be absent. The authorization hook is a query that
receives `{credentials, method, args, partition, delegation}` and returns the
principal; with `"result": "decision"` it returns `{principal, readArgs}`
instead, `readArgs` saying what deciding read of `args`: nothing (`false`),
the top-level fields it names (an array of their names, whose whole values it
may have read), or anything else (`true`). The host reuses a decision for
later calls with the same credentials, method, partition and delegation whose
`args` (an object, when fields are named) agree on those fields, present or
absent, while every record it read is unchanged and its time (`changesAt`, as
for queries) has not come. A decision that read all of `args` (`true`, as
for arguments that are not an object, such as none), and a principal from a
hook without `"result": "decision"`, holds the same way for calls whose
`args` are the same as well (at most 16 KiB of JSON; absent `args` are
`null`), as a query's result does; one that polled `now`
or read untracked state is not reused. The host
validates the manifest: HTTP aliases,
maintenance and authorization must name definitions of the right kind, an
alias's `consistency`/`cache`/`watch` (queries) and `receipt` (mutations) must match its
definition's, and
names starting with `$flower.` are reserved for SDK-generated definitions.
A collection's optional `access` holds its policy: `read`, `insert`, `update`
and `delete` rules plus per-field `read`/`write` rules, each a JSON rule tree
(`const`, `all`, `any`, `not`, `eq`, `ne`, `in`, `exists`, `lt`, `lte`, `gt`,
`gte`, `startsWith` over `{"ref": path}` and `{"value": json}` operands; paths
start with `principal`, `row`, `next` or `key`, or are exactly `["now"]`). The
host enforces it on the collection operations of queries and mutations that
have a caller; see `src/evaluator/rust_engine/access.rs`. The host `set`
operation takes an optional fourth argument `{"clear": [field, …]}`: hidden
fields the value leaves out are removed instead of kept (the SDK sends it only
when `ctx.set(…, {clear})` lists fields). A derived definition's optional
`access` is one such rule over `principal`, `args` (the arguments it is read
with) and `now`: a method with a caller may `get` the value only where it
holds, and otherwise fails with `ACCESS_DENIED`.
A collection's optional `references` are foreign keys to its `target`
collection: a row holds a target row's key in `fields` (their values, in
order), in its whole key (`"key": true`), or in the first `key` components
of its tuple key. With `json` the target's keys are canonical JSON, a single
part being the key and several a tuple; otherwise a single part, a string, is
the key. A missing or null part refers to nothing. At the end of every
mutation, after its triggers, the host fails it with `FOREIGN_KEY_VIOLATION`
if a source row it wrote refers to a row that does not exist or a row it
deleted is still referred to, whatever the access rules; a deployment checks
the rows already there for the references it adds. The host enforces
references only: deleting or clearing referring rows (`onDelete`) is the
SDK's, as a trigger. A reference held in fields gets an index of them, as if
declared. See `src/evaluator/rust_engine/references.rs`.

## Resource limits

Each invocation shares one budget with its nested callbacks: a deadline, linear
memory, nesting depth and native stack. Epoch interruption stops runaway loops.
Invocation arguments, outcomes and host-call payloads are each bounded by
`FLOWER_RESULT_MAX_BYTES`. An invocation that traps, exhausts a budget or grows
its memory is discarded; none of its effects commit.

## The QuickJS guest

`quickjs.wasm` additionally exports setup functions that only the host's image
builder calls before snapshotting: `flower_eval`, `flower_compile`,
`flower_load`, `flower_free` and `flower_snapshot_prepare`. Bundles that do not
opt into static initialization run from a shared base image and load their
bytecode with `flower_load` before `flower_invoke`.

Encoding JavaScript values reads QuickJS's own object shapes, arrays and
string buffers, so it never runs application code: no getter, proxy trap or
`toJSON` hook. Values must be plain data: `null`, booleans, finite numbers,
strings, arrays without holes or named properties, and objects whose prototype
is `Object.prototype` or `null` with only enumerable string-keyed data
properties. Shared references are copied; cycles are rejected. A callback that
returns anything else fails with `INVALID_VALUE`, and passing it to the
database throws a catchable error with that code.


## Experimental SQL catalog and terminal extension (HOLD)

Optional top-level `sql` is an array of at most eight explicit catalogs. A catalog
has `{name,version,authority,tables,relationships}`; a table has
`{name,sources:[{name,jsonKey?}],columns,indexes?,provider,description?,grain?,coverage?}`.
Columns are the explicit scalar descriptors of `sdk/sql.ts`; mappings are native
`sourceField`/`sourceKey`, never inferred fields. Authority/provider references
must target the dedicated callback kinds, and every source/index must be deployed
in collections. Catalog/code/policies cut over as one schema. No collection is
implicitly SQL-readable. Removing this metadata is not permission to downgrade
replicas below the manifest/schema version they can read.

### Terminal manifest and dedicated callback profiles

The SDK's `sqlMethod` emits matching optional `terminal` metadata on its **query**
definition and public HTTP alias:

```json
{
  "catalog": "notes",
  "operation": "query",
  "finalizer": "sql.query.$sql.finalize",
  "signingKeys": []
}
```

`operation` is exactly `query`, `explain`, `catalog`, or `cancel`. A terminal must
be a fresh linearizable one-shot query with explicit `cache:false,watch:false`,
not a replica-local/mutation/transaction method. Its catalog must be explicitly
registered in top-level `sql`; the SDK requires the exact catalog declaration in
`define({sql:[catalog]})`. Its `finalizer` must reference a dedicated
`sqlFinalizer` definition; the SDK generates `${methodName}.$sql.finalize` even
without a custom application finalizer. The callback is internal, never an HTTP
alias. `signingKeys` contains at most eight full managed-key descriptors matching
entries in top-level `keys`, each with `sign` usage. The SDK merges these key
declarations into that manifest and requires a custom finalizer for a nonempty
list. Descriptor presence is not loaded-key authority.

Invocation kind **6 (`sqlPlan`)** uses the terminal's query definition, not a new
manifest definition kind. The application `plan(invoker,args)` receives only the
actual verified principal (or null) and schema-validated method arguments. It
returns `{input,purpose}` with both members present; input is `SqlQueryInput`,
`{queryId}`, or null. The default plan returns `{input:args ?? null,purpose:null}`.
There is no source/SQL/write/definer/managed-key capability in this readless
profile. Purpose remains untrusted until catalog authority validates it.

Invocation kind **7 (`sqlFinalizer`)** receives trusted callback transport:

```text
{request, result, provenance, binding}
binding = {invoker, principal, clock, history, codeVersion, catalogVersion,
           authorityContext, sourceRevision, partition}
partition = {name, epoch} | null
history = {database, incarnation} | null
```

The SDK adapts this to **exactly `finalize(ctx,execution,metadata)`**, three
arguments. For a query, execution is `{result,provenance}`; otherwise it is the
public explain/catalog/boolean result. Metadata contains all binding members plus
`request`. The frozen readless context has only `principal()`, `clock()`,
`history()`, `codeVersion()` and readonly `binding`, supplied from that trusted
transport, not a database host. No source getter, SQL, writes, definer elevation,
ambient `now()` or secret handle exists. With no custom finalizer the public
result alone is returned, never query provenance.

The native terminal lifecycle is **not implemented or enabled yet**. The current
service rejects terminal requests with `SQL_TERMINAL_UNAVAILABLE`; callback
numbers, manifest declarations and SDK adapters are not evidence of serving.
Before enabling it, native code must enforce quota-first detached owned capture,
drop original Records/storage pins before callbacks/SQLite, seal only authorized
typed logical rows, and freshly validate authority/source/expiry/code/history
before supplying this finish binding. Finalizer managed signing must be limited
to `signingKeys` and signing operations; general managed-key access is not part
of its profile. SourceRevision/history must bind the actual capture, never
client args or application result fields. Agent exposure/log append still needs
independent atomic current-recipient authorization.

### Legacy host operations, permanently held

Operation **15** is the legacy `ctx.sql` route, **permanently on HOLD**. It takes
`[operation,catalogName,input,purpose]`, where operation is
query/catalog/explain/cancel. Query/explain input is the `SqlQueryInput` of
`sdk/sql.ts`; cancel input is `{queryId}`. No principal argument exists. Its
one-shot aliases require `cache:false,watch:false`; those flags bypass cache
lookup/coalescing/insertion and deny watch registration, but cannot bound an
original retained snapshot. This is not the terminal execution route, and a
terminal declaration must never fall back to it.

Legacy query's internal type is `{result,provenance}`; only result is public
human data. Provider rows bind to batch-local source ordinals and native
ACL-redacted mapped columns. Policy reads join dependency certificates. Providers
cannot write, elevate, read derived values, access managed keys or recursively
invoke SQL. Authority's pure validation read rights never become provider rights.
These foundation constraints do not prove a completed terminal provider runtime.

Operation **16** observes bundle/schema and returns the native SHA-256 of their
canonical binding, or null without a deployment. It is available to queries and
mutations for current-generation proof comparison, not user-selected generation.
Terminal finalizer codeVersion is instead supplied in the trusted finish binding.

Cargo default features remain `[]`; native SQLite is compiled only with feature
`sql`. The Nix `flower-sql` artifact explicitly selects it; default `flower` does
not. Compilation never opens the runtime gates. **Legacy serving-snapshot
retention is not proved:** `Records::sql_snapshot_reservation_bytes()` returns
`None` for all roots. Operation-15 calls fail before callbacks with
`SQL_SNAPSHOT_UNBOUNDED` in that build (`SQL_UNAVAILABLE` without it). No test/public
bypass exists. Read `SQL.md` and `src/consensus/records_sql_snapshot.md`; standalone
SQLite tests do not establish provider-policy/end-to-end launch evidence.
