# Owned SQL frame — final integration contract and measured evidence

Only parent import required in `evaluator.rs`:

```rust
#[cfg(feature = "sql")]
pub(crate) mod sql_frame;
```

The module contains no serving `Records`, `Arc<Value>`, owned `serde_json::Value`, provider/source callbacks, managed-key handles, or database getters. Caller ACL/source selection must happen **before typed insertion**. Caller-owned serving/guest/callback state must be destroyed before SQLite compute. Ordinary `ctx.sql` remains permanent Records HARD HOLD. These are owned-frame tests, not a Records-gate bypass or a terminal-driver launch claim.

## Exact API

```rust
FrameControl::new(cancelled: &AtomicBool, deadline: Instant) -> FrameControl<'_>

FrameBuilder::new(FrameLimits::default(), &control) -> Result<FrameBuilder, FrameError>
reserve_json(JsonBank::{Raw, Support}, byte_len: usize) -> Result<JsonId, FrameError>
append_json_chunk(JsonId, &[u8]) -> Result<(), FrameError> // each <=64KiB
finish_json(JsonId, &control) -> Result<(), FrameError>
raw_json(JsonId) -> Result<&str, FrameError>
json(JsonId, &control) -> Result<ArenaValue<'_>, FrameError>
retain_key(&str) -> Result<KeyId, FrameError>
key(KeyId) -> Result<&str, FrameError>
append_provenance(&[u8]) -> Result<(), FrameError> // trusted/internal, bounded
add_table(name: &str, columns: &[FrameColumn<'_>]) -> Result<TableId, FrameError>
insert_row(TableId, &[FrameCell<'_>], &control) -> Result<(), FrameError>
insert_source_row(TableId, JsonId, &[SourceColumn<'_>], &control) -> Result<(), FrameError>
insert_tagged_row(TableId, JsonId, &control) -> Result<(), FrameError>
insert_tagged_rows(TableId, JsonId, &control) -> Result<(), FrameError>
seal(self, &control) -> Result<SealedSqlFrame, FrameError>

FrameCell<'a> = Null | Integer(i64) | Real(f64) | Text(&'a str)
SourceColumn<'a> = Field(&'a str) | Key(KeyId)
FrameColumn<'a> {
    name, kind: ColumnKind, nullable,
    logical_type: Option<&'a str>, unit: Option<&'a str>, equality: bool,
}
ColumnKind = Integer | Real | Text
FrameError = Capacity | Invalid | Unsupported | WorkLimit | Cancelled | Deadline
```

`FrameControl` holds only a borrowed atomic cancellation flag and monotonic deadline: no callback, source, Records owner, or key capability. It is borrowed per operation, **never retained by FrameBuilder or SealedSqlFrame**. Only a pre-seal borrowed `ArenaValue` carries a control reference. Use the native job's cancellation flag and deadline, not a newly reset deadline.

`JsonId`/`KeyId` are builder-local opaque offsets; never mix IDs between builders. `TableId::index()` is the native table ordinal. Mutating/capture errors are sticky. Cumulative access-work/cancellation/deadline errors poison the capture arena even if a caller ignores their returned Result. `seal` cannot return an unfinished or partial frame. Reserving a document charges its full declared raw byte range before the first captured byte; append/finish cannot exceed or amend it.

## Arena inspection and CPU/cancellation invariant

`ArenaValue` supports these **fallible, cumulatively charged** accesses:

- `get(&str) -> Result<Option<ArenaValue>, FrameError>`
- `get_path(&[&str]) -> Result<Option<ArenaValue>, FrameError>` (path<=64)
- `at(usize) -> Result<Option<ArenaValue>, FrameError>`
- `as_f64() -> Result<Option<f64>, FrameError>`
- `source_integer() -> Result<Option<i64>, FrameError>`
- `children() -> ArenaIter`, whose Item is `Result<ArenaEntry, FrameError>`

Kind/null/bool/borrowed text/raw-number-lexeme getters are O(1) and do not traverse data. Every input-dependent hash, comparison, probe, iterator step, scalar conversion, and native row projection shares one finite sticky Budget. Public access boundaries check primitive cancellation/deadline. Hash/comparison/scanner work checks/debits in<=1024-byte units. UTF8 validation, pre-touch/default initialization, and typed text copies check in<=64KiB units. There is no caller-only periodic-check waiver.

The audit's repeated-long-mantissa defect is fixed: scanner classifies each number once and stores cached finite f64 plus exact-safe-i64 status. Native projection does not reparse or re-walk the raw mantissa. Numeric tokens have a hard **1024-byte cap**, checked before consuming beyond it or calling Rust core's bounded numeric parser. Canonical text i64 conversion is at most20bytes; invalid larger text fails without traversal. JSON strings can still occupy the bounded8MiB decoded slab.

The syntax scanner uses a fixed explicit depth64 stack, not recursive calls or serde scratch. Strings decode into one preallocated slab; node offsets and a preallocated duplicate-key hash index replace object graphs/maps. It rejects malformed JSON, invalid UTF8/control bytes/escapes, lone surrogates, duplicate decoded keys, and nonfinite numeric overflow. Exact original JSON remains borrowed through `raw_json` for the quota-safe guest ABI; no UTF16/canonical ordering rewrite is attempted.

Native source integer conversion accepts bool0/1, canonical decimal i64 text, or exact integral JSON decimal values within ±(2^53−1). Decimal exactness is classified independently of binary rounding, so `9007199254740990.5` and nonzero underflow `1e-999` are not integers. Tagged guest rows are arrays of null or exactly one `{integer:"..."}` / `{real:number}` / `{text:"..."}` object. Tagged booleans are rejected; text integers preserve signed64 MIN/MAX.

## Quota-first ownership and sealing

Before accepting capture bytes, the builder maps/initializes/pre-touches all raw/support/decoded-text/node/document/parser-index/key/key-byte/table/column/row/cell/row-order/typed-text/provenance slabs. All page-rounded sizes, descriptors/indexes and a64KiB finite control reserve are overflow-checked and admitted before the first mapping. Capture/parser/projection/insertion/seal use no allocator-backed growing Vec/String/BTreeMap/tree. Mapping construction owns the region before initialization so cancellation unmaps partially initialized slabs too. Linux/macOS are implemented; only Linux was actually tested. Unsupported platforms fail closed.

Hard maxima:

- Raw+support capture **combined8MiB**, with independently bounded/preallocated banks.
- Decoded text, typed text, retained-key bytes:8MiB each.
- Nodes262144; documents/keys20000 each; depth64; numeric token1024bytes.
-64 ordinary logical tables plus exactly `sql_tables`, `sql_columns`, `sql_relationships`;64columns/table.
-20000 total typed rows;1280000cells;256KiB trusted provenance.
- Cumulative scanner/access/projection/copy/index work64Mi units; caller may reduce every cap, not raise it.
- Page-rounded mappings plus control <=128MiB.

Measured default Linux4KiB-page allocation: **90,968,064 bytes before capture;29,585,408 bytes sealed**, including control reserve. These are computed mapping/layout sizes, not parsed-tree estimates or RSS. Control structs and explicit stack/small row/token arrays are finite;64KiB is reserved, not dynamically allocated.

`seal(self,&control)` consumes/drops raw/support/parser/retained-key state and actually unmaps all8 witness slabs. Sealed fields are only TypedArena plus a byte count: logical descriptors, typed scalar/text cells, row ranges/order and trusted internal provenance. No raw/capture/key/control getters remain. Linux `mincore` tests verify capture pages were resident before sealing and no longer mapped afterwards.

## Sealed Source and metadata

`SealedSqlFrame: sqlite::Source` lazily copies bounded owned row batches. Two passes admit exact outer Vec, row Vec, text String and ordinal-token capacities against `ScanRequest.max_bytes` **before allocating**. Exact requested allocation Layouts avoid spare/growth capacity. Tokens are canonical table/row ordinals, never source/provider cursors. Equality is conservative residual-only; the native vtable keeps omit=false. No source/policy/provider callback can run from the frame.

Source capacity error maps to native MemoryLimit; the actual native engine discards the whole query, including prior aggregate state. Result-row truncation is separate and never truncates aggregate inputs. Captured but unapproved raw rows/physical key witnesses are not SQL sources: only caller-approved typed insertion creates a row.

Borrowed sealed `table`/`column` views expose logical names/types/nullable/units, no physical field selectors. `native_tables(max_bytes)` produces exact-capacity logical `Vec<VirtualTable>`; caller reserves this separate native descriptor buffer allowance first. Native Vec/String budgets count allocated capacities, matching Source's ABI contract—not allocator-global RSS metadata.

## Measured checks / reproduction

Owned `harness.rs` imports the **current actual SQLite engine**, with a test-only counting allocator in the independent crate. It is not compiled into Flower production/library tests. External `/workspace/sql-frame-harness/Cargo.toml` points to this entry and uses parent-lockfile versions libc0.2.189, SQLite0.38.2, serde1.0.229, serde_json1.0.151.

```sh
cd /workspace/sql-frame-harness
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo test -- --test-threads=1
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 cargo clippy --all-targets -- -D warnings
rustfmt --edition 2024 --config skip_children=true --check \
  /workspace/flower/src/evaluator/sql_frame.rs \
  /workspace/flower/src/evaluator/sql_frame/*.rs
```

**53/53 PASS on current native HEAD8c56e9ed21bbe62b68d280f9fd23d02bd7d29c61**, not the earlier frozen baseline:28frame,7allocator evidence,18native tests (including current preparation scratch/reference bitmap/exact refusal taxonomy). Independent clippy-Dwarnings and owned-file fmt check pass. Constructor/capture/scanner/path+scalar/slow numeric/source projection/insertion/seal and error paths measured0Rust heap allocations; failed output/descriptor preflight0; successful buffer Layout/capacities equal admission exactly.

Regressions cover cached long-number64×64 projection with identical work debit to short1, ignored repeated-access work errors blocking seal, in-call scanner cancellation/deadline, numeric token bound, UTF8 split boundaries, malformed/duplicate JSON, signed integers, depth/node/raw/row/cell/text/provenance caps, actual unmapping, indexed joins, duplicate aliases, explicit hidden-captured-but-uninserted rows, exact SUM beyond2^53, complete aggregate inputs despite row cap, and fatal late source-memory failure without a partial COUNT. Reference syntax mutations use serde IgnoredAny plus UTF8 validation, never a Value tree.

The earlier shared native DELETE-taxonomy/Context-initializer issues are resolved in HEAD8c56 and were rerun successfully. Terminal-controller, raw-Wasm/managed-crypto/capture/freshness/authority/storage-retention gates and full HTTP launch remain the parent's work; no whole-application or production pass is claimed here.

No commit, push, PR, deployment, repository Cargo changes, or shared evaluator/SDK/service/consensus/native-engine edits by this child.
