# Phase-0 native SQLite integration contract

Parent integrates `#[cfg(feature = "sql")] pub(crate) mod sqlite;` in `src/evaluator.rs`. This module owns no Flower/provider policy. The bundled dependency is `libsqlite3-sys = 0.38.2` (the parent currently gates it behind the default-off `sql` feature).

Frozen public API (implemented in `mod.rs`):

```rust
pub enum SqlCell { Null, Integer(i64), Real(f64), Text(String) }
pub struct VirtualTable {
    pub name: String,
    pub columns: Vec<String>, // declared WITHOUT affinity; caller defines safe logical schema
    pub equality_columns: Vec<usize>, // only these BINARY equality columns can be pushed
}
pub struct Equality { pub column: usize, pub value: SqlCell }
pub struct ScanRequest<'a> {
    pub table: usize,
    pub constraints: &'a [Equality],
    pub after: Option<&'a str>, // opaque bounded provider token
    pub limit: usize,
    pub max_bytes: usize, // reserved batch capacity; provider must respect before allocating
}
pub struct Batch { pub rows: Vec<Vec<SqlCell>>, pub next: Option<String> }
pub trait Source {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError>;
}
pub struct QueryOptions {
    pub max_rows: usize, pub max_native_bytes: usize,
    pub max_output_bytes: usize, pub max_work: u64, pub batch_rows: usize,
}
pub struct SqlResult { pub columns: Vec<String>, pub rows: Vec<Vec<SqlCell>>, pub truncated: bool }
pub enum SqlError { InvalidRequest, Forbidden, InvalidSql, MemoryLimit, WorkLimit,
                    Cancelled, Deadline, Provider, OutputLimit, UnsupportedValue, Unavailable }
pub fn execute(
    sql: &str, parameters: &[SqlCell], tables: &[VirtualTable],
    source: &mut dyn Source, options: QueryOptions,
    check: &mut dyn FnMut() -> Result<(), SqlError>,
) -> Result<SqlResult, SqlError>;
```

`Source::scan` is called lazily, with at most `batch_rows` requested rows; it MUST bound its own allocations/work before producing a batch, respect `max_bytes` before allocating returned Vec/String capacities, and return a stable snapshot. The module reserves that budget first and validates actual capacities on return, but cannot retroactively constrain an out-of-contract provider's private allocations. `next = None` means end-of-scan. A continuation must accompany a nonempty batch and must advance. Tokens are at most 4096 bytes. Equality pushdown must be a conservative candidate restriction compatible with SQLite's no-affinity BINARY equality semantics (including integer/real numeric equality): never discard a row SQLite would retain. SQLite always rechecks (omit=false), and ORDER BY is never declared consumed. Provider/index use is the caller's responsibility.

Every provider invocation and every 100 VM instructions charges work and invokes `check`. Provider errors/panics and check failures are sticky: the entire query fails, with no partial aggregates/results. Callbacks are synchronous and must not reenter this module on the same thread. Options default/hard maxima: rows 1000, native 16 MiB, output 1 MiB, work 100000, batches 64 (maximum 256). SQL 64 KiB, parameters 256, cell length 1 MiB, columns 128, native descriptors 67 (64 logical catalog tables plus three discovery relations). Caller can lower limits, never raise hard limits.

Exact transport: `null`, `{ "integer": "9223372036854775807" }` (decimal string, not lossy JSON number), `{ "real": 1.5 }`, `{ "text": "..." }`. Nonfinite reals and blobs are rejected.

SQLite is globally configured with the header-owner custom allocator exactly once, before its first use. If another library has already initialized SQLite, initialization fails closed (never shuts another client's SQLite down). Initialization has a separate fixed 1 MiB quota; post-init native allocations require a query TLS quota. A private VFS denies filesystem opens, deletion, dynamic libraries, entropy, and time; connections are memory-only, temp_store=MEMORY, no worker threads. Each connection/statement is closed before its TLS scope ends. Cursor/batch/result Rust storage additionally reserves the query quota and output is capped using a conservative encoded-size/capacity bound; provider-private state still requires the caller's separate bounds. Result column names remain positional and duplicate aliases are preserved.

Verification (October 3, 2026): `cargo test --lib --features sql evaluator::sqlite` passes all 16 tests in Flower. The independent native harness also passes all 16 tests and `cargo clippy --all-targets -- -D warnings`; rustfmt passes on these files. High-cardinality sort exhaustion verifies peak quota <= 512 KiB, zero retained query allocations on failure, and zero VFS open attempts. Parallel isolation covers 120 successful/failing queries across 12 threads; header ownership is also tested after TLS scope exit and on another freeing thread.
