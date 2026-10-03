//! Bounded, read-only SQLite over caller-approved lazy logical tables.
//!
//! This module is intentionally independent of Flower's policy/catalog: the caller
//! supplies only the readable schema and a snapshot-bound Source. All connections
//! are short-lived and synchronous, on the current thread. See README.md for the
//! provider contract and exact transport. No SQLite error text is exposed.
mod allocator;
mod init;
mod vtab;

use std::alloc::{Layout, alloc};
use std::cell::{Cell, RefCell};
use std::ffi::{CStr, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Arc;

use libsqlite3_sys as ffi;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};

use allocator::{Quota, Scope};

pub const MAX_SQL_BYTES: usize = 64 * 1024;
pub const MAX_PARAMETERS: usize = 256;
pub const MAX_CELL_BYTES: usize = 1024 * 1024;
pub const MAX_ROWS: usize = 1000;
pub const MAX_NATIVE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
pub const MAX_WORK: u64 = 100_000;
pub const MAX_COLUMNS: usize = 128;
// Leave descriptor slots for three bounded discovery relations in addition to
// the caller's 64-table logical catalog. SQLite itself still caps joins at 64.
pub const MAX_TABLES: usize = 67;
pub const MAX_TOKEN_BYTES: usize = 4096;
const PROGRESS_QUANTUM: u64 = 100;

#[derive(Clone, Debug, PartialEq)]
pub enum SqlCell {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
}
impl Serialize for SqlCell {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if matches!(self, Self::Null) {
            return serializer.serialize_unit();
        }
        let mut state = serializer.serialize_struct("SqlCell", 1)?;
        match self {
            Self::Null => unreachable!(),
            Self::Integer(value) => state.serialize_field("integer", &value.to_string())?,
            Self::Real(value) => {
                if !value.is_finite() {
                    return Err(serde::ser::Error::custom("nonfinite SQL value"));
                }
                state.serialize_field("real", value)?;
            }
            Self::Text(value) => state.serialize_field("text", value)?,
        }
        state.end()
    }
}
impl<'de> Deserialize<'de> for SqlCell {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged, deny_unknown_fields)]
        enum Wire {
            Null(()),
            Integer { integer: String },
            Real { real: f64 },
            Text { text: String },
        }
        match Wire::deserialize(deserializer)? {
            Wire::Null(()) => Ok(Self::Null),
            Wire::Integer { integer: value } => {
                let integer = value
                    .parse::<i64>()
                    .map_err(|_| serde::de::Error::custom("invalid SQL integer"))?;
                if integer.to_string() != value {
                    return Err(serde::de::Error::custom("invalid SQL integer"));
                }
                Ok(Self::Integer(integer))
            }
            Wire::Real { real: value } if value.is_finite() => Ok(Self::Real(value)),
            Wire::Real { .. } => Err(serde::de::Error::custom("nonfinite SQL value")),
            Wire::Text { text: value } if value.len() <= MAX_CELL_BYTES => Ok(Self::Text(value)),
            Wire::Text { .. } => Err(serde::de::Error::custom("oversized SQL value")),
        }
    }
}
impl SqlCell {
    fn valid(&self) -> bool {
        match self {
            Self::Real(n) => n.is_finite(),
            Self::Text(s) => s.len() <= MAX_CELL_BYTES,
            _ => true,
        }
    }
    fn heap_bytes(&self) -> usize {
        match self {
            Self::Text(s) => s.capacity(),
            _ => 0,
        }
    }
}

#[derive(Clone, Debug)]
pub struct VirtualTable {
    pub name: String,
    pub columns: Vec<String>,
    pub equality_columns: Vec<usize>,
}
#[derive(Clone, Debug, PartialEq)]
pub struct Equality {
    pub column: usize,
    pub value: SqlCell,
}
pub struct ScanRequest<'a> {
    pub table: usize,
    pub constraints: &'a [Equality],
    pub after: Option<&'a str>,
    pub limit: usize,
    /// Provider MUST bound its returned batch's allocated capacities to this
    /// many bytes (including Vec/row/cell/token capacities), before allocating.
    pub max_bytes: usize,
}
#[derive(Debug, Default)]
pub struct Batch {
    pub rows: Vec<Vec<SqlCell>>,
    pub next: Option<String>,
}
pub trait Source {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError>;
}

#[derive(Clone, Copy, Debug)]
pub struct QueryOptions {
    pub max_rows: usize,
    pub max_native_bytes: usize,
    pub max_output_bytes: usize,
    pub max_work: u64,
    pub batch_rows: usize,
}
impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            max_rows: MAX_ROWS,
            max_native_bytes: MAX_NATIVE_BYTES,
            max_output_bytes: MAX_OUTPUT_BYTES,
            max_work: MAX_WORK,
            batch_rows: 64,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SqlResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlCell>>,
    pub truncated: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SqlError {
    InvalidRequest,
    Forbidden,
    InvalidSql,
    MemoryLimit,
    WorkLimit,
    Cancelled,
    Deadline,
    Provider,
    OutputLimit,
    UnsupportedValue,
    Unavailable,
}
impl std::fmt::Display for SqlError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::InvalidRequest => "invalid SQL request",
            Self::Forbidden => "SQL operation is not allowed",
            Self::InvalidSql => "SQL statement failed",
            Self::MemoryLimit => "SQL memory budget exceeded",
            Self::WorkLimit => "SQL work budget exceeded",
            Self::Cancelled => "SQL query cancelled",
            Self::Deadline => "SQL deadline exceeded",
            Self::Provider => "SQL source failed",
            Self::OutputLimit => "SQL output budget exceeded",
            Self::UnsupportedValue => "unsupported SQL value",
            Self::Unavailable => "bounded SQL is unavailable",
        })
    }
}
impl std::error::Error for SqlError {}

/// Rust-owned callback/cursor buffers also reserve the query's hard quota. The
/// provider receives a reservation before it allocates a batch. Output has its
/// own smaller bound and ceases being query-owned when returned to the caller.
struct Lease {
    quota: Arc<Quota>,
    bytes: usize,
}
impl Lease {
    fn new(quota: &Arc<Quota>, bytes: usize) -> Result<Self, SqlError> {
        if !quota.charge(bytes) {
            return Err(SqlError::MemoryLimit);
        }
        Ok(Self {
            quota: quota.clone(),
            bytes,
        })
    }
    fn shrink(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.bytes);
        self.quota.release(self.bytes - bytes);
        self.bytes = bytes;
    }
    fn grow(&mut self, bytes: usize) -> Result<(), SqlError> {
        let growth = bytes.saturating_sub(self.bytes);
        if !self.quota.charge(growth) {
            return Err(SqlError::MemoryLimit);
        }
        self.bytes = self.bytes.max(bytes);
        Ok(())
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.quota.release(self.bytes);
    }
}

// Exact Rust allocation payloads, admitted BEFORE the allocator is called.
// Vec::with_capacity/format!/CString temporaries would otherwise bypass the
// SQLite owner allocator. Capacity is exact and no push can grow these buffers.
fn exact_vec<T>(capacity: usize) -> Result<Vec<T>, SqlError> {
    if capacity == 0 {
        return Ok(Vec::new());
    }
    if size_of::<T>() == 0 {
        return Err(SqlError::InvalidRequest);
    }
    let layout = Layout::array::<T>(capacity).map_err(|_| SqlError::MemoryLimit)?;
    let pointer = unsafe { alloc(layout) };
    if pointer.is_null() {
        return Err(SqlError::MemoryLimit);
    }
    Ok(unsafe { Vec::from_raw_parts(pointer.cast::<T>(), 0, capacity) })
}
struct QuotaBuffer {
    bytes: Vec<u8>,
    _lease: Lease,
}
impl QuotaBuffer {
    fn new(quota: &Arc<Quota>, capacity: usize) -> Result<Self, SqlError> {
        let lease = Lease::new(quota, capacity)?;
        let bytes = exact_vec(capacity)?;
        Ok(Self {
            bytes,
            _lease: lease,
        })
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), SqlError> {
        if self
            .bytes
            .len()
            .checked_add(bytes.len())
            .is_none_or(|len| len > self.bytes.capacity())
        {
            return Err(SqlError::MemoryLimit);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn c_text(quota: &Arc<Quota>, parts: &[&[u8]]) -> Result<Self, SqlError> {
        let capacity = parts.iter().try_fold(1usize, |sum, part| {
            sum.checked_add(part.len()).ok_or(SqlError::MemoryLimit)
        })?;
        if parts.iter().any(|part| part.contains(&0)) {
            return Err(SqlError::InvalidRequest);
        }
        let mut buffer = Self::new(quota, capacity)?;
        for part in parts {
            buffer.append(part)?;
        }
        buffer.append(&[0])?;
        Ok(buffer)
    }
    fn pointer(&self) -> *const c_char {
        debug_assert_eq!(self.bytes.last(), Some(&0));
        self.bytes.as_ptr().cast()
    }
}

struct Context<'a> {
    source: RefCell<&'a mut dyn Source>,
    check: RefCell<&'a mut dyn FnMut() -> Result<(), SqlError>>,
    tables: &'a [VirtualTable],
    quota: Arc<Quota>,
    options: QueryOptions,
    failure: Cell<Option<SqlError>>,
    work: Cell<u64>,
    referenced: Cell<u128>,
    prepare_only: bool,
}
impl Context<'_> {
    fn fail(&self, error: SqlError) -> SqlError {
        if error == SqlError::MemoryLimit {
            self.quota.fail();
        }
        if self.failure.get().is_none() {
            self.failure.set(Some(error));
        }
        self.failure.get().unwrap_or(error)
    }
    fn status(&self) -> Result<(), SqlError> {
        if let Some(error) = self.failure.get() {
            return Err(error);
        }
        if self.quota.failed() {
            return Err(self.fail(SqlError::MemoryLimit));
        }
        Ok(())
    }
    fn poll(&self, cost: u64) -> Result<(), SqlError> {
        self.status()?;
        let Some(work) = self
            .work
            .get()
            .checked_add(cost)
            .filter(|work| *work <= self.options.max_work)
        else {
            return Err(self.fail(SqlError::WorkLimit));
        };
        self.work.set(work);
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut check = self
                .check
                .try_borrow_mut()
                .map_err(|_| SqlError::Provider)?;
            check()
        }))
        .unwrap_or(Err(SqlError::Provider));
        result.map_err(|error| self.fail(error))
    }
    fn callback(&self, f: impl FnOnce() -> Result<(), SqlError>) -> c_int {
        match catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(SqlError::Provider)) {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) => {
                self.fail(error);
                match error {
                    SqlError::MemoryLimit => ffi::SQLITE_NOMEM,
                    _ => ffi::SQLITE_ABORT,
                }
            }
        }
    }
    fn sqlite_error(&self, code: c_int) -> SqlError {
        if let Err(error) = self.status() {
            return error;
        }
        match code & 0xff {
            ffi::SQLITE_NOMEM => self.fail(SqlError::MemoryLimit),
            ffi::SQLITE_AUTH | ffi::SQLITE_PERM | ffi::SQLITE_READONLY => SqlError::Forbidden,
            ffi::SQLITE_TOOBIG => SqlError::OutputLimit,
            _ => SqlError::InvalidSql,
        }
    }
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && !name.to_ascii_lowercase().starts_with("sqlite_")
        && name.bytes().enumerate().all(|(i, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || i > 0 && byte.is_ascii_digit()
        })
}
fn validate(
    sql: &str,
    params: &[SqlCell],
    tables: &[VirtualTable],
    options: QueryOptions,
) -> Result<(), SqlError> {
    if sql.is_empty()
        || sql.len() > MAX_SQL_BYTES
        || sql.contains('\0')
        || params.len() > MAX_PARAMETERS
        || tables.len() > MAX_TABLES
        || options.max_rows > MAX_ROWS
        || options.max_native_bytes == 0
        || options.max_native_bytes > MAX_NATIVE_BYTES
        || options.max_output_bytes == 0
        || options.max_output_bytes > MAX_OUTPUT_BYTES
        || options.max_work == 0
        || options.max_work > MAX_WORK
        || options.batch_rows == 0
        || options.batch_rows > 256
    {
        return Err(SqlError::InvalidRequest);
    }
    let mut parameter_bytes = 0usize;
    for value in params {
        parameter_bytes = parameter_bytes.saturating_add(size_of::<SqlCell>() + value.heap_bytes());
        if !value.valid() || parameter_bytes > MAX_CELL_BYTES {
            return Err(SqlError::InvalidRequest);
        }
    }
    for (i, table) in tables.iter().enumerate() {
        if !identifier(&table.name)
            || table.columns.is_empty()
            || table.columns.len() > MAX_COLUMNS
            || tables[..i]
                .iter()
                .any(|t| t.name.eq_ignore_ascii_case(&table.name))
            || table.equality_columns.len() > table.columns.len()
            || table.equality_columns.iter().enumerate().any(|(j, index)| {
                *index >= table.columns.len() || table.equality_columns[..j].contains(index)
            })
        {
            return Err(SqlError::InvalidRequest);
        }
        for (j, column) in table.columns.iter().enumerate() {
            if !identifier(column)
                || ["rowid", "_rowid_", "oid"]
                    .iter()
                    .any(|hidden| column.eq_ignore_ascii_case(hidden))
                || table.columns[..j]
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(column))
            {
                return Err(SqlError::InvalidRequest);
            }
        }
    }
    Ok(())
}

struct Database(*mut ffi::sqlite3);
impl Drop for Database {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ffi::sqlite3_close(self.0);
            }
        }
    }
}
struct Statement(*mut ffi::sqlite3_stmt);
impl Drop for Statement {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                ffi::sqlite3_finalize(self.0);
            }
        }
    }
}

/// Only a single read-only SQL statement with positional parameters is accepted.
/// An error discards all accumulated output. Do not call this recursively from
/// Source/check: there is deliberately no nested query quota scope.
pub fn execute(
    sql: &str,
    parameters: &[SqlCell],
    tables: &[VirtualTable],
    source: &mut dyn Source,
    options: QueryOptions,
    check: &mut dyn FnMut() -> Result<(), SqlError>,
) -> Result<SqlResult, SqlError> {
    validate(sql, parameters, tables, options)?;
    init::initialize()?;
    let quota = Quota::new(options.max_native_bytes);
    let _scope = Scope::enter(quota.clone()).ok_or(SqlError::Unavailable)?;
    let context = Context {
        source: RefCell::new(source),
        check: RefCell::new(check),
        tables,
        quota,
        options,
        failure: Cell::new(None),
        work: Cell::new(0),
        referenced: Cell::new(0),
        prepare_only: false,
    };
    execute_scoped(sql, parameters, &context)
}

/// Exact logical relations authorized while preparing one statement. This
/// creates no Source cursor, executes no user opcode, and retains no database,
/// statement or source capability on return. All referenced inputs must be
/// captured completely under their independent caps unless a separately proved
/// mandatory restriction is available. A native planner preference is NOT such
/// a restriction, and this API deliberately does not expose it as one.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReferencedTables(u128);
impl ReferencedTables {
    pub fn contains(self, table: usize) -> bool {
        table < MAX_TABLES && self.0 & (1u128 << table) != 0
    }
}
pub fn referenced_tables(
    sql: &str,
    parameters: &[SqlCell],
    tables: &[VirtualTable],
    options: QueryOptions,
    check: &mut dyn FnMut() -> Result<(), SqlError>,
) -> Result<ReferencedTables, SqlError> {
    struct NoSource;
    impl Source for NoSource {
        fn scan(&mut self, _: ScanRequest<'_>) -> Result<Batch, SqlError> {
            Err(SqlError::Provider)
        }
    }
    validate(sql, parameters, tables, options)?;
    init::initialize()?;
    let quota = Quota::new(options.max_native_bytes);
    let _scope = Scope::enter(quota.clone()).ok_or(SqlError::Unavailable)?;
    let mut source = NoSource;
    let context = Context {
        source: RefCell::new(&mut source),
        check: RefCell::new(check),
        tables,
        quota,
        options,
        failure: Cell::new(None),
        work: Cell::new(0),
        referenced: Cell::new(0),
        prepare_only: true,
    };
    execute_scoped(sql, parameters, &context)?;
    context.status()?;
    Ok(ReferencedTables(context.referenced.get()))
}

fn execute_scoped(
    sql: &str,
    parameters: &[SqlCell],
    context: &Context<'_>,
) -> Result<SqlResult, SqlError> {
    context.poll(PROGRESS_QUANTUM)?; // reserve the first progress quantum in advance
    // Bindings outlive database/module callbacks: declaration order matters.
    let _bindings_lease = Lease::new(
        &context.quota,
        context
            .tables
            .len()
            .checked_mul(size_of::<Box<vtab::Binding>>())
            .ok_or(SqlError::MemoryLimit)?,
    )?;
    let mut bindings = exact_vec(context.tables.len())?;
    let sql = QuotaBuffer::c_text(&context.quota, &[sql.as_bytes()])?;
    let mut handle = ptr::null_mut();
    let code = unsafe {
        ffi::sqlite3_open_v2(
            c":memory:".as_ptr(),
            &mut handle,
            ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE
                | ffi::SQLITE_OPEN_MEMORY
                | ffi::SQLITE_OPEN_NOMUTEX,
            init::VFS_NAME.as_ptr(),
        )
    };
    let database = Database(handle);
    if code != ffi::SQLITE_OK {
        return Err(context.sqlite_error(code));
    }
    let db = database.0;
    unsafe {
        ffi::sqlite3_extended_result_codes(db, 1);
        for (category, limit) in [
            (ffi::SQLITE_LIMIT_LENGTH, MAX_CELL_BYTES as c_int),
            (ffi::SQLITE_LIMIT_SQL_LENGTH, MAX_SQL_BYTES as c_int),
            (ffi::SQLITE_LIMIT_COLUMN, MAX_COLUMNS as c_int),
            (ffi::SQLITE_LIMIT_VARIABLE_NUMBER, MAX_PARAMETERS as c_int),
            (ffi::SQLITE_LIMIT_EXPR_DEPTH, 64),
            (ffi::SQLITE_LIMIT_COMPOUND_SELECT, 16),
            (ffi::SQLITE_LIMIT_VDBE_OP, 100_000),
            (ffi::SQLITE_LIMIT_FUNCTION_ARG, 32),
            (ffi::SQLITE_LIMIT_ATTACHED, 0),
            (ffi::SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 0),
            (ffi::SQLITE_LIMIT_TRIGGER_DEPTH, 0),
            (ffi::SQLITE_LIMIT_WORKER_THREADS, 0),
        ] {
            ffi::sqlite3_limit(db, category, limit);
        }
        for (setting, enabled) in [
            (ffi::SQLITE_DBCONFIG_DEFENSIVE, 1),
            (ffi::SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0),
            (ffi::SQLITE_DBCONFIG_DQS_DML, 0),
            (ffi::SQLITE_DBCONFIG_DQS_DDL, 0),
            (ffi::SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0),
            (ffi::SQLITE_DBCONFIG_ENABLE_TRIGGER, 0),
            (ffi::SQLITE_DBCONFIG_ENABLE_VIEW, 0),
        ] {
            let rc =
                ffi::sqlite3_db_config(db, setting, enabled as c_int, ptr::null_mut::<c_int>());
            if rc != ffi::SQLITE_OK {
                return Err(context.sqlite_error(rc));
            }
        }
        // Trusted configuration precedes the deny-by-default user authorizer.
        let rc = ffi::sqlite3_exec(
            db,
            c"PRAGMA temp_store=MEMORY; PRAGMA cache_spill=OFF; PRAGMA threads=0;".as_ptr(),
            None,
            ptr::null_mut(),
            ptr::null_mut(),
        );
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
    }
    vtab::register(db, context, &mut bindings)?;
    unsafe {
        let data = (context as *const Context<'_>).cast_mut().cast::<c_void>();
        let rc = ffi::sqlite3_set_authorizer(db, Some(authorizer), data);
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
        ffi::sqlite3_progress_handler(db, PROGRESS_QUANTUM as c_int, Some(progress), data);
    }
    let mut stmt = ptr::null_mut();
    let mut tail = ptr::null();
    let rc = unsafe {
        ffi::sqlite3_prepare_v3(
            db,
            sql.pointer(),
            (sql.bytes.len() - 1) as c_int,
            0,
            &mut stmt,
            &mut tail,
        )
    };
    let statement = Statement(stmt);
    if rc != ffi::SQLITE_OK {
        return Err(context.sqlite_error(rc));
    }
    if stmt.is_null() || unsafe { ffi::sqlite3_stmt_readonly(stmt) } == 0 {
        return Err(SqlError::Forbidden);
    }
    // Prepare the remainder under the same authorizer; never execute it. Comments
    // and whitespace are accepted, an additional statement (even SELECT) is not.
    if !tail.is_null() {
        let mut extra = ptr::null_mut();
        let extra_rc =
            unsafe { ffi::sqlite3_prepare_v3(db, tail, -1, 0, &mut extra, ptr::null_mut()) };
        let extra_statement = Statement(extra);
        if extra_rc != ffi::SQLITE_OK || !extra_statement.0.is_null() {
            return Err(SqlError::InvalidSql);
        }
    }
    if unsafe { ffi::sqlite3_bind_parameter_count(stmt) } as usize != parameters.len() {
        return Err(SqlError::InvalidRequest);
    }
    for (i, cell) in parameters.iter().enumerate() {
        let name = unsafe { ffi::sqlite3_bind_parameter_name(stmt, i as c_int + 1) };
        if !name.is_null() && unsafe { CStr::from_ptr(name) }.to_bytes().first() != Some(&b'?') {
            return Err(SqlError::InvalidRequest);
        }
        let code = unsafe { bind(stmt, i as c_int + 1, cell) };
        if code != ffi::SQLITE_OK {
            return Err(context.sqlite_error(code));
        }
    }
    let count = unsafe { ffi::sqlite3_column_count(stmt) } as usize;
    if count == 0 || count > MAX_COLUMNS {
        return Err(SqlError::InvalidSql);
    }
    if context.prepare_only {
        context.status()?;
        return Ok(SqlResult {
            columns: Vec::new(),
            rows: Vec::new(),
            truncated: false,
        });
    }
    // A conservative encoded-output bound also covers String/Vec capacity and
    // the outer row Vec's geometric growth. Reserve before Rust allocations.
    let mut output_bytes = 64 + count * 32;
    if output_bytes > context.options.max_output_bytes {
        return Err(SqlError::OutputLimit);
    }
    let mut output_lease = Lease::new(&context.quota, output_bytes)?;
    let mut columns = Vec::with_capacity(count);
    for i in 0..count {
        let name = unsafe { ffi::sqlite3_column_name(stmt, i as c_int) };
        if name.is_null() {
            return Err(context.sqlite_error(ffi::SQLITE_NOMEM));
        }
        let name = unsafe { CStr::from_ptr(name) }
            .to_str()
            .map_err(|_| SqlError::UnsupportedValue)?;
        output_bytes += 6 * name.len() + 4;
        if output_bytes > context.options.max_output_bytes {
            return Err(SqlError::OutputLimit);
        }
        output_lease.grow(output_bytes)?;
        columns.push(name.to_owned()); // duplicates deliberately preserved by position
    }
    let mut rows = Vec::new();
    let mut truncated = false;
    loop {
        context.poll(1)?;
        let rc = unsafe { ffi::sqlite3_step(statement.0) };
        context.status()?;
        if rc == ffi::SQLITE_DONE {
            break;
        }
        if rc != ffi::SQLITE_ROW {
            return Err(context.sqlite_error(rc));
        }
        if rows.len() == context.options.max_rows {
            truncated = true;
            break;
        }
        let mut row_bytes = 2 + count;
        for i in 0..count {
            row_bytes += 96;
            if unsafe { ffi::sqlite3_column_type(stmt, i as c_int) } == ffi::SQLITE_TEXT {
                let bytes = unsafe { ffi::sqlite3_column_bytes(stmt, i as c_int) };
                if bytes < 0 || bytes as usize > MAX_CELL_BYTES {
                    return Err(SqlError::OutputLimit);
                }
                row_bytes += 6 * bytes as usize;
            }
        }
        context.status()?;
        output_bytes += row_bytes;
        if output_bytes > context.options.max_output_bytes {
            return Err(SqlError::OutputLimit);
        }
        output_lease.grow(output_bytes)?;
        let mut row = Vec::with_capacity(count);
        for i in 0..count {
            row.push(unsafe { read_column(stmt, i as c_int) }?);
        }
        rows.push(row);
    }
    context.status()?;
    Ok(SqlResult {
        columns,
        rows,
        truncated,
    })
}

unsafe fn bind(stmt: *mut ffi::sqlite3_stmt, column: c_int, cell: &SqlCell) -> c_int {
    unsafe {
        match cell {
            SqlCell::Null => ffi::sqlite3_bind_null(stmt, column),
            SqlCell::Integer(value) => ffi::sqlite3_bind_int64(stmt, column, *value),
            SqlCell::Real(value) => ffi::sqlite3_bind_double(stmt, column, *value),
            SqlCell::Text(value) => ffi::sqlite3_bind_text(
                stmt,
                column,
                value.as_ptr().cast(),
                value.len() as c_int,
                ffi::SQLITE_TRANSIENT(),
            ),
        }
    }
}
unsafe fn text(pointer: *const u8, len: c_int) -> Result<SqlCell, SqlError> {
    if len < 0 || len as usize > MAX_CELL_BYTES {
        return Err(SqlError::UnsupportedValue);
    }
    if pointer.is_null() {
        return if len == 0 {
            Ok(SqlCell::Text(String::new()))
        } else {
            Err(SqlError::MemoryLimit)
        };
    }
    let bytes = unsafe { std::slice::from_raw_parts(pointer, len as usize) };
    Ok(SqlCell::Text(
        std::str::from_utf8(bytes)
            .map_err(|_| SqlError::UnsupportedValue)?
            .to_owned(),
    ))
}
unsafe fn read_column(stmt: *mut ffi::sqlite3_stmt, column: c_int) -> Result<SqlCell, SqlError> {
    unsafe {
        match ffi::sqlite3_column_type(stmt, column) {
            ffi::SQLITE_NULL => Ok(SqlCell::Null),
            ffi::SQLITE_INTEGER => Ok(SqlCell::Integer(ffi::sqlite3_column_int64(stmt, column))),
            ffi::SQLITE_FLOAT => {
                let n = ffi::sqlite3_column_double(stmt, column);
                if n.is_finite() {
                    Ok(SqlCell::Real(n))
                } else {
                    Err(SqlError::UnsupportedValue)
                }
            }
            ffi::SQLITE_TEXT => {
                let p = ffi::sqlite3_column_text(stmt, column);
                text(p, ffi::sqlite3_column_bytes(stmt, column))
            }
            _ => Err(SqlError::UnsupportedValue),
        }
    }
}
pub(super) unsafe fn read_value(value: *mut ffi::sqlite3_value) -> Result<SqlCell, SqlError> {
    unsafe {
        match ffi::sqlite3_value_type(value) {
            ffi::SQLITE_NULL => Ok(SqlCell::Null),
            ffi::SQLITE_INTEGER => Ok(SqlCell::Integer(ffi::sqlite3_value_int64(value))),
            ffi::SQLITE_FLOAT => {
                let n = ffi::sqlite3_value_double(value);
                if n.is_finite() {
                    Ok(SqlCell::Real(n))
                } else {
                    Err(SqlError::UnsupportedValue)
                }
            }
            ffi::SQLITE_TEXT => {
                let p = ffi::sqlite3_value_text(value);
                text(p, ffi::sqlite3_value_bytes(value))
            }
            _ => Err(SqlError::UnsupportedValue),
        }
    }
}
unsafe extern "C" fn progress(data: *mut c_void) -> c_int {
    let context = unsafe { &*data.cast::<Context<'_>>() };
    i32::from(context.poll(PROGRESS_QUANTUM).is_err())
}
unsafe fn string<'a>(pointer: *const c_char) -> &'a [u8] {
    if pointer.is_null() {
        b""
    } else {
        unsafe { CStr::from_ptr(pointer).to_bytes() }
    }
}
unsafe extern "C" fn authorizer(
    data: *mut c_void,
    action: c_int,
    first: *const c_char,
    second: *const c_char,
    db: *const c_char,
    _: *const c_char,
) -> c_int {
    let context = unsafe { &*data.cast::<Context<'_>>() };
    if context.poll(1).is_err() {
        return ffi::SQLITE_DENY;
    }
    let allow = match action {
        ffi::SQLITE_SELECT => true,
        ffi::SQLITE_READ => {
            let table = unsafe { string(first) };
            let column = unsafe { string(second) };
            // SQLite's count(*)/unused-table authorization has db=NULL for
            // unqualified logical tables; ordinary column reads require main.
            let database = unsafe { string(db) };
            (database.eq_ignore_ascii_case(b"main") || database.is_empty() && column.is_empty())
                && context.tables.iter().enumerate().any(|(index, t)| {
                    let readable = t.name.as_bytes().eq_ignore_ascii_case(table)
                        && (column.is_empty()
                            || t.columns
                                .iter()
                                .any(|c| c.as_bytes().eq_ignore_ascii_case(column)));
                    if readable {
                        context
                            .referenced
                            .set(context.referenced.get() | (1u128 << index));
                    }
                    readable
                })
        }
        ffi::SQLITE_FUNCTION => {
            let function = unsafe { string(second) };
            [
                "count",
                "sum",
                "min",
                "max",
                "avg",
                "total",
                "coalesce",
                "ifnull",
                "nullif",
                "length",
                "lower",
                "upper",
                "abs",
                "json_extract",
                "json_valid",
            ]
            .iter()
            .any(|name| function.eq_ignore_ascii_case(name.as_bytes()))
        }
        // Explicitly includes SQLITE_RECURSIVE; all new action codes fail closed.
        _ => false,
    };
    if allow {
        ffi::SQLITE_OK
    } else {
        context.fail(SqlError::Forbidden);
        ffi::SQLITE_DENY
    }
}

#[cfg(test)]
mod tests;
