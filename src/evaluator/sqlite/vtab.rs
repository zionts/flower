//! Minimal read-only virtual tables. Equality is a candidate restriction only:
//! omit remains false, no affinity is declared, only BINARY comparisons are
//! pushed, and ORDER BY is never claimed. Every cursor has its own bounded batch.
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::ptr;

use libsqlite3_sys as ffi;

use super::{
    Batch, Context, Equality, Lease, MAX_CELL_BYTES, MAX_COLUMNS, MAX_TOKEN_BYTES, ScanRequest,
    SqlCell, SqlError, read_value,
};

pub(super) struct Binding {
    context: *const c_void,
    table: usize,
    _lease: Lease,
}
impl Binding {
    fn context(&self) -> &Context<'_> {
        // SAFETY: register is only called from execute_scoped, which closes the
        // database/cursors before dropping bindings or their borrowed context.
        unsafe { &*self.context.cast::<Context<'_>>() }
    }
}
#[repr(C)]
struct Table {
    base: ffi::sqlite3_vtab,
    binding: *const Binding,
    _lease: Lease,
}
impl Table {
    fn binding(&self) -> &Binding {
        unsafe { &*self.binding }
    }
}
#[repr(C)]
struct Cursor {
    base: ffi::sqlite3_vtab_cursor,
    binding: *const Binding,
    constraints: Vec<Equality>,
    constraint_lease: Option<Lease>,
    batch: Batch,
    batch_lease: Option<Lease>,
    position: usize,
    rowid: i64,
    _lease: Lease,
}
impl Cursor {
    fn binding(&self) -> &Binding {
        unsafe { &*self.binding }
    }
    fn load(&mut self) -> Result<(), SqlError> {
        let binding = unsafe { &*self.binding };
        let context = binding.context();
        context.poll(1)?;
        // Reserve before asking the provider to allocate. The provider must
        // honor max_bytes itself: its own out-of-contract allocations cannot be
        // undone by a consumer after it has returned a Batch.
        let bytes = (context.quota.remaining() / 2).min(MAX_CELL_BYTES);
        if bytes < 256 {
            return Err(SqlError::MemoryLimit);
        }
        let mut lease = Lease::new(&context.quota, bytes)?;
        let after = self.batch.next.as_deref();
        let batch = {
            let mut source = context
                .source
                .try_borrow_mut()
                .map_err(|_| SqlError::Provider)?;
            source.scan(ScanRequest {
                table: binding.table,
                constraints: &self.constraints,
                after,
                limit: context.options.batch_rows,
                max_bytes: bytes,
            })?
        };
        context.poll(batch.rows.len() as u64)?;
        if batch.rows.len() > context.options.batch_rows
            || batch.rows.iter().any(|row| {
                row.len() != context.tables[binding.table].columns.len()
                    || row.iter().any(|value| !value.valid())
            })
            || batch.next.as_ref().is_some_and(|token| {
                token.len() > MAX_TOKEN_BYTES
                    || token.is_empty()
                    || Some(token.as_str()) == after
                    || batch.rows.is_empty()
            })
        {
            return Err(SqlError::Provider);
        }
        let actual = batch_bytes(&batch);
        if actual > bytes {
            return Err(SqlError::Provider);
        }
        lease.shrink(actual);
        self.batch = batch;
        self.batch_lease = Some(lease);
        self.position = 0;
        Ok(())
    }
}
fn batch_bytes(batch: &Batch) -> usize {
    batch.rows.capacity() * size_of::<Vec<SqlCell>>()
        + batch
            .rows
            .iter()
            .map(|row| {
                row.capacity() * size_of::<SqlCell>()
                    + row.iter().map(SqlCell::heap_bytes).sum::<usize>()
            })
            .sum::<usize>()
        + batch.next.as_ref().map_or(0, String::capacity)
}

// Immutable function-pointer-only static; SQLite keeps this pointer until close.
static MODULE: ffi::sqlite3_module = ffi::sqlite3_module {
    iVersion: 1,
    xCreate: Some(connect),
    xConnect: Some(connect),
    xBestIndex: Some(best_index),
    xDisconnect: Some(disconnect),
    xDestroy: Some(disconnect),
    xOpen: Some(open),
    xClose: Some(close),
    xFilter: Some(filter),
    xNext: Some(next),
    xEof: Some(eof),
    xColumn: Some(column),
    xRowid: Some(rowid),
    xUpdate: None,
    xBegin: None,
    xSync: None,
    xCommit: None,
    xRollback: None,
    xFindFunction: None,
    xRename: None,
    xSavepoint: None,
    xRelease: None,
    xRollbackTo: None,
    xShadowName: None,
    xIntegrity: None,
};

// SQLite retains each auxiliary pointer; Vec growth must not move a Binding.
#[allow(clippy::vec_box)]
pub(super) fn register(
    db: *mut ffi::sqlite3,
    context: &Context<'_>,
    bindings: &mut Vec<Box<Binding>>,
) -> Result<(), SqlError> {
    for (i, table) in context.tables.iter().enumerate() {
        context.poll(1)?;
        let binding = Box::new(Binding {
            context: (context as *const Context<'_>).cast(),
            table: i,
            _lease: Lease::new(&context.quota, size_of::<Binding>())?,
        });
        let module_name =
            CString::new(format!("flower_source_{i}")).map_err(|_| SqlError::InvalidRequest)?;
        let rc = unsafe {
            ffi::sqlite3_create_module_v2(
                db,
                module_name.as_ptr(),
                &MODULE,
                (&*binding as *const Binding).cast_mut().cast(),
                None,
            )
        };
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
        bindings.push(binding);
        // All identifiers were checked against a strict ASCII grammar. Quotes
        // additionally protect SQL keywords, not user-supplied SQL interpolation.
        let declaration = CString::new(format!(
            "CREATE VIRTUAL TABLE \"{}\" USING flower_source_{i}",
            table.name
        ))
        .map_err(|_| SqlError::InvalidRequest)?;
        let rc = unsafe {
            ffi::sqlite3_exec(
                db,
                declaration.as_ptr(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
    }
    Ok(())
}
unsafe extern "C" fn connect(
    db: *mut ffi::sqlite3,
    data: *mut c_void,
    _: c_int,
    _: *const *const c_char,
    out: *mut *mut ffi::sqlite3_vtab,
    _: *mut *mut c_char,
) -> c_int {
    let binding = unsafe { &*data.cast::<Binding>() };
    let context = binding.context();
    context.callback(|| {
        context.poll(1)?;
        let schema = &context.tables[binding.table];
        let columns = schema
            .columns
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let declaration = CString::new(format!("CREATE TABLE logical({columns})"))
            .map_err(|_| SqlError::Provider)?;
        let rc = unsafe { ffi::sqlite3_declare_vtab(db, declaration.as_ptr()) };
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
        // Direct-only prevents use inside any indirectly stored schema, even if
        // someone changes connection configuration in a future integration.
        let rc = unsafe { ffi::sqlite3_vtab_config(db, ffi::SQLITE_VTAB_DIRECTONLY) };
        if rc != ffi::SQLITE_OK {
            return Err(context.sqlite_error(rc));
        }
        let table = Box::new(Table {
            base: ffi::sqlite3_vtab {
                pModule: ptr::null(),
                nRef: 0,
                zErrMsg: ptr::null_mut(),
            },
            binding: data.cast(),
            _lease: Lease::new(&context.quota, size_of::<Table>())?,
        });
        unsafe {
            *out = Box::into_raw(table).cast();
        }
        Ok(())
    })
}
unsafe extern "C" fn best_index(
    table: *mut ffi::sqlite3_vtab,
    info: *mut ffi::sqlite3_index_info,
) -> c_int {
    let table = unsafe { &*table.cast::<Table>() };
    let binding = table.binding();
    let context = binding.context();
    context.callback(|| {
        context.poll(1)?;
        let schema = &context.tables[binding.table];
        // Do not hold a Rust &mut to the info structure across SQLite's
        // collation callback, which reads the original C pointer.
        let (constraint_count, constraints, usages) = unsafe {
            (
                (*info).nConstraint,
                (*info).aConstraint,
                (*info).aConstraintUsage,
            )
        };
        let mut columns = [0usize; MAX_COLUMNS];
        let mut seen = [false; MAX_COLUMNS];
        let mut count = 0;
        for index in 0..constraint_count as usize {
            let constraint = unsafe { &*constraints.add(index) };
            if constraint.usable == 0
                || constraint.op != ffi::SQLITE_INDEX_CONSTRAINT_EQ as u8
                || constraint.iColumn < 0
            {
                continue;
            }
            let column = constraint.iColumn as usize;
            if column >= schema.columns.len()
                || seen[column]
                || !schema.equality_columns.contains(&column)
            {
                continue;
            }
            let collation = unsafe { ffi::sqlite3_vtab_collation(info, index as c_int) };
            if collation.is_null()
                || !unsafe { CStr::from_ptr(collation) }
                    .to_bytes()
                    .eq_ignore_ascii_case(b"BINARY")
            {
                continue;
            }
            columns[count] = column;
            seen[column] = true;
            count += 1;
            let usage = unsafe { &mut *usages.add(index) };
            usage.argvIndex = count as c_int;
            usage.omit = 0; // SQLite ALWAYS rechecks provider candidates
        }
        let info_ref = unsafe { &mut *info };
        info_ref.orderByConsumed = 0;
        info_ref.idxFlags = 0; // never assert uniqueness
        info_ref.estimatedCost = if count == 0 { 100_000.0 } else { 10.0 };
        info_ref.estimatedRows = if count == 0 { 100_000 } else { 16 };
        if count != 0 {
            let mut encoded = [0u8; MAX_COLUMNS * 4 + 1];
            let mut length = 0;
            for column in columns[..count].iter().copied() {
                // Every column fits in three decimal digits.
                if column >= 100 {
                    encoded[length] = b'0' + (column / 100) as u8;
                    length += 1;
                }
                if column >= 10 {
                    encoded[length] = b'0' + ((column / 10) % 10) as u8;
                    length += 1;
                }
                encoded[length] = b'0' + (column % 10) as u8;
                length += 1;
                encoded[length] = b',';
                length += 1;
            }
            let p = unsafe { ffi::sqlite3_malloc64((length + 1) as u64) }.cast::<u8>();
            if p.is_null() {
                return Err(SqlError::MemoryLimit);
            }
            unsafe {
                ptr::copy_nonoverlapping(encoded.as_ptr(), p, length + 1);
            }
            info_ref.idxStr = p.cast();
            info_ref.needToFreeIdxStr = 1;
        }
        info_ref.idxNum = count as c_int;
        Ok(())
    })
}
unsafe extern "C" fn disconnect(table: *mut ffi::sqlite3_vtab) -> c_int {
    unsafe {
        drop(Box::from_raw(table.cast::<Table>()));
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn open(
    table: *mut ffi::sqlite3_vtab,
    out: *mut *mut ffi::sqlite3_vtab_cursor,
) -> c_int {
    let table_ref = unsafe { &*table.cast::<Table>() };
    let binding = table_ref.binding();
    let context = binding.context();
    context.callback(|| {
        context.poll(1)?;
        let cursor = Box::new(Cursor {
            base: ffi::sqlite3_vtab_cursor { pVtab: table },
            binding: table_ref.binding,
            constraints: Vec::new(),
            constraint_lease: None,
            batch: Batch::default(),
            batch_lease: None,
            position: 0,
            rowid: 1,
            _lease: Lease::new(&context.quota, size_of::<Cursor>())?,
        });
        unsafe {
            *out = Box::into_raw(cursor).cast();
        }
        Ok(())
    })
}
unsafe extern "C" fn close(cursor: *mut ffi::sqlite3_vtab_cursor) -> c_int {
    unsafe {
        drop(Box::from_raw(cursor.cast::<Cursor>()));
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn filter(
    cursor: *mut ffi::sqlite3_vtab_cursor,
    number: c_int,
    encoded: *const c_char,
    argc: c_int,
    argv: *mut *mut ffi::sqlite3_value,
) -> c_int {
    let cursor = unsafe { &mut *cursor.cast::<Cursor>() };
    let binding = unsafe { &*cursor.binding };
    let context = binding.context();
    context.callback(|| {
        context.poll(1)?;
        if argc < 0 || argc != number || argc as usize > MAX_COLUMNS {
            return Err(SqlError::Provider);
        }
        cursor.constraints = Vec::new();
        cursor.constraint_lease = None;
        cursor.batch = Batch::default();
        cursor.batch_lease = None;
        cursor.position = 0;
        cursor.rowid = 1;
        if argc != 0 {
            if encoded.is_null() {
                return Err(SqlError::Provider);
            }
            let encoded = unsafe { CStr::from_ptr(encoded) }
                .to_str()
                .map_err(|_| SqlError::Provider)?;
            if encoded.len() > MAX_COLUMNS * 4 {
                return Err(SqlError::Provider);
            }
            let mut bytes = argc as usize * size_of::<Equality>();
            for index in 0..argc as usize {
                let value = unsafe { *argv.add(index) };
                if unsafe { ffi::sqlite3_value_type(value) } == ffi::SQLITE_TEXT {
                    bytes = bytes
                        .checked_add(unsafe { ffi::sqlite3_value_bytes(value) } as usize)
                        .ok_or(SqlError::MemoryLimit)?;
                }
            }
            if bytes > MAX_CELL_BYTES {
                return Err(SqlError::MemoryLimit);
            }
            let lease = Lease::new(&context.quota, bytes)?;
            cursor.constraints = Vec::with_capacity(argc as usize);
            for (index, column) in encoded.split(',').filter(|s| !s.is_empty()).enumerate() {
                if index >= argc as usize {
                    return Err(SqlError::Provider);
                }
                let column = column.parse::<usize>().map_err(|_| SqlError::Provider)?;
                if !context.tables[binding.table]
                    .equality_columns
                    .contains(&column)
                {
                    return Err(SqlError::Provider);
                }
                let value = unsafe { read_value(*argv.add(index)) }?;
                cursor.constraints.push(Equality { column, value });
            }
            if cursor.constraints.len() != argc as usize {
                return Err(SqlError::Provider);
            }
            cursor.constraint_lease = Some(lease);
        }
        // Equality to NULL cannot match any row. Do not ask a provider to invent
        // null equality semantics; no rows are a safe restriction in this case.
        if cursor.constraints.iter().any(|e| e.value == SqlCell::Null) {
            return Ok(());
        }
        cursor.load()
    })
}
unsafe extern "C" fn next(cursor: *mut ffi::sqlite3_vtab_cursor) -> c_int {
    let cursor = unsafe { &mut *cursor.cast::<Cursor>() };
    let binding = unsafe { &*cursor.binding };
    let context = binding.context();
    context.callback(|| {
        context.poll(1)?;
        cursor.position += 1;
        cursor.rowid = cursor.rowid.checked_add(1).ok_or(SqlError::WorkLimit)?;
        if cursor.position >= cursor.batch.rows.len() && cursor.batch.next.is_some() {
            cursor.load()?;
        }
        Ok(())
    })
}
unsafe extern "C" fn eof(cursor: *mut ffi::sqlite3_vtab_cursor) -> c_int {
    let cursor = unsafe { &*cursor.cast::<Cursor>() };
    i32::from(
        cursor.binding().context().status().is_err() || cursor.position >= cursor.batch.rows.len(),
    )
}
unsafe extern "C" fn column(
    cursor: *mut ffi::sqlite3_vtab_cursor,
    out: *mut ffi::sqlite3_context,
    index: c_int,
) -> c_int {
    let cursor = unsafe { &*cursor.cast::<Cursor>() };
    let context = cursor.binding().context();
    context.callback(|| {
        context.status()?;
        let value = cursor
            .batch
            .rows
            .get(cursor.position)
            .and_then(|row| usize::try_from(index).ok().and_then(|i| row.get(i)))
            .ok_or(SqlError::Provider)?;
        unsafe {
            match value {
                SqlCell::Null => ffi::sqlite3_result_null(out),
                SqlCell::Integer(n) => ffi::sqlite3_result_int64(out, *n),
                SqlCell::Real(n) => ffi::sqlite3_result_double(out, *n),
                SqlCell::Text(s) => ffi::sqlite3_result_text(
                    out,
                    s.as_ptr().cast(),
                    s.len() as c_int,
                    ffi::SQLITE_TRANSIENT(),
                ),
            }
        }
        context.status()
    })
}
unsafe extern "C" fn rowid(
    cursor: *mut ffi::sqlite3_vtab_cursor,
    out: *mut ffi::sqlite3_int64,
) -> c_int {
    let cursor = unsafe { &*cursor.cast::<Cursor>() };
    unsafe {
        *out = cursor.rowid;
    }
    ffi::SQLITE_OK
}

#[cfg(test)]
pub(super) fn test_batch_bytes(batch: &Batch) -> usize {
    batch_bytes(batch)
}
