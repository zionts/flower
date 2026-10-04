//! Quota-first, hard-owned SQL capture and typed compute frame.
//!
//! The builder maps and pre-touches every slab before accepting capture bytes.
//! JSON parsing uses only those slabs and a fixed-depth explicit stack. Sealing
//! destroys raw/support/parser/key state; SQLite sees typed authorized rows, not
//! a serving database, a provider, an owned JSON Value, or a source callback.
//! Authorization, source selection and final freshness checks belong to the
//! caller. This module does not change ordinary ctx.sql's Records HARD HOLD.
#[path = "sql_frame/control.rs"]
mod control;
#[path = "sql_frame/json.rs"]
mod json;
#[cfg(test)]
#[path = "sql_frame/mapping_tests.rs"]
mod mapping_tests;
#[path = "sql_frame/slab.rs"]
mod slab;

use super::sqlite::{self, Batch, ScanRequest, Source, SqlCell, SqlError, VirtualTable};
use control::Budget;
pub(crate) use control::FrameControl;
use json::{CaptureArena, Document, JsonNode, KeyEntry, ObjectKey, ParsedCell, TextRef};
use slab::{Slab, exact_string, exact_vec, mapped_bytes};

pub(crate) const MAX_FRAME_BYTES: usize = 128 * 1024 * 1024;
pub(crate) const MAX_CAPTURE_SLICE: usize = 64 * 1024;
const MAX_TEXT_BYTES: usize = 8 * 1024 * 1024;
const MAX_NODES: usize = 262_144;
const MAX_DOCUMENTS: usize = 20_000;
const MAX_KEYS: usize = 20_000;
const MAX_TABLES: usize = 67;
const MAX_COLUMNS: usize = 64;
const MAX_ROWS: usize = 20_000;
const MAX_CELLS: usize = MAX_ROWS * MAX_COLUMNS;
const MAX_PROVENANCE: usize = 256 * 1024;
// Explicit stack/small local arrays and both owning control structs have no
// dynamic allocation. Reserve this finite control allowance in arena admission.
const CONTROL_BYTES: usize = 64 * 1024;
const NONE: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FrameError {
    Capacity,
    Invalid,
    Unsupported,
    WorkLimit,
    Cancelled,
    Deadline,
}
impl std::fmt::Display for FrameError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Capacity => "SQL frame capacity exceeded",
            Self::Invalid => "invalid SQL frame input",
            Self::Unsupported => "unsupported SQL frame value",
            Self::WorkLimit => "SQL frame work budget exceeded",
            Self::Cancelled => "SQL frame cancelled",
            Self::Deadline => "SQL frame deadline exceeded",
        })
    }
}
impl std::error::Error for FrameError {}
impl From<FrameError> for SqlError {
    fn from(value: FrameError) -> Self {
        match value {
            FrameError::Capacity => Self::MemoryLimit,
            FrameError::Invalid => Self::Provider,
            FrameError::Unsupported => Self::UnsupportedValue,
            FrameError::WorkLimit => Self::WorkLimit,
            FrameError::Cancelled => Self::Cancelled,
            FrameError::Deadline => Self::Deadline,
        }
    }
}

/// Tests/callers may decrease caps. No cap can exceed its hard maximum.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameLimits {
    pub raw_bytes: usize,
    pub support_bytes: usize,
    pub decoded_bytes: usize,
    pub nodes: usize,
    pub documents: usize,
    pub keys: usize,
    pub key_bytes: usize,
    pub tables: usize,
    pub columns: usize,
    pub rows: usize,
    pub cells: usize,
    pub text_bytes: usize,
    pub provenance_bytes: usize,
    pub parse_work: usize,
}
impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            raw_bytes: MAX_TEXT_BYTES,
            support_bytes: MAX_TEXT_BYTES,
            decoded_bytes: MAX_TEXT_BYTES,
            nodes: MAX_NODES,
            documents: MAX_DOCUMENTS,
            keys: MAX_KEYS,
            key_bytes: MAX_TEXT_BYTES,
            tables: MAX_TABLES,
            columns: MAX_TABLES * MAX_COLUMNS,
            rows: MAX_ROWS,
            cells: MAX_CELLS,
            text_bytes: MAX_TEXT_BYTES,
            provenance_bytes: MAX_PROVENANCE,
            parse_work: 64 * 1024 * 1024,
        }
    }
}
impl FrameLimits {
    fn valid(self) -> bool {
        self.raw_bytes <= MAX_TEXT_BYTES
            && self.support_bytes <= MAX_TEXT_BYTES
            && self.decoded_bytes <= MAX_TEXT_BYTES
            && self.nodes <= MAX_NODES
            && self.documents <= MAX_DOCUMENTS
            && self.keys <= MAX_KEYS
            && self.key_bytes <= MAX_TEXT_BYTES
            && self.tables <= MAX_TABLES
            && self.columns <= MAX_TABLES * MAX_COLUMNS
            && self.rows <= MAX_ROWS
            && self.cells <= MAX_CELLS
            && self.text_bytes <= MAX_TEXT_BYTES
            && self.provenance_bytes <= MAX_PROVENANCE
            && self.parse_work <= 64 * 1024 * 1024
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum JsonBank {
    #[default]
    Raw,
    Support,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct JsonId(u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyId(u32);
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableId(u16);
impl TableId {
    pub(crate) fn index(self) -> usize {
        self.0 as usize
    }
}

pub(crate) use json::{ArenaEntry, ArenaIter, ArenaKind, ArenaValue};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum ColumnKind {
    #[default]
    Integer,
    Real,
    Text,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct FrameColumn<'a> {
    pub name: &'a str,
    pub kind: ColumnKind,
    pub nullable: bool,
    pub logical_type: Option<&'a str>,
    pub unit: Option<&'a str>,
    // Equality can be advertised to SQLite, but is always residual-only here.
    pub equality: bool,
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum SourceColumn<'a> {
    Field(&'a str),
    Key(KeyId),
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum FrameCell<'a> {
    Null,
    Integer(i64),
    Real(f64),
    Text(&'a str),
}
#[derive(Clone, Copy, Debug, Default)]
enum OwnedCell {
    #[default]
    Null,
    Integer(i64),
    Real(f64),
    Text(TextRef),
}
#[derive(Clone, Copy, Default)]
struct OwnedColumn {
    name: TextRef,
    kind: ColumnKind,
    nullable: bool,
    logical_type: TextRef,
    has_logical_type: bool,
    unit: TextRef,
    has_unit: bool,
    equality: bool,
}
#[derive(Clone, Copy, Default)]
struct OwnedTable {
    name: TextRef,
    column_start: u32,
    column_count: u16,
    row_start: u32,
    row_count: u32,
}
#[derive(Clone, Copy, Default)]
struct OwnedRow {
    table: u16,
    start: u32,
    count: u16,
}
struct TypedArena {
    text: Slab<u8>,
    tables: Slab<OwnedTable>,
    columns: Slab<OwnedColumn>,
    rows: Slab<OwnedRow>,
    cells: Slab<OwnedCell>,
    row_order: Slab<u32>,
    provenance: Slab<u8>,
    text_len: usize,
    table_len: usize,
    ordinary_tables: usize,
    column_len: usize,
    row_len: usize,
    cell_len: usize,
    provenance_len: usize,
}
impl TypedArena {
    fn text(&self, value: TextRef) -> &str {
        // All text enters from validated &str and refs are created internally.
        unsafe { std::str::from_utf8_unchecked(&self.text[value.range()]) }
    }
    fn copy_text(&mut self, text: &str) -> TextRef {
        let reference = TextRef::new(self.text_len, text.len());
        self.text[reference.range()].copy_from_slice(text.as_bytes());
        self.text_len += text.len();
        reference
    }
    fn copy_text_checked(
        &mut self,
        text: &str,
        budget: &Budget,
        control: &FrameControl<'_>,
    ) -> Result<TextRef, FrameError> {
        let reference = TextRef::new(self.text_len, text.len());
        let mut offset = self.text_len;
        for chunk in text.as_bytes().chunks(MAX_CAPTURE_SLICE) {
            budget.debit(chunk.len(), control)?;
            self.text[offset..offset + chunk.len()].copy_from_slice(chunk);
            offset += chunk.len();
        }
        self.text_len += text.len();
        Ok(reference)
    }
    fn row(&self, ordinal: usize, table: OwnedTable) -> &[OwnedCell] {
        let index = self.row_order[table.row_start as usize + ordinal] as usize;
        let row = self.rows[index];
        &self.cells[row.start as usize..row.start as usize + row.count as usize]
    }
    fn column(&self, table: OwnedTable, index: usize) -> OwnedColumn {
        self.columns[table.column_start as usize + index]
    }
    fn bytes(&self) -> usize {
        self.text.mapped_bytes()
            + self.tables.mapped_bytes()
            + self.columns.mapped_bytes()
            + self.rows.mapped_bytes()
            + self.cells.mapped_bytes()
            + self.row_order.mapped_bytes()
            + self.provenance.mapped_bytes()
    }
}

/// Capturing/parsing phase only. No reference to the serving database is stored.
pub(crate) struct FrameBuilder {
    capture: CaptureArena,
    typed: TypedArena,
    failed: Option<FrameError>,
    allocation_bytes: usize,
}
impl FrameBuilder {
    pub(crate) fn new(limits: FrameLimits, control: &FrameControl<'_>) -> Result<Self, FrameError> {
        control.check()?;
        if !limits.valid() {
            return Err(FrameError::Capacity);
        }
        let index_slots = limits
            .nodes
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(FrameError::Capacity)?;
        // The admission pass happens before ANY arena mapping, initialization or
        // capture. Page rounding, descriptors, row indexes, parser key index,
        // all raw/support/key bytes and finite control reserve are included.
        let sizes = [
            mapped_bytes::<u8>(limits.raw_bytes)?,
            mapped_bytes::<u8>(limits.support_bytes)?,
            mapped_bytes::<u8>(limits.decoded_bytes)?,
            mapped_bytes::<JsonNode>(limits.nodes)?,
            mapped_bytes::<Document>(limits.documents)?,
            mapped_bytes::<ObjectKey>(index_slots)?,
            mapped_bytes::<KeyEntry>(limits.keys)?,
            mapped_bytes::<u8>(limits.key_bytes)?,
            mapped_bytes::<u8>(limits.text_bytes)?,
            mapped_bytes::<OwnedTable>(limits.tables)?,
            mapped_bytes::<OwnedColumn>(limits.columns)?,
            mapped_bytes::<OwnedRow>(limits.rows)?,
            mapped_bytes::<OwnedCell>(limits.cells)?,
            mapped_bytes::<u32>(limits.rows)?,
            mapped_bytes::<u8>(limits.provenance_bytes)?,
        ];
        let allocation_bytes = sizes.iter().try_fold(CONTROL_BYTES, |sum, bytes| {
            sum.checked_add(*bytes).ok_or(FrameError::Capacity)
        })?;
        if allocation_bytes > MAX_FRAME_BYTES {
            return Err(FrameError::Capacity);
        }
        Ok(Self {
            capture: CaptureArena::new(limits, index_slots, control)?,
            typed: TypedArena {
                text: Slab::new(limits.text_bytes, control)?,
                tables: Slab::new(limits.tables, control)?,
                columns: Slab::new(limits.columns, control)?,
                rows: Slab::new(limits.rows, control)?,
                cells: Slab::new(limits.cells, control)?,
                row_order: Slab::new(limits.rows, control)?,
                provenance: Slab::new(limits.provenance_bytes, control)?,
                text_len: 0,
                table_len: 0,
                ordinary_tables: 0,
                column_len: 0,
                row_len: 0,
                cell_len: 0,
                provenance_len: 0,
            },
            failed: None,
            allocation_bytes,
        })
    }
    fn healthy(&self) -> Result<(), FrameError> {
        self.failed.or(self.capture.failure()).map_or(Ok(()), Err)
    }
    fn keep<T>(&mut self, result: Result<T, FrameError>) -> Result<T, FrameError> {
        if let Err(error) = result {
            self.failed.get_or_insert(error);
        }
        result
    }
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.allocation_bytes
    }
    pub(crate) fn reserve_json(
        &mut self,
        bank: JsonBank,
        byte_len: usize,
    ) -> Result<JsonId, FrameError> {
        self.healthy()?;
        let result = self.capture.reserve(bank, byte_len);
        self.keep(result)
    }
    pub(crate) fn append_json_chunk(&mut self, id: JsonId, bytes: &[u8]) -> Result<(), FrameError> {
        self.healthy()?;
        let result = self.capture.append(id, bytes);
        self.keep(result)
    }
    pub(crate) fn finish_json(
        &mut self,
        id: JsonId,
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.healthy()?;
        let result = self.capture.finish(id, control);
        self.keep(result)
    }
    pub(crate) fn raw_json(&self, id: JsonId) -> Result<&str, FrameError> {
        self.healthy()?;
        self.capture.raw_json(id)
    }
    pub(crate) fn json<'a>(
        &'a self,
        id: JsonId,
        control: &'a FrameControl<'a>,
    ) -> Result<ArenaValue<'a>, FrameError> {
        self.healthy()?;
        self.capture.value(id, control)
    }
    pub(crate) fn retain_key(&mut self, key: &str) -> Result<KeyId, FrameError> {
        self.healthy()?;
        let result = self.capture.retain_key(key);
        self.keep(result)
    }
    pub(crate) fn key(&self, id: KeyId) -> Result<&str, FrameError> {
        self.healthy()?;
        self.capture.key(id)
    }
    /// Caller supplies trusted provenance; no parser/SQL value can populate it.
    pub(crate) fn append_provenance(&mut self, bytes: &[u8]) -> Result<(), FrameError> {
        self.healthy()?;
        let result = (|| {
            let end = self
                .typed
                .provenance_len
                .checked_add(bytes.len())
                .filter(|end| *end <= self.typed.provenance.len())
                .ok_or(FrameError::Capacity)?;
            self.typed.provenance[self.typed.provenance_len..end].copy_from_slice(bytes);
            self.typed.provenance_len = end;
            Ok(())
        })();
        self.keep(result)
    }
    pub(crate) fn add_table(
        &mut self,
        name: &str,
        columns: &[FrameColumn<'_>],
    ) -> Result<TableId, FrameError> {
        self.healthy()?;
        let result = self.add_table_inner(name, columns);
        self.keep(result)
    }
    fn add_table_inner(
        &mut self,
        name: &str,
        columns: &[FrameColumn<'_>],
    ) -> Result<TableId, FrameError> {
        let metadata = matches!(name, "sql_tables" | "sql_columns" | "sql_relationships");
        if !identifier(name)
            || matches!(
                name,
                "sqlite_master" | "sqlite_schema" | "sqlite_temp_master" | "sqlite_temp_schema"
            )
            || columns.is_empty()
            || columns.len() > MAX_COLUMNS
            || self.typed.tables[..self.typed.table_len]
                .iter()
                .any(|table| self.typed.text(table.name) == name)
        {
            return Err(FrameError::Invalid);
        }
        if self.typed.table_len >= self.typed.tables.len()
            || (!metadata && self.typed.ordinary_tables >= 64)
            || columns.len() > self.typed.columns.len() - self.typed.column_len
        {
            return Err(FrameError::Capacity);
        }
        let mut text_bytes = name.len();
        for (index, column) in columns.iter().enumerate() {
            if !identifier(column.name)
                || columns[..index].iter().any(|prev| prev.name == column.name)
                || column.logical_type.is_some_and(|text| text.len() > 16_384)
                || column.unit.is_some_and(|text| text.len() > 16_384)
            {
                return Err(FrameError::Invalid);
            }
            text_bytes = add(text_bytes, column.name.len())?;
            text_bytes = add(text_bytes, column.logical_type.map_or(0, str::len))?;
            text_bytes = add(text_bytes, column.unit.map_or(0, str::len))?;
        }
        if text_bytes > self.typed.text.len() - self.typed.text_len {
            return Err(FrameError::Capacity);
        }
        let table_index = self.typed.table_len;
        let table_name = self.typed.copy_text(name);
        let column_start = self.typed.column_len;
        for column in columns {
            let name = self.typed.copy_text(column.name);
            let logical_type = self.typed.copy_text(column.logical_type.unwrap_or(""));
            let unit = self.typed.copy_text(column.unit.unwrap_or(""));
            self.typed.columns[self.typed.column_len] = OwnedColumn {
                name,
                kind: column.kind,
                nullable: column.nullable,
                logical_type,
                has_logical_type: column.logical_type.is_some(),
                unit,
                has_unit: column.unit.is_some(),
                equality: column.equality,
            };
            self.typed.column_len += 1;
        }
        self.typed.tables[table_index] = OwnedTable {
            name: table_name,
            column_start: column_start as u32,
            column_count: columns.len() as u16,
            row_start: 0,
            row_count: 0,
        };
        self.typed.table_len += 1;
        self.typed.ordinary_tables += usize::from(!metadata);
        Ok(TableId(table_index as u16))
    }
    pub(crate) fn insert_row(
        &mut self,
        table: TableId,
        cells: &[FrameCell<'_>],
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.healthy()?;
        let result = self.insert_row_inner(table, cells, control);
        self.keep(result)
    }
    fn insert_row_inner(
        &mut self,
        table: TableId,
        cells: &[FrameCell<'_>],
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.capture.budget.check(control)?;
        let descriptor = self.table_descriptor(table)?;
        self.row_capacity(descriptor, cells.len())?;
        let mut bytes = 0;
        for (index, cell) in cells.iter().enumerate() {
            validate_cell(self.typed.column(descriptor, index), *cell)?;
            if let FrameCell::Text(text) = cell {
                bytes = add(bytes, text.len())?;
            }
        }
        if bytes > self.typed.text.len() - self.typed.text_len {
            return Err(FrameError::Capacity);
        }
        let start = self.typed.cell_len;
        for cell in cells {
            self.capture.budget.debit(1, control)?;
            let owned = match *cell {
                FrameCell::Null => OwnedCell::Null,
                FrameCell::Integer(value) => OwnedCell::Integer(value),
                FrameCell::Real(value) => OwnedCell::Real(value),
                FrameCell::Text(text) => OwnedCell::Text(self.typed.copy_text_checked(
                    text,
                    &self.capture.budget,
                    control,
                )?),
            };
            self.typed.cells[self.typed.cell_len] = owned;
            self.typed.cell_len += 1;
        }
        self.finish_row(table, start, cells.len());
        Ok(())
    }
    /// Direct scalar projection from an already policy-approved raw source.
    /// Physical field names and retained keys are used only while building and
    /// are never stored in sealed descriptors. Source ACL must run BEFORE this.
    pub(crate) fn insert_source_row(
        &mut self,
        table: TableId,
        document: JsonId,
        projection: &[SourceColumn<'_>],
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.healthy()?;
        let result = self.insert_source_row_inner(table, document, projection, control);
        self.keep(result)
    }
    fn insert_source_row_inner(
        &mut self,
        table: TableId,
        document: JsonId,
        projection: &[SourceColumn<'_>],
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        let descriptor = self.table_descriptor(table)?;
        self.row_capacity(descriptor, projection.len())?;
        let source = self.capture.value(document, control)?;
        let mut cells = [FrameCell::Null; MAX_COLUMNS];
        let mut bytes = 0usize;
        for (index, selection) in projection.iter().enumerate() {
            let column = self.typed.column(descriptor, index);
            let cell = match *selection {
                SourceColumn::Key(key) => FrameCell::Text(self.capture.key(key)?),
                SourceColumn::Field(field) => match source.get(field)? {
                    None => FrameCell::Null,
                    Some(value) if value.is_null() => FrameCell::Null,
                    Some(value) => match column.kind {
                        ColumnKind::Integer => FrameCell::Integer(
                            value.source_integer()?.ok_or(FrameError::Unsupported)?,
                        ),
                        ColumnKind::Real => {
                            FrameCell::Real(value.as_f64()?.ok_or(FrameError::Unsupported)?)
                        }
                        ColumnKind::Text => {
                            FrameCell::Text(value.as_str().ok_or(FrameError::Unsupported)?)
                        }
                    },
                },
            };
            validate_cell(column, cell)?;
            if let FrameCell::Text(text) = cell {
                bytes = add(bytes, text.len())?;
            }
            cells[index] = cell;
        }
        if bytes > self.typed.text.len() - self.typed.text_len {
            return Err(FrameError::Capacity);
        }
        let start = self.typed.cell_len;
        for cell in &cells[..projection.len()] {
            self.capture.budget.debit(1, control)?;
            self.typed.cells[self.typed.cell_len] = match *cell {
                FrameCell::Null => OwnedCell::Null,
                FrameCell::Integer(value) => OwnedCell::Integer(value),
                FrameCell::Real(value) => OwnedCell::Real(value),
                FrameCell::Text(text) => OwnedCell::Text(self.typed.copy_text_checked(
                    text,
                    &self.capture.budget,
                    control,
                )?),
            };
            self.typed.cell_len += 1;
        }
        self.finish_row(table, start, projection.len());
        Ok(())
    }
    fn table_descriptor(&self, table: TableId) -> Result<OwnedTable, FrameError> {
        if table.index() >= self.typed.table_len {
            return Err(FrameError::Invalid);
        }
        Ok(self.typed.tables[table.index()])
    }
    fn row_capacity(&self, table: OwnedTable, cells: usize) -> Result<(), FrameError> {
        if cells != table.column_count as usize {
            return Err(FrameError::Invalid);
        }
        if self.typed.row_len >= self.typed.rows.len()
            || cells > self.typed.cells.len() - self.typed.cell_len
        {
            return Err(FrameError::Capacity);
        }
        Ok(())
    }
    fn finish_row(&mut self, table: TableId, start: usize, count: usize) {
        self.typed.rows[self.typed.row_len] = OwnedRow {
            table: table.0,
            start: start as u32,
            count: count as u16,
        };
        self.typed.row_len += 1;
        self.typed.tables[table.index()].row_count += 1;
    }
    /// Native actor output: a JSON array of null or single-tag typed cells.
    /// Conversion does not construct a Value or allocate a temporary row Vec.
    pub(crate) fn insert_tagged_row(
        &mut self,
        table: TableId,
        document: JsonId,
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.healthy()?;
        let result = self
            .capture
            .document_root(document)
            .and_then(|root| self.insert_arena_row(table, root, control));
        self.keep(result)
    }
    /// Convenience for a guest's array of typed rows; any error poisons the
    /// entire frame, including rows already admitted from earlier documents.
    pub(crate) fn insert_tagged_rows(
        &mut self,
        table: TableId,
        document: JsonId,
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.healthy()?;
        let result = (|| {
            let root = self.capture.document_root(document)?;
            let mut row = self.capture.array_first(root, control)?;
            while row != NONE {
                let next = self.capture.node(row).next;
                self.insert_arena_row(table, row, control)?;
                row = next;
            }
            Ok(())
        })();
        self.keep(result)
    }
    fn insert_arena_row(
        &mut self,
        table: TableId,
        root: u32,
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        let descriptor = self.table_descriptor(table)?;
        let first = self.capture.array_first(root, control)?;
        // A fixed stack row is finite control, not growing parser scratch. Text
        // refs point into capture only during this method and are copied below.
        let mut converted = [ParsedCell::Null; MAX_COLUMNS];
        let mut cursor = first;
        let mut count = 0;
        let mut bytes = 0;
        while cursor != NONE {
            if count >= descriptor.column_count as usize {
                return Err(FrameError::Invalid);
            }
            let value = self.capture.tagged_cell(cursor, control)?;
            let borrowed = value.borrow(&self.capture);
            validate_cell(self.typed.column(descriptor, count), borrowed)?;
            if let ParsedCell::Text(text) = value {
                bytes = add(bytes, text.len as usize)?;
            }
            converted[count] = value;
            count += 1;
            cursor = self.capture.node(cursor).next;
        }
        self.row_capacity(descriptor, count)?;
        if bytes > self.typed.text.len() - self.typed.text_len {
            return Err(FrameError::Capacity);
        }
        let start = self.typed.cell_len;
        for cell in &converted[..count] {
            self.typed.cells[self.typed.cell_len] = match *cell {
                ParsedCell::Null => OwnedCell::Null,
                ParsedCell::Integer(value) => OwnedCell::Integer(value),
                ParsedCell::Real(value) => OwnedCell::Real(value),
                ParsedCell::Text(text) => OwnedCell::Text(self.typed.copy_text_checked(
                    self.capture.text(text),
                    &self.capture.budget,
                    control,
                )?),
            };
            self.typed.cell_len += 1;
        }
        self.finish_row(table, start, count);
        Ok(())
    }
    /// Consumes capture capability and drops ALL raw/support/parser/key slabs.
    /// The return type cannot contain a provider, Records, Value, or key handle.
    pub(crate) fn seal(self, control: &FrameControl<'_>) -> Result<SealedSqlFrame, FrameError> {
        self.healthy()?;
        self.capture.budget.check(control)?;
        if self.capture.has_unfinished_documents() {
            return Err(FrameError::Invalid);
        }
        let Self {
            capture,
            mut typed,
            failed: _,
            allocation_bytes: _,
        } = self;
        let mut offset = 0u32;
        let mut filled = [0u32; MAX_TABLES];
        for table in &mut typed.tables[..typed.table_len] {
            capture.budget.debit(1, control)?;
            table.row_start = offset;
            offset += table.row_count;
        }
        for (index, row) in typed.rows[..typed.row_len].iter().enumerate() {
            capture.budget.debit(1, control)?;
            let table = row.table as usize;
            typed.row_order[typed.tables[table].row_start as usize + filled[table] as usize] =
                index as u32;
            filled[table] += 1;
        }
        capture.budget.check(control)?;
        drop(capture);
        let allocation_bytes = typed.bytes() + CONTROL_BYTES;
        Ok(SealedSqlFrame {
            typed,
            allocation_bytes,
        })
    }
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.as_bytes()[0].is_ascii_lowercase()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}
fn add(left: usize, right: usize) -> Result<usize, FrameError> {
    left.checked_add(right).ok_or(FrameError::Capacity)
}
fn mul(left: usize, right: usize) -> Result<usize, FrameError> {
    left.checked_mul(right).ok_or(FrameError::Capacity)
}
fn validate_cell(column: OwnedColumn, cell: FrameCell<'_>) -> Result<(), FrameError> {
    match cell {
        FrameCell::Null if column.nullable => Ok(()),
        FrameCell::Integer(_) if column.kind == ColumnKind::Integer => Ok(()),
        FrameCell::Real(value) if column.kind == ColumnKind::Real && value.is_finite() => Ok(()),
        FrameCell::Text(text) if column.kind == ColumnKind::Text => {
            if text.len() > sqlite::MAX_CELL_BYTES {
                Err(FrameError::Capacity)
            } else {
                Ok(())
            }
        }
        _ => Err(FrameError::Unsupported),
    }
}

/// Only owned logical descriptors, typed scalars/text and trusted provenance.
/// No capture getter or provider callback exists on the sealed type.
pub(crate) struct SealedSqlFrame {
    typed: TypedArena,
    allocation_bytes: usize,
}
pub(crate) struct TableView<'a> {
    pub name: &'a str,
    pub columns: usize,
    pub rows: usize,
}
pub(crate) struct ColumnView<'a> {
    pub name: &'a str,
    pub kind: ColumnKind,
    pub nullable: bool,
    pub logical_type: Option<&'a str>,
    pub unit: Option<&'a str>,
}
impl SealedSqlFrame {
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.allocation_bytes
    }
    pub(crate) fn table_count(&self) -> usize {
        self.typed.table_len
    }
    pub(crate) fn table(&self, index: usize) -> Option<TableView<'_>> {
        let table = *self.typed.tables[..self.typed.table_len].get(index)?;
        Some(TableView {
            name: self.typed.text(table.name),
            columns: table.column_count as usize,
            rows: table.row_count as usize,
        })
    }
    pub(crate) fn column(&self, table: usize, index: usize) -> Option<ColumnView<'_>> {
        let table = *self.typed.tables[..self.typed.table_len].get(table)?;
        if index >= table.column_count as usize {
            return None;
        }
        let column = self.typed.column(table, index);
        Some(ColumnView {
            name: self.typed.text(column.name),
            kind: column.kind,
            nullable: column.nullable,
            logical_type: column
                .has_logical_type
                .then(|| self.typed.text(column.logical_type)),
            unit: column.has_unit.then(|| self.typed.text(column.unit)),
        })
    }
    /// Internal trusted channel only. Never exposed as a SQL relation/column.
    pub(crate) fn provenance(&self) -> &[u8] {
        &self.typed.provenance[..self.typed.provenance_len]
    }
    /// The caller reserves this separate native descriptor budget BEFORE use.
    /// Capacity arithmetic is exact, including every Vec/String capacity.
    pub(crate) fn native_tables(&self, max_bytes: usize) -> Result<Vec<VirtualTable>, FrameError> {
        let mut bytes = mul(self.typed.table_len, size_of::<VirtualTable>())?;
        for table in &self.typed.tables[..self.typed.table_len] {
            bytes = add(bytes, table.name.len as usize)?;
            bytes = add(
                bytes,
                mul(table.column_count as usize, size_of::<String>())?,
            )?;
            for index in 0..table.column_count as usize {
                let column = self.typed.column(*table, index);
                bytes = add(bytes, column.name.len as usize)?;
                if column.equality {
                    bytes = add(bytes, size_of::<usize>())?;
                }
            }
        }
        if bytes > max_bytes {
            return Err(FrameError::Capacity);
        }
        let mut tables = exact_vec(self.typed.table_len)?;
        for table in &self.typed.tables[..self.typed.table_len] {
            let mut columns = exact_vec(table.column_count as usize)?;
            let equality_count = (0..table.column_count as usize)
                .filter(|index| self.typed.column(*table, *index).equality)
                .count();
            let mut equality_columns = exact_vec(equality_count)?;
            for index in 0..table.column_count as usize {
                let column = self.typed.column(*table, index);
                columns.push(exact_string(self.typed.text(column.name))?);
                if column.equality {
                    equality_columns.push(index);
                }
            }
            tables.push(VirtualTable {
                name: exact_string(self.typed.text(table.name))?,
                columns,
                equality_columns,
            });
        }
        Ok(tables)
    }
    fn scan_inner(&self, request: ScanRequest<'_>) -> Result<Batch, FrameError> {
        let table = *self.typed.tables[..self.typed.table_len]
            .get(request.table)
            .ok_or(FrameError::Invalid)?;
        if request.limit == 0
            || request
                .constraints
                .iter()
                .any(|value| value.column >= table.column_count as usize)
        {
            return Err(FrameError::Invalid);
        }
        let start = match request.after {
            Some(token) => parse_token(token, request.table)?,
            None => 0,
        };
        let total = table.row_count as usize;
        if start > total {
            return Err(FrameError::Invalid);
        }
        if start == total {
            return Ok(Batch::default());
        }
        let cap = request.limit.min(total - start);
        let mut bytes = 0usize;
        let mut count = 0usize;
        let mut token = [0u8; 32];
        // Two-pass output: count and charge exact capacities before the first
        // Rust allocation. Row/text copies are lazy, only for the selected batch.
        for ordinal in start..start + cap {
            let row = self.typed.row(ordinal, table);
            let mut row_bytes = add(
                size_of::<Vec<SqlCell>>(),
                mul(row.len(), size_of::<SqlCell>())?,
            )?;
            for cell in row {
                if let OwnedCell::Text(text) = cell {
                    row_bytes = add(row_bytes, text.len as usize)?;
                }
            }
            let proposed = add(bytes, row_bytes)?;
            let end = ordinal + 1;
            let token_bytes = if end < total {
                format_token(request.table, end, &mut token).len()
            } else {
                0
            };
            if add(proposed, token_bytes)? > request.max_bytes {
                if count == 0 {
                    return Err(FrameError::Capacity);
                }
                break;
            }
            bytes = proposed;
            count += 1;
        }
        let end = start + count;
        let next = (end < total).then(|| format_token(request.table, end, &mut token));
        // The token for the accepted final ordinal can have fewer digits than
        // the last rejected candidate. Recompute before any allocation.
        if add(bytes, next.map_or(0, str::len))? > request.max_bytes {
            return Err(FrameError::Capacity);
        }
        let mut rows = exact_vec(count)?;
        for ordinal in start..end {
            let stored = self.typed.row(ordinal, table);
            let mut row = exact_vec(stored.len())?;
            for cell in stored {
                row.push(match *cell {
                    OwnedCell::Null => SqlCell::Null,
                    OwnedCell::Integer(value) => SqlCell::Integer(value),
                    OwnedCell::Real(value) => SqlCell::Real(value),
                    OwnedCell::Text(text) => SqlCell::Text(exact_string(self.typed.text(text))?),
                });
            }
            rows.push(row);
        }
        Ok(Batch {
            rows,
            next: next.map(exact_string).transpose()?,
        })
    }
}
impl Source for SealedSqlFrame {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError> {
        // Never push candidate equality into Flower or claim it is authoritative.
        // SQLite's virtual-table omit=false performs all residual comparisons.
        self.scan_inner(request).map_err(Into::into)
    }
}
fn format_token(table: usize, ordinal: usize, buffer: &mut [u8; 32]) -> &str {
    // Hard caps table<=67 and ordinal<=20000 require at most eight bytes.
    let mut cursor = 0;
    for (index, value) in [table, ordinal].into_iter().enumerate() {
        if index == 1 {
            buffer[cursor] = b':';
            cursor += 1;
        }
        let mut digits = [0u8; 20];
        let mut used = 0;
        let mut value = value;
        loop {
            digits[used] = b'0' + (value % 10) as u8;
            used += 1;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        for digit in digits[..used].iter().rev() {
            buffer[cursor] = *digit;
            cursor += 1;
        }
    }
    unsafe { std::str::from_utf8_unchecked(&buffer[..cursor]) }
}
fn parse_token(token: &str, table: usize) -> Result<usize, FrameError> {
    if token.len() > 8 {
        return Err(FrameError::Invalid);
    }
    let (prefix, ordinal) = token.split_once(':').ok_or(FrameError::Invalid)?;
    fn decimal(text: &str) -> Result<usize, FrameError> {
        if text.is_empty() || (text.len() > 1 && text.starts_with('0')) {
            return Err(FrameError::Invalid);
        }
        text.bytes().try_fold(0usize, |value, digit| {
            if !digit.is_ascii_digit() {
                return Err(FrameError::Invalid);
            }
            value
                .checked_mul(10)
                .and_then(|value| value.checked_add((digit - b'0') as usize))
                .ok_or(FrameError::Invalid)
        })
    }
    if decimal(prefix)? != table {
        return Err(FrameError::Invalid);
    }
    let ordinal = decimal(ordinal)?;
    if ordinal == 0 || ordinal > MAX_ROWS {
        return Err(FrameError::Invalid);
    }
    Ok(ordinal)
}

#[cfg(test)]
#[path = "sql_frame/tests.rs"]
mod tests;
