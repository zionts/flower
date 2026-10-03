//! Native SQLite's lazy Source, fed exclusively by same-snapshot authorized rows.
use super::*;
use crate::evaluator::sqlite::{
    self, Batch, Equality, QueryOptions, ScanRequest, Source, SqlCell, SqlError, VirtualTable,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::ops::Bound;
use std::rc::Rc;

fn native_error(error: SqlError) -> EngineError {
    let code = match error {
        SqlError::InvalidRequest => "SQL_INPUT_INVALID",
        SqlError::Forbidden => "SQL_FORBIDDEN",
        SqlError::InvalidSql => "SQL_INVALID",
        SqlError::MemoryLimit => "SQL_MEMORY_BUDGET",
        SqlError::WorkLimit => "SQL_WORK_BUDGET",
        SqlError::Cancelled => "SQL_CANCELLED",
        SqlError::Deadline => "SQL_DEADLINE",
        SqlError::Provider => "SQL_PROVIDER_FAILED",
        SqlError::OutputLimit => "SQL_OUTPUT_BUDGET",
        SqlError::UnsupportedValue => "SQL_VALUE_INVALID",
        SqlError::Unavailable => "SQL_UNAVAILABLE",
    };
    EngineError::new(code, error.to_string())
}
fn encode_cell(cell: &SqlCell) -> Value {
    match cell {
        SqlCell::Null => Value::Null,
        SqlCell::Integer(integer) => json!({"integer":integer.to_string()}),
        SqlCell::Real(real) => json!({"real":real}),
        SqlCell::Text(text) => json!({"text":text}),
    }
}
fn parse_cell(value: &Value) -> EngineResult<SqlCell> {
    if value.is_null() {
        return Ok(SqlCell::Null);
    }
    let object = value
        .as_object()
        .filter(|object| object.len() == 1)
        .ok_or_else(|| EngineError::new("SQL_PROVIDER_INVALID", "Invalid typed SQL cell"))?;
    if let Some(value) = object.get("integer").and_then(Value::as_str) {
        let integer = value
            .parse::<i64>()
            .ok()
            .filter(|integer| integer.to_string() == value)
            .ok_or_else(|| {
                EngineError::new(
                    "SQL_INTEGER_OVERFLOW",
                    "SQL integer is outside signed 64-bit range",
                )
            })?;
        return Ok(SqlCell::Integer(integer));
    }
    if let Some(value) = object
        .get("real")
        .and_then(Value::as_f64)
        .filter(|value| value.is_finite())
    {
        return Ok(SqlCell::Real(value));
    }
    if let Some(value) = object
        .get("text")
        .and_then(Value::as_str)
        .filter(|value| value.len() <= catalog::MAX_OUTPUT_BYTES)
    {
        return Ok(SqlCell::Text(value.to_owned()));
    }
    Err(EngineError::new(
        "SQL_PROVIDER_INVALID",
        "Invalid typed SQL cell",
    ))
}
fn source_cell(
    column: &catalog::Column,
    key: &str,
    value: &Value,
    cell: &Value,
) -> EngineResult<SqlCell> {
    if column.source_key == Some(true) {
        return Ok(SqlCell::Text(key.to_owned()));
    }
    let Some(field) = &column.source_field else {
        return parse_cell(cell);
    };
    let value = value.get(field).unwrap_or(&Value::Null);
    if value.is_null() {
        return Ok(SqlCell::Null);
    }
    match column.column_type {
        catalog::ColumnType::Text => value
            .as_str()
            .map(|text| SqlCell::Text(text.to_owned()))
            .ok_or_else(|| {
                EngineError::new(
                    "SQL_PROVIDER_INVALID",
                    "SQL source column has an invalid type",
                )
            }),
        catalog::ColumnType::Real => value
            .as_f64()
            .filter(|number| number.is_finite())
            .map(SqlCell::Real)
            .ok_or_else(|| {
                EngineError::new(
                    "SQL_PROVIDER_INVALID",
                    "SQL source column has an invalid type",
                )
            }),
        catalog::ColumnType::Integer => {
            if let Some(boolean) = value.as_bool() {
                return Ok(SqlCell::Integer(i64::from(boolean)));
            }
            if let Some(integer) = value.as_str() {
                return parse_cell(&json!({"integer":integer}));
            }
            let integer = value
                .as_f64()
                .filter(|number| number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0)
                .map(|number| number as i64);
            integer.map(SqlCell::Integer).ok_or_else(|| {
                EngineError::new(
                    "SQL_INTEGER_OVERFLOW",
                    "Native source integer must be exact decimal text or a safe JSON integer",
                )
            })
        }
    }
}
fn cells_bytes(rows: &VecDeque<Vec<SqlCell>>) -> usize {
    rows.iter().fold(0usize, |total, row| {
        total.saturating_add(
            64 + row.len() * 64
                + row
                    .iter()
                    .map(|cell| match cell {
                        SqlCell::Text(text) => text.capacity(),
                        _ => 0,
                    })
                    .sum::<usize>(),
        )
    })
}
type CandidatePage = (Vec<(String, Arc<Value>)>, Option<String>, bool);

struct Cursor {
    table: usize,
    constraints: Vec<Equality>,
    source: usize,
    last: Option<String>,
    pending: VecDeque<Vec<SqlCell>>,
    done: bool,
    generation: u64,
}
struct Providers<'a, 'e> {
    engine: Rc<RefCell<&'a mut Engine<'e>>>,
    catalog: &'a Catalog,
    purpose: Value,
    provenance: BTreeSet<String>,
    cursors: HashMap<u64, Cursor>,
    next_cursor: u64,
    metadata: Vec<Vec<Vec<SqlCell>>>,
}
impl Providers<'_, '_> {
    fn scan_engine(&mut self, request: ScanRequest<'_>) -> EngineResult<Batch> {
        self.engine.borrow_mut().sql_check()?;
        if request.table >= self.catalog.tables.len() {
            let metadata_index = request.table - self.catalog.tables.len();
            let rows = self.metadata.get(metadata_index).ok_or_else(|| {
                EngineError::new("SQL_PROVIDER_INVALID", "Unknown SQL metadata table")
            })?;
            let offset: usize = request
                .after
                .map(str::parse)
                .transpose()
                .map_err(|_| {
                    EngineError::new("SQL_PROVIDER_INVALID", "Invalid metadata continuation")
                })?
                .unwrap_or(0);
            let end = offset.saturating_add(request.limit).min(rows.len());
            let selected = rows.get(offset..end).ok_or_else(|| {
                EngineError::new("SQL_PROVIDER_INVALID", "Invalid metadata continuation")
            })?;
            let bytes = std::mem::size_of_val(selected)
                + selected
                    .iter()
                    .map(|row| {
                        row.len() * std::mem::size_of::<SqlCell>()
                            + row
                                .iter()
                                .map(|cell| match cell {
                                    SqlCell::Text(text) => text.len(),
                                    _ => 0,
                                })
                                .sum::<usize>()
                    })
                    .sum::<usize>()
                + 32;
            if bytes > request.max_bytes {
                return self.engine.borrow_mut().abort(
                    "SQL_BRIDGE_BUDGET",
                    "SQL metadata batch exceeds reserved allowance",
                );
            }
            let batch = selected.to_vec();
            return Ok(Batch {
                rows: batch,
                next: (end < rows.len()).then(|| end.to_string()),
            });
        }
        if request
            .constraints
            .iter()
            .map(|constraint| match &constraint.value {
                SqlCell::Text(text) => text.len() + 128,
                _ => 128,
            })
            .sum::<usize>()
            > request.max_bytes.min(512 * 1024)
        {
            return self.engine.borrow_mut().abort(
                "SQL_BRIDGE_BUDGET",
                "SQL cursor constraint allowance exceeded",
            );
        }
        if self.cursors.len() >= 64 && request.after.is_none() {
            return self.engine.borrow_mut().abort(
                "SQL_BRIDGE_BUDGET",
                "SQL active source-cursor allowance exceeded",
            );
        }
        let (id, mut cursor) = match request.after {
            None => {
                self.next_cursor += 1;
                (
                    self.next_cursor,
                    Cursor {
                        table: request.table,
                        constraints: request.constraints.to_vec(),
                        source: 0,
                        last: None,
                        pending: VecDeque::new(),
                        done: false,
                        generation: 0,
                    },
                )
            }
            Some(token) => {
                let (id, generation) = token.split_once(':').ok_or_else(|| {
                    EngineError::new("SQL_PROVIDER_INVALID", "Invalid SQL source continuation")
                })?;
                let id = id.parse::<u64>().map_err(|_| {
                    EngineError::new("SQL_PROVIDER_INVALID", "Invalid SQL source continuation")
                })?;
                let generation = generation.parse::<u64>().map_err(|_| {
                    EngineError::new("SQL_PROVIDER_INVALID", "Invalid SQL source continuation")
                })?;
                let cursor = self
                    .cursors
                    .remove(&id)
                    .filter(|cursor| {
                        cursor.generation == generation
                            && cursor.table == request.table
                            && cursor.constraints == request.constraints
                    })
                    .ok_or_else(|| {
                        EngineError::new("SQL_PROVIDER_INVALID", "Invalid SQL source continuation")
                    })?;
                (id, cursor)
            }
        };
        let table = &self.catalog.tables[cursor.table];
        let mut output = Vec::new();
        while output.len() < request.limit {
            while output.len() < request.limit {
                let Some(row) = cursor.pending.pop_front() else {
                    break;
                };
                output.push(row);
            }
            if output.len() == request.limit || cursor.done {
                break;
            }
            if cursor.source >= table.sources.len() {
                cursor.done = true;
                break;
            }
            let source = &table.sources[cursor.source];
            let mut engine = self.engine.borrow_mut();
            engine.sql_check()?;
            let (rows, last, finished) = engine.sql_candidates(
                table,
                source,
                &cursor.constraints,
                cursor.last.as_deref(),
            )?;
            cursor.last = last;
            if finished {
                cursor.source += 1;
                cursor.last = None;
            }
            if rows.is_empty() {
                continue;
            }
            let input = json!({"source":{"name":source.name},"rows":rows.iter().map(|(key,value)|json!({"key":key,"value":value})).collect::<Vec<_>>(),"purpose":self.purpose});
            let projected = engine.sql_callback(Callback::Provider, &table.provider, &input)?;
            if allocation_cost(&projected) > request.max_bytes.min(512 * 1024) {
                return engine.abort(
                    "SQL_BRIDGE_BUDGET",
                    "SQL provider output exceeds bounded bridge allowance",
                );
            }
            let projected_rows =
                projected
                    .get("rows")
                    .and_then(Value::as_array)
                    .ok_or_else(|| {
                        EngineError::new(
                            "SQL_PROVIDER_INVALID",
                            "SQL provider must return projected rows",
                        )
                    })?;
            engine.sql.projected_rows = engine
                .sql
                .projected_rows
                .saturating_add(projected_rows.len());
            if engine.sql.projected_rows > catalog::MAX_PROVIDER_ROWS {
                return engine.abort("SQL_SOURCE_BUDGET", "SQL projected-row budget exceeded");
            }
            for row in projected_rows {
                let ordinal = row
                    .get("sourceRow")
                    .and_then(Value::as_u64)
                    .and_then(|ordinal| usize::try_from(ordinal).ok())
                    .filter(|ordinal| *ordinal < rows.len())
                    .ok_or_else(|| {
                        EngineError::new(
                            "SQL_PROVIDER_INVALID",
                            "SQL projected row lacks a valid source binding",
                        )
                    })?;
                let cells = row
                    .get("cells")
                    .and_then(Value::as_array)
                    .filter(|cells| cells.len() == table.columns.len())
                    .ok_or_else(|| {
                        EngineError::new(
                            "SQL_PROVIDER_INVALID",
                            "SQL projected row column count differs",
                        )
                    })?;
                let (key, value) = &rows[ordinal];
                let cells = table
                    .columns
                    .iter()
                    .zip(cells)
                    .map(|(column, cell)| source_cell(column, key, value, cell))
                    .collect::<EngineResult<Vec<_>>>()?;
                let retained = self
                    .cursors
                    .values()
                    .map(|cursor| {
                        cells_bytes(&cursor.pending)
                            + cursor
                                .constraints
                                .iter()
                                .map(|constraint| match &constraint.value {
                                    SqlCell::Text(text) => text.len() + 128,
                                    _ => 128,
                                })
                                .sum::<usize>()
                    })
                    .sum::<usize>();
                let added = 64
                    + cells.len() * 64
                    + cells
                        .iter()
                        .map(|cell| match cell {
                            SqlCell::Text(text) => text.len(),
                            _ => 0,
                        })
                        .sum::<usize>();
                if retained
                    .saturating_add(cells_bytes(&cursor.pending))
                    .saturating_add(added)
                    > 2 * 1024 * 1024
                {
                    return engine.abort(
                        "SQL_BRIDGE_BUDGET",
                        "SQL retained source-cursor allowance exceeded",
                    );
                }
                cursor.pending.push_back(cells);
                if cells_bytes(&cursor.pending) > request.max_bytes.min(512 * 1024) {
                    return engine.abort(
                        "SQL_BRIDGE_BUDGET",
                        "SQL expansion exceeds bounded bridge allowance",
                    );
                }
            }
            if let Some(provenance) = projected.get("provenance") {
                let values = provenance.as_array().ok_or_else(|| {
                    EngineError::new("SQL_PROVIDER_INVALID", "Invalid SQL provenance")
                })?;
                for value in values {
                    self.provenance.insert(canonical_json(value));
                }
                if self
                    .provenance
                    .iter()
                    .map(|value| value.len() + 64)
                    .sum::<usize>()
                    > catalog::MAX_PROVENANCE_BYTES
                {
                    return engine.abort("SQL_PROVENANCE_BUDGET", "SQL provenance budget exceeded");
                }
            }
        }
        let next = if cursor.done && cursor.pending.is_empty() {
            None
        } else {
            cursor.generation += 1;
            let token = format!("{id}:{}", cursor.generation);
            self.cursors.insert(id, cursor);
            Some(token)
        };
        let batch_bytes = output
            .iter()
            .map(|row| {
                64 + row.len() * 64
                    + row
                        .iter()
                        .map(|cell| match cell {
                            SqlCell::Text(text) => text.capacity(),
                            _ => 0,
                        })
                        .sum::<usize>()
            })
            .sum::<usize>();
        if batch_bytes > request.max_bytes {
            return self.engine.borrow_mut().abort(
                "SQL_BRIDGE_BUDGET",
                "SQL provider batch reservation exceeded",
            );
        }
        Ok(Batch { rows: output, next })
    }
}
impl Source for Providers<'_, '_> {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError> {
        self.scan_engine(request).map_err(|error| {
            self.engine.borrow_mut().fatal.get_or_insert(error);
            SqlError::Provider
        })
    }
}
impl Engine<'_> {
    fn sql_candidates(
        &mut self,
        table: &catalog::Table,
        source: &catalog::Source,
        constraints: &[Equality],
        after: Option<&str>,
    ) -> EngineResult<CandidatePage> {
        self.marker_read(collection_id(&source.name));
        // Source-key equality is an exact point read, independently of SQL order.
        if let Some(key) = constraints.iter().find_map(|constraint| {
            (table.columns[constraint.column].source_key == Some(true))
                .then_some(&constraint.value)
                .and_then(|cell| {
                    if let SqlCell::Text(key) = cell {
                        Some(key)
                    } else {
                        None
                    }
                })
        }) {
            if after.is_some() {
                return Ok((Vec::new(), None, true));
            }
            let id = source_id(&source.name, key);
            self.record_read(&id);
            let value = self.source(&id).cloned();
            self.sql_charge_source(value.as_deref().unwrap_or(&Value::Null))?;
            let rows = match value {
                Some(value) => self
                    .sql_visible(&source.name, key, value)?
                    .map(|value| vec![(key.clone(), value)])
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            return Ok((rows, None, true));
        }
        // Only BINARY TEXT equality on an enforced native field mapping is pushed.
        // No string ranges, ordering, NULL, numeric affinity, or LIMIT pushdown.
        let mut pushed: Option<(Vec<String>, Vec<Value>)> = None;
        for index in &table.indexes {
            let mut fields = Vec::new();
            let mut values = Vec::new();
            for name in &index.columns {
                let column = table
                    .columns
                    .iter()
                    .position(|column| column.name == *name)
                    .expect("validated SQL index");
                let Some(value) = constraints
                    .iter()
                    .find(|constraint| constraint.column == column)
                    .and_then(|constraint| {
                        if let SqlCell::Text(value) = &constraint.value {
                            Some(value)
                        } else {
                            None
                        }
                    })
                else {
                    break;
                };
                if table.columns[column].column_type != catalog::ColumnType::Text {
                    break;
                }
                fields.push(
                    table.columns[column]
                        .source_field
                        .clone()
                        .expect("validated SQL mapping"),
                );
                values.push(json!(value));
            }
            if !fields.is_empty() {
                let all_fields: Vec<String> = index
                    .columns
                    .iter()
                    .map(|name| {
                        table
                            .columns
                            .iter()
                            .find(|column| column.name == *name)
                            .and_then(|column| column.source_field.clone())
                            .expect("validated SQL mapping")
                    })
                    .collect();
                // Keep the full native tuple index, restrict only its equality prefix.
                pushed = Some((all_fields, values));
                break;
            }
        }
        if let Some((fields, values)) = pushed {
            let mut options = json!({"prefix":values,"limit":catalog::BATCH_ROWS});
            if let Some(after) = after {
                options["after"] = json!(after);
            }
            let query = ranges::RangeQuery::parse(
                &json!({"kind":"range","collection":source.name,"fields":fields,"options":options}),
            )?;
            let page = self.range_rows(&query, true)?.rows.into_value();
            let rows = page["rows"]
                .as_array()
                .expect("native page")
                .iter()
                .map(|row| {
                    (
                        row["key"].as_str().expect("native key").to_owned(),
                        Arc::new(row["value"].clone()),
                    )
                })
                .collect();
            let next = page["cursor"].as_str().map(str::to_owned);
            return Ok((rows, next.clone(), next.is_none()));
        }
        // Walk native encoded source IDs directly. ctx.scan's fallback sorts a whole
        // collection even with a LIMIT, so it is deliberately not used here.
        let prefix = format!(
            "source:[{},",
            serde_json::to_string(&source.name).expect("source name")
        );
        let lower = after.map_or_else(|| prefix.clone(), |after| format!("{after}\0"));
        let snapshot = self.staged.clone();
        let mut rows = Vec::new();
        let mut last = None;
        let mut scanned = 0;
        for (id, value) in snapshot.entries((Bound::Included(lower.as_str()), Bound::Unbounded)) {
            if !id.starts_with(&prefix) {
                break;
            }
            self.sql_charge_source(&value)?;
            self.record_read(&id);
            let (_, key) = source_pair(&id)?;
            scanned += 1;
            last = Some(id);
            if let Some(value) = self.sql_visible(&source.name, &key, value)? {
                rows.push((key, value));
            }
            if scanned == catalog::BATCH_ROWS {
                return Ok((rows, last, false));
            }
        }
        Ok((rows, last, true))
    }
    fn sql_visible(
        &mut self,
        collection: &str,
        key: &str,
        value: Arc<Value>,
    ) -> EngineResult<Option<Arc<Value>>> {
        let Some(access) = self.read_access(collection) else {
            return Ok(Some(value));
        };
        let shown = self.looking_up(|lookup| {
            access
                .visible(key, &value, &[], lookup)
                .then(|| access.redact(key, &value, lookup))
        })?;
        self.settle_access(&access)?;
        Ok(shown)
    }
    pub(super) fn sql_execute(
        &mut self,
        operation: &str,
        registered: &Catalog,
        input: &Value,
        purpose: Value,
    ) -> EngineResult<Reply> {
        if self.sql.executed {
            return self.abort(
                "SQL_WORK_BUDGET",
                "Only one SQL evaluator invocation is permitted per method invocation",
            );
        }
        self.sql.executed = true;
        let object = input
            .as_object()
            .filter(|input| {
                input
                    .keys()
                    .all(|key| ["sql", "parameters", "maxRows", "queryId"].contains(&key.as_str()))
            })
            .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "Invalid SQL request"))?;
        let sql = object
            .get("sql")
            .and_then(Value::as_str)
            .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "SQL text required"))?;
        if sql.is_empty() || sql.len() > sqlite::MAX_SQL_BYTES {
            return self.abort("SQL_INPUT_INVALID", "SQL text exceeds bounded allowance");
        }
        let parameter_values = match object.get("parameters") {
            None => &[][..],
            Some(Value::Array(parameters)) => parameters.as_slice(),
            _ => {
                return self.abort(
                    "SQL_INPUT_INVALID",
                    "Parameters must be positional JSON scalars",
                );
            }
        };
        if parameter_values.len() > sqlite::MAX_PARAMETERS
            || parameter_values
                .iter()
                .map(allocation_cost)
                .fold(0usize, usize::saturating_add)
                > 1024 * 1024
        {
            return self.abort(
                "SQL_INPUT_INVALID",
                "SQL parameters exceed bounded allowance",
            );
        }
        let parameters = parameter_values
            .iter()
            .map(|value| match value {
                Value::Null => Ok(SqlCell::Null),
                Value::Bool(value) => Ok(SqlCell::Integer(i64::from(*value))),
                Value::String(value) => Ok(SqlCell::Text(value.clone())),
                Value::Number(value) => value
                    .as_f64()
                    .filter(|number| number.is_finite())
                    .map(|number| {
                        if number.fract() == 0.0 && number.abs() <= 9_007_199_254_740_991.0 {
                            SqlCell::Integer(number as i64)
                        } else {
                            SqlCell::Real(number)
                        }
                    })
                    .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "Invalid SQL parameter")),
                _ => Err(EngineError::new(
                    "SQL_INPUT_INVALID",
                    "Parameters must be positional JSON scalars",
                )),
            })
            .collect::<EngineResult<Vec<_>>>()?;
        let max_rows = match object.get("maxRows") {
            None => 100,
            Some(value) => value
                .as_u64()
                .filter(|value| *value <= 1000 && *value > 0)
                .map(|value| value as usize)
                .ok_or_else(|| {
                    EngineError::new("SQL_INPUT_INVALID", "maxRows must be 1 to 1000")
                })?,
        };
        if let Some(query_id) = object.get("queryId") {
            let query_id = query_id
                .as_str()
                .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "queryId must be text"))?;
            crate::service::cancellation::bind_effective(&self.principal, &purpose)
                .map_err(cancel_error)?;
            crate::service::cancellation::register(query_id).map_err(cancel_error)?;
        }
        let mut tables = registered
            .tables
            .iter()
            .map(|table| VirtualTable {
                name: table.name.clone(),
                columns: table
                    .columns
                    .iter()
                    .map(|column| column.name.clone())
                    .collect(),
                equality_columns: table
                    .columns
                    .iter()
                    .enumerate()
                    .filter(|(_, column)| {
                        column.source_key == Some(true)
                            || column.column_type == catalog::ColumnType::Text
                                && column.source_field.is_some()
                                && table
                                    .indexes
                                    .iter()
                                    .any(|index| index.columns.first() == Some(&column.name))
                    })
                    .map(|(ordinal, _)| ordinal)
                    .collect(),
            })
            .collect::<Vec<_>>();
        let (metadata_tables, metadata) = metadata(registered);
        tables.extend(metadata_tables);
        let engine = Rc::new(RefCell::new(self));
        let mut providers = Providers {
            engine: engine.clone(),
            catalog: registered,
            purpose,
            provenance: BTreeSet::new(),
            cursors: HashMap::new(),
            next_cursor: 0,
            metadata,
        };
        let mut check = || {
            engine
                .borrow_mut()
                .sql_check()
                .map_err(|_| SqlError::Deadline)
        };
        let options = QueryOptions {
            max_rows,
            max_native_bytes: catalog::NATIVE_BYTES,
            max_output_bytes: catalog::MAX_OUTPUT_BYTES,
            max_work: sqlite::MAX_WORK,
            batch_rows: catalog::BATCH_ROWS,
        };
        let query = if operation == "explain" {
            format!("EXPLAIN QUERY PLAN {sql}")
        } else {
            sql.to_owned()
        };
        let evaluated = sqlite::execute(
            &query,
            &parameters,
            &tables,
            &mut providers,
            options,
            &mut check,
        );
        engine.borrow_mut().sql_check()?;
        let evaluated = match evaluated {
            Ok(result) => result,
            Err(error) => {
                let mut engine = engine.borrow_mut();
                if let Some(error) = engine.fatal.as_ref() {
                    return Err(error.clone());
                }
                return engine.abort(&native_error(error).code, native_error(error).message);
            }
        };
        let warnings = registered
            .tables
            .iter()
            .filter_map(|table| {
                table
                    .coverage
                    .as_ref()
                    .map(|coverage| format!("{}: {coverage}", table.name))
            })
            .collect::<Vec<_>>();
        let value = if operation == "explain" {
            json!({"catalogVersion":registered.version,"plan":evaluated.rows.iter().map(|row|json!({"detail":row.last().map(encode_cell).and_then(|cell|cell.get("text").cloned()).unwrap_or(json!("bounded logical plan"))})).collect::<Vec<_>>(),"warnings":warnings})
        } else {
            let result = json!({"columns":evaluated.columns.iter().map(|name|json!({"name":name})).collect::<Vec<_>>(),"rows":evaluated.rows.iter().map(|row|row.iter().map(encode_cell).collect::<Vec<_>>()).collect::<Vec<_>>(),"resultTruncated":evaluated.truncated,"warnings":warnings,"catalogVersion":registered.version});
            json!({"result":result,"provenance":providers.provenance.iter().map(|value|serde_json::from_str::<Value>(value).expect("canonical provenance")).collect::<Vec<_>>()})
        };
        if encoded_len(&value) > catalog::MAX_OUTPUT_BYTES {
            return engine
                .borrow_mut()
                .abort("SQL_OUTPUT_BUDGET", "SQL output exceeds response budget");
        }
        Ok(Reply::Value(value))
    }
}
fn nullable_text(value: &Option<String>) -> SqlCell {
    value.clone().map(SqlCell::Text).unwrap_or(SqlCell::Null)
}
fn metadata(registered: &Catalog) -> (Vec<VirtualTable>, Vec<Vec<Vec<SqlCell>>>) {
    let names = [
        (
            "sql_tables",
            vec!["name", "description", "grain", "coverage"],
        ),
        (
            "sql_columns",
            vec![
                "table_name",
                "name",
                "ordinal",
                "type",
                "nullable",
                "description",
                "logical_type",
                "unit",
            ],
        ),
        (
            "sql_relationships",
            vec![
                "name",
                "from_table",
                "from_columns",
                "to_table",
                "to_columns",
                "description",
            ],
        ),
    ];
    let tables = names
        .into_iter()
        .map(|(name, columns)| VirtualTable {
            name: name.into(),
            columns: columns.into_iter().map(str::to_owned).collect(),
            equality_columns: Vec::new(),
        })
        .collect();
    let table_rows = registered
        .tables
        .iter()
        .map(|table| {
            vec![
                SqlCell::Text(table.name.clone()),
                nullable_text(&table.description),
                nullable_text(&table.grain),
                nullable_text(&table.coverage),
            ]
        })
        .collect();
    let column_rows = registered
        .tables
        .iter()
        .flat_map(|table| {
            table.columns.iter().enumerate().map(|(ordinal, column)| {
                vec![
                    SqlCell::Text(table.name.clone()),
                    SqlCell::Text(column.name.clone()),
                    SqlCell::Integer(ordinal as i64),
                    SqlCell::Text(
                        match column.column_type {
                            catalog::ColumnType::Integer => "integer",
                            catalog::ColumnType::Real => "real",
                            catalog::ColumnType::Text => "text",
                        }
                        .into(),
                    ),
                    column
                        .nullable
                        .map(|nullable| SqlCell::Integer(i64::from(nullable)))
                        .unwrap_or(SqlCell::Null),
                    nullable_text(&column.description),
                    nullable_text(&column.logical_type),
                    nullable_text(&column.unit),
                ]
            })
        })
        .collect();
    let relationship_rows = registered
        .relationships
        .iter()
        .map(|relationship| {
            vec![
                SqlCell::Text(relationship.name.clone()),
                SqlCell::Text(relationship.from_table.clone()),
                SqlCell::Text(
                    serde_json::to_string(&relationship.from_columns)
                        .expect("relationship columns"),
                ),
                SqlCell::Text(relationship.to_table.clone()),
                SqlCell::Text(
                    serde_json::to_string(&relationship.to_columns).expect("relationship columns"),
                ),
                nullable_text(&relationship.description),
            ]
        })
        .collect();
    (tables, vec![table_rows, column_rows, relationship_rows])
}
