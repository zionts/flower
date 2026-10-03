//! Rights-preserving SQL host bridge. The evaluator is absent in default builds.
use super::*;
use crate::evaluator::sql::{self as catalog, Catalog};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Callback {
    Authority,
    #[cfg(feature = "sql")]
    Provider,
}
#[derive(Default)]
pub(super) struct Allowance {
    pub callback: Option<Callback>,
    pub deadline: Option<Instant>,
    pub source_rows: std::cell::Cell<usize>,
    pub source_bytes: std::cell::Cell<usize>,
    pub failure: std::cell::RefCell<Option<EngineError>>,
    #[cfg(feature = "sql")]
    pub projected_rows: usize,
    #[cfg(feature = "sql")]
    pub executed: bool,
}
impl Engine<'_> {
    pub(super) fn sql_check(&mut self) -> EngineResult<()> {
        self.check_fatal()?;
        if self
            .sql
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return self.abort("SQL_DEADLINE", "SQL execution deadline exceeded");
        }
        Ok(())
    }
    pub(super) fn sql_charge_source(&self, value: &Value) -> EngineResult<()> {
        if self.sql.deadline.is_none() {
            return Ok(());
        }
        self.check_fatal()?;
        self.sql
            .source_rows
            .set(self.sql.source_rows.get().saturating_add(1));
        self.sql.source_bytes.set(
            self.sql
                .source_bytes
                .get()
                .saturating_add(allocation_cost(value)),
        );
        if self.sql.source_rows.get() > catalog::MAX_SOURCE_ROWS
            || self.sql.source_bytes.get() > catalog::MAX_SOURCE_BYTES
        {
            let error = EngineError::new("SQL_SOURCE_BUDGET", "SQL source work budget exceeded");
            *self.sql.failure.borrow_mut() = Some(error.clone());
            return Err(error);
        }
        Ok(())
    }
    fn sql_callback(&mut self, kind: Callback, name: &str, args: &Value) -> EngineResult<Value> {
        let previous = self.sql.callback.replace(kind);
        let execute = self.execute;
        let result = execute.execute(
            if kind == Callback::Authority {
                "sqlAuthority"
            } else {
                "sqlProvider"
            },
            name,
            args,
            &mut |operation, payload| self.method_host(operation, payload),
        );
        self.sql.callback = previous;
        self.sql_check()?;
        result
    }
    pub(super) fn sql_host(&mut self, arguments: &[Value]) -> EngineResult<Reply> {
        if !cfg!(feature = "sql") {
            return self.abort(
                "SQL_UNAVAILABLE",
                "Native SQL is disabled in this Flower build",
            );
        }
        #[cfg(feature = "sql")]
        {
            let Some(bytes) = self.base.sql_snapshot_reservation_bytes() else {
                return self.abort(
                    "SQL_SNAPSHOT_UNBOUNDED",
                    "SQL is unavailable until complete snapshot retention is hard-bounded",
                );
            };
            if bytes > catalog::SNAPSHOT_BYTES {
                return self.abort(
                    "SQL_SNAPSHOT_BUDGET",
                    "SQL snapshot reservation exceeds the admitted allowance",
                );
            }
        }
        if self.mode != "query" || self.system || self.definer > 0 || self.sql.callback.is_some() {
            return self.abort(
                "SQL_AUTHORITY_FORBIDDEN",
                "SQL requires an authenticated invoker in a one-shot read method",
            );
        }
        let operation = arguments
            .first()
            .and_then(Value::as_str)
            .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "SQL operation required"))?;
        let name = arguments
            .get(1)
            .and_then(Value::as_str)
            .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "SQL catalog required"))?;
        let input = arguments.get(2).unwrap_or(&Value::Null);
        let purpose = arguments.get(3).unwrap_or(&Value::Null);
        if arguments.len() > 4 {
            return self.abort("SQL_INPUT_INVALID", "Invalid SQL host arguments");
        }
        if allocation_cost(purpose) > 256 * 1024 || allocation_cost(&self.principal) > 128 * 1024 {
            return self.abort(
                "SQL_BRIDGE_BUDGET",
                "SQL authority input exceeds bounded bridge allowance",
            );
        }
        // No alias may enter SQL while retaining automatic cache or watch semantics.
        self.record_read("httpMethods");
        let one_shot = self
            .staged
            .get("httpMethods")
            .and_then(Value::as_object)
            .is_some_and(|methods| {
                let mut matching = methods
                    .values()
                    .filter(|method| method["name"] == self.sql_method);
                matching.any(|method| {
                    method["kind"] == "query"
                        && method["cache"] == false
                        && method["watch"] == false
                })
            });
        if !one_shot {
            return self.abort(
                "SQL_METHOD_NOT_ONESHOT",
                "SQL methods must declare cache:false and watch:false",
            );
        }
        self.query_cacheable = false;
        self.record_read("schema");
        let registered = self
            .schema
            .sql
            .iter()
            .find(|catalog| catalog.name == name)
            .cloned()
            .ok_or_else(|| EngineError::new("SQL_CATALOG_DENIED", "SQL catalog unavailable"))?;
        self.sql
            .deadline
            .get_or_insert_with(|| Instant::now() + Duration::from_secs(2));
        self.sql_check()?;
        // Dedicated authority callback may read application auth rows, never derived
        // values, write, invoke SQL, gain entropy, or retain its rights into providers.
        let original_system = self.system;
        let original_access = std::mem::take(&mut self.access);
        self.system = true;
        let request = json!({"catalog":registered.name,"invoker":self.principal,"purpose":purpose});
        let decision = self.sql_callback(Callback::Authority, &registered.authority, &request);
        self.system = original_system;
        self.access = original_access;
        let decision = decision?;
        if allocation_cost(&decision) > 512 * 1024 {
            return self.abort(
                "SQL_BRIDGE_BUDGET",
                "SQL authority decision exceeds bounded bridge allowance",
            );
        }
        let principal = decision
            .get("principal")
            .cloned()
            .ok_or_else(|| EngineError::new("SQL_AUTHORITY_DENIED", "SQL read authority denied"))?;
        let principal_object = principal
            .as_object()
            .filter(|principal| {
                principal
                    .keys()
                    .all(|key| ["subject", "tenant", "claims"].contains(&key.as_str()))
            })
            .ok_or_else(|| {
                EngineError::new("SQL_AUTHORITY_DENIED", "Invalid SQL authority decision")
            })?;
        if !principal_object
            .get("subject")
            .and_then(Value::as_str)
            .is_some_and(|subject| !subject.is_empty() && subject != "$anonymous")
            || principal.get("tenant") != self.principal.get("tenant")
        {
            return self.abort("SQL_AUTHORITY_DENIED", "Invalid SQL authority decision");
        }
        let allowed = decision
            .get("tables")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                EngineError::new("SQL_AUTHORITY_DENIED", "SQL table allowlist required")
            })?;
        if allowed.len() > registered.tables.len()
            || allowed.iter().any(|name| {
                !name
                    .as_str()
                    .is_some_and(|name| registered.tables.iter().any(|table| table.name == name))
            })
        {
            return self.abort("SQL_AUTHORITY_DENIED", "Invalid SQL table allowlist");
        }
        let mut registered = registered;
        registered
            .tables
            .retain(|table| allowed.iter().any(|name| name == &table.name));
        registered.relationships.retain(|relationship| {
            registered
                .tables
                .iter()
                .any(|table| table.name == relationship.from_table)
                && registered
                    .tables
                    .iter()
                    .any(|table| table.name == relationship.to_table)
        });
        if decision
            .get("context")
            .is_none_or(|context| allocation_cost(context) > 256 * 1024)
            || allocation_cost(&principal) > 128 * 1024
        {
            return self.abort(
                "SQL_BRIDGE_BUDGET",
                "SQL effective context exceeds bounded bridge allowance",
            );
        }
        let context = decision.get("context").cloned().ok_or_else(|| {
            EngineError::new("SQL_AUTHORITY_DENIED", "Validated SQL context required")
        })?;
        let original_principal = std::mem::replace(&mut self.principal, principal);
        let original_access = std::mem::take(&mut self.access);
        let result = self.sql_authorized(operation, &registered, input, context);
        self.principal = original_principal;
        self.access = original_access;
        self.sql_check()?;
        result
    }
    #[cfg_attr(not(feature = "sql"), allow(unused_variables))]
    fn sql_authorized(
        &mut self,
        operation: &str,
        registered: &Catalog,
        input: &Value,
        purpose: Value,
    ) -> EngineResult<Reply> {
        match operation {
            "catalog" => Ok(catalog_info(registered).into()),
            #[cfg(feature = "sql")]
            "query" | "explain" => self.sql_execute(operation, registered, input, purpose),
            #[cfg(feature = "sql")]
            "cancel" => {
                let query_id = input
                    .get("queryId")
                    .and_then(Value::as_str)
                    .ok_or_else(|| EngineError::new("SQL_INPUT_INVALID", "queryId required"))?;
                crate::service::cancellation::bind_effective(&self.principal, &purpose)
                    .map_err(cancel_error)?;
                crate::service::cancellation::cancel(query_id)
                    .map(|cancelled| json!(cancelled).into())
                    .map_err(cancel_error)
            }
            #[cfg(not(feature = "sql"))]
            "query" | "explain" | "cancel" => Err(EngineError::new(
                "SQL_UNAVAILABLE",
                "Native SQL is disabled in this Flower build",
            )),
            _ => Err(EngineError::new(
                "SQL_INPUT_INVALID",
                "Unknown SQL operation",
            )),
        }
    }
}
fn column_info(column: &catalog::Column) -> Value {
    let mut value = serde_json::to_value(column).expect("SQL metadata");
    let object = value.as_object_mut().expect("SQL column object");
    object.remove("sourceField");
    object.remove("sourceKey");
    value
}
fn catalog_info(registered: &Catalog) -> Value {
    json!({"name":registered.name,"catalogVersion":registered.version,"tables":registered.tables.iter().map(|table| {
        let mut value = json!({"name":table.name,"columns":table.columns.iter().map(column_info).collect::<Vec<_>>()});
        for (name, text) in [("description", &table.description),("grain",&table.grain),("coverage",&table.coverage)] {
            if let Some(text) = text { value[name] = json!(text); }
        }
        value
    }).collect::<Vec<_>>(),"relationships":registered.relationships})
}
#[cfg(feature = "sql")]
fn cancel_error(_: anyhow::Error) -> EngineError {
    EngineError::new(
        "SQL_CANCEL_DENIED",
        "SQL cancellation unavailable or denied",
    )
}

#[cfg(feature = "sql")]
mod native;

#[cfg(test)]
mod tests;
