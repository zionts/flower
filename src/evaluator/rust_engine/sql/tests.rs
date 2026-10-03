use crate::consensus::Records;
use crate::evaluator::rust_engine::{EngineError, EngineResult, Executor};
use crate::evaluator::wire::Reply;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
struct Probe {
    children: AtomicUsize,
    operation: &'static str,
    catch: bool,
}
impl Executor for Probe {
    fn execute(
        &self,
        kind: &str,
        _name: &str,
        _args: &Value,
        host: &mut dyn FnMut(&str, Value) -> EngineResult<Reply>,
    ) -> EngineResult<Value> {
        if kind != "query" {
            self.children.fetch_add(1, Ordering::Relaxed);
            return Err(EngineError::new(
                "TEST_CHILD_UNEXPECTED",
                "No callback should run before hard admission",
            ));
        }
        let result = host(
            "sql",
            json!([self.operation,"unavailable_catalog",{"sql":"SELECT private_literal"},null]),
        );
        if self.catch {
            Ok(json!({"caught":result.is_err()}))
        } else {
            result.map(Reply::into_value)
        }
    }
}
#[test]
fn sql_snapshot_hold_precedes_catalog_policy_provider_or_sql_execution_and_is_sticky() {
    let records = Records::from(BTreeMap::from([(
        "httpMethods".into(),
        json!({"sql.query":{"name":"read","kind":"query","cache":false,"watch":false}}),
    )]));
    for operation in ["query", "explain", "catalog", "cancel"] {
        for catch in [false, true] {
            let probe = Probe {
                children: AtomicUsize::new(0),
                operation,
                catch,
            };
            let error = crate::evaluator::rust_engine::run(
                records.clone(),
                json!({"name":"read","args":null,"$principal":{"subject":"alice"}}),
                "query",
                Some(1000),
                &probe,
            )
            .unwrap_err();
            #[cfg(feature = "sql")]
            assert_eq!(error.code, "SQL_SNAPSHOT_UNBOUNDED");
            #[cfg(not(feature = "sql"))]
            assert_eq!(error.code, "SQL_UNAVAILABLE");
            assert_eq!(probe.children.load(Ordering::Relaxed), 0);
            assert!(!error.message.contains("private_literal"));
        }
    }
}
