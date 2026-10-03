use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Data {
    tables: Vec<Vec<Vec<SqlCell>>>,
    calls: usize,
    pushed: usize,
    failure_after: Option<usize>,
    ignore_push: bool,
}
impl Source for Data {
    fn scan(&mut self, request: ScanRequest<'_>) -> Result<Batch, SqlError> {
        self.calls += 1;
        if self.failure_after.is_some_and(|after| self.calls > after) {
            return Err(SqlError::Provider);
        }
        self.pushed += usize::from(!request.constraints.is_empty());
        let candidates = self.tables[request.table].iter().filter(|row| {
            self.ignore_push || request.constraints.iter().all(|e| row[e.column] == e.value)
        });
        let start = request
            .after
            .map(|s| s.parse::<usize>().unwrap())
            .unwrap_or(0);
        let mut candidates = candidates.skip(start).peekable();
        // Budget the outer Vec before allocating it; each candidate is cloned
        // only if the bounded result can retain it.
        let first_bytes = candidates.peek().map_or(0, |row| {
            row.len() * size_of::<SqlCell>() + row.iter().map(SqlCell::heap_bytes).sum::<usize>()
        });
        let capacity = request
            .limit
            .min(request.max_bytes.saturating_sub(32) / (size_of::<Vec<SqlCell>>() + first_bytes));
        if capacity == 0 && candidates.peek().is_some() {
            return Err(SqlError::MemoryLimit);
        }
        let outer = capacity * size_of::<Vec<SqlCell>>();
        let mut rows = Vec::with_capacity(capacity);
        let mut bytes = outer + 32;
        while rows.len() < capacity {
            let Some(row) = candidates.peek() else {
                break;
            };
            let next_bytes = row.len() * size_of::<SqlCell>()
                + row.iter().map(SqlCell::heap_bytes).sum::<usize>();
            if bytes + next_bytes > request.max_bytes {
                if rows.is_empty() {
                    return Err(SqlError::MemoryLimit);
                }
                break;
            }
            bytes += next_bytes;
            rows.push(candidates.next().unwrap().clone());
        }
        let next = if candidates.peek().is_some() {
            Some((start + rows.len()).to_string())
        } else {
            None
        };
        let batch = Batch { rows, next };
        assert!(vtab::test_batch_bytes(&batch) <= request.max_bytes);
        Ok(batch)
    }
}
fn table(name: &str, columns: &[&str], equality_columns: &[usize]) -> VirtualTable {
    VirtualTable {
        name: name.into(),
        columns: columns.iter().map(|s| (*s).into()).collect(),
        equality_columns: equality_columns.into(),
    }
}
fn data(tables: Vec<Vec<Vec<SqlCell>>>) -> Data {
    Data {
        tables,
        calls: 0,
        pushed: 0,
        failure_after: None,
        ignore_push: false,
    }
}
fn run(
    sql: &str,
    params: &[SqlCell],
    tables: &[VirtualTable],
    data: &mut Data,
) -> Result<SqlResult, SqlError> {
    execute(
        sql,
        params,
        tables,
        data,
        QueryOptions::default(),
        &mut || Ok(()),
    )
}

#[test]
fn real_indexed_join_and_exact_aggregate() {
    let tables = [
        table("people", &["id", "name"], &[0]),
        table("orders", &["person", "amount"], &[0]),
    ];
    let mut source = data(vec![
        vec![
            vec![SqlCell::Integer(1), SqlCell::Text("Ada".into())],
            vec![SqlCell::Integer(2), SqlCell::Text("Grace".into())],
        ],
        vec![
            vec![SqlCell::Integer(1), SqlCell::Integer(9007199254740993)],
            vec![SqlCell::Integer(1), SqlCell::Integer(2)],
            vec![SqlCell::Integer(2), SqlCell::Integer(10)],
        ],
    ]);
    let result = run("SELECT p.name, sum(o.amount) AS total FROM people p JOIN orders o ON o.person=p.id GROUP BY p.name ORDER BY p.name", &[], &tables, &mut source).unwrap();
    assert_eq!(
        result.rows,
        vec![
            vec![
                SqlCell::Text("Ada".into()),
                SqlCell::Integer(9007199254740995)
            ],
            vec![SqlCell::Text("Grace".into()), SqlCell::Integer(10)]
        ]
    );
    assert!(
        source.pushed > 0,
        "join planner must use safe equality pushdown"
    );
    assert!(!result.truncated);
}
#[test]
fn tagged_transport_preserves_i64_and_duplicate_aliases() {
    let mut source = data(vec![]);
    let result = run(
        "SELECT ? AS x, ? AS x, ? AS y, ? AS z",
        &[
            SqlCell::Integer(i64::MAX),
            SqlCell::Null,
            SqlCell::Real(1.25),
            SqlCell::Text("hello\0world".into()),
        ],
        &[],
        &mut source,
    )
    .unwrap();
    assert_eq!(result.columns, ["x", "x", "y", "z"]);
    let wire = serde_json::to_string(&result).unwrap();
    assert!(wire.contains("\"integer\":\"9223372036854775807\""));
    assert_eq!(serde_json::from_str::<SqlResult>(&wire).unwrap(), result);
    assert!(serde_json::from_str::<SqlCell>(r#"{"integer":9223372036854775807}"#).is_err());
    assert!(serde_json::to_string(&SqlCell::Real(f64::INFINITY)).is_err());
}
#[test]
fn rejects_writes_recursion_other_statements_and_unapproved_functions() {
    let table = table("items", &["id"], &[0]);
    let mut source = data(vec![vec![vec![SqlCell::Integer(1)]]]);
    for sql in [
        "DELETE FROM items",
        "CREATE TABLE bad(x)",
        "PRAGMA temp_store",
        "ATTACH ':memory:' AS other",
        "SELECT random()",
        "SELECT date('now')",
        "SELECT load_extension('bad')",
        "SELECT readfile('/etc/passwd')",
        "SELECT * FROM sqlite_schema",
        "SELECT * FROM pragma_database_list",
        "SELECT rowid FROM items",
        "WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n WHERE x<10) SELECT sum(x) FROM n",
    ] {
        assert!(
            run(sql, &[], std::slice::from_ref(&table), &mut source).is_err(),
            "must reject {sql}"
        );
    }
    assert!(run("SELECT 1; SELECT 2", &[], &[], &mut source).is_err());
    assert!(
        run(
            "SELECT 1; -- permitted trailing comment",
            &[],
            &[],
            &mut source
        )
        .is_ok()
    );
    assert!(
        run(
            "WITH n AS (SELECT 1 AS x) SELECT sum(x) FROM n",
            &[],
            &[],
            &mut source
        )
        .is_ok()
    );
    assert!(
        run(
            "SELECT abs(-1), lower('ABC'), json_extract('{\"x\":2}', '$.x')",
            &[],
            &[],
            &mut source
        )
        .is_ok()
    );
}
#[test]
fn rechecks_pushdown_and_never_consumes_order() {
    let table = table("items", &["id", "name"], &[0, 1]);
    let mut source = data(vec![vec![
        vec![SqlCell::Integer(2), SqlCell::Text("a".into())],
        vec![SqlCell::Integer(1), SqlCell::Text("A".into())],
        vec![SqlCell::Integer(3), SqlCell::Text("z".into())],
    ]]);
    source.ignore_push = true; // deliberately return extra candidates
    assert_eq!(
        run(
            "SELECT id FROM items WHERE id=1",
            &[],
            std::slice::from_ref(&table),
            &mut source
        )
        .unwrap()
        .rows,
        vec![vec![SqlCell::Integer(1)]]
    );
    source.ignore_push = false;
    let prior = source.pushed;
    assert_eq!(
        run(
            "SELECT id FROM items WHERE name='a' COLLATE NOCASE ORDER BY id",
            &[],
            &[table],
            &mut source
        )
        .unwrap()
        .rows,
        vec![vec![SqlCell::Integer(1)], vec![SqlCell::Integer(2)]]
    );
    assert_eq!(
        source.pushed, prior,
        "non-BINARY equality must not be pushed"
    );
}
#[test]
fn provider_failure_discards_aggregate_and_cancellation_is_sticky() {
    let table = table("items", &["id"], &[]);
    let rows = (0..200).map(|n| vec![SqlCell::Integer(n)]).collect();
    let mut source = data(vec![rows]);
    source.failure_after = Some(1);
    assert_eq!(
        run(
            "SELECT count(*) FROM items",
            &[],
            std::slice::from_ref(&table),
            &mut source
        ),
        Err(SqlError::Provider)
    );
    source.failure_after = None;
    let mut checks = 0;
    let result = execute(
        "SELECT sum(id) FROM items",
        &[],
        &[table],
        &mut source,
        QueryOptions::default(),
        &mut || {
            checks += 1;
            if checks > 20 {
                Err(SqlError::Cancelled)
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(result, Err(SqlError::Cancelled));
    assert_eq!(
        execute(
            "SELECT 1",
            &[],
            &[],
            &mut source,
            QueryOptions::default(),
            &mut || Err(SqlError::Deadline)
        ),
        Err(SqlError::Deadline)
    );
}
#[test]
fn sort_cross_join_and_integer_overflow_are_bounded() {
    let table = table("items", &["id"], &[]);
    let mut source = data(vec![
        (0..10000).map(|n| vec![SqlCell::Integer(n)]).collect(),
    ]);
    assert_eq!(
        run(
            "SELECT count(*) FROM items a CROSS JOIN items b",
            &[],
            std::slice::from_ref(&table),
            &mut source
        ),
        Err(SqlError::WorkLimit)
    );
    let before = init::open_attempts();
    let result = execute(
        "SELECT id FROM items ORDER BY id DESC",
        &[],
        &[],
        &mut source,
        QueryOptions::default(),
        &mut || Ok(()),
    );
    assert!(result.is_err()); // table absent in supplied catalog
    let result = execute(
        "SELECT id FROM items ORDER BY id DESC",
        &[],
        std::slice::from_ref(&table),
        &mut source,
        QueryOptions {
            max_native_bytes: 64 * 1024,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    );
    assert!(matches!(
        result,
        Err(SqlError::MemoryLimit) | Err(SqlError::WorkLimit)
    ));
    assert_eq!(
        init::open_attempts(),
        before,
        "neither regular nor temp filesystem opens are attempted"
    );
    let mut source = data(vec![vec![
        vec![SqlCell::Integer(i64::MAX)],
        vec![SqlCell::Integer(1)],
    ]]);
    assert_eq!(
        run("SELECT sum(id) FROM items", &[], &[table], &mut source),
        Err(SqlError::InvalidSql)
    );
}
#[test]
fn lazy_rows_truncation_and_output_budget() {
    let table = table("items", &["id"], &[]);
    let mut source = data(vec![
        (0..10000).map(|n| vec![SqlCell::Integer(n)]).collect(),
    ]);
    let result = execute(
        "SELECT id FROM items",
        &[],
        &[table],
        &mut source,
        QueryOptions {
            max_rows: 2,
            batch_rows: 4,
            ..QueryOptions::default()
        },
        &mut || Ok(()),
    )
    .unwrap();
    assert_eq!(result.rows.len(), 2);
    assert!(result.truncated);
    assert_eq!(
        source.calls, 1,
        "must not materialize an entire logical source"
    );
    assert_eq!(
        execute(
            "SELECT ?",
            &[SqlCell::Text("a".repeat(100))],
            &[],
            &mut source,
            QueryOptions {
                max_output_bytes: 100,
                ..QueryOptions::default()
            },
            &mut || Ok(())
        ),
        Err(SqlError::OutputLimit)
    );
}
#[test]
fn parallel_query_memory_limits_are_independent() {
    let passed = Arc::new(AtomicUsize::new(0));
    std::thread::scope(|scope| {
        for index in 0..12 {
            let passed = passed.clone();
            scope.spawn(move || {
                for _ in 0..10 {
                    let mut source = data(vec![]);
                    let limit = if index % 2 == 0 {
                        1024
                    } else {
                        MAX_NATIVE_BYTES
                    };
                    let result = execute(
                        "SELECT sum(1), ?",
                        &[SqlCell::Integer(i64::MAX)],
                        &[],
                        &mut source,
                        QueryOptions {
                            max_native_bytes: limit,
                            ..QueryOptions::default()
                        },
                        &mut || Ok(()),
                    );
                    if index % 2 == 0 {
                        assert_eq!(result, Err(SqlError::MemoryLimit));
                    } else {
                        assert_eq!(result.unwrap().rows[0][1], SqlCell::Integer(i64::MAX));
                    }
                    passed.fetch_add(1, Ordering::Relaxed);
                }
            });
        }
    });
    assert_eq!(passed.load(Ordering::Relaxed), 120);
}
#[test]
fn invalid_params_catalog_blobs_and_values_do_not_escape() {
    let mut source = data(vec![]);
    for sql in [
        "SELECT :named",
        "SELECT ?257",
        "SELECT x'ff'",
        "SELECT CAST(x'ff' AS TEXT)",
        "SELECT 1e999",
    ] {
        assert!(run(sql, &[], &[], &mut source).is_err());
    }
    assert!(run("SELECT ?", &[SqlCell::Real(f64::NAN)], &[], &mut source).is_err());
    assert!(
        run(
            "SELECT 1",
            &[],
            &[table("sqlite_schema", &["x"], &[])],
            &mut source
        )
        .is_err()
    );
    assert_eq!(SqlError::InvalidSql.to_string(), "SQL statement failed");
}

#[test]
fn high_cardinality_sort_hits_native_quota_without_leak_or_spill() {
    init::initialize().unwrap();
    let tables = [table("items", &["id", "name"], &[])];
    let mut source = data(vec![
        (0..5000)
            .map(|n| {
                vec![
                    SqlCell::Integer(n),
                    SqlCell::Text(format!("{n:06}{}", "x".repeat(128))),
                ]
            })
            .collect(),
    ]);
    let quota = Quota::new(512 * 1024);
    let before = init::open_attempts();
    {
        let _scope = Scope::enter(quota.clone()).unwrap();
        let mut check = || Ok(());
        let context = Context {
            source: RefCell::new(&mut source),
            check: RefCell::new(&mut check),
            tables: &tables,
            quota: quota.clone(),
            options: QueryOptions {
                max_native_bytes: 512 * 1024,
                max_rows: 10,
                ..QueryOptions::default()
            },
            failure: Cell::new(None),
            work: Cell::new(0),
        };
        assert_eq!(
            execute_scoped("SELECT id FROM items ORDER BY name DESC", &[], &context),
            Err(SqlError::MemoryLimit)
        );
    }
    assert!(
        source.calls > 3,
        "real sort must scan many batches before hitting memory limit"
    );
    assert_eq!(
        quota.used(),
        0,
        "all native allocations and cursor leases must be reclaimed"
    );
    assert!(quota.peak() <= 512 * 1024);
    assert_eq!(init::open_attempts(), before);
    assert!(
        quota.failed(),
        "the allocator failure must remain sticky after cleanup"
    );
}

#[test]
fn source_and_check_panics_fail_closed_without_unwinding_through_c() {
    struct Panics;
    impl Source for Panics {
        fn scan(&mut self, _: ScanRequest<'_>) -> Result<Batch, SqlError> {
            panic!("source panic");
        }
    }
    let tables = [table("items", &["id"], &[])];
    assert_eq!(
        execute(
            "SELECT count(*) FROM items",
            &[],
            &tables,
            &mut Panics,
            QueryOptions::default(),
            &mut || Ok(())
        ),
        Err(SqlError::Provider)
    );
    assert_eq!(
        execute(
            "SELECT 1",
            &[],
            &[],
            &mut Panics,
            QueryOptions::default(),
            &mut || panic!("check panic")
        ),
        Err(SqlError::Provider)
    );
}

#[test]
fn init_refuses_an_already_initialized_sqlite_in_fresh_process() {
    let test = module_path!().split_once("::").unwrap().1;
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("{test}::preinitialized_child"),
            "--nocapture",
        ])
        .env("FLOWER_SQL_PREINITIALIZED_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
#[test]
fn preinitialized_child() {
    if std::env::var_os("FLOWER_SQL_PREINITIALIZED_CHILD").is_none() {
        return;
    }
    assert_eq!(unsafe { ffi::sqlite3_initialize() }, ffi::SQLITE_OK);
    let mut source = data(vec![]);
    assert_eq!(
        run("SELECT 1", &[], &[], &mut source),
        Err(SqlError::Unavailable)
    );
}

#[test]
fn post_init_unscoped_native_allocations_are_rejected() {
    init::initialize().unwrap();
    assert!(unsafe { ffi::sqlite3_malloc64(1024) }.is_null());
    assert_eq!(
        run("SELECT 42", &[], &[], &mut data(vec![])).unwrap().rows,
        vec![vec![SqlCell::Integer(42)]]
    );
}
