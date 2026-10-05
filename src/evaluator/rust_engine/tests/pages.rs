//! Inventory pages exercise the actual native engine, including backing and ACLs.
use super::*;
use crate::evaluator::rust_engine::pages as source_pages;
use std::cell::Cell;

fn reference(collection: &str, options: Value) -> Value {
    json!({"kind":"sourcePage", "collection":collection, "options":options})
}

fn cursor(collection: &str, key: &str) -> String {
    canonical_json(
        &json!({"version":1, "scope":canonical_json(&json!(["sourcePage",collection])), "last":source_id(collection,key)}),
    )
}

fn fixture() -> Fixture {
    Fixture::new([
        (
            "page",
            (|args, host| host("range", json!([reference("items", args.clone())]))) as Callback,
        ),
        (
            "reference",
            (|args, host| host("range", json!([args]))) as Callback,
        ),
        (
            "old",
            (|args, host| host("scan", json!([{"kind":"collection","name":"items"},args])))
                as Callback,
        ),
        (
            "derived",
            (|args, host| get(host, "derived", "page", args.clone())) as Callback,
        ),
        (
            "write",
            (|args, host| {
                set(
                    host,
                    "items",
                    args["key"].as_str().unwrap(),
                    args["value"].clone(),
                )
            }) as Callback,
        ),
        (
            "delete",
            (|args, host| host("delete", json!([{"kind":"collection","name":"items"},args])))
                as Callback,
        ),
        (
            "overlay",
            (|args, host| {
                for edit in args["edits"].as_array().unwrap() {
                    if edit.get("value").is_some() {
                        set(
                            host,
                            "items",
                            edit["key"].as_str().unwrap(),
                            edit["value"].clone(),
                        )?;
                    } else {
                        host(
                            "delete",
                            json!([{"kind":"collection","name":"items"},edit["key"]]),
                        )?;
                    }
                }
                let direct = host(
                    "range",
                    json!([reference("items", args["options"].clone())]),
                )?;
                let derived = get(host, "derived", "page", args["options"].clone())?;
                Ok(json!({"direct":direct, "derived":derived}))
            }) as Callback,
        ),
        (
            "catch",
            (|args, host| {
                let _ = host("range", json!([reference("items", args.clone())]));
                Ok(json!("caught"))
            }) as Callback,
        ),
    ])
}

fn call(
    data: &Records,
    name: &str,
    args: Value,
    principal: Option<Value>,
) -> EngineResult<Evaluation> {
    let mut invocation = json!({"name":name,"args":args});
    if let Some(principal) = principal {
        invocation["$principal"] = principal;
    }
    run(data.clone(), invocation, "query", None, &fixture())
}

fn keys(page: &Value) -> Vec<&str> {
    page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["key"].as_str().unwrap())
        .collect()
}

fn data(count: usize) -> Records {
    (0..count)
        .map(|i| (source_id("items", &format!("k{i:05}")), json!({"i":i})))
        .collect()
}

fn with_policies(data: &mut Records, policies: Value) {
    let result = run_with_schema(
        data.clone(),
        json!({"requestId":"schema"}),
        "deployment",
        None,
        &fixture(),
        Some(Schema {
            indexes: Vec::new(),
            aggregates: BTreeMap::new(),
            policies: serde_json::from_value(policies).unwrap(),
            derived_access: BTreeMap::new(),
            aggregate_versions: BTreeMap::new(),
            references: Vec::new(),
        }),
    )
    .unwrap();
    apply(data, result);
}

#[test]
fn source_pages_include_every_shape_and_follow_physical_not_utf16_order() {
    let names = [
        "",
        "a",
        "a\"",
        "a\\",
        "a\n",
        "a\0",
        "[\"x\",1]",
        "é",
        "😀",
        "\u{e000}",
    ];
    let values = [
        Value::Null,
        json!(false),
        json!(42),
        json!("primitive"),
        json!([]),
        json!({}),
        json!({"rank":[]}),
        json!({"rank":{}}),
        json!({"rank":null}),
        json!({"rank":3}),
    ];
    for collection in ["items", "quoted\"\\\n😀", ""] {
        let mut data: Records = names
            .iter()
            .zip(&values)
            .map(|(key, value)| (source_id(collection, key), value.clone()))
            .collect();
        data.insert(
            source_id(&format!("{collection}x"), "outside"),
            json!("not returned"),
        );
        let mut expected: Vec<_> = names
            .iter()
            .zip(&values)
            .map(|(key, value)| (source_id(collection, key), json!({"key":key,"value":value})))
            .collect();
        expected.sort_by(|a, b| a.0.cmp(&b.0));
        for data in [data.clone(), data.backed_copy()] {
            let mut after = None;
            let mut found = Vec::new();
            for _ in 0..names.len() {
                let mut options = json!({"limit":3});
                if let Some(after) = after {
                    options["after"] = Value::String(after);
                }
                let page = call(&data, "reference", reference(collection, options), None)
                    .unwrap()
                    .value;
                found.extend(page["rows"].as_array().unwrap().clone());
                after = page["cursor"].as_str().map(str::to_owned);
                if let Some(after) = &after {
                    let last = found.last().unwrap()["key"].as_str().unwrap();
                    assert_eq!(after, &cursor(collection, last));
                } else {
                    break;
                }
            }
            assert_eq!(
                found,
                expected
                    .iter()
                    .map(|(_, row)| row.clone())
                    .collect::<Vec<_>>()
            );
            let page = call(
                &data,
                "reference",
                reference(collection, json!({"limit":100})),
                None,
            )
            .unwrap()
            .value;
            assert!(page["cursor"].is_null());
            assert_eq!(page["rows"], json!(found));
        }
    }
    assert!(source_id("items", "\u{e000}") < source_id("items", "😀"));
    assert_eq!(compare("\u{e000}", "😀"), std::cmp::Ordering::Greater);
    assert_eq!(
        call(&Records::default(), "page", json!({"limit":1}), None)
            .unwrap()
            .value,
        json!({"rows":[],"cursor":null})
    );
}

#[test]
fn source_pages_ten_thousand_rows_seek_boundedly_and_complete_on_both_backends() {
    let memory = data(10_000);
    for data in [memory.clone(), memory.backed_copy()] {
        for (after, start, len, visits, more) in [
            (None, 0, 25, 26, true),
            (Some("k08999"), 9000, 25, 26, true),
            (Some("k09974"), 9975, 25, 25, false),
            (Some("k09999"), 10000, 0, 0, false),
        ] {
            let mut options = json!({"limit":25});
            if let Some(after) = after {
                options["after"] = json!(cursor("items", after));
            }
            source_pages::take_visits();
            let page = call(&data, "page", options, None).unwrap().value;
            assert_eq!(source_pages::take_visits(), (visits, 0));
            assert_eq!(
                keys(&page),
                (start..start + len)
                    .map(|i| format!("k{i:05}"))
                    .collect::<Vec<_>>()
            );
            assert_eq!(page["cursor"].is_string(), more);
        }
        let mut after = None;
        let mut found = Vec::new();
        source_pages::take_visits();
        for _ in 0..400 {
            let mut options = json!({"limit":25});
            if let Some(after) = after {
                options["after"] = Value::String(after);
            }
            let page = call(&data, "page", options, None).unwrap().value;
            found.extend(keys(&page).into_iter().map(str::to_owned));
            after = page["cursor"].as_str().map(str::to_owned);
            if after.is_none() {
                break;
            }
        }
        assert_eq!(
            found,
            (0..10_000).map(|i| format!("k{i:05}")).collect::<Vec<_>>()
        );
        assert!(after.is_none());
        assert_eq!(source_pages::take_visits(), (10_399, 0));
    }
}

#[test]
fn source_page_cursor_does_not_require_its_row_to_survive() {
    let mut data = data(8);
    let first = call(&data, "page", json!({"limit":3}), None).unwrap().value;
    data.remove(&source_id("items", "k00002"));
    data.remove(&source_id("items", "k00003"));
    for data in [data.clone(), data.backed_copy()] {
        let page = call(
            &data,
            "page",
            json!({"limit":3,"after":first["cursor"]}),
            None,
        )
        .unwrap()
        .value;
        assert_eq!(keys(&page), ["k00004", "k00005", "k00006"]);
    }
}

#[test]
fn source_page_merges_pending_inserts_updates_deletes_and_preview() {
    let memory = data(6);
    for data in [memory.clone(), memory.backed_copy()] {
        let result = run(data, json!({"name":"overlay","requestId":"overlay","args":{
            "edits":[{"key":"k00000"},{"key":"k00001","value":null},{"key":"k00002"},{"key":"k000015","value":{"insert":true}}, {"key":"z","value":false}],
            "options":{"limit":3,"after":cursor("items","k00000")}
        }}), "mutation",None,&fixture()).unwrap();
        let expected = json!({"rows":[{"key":"k00001","value":null},{"key":"k000015","value":{"insert":true}},{"key":"k00003","value":{"i":3}}],"cursor":cursor("items","k00003")});
        assert_eq!(result.value, json!({"direct":expected,"derived":expected}));
        assert!(result.deletes.contains(&source_id("items", "k00000")));
        assert_eq!(result.puts[&source_id("items", "k00001")], Value::Null);
    }
}

#[test]
fn source_page_reference_validation_is_closed_and_precedes_traversal() {
    let data = data(3);
    let mut invalid = vec![
        Value::Null,
        json!({}),
        json!({"kind":"sourcePage","collection":"items"}),
        json!({"kind":"sourcePage","collection":3,"options":{"limit":1}}),
        json!({"kind":"sourcePage","collection":"items","options":{"limit":1},"extra":true}),
    ];
    for options in [
        json!({}),
        json!({"limit":0}),
        json!({"limit":-1}),
        json!({"limit":1.5}),
        json!({"limit":"1"}),
        json!({"limit":9_007_199_254_740_992_u64}),
        json!({"limit":1,"reverse":false}),
        json!({"limit":1,"offset":0}),
        json!({"limit":1,"after":null}),
    ] {
        invalid.push(reference("items", options));
    }
    let scope = canonical_json(&json!(["sourcePage", "items"]));
    let valid = cursor("items", "k00000");
    let mut cursors = vec![
        "".into(),
        "{".into(),
        "null".into(),
        format!(" {valid}"),
        cursor("other", "k00000"),
    ];
    for last in [
        "",
        "a",
        "💐",
        "source:",
        "source:null",
        "source:[\"items\",\"k00000\",\"extra\"]",
        "source:[\"items\", \"k00000\"]",
        "source:[\"other\",\"k00000\"]",
        "source:[\"items\",\"\\u006b00000\"]",
    ] {
        cursors.push(canonical_json(
            &json!({"version":1,"scope":scope,"last":last}),
        ));
    }
    for cursor in [
        json!({"version":2,"scope":scope,"last":source_id("items","k00000")}),
        json!({"version":1,"scope":scope,"last":source_id("items","k00000"),"extra":0}),
        json!({"version":1,"scope":scope}),
        json!({"version":1,"scope":scope,"last":null}),
    ] {
        cursors.push(canonical_json(&cursor));
    }
    for after in cursors {
        invalid.push(reference("items", json!({"limit":1,"after":after})));
    }
    for reference in invalid {
        source_pages::take_visits();
        let error = call(&data, "reference", reference.clone(), None).unwrap_err();
        assert_eq!(error.code, "INVALID_REFERENCE", "{reference}");
        assert_eq!(source_pages::take_visits(), (0, 0), "{reference}");
    }
    // JSON accepts 1.0 as the same positive safe integer.
    assert_eq!(
        keys(
            &call(&data, "page", json!({"limit":1.0}), None)
                .unwrap()
                .value
        ),
        ["k00000"]
    );
}

#[test]
fn source_pages_apply_row_and_field_acl_before_limits_and_do_not_leak_hidden_cursors() {
    let mut memory: Records = (0..9)
        .map(|i| {
            (
                source_id("items", &format!("k{i}")),
                json!({"owner":if i%3==0 {"alice"} else {"bob"},"secret":i,"public":i}),
            )
        })
        .collect();
    with_policies(
        &mut memory,
        json!({"items":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"fields":{"secret":{"read":{"const":false}}}}}),
    );
    for data in [memory.clone(), memory.backed_copy()] {
        let first = call(
            &data,
            "page",
            json!({"limit":2}),
            Some(json!({"subject":"alice"})),
        )
        .unwrap()
        .value;
        assert_eq!(keys(&first), ["k0", "k3"]);
        assert_eq!(first["cursor"], cursor("items", "k3"));
        assert!(
            first["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|row| row["value"].get("secret").is_none())
        );
        let next = call(
            &data,
            "page",
            json!({"limit":2,"after":first["cursor"]}),
            Some(json!({"subject":"alice"})),
        )
        .unwrap()
        .value;
        assert_eq!(keys(&next), ["k6"]);
        assert!(next["cursor"].is_null());
        for principal in [json!({"subject":"wrong"}), Value::Null] {
            assert_eq!(
                call(
                    &data,
                    "page",
                    json!({"limit":2,"after":first["cursor"]}),
                    Some(principal)
                )
                .unwrap()
                .value,
                json!({"rows":[],"cursor":null})
            );
        }
        // Same cursor is merely a position, not authority: Bob gets Bob's rows.
        assert_eq!(
            keys(
                &call(
                    &data,
                    "page",
                    json!({"limit":2,"after":first["cursor"]}),
                    Some(json!({"subject":"bob"}))
                )
                .unwrap()
                .value
            ),
            ["k4", "k5"]
        );
        assert_eq!(
            call(&data, "page", json!({"limit":20}), None)
                .unwrap()
                .value["rows"]
                .as_array()
                .unwrap()
                .len(),
            9
        );
        // Derived computations keep their normal caller-independent semantics.
        assert_eq!(
            call(
                &data,
                "derived",
                json!({"limit":20}),
                Some(json!({"subject":"wrong"}))
            )
            .unwrap()
            .value["rows"]
                .as_array()
                .unwrap()
                .len(),
            9
        );
    }
}

#[test]
fn source_page_certificates_follow_collection_and_access_lookup_changes() {
    let mut data = Records::from([
        (
            source_id("items", "a"),
            json!({"permission":"a","secret":1}),
        ),
        (
            source_id("items", "b"),
            json!({"permission":"b","secret":2}),
        ),
        (source_id("permissions", "a"), json!({"owner":"alice"})),
        (source_id("permissions", "b"), json!({"owner":"bob"})),
    ]);
    with_policies(
        &mut data,
        json!({"items":{"read":{"readable":["permissions",{"ref":["row","permission"]}]}},"permissions":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}}),
    );
    let result = call(
        &data,
        "page",
        json!({"limit":1}),
        Some(json!({"subject":"alice"})),
    )
    .unwrap();
    assert_eq!(keys(&result.value), ["a"]);
    assert!(result.value["cursor"].is_null());
    let certificate = result.query_certificate.unwrap();
    for read in [
        collection_id("items"),
        source_id("items", "a"),
        source_id("permissions", "a"),
        source_id("permissions", "b"),
    ] {
        assert!(certificate.observed().contains(&read.as_str()), "{read}");
    }
    assert!(certificate.valid(&data));
    let mut unrelated = data.clone();
    unrelated.insert(source_id("unrelated", "a"), json!(1));
    assert!(certificate.valid(&unrelated));
    for (collection, key, value) in [
        ("items", "z", json!(null)),
        ("items", "b", json!({"permission":"a"})),
        ("permissions", "b", json!({"owner":"alice"})),
        ("permissions", "a", json!({"owner":"bob"})),
    ] {
        let mut changed = data.clone();
        changed.insert(source_id(collection, key), value);
        assert!(!certificate.valid(&changed), "{collection}/{key}");
    }
}

#[test]
fn source_pages_invalidate_materialized_and_cached_derived_values() {
    let fixture = fixture();
    let mut data = data(4);
    let options = json!({"limit":2});
    deploy(
        &mut data,
        json!({"materialize":[{"name":"page","args":options}]}),
        &fixture,
    );
    let result = call(&data, "derived", options.clone(), None).unwrap();
    let certificate = result.query_certificate.unwrap();
    assert!(certificate.valid(&data));
    let deps = data[&cell_id("page", &options)]["deps"].as_array().unwrap();
    assert!(deps.contains(&json!(collection_id("items"))));
    let edit = run(
        data.clone(),
        json!({"name":"write","requestId":"write","args":{"key":"k00000","value":null}}),
        "mutation",
        None,
        &fixture,
    )
    .unwrap();
    assert!(edit.evaluated.contains(&cell_id("page", &options)));
    apply(&mut data, edit);
    assert!(!certificate.valid(&data));
    assert_eq!(
        call(&data, "derived", options.clone(), None).unwrap().value["rows"][0]["value"],
        Value::Null
    );
    let edit = run(
        data.clone(),
        json!({"name":"delete","requestId":"delete","args":"k00001"}),
        "mutation",
        None,
        &fixture,
    )
    .unwrap();
    apply(&mut data, edit);
    assert_eq!(
        keys(&call(&data, "derived", options, None).unwrap().value),
        ["k00000", "k00002"]
    );
}

struct BudgetFixture {
    fixture: Fixture,
    checks: Cell<usize>,
    limit: usize,
}
impl Executor for BudgetFixture {
    fn check_budget(&self) -> EngineResult<()> {
        let checks = self.checks.get() + 1;
        self.checks.set(checks);
        if checks > self.limit {
            Err(EngineError::new("EVALUATION_BUDGET", "test deadline"))
        } else {
            Ok(())
        }
    }
    fn execute(
        &self,
        kind: &str,
        name: &str,
        args: &Value,
        host: &mut EngineHost<'_>,
    ) -> EngineResult<Value> {
        self.fixture.execute(kind, name, args, host)
    }
}

#[test]
fn source_page_work_is_bounded_independently_of_position_unlike_offset_scan() {
    let data = data(10_000);
    let counts = [
        ("page", json!({"limit":25})),
        ("page", json!({"limit":25,"after":cursor("items","k08999")})),
        ("old", json!({"limit":25,"offset":9000})),
    ]
    .map(|(name, args)| {
        let fixture = BudgetFixture {
            fixture: fixture(),
            checks: Cell::new(0),
            limit: usize::MAX,
        };
        run(
            data.clone(),
            json!({"name":name,"args":args}),
            "query",
            None,
            &fixture,
        )
        .unwrap();
        fixture.checks.get()
    });
    assert_eq!(counts[0], counts[1]);
    assert!(
        counts[2] > counts[1],
        "old scan checks={} page checks={}",
        counts[2],
        counts[1]
    );
}

#[test]
fn source_page_memory_and_deadline_failures_remain_sticky_when_caught() {
    let large = Records::from([(source_id("items", "large"), json!("x".repeat(40_000)))]);
    let error = run_with_limit(
        large,
        json!({"name":"catch","args":{"limit":1}}),
        "query",
        None,
        &fixture(),
        8192,
    )
    .unwrap_err();
    assert_eq!(error.code, "EVALUATION_BUDGET");
    let mut hidden = data(10_000);
    with_policies(&mut hidden, json!({"items":{"read":{"const":false}}}));
    let fixture = BudgetFixture {
        fixture: fixture(),
        checks: Cell::new(0),
        limit: 150,
    };
    let error = run(
        hidden,
        json!({"name":"catch","args":{"limit":25},"$principal":{"subject":"nobody"}}),
        "query",
        None,
        &fixture,
    )
    .unwrap_err();
    assert_eq!(error.code, "EVALUATION_BUDGET");
    assert!(fixture.checks.get() < 160);
}

#[test]
fn source_pages_cross_the_real_wasm_range_bridge_and_preserve_native_acl_and_writes() {
    use crate::evaluator::{evaluate_at, hash, invoke_as, invoke_at};
    // As server startup does: compiling the shared sandbox is not part of a
    // timed application request. Keep every invocation's normal deadline.
    crate::evaluator::warmup().unwrap();
    for marker in ["", "/* flower:static-init */"] {
        let javascript = format!(
            r#"{marker}
        const items={{kind:'collection',name:'items'}};
        const page=(ctx,options)=>ctx.range({{kind:'sourcePage',collection:'items',options}});
        var __flowerBundle={{default:{{
            collections:[{{name:'items',indexes:{{}},access:{{
                read:{{eq:[{{ref:['row','owner']}},{{ref:['principal','subject']}}]}},
                fields:{{secret:{{read:{{const:false}}}}}}
            }}}}],
            definitions:{{
                page:{{kind:'derived',name:'page',compute:(ctx,args)=>page(ctx,args)}},
                read:{{kind:'queryMethod',name:'read',compute:(ctx,args)=>page(ctx,args)}},
                save:{{kind:'mutationMethod',name:'save',compute:ctx=>{{
                    ctx.delete(items,'b');ctx.set(items,'aa',null);ctx.set(items,'c',{{changed:true}});
                    return {{direct:page(ctx,{{limit:3}}),derived:ctx.get({{kind:'derived',name:'page'}},{{limit:3}})}};
                }}}},
                malformed:{{kind:'queryMethod',name:'malformed',compute:ctx=>{{
                    try {{page(ctx,{{limit:1,after:'{{"last":"a","scope":"wrong","version":1}}'}});return 'bad';}}
                    catch(error) {{return error.code;}}
                }}}}
            }},
            http:{{read:{{kind:'query',name:'read'}},save:{{kind:'mutation',name:'save'}},malformed:{{kind:'query',name:'malformed'}}}}
        }}}};"#
        );
        let deployed = evaluate_at(
            BTreeMap::new(),
            json!({
                "requestId":"source-pages-wasm-deploy",
                "bundle":{"hash":hash(javascript.as_bytes()),"javascript":javascript},
                "writes":[
                    {"collection":"items","key":"a","value":{"owner":"alice","secret":1}},
                    {"collection":"items","key":"b","value":{"owner":"bob","secret":2}},
                    {"collection":"items","key":"c","value":{"owner":"alice","secret":3}},
                    {"collection":"items","key":"d","value":null},
                    {"collection":"items","key":"e","value":{"owner":"alice"}}
                ]
            }),
            100,
        )
        .unwrap_or_else(|error| panic!("source-page Wasm deployment ({marker:?}): {error:#}"));
        let data: Records = deployed.puts.into();
        let page = invoke_at(
            data.clone(),
            json!({"name":"read","args":{"limit":2}}),
            "query",
            100,
        )
        .unwrap()
        .value;
        assert_eq!(keys(&page), ["a", "b"]);
        assert_eq!(page["cursor"], cursor("items", "b"));
        let page = invoke_at(
            data.clone(),
            json!({"name":"read","args":{"limit":3,"after":page["cursor"]}}),
            "query",
            100,
        )
        .unwrap()
        .value;
        assert_eq!(keys(&page), ["c", "d", "e"]);
        assert!(page["cursor"].is_null());
        let page = invoke_as(
            data.clone(),
            json!({"name":"read","args":{"limit":1}}),
            "query",
            100,
            json!({"subject":"alice"}),
        )
        .unwrap()
        .value;
        assert_eq!(
            page,
            json!({"rows":[{"key":"a","value":{"owner":"alice"}}],"cursor":cursor("items","a")})
        );
        let denied = invoke_as(
            data.clone(),
            json!({"name":"read","args":{"limit":1,"after":page["cursor"]}}),
            "query",
            100,
            json!({"subject":"nobody"}),
        )
        .unwrap()
        .value;
        assert_eq!(denied, json!({"rows":[],"cursor":null}));
        let changed = invoke_at(
            data.clone(),
            json!({"name":"save","requestId":"source-pages-wasm-save"}),
            "mutation",
            100,
        )
        .unwrap()
        .value;
        let expected = json!({"rows":[{"key":"a","value":{"owner":"alice","secret":1}},{"key":"aa","value":null},{"key":"c","value":{"changed":true}}],"cursor":cursor("items","c")});
        assert_eq!(changed, json!({"direct":expected,"derived":expected}));
        assert_eq!(
            invoke_at(data, json!({"name":"malformed"}), "query", 100)
                .unwrap()
                .value,
            "INVALID_REFERENCE"
        );
    }
}

#[test]
fn source_pages_ignore_declared_index_membership_and_open_policies_are_bounded() {
    let mut data = data(10_000);
    for (key, value) in [
        ("missing", json!({})),
        ("null", Value::Null),
        ("nonscalar", json!({"i":[]})),
    ] {
        data.insert(source_id("items", key), value);
    }
    let installed = run_with_schema(
        data.clone(),
        json!({"requestId":"indexed"}),
        "deployment",
        None,
        &fixture(),
        Some(Schema {
            indexes: vec![indexes::IndexSpec {
                collection: "items".into(),
                fields: vec!["i".into()],
            }],
            aggregates: BTreeMap::new(),
            policies: serde_json::from_value(json!({"items":{"read":{"const":true}}})).unwrap(),
            derived_access: BTreeMap::new(),
            aggregate_versions: BTreeMap::new(),
            references: Vec::new(),
        }),
    )
    .unwrap();
    apply(&mut data, installed);
    for data in [data.clone(), data.backed_copy()] {
        source_pages::take_visits();
        let result = call(
            &data,
            "page",
            json!({"limit":25,"after":cursor("items","k08999")}),
            Some(json!({"subject":"any"})),
        )
        .unwrap();
        assert_eq!(source_pages::take_visits(), (26, 0));
        assert_eq!(keys(&result.value).len(), 25);
        let result = call(
            &data,
            "page",
            json!({"limit":25,"after":cursor("items","k09999")}),
            Some(json!({"subject":"any"})),
        )
        .unwrap();
        assert_eq!(keys(&result.value), ["missing", "nonscalar", "null"]);
        assert!(result.value["cursor"].is_null());
    }
}

#[test]
fn source_pages_record_field_redaction_lookups_and_time_dependencies() {
    let mut data = Records::from([
        (
            source_id("items", "a"),
            json!({"permission":"a","secret":1,"until":200}),
        ),
        (source_id("permissions", "a"), json!({"owner":"alice"})),
    ]);
    with_policies(
        &mut data,
        json!({
            "items":{"read":{"gt":[{"ref":["row","until"]},{"ref":["now"]}]},"fields":{"secret":{"read":{"readable":["permissions",{"ref":["row","permission"]}]}}}},
            "permissions":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}
        }),
    );
    let invocation = json!({"name":"page","args":{"limit":1},"$principal":{"subject":"bob"}});
    let result = run(
        data.clone(),
        invocation.clone(),
        "query",
        Some(100),
        &fixture(),
    )
    .unwrap();
    assert_eq!(result.value["rows"][0]["value"].get("secret"), None);
    assert_eq!(result.query_changes_at, Some(200));
    assert!(result.query_clock_polled);
    assert!(!result.query_cacheable);
    assert!(result.query_certificate.is_none());
    data.insert(source_id("permissions", "a"), json!({"owner":"bob"}));
    assert_eq!(
        run(
            data.clone(),
            invocation.clone(),
            "query",
            Some(100),
            &fixture()
        )
        .unwrap()
        .value["rows"][0]["value"]["secret"],
        1
    );
    assert!(
        run(data, invocation, "query", Some(200), &fixture())
            .unwrap()
            .value["rows"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn source_pages_release_hidden_backing_rows_but_bound_retained_access_lookups() {
    let mut hidden = data(10_000);
    with_policies(&mut hidden, json!({"items":{"read":{"const":false}}}));
    for hidden in [hidden.clone(), hidden.backed_copy()] {
        let result = run_with_limit(
            hidden,
            json!({"name":"page","args":{"limit":25},"$principal":{"subject":"none"}}),
            "query",
            None,
            &fixture(),
            16 * 1024,
        )
        .unwrap();
        assert_eq!(result.value, json!({"rows":[],"cursor":null}));
    }
    let mut lookups = Records::default();
    for i in 0..100 {
        lookups.insert(
            source_id("items", &format!("k{i:03}")),
            json!({"permission":format!("k{i:03}")}),
        );
        lookups.insert(
            source_id("permissions", &format!("k{i:03}")),
            json!({"owner":"other","payload":"x".repeat(1024)}),
        );
    }
    with_policies(
        &mut lookups,
        json!({"items":{"read":{"readable":["permissions",{"ref":["row","permission"]}]}},"permissions":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}}),
    );
    let error = run_with_limit(
        lookups.backed_copy(),
        json!({"name":"catch","args":{"limit":25},"$principal":{"subject":"none"}}),
        "query",
        None,
        &fixture(),
        16 * 1024,
    )
    .unwrap_err();
    assert_eq!(error.code, "EVALUATION_BUDGET");
}

#[test]
fn source_page_acl_lookup_reads_pending_inserts_updates_and_deletes() {
    let mut data = Records::from([(
        source_id("items", "a"),
        json!({"permission":"p","secret":42}),
    )]);
    with_policies(
        &mut data,
        json!({
            "items":{"read":{"readable":["permissions",{"ref":["row","permission"]}]},"fields":{"secret":{"read":{"const":false}}}},
            "permissions":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]},"insert":{"const":true},"update":{"const":true},"delete":{"const":true}}
        }),
    );
    let fixture = Fixture::new([(
        "work",
        (|_, host| {
            let page = |host: &mut Host<'_>| {
                host("range", json!([reference("items", json!({"limit":1}))]))
            };
            let absent = page(host)?;
            set(host, "permissions", "p", json!({"owner":"alice"}))?;
            let inserted = page(host)?;
            set(host, "permissions", "p", json!({"owner":"bob"}))?;
            let updated = page(host)?;
            host(
                "delete",
                json!([{"kind":"collection","name":"permissions"},"p"]),
            )?;
            let deleted = page(host)?;
            Ok(json!([absent, inserted, updated, deleted]))
        }) as Callback,
    )]);
    for data in [data.clone(), data.backed_copy()] {
        let result = run(
            data,
            json!({"name":"work","requestId":"acl-overlay","$principal":{"subject":"alice"}}),
            "mutation",
            None,
            &fixture,
        )
        .unwrap();
        let empty = json!({"rows":[],"cursor":null});
        assert_eq!(
            result.value,
            json!([empty,{"rows":[{"key":"a","value":{"permission":"p"}}],"cursor":null},empty,empty])
        );
    }
}

#[test]
fn source_page_field_lookup_is_in_its_stable_certificate() {
    let mut data = Records::from([
        (source_id("items", "a"), json!({"secret":42})),
        (source_id("permissions", "p"), json!({"owner":"alice"})),
    ]);
    with_policies(
        &mut data,
        json!({
            "items":{"read":{"const":true},"fields":{"secret":{"read":{"readable":["permissions",{"value":"p"}]}}}},
            "permissions":{"read":{"eq":[{"ref":["row","owner"]},{"ref":["principal","subject"]}]}}
        }),
    );
    let result = call(
        &data,
        "page",
        json!({"limit":1}),
        Some(json!({"subject":"bob"})),
    )
    .unwrap();
    assert_eq!(result.value["rows"][0]["value"], json!({}));
    let certificate = result.query_certificate.unwrap();
    assert!(
        certificate
            .observed()
            .contains(&source_id("permissions", "p").as_str())
    );
    data.insert(source_id("permissions", "p"), json!({"owner":"bob"}));
    assert!(!certificate.valid(&data));
    assert_eq!(
        call(
            &data,
            "page",
            json!({"limit":1}),
            Some(json!({"subject":"bob"}))
        )
        .unwrap()
        .value["rows"][0]["value"]["secret"],
        42
    );
}
