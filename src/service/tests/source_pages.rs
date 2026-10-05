//! Real HTTP -> service authorization/cache -> Wasm range bridge -> native page.
use super::*;

#[tokio::test]
async fn source_page_http_uses_current_principal_and_invalidates_warm_pages() {
    // Production initializes the shared Wasm runtime before serving requests.
    evaluator::warmup().unwrap();
    let javascript = r#"
        const records={kind:'collection',name:'records'};
        const notes={kind:'collection',name:'notes'};
        const page=(ctx,args)=>ctx.range({kind:'sourcePage',collection:'notes',options:args});
        var __flowerBundle={default:{
            collections:[{name:'notes',indexes:{},access:{
                read:{eq:[{ref:['row','owner']},{ref:['principal','subject']}]},
                insert:{const:true},update:{const:true},delete:{const:true},
                fields:{secret:{read:{const:false},write:{const:true}}}
            }}],
            definitions:{
                stable:{kind:'derived',name:'stable',compute:ctx=>ctx.get(records,'value')},
                authorize:{kind:'queryMethod',name:'authorize',compute:(_ctx,req)=>
                    typeof req.credentials==='string'?{subject:req.credentials}:null},
                read:{kind:'queryMethod',name:'read',compute:page},
                seed:{kind:'mutationMethod',name:'seed',compute:ctx=>{
                    ctx.set(notes,'a',{owner:'alice',secret:1});
                    ctx.set(notes,'b',{owner:'bob',secret:2});
                    ctx.set(notes,'c',{owner:'alice',secret:3});
                    ctx.set(notes,'d',null);
                    return page(ctx,{limit:1});
                }},
                replace:{kind:'mutationMethod',name:'replace',compute:(ctx,args)=>{
                    ctx.set(notes,args.key,args.value);return null;
                }}
            },
            authorize:{name:'authorize'},
            http:{read:{kind:'query',name:'read'},seed:{kind:'mutation',name:'seed'},replace:{kind:'mutation',name:'replace'}}
        }};
    "#.to_owned();
    let (_directory, app) = application(javascript).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = super::super::router(app.consensus.clone(), "test-only-secret".into());
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let post = |path: &'static str, body: Value| {
        let client = client.clone();
        async move {
            let response = client
                .post(format!("http://{address}{path}"))
                .json(&body)
                .send()
                .await
                .unwrap();
            let status = response.status();
            let value: Value = response.json().await.unwrap();
            assert!(status.is_success(), "{status}: {value}");
            value["value"].clone()
        }
    };
    let first = post(
        "/v1/mutate",
        json!({"name":"seed","credentials":"alice","requestId":"source-page-seed"}),
    )
    .await;
    assert_eq!(
        first["rows"],
        json!([{"key":"a","value":{"owner":"alice"}}])
    );
    let cursor = first["cursor"].as_str().unwrap();
    assert!(cursor.contains("sourcePage"));
    let read = json!({"name":"read","credentials":"alice","args":{"limit":1}});
    for _ in 0..2 {
        assert_eq!(post("/v1/query", read.clone()).await, first);
    }
    let next = post(
        "/v1/query",
        json!({"name":"read","credentials":"alice","args":{"limit":1,"after":cursor}}),
    )
    .await;
    assert_eq!(
        next,
        json!({"rows":[{"key":"c","value":{"owner":"alice"}}],"cursor":null})
    );
    let bob = post(
        "/v1/query",
        json!({"name":"read","credentials":"bob","args":{"limit":1,"after":cursor}}),
    )
    .await;
    assert_eq!(
        bob,
        json!({"rows":[{"key":"b","value":{"owner":"bob"}}],"cursor":null})
    );
    let denied = post(
        "/v1/query",
        json!({"name":"read","credentials":"outsider","args":{"limit":1,"after":cursor}}),
    )
    .await;
    assert_eq!(denied, json!({"rows":[],"cursor":null}));
    post("/v1/mutate",json!({"name":"replace","credentials":"alice","requestId":"source-page-replace","args":{"key":"a","value":{"owner":"bob","secret":9}}})).await;
    let refreshed = post("/v1/query", read).await;
    assert_eq!(
        refreshed,
        json!({"rows":[{"key":"c","value":{"owner":"alice"}}],"cursor":null})
    );
    stop.send(()).unwrap();
    server.await.unwrap();
    app.consensus.shutdown().await.unwrap();
}
