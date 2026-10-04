use super::*;
use crate::consensus::Consensus;
use crate::service::clock::Clock;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sql_commit_native_authorized_proposal_can_flush_after_expiry_but_later_native_read_refuses()
 {
    let directory = tempfile::tempdir().unwrap();
    let shared = SharedDatabase::open(&directory.path().join("delayed.redb")).unwrap();
    let address = "127.0.0.1:7997".to_owned();
    let consensus = Consensus::open(
        1,
        address.clone(),
        Storage::Shared {
            database: shared.clone(),
            prefix: "sql-delay".into(),
            directory: directory.path().into(),
        },
        "sql-delay-test-only-token".into(),
    )
    .await
    .unwrap();
    consensus
        .initialize(BTreeMap::from([(1, address)]))
        .await
        .unwrap();
    consensus
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native leader ready")
        .await
        .unwrap();
    let clock = Clock::new();
    // Real QuickJS read guard; code warmup completes before the 1.5s lease.
    let javascript = r#"const rows={kind:'collection',name:'sql-proof'};var __flowerBundle={default:{definitions:{
        read:{name:'read',kind:'queryMethod',compute:ctx=>{
            const expiry=ctx.get(rows,'expiry'),now=ctx.clock();
            if(now>=expiry)throw Object.assign(new Error('Permission expired'),{code:'PERMISSION_EXPIRED'});
            ctx.changesAt(expiry);return ctx.get(rows,'private');
        }}},http:{read:{name:'read',kind:'query'}}}};"#;
    let deployment = crate::evaluator::evaluate_at(Records::default(), json!({"requestId":"sql-delay-deploy","bundle":{"hash":crate::evaluator::hash(javascript.as_bytes()),"javascript":javascript}}), clock.sample_after(0).unwrap()).unwrap();
    consensus
        .commit(Commit {
            sql_commit_before: None,
            internal: false,
            request_id: "sql-delay-deploy".into(),
            fingerprint: "deploy".into(),
            expected_revision: 0,
            puts: deployment.puts,
            deletes: deployment.deletes,
            result: Value::Null,
        })
        .await
        .unwrap();
    let (baseline, basis) = consensus.read_for_writer_with_basis(None).await.unwrap();
    let logs = consensus.test_log_entries().await;
    let now = clock.sample(&baseline).unwrap();
    let before = now + 1500;
    let command = Commit {
        sql_commit_before: Some(before),
        internal: false,
        request_id: "sql-delayed-flush".into(),
        fingerprint: "verified-body".into(),
        expected_revision: baseline.revision,
        puts: BTreeMap::from([
            ("source:[\"sql-proof\",\"expiry\"]".into(), json!(before)),
            (
                "source:[\"sql-proof\",\"private\"]".into(),
                json!("SQL_DELAYED_PRIVATE_SENTINEL"),
            ),
        ]),
        deletes: vec![],
        result: json!("SQL_DELAYED_PRIVATE_SENTINEL"),
    };
    // The REAL redb writer lock blocks log fsync, not ordered authorization.
    let blocker = shared.database().begin_write().unwrap();
    {
        let writing = consensus.commit_with_clock(command, clock.clone(), basis);
        tokio::pin!(writing);
        assert!(futures_util::poll!(&mut writing).is_pending());
        consensus.raft.with_raft_state(|_| ()).await.unwrap();
        // The core barrier runs after the request's synchronous ordered append.
        // The readable, not-yet-flushed suffix carries the actual native witness.
        let pending = consensus.test_log_entries().await;
        let entry = pending.last().unwrap();
        assert!(entry.log_id.index > logs.last().unwrap().log_id.index);
        let EntryPayload::Normal(RaftCommand::Sql {
            sql_admission,
            command,
        }) = &entry.payload
        else {
            panic!("SQL admission witness missing")
        };
        assert!(sql_admission.valid(command, entry.log_id));
        assert_eq!(consensus.local_snapshot().await, baseline);
        tokio::time::sleep(Duration::from_millis(
            before.saturating_sub(clock.sample_after(0).unwrap()) + 30,
        ))
        .await;
        assert!(clock.sample_after(0).unwrap() > before);
        assert!(
            futures_util::poll!(&mut writing).is_pending(),
            "no ack or apply while fsync blocked"
        );
        drop(blocker);
        // Already-authorized in-flight proposal is NOT falsely aborted at apply.
        assert!(!writing.await.unwrap().duplicate);
    }
    let current = consensus.read_for_writer().await.unwrap();
    assert_eq!(current.revision, baseline.revision + 1);
    assert!(current.requests.contains_key("sql-delayed-flush"));
    let error = crate::evaluator::invoke_as(
        current.data.clone(),
        json!({"name":"read","args":null}),
        "query",
        clock.sample(&current).unwrap(),
        json!({"subject":"reader"}),
    )
    .unwrap_err();
    assert!(error.to_string().contains("PERMISSION_EXPIRED"));
    assert!(!error.to_string().contains("SQL_DELAYED_PRIVATE_SENTINEL"));
    consensus.shutdown().await.unwrap();
}
