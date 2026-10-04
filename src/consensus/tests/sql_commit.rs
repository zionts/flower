use super::*;
use crate::service::clock::Clock;
use openraft::RaftLogReader;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sql_commit_native_core_queue_expiry_refuses_before_any_log_id_or_payload() {
    let mut node = Node::new(1).await;
    node.raft()
        .initialize(BTreeMap::from([(1, node.address.clone())]))
        .await
        .unwrap();
    node.raft()
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native leader ready")
        .await
        .unwrap();
    let (baseline, basis) = node.raft().read_for_writer_with_basis(None).await.unwrap();
    let logs = node.raft().test_log_entries().await;
    let (entered, at_barrier) = tokio::sync::oneshot::channel();
    let (release, blocked) = std::sync::mpsc::sync_channel(1);
    node.raft().raft.external_request(move |_| {
        entered.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    tokio::time::timeout(Duration::from_secs(5), at_barrier)
        .await
        .unwrap()
        .unwrap();
    let clock = Clock::new();
    let before = clock.sample(&baseline).unwrap() + 1500;
    let mut command = commit("sql-core-expired", baseline.revision, 42);
    command.sql_commit_before = Some(before);
    command.result = json!("SQL_PRIVATE_CORE_SENTINEL");
    {
        let writing = node.raft().commit_with_clock(command, clock.clone(), basis);
        tokio::pin!(writing);
        assert!(
            futures_util::poll!(&mut writing).is_pending(),
            "real request queued behind the ordered core barrier"
        );
        tokio::time::sleep(Duration::from_millis(
            before.saturating_sub(clock.sample_after(0).unwrap()) + 30,
        ))
        .await;
        assert!(clock.sample_after(0).unwrap() > before);
        assert_eq!(node.raft().local_snapshot().await, baseline);
        release.send(()).unwrap();
        let error = writing.await.unwrap_err();
        assert!(crate::sql_commit::is_expired(&error), "{error}");
    }
    assert_eq!(node.raft().read_for_writer().await.unwrap(), baseline);
    assert_eq!(node.raft().test_log_entries().await, logs);
    node.stop().await;
}

#[tokio::test]
async fn sql_commit_native_logged_admission_is_deterministic_across_late_replay_and_term_change() {
    let mut node = Node::new(1).await;
    node.raft()
        .initialize(BTreeMap::from([(1, node.address.clone())]))
        .await
        .unwrap();
    node.raft()
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native leader ready")
        .await
        .unwrap();
    let (_, basis) = node.raft().read_for_writer_with_basis(None).await.unwrap();
    let clock = Clock::new();
    let now = clock.sample_after(0).unwrap();
    let mut command = commit("sql-replay", 0, 42);
    command.sql_commit_before = Some(now + 1500);
    let result = node
        .raft()
        .commit_with_clock(command, clock.clone(), basis)
        .await
        .unwrap();
    assert!(!result.duplicate);
    let mut stored = node.raft().store.clone();
    let mut entries = stored.try_get_log_entries(..).await.unwrap();
    let entry = entries.pop().unwrap();
    drop(stored);
    let EntryPayload::Normal(RaftCommand::Sql {
        ref sql_admission,
        ref command,
    }) = entry.payload
    else {
        panic!("actual SQL proposal witness missing")
    };
    assert!(sql_admission.valid(command, entry.log_id));
    tokio::time::sleep(Duration::from_millis(
        (now + 1500).saturating_sub(clock.sample_after(0).unwrap()) + 30,
    ))
    .await;
    let before = node.raft().read_for_writer().await.unwrap();
    node.stop().await;
    node.restart().await;
    node.raft()
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native restarted leader ready")
        .await
        .unwrap();
    assert_eq!(node.raft().read_for_writer().await.unwrap(), before);
    // Logged admission, not today's replica clock, determines replay. A receipt
    // replays its prior authorized outcome, never reapplies or pretends an abort.
    let mut replay = entry.clone();

    let results = node
        .raft()
        .store
        .clone()
        .apply([replay.clone()])
        .await
        .unwrap();
    assert!(matches!(&results[0], ApplyResult::Committed(value) if value.duplicate));
    assert_eq!(node.raft().local_snapshot().await, before);
    // The exact leader identity, including node, is bound in the durable entry.

    replay.log_id.leader_id = CommittedLeaderId::new(entry.log_id.leader_id.term, 2);
    assert!(matches!(
        node.raft().store.clone().apply([replay]).await.unwrap()[0],
        ApplyResult::Rejected(_)
    ));
    assert_eq!(node.raft().local_snapshot().await, before);
    node.stop().await;
}

#[tokio::test]
async fn sql_commit_native_revision_change_refuses_private_payload_before_log() {
    let mut node = Node::new(1).await;
    node.raft()
        .initialize(BTreeMap::from([(1, node.address.clone())]))
        .await
        .unwrap();
    node.raft()
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native leader ready")
        .await
        .unwrap();
    let (baseline, basis) = node.raft().read_for_writer_with_basis(None).await.unwrap();
    node.raft()
        .commit(commit("authority-change", baseline.revision, 1))
        .await
        .unwrap();
    let current = node.raft().read_for_writer().await.unwrap();
    let logs = node.raft().test_log_entries().await;
    let clock = Clock::new();
    let mut guarded = commit("stale-private", baseline.revision, 2);
    guarded.sql_commit_before = Some(clock.sample_after(0).unwrap() + 60000);
    guarded.result = json!("SQL_STALE_PRIVATE_SENTINEL");
    let error = node
        .raft()
        .commit_with_clock(guarded, clock, basis)
        .await
        .unwrap_err();
    assert!(crate::sql_commit::is_stale(&error), "{error}");
    assert_eq!(node.raft().read_for_writer().await.unwrap(), current);
    assert_eq!(node.raft().test_log_entries().await, logs);
    node.stop().await;
}

#[tokio::test]
async fn sql_commit_native_same_revision_snapshot_install_refuses_original_basis_before_log() {
    let mut node = Node::new(1).await;
    node.raft()
        .initialize(BTreeMap::from([(1, node.address.clone())]))
        .await
        .unwrap();
    node.raft()
        .raft
        .wait(Some(Duration::from_secs(5)))
        .current_leader(1, "native leader ready")
        .await
        .unwrap();
    let (baseline, basis) = node.raft().read_for_writer_with_basis(None).await.unwrap();
    let mut store = node.raft().store.clone();
    let snapshot = store.build_snapshot().await.unwrap();
    store
        .install_snapshot(&snapshot.meta, snapshot.snapshot)
        .await
        .unwrap();
    assert_eq!(
        node.raft().local_snapshot().await.revision,
        baseline.revision
    );
    let logs = node.raft().test_log_entries().await;
    let clock = Clock::new();
    let mut guarded = commit("installed-private", baseline.revision, 2);
    guarded.sql_commit_before = Some(clock.sample_after(0).unwrap() + 60000);
    let error = node
        .raft()
        .commit_with_clock(guarded, clock, basis)
        .await
        .unwrap_err();
    assert!(crate::sql_commit::is_stale(&error), "{error}");
    assert_eq!(node.raft().local_snapshot().await, baseline);
    assert_eq!(node.raft().test_log_entries().await, logs);
    drop(store);
    node.stop().await;
}
