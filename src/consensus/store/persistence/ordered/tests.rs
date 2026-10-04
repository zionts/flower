use super::*;
use crate::consensus::PartitionCommand;
use crate::consensus::sql_registry::directory::SourceStatus;
use serde_json::json;

// Concrete ordinary-data callback only. This test does not synthesize native
// source admission, accepted work, META, or the production actor/apply hook.
fn publish(
    state: &mut StoredState,
    published: &mut Published,
    mut projected: StateWrite,
    sequence: u64,
) -> anyhow::Result<()> {
    state.application.data.keep_deletions();
    state.application.requests.keep_deletions();
    for (key, bytes) in projected.data {
        if let Some(bytes) = bytes {
            let version = u64::from_le_bytes(bytes[..8].try_into().unwrap());
            let json = crate::consensus::packed::unpack(&bytes[8..])?;
            let value: Value = serde_json::from_slice(&json)?;
            state
                .application
                .data
                .insert_versioned(key.clone(), Arc::new(value), version);
        } else {
            state.application.data.remove(&key);
        }
        state.application.data.stamp(&key, sequence);
    }
    for key in projected.deleted_requests {
        state.application.requests.remove(&key);
        state.application.requests.stamp(&key, sequence);
    }
    for (key, bytes) in projected.requests {
        let version = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let json = crate::consensus::packed::unpack(&bytes[8..])?;
        let receipt: Receipt = serde_json::from_slice(&json)?;
        state
            .application
            .requests
            .insert_versioned(key.clone(), Arc::new(receipt), version);
        state.application.requests.stamp(&key, sequence);
    }
    for (_, mut partition) in std::mem::take(&mut projected.partitions) {
        partition.stamp(sequence);
        state.partitions.insert(partition.state);
    }
    state.last_applied = projected.metadata.last_applied;
    state.membership = projected.metadata.membership;
    state.application.revision = projected.metadata.revision;
    let mut next = Published::from(&*state);
    next.installation = published.installation;
    *published = next;
    Ok(())
}

fn status(store: &Store) -> SourceStatus {
    crate::consensus::sql_registry::source_registry()
        .unwrap()
        .directory()
        .unwrap()
        .store_status_native(store.inner.capture_identity)
        .unwrap()
}
fn counts(store: &Store) -> (u64, u64) {
    (
        store.inner.persistence.submitted_count(),
        store.inner.persistence.persisted_count(),
    )
}
fn assert_uncredited_disk(store: &Store) {
    assert_eq!(counts(store), (0, 0));
    let tx = store.inner.shared.begin_read().unwrap();
    assert!(
        tx.open_table(store.inner.tables.data)
            .unwrap()
            .get(b"row".as_slice())
            .unwrap()
            .is_none()
    );
    assert!(
        tx.open_table(store.inner.tables.requests)
            .unwrap()
            .get(b"receipt".as_slice())
            .unwrap()
            .is_none()
    );
    let meta = tx.open_table(store.inner.tables.meta).unwrap();
    let metadata: StateMetadata =
        serde_json::from_slice(meta.get(STATE_META).unwrap().unwrap().value()).unwrap();
    assert_eq!(metadata.revision, 0);
    assert_eq!(metadata.last_applied, None);
}
fn add_receipt(projected: &mut StateWrite) {
    projected.requests.push((
        "receipt".into(),
        crate::consensus::backing::encode(
            crate::consensus::next_version(),
            &serde_json::to_vec(&Receipt {
                fingerprint: "complete".into(),
                revision: projected.metadata.revision,
                result: Value::Null,
                epoch: None,
            })
            .unwrap(),
        ),
    ));
}

fn log(index: u64) -> LogId<u64> {
    LogId::new(openraft::CommittedLeaderId::new(3, 1), index)
}
fn write(state: &StoredState, revision: u64, rows: &[(&str, Option<Value>)]) -> StateWrite {
    let mut metadata = StateMetadata::from(state);
    metadata.last_applied = Some(log(revision));
    metadata.revision = revision;
    StateWrite {
        data: rows
            .iter()
            .map(|(key, value)| {
                (
                    key.to_string(),
                    value.as_ref().map(|value| {
                        crate::consensus::backing::encode(
                            crate::consensus::next_version(),
                            &serde_json::to_vec(value).unwrap(),
                        )
                    }),
                )
            })
            .collect(),
        requests: vec![],
        deleted_requests: vec![],
        metadata,
        partitions: BTreeMap::new(),
    }
}

#[tokio::test]
async fn native_inline_projection_requires_actual_same_store_owned_order_guards() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let store = Store::open(1, a.path().into()).await.unwrap();
    let foreign = Store::open(2, b.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let other_state = foreign.inner.state.clone().write_owned().await;
    let other_io = foreign.inner.io.clone().lock_owned().await;
    assert!(InlineProjection::begin(&store.inner, &other_state, &io).is_err());
    assert!(InlineProjection::begin(&store.inner, &state, &other_io).is_err());
    let token = InlineProjection::begin(&store.inner, &state, &io).unwrap();
    assert_eq!(token.sequence(), 1);
    drop(token);
    assert_eq!(store.inner.persistence.submitted_count(), 0);
    assert_eq!(store.inner.persistence.persisted_count(), 0);
}

#[tokio::test]
async fn native_inline_projection_aborted_real_transaction_never_counts_as_submitted_or_persisted()
{
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let token = InlineProjection::begin(&store.inner, &state, &io).unwrap();
    let projected = write(&state, 1, &[("row", Some(json!(null)))]);
    store.database_work().run(|db| {
        let transaction = db.begin_write().unwrap();
        // A REAL table-open error, not a fake caller error/commit receipt.
        let held_table = transaction.open_table(store.inner.tables.data).unwrap();
        assert!(
            projected
                .project(
                    &transaction,
                    store.inner.tables,
                    &mut StorageTrace::default()
                )
                .is_err()
        );
        drop(held_table);
        transaction.abort().unwrap();
    });
    drop(token);
    assert_eq!(store.inner.persistence.submitted_count(), 0);
    assert_eq!(store.inner.persistence.persisted_count(), 0);
    let tx = store.inner.shared.begin_read().unwrap();
    assert!(
        tx.open_table(store.inner.tables.data)
            .unwrap()
            .get(b"row".as_slice())
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn native_inline_projection_commits_complete_rows_receipts_metadata_and_versions_together() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let token = InlineProjection::begin(&store.inner, &state, &io).unwrap();
    let mut projected = write(
        &state,
        1,
        &[("null-row", Some(Value::Null)), ("gone", None)],
    );
    let receipt = Receipt {
        fingerprint: "native-inline".into(),
        revision: 1,
        result: json!({"ok":true}),
        epoch: None,
    };
    projected.requests.push((
        "native-inline".into(),
        crate::consensus::backing::encode(
            crate::consensus::next_version(),
            &serde_json::to_vec(&receipt).unwrap(),
        ),
    ));
    projected.deleted_requests.push("old-receipt".into());
    let expected_data = projected.data[0].1.clone().unwrap();
    let expected_request = projected.requests[0].1.clone();
    drop(token);
    let sequence = store
        .database_work()
        .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
        .run(publish)
        .unwrap();
    assert_eq!(sequence, 1);
    assert_eq!(store.inner.persistence.submitted_count(), 1);
    assert_eq!(store.inner.persistence.persisted_count(), 1);
    let tx = store.inner.shared.begin_read().unwrap();
    let data = tx.open_table(store.inner.tables.data).unwrap();
    assert!(data.get(b"gone".as_slice()).unwrap().is_none());
    assert_eq!(
        data.get(b"null-row".as_slice()).unwrap().unwrap().value(),
        expected_data.as_slice()
    );
    let requests = tx.open_table(store.inner.tables.requests).unwrap();
    assert!(requests.get(b"old-receipt".as_slice()).unwrap().is_none());
    assert_eq!(
        requests
            .get(b"native-inline".as_slice())
            .unwrap()
            .unwrap()
            .value(),
        expected_request.as_slice()
    );
    let meta = tx.open_table(store.inner.tables.meta).unwrap();
    let metadata: StateMetadata =
        serde_json::from_slice(meta.get(STATE_META).unwrap().unwrap().value()).unwrap();
    assert_eq!(metadata.last_applied, Some(log(1)));
    assert_eq!(metadata.revision, 1);
    assert!(metadata.versions >= crate::consensus::versions_high_water());
}

#[tokio::test]
async fn native_inline_projection_refuses_undrained_actual_queue_and_accepts_after_real_completion()
{
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    let blocked_io = store.inner.io.clone().lock_owned().await;
    store
        .apply([Entry {
            log_id: log(1),
            payload: EntryPayload::Normal(RaftCommand::Single(Commit {
                sql_commit_before: None,
                internal: true,
                request_id: "queued".into(),
                fingerprint: "queued".into(),
                expected_revision: 0,
                puts: BTreeMap::from([("row".into(), json!(1))]),
                deletes: vec![],
                result: Value::Null,
            })),
        }])
        .await
        .unwrap();
    {
        let state = store.inner.state.clone().write_owned().await;
        assert!(InlineProjection::begin(&store.inner, &state, &blocked_io).is_err());
    }
    drop(blocked_io);
    store.inner.persistence.drain().await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    store.inner.pending.idle().await;
    let token = InlineProjection::begin(&store.inner, &state, &io).unwrap();
    assert_eq!(token.sequence(), 2);
    drop(token);
    assert_eq!(store.inner.persistence.submitted_count(), 1);
    assert_eq!(store.inner.persistence.persisted_count(), 1);
}

#[tokio::test]
async fn native_inline_projection_real_scoped_write_keeps_exact_namespace_and_root_separation() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let namespace = "A\0source-💚";
    let mut scoped = BTreeMap::new();
    assert!(matches!(
        apply_partition_control(
            &state.partitions,
            &mut scoped,
            PartitionCommand::Create {
                partition: namespace.into(),
                epoch: 1,
                operation: "native-inline-scoped".into(),
            }
        ),
        ApplyResult::Partition(_)
    ));
    assert!(matches!(
        apply_partition_control(
            &state.partitions,
            &mut scoped,
            PartitionCommand::Activate {
                partition: namespace.into(),
                epoch: 1,
                operation: "native-inline-scoped".into(),
            }
        ),
        ApplyResult::Partition(_)
    )); // REAL Staged -> Active boundary, not a forged phase.
    let key = r#"source:["rows","key"]"#;
    assert!(matches!(
        apply_scoped(
            &state.partitions,
            &mut scoped,
            PartitionBinding {
                partition: namespace.into(),
                epoch: 1
            },
            RaftCommand::Single(Commit {
                sql_commit_before: None,
                internal: true,
                request_id: "native-inline-scoped".into(),
                fingerprint: "scoped".into(),
                expected_revision: 0,
                puts: BTreeMap::from([(key.into(), Value::Null)]),
                deletes: vec![],
                result: Value::Null,
            }),
            log(3)
        ),
        ApplyResult::Committed(_)
    ));
    let mut projected = write(&state, 0, &[("root", Some(json!(true)))]);
    projected.metadata.last_applied = Some(log(3));
    projected.partitions = scoped;
    let token = InlineProjection::begin(&store.inner, &state, &io).unwrap();
    drop(token);
    assert_eq!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    let tx = store.inner.shared.begin_read().unwrap();
    let root = tx.open_table(store.inner.tables.data).unwrap();
    assert!(root.get(key.as_bytes()).unwrap().is_none());
    let data = tx.open_table(store.inner.tables.partition_data).unwrap();
    let stored = data
        .get((namespace.as_bytes(), key.as_bytes()))
        .unwrap()
        .unwrap();
    assert_eq!(&stored.value()[8..], b"null");
    assert!(
        data.get((b"A".as_slice(), key.as_bytes()))
            .unwrap()
            .is_none()
    );
    assert!(
        data.get((namespace.as_bytes(), b"root".as_slice()))
            .unwrap()
            .is_none()
    );
    let metadata = tx.open_table(store.inner.tables.partition_meta).unwrap();
    assert!(metadata.get(namespace).unwrap().is_some());
    assert!(metadata.get("A").unwrap().is_none());
}

#[tokio::test]
async fn native_inline_factory_refuses_foreign_physical_database_before_mutation_or_publication() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    // Equal physical table spellings are deliberately NOT owner identity.
    let store = Store::open(1, a.path().into()).await.unwrap();
    let foreign = Store::open(1, b.path().into()).await.unwrap();
    assert_eq!(
        store.inner.tables.data.name(),
        foreign.inner.tables.data.name()
    );
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    // Ordinary ? propagation has NO foreign armed Pubguard to poison B.
    let refusal = (|| -> anyhow::Result<()> {
        foreign
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)?;
        Ok(())
    })();
    assert!(
        refusal
            .unwrap_err()
            .to_string()
            .contains("different physical database")
    );
    assert_uncredited_disk(&store);
    assert_uncredited_disk(&foreign);
    assert_eq!(status(&store), SourceStatus::Ready);
    assert_eq!(status(&foreign), SourceStatus::Ready);
    assert!(store.check_availability(None).is_ok());
    assert!(foreign.check_availability(None).is_ok());
}

#[tokio::test]
async fn native_inline_factory_same_physical_database_uses_actual_inner_prefix_only() {
    let directory = tempfile::tempdir().unwrap();
    let shared = SharedDatabase::open(&directory.path().join("shared.redb")).unwrap();
    let a = Store::open(
        1,
        Storage::Shared {
            database: shared.clone(),
            prefix: "A/💚\0".into(),
            directory: directory.path().into(),
        },
    )
    .await
    .unwrap();
    let b = Store::open(
        2,
        Storage::Shared {
            database: shared.clone(),
            prefix: "B/💚\0".into(),
            directory: directory.path().into(),
        },
    )
    .await
    .unwrap();
    let state = a.inner.state.clone().write_owned().await;
    let io = a.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    // DatabaseWork owns a physical file, NOT caller-selectable tables. Even
    // obtaining it from B cannot redirect A's transaction into B's namespace.
    assert_eq!(
        b.database_work()
            .prepare_inline_ordinary(&a, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    assert_eq!(counts(&a), (1, 1));
    assert_uncredited_disk(&b);
    let tx = shared.begin_read().unwrap();
    assert!(
        tx.open_table(a.inner.tables.data)
            .unwrap()
            .get(b"row".as_slice())
            .unwrap()
            .is_some()
    );
    assert!(
        tx.open_table(a.inner.tables.requests)
            .unwrap()
            .get(b"receipt".as_slice())
            .unwrap()
            .is_some()
    );
    assert_eq!(status(&a), SourceStatus::Ready);
    assert_eq!(status(&b), SourceStatus::Ready);
}

#[tokio::test]
async fn native_inline_factory_failed_requests_after_real_data_prefix_aborts_and_marks_only_a_fatal()
 {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    let store = Store::open(1, a.path().into()).await.unwrap();
    let healthy = Store::open(2, b.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    let published = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let called = published.clone();
    let error = store
        .database_work()
        .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
        .run_with_fault(
            move |_, _, _, _| {
                called.store(true, Ordering::Release);
                Ok(())
            },
            InlineFault::RequestsAlreadyOpen,
        )
        .unwrap_err();
    assert!(matches!(error.downcast_ref::<redb::TableError>(),
        Some(redb::TableError::TableAlreadyOpen(name, _)) if name == store.inner.tables.requests.name()
    ));
    assert!(!published.load(Ordering::Acquire));
    assert_uncredited_disk(&store);
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert!(store.check_availability(None).is_err());
    assert!(store.snapshot_for(None).await.is_err());
    assert_eq!(status(&healthy), SourceStatus::Ready);
    assert!(healthy.check_availability(None).is_ok());
}

#[tokio::test]
async fn native_inline_factory_failed_state_meta_after_rows_and_receipts_aborts_complete_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    let error = store
        .database_work()
        .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
        .run_with_fault(publish, InlineFault::StateMetaAlreadyOpen)
        .unwrap_err();
    assert!(matches!(error.downcast_ref::<redb::TableError>(),
        Some(redb::TableError::TableAlreadyOpen(name, _)) if name == store.inner.tables.meta.name()
    ));
    assert_uncredited_disk(&store);
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert_eq!(store.inner.published.read().unwrap().revision, 0);
}

fn scoped(state: &StoredState, namespace: &str) -> BTreeMap<String, PartitionWrite> {
    let mut projected = BTreeMap::new();
    for command in [
        PartitionCommand::Create {
            partition: namespace.into(),
            epoch: 1,
            operation: "ordinary".into(),
        },
        PartitionCommand::Activate {
            partition: namespace.into(),
            epoch: 1,
            operation: "ordinary".into(),
        },
    ] {
        assert!(matches!(
            apply_partition_control(&state.partitions, &mut projected, command),
            ApplyResult::Partition(_)
        ));
    }
    assert!(matches!(
        apply_scoped(
            &state.partitions,
            &mut projected,
            PartitionBinding {
                partition: namespace.into(),
                epoch: 1
            },
            RaftCommand::Single(Commit {
                sql_commit_before: None,
                internal: true,
                request_id: "scoped-receipt".into(),
                fingerprint: "ordinary".into(),
                expected_revision: 0,
                puts: BTreeMap::from([("null\0💚".into(), Value::Null)]),
                deletes: vec![],
                result: Value::Null,
            }),
            log(3)
        ),
        ApplyResult::Committed(_)
    ));
    projected
}

#[tokio::test]
async fn native_inline_factory_partition_table_failure_aborts_root_and_receipt_prefix() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    projected.partitions = scoped(&state, "A\0💚");
    let error = store
        .database_work()
        .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
        .run_with_fault(publish, InlineFault::PartitionMetaAlreadyOpen)
        .unwrap_err();
    assert!(matches!(error.downcast_ref::<redb::TableError>(),
        Some(redb::TableError::TableAlreadyOpen(name, _)) if name == store.inner.tables.partition_meta.name()
    ));
    assert_uncredited_disk(&store);
    assert_eq!(status(&store), SourceStatus::Fatal);
    let tx = store.inner.shared.begin_read().unwrap();
    assert!(
        tx.open_table(store.inner.tables.partition_meta)
            .unwrap()
            .get("A\0💚")
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn native_inline_factory_malformed_codec_tail_after_complete_projection_aborts_all_tables() {
    for bytes in [
        vec![1, 2, 3],
        [1u64.to_le_bytes().as_slice(), b"\0\x01"].concat(),
        [1u64.to_le_bytes().as_slice(), b"{broken"].concat(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(1, directory.path().into()).await.unwrap();
        let state = store.inner.state.clone().write_owned().await;
        let io = store.inner.io.clone().lock_owned().await;
        let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
        projected
            .data
            .push(("zz-malformed-tail".into(), Some(bytes)));
        add_receipt(&mut projected);
        let error = store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish);
        assert!(error.is_err());
        assert_uncredited_disk(&store);
        assert_eq!(status(&store), SourceStatus::Fatal);
        let tx = store.inner.shared.begin_read().unwrap();
        assert!(
            tx.open_table(store.inner.tables.data)
                .unwrap()
                .get(b"zz-malformed-tail".as_slice())
                .unwrap()
                .is_none()
        );
        assert_eq!(store.inner.published.read().unwrap().revision, 0);
    }
}

#[tokio::test]
async fn native_inline_factory_empty_delta_still_forces_real_complete_state_metadata_projection() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let projected = write(&state, 1, &[]);
    assert_eq!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    assert_eq!(counts(&store), (1, 1));
    let tx = store.inner.shared.begin_read().unwrap();
    let meta = tx.open_table(store.inner.tables.meta).unwrap();
    let metadata: StateMetadata =
        serde_json::from_slice(meta.get(STATE_META).unwrap().unwrap().value()).unwrap();
    assert_eq!(metadata.revision, 1);
    assert_eq!(metadata.last_applied, Some(log(1)));
    assert_eq!(store.snapshot_for(None).await.unwrap().revision, 1);
}

#[tokio::test]
async fn native_inline_factory_sensitive_projection_refuses_before_mutation_and_keeps_unknown_not_empty()
 {
    for key in ["bundle", "schema", "httpMethods", "terminalMethods"] {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(1, directory.path().into()).await.unwrap();
        let state = store.inner.state.clone().write_owned().await;
        let io = store.inner.io.clone().lock_owned().await;
        let projected = write(&state, 1, &[("row", Some(Value::Null)), (key, None)]);
        assert!(
            store
                .database_work()
                .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
                .run(publish)
                .is_err()
        );
        assert_uncredited_disk(&store);
        assert_eq!(status(&store), SourceStatus::Ready);
    }
}

#[tokio::test]
async fn native_inline_factory_scoped_sensitive_or_control_work_requires_unimplemented_meta_hook() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[]);
    projected.partitions = scoped(&state, "scope");
    projected
        .partitions
        .get_mut("scope")
        .unwrap()
        .state
        .snapshot
        .data
        .insert_versioned(
            "schema".into(),
            Arc::new(json!({"protected_sources":true})),
            crate::consensus::next_version(),
        );
    assert!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .is_err()
    );
    assert_uncredited_disk(&store);
    assert_eq!(status(&store), SourceStatus::Ready);
}

#[tokio::test]
async fn native_inline_factory_panic_after_staging_marks_fatal_without_fictional_credit() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let healthy_dir = tempfile::tempdir().unwrap();
    let healthy = Store::open(2, healthy_dir.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run_with_fault(publish, InlineFault::BeforeCommitPanic)
    }));
    assert!(result.is_err());
    assert_eq!(counts(&store), (0, 0));
    // Actual redb Drop under panic marks repair, NOT guaranteed clean abort.
    // Do not assert disk rollback or try to publish/retry it as Ready.
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert!(store.check_availability(None).is_err());
    assert!(store.inner.published.is_poisoned());
    assert_eq!(status(&healthy), SourceStatus::Ready);
    assert!(healthy.check_availability(None).is_ok());
    assert!(store.inner.state.try_write().is_ok());
    assert!(store.inner.io.try_lock().is_ok());
}

#[tokio::test]
async fn native_inline_factory_publication_failure_after_real_commit_retains_true_counts_but_is_fatal()
 {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let projected = write(&state, 1, &[("row", Some(Value::Null))]);
    let result = store
        .database_work()
        .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
        .run(|_, _, _, _| -> anyhow::Result<()> {
            anyhow::bail!("actual publication failed after commit")
        });
    assert!(result.is_err());
    assert_eq!(counts(&store), (1, 1));
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert!(store.check_availability(None).is_err());
    assert!(
        store
            .inner
            .shared
            .begin_read()
            .unwrap()
            .open_table(store.inner.tables.data)
            .unwrap()
            .get(b"row".as_slice())
            .unwrap()
            .is_some()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inline_factory_publication_panic_is_sticky_fatal_before_waiter_reads() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let projected = write(&state, 1, &[("row", Some(Value::Null))]);
    let prepared = store.database_work().prepare_inline_ordinary(
        &store,
        state,
        io,
        projected,
        StorageTrace::default(),
    );
    let witness = store.clone();
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let job = tokio::task::spawn_blocking(move || {
        prepared.run(move |_, _, _, _| -> anyhow::Result<()> {
            entered.send(()).unwrap();
            release_rx.recv().unwrap();
            panic!("actual post-commit publication unwind");
        })
    });
    entered_rx.await.unwrap();
    assert_eq!(counts(&store), (1, 1));
    let reader = tokio::task::spawn_blocking(move || witness.check_availability(None).is_err());
    release.send(()).unwrap();
    assert!(job.await.unwrap_err().is_panic());
    assert!(reader.await.unwrap());
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert!(store.check_availability(None).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inline_factory_cancelled_waiter_keeps_real_inner_guards_and_capture_exclusion_through_publication()
 {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let weak = Arc::downgrade(&store.inner);
    let identity = store.inner.capture_identity;
    let shared = store.inner.shared.clone();
    let state_lock = store.inner.state.clone();
    let io_lock = store.inner.io.clone();
    let state = state_lock.clone().write_owned().await;
    let io = io_lock.clone().lock_owned().await;
    let projected = write(&state, 1, &[("row", Some(Value::Null))]);
    let prepared = store.database_work().prepare_inline_ordinary(
        &store,
        state,
        io,
        projected,
        StorageTrace::default(),
    );
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let (done, done_rx) = tokio::sync::oneshot::channel();
    let job = tokio::task::spawn_blocking(move || {
        let result = prepared.run(move |state, published, projected, sequence| {
            entered.send(()).unwrap();
            release_rx.recv().unwrap();
            publish(state, published, projected, sequence)
        });
        // The factory has returned: ALL its genuine owners/cleanup finished.
        done.send(result).unwrap();
    });
    entered_rx.await.unwrap();
    let mut waiting = Box::pin(async move { job.await });
    assert!(futures_util::poll!(&mut waiting).is_pending());
    drop(waiting);
    drop(store);
    assert!(weak.upgrade().is_some());
    assert!(state_lock.try_write().is_err());
    assert!(io_lock.try_lock().is_err());
    assert!(matches!(
        shared.try_capture_permit(),
        Err(shared::CaptureUnavailable::Busy)
    ));
    assert_eq!(
        crate::consensus::sql_registry::source_registry()
            .unwrap()
            .directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Ready
    );
    release.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(30), done_rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        1
    );
    assert!(
        weak.upgrade().is_none(),
        "real detached inline job must not leak Inner"
    );
    assert!(state_lock.try_write().is_ok());
    assert!(io_lock.try_lock().is_ok());
    assert!(shared.try_capture_permit().is_ok());
    let directory = crate::consensus::sql_registry::source_registry()
        .unwrap()
        .directory()
        .unwrap();
    directory.retire_store_native(identity).unwrap();
    assert_eq!(
        directory.store_status_native(identity).unwrap(),
        SourceStatus::Unregistered
    );
}

fn entry(
    index: u64,
    expected: u64,
    id: &str,
    puts: &[(&str, Value)],
    deletes: &[&str],
) -> Entry<TypeConfig> {
    Entry {
        log_id: log(index),
        payload: EntryPayload::Normal(RaftCommand::Single(Commit {
            sql_commit_before: None,
            internal: false,
            request_id: id.into(),
            fingerprint: id.into(),
            expected_revision: expected,
            puts: puts
                .iter()
                .map(|(k, v)| (k.to_string(), v.clone()))
                .collect(),
            deletes: deletes.iter().map(|key| key.to_string()).collect(),
            result: Value::Null,
        })),
    }
}

#[tokio::test]
async fn native_inline_factory_real_queue_before_and_after_inline_preserves_sequence_rebase_and_tombstones()
 {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    store
        .apply([entry(
            1,
            0,
            "queued-before",
            &[("gone", json!(1)), ("overwrite", json!(1))],
            &[],
        )])
        .await
        .unwrap();
    assert!(
        store
            .snapshot_for(Some("queued-before"))
            .await
            .unwrap()
            .requests
            .contains_key("queued-before"),
        "real ordinary receipt exists before inline deletion"
    );
    let state = store.inner.state.clone().write_owned().await;
    store.inner.persistence.drain().await.unwrap();
    let io = store.inner.io.clone().lock_owned().await;
    store.inner.pending.idle().await;
    assert_eq!(counts(&store), (1, 1));
    let mut projected = write(
        &state,
        2,
        &[
            ("gone", None),
            ("overwrite", Some(Value::Null)),
            ("inline\0💚", Some(json!(true))),
        ],
    );
    projected.deleted_requests.push("queued-before".into());
    add_receipt(&mut projected);
    assert_eq!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        2
    );
    assert_eq!(counts(&store), (2, 2));
    store
        .apply([entry(
            3,
            2,
            "queued-after",
            &[("after", json!(3))],
            &["inline\0💚"],
        )])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(counts(&store), (3, 3));
    // The next actual apply rebases against persisted=3. A fictitious inline
    // credit would incorrectly retire either the insertion or tombstone here.
    store
        .apply([entry(4, 3, "rebase", &[("final", json!(4))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(counts(&store), (4, 4));
    let snapshot = store.snapshot_for(None).await.unwrap();
    assert_eq!(snapshot.revision, 4);
    assert!(!snapshot.data.contains_key("gone"));
    assert!(!snapshot.data.contains_key("inline\0💚"));
    assert_eq!(snapshot.data.get("overwrite"), Some(&Value::Null));
    assert_eq!(snapshot.data.get("after"), Some(&json!(3)));
    assert_eq!(snapshot.data.get("final"), Some(&json!(4)));
    assert!(
        !store
            .snapshot_for(Some("queued-before"))
            .await
            .unwrap()
            .requests
            .contains_key("queued-before")
    );
    assert!(
        store
            .snapshot_for(Some("receipt"))
            .await
            .unwrap()
            .requests
            .contains_key("receipt")
    );
    assert!(
        store
            .snapshot_for(Some("queued-after"))
            .await
            .unwrap()
            .requests
            .contains_key("queued-after")
    );
    drop(snapshot);
    store.close().await.unwrap();
    drop(store);
    let reopened = Store::open(1, directory.path().into()).await.unwrap();
    let snapshot = reopened.snapshot_for(None).await.unwrap();
    assert_eq!(snapshot.revision, 4);
    assert!(!snapshot.data.contains_key("gone"));
    assert!(!snapshot.data.contains_key("inline\0💚"));
    assert_eq!(snapshot.data.get("overwrite"), Some(&Value::Null));
    assert_eq!(snapshot.data.get("after"), Some(&json!(3)));
}

#[tokio::test]
async fn native_inline_factory_actual_queued_projection_encoding_matches_root_scoped_null_unicode_and_nul()
 {
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    let a = Store::open(1, a_dir.path().into()).await.unwrap();
    let b = Store::open(2, b_dir.path().into()).await.unwrap();
    let state = a.inner.state.clone().write_owned().await;
    let io = a.inner.io.clone().lock_owned().await;
    let mut projected = write(
        &state,
        1,
        &[
            ("root\0💚", Some(Value::Null)),
            (
                "packed-é",
                Some(json!("same encoded real codec".repeat(1000))),
            ),
            ("gone", None),
        ],
    );
    projected.partitions = scoped(&state, "A\0💚");
    add_receipt(&mut projected);
    let queued = StateWrite {
        data: projected.data.clone(),
        requests: projected.requests.clone(),
        deleted_requests: projected.deleted_requests.clone(),
        metadata: projected.metadata.clone(),
        partitions: projected.partitions.clone(),
    };
    // The ACTUAL ordinary persistence runner uses the exact same StateWrite,
    // not a stand-in root, fabricated encode function, or success boolean.
    b.inner
        .persistence
        .submit(Arc::downgrade(&b.inner), b.inner.holders.clone(), queued);
    b.inner.persistence.drain().await.unwrap();
    assert_eq!(
        a.database_work()
            .prepare_inline_ordinary(&a, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    assert_eq!(counts(&a), (1, 1));
    assert_eq!(counts(&b), (1, 1));
    let a_tx = a.inner.shared.begin_read().unwrap();
    let b_tx = b.inner.shared.begin_read().unwrap();
    type EncodedRow = (Vec<u8>, Vec<u8>);
    type EncodedPairRow = (Vec<u8>, Vec<u8>, Vec<u8>);
    let plain = |tx: &redb::ReadTransaction, table: Table<&'static [u8]>| -> Vec<EncodedRow> {
        tx.open_table(table)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| {
                let (k, v) = row.unwrap();
                (k.value().to_vec(), v.value().to_vec())
            })
            .collect()
    };
    let pairs = |tx: &redb::ReadTransaction, table: PairTable| -> Vec<EncodedPairRow> {
        tx.open_table(table)
            .unwrap()
            .iter()
            .unwrap()
            .map(|row| {
                let (k, v) = row.unwrap();
                (
                    k.value().0.to_vec(),
                    k.value().1.to_vec(),
                    v.value().to_vec(),
                )
            })
            .collect()
    };
    assert_eq!(
        plain(&a_tx, a.inner.tables.data),
        plain(&b_tx, b.inner.tables.data)
    );
    assert_eq!(
        plain(&a_tx, a.inner.tables.requests),
        plain(&b_tx, b.inner.tables.requests)
    );
    assert_eq!(
        pairs(&a_tx, a.inner.tables.partition_data),
        pairs(&b_tx, b.inner.tables.partition_data)
    );
    assert_eq!(
        pairs(&a_tx, a.inner.tables.partition_requests),
        pairs(&b_tx, b.inner.tables.partition_requests)
    );
    let a_meta = a_tx.open_table(a.inner.tables.partition_meta).unwrap();
    let b_meta = b_tx.open_table(b.inner.tables.partition_meta).unwrap();
    assert_eq!(
        a_meta.get("A\0💚").unwrap().unwrap().value(),
        b_meta.get("A\0💚").unwrap().unwrap().value()
    );
    assert!(a_meta.get("A").unwrap().is_none());
    assert!(b_meta.get("A").unwrap().is_none());
    for (tx, tables) in [(&a_tx, a.inner.tables), (&b_tx, b.inner.tables)] {
        let meta = tx.open_table(tables.meta).unwrap();
        let stored: StateMetadata =
            serde_json::from_slice(meta.get(STATE_META).unwrap().unwrap().value()).unwrap();
        assert_eq!(stored.revision, 1);
        assert_eq!(stored.last_applied, Some(log(1)));
    }
}

// Actual Store/source-startup fixture, same fields as store::tests; not a native grant.
fn fault_store_with_database(directory: &std::path::Path, db: Database) -> Store {
    sql_source::test_bootstrap().unwrap();
    let source_startup = sql_source::PreparingStore::begin().unwrap();
    let transaction = db.begin_write().unwrap();
    transaction.open_table(LOGS).unwrap();
    let mut state = load_application(&transaction, Tables::new("")).unwrap();
    transaction.open_table(DATA).unwrap();
    transaction.open_table(REQUESTS).unwrap();
    let checkpoint = recover_checkpoint(&transaction, Tables::new(""), 1, &state).unwrap();
    transaction.commit().unwrap();
    state.application =
        stored_application(&db, Tables::new(""), state.application.revision).unwrap();
    let current_snapshot = checkpoint;
    let store = Store {
        inner: Arc::new(Inner {
            appending: Arc::new(PublishedLock::new(Vec::new())),
            pending: Default::default(),
            id: 1,
            shared: SharedDatabase::with_database(db),
            tables: Tables::new(""),
            snapshot_directory: directory.to_path_buf(),
            io: Arc::new(Mutex::new(())),
            capture_identity: source_startup.identity(),
            snapshot_installation: AtomicU64::new(0),
            current_snapshot: PublishedLock::new(current_snapshot),
            snapshot_accounting: crate::consensus::snapshot_policy::Accounting::new(0, None, None),
            published: Arc::new(PublishedLock::new(Published::from(&state))),
            state: Arc::new(RwLock::new(state)),
            lazy: Default::default(),
            persistence: Default::default(),
            backing_persisted: Default::default(),
            rebase_rounds: Default::default(),
            replaced_partitions: Default::default(),
            holders: Default::default(),
            changes: crate::consensus::changes::sender(),
            backup: Default::default(),
        }),
        raft_lifetime: None,
    };
    source_startup.finish(&store.inner).unwrap();
    store
}

#[derive(Debug)]
struct PausedCommitFault {
    entered: tokio::sync::oneshot::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
}

#[derive(Debug)]
struct CommitFaultBackend {
    file: redb::backends::FileBackend,
    armed: Arc<std::sync::atomic::AtomicBool>,
    faults: Arc<std::sync::atomic::AtomicUsize>,
    pause: Arc<std::sync::Mutex<Option<PausedCommitFault>>>,
}
impl CommitFaultBackend {
    fn fail_if_armed(&self) -> std::io::Result<()> {
        if !self.armed.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Some(pause) = self.pause.lock().unwrap().take() {
            pause.entered.send(()).unwrap();
            pause.release.recv().unwrap();
        }
        self.faults.fetch_add(1, Ordering::AcqRel);
        Err(std::io::Error::other("actual inline commit backend fault"))
    }
}
impl redb::StorageBackend for CommitFaultBackend {
    fn len(&self) -> std::io::Result<u64> {
        self.file.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        self.fail_if_armed()?;
        self.file.read(offset, out)
    }
    fn write(&self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.fail_if_armed()?;
        self.file.write(offset, bytes)
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        self.file.set_len(len)
    }
    fn sync_data(&self) -> std::io::Result<()> {
        self.file.sync_data()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inline_factory_real_redb_commit_error_is_uncredited_and_fatal_not_retried() {
    let directory = tempfile::tempdir().unwrap();
    drop(Store::open(1, directory.path().into()).await.unwrap());
    let armed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let faults = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (entered, entered_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let pause = Arc::new(std::sync::Mutex::new(Some(PausedCommitFault {
        entered,
        release: release_rx,
    })));
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(directory.path().join("flower.redb"))
        .unwrap();
    let database = Database::builder()
        .set_cache_size(0)
        .create_with_backend(CommitFaultBackend {
            file: redb::backends::FileBackend::new(file).unwrap(),
            armed: armed.clone(),
            faults: faults.clone(),
            pause,
        })
        .unwrap();
    let store = fault_store_with_database(directory.path(), database);
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 1, &[("row", Some(Value::Null))]);
    add_receipt(&mut projected);
    let prepared = store.database_work().prepare_inline_ordinary(
        &store,
        state,
        io,
        projected,
        StorageTrace::default(),
    );
    let job = tokio::task::spawn_blocking(move || {
        prepared.run_with_fault(publish, InlineFault::BeforeCommitIo(armed))
    });
    // This event comes from a real backend operation within actual commit;
    // staging completed and SAME publication/state/io/mutation custody is live.
    tokio::time::timeout(std::time::Duration::from_secs(30), entered_rx)
        .await
        .unwrap()
        .unwrap();
    let witness = store.clone();
    let (reading, reading_rx) = tokio::sync::oneshot::channel();
    let reader = tokio::task::spawn_blocking(move || {
        reading.send(()).unwrap();
        witness.check_availability(None).is_err()
    });
    reading_rx.await.unwrap();
    release.send(()).unwrap();
    let error = job.await.unwrap().unwrap_err();
    assert!(
        reader.await.unwrap(),
        "waiter must never read Ready after failed commit"
    );
    // No synthetic bool/commit receipt: prove this is the actual consuming
    // redb commit, not a staging/begin error or an unchanged caller assertion.
    assert!(
        error.downcast_ref::<redb::CommitError>().is_some(),
        "{error:#}"
    );
    assert!(faults.load(Ordering::Acquire) > 0);
    assert_eq!(counts(&store), (0, 0));
    assert_eq!(status(&store), SourceStatus::Fatal);
    assert!(store.check_availability(None).is_err());
    assert!(store.snapshot_for(None).await.is_err());
    assert_eq!(store.inner.published.read().unwrap().revision, 0);
    assert!(store.inner.state.try_write().is_ok());
    assert!(store.inner.io.try_lock().is_ok());
    // A commit Err need not imply physical rollback. No disk-absence claim,
    // retry, failed-counter refund, or recovery-to-Ready is asserted here.
}

#[tokio::test]
async fn native_inline_factory_existing_partition_retirement_requires_native_meta_and_cannot_land_rows_only()
 {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 0, &[]);
    projected.metadata.last_applied = Some(log(3));
    projected.partitions = scoped(&state, "scope");
    assert_eq!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 0, &[("row", Some(Value::Null))]);
    assert!(matches!(
        apply_partition_control(
            &state.partitions,
            &mut projected.partitions,
            PartitionCommand::Discard {
                partition: "scope".into(),
                epoch: 1,
                operation: "retire".into()
            }
        ),
        ApplyResult::Partition(_)
    ));
    assert!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .is_err()
    );
    assert_eq!(counts(&store), (1, 1));
    assert_eq!(status(&store), SourceStatus::Ready);
    assert_eq!(
        store.partition_info("scope").unwrap().phase,
        crate::consensus::PartitionPhase::Active
    );
    let tx = store.inner.shared.begin_read().unwrap();
    assert!(
        tx.open_table(store.inner.tables.data)
            .unwrap()
            .get(b"row".as_slice())
            .unwrap()
            .is_none()
    );
    assert!(
        tx.open_table(store.inner.tables.partition_data)
            .unwrap()
            .get((b"scope".as_slice(), "null\0💚".as_bytes()))
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn native_inline_factory_existing_scoped_absent_code_delete_is_not_an_ordinary_meta_claim() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 0, &[]);
    projected.partitions = scoped(&state, "scope");
    assert_eq!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .unwrap(),
        1
    );
    let state = store.inner.state.clone().write_owned().await;
    let io = store.inner.io.clone().lock_owned().await;
    let mut projected = write(&state, 0, &[]);
    assert!(matches!(
        apply_scoped(
            &state.partitions,
            &mut projected.partitions,
            PartitionBinding {
                partition: "scope".into(),
                epoch: 1
            },
            RaftCommand::Single(Commit {
                sql_commit_before: None,
                internal: true,
                request_id: "absent-code".into(),
                fingerprint: "absent-code".into(),
                expected_revision: 1,
                puts: BTreeMap::new(),
                deletes: vec!["schema".into()],
                result: Value::Null,
            }),
            log(4)
        ),
        ApplyResult::Committed(_)
    ));
    assert_eq!(
        projected.partitions["scope"]
            .state
            .snapshot
            .data
            .raw_version("schema"),
        None
    );
    assert!(
        store
            .database_work()
            .prepare_inline_ordinary(&store, state, io, projected, StorageTrace::default())
            .run(publish)
            .is_err()
    );
    assert_eq!(counts(&store), (1, 1));
    assert_eq!(status(&store), SourceStatus::Ready);
}

// This exact assertion is first run against the reviewed old factory, then
// retained while its source argument becomes an authentic target custodian.
async fn inline_shutdown_span(sibling_work: bool) {
    let directory = tempfile::tempdir().unwrap();
    let shared = SharedDatabase::open(&directory.path().join("shared.redb")).unwrap();
    let a = Store::open(
        1,
        Storage::Shared {
            database: shared.clone(),
            prefix: "A/".into(),
            directory: directory.path().into(),
        },
    )
    .await
    .unwrap();
    let b = Store::open(
        2,
        Storage::Shared {
            database: shared.clone(),
            prefix: "B/".into(),
            directory: directory.path().into(),
        },
    )
    .await
    .unwrap();
    let (tracked, mut drained) = a.raft_storage();
    let state_lock = a.inner.state.clone();
    let io_lock = a.inner.io.clone();
    let state = state_lock.clone().write_owned().await;
    let io = io_lock.clone().lock_owned().await;
    let projected = write(&state, 1, &[("row", Some(Value::Null))]);
    let work = if sibling_work {
        b.database_work()
    } else {
        a.database_work()
    };
    let prepared = work.prepare_inline_ordinary(&a, state, io, projected, StorageTrace::default());
    let (queued, queued_rx) = tokio::sync::oneshot::channel();
    let (start, start_rx) = std::sync::mpsc::channel();
    let (publishing, publishing_rx) = tokio::sync::oneshot::channel();
    let (release, release_rx) = std::sync::mpsc::channel();
    let (done, done_rx) = tokio::sync::oneshot::channel();
    let job = tokio::task::spawn_blocking(move || {
        queued.send(()).unwrap();
        start_rx.recv().unwrap();
        let result = prepared.run(move |state, published, projected, sequence| {
            publishing.send(()).unwrap();
            release_rx.recv().unwrap();
            publish(state, published, projected, sequence)
        });
        done.send(result).unwrap();
    });
    queued_rx.await.unwrap();
    let mut waiting = Box::pin(job);
    assert!(futures_util::poll!(&mut waiting).is_pending());
    drop(waiting); // real blocking work is now detached, not stopped
    drop(tracked); // actual Raft lifetime runs close before its drained signal
    let mut closing = Box::pin(a.close());
    let queued_pending = futures_util::poll!(&mut closing).is_pending();
    if !queued_pending {
        // Cleanup the real blocked worker even when OLD custody fails.
        drop(closing);
        start.send(()).unwrap();
        release.send(()).unwrap();
        let _ = done_rx.await;
        assert!(
            queued_pending,
            "actual target close returned while its detached inline job was queued"
        );
        return;
    }
    start.send(()).unwrap();
    publishing_rx.await.unwrap();
    assert_eq!(counts(&a), (1, 1));
    let publishing_pending = futures_util::poll!(&mut closing).is_pending();
    if !publishing_pending {
        drop(closing);
        release.send(()).unwrap();
        let _ = done_rx.await;
        assert!(
            publishing_pending,
            "actual target close returned before its committed inline publication completed"
        );
        return;
    }
    assert!(matches!(drained.has_changed(), Ok(false)));
    release.send(()).unwrap();
    assert_eq!(done_rx.await.unwrap().unwrap(), 1);
    closing.await.unwrap();
    assert!(
        drained.changed().await.is_err(),
        "actual Raft drained signal must close after genuine target cleanup"
    );
    assert!(state_lock.try_write().is_ok());
    assert!(io_lock.try_lock().is_ok());
    assert!(shared.try_capture_permit().is_ok());
    assert_eq!(a.snapshot_for(None).await.unwrap().revision, 1);
    assert_eq!(b.snapshot_for(None).await.unwrap().revision, 0);
    assert_eq!(status(&a), SourceStatus::Ready);
    assert_eq!(status(&b), SourceStatus::Ready);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inline_shutdown_sibling_work_counts_actual_target_before_detached_dispatch() {
    inline_shutdown_span(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_inline_shutdown_untracked_work_counts_actual_target_before_detached_dispatch() {
    inline_shutdown_span(false).await;
}

#[tokio::test]
async fn native_inline_shutdown_dropping_undispatched_job_releases_all_resources_before_target_holder()
 {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let (tracked, mut drained) = store.raft_storage();
    let state_lock = store.inner.state.clone();
    let io_lock = store.inner.io.clone();
    let state = state_lock.clone().write_owned().await;
    let io = io_lock.clone().lock_owned().await;
    let projected = write(&state, 1, &[("row", Some(Value::Null))]);
    let prepared = tracked.database_work().prepare_inline_ordinary(
        &store,
        state,
        io,
        projected,
        StorageTrace::default(),
    );
    drop(tracked);
    let mut closing = Box::pin(store.close());
    assert!(futures_util::poll!(&mut closing).is_pending());
    assert!(state_lock.try_write().is_err());
    assert!(io_lock.try_lock().is_err());
    // No worker dispatch, transaction, SourceReady or fabricated completion.
    // Rust drops this job's actual fields before its last target Held field.
    drop(prepared);
    closing.await.unwrap();
    assert!(drained.changed().await.is_err());
    assert!(state_lock.try_write().is_ok());
    assert!(io_lock.try_lock().is_ok());
    assert_uncredited_disk(&store);
    assert_eq!(status(&store), SourceStatus::Ready);
}
