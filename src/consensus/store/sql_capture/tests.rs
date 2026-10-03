use super::*;
use openraft::CommittedLeaderId;
use serde_json::json;
use std::time::Duration;

fn log(index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(3, 1), index)
}
fn entry(index: u64, revision: u64, key: &str, value: Value) -> Entry<TypeConfig> {
    Entry {
        log_id: log(index),
        payload: EntryPayload::Normal(
            Commit {
                internal: true,
                request_id: String::new(),
                fingerprint: String::new(),
                expected_revision: revision,
                puts: BTreeMap::from([(key.to_owned(), value)]),
                deletes: Vec::new(),
                result: Value::Null,
            }
            .into(),
        ),
    }
}
fn buffer() -> SqlCaptureBuffer {
    SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
}
fn request<'a>(keys: &'a [&'a str]) -> SqlCaptureRequest<'a> {
    SqlCaptureRequest {
        selection: SqlCaptureSelection::Keys(keys),
        max_records: 32,
        max_examined: 128,
    }
}
async fn capture(
    store: &Store,
    fence: &SqlCaptureFence,
    expected: Option<&SqlCaptureEpoch>,
    keys: &[&str],
) -> Result<SqlCapturedSlice, SqlCaptureError> {
    // One scheduled due wake is not polling. No writers remain in these fixtures.
    match store.sql_capture_slice(None, fence, expected, request(keys), buffer()) {
        Err(SqlCaptureError::Paced(due)) => {
            tokio::time::sleep_until(due.into()).await;
            store.sql_capture_slice(None, fence, expected, request(keys), buffer())
        }
        result => result,
    }
}

#[tokio::test]
async fn sql_capture_store_binds_fence_and_rejects_revision_or_installation_change() {
    let first_dir = tempfile::tempdir().unwrap();
    let second_dir = tempfile::tempdir().unwrap();
    let mut first = Store::open(1, first_dir.path().into()).await.unwrap();
    let mut second = Store::open(1, second_dir.path().into()).await.unwrap();
    first
        .apply([entry(1, 0, "key", json!({"old":true}))])
        .await
        .unwrap();
    second
        .apply([entry(2, 0, "key", json!({"different":true}))])
        .await
        .unwrap();
    first.inner.persistence.drain().await.unwrap();
    second.inner.persistence.drain().await.unwrap();
    let fence = first.sql_capture_bind_fence(first.read_fence().unwrap(), None);
    assert_eq!(
        second
            .sql_capture_slice(None, &fence, None, request(&["key"]), buffer())
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    let input = capture(&first, &fence, None, &["key", "missing"])
        .await
        .unwrap();
    assert_eq!(input.epoch.revision, 1);
    assert!(input.buffer.records().nth(1).unwrap().body.is_none());
    first
        .apply([entry(3, 1, "key", json!({"new":true}))])
        .await
        .unwrap();
    first.inner.persistence.drain().await.unwrap();
    let fresh = first.sql_capture_bind_fence(first.read_fence().unwrap(), None);
    assert_eq!(
        capture(&first, &fresh, Some(&input.epoch), &["key"])
            .await
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    let current = capture(&first, &fresh, None, &["key"]).await.unwrap();
    // An installation may reuse a logical revision; this identity is separate.
    first
        .inner
        .snapshot_installation
        .fetch_add(1, Ordering::AcqRel);
    assert_eq!(
        capture(&first, &fresh, Some(&current.epoch), &["key"])
            .await
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    first.close().await.unwrap();
    second.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_store_refuses_registered_actual_writer_and_releases_publication_before_control()
 {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, "key", json!({"n":1}))])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let job = store.database_work();
    let (entered, seen) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let writer = tokio::task::spawn_blocking(move || {
        job.run(|db| {
            let transaction = db.begin_write().unwrap();
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            transaction.abort().unwrap();
        })
    });
    tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();
    assert_eq!(
        store
            .sql_capture_slice(None, &fence, None, request(&["key"]), buffer())
            .unwrap_err(),
        SqlCaptureError::Busy
    );
    release.send(()).unwrap();
    writer.await.unwrap();
    let copied = capture(&store, &fence, None, &["key"]).await.unwrap();
    // Owned bytes remain, but no publication read guard/source root prevents
    // a real Raft vote or a subsequent application publication.
    tokio::time::timeout(Duration::from_secs(5), store.save_vote(&Vote::new(4, 1)))
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(
        Duration::from_secs(5),
        store.apply([entry(2, 1, "key", json!({"n":2}))]),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(copied.epoch.revision, 1);
    assert_eq!(copied.buffer.records().len(), 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_store_cancelled_waiter_does_not_release_actual_storage_job() {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, "key", json!({"n":1}))])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let job = store.database_work();
    let (entered, seen) = std::sync::mpsc::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let writer = tokio::task::spawn_blocking(move || {
        job.run(|db| {
            let transaction = db.begin_write().unwrap();
            entered.send(()).unwrap();
            wait.recv_timeout(Duration::from_secs(5)).unwrap();
            transaction.abort().unwrap();
        })
    });
    tokio::task::spawn_blocking(move || seen.recv_timeout(Duration::from_secs(5)).unwrap())
        .await
        .unwrap();
    writer.abort();
    assert_eq!(
        store
            .sql_capture_slice(None, &fence, None, request(&["key"]), buffer())
            .unwrap_err(),
        SqlCaptureError::Busy
    );
    release.send(()).unwrap();
    let _ = writer.await;
    let copied = capture(&store, &fence, None, &["key"]).await.unwrap();
    assert_eq!(copied.buffer.records().len(), 1);
    store.close().await.unwrap();
}
