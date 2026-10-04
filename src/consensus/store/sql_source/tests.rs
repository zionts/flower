//! Actual Store/open/Inner publication-guard tests. The source pool bootstrap
//! here is the explicitly approved cfg(test) fixture, NOT NativeNode backing or
//! a current-registry/serving/controller proof.
use super::*;
use crate::consensus::sql_registry::directory::SourceStatus;

#[tokio::test]
async fn sql_source_actual_open_registers_ready_and_final_inner_retires_without_new_fields() {
    fixture::bootstrap().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let identity = store.inner.capture_identity;
    let pool = pool().unwrap();
    assert_eq!(
        pool.directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Ready
    );
    let observer = Arc::downgrade(&store.inner);
    let clone = store.clone();
    drop(store);
    assert!(observer.upgrade().is_some());
    assert_eq!(
        pool.directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Ready
    );
    drop(clone);
    assert!(observer.upgrade().is_none());
    // A concurrent gate can leave the actual logical retirement tag until the
    // next bounded gate; reclaim explicitly, not by polling/waiting/sleeping.
    pool.directory()
        .unwrap()
        .retire_store_native(identity)
        .unwrap();
    assert_eq!(
        pool.directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Unregistered
    );
}

#[tokio::test]
async fn sql_source_cancelled_actual_open_keeps_preparing_until_real_blocking_worker_ends() {
    fixture::bootstrap().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let shared = SharedDatabase::open(&directory.path().join("flower.redb")).unwrap();
    let blocker = shared.database().begin_write().unwrap();
    let mut preparing = PreparingStore::begin().unwrap();
    let identity = preparing.identity();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    preparing.notify_retirement(sender);
    let mut opening = Box::pin(Store::open_started(
        1,
        Storage::Shared {
            database: shared.clone(),
            prefix: "startup/".into(),
            directory: directory.path().to_owned(),
        },
        preparing,
    ));
    assert!(futures_util::poll!(&mut opening).is_pending());
    drop(opening);
    assert_eq!(
        pool()
            .unwrap()
            .directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Preparing
    );
    drop(blocker);
    // This event comes from the armed guard's actual retirement, AFTER its real
    // blocking startup output drops. The wait is a test hang watchdog only.
    tokio::time::timeout(std::time::Duration::from_secs(30), receiver)
        .await
        .unwrap()
        .unwrap();
    pool()
        .unwrap()
        .directory()
        .unwrap()
        .retire_store_native(identity)
        .unwrap();
    assert_eq!(
        pool()
            .unwrap()
            .directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Unregistered
    );
}

#[tokio::test]
async fn sql_source_actual_open_failure_retires_preparing_and_never_exposes_inner() {
    fixture::bootstrap().unwrap();
    let file = tempfile::NamedTempFile::new().unwrap();
    let preparing = PreparingStore::begin().unwrap();
    let identity = preparing.identity();
    assert!(
        Store::open_started(1, file.path().into(), preparing)
            .await
            .is_err()
    );
    pool()
        .unwrap()
        .directory()
        .unwrap()
        .retire_store_native(identity)
        .unwrap();
    assert_eq!(
        pool()
            .unwrap()
            .directory()
            .unwrap()
            .store_status_native(identity)
            .unwrap(),
        SourceStatus::Unregistered
    );
    // Actual subsequent useful open succeeds; failed startup didn't permanently
    // consume a finite lifecycle slot or reset/reuse the private source issuer.
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    assert!(store.inner.capture_identity > identity);
    assert!(store.check_availability(None).is_ok());
}

#[tokio::test]
async fn sql_source_actual_publication_failure_marks_only_affected_store_before_real_guard_unlock()
{
    fixture::bootstrap().unwrap();
    let failed_dir = tempfile::tempdir().unwrap();
    let healthy_dir = tempfile::tempdir().unwrap();
    let failed = Store::open(1, failed_dir.path().into()).await.unwrap();
    let healthy = Store::open(2, healthy_dir.path().into()).await.unwrap();
    let guard = PublicationGuard::acquire(&failed.inner).unwrap();
    let witness = failed.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let job = tokio::task::spawn_blocking(move || {
        // Actual source availability takes the same Published read lock. It
        // cannot observe Ready after this failed publication unlocks.
        let result = witness.check_availability(None);
        let _ = sender.send(result.is_err());
    });
    drop(guard); // simulated partial-transition refusal, not a caller ready flag
    assert!(receiver.await.unwrap());
    job.await.unwrap();
    assert_eq!(
        pool()
            .unwrap()
            .directory()
            .unwrap()
            .store_status_native(failed.inner.capture_identity)
            .unwrap(),
        SourceStatus::Fatal
    );
    assert!(failed.check_availability(None).is_err());
    assert!(healthy.check_availability(None).is_ok());
    // A successful actual guarded publication can release without poisoning
    // the healthy Store; completion doesn't reset the failed Store.
    PublicationGuard::acquire(&healthy.inner)
        .unwrap()
        .complete();
    assert!(healthy.check_availability(None).is_ok());
    assert!(PublicationGuard::acquire(&failed.inner).is_err());
}

#[tokio::test]
async fn sql_source_actual_writer_basis_refuses_fatal_before_clone_and_before_final_clock() {
    fixture::bootstrap().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(1, directory.path().into()).await.unwrap();
    let leader = openraft::CommittedLeaderId::new(3, 1);
    let (_, basis) = store
        .snapshot_for_writer_with_basis(None, None, leader)
        .unwrap();
    assert_eq!(basis.decide(0, leader, None, || Ok(7)), Ok(7));
    drop(PublicationGuard::acquire(&store.inner).unwrap());
    assert!(
        store
            .snapshot_for_writer_with_basis(None, None, leader)
            .is_err()
    );
    let sampled = std::sync::atomic::AtomicBool::new(false);
    assert!(
        basis
            .decide(0, leader, None, || {
                sampled.store(true, Ordering::Relaxed);
                Ok(7)
            })
            .is_err()
    );
    assert!(
        !sampled.load(Ordering::Relaxed),
        "fatal source must not reach the final clock/authorization decision"
    );
}
