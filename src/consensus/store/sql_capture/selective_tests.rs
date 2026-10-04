use super::*;
use openraft::CommittedLeaderId;
use serde_json::json;

fn entry(index: u64, revision: u64, puts: &[(&str, Value)], deletes: &[&str]) -> Entry<TypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(3, 1), index),
        payload: EntryPayload::Normal(
            Commit {
                internal: true,
                request_id: String::new(),
                fingerprint: String::new(),
                expected_revision: revision,
                puts: puts.iter().map(|(k, v)| ((*k).into(), v.clone())).collect(),
                deletes: deletes.iter().map(|k| (*k).into()).collect(),
                result: Value::Null,
            }
            .into(),
        ),
    }
}
fn certificate(fence: &SqlCaptureFence) -> SqlCaptureCertificate {
    SqlCaptureCertificate::from_reserved(
        fence,
        vec![0; SQL_CAPTURE_MAX_DEPENDENCY_BYTES].into_boxed_slice(),
    )
    .unwrap()
}
fn buffer() -> SqlCaptureBuffer {
    SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
}
fn keys<'a>(keys: &'a [&'a str]) -> SqlCaptureRequest<'a> {
    SqlCaptureRequest {
        selection: SqlCaptureSelection::Keys(keys),
        max_records: 32,
        max_examined: 128,
    }
}
async fn admitted<T>(
    mut operation: impl FnMut() -> Result<T, SqlCaptureError>,
) -> Result<T, SqlCaptureError> {
    // Each actual paced rejection supplies its next scheduled deadline. No Busy
    // polling: these fixtures drain actual storage jobs before admission.
    loop {
        match operation() {
            Err(SqlCaptureError::Paced(due)) => tokio::time::sleep_until(due.into()).await,
            result => return result,
        }
    }
}

#[tokio::test]
async fn sql_capture_selective_uses_one_final_revision_and_covers_only_certified_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(
            1,
            0,
            &[
                ("source:[\"rows\",\"a\"]", json!({"n":1})),
                ("bundle", json!({"code":"x"})),
            ],
            &[],
        )])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    let initial = admitted(|| {
        store.sql_capture_certify(
            None,
            &fence,
            &mut cert,
            &[
                SqlCaptureDependency::Collection("rows"),
                SqlCaptureDependency::Point("bundle"),
                SqlCaptureDependency::Point("absent"),
            ],
        )
    })
    .await
    .unwrap();
    let copied = admitted(|| {
        store.sql_capture_certified_slice(
            None,
            &fence,
            &cert,
            keys(&["source:[\"rows\",\"a\"]", "bundle", "absent"]),
            buffer(),
        )
    })
    .await
    .unwrap();
    assert!(copied.buffer.records().nth(2).unwrap().body.is_none());
    assert_eq!(
        store
            .sql_capture_certified_slice(None, &fence, &cert, keys(&["unobserved"]), buffer())
            .unwrap_err(),
        SqlCaptureError::InvalidRequest
    );
    let bad_range = SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: "source:[\"rows\",",
            upper: None,
            after: None,
        },
        max_records: 32,
        max_examined: 128,
    };
    assert_eq!(
        store
            .sql_capture_certified_slice(None, &fence, &cert, bad_range, buffer())
            .unwrap_err(),
        SqlCaptureError::InvalidRequest
    );
    store
        .apply([entry(
            2,
            1,
            &[("source:[\"unrelated\",\"x\"]", json!(2))],
            &[],
        )])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let common = admitted(|| store.sql_capture_validate(None, &fence, &cert))
        .await
        .unwrap();
    assert!(common.revision > initial.revision);
    assert_eq!(common.revision, 2);
    assert_eq!(copied.epoch.revision, 1);
    // A point checked absent cannot become present without invalidating ALL.
    store
        .apply([entry(3, 2, &[("absent", json!(true))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(
        admitted(|| store.sql_capture_validate(None, &fence, &cert))
            .await
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    // Adding a new support point never adopts the changed old dependency.
    assert_eq!(
        admitted(|| store.sql_capture_certify(
            None,
            &fence,
            &mut cert,
            &[SqlCaptureDependency::Point("new")]
        ))
        .await
        .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_selective_rejects_presence_neutral_rewrite_phantom_delete_and_collection_aba()
{
    for change in 0..4 {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, dir.path().into()).await.unwrap();
        let key = "source:[\"rows\",\"a\"]";
        store
            .apply([entry(1, 0, &[(key, json!(1))], &[])])
            .await
            .unwrap();
        store.inner.persistence.drain().await.unwrap();
        let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
        let mut cert = certificate(&fence);
        admitted(|| {
            store.sql_capture_certify(
                None,
                &fence,
                &mut cert,
                &[SqlCaptureDependency::Collection("rows")],
            )
        })
        .await
        .unwrap();
        match change {
            0 => {
                store
                    .apply([entry(2, 1, &[(key, json!(2))], &[])])
                    .await
                    .unwrap();
            }
            1 => {
                store
                    .apply([entry(
                        2,
                        1,
                        &[("source:[\"rows\",\"phantom\"]", json!(2))],
                        &[],
                    )])
                    .await
                    .unwrap();
            }
            2 => {
                store.apply([entry(2, 1, &[], &[key])]).await.unwrap();
            }
            _ => {
                // Distinct serving publications: a net-zero single apply batch
                // has no observable intermediate member and may preserve None.
                store
                    .apply([entry(
                        2,
                        1,
                        &[("source:[\"rows\",\"temporary\"]", json!(2))],
                        &[],
                    )])
                    .await
                    .unwrap();
                store
                    .apply([entry(3, 2, &[], &["source:[\"rows\",\"temporary\"]"])])
                    .await
                    .unwrap();
            }
        }
        store.inner.persistence.drain().await.unwrap();
        assert_eq!(
            admitted(|| store.sql_capture_validate(None, &fence, &cert))
                .await
                .unwrap_err(),
            SqlCaptureError::SnapshotChanged,
            "change {change}"
        );
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_selective_negative_point_is_final_absence_not_no_intervening_write() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, &[("base", json!(1))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    admitted(|| {
        store.sql_capture_certify(
            None,
            &fence,
            &mut cert,
            &[SqlCaptureDependency::Point("missing")],
        )
    })
    .await
    .unwrap();
    store
        .apply([
            entry(2, 1, &[("missing", json!(2))], &[]),
            entry(3, 2, &[], &["missing"]),
        ])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(
        admitted(|| store.sql_capture_validate(None, &fence, &cert))
            .await
            .unwrap()
            .revision,
        3
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_selective_caps_total_selectors_and_admitted_key_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store.apply([entry(1, 0, &[], &[])]).await.unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    let names: Vec<_> = (0..128).map(|n| format!("k{n}")).collect();
    let selectors: Vec<_> = names
        .iter()
        .map(|name| SqlCaptureDependency::Point(name))
        .collect();
    admitted(|| store.sql_capture_certify(None, &fence, &mut cert, &selectors))
        .await
        .unwrap();
    assert_eq!(cert.dependencies(), 128);
    assert_eq!(
        store
            .sql_capture_certify(
                None,
                &fence,
                &mut cert,
                &[SqlCaptureDependency::Point("129")]
            )
            .unwrap_err(),
        SqlCaptureError::WorkLimit
    );
    let mut tiny =
        SqlCaptureCertificate::from_reserved(&fence, vec![0; 1].into_boxed_slice()).unwrap();
    assert_eq!(
        store
            .sql_capture_certify(
                None,
                &fence,
                &mut tiny,
                &[SqlCaptureDependency::Point("two")]
            )
            .unwrap_err(),
        SqlCaptureError::Oversized
    );
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_selective_rejects_real_same_revision_snapshot_install_and_cross_store() {
    use std::io::{Seek, Write};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, &[("source:[\"rows\",\"a\"]", json!(1))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    // Fully materialize the fixture image BEFORE capture, then discard its
    // lazy builder handle, so the certificate doesn't hide a test-owned pin.
    let snapshot = store.build_snapshot().await.unwrap();
    let meta = snapshot.meta;
    let mut source_file = snapshot.snapshot;
    source_file.rewind().await.unwrap();
    let mut bytes = Vec::new();
    source_file.read_to_end(&mut bytes).await.unwrap();
    drop(source_file);
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    admitted(|| {
        store.sql_capture_certify(
            None,
            &fence,
            &mut cert,
            &[SqlCaptureDependency::Collection("rows")],
        )
    })
    .await
    .unwrap();
    let other_dir = tempfile::tempdir().unwrap();
    let mut other = Store::open(1, other_dir.path().into()).await.unwrap();
    other.apply([entry(1, 0, &[], &[])]).await.unwrap();
    other.inner.persistence.drain().await.unwrap();
    let other_fence = other.sql_capture_bind_fence(other.read_fence().unwrap(), None);
    assert_eq!(
        admitted(|| other.sql_capture_validate(None, &other_fence, &cert))
            .await
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    let mut file = tempfile::tempfile().unwrap();
    file.write_all(&bytes).unwrap();
    file.rewind().unwrap();
    store
        .install_snapshot(&meta, Box::new(SnapshotData::from_std(file)))
        .await
        .unwrap();
    assert_eq!(store.inner.published.read().unwrap().revision, 1);
    let new_fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    assert_eq!(
        admitted(|| store.sql_capture_validate(None, &new_fence, &cert))
            .await
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    store.close().await.unwrap();
    other.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_selective_raw_points_stay_valid_through_actual_rebase() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, &[("metadata", json!({"schema":1}))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    admitted(|| {
        store.sql_capture_certify(
            None,
            &fence,
            &mut cert,
            &[SqlCaptureDependency::Point("metadata")],
        )
    })
    .await
    .unwrap();
    store
        .apply([entry(2, 1, &[("unrelated", json!(2))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    // A subsequent application performs ordinary persistence-backed rebase.
    store
        .apply([entry(3, 2, &[("unrelated", json!(3))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(
        admitted(|| store.sql_capture_validate(None, &fence, &cert))
            .await
            .unwrap()
            .revision,
        3
    );
    let copied = admitted(|| {
        store.sql_capture_certified_slice(None, &fence, &cert, keys(&["metadata"]), buffer())
    })
    .await
    .unwrap();
    assert_eq!(copied.buffer.records().len(), 1);
    store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_selective_escaped_collection_names_cannot_cover_another_collection() {
    for name in ["", "quotes\" and\\slash", "東京🌸\n", "rows\",\"evil"] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, dir.path().into()).await.unwrap();
        let encoded = serde_json::to_string(name).unwrap();
        let key = format!("source:[{encoded},\"one\"]");
        let lower = format!("source:[{encoded},");
        let upper = format!("source:[{encoded}-");
        store
            .apply([entry(
                1,
                0,
                &[
                    (&key, json!({"n":1})),
                    ("source:[\"other\",\"one\"]", json!({"n":2})),
                ],
                &[],
            )])
            .await
            .unwrap();
        store.inner.persistence.drain().await.unwrap();
        let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
        let mut cert = certificate(&fence);
        admitted(|| {
            store.sql_capture_certify(
                None,
                &fence,
                &mut cert,
                &[SqlCaptureDependency::Collection(name)],
            )
        })
        .await
        .unwrap();
        let request = SqlCaptureRequest {
            selection: SqlCaptureSelection::Range {
                lower: &lower,
                upper: Some(&upper),
                after: None,
            },
            max_records: 32,
            max_examined: 128,
        };
        let copied =
            admitted(|| store.sql_capture_certified_slice(None, &fence, &cert, request, buffer()))
                .await
                .unwrap();
        assert!(copied.buffer.complete());
        assert_eq!(copied.buffer.records().len(), 1);
        let row = copied.buffer.records().next().unwrap();
        assert_eq!(&copied.buffer.bytes()[row.key.clone()], key.as_bytes());
        assert_eq!(
            store
                .sql_capture_certified_slice(
                    None,
                    &fence,
                    &cert,
                    keys(&["source:[\"other\",\"one\"]"]),
                    buffer()
                )
                .unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
        let invalid_after = SqlCaptureRequest {
            selection: SqlCaptureSelection::Range {
                lower: &lower,
                upper: Some(&upper),
                after: Some(&upper),
            },
            max_records: 32,
            max_examined: 128,
        };
        assert_eq!(
            store
                .sql_capture_certified_slice(None, &fence, &cert, invalid_after, buffer())
                .unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_selective_rejects_frozen_and_retired_partition_binding() {
    use crate::consensus::{PartitionCommand, PartitionTransfer};
    for retired in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(1, dir.path().into()).await.unwrap();
        let binding = PartitionBinding {
            partition: "selected".into(),
            epoch: 1,
        };
        for (index, control) in [
            PartitionCommand::Create {
                partition: "selected".into(),
                epoch: 1,
                operation: "init".into(),
            },
            PartitionCommand::Activate {
                partition: "selected".into(),
                epoch: 1,
                operation: "init".into(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let result = store
                .apply([Entry {
                    log_id: LogId::new(CommittedLeaderId::new(3, 1), index as u64 + 1),
                    payload: EntryPayload::Normal(RaftCommand::PartitionControl {
                        partition_control: control,
                        leader_id: None,
                    }),
                }])
                .await
                .unwrap();
            assert!(matches!(result.as_slice(), [ApplyResult::Partition(_)]));
        }
        store.inner.persistence.drain().await.unwrap();
        let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), Some(&binding));
        let mut cert = certificate(&fence);
        admitted(|| {
            store.sql_capture_certify(
                Some(&binding),
                &fence,
                &mut cert,
                &[SqlCaptureDependency::Collection("rows")],
            )
        })
        .await
        .unwrap();
        let control = if retired {
            PartitionCommand::Discard {
                partition: "selected".into(),
                epoch: 1,
                operation: "drop".into(),
            }
        } else {
            PartitionCommand::Freeze {
                transfer: PartitionTransfer {
                    partition: "selected".into(),
                    operation: "move".into(),
                    source: "a".into(),
                    destination: "b".into(),
                    source_epoch: 1,
                    epoch: 2,
                },
                expected_revision: 0,
            }
        };
        let result = store
            .apply([Entry {
                log_id: LogId::new(CommittedLeaderId::new(3, 1), 3),
                payload: EntryPayload::Normal(RaftCommand::PartitionControl {
                    partition_control: control,
                    leader_id: None,
                }),
            }])
            .await
            .unwrap();
        assert!(matches!(result.as_slice(), [ApplyResult::Partition(_)]));
        store.inner.persistence.drain().await.unwrap();
        let fresh = store.sql_capture_bind_fence(store.read_fence().unwrap(), Some(&binding));
        assert_eq!(
            admitted(|| store.sql_capture_validate(Some(&binding), &fresh, &cert))
                .await
                .unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_progress_enrolls_before_actual_mutation_without_retaining_store() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(1, 0, &[("value", json!(1))], &[])])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let notified = store.sql_capture_progress();
    tokio::pin!(notified);
    notified.as_mut().enable();
    let permit = store.inner.shared.mutation_permit();
    assert_eq!(
        store
            .sql_capture_slice(None, &fence, None, keys(&["value"]), buffer())
            .unwrap_err(),
        SqlCaptureError::Busy
    );
    drop(permit);
    // Completion happened BEFORE polling the wait; enrollment prevents loss.
    notified.await;
    let pending = store.sql_capture_progress();
    tokio::pin!(pending);
    pending.as_mut().enable();
    let copied =
        admitted(|| store.sql_capture_slice(None, &fence, None, keys(&["value"]), buffer()))
            .await
            .unwrap();
    assert_eq!(copied.buffer.records().len(), 1);
    assert!(
        futures_util::poll!(pending.as_mut()).is_pending(),
        "capture cannot self-signal Busy retry"
    );
    let witness = Arc::downgrade(&store.inner);
    store.close().await.unwrap();
    drop(store);
    assert!(
        witness.upgrade().is_none(),
        "pending Notify must not own Store/source"
    );
}

#[tokio::test]
async fn sql_capture_combined_certificate_copy_validate_and_rebase_have_zero_heap_inside_scope() {
    use crate::consensus::sql_capture::allocation_probe::{self, Counts};
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, dir.path().into()).await.unwrap();
    store
        .apply([entry(
            1,
            0,
            &[
                (
                    "source:[\"rows\",\"a\"]",
                    json!({"text":"東京🌸\n","n":1.0}),
                ),
                ("bundle", json!({"javascript":"x"})),
            ],
            &[],
        )])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), None);
    let mut cert = certificate(&fence);
    let deps = [
        SqlCaptureDependency::Collection("rows"),
        SqlCaptureDependency::Point("bundle"),
    ];
    let result = admitted(|| {
        let (result, counts) =
            allocation_probe::run(|| store.sql_capture_certify(None, &fence, &mut cert, &deps));
        assert_eq!(counts, Counts::default());
        result
    })
    .await;
    result.unwrap();
    for phase in 0..2 {
        if phase == 1 {
            store
                .apply([entry(2, 1, &[("noise", json!(2))], &[])])
                .await
                .unwrap();
            store.inner.persistence.drain().await.unwrap();
        }
        admitted(|| {
            let (result, counts) = allocation_probe::run(|| {
                store.sql_capture_certified_slice(
                    None,
                    &fence,
                    &cert,
                    keys(&["bundle", "source:[\"rows\",\"a\"]"]),
                    buffer(),
                )
            });
            assert_eq!(counts, Counts::default());
            result
        })
        .await
        .unwrap();
        admitted(|| {
            let (result, counts) =
                allocation_probe::run(|| store.sql_capture_validate(None, &fence, &cert));
            assert_eq!(counts, Counts::default());
            result
        })
        .await
        .unwrap();
    }
    let mut writer = store.clone();
    writer
        .apply([entry(
            3,
            2,
            &[("source:[\"rows\",\"a\"]", json!({"n":2}))],
            &[],
        )])
        .await
        .unwrap();
    store.inner.persistence.drain().await.unwrap();
    assert_eq!(
        admitted(|| {
            let (result, counts) =
                allocation_probe::run(|| store.sql_capture_validate(None, &fence, &cert));
            assert_eq!(counts, Counts::default());
            result
        })
        .await
        .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    store.close().await.unwrap();
}
