//! Native history-source fixtures only; not controller/retry/cancellation or
//! public SQL activation proof. All decoding below is fixture-only, outside
//! capture guards. Production decoding must use its admitted bounded frame.
use super::*;
use crate::consensus::sql_capture::allocation_probe::{self, Counts};
use crate::consensus::{PartitionCommand, PartitionTransfer, partition_image_digest, retention};
use openraft::CommittedLeaderId;
use serde_json::json;
use std::ops::Bound;

const DATABASE: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const INCARNATION: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const NEXT_INCARNATION: &str = "cccccccccccccccccccccccccccccccc";

fn entry(index: u64, command: RaftCommand) -> Entry<TypeConfig> {
    Entry {
        log_id: LogId::new(CommittedLeaderId::new(3, 1), index),
        payload: EntryPayload::Normal(command),
    }
}
fn scope(binding: Option<&PartitionBinding>, command: RaftCommand) -> RaftCommand {
    match binding {
        Some(binding) => RaftCommand::Scoped {
            partition: binding.partition.clone(),
            epoch: binding.epoch,
            command: Box::new(command),
        },
        None => command,
    }
}
fn buffer() -> SqlCaptureBuffer {
    SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
}
fn certificate(fence: &SqlCaptureFence) -> SqlCaptureCertificate {
    SqlCaptureCertificate::from_reserved(fence, vec![0; 4096].into_boxed_slice()).unwrap()
}
async fn admitted<T>(
    mut operation: impl FnMut() -> Result<T, SqlCaptureError>,
) -> Result<T, SqlCaptureError> {
    // Repay the actual shared scheduled debt. Busy is NEVER polled. Every
    // ordinary storage job is drained before these fixtures attempt capture.
    loop {
        match operation() {
            Err(SqlCaptureError::Paced(due)) => tokio::time::sleep_until(due.into()).await,
            result => return result,
        }
    }
}
async fn certify(
    fixture: &Fixture,
    fence: &SqlCaptureFence,
    certificate: &mut SqlCaptureCertificate,
    additions: &[SqlCaptureDependency<'_>],
) -> Result<SqlCaptureEpoch, SqlCaptureError> {
    admitted(|| {
        let (result, counts) = allocation_probe::run(|| {
            fixture.store.sql_capture_certify(
                fixture.binding.as_ref(),
                fence,
                certificate,
                additions,
            )
        });
        assert_eq!(counts, Counts::default());
        result
    })
    .await
}
async fn capture(
    fixture: &Fixture,
    fence: &SqlCaptureFence,
    certificate: &SqlCaptureCertificate,
) -> Result<SqlCapturedHistoryIdentity, SqlCaptureError> {
    admitted(|| {
        // Owner reservation/pre-touch is outside the capture instrumentation.
        let buffer = buffer();
        let (result, counts) = allocation_probe::run(|| {
            fixture.store.sql_capture_history_identity(
                fixture.binding.as_ref(),
                fence,
                certificate,
                buffer,
            )
        });
        // This is actual redb resident TLS scope introspection, not a local
        // fake allocator/boolean. The crate owns ONE test-only global allocator.
        assert_eq!(counts, Counts::default());
        result
    })
    .await
}
async fn validate(
    fixture: &Fixture,
    fence: &SqlCaptureFence,
    certificate: &SqlCaptureCertificate,
) -> Result<SqlCaptureEpoch, SqlCaptureError> {
    admitted(|| {
        let (result, counts) = allocation_probe::run(|| {
            fixture
                .store
                .sql_capture_validate(fixture.binding.as_ref(), fence, certificate)
        });
        assert_eq!(counts, Counts::default());
        result
    })
    .await
}
fn fixture_value(input: &SqlCapturedHistoryIdentity) -> Option<Value> {
    assert!(
        !redb::resident_scope_active(),
        "no fixture parser under resident guard"
    );
    let (record, body) = input.raw_record();
    assert_eq!(record.encoding, SqlCaptureEncoding::PackedJson);
    assert_eq!(record.body_offset, 0);
    body.map(|body| {
        assert_eq!(body.len(), record.total_body_bytes);
        assert!(body.len() <= SQL_CAPTURE_MAX_BYTES);
        assert!(record.json_bytes <= SQL_CAPTURE_MAX_BYTES);
        let json = crate::consensus::packed::unpack(body).unwrap();
        assert_eq!(json.len(), record.json_bytes);
        serde_json::from_slice(&json).unwrap()
    })
}

struct Fixture {
    _directory: tempfile::TempDir,
    store: Store,
    binding: Option<PartitionBinding>,
    index: u64,
    revision: u64,
}
impl Fixture {
    async fn new(scoped: bool, initialized: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(1, directory.path().into()).await.unwrap();
        let binding = scoped.then(|| PartitionBinding {
            partition: "history-東京🌸".into(),
            epoch: 2,
        });
        let mut fixture = Self {
            _directory: directory,
            store,
            binding,
            index: 0,
            revision: 0,
        };
        if let Some(binding) = &fixture.binding {
            // Real FOUR-command import of an EMPTY state. BeginImport plus
            // Activate alone is not a valid fixture and cannot claim absence.
            let image = serde_json::to_string(&Snapshot::default()).unwrap();
            let operation = "empty-history-import";
            let transfer = PartitionTransfer {
                partition: binding.partition.clone(),
                operation: operation.into(),
                source: "isolated-source".into(),
                destination: "isolated-destination".into(),
                source_epoch: 1,
                epoch: binding.epoch,
            };
            let controls = [
                PartitionCommand::BeginImport {
                    transfer,
                    revision: 0,
                    digest: partition_image_digest(image.as_bytes()),
                    bytes: image.len() as u64,
                },
                PartitionCommand::ImportChunk {
                    partition: binding.partition.clone(),
                    epoch: binding.epoch,
                    operation: operation.into(),
                    index: 0,
                    data: image,
                },
                PartitionCommand::SealImport {
                    partition: binding.partition.clone(),
                    epoch: binding.epoch,
                    operation: operation.into(),
                },
                PartitionCommand::Activate {
                    partition: binding.partition.clone(),
                    epoch: binding.epoch,
                    operation: operation.into(),
                },
            ];
            for partition_control in controls {
                fixture.index += 1;
                let results = fixture
                    .store
                    .apply([entry(
                        fixture.index,
                        RaftCommand::PartitionControl {
                            partition_control,
                            leader_id: None,
                        },
                    )])
                    .await
                    .unwrap();
                assert!(
                    matches!(results.as_slice(), [ApplyResult::Partition(_)]),
                    "{results:?}"
                );
            }
            {
                let published = fixture.store.inner.published.read().unwrap();
                let state = published.partitions.get(&binding.partition).unwrap();
                assert_eq!(state.snapshot.revision, 0);
                assert!(state.snapshot.data.is_empty());
                assert!(state.snapshot.requests.is_empty());
            }
        } else {
            fixture.blank().await;
        }
        if initialized {
            fixture.initialize().await;
        }
        fixture.store.inner.persistence.drain().await.unwrap();
        fixture
    }
    fn fence(&self) -> SqlCaptureFence {
        self.store
            .sql_capture_bind_fence(self.store.read_fence().unwrap(), self.binding.as_ref())
    }
    async fn blank(&mut self) {
        self.index += 1;
        let results = self
            .store
            .apply([Entry {
                log_id: LogId::new(CommittedLeaderId::new(3, 1), self.index),
                payload: EntryPayload::Blank,
            }])
            .await
            .unwrap();
        assert!(matches!(results.as_slice(), [ApplyResult::Internal]));
        self.store.inner.persistence.drain().await.unwrap();
    }
    async fn apply(&mut self, command: RaftCommand) -> ApplyResult {
        self.index += 1;
        let mut results = self
            .store
            .apply([entry(self.index, scope(self.binding.as_ref(), command))])
            .await
            .unwrap();
        assert_eq!(results.len(), 1);
        let result = results.remove(0);
        self.store.inner.persistence.drain().await.unwrap();
        result
    }
    async fn committed(&mut self, command: RaftCommand) {
        let result = self.apply(command).await;
        let ApplyResult::Committed(committed) = result else {
            panic!("actual ApplyResult must commit, not merely return Ok: {result:?}");
        };
        assert!(!committed.duplicate);
        assert_eq!(committed.revision, self.revision + 1);
        self.revision = committed.revision;
    }
    fn action(&self, action: retention::Action) -> RaftCommand {
        RaftCommand::Retention {
            retention: retention::Command {
                expected_revision: self.revision,
                action,
            },
        }
    }
    async fn initialize(&mut self) {
        self.committed(self.action(retention::Action::Initialize {
            database: DATABASE.into(),
            incarnation: INCARNATION.into(),
            max_receipt_bytes: None,
        }))
        .await;
    }
    fn ordinary(
        &self,
        id: &str,
        puts: BTreeMap<String, Value>,
        deletes: Vec<String>,
    ) -> RaftCommand {
        Commit {
            sql_commit_before: None,
            internal: false,
            request_id: id.into(),
            fingerprint: "isolated-history-fixture".into(),
            expected_revision: self.revision,
            puts,
            deletes,
            result: json!({"fixture":true}),
        }
        .into()
    }
    async fn business(&mut self, id: &str, value: u64) {
        self.committed(self.ordinary(
            id,
            BTreeMap::from([("source:[\"noise\",\"one\"]".into(), json!({"n":value}))]),
            Vec::new(),
        ))
        .await;
    }
    async fn settled_native(&mut self) {
        // A real later application rebases persisted overlay records onto the
        // native plain/paired tables. No lazy snapshot/Records owner is kept.
        self.store.inner.persistence.drain().await.unwrap();
        self.blank().await;
        {
            let published = self.store.inner.published.read().unwrap();
            let data = match self.binding.as_ref() {
                Some(binding) => {
                    &published
                        .partitions
                        .get(&binding.partition)
                        .unwrap()
                        .snapshot
                        .data
                }
                None => &published.data,
            };
            assert_eq!(
                data.overlay_len(),
                0,
                "exercise native backing, not just overlay"
            );
            let backing = data.backing().expect("actual persisted backing");
            // Fixture resident baseline setup only; not capture fallback I/O.
            // All raw read handles/source refs end before the capture attempt.
            for raw in backing.range(Bound::Included(""), Bound::Unbounded) {
                assert!(!raw.key.is_empty());
            }
        }
    }
    async fn history_stamp(&self, fence: &SqlCaptureFence) -> (Option<u64>, Option<u64>) {
        // Scalar-only inspection; no serving root or Value escapes this guard.
        admitted(|| {
            self.store
                .sql_current_capture(self.binding.as_ref(), fence, |data, _, _| {
                    Ok((
                        data.sql_capture_version(retention::KEY)?,
                        data.generation(crate::consensus::HISTORY_MARKER),
                    ))
                })
                .map(|(_, stamp)| stamp)
        })
        .await
        .unwrap()
    }
}

#[tokio::test]
async fn sql_capture_history_identity_real_accounting_rewrites_do_not_starve_common_revision() {
    for scoped in [false, true] {
        let mut fixture = Fixture::new(scoped, true).await;
        fixture.settled_native().await;
        let fence = fixture.fence();
        let mut certificate = certificate(&fence);
        let initial = certify(
            &fixture,
            &fence,
            &mut certificate,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        let before_stamp = fixture.history_stamp(&fence).await;
        assert!(before_stamp.0.is_some());
        let input = capture(&fixture, &fence, &certificate).await.unwrap();
        let before = fixture_value(&input).unwrap();
        assert_eq!(before["database"], DATABASE);
        assert_eq!(before["incarnation"], INCARNATION);
        assert_eq!(before["receiptCount"], 0);
        assert_eq!(input.raw_record().0.version, before_stamp.0);
        fixture.business("ordinary receipt one", 1).await;
        fixture.business("ordinary receipt two", 2).await;
        let after_stamp = fixture.history_stamp(&fence).await;
        assert_ne!(
            after_stamp.0, before_stamp.0,
            "physical retention u64 MUST change"
        );
        assert_eq!(
            after_stamp.1, before_stamp.1,
            "identity generation MUST not change"
        );
        let current = capture(&fixture, &fence, &certificate).await.unwrap();
        let after = fixture_value(&current).unwrap();
        assert_eq!(after["database"], before["database"]);
        assert_eq!(after["incarnation"], before["incarnation"]);
        assert_eq!(after["receiptCount"], 2);
        assert!(after["receiptBytes"].as_u64().unwrap() > 0);
        assert_eq!(current.raw_record().0.version, after_stamp.0);
        assert_eq!(
            fixture_value(&input).unwrap(),
            before,
            "owned old bytes remain detached"
        );
        let common = validate(&fixture, &fence, &certificate).await.unwrap();
        assert_eq!(common.revision, fixture.revision);
        assert_eq!(common.revision, initial.revision + 2);
        assert_eq!(input.epoch.revision, initial.revision);
        assert_eq!(current.epoch.revision, common.revision);
        fixture.store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_history_identity_known_absence_is_invalidated_by_actual_initialize() {
    for scoped in [false, true] {
        let mut fixture = Fixture::new(scoped, false).await;
        fixture.settled_native().await;
        let fence = fixture.fence();
        let mut certificate = certificate(&fence);
        certify(
            &fixture,
            &fence,
            &mut certificate,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        let absent = capture(&fixture, &fence, &certificate).await.unwrap();
        assert!(fixture_value(&absent).is_none());
        assert_eq!(absent.raw_record().0.version, None);
        validate(&fixture, &fence, &certificate).await.unwrap();
        fixture.initialize().await;
        assert_eq!(
            capture(&fixture, &fence, &certificate).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert_eq!(
            validate(&fixture, &fence, &certificate).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert!(
            fixture_value(&absent).is_none(),
            "absence slot does not adopt fresh data"
        );
        fixture.store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_history_identity_reincarnation_invalidates_and_native_protocol_rejects_aba() {
    for scoped in [false, true] {
        let mut fixture = Fixture::new(scoped, true).await;
        fixture.settled_native().await;
        let fence = fixture.fence();
        let mut old = certificate(&fence);
        certify(
            &fixture,
            &fence,
            &mut old,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        let input = capture(&fixture, &fence, &old).await.unwrap();
        fixture
            .committed(fixture.action(retention::Action::Reincarnate {
                incarnation: INCARNATION.into(),
                new_incarnation: NEXT_INCARNATION.into(),
                fence_attestation: "isolated native fixture; no deployed history".into(),
            }))
            .await;
        assert_eq!(
            capture(&fixture, &fence, &old).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert_eq!(
            validate(&fixture, &fence, &old).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert_eq!(fixture_value(&input).unwrap()["incarnation"], INCARNATION);
        let fresh = fixture.fence();
        let mut current = certificate(&fresh);
        certify(
            &fixture,
            &fresh,
            &mut current,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        assert_eq!(
            fixture_value(&capture(&fixture, &fresh, &current).await.unwrap()).unwrap()["incarnation"],
            NEXT_INCARNATION
        );
        let rejected = fixture
            .apply(fixture.action(retention::Action::Reincarnate {
                incarnation: NEXT_INCARNATION.into(),
                new_incarnation: INCARNATION.into(),
                fence_attestation: "attempt forbidden native ABA".into(),
            }))
            .await;
        assert!(
            matches!(rejected, ApplyResult::Rejected(error) if error.contains("HISTORY_REUSED"))
        );
        // No fake successful reincarnation back to the archived identity. The
        // lower Records fixture separately tests the actual generation ABA.
        validate(&fixture, &fresh, &current).await.unwrap();
        assert_eq!(
            validate(&fixture, &fence, &old).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        fixture.store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_history_identity_never_grants_generic_retention_or_archive_reads() {
    let mut fixture = Fixture::new(false, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut identity_only = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut identity_only,
        &[SqlCaptureDependency::HistoryIdentity],
    )
    .await
    .unwrap();
    for selection in [
        SqlCaptureSelection::Keys(&[retention::KEY]),
        SqlCaptureSelection::KeyChunk {
            key: retention::KEY,
            offset: 0,
        },
        SqlCaptureSelection::StringChunk {
            key: retention::KEY,
            field: "incarnation",
            offset: 0,
        },
        SqlCaptureSelection::Keys(&["$flower.history"]),
        SqlCaptureSelection::Keys(&[crate::consensus::HISTORY_MARKER]),
    ] {
        assert_eq!(
            fixture
                .store
                .sql_capture_certified_slice(
                    None,
                    &fence,
                    &identity_only,
                    SqlCaptureRequest {
                        selection,
                        max_records: 1,
                        max_examined: 1
                    },
                    buffer()
                )
                .unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
    }
    // Physical raw-point stamps, the archive, and a physical key whose name
    // resembles a marker cannot substitute for a typed history dependency.
    for dependency in [
        SqlCaptureDependency::Point(retention::KEY),
        SqlCaptureDependency::Point("$flower.history"),
        SqlCaptureDependency::Point(crate::consensus::HISTORY_MARKER),
        SqlCaptureDependency::Collection("history:retention"),
    ] {
        let mut ordinary = certificate(&fence);
        certify(&fixture, &fence, &mut ordinary, &[dependency])
            .await
            .unwrap();
        assert_eq!(
            capture(&fixture, &fence, &ordinary).await.unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
    }
    let untouched = certificate(&fence);
    assert_eq!(
        capture(&fixture, &fence, &untouched).await.unwrap_err(),
        SqlCaptureError::InvalidRequest
    );
    capture(&fixture, &fence, &identity_only).await.unwrap();
    fixture.store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_history_identity_checks_all_support_dependencies_not_just_identity() {
    let mut fixture = Fixture::new(false, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut certificate = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut certificate,
        &[
            SqlCaptureDependency::HistoryIdentity,
            SqlCaptureDependency::Point("source:[\"noise\",\"one\"]"),
        ],
    )
    .await
    .unwrap();
    let input = capture(&fixture, &fence, &certificate).await.unwrap();
    let before = fixture.history_stamp(&fence).await;
    fixture.business("support point now present", 1).await;
    assert_eq!(fixture.history_stamp(&fence).await.1, before.1);
    assert_eq!(
        capture(&fixture, &fence, &certificate).await.unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    assert_eq!(
        validate(&fixture, &fence, &certificate).await.unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    assert_eq!(fixture_value(&input).unwrap()["incarnation"], INCARNATION);
    fixture.store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_history_identity_refuses_partial_capacity_and_dirty_owner_buffer() {
    let mut fixture = Fixture::new(false, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut certificate = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut certificate,
        &[SqlCaptureDependency::HistoryIdentity],
    )
    .await
    .unwrap();
    assert_eq!(
        admitted(|| fixture.store.sql_capture_history_identity(
            None,
            &fence,
            &certificate,
            SqlCaptureBuffer::from_reserved(vec![0; 32].into_boxed_slice()).unwrap()
        ))
        .await
        .unwrap_err(),
        SqlCaptureError::Oversized
    );
    let mut dirty = buffer();
    dirty.record("unrelated", None, None, 0).unwrap();
    assert_eq!(
        fixture
            .store
            .sql_capture_history_identity(None, &fence, &certificate, dirty)
            .unwrap_err(),
        SqlCaptureError::InvalidRequest
    );
    // Refusal does not silently stamp a partial result or poison valid history.
    capture(&fixture, &fence, &certificate).await.unwrap();
    validate(&fixture, &fence, &certificate).await.unwrap();
    fixture.store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_history_identity_actual_large_gc_cursor_refuses_advertised_json_bound() {
    let mut fixture = Fixture::new(false, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut certificate = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut certificate,
        &[SqlCaptureDependency::HistoryIdentity],
    )
    .await
    .unwrap();
    let before = fixture.history_stamp(&fence).await;
    // Ordinary non-internal legacy request IDs are admitted by the real native
    // protocol. A bounded GC page can retain a large last-inspected ID in its
    // live state even after that receipt itself has been collected.
    let large_id = "m".repeat(SQL_CAPTURE_MAX_BYTES + 1);
    fixture.business(&large_id, 1).await;
    fixture.business("z", 2).await;
    fixture
        .committed(fixture.action(retention::Action::Advance {
            incarnation: INCARNATION.into(),
            current_epoch: 1,
            min_epoch: 1,
        }))
        .await;
    fixture
        .committed(fixture.action(retention::Action::Collect {
            incarnation: INCARNATION.into(),
            limit: 1,
        }))
        .await;
    fixture.settled_native().await;
    assert_eq!(fixture.history_stamp(&fence).await.1, before.1);
    assert_eq!(
        capture(&fixture, &fence, &certificate).await.unwrap_err(),
        SqlCaptureError::Oversized
    );
    // The dependency remains semantically valid: it is the raw/advertised input
    // bound that refuses, with no chunk or billing/identity shortcut fallback.
    assert_eq!(
        validate(&fixture, &fence, &certificate)
            .await
            .unwrap()
            .revision,
        fixture.revision
    );
    fixture.store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_history_identity_ordinary_commit_cannot_delete_live_retention() {
    let mut fixture = Fixture::new(false, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut certificate = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut certificate,
        &[SqlCaptureDependency::HistoryIdentity],
    )
    .await
    .unwrap();
    let result = fixture
        .apply(fixture.ordinary(
            "forbidden deletion",
            BTreeMap::new(),
            vec![retention::KEY.into()],
        ))
        .await;
    assert!(
        matches!(result, ApplyResult::Rejected(error) if error.contains("RETENTION_METADATA_PROTECTED"))
    );
    assert_eq!(
        fixture_value(&capture(&fixture, &fence, &certificate).await.unwrap()).unwrap()["incarnation"],
        INCARNATION
    );
    validate(&fixture, &fence, &certificate).await.unwrap();
    fixture.store.close().await.unwrap();
}

#[tokio::test]
async fn sql_capture_history_identity_rejects_actual_same_revision_install_and_cross_store() {
    use std::io::{Seek, Write};
    use tokio::io::{AsyncReadExt, AsyncSeekExt};
    for scoped in [false, true] {
        let mut fixture = Fixture::new(scoped, true).await;
        fixture.settled_native().await;
        // Materialize and discard the lazy image/file/source owner BEFORE
        // certificate capture; the test must not hide a retained serving pin.
        let snapshot = fixture.store.build_snapshot().await.unwrap();
        let meta = snapshot.meta;
        let mut source = snapshot.snapshot;
        source.rewind().await.unwrap();
        let mut image = Vec::new();
        source.read_to_end(&mut image).await.unwrap();
        drop(source);
        fixture.store.inner.persistence.drain().await.unwrap();
        let fence = fixture.fence();
        let mut certificate = certificate(&fence);
        certify(
            &fixture,
            &fence,
            &mut certificate,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        let before = capture(&fixture, &fence, &certificate).await.unwrap();
        let other = Fixture::new(scoped, true).await;
        let other_fence = other.fence();
        assert_eq!(
            capture(&other, &other_fence, &certificate)
                .await
                .unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert_eq!(
            validate(&other, &other_fence, &certificate)
                .await
                .unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&image).unwrap();
        file.rewind().unwrap();
        fixture
            .store
            .install_snapshot(&meta, Box::new(SnapshotData::from_std(file)))
            .await
            .unwrap();
        fixture.store.inner.persistence.drain().await.unwrap();
        let fresh = fixture.fence();
        assert_eq!(
            capture(&fixture, &fresh, &certificate).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        assert_eq!(
            validate(&fixture, &fresh, &certificate).await.unwrap_err(),
            SqlCaptureError::SnapshotChanged
        );
        let mut new_certificate = self::certificate(&fresh);
        certify(
            &fixture,
            &fresh,
            &mut new_certificate,
            &[SqlCaptureDependency::HistoryIdentity],
        )
        .await
        .unwrap();
        let after = capture(&fixture, &fresh, &new_certificate).await.unwrap();
        assert_eq!(
            after.epoch.revision, before.epoch.revision,
            "same logical R installation"
        );
        assert_ne!(after.epoch.installation, before.epoch.installation);
        assert_eq!(fixture_value(&after), fixture_value(&before));
        fixture.store.close().await.unwrap();
        other.store.close().await.unwrap();
    }
}

#[tokio::test]
async fn sql_capture_history_identity_rejects_wrong_scope_and_retired_binding() {
    let mut fixture = Fixture::new(true, true).await;
    fixture.settled_native().await;
    let fence = fixture.fence();
    let mut certificate = certificate(&fence);
    certify(
        &fixture,
        &fence,
        &mut certificate,
        &[SqlCaptureDependency::HistoryIdentity],
    )
    .await
    .unwrap();
    assert_eq!(
        fixture
            .store
            .sql_capture_history_identity(None, &fence, &certificate, buffer())
            .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    let binding = fixture.binding.as_ref().unwrap().clone();
    let wrong = PartitionBinding {
        epoch: binding.epoch + 1,
        ..binding.clone()
    };
    let wrong_fence = fixture
        .store
        .sql_capture_bind_fence(fixture.store.read_fence().unwrap(), Some(&wrong));
    assert_eq!(
        admitted(|| fixture.store.sql_capture_history_identity(
            Some(&wrong),
            &wrong_fence,
            &certificate,
            buffer()
        ))
        .await
        .unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    fixture.index += 1;
    let result = fixture
        .store
        .apply([entry(
            fixture.index,
            RaftCommand::PartitionControl {
                partition_control: PartitionCommand::Discard {
                    partition: binding.partition.clone(),
                    epoch: binding.epoch,
                    operation: "history-drop".into(),
                },
                leader_id: None,
            },
        )])
        .await
        .unwrap();
    assert!(
        matches!(result.as_slice(), [ApplyResult::Partition(_)]),
        "{result:?}"
    );
    fixture.store.inner.persistence.drain().await.unwrap();
    let fresh = fixture.fence();
    assert_eq!(
        capture(&fixture, &fresh, &certificate).await.unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    assert_eq!(
        validate(&fixture, &fresh, &certificate).await.unwrap_err(),
        SqlCaptureError::SnapshotChanged
    );
    fixture.store.close().await.unwrap();
}
