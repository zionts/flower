//! Native Store capture liveness fixtures, not SQLite/public-SQL launch proof.
//! No serving root leaves fixture setup or a capture call. Retained input is
//! copied bytes; decoding and exact result checks happen after capture/sealing.
use super::*;
use crate::consensus::{PartitionCommand, retention};
use openraft::CommittedLeaderId;
use serde_json::json;
use std::ops::{Bound, Range};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const ROWS: usize = 10_000;
const FRAME_BYTES: usize = 8 * 1024 * 1024;
const LOWER: &str = "source:[\"rows\",";
// The successor of the entire collection prefix, not a selected row window.
const UPPER: &str = "source:[\"rows\"-";
const NOISE: &str = "source:[\"unrelated\",\"tick\"]";
const POINTS: [&str; 2] = ["bundle", "$flower.history"];
const INCARNATION: &str = "cccccccccccccccccccccccccccccccc";
// Hang watchdogs only: elapsed time is reported, never a performance assertion.
const WATCHDOG: Duration = Duration::from_secs(30);

fn log(index: u64) -> LogId<u64> {
    LogId::new(CommittedLeaderId::new(3, 1), index)
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
fn entry(index: u64, command: RaftCommand) -> Entry<TypeConfig> {
    Entry {
        log_id: log(index),
        payload: EntryPayload::Normal(command),
    }
}
fn commit(revision: u64, puts: BTreeMap<String, Value>) -> RaftCommand {
    Commit {
        sql_commit_before: None,
        internal: true,
        request_id: String::new(),
        fingerprint: String::new(),
        expected_revision: revision,
        puts,
        deletes: Vec::new(),
        result: Value::Null,
    }
    .into()
}
fn committed(results: Vec<ApplyResult>, revision: u64) {
    assert_eq!(results.len(), 1);
    assert!(
        matches!(&results[0], ApplyResult::Committed(result)
            if result.revision == revision && !result.duplicate),
        "actual apply must commit, not merely return Ok: {results:?}"
    );
}
fn buffer() -> SqlCaptureBuffer {
    SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
}
fn certificate(fence: &SqlCaptureFence) -> SqlCaptureCertificate {
    assert_eq!(SQL_CAPTURE_MAX_DEPENDENCY_BYTES, 512 * 1024);
    SqlCaptureCertificate::from_reserved(fence, vec![0; 512 * 1024].into_boxed_slice()).unwrap()
}
fn dependencies() -> [SqlCaptureDependency<'static>; 3] {
    [
        SqlCaptureDependency::Collection("rows"),
        SqlCaptureDependency::Point(POINTS[0]),
        SqlCaptureDependency::Point(POINTS[1]),
    ]
}
fn request(after: Option<&str>) -> SqlCaptureRequest<'_> {
    SqlCaptureRequest {
        selection: SqlCaptureSelection::Range {
            lower: LOWER,
            upper: Some(UPPER),
            after,
        },
        max_records: 32,
        max_examined: 128,
    }
}

struct Fixture {
    _directory: tempfile::TempDir,
    store: Store,
    binding: Option<PartitionBinding>,
    index: u64,
    revision: u64,
}
async fn fixture(scoped: bool, rows: usize) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let mut store = Store::open(1, directory.path().into()).await.unwrap();
    let binding = scoped.then(|| PartitionBinding {
        partition: "selected".into(),
        epoch: 1,
    });
    let mut index = 0;
    if let Some(binding) = &binding {
        for partition_control in [
            PartitionCommand::Create {
                partition: binding.partition.clone(),
                epoch: binding.epoch,
                operation: "capture-fixture".into(),
            },
            PartitionCommand::Activate {
                partition: binding.partition.clone(),
                epoch: binding.epoch,
                operation: "capture-fixture".into(),
            },
        ] {
            index += 1;
            let results = store
                .apply([entry(
                    index,
                    RaftCommand::PartitionControl {
                        partition_control,
                        leader_id: None,
                    },
                )])
                .await
                .unwrap();
            assert!(matches!(results.as_slice(), [ApplyResult::Partition(_)]));
        }
    }
    // Produce a positive production history point through its native protocol;
    // an ordinary Commit may not manufacture protected history metadata.
    let old_incarnation = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    for (revision, action) in [
        retention::Action::Initialize {
            database: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            incarnation: old_incarnation.into(),
            max_receipt_bytes: None,
        },
        retention::Action::Reincarnate {
            incarnation: old_incarnation.into(),
            new_incarnation: INCARNATION.into(),
            fence_attestation: "isolated native test fixture; no deployed history".into(),
        },
    ]
    .into_iter()
    .enumerate()
    {
        index += 1;
        committed(
            store
                .apply([entry(
                    index,
                    scope(
                        binding.as_ref(),
                        RaftCommand::Retention {
                            retention: retention::Command {
                                expected_revision: revision as u64,
                                action,
                            },
                        },
                    ),
                )])
                .await
                .unwrap(),
            revision as u64 + 1,
        );
    }
    let mut puts: BTreeMap<_, _> = (0..rows)
        .map(|n| (format!("source:[\"rows\",\"{n:08}\"]"), json!({"n":n})))
        .collect();
    puts.insert(
        POINTS[0].into(),
        json!({"javascript":"export const fixture = true;"}),
    );
    index += 1;
    committed(
        store
            .apply([entry(index, scope(binding.as_ref(), commit(2, puts)))])
            .await
            .unwrap(),
        3,
    );
    store.inner.persistence.drain().await.unwrap();
    // A real later apply rebases the persisted rows onto the plain/paired native
    // backing. Drain again before starting the capture controller.
    index += 1;
    let results = store
        .apply([Entry {
            log_id: log(index),
            payload: EntryPayload::Blank,
        }])
        .await
        .unwrap();
    assert!(matches!(results.as_slice(), [ApplyResult::Internal]));
    store.inner.persistence.drain().await.unwrap();
    {
        let published = store.inner.published.read().unwrap();
        let data = match binding.as_ref() {
            Some(binding) => {
                &partitions::active(published.partitions.get(&binding.partition), binding)
                    .unwrap()
                    .data
            }
            None => &published.data,
        };
        assert_eq!(data.overlay_len(), 0, "must test real native backing rows");
        let backing = data.backing().expect("persisted native backing");
        // Resident baseline setup, not capture prefetch/recovery: raw warming
        // neither parses JSON nor leaves a read owner in the controller.
        for raw in backing.range(Bound::Included(""), Bound::Unbounded) {
            assert!(!raw.key.is_empty());
        }
    }
    Fixture {
        _directory: directory,
        store,
        binding,
        index,
        revision: 3,
    }
}

struct WriteRequest {
    rewrite_selected: bool,
    completed: oneshot::Sender<Progress>,
}
#[derive(Debug)]
struct Progress {
    revision: u64,
    index: u64,
    writes: usize,
    votes: usize,
}
struct Writer {
    requests: mpsc::Sender<WriteRequest>,
    task: tokio::task::JoinHandle<Progress>,
}
impl Writer {
    fn start(fixture: &Fixture) -> Self {
        let (requests, mut receiver) = mpsc::channel::<WriteRequest>(1);
        let mut store = fixture.store.clone();
        let binding = fixture.binding.clone();
        let mut index = fixture.index;
        let mut revision = fixture.revision;
        let task = tokio::spawn(async move {
            let mut writes = 0;
            let mut votes = 0;
            while let Some(request) = receiver.recv().await {
                // This always changes a different collection IN THE SELECTED
                // partition/root. Other-partition progress cannot pass this test.
                let mut puts = BTreeMap::from([(NOISE.into(), json!({"tick":writes + 1}))]);
                if request.rewrite_selected {
                    puts.insert("source:[\"rows\",\"00000000\"]".into(), json!({"n":99_999}));
                }
                index += 1;
                committed(
                    store
                        .apply([entry(
                            index,
                            scope(binding.as_ref(), commit(revision, puts)),
                        )])
                        .await
                        .unwrap(),
                    revision + 1,
                );
                revision += 1;
                writes += 1;
                store.inner.persistence.drain().await.unwrap();
                // Real control publication also rebases the persisted input;
                // neither the copied buffer nor a certificate may obstruct it.
                index += 1;
                let results = store
                    .apply([Entry {
                        log_id: log(index),
                        payload: EntryPayload::Blank,
                    }])
                    .await
                    .unwrap();
                assert!(matches!(results.as_slice(), [ApplyResult::Internal]));
                store.inner.persistence.drain().await.unwrap();
                let vote = Vote::new(4 + votes as u64, 1);
                store.save_vote(&vote).await.unwrap();
                assert_eq!(store.read_vote().await.unwrap(), Some(vote));
                votes += 1;
                assert_eq!(store.read_fence().unwrap().applied, log(index));
                // The completion is an actual storage/control progress event,
                // sent only after apply, persistence and vote reads complete.
                let _ = request.completed.send(Progress {
                    revision,
                    index,
                    writes,
                    votes,
                });
            }
            Progress {
                revision,
                index,
                writes,
                votes,
            }
        });
        Self { requests, task }
    }
    async fn finish(self) -> Progress {
        drop(self.requests);
        tokio::time::timeout(WATCHDOG, self.task)
            .await
            .expect("writer shutdown stalled")
            .expect("background writer failed")
    }
}
async fn progress(requests: &mpsc::Sender<WriteRequest>, rewrite_selected: bool) -> Progress {
    let (completed, notification) = oneshot::channel();
    tokio::time::timeout(WATCHDOG, async {
        requests
            .send(WriteRequest {
                rewrite_selected,
                completed,
            })
            .await
            .expect("background writer stopped");
        notification
            .await
            .expect("background writer failed before completion")
    })
    .await
    .expect("actual writer/control progress stalled while copied input was held")
}
async fn admitted<T>(
    requests: &mpsc::Sender<WriteRequest>,
    mut operation: impl FnMut() -> Result<T, SqlCaptureError>,
) -> T {
    // A bounded number of retries, each Busy retry AFTER an actual completed
    // background write/control notification. No Busy timer/yield retry loop.
    for _ in 0..16 {
        let mut result = operation();
        if let Err(SqlCaptureError::Paced(due)) = result {
            tokio::time::sleep_until(due.into()).await;
            result = operation(); // One scheduled deadline wake, then admission.
        }
        match result {
            Ok(value) => return value,
            Err(SqlCaptureError::Busy) => {
                progress(requests, false).await;
            }
            Err(error) => panic!("capture must succeed, not silently abort: {error:?}"),
        }
    }
    panic!("capture remained Busy after 16 actual write/control completions");
}

struct Frame {
    bytes: Vec<u8>,
    bodies: Vec<Range<usize>>,
}
impl Frame {
    fn admitted(rows: usize) -> Self {
        // The complete raw frame and its body directory are reserved BEFORE
        // capture. No extend/push may grow them, even outside the capture guard.
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(FRAME_BYTES).unwrap();
        let mut bodies = Vec::new();
        bodies.try_reserve_exact(rows + POINTS.len()).unwrap();
        Self { bytes, bodies }
    }
    fn append(&mut self, slice: &SqlCapturedSlice) {
        for record in slice.buffer.records() {
            assert_eq!(record.encoding, SqlCaptureEncoding::PackedJson);
            assert_eq!(record.body_offset, 0);
            let body = record.body.as_ref().expect("positive actual copied body");
            assert_eq!(body.len(), record.total_body_bytes);
            assert!(self.bytes.len() + body.len() <= FRAME_BYTES);
            assert!(self.bodies.len() < self.bodies.capacity());
            let start = self.bytes.len();
            self.bytes
                .extend_from_slice(&slice.buffer.bytes()[body.clone()]);
            self.bodies.push(start..self.bytes.len());
        }
    }
    fn json(&self, body: usize) -> Value {
        let raw = &self.bytes[self.bodies[body].clone()];
        let json = crate::consensus::packed::unpack(raw).unwrap();
        serde_json::from_slice(&json).unwrap()
    }
}
async fn ten_thousand_rows(scoped: bool) {
    let fixture = fixture(scoped, ROWS).await;
    let store = &fixture.store;
    let binding = fixture.binding.as_ref();
    let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), binding);
    let mut certificate = certificate(&fence);
    let mut frame = Frame::admitted(ROWS);
    let frame_capacity = frame.bytes.capacity();
    let body_capacity = frame.bodies.capacity();
    let mut after = String::with_capacity(SQL_CAPTURE_MAX_KEY_BYTES);
    let writer = Writer::start(&fixture);
    let started = Instant::now();
    let initial = admitted(&writer.requests, || {
        store.sql_capture_certify(binding, &fence, &mut certificate, &dependencies())
    })
    .await;
    assert_eq!(certificate.dependencies(), 3);
    let code_history = admitted(&writer.requests, || {
        store.sql_capture_certified_slice(
            binding,
            &fence,
            &certificate,
            SqlCaptureRequest {
                selection: SqlCaptureSelection::Keys(&POINTS),
                max_records: 32,
                max_examined: 128,
            },
            buffer(),
        )
    })
    .await;
    frame.append(&code_history);
    let mut latest = progress(&writer.requests, false).await;
    assert!(latest.revision > code_history.epoch.revision);
    assert_eq!(code_history.buffer.records().len(), POINTS.len());
    drop(code_history);
    let mut slices = 0;
    let mut copied_rows = 0;
    loop {
        let copied = admitted(&writer.requests, || {
            store.sql_capture_certified_slice(
                binding,
                &fence,
                &certificate,
                request((!after.is_empty()).then_some(after.as_str())),
                buffer(),
            )
        })
        .await;
        assert!(copied.buffer.examined() <= 128);
        assert!(copied.buffer.records().len() <= 32);
        assert!(
            copied.buffer.records().len() > 0,
            "no empty/all-abort success"
        );
        slices += 1;
        assert!(slices <= ROWS.div_ceil(32));
        copied_rows += copied.buffer.records().len();
        frame.append(&copied);
        let complete = copied.buffer.complete();
        let continuation = copied.buffer.continuation().expect("native continuation");
        assert!(after.is_empty() || continuation > after.as_str());
        after.clear();
        after.push_str(continuation);
        // Keep the actual returned slice alive while its same-partition writer,
        // persistence, blank control and vote all finish on another executor.
        latest = progress(&writer.requests, false).await;
        assert!(latest.revision > copied.epoch.revision);
        assert_eq!(
            copied.buffer.records().len(),
            if complete { 16 } else { 32 }
        );
        drop(copied);
        tokio::task::yield_now().await;
        if complete {
            break;
        }
    }
    let seal = admitted(&writer.requests, || {
        store.sql_capture_validate(binding, &fence, &certificate)
    })
    .await;
    let writer_result = writer.finish().await;
    assert_eq!(seal.revision, writer_result.revision);
    assert_eq!(seal.partition.as_ref(), binding);
    assert!(seal.revision > initial.revision);
    assert!(writer_result.writes > slices);
    assert_eq!(writer_result.writes, writer_result.votes);
    assert!(writer_result.index >= latest.index);
    assert_eq!(copied_rows, ROWS);
    assert_eq!(slices, ROWS.div_ceil(32));
    assert_eq!(frame.bytes.capacity(), frame_capacity);
    assert_eq!(frame.bodies.capacity(), body_capacity);
    assert_eq!(frame.bodies.len(), ROWS + POINTS.len());
    // Only now unpack and parse actual copied JSON, with no capture/publication
    // guard or Records/source owner. Exact set membership catches duplicates.
    assert_eq!(frame.json(0)["javascript"], "export const fixture = true;");
    assert_eq!(frame.json(1)["incarnation"], INCARNATION);
    let mut seen = vec![false; ROWS];
    let mut sum = 0_u64;
    let mut count = 0;
    for body in POINTS.len()..frame.bodies.len() {
        let n = frame.json(body)["n"].as_u64().expect("actual JSON integer");
        assert!(n < ROWS as u64);
        assert!(
            !std::mem::replace(&mut seen[n as usize], true),
            "duplicate row {n}"
        );
        sum += n;
        count += 1;
    }
    assert!(seen.into_iter().all(|present| present));
    assert_eq!(count, ROWS);
    assert_eq!(sum, (ROWS as u64 - 1) * ROWS as u64 / 2);
    eprintln!(
        "native selective capture scoped={scoped}: elapsed={:?} slices={slices} writes={} votes={} count={count} sum={sum} raw_bytes={} Rseal={}",
        started.elapsed(),
        writer_result.writes,
        writer_result.votes,
        frame.bytes.len(),
        seal.revision
    );
    fixture.store.close().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_capture_liveness_root_ten_thousand_rows_with_interleaved_native_writes() {
    ten_thousand_rows(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_capture_liveness_scoped_ten_thousand_rows_with_same_partition_writes() {
    ten_thousand_rows(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sql_capture_liveness_cancelled_controller_retains_only_copied_input() {
    for scoped in [false, true] {
        let fixture = fixture(scoped, 64).await;
        let writer = Writer::start(&fixture);
        let store = fixture.store.clone();
        let binding = fixture.binding.clone();
        let requests = writer.requests.clone();
        let (copied_sender, copied_receiver) = oneshot::channel();
        let (resume_sender, resume_receiver) = oneshot::channel::<()>();
        let started = Instant::now();
        let controller = tokio::spawn(async move {
            let binding = binding.as_ref();
            let fence = store.sql_capture_bind_fence(store.read_fence().unwrap(), binding);
            let mut certificate = certificate(&fence);
            admitted(&requests, || {
                store.sql_capture_certify(binding, &fence, &mut certificate, &dependencies())
            })
            .await;
            let copied = admitted(&requests, || {
                store.sql_capture_certified_slice(
                    binding,
                    &fence,
                    &certificate,
                    request(None),
                    buffer(),
                )
            })
            .await;
            copied_sender.send(copied).unwrap();
            // Cancel while the controller is waiting to resume another slice;
            // its certificate/fence are genuinely live across this await.
            resume_receiver.await.unwrap();
            admitted(&requests, || {
                store.sql_capture_validate(binding, &fence, &certificate)
            })
            .await
        });
        let copied = tokio::time::timeout(WATCHDOG, copied_receiver)
            .await
            .expect("controller did not deliver native copied input")
            .unwrap();
        assert_eq!(copied.buffer.records().len(), 32);
        controller.abort();
        let cancelled = tokio::time::timeout(WATCHDOG, controller)
            .await
            .unwrap()
            .unwrap_err();
        assert!(cancelled.is_cancelled());
        drop(resume_sender);
        // Deliberately rewrite an actual SELECTED row after cancellation. The
        // retained input must be immutable bytes, not a retained source owner.
        let completed = progress(&writer.requests, true).await;
        assert!(completed.revision > copied.epoch.revision);
        let snapshot = match fixture.binding.as_ref() {
            Some(binding) => fixture
                .store
                .partition_snapshot(binding, None, false)
                .unwrap(),
            None => fixture.store.snapshot_for(None).await,
        };
        assert_eq!(
            snapshot.data.get("source:[\"rows\",\"00000000\"]").unwrap()["n"],
            99_999
        );
        drop(snapshot);
        let mut frame = Frame::admitted(32);
        frame.append(&copied);
        let mut sum = 0_u64;
        for body in 0..frame.bodies.len() {
            let n = frame.json(body)["n"].as_u64().unwrap();
            assert_eq!(n, body as u64);
            sum += n;
        }
        assert_eq!(sum, 31 * 32 / 2);
        let writer_result = writer.finish().await;
        assert!(writer_result.writes >= 1);
        assert_eq!(writer_result.writes, writer_result.votes);
        assert_eq!(copied.buffer.records().len(), 32);
        eprintln!(
            "native cancelled capture scoped={scoped}: elapsed={:?} slices=1 writes={} votes={} count=32 sum={sum}",
            started.elapsed(),
            writer_result.writes,
            writer_result.votes
        );
        drop(copied);
        fixture.store.close().await.unwrap();
    }
}
