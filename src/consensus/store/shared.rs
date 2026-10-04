//! One redb database for every replica a process hosts, with group commit.
//!
//! Log appends and applied-state writes queue here and commit together: each
//! batch is one transaction, flushed once when any write in it must be
//! durable. Replicas that share a disk therefore share its fsyncs instead of
//! contending for them, and a durable commit also persists every earlier
//! no-sync commit of every replica. Rare writes (votes, truncation, purges,
//! snapshots) still run their own transactions; redb orders them between
//! batches.
//!
//! A staged write that fails aborts its batch; the others are staged again in a
//! fresh transaction, so one replica's failure never lands a partial write or
//! an error in another's. Staging may therefore run more than once, and must
//! only write the transaction. A failed commit fails the whole batch.
use super::*;
use std::path::Path;

#[path = "capture_gate.rs"]
#[cfg_attr(not(feature = "sql"), allow(dead_code))]
mod capture_gate;
use capture_gate::CaptureGate;
pub(crate) use capture_gate::{CapturePermit, CaptureUnavailable, MutationPermit};

type Stage = Box<dyn FnMut(&WriteTransaction, &mut StorageTrace) -> anyhow::Result<()> + Send>;

struct Job {
    durable: bool,
    stage: Stage,
    profile: StorageTrace,
    done: tokio::sync::oneshot::Sender<Result<(), Arc<anyhow::Error>>>,
    // Held until the batch completes, so Raft's storage drain waits for it
    // even when the awaiting future was cancelled.
    _lifetime: Option<Arc<RaftLifetime>>,
}

#[derive(Default)]
struct Queue {
    jobs: Vec<Job>,
    running: bool,
}

pub struct SharedDatabase {
    db: Database,
    // One gate for every replica/root sharing this physical database. Guards
    // own only this small gate; they never retain the redb database itself.
    capture_gate: Arc<CaptureGate>,
    queue: std::sync::Mutex<Queue>,
    batches: AtomicU64,
    durable_batches: AtomicU64,
    staged: AtomicU64,
    // Microseconds from beginning each batch's transaction through its commit,
    // and the part of that spent committing.
    busy_micros: AtomicU64,
    commit_micros: AtomicU64,
}

fn cache_bytes(name: &str) -> anyhow::Result<Option<usize>> {
    std::env::var(name)
        .ok()
        .map(|raw| {
            raw.parse()
                .with_context(|| format!("{name} must be a nonnegative byte count"))
        })
        .transpose()
}

/// This file's own bookkeeping, outside every replica's tables.
pub(super) const FILE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("database_file_v1");

/// Give back the space of a file that is mostly free pages. redb reuses free
/// pages but never returns them, and retained snapshot images once kept it
/// from reusing any between snapshots, growing files to several times their
/// data. Counting live pages walks every table, so a file is checked again
/// only once it has doubled since its last check. Compaction is best effort:
/// it stops at the first page it cannot move lower.
fn compact_when_doubled(db: &mut Database, path: &Path) -> anyhow::Result<()> {
    const CHECKED: &str = "checked_bytes";
    let before = std::fs::metadata(path)?.len();
    let transaction = db.begin_write()?;
    let checked = transaction
        .open_table(FILE_META)?
        .get(CHECKED)?
        .and_then(|bytes| bytes.value().try_into().ok().map(u64::from_le_bytes))
        .unwrap_or(0);
    if before < (16 << 20).max(checked.saturating_mul(2)) {
        transaction.abort()?;
        return Ok(());
    }
    // Count after a commit: it frees the pages a file closed mid-use still
    // held for its readers.
    transaction.commit()?;
    let transaction = db.begin_write()?;
    let stats = transaction.stats()?;
    transaction.abort()?;
    let live = stats.allocated_pages() * stats.page_size() as u64;
    if live.saturating_mul(2) <= before {
        let started = Instant::now();
        db.compact().context("compact Raft database")?;
        tracing::info!(
            target: "flower::storage",
            before,
            after = std::fs::metadata(path)?.len(),
            ms = started.elapsed().as_millis() as u64,
            "compacted a database file that was mostly free pages"
        );
    }
    let transaction = db.begin_write()?;
    let after = std::fs::metadata(path)?.len();
    transaction
        .open_table(FILE_META)?
        .insert(CHECKED, after.to_le_bytes().as_slice())?;
    transaction.commit()?;
    Ok(())
}

impl SharedDatabase {
    /// Open or create the database file. Blocking.
    pub fn open(path: &Path) -> anyhow::Result<Arc<Self>> {
        let mut builder = Database::builder();
        // Application state is served from this file, so its page cache is
        // most of what a replica keeps of it in memory.
        if let Some(bytes) = cache_bytes("FLOWER_REDB_CACHE_BYTES")? {
            builder.set_cache_size(bytes);
        }
        // Read on first use, which must not be where a bad value surfaces.
        cache_bytes("FLOWER_VALUE_CACHE_BYTES")?;
        let mut db = builder.create(path).map_err(|error| match error {
            redb::DatabaseError::UpgradeRequired(version) => anyhow::anyhow!(
                "Raft database uses unsupported legacy redb format v{version}; this release requires a current-format data directory"
            ),
            error => anyhow::Error::new(error).context("open Raft database"),
        })?;
        compact_when_doubled(&mut db, path)?;
        Ok(Self::with_database(db))
    }

    pub(super) fn with_database(db: Database) -> Arc<Self> {
        Arc::new(Self {
            db,
            capture_gate: Arc::new(CaptureGate::default()),
            queue: std::sync::Mutex::default(),
            batches: AtomicU64::new(0),
            durable_batches: AtomicU64::new(0),
            staged: AtomicU64::new(0),
            busy_micros: AtomicU64::new(0),
            commit_micros: AtomicU64::new(0),
        })
    }

    /// Ordinary mutations coexist, but exclude native snapshot capture.
    /// Blocking: acquire only inside a storage spawn_blocking job, and hold
    /// through transaction commit/abort/drop and logical root publication.
    /// The returned guard does not borrow or retain this database.
    pub(crate) fn mutation_permit(&self) -> MutationPermit {
        self.capture_gate.mutation_permit()
    }

    /// Try immediate native-copy admission across every replica in this file.
    /// Never waits, including on the bookkeeping mutex. Busy and a paced
    /// NextDue deadline are distinct; neither permits polling. Keep the guard
    /// around the bounded native copy only, not SQL/guest/compiler work or I/O.
    #[cfg_attr(not(feature = "sql"), allow(dead_code))]
    pub(crate) fn try_capture_permit(&self) -> Result<CapturePermit, CaptureUnavailable> {
        self.capture_gate.try_capture_permit()
    }

    #[cfg_attr(not(feature = "sql"), allow(dead_code))]
    pub(crate) fn sql_capture_progress(&self) -> tokio::sync::futures::OwnedNotified {
        self.capture_gate.mutation_progress()
    }

    /// Raw write-capable access requires this database's live mutation permit.
    /// The reference cannot outlive that permit. Production readers get only
    /// begin_read; fixture-only database() intentionally bypasses exclusion.
    pub(super) fn database_under_mutation<'a>(
        &'a self,
        permit: &'a MutationPermit,
    ) -> &'a Database {
        assert!(
            permit.belongs_to(&self.capture_gate),
            "foreign database mutation permit"
        );
        &self.db
    }

    pub(super) fn begin_read(&self) -> Result<redb::ReadTransaction, redb::TransactionError> {
        self.db.begin_read()
    }

    #[cfg(test)]
    pub(super) fn database(&self) -> &Database {
        &self.db
    }

    /// Counters shared by every replica in this database.
    pub(super) fn metrics(&self) -> serde_json::Value {
        let (batches, durable, staged) = self.batches();
        serde_json::json!({
            "batches": batches, "durableBatches": durable, "stagedWrites": staged,
            "busyMicros": self.busy_micros.load(Ordering::Acquire),
            "commitMicros": self.commit_micros.load(Ordering::Acquire),
        })
    }

    /// Batches committed so far, how many of them flushed, and writes staged.
    pub(super) fn batches(&self) -> (u64, u64, u64) {
        (
            self.batches.load(Ordering::Acquire),
            self.durable_batches.load(Ordering::Acquire),
            self.staged.load(Ordering::Acquire),
        )
    }

    /// Queue `write` for the next batch, durable when `durable`. Batches
    /// commit in submission order, so a caller may release its own ordering
    /// as soon as this returns.
    pub(super) fn submit(
        self: &Arc<Self>,
        durable: bool,
        profile: StorageTrace,
        lifetime: Option<Arc<RaftLifetime>>,
        write: impl FnMut(&WriteTransaction, &mut StorageTrace) -> anyhow::Result<()> + Send + 'static,
    ) -> Submitted {
        let (done, completed) = tokio::sync::oneshot::channel();
        let job = Job {
            durable,
            stage: Box::new(write),
            profile,
            done,
            _lifetime: lifetime,
        };
        let start = {
            let mut queue = self.queue.lock().expect("shared database queue lock");
            queue.jobs.push(job);
            !std::mem::replace(&mut queue.running, true)
        };
        if start {
            self.spawn();
        }
        Submitted(completed)
    }

    fn spawn(self: &Arc<Self>) {
        let shared = self.clone();
        tokio::task::spawn_blocking(move || shared.run());
    }

    fn run(self: Arc<Self>) {
        // A panicking write must not leave the queue marked running forever.
        struct Restart(std::sync::Weak<SharedDatabase>);
        impl Drop for Restart {
            fn drop(&mut self) {
                let Some(shared) = self.0.upgrade().filter(|_| std::thread::panicking()) else {
                    return;
                };
                let mut queue = shared.queue.lock().expect("shared database queue lock");
                queue.running = !queue.jobs.is_empty();
                if queue.running {
                    drop(queue);
                    shared.spawn();
                }
            }
        }
        let _restart = Restart(Arc::downgrade(&self));
        let mut shared = Some(self);
        while let Some(this) = &shared {
            let jobs = {
                let mut queue = this.queue.lock().expect("shared database queue lock");
                if queue.jobs.is_empty() {
                    queue.running = false;
                    return;
                }
                std::mem::take(&mut queue.jobs)
            };
            let (jobs, result) = this.commit(jobs);
            {
                let mut queue = this.queue.lock().expect("shared database queue lock");
                if queue.jobs.is_empty() {
                    queue.running = false;
                    // Release the database before waking anyone: a waiter may
                    // close its replica and reopen this file at once.
                    drop(queue);
                    shared = None;
                }
            }
            complete(jobs, result);
        }
    }

    /// Commit a batch; returns the jobs to complete with its outcome. A job
    /// whose staging fails completes at once and the others restage.
    fn commit(&self, mut jobs: Vec<Job>) -> (Vec<Job>, Result<(), Arc<anyhow::Error>>) {
        for job in &mut jobs {
            job.profile.phase(StoragePhase::BlockingQueue);
        }
        // This method runs only in run()'s spawn_blocking worker. Keep one
        // shared-side permit across the entire batch, including abort/drop,
        // failed staging, retries, and commit. Cancelling Submitted::committed
        // cannot shorten the lifetime of the actual storage job's exclusion.
        let _mutation = self.mutation_permit();
        loop {
            if jobs.is_empty() {
                return (jobs, Ok(()));
            }
            let durable = jobs.iter().any(|job| job.durable);
            let began = Instant::now();
            let transaction =
                self.db
                    .begin_write()
                    .map_err(anyhow::Error::new)
                    .and_then(|mut transaction| {
                        transaction.set_durability(if durable {
                            Durability::Immediate
                        } else {
                            Durability::None
                        })?;
                        Ok(transaction)
                    });
            let transaction = match transaction {
                Ok(transaction) => transaction,
                Err(error) => return (jobs, Err(Arc::new(error))),
            };
            let mut failed = None;
            for (index, job) in jobs.iter_mut().enumerate() {
                job.profile.phase(StoragePhase::Begin);
                if let Err(error) = (job.stage)(&transaction, &mut job.profile) {
                    failed = Some((index, error));
                    break;
                }
                job.profile.phase(StoragePhase::Write);
            }
            if let Some((index, error)) = failed {
                // Dropping the transaction aborts it; the rest restage.
                drop(transaction);
                complete(vec![jobs.remove(index)], Err(Arc::new(error)));
                continue;
            }
            let committing = Instant::now();
            let result = transaction
                .commit()
                .map_err(|error| Arc::new(anyhow::Error::new(error)));
            let micros = |since: Instant| since.elapsed().as_micros().min(u64::MAX as u128) as u64;
            self.busy_micros.fetch_add(micros(began), Ordering::AcqRel);
            self.commit_micros
                .fetch_add(micros(committing), Ordering::AcqRel);
            self.batches.fetch_add(1, Ordering::AcqRel);
            self.durable_batches
                .fetch_add(durable as u64, Ordering::AcqRel);
            self.staged.fetch_add(jobs.len() as u64, Ordering::AcqRel);
            return (jobs, result);
        }
    }
}

/// A queued write.
pub(super) struct Submitted(tokio::sync::oneshot::Receiver<Result<(), Arc<anyhow::Error>>>);

impl Submitted {
    /// Wait until the write's batch has committed.
    pub(super) async fn committed(self) -> anyhow::Result<()> {
        match self.0.await {
            Ok(result) => result.map_err(|error| anyhow::anyhow!("{error:#}")),
            Err(_) => bail!("shared database committer stopped"),
        }
    }
}

fn complete(jobs: Vec<Job>, result: Result<(), Arc<anyhow::Error>>) {
    for mut job in jobs {
        job.profile.phase(StoragePhase::Flush);
        job.profile.report(result.is_ok());
        let _ = job.done.send(result.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    const PROBE: TableDefinition<&str, u64> = TableDefinition::new("capture_gate_probe");

    fn job(
        stage: impl FnMut(&WriteTransaction, &mut StorageTrace) -> anyhow::Result<()> + Send + 'static,
    ) -> (
        Job,
        tokio::sync::oneshot::Receiver<Result<(), Arc<anyhow::Error>>>,
    ) {
        let (done, completed) = tokio::sync::oneshot::channel();
        (
            Job {
                durable: true,
                stage: Box::new(stage),
                profile: StorageTrace::default(),
                done,
                _lifetime: None,
            },
            completed,
        )
    }

    #[test]
    fn permits_do_not_borrow_or_retain_the_physical_database() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("flower.redb");
        let shared = SharedDatabase::open(&path).unwrap();
        let weak = Arc::downgrade(&shared);
        let mutation = shared.mutation_permit();
        drop(shared);
        assert!(weak.upgrade().is_none());
        // A guard retaining the database would also retain redb's file lock.
        let shared = SharedDatabase::open(&path).unwrap();
        drop(mutation);
        let weak = Arc::downgrade(&shared);
        let capture = shared.try_capture_permit().unwrap();
        drop(shared);
        assert!(weak.upgrade().is_none());
        let reopened = SharedDatabase::open(&path).unwrap();
        drop(capture);
        drop(reopened);
    }

    #[test]
    fn batch_excludes_capture_through_failed_staging_abort_and_restage() {
        let directory = tempfile::tempdir().unwrap();
        let shared = SharedDatabase::open(&directory.path().join("flower.redb")).unwrap();
        let (survivor, mut survived) = {
            let shared = shared.clone();
            let mut attempts = 0;
            job(move |transaction, _| {
                attempts += 1;
                assert!(matches!(
                    shared.try_capture_permit(),
                    Err(CaptureUnavailable::Busy)
                ));
                transaction.open_table(PROBE)?.insert("kept", attempts)?;
                Ok(())
            })
        };
        let (failed, mut rejected) = {
            let shared = shared.clone();
            job(move |transaction, _| {
                assert!(matches!(
                    shared.try_capture_permit(),
                    Err(CaptureUnavailable::Busy)
                ));
                transaction.open_table(PROBE)?.insert("aborted", 99)?;
                bail!("staging failed after a write")
            })
        };
        let (jobs, result) = shared.commit(vec![survivor, failed]);
        assert!(result.is_ok());
        assert!(rejected.try_recv().unwrap().is_err());
        complete(jobs, result);
        assert!(survived.try_recv().unwrap().is_ok());
        let transaction = shared.database().begin_read().unwrap();
        let table = transaction.open_table(PROBE).unwrap();
        assert_eq!(table.get("kept").unwrap().unwrap().value(), 2);
        assert!(table.get("aborted").unwrap().is_none());
        assert_eq!(shared.batches(), (1, 1, 1));
        assert!(shared.try_capture_permit().is_ok());
    }

    #[test]
    fn panicking_batch_drops_transaction_and_mutation_permit() {
        let directory = tempfile::tempdir().unwrap();
        let shared = SharedDatabase::open(&directory.path().join("flower.redb")).unwrap();
        let (panicking, _completed) = job(|transaction, _| {
            transaction.open_table(PROBE)?.insert("aborted", 99)?;
            panic!("staging panicked after a write");
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = shared.commit(vec![panicking]);
        }));
        assert!(result.is_err());
        assert!(shared.try_capture_permit().is_ok());
        // The aborted transaction cannot keep redb's writer lock either.
        let transaction = shared.database().begin_write().unwrap();
        let table = transaction.open_table(PROBE).unwrap();
        assert!(table.get("aborted").unwrap().is_none());
        drop(table);
        transaction.abort().unwrap();
    }

    #[tokio::test]
    async fn cancelled_submitted_future_keeps_exclusion_until_storage_finishes() {
        struct Finished(Option<tokio::sync::oneshot::Sender<()>>);
        impl Drop for Finished {
            fn drop(&mut self) {
                if let Some(done) = self.0.take() {
                    let _ = done.send(());
                }
            }
        }
        let directory = tempfile::tempdir().unwrap();
        let shared = SharedDatabase::open(&directory.path().join("flower.redb")).unwrap();
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = mpsc::channel();
        let (finished, finished_rx) = tokio::sync::oneshot::channel();
        let notice = Finished(Some(finished));
        let mut entered = Some(entered);
        let submitted = shared.submit(
            true,
            StorageTrace::default(),
            None,
            move |transaction, _| {
                let _notice = &notice;
                transaction.open_table(PROBE)?.insert("committed", 1)?;
                entered.take().unwrap().send(()).unwrap();
                release_rx.recv_timeout(TEST_DEADLINE).unwrap();
                Ok(())
            },
        );
        let waiter = tokio::spawn(submitted.committed());
        tokio::time::timeout(TEST_DEADLINE, entered_rx)
            .await
            .unwrap()
            .unwrap();
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        assert!(matches!(
            shared.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        release.send(()).unwrap();
        // Stage's captured notice is dropped by complete(), only after commit
        // has returned and released its actual blocking job's mutation permit.
        tokio::time::timeout(TEST_DEADLINE, finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(shared.batches(), (1, 1, 1));
        assert!(shared.try_capture_permit().is_ok());
        let transaction = shared.database().begin_read().unwrap();
        assert_eq!(
            transaction
                .open_table(PROBE)
                .unwrap()
                .get("committed")
                .unwrap()
                .unwrap()
                .value(),
            1
        );
    }
}
