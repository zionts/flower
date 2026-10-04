//! Actual complete StateWrite projection, shared by queued and ordered apply.
//!
//! No new queue fields, source bodies/cells/roster bank or allocator allowance.
//! The source parent still owns accepted-entry lifetime/source folding and SAME
//! transaction META hooks. This writer is not a pairing or KnownEmpty proof.
use super::*;

impl StateWrite {
    /// The actual queue writer's complete projection, with the same physical
    /// versions/deletes/receipts/partition representation and metadata ordering.
    /// Additional native META must be prepared/written in THIS transaction from
    /// THIS accepted projection, never sampled from a later live directory.
    pub(in crate::consensus::store) fn project(
        &self,
        transaction: &WriteTransaction,
        tables: Tables,
        profile: &mut StorageTrace,
    ) -> anyhow::Result<()> {
        {
            let mut data = transaction.open_table(tables.data)?;
            for (key, value) in &self.data {
                match value {
                    Some(value) => {
                        data.insert(key.as_bytes(), value.as_slice())?;
                    }
                    None => {
                        data.remove(key.as_bytes())?;
                    }
                }
            }
            let mut requests = transaction.open_table(tables.requests)?;
            for key in &self.deleted_requests {
                requests.remove(key.as_bytes())?;
            }
            for (key, value) in &self.requests {
                requests.insert(key.as_bytes(), value.as_slice())?;
            }
        }
        write_partitions(transaction, tables, &self.partitions, profile)?;
        // Keep the ACTUAL high water at projection time, not the older apply's
        // snapshot value. Partitions may have received newer encoded versions.
        let mut metadata = self.metadata.clone();
        metadata.versions = metadata
            .versions
            .max(crate::consensus::versions_high_water());
        transaction
            .open_table(tables.meta)?
            .insert(STATE_META, profile.encode(&metadata)?.as_slice())?;
        Ok(())
    }
}

/// A nonduplicable inline sequence, borrowing BOTH real same-Store owned order
/// guards. Ordinary applies cannot submit behind this token, and direct/queued
/// disk work cannot overtake it. Construction requires predecessor drain AND
/// pending completion, before a redb transaction exists; it never blocks on a
/// redb writer while waiting for queued persistence. No new persistent fields.
pub(in crate::consensus::store) struct InlineProjection<'a> {
    persistence: &'a Persistence,
    // References keep the genuine guards locked until the token is consumed.
    _state: &'a tokio::sync::OwnedRwLockWriteGuard<StoredState>,
    _io: &'a tokio::sync::OwnedMutexGuard<()>,
    previous: u64,
    sequence: u64,
}
impl<'a> InlineProjection<'a> {
    pub(in crate::consensus::store) fn begin(
        inner: &'a Inner,
        state: &'a tokio::sync::OwnedRwLockWriteGuard<StoredState>,
        io: &'a tokio::sync::OwnedMutexGuard<()>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            Arc::ptr_eq(
                tokio::sync::OwnedRwLockWriteGuard::rwlock(state),
                &inner.state
            ) && Arc::ptr_eq(tokio::sync::OwnedMutexGuard::mutex(io), &inner.io),
            "inline projection requires the actual Store state and I/O order guards"
        );
        let persistence = &*inner.persistence;
        persistence.check()?;
        let previous = persistence.submitted_count();
        anyhow::ensure!(
            previous == persistence.persisted_count()
                && inner.pending.count.load(Ordering::Acquire) == 0
                && persistence
                    .queue
                    .lock()
                    .expect("persistence queue lock")
                    .writes
                    .is_empty(),
            "inline projection requires complete predecessor drain and pending disk order"
        );
        // queue.running may still be true after its final committed batch
        // notified drain: that task can only discover its empty queue and exit.
        // There is NO uncounted earlier projection when persisted == submitted.
        let sequence = previous
            .checked_add(1)
            .context("persistence sequence exhausted")?;
        Ok(Self {
            persistence,
            _state: state,
            _io: io,
            previous,
            sequence,
        })
    }
    pub(in crate::consensus::store) fn sequence(&self) -> u64 {
        self.sequence
    }

    fn check_unchanged(&self) -> anyhow::Result<()> {
        self.persistence.check()?;
        anyhow::ensure!(
            self.persistence.submitted_count() == self.previous
                && self.persistence.persisted_count() == self.previous,
            "inline projection sequence changed under native order guards"
        );
        Ok(())
    }

    // PRIVATE: the only call is below, after this factory's own complete real
    // transaction commits. No raw transaction or caller success flag can earn
    // credit. The owned state guard excludes every actual submitter.
    fn committed(self) -> u64 {
        let sequence = self.sequence();
        self.persistence
            .submitted
            .store(sequence, Ordering::Release);
        self.persistence
            .persisted
            .store(sequence, Ordering::Release);
        self.persistence.persisted_changed.notify_waiters();
        sequence
    }
}

/// Closed required same-transaction hook. Ordinary data is NOT KnownEmpty or
/// a native source-META claim. There is deliberately no constructor for native
/// preparation: accepted-entry/source folding and that hook remain HOLD. Do
/// not replace this with a caller closure, optional hook or success boolean.
enum PreparedMetadata {
    OrdinaryData,
    #[allow(dead_code)]
    NativeSource(std::convert::Infallible),
}
impl PreparedMetadata {
    fn ordinary(write: &StateWrite, state: &StoredState) -> anyhow::Result<Self> {
        let source_key =
            |key: &str| matches!(key, "bundle" | "schema" | "httpMethods" | "terminalMethods");
        anyhow::ensure!(
            !write.data.iter().any(|(key, _)| source_key(key)),
            "native source projection requires the unimplemented prepared META hook"
        );
        for (id, projected) in &write.partitions {
            // Inspect the actual changed-key set as well as stored versions:
            // deleting an already absent code key is still a native source
            // touch in a data-only existing partition projection.
            anyhow::ensure!(
                !projected
                    .changes(id)
                    .keys
                    .as_ref()
                    .is_some_and(|keys| { keys.iter().any(|key| source_key(key)) }),
                "native scoped source touch requires prepared META"
            );
            let previous = state.partitions.get(id);
            // Existing controls/replacement can invalidate a native source even
            // without touching its four rows. Only data-only existing scopes
            // and genuinely new source-free scopes are admitted here.
            if let Some(previous) = previous {
                let mut info = projected.state.info.clone();
                info.revision = previous.info.revision;
                anyhow::ensure!(
                    !projected.replaces() && info == previous.info,
                    "partition source/control projection requires prepared META"
                );
            } else {
                anyhow::ensure!(
                    projected.state.info.transfer.is_none()
                        && projected.state.base.is_none()
                        && projected.state.last_import.is_none()
                        && matches!(
                            projected.state.info.phase,
                            crate::consensus::PartitionPhase::Staged
                                | crate::consensus::PartitionPhase::Active
                        ),
                    "partition import/control projection requires prepared META"
                );
            }
            for key in ["bundle", "schema", "httpMethods", "terminalMethods"] {
                anyhow::ensure!(
                    projected.state.snapshot.data.raw_version(key)
                        == previous.and_then(|state| state.snapshot.data.raw_version(key)),
                    "native scoped source projection requires prepared META"
                );
            }
        }
        Ok(Self::OrdinaryData)
    }

    fn stage(
        &self,
        transaction: &WriteTransaction,
        tables: Tables,
        write: &StateWrite,
    ) -> anyhow::Result<()> {
        match self {
            Self::NativeSource(never) => match *never {},
            Self::OrdinaryData => {
                // Validate THIS transaction's actual raw codec, not a caller
                // bool. A malformed tail after successful DATA staging must
                // never become a committed prefix. Queued behavior is unchanged.
                let data = transaction.open_table(tables.data)?;
                for (key, value) in &write.data {
                    if value.is_some() {
                        let row = data.get(key.as_bytes())?.context("projected row missing")?;
                        let bytes = row.value().get(8..).context("truncated projected record")?;
                        let json = crate::consensus::packed::unpack(bytes)?;
                        serde_json::from_slice::<Value>(&json)?;
                    }
                }
                let requests = transaction.open_table(tables.requests)?;
                for (key, _) in &write.requests {
                    let row = requests
                        .get(key.as_bytes())?
                        .context("projected receipt missing")?;
                    let bytes = row
                        .value()
                        .get(8..)
                        .context("truncated projected receipt")?;
                    let json = crate::consensus::packed::unpack(bytes)?;
                    serde_json::from_slice::<Receipt>(&json)?;
                }
                Ok(())
            }
        }
    }
}

enum InlineFault {
    None,
    #[cfg(test)]
    RequestsAlreadyOpen,
    #[cfg(test)]
    StateMetaAlreadyOpen,
    #[cfg(test)]
    PartitionMetaAlreadyOpen,
    #[cfg(test)]
    BeforeCommitPanic,
    #[cfg(test)]
    BeforeCommitIo(Arc<std::sync::atomic::AtomicBool>),
}

/// A complete pre-dispatch storage job with actual TARGET shutdown custody.
/// A strong Inner or same-file sibling DatabaseWork is not enough: close waits
/// the existing target Holders counter, not state/I/O locks. No Source actor,
/// work/backing/stack admission, authority, new queue field or bank is issued.
///
/// Construct before any detachable dispatch. Every resource is owned together,
/// and held is LAST: even dropping an undispatched job releases its actual
/// guards, projection and DatabaseWork BEFORE announcing target completion.
/// No raw transaction, caller Tables, Pubguard, Inner or success flag enters
/// run. Native-sensitive preparation remains unconstructible/HOLD below.
pub(in crate::consensus::store) struct InlineOrdinaryWork {
    state: tokio::sync::OwnedRwLockWriteGuard<StoredState>,
    io: tokio::sync::OwnedMutexGuard<()>,
    write: StateWrite,
    profile: StorageTrace,
    work: DatabaseWork,
    held: Held,
}
impl InlineOrdinaryWork {
    #[allow(dead_code)] // Production accepted apply/resources remain HOLD.
    pub(in crate::consensus::store) fn run(
        self,
        publish: impl FnOnce(&mut StoredState, &mut Published, StateWrite, u64) -> anyhow::Result<()>,
    ) -> anyhow::Result<u64> {
        self.run_with_fault(publish, InlineFault::None)
    }

    fn run_with_fault(
        self,
        publish: impl FnOnce(&mut StoredState, &mut Published, StateWrite, u64) -> anyhow::Result<()>,
        fault: InlineFault,
    ) -> anyhow::Result<u64> {
        let Self {
            state,
            io,
            write,
            profile,
            work,
            held,
        } = self;
        // held is outside the complete worker frame. All return/error/unwind
        // paths first destroy its real transaction, Pubguard, mutation permit,
        // state/I/O, projection and DatabaseWork. Counts after commit do NOT
        // mean publication or target shutdown completion.
        let result = work.inline_ordinary_owned(
            &held.store().inner,
            state,
            io,
            write,
            profile,
            publish,
            fault,
        );
        drop(held);
        result
    }
}

impl DatabaseWork {
    /// Bind the actual target and ALL operation resources before dispatch can
    /// detach. Acquire the accepted actor lease (still absent/HOLD), then target
    /// state -> predecessor drain -> io -> pending idle before this preparation.
    /// The genuine held Store, not this DatabaseWork's optional sibling Raft
    /// lifetime, is the target shutdown authority. No transaction exists yet.
    #[allow(dead_code)] // Parent's actual accepted apply integration is HOLD.
    pub(in crate::consensus::store) fn prepare_inline_ordinary(
        self,
        target: &Store,
        state: tokio::sync::OwnedRwLockWriteGuard<StoredState>,
        io: tokio::sync::OwnedMutexGuard<()>,
        write: StateWrite,
        profile: StorageTrace,
    ) -> InlineOrdinaryWork {
        // A borrowed live Store makes this actual Weak upgrade infallible.
        let held = target
            .inner
            .holders
            .hold(&Arc::downgrade(&target.inner))
            .expect("live target Store for inline custody");
        InlineOrdinaryWork {
            state,
            io,
            write,
            profile,
            work: self,
            held,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn inline_ordinary_owned(
        self,
        inner: &Inner,
        mut state: tokio::sync::OwnedRwLockWriteGuard<StoredState>,
        io: tokio::sync::OwnedMutexGuard<()>,
        write: StateWrite,
        mut profile: StorageTrace,
        publish: impl FnOnce(&mut StoredState, &mut Published, StateWrite, u64) -> anyhow::Result<()>,
        _fault: InlineFault,
    ) -> anyhow::Result<u64> {
        anyhow::ensure!(
            Arc::ptr_eq(&self.shared, &inner.shared),
            "inline database work belongs to a different physical database"
        );
        let token = InlineProjection::begin(inner, &state, &io)?;
        let metadata = PreparedMetadata::ordinary(&write, &state)?;
        // The actual Held in the outer custody frame owns Inner externally to
        // borrowed guards: no Arc + self-reference. Target shutdown stays
        // outstanding through ALL transaction cleanup and final publication.
        let mutation = self.shared.mutation_permit();
        let database = self.shared.database_under_mutation(&mutation);
        let mut publication = sql_source::PublicationGuard::acquire(inner)?;
        publication.require_owner(inner)?;
        // Declared AFTER publication: transaction abort/Drop (including redb's
        // repair marking instead of normal abort on panic) precedes Pubunlock.
        // Commit errors may have applied the whole physical transaction; never
        // retry, refund or infer rollback. The armed guard fails SAME Inner.
        let mut transaction = database.begin_write()?;
        transaction.set_durability(Durability::None)?;
        profile.phase(StoragePhase::Begin);
        // Fixture-only real redb handle faults. No production caller stages
        // arbitrary work or receives this transaction.
        #[cfg(test)]
        let held_requests = matches!(_fault, InlineFault::RequestsAlreadyOpen)
            .then(|| transaction.open_table(inner.tables.requests).unwrap());
        #[cfg(test)]
        let held_meta = matches!(_fault, InlineFault::StateMetaAlreadyOpen)
            .then(|| transaction.open_table(inner.tables.meta).unwrap());
        #[cfg(test)]
        let held_partition_meta = matches!(_fault, InlineFault::PartitionMetaAlreadyOpen)
            .then(|| transaction.open_table(inner.tables.partition_meta).unwrap());
        let projection = write.project(&transaction, inner.tables, &mut profile);
        #[cfg(test)]
        {
            drop(held_requests);
            drop(held_meta);
            drop(held_partition_meta);
        }
        projection?;
        #[cfg(test)]
        if matches!(_fault, InlineFault::BeforeCommitPanic) {
            panic!("injected panic after actual complete staging, before commit");
        }
        metadata.stage(&transaction, inner.tables, &write)?;
        profile.phase(StoragePhase::Write);
        token.check_unchanged()?;
        #[cfg(test)]
        if let InlineFault::BeforeCommitIo(armed) = _fault {
            // Arm the real StorageBackend only AFTER complete projection.
            armed.store(true, Ordering::Release);
        }
        transaction.commit()?;
        profile.phase(StoragePhase::Flush);
        let sequence = token.committed();
        // State remains exclusively locked after token consumption. A callback
        // failure/panic AFTER commit leaves true counts, but Fatal before any
        // waiter can acquire Pubread. Mutation exclusion lasts through this.
        publish(&mut state, &mut publication, write, sequence)?;
        publication.complete();
        profile.phase(StoragePhase::Publish);
        profile.report(true);
        drop(mutation);
        drop(io);
        drop(state);
        drop(self);
        Ok(sequence)
    }
}

#[cfg(test)]
#[path = "ordered/tests.rs"]
mod tests;
