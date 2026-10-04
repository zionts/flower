//! Private scalar authorization basis paired with an actual writer snapshot.
//! No Records/root/read transaction escapes in this token. It is not a public
//! scope identifier, certificate supplied by a guest, or authority capability.
use super::*;
use std::sync::Weak;

pub(crate) struct NativeWriteBasis {
    retained: std::sync::Mutex<Option<crate::service::admission::StrongInput>>,
    origin: Weak<Inner>,
    binding: Option<PartitionBinding>,
    selected_revision: u64,
    history: Option<u64>,
    installation: u64,
    leader: openraft::CommittedLeaderId<u64>,
}
impl std::fmt::Debug for NativeWriteBasis {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str("NativeWriteBasis")
    }
}
impl NativeWriteBasis {
    pub(crate) fn retain(&self, input: crate::service::admission::StrongInput) {
        let mut retained = self.retained.lock().expect("native basis retention lock");
        assert!(retained.is_none(), "native basis already charged");
        *retained = Some(input);
    }
    pub(crate) fn allocation_cost(&self) -> usize {
        std::mem::size_of::<Self>()
            + 32
            + self
                .binding
                .as_ref()
                .map_or(0, |binding| binding.partition.capacity())
    }
    pub(in crate::consensus) fn belongs_to(
        &self,
        store: &Store,
        binding: Option<&PartitionBinding>,
    ) -> bool {
        Weak::ptr_eq(&self.origin, &Arc::downgrade(&store.inner))
            && self.binding.as_ref() == binding
    }
    /// Hold one actual publication read guard through the last clock decision.
    /// The ordered core passes its previous head, so no unapplied prefix can
    /// hide a preceding revocation/control operation from this decision.
    pub(crate) fn decide<T>(
        &self,
        expected_revision: u64,
        leader: openraft::CommittedLeaderId<u64>,
        previous: Option<LogId<u64>>,
        decide: impl FnOnce() -> Result<T, String>,
    ) -> Result<T, String> {
        let changed = || crate::sql_commit::STALE_MESSAGE.to_owned();
        if leader != self.leader || expected_revision < self.selected_revision {
            return Err(changed());
        }
        let origin = self.origin.upgrade().ok_or_else(changed)?;
        let guard = origin.published.read().map_err(|_| changed())?;
        #[cfg(feature = "sql")]
        sql_source::require_ready(&origin).map_err(|_| changed())?;
        if guard.installation != self.installation || guard.last_applied != previous {
            return Err(changed());
        }
        let (revision, data) = match &self.binding {
            None => (guard.revision, &guard.data),
            Some(binding) => {
                let partition = guard.partitions.get(&binding.partition);
                partitions::active(partition, binding).map_err(|_| changed())?;
                let state = partition.ok_or_else(changed)?;
                (state.snapshot.revision, &state.snapshot.data)
            }
        };
        if revision != expected_revision
            || data.generation(super::super::HISTORY_MARKER) != self.history
        {
            return Err(changed());
        }
        // Deliberately not tail-position: keep the guard alive until this exact
        // real-clock decision has finished. No I/O, parsing or root clone here.
        let result = decide();
        drop(guard);
        result
    }
}
impl Store {
    /// Select data/receipts and their PRIVATE scalar origin under ONE guard.
    /// A successor's private overlay may advance the revision; it retains this
    /// selected installation/history/term rather than recapturing after work.
    pub(crate) fn snapshot_for_writer_with_basis(
        &self,
        binding: Option<&PartitionBinding>,
        request_ids: Option<&[String]>,
        leader: openraft::CommittedLeaderId<u64>,
    ) -> anyhow::Result<(Snapshot, Arc<NativeWriteBasis>)> {
        let guard = self.inner.published.read().expect("published state lock");
        #[cfg(feature = "sql")]
        sql_source::require_ready(&self.inner)?;
        let (revision, data, requests) = match binding {
            None => (guard.revision, &guard.data, &guard.requests),
            Some(binding) => {
                let partition = guard.partitions.get(&binding.partition);
                partitions::active(partition, binding)?;
                let state = partition.context("partition does not exist")?;
                (
                    state.snapshot.revision,
                    &state.snapshot.data,
                    &state.snapshot.requests,
                )
            }
        };
        let basis = Arc::new(NativeWriteBasis {
            retained: std::sync::Mutex::new(None),
            origin: Arc::downgrade(&self.inner),
            binding: binding.cloned(),
            selected_revision: revision,
            history: data.generation(super::super::HISTORY_MARKER),
            installation: guard.installation,
            leader,
        });
        let requests = match request_ids {
            None => requests.clone(),
            Some(ids) => ids
                .iter()
                .filter_map(|id| {
                    requests
                        .get_shared(id)
                        .map(|receipt| (id.clone(), receipt.clone()))
                })
                .collect(),
        };
        Ok((
            Snapshot {
                revision,
                data: data.clone(),
                requests,
            },
            basis,
        ))
    }
}
