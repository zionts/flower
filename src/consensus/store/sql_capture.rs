//! Capture owns a barrier only while borrowing the current publication and
//! copying quota-first resident bytes. It returns no source reference/handle.
use super::*;
use crate::consensus::sql_capture::*;

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);
pub(super) fn next_identity() -> anyhow::Result<u64> {
    NEXT_IDENTITY
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| anyhow::anyhow!("SQL capture store identity exhausted"))
}
impl Store {
    pub(crate) fn sql_capture_bind_fence(
        &self,
        fence: crate::consensus::read::ReadFence,
        partition: Option<&PartitionBinding>,
    ) -> SqlCaptureFence {
        SqlCaptureFence {
            fence,
            store: self.inner.capture_identity,
            partition: partition.cloned(),
        }
    }

    pub(crate) fn sql_capture_slice(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        expected: Option<&SqlCaptureEpoch>,
        request: SqlCaptureRequest<'_>,
        mut buffer: SqlCaptureBuffer,
    ) -> Result<SqlCapturedSlice, SqlCaptureError> {
        request.validate()?;
        if fence.store != self.inner.capture_identity || fence.partition.as_ref() != binding {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        if buffer.count != 0 || buffer.examined != 0 || !buffer.bytes().is_empty() {
            return Err(SqlCaptureError::InvalidRequest);
        }
        if binding.is_some_and(|binding| binding.partition.len() > SQL_CAPTURE_MAX_KEY_BYTES) {
            return Err(SqlCaptureError::InvalidRequest);
        }
        // This bounded metadata allocation precedes every capture/root borrow.
        let binding = binding.cloned();
        let _capture = self
            .inner
            .shared
            .try_capture_permit()
            .map_err(|error| match error {
                shared::CaptureUnavailable::Busy => SqlCaptureError::Busy,
                shared::CaptureUnavailable::NextDue(due) => SqlCaptureError::Paced(due),
            })?;
        let published = self
            .inner
            .published
            .try_read()
            .map_err(|_| SqlCaptureError::Busy)?;
        let applied = published
            .last_applied
            .ok_or(SqlCaptureError::FenceNotReady)?;
        let fence = &fence.fence;
        if applied.index < fence.applied.index || published.revision < fence.revision {
            return Err(SqlCaptureError::FenceNotReady);
        }
        if (applied.index == fence.applied.index && applied != fence.applied)
            || applied.leader_id < fence.applied.leader_id
            || (applied == fence.applied && published.revision != fence.revision)
        {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        let (revision, data) = match binding.as_ref() {
            Some(binding) => {
                let state =
                    partitions::active(published.partitions.get(&binding.partition), binding)
                        .map_err(|_| SqlCaptureError::SnapshotChanged)?;
                (state.revision, &state.data)
            }
            None => (published.revision, &published.data),
        };
        let epoch = SqlCaptureEpoch {
            store: self.inner.capture_identity,
            installation: self.inner.snapshot_installation.load(Ordering::Acquire),
            revision,
            partition: binding,
        };
        if expected.is_some_and(|expected| *expected != epoch) {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        // The resident scope rejects a cold extent before allocating its Arc or
        // reaching backend I/O. It never fills/evicts/flushes a global cache.
        // Each requested extent is cumulatively charged, including repeats.
        redb::with_resident_reads(32 * 1024 * 1024, || {
            data.sql_capture_raw(&request, &mut buffer)
        })?;
        // No read guard, iterator, table, Records clone or source Arc survives
        // this point. Publication and physical/logical mutation exclusion drop
        // before the caller decodes or executes any guest/SQLite code.
        drop(published);
        drop(_capture);
        Ok(SqlCapturedSlice { epoch, buffer })
    }
}

mod selective;

#[cfg(test)]
mod liveness_tests;
#[cfg(test)]
mod selective_tests;
#[cfg(test)]
mod tests;
