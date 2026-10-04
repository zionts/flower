//! Capture owns a barrier only while borrowing the current publication and
//! copying quota-first resident bytes. It returns no source reference/handle.
use super::*;
use crate::consensus::sql_capture::*;

impl Store {
    pub(crate) fn sql_capture_progress(&self) -> tokio::sync::futures::OwnedNotified {
        self.inner.shared.sql_capture_progress()
    }

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
        let mut scratch = SqlCaptureScratch::prepare(fence, &request)?;
        let (epoch, ()) =
            self.sql_current_capture(binding, fence, |data, installation, revision| {
                if expected.is_some_and(|expected| {
                    expected.store != self.inner.capture_identity
                        || expected.installation != installation
                        || expected.revision != revision
                        || expected.partition.as_ref() != binding
                }) {
                    return Err(SqlCaptureError::SnapshotChanged);
                }
                data.sql_capture_prepared(&request, &mut buffer, &mut scratch)
            })?;
        Ok(SqlCapturedSlice { epoch, buffer })
    }
}

mod history;
#[cfg(test)]
mod history_tests;
mod selective;

#[cfg(test)]
mod liveness_tests;
#[cfg(test)]
mod selective_tests;
#[cfg(test)]
mod tests;
