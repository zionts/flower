use super::*;

impl Store {
    /// A single common serving publication under existing physical/logical
    /// exclusion. No root is cloned; returned metadata is pre-owned/scalar.
    pub(super) fn sql_current_capture<T>(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        operation: impl FnOnce(&Records, u64, u64) -> Result<T, SqlCaptureError>,
    ) -> Result<(SqlCaptureEpoch, T), SqlCaptureError> {
        if fence.store != self.inner.capture_identity || fence.partition.as_ref() != binding {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        if binding.is_some_and(|p| p.partition.len() > SQL_CAPTURE_MAX_KEY_BYTES) {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let binding = binding.cloned();
        let capture = self
            .inner
            .shared
            .try_capture_permit()
            .map_err(|error| match error {
                shared::CaptureUnavailable::Busy => SqlCaptureError::Busy,
                shared::CaptureUnavailable::NextDue(due) => SqlCaptureError::Paced(due),
            })?;
        let result = redb::with_resident_reads(32 * 1024 * 1024, || {
            // Publication/source borrows live INSIDE the resident scope, so all
            // refs/guards end before budget reset as well as before exclusion.
            let published = self
                .inner
                .published
                .try_read()
                .map_err(|error| match error {
                    std::sync::TryLockError::WouldBlock => SqlCaptureError::Busy,
                    std::sync::TryLockError::Poisoned(_) => SqlCaptureError::Storage,
                })?;
            super::super::sql_source::require_ready(&self.inner)
                .map_err(|_| SqlCaptureError::Storage)?;
            let applied = published
                .last_applied
                .ok_or(SqlCaptureError::FenceNotReady)?;
            let proof = &fence.fence;
            if applied.index < proof.applied.index || published.revision < proof.revision {
                return Err(SqlCaptureError::FenceNotReady);
            }
            if (applied.index == proof.applied.index && applied != proof.applied)
                || applied.leader_id < proof.applied.leader_id
                || (applied == proof.applied && published.revision != proof.revision)
            {
                return Err(SqlCaptureError::SnapshotChanged);
            }
            let (revision, data) = match binding.as_ref() {
                Some(binding) => {
                    let state = published
                        .partitions
                        .get(&binding.partition)
                        .filter(|state| {
                            state.info.epoch == binding.epoch
                                && state.info.phase == super::super::super::PartitionPhase::Active
                        })
                        .ok_or(SqlCaptureError::SnapshotChanged)?;
                    (state.snapshot.revision, &state.snapshot.data)
                }
                None => (published.revision, &published.data),
            };
            if !data.has_valid_depth() || !data.has_valid_source_ids() {
                return Err(SqlCaptureError::Storage);
            }
            let installation = self.inner.snapshot_installation.load(Ordering::Acquire);
            let result = operation(data, installation, revision)?;
            drop(published);
            Ok((
                SqlCaptureEpoch {
                    store: self.inner.capture_identity,
                    installation,
                    revision,
                    partition: binding,
                },
                result,
            ))
        });
        drop(capture);
        result
    }

    pub(super) fn sql_certificate_origin(
        &self,
        binding: Option<&PartitionBinding>,
        certificate: &SqlCaptureCertificate,
        installation: u64,
    ) -> Result<(), SqlCaptureError> {
        if certificate.store != self.inner.capture_identity
            || certificate.partition.as_ref() != binding
            || certificate
                .installation
                .is_some_and(|expected| expected != installation)
            || certificate.invalid
        {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        Ok(())
    }
    pub(crate) fn sql_capture_certify(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        certificate: &mut SqlCaptureCertificate,
        additions: &[SqlCaptureDependency<'_>],
    ) -> Result<SqlCaptureEpoch, SqlCaptureError> {
        // All selector encoding/allocation/pre-touch precedes source ownership.
        if let Err(error) = certificate.prepare(additions) {
            certificate.invalid = true;
            return Err(error);
        }
        let result = self.sql_current_capture(binding, fence, |data, installation, _revision| {
            self.sql_certificate_origin(binding, certificate, installation)?;
            certificate.check_and_stamp(data)
        });
        match result {
            Ok((epoch, ())) => {
                certificate.installation = Some(epoch.installation);
                Ok(epoch)
            }
            Err(error) => {
                if !matches!(
                    error,
                    SqlCaptureError::Busy
                        | SqlCaptureError::Paced(_)
                        | SqlCaptureError::FenceNotReady
                ) {
                    certificate.invalid = true;
                }
                Err(error)
            }
        }
    }
    pub(crate) fn sql_capture_certified_slice(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        certificate: &SqlCaptureCertificate,
        request: SqlCaptureRequest<'_>,
        mut buffer: SqlCaptureBuffer,
    ) -> Result<SqlCapturedSlice, SqlCaptureError> {
        request.validate()?;
        if buffer.count != 0
            || buffer.examined != 0
            || !buffer.bytes().is_empty()
            || !certificate.covers(&request)
            || certificate.installation.is_none()
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let mut scratch = SqlCaptureScratch::prepare(fence, &request)?;
        let (epoch, ()) =
            self.sql_current_capture(binding, fence, |data, installation, _revision| {
                self.sql_certificate_origin(binding, certificate, installation)?;
                certificate.validate(data)?;
                data.sql_capture_prepared(&request, &mut buffer, &mut scratch)
            })?;
        Ok(SqlCapturedSlice { epoch, buffer })
    }
    pub(crate) fn sql_capture_validate(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        certificate: &SqlCaptureCertificate,
    ) -> Result<SqlCaptureEpoch, SqlCaptureError> {
        if certificate.installation.is_none() {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let (epoch, ()) =
            self.sql_current_capture(binding, fence, |data, installation, _revision| {
                self.sql_certificate_origin(binding, certificate, installation)?;
                certificate.validate(data)
            })?;
        Ok(epoch)
    }
}
