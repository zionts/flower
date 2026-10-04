//! Dedicated live-history copy under one common certificate/publication check.
//! History-generation coverage never grants generic raw retention-point reads.
use super::*;
use crate::consensus::retention;
use crate::consensus::sql_capture::SqlCapturedHistoryIdentity;

impl Store {
    pub(crate) fn sql_capture_history_identity(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        certificate: &SqlCaptureCertificate,
        mut buffer: SqlCaptureBuffer,
    ) -> Result<SqlCapturedHistoryIdentity, SqlCaptureError> {
        if buffer.count != 0
            || buffer.examined != 0
            || !buffer.bytes().is_empty()
            || buffer.complete()
            || buffer.continuation().is_some()
            || !certificate.has_history_identity()
            || certificate.installation.is_none()
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        // This selector is INTERNAL to this dedicated operation. Do not ask
        // certificate.covers(Keys(...)): identity is not raw-point coverage.
        // Complete point copying caps both packed and advertised JSON lengths
        // at the admitted 64 KiB slice; no partial/chunk fallback is allowed.
        let request = SqlCaptureRequest {
            selection: SqlCaptureSelection::Keys(&[retention::KEY]),
            max_records: 1,
            max_examined: 1,
        };
        // Prepare and touch all native scratch before borrowing a source root.
        // Worker-stack/frame/decoder admission remains the controller's job.
        let mut scratch = SqlCaptureScratch::prepare(fence, &request)?;
        let (epoch, ()) =
            self.sql_current_capture(binding, fence, |data, installation, _revision| {
                self.sql_certificate_origin(binding, certificate, installation)?;
                // Validate ALL dependencies against this SAME publication,
                // not history alone and not a separately reacquired root.
                certificate.validate(data)?;
                data.sql_capture_prepared(&request, &mut buffer, &mut scratch)
            })?;
        // No caller parser/callback or source borrow lives under the permit.
        SqlCapturedHistoryIdentity::new(epoch, buffer)
    }
}
