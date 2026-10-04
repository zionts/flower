//! A dedicated live-history input, not general coverage of retention metadata.
//!
//! The certificate stamps Records' history generation, while the source copy
//! includes the entire bounded *current* retention record. Ordinary accounting
//! rewrites may therefore change its physical version without invalidating the
//! database/incarnation projection. The archive `$flower.history` is not proof
//! of that live identity. No raw record is exposed through a public guest API.
use super::*;
use crate::consensus::retention;

/// Root-free bytes reserved by the admitted native owner before capture.
///
/// Only a trusted, quota-owning native identity decoder may inspect the copied
/// record. It must project canonical database/incarnation strings (or the
/// captured absence), discard all accounting fields, and must not register the
/// raw record in a general provider/guest lookup map.
#[derive(Debug)]
pub struct SqlCapturedHistoryIdentity {
    pub epoch: SqlCaptureEpoch,
    buffer: SqlCaptureBuffer,
}

impl SqlCapturedHistoryIdentity {
    /// Internal construction only. A partial record, foreign point or generic
    /// captured slice cannot masquerade as a complete live-history input.
    pub(in crate::consensus) fn new(
        epoch: SqlCaptureEpoch,
        buffer: SqlCaptureBuffer,
    ) -> Result<Self, SqlCaptureError> {
        if buffer.count != 1
            || buffer.examined != 1
            || !buffer.complete()
            || buffer.continuation().is_some()
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let record = buffer.records().next().ok_or(SqlCaptureError::Storage)?;
        let bytes = buffer.bytes();
        if bytes.get(record.key.clone()) != Some(retention::KEY.as_bytes())
            || record.key.start != 0
            || record.body_offset != 0
            || record.encoding != SqlCaptureEncoding::PackedJson
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        if record.json_bytes > SQL_CAPTURE_MAX_BYTES
            || record.total_body_bytes > SQL_CAPTURE_MAX_BYTES
        {
            return Err(SqlCaptureError::Oversized);
        }
        match (&record.body, record.version) {
            (Some(body), Some(_))
                if body.start == record.key.end
                    && body.end == bytes.len()
                    && body.len() == record.total_body_bytes
                    && bytes.get(body.clone()).is_some() => {}
            (None, None)
                if record.key.end == bytes.len()
                    && record.total_body_bytes == 0
                    && record.json_bytes == 0 => {}
            _ => return Err(SqlCaptureError::InvalidRequest),
        }
        Ok(Self { epoch, buffer })
    }

    /// Trusted native-only view. `body` excludes the stored version header and
    /// may be packed JSON. `record.json_bytes` is its bounded advertised JSON
    /// length; decoding/decompression needs a separately admitted reservation.
    /// The key/body ranges describe the private capture buffer, not `body`.
    pub(crate) fn raw_record(&self) -> (&SqlCapturedRecord, Option<&[u8]>) {
        let record = self
            .buffer
            .records()
            .next()
            .expect("complete history input");
        let body = record
            .body
            .as_ref()
            .map(|body| &self.buffer.bytes()[body.clone()]);
        (record, body)
    }

    /// Consume the private raw input as soon as a trusted native decoder has
    /// projected identity into its admitted frame. The callback runs only
    /// after the Store's publication guard and physical permit have ended.
    /// This does not admit parser memory, native stacks, cancellation or work.
    /// In particular, it must not use unreserved `packed::unpack`/serde `Value`
    /// parsing in production or return arbitrary raw fields to a guest.
    pub(crate) fn into_raw_for_identity_decoder<T, E>(
        self,
        decoder: impl FnOnce(&SqlCapturedRecord, Option<&[u8]>) -> Result<T, E>,
    ) -> Result<T, E> {
        let (record, body) = self.raw_record();
        let result = decoder(record, body);
        drop(self);
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{Records, read::ReadFence};
    use openraft::{CommittedLeaderId, LogId};
    use serde_json::json;

    fn epoch() -> SqlCaptureEpoch {
        SqlCaptureEpoch {
            store: 1,
            installation: 0,
            revision: 1,
            partition: None,
        }
    }
    fn buffer() -> SqlCaptureBuffer {
        SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
    }
    fn certificate(data: &Records) -> SqlCaptureCertificate {
        let fence = SqlCaptureFence {
            fence: ReadFence {
                applied: LogId::new(CommittedLeaderId::new(3, 1), 1),
                revision: 1,
            },
            store: 1,
            partition: None,
        };
        let mut certificate =
            SqlCaptureCertificate::from_reserved(&fence, vec![0; 128].into_boxed_slice()).unwrap();
        certificate
            .prepare(&[SqlCaptureDependency::HistoryIdentity])
            .unwrap();
        certificate.check_and_stamp(data).unwrap();
        certificate
    }
    fn state(incarnation: &str, receipt_bytes: u64) -> serde_json::Value {
        json!({
            "database":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "incarnation":incarnation,
            "receiptBytes":receipt_bytes
        })
    }

    #[test]
    fn sql_capture_history_identity_constructor_rejects_foreign_partial_or_expanding_input() {
        let mut foreign = buffer();
        foreign.record("$flower.history", None, None, 0).unwrap();
        foreign.examined = 1;
        foreign.complete = true;
        assert_eq!(
            SqlCapturedHistoryIdentity::new(epoch(), foreign).unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
        let mut partial = SqlCaptureBuffer::from_reserved(vec![0; 32].into_boxed_slice()).unwrap();
        partial
            .chunk(
                retention::KEY,
                7,
                &[b'x'; 64],
                64,
                0,
                SqlCaptureEncoding::PackedJson,
            )
            .unwrap();
        partial.examined = 1;
        assert!(!partial.complete());
        assert_eq!(
            SqlCapturedHistoryIdentity::new(epoch(), partial).unwrap_err(),
            SqlCaptureError::InvalidRequest
        );
        let mut expanding = buffer();
        expanding
            .record(retention::KEY, Some(1), Some(b"{}"), 2)
            .unwrap();
        expanding.examined = 1;
        expanding.complete = true;
        // Corrupt fixture metadata only: production copying refuses this bound.
        expanding.records[0].as_mut().unwrap().json_bytes = SQL_CAPTURE_MAX_BYTES + 1;
        assert_eq!(
            SqlCapturedHistoryIdentity::new(epoch(), expanding).unwrap_err(),
            SqlCaptureError::Oversized
        );
    }

    #[test]
    fn sql_capture_history_identity_consuming_decoder_preserves_proved_absence() {
        let mut absent = buffer();
        absent.record(retention::KEY, None, None, 0).unwrap();
        absent.examined = 1;
        absent.complete = true;
        let input = SqlCapturedHistoryIdentity::new(epoch(), absent).unwrap();
        let decoded: Result<bool, SqlCaptureError> =
            input.into_raw_for_identity_decoder(|record, body| {
                assert_eq!(record.version, None);
                assert_eq!(record.json_bytes, 0);
                assert_eq!(record.total_body_bytes, 0);
                assert_eq!(record.body_offset, 0);
                assert_eq!(record.encoding, SqlCaptureEncoding::PackedJson);
                Ok(body.is_none())
            });
        assert_eq!(decoded, Ok(true));
    }

    #[test]
    fn sql_capture_history_identity_actual_records_remove_and_reinsert_cannot_revive_certificate() {
        // Lower-level removal exercises the real Records mutation path. The
        // ordinary Store protocol protects this point from Commit deletion.
        let mut data = Records::new();
        let original = state("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0);
        data.insert(retention::KEY.into(), original.clone());
        let certificate = certificate(&data);
        let generation = data.generation(crate::consensus::HISTORY_MARKER);
        let version = data.sql_capture_version(retention::KEY).unwrap();
        data.insert(
            retention::KEY.into(),
            state("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 17),
        );
        assert_ne!(data.sql_capture_version(retention::KEY).unwrap(), version);
        assert_eq!(
            data.generation(crate::consensus::HISTORY_MARKER),
            generation
        );
        certificate.validate(&data).unwrap();
        assert!(data.remove(retention::KEY).is_some());
        assert_ne!(
            data.generation(crate::consensus::HISTORY_MARKER),
            generation
        );
        assert_eq!(
            certificate.validate(&data),
            Err(SqlCaptureError::SnapshotChanged)
        );
        data.insert(retention::KEY.into(), original);
        assert_eq!(
            certificate.validate(&data),
            Err(SqlCaptureError::SnapshotChanged)
        );
    }

    #[test]
    fn sql_capture_history_identity_actual_records_identity_aba_is_not_value_equality() {
        let mut data = Records::new();
        let original = state("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0);
        data.insert(retention::KEY.into(), original.clone());
        let certificate = certificate(&data);
        data.insert(
            retention::KEY.into(),
            state("cccccccccccccccccccccccccccccccc", 0),
        );
        assert_eq!(
            certificate.validate(&data),
            Err(SqlCaptureError::SnapshotChanged)
        );
        data.insert(retention::KEY.into(), original);
        assert_eq!(
            certificate.validate(&data),
            Err(SqlCaptureError::SnapshotChanged)
        );
    }

    #[test]
    fn sql_capture_history_identity_archive_is_not_live_identity_or_generic_coverage() {
        let mut data = Records::new();
        data.insert("$flower.history".into(), json!({"incarnation":"archived"}));
        let certificate = certificate(&data);
        assert!(certificate.has_history_identity());
        for selection in [
            SqlCaptureSelection::Keys(&[retention::KEY]),
            SqlCaptureSelection::KeyChunk {
                key: retention::KEY,
                offset: 0,
            },
            SqlCaptureSelection::Keys(&["$flower.history"]),
        ] {
            assert!(!certificate.covers(&SqlCaptureRequest {
                selection,
                max_records: 1,
                max_examined: 1,
            }));
        }
        data.insert(
            "$flower.history".into(),
            json!({"incarnation":"another archive"}),
        );
        certificate.validate(&data).unwrap();
        data.insert(
            retention::KEY.into(),
            state("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 0),
        );
        assert_eq!(
            certificate.validate(&data),
            Err(SqlCaptureError::SnapshotChanged)
        );
    }
}
