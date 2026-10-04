//! Resident fixed-buffer access only; no allocation, decoding, or spool I/O.
use super::*;
use crate::consensus::sql_capture::{
    SQL_CAPTURE_MAX_KEY_BYTES, SqlCaptureError, SqlCaptureScratch,
};
use redb::StorageError;

pub(crate) fn capture_error(error: StorageError) -> SqlCaptureError {
    match redb::resident_read_fault(&error) {
        Some(redb::ResidentReadFault::ColdPage { .. }) => SqlCaptureError::ColdPage,
        Some(redb::ResidentReadFault::Contended) => SqlCaptureError::Busy,
        Some(redb::ResidentReadFault::Budget | redb::ResidentReadFault::Depth) => {
            SqlCaptureError::WorkLimit
        }
        Some(redb::ResidentReadFault::InvalidRequest | redb::ResidentReadFault::Inactive) => {
            SqlCaptureError::InvalidRequest
        }
        Some(redb::ResidentReadFault::Corrupt) | None => SqlCaptureError::Storage,
    }
}
pub(crate) enum RawKey<'a> {
    Plain(AccessGuard<'a, &'static [u8]>),
    Pair(AccessGuard<'a, (&'static [u8], &'static [u8])>),
}
pub(crate) struct RawEntry<'a> {
    key: RawKey<'a>,
    pub(crate) value: AccessGuard<'a, &'static [u8]>,
}
impl RawEntry<'_> {
    pub(crate) fn key(&self) -> Result<&str, SqlCaptureError> {
        let bytes = match &self.key {
            RawKey::Plain(key) => key.value(),
            RawKey::Pair(key) => key.value().1,
        };
        if bytes.len() > SQL_CAPTURE_MAX_KEY_BYTES {
            return Err(SqlCaptureError::Oversized);
        }
        std::str::from_utf8(bytes).map_err(|_| SqlCaptureError::Storage)
    }
}
pub(crate) enum RawRange<'a> {
    Empty,
    Plain(redb::ResidentRange<'a, &'static [u8]>),
    Pair(redb::ResidentRange<'a, (&'static [u8], &'static [u8])>),
}
impl<'a> Iterator for RawRange<'a> {
    type Item = Result<RawEntry<'a>, SqlCaptureError>;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Empty => None,
            Self::Plain(range) => range.next().map(|entry| {
                entry
                    .map(|(key, value)| RawEntry {
                        key: RawKey::Plain(key),
                        value,
                    })
                    .map_err(capture_error)
            }),
            Self::Pair(range) => range.next().map(|entry| {
                entry
                    .map(|(key, value)| RawEntry {
                        key: RawKey::Pair(key),
                        value,
                    })
                    .map_err(capture_error)
            }),
        }
    }
}
impl Backing {
    #[cfg(test)]
    pub(crate) fn capture_raw_partition(&self) -> Option<&str> {
        match &self.table {
            Table::Pair(_, partition) => Some(partition),
            _ => None,
        }
    }
    pub(crate) fn capture_raw_get(
        &self,
        key: &str,
    ) -> Result<Option<AccessGuard<'_, &'static [u8]>>, SqlCaptureError> {
        match &self.table {
            Table::Empty => Ok(None),
            Table::Plain(table) => table.resident_get(key.as_bytes()).map_err(capture_error),
            Table::Pair(table, partition) => table
                .resident_get_pair(partition.as_bytes(), key.as_bytes())
                .map_err(capture_error),
            Table::Run(_) => Err(SqlCaptureError::UnsupportedBacking),
        }
    }
    pub(crate) fn capture_raw_range<'a>(
        &'a self,
        scratch: &'a mut SqlCaptureScratch,
    ) -> Result<RawRange<'a>, SqlCaptureError> {
        match &self.table {
            Table::Empty => Ok(RawRange::Empty),
            Table::Plain(table) => table
                .resident_range(&scratch.bounds, &mut scratch.range)
                .map(RawRange::Plain)
                .map_err(capture_error),
            Table::Pair(table, _) => table
                .resident_partition_range(&scratch.bounds, &mut scratch.range)
                .map(RawRange::Pair)
                .map_err(capture_error),
            Table::Run(_) => Err(SqlCaptureError::UnsupportedBacking),
        }
    }
}
