//! Fallible raw access used only inside an epoch-checked native capture slice.
//! No key is allocated, value parsed, memo filled, or spool block loaded here.
use super::*;
use crate::consensus::sql_capture::{SQL_CAPTURE_MAX_KEY_BYTES, SqlCaptureError};
use redb::StorageError;

pub(crate) fn capture_error(error: StorageError) -> SqlCaptureError {
    match redb::resident_read_fault(&error) {
        Some(redb::ResidentReadFault::ColdPage { .. }) => SqlCaptureError::ColdPage,
        Some(redb::ResidentReadFault::Contended) => SqlCaptureError::Busy,
        Some(redb::ResidentReadFault::Budget) => SqlCaptureError::WorkLimit,
        None => SqlCaptureError::Storage,
    }
}

pub(crate) enum RawKey {
    Plain(AccessGuard<'static, &'static [u8]>),
    Pair(AccessGuard<'static, (&'static [u8], &'static [u8])>),
}
pub(crate) struct RawEntry {
    key: RawKey,
    pub(crate) value: AccessGuard<'static, &'static [u8]>,
}
impl RawEntry {
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
pub(crate) enum RawRange {
    Empty,
    Plain(redb::Range<'static, &'static [u8], &'static [u8]>),
    Pair(redb::Range<'static, (&'static [u8], &'static [u8]), &'static [u8]>),
}
impl Iterator for RawRange {
    type Item = Result<RawEntry, SqlCaptureError>;
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
    pub(crate) fn capture_raw_get(
        &self,
        key: &str,
    ) -> Result<Option<AccessGuard<'static, &'static [u8]>>, SqlCaptureError> {
        match &self.table {
            Table::Empty => Ok(None),
            Table::Plain(table) => table.get(key.as_bytes()).map_err(capture_error),
            Table::Pair(table, partition) => {
                if partition.len() > SQL_CAPTURE_MAX_KEY_BYTES {
                    return Err(SqlCaptureError::Oversized);
                }
                table
                    .get((partition.as_bytes(), key.as_bytes()))
                    .map_err(capture_error)
            }
            Table::Run(_) => Err(SqlCaptureError::UnsupportedBacking),
        }
    }
    pub(crate) fn capture_raw_range(
        &self,
        lower: Bound<&str>,
        upper_bound: Bound<&str>,
    ) -> Result<RawRange, SqlCaptureError> {
        match &self.table {
            Table::Empty => Ok(RawRange::Empty),
            Table::Plain(table) => table
                .range::<&[u8]>((lower.map(str::as_bytes), upper_bound.map(str::as_bytes)))
                .map(RawRange::Plain)
                .map_err(capture_error),
            Table::Pair(table, partition) => {
                if partition.len() > SQL_CAPTURE_MAX_KEY_BYTES {
                    return Err(SqlCaptureError::Oversized);
                }
                let after = upper(partition);
                let partition = partition.as_bytes();
                let lower = match lower {
                    Bound::Included(key) => Bound::Included((partition, key.as_bytes())),
                    Bound::Excluded(key) => Bound::Excluded((partition, key.as_bytes())),
                    Bound::Unbounded => Bound::Included((partition, &b""[..])),
                };
                let upper = match upper_bound {
                    Bound::Included(key) => Bound::Included((partition, key.as_bytes())),
                    Bound::Excluded(key) => Bound::Excluded((partition, key.as_bytes())),
                    Bound::Unbounded => Bound::Excluded((after.as_bytes(), &b""[..])),
                };
                table
                    .range::<(&[u8], &[u8])>((lower, upper))
                    .map(RawRange::Pair)
                    .map_err(capture_error)
            }
            Table::Run(_) => Err(SqlCaptureError::UnsupportedBacking),
        }
    }
}
