//! SQL-owned raw input, never a serving Records snapshot.
//!
//! The capture caller reserves and supplies its buffer before acquiring a slice.
//! Returned values own only copied bytes and scalar epoch/offset metadata. They
//! cannot prolong any database read transaction or persistent Records root.
use super::{PartitionBinding, read::ReadFence};
use std::{fmt, ops::Range};

pub const SQL_CAPTURE_MAX_BYTES: usize = 64 * 1024;
pub const SQL_CAPTURE_MAX_RECORDS: usize = 32;
pub const SQL_CAPTURE_MAX_EXAMINED: usize = 128;
pub const SQL_CAPTURE_MAX_KEY_BYTES: usize = 4096;
pub const SQL_CAPTURE_MAX_JSON_NODES: usize = 4096;
pub const SQL_CAPTURE_MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;

/// A fresh quorum fence, not a snapshot or an authority chosen by the caller.
#[derive(Clone, Debug)]
pub struct SqlCaptureFence {
    pub(super) fence: ReadFence,
    pub(super) store: u64,
    pub(super) partition: Option<PartitionBinding>,
}

/// The exact serving epoch shared by every slice of one attempted frame.
/// A physical installation can reuse a revision, so revision alone is unsafe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlCaptureEpoch {
    pub(super) store: u64,
    pub(super) installation: u64,
    pub revision: u64,
    pub partition: Option<PartitionBinding>,
}

#[derive(Clone, Copy, Debug)]
pub enum SqlCaptureSelection<'a> {
    /// Every requested key yields a slot, including an authoritative absence.
    Keys(&'a [&'a str]),
    /// A large stored metadata body, copied without unpacking across slices.
    KeyChunk { key: &'a str, offset: usize },
    /// A large overlay string (notably bundle.javascript), without serializing
    /// or scanning the whole record. UTF-8 bytes are joined before compilation.
    StringChunk {
        key: &'a str,
        field: &'a str,
        offset: usize,
    },
    /// Physical native source/index keys in [lower, upper), after `after`.
    /// Unlike ordinary merged iteration, shadowed/deleted entries count work.
    Range {
        lower: &'a str,
        upper: Option<&'a str>,
        after: Option<&'a str>,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct SqlCaptureRequest<'a> {
    pub selection: SqlCaptureSelection<'a>,
    pub max_records: usize,
    pub max_examined: usize,
}
impl SqlCaptureRequest<'_> {
    pub(super) fn validate(&self) -> Result<(), SqlCaptureError> {
        if self.max_records == 0
            || self.max_records > SQL_CAPTURE_MAX_RECORDS
            || self.max_examined == 0
            || self.max_examined > SQL_CAPTURE_MAX_EXAMINED
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let valid_key = |key: &str| key.len() <= SQL_CAPTURE_MAX_KEY_BYTES;
        match self.selection {
            SqlCaptureSelection::Keys(keys) => {
                if keys.len() > self.max_records || keys.iter().any(|key| !valid_key(key)) {
                    return Err(SqlCaptureError::InvalidRequest);
                }
            }
            SqlCaptureSelection::KeyChunk { key, offset } => {
                if !valid_key(key) || offset > SQL_CAPTURE_MAX_METADATA_BYTES {
                    return Err(SqlCaptureError::InvalidRequest);
                }
            }
            SqlCaptureSelection::StringChunk { key, field, offset } => {
                if !valid_key(key) || !valid_key(field) || offset > SQL_CAPTURE_MAX_METADATA_BYTES {
                    return Err(SqlCaptureError::InvalidRequest);
                }
            }
            SqlCaptureSelection::Range {
                lower,
                upper,
                after,
            } => {
                if !valid_key(lower)
                    || upper.is_some_and(|key| !valid_key(key) || key <= lower)
                    || after.is_some_and(|key| !valid_key(key) || key < lower)
                {
                    return Err(SqlCaptureError::InvalidRequest);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlCaptureEncoding {
    PackedJson,
    Utf8,
}

#[derive(Clone, Debug)]
pub struct SqlCapturedRecord {
    pub key: Range<usize>,
    /// Packed JSON body (without the storage version header), or None for a
    /// checked absence. No missing demand-read may manufacture this slot.
    pub body: Option<Range<usize>>,
    pub json_bytes: usize,
    pub version: Option<u64>,
    pub encoding: SqlCaptureEncoding,
    pub body_offset: usize,
    pub total_body_bytes: usize,
}

/// A buffer allocated, charged and touched by the admitted owner before use.
/// No allocation/reallocation occurs in `append` or while the root is borrowed.
pub struct SqlCaptureBuffer {
    bytes: Box<[u8]>,
    used: usize,
    pub(super) records: [Option<SqlCapturedRecord>; SQL_CAPTURE_MAX_RECORDS],
    pub(super) count: usize,
    pub(super) examined: usize,
    continuation: [u8; SQL_CAPTURE_MAX_KEY_BYTES],
    continuation_len: usize,
    continuation_present: bool,
    pub(super) complete: bool,
}
impl fmt::Debug for SqlCaptureBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlCaptureBuffer")
            .field("capacity", &self.bytes.len())
            .field("used", &self.used)
            .field("records", &self.count)
            .field("examined", &self.examined)
            .field("complete", &self.complete)
            .finish()
    }
}
impl SqlCaptureBuffer {
    pub fn from_reserved(mut bytes: Box<[u8]>) -> Result<Self, SqlCaptureError> {
        if bytes.is_empty() || bytes.len() > SQL_CAPTURE_MAX_BYTES {
            return Err(SqlCaptureError::InvalidRequest);
        }
        // Touch before borrowing the publication or entering write exclusion.
        bytes.fill(0);
        Ok(Self {
            bytes,
            used: 0,
            records: std::array::from_fn(|_| None),
            count: 0,
            examined: 0,
            continuation: [0; SQL_CAPTURE_MAX_KEY_BYTES],
            continuation_len: 0,
            continuation_present: false,
            complete: false,
        })
    }
    /// Includes fixed slots/continuation and the supplied allocation; the
    /// admitted caller must charge this storage in addition to its frame.
    pub fn reservation_bytes(capacity: usize) -> Option<usize> {
        (capacity > 0 && capacity <= SQL_CAPTURE_MAX_BYTES)
            .then(|| std::mem::size_of::<Self>().checked_add(capacity))
            .flatten()
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
    pub fn records(&self) -> impl ExactSizeIterator<Item = &SqlCapturedRecord> {
        self.records[..self.count]
            .iter()
            .map(|record| record.as_ref().expect("captured slot"))
    }
    pub fn examined(&self) -> usize {
        self.examined
    }
    pub fn complete(&self) -> bool {
        self.complete
    }
    pub fn continuation(&self) -> Option<&str> {
        self.continuation_present.then(|| {
            std::str::from_utf8(&self.continuation[..self.continuation_len])
                .expect("captured UTF-8 key")
        })
    }
    pub(super) fn remaining(&self) -> usize {
        self.bytes.len() - self.used
    }
    pub(super) fn append(&mut self, bytes: &[u8]) -> Result<Range<usize>, SqlCaptureError> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or(SqlCaptureError::Oversized)?;
        let range = self.used..end;
        self.bytes[range.clone()].copy_from_slice(bytes);
        self.used = end;
        Ok(range)
    }
    pub(super) fn set_continuation(&mut self, key: &str) -> Result<(), SqlCaptureError> {
        if key.len() > self.continuation.len() {
            return Err(SqlCaptureError::Oversized);
        }
        self.continuation[..key.len()].copy_from_slice(key.as_bytes());
        self.continuation_len = key.len();
        self.continuation_present = true;
        Ok(())
    }
    pub(super) fn record(
        &mut self,
        key: &str,
        version: Option<u64>,
        body: Option<&[u8]>,
        json_bytes: usize,
    ) -> Result<(), SqlCaptureError> {
        if self.count >= SQL_CAPTURE_MAX_RECORDS || key.len() > SQL_CAPTURE_MAX_KEY_BYTES {
            return Err(SqlCaptureError::Oversized);
        }
        let needed = key
            .len()
            .checked_add(body.map_or(0, <[u8]>::len))
            .ok_or(SqlCaptureError::Oversized)?;
        if needed > self.remaining() || json_bytes > SQL_CAPTURE_MAX_BYTES {
            return Err(SqlCaptureError::Oversized);
        }
        let key = self.append(key.as_bytes())?;
        let body = body.map(|bytes| self.append(bytes)).transpose()?;
        self.records[self.count] = Some(SqlCapturedRecord {
            key,
            total_body_bytes: body.as_ref().map_or(0, Range::len),
            body,
            json_bytes,
            version,
            encoding: SqlCaptureEncoding::PackedJson,
            body_offset: 0,
        });
        self.count += 1;
        Ok(())
    }
    pub(super) fn chunk(
        &mut self,
        key: &str,
        version: u64,
        body: &[u8],
        json_bytes: usize,
        offset: usize,
        encoding: SqlCaptureEncoding,
    ) -> Result<(), SqlCaptureError> {
        if self.count != 0
            || key.len() > SQL_CAPTURE_MAX_KEY_BYTES
            || body.len() > SQL_CAPTURE_MAX_METADATA_BYTES
            || json_bytes > SQL_CAPTURE_MAX_METADATA_BYTES
            || offset > body.len()
            || key.len() >= self.remaining()
        {
            return Err(SqlCaptureError::Oversized);
        }
        let key_range = self.append(key.as_bytes())?;
        let end = offset.saturating_add(self.remaining()).min(body.len());
        let part = self.append(&body[offset..end])?;
        self.records[0] = Some(SqlCapturedRecord {
            key: key_range,
            body: Some(part),
            json_bytes,
            version: Some(version),
            encoding,
            body_offset: offset,
            total_body_bytes: body.len(),
        });
        self.count = 1;
        self.complete = end == body.len();
        Ok(())
    }
    pub(super) fn value(
        &mut self,
        key: &str,
        version: u64,
        value: &serde_json::Value,
    ) -> Result<(), SqlCaptureError> {
        let mut work = 0;
        let bound = json_bound(value, &mut work, 0)?;
        if self.count >= SQL_CAPTURE_MAX_RECORDS
            || key.len() > SQL_CAPTURE_MAX_KEY_BYTES
            || key
                .len()
                .checked_add(bound)
                .is_none_or(|needed| needed > self.remaining())
        {
            return Err(SqlCaptureError::Oversized);
        }
        let key = self.append(key.as_bytes())?;
        let begin = self.used;
        let mut writer = SliceWriter {
            bytes: &mut self.bytes,
            used: &mut self.used,
        };
        serde_json::to_writer(&mut writer, value).map_err(|_| SqlCaptureError::Oversized)?;
        let body = begin..self.used;
        self.records[self.count] = Some(SqlCapturedRecord {
            key,
            json_bytes: body.len(),
            total_body_bytes: body.len(),
            body: Some(body),
            version: Some(version),
            encoding: SqlCaptureEncoding::PackedJson,
            body_offset: 0,
        });
        self.count += 1;
        Ok(())
    }
}

/// Conservative preflight bounds traversal and escaping *before* the serializer
/// can scan a very large string or recurse through an enormous overlay value.
fn json_bound(
    value: &serde_json::Value,
    work: &mut usize,
    depth: usize,
) -> Result<usize, SqlCaptureError> {
    *work += 1;
    if *work > SQL_CAPTURE_MAX_JSON_NODES || depth > 128 {
        return Err(SqlCaptureError::WorkLimit);
    }
    let text = |value: &str| {
        value
            .len()
            .checked_mul(6)
            .and_then(|size| size.checked_add(2))
            .filter(|size| *size <= SQL_CAPTURE_MAX_BYTES)
            .ok_or(SqlCaptureError::Oversized)
    };
    let mut size = match value {
        serde_json::Value::Null => 4,
        serde_json::Value::Bool(_) => 5,
        serde_json::Value::Number(_) => 32,
        serde_json::Value::String(value) => text(value)?,
        serde_json::Value::Array(values) => {
            if values.len() > SQL_CAPTURE_MAX_JSON_NODES.saturating_sub(*work) {
                return Err(SqlCaptureError::WorkLimit);
            }
            let mut size = 2usize;
            for value in values {
                size = size
                    .checked_add(json_bound(value, work, depth + 1)? + 1)
                    .filter(|size| *size <= SQL_CAPTURE_MAX_BYTES)
                    .ok_or(SqlCaptureError::Oversized)?;
            }
            size
        }
        serde_json::Value::Object(values) => {
            if values.len() > SQL_CAPTURE_MAX_JSON_NODES.saturating_sub(*work) {
                return Err(SqlCaptureError::WorkLimit);
            }
            let mut size = 2usize;
            for (key, value) in values {
                let child = json_bound(value, work, depth + 1)?;
                size = size
                    .checked_add(text(key)?)
                    .and_then(|size| size.checked_add(2))
                    .and_then(|size| size.checked_add(child))
                    .filter(|size| *size <= SQL_CAPTURE_MAX_BYTES)
                    .ok_or(SqlCaptureError::Oversized)?;
            }
            size
        }
    };
    if size > SQL_CAPTURE_MAX_BYTES {
        return Err(SqlCaptureError::Oversized);
    }
    // Keep the expression above explicit about each upper bound.
    size = size.max(1);
    Ok(size)
}
struct SliceWriter<'a> {
    bytes: &'a mut [u8],
    used: &'a mut usize,
}
impl std::io::Write for SliceWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| std::io::Error::other("SQL capture buffer exhausted"))?;
        self.bytes[*self.used..end].copy_from_slice(bytes);
        *self.used = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
pub struct SqlCapturedSlice {
    pub epoch: SqlCaptureEpoch,
    pub buffer: SqlCaptureBuffer,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SqlCaptureError {
    Busy,
    /// One shared cooldown deadline; schedule a wake, never poll Busy.
    Paced(std::time::Instant),
    SnapshotChanged,
    FenceNotReady,
    InvalidRequest,
    ColdPage,
    Oversized,
    WorkLimit,
    UnsupportedBacking,
    Storage,
}
impl fmt::Display for SqlCaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for SqlCaptureError {}

#[cfg(test)]
mod tests {
    use super::*;
    fn buffer() -> SqlCaptureBuffer {
        SqlCaptureBuffer::from_reserved(vec![0; SQL_CAPTURE_MAX_BYTES].into_boxed_slice()).unwrap()
    }
    #[test]
    fn sql_capture_buffer_copies_and_preserves_checked_absence() {
        let mut input = buffer();
        input.record("missing", None, None, 0).unwrap();
        input
            .value("present", 3, &serde_json::json!({"text":"a\\b\n", "n":17}))
            .unwrap();
        let rows: Vec<_> = input.records().collect();
        assert!(rows[0].body.is_none());
        assert_eq!(rows[1].version, Some(3));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(
                &input.bytes()[rows[1].body.clone().unwrap()]
            )
            .unwrap(),
            serde_json::json!({"text":"a\\b\n", "n":17})
        );
    }
    #[test]
    fn sql_capture_overlay_refuses_large_strings_and_nodes_before_serializing() {
        let mut input = buffer();
        let large = serde_json::json!({"value":"x".repeat(SQL_CAPTURE_MAX_BYTES)});
        assert_eq!(
            input.value("large", 1, &large),
            Err(SqlCaptureError::Oversized)
        );
        assert_eq!(input.used, 0);
        let nodes =
            serde_json::Value::Array(vec![serde_json::Value::Null; SQL_CAPTURE_MAX_JSON_NODES]);
        assert_eq!(
            input.value("nodes", 1, &nodes),
            Err(SqlCaptureError::WorkLimit)
        );
        assert_eq!(input.used, 0);
    }
    #[test]
    fn sql_capture_raw_refuses_expansion_and_capacity_before_copying() {
        let mut input = SqlCaptureBuffer::from_reserved(vec![0; 16].into_boxed_slice()).unwrap();
        assert_eq!(
            input.record("key", Some(1), Some(&[0; 15]), 15),
            Err(SqlCaptureError::Oversized)
        );
        assert_eq!(input.used, 0);
        assert_eq!(
            input.record("key", Some(1), Some(b"small"), SQL_CAPTURE_MAX_BYTES + 1),
            Err(SqlCaptureError::Oversized)
        );
        assert_eq!(input.used, 0);
    }
}
