//! Bounded scalar selective dependencies, never a Records/source owner.
use super::*;

pub const SQL_CAPTURE_MAX_DEPENDENCIES: usize = 128;
pub const SQL_CAPTURE_MAX_DEPENDENCY_BYTES: usize =
    SQL_CAPTURE_MAX_DEPENDENCIES * SQL_CAPTURE_MAX_KEY_BYTES;

/// Physical points (including negative reads), or an entire source collection's
/// VALUE generation. Collection takes the unencoded logical collection name.
/// No key-only, window, prefix, or index marker is accepted here.
#[derive(Clone, Copy, Debug)]
pub enum SqlCaptureDependency<'a> {
    Point(&'a str),
    Collection(&'a str),
    /// Live host database/incarnation only, never raw retention accounting.
    HistoryIdentity,
}

#[derive(Clone, Debug)]
struct Check {
    key: Range<usize>,
    collection: bool,
    history: bool,
    stamped: bool,
    version: Option<u64>,
}

/// The admitted owner supplies the complete selector slab before capture.
/// Private stamps cannot be forged or reset. No mutation revalidates an old
/// dependency by adopting its changed generation. Busy/Paced may be scheduled
/// again; a dependency/source failure poisons this attempted certificate.
pub struct SqlCaptureCertificate {
    keys: Box<[u8]>,
    used: usize,
    checks: [Option<Check>; SQL_CAPTURE_MAX_DEPENDENCIES],
    count: usize,
    pub(in crate::consensus) store: u64,
    pub(in crate::consensus) partition: Option<PartitionBinding>,
    pub(in crate::consensus) installation: Option<u64>,
    pub(in crate::consensus) invalid: bool,
}
impl fmt::Debug for SqlCaptureCertificate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqlCaptureCertificate")
            .field("dependencies", &self.count)
            .field("bytes", &self.used)
            .field("invalid", &self.invalid)
            .finish()
    }
}
impl SqlCaptureCertificate {
    pub fn from_reserved(
        fence: &SqlCaptureFence,
        mut keys: Box<[u8]>,
    ) -> Result<Self, SqlCaptureError> {
        if keys.is_empty()
            || keys.len() > SQL_CAPTURE_MAX_DEPENDENCY_BYTES
            || fence
                .partition
                .as_ref()
                .is_some_and(|p| p.partition.len() > SQL_CAPTURE_MAX_KEY_BYTES)
        {
            return Err(SqlCaptureError::InvalidRequest);
        }
        keys.fill(0);
        Ok(Self {
            keys,
            used: 0,
            checks: std::array::from_fn(|_| None),
            count: 0,
            store: fence.store,
            partition: fence.partition.clone(),
            installation: None,
            invalid: false,
        })
    }
    /// Additional to capture/frame/decoder/native scratch; includes fixed slots.
    /// The bounded partition binding clone also needs its own admission.
    pub fn reservation_bytes(capacity: usize) -> Option<usize> {
        (capacity > 0 && capacity <= SQL_CAPTURE_MAX_DEPENDENCY_BYTES)
            .then(|| std::mem::size_of::<Self>().checked_add(capacity))
            .flatten()
    }
    pub fn dependencies(&self) -> usize {
        self.count
    }
    pub(in crate::consensus) fn prepare(
        &mut self,
        additions: &[SqlCaptureDependency<'_>],
    ) -> Result<(), SqlCaptureError> {
        if self.invalid || additions.len() > SQL_CAPTURE_MAX_DEPENDENCIES {
            return Err(SqlCaptureError::InvalidRequest);
        }
        for addition in additions {
            // Encoding and descriptor processing happen BEFORE exclusion/root
            // ownership. Fixed scratch also caps escaping work/serialized size.
            let mut encoded = [0u8; SQL_CAPTURE_MAX_KEY_BYTES];
            let history = matches!(addition, SqlCaptureDependency::HistoryIdentity);
            let (collection, len) = match addition {
                SqlCaptureDependency::Point(key) => {
                    if key.len() > encoded.len() {
                        return Err(SqlCaptureError::InvalidRequest);
                    }
                    encoded[..key.len()].copy_from_slice(key.as_bytes());
                    (false, key.len())
                }
                SqlCaptureDependency::HistoryIdentity => {
                    let marker = super::super::records::HISTORY_MARKER.as_bytes();
                    encoded[..marker.len()].copy_from_slice(marker);
                    (false, marker.len())
                }
                SqlCaptureDependency::Collection(name) => {
                    if name.len() > SQL_CAPTURE_MAX_KEY_BYTES {
                        return Err(SqlCaptureError::InvalidRequest);
                    }
                    let prefix = b"collection:";
                    encoded[..prefix.len()].copy_from_slice(prefix);
                    let mut used = 0;
                    fixed_json::FixedJsonWriter {
                        bytes: &mut encoded[prefix.len()..],
                        used: &mut used,
                    }
                    .string(name)?;
                    (true, prefix.len() + used)
                }
            };
            let bytes = &encoded[..len];
            if self.checks[..self.count].iter().flatten().any(|check| {
                check.collection == collection
                    && check.history == history
                    && &self.keys[check.key.clone()] == bytes
            }) {
                continue;
            }
            if self.count == SQL_CAPTURE_MAX_DEPENDENCIES {
                return Err(SqlCaptureError::WorkLimit);
            }
            let end = self
                .used
                .checked_add(len)
                .filter(|end| *end <= self.keys.len())
                .ok_or(SqlCaptureError::Oversized)?;
            self.keys[self.used..end].copy_from_slice(bytes);
            self.checks[self.count] = Some(Check {
                key: self.used..end,
                collection,
                history,
                stamped: false,
                version: None,
            });
            self.count += 1;
            self.used = end;
        }
        Ok(())
    }
    pub(in crate::consensus) fn check_and_stamp(
        &mut self,
        data: &super::super::Records,
    ) -> Result<(), SqlCaptureError> {
        if self.invalid || self.count == 0 {
            return Err(SqlCaptureError::InvalidRequest);
        }
        for check in self.checks[..self.count].iter_mut().flatten() {
            let key =
                std::str::from_utf8(&self.keys[check.key.clone()]).expect("copied UTF8 selector");
            let actual = if check.collection || check.history {
                data.generation(key)
            } else {
                data.sql_capture_version(key)?
            };
            if check.stamped && check.version != actual {
                return Err(SqlCaptureError::SnapshotChanged);
            }
            if !check.stamped {
                check.version = actual;
                check.stamped = true;
            }
        }
        Ok(())
    }
    pub(in crate::consensus) fn validate(
        &self,
        data: &super::super::Records,
    ) -> Result<(), SqlCaptureError> {
        if self.invalid || self.count == 0 {
            return Err(SqlCaptureError::InvalidRequest);
        }
        for check in self.checks[..self.count].iter().flatten() {
            if !check.stamped {
                return Err(SqlCaptureError::InvalidRequest);
            }
            let key =
                std::str::from_utf8(&self.keys[check.key.clone()]).expect("copied UTF8 selector");
            let actual = if check.collection || check.history {
                data.generation(key)
            } else {
                data.sql_capture_version(key)?
            };
            if check.version != actual {
                return Err(SqlCaptureError::SnapshotChanged);
            }
        }
        Ok(())
    }
    pub(in crate::consensus) fn has_history_identity(&self) -> bool {
        !self.invalid
            && self.checks[..self.count]
                .iter()
                .flatten()
                .any(|check| check.stamped && check.history)
    }
    fn point_covered(&self, key: &str) -> bool {
        self.checks[..self.count].iter().flatten().any(|check| {
            if !check.stamped || check.history {
                return false;
            }
            let selector =
                std::str::from_utf8(&self.keys[check.key.clone()]).expect("UTF8 selector");
            if !check.collection {
                return selector == key;
            }
            let encoded = selector
                .strip_prefix("collection:")
                .expect("collection selector");
            key.strip_prefix("source:[")
                .and_then(|key| key.strip_prefix(encoded))
                .is_some_and(|tail| tail.starts_with(','))
        })
    }
    pub(in crate::consensus) fn covers(&self, request: &SqlCaptureRequest<'_>) -> bool {
        match request.selection {
            SqlCaptureSelection::Keys(keys) => keys.iter().all(|key| self.point_covered(key)),
            SqlCaptureSelection::KeyChunk { key, .. }
            | SqlCaptureSelection::StringChunk { key, .. } => self.point_covered(key),
            SqlCaptureSelection::Range {
                lower,
                upper,
                after,
            } => {
                let Some(upper) = upper else {
                    return false;
                };
                self.checks[..self.count].iter().flatten().any(|check| {
                    if !check.stamped || !check.collection {
                        return false;
                    }
                    let selector =
                        std::str::from_utf8(&self.keys[check.key.clone()]).expect("UTF8 selector");
                    let encoded = selector
                        .strip_prefix("collection:")
                        .expect("collection selector");
                    let in_collection = |key: &str| {
                        key.strip_prefix("source:[")
                            .and_then(|key| key.strip_prefix(encoded))
                            .is_some_and(|tail| tail.starts_with(','))
                    };
                    // Lexicographic successor of the WHOLE collection prefix,
                    // comma→hyphen, with no window/row-count equivalence claim.
                    let mut bound = [0u8; SQL_CAPTURE_MAX_KEY_BYTES];
                    let n = 8 + encoded.len();
                    if n + 1 > bound.len() {
                        return false;
                    }
                    bound[..8].copy_from_slice(b"source:[");
                    bound[8..n].copy_from_slice(encoded.as_bytes());
                    bound[n] = b'-';
                    in_collection(lower)
                        && after.is_none_or(in_collection)
                        && upper.as_bytes() <= &bound[..n + 1]
                })
            }
        }
    }
}
