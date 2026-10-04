//! Quota-first raw copying. This module never clones a Records/Backing/value.
use super::*;
use crate::consensus::backing::sql_capture::RawRange;
use crate::consensus::sql_capture::*;

fn stored_parts(bytes: &[u8]) -> Result<(u64, &[u8], usize), SqlCaptureError> {
    let header = bytes.get(..8).ok_or(SqlCaptureError::Storage)?;
    let version = u64::from_le_bytes(header.try_into().map_err(|_| SqlCaptureError::Storage)?);
    let body = &bytes[8..];
    let json_bytes = super::super::packed::json_len(body);
    if json_bytes > SQL_CAPTURE_MAX_METADATA_BYTES || body.len() > SQL_CAPTURE_MAX_METADATA_BYTES {
        return Err(SqlCaptureError::Oversized);
    }
    Ok((version, body, json_bytes))
}
impl Records {
    /// Resident-only version/checked absence. No ordinary backing read, body
    /// decode, memo, global cache or fallback walk is used for certificates.
    pub(crate) fn sql_capture_version(&self, key: &str) -> Result<Option<u64>, SqlCaptureError> {
        if let Some(entry) = self.map.get(key) {
            return Ok(entry.value.as_ref().map(|_| entry.version));
        }
        let Some(backing) = &self.backing else {
            return Ok(None);
        };
        let Some(value) = backing.capture_raw_get(key)? else {
            return Ok(None);
        };
        let header = value.value().get(..8).ok_or(SqlCaptureError::Storage)?;
        Ok(Some(u64::from_le_bytes(
            header.try_into().map_err(|_| SqlCaptureError::Storage)?,
        )))
    }
    #[cfg(test)]
    pub(crate) fn sql_capture_raw(
        &self,
        request: &SqlCaptureRequest<'_>,
        output: &mut SqlCaptureBuffer,
    ) -> Result<(), SqlCaptureError> {
        let mut scratch = SqlCaptureScratch::for_partition(
            self.backing
                .as_ref()
                .and_then(|b| b.capture_raw_partition()),
            request,
        )?;
        self.sql_capture_prepared(request, output, &mut scratch)
    }
    pub(crate) fn sql_capture_prepared(
        &self,
        request: &SqlCaptureRequest<'_>,
        output: &mut SqlCaptureBuffer,
        scratch: &mut SqlCaptureScratch,
    ) -> Result<(), SqlCaptureError> {
        request.validate()?;
        if !self.has_valid_depth() || !self.has_valid_source_ids() {
            return Err(SqlCaptureError::Storage);
        }
        match request.selection {
            SqlCaptureSelection::Keys(keys) => {
                for key in keys {
                    if output.examined >= request.max_examined {
                        return Err(SqlCaptureError::WorkLimit);
                    }
                    output.examined += 1;
                    match self.map.get(*key) {
                        Some(entry) => match &entry.value {
                            Some(value) => output.value(key, entry.version, value)?,
                            None => output.record(key, None, None, 0)?,
                        },
                        None => match self
                            .backing
                            .as_ref()
                            .map(|backing| backing.capture_raw_get(key))
                            .transpose()?
                            .flatten()
                        {
                            Some(value) => {
                                let (version, body, json_bytes) = stored_parts(value.value())?;
                                output.record(key, Some(version), Some(body), json_bytes)?;
                            }
                            None => output.record(key, None, None, 0)?,
                        },
                    }
                }
                output.complete = true;
            }
            SqlCaptureSelection::KeyChunk { key, offset } => {
                output.examined += 1;
                match self.map.get(key) {
                    Some(entry) => match &entry.value {
                        Some(value) => {
                            // Small overlays fit one bounded serializer pass. Large
                            // strings use StringChunk; generic large overlays refuse.
                            output.value(key, entry.version, value)?;
                            let row = output.records[0].as_mut().expect("captured value");
                            let body = row.body.as_mut().expect("present value");
                            if offset > body.len() {
                                return Err(SqlCaptureError::InvalidRequest);
                            }
                            body.start += offset;
                            row.body_offset = offset;
                            output.complete = true;
                        }
                        None => {
                            output.record(key, None, None, 0)?;
                            output.complete = true;
                        }
                    },
                    None => match self
                        .backing
                        .as_ref()
                        .map(|backing| backing.capture_raw_get(key))
                        .transpose()?
                        .flatten()
                    {
                        Some(value) => {
                            let (version, body, json_bytes) = stored_parts(value.value())?;
                            output.chunk(
                                key,
                                version,
                                body,
                                json_bytes,
                                offset,
                                SqlCaptureEncoding::PackedJson,
                            )?;
                        }
                        None => {
                            output.record(key, None, None, 0)?;
                            output.complete = true;
                        }
                    },
                }
            }
            SqlCaptureSelection::StringChunk { key, field, offset } => {
                output.examined += 1;
                let Some(entry) = self.map.get(key) else {
                    return Err(SqlCaptureError::UnsupportedBacking);
                };
                let Some(value) = &entry.value else {
                    output.record(key, None, None, 0)?;
                    output.complete = true;
                    return Ok(());
                };
                let text = value
                    .get(field)
                    .and_then(Value::as_str)
                    .ok_or(SqlCaptureError::InvalidRequest)?;
                output.chunk(
                    key,
                    entry.version,
                    text.as_bytes(),
                    text.len(),
                    offset,
                    SqlCaptureEncoding::Utf8,
                )?;
            }
            SqlCaptureSelection::Range {
                lower,
                upper,
                after,
            } => {
                let mut query = [0u8; SQL_CAPTURE_MAX_KEY_BYTES + 1];
                let mut query_len = after.map_or(lower.len(), |key| key.len() + 1);
                if let Some(after) = after {
                    query[..after.len()].copy_from_slice(after.as_bytes());
                } else {
                    query[..lower.len()].copy_from_slice(lower.as_bytes());
                }
                let mut tree = None;
                let mut need_tree = !self.map.is_empty();
                let mut tree_done = !need_tree;
                let mut stored = match &self.backing {
                    Some(backing) => backing.capture_raw_range(scratch)?,
                    None => RawRange::Empty,
                };
                let mut disk = None;
                let mut need_disk = !matches!(&stored, RawRange::Empty);
                let mut disk_done = !need_disk;
                loop {
                    // Never probe a successor after filling the permitted row
                    // slice. It may be cold/oversized and is not this slice's work.
                    if output.count >= request.max_records {
                        output.complete = false;
                        break;
                    }
                    if need_tree {
                        if output.examined >= request.max_examined {
                            if output.continuation().is_none() {
                                return Err(SqlCaptureError::WorkLimit);
                            }
                            output.complete = false;
                            break;
                        }
                        output.examined += 1; // charged BEFORE lookup/prefetch
                        let key = std::str::from_utf8(&query[..query_len])
                            .map_err(|_| SqlCaptureError::Storage)?;
                        tree = self
                            .map
                            .get_next_bounded(key)
                            .map_err(|_| SqlCaptureError::WorkLimit)?
                            .filter(|(key, _)| upper.is_none_or(|upper| key.as_str() < upper));
                        tree_done = tree.is_none();
                        need_tree = false;
                    }
                    if need_disk {
                        if output.examined >= request.max_examined {
                            if output.continuation().is_none() {
                                return Err(SqlCaptureError::WorkLimit);
                            }
                            output.complete = false;
                            break;
                        }
                        output.examined += 1; // misses/end probes also consume work
                        disk = stored.next().transpose()?;
                        disk_done = disk.is_none();
                        need_disk = false;
                    }
                    if tree_done && disk_done {
                        output.complete = true;
                        break;
                    }
                    let order = match (tree.as_ref(), disk.as_ref()) {
                        (Some((key, _)), Some(raw)) => key.as_str().cmp(raw.key()?),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => unreachable!(),
                    };
                    if order != std::cmp::Ordering::Greater {
                        let (key, entry) = tree.take().expect("loaded overlay");
                        if key.len() > SQL_CAPTURE_MAX_KEY_BYTES {
                            return Err(SqlCaptureError::Oversized);
                        }
                        if let Some(value) = &entry.value {
                            match output.value(key, entry.version, value) {
                                Err(SqlCaptureError::Oversized) if output.count > 0 => {
                                    output.complete = false;
                                    break;
                                }
                                result => result?,
                            }
                        }
                        output.set_continuation(key)?;
                        query[..key.len()].copy_from_slice(key.as_bytes());
                        query[key.len()] = 0;
                        query_len = key.len() + 1;
                        need_tree = true;
                    } else {
                        let raw = disk.as_ref().expect("loaded stored record");
                        let key = raw.key()?;
                        let (version, body, json_bytes) = stored_parts(raw.value.value())?;
                        match output.record(key, Some(version), Some(body), json_bytes) {
                            Err(SqlCaptureError::Oversized) if output.count > 0 => {
                                output.complete = false;
                                break;
                            }
                            result => result?,
                        }
                        output.set_continuation(key)?;
                    }
                    if order != std::cmp::Ordering::Less {
                        // Drop the consumed/shadowed pending page guards before
                        // any successor read. Next iteration first checks quotas.
                        drop(disk.take());
                        need_disk = true;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
