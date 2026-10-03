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
    pub(crate) fn sql_capture_raw(
        &self,
        request: &SqlCaptureRequest<'_>,
        output: &mut SqlCaptureBuffer,
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
                let lo = after.map_or(Bound::Included(lower), Bound::Excluded);
                let hi = upper.map_or(Bound::Unbounded, Bound::Excluded);
                // Bound allocations are capped by request.validate; no source keys
                // or payloads are allocated by the backing's raw iterator.
                let mut tree = self
                    .map
                    .range::<_, String>((lo.map(str::to_owned), hi.map(str::to_owned)))
                    .peekable();
                let mut stored = match &self.backing {
                    Some(backing) => backing.capture_raw_range(lo, hi)?,
                    None => RawRange::Empty,
                };
                let mut disk = stored.next().transpose()?;
                if disk.is_some() {
                    output.examined += 1;
                }
                loop {
                    if output.count >= request.max_records {
                        output.complete = false;
                        break;
                    }
                    if tree.peek().is_none() && disk.is_none() {
                        output.complete = true;
                        break;
                    }
                    let order = match (tree.peek(), disk.as_ref()) {
                        (Some((key, _)), Some(raw)) => key.as_str().cmp(raw.key()?),
                        (Some(_), None) => std::cmp::Ordering::Less,
                        (None, Some(_)) => std::cmp::Ordering::Greater,
                        (None, None) => unreachable!(),
                    };
                    if order != std::cmp::Ordering::Greater
                        && output.examined >= request.max_examined
                    {
                        if output.continuation().is_none() {
                            return Err(SqlCaptureError::WorkLimit);
                        }
                        output.complete = false;
                        break;
                    }
                    if order != std::cmp::Ordering::Greater {
                        let (key, entry) = tree.next().expect("peeked overlay");
                        output.examined += 1;
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
                    } else {
                        let raw = disk.as_ref().expect("peeked stored record");
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
                        // Every stored entry inspected is charged, even when an
                        // overlay tombstone shadows it. No unbounded Merge::next.
                        if output.examined >= request.max_examined {
                            output.complete = false;
                            break;
                        }
                        disk = stored.next().transpose()?;
                        if disk.is_some() {
                            output.examined += 1;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
