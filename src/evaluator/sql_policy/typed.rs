//! Native-only correlation of captured logical keys; no serving acquisition.
//! All handles belong to ONE already-admitted frame. This private witness proves
//! shape/canonical/key-offset correlation, NOT trusted controller origin.
use super::super::sql_frame::{FrameBuilder, FrameControl, JsonId, KeyId};
use super::rule::{Resolved, Subject};
use super::*;
use std::cmp::Ordering;

#[derive(Clone, Copy)]
pub(crate) enum NativeDecodedKey<'a> {
    String(&'a str),
    Json(ArenaValue<'a>),
}
#[derive(Clone, Copy)]
pub(crate) struct NativeKeyRow<'a> {
    owner: &'a FrameBuilder,
    collection: &'a str,
    key_id: KeyId,
    encoded: &'a str,
    decoded: Option<ArenaValue<'a>>,
    json_key: bool,
    row: Option<ArenaValue<'a>>,
}
impl<'a> NativeKeyRow<'a> {
    /// `source_pair` is the owned canonical [collection,encoded_key] suffix of
    /// an actual native physical source ID. NEVER expose that ID to a guest.
    /// Decode into this frame before binding; its parse/node/raw/decoded quotas
    /// and original FrameControl are charged by FrameBuilder. No parsing here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn bind_owned_native_capture(
        frame: &'a FrameBuilder,
        source_declaration: JsonId,
        source_pair: JsonId,
        retained_key: KeyId,
        decoded_key: Option<JsonId>,
        row: Option<JsonId>,
        control: &'a FrameControl<'a>,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Self, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            // Work checks the original job on every charged operation. The
            // caller supplies that same job's FrameControl while capturing and
            // borrowing; FrameControl exposes no introspection API here.
            let declaration = work.frame(frame.json(source_declaration, control))?;
            work.touch(declaration)?;
            if declaration.kind() != ArenaKind::Object {
                return Err(PolicyError::Unsupported);
            }
            let mut name = None;
            let mut json_key = false; // native Source's serde default
            let mut iter = declaration.children();
            while let Some(entry) = work.next(&mut iter)? {
                match entry.key {
                    Some("name") => name = entry.value.as_str(),
                    Some("jsonKey") => {
                        json_key = entry.value.as_bool().ok_or(PolicyError::Unsupported)?;
                    }
                    _ => return Err(PolicyError::Unsupported),
                }
            }
            let collection = name
                .filter(|name| plain_collection(name))
                .ok_or(PolicyError::Unsupported)?;
            let encoded = work.frame(frame.key(retained_key))?;
            plain_key(encoded)?;
            let pair = work.frame(frame.json(source_pair, control))?;
            work.touch(pair)?;
            if pair.kind() != ArenaKind::Array {
                return Err(PolicyError::Unsupported);
            }
            let mut iter = pair.children();
            let name = work
                .next(&mut iter)?
                .and_then(|entry| entry.value.as_str())
                .ok_or(PolicyError::Unsupported)?;
            let key = work
                .next(&mut iter)?
                .and_then(|entry| entry.value.as_str())
                .ok_or(PolicyError::Unsupported)?;
            if work.next(&mut iter)?.is_some()
                || !work.text_same(name, collection)?
                || !work.text_same(key, encoded)?
            {
                return Err(PolicyError::Unsupported);
            }
            let raw_pair = work.frame(frame.raw_json(source_pair))?;
            let mut sink = Match::new(raw_pair);
            sink.bytes(b"[", &mut work)?;
            string(collection, &mut sink, &mut work)?;
            sink.bytes(b",", &mut work)?;
            string(encoded, &mut sink, &mut work)?;
            sink.bytes(b"]", &mut work)?;
            if !sink.finish() {
                return Err(PolicyError::Unsupported);
            }
            let decoded = decoded_key
                .map(|id| work.frame(frame.json(id, control)))
                .transpose()?;
            if let Some(decoded) = decoded {
                work.touch(decoded)?;
            }
            if let Some(id) = decoded_key {
                // Parse MUST describe the exact retained token stream. Merely
                // canonical-equal is insufficient: >2^53 integer tokens can
                // share canonical bytes yet differ in native integer ordering.
                let raw = work.frame(frame.raw_json(id))?;
                if !work.text_same(raw, encoded)? {
                    return Err(PolicyError::Unsupported);
                }
            }
            if json_key {
                let decoded = decoded.ok_or(PolicyError::NeedCapture)?;
                if !canonical_matches(decoded, encoded, &mut work)? {
                    return Err(PolicyError::Unsupported);
                }
                if let Some(text) = decoded.as_str() {
                    plain_key(text)?;
                }
            } else if let Some(id) = decoded_key {
                // Untyped native KeyPart parses the ORIGINAL string, not its
                // canonicalization. Noncanonical but valid structured strings
                // are ordinary native inputs and retain their exact identity.
                if !work.text_same(work.frame(frame.raw_json(id))?, encoded)? {
                    return Err(PolicyError::Unsupported);
                }
            } else {
                // No guest flag may assert that a potentially structured key
                // has no parts. Invalid JSON in this domain explicitly refuses;
                // the controller may not turn a parse failure into absence.
                let mut first = None;
                for chunk in encoded.as_bytes().chunks(1024) {
                    work.debit(chunk.len())?;
                    first = chunk
                        .iter()
                        .copied()
                        .find(|byte| !matches!(byte, b' ' | b'\n' | b'\r' | b'\t'));
                    if first.is_some() {
                        break;
                    }
                }
                if matches!(first, Some(b'[' | b'{')) {
                    return Err(PolicyError::NeedCapture);
                }
            }
            let row = row
                .map(|id| work.frame(frame.json(id, control)))
                .transpose()?;
            if let Some(row) = row {
                work.touch(row)?;
            }
            Ok(Self {
                owner: frame,
                collection,
                key_id: retained_key,
                encoded,
                decoded,
                json_key,
                row,
            })
        })();
        work.keep(result)
    }
    pub(crate) fn encoded_key(self) -> &'a str {
        self.encoded
    }
    pub(crate) fn retained_key(self) -> KeyId {
        self.key_id
    }
    /// Logical application keys have this shape. Existing raw SDK host.scan /
    /// provider adapters still take encoded_key strings and decode ONCE in SDK;
    /// do not double-decode their inputs. Mapped sourceKey stays encoded text.
    /// Neither accessor returns a physical ID.
    pub(crate) fn logical_key(self) -> NativeDecodedKey<'a> {
        if self.json_key {
            NativeDecodedKey::Json(self.decoded.expect("private checked typed key"))
        } else {
            NativeDecodedKey::String(self.encoded)
        }
    }
    fn parts(self) -> Option<ArenaValue<'a>> {
        self.decoded
            .filter(|value| matches!(value.kind(), ArenaKind::Array | ArenaKind::Object))
    }
}
impl<'a> CapturedSupport<'a> {
    /// No changes to the old public descriptor fields. Validate ALL names and
    /// duplicate native keys before the first candidate, not just on lookup.
    pub(crate) fn from_owned_native_capture(
        collections: &'a [CapturedCollection<'a>],
        rows: &'a [NativeKeyRow<'a>],
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Self, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            if collections.len() > MAX_COLLECTIONS || rows.len() > MAX_SUPPORT_ROWS {
                return Err(PolicyError::Capacity);
            }
            for (index, collection) in collections.iter().enumerate() {
                work.debit(1)?;
                if !plain_collection(collection.name) {
                    return Err(PolicyError::Unsupported);
                }
                if let Some(policy) = collection.policy {
                    work.touch(policy)?;
                }
                for previous in &collections[..index] {
                    if work.text_same(previous.name, collection.name)? {
                        return Err(PolicyError::Unsupported);
                    }
                }
            }
            for (index, row) in rows.iter().enumerate() {
                work.debit(1)?;
                if let Some(first) = rows.first()
                    && !std::ptr::eq(row.owner, first.owner)
                {
                    return Err(PolicyError::Unsupported);
                }
                let mut declared = false;
                for collection in collections {
                    declared |= work.text_same(collection.name, row.collection)?;
                }
                if !declared {
                    return Err(PolicyError::NeedCapture);
                }
                for previous in &rows[..index] {
                    if work.text_same(previous.collection, row.collection)?
                        && work.text_same(previous.encoded, row.encoded)?
                    {
                        return Err(PolicyError::Unsupported);
                    }
                }
            }
            Ok(Self {
                collections,
                rows: &[],
                native_rows: Some(rows),
            })
        })();
        work.keep(result)
    }
    fn native_row(
        self,
        collection: &str,
        key: Resolved<'a>,
        work: &mut Work<'_>,
    ) -> Result<NativeKeyRow<'a>, PolicyError> {
        let rows = self.native_rows.ok_or(PolicyError::Unsupported)?;
        let mut found = None;
        for row in rows {
            work.debit(1)?;
            if !work.text_same(row.collection, collection)? {
                continue;
            }
            let same = match key {
                Resolved::Json(value)
                    if matches!(value.kind(), ArenaKind::Array | ArenaKind::Object) =>
                {
                    canonical_matches(value, row.encoded, work)?
                }
                key => key
                    .text()
                    .map(|key| work.text_same(key, row.encoded))
                    .transpose()?
                    .unwrap_or(false),
            };
            if same {
                if found.is_some() {
                    return Err(PolicyError::Unsupported);
                }
                found = Some(*row);
            }
        }
        found.ok_or(PolicyError::NeedCapture)
    }
}
impl<'a> PolicyEngine<'a> {
    /// Native-only alternative: collection/key/raw row cannot be independently
    /// substituted. Complete support validation precedes any row output.
    pub(crate) fn authorize_native(
        &self,
        row: NativeKeyRow<'a>,
        selecting_fields: &[&str],
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<ReadAuthorization<'a>, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            let rows = self.support.native_rows.ok_or(PolicyError::Unsupported)?;
            if let Some(first) = rows.first()
                && !std::ptr::eq(first.owner, row.owner)
            {
                return Err(PolicyError::Unsupported);
            }
            let value = row.row.ok_or(PolicyError::Unsupported)?;
            work.touch(value)?;
            let policy = self.support.collection(row.collection, &mut work)?;
            let parts = rule::policy_parts(policy, &mut work)?;
            rule::validate_policy_reads(parts, self.support, true, &mut work)?;
            let subject = Subject {
                engine: *self,
                key: row.encoded,
                parts: row.parts(),
                native: true,
                row: value,
            };
            let mut decision = rule::evaluate_optional(parts.read, false, subject, &mut work)?;
            if policy.is_none() {
                decision.allowed = true;
            }
            if decision.allowed {
                for field in selecting_fields {
                    let shown = rule::field_decision(parts.fields, field, subject, &mut work)?;
                    decision.allowed &= shown.allowed;
                    decision.validity = decision.validity.intersect(shown.validity);
                }
            }
            if decision.allowed
                && let Some(fields) = parts.fields
            {
                let mut iter = fields.children();
                while let Some(entry) = work.next(&mut iter)? {
                    let name = entry.key.ok_or(PolicyError::Unsupported)?;
                    if work.get(value, name)?.is_some() {
                        let shown = rule::field_decision(parts.fields, name, subject, &mut work)?;
                        decision.validity = decision.validity.intersect(shown.validity);
                    }
                }
            }
            budget.note(decision.validity, self.now);
            Ok(ReadAuthorization {
                decision,
                candidate: decision.allowed.then_some(RedactedRow {
                    subject,
                    fields: parts.fields,
                    validity: decision.validity,
                }),
            })
        })();
        work.keep(result)
    }
}
pub(super) fn readable(
    collection: &str,
    key: Resolved<'_>,
    subject: Subject<'_>,
    work: &mut Work<'_>,
) -> Result<Decision, PolicyError> {
    if key.text().is_none()
        && !matches!(key, Resolved::Json(value) if matches!(value.kind(), ArenaKind::Array | ArenaKind::Object))
    {
        return Ok(Decision {
            allowed: false,
            validity: Validity::Independent,
        });
    }
    let policy = subject
        .engine
        .support
        .collection(collection, work)?
        .ok_or(PolicyError::Unsupported)?;
    let parts = rule::policy_parts(Some(policy), work)?;
    let target = subject.engine.support.native_row(collection, key, work)?;
    match target.row {
        Some(row) => rule::evaluate_optional(
            parts.read,
            false,
            Subject {
                key: target.encoded,
                parts: target.parts(),
                row,
                ..subject
            },
            work,
        ),
        None => Ok(Decision {
            allowed: false,
            validity: Validity::Independent,
        }),
    }
}
fn plain_collection(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with("$flower.")
        && !name.starts_with("__flower")
        && !physical_prefix(name)
}
fn physical_prefix(key: &str) -> bool {
    [
        "source:",
        "collection:",
        "cell:",
        "root:",
        "index:",
        "$flower.",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}
fn plain_key(key: &str) -> Result<(), PolicyError> {
    if physical_prefix(key) {
        Err(PolicyError::Unsupported)
    } else {
        Ok(())
    }
}

/// Streaming canonical-byte matcher: no stringify buffer/tree/scratch mapping.
/// Arrays preserve order; object members use EXACT native UTF-16 ordering, not
/// ACL string ordering (which is UTF-8). O(n²) selection is cumulatively metered.
struct Match<'a> {
    bytes: &'a [u8],
    position: usize,
    same: bool,
}
impl<'a> Match<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            position: 0,
            same: true,
        }
    }
    fn bytes(&mut self, bytes: &[u8], work: &mut Work<'_>) -> Result<(), PolicyError> {
        for chunk in bytes.chunks(1024) {
            work.debit(chunk.len())?;
            let end = self
                .position
                .checked_add(chunk.len())
                .ok_or(PolicyError::Capacity)?;
            self.same &= self.bytes.get(self.position..end) == Some(chunk);
            self.position = end;
        }
        Ok(())
    }
    fn finish(self) -> bool {
        self.same && self.position == self.bytes.len()
    }
}
fn string(text: &str, sink: &mut Match<'_>, work: &mut Work<'_>) -> Result<(), PolicyError> {
    sink.bytes(b"\"", work)?;
    for chunk in text.as_bytes().chunks(1024) {
        work.debit(chunk.len())?;
        let mut start = 0;
        for (index, &byte) in chunk.iter().enumerate() {
            let escape: Option<&[u8]> = match byte {
                b'"' => Some(b"\\\""),
                b'\\' => Some(b"\\\\"),
                b'\x08' => Some(b"\\b"),
                b'\x0c' => Some(b"\\f"),
                b'\n' => Some(b"\\n"),
                b'\r' => Some(b"\\r"),
                b'\t' => Some(b"\\t"),
                0..=31 => Some(b""),
                _ => None,
            };
            if let Some(escape) = escape {
                sink.bytes(&chunk[start..index], work)?;
                if escape.is_empty() {
                    const HEX: &[u8] = b"0123456789abcdef";
                    sink.bytes(
                        &[
                            b'\\',
                            b'u',
                            b'0',
                            b'0',
                            HEX[(byte >> 4) as usize],
                            HEX[(byte & 15) as usize],
                        ],
                        work,
                    )?;
                } else {
                    sink.bytes(escape, work)?;
                }
                start = index + 1;
            }
        }
        sink.bytes(&chunk[start..], work)?;
    }
    sink.bytes(b"\"", work)
}
fn utf16_order(left: &str, right: &str, work: &mut Work<'_>) -> Result<Ordering, PolicyError> {
    let mut left = left.encode_utf16();
    let mut right = right.encode_utf16();
    loop {
        work.debit(2)?;
        match (left.next(), right.next()) {
            (Some(a), Some(b)) if a == b => {}
            (a, b) => return Ok(a.cmp(&b)),
        }
    }
}
struct CanonLevel<'a> {
    value: ArenaValue<'a>,
    iter: ArenaIter<'a>,
    last: Option<&'a str>,
    first: bool,
}
fn canonical_matches(
    value: ArenaValue<'_>,
    encoded: &str,
    work: &mut Work<'_>,
) -> Result<bool, PolicyError> {
    let mut sink = Match::new(encoded);
    let mut stack: [Option<CanonLevel<'_>>; 64] = std::array::from_fn(|_| None);
    let mut depth = 0;
    let mut current = Some(value);
    loop {
        if let Some(value) = current.take() {
            work.touch(value)?;
            match value.kind() {
                ArenaKind::Null => sink.bytes(b"null", work)?,
                ArenaKind::Boolean => sink.bytes(
                    if value.as_bool() == Some(true) {
                        b"true"
                    } else {
                        b"false"
                    },
                    work,
                )?,
                ArenaKind::Text => string(
                    value.as_str().ok_or(PolicyError::Unsupported)?,
                    &mut sink,
                    work,
                )?,
                ArenaKind::Number => {
                    let number = compare::number(Resolved::Json(value), work)?
                        .and_then(|n| n.as_f64())
                        .ok_or(PolicyError::Unsupported)?;
                    if number == 0.0 {
                        sink.bytes(b"0", work)?;
                    } else {
                        sink.bytes(ryu_js::Buffer::new().format_finite(number).as_bytes(), work)?;
                    }
                }
                ArenaKind::Array | ArenaKind::Object => {
                    if depth == stack.len() {
                        return Err(PolicyError::Unsupported);
                    }
                    sink.bytes(
                        if value.kind() == ArenaKind::Object {
                            b"{"
                        } else {
                            b"["
                        },
                        work,
                    )?;
                    stack[depth] = Some(CanonLevel {
                        value,
                        iter: value.children(),
                        last: None,
                        first: true,
                    });
                    depth += 1;
                }
            }
        }
        while depth > 0 {
            let level = stack[depth - 1].as_mut().ok_or(PolicyError::Unsupported)?;
            let object = level.value.kind() == ArenaKind::Object;
            let next = if object {
                let mut iter = level.value.children();
                let mut best: Option<ArenaEntry<'_>> = None;
                while let Some(entry) = work.next(&mut iter)? {
                    let key = entry.key.ok_or(PolicyError::Unsupported)?;
                    if let Some(last) = level.last
                        && utf16_order(key, last, work)? != Ordering::Greater
                    {
                        continue;
                    }
                    if best.as_ref().is_none()
                        || utf16_order(
                            key,
                            best.as_ref()
                                .and_then(|e| e.key)
                                .ok_or(PolicyError::Unsupported)?,
                            work,
                        )? == Ordering::Less
                    {
                        best = Some(entry);
                    }
                }
                best
            } else {
                work.next(&mut level.iter)?
            };
            if let Some(entry) = next {
                if !level.first {
                    sink.bytes(b",", work)?;
                }
                level.first = false;
                if object {
                    let key = entry.key.ok_or(PolicyError::Unsupported)?;
                    level.last = Some(key);
                    string(key, &mut sink, work)?;
                    sink.bytes(b":", work)?;
                }
                current = Some(entry.value);
                break;
            }
            sink.bytes(if object { b"}" } else { b"]" }, work)?;
            stack[depth - 1] = None;
            depth -= 1;
        }
        if current.is_none() {
            return Ok(sink.finish());
        }
    }
}
