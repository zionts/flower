//! Authorized-only projection and fixed-output redacted JSON. No raw source
//! override is accepted. Hidden/missing mapped fields are always SQL Null.
use super::super::sql_frame::{ColumnKind, FrameCell};
use super::*;

impl<'a> RedactedRow<'a> {
    pub(crate) fn validity(&self) -> Validity {
        self.validity
    }
    pub(crate) fn field_visible(
        &self,
        name: &str,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Decision, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = work
            .touch(self.subject.row)
            .and_then(|()| rule::field_decision(self.fields, name, self.subject, &mut work));
        work.keep(result.map(|mut decision| {
            decision.validity = decision.validity.intersect(self.validity);
            budget.note(decision.validity, self.subject.engine.now);
            decision
        }))
    }
    pub(crate) fn field(
        &self,
        name: &str,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = self.visible_value(name, &mut work);
        work.keep(result)
    }
    fn visible_value(
        &self,
        name: &str,
        work: &mut Work<'_>,
    ) -> Result<Option<ArenaValue<'a>>, PolicyError> {
        work.touch(self.subject.row)?;
        if !rule::field_decision(self.fields, name, self.subject, work)?.allowed {
            return Ok(None);
        }
        work.get(self.subject.row, name)
    }
    /// Controller supplies a trusted logical mapping's field/kind, NOT a value
    /// supplied by guest or fetched again from a serving source. This helper
    /// cannot substitute raw source data for an unreadable candidate field.
    pub(crate) fn mapped_cell(
        &self,
        field: &str,
        kind: ColumnKind,
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<FrameCell<'a>, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = (|| {
            let Some(value) = self.visible_value(field, &mut work)? else {
                return Ok(FrameCell::Null);
            };
            if value.is_null() {
                return Ok(FrameCell::Null);
            }
            Ok(match kind {
                ColumnKind::Integer => work
                    .frame(value.source_integer())?
                    .map_or(FrameCell::Null, FrameCell::Integer),
                ColumnKind::Real => work
                    .frame(value.as_f64())?
                    .map(FrameCell::Real)
                    .ok_or(PolicyError::Unsupported)?,
                ColumnKind::Text => {
                    FrameCell::Text(value.as_str().ok_or(PolicyError::Unsupported)?)
                }
            })
        })();
        work.keep(result)
    }
    /// Borrowed caller-owned bounded scratch. Only the returned initialized
    /// prefix is valid; an error is sticky/fatal and requires discarding output.
    /// Object member order is retained, not canonicalized; ordinary redaction
    /// removes top-level fields only. Nonobjects remain unchanged as access.rs.
    pub(crate) fn encode_json(
        &self,
        output: &mut [u8],
        budget: &PolicyBudget,
        job: &mut JobControl,
    ) -> Result<usize, PolicyError> {
        let mut work = budget.operation(job)?;
        let result = self.encode(output, &mut work);
        work.keep(result)
    }
    fn encode(&self, output: &mut [u8], work: &mut Work<'_>) -> Result<usize, PolicyError> {
        work.touch(self.subject.row)?;
        let mut writer = Writer { output, used: 0 };
        let mut stack: [Option<Level<'a>>; 64] = std::array::from_fn(|_| None);
        let mut depth = 0;
        let mut current = Some(self.subject.row);
        loop {
            if let Some(value) = current.take() {
                work.debit(1)?;
                match value.kind() {
                    ArenaKind::Null => writer.bytes(b"null", work)?,
                    ArenaKind::Boolean => writer.bytes(
                        if value.as_bool() == Some(true) {
                            b"true"
                        } else {
                            b"false"
                        },
                        work,
                    )?,
                    ArenaKind::Number => writer.bytes(
                        value
                            .number_text()
                            .ok_or(PolicyError::Unsupported)?
                            .as_bytes(),
                        work,
                    )?,
                    ArenaKind::Text => {
                        writer.string(value.as_str().ok_or(PolicyError::Unsupported)?, work)?
                    }
                    ArenaKind::Array | ArenaKind::Object => {
                        if depth == stack.len() {
                            return Err(PolicyError::Unsupported);
                        }
                        let object = value.kind() == ArenaKind::Object;
                        writer.bytes(if object { b"{" } else { b"[" }, work)?;
                        stack[depth] = Some(Level {
                            iter: value.children(),
                            object,
                            first: true,
                            redact: object && depth == 0,
                        });
                        depth += 1;
                    }
                }
            }
            while depth > 0 {
                let level = stack[depth - 1].as_mut().ok_or(PolicyError::Unsupported)?;
                if let Some(entry) = work.next(&mut level.iter)? {
                    if level.redact
                        && !rule::field_decision(
                            self.fields,
                            entry.key.ok_or(PolicyError::Unsupported)?,
                            self.subject,
                            work,
                        )?
                        .allowed
                    {
                        continue;
                    }
                    if !level.first {
                        writer.bytes(b",", work)?;
                    }
                    level.first = false;
                    if level.object {
                        writer.string(entry.key.ok_or(PolicyError::Unsupported)?, work)?;
                        writer.bytes(b":", work)?;
                    }
                    current = Some(entry.value);
                    break;
                }
                writer.bytes(if level.object { b"}" } else { b"]" }, work)?;
                stack[depth - 1] = None;
                depth -= 1;
            }
            if current.is_none() {
                return Ok(writer.used);
            }
        }
    }
}
struct Level<'a> {
    iter: ArenaIter<'a>,
    object: bool,
    first: bool,
    redact: bool,
}
struct Writer<'a> {
    output: &'a mut [u8],
    used: usize,
}
impl Writer<'_> {
    fn bytes(&mut self, bytes: &[u8], work: &mut Work<'_>) -> Result<(), PolicyError> {
        let end = self
            .used
            .checked_add(bytes.len())
            .filter(|end| *end <= self.output.len())
            .ok_or(PolicyError::Capacity)?;
        for chunk in bytes.chunks(1024) {
            work.debit(chunk.len())?;
            self.output[self.used..self.used + chunk.len()].copy_from_slice(chunk);
            self.used += chunk.len();
        }
        debug_assert_eq!(self.used, end);
        Ok(())
    }
    fn string(&mut self, text: &str, work: &mut Work<'_>) -> Result<(), PolicyError> {
        self.bytes(b"\"", work)?;
        // Runs copied in <=1024 byte chunks, scan checks through every byte.
        let mut start = 0;
        for (index, byte) in text.bytes().enumerate() {
            work.debit(1)?;
            let escape: Option<&[u8]> = match byte {
                b'"' => Some(b"\\\""),
                b'\\' => Some(b"\\\\"),
                8 => Some(b"\\b"),
                9 => Some(b"\\t"),
                10 => Some(b"\\n"),
                12 => Some(b"\\f"),
                13 => Some(b"\\r"),
                _ => None,
            };
            if let Some(escape) = escape {
                self.bytes(&text.as_bytes()[start..index], work)?;
                self.bytes(escape, work)?;
                start = index + 1;
            } else if byte < 32 {
                self.bytes(&text.as_bytes()[start..index], work)?;
                const HEX: &[u8; 16] = b"0123456789abcdef";
                self.bytes(
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
                start = index + 1;
            }
        }
        self.bytes(&text.as_bytes()[start..], work)?;
        self.bytes(b"\"", work)
    }
}
