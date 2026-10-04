//! Native projector boundary: inputs are filtered BEFORE arbitrary guest
//! aggregation; outputs reference only the actual filtered batch ordinal.
use super::*;

impl SqlHost<'_> {
    /// Bind an existing retained LOGICAL KeyId to the concrete captured native
    /// source pair [collection, logical_key] and actual catalog Source. The pair
    /// document is the canonical JSON suffix of native source_id(), captured by
    /// the controller; no guest/source-owner boolean or physical key is accepted.
    /// Controller must use this before forming a production OwnedRelation.
    /// This constructor checks correlation, not source-root/certificate origin.
    pub(crate) fn bind_owned_native_string_row(
        &mut self,
        source_declaration: JsonId,
        source_pair: JsonId,
        row: OwnedRow,
    ) -> Result<OwnedRow, HostError> {
        let cancellation = self.cancellation.clone();
        let frame = self.frame;
        let control = FrameControl::new(&cancellation, self.job.deadline());
        let mut work = Work {
            budget: &mut self.admission.budget,
            job: self.job,
        };
        let result = (|| {
            work.debit(1)?;
            if !matches!(self.phase, NativePhase::Authority | NativePhase::Provider)
                || self.completed.is_some()
            {
                return Err(HostError::Forbidden);
            }
            let source = CapturedStringSource::from_native_catalog(
                frame.json(source_declaration, &control)?,
                &mut work,
            )?;
            read::bind_native_captured_row(
                frame,
                source.name,
                source_pair,
                row,
                &control,
                &mut work,
            )
        })();
        work.keep(result)
    }
    /// Exact native catalog Source declaration captured in the SAME owned
    /// frame, never a caller's name/jsonKey/"allowed" flag. Current production
    /// subset is string keys; jsonKey=true refuses rather than guessing SDK
    /// canonical JSON/decode semantics. Field-redacted rows retain logical keys.
    pub(crate) fn prepare_provider_input_from_native_catalog(
        &mut self,
        source_declaration: JsonId,
    ) -> Result<&[u8], HostError> {
        let cancellation = self.cancellation.clone();
        let frame = self.frame;
        let control = FrameControl::new(&cancellation, self.job.deadline());
        let mut work = Work {
            budget: &mut self.admission.budget,
            job: self.job,
        };
        let result = (|| {
            work.debit(1)?;
            if self.phase != NativePhase::Provider
                || self.completed.is_some()
                || self.provider_rows.is_some()
            {
                return Err(HostError::Forbidden);
            }
            if let Some(capture) = self.native_capture {
                capture.source(source_declaration, &mut work)
            } else {
                let source = frame.json(source_declaration, &control)?;
                let bound = CapturedStringSource::from_native_catalog(source, &mut work)?;
                Ok::<_, HostError>(bound.name)
            }
        })();
        let name = work.keep(result)?;
        self.prepare_string_provider_input(name)
    }
    /// Test-only shorthand. Production must bind a captured native Source,
    /// including its declared jsonKey semantics, through the method above.
    #[cfg(test)]
    pub(crate) fn prepare_provider_input(
        &mut self,
        native_source: &str,
    ) -> Result<&[u8], HostError> {
        self.prepare_string_provider_input(native_source)
    }
    fn prepare_string_provider_input(&mut self, native_source: &str) -> Result<&[u8], HostError> {
        let HostAdmission {
            input,
            output,
            budget,
            ..
        } = &mut *self.admission;
        let mut work = Work {
            budget,
            job: self.job,
        };
        work.debit(0)?;
        if self.phase != NativePhase::Provider
            || self.completed.is_some()
            || self.provider_rows.is_some()
        {
            return Err(work.fail(HostError::Forbidden));
        }
        let control = FrameControl::new(&self.cancellation, work.job.deadline());
        let r = input.reset_checked(&mut || work.checker());
        work.keep(r)?;
        let r = output.reset_checked(&mut || work.checker());
        work.keep(r)?;
        let r = (|| {
            let reference = input.object()?;
            let kind = copy::text(input, "collection", &mut work)?;
            copy::insert(input, reference, "kind", kind, &mut work)?;
            let name = copy::text(input, native_source, &mut work)?;
            copy::insert(input, reference, "name", name, &mut work)?;
            let rows = read::read(
                "scan",
                &[Some(input.value(reference)?)],
                output,
                self.frame,
                self.relations,
                self.binding,
                self.phase,
                self.support,
                self.native_capture,
                self.policy_budget,
                &control,
                &mut work,
            )?;
            work.debit(1)?;
            let count = output.value(rows)?.len().ok_or(HostError::Invalid)?;
            let root = output.object()?;
            let source = output.object()?;
            let name = copy::text(output, native_source, &mut work)?;
            copy::insert(output, source, "name", name, &mut work)?;
            copy::insert(output, root, "source", source, &mut work)?;
            copy::insert(output, root, "rows", rows, &mut work)?;
            let purpose = copy::arena(
                self.frame.json(self.binding.authority_context, &control)?,
                output,
                &mut work,
            )?;
            copy::insert(output, root, "purpose", purpose, &mut work)?;
            Ok::<_, HostError>((root, count))
        })();
        let (root, count) = work.keep(r)?;
        let r = output.encode_checked(root, &mut || work.checker());
        let bytes = work.keep(r)?;
        self.provider_rows = Some(count);
        Ok(bytes)
    }
    /// Validate the ENTIRE completed projector result before typed insertion.
    /// Column count is from the native catalog; no guest schema/select flag.
    /// Returns a host-borrowed fixed arena array, not a growing row owner. The
    /// controller must copy approved tagged cells into its admitted typed frame.
    pub(crate) fn validated_provider_rows(
        &mut self,
        native_columns: usize,
    ) -> Result<WireValue<'_>, HostError> {
        let HostAdmission { output, budget, .. } = &mut *self.admission;
        let mut work = Work {
            budget,
            job: self.job,
        };
        work.debit(0)?;
        let r = (|| {
            if self.phase != NativePhase::Provider || native_columns == 0 || native_columns > 64 {
                return Err(HostError::Forbidden);
            }
            let count = self.provider_rows.ok_or(HostError::Forbidden)?;
            let WireOutcome::Success(id) = self.completed.ok_or(HostError::Invalid)? else {
                return Err(HostError::Invalid);
            };
            let root = output.value(id)?;
            if root.kind() != WireKind::Object {
                return Err(HostError::Invalid);
            }
            let mut rows = None;
            for entry in root.iter()? {
                work.debit(1)?;
                match entry.key {
                    Some("rows") if entry.value.kind() == WireKind::Array => {
                        rows = Some(entry.value)
                    }
                    Some("provenance") if entry.value.kind() == WireKind::Array => (),
                    _ => return Err(HostError::Invalid),
                }
            }
            let rows = rows.ok_or(HostError::Invalid)?;
            if rows.len().is_none_or(|n| n > MAX_CAPTURED_ROWS) {
                return Err(HostError::Capacity);
            }
            for entry in rows.iter()? {
                work.debit(1)?;
                let row = entry.value;
                if row.kind() != WireKind::Object || row.len() != Some(2) {
                    return Err(HostError::Invalid);
                }
                let ordinal = work
                    .member(row, "sourceRow")?
                    .and_then(WireValue::as_f64)
                    .ok_or(HostError::Invalid)?;
                if ordinal < 0.0 || ordinal.fract() != 0.0 || ordinal >= count as f64 {
                    return Err(HostError::Invalid);
                }
                let cells = work.member(row, "cells")?.ok_or(HostError::Invalid)?;
                if cells.kind() != WireKind::Array || cells.len() != Some(native_columns) {
                    return Err(HostError::Invalid);
                }
                for entry in cells.iter()? {
                    work.debit(1)?;
                    let cell = entry.value;
                    if cell.kind() == WireKind::Null {
                        continue;
                    }
                    if cell.kind() != WireKind::Object || cell.len() != Some(1) {
                        return Err(HostError::Invalid);
                    }
                    work.debit(1)?;
                    let tag = cell.iter()?.next().ok_or(HostError::Invalid)?;
                    match tag.key {
                        Some("integer") => {
                            let text = tag.value.as_str().ok_or(HostError::Invalid)?;
                            if text.len() > 20 {
                                return Err(HostError::Invalid);
                            }
                            work.bytes(text.len())?;
                            let number = text.parse::<i64>().map_err(|_| HostError::Invalid)?;
                            // Canonical decimal: no plus/leading zeros/negative zero.
                            let digits = text.strip_prefix('-').unwrap_or(text);
                            if digits.is_empty()
                                || (digits.len() > 1 && digits.starts_with('0'))
                                || text.starts_with('+')
                                || (number == 0 && text != "0")
                            {
                                return Err(HostError::Invalid);
                            }
                        }
                        Some("real")
                            if matches!(tag.value.kind(), WireKind::Integer | WireKind::Real) => {}
                        Some("text") if tag.value.kind() == WireKind::Text => (),
                        _ => return Err(HostError::Invalid),
                    }
                }
            }
            Ok::<_, HostError>(rows)
        })();
        work.keep(r)
    }
}

/// Private checked view of actual serde Source{name,json_key} capture. An
/// ArenaValue can only borrow the native owned frame, not guest WireValue IDs.
/// Capture origin/catalog membership remain the controller's native proof.
struct CapturedStringSource<'a> {
    name: &'a str,
}
impl<'a> CapturedStringSource<'a> {
    fn from_native_catalog(
        declaration: ArenaValue<'a>,
        work: &mut Work<'_>,
    ) -> Result<Self, HostError> {
        if declaration.kind() != super::super::sql_frame::ArenaKind::Object {
            return Err(HostError::Invalid);
        }
        let mut name = None;
        let mut json_key = false; // exact serde #[serde(default)] Source behavior
        for entry in declaration.children() {
            work.debit(1)?;
            let entry = entry?;
            match entry.key {
                Some("name") => name = Some(entry.value.as_str().ok_or(HostError::Invalid)?),
                Some("jsonKey") => json_key = entry.value.as_bool().ok_or(HostError::Invalid)?,
                _ => return Err(HostError::Invalid),
            }
        }
        let name = name.ok_or(HostError::Invalid)?;
        work.bytes(name.len())?;
        if !plain_collection(name) {
            return Err(HostError::Forbidden);
        }
        if json_key {
            return Err(HostError::Unsupported);
        }
        Ok(Self { name })
    }
}
