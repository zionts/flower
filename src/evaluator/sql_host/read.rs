//! Complete, bounded owned-only reads; no provider/source/I/O callbacks.
use super::super::sql_frame::ArenaKind;
use super::super::sql_policy::RedactedRow;
use super::*;

enum Lookup<'a> {
    Uncaptured,
    AuthoritativeAbsent,
    Row(&'a OwnedRow),
}
#[allow(clippy::too_many_arguments)]
pub(super) fn read(
    operation: &str,
    args: &[Option<WireValue<'_>>],
    output: &mut WireArena,
    frame: &FrameBuilder,
    relations: &[OwnedRelation<'_>],
    binding: NativeBinding<'_>,
    phase: NativePhase,
    support: Option<CapturedSupport<'_>>,
    native_capture: Option<NativeCapture<'_>>,
    budget: &PolicyBudget,
    control: &FrameControl<'_>,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    if (operation == "get" && args.len() != 2) || (operation == "scan" && args.len() != 1) {
        return Err(HostError::Unsupported);
    }
    let reference = args.first().copied().flatten().ok_or(HostError::Invalid)?;
    let name = collection(reference, work)?;
    if !plain_collection(name.as_str().ok_or(HostError::Invalid)?) {
        return Err(HostError::Forbidden);
    }
    let name_text = name.as_str().ok_or(HostError::Invalid)?;
    // Validate the supported key type BEFORE deciding a capture demand.
    if operation == "get" {
        logical_key(
            args[1]
                .and_then(WireValue::as_str)
                .ok_or(HostError::Unsupported)?,
            work,
        )?;
    }
    let mut found = None;
    for relation in relations {
        work.debit(1)?;
        if work.same(relation.name, name_text)? {
            if found.is_some() {
                return Err(HostError::Invalid);
            }
            found = Some(relation);
        }
    }
    let relation = found.ok_or_else(|| {
        work.need(
            if operation == "get" {
                DemandKind::Get
            } else {
                DemandKind::CompleteScan
            },
            Some(name.id()),
            args.get(1).copied().flatten().map(WireValue::id),
        )
    })?;
    let result = work.budget.temporal.active_point(work.job);
    let point = work.keep(result)?;
    let engine = if phase.authentication() || phase == NativePhase::Authority {
        None
    } else {
        let principal = frame.json(
            if phase == NativePhase::Authority {
                binding.invoker
            } else {
                binding.principal
            },
            control,
        )?;
        let verified = VerifiedPrincipal::from_native_auth(principal, budget, work.job)?;
        Some(PolicyEngine::new(
            support.ok_or(HostError::Forbidden)?,
            verified,
            binding.clock,
        ))
    };
    if operation == "get" {
        let key = args[1].ok_or(HostError::Invalid)?;
        let key_text = key.as_str().ok_or(HostError::Unsupported)?;
        work.bytes(key_text.len())?;
        let mut found = None;
        for row in relation.rows {
            work.debit(1)?;
            let logical = logical_key(frame.key(row.key)?, work)?;
            if work.same(logical, key_text)? {
                if found.is_some() {
                    return Err(HostError::Invalid);
                }
                found = Some(row);
            }
        }
        let lookup = match found {
            Some(row) if row.value.is_some() => Lookup::Row(row),
            Some(_) => Lookup::AuthoritativeAbsent,
            None if relation.coverage == CaptureCoverage::Complete => Lookup::AuthoritativeAbsent,
            _ => Lookup::Uncaptured,
        };
        match lookup {
            Lookup::Uncaptured => Err(work.need(DemandKind::Get, Some(name.id()), Some(key.id()))),
            Lookup::AuthoritativeAbsent => {
                work.debit(1)?;
                Ok(output.null()?)
            }
            Lookup::Row(row) => {
                let raw = frame.json(row.value.ok_or(HostError::Invalid)?, control)?;
                if let Some(engine) = engine {
                    let auth = if let Some(capture) = native_capture {
                        engine.authorize_native(
                            capture.row(name_text, *row, control, work)?,
                            &[],
                            budget,
                            work.job,
                        )
                    } else {
                        engine.authorize(name_text, frame.key(row.key)?, raw, &[], budget, work.job)
                    }
                    .map_err(|e| policy_failure(e, work))?;
                    register_policy(point, binding.clock, budget, work)?;
                    if let Some(row) = auth.candidate {
                        redacted(raw, &row, output, budget, point, binding.clock, work)
                    } else {
                        Ok(output.null()?)
                    }
                } else {
                    copy::arena(raw, output, work)
                }
            }
        }
    } else {
        if relation.coverage != CaptureCoverage::Complete {
            return Err(work.need(DemandKind::CompleteScan, Some(name.id()), None));
        }
        // Native canonical ordering proves duplicate freedom in one metered
        // pass; quadratic comparison is not needed for a complete relation.
        let mut previous = None;
        for row in relation.rows {
            work.debit(1)?;
            let key = logical_key(frame.key(row.key)?, work)?;
            if let Some(prior) = previous
                && !less(prior, key, work)?
            {
                return Err(HostError::Unsupported);
            }
            previous = Some(key);
        }
        let root = output.array()?;
        // The complete ordering pass above was performed before output.
        for row in relation.rows {
            work.debit(1)?;
            let key = logical_key(frame.key(row.key)?, work)?;
            let Some(id) = row.value else {
                continue;
            };
            let raw = frame.json(id, control)?;
            let value = if let Some(engine) = engine {
                let auth = if let Some(capture) = native_capture {
                    engine.authorize_native(
                        capture.row(name_text, *row, control, work)?,
                        &[],
                        budget,
                        work.job,
                    )
                } else {
                    engine.authorize(name_text, key, raw, &[], budget, work.job)
                }
                .map_err(|e| policy_failure(e, work))?;
                register_policy(point, binding.clock, budget, work)?;
                let Some(row) = auth.candidate else {
                    continue;
                };
                // Native Access::filter and RangeQuery preserve the authorized
                // LOGICAL key and redact only the value. Field redaction does
                // not revoke row-key disclosure; hidden selecting/index fields
                // instead suppress the whole candidate in authorize(). The
                // complete scan uses no selecting fields and never a physical ID.
                redacted(raw, &row, output, budget, point, binding.clock, work)?
            } else {
                copy::arena(raw, output, work)?
            };
            let item = output.object()?;
            let key = copy::text(output, key, work)?;
            copy::insert(output, item, "key", key, work)?;
            copy::insert(output, item, "value", value, work)?;
            output.push(root, item)?;
        }
        Ok(root)
    }
}
/// Every KeyId in an OwnedRelation is an encoded LOGICAL collection key,
/// not native source_id(collection,key). Prefix-looking logical strings are an
/// explicitly unsupported subset, even though ordinary Flower allows them:
/// a misplaced native physical identity must never leave this detached host.
/// Internal collection names are rejected separately by collection().
fn logical_key<'a>(key: &'a str, work: &mut Work<'_>) -> Result<&'a str, HostError> {
    work.debit(1)?;
    if ["source:", "collection:", "cell:", "root:", "index:"]
        .iter()
        .any(|prefix| key.starts_with(prefix))
        || key.starts_with("$flower.")
    {
        return Err(HostError::Forbidden);
    }
    Ok(key)
}
/// Constructor's validated key ID stays private until exact source/key
/// correlation succeeds. It can never contain a native physical prefix.
struct NativeLogicalKey {
    id: KeyId,
}
pub(super) fn bind_native_captured_row(
    frame: &FrameBuilder,
    source: &str,
    source_pair: JsonId,
    row: OwnedRow,
    control: &FrameControl<'_>,
    work: &mut Work<'_>,
) -> Result<OwnedRow, HostError> {
    work.debit(1)?;
    let pair = frame.json(source_pair, control)?;
    if pair.kind() != ArenaKind::Array {
        return Err(HostError::Invalid);
    }
    let mut iter = pair.children();
    let name = iter
        .next()
        .transpose()?
        .and_then(|entry| entry.value.as_str())
        .ok_or(HostError::Invalid)?;
    let key = iter
        .next()
        .transpose()?
        .and_then(|entry| entry.value.as_str())
        .ok_or(HostError::Invalid)?;
    let logical = logical_key(frame.key(row.key)?, work)?;
    if iter.next().transpose()?.is_some()
        || !work.same(name, source)?
        || !work.same(key, logical)?
    {
        return Err(HostError::Invalid);
    }
    // Exactly native serde's source_pair/source_id round trip. Frame JSON
    // syntax validation alone would also accept a noncanonical physical ID.
    let raw = frame.raw_json(source_pair)?.as_bytes();
    let mut position = 0;
    canonical_bytes(raw, &mut position, b"[", work)?;
    canonical_string(raw, &mut position, name, work)?;
    canonical_bytes(raw, &mut position, b",", work)?;
    canonical_string(raw, &mut position, key, work)?;
    canonical_bytes(raw, &mut position, b"]", work)?;
    if position != raw.len() {
        return Err(HostError::Invalid);
    }
    if let Some(value) = row.value {
        frame.json(value, control)?;
    }
    let verified = NativeLogicalKey { id: row.key };
    Ok(OwnedRow {
        key: verified.id,
        value: row.value,
    })
}
fn canonical_bytes(
    raw: &[u8],
    position: &mut usize,
    expected: &[u8],
    work: &mut Work<'_>,
) -> Result<(), HostError> {
    work.debit(expected.len())?;
    let end = position
        .checked_add(expected.len())
        .ok_or(HostError::Invalid)?;
    if raw.get(*position..end) != Some(expected) {
        return Err(HostError::Invalid);
    }
    *position = end;
    Ok(())
}
fn canonical_string(
    raw: &[u8],
    position: &mut usize,
    value: &str,
    work: &mut Work<'_>,
) -> Result<(), HostError> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    canonical_bytes(raw, position, b"\"", work)?;
    for byte in value.bytes() {
        let escaped = match byte {
            b'"' => Some(b"\\\"".as_slice()),
            b'\\' => Some(b"\\\\".as_slice()),
            8 => Some(b"\\b".as_slice()),
            9 => Some(b"\\t".as_slice()),
            10 => Some(b"\\n".as_slice()),
            12 => Some(b"\\f".as_slice()),
            13 => Some(b"\\r".as_slice()),
            _ => None,
        };
        if let Some(escaped) = escaped {
            canonical_bytes(raw, position, escaped, work)?;
        } else if byte < 32 {
            let escaped = [
                b'\\',
                b'u',
                b'0',
                b'0',
                HEX[usize::from(byte >> 4)],
                HEX[usize::from(byte & 15)],
            ];
            canonical_bytes(raw, position, &escaped, work)?;
        } else {
            canonical_bytes(raw, position, &[byte], work)?;
        }
    }
    canonical_bytes(raw, position, b"\"", work)
}
pub(super) fn policy_failure(error: PolicyError, work: &mut Work<'_>) -> HostError {
    if error == PolicyError::NeedCapture {
        work.need(DemandKind::PolicySupport, None, None)
    } else {
        work.fail(error.into())
    }
}
fn collection<'a>(
    reference: WireValue<'a>,
    work: &mut Work<'_>,
) -> Result<WireValue<'a>, HostError> {
    if reference.kind() != WireKind::Object || reference.len() != Some(2) {
        return Err(HostError::Forbidden);
    }
    let kind = work
        .member(reference, "kind")?
        .and_then(WireValue::as_str)
        .ok_or(HostError::Forbidden)?;
    if !work.same(kind, "collection")? {
        return Err(HostError::Forbidden);
    }
    let name = work
        .member(reference, "name")?
        .ok_or(HostError::Forbidden)?;
    name.as_str().ok_or(HostError::Forbidden)?;
    Ok(name)
}
fn less(left: &str, right: &str, work: &mut Work<'_>) -> Result<bool, HostError> {
    // SDK/native key ordering is JS UTF-16 order, not UTF-8 byte order.
    let mut left = left.encode_utf16();
    let mut right = right.encode_utf16();
    loop {
        work.debit(1)?;
        match (left.next(), right.next()) {
            (Some(a), Some(b)) if a == b => (),
            (Some(a), Some(b)) => return Ok(a < b),
            (None, Some(_)) => return Ok(true),
            _ => return Ok(false),
        }
    }
}
fn redacted(
    raw: ArenaValue<'_>,
    row: &RedactedRow<'_>,
    output: &mut WireArena,
    budget: &PolicyBudget,
    point: NativeTimePoint,
    native_clock: u64,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    if raw.kind() != ArenaKind::Object {
        return copy::arena(raw, output, work);
    }
    let root = output.object()?;
    for entry in raw.children() {
        work.debit(1)?;
        let entry = entry?;
        let key = entry.key.ok_or(HostError::Invalid)?;
        let value = row
            .field(key, budget, work.job)
            .map_err(|e| policy_failure(e, work))?;
        register_policy(point, native_clock, budget, work)?;
        if let Some(value) = value {
            let child = copy::arena(value, output, work)?;
            copy::insert(output, root, key, child, work)?;
        }
    }
    Ok(root)
}

/// Actual cumulative collection/hidden/field/support policy validity only.
/// This witness deliberately DOES NOT certify arbitrary callback clock reads.
fn register_policy(
    point: NativeTimePoint,
    native_clock: u64,
    budget: &PolicyBudget,
    work: &mut Work<'_>,
) -> Result<(), HostError> {
    let result = budget.finish(work.job, native_clock);
    let validity = work.keep(result)?;
    // SAFETY: unmodified actual PolicyBudget::finish at the exact native point.
    let result = unsafe { NativeBoundary::from_native_policy(point, validity) };
    let boundary = work.keep(result)?;
    let result = work
        .budget
        .temporal
        .register_native_boundary(boundary, work.job);
    work.keep(result)
}
