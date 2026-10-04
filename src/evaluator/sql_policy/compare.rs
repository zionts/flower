//! Exact ordinary-native comparisons, using a bounded scalar Number parser,
//! never serde Value/tree decoding or SQLite/source integer coercion.
use super::rule::{Op, Resolved};
use super::*;
use std::cmp::Ordering;

// Arbitrary-precision Number is an owned String, not the admitted scalar ABI.
// Fail the build rather than silently accepting that allocating dependency mode.
const _: () =
    assert!(std::mem::size_of::<usize>() == 8 && std::mem::size_of::<serde_json::Number>() <= 16);

pub(super) fn number(
    value: Resolved<'_>,
    work: &mut Work<'_>,
) -> Result<Option<serde_json::Number>, PolicyError> {
    match value {
        Resolved::Now(now) => Ok(Some(now.into())),
        Resolved::Json(value) if value.kind() == ArenaKind::Number => {
            let raw = value.number_text().ok_or(PolicyError::Unsupported)?;
            if raw.len() > 1024 {
                return Err(PolicyError::Unsupported);
            }
            work.debit(raw.len())?;
            // Keep a wide finite margin from serde's overflow/error constructor,
            // which itself owns a boxed error. Scanner syntax is already valid;
            // exponents within nine digits cannot overflow the native i32 parser.
            // Never invoke scalar serde on an unproved numeric/error domain.
            let cached = work
                .frame(value.as_f64())?
                .ok_or(PolicyError::Unsupported)?;
            if cached.abs() > 1e300 {
                return Err(PolicyError::Unsupported);
            }
            if let Some((_, exponent)) = raw.split_once(['e', 'E']) {
                let digits = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
                if digits.len() > 9 {
                    return Err(PolicyError::Unsupported);
                }
            }
            work.debit(raw.len())?;
            // Same PINNED default (no float_roundtrip) parser/features as native
            // access. The isolated allocator/feature gate MUST be rerun after a
            // dependency change; float_roundtrip's long-number scratch is HOLD.
            // Default Number is a finite scalar, never an owned Value/tree.
            let parsed = serde_json::from_str::<serde_json::Number>(raw)
                .map_err(|_| PolicyError::Unsupported)?;
            work.debit(0)?;
            if parsed.as_f64().is_none_or(|number| !number.is_finite()) {
                return Err(PolicyError::Unsupported);
            }
            Ok(Some(parsed))
        }
        _ => Ok(None),
    }
}
fn count_children(value: ArenaValue<'_>, work: &mut Work<'_>) -> Result<usize, PolicyError> {
    let mut count = 0;
    let mut iter = value.children();
    while work.next(&mut iter)?.is_some() {
        count += 1;
    }
    Ok(count)
}
struct DeepLevel<'a> {
    left: ArenaIter<'a>,
    right: ArenaIter<'a>,
    object: Option<ArenaValue<'a>>,
}
impl<'a> DeepLevel<'a> {
    fn next(
        &mut self,
        work: &mut Work<'_>,
    ) -> Result<Option<(ArenaValue<'a>, ArenaValue<'a>)>, PolicyError> {
        let Some(left) = work.next(&mut self.left)? else {
            return Ok(None);
        };
        let right = if let Some(object) = self.object {
            work.get(object, left.key.ok_or(PolicyError::Unsupported)?)?
        } else {
            work.next(&mut self.right)?.map(|entry| entry.value)
        };
        Ok(right.map(|right| (left.value, right)))
    }
}
/// Object order is immaterial, array order is material. Nested null==null is
/// true; top-level null/missing is excluded by same(), exactly as access.rs.
fn deep_same<'a>(
    left: ArenaValue<'a>,
    right: ArenaValue<'a>,
    work: &mut Work<'_>,
) -> Result<bool, PolicyError> {
    let mut stack: [Option<DeepLevel<'a>>; 64] = std::array::from_fn(|_| None);
    let mut depth = 0;
    let mut pair = (left, right);
    loop {
        work.debit(1)?;
        let (left, right) = pair;
        if left.kind() != right.kind() {
            return Ok(false);
        }
        let same = match left.kind() {
            ArenaKind::Null => true,
            ArenaKind::Boolean => left.as_bool() == right.as_bool(),
            ArenaKind::Text => work.text_same(
                left.as_str().ok_or(PolicyError::Unsupported)?,
                right.as_str().ok_or(PolicyError::Unsupported)?,
            )?,
            ArenaKind::Number => {
                number(Resolved::Json(left), work)?.and_then(|value| value.as_f64())
                    == number(Resolved::Json(right), work)?.and_then(|value| value.as_f64())
            }
            ArenaKind::Array | ArenaKind::Object => {
                let count = count_children(left, work)?;
                if count != count_children(right, work)? {
                    return Ok(false);
                }
                if count > 0 {
                    if depth == stack.len() {
                        return Err(PolicyError::Unsupported);
                    }
                    let mut level = DeepLevel {
                        left: left.children(),
                        right: right.children(),
                        object: (left.kind() == ArenaKind::Object).then_some(right),
                    };
                    let Some(next) = level.next(work)? else {
                        return Ok(false);
                    };
                    stack[depth] = Some(level);
                    depth += 1;
                    pair = next;
                    continue;
                }
                true
            }
        };
        if !same {
            return Ok(false);
        }
        loop {
            if depth == 0 {
                return Ok(true);
            }
            let level = stack[depth - 1].as_mut().ok_or(PolicyError::Unsupported)?;
            // A missing object key must be false, not premature exhaustion.
            let next_left = work.next(&mut level.left)?;
            if let Some(left) = next_left {
                let right = if let Some(object) = level.object {
                    work.get(object, left.key.ok_or(PolicyError::Unsupported)?)?
                } else {
                    work.next(&mut level.right)?.map(|entry| entry.value)
                };
                let Some(right) = right else {
                    return Ok(false);
                };
                pair = (left.value, right);
                break;
            }
            stack[depth - 1] = None;
            depth -= 1;
        }
    }
}
fn same<'a>(
    left: Resolved<'a>,
    right: Resolved<'a>,
    work: &mut Work<'_>,
) -> Result<Option<bool>, PolicyError> {
    if !left.present() || !right.present() {
        return Ok(None);
    }
    let same = if let (Some(left), Some(right)) = (left.text(), right.text()) {
        work.text_same(left, right)?
    } else if let (Some(left), Some(right)) = (number(left, work)?, number(right, work)?) {
        left.as_f64() == right.as_f64()
    } else {
        match (left, right) {
            (Resolved::Json(left), Resolved::Json(right)) => deep_same(left, right, work)?,
            _ => false,
        }
    };
    Ok(Some(same))
}
fn order(
    left: Resolved<'_>,
    right: Resolved<'_>,
    work: &mut Work<'_>,
) -> Result<Option<Ordering>, PolicyError> {
    if let (Some(left), Some(right)) = (left.text(), right.text()) {
        return work.text_order(left, right).map(Some);
    }
    let (Some(left), Some(right)) = (number(left, work)?, number(right, work)?) else {
        return Ok(None);
    };
    Ok(
        if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
            Some(left.cmp(&right))
        } else if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
            Some(left.cmp(&right))
        } else {
            left.as_f64()
                .and_then(|left| right.as_f64().and_then(|right| left.partial_cmp(&right)))
        },
    )
}
fn holds<'a>(
    op: Op,
    left: Resolved<'a>,
    right: Resolved<'a>,
    work: &mut Work<'_>,
) -> Result<bool, PolicyError> {
    Ok(match op {
        Op::Eq => same(left, right, work)? == Some(true),
        Op::Ne => same(left, right, work)? == Some(false),
        Op::In => {
            if let Resolved::Json(list) = right {
                if list.kind() == ArenaKind::Array && left.present() {
                    let mut iter = list.children();
                    let mut found = false;
                    while let Some(entry) = work.next(&mut iter)? {
                        if same(left, Resolved::Json(entry.value), work)? == Some(true) {
                            found = true;
                            break;
                        }
                    }
                    found
                } else {
                    false
                }
            } else {
                false
            }
        }
        Op::Lt => order(left, right, work)? == Some(Ordering::Less),
        Op::Lte => matches!(
            order(left, right, work)?,
            Some(Ordering::Less | Ordering::Equal)
        ),
        Op::Gt => order(left, right, work)? == Some(Ordering::Greater),
        Op::Gte => matches!(
            order(left, right, work)?,
            Some(Ordering::Greater | Ordering::Equal)
        ),
        Op::StartsWith => match (left.text(), right.text()) {
            (Some(text), Some(prefix)) if prefix.len() <= text.len() => {
                // Bytes, not a potentially non-boundary UTF8 str slice.
                let mut same = true;
                for (offset, chunk) in prefix.as_bytes().chunks(1024).enumerate() {
                    work.debit(chunk.len())?;
                    let start = offset * 1024;
                    if &text.as_bytes()[start..start + chunk.len()] != chunk {
                        same = false;
                        break;
                    }
                }
                same
            }
            _ => false,
        },
    })
}
fn temporal(
    op: Op,
    now: u64,
    other: Resolved<'_>,
    work: &mut Work<'_>,
) -> Result<Validity, PolicyError> {
    const MAX: f64 = 9_007_199_254_740_990.0;
    if now > MAX as u64 || matches!(op, Op::In | Op::StartsWith) {
        return Err(PolicyError::UncertifiedTemporal);
    }
    let Some(other) = number(other, work)? else {
        // A fixed captured non-number is never numerically equal/ordered with
        // now. Missing/null's eq AND ne are false; fixed present types' ne true.
        return Ok(Validity::ClockInvariant);
    };
    let value = other.as_f64().ok_or(PolicyError::UncertifiedTemporal)?;
    if !(-MAX..=MAX).contains(&value) {
        return Err(PolicyError::UncertifiedTemporal);
    }
    let boundary = match op {
        Op::Lt | Op::Gte => value.ceil(),
        Op::Lte | Op::Gt => value.floor() + 1.0,
        Op::Eq | Op::Ne => {
            if value.fract() != 0.0 {
                return Ok(Validity::ClockInvariant);
            }
            if value > now as f64 {
                value
            } else if value == now as f64 {
                value + 1.0
            } else {
                return Ok(Validity::ClockInvariant);
            }
        }
        _ => return Err(PolicyError::UncertifiedTemporal),
    };
    if boundary > now as f64 {
        Ok(Validity::Until(boundary as u64))
    } else {
        Ok(Validity::ClockInvariant)
    }
}
pub(super) fn decide<'a>(
    op: Op,
    left: Resolved<'a>,
    right: Resolved<'a>,
    work: &mut Work<'_>,
) -> Result<Decision, PolicyError> {
    let validity = match (left, right) {
        (Resolved::Now(_), Resolved::Now(_)) => Validity::ClockInvariant,
        (Resolved::Now(now), other) => temporal(op, now, other, work)?,
        (other, Resolved::Now(now)) => temporal(op.swapped(), now, other, work)?,
        _ => Validity::Independent,
    };
    Ok(Decision {
        allowed: holds(op, left, right, work)?,
        validity,
    })
}
