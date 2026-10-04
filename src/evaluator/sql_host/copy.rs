//! Iterative depth-bounded copies. WireValue read-only iteration is explicitly
//! charged here; source ArenaValue iteration also charges its own sticky budget.
use super::super::sql_bridge::WireIter;
use super::super::sql_frame::{ArenaIter, ArenaKind};
use super::*;

pub(super) fn text(
    output: &mut WireArena,
    value: &str,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    work.bytes(value.len())?;
    let r = output.text_checked(value, &mut || work.checker());
    work.keep(r)
}
pub(super) fn insert(
    output: &mut WireArena,
    parent: WireId,
    key: &str,
    child: WireId,
    work: &mut Work<'_>,
) -> Result<(), HostError> {
    work.bytes(key.len())?;
    let r = output.insert_checked(parent, key, child, &mut || work.checker());
    work.keep(r)
}
fn attach(
    output: &mut WireArena,
    parent: WireId,
    key: Option<&str>,
    child: WireId,
    work: &mut Work<'_>,
) -> Result<(), HostError> {
    work.debit(1)?;
    if let Some(key) = key {
        insert(output, parent, key, child, work)
    } else {
        Ok(output.push(parent, child)?)
    }
}
struct WireLevel<'a> {
    iter: WireIter<'a>,
    parent: WireId,
}
pub(super) fn wire(
    value: WireValue<'_>,
    output: &mut WireArena,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    let mut stack: [Option<WireLevel<'_>>; 64] = std::array::from_fn(|_| None);
    let mut depth = 0;
    let mut next = Some((value, None));
    let mut root = None;
    loop {
        if let Some((value, key)) = next.take() {
            work.debit(1)?;
            let id = match value.kind() {
                WireKind::Null => output.null()?,
                WireKind::Bool => output.boolean(value.as_bool().ok_or(HostError::Invalid)?)?,
                WireKind::Integer => output.integer(value.as_i32().ok_or(HostError::Invalid)?)?,
                WireKind::Real => output.real(value.as_f64().ok_or(HostError::Invalid)?)?,
                WireKind::Text => text(output, value.as_str().ok_or(HostError::Invalid)?, work)?,
                WireKind::Array => output.array()?,
                WireKind::Object => output.object()?,
            };
            if depth == 0 {
                root = Some(id);
            } else {
                attach(
                    output,
                    stack[depth - 1].as_ref().ok_or(HostError::Invalid)?.parent,
                    key,
                    id,
                    work,
                )?;
            }
            if matches!(value.kind(), WireKind::Array | WireKind::Object) {
                if depth == stack.len() {
                    return Err(HostError::Capacity);
                }
                stack[depth] = Some(WireLevel {
                    iter: value.iter()?,
                    parent: id,
                });
                depth += 1;
            }
        }
        while depth > 0 {
            work.debit(1)?;
            let level = stack[depth - 1].as_mut().ok_or(HostError::Invalid)?;
            if let Some(entry) = level.iter.next() {
                next = Some((entry.value, entry.key));
                break;
            }
            stack[depth - 1] = None;
            depth -= 1;
        }
        if next.is_none() {
            return root.ok_or(HostError::Invalid);
        }
    }
}
struct ArenaLevel<'a> {
    iter: ArenaIter<'a>,
    parent: WireId,
}
pub(super) fn arena(
    value: ArenaValue<'_>,
    output: &mut WireArena,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    let mut stack: [Option<ArenaLevel<'_>>; 64] = std::array::from_fn(|_| None);
    let mut depth = 0;
    let mut next = Some((value, None));
    let mut root = None;
    loop {
        if let Some((value, key)) = next.take() {
            work.debit(1)?;
            let id = match value.kind() {
                ArenaKind::Null => output.null()?,
                ArenaKind::Boolean => output.boolean(value.as_bool().ok_or(HostError::Invalid)?)?,
                ArenaKind::Number => output.real(value.as_f64()?.ok_or(HostError::Invalid)?)?,
                ArenaKind::Text => text(output, value.as_str().ok_or(HostError::Invalid)?, work)?,
                ArenaKind::Array => output.array()?,
                ArenaKind::Object => output.object()?,
            };
            if depth == 0 {
                root = Some(id);
            } else {
                attach(
                    output,
                    stack[depth - 1].as_ref().ok_or(HostError::Invalid)?.parent,
                    key,
                    id,
                    work,
                )?;
            }
            if matches!(value.kind(), ArenaKind::Array | ArenaKind::Object) {
                if depth == stack.len() {
                    return Err(HostError::Capacity);
                }
                stack[depth] = Some(ArenaLevel {
                    iter: value.children(),
                    parent: id,
                });
                depth += 1;
            }
        }
        while depth > 0 {
            work.debit(1)?;
            let level = stack[depth - 1].as_mut().ok_or(HostError::Invalid)?;
            if let Some(entry) = level.iter.next() {
                let entry = entry?;
                next = Some((entry.value, entry.key));
                break;
            }
            stack[depth - 1] = None;
            depth -= 1;
        }
        if next.is_none() {
            return root.ok_or(HostError::Invalid);
        }
    }
}
pub(super) fn failure(
    code: &str,
    message: &str,
    details: Option<WireId>,
    output: &mut WireArena,
    work: &mut Work<'_>,
) -> Result<WireOutcome, HostError> {
    let root = output.object()?;
    let code = text(output, code, work)?;
    let message = text(output, message, work)?;
    insert(output, root, "code", code, work)?;
    insert(output, root, "message", message, work)?;
    if let Some(details) = details {
        insert(output, root, "details", details, work)?;
    }
    Ok(WireOutcome::Failure {
        code,
        message,
        details,
    })
}
pub(super) fn binding(
    binding: NativeBinding<'_>,
    valid_until: Option<u64>,
    frame: &FrameBuilder,
    control: &FrameControl<'_>,
    output: &mut WireArena,
    work: &mut Work<'_>,
) -> Result<WireId, HostError> {
    let root = output.object()?;
    for (name, id) in [
        ("invoker", binding.invoker),
        ("principal", binding.principal),
        ("history", binding.history),
        ("authorityContext", binding.authority_context),
        ("partition", binding.partition),
    ] {
        let v = arena(frame.json(id, control)?, output, work)?;
        insert(output, root, name, v, work)?;
    }
    for (name, n) in [
        ("clock", binding.clock),
        ("sourceRevision", binding.source_revision),
    ] {
        work.debit(1)?;
        let v = output.real(n as f64)?;
        insert(output, root, name, v, work)?;
    }
    let expiry = if let Some(at) = valid_until {
        output.real(at as f64)?
    } else {
        output.null()?
    };
    insert(output, root, "validUntil", expiry, work)?;
    for (name, s) in [
        ("codeVersion", binding.code_version),
        ("catalogVersion", binding.catalog_version),
    ] {
        let v = text(output, s, work)?;
        insert(output, root, name, v, work)?;
    }
    Ok(root)
}
