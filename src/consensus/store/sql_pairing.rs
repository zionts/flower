//! Borrowed accepted-entry producer pairing, BEFORE ordinary delta compaction.
//!
//! This verifies the canonical subset emitted by the ACTUAL HttpMethod and
//! sql_registry::build serializers, plus TerminalMethod::validate's metadata
//! constraints. It does NOT authenticate keys, catalog, callback or finalizer
//! provenance. Ordinary HTTP descriptors are inspected only for object shape
//! and terminal membership, not re-decoded or cloned.
//!
//! No Rust heap allocation, source/backing read, native decoder, serde error,
//! recursive JSON walk or newly invented allowance belongs to this component.
//! The caller MUST lend the SAME original cumulative work ledger. Its actual
//! accepted-entry/tombstone/failure-hook/native admission integration is HOLD.
use serde_json::{Map, Number, Value};
use std::collections::BTreeMap;
use std::fmt::{self, Write as _};

const MAX_BYTES: usize = 32 * 1024;
const MAX_ALIASES: usize = 32;
const MAX_NAME_BYTES: usize = 256;
const MAX_DEPTH: usize = 128;
const RECORD: &str = crate::evaluator::sql_registry::RECORD;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Pairing {
    Keep,
    Paired,
    Invalidate,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WorkFault {
    Work,
}
// Preserve the draft API spelling; neither spelling is a replicated rejection.
pub(super) type PairingFault = WorkFault;

/// Only the existing accepted entry is observed. Header-only is unknown; ANY
/// code-key put/delete needs a valid SAME-entry HTTP + terminal registry put.
/// A bundle deletion without a replacing put cannot establish installed code.
/// Work exhaustion is a source failure, never Invalidate or Rejected.
pub(super) fn effect(
    puts: &BTreeMap<String, Value>,
    deletes: &[String],
    remaining: &mut usize,
) -> Result<Pairing, PairingFault> {
    let mut touched = false;
    let mut bundle_put = false;
    let mut bundle_delete = false;
    let mut registry = None;
    let mut http = None;
    debit(remaining, 1)?;
    let mut entries = puts.iter();
    loop {
        debit(remaining, 1)?;
        let Some((key, value)) = entries.next() else {
            break;
        };
        match code_key(key, remaining)? {
            0 => {}
            1 => {
                touched = true;
                bundle_put = true;
            }
            2 => touched = true,
            3 => {
                touched = true;
                http = Some(value);
            }
            4 => {
                touched = true;
                registry = Some(value);
            }
            _ => unreachable!(),
        }
    }
    debit(remaining, 1)?;
    let mut entries = deletes.iter();
    loop {
        debit(remaining, 1)?;
        let Some(key) = entries.next() else { break };
        let code = code_key(key, remaining)?;
        touched |= code != 0;
        bundle_delete |= code == 1;
    }
    if !touched {
        return Ok(Pairing::Keep);
    }
    let (Some(registry), Some(http)) = (registry, http) else {
        return Ok(Pairing::Invalidate);
    };
    if bundle_delete && !bundle_put {
        return Ok(Pairing::Invalidate);
    }
    Ok(if valid_producer(registry, http, remaining)? {
        Pairing::Paired
    } else {
        Pairing::Invalidate
    })
}

fn debit(remaining: &mut usize, amount: usize) -> Result<(), WorkFault> {
    *remaining = remaining.checked_sub(amount).ok_or(WorkFault::Work)?;
    Ok(())
}

/// O(1) length mismatch first; charge every potentially compared byte BEFORE
/// String equality. No hidden BTreeMap::get/contains_key comparisons occur.
fn text_eq(a: &str, b: &str, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    if a.len() != b.len() {
        return Ok(false);
    }
    debit(remaining, a.len())?;
    Ok(a == b)
}
fn code_key(key: &str, remaining: &mut usize) -> Result<u8, WorkFault> {
    // Prepay the complete fixed four-key scan before iterator construction.
    debit(remaining, 5)?;
    for (index, candidate) in ["bundle", "schema", "httpMethods", RECORD]
        .iter()
        .enumerate()
    {
        debit(remaining, 1)?;
        if text_eq(key, candidate, remaining)? {
            return Ok(index as u8 + 1);
        }
    }
    Ok(0)
}
fn field<'a>(
    object: &'a Map<String, Value>,
    name: &str,
    remaining: &mut usize,
) -> Result<Option<&'a Value>, WorkFault> {
    debit(remaining, 1)?;
    let mut fields = object.iter();
    loop {
        debit(remaining, 1)?;
        let Some((key, value)) = fields.next() else {
            return Ok(None);
        };
        if text_eq(key, name, remaining)? {
            return Ok(Some(value));
        }
    }
}
fn string_is(value: &Value, expected: &str, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    match value.as_str() {
        Some(text) => text_eq(text, expected, remaining),
        None => Ok(false),
    }
}

// Fixed, nonrecursive borrowed walk. Every iterator advance, unwind, node and
// key is charged before access. Root depth is zero; even an empty container at
// depth 128 is legal. Its nonempty child at depth 129 is refused before push.
// Stack initialization is fixed work, charged by each consumer before new().
enum Frame<'a> {
    Array(std::slice::Iter<'a, Value>),
    Object(serde_json::map::Iter<'a>),
}
enum Token<'a> {
    Null,
    Bool(bool),
    Number(&'a Number),
    String(&'a str),
    Key(&'a str),
    Array(usize),
    Object(usize),
    TooDeep,
}
struct Walk<'a> {
    pending: Option<&'a Value>,
    frames: [Option<Frame<'a>>; MAX_DEPTH + 1],
    len: usize,
}
impl<'a> Walk<'a> {
    fn new(root: &'a Value) -> Self {
        Self {
            pending: Some(root),
            frames: [const { None }; MAX_DEPTH + 1],
            len: 0,
        }
    }
    fn next(&mut self, remaining: &mut usize) -> Result<Option<Token<'a>>, WorkFault> {
        loop {
            debit(remaining, 1)?;
            if let Some(value) = self.pending.take() {
                if self.len > MAX_DEPTH {
                    return Ok(Some(Token::TooDeep));
                }
                return Ok(Some(match value {
                    Value::Null => Token::Null,
                    Value::Bool(value) => Token::Bool(*value),
                    Value::Number(value) => Token::Number(value),
                    Value::String(value) => Token::String(value),
                    Value::Array(values) => {
                        self.frames[self.len] = Some(Frame::Array(values.iter()));
                        self.len += 1;
                        Token::Array(values.len())
                    }
                    Value::Object(values) => {
                        self.frames[self.len] = Some(Frame::Object(values.iter()));
                        self.len += 1;
                        Token::Object(values.len())
                    }
                }));
            }
            if self.len == 0 {
                return Ok(None);
            }
            debit(remaining, 1)?;
            match self.frames[self.len - 1].as_mut().unwrap() {
                Frame::Array(values) => {
                    if let Some(value) = values.next() {
                        self.pending = Some(value);
                        continue;
                    }
                }
                Frame::Object(values) => {
                    if let Some((key, value)) = values.next() {
                        self.pending = Some(value);
                        return Ok(Some(Token::Key(key)));
                    }
                }
            }
            self.len -= 1;
            self.frames[self.len] = None;
        }
    }
}

/// Actual pinned serde_json::Number Display and default JSON serializer both
/// use itoa / zmij. No arbitrary_precision is enabled in the actual profiles.
/// The fixed 32-byte fmt writer cannot allocate or produce a serde error box.
struct NumberBuffer {
    bytes: [u8; 32],
    len: usize,
}
impl fmt::Write for NumberBuffer {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.len.checked_add(text.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.len = end;
        Ok(())
    }
}
fn number_bytes(number: &Number, remaining: &mut usize) -> Result<Option<NumberBuffer>, WorkFault> {
    debit(remaining, 33)?;
    let mut buffer = NumberBuffer {
        bytes: [0; 32],
        len: 0,
    };
    Ok(write!(&mut buffer, "{number}").is_ok().then_some(buffer))
}
fn add_bytes(count: &mut usize, amount: usize, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    let Some(next) = count.checked_add(amount).filter(|next| *next <= MAX_BYTES) else {
        return Ok(false);
    };
    debit(remaining, amount)?;
    *count = next;
    Ok(true)
}
fn string_bytes(text: &str, count: &mut usize, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    // Every UTF-8 byte needs at least one encoded byte, plus the quotes. This
    // is an O(1) deterministic overflow refusal, not an uncharged string scan.
    if text.len() > MAX_BYTES.saturating_sub(*count).saturating_sub(2)
        || !add_bytes(count, 2, remaining)?
    {
        return Ok(false);
    }
    let mut bytes = text.bytes();
    loop {
        debit(remaining, 1)?;
        let Some(byte) = bytes.next() else { break };
        let encoded = match byte {
            b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
            0..=0x1f => 6,
            _ => 1,
        };
        if !add_bytes(count, encoded, remaining)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// EXACT serde_json compact Value byte count, not a lower-bound preflight or
/// to_writer(error-box) attempt. No source tree clone or temporary Vec/String.
fn encoded_bytes(value: &Value, remaining: &mut usize) -> Result<Option<usize>, WorkFault> {
    debit(remaining, MAX_DEPTH + 1)?;
    let mut walk = Walk::new(value);
    let mut count = 0;
    loop {
        let Some(token) = walk.next(remaining)? else {
            return Ok(Some(count));
        };
        let fits = match token {
            Token::Null => add_bytes(&mut count, 4, remaining)?,
            Token::Bool(value) => add_bytes(&mut count, if value { 4 } else { 5 }, remaining)?,
            Token::Number(value) => match number_bytes(value, remaining)? {
                Some(buffer) => add_bytes(&mut count, buffer.len, remaining)?,
                None => false,
            },
            Token::String(text) | Token::Key(text) => string_bytes(text, &mut count, remaining)?,
            Token::Array(len) => {
                add_bytes(&mut count, 2, remaining)?
                    && add_bytes(&mut count, len.saturating_sub(1), remaining)?
            }
            Token::Object(len) => {
                add_bytes(&mut count, 2, remaining)?
                    && add_bytes(&mut count, len.saturating_sub(1), remaining)?
                    && add_bytes(&mut count, len, remaining)?
            }
            Token::TooDeep => false,
        };
        if !fits {
            return Ok(None);
        }
    }
}

/// Structural equality with explicit finite stacks and metered string/key
/// comparisons. HTTP can be arbitrarily large: an unmatched container length
/// is refused without walking its children; no Value::PartialEq is invoked.
fn same_json(a: &Value, b: &Value, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 2 * (MAX_DEPTH + 1))?;
    let mut left = Walk::new(a);
    let mut right = Walk::new(b);
    loop {
        let a = left.next(remaining)?;
        let b = right.next(remaining)?;
        debit(remaining, 1)?;
        let same = match (a, b) {
            (None, None) => return Ok(true),
            (Some(Token::Null), Some(Token::Null)) => true,
            (Some(Token::Bool(a)), Some(Token::Bool(b))) => a == b,
            (Some(Token::Array(a)), Some(Token::Array(b)))
            | (Some(Token::Object(a)), Some(Token::Object(b))) => a == b,
            (Some(Token::String(a)), Some(Token::String(b)))
            | (Some(Token::Key(a)), Some(Token::Key(b))) => text_eq(a, b, remaining)?,
            // Compare ACTUAL canonical serialized scalars, not Number's
            // float equality: +0.0 and -0.0 compare equal as Values but are
            // different native producer bytes. Both fmt buffers are fixed.
            (Some(Token::Number(a)), Some(Token::Number(b))) => {
                let Some(a) = number_bytes(a, remaining)? else {
                    return Ok(false);
                };
                let Some(b) = number_bytes(b, remaining)? else {
                    return Ok(false);
                };
                debit(remaining, 1)?;
                if a.len != b.len {
                    false
                } else {
                    debit(remaining, a.len)?;
                    a.bytes[..a.len] == b.bytes[..b.len]
                }
            }
            _ => false,
        };
        if !same {
            return Ok(false);
        }
    }
}

fn valid_producer(
    registry: &Value,
    http: &Value,
    remaining: &mut usize,
) -> Result<bool, WorkFault> {
    if encoded_bytes(registry, remaining)?.is_none() {
        return Ok(false);
    }
    debit(remaining, 1)?;
    let Some(object) = registry.as_object() else {
        return Ok(false);
    };
    if object.len() != 2 {
        return Ok(false);
    }
    let format = field(object, "format", remaining)?;
    debit(remaining, 1)?;
    if format.and_then(Value::as_u64) != Some(1) {
        return Ok(false);
    }
    let methods = field(object, "methods", remaining)?;
    debit(remaining, 1)?;
    let Some(methods) = methods.and_then(Value::as_object) else {
        return Ok(false);
    };
    if methods.len() > MAX_ALIASES {
        return Ok(false);
    }
    debit(remaining, 1)?;
    let Some(http) = http.as_object() else {
        return Ok(false);
    };
    debit(remaining, 2)?;
    let mut ordinary = http.iter();
    let mut committed = methods.iter();
    // Both maps are the ACTUAL serde_json BTreeMap-backed profile. Ordered
    // subset merge avoids all implicit lookup/comparison/repeated alias scans.
    loop {
        debit(remaining, 1)?;
        let Some((alias, descriptor)) = ordinary.next() else {
            break;
        };
        debit(remaining, 1)?;
        // RawHttpMethod serde accepts positional arrays. Every descriptor MUST
        // be an object BEFORE field lookup, including ordinary-only entries.
        let Some(object) = descriptor.as_object() else {
            return Ok(false);
        };
        let terminal = field(object, "terminal", remaining)?;
        debit(remaining, 1)?;
        if terminal.is_none_or(Value::is_null) {
            continue;
        }
        debit(remaining, 1)?;
        if alias.len() > MAX_NAME_BYTES {
            return Ok(false);
        }
        debit(remaining, 1)?;
        let Some((registered_alias, registered)) = committed.next() else {
            return Ok(false);
        };
        if !text_eq(alias, registered_alias, remaining)?
            || !canonical_http(registered, remaining)?
            || !same_json(registered, descriptor, remaining)?
        {
            return Ok(false);
        }
    }
    debit(remaining, 1)?;
    Ok(committed.next().is_none())
}

/// A native terminal HttpMethod serializes exactly these five fields. Fresh
/// one-shot queries have default consistency/receipt, so BOTH are omitted.
/// A handwritten default property (or omitted signingKeys) is NOT the producer.
fn canonical_http(value: &Value, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    let Some(object) = value.as_object() else {
        return Ok(false);
    };
    if object.len() != 5 {
        return Ok(false);
    }
    let mut seen = 0u8;
    debit(remaining, 1)?;
    let mut fields = object.iter();
    loop {
        debit(remaining, 1)?;
        let Some((key, value)) = fields.next() else {
            break;
        };
        if text_eq(key, "name", remaining)? {
            debit(remaining, 1)?;
            if !value
                .as_str()
                .is_some_and(|name| name.len() <= MAX_NAME_BYTES)
            {
                return Ok(false);
            }
            seen |= 1;
        } else if text_eq(key, "kind", remaining)? {
            if !string_is(value, "query", remaining)? {
                return Ok(false);
            }
            seen |= 2;
        } else if text_eq(key, "cache", remaining)? {
            debit(remaining, 1)?;
            if value.as_bool() != Some(false) {
                return Ok(false);
            }
            seen |= 4;
        } else if text_eq(key, "watch", remaining)? {
            debit(remaining, 1)?;
            if value.as_bool() != Some(false) {
                return Ok(false);
            }
            seen |= 8;
        } else if text_eq(key, "terminal", remaining)? {
            if !canonical_terminal(value, remaining)? {
                return Ok(false);
            }
            seen |= 16;
        } else {
            return Ok(false);
        }
    }
    Ok(seen == 31)
}

fn identifier(name: &str, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    if name.is_empty() || name.len() > 63 {
        return Ok(false);
    }
    debit(remaining, name.len() + 1)?;
    if !name.as_bytes()[0].is_ascii_lowercase()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Ok(false);
    }
    debit(remaining, 8)?;
    for reserved in [
        "sql_tables",
        "sql_columns",
        "sql_relationships",
        "sqlite_master",
        "sqlite_schema",
        "sqlite_temp_master",
        "sqlite_temp_schema",
    ] {
        debit(remaining, 1)?;
        if text_eq(name, reserved, remaining)? {
            return Ok(false);
        }
    }
    Ok(true)
}
fn canonical_terminal(value: &Value, remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 1)?;
    let Some(object) = value.as_object() else {
        return Ok(false);
    };
    if !(4..=5).contains(&object.len()) {
        return Ok(false);
    }
    let mut seen = 0u8;
    let mut cancel = false;
    let mut cancel_result = false;
    let mut signers = None;
    debit(remaining, 1)?;
    let mut fields = object.iter();
    loop {
        debit(remaining, 1)?;
        let Some((key, value)) = fields.next() else {
            break;
        };
        if text_eq(key, "catalog", remaining)? {
            debit(remaining, 1)?;
            let Some(name) = value.as_str() else {
                return Ok(false);
            };
            if !identifier(name, remaining)? {
                return Ok(false);
            }
            seen |= 1;
        } else if text_eq(key, "operation", remaining)? {
            cancel = string_is(value, "cancel", remaining)?;
            if !cancel
                && !string_is(value, "query", remaining)?
                && !string_is(value, "explain", remaining)?
                && !string_is(value, "catalog", remaining)?
            {
                return Ok(false);
            }
            seen |= 2;
        } else if text_eq(key, "finalizer", remaining)? {
            debit(remaining, 1)?;
            if !value
                .as_str()
                .is_some_and(|name| !name.is_empty() && name.len() <= 384)
            {
                return Ok(false);
            }
            seen |= 4;
        } else if text_eq(key, "signingKeys", remaining)? {
            debit(remaining, 1)?;
            signers = value.as_array();
            if signers.is_none() {
                return Ok(false);
            }
            seen |= 8;
        } else if text_eq(key, "cancelResult", remaining)? {
            if !string_is(value, "boolean", remaining)?
                && !string_is(value, "cancelled", remaining)?
            {
                return Ok(false);
            }
            cancel_result = true;
        } else {
            return Ok(false);
        }
    }
    debit(remaining, 1)?;
    if seen != 15 || (cancel_result && !cancel) {
        return Ok(false);
    }
    let signers = signers.unwrap();
    if signers.len() > 8 || (cancel && !signers.is_empty()) {
        return Ok(false);
    }
    canonical_signers(signers, remaining)
}

/// Match TerminalMethod::validate exactly: only STRING names participate in
/// distinctness; metadata doesn't require name/kind/algorithm or authenticate
/// a key. Arbitrary extra key values are preserved by native serialization.
fn canonical_signers(signers: &[Value], remaining: &mut usize) -> Result<bool, WorkFault> {
    debit(remaining, 8)?;
    let mut names = [None; 8];
    let mut names_len = 0;
    debit(remaining, 1)?;
    let mut entries = signers.iter();
    loop {
        debit(remaining, 1)?;
        let Some(key) = entries.next() else { break };
        debit(remaining, 1)?;
        let Some(key) = key.as_object() else {
            return Ok(false);
        };
        let name = field(key, "name", remaining)?;
        debit(remaining, 1)?;
        if let Some(name) = name.and_then(Value::as_str) {
            debit(remaining, 1)?;
            let mut previous = names[..names_len].iter();
            loop {
                debit(remaining, 1)?;
                let Some(previous) = previous.next() else {
                    break;
                };
                if text_eq(name, previous.unwrap(), remaining)? {
                    return Ok(false);
                }
            }
            names[names_len] = Some(name);
            names_len += 1;
        }
        let usages = field(key, "usages", remaining)?;
        debit(remaining, 1)?;
        let Some(usages) = usages.and_then(Value::as_array) else {
            return Ok(false);
        };
        debit(remaining, 1)?;
        let mut usages = usages.iter();
        let found = loop {
            debit(remaining, 1)?;
            let Some(usage) = usages.next() else {
                break false;
            };
            if string_is(usage, "sign", remaining)? {
                break true;
            }
        };
        if !found {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests;
