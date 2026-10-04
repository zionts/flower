//! Later owned, mapped SQL input. Construction/admission precedes copying.
//! This does not accept a caller classification flag or produce a witness.
use super::scanner::{Scanner, Work, decode, decoded_len, safe_u64};
use super::storage::{Mapping, rounded};
use super::{
    CHECK_QUANTUM, CONTROL_BYTES, Check, Error, Header, KEY_SLOTS, Key, Level, Limits, MAX_DEPTH,
    MAX_INPUT_BYTES, MAX_NAME_BYTES, MAX_PARAMETERS, MAX_ROWS, MAX_SQL_BYTES, MAX_TOKEN_BYTES,
    Pool, Span, Ticket,
};

#[derive(Clone, Copy, Debug)]
pub(crate) struct OwnedLimits {
    pub bytes: usize,
    pub decoded_bytes: usize,
    pub work: usize,
}
impl Default for OwnedLimits {
    fn default() -> Self {
        Self {
            bytes: MAX_INPUT_BYTES,
            decoded_bytes: MAX_INPUT_BYTES,
            work: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Default)]
enum Parameter {
    #[default]
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Text(Span),
}
/// No Debug/Display: parameter values are confidential input.
pub(crate) enum NativeParameter<'a> {
    Null,
    Bool(bool),
    Integer(i64),
    Real(f64),
    Text(&'a str),
}
/// Borrowed view of a completely decoded query in the admitted native owner.
/// No operation/authority field exists; callers MUST use their sealed witness.
pub(crate) struct NativeQuery<'a> {
    data: &'a [u8],
    sql: Span,
    parameters: &'a [Parameter],
    max_rows: Option<u64>,
    query_id: Option<Span>,
}
impl<'a> NativeQuery<'a> {
    pub(crate) fn sql(&self) -> &'a str {
        text(self.sql.slice(self.data))
    }
    pub(crate) fn parameters(&self) -> impl ExactSizeIterator<Item = NativeParameter<'a>> + 'a {
        let data = self.data;
        self.parameters.iter().map(move |p| match p {
            Parameter::Null => NativeParameter::Null,
            Parameter::Bool(v) => NativeParameter::Bool(*v),
            Parameter::Integer(v) => NativeParameter::Integer(*v),
            Parameter::Real(v) => NativeParameter::Real(*v),
            Parameter::Text(s) => NativeParameter::Text(text(s.slice(data))),
        })
    }
    pub(crate) fn max_rows(&self) -> Option<u64> {
        self.max_rows
    }
    pub(crate) fn query_id(&self) -> Option<&'a str> {
        self.query_id.map(|s| text(s.slice(self.data)))
    }
}
fn text(bytes: &[u8]) -> &str {
    // Only strict string decoder or Header::name can populate these spans.
    unsafe { std::str::from_utf8_unchecked(bytes) }
}

/// Owns only fixed private mapped bytes and descriptors, never an App, Records,
/// Snapshot, provider, callback, source, String/Value tree or transport owner.
/// No Debug/Display and mapped bytes are volatile-scrubbed on all Drop paths.
pub(crate) struct NativeInput<'pool> {
    data: Mapping<u8>,
    decoded: Mapping<u8>,
    levels: Mapping<Level>,
    keys: Mapping<Key>,
    parameters: Mapping<Parameter>,
    name: Span,
    args: Span,
    credentials: Option<Span>,
    request_id: Option<Span>,
    expected_revision: Option<u64>,
    len: usize,
    decoded_len: usize,
    remaining: usize,
    imported: bool,
    decoded_query: bool,
    failed: Option<Error>,
    check: &'pool dyn Check,
    _ticket: Ticket<'pool>,
}
impl<'pool> NativeInput<'pool> {
    pub(crate) fn admission_bytes(limits: OwnedLimits) -> Result<usize, Error> {
        if limits.bytes == 0
            || limits.bytes > MAX_INPUT_BYTES
            || limits.decoded_bytes == 0
            || limits.decoded_bytes > MAX_INPUT_BYTES
            || limits.work == 0
            || limits.work > 64 * 1024 * 1024
        {
            return Err(Error::Capacity);
        }
        rounded::<u8>(limits.bytes)?
            .checked_add(rounded::<u8>(limits.decoded_bytes)?)
            .and_then(|n| n.checked_add(rounded::<Level>(MAX_DEPTH).ok()?))
            .and_then(|n| n.checked_add(rounded::<Key>(KEY_SLOTS).ok()?))
            .and_then(|n| n.checked_add(rounded::<Parameter>(MAX_PARAMETERS).ok()?))
            .and_then(|n| n.checked_add(CONTROL_BYTES))
            .ok_or(Error::Capacity)
    }
    pub(crate) fn new(
        pool: &'pool Pool,
        limits: OwnedLimits,
        check: &'pool dyn Check,
    ) -> Result<Self, Error> {
        let bytes = Self::admission_bytes(limits)?;
        check.check()?;
        let ticket = pool.reserve(bytes, check)?;
        let data = Mapping::new(limits.bytes, check)?;
        let decoded = Mapping::new(limits.decoded_bytes, check)?;
        let levels = Mapping::new(MAX_DEPTH, check)?;
        let keys = Mapping::new(KEY_SLOTS, check)?;
        let parameters = Mapping::new(MAX_PARAMETERS, check)?;
        Ok(Self {
            data,
            decoded,
            levels,
            keys,
            parameters,
            name: Span::default(),
            args: Span::default(),
            credentials: None,
            request_id: None,
            expected_revision: None,
            len: 0,
            decoded_len: 0,
            remaining: limits.work,
            imported: false,
            decoded_query: false,
            failed: None,
            check,
            _ticket: ticket,
        })
    }
    #[cfg(test)]
    pub(super) fn mapped_charge_actual(&self) -> usize {
        self.data.mapped_bytes()
            + self.decoded.mapped_bytes()
            + self.levels.mapped_bytes()
            + self.keys.mapped_bytes()
            + self.parameters.mapped_bytes()
            + CONTROL_BYTES
    }
    /// Only call AFTER native node admission, native absolute deadline start,
    /// and the parent's sealed-registry decision. The helper deliberately cannot
    /// certify that contract; there is no caller bool masquerading as authority.
    /// Caller may drop the original body/lease AFTER this succeeds.
    pub(crate) fn import(&mut self, header: &Header<'_>) -> Result<(), Error> {
        let check = self.check;
        if let Some(error) = self.failed {
            return Err(error);
        }
        if self.imported {
            return Err(Error::Invalid);
        }
        self.imported = true;
        let result = (|| {
            check.check()?;
            if header.body_len() > MAX_INPUT_BYTES {
                return Err(Error::Capacity);
            }
            let credentials = header.credentials_json();
            let mut work = Work::new(&mut self.remaining, check);
            self.name = copy(
                &mut self.data,
                &mut self.len,
                header.name().as_bytes(),
                &mut work,
            )?;
            self.args = copy(&mut self.data, &mut self.len, header.args_json(), &mut work)?;
            self.credentials = credentials
                .map(|c| copy(&mut self.data, &mut self.len, c, &mut work))
                .transpose()?;
            self.request_id = header
                .request_id_json()
                .map(|c| copy(&mut self.data, &mut self.len, c, &mut work))
                .transpose()?;
            self.expected_revision = header.expected_revision();
            check.check()
        })();
        if let Err(e) = result {
            self.failed = Some(e);
        }
        result
    }
    fn ready(&self) -> Result<(), Error> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        if !self.imported {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    pub(crate) fn name(&self) -> Result<&str, Error> {
        self.ready()?;
        Ok(text(self.name.slice(&self.data)))
    }
    pub(crate) fn args_json(&self) -> Result<&[u8], Error> {
        self.ready()?;
        Ok(self.args.slice(&self.data))
    }
    pub(crate) fn credentials_json(&self) -> Result<Option<&[u8]>, Error> {
        self.ready()?;
        Ok(self.credentials.map(|s| s.slice(&self.data)))
    }
    pub(crate) fn request_id_json(&self) -> Result<Option<&[u8]>, Error> {
        self.ready()?;
        Ok(self.request_id.map(|s| s.slice(&self.data)))
    }
    pub(crate) fn expected_revision(&self) -> Result<Option<u64>, Error> {
        self.ready()?;
        Ok(self.expected_revision)
    }
    /// Optional primitive-only string credential extraction, e.g. a JWT.
    /// Arbitrary authorization credentials remain raw JSON. This does NOT parse
    /// a token, confer a principal, or search attacker-chosen object field names.
    pub(crate) fn decode_string_credentials(&mut self) -> Result<Option<&[u8]>, Error> {
        let check = self.check;
        self.ready()?;
        let Some(span) = self.credentials else {
            return Ok(None);
        };
        let start = self.decoded_len;
        let prefix = &self.data;
        let suffix = &mut self.decoded[start..];
        let mut work = Work::new(&mut self.remaining, check);
        let result = (|| {
            let len = decoded_len(prefix, span, &mut work)?;
            if len > MAX_TOKEN_BYTES || len > suffix.len() {
                return Err(Error::Capacity);
            }
            decode(prefix, span, &mut suffix[..len], &mut work)?;
            work.check()?;
            Ok(len)
        })();
        match result {
            Ok(len) => {
                self.decoded_len += len;
                Ok(Some(&self.decoded[start..self.decoded_len]))
            }
            Err(e) => {
                self.failed = Some(e);
                Err(e)
            }
        }
    }
    /// Decode default direct query args (sql, parameters, maxRows, queryId).
    /// Custom deployed readless plans instead call query_json with their bounded
    /// emitted JSON bytes; no conversion through serde Value is permitted.
    /// Merely calling this does NOT select the terminal operation.
    pub(crate) fn query_args(&mut self) -> Result<NativeQuery<'_>, Error> {
        let check = self.check;
        self.ready()?;
        if self.decoded_query {
            return Err(Error::Invalid);
        }
        self.decoded_query = true;
        let base = self.decoded_len;
        let result = build_query(
            self.args.slice(&self.data),
            &mut self.decoded[base..],
            &mut self.levels,
            &mut self.keys,
            &mut self.parameters,
            &mut self.remaining,
            check,
        );
        self.query_result(result, base)
    }
    pub(crate) fn query_json(&mut self, raw: &[u8]) -> Result<NativeQuery<'_>, Error> {
        let check = self.check;
        self.ready()?;
        if self.decoded_query {
            return Err(Error::Invalid);
        }
        self.decoded_query = true;
        let base = self.decoded_len;
        let result = build_query(
            raw,
            &mut self.decoded[base..],
            &mut self.levels,
            &mut self.keys,
            &mut self.parameters,
            &mut self.remaining,
            check,
        );
        self.query_result(result, base)
    }
    fn query_result(
        &mut self,
        result: Result<QueryParts, Error>,
        base: usize,
    ) -> Result<NativeQuery<'_>, Error> {
        match result {
            Err(e) => {
                self.failed = Some(e);
                Err(e)
            }
            Ok(parts) => {
                self.decoded_len += parts.bytes;
                Ok(NativeQuery {
                    data: &self.decoded[base..self.decoded_len],
                    sql: parts.sql,
                    parameters: &self.parameters[..parts.parameters],
                    max_rows: parts.max_rows,
                    query_id: parts.query_id,
                })
            }
        }
    }
}
fn copy(out: &mut [u8], len: &mut usize, raw: &[u8], work: &mut Work<'_>) -> Result<Span, Error> {
    let start = *len;
    let end = start
        .checked_add(raw.len())
        .filter(|n| *n <= out.len())
        .ok_or(Error::Capacity)?;
    for (source, target) in raw
        .chunks(CHECK_QUANTUM)
        .zip(out[start..end].chunks_mut(CHECK_QUANTUM))
    {
        work.debit(source.len())?;
        target.copy_from_slice(source);
    }
    *len = end;
    Ok(Span { start, end })
}
fn decode_text(
    raw: &[u8],
    span: Span,
    out: &mut [u8],
    len: &mut usize,
    cap: usize,
    work: &mut Work<'_>,
) -> Result<Span, Error> {
    let n = decoded_len(raw, span, work)?;
    if n > cap {
        return Err(Error::Capacity);
    }
    let start = *len;
    let end = start
        .checked_add(n)
        .filter(|n| *n <= out.len())
        .ok_or(Error::Capacity)?;
    decode(raw, span, &mut out[start..end], work)?;
    *len = end;
    Ok(Span { start, end })
}
struct QueryParts {
    sql: Span,
    parameters: usize,
    max_rows: Option<u64>,
    query_id: Option<Span>,
    bytes: usize,
}
fn build_query(
    raw: &[u8],
    output: &mut [u8],
    levels: &mut [Level],
    keys: &mut [Key],
    parameters: &mut [Parameter],
    remaining: &mut usize,
    check: &dyn Check,
) -> Result<QueryParts, Error> {
    check.check()?;
    if raw.len() > MAX_INPUT_BYTES {
        return Err(Error::Capacity);
    }
    let limits = Limits {
        body_bytes: MAX_INPUT_BYTES,
        ..Limits::default()
    };
    let fields = {
        let mut scanner = Scanner::new(raw, levels, keys, limits, remaining, check);
        scanner.fields(["sql", "parameters", "maxRows", "queryId"])?
    };
    let mut work = Work::new(remaining, check);
    let mut len = 0;
    let sql = decode_text(
        raw,
        fields[0].ok_or(Error::Invalid)?,
        output,
        &mut len,
        MAX_SQL_BYTES,
        &mut work,
    )?;
    if sql.start == sql.end {
        return Err(Error::Invalid);
    }
    let max_rows = fields[2]
        .map(|s| safe_u64(s.slice(raw), &mut work))
        .transpose()?;
    if max_rows.is_some_and(|n| n > MAX_ROWS) {
        // Exact current sqlite::MAX_ROWS; later engine validation still owns the
        // SQL grammar, table contract and actual operator/output budgets.
        return Err(Error::Capacity);
    }
    let query_id = fields[3]
        .map(|s| decode_text(raw, s, output, &mut len, MAX_NAME_BYTES, &mut work))
        .transpose()?;
    if query_id.is_some_and(|s| s.start == s.end) {
        return Err(Error::Invalid);
    }
    let mut count = 0;
    if let Some(span) = fields[1] {
        // The complete syntax was already scanned; bounded leaf spans suffice.
        // No SQL lexing, Value tree, callback or operation discovery happens here.
        let bytes = span.slice(raw);
        if bytes.first() != Some(&b'[') {
            return Err(Error::Invalid);
        }
        let mut pos = span.start + 1;
        while raw.get(pos).is_some_and(|b| b.is_ascii_whitespace()) {
            work.debit(1)?;
            pos += 1;
        }
        if raw.get(pos) != Some(&b']') {
            loop {
                if count >= parameters.len() {
                    return Err(Error::Capacity);
                }
                let start = pos;
                let parameter = if raw.get(pos) == Some(&b'"') {
                    // Find the closing quote without decoding twice beyond work.
                    pos += 1;
                    let mut escaped = false;
                    loop {
                        work.debit(1)?;
                        let b = *raw.get(pos).ok_or(Error::Invalid)?;
                        pos += 1;
                        if !escaped && b == b'"' {
                            break;
                        }
                        escaped = !escaped && b == b'\\';
                    }
                    let end = pos;
                    Parameter::Text(decode_text(
                        raw,
                        Span { start, end },
                        output,
                        &mut len,
                        MAX_INPUT_BYTES,
                        &mut work,
                    )?)
                } else {
                    while raw
                        .get(pos)
                        .is_some_and(|b| !matches!(b, b',' | b']' | b' ' | b'\t' | b'\r' | b'\n'))
                    {
                        work.debit(1)?;
                        pos += 1;
                    }
                    let lexeme = &raw[start..pos];
                    match lexeme {
                        b"null" => Parameter::Null,
                        b"true" => Parameter::Bool(true),
                        b"false" => Parameter::Bool(false),
                        _ => {
                            work.debit(lexeme.len())?;
                            work.check()?;
                            let number = std::str::from_utf8(lexeme).map_err(|_| Error::Invalid)?;
                            if let Ok(integer) = number.parse::<i64>() {
                                Parameter::Integer(integer)
                            } else {
                                let real = number.parse::<f64>().map_err(|_| Error::Invalid)?;
                                if !real.is_finite() {
                                    return Err(Error::Invalid);
                                }
                                Parameter::Real(real)
                            }
                        }
                    }
                };
                // Actual fixed descriptor storage + decoded text, not a guessed
                // per-JSON-node multiplier. Decoded input stays <=1MiB; raw and
                // decoded physical maps are BOTH reserved before decoding.
                if (count + 1)
                    .checked_mul(size_of::<Parameter>())
                    .and_then(|n| n.checked_add(len))
                    .is_none_or(|n| n > MAX_INPUT_BYTES)
                {
                    return Err(Error::Capacity);
                }
                parameters[count] = parameter;
                count += 1;
                while raw.get(pos).is_some_and(|b| b.is_ascii_whitespace()) {
                    work.debit(1)?;
                    pos += 1;
                }
                match raw.get(pos) {
                    Some(b']') => break,
                    Some(b',') => {
                        pos += 1;
                        work.debit(1)?;
                    }
                    _ => return Err(Error::Invalid),
                }
                while raw.get(pos).is_some_and(|b| b.is_ascii_whitespace()) {
                    work.debit(1)?;
                    pos += 1;
                }
            }
        }
    }
    work.check()?;
    Ok(QueryParts {
        sql,
        parameters: count,
        max_rows,
        query_id,
        bytes: len,
    })
}
