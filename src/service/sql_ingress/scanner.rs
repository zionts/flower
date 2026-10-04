//! Allocation-free complete JSON scanner with a prepaid duplicate-key index.
use super::{
    CHECK_QUANTUM, Check, Error, Header, Limits, MAX_LOOKUP_DEPTH, MAX_NAME_BYTES, NameLookup,
    Span, Transport,
};

#[derive(Clone, Copy, Default)]
pub(super) struct Level {
    id: u32,
    kind: u8,
    state: u8,
}
#[derive(Clone, Copy, Default)]
pub(super) struct Key {
    parent: u32,
    occupied: bool,
    hash: u64,
    span: Span,
}

pub(super) struct Work<'a> {
    remaining: &'a mut usize,
    check: &'a dyn Check,
    since: usize,
}
impl<'a> Work<'a> {
    pub(super) fn new(remaining: &'a mut usize, check: &'a dyn Check) -> Self {
        Self {
            remaining,
            check,
            since: CHECK_QUANTUM,
        }
    }
    pub(super) fn debit(&mut self, n: usize) -> Result<(), Error> {
        if self.since >= CHECK_QUANTUM || n >= CHECK_QUANTUM {
            self.check.check()?;
            self.since = 0;
        }
        *self.remaining = self.remaining.checked_sub(n).ok_or(Error::WorkLimit)?;
        self.since = self.since.saturating_add(n);
        Ok(())
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.check.check()
    }
}

pub(super) struct Scanner<'body, 'scratch> {
    input: &'body [u8],
    pos: usize,
    levels: &'scratch mut [Level],
    keys: &'scratch mut [Key],
    limits: Limits,
    nodes: usize,
    key_count: usize,
    duplicate_keys: bool,
    base_depth: usize,
    finite_numbers: bool,
    work: Work<'scratch>,
}
impl<'body, 'scratch> Scanner<'body, 'scratch> {
    pub(super) fn new(
        input: &'body [u8],
        levels: &'scratch mut [Level],
        keys: &'scratch mut [Key],
        limits: Limits,
        remaining: &'scratch mut usize,
        check: &'scratch dyn Check,
    ) -> Self {
        Self {
            input,
            pos: 0,
            levels,
            keys,
            limits,
            nodes: 0,
            key_count: 0,
            duplicate_keys: true,
            base_depth: 1,
            finite_numbers: false,
            work: Work::new(remaining, check),
        }
    }
    fn byte(&mut self) -> Result<u8, Error> {
        self.work.debit(1)?;
        let v = *self.input.get(self.pos).ok_or(Error::Invalid)?;
        self.pos += 1;
        Ok(v)
    }
    fn ws(&mut self) -> Result<(), Error> {
        while self
            .input
            .get(self.pos)
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.byte()?;
        }
        Ok(())
    }
    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.byte()? != byte {
            return Err(Error::Invalid);
        }
        Ok(())
    }
    fn node(&mut self) -> Result<u32, Error> {
        self.work.debit(1)?;
        if self.nodes >= self.limits.nodes {
            return Err(Error::Capacity);
        }
        self.nodes += 1;
        Ok(self.nodes as u32)
    }
    fn string(&mut self, out: Option<&mut [u8]>) -> Result<(Span, usize, u64), Error> {
        let start = self.pos;
        let mut decoder = Decoder::new(self.input, self.pos, &mut self.work)?;
        let mut len = 0usize;
        let mut hash = 0xcbf29ce484222325u64;
        let mut out = out;
        while let Some(unit) = decoder.next(&mut self.work)? {
            let end = len.checked_add(unit.len).ok_or(Error::Capacity)?;
            if let Some(buffer) = out.as_deref_mut() {
                if end > buffer.len() {
                    return Err(Error::Capacity);
                }
                buffer[len..end].copy_from_slice(&unit.bytes[..unit.len]);
            }
            for b in &unit.bytes[..unit.len] {
                self.work.debit(1)?;
                hash = (hash ^ u64::from(*b)).wrapping_mul(0x100000001b3);
            }
            len = end;
        }
        self.pos = decoder.pos;
        Ok((
            Span {
                start,
                end: self.pos,
            },
            len,
            hash,
        ))
    }
    fn same_key(&mut self, a: Span, b: Span) -> Result<bool, Error> {
        let mut a = Decoder::new(self.input, a.start, &mut self.work)?;
        let mut b = Decoder::new(self.input, b.start, &mut self.work)?;
        loop {
            self.work.debit(4)?;
            match (a.next(&mut self.work)?, b.next(&mut self.work)?) {
                (None, None) => return Ok(true),
                (Some(a), Some(b)) if a.len == b.len && a.bytes[..a.len] == b.bytes[..b.len] => (),
                _ => return Ok(false),
            }
        }
    }
    fn insert_key(&mut self, parent: u32, span: Span, hash: u64) -> Result<(), Error> {
        if !self.duplicate_keys {
            return Ok(());
        }
        if self.key_count >= self.limits.keys {
            return Err(Error::Capacity);
        }
        let start = (hash ^ u64::from(parent).wrapping_mul(0x9e3779b97f4a7c15)) as usize;
        for offset in 0..self.keys.len() {
            self.work.debit(1)?;
            let index = start.wrapping_add(offset) % self.keys.len();
            let key = self.keys[index];
            if !key.occupied {
                self.keys[index] = Key {
                    parent,
                    occupied: true,
                    hash,
                    span,
                };
                self.key_count += 1;
                return Ok(());
            }
            if key.parent == parent && key.hash == hash && self.same_key(key.span, span)? {
                return Err(Error::Duplicate);
            }
        }
        Err(Error::Capacity)
    }
    fn number(&mut self) -> Result<(), Error> {
        let start = self.pos;
        if self.input.get(self.pos) == Some(&b'-') {
            self.byte()?;
        }
        match self.input.get(self.pos) {
            Some(b'0') => {
                self.byte()?;
            }
            Some(b'1'..=b'9') => {
                self.digits(start)?;
            }
            _ => return Err(Error::Invalid),
        }
        if self.input.get(self.pos) == Some(&b'.') {
            self.byte()?;
            if !self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                return Err(Error::Invalid);
            }
            self.digits(start)?;
        }
        if self
            .input
            .get(self.pos)
            .is_some_and(|b| matches!(b, b'e' | b'E'))
        {
            self.byte()?;
            if self
                .input
                .get(self.pos)
                .is_some_and(|b| matches!(b, b'+' | b'-'))
            {
                self.byte()?;
            }
            if !self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
                return Err(Error::Invalid);
            }
            self.digits(start)?;
        }
        if self.pos - start > self.limits.number_bytes {
            return Err(Error::Capacity);
        }
        if self.finite_numbers {
            // Real build serializes Value numbers canonically (<64 bytes).
            // Refuse noncanonical huge mantissas explicitly rather than invoke
            // an opaque numeric conversion loop beyond the check quantum.
            if self.pos - start > 64 {
                return Err(Error::Unsupported);
            }
            self.work.debit(self.pos - start)?;
            // This is a bounded ASCII span already validated by the scanner.
            // Stored serde_json::Value cannot contain a non-finite number.
            let number = unsafe { std::str::from_utf8_unchecked(&self.input[start..self.pos]) };
            if !number.parse::<f64>().is_ok_and(f64::is_finite) {
                return Err(Error::Unsupported);
            }
        }
        Ok(())
    }
    fn digits(&mut self, start: usize) -> Result<(), Error> {
        while self.input.get(self.pos).is_some_and(u8::is_ascii_digit) {
            if self.pos - start >= self.limits.number_bytes {
                return Err(Error::Capacity);
            }
            self.byte()?;
        }
        Ok(())
    }
    fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        for b in literal {
            self.expect(*b)?;
        }
        Ok(())
    }
    // A leaf returns true; a container pushes a paid explicit level and returns
    // false. No invocation of value() occurs recursively.
    fn atom(&mut self, depth: &mut usize) -> Result<bool, Error> {
        self.ws()?;
        let id = self.node()?;
        match self.input.get(self.pos) {
            Some(b'"') => {
                self.string(None)?;
            }
            Some(b'n') => self.literal(b"null")?,
            Some(b't') => self.literal(b"true")?,
            Some(b'f') => self.literal(b"false")?,
            Some(b'-' | b'0'..=b'9') => self.number()?,
            Some(b'[' | b'{') => {
                // The outer public object also counts toward depth64.
                if *depth + self.base_depth >= self.limits.depth || *depth >= self.levels.len() {
                    return Err(Error::Capacity);
                }
                let kind = self.byte()?;
                self.levels[*depth] = Level { id, kind, state: 0 };
                *depth += 1;
                return Ok(false);
            }
            _ => return Err(Error::Invalid),
        }
        Ok(true)
    }
    pub(super) fn value(&mut self) -> Result<Span, Error> {
        self.ws()?;
        let start = self.pos;
        let mut depth = 0;
        if self.atom(&mut depth)? {
            return Ok(Span {
                start,
                end: self.pos,
            });
        }
        while depth != 0 {
            self.ws()?;
            let level = self.levels[depth - 1];
            if level.kind == b'[' {
                match level.state {
                    0 | 1 => {
                        if self.input.get(self.pos) == Some(&b']') {
                            if level.state == 1 {
                                return Err(Error::Invalid);
                            }
                            self.byte()?;
                            depth -= 1;
                        } else {
                            self.levels[depth - 1].state = 2;
                            self.atom(&mut depth)?;
                        }
                    }
                    _ => match self.byte()? {
                        b',' => self.levels[depth - 1].state = 1,
                        b']' => depth -= 1,
                        _ => return Err(Error::Invalid),
                    },
                }
            } else {
                match level.state {
                    0 | 1 => {
                        if self.input.get(self.pos) == Some(&b'}') {
                            if level.state == 1 {
                                return Err(Error::Invalid);
                            }
                            self.byte()?;
                            depth -= 1;
                        } else {
                            let (span, _, hash) = self.string(None)?;
                            self.insert_key(level.id, span, hash)?;
                            self.ws()?;
                            self.expect(b':')?;
                            self.levels[depth - 1].state = 2;
                            self.atom(&mut depth)?;
                        }
                    }
                    _ => match self.byte()? {
                        b',' => self.levels[depth - 1].state = 1,
                        b'}' => depth -= 1,
                        _ => return Err(Error::Invalid),
                    },
                }
            }
        }
        Ok(Span {
            start,
            end: self.pos,
        })
    }
    pub(super) fn fields<const N: usize>(
        &mut self,
        names: [&str; N],
    ) -> Result<[Option<Span>; N], Error> {
        let mut fields = [None; N];
        self.ws()?;
        self.expect(b'{')?;
        let parent = self.node()?;
        self.ws()?;
        if self.input.get(self.pos) == Some(&b'}') {
            self.byte()?;
        } else {
            loop {
                let mut decoded = [0u8; 32];
                let (span, len, hash) = self.string(Some(&mut decoded)).map_err(|e| {
                    if e == Error::Capacity {
                        Error::UnknownField
                    } else {
                        e
                    }
                })?;
                self.insert_key(parent, span, hash)?;
                let index = names
                    .iter()
                    .position(|name| name.as_bytes() == &decoded[..len])
                    .ok_or(Error::UnknownField)?;
                self.ws()?;
                self.expect(b':')?;
                fields[index] = Some(self.value()?);
                self.ws()?;
                match self.byte()? {
                    b'}' => break,
                    b',' => {
                        self.ws()?;
                    }
                    _ => return Err(Error::Invalid),
                }
            }
        }
        self.ws()?;
        if self.pos != self.input.len() {
            return Err(Error::Invalid);
        }
        self.work.check()?;
        Ok(fields)
    }
    pub(super) fn clear_keys(&mut self) -> Result<(), Error> {
        for key in self.keys.iter_mut() {
            self.work.debit(size_of::<Key>())?;
            *key = Key::default();
        }
        self.key_count = 0;
        Ok(())
    }
    /// Full metadata syntax/decoded-key/depth validation precedes semantics.
    pub(super) fn complete(&mut self) -> Result<Span, Error> {
        self.base_depth = 0;
        self.finite_numbers = true;
        self.clear_keys()?;
        let span = self.value()?;
        self.ws()?;
        if self.pos != self.input.len() {
            return Err(Error::Invalid);
        }
        self.work.check()?;
        // Reinspection cannot reset work. Capacity and duplicate checks already
        // covered the entire immutable document; repeated semantic visits are
        // still byte/node/hash/decode-metered, not new tree quota admissions.
        self.duplicate_keys = false;
        self.limits.nodes = usize::MAX;
        Ok(span)
    }
    pub(super) fn object(&mut self, span: Span) -> Result<ObjectCursor, Error> {
        self.pos = span.start;
        self.expect(b'{')?;
        Ok(ObjectCursor {
            pos: self.pos,
            end: span.end,
            finished: false,
        })
    }
    pub(super) fn object_next(
        &mut self,
        cursor: &mut ObjectCursor,
    ) -> Result<Option<(Span, Span)>, Error> {
        if cursor.finished {
            return Ok(None);
        }
        self.pos = cursor.pos;
        self.ws()?;
        if self.input.get(self.pos) == Some(&b'}') {
            self.byte()?;
            if self.pos != cursor.end {
                return Err(Error::Invalid);
            }
            cursor.finished = true;
            return Ok(None);
        }
        let (key, _, _) = self.string(None)?;
        self.ws()?;
        self.expect(b':')?;
        let value = self.value()?;
        self.ws()?;
        match self.byte()? {
            b'}' => {
                if self.pos != cursor.end {
                    return Err(Error::Invalid);
                }
                cursor.finished = true;
            }
            b',' => (),
            _ => return Err(Error::Invalid),
        }
        cursor.pos = self.pos;
        Ok(Some((key, value)))
    }
    pub(super) fn array(&mut self, span: Span) -> Result<ArrayCursor, Error> {
        self.pos = span.start;
        self.expect(b'[')?;
        Ok(ArrayCursor {
            pos: self.pos,
            end: span.end,
            finished: false,
        })
    }
    pub(super) fn array_next(&mut self, cursor: &mut ArrayCursor) -> Result<Option<Span>, Error> {
        if cursor.finished {
            return Ok(None);
        }
        self.pos = cursor.pos;
        self.ws()?;
        if self.input.get(self.pos) == Some(&b']') {
            self.byte()?;
            if self.pos != cursor.end {
                return Err(Error::Invalid);
            }
            cursor.finished = true;
            return Ok(None);
        }
        let value = self.value()?;
        self.ws()?;
        match self.byte()? {
            b']' => {
                if self.pos != cursor.end {
                    return Err(Error::Invalid);
                }
                cursor.finished = true;
            }
            b',' => (),
            _ => return Err(Error::Invalid),
        }
        cursor.pos = self.pos;
        Ok(Some(value))
    }
    pub(super) fn fields_at<const N: usize>(
        &mut self,
        span: Span,
        names: [&str; N],
    ) -> Result<[Option<Span>; N], Error> {
        let mut fields = [None; N];
        let mut cursor = self.object(span)?;
        while let Some((key, value)) = self.object_next(&mut cursor)? {
            let mut decoded = [0u8; 32];
            let len = self.decode(key, &mut decoded).map_err(|error| {
                if error == Error::Capacity {
                    Error::UnknownField
                } else {
                    error
                }
            })?;
            self.work.debit(N * decoded.len())?;
            let index = names
                .iter()
                .position(|name| name.as_bytes() == &decoded[..len])
                .ok_or(Error::UnknownField)?;
            fields[index] = Some(value);
        }
        Ok(fields)
    }
    pub(super) fn decode(&mut self, span: Span, out: &mut [u8]) -> Result<usize, Error> {
        decode(self.input, span, out, &mut self.work)
    }
    pub(super) fn string_equals(&mut self, span: Span, expected: &[u8]) -> Result<bool, Error> {
        if self.input.get(span.start) != Some(&b'"') {
            return Ok(false);
        }
        let mut decoder = Decoder::new(self.input, span.start, &mut self.work)?;
        let mut len = 0usize;
        let mut same = true;
        while let Some(unit) = decoder.next(&mut self.work)? {
            for byte in &unit.bytes[..unit.len] {
                self.work.debit(1)?;
                same &= expected.get(len) == Some(byte);
                len = len.checked_add(1).ok_or(Error::Capacity)?;
            }
        }
        if decoder.pos != span.end {
            return Err(Error::Invalid);
        }
        Ok(same && len == expected.len())
    }
    pub(super) fn same_string(&mut self, a: Span, b: Span) -> Result<bool, Error> {
        self.same_key(a, b)
    }
    pub(super) fn raw_equals(&mut self, span: Span, expected: &[u8]) -> Result<bool, Error> {
        self.work.debit(expected.len())?;
        Ok(span.slice(self.input) == expected)
    }
    pub(super) fn first(&self, span: Span) -> Option<u8> {
        self.input.get(span.start).copied()
    }
    pub(super) fn debit(&mut self, n: usize) -> Result<(), Error> {
        self.work.debit(n)
    }
    pub(super) fn check(&self) -> Result<(), Error> {
        self.work.check()
    }
    pub(super) fn lookup_name(&mut self) -> Result<NameLookup<'body>, Error> {
        // Discovery is bounded by actual transport bytes/work and the pinned
        // ordinary recursion limit, not SQL-specific decoded-tree limits.
        self.duplicate_keys = false;
        self.limits.depth = MAX_LOOKUP_DEPTH;
        self.limits.nodes = self.input.len().saturating_add(1);
        self.limits.number_bytes = self.input.len().max(1);
        self.ws()?;
        self.expect(b'{')?;
        self.node()?;
        self.ws()?;
        let mut name_span = None;
        if self.input.get(self.pos) == Some(&b'}') {
            self.byte()?;
        } else {
            loop {
                let (key, len, _) = self.string(None)?;
                let is_name = if len == 4 {
                    let mut decoded = [0u8; 4];
                    decode(self.input, key, &mut decoded, &mut self.work)?;
                    decoded == *b"name"
                } else {
                    false
                };
                self.ws()?;
                self.expect(b':')?;
                let span = self.value()?;
                if is_name {
                    name_span = Some(span);
                }
                self.ws()?;
                match self.byte()? {
                    b'}' => break,
                    b',' => self.ws()?,
                    _ => return Err(Error::Invalid),
                }
            }
        }
        self.ws()?;
        if self.pos != self.input.len() {
            return Err(Error::Invalid);
        }
        let mut name = [0u8; MAX_NAME_BYTES];
        let name_len = decode_prefix(
            self.input,
            name_span.ok_or(Error::Invalid)?,
            &mut name,
            &mut self.work,
        )?;
        if name_len == 0 {
            return Err(Error::Invalid);
        }
        self.work.check()?;
        Ok(NameLookup {
            body: self.input,
            name,
            name_len,
        })
    }
    pub(super) fn envelope(&mut self, transport: Transport) -> Result<Header<'body>, Error> {
        let fields = self.fields([
            "name",
            "args",
            "credentials",
            "requestId",
            "expectedRevision",
        ])?;
        if transport == Transport::Query && (fields[3].is_some() || fields[4].is_some()) {
            return Err(Error::UnknownField);
        }
        let mut name = [0u8; MAX_NAME_BYTES];
        let name_len = decode(
            self.input,
            fields[0].ok_or(Error::Invalid)?,
            &mut name,
            &mut self.work,
        )?;
        if name_len == 0 {
            return Err(Error::Invalid);
        }
        if let Some(id) = fields[3]
            && decoded_len(self.input, id, &mut self.work)? == 0
        {
            return Err(Error::Invalid);
        }
        let expected_revision = fields[4]
            .map(|s| safe_u64(s.slice(self.input), &mut self.work))
            .transpose()?;
        Ok(Header {
            body: self.input,
            name,
            name_len,
            args: fields[1],
            credentials: fields[2],
            request_id: fields[3],
            expected_revision,
        })
    }
}

pub(super) struct ObjectCursor {
    pos: usize,
    end: usize,
    finished: bool,
}
pub(super) struct ArrayCursor {
    pos: usize,
    end: usize,
    finished: bool,
}

/// Count and validate the ENTIRE string, storing only a complete UTF-8 prefix.
/// The caller may expose the buffer only if the final decoded length fits.
fn decode_prefix(
    input: &[u8],
    span: Span,
    out: &mut [u8],
    work: &mut Work<'_>,
) -> Result<usize, Error> {
    let mut decoder = Decoder::new(input, span.start, work)?;
    let mut len = 0usize;
    while let Some(unit) = decoder.next(work)? {
        let end = len.checked_add(unit.len).ok_or(Error::Capacity)?;
        if end <= out.len() {
            out[len..end].copy_from_slice(&unit.bytes[..unit.len]);
        }
        len = end;
    }
    if decoder.pos != span.end {
        return Err(Error::Invalid);
    }
    Ok(len)
}

pub(super) fn safe_u64(bytes: &[u8], work: &mut Work<'_>) -> Result<u64, Error> {
    // The largest public safe integer has16digits. Do not perform an unmetered
    // whole-number pass over a mantissa; reject before semantic conversion.
    if bytes.is_empty() || bytes.len() > 16 {
        return Err(Error::Invalid);
    }
    let mut n = 0u64;
    for b in bytes {
        work.debit(1)?;
        if !b.is_ascii_digit() {
            return Err(Error::Invalid);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u64::from(*b - b'0')))
            .filter(|n| *n <= 9_007_199_254_740_991)
            .ok_or(Error::Invalid)?;
    }
    Ok(n)
}

pub(super) fn decoded_len(input: &[u8], span: Span, work: &mut Work<'_>) -> Result<usize, Error> {
    let mut decoder = Decoder::new(input, span.start, work)?;
    let mut len = 0usize;
    while let Some(unit) = decoder.next(work)? {
        len = len.checked_add(unit.len).ok_or(Error::Capacity)?;
    }
    if decoder.pos != span.end {
        return Err(Error::Invalid);
    }
    Ok(len)
}
pub(super) fn decode(
    input: &[u8],
    span: Span,
    out: &mut [u8],
    work: &mut Work<'_>,
) -> Result<usize, Error> {
    let mut decoder = Decoder::new(input, span.start, work)?;
    let mut len = 0usize;
    while let Some(unit) = decoder.next(work)? {
        let end = len
            .checked_add(unit.len)
            .filter(|n| *n <= out.len())
            .ok_or(Error::Capacity)?;
        out[len..end].copy_from_slice(&unit.bytes[..unit.len]);
        len = end;
    }
    if decoder.pos != span.end {
        return Err(Error::Invalid);
    }
    Ok(len)
}
struct Unit {
    bytes: [u8; 4],
    len: usize,
}
struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
}
impl<'a> Decoder<'a> {
    fn new(input: &'a [u8], start: usize, work: &mut Work<'_>) -> Result<Self, Error> {
        let mut d = Self { input, pos: start };
        if d.byte(work)? != b'"' {
            return Err(Error::Invalid);
        }
        Ok(d)
    }
    fn byte(&mut self, work: &mut Work<'_>) -> Result<u8, Error> {
        work.debit(1)?;
        let b = *self.input.get(self.pos).ok_or(Error::Invalid)?;
        self.pos += 1;
        Ok(b)
    }
    fn hex(&mut self, work: &mut Work<'_>) -> Result<u32, Error> {
        let mut n = 0;
        for _ in 0..4 {
            n = n * 16
                + match self.byte(work)? {
                    b @ b'0'..=b'9' => u32::from(b - b'0'),
                    b @ b'a'..=b'f' => u32::from(b - b'a' + 10),
                    b @ b'A'..=b'F' => u32::from(b - b'A' + 10),
                    _ => return Err(Error::Invalid),
                };
        }
        Ok(n)
    }
    fn next(&mut self, work: &mut Work<'_>) -> Result<Option<Unit>, Error> {
        let b = self.byte(work)?;
        if b == b'"' {
            return Ok(None);
        }
        if b < 0x20 {
            return Err(Error::Invalid);
        }
        let mut bytes = [0u8; 4];
        if b == b'\\' {
            let ch = match self.byte(work)? {
                b'"' => '"',
                b'\\' => '\\',
                b'/' => '/',
                b'b' => '\u{8}',
                b'f' => '\u{c}',
                b'n' => '\n',
                b'r' => '\r',
                b't' => '\t',
                b'u' => {
                    let hi = self.hex(work)?;
                    let value = if (0xd800..=0xdbff).contains(&hi) {
                        if self.byte(work)? != b'\\' || self.byte(work)? != b'u' {
                            return Err(Error::Invalid);
                        }
                        let lo = self.hex(work)?;
                        if !(0xdc00..=0xdfff).contains(&lo) {
                            return Err(Error::Invalid);
                        }
                        0x10000 + ((hi - 0xd800) << 10) + lo - 0xdc00
                    } else {
                        hi
                    };
                    char::from_u32(value).ok_or(Error::Invalid)?
                }
                _ => return Err(Error::Invalid),
            };
            let len = ch.encode_utf8(&mut bytes).len();
            return Ok(Some(Unit { bytes, len }));
        }
        bytes[0] = b;
        let len = if b < 0x80 {
            1
        } else if (0xc2..=0xdf).contains(&b) {
            2
        } else if (0xe0..=0xef).contains(&b) {
            3
        } else if (0xf0..=0xf4).contains(&b) {
            4
        } else {
            return Err(Error::Invalid);
        };
        for slot in bytes.iter_mut().take(len).skip(1) {
            *slot = self.byte(work)?;
        }
        std::str::from_utf8(&bytes[..len]).map_err(|_| Error::Invalid)?;
        Ok(Some(Unit { bytes, len }))
    }
}

// Enumerated fixed semantic controls/temporaries, not an allocator or thread-
// stack estimate. All arrays/cursors are real types used by the scanner/helpers.
pub(super) const fn borrowed_control_layout_bytes() -> usize {
    2 * size_of::<Work<'static>>()
        + 4 * size_of::<Decoder<'static>>()
        + 4 * size_of::<Unit>()
        + 4 * size_of::<ObjectCursor>()
        + 3 * size_of::<ArrayCursor>()
        + size_of::<[Option<Span>; 2]>()
        + size_of::<[Option<Span>; 7]>()
        + size_of::<[Option<Span>; 5]>()
        + size_of::<[Option<Span>; 8]>()
        + size_of::<[u8; 32]>()
        + size_of::<[u8; 4]>()
        + 2 * size_of::<Key>()
        + 2 * size_of::<Level>()
        + 4 * size_of::<Span>()
        + 4 * size_of::<usize>()
        + 2 * size_of::<u64>()
}
