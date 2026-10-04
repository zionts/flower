//! Fixed-stack native wire parser and fixed-buffer wire/JSON writer.
use super::*;

#[path = "arguments.rs"]
mod arguments;

#[derive(Clone, Copy, Default)]
struct Level {
    parent: u32,
    remaining: u32,
    object: bool,
}
pub(super) struct Decoder<'a> {
    arena: &'a mut WireArena,
    input: &'a [u8],
    position: usize,
    stack: [Level; MAX_DEPTH],
    depth: usize,
}
impl<'a> Decoder<'a> {
    pub(super) fn decode(
        arena: &'a mut WireArena,
        input: &'a [u8],
        outcome: bool,
        check: &mut Check<'_>,
    ) -> Result<(WireId, u8), WireError> {
        arena.ready()?;
        check()?;
        if input.len() > arena.limits.message_bytes {
            return Err(WireError::Capacity);
        }
        if arena.decoded || arena.node_len != 0 {
            return Err(WireError::Invalid("decode needs a reset arena"));
        }
        let mut parser = Self {
            arena,
            input,
            position: 0,
            stack: [Level::default(); MAX_DEPTH],
            depth: 0,
        };
        let status = if outcome {
            let status = parser.byte(check)?;
            if !matches!(status, SUCCESS | FAILURE) {
                return Err(WireError::Invalid("unknown outcome status"));
            }
            status
        } else {
            SUCCESS
        };
        let (root, count, object) = parser.node(1, check)?;
        if let Some(remaining) = count {
            parser.stack[0] = Level {
                parent: root,
                remaining,
                object,
            };
            parser.depth = 1;
        }
        while parser.depth != 0 {
            let level = parser.stack[parser.depth - 1];
            if level.remaining == 0 {
                parser.depth -= 1;
                if parser.depth != 0 {
                    let parent = parser.stack[parser.depth - 1].parent;
                    let height = parser.arena.nodes[level.parent as usize].height + 1;
                    parser.arena.nodes[parent as usize].height =
                        parser.arena.nodes[parent as usize].height.max(height);
                }
                continue;
            }
            let depth = parser.depth + 1;
            if depth > parser.arena.limits.depth {
                return Err(WireError::Capacity);
            }
            let key = if level.object {
                parser.key(level.parent, check)?
            } else {
                TextRef::default()
            };
            let (child, count, object) = parser.node(depth, check)?;
            parser.arena.link(level.parent, child, key);
            parser.arena.nodes[level.parent as usize].height =
                parser.arena.nodes[level.parent as usize].height.max(2);
            parser.stack[parser.depth - 1].remaining -= 1;
            if let Some(remaining) = count {
                if parser.depth >= MAX_DEPTH {
                    return Err(WireError::Capacity);
                }
                parser.stack[parser.depth] = Level {
                    parent: child,
                    remaining,
                    object,
                };
                parser.depth += 1;
            }
        }
        if parser.position != input.len() {
            return Err(WireError::Invalid("trailing wire bytes"));
        }
        parser.arena.decoded = true;
        check()?;
        Ok((parser.arena.id(root), status))
    }
    fn take(&mut self, len: usize, check: &mut Check<'_>) -> Result<&'a [u8], WireError> {
        let end = self
            .position
            .checked_add(len)
            .filter(|end| *end <= self.input.len())
            .ok_or(WireError::Invalid("truncated wire value"))?;
        self.arena.budget.charge(len, check)?;
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self, check: &mut Check<'_>) -> Result<u8, WireError> {
        Ok(self.take(1, check)?[0])
    }
    fn u32(&mut self, check: &mut Check<'_>) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.take(4, check)?.try_into().unwrap()))
    }
    fn string(&mut self, tag: u8, check: &mut Check<'_>) -> Result<TextRef, WireError> {
        let count = self.u32(check)? as usize;
        let bytes_len = if tag == UTF16 {
            count.checked_mul(2).ok_or(WireError::Capacity)?
        } else {
            count
        };
        // Admission before scan and before a single decoded byte is written.
        if count > self.arena.text.len() - self.arena.text_len {
            return Err(WireError::Capacity);
        }
        let bytes = self.take(bytes_len, check)?;
        let mut decoded = 0usize;
        match tag {
            UTF8 => {
                let mut position = 0;
                while position < bytes.len() {
                    let end = (position + CHECK_INTERVAL).min(bytes.len());
                    self.arena.budget.charge(end - position, check)?;
                    match std::str::from_utf8(&bytes[position..end]) {
                        Ok(_) => position = end,
                        Err(error)
                            if error.error_len().is_none()
                                && end != bytes.len()
                                && error.valid_up_to() != 0 =>
                        {
                            position += error.valid_up_to()
                        }
                        Err(_) => return Err(WireError::Invalid("string is not UTF-8")),
                    }
                }
                decoded = bytes.len();
            }
            LATIN1 => {
                for &byte in bytes {
                    self.arena.budget.charge(1, check)?;
                    decoded = decoded
                        .checked_add(if byte < 128 { 1 } else { 2 })
                        .ok_or(WireError::Capacity)?;
                }
            }
            UTF16 => {
                let units = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]));
                for scalar in char::decode_utf16(units) {
                    self.arena.budget.charge(2, check)?;
                    decoded = decoded
                        .checked_add(
                            scalar
                                .map_err(|_| WireError::Invalid("string has a lone surrogate"))?
                                .len_utf8(),
                        )
                        .ok_or(WireError::Capacity)?;
                }
            }
            _ => return Err(WireError::Invalid("string tag invalid")),
        }
        let start = self.arena.text_len;
        let end = start
            .checked_add(decoded)
            .filter(|end| *end <= self.arena.text.len())
            .ok_or(WireError::Capacity)?;
        match tag {
            UTF8 => {
                for (src, dst) in bytes
                    .chunks(CHECK_INTERVAL)
                    .zip(self.arena.text[start..end].chunks_mut(CHECK_INTERVAL))
                {
                    self.arena.budget.charge(src.len(), check)?;
                    dst.copy_from_slice(src);
                }
            }
            LATIN1 => {
                let mut offset = start;
                for &byte in bytes {
                    let mut buffer = [0; 4];
                    let utf8 = char::from(byte).encode_utf8(&mut buffer).as_bytes();
                    self.arena.budget.charge(utf8.len(), check)?;
                    self.arena.text[offset..offset + utf8.len()].copy_from_slice(utf8);
                    offset += utf8.len();
                }
            }
            UTF16 => {
                let mut offset = start;
                let units = bytes
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]));
                for scalar in char::decode_utf16(units) {
                    let scalar =
                        scalar.map_err(|_| WireError::Invalid("string has a lone surrogate"))?;
                    let mut buffer = [0; 4];
                    let utf8 = scalar.encode_utf8(&mut buffer).as_bytes();
                    self.arena.budget.charge(utf8.len(), check)?;
                    self.arena.text[offset..offset + utf8.len()].copy_from_slice(utf8);
                    offset += utf8.len();
                }
            }
            _ => unreachable!(),
        }
        self.arena.text_len = end;
        Ok(TextRef {
            start: start as u32,
            len: decoded as u32,
        })
    }
    fn key(&mut self, parent: u32, check: &mut Check<'_>) -> Result<TextRef, WireError> {
        if self.arena.key_uses >= self.arena.limits.keys {
            return Err(WireError::Capacity);
        }
        let text = match self.byte(check)? {
            KEY => {
                let index = self.u32(check)? as usize;
                if index >= self.arena.key_len {
                    return Err(WireError::Invalid("unknown key reference"));
                }
                self.arena.keys[index]
            }
            tag @ (UTF8 | LATIN1 | UTF16) => {
                if self.arena.key_len >= self.arena.keys.len() {
                    return Err(WireError::Capacity);
                }
                let text = self.string(tag, check)?;
                self.arena.keys[self.arena.key_len] = text;
                self.arena.key_len += 1;
                text
            }
            _ => return Err(WireError::Invalid("map key is not a string")),
        };
        self.arena.key_use(text.len as usize, check)?;
        self.arena.object_key(parent, text, check)?;
        Ok(text)
    }
    fn node(
        &mut self,
        depth: usize,
        check: &mut Check<'_>,
    ) -> Result<(u32, Option<u32>, bool), WireError> {
        if depth > self.arena.limits.depth || self.arena.node_len >= self.arena.nodes.len() {
            return Err(WireError::Capacity);
        }
        let mut count = None;
        let mut object = false;
        let kind = match self.byte(check)? {
            NULL => Kind::Null,
            FALSE => Kind::Bool(false),
            TRUE => Kind::Bool(true),
            INT => Kind::Integer(i32::from_le_bytes(self.take(4, check)?.try_into().unwrap())),
            FLOAT => {
                let value = f64::from_le_bytes(self.take(8, check)?.try_into().unwrap());
                if !value.is_finite() {
                    return Err(WireError::Invalid("number is not finite"));
                }
                Kind::Real(value)
            }
            tag @ (UTF8 | LATIN1 | UTF16) => Kind::Text(self.string(tag, check)?),
            tag @ (ARRAY | MAP) => {
                let n = self.u32(check)?;
                let remaining = self.input.len() - self.position;
                let minimum = (n as usize)
                    .checked_mul(if tag == MAP { 6 } else { 1 })
                    .ok_or(WireError::Capacity)?;
                if minimum > remaining {
                    return Err(WireError::Invalid("truncated container count"));
                }
                if n as usize > self.arena.nodes.len() - self.arena.node_len - 1
                    || (tag == MAP && n as usize > self.arena.limits.keys - self.arena.key_uses)
                    || (n != 0 && depth >= self.arena.limits.depth)
                {
                    return Err(WireError::Capacity);
                }
                object = tag == MAP;
                count = Some(n);
                if object { Kind::Object } else { Kind::Array }
            }
            _ => return Err(WireError::Invalid("unknown wire tag")),
        };
        let index = self.arena.new_node(kind, check)?;
        Ok((index, count, object))
    }
}

#[derive(Clone, Copy, Default)]
struct WriteLevel {
    parent: u32,
    next: u32,
    ordinal: u32,
}
pub(super) struct Writer<'a> {
    arena: &'a mut WireArena,
    stack: [WriteLevel; MAX_DEPTH],
    depth: usize,
    key_count: u32,
    key_uses: usize,
    logical_keys: usize,
    json: bool,
}
impl<'a> Writer<'a> {
    pub(super) fn encode(
        arena: &'a mut WireArena,
        id: WireId,
        status: Option<u8>,
        json: bool,
        check: &mut Check<'_>,
    ) -> Result<(), WireError> {
        let root = arena.valid(id)?;
        check()?;
        arena.output_len = 0;
        // Fixed scratch: order every object's linked entries by UTF-16 code
        // units using in-place heapsort. Across all objects <=nodes entries.
        Self::orders(arena, check)?;
        if !json {
            for entry in &mut *arena.encode_index {
                arena.budget.charge(1, check)?;
                *entry = IndexEntry::default();
            }
        }
        let mut writer = Self {
            arena,
            stack: [WriteLevel::default(); MAX_DEPTH],
            depth: 0,
            key_count: 0,
            key_uses: 0,
            logical_keys: 0,
            json,
        };
        if let Some(status) = status {
            writer.output(&[status], check)?;
        }
        writer.node(root, check)?;
        while writer.depth != 0 {
            let level = writer.stack[writer.depth - 1];
            let parent = writer.arena.nodes[level.parent as usize];
            if level.ordinal == parent.count {
                if json {
                    writer.output(
                        if matches!(parent.kind, Kind::Object) {
                            b"}"
                        } else {
                            b"]"
                        },
                        check,
                    )?;
                }
                writer.depth -= 1;
                continue;
            }
            let object = matches!(parent.kind, Kind::Object);
            let child = if object {
                writer.arena.order[parent.order_start as usize + level.ordinal as usize]
            } else {
                level.next
            };
            if child == NONE {
                return Err(WireError::Invalid("broken child links"));
            }
            let node = writer.arena.nodes[child as usize];
            if json && level.ordinal != 0 {
                writer.output(b",", check)?;
            }
            if object {
                writer.key(node.key, check)?;
                if json {
                    writer.output(b":", check)?;
                }
            }
            writer.stack[writer.depth - 1].ordinal += 1;
            writer.stack[writer.depth - 1].next = node.next;
            if writer.depth + 1 > writer.arena.limits.depth {
                return Err(WireError::Capacity);
            }
            writer.node(child, check)?;
        }
        check()?;
        Ok(())
    }
    fn orders(arena: &mut WireArena, check: &mut Check<'_>) -> Result<(), WireError> {
        let mut used = 0usize;
        for index in 0..arena.node_len {
            arena.budget.charge(1, check)?;
            let node = arena.nodes[index];
            if !matches!(node.kind, Kind::Object) {
                continue;
            }
            let count = node.count as usize;
            let end = used
                .checked_add(count)
                .filter(|end| *end <= arena.order.len())
                .ok_or(WireError::Capacity)?;
            let mut child = node.child;
            for slot in used..end {
                arena.budget.charge(1, check)?;
                if child == NONE {
                    return Err(WireError::Invalid("broken object links"));
                }
                arena.order[slot] = child;
                child = arena.nodes[child as usize].next;
            }
            if child != NONE {
                return Err(WireError::Invalid("object count mismatch"));
            }
            arena.nodes[index].order_start = used as u32;
            // Heapsort's comparisons, UTF-16 conversions, probes and moves all
            // consume job work. No recursion, allocation or attacker hash growth.
            if count > 1 {
                for root in (0..count / 2).rev() {
                    Self::sift(arena, used, root, count, check)?;
                }
                for last in (1..count).rev() {
                    arena.budget.charge(1, check)?;
                    arena.order.swap(used, used + last);
                    Self::sift(arena, used, 0, last, check)?;
                }
            }
            used = end;
        }
        Ok(())
    }
    fn compare(
        arena: &mut WireArena,
        left: u32,
        right: u32,
        check: &mut Check<'_>,
    ) -> Result<std::cmp::Ordering, WireError> {
        let left = arena.nodes[left as usize].key;
        let right = arena.nodes[right as usize].key;
        // Split fields: comparison can borrow immutable text and mutable budget.
        let a = unsafe { std::str::from_utf8_unchecked(&arena.text[left.range()]) };
        let b = unsafe { std::str::from_utf8_unchecked(&arena.text[right.range()]) };
        let mut a = a.encode_utf16();
        let mut b = b.encode_utf16();
        loop {
            arena.budget.charge(8, check)?;
            match (a.next(), b.next()) {
                (None, None) => return Ok(std::cmp::Ordering::Equal),
                (None, _) => return Ok(std::cmp::Ordering::Less),
                (_, None) => return Ok(std::cmp::Ordering::Greater),
                (Some(a), Some(b)) if a != b => return Ok(a.cmp(&b)),
                _ => {}
            }
        }
    }
    fn sift(
        arena: &mut WireArena,
        base: usize,
        mut root: usize,
        count: usize,
        check: &mut Check<'_>,
    ) -> Result<(), WireError> {
        loop {
            arena.budget.charge(1, check)?;
            let child = root
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(WireError::Capacity)?;
            if child >= count {
                return Ok(());
            }
            let mut max = child;
            if child + 1 < count
                && Self::compare(
                    arena,
                    arena.order[base + child],
                    arena.order[base + child + 1],
                    check,
                )?
                .is_lt()
            {
                max += 1;
            }
            if !Self::compare(
                arena,
                arena.order[base + root],
                arena.order[base + max],
                check,
            )?
            .is_lt()
            {
                return Ok(());
            }
            arena.order.swap(base + root, base + max);
            root = max;
        }
    }
    fn output(&mut self, bytes: &[u8], check: &mut Check<'_>) -> Result<(), WireError> {
        let start = self.arena.output_len;
        let end = start
            .checked_add(bytes.len())
            .filter(|n| *n <= self.arena.output.len())
            .ok_or(WireError::Capacity)?;
        for (src, dst) in bytes
            .chunks(CHECK_INTERVAL)
            .zip(self.arena.output[start..end].chunks_mut(CHECK_INTERVAL))
        {
            self.arena.budget.charge(src.len(), check)?;
            dst.copy_from_slice(src);
        }
        self.arena.output_len = end;
        Ok(())
    }
    fn head(&mut self, tag: u8, count: u32, check: &mut Check<'_>) -> Result<(), WireError> {
        let mut head = [0; 5];
        head[0] = tag;
        head[1..].copy_from_slice(&count.to_le_bytes());
        self.output(&head, check)
    }
    fn text(&mut self, text: TextRef, check: &mut Check<'_>) -> Result<(), WireError> {
        // Borrow separate input slab during writes; no owned intermediary.
        let start = self.arena.output_len;
        let bytes = &self.arena.text[text.range()];
        if !self.json {
            let mut ascii = true;
            for chunk in bytes.chunks(CHECK_INTERVAL) {
                self.arena.budget.charge(chunk.len(), check)?;
                ascii &= chunk.is_ascii();
            }
            let end = start
                .checked_add(5)
                .and_then(|n| n.checked_add(bytes.len()))
                .filter(|n| *n <= self.arena.output.len())
                .ok_or(WireError::Capacity)?;
            self.arena.output[start] = if ascii { LATIN1 } else { UTF8 };
            self.arena.output[start + 1..start + 5].copy_from_slice(&text.len.to_le_bytes());
            self.arena.budget.charge(5, check)?;
            for (src, dst) in bytes
                .chunks(CHECK_INTERVAL)
                .zip(self.arena.output[start + 5..end].chunks_mut(CHECK_INTERVAL))
            {
                self.arena.budget.charge(src.len(), check)?;
                dst.copy_from_slice(src);
            }
            self.arena.output_len = end;
            return Ok(());
        }
        // Preflight exact escaped length, then write; malformed/overflow cannot
        // leave a public partial JSON buffer.
        let mut len = 2usize;
        for &byte in bytes {
            self.arena.budget.charge(1, check)?;
            len = len
                .checked_add(match byte {
                    b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
                    0..=31 => 6,
                    _ => 1,
                })
                .ok_or(WireError::Capacity)?;
        }
        let end = start
            .checked_add(len)
            .filter(|n| *n <= self.arena.output.len())
            .ok_or(WireError::Capacity)?;
        self.arena.budget.charge(len, check)?;
        let mut offset = start;
        self.arena.output[offset] = b'"';
        offset += 1;
        for &byte in bytes {
            self.arena.budget.charge(1, check)?;
            let escape = match byte {
                b'"' => Some(b'"'),
                b'\\' => Some(b'\\'),
                8 => Some(b'b'),
                9 => Some(b't'),
                10 => Some(b'n'),
                12 => Some(b'f'),
                13 => Some(b'r'),
                _ => None,
            };
            if let Some(escape) = escape {
                self.arena.output[offset] = b'\\';
                self.arena.output[offset + 1] = escape;
                offset += 2;
            } else if byte < 32 {
                self.arena.output[offset..offset + 4].copy_from_slice(b"\\u00");
                self.arena.output[offset + 4] = b"0123456789abcdef"[(byte >> 4) as usize];
                self.arena.output[offset + 5] = b"0123456789abcdef"[(byte & 15) as usize];
                offset += 6;
            } else {
                self.arena.output[offset] = byte;
                offset += 1;
            }
        }
        self.arena.output[offset] = b'"';
        debug_assert_eq!(offset + 1, end);
        self.arena.output_len = end;
        Ok(())
    }
    fn key(&mut self, text: TextRef, check: &mut Check<'_>) -> Result<(), WireError> {
        if self.key_uses >= self.arena.limits.keys {
            return Err(WireError::Capacity);
        }
        self.logical_keys = self
            .logical_keys
            .checked_add(text.len as usize)
            .filter(|n| *n <= self.arena.limits.logical_key_bytes)
            .ok_or(WireError::Capacity)?;
        self.key_uses += 1;
        self.arena.budget.charge(text.len as usize + 1, check)?;
        if self.json {
            return self.text(text, check);
        }
        let hash = key_hash(
            0,
            &self.arena.text[text.range()],
            &mut self.arena.budget,
            check,
        )?;
        let mask = self.arena.encode_index.len() - 1;
        let mut slot = hash as usize & mask;
        for _ in 0..self.arena.encode_index.len() {
            self.arena.budget.charge(1, check)?;
            let entry = self.arena.encode_index[slot];
            if entry.parent == NONE {
                self.arena.encode_index[slot] = IndexEntry {
                    parent: 0,
                    hash,
                    text,
                    ordinal: self.key_count,
                };
                self.key_count += 1;
                return self.text(text, check);
            }
            if entry.hash == hash
                && text_equal(
                    &self.arena.text[entry.text.range()],
                    &self.arena.text[text.range()],
                    &mut self.arena.budget,
                    check,
                )?
            {
                return self.head(KEY, entry.ordinal, check);
            }
            slot = (slot + 1) & mask;
        }
        Err(WireError::Capacity)
    }
    fn node(&mut self, index: u32, check: &mut Check<'_>) -> Result<(), WireError> {
        self.arena.budget.charge(1, check)?;
        let node = self.arena.nodes[index as usize];
        match node.kind {
            Kind::Null => self.output(if self.json { b"null" } else { &[NULL] }, check),
            Kind::Bool(value) => {
                if self.json {
                    self.output(if value { b"true" } else { b"false" }, check)
                } else {
                    self.output(&[if value { TRUE } else { FALSE }], check)
                }
            }
            Kind::Integer(value) => {
                if self.json {
                    let mut buffer = ryu_js::Buffer::new();
                    self.output(buffer.format(f64::from(value)).as_bytes(), check)
                } else {
                    self.output(&[INT], check)?;
                    self.output(&value.to_le_bytes(), check)
                }
            }
            Kind::Real(value) => {
                if self.json {
                    let mut buffer = ryu_js::Buffer::new();
                    self.output(buffer.format(value).as_bytes(), check)
                } else {
                    self.output(&[FLOAT], check)?;
                    self.output(&value.to_le_bytes(), check)
                }
            }
            Kind::Text(text) => self.text(text, check),
            Kind::Array | Kind::Object => {
                let object = matches!(node.kind, Kind::Object);
                if self.depth >= MAX_DEPTH
                    || (node.count != 0 && self.depth + 1 >= self.arena.limits.depth)
                {
                    return Err(WireError::Capacity);
                }
                if self.json {
                    self.output(if object { b"{" } else { b"[" }, check)?;
                } else {
                    self.head(if object { MAP } else { ARRAY }, node.count, check)?;
                }
                self.stack[self.depth] = WriteLevel {
                    parent: index,
                    next: node.child,
                    ordinal: 0,
                };
                self.depth += 1;
                Ok(())
            }
        }
    }
}
