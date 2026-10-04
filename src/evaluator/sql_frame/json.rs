//! Allocation-free bounded JSON syntax scanner and compact borrowed views.
//!
//! Not a SQL parser. JSON numbers preserve their exact lexeme; strings decode
//! into a preallocated text slab. Invalid UTF-8, control bytes, malformed escape
//! sequences, lone surrogates and duplicate decoded object keys are rejected.
//! Containers use an explicit 64-entry stack, never recursive calls or serde
//! scratch allocation. The fixed key index and input steps share a work cap.
use std::ops::Range;

use super::control::{Budget, FrameControl};
use super::slab::Slab;
use super::{FrameCell, FrameError, FrameLimits, JsonBank, JsonId, KeyId, MAX_CAPTURE_SLICE, NONE};
const MAX_DEPTH: usize = 64;
const MAX_NUMBER_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct TextRef {
    pub(super) start: u32,
    pub(super) len: u32,
}
impl TextRef {
    pub(super) fn new(start: usize, len: usize) -> Self {
        Self {
            start: start as u32,
            len: len as u32,
        }
    }
    pub(super) fn range(self) -> Range<usize> {
        self.start as usize..self.start as usize + self.len as usize
    }
}
#[derive(Clone, Copy, Debug, Default)]
struct RawRef {
    bank: JsonBank,
    text: TextRef,
}
#[derive(Clone, Copy, Debug, Default)]
struct NumberData {
    raw: RawRef,
    real: f64,
    integer: Option<i64>,
}
#[derive(Clone, Copy, Debug, Default)]
enum NodeKind {
    #[default]
    Null,
    Bool(bool),
    Number(NumberData),
    Text(TextRef),
    Array,
    Object,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct JsonNode {
    kind: NodeKind,
    pub(super) next: u32,
    child: u32,
    key: TextRef,
}
impl Default for JsonNode {
    fn default() -> Self {
        Self {
            kind: NodeKind::Null,
            next: NONE,
            child: NONE,
            key: TextRef::default(),
        }
    }
}
#[derive(Clone, Copy, Default)]
pub(super) struct Document {
    bank: JsonBank,
    bytes: TextRef,
    written: u32,
    root: u32,
    parsed: bool,
}
#[derive(Clone, Copy, Default)]
pub(super) struct KeyEntry {
    bytes: TextRef,
}
#[derive(Clone, Copy)]
pub(super) struct ObjectKey {
    parent: u32,
    child: u32,
    hash: u64,
    text: TextRef,
}
impl Default for ObjectKey {
    fn default() -> Self {
        Self {
            parent: NONE,
            child: NONE,
            hash: 0,
            text: TextRef::default(),
        }
    }
}

pub(super) struct CaptureArena {
    raw: Slab<u8>,
    support: Slab<u8>,
    decoded: Slab<u8>,
    nodes: Slab<JsonNode>,
    documents: Slab<Document>,
    object_keys: Slab<ObjectKey>,
    keys: Slab<KeyEntry>,
    key_bytes: Slab<u8>,
    raw_len: usize,
    support_len: usize,
    decoded_len: usize,
    node_len: usize,
    document_len: usize,
    key_len: usize,
    key_bytes_len: usize,
    pub(super) budget: Budget,
}
impl CaptureArena {
    pub(super) fn new(
        limits: FrameLimits,
        index_slots: usize,
        control: &FrameControl<'_>,
    ) -> Result<Self, FrameError> {
        Ok(Self {
            raw: Slab::new(limits.raw_bytes, control)?,
            support: Slab::new(limits.support_bytes, control)?,
            decoded: Slab::new(limits.decoded_bytes, control)?,
            nodes: Slab::new(limits.nodes, control)?,
            documents: Slab::new(limits.documents, control)?,
            object_keys: Slab::new(index_slots, control)?,
            keys: Slab::new(limits.keys, control)?,
            key_bytes: Slab::new(limits.key_bytes, control)?,
            raw_len: 0,
            support_len: 0,
            decoded_len: 0,
            node_len: 0,
            document_len: 0,
            key_len: 0,
            key_bytes_len: 0,
            budget: Budget::new(limits.parse_work),
        })
    }
    pub(super) fn reserve(&mut self, bank: JsonBank, len: usize) -> Result<JsonId, FrameError> {
        if self.document_len >= self.documents.len()
            || self
                .raw_len
                .checked_add(self.support_len)
                .and_then(|used| used.checked_add(len))
                .is_none_or(|total| total > super::MAX_TEXT_BYTES)
        {
            return Err(FrameError::Capacity);
        }
        let (used, capacity) = match bank {
            JsonBank::Raw => (&mut self.raw_len, self.raw.len()),
            JsonBank::Support => (&mut self.support_len, self.support.len()),
        };
        let end = used
            .checked_add(len)
            .filter(|end| *end <= capacity)
            .ok_or(FrameError::Capacity)?;
        let index = self.document_len;
        self.documents[index] = Document {
            bank,
            bytes: TextRef::new(*used, len),
            written: 0,
            root: NONE,
            parsed: false,
        };
        *used = end;
        self.document_len += 1;
        Ok(JsonId(index as u32))
    }
    fn document(&self, id: JsonId) -> Result<Document, FrameError> {
        self.documents[..self.document_len]
            .get(id.0 as usize)
            .copied()
            .ok_or(FrameError::Invalid)
    }
    pub(super) fn append(&mut self, id: JsonId, bytes: &[u8]) -> Result<(), FrameError> {
        let document = self.document(id)?;
        if document.parsed {
            return Err(FrameError::Invalid);
        }
        if bytes.len() > MAX_CAPTURE_SLICE {
            return Err(FrameError::Capacity);
        }
        let end = (document.written as usize)
            .checked_add(bytes.len())
            .filter(|end| *end <= document.bytes.len as usize)
            .ok_or(FrameError::Capacity)?;
        let start = document.bytes.start as usize + document.written as usize;
        let slab = match document.bank {
            JsonBank::Raw => &mut self.raw,
            JsonBank::Support => &mut self.support,
        };
        slab[start..start + bytes.len()].copy_from_slice(bytes);
        self.documents[id.0 as usize].written = end as u32;
        Ok(())
    }
    pub(super) fn finish(
        &mut self,
        id: JsonId,
        control: &FrameControl<'_>,
    ) -> Result<(), FrameError> {
        self.budget.check(control)?;
        let document = self.document(id)?;
        if document.parsed || document.written != document.bytes.len {
            return Err(FrameError::Invalid);
        }
        let bytes = match document.bank {
            JsonBank::Raw => &self.raw[document.bytes.range()],
            JsonBank::Support => &self.support[document.bytes.range()],
        };
        validate_utf8(bytes, &self.budget, control)?;
        let mut scanner = Scanner {
            input: bytes,
            bank: document.bank,
            base: document.bytes.start,
            position: 0,
            decoded: &mut self.decoded,
            decoded_len: &mut self.decoded_len,
            nodes: &mut self.nodes,
            node_len: &mut self.node_len,
            object_keys: &mut self.object_keys,
            budget: &self.budget,
            control,
            levels: [Level::default(); MAX_DEPTH],
            depth: 0,
        };
        let root = scanner.parse()?;
        self.documents[id.0 as usize].root = root;
        self.documents[id.0 as usize].parsed = true;
        Ok(())
    }
    #[cfg(test)]
    pub(super) fn mapped_regions(&self) -> [super::mapping_tests::Region; 8] {
        [
            self.raw.region(),
            self.support.region(),
            self.decoded.region(),
            self.nodes.region(),
            self.documents.region(),
            self.object_keys.region(),
            self.keys.region(),
            self.key_bytes.region(),
        ]
    }
    #[cfg(test)]
    pub(super) fn remaining_work(&self) -> usize {
        self.budget.remaining_work()
    }
    pub(super) fn failure(&self) -> Option<FrameError> {
        self.budget.failure()
    }
    pub(super) fn has_unfinished_documents(&self) -> bool {
        self.documents[..self.document_len]
            .iter()
            .any(|document| !document.parsed)
    }
    pub(super) fn document_root(&self, id: JsonId) -> Result<u32, FrameError> {
        let document = self.document(id)?;
        if !document.parsed {
            return Err(FrameError::Invalid);
        }
        Ok(document.root)
    }
    pub(super) fn raw_json(&self, id: JsonId) -> Result<&str, FrameError> {
        let document = self.document(id)?;
        if !document.parsed {
            return Err(FrameError::Invalid);
        }
        Ok(self.raw_text(RawRef {
            bank: document.bank,
            text: document.bytes,
        }))
    }
    pub(super) fn value<'a>(
        &'a self,
        id: JsonId,
        control: &'a FrameControl<'a>,
    ) -> Result<ArenaValue<'a>, FrameError> {
        self.budget.check(control)?;
        self.budget.debit(1, control)?;
        Ok(ArenaValue {
            arena: self,
            index: self.document_root(id)?,
            control,
        })
    }
    pub(super) fn node(&self, index: u32) -> JsonNode {
        self.nodes[index as usize]
    }
    pub(super) fn text(&self, value: TextRef) -> &str {
        unsafe { std::str::from_utf8_unchecked(&self.decoded[value.range()]) }
    }
    fn raw_text(&self, value: RawRef) -> &str {
        let bytes = match value.bank {
            JsonBank::Raw => &self.raw[value.text.range()],
            JsonBank::Support => &self.support[value.text.range()],
        };
        unsafe { std::str::from_utf8_unchecked(bytes) }
    }
    pub(super) fn retain_key(&mut self, text: &str) -> Result<KeyId, FrameError> {
        if self.key_len >= self.keys.len() || text.len() > self.key_bytes.len() - self.key_bytes_len
        {
            return Err(FrameError::Capacity);
        }
        let reference = TextRef::new(self.key_bytes_len, text.len());
        self.key_bytes[reference.range()].copy_from_slice(text.as_bytes());
        let index = self.key_len;
        self.keys[index] = KeyEntry { bytes: reference };
        self.key_bytes_len += text.len();
        self.key_len += 1;
        Ok(KeyId(index as u32))
    }
    pub(super) fn key(&self, id: KeyId) -> Result<&str, FrameError> {
        let key = self.keys[..self.key_len]
            .get(id.0 as usize)
            .ok_or(FrameError::Invalid)?;
        Ok(unsafe { std::str::from_utf8_unchecked(&self.key_bytes[key.bytes.range()]) })
    }
    pub(super) fn array_first(
        &self,
        root: u32,
        control: &FrameControl<'_>,
    ) -> Result<u32, FrameError> {
        self.budget.debit(1, control)?;
        let node = self.node(root);
        if !matches!(node.kind, NodeKind::Array) {
            return Err(FrameError::Invalid);
        }
        Ok(node.child)
    }
    pub(super) fn tagged_cell(
        &self,
        root: u32,
        control: &FrameControl<'_>,
    ) -> Result<ParsedCell, FrameError> {
        self.budget.debit(1, control)?;
        let node = self.node(root);
        if matches!(node.kind, NodeKind::Null) {
            return Ok(ParsedCell::Null);
        }
        if !matches!(node.kind, NodeKind::Object) || node.child == NONE {
            return Err(FrameError::Unsupported);
        }
        let tag = self.node(node.child);
        if tag.next != NONE {
            return Err(FrameError::Unsupported);
        }
        match (self.text(tag.key), tag.kind) {
            ("integer", NodeKind::Text(text)) => {
                exact_integer(self.text(text)).map(ParsedCell::Integer)
            }
            ("real", NodeKind::Number(number)) => Ok(ParsedCell::Real(number.real)),
            ("text", NodeKind::Text(text)) => Ok(ParsedCell::Text(text)),
            _ => Err(FrameError::Unsupported),
        }
    }
}

#[derive(Clone, Copy)]
pub(super) enum ParsedCell {
    Null,
    Integer(i64),
    Real(f64),
    Text(TextRef),
}
impl ParsedCell {
    pub(super) fn borrow(self, arena: &CaptureArena) -> FrameCell<'_> {
        match self {
            Self::Null => FrameCell::Null,
            Self::Integer(value) => FrameCell::Integer(value),
            Self::Real(value) => FrameCell::Real(value),
            Self::Text(text) => FrameCell::Text(arena.text(text)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArenaKind {
    Null,
    Boolean,
    Number,
    Text,
    Array,
    Object,
}
#[derive(Clone, Copy)]
pub(crate) struct ArenaValue<'a> {
    arena: &'a CaptureArena,
    index: u32,
    control: &'a FrameControl<'a>,
}
impl<'a> ArenaValue<'a> {
    pub(crate) fn kind(self) -> ArenaKind {
        match self.arena.node(self.index).kind {
            NodeKind::Null => ArenaKind::Null,
            NodeKind::Bool(_) => ArenaKind::Boolean,
            NodeKind::Number(_) => ArenaKind::Number,
            NodeKind::Text(_) => ArenaKind::Text,
            NodeKind::Array => ArenaKind::Array,
            NodeKind::Object => ArenaKind::Object,
        }
    }
    pub(crate) fn is_null(self) -> bool {
        self.kind() == ArenaKind::Null
    }
    pub(crate) fn as_bool(self) -> Option<bool> {
        match self.arena.node(self.index).kind {
            NodeKind::Bool(value) => Some(value),
            _ => None,
        }
    }
    pub(crate) fn as_str(self) -> Option<&'a str> {
        match self.arena.node(self.index).kind {
            NodeKind::Text(text) => Some(self.arena.text(text)),
            _ => None,
        }
    }
    pub(crate) fn number_text(self) -> Option<&'a str> {
        match self.arena.node(self.index).kind {
            NodeKind::Number(number) => Some(self.arena.raw_text(number.raw)),
            _ => None,
        }
    }
    pub(crate) fn as_f64(self) -> Result<Option<f64>, FrameError> {
        self.arena.budget.check(self.control)?;
        self.arena.budget.debit(1, self.control)?;
        Ok(match self.arena.node(self.index).kind {
            NodeKind::Number(number) => Some(number.real),
            _ => None,
        })
    }
    /// Numeric classification is cached once during bounded scanner work. A
    /// repeated native projection never re-walks a raw decimal mantissa.
    pub(crate) fn source_integer(self) -> Result<Option<i64>, FrameError> {
        self.arena.budget.check(self.control)?;
        self.arena.budget.debit(1, self.control)?;
        match self.arena.node(self.index).kind {
            NodeKind::Null => Ok(None),
            NodeKind::Bool(value) => Ok(Some(i64::from(value))),
            NodeKind::Text(text) => {
                // Canonical i64 text is at most20 bytes. Invalid longer text
                // fails in constant time, rather than an uncharged traversal.
                if text.len > 20 {
                    return Err(FrameError::Unsupported);
                }
                self.arena.budget.debit(text.len as usize, self.control)?;
                exact_integer(self.arena.text(text)).map(Some)
            }
            NodeKind::Number(number) => number.integer.map(Some).ok_or(FrameError::Unsupported),
            _ => Err(FrameError::Unsupported),
        }
    }
    pub(crate) fn get(self, key: &str) -> Result<Option<Self>, FrameError> {
        self.arena.budget.check(self.control)?;
        self.arena.budget.debit(1, self.control)?;
        if !matches!(self.arena.node(self.index).kind, NodeKind::Object) {
            return Ok(None);
        }
        let hash = key_hash_checked(self.index, key.as_bytes(), &self.arena.budget, self.control)?;
        let mask = self.arena.object_keys.len() - 1;
        let mut slot = hash as usize & mask;
        for _ in 0..self.arena.object_keys.len() {
            self.arena.budget.debit(1, self.control)?;
            let entry = self.arena.object_keys[slot];
            if entry.parent == NONE {
                return Ok(None);
            }
            if entry.parent == self.index
                && entry.hash == hash
                && equal_text_checked(
                    self.arena.text(entry.text).as_bytes(),
                    key.as_bytes(),
                    &self.arena.budget,
                    self.control,
                )?
            {
                return Ok(Some(Self {
                    arena: self.arena,
                    index: entry.child,
                    control: self.control,
                }));
            }
            slot = (slot + 1) & mask;
        }
        Ok(None)
    }
    pub(crate) fn get_path(self, path: &[&str]) -> Result<Option<Self>, FrameError> {
        if path.len() > MAX_DEPTH {
            return Err(self.arena.budget.fail(FrameError::Capacity));
        }
        let mut value = self;
        for key in path {
            let Some(next) = value.get(key)? else {
                return Ok(None);
            };
            value = next;
        }
        Ok(Some(value))
    }
    pub(crate) fn at(self, ordinal: usize) -> Result<Option<Self>, FrameError> {
        self.arena.budget.check(self.control)?;
        self.arena.budget.debit(1, self.control)?;
        if self.kind() != ArenaKind::Array {
            return Ok(None);
        }
        for (index, entry) in self.children().enumerate() {
            let entry = entry?;
            if index == ordinal {
                return Ok(Some(entry.value));
            }
        }
        Ok(None)
    }
    pub(crate) fn children(self) -> ArenaIter<'a> {
        let node = self.arena.node(self.index);
        ArenaIter {
            arena: self.arena,
            cursor: node.child,
            object: matches!(node.kind, NodeKind::Object),
            control: self.control,
        }
    }
}
pub(crate) struct ArenaEntry<'a> {
    pub key: Option<&'a str>,
    pub value: ArenaValue<'a>,
}
pub(crate) struct ArenaIter<'a> {
    arena: &'a CaptureArena,
    cursor: u32,
    object: bool,
    control: &'a FrameControl<'a>,
}
impl<'a> Iterator for ArenaIter<'a> {
    type Item = Result<ArenaEntry<'a>, FrameError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor == NONE {
            return None;
        }
        if let Err(error) = self
            .arena
            .budget
            .check(self.control)
            .and_then(|()| self.arena.budget.debit(1, self.control))
        {
            self.cursor = NONE;
            return Some(Err(error));
        }
        let index = self.cursor;
        let node = self.arena.node(index);
        self.cursor = node.next;
        Some(Ok(ArenaEntry {
            key: self.object.then(|| self.arena.text(node.key)),
            value: ArenaValue {
                arena: self.arena,
                index,
                control: self.control,
            },
        }))
    }
}

#[derive(Clone, Copy, Default)]
enum State {
    #[default]
    ArrayFirst,
    ArrayValue,
    ArrayAfter,
    ObjectFirst,
    ObjectKey,
    ObjectColon,
    ObjectValue,
    ObjectAfter,
}
#[derive(Clone, Copy, Default)]
struct Level {
    node: u32,
    last: u32,
    state: State,
    key: TextRef,
}
struct Scanner<'a> {
    input: &'a [u8],
    bank: JsonBank,
    base: u32,
    position: usize,
    decoded: &'a mut [u8],
    decoded_len: &'a mut usize,
    nodes: &'a mut [JsonNode],
    node_len: &'a mut usize,
    object_keys: &'a mut [ObjectKey],
    budget: &'a Budget,
    control: &'a FrameControl<'a>,
    levels: [Level; MAX_DEPTH],
    depth: usize,
}
impl Scanner<'_> {
    fn work(&mut self, units: usize) -> Result<(), FrameError> {
        self.budget.debit(units, self.control)
    }
    fn take(&mut self) -> Result<u8, FrameError> {
        let value = *self.input.get(self.position).ok_or(FrameError::Invalid)?;
        self.work(1)?;
        self.position += 1;
        Ok(value)
    }
    fn peek(&self) -> Option<u8> {
        self.input.get(self.position).copied()
    }
    fn whitespace(&mut self) -> Result<(), FrameError> {
        while matches!(self.peek(), Some(b' ' | b'\n' | b'\r' | b'\t')) {
            self.take()?;
        }
        Ok(())
    }
    fn expect(&mut self, byte: u8) -> Result<(), FrameError> {
        if self.take()? != byte {
            return Err(FrameError::Invalid);
        }
        Ok(())
    }
    fn parse(&mut self) -> Result<u32, FrameError> {
        self.whitespace()?;
        let root = self.value(TextRef::default())?;
        while self.depth != 0 {
            self.whitespace()?;
            let top = self.depth - 1;
            let state = self.levels[top].state;
            self.work(1)?;
            match state {
                State::ArrayFirst | State::ArrayValue => {
                    if self.peek() == Some(b']') && matches!(state, State::ArrayFirst) {
                        self.take()?;
                        self.depth -= 1;
                    } else {
                        self.levels[top].state = State::ArrayAfter;
                        let child = self.value(TextRef::default())?;
                        self.attach(top, child);
                    }
                }
                State::ArrayAfter => match self.take()? {
                    b',' => self.levels[top].state = State::ArrayValue,
                    b']' => self.depth -= 1,
                    _ => return Err(FrameError::Invalid),
                },
                State::ObjectFirst | State::ObjectKey => {
                    if self.peek() == Some(b'}') && matches!(state, State::ObjectFirst) {
                        self.take()?;
                        self.depth -= 1;
                    } else {
                        let key = self.string()?;
                        self.insert_key(self.levels[top].node, key)?;
                        self.levels[top].key = key;
                        self.levels[top].state = State::ObjectColon;
                    }
                }
                State::ObjectColon => {
                    self.expect(b':')?;
                    self.levels[top].state = State::ObjectValue;
                }
                State::ObjectValue => {
                    self.levels[top].state = State::ObjectAfter;
                    let child = self.value(self.levels[top].key)?;
                    self.attach(top, child);
                }
                State::ObjectAfter => match self.take()? {
                    b',' => self.levels[top].state = State::ObjectKey,
                    b'}' => self.depth -= 1,
                    _ => return Err(FrameError::Invalid),
                },
            }
        }
        self.whitespace()?;
        if self.position != self.input.len() {
            return Err(FrameError::Invalid);
        }
        Ok(root)
    }
    fn attach(&mut self, level: usize, child: u32) {
        let parent = self.levels[level];
        if parent.last == NONE {
            self.nodes[parent.node as usize].child = child;
        } else {
            self.nodes[parent.last as usize].next = child;
        }
        self.levels[level].last = child;
    }
    fn value(&mut self, key: TextRef) -> Result<u32, FrameError> {
        if *self.node_len >= self.nodes.len() {
            return Err(FrameError::Capacity);
        }
        let index = *self.node_len as u32;
        *self.node_len += 1;
        let kind = match self.peek().ok_or(FrameError::Invalid)? {
            b'n' => {
                self.literal(b"null")?;
                NodeKind::Null
            }
            b't' => {
                self.literal(b"true")?;
                NodeKind::Bool(true)
            }
            b'f' => {
                self.literal(b"false")?;
                NodeKind::Bool(false)
            }
            b'"' => NodeKind::Text(self.string()?),
            b'[' | b'{' => {
                if self.depth == MAX_DEPTH {
                    return Err(FrameError::Capacity);
                }
                let opening = self.take()?;
                self.levels[self.depth] = Level {
                    node: index,
                    last: NONE,
                    state: if opening == b'[' {
                        State::ArrayFirst
                    } else {
                        State::ObjectFirst
                    },
                    key: TextRef::default(),
                };
                self.depth += 1;
                if opening == b'[' {
                    NodeKind::Array
                } else {
                    NodeKind::Object
                }
            }
            b'-' | b'0'..=b'9' => NodeKind::Number(self.number()?),
            _ => return Err(FrameError::Invalid),
        };
        self.nodes[index as usize] = JsonNode {
            kind,
            next: NONE,
            child: NONE,
            key,
        };
        Ok(index)
    }
    fn literal(&mut self, text: &[u8]) -> Result<(), FrameError> {
        for byte in text {
            self.expect(*byte)?;
        }
        Ok(())
    }
    fn take_number(&mut self, start: usize) -> Result<u8, FrameError> {
        if self.position - start >= MAX_NUMBER_BYTES {
            return Err(FrameError::Capacity);
        }
        self.take()
    }
    fn number(&mut self) -> Result<NumberData, FrameError> {
        let start = self.position;
        if self.peek() == Some(b'-') {
            self.take_number(start)?;
        }
        match self.take_number(start)? {
            b'0' => {
                if self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    return Err(FrameError::Invalid);
                }
            }
            b'1'..=b'9' => {
                while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                    self.take_number(start)?;
                }
            }
            _ => return Err(FrameError::Invalid),
        }
        if self.peek() == Some(b'.') {
            self.take_number(start)?;
            if !self.take_number(start)?.is_ascii_digit() {
                return Err(FrameError::Invalid);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.take_number(start)?;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.take_number(start)?;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.take_number(start)?;
            }
            if !self.take_number(start)?.is_ascii_digit() {
                return Err(FrameError::Invalid);
            }
            while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
                self.take_number(start)?;
            }
        }
        if self.position - start > MAX_NUMBER_BYTES {
            return Err(FrameError::Capacity);
        }
        let text = unsafe { std::str::from_utf8_unchecked(&self.input[start..self.position]) };
        // Rust core's numeric parser cannot use alloc; reject overflow/nonfinite
        // immediately without allocating any serde scratch or owned number.
        self.budget.debit(text.len() * 8, self.control)?;
        let real = finite_real(text)?;
        let integer = safe_json_integer(text).ok();
        self.budget.check(self.control)?;
        Ok(NumberData {
            raw: RawRef {
                bank: self.bank,
                text: TextRef::new(self.base as usize + start, self.position - start),
            },
            real,
            integer,
        })
    }
    fn decoded_byte(&mut self, byte: u8) -> Result<(), FrameError> {
        if *self.decoded_len >= self.decoded.len() {
            return Err(FrameError::Capacity);
        }
        self.decoded[*self.decoded_len] = byte;
        *self.decoded_len += 1;
        Ok(())
    }
    fn string(&mut self) -> Result<TextRef, FrameError> {
        self.expect(b'"')?;
        let start = *self.decoded_len;
        loop {
            match self.take()? {
                b'"' => return Ok(TextRef::new(start, *self.decoded_len - start)),
                b'\\' => match self.take()? {
                    b'"' => self.decoded_byte(b'"')?,
                    b'\\' => self.decoded_byte(b'\\')?,
                    b'/' => self.decoded_byte(b'/')?,
                    b'b' => self.decoded_byte(8)?,
                    b'f' => self.decoded_byte(12)?,
                    b'n' => self.decoded_byte(b'\n')?,
                    b'r' => self.decoded_byte(b'\r')?,
                    b't' => self.decoded_byte(b'\t')?,
                    b'u' => {
                        let high = self.hex4()?;
                        let scalar = match high {
                            0xd800..=0xdbff => {
                                self.expect(b'\\')?;
                                self.expect(b'u')?;
                                let low = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err(FrameError::Invalid);
                                }
                                0x10000 + ((high as u32 - 0xd800) << 10) + (low as u32 - 0xdc00)
                            }
                            0xdc00..=0xdfff => return Err(FrameError::Invalid),
                            _ => high as u32,
                        };
                        let character = char::from_u32(scalar).ok_or(FrameError::Invalid)?;
                        let mut utf8 = [0u8; 4];
                        for byte in character.encode_utf8(&mut utf8).bytes() {
                            self.decoded_byte(byte)?;
                        }
                    }
                    _ => return Err(FrameError::Invalid),
                },
                0..=31 => return Err(FrameError::Invalid),
                byte => self.decoded_byte(byte)?,
            }
        }
    }
    fn hex4(&mut self) -> Result<u16, FrameError> {
        let mut result = 0u16;
        for _ in 0..4 {
            let digit = match self.take()? {
                digit @ b'0'..=b'9' => digit - b'0',
                digit @ b'a'..=b'f' => digit - b'a' + 10,
                digit @ b'A'..=b'F' => digit - b'A' + 10,
                _ => return Err(FrameError::Invalid),
            };
            result = result * 16 + digit as u16;
        }
        Ok(result)
    }
    fn insert_key(&mut self, parent: u32, text: TextRef) -> Result<(), FrameError> {
        let bytes = &self.decoded[text.range()];
        let hash = key_hash_checked(parent, bytes, self.budget, self.control)?;
        // Both hashing and comparisons check cancellation in bounded chunks.
        let mask = self.object_keys.len() - 1;
        let mut slot = hash as usize & mask;
        loop {
            self.work(1)?;
            let entry = self.object_keys[slot];
            if entry.parent == NONE {
                self.object_keys[slot] = ObjectKey {
                    parent,
                    child: *self.node_len as u32,
                    hash,
                    text,
                };
                return Ok(());
            }
            if entry.parent == parent
                && entry.hash == hash
                && equal_text_checked(
                    &self.decoded[entry.text.range()],
                    &self.decoded[text.range()],
                    self.budget,
                    self.control,
                )?
            {
                return Err(FrameError::Invalid);
            }
            slot = (slot + 1) & mask;
        }
    }
}
fn key_hash_checked(
    parent: u32,
    bytes: &[u8],
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<u64, FrameError> {
    let mut hash = 0xcbf29ce484222325u64 ^ parent as u64;
    for chunk in bytes.chunks(1024) {
        budget.debit(chunk.len(), control)?;
        for byte in chunk {
            hash = (hash ^ *byte as u64).wrapping_mul(0x100000001b3);
        }
    }
    Ok(hash)
}
fn equal_text_checked(
    left: &[u8],
    right: &[u8],
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<bool, FrameError> {
    budget.debit(1, control)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left.chunks(1024).zip(right.chunks(1024)) {
        budget.debit(left.len(), control)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}
fn validate_utf8(
    input: &[u8],
    budget: &Budget,
    control: &FrameControl<'_>,
) -> Result<(), FrameError> {
    let mut offset = 0;
    while offset < input.len() {
        let end = offset.saturating_add(MAX_CAPTURE_SLICE).min(input.len());
        budget.debit(end - offset, control)?;
        match std::str::from_utf8(&input[offset..end]) {
            Ok(_) => offset = end,
            Err(error) if error.error_len().is_none() && end < input.len() => {
                offset += error.valid_up_to(); // Revisit at most3 split UTF-8 bytes.
            }
            Err(_) => return Err(FrameError::Invalid),
        }
    }
    Ok(())
}
fn finite_real(text: &str) -> Result<f64, FrameError> {
    let number = text.parse::<f64>().map_err(|_| FrameError::Unsupported)?;
    if !number.is_finite() {
        return Err(FrameError::Unsupported);
    }
    Ok(number)
}
fn exact_integer(text: &str) -> Result<i64, FrameError> {
    if text.len() > 20 {
        return Err(FrameError::Unsupported);
    }
    let (negative, digits) = text
        .strip_prefix('-')
        .map_or((false, text), |digits| (true, digits));
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || (negative && digits == "0")
    {
        return Err(FrameError::Unsupported);
    }
    // Accumulate as a negative number so signed i64 MIN is represented exactly.
    let mut value = 0i64;
    for digit in digits.bytes() {
        if !digit.is_ascii_digit() {
            return Err(FrameError::Unsupported);
        }
        value = value
            .checked_mul(10)
            .and_then(|value| value.checked_sub((digit - b'0') as i64))
            .ok_or(FrameError::Unsupported)?;
    }
    if negative {
        Ok(value)
    } else {
        value.checked_neg().ok_or(FrameError::Unsupported)
    }
}

// Evaluate the decimal lexeme, NOT its rounded binary float. In particular,
// 9007199254740990.5 and tiny nonzero 1e-999 are not exact source integers.
fn safe_json_integer(text: &str) -> Result<i64, FrameError> {
    const MAX_SAFE: u64 = 9_007_199_254_740_991;
    let (negative, unsigned) = text
        .strip_prefix('-')
        .map_or((false, text), |value| (true, value));
    let (mantissa, exponent) = unsigned
        .split_once(['e', 'E'])
        .map_or((unsigned, ""), |(mantissa, exponent)| (mantissa, exponent));
    let fraction = mantissa
        .split_once('.')
        .map_or(0, |(_, digits)| digits.len());
    let mut leading = 0usize;
    let mut trailing = 0usize;
    let mut digits = 0usize;
    let mut nonzero = false;
    for byte in mantissa.bytes().filter(|byte| *byte != b'.') {
        digits += 1;
        if byte == b'0' {
            if !nonzero {
                leading += 1;
            }
            trailing += 1;
        } else {
            nonzero = true;
            trailing = 0;
        }
    }
    if !nonzero {
        return Ok(0);
    }
    let (exp_negative, exp_digits) = exponent.strip_prefix('-').map_or(
        (false, exponent.strip_prefix('+').unwrap_or(exponent)),
        |text| (true, text),
    );
    let mut exp = 0i64;
    // Saturation outside the input-length bound cannot turn a nonintegral
    // value into an accepted integer, but avoids integer overflow for e999....
    let saturation = super::MAX_TEXT_BYTES as i64 + 32;
    for digit in exp_digits.bytes() {
        exp = (exp * 10 + (digit - b'0') as i64).min(saturation);
    }
    if exp_negative {
        exp = -exp;
    }
    let scale = exp - fraction as i64 + trailing as i64;
    let significant = digits - leading - trailing;
    if scale < 0 || significant > 16 || scale > 16 {
        return Err(FrameError::Unsupported);
    }
    let mut value = 0u64;
    for (index, byte) in mantissa.bytes().filter(|byte| *byte != b'.').enumerate() {
        if index >= leading && index < digits - trailing {
            value = value * 10 + (byte - b'0') as u64;
        }
    }
    for _ in 0..scale {
        value = value.checked_mul(10).ok_or(FrameError::Unsupported)?;
    }
    if value > MAX_SAFE {
        return Err(FrameError::Unsupported);
    }
    Ok(if negative {
        -(value as i64)
    } else {
        value as i64
    })
}
