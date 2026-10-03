//! Quota-first SQL-only GUEST_ABI arena: never constructs an owned JSON tree.
//!
//! All dynamic state is mapped, pre-touched and admitted before input. The
//! finite parser/writer stacks and owning control fit CONTROL_BYTES. This is a
//! bound on this arena's user-space retained bytes, NOT a proof of process-wide
//! native/physical memory (kernel metadata, OS reclaim and Wasm remain HOLD).
#[path = "sql_bridge/codec.rs"]
mod codec;
#[path = "sql_bridge/slab.rs"]
mod slab;
#[cfg(test)]
#[path = "sql_bridge/tests.rs"]
mod tests;

use super::wire::{
    ARRAY, FAILURE, FALSE, FLOAT, INT, KEY, LATIN1, MAP, NULL, SUCCESS, TRUE, UTF8, UTF16,
};
use slab::{Slab, mapped_bytes, page_size};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) const MAX_ARENA_BYTES: usize = 32 * 1024 * 1024;
pub(crate) const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_NODES: usize = 131_072;
const MAX_KEYS: usize = 131_072;
const MAX_LOGICAL_BYTES: usize = 16 * 1024 * 1024;
const MAX_WORK: usize = 256 * 1024 * 1024;
const MAX_DEPTH: usize = 64;
const CONTROL_BYTES: usize = 64 * 1024;
const NONE: u32 = u32::MAX;
const CHECK_INTERVAL: usize = 4096;
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
type Check<'a> = dyn FnMut() -> Result<(), WireError> + 'a;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireError {
    Capacity,
    WorkLimit,
    Cancelled,
    Unsupported,
    Invalid(&'static str),
    StaleId,
    Poisoned,
}
impl std::fmt::Display for WireError {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(match self {
            Self::Capacity => "SQL wire capacity exceeded",
            Self::WorkLimit => "SQL wire cumulative work exhausted",
            Self::Cancelled => "SQL wire cancelled",
            Self::Unsupported => "SQL wire mappings unsupported",
            Self::Invalid(message) => message,
            Self::StaleId => "stale or foreign SQL wire ID",
            Self::Poisoned => "SQL wire callback needs reset",
        })
    }
}
impl std::error::Error for WireError {}

#[derive(Clone, Copy, Debug)]
pub(crate) struct WireLimits {
    pub message_bytes: usize,
    pub text_bytes: usize,
    pub nodes: usize,
    pub keys: usize,
    /// Includes every key use (including KEY references), not only stored bytes.
    pub logical_key_bytes: usize,
    pub output_bytes: usize,
    pub depth: usize,
    pub job_work: usize,
}
impl Default for WireLimits {
    fn default() -> Self {
        Self {
            message_bytes: MAX_MESSAGE_BYTES,
            text_bytes: MAX_TEXT_BYTES,
            nodes: 65_536,
            keys: 65_536,
            logical_key_bytes: MAX_LOGICAL_BYTES,
            output_bytes: MAX_MESSAGE_BYTES,
            depth: MAX_DEPTH,
            job_work: 64 * 1024 * 1024,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WireId {
    owner: u64,
    generation: u64,
    index: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireOutcome {
    Success(WireId),
    Failure {
        code: WireId,
        message: WireId,
        details: Option<WireId>,
    },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WireKind {
    Null,
    Bool,
    Integer,
    Real,
    Text,
    Array,
    Object,
}
#[derive(Clone, Copy, Default)]
struct TextRef {
    start: u32,
    len: u32,
}
impl TextRef {
    fn range(self) -> std::ops::Range<usize> {
        self.start as usize..self.start as usize + self.len as usize
    }
}
#[derive(Clone, Copy, Default)]
enum Kind {
    #[default]
    Null,
    Bool(bool),
    Integer(i32),
    Real(f64),
    Text(TextRef),
    Array,
    Object,
}
#[derive(Clone, Copy)]
struct Node {
    kind: Kind,
    key: TextRef,
    parent: u32,
    child: u32,
    last: u32,
    next: u32,
    count: u32,
    height: u8,
    order_start: u32,
}
impl Default for Node {
    fn default() -> Self {
        Self {
            kind: Kind::Null,
            key: TextRef::default(),
            parent: NONE,
            child: NONE,
            last: NONE,
            next: NONE,
            count: 0,
            height: 1,
            order_start: 0,
        }
    }
}
#[derive(Clone, Copy)]
struct IndexEntry {
    parent: u32,
    hash: u64,
    text: TextRef,
    ordinal: u32,
}
impl Default for IndexEntry {
    fn default() -> Self {
        Self {
            parent: NONE,
            hash: 0,
            text: TextRef::default(),
            ordinal: 0,
        }
    }
}
struct Budget {
    remaining: usize,
    since_check: usize,
}
impl Budget {
    fn charge(&mut self, amount: usize, check: &mut Check<'_>) -> Result<(), WireError> {
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or(WireError::WorkLimit)?;
        self.since_check = self
            .since_check
            .checked_add(amount)
            .ok_or(WireError::WorkLimit)?;
        if self.since_check >= CHECK_INTERVAL {
            self.since_check = 0;
            check()?;
        }
        Ok(())
    }
}

pub(crate) struct WireArena {
    limits: WireLimits,
    text: Slab<u8>,
    nodes: Slab<Node>,
    keys: Slab<TextRef>,
    object_index: Slab<IndexEntry>,
    encode_index: Slab<IndexEntry>,
    order: Slab<u32>,
    output: Slab<u8>,
    text_len: usize,
    node_len: usize,
    key_len: usize,
    key_uses: usize,
    logical_key_bytes: usize,
    output_len: usize,
    owner: u64,
    generation: u64,
    failed: bool,
    decoded: bool,
    bytes: usize,
    budget: Budget,
}
impl WireArena {
    /// Maps only after every limit/layout/rounded-byte sum has been admitted.
    pub(crate) fn new(limits: WireLimits) -> Result<Self, WireError> {
        if limits.message_bytes > MAX_MESSAGE_BYTES
            || limits.text_bytes > MAX_TEXT_BYTES
            || limits.nodes > MAX_NODES
            || limits.keys > MAX_KEYS
            || limits.logical_key_bytes > MAX_LOGICAL_BYTES
            || limits.output_bytes > MAX_MESSAGE_BYTES
            || limits.depth == 0
            || limits.depth > MAX_DEPTH
            || limits.job_work > MAX_WORK
        {
            return Err(WireError::Capacity);
        }
        let page = page_size()?;
        let slots = limits
            .keys
            .max(1)
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .ok_or(WireError::Capacity)?;
        let pieces = [
            mapped_bytes::<u8>(limits.text_bytes, page)?,
            mapped_bytes::<Node>(limits.nodes, page)?,
            mapped_bytes::<TextRef>(limits.keys, page)?,
            mapped_bytes::<IndexEntry>(slots, page)?,
            mapped_bytes::<IndexEntry>(slots, page)?,
            mapped_bytes::<u32>(limits.nodes, page)?,
            mapped_bytes::<u8>(limits.output_bytes, page)?,
        ];
        let bytes = pieces
            .into_iter()
            .try_fold(CONTROL_BYTES, |n, piece| n.checked_add(piece))
            .filter(|n| *n <= MAX_ARENA_BYTES)
            .ok_or(WireError::Capacity)?;
        // These are compiler-checked finite controls, not a postparse estimate.
        const {
            assert!(
                size_of::<WireArena>()
                    + size_of::<codec::Decoder<'_>>()
                    + size_of::<codec::Writer<'_>>()
                    + 8192
                    < CONTROL_BYTES
            );
        }
        // Keep Flower's declared Rust 1.96 MSRV; renamed in Rust 1.99.
        #[allow(deprecated)]
        let owner = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| WireError::Capacity)?;
        Ok(Self {
            limits,
            text: Slab::new(limits.text_bytes, page)?,
            nodes: Slab::new(limits.nodes, page)?,
            keys: Slab::new(limits.keys, page)?,
            object_index: Slab::new(slots, page)?,
            encode_index: Slab::new(slots, page)?,
            order: Slab::new(limits.nodes, page)?,
            output: Slab::new(limits.output_bytes, page)?,
            text_len: 0,
            node_len: 0,
            key_len: 0,
            key_uses: 0,
            logical_key_bytes: 0,
            output_len: 0,
            owner,
            generation: 1,
            failed: false,
            decoded: false,
            bytes,
            budget: Budget {
                remaining: limits.job_work,
                since_check: 0,
            },
        })
    }
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.bytes
    }
    pub(crate) fn work_remaining(&self) -> usize {
        self.budget.remaining
    }
    pub(crate) fn reset(&mut self) -> Result<(), WireError> {
        self.reset_checked(&mut || Ok(()))
    }
    pub(crate) fn reset_checked(&mut self, check: &mut Check<'_>) -> Result<(), WireError> {
        // Invalidate handles even if cancellation/work prevents clearing state.
        self.failed = true;
        self.generation = self.generation.checked_add(1).ok_or(WireError::Capacity)?;
        check()?;
        for entry in &mut *self.object_index {
            self.budget.charge(1, check)?;
            *entry = IndexEntry::default();
        }
        for entry in &mut *self.encode_index {
            self.budget.charge(1, check)?;
            *entry = IndexEntry::default();
        }
        self.text_len = 0;
        self.node_len = 0;
        self.key_len = 0;
        self.key_uses = 0;
        self.logical_key_bytes = 0;
        self.output_len = 0;
        self.decoded = false;
        self.failed = false;
        Ok(())
    }
    fn ready(&self) -> Result<(), WireError> {
        if self.failed {
            Err(WireError::Poisoned)
        } else {
            Ok(())
        }
    }
    fn complete<T>(&mut self, result: Result<T, WireError>) -> Result<T, WireError> {
        if result.is_err() {
            self.failed = true;
            self.output_len = 0;
        }
        result
    }
    fn id(&self, index: u32) -> WireId {
        WireId {
            owner: self.owner,
            generation: self.generation,
            index,
        }
    }
    fn valid(&self, id: WireId) -> Result<u32, WireError> {
        self.ready()?;
        if id.owner != self.owner
            || id.generation != self.generation
            || id.index as usize >= self.node_len
        {
            Err(WireError::StaleId)
        } else {
            Ok(id.index)
        }
    }
    fn text_ref(&self, text: TextRef) -> &str {
        // Only validated UTF-8/char normalization and &str copying creates refs.
        unsafe { std::str::from_utf8_unchecked(&self.text[text.range()]) }
    }
    fn new_node(&mut self, kind: Kind, check: &mut Check<'_>) -> Result<u32, WireError> {
        if self.node_len >= self.nodes.len() {
            return Err(WireError::Capacity);
        }
        self.budget.charge(1, check)?;
        let index = self.node_len as u32;
        self.nodes[self.node_len] = Node {
            kind,
            ..Node::default()
        };
        self.node_len += 1;
        Ok(index)
    }
    fn copy_text(&mut self, value: &str, check: &mut Check<'_>) -> Result<TextRef, WireError> {
        let end = self
            .text_len
            .checked_add(value.len())
            .filter(|end| *end <= self.text.len())
            .ok_or(WireError::Capacity)?;
        let reference = TextRef {
            start: self.text_len as u32,
            len: value.len() as u32,
        };
        for (source, dest) in value
            .as_bytes()
            .chunks(CHECK_INTERVAL)
            .zip(self.text[self.text_len..end].chunks_mut(CHECK_INTERVAL))
        {
            self.budget.charge(source.len(), check)?;
            dest.copy_from_slice(source);
        }
        self.text_len = end;
        Ok(reference)
    }
    fn key_use(&mut self, len: usize, check: &mut Check<'_>) -> Result<(), WireError> {
        if self.key_uses >= self.limits.keys {
            return Err(WireError::Capacity);
        }
        let end = self
            .logical_key_bytes
            .checked_add(len)
            .filter(|end| *end <= self.limits.logical_key_bytes)
            .ok_or(WireError::Capacity)?;
        self.budget
            .charge(len.checked_add(1).ok_or(WireError::WorkLimit)?, check)?;
        self.key_uses += 1;
        self.logical_key_bytes = end;
        Ok(())
    }
    fn object_key(
        &mut self,
        parent: u32,
        text: TextRef,
        check: &mut Check<'_>,
    ) -> Result<(), WireError> {
        let hash = key_hash(parent, &self.text[text.range()], &mut self.budget, check)?;
        let mask = self.object_index.len() - 1;
        let mut slot = hash as usize & mask;
        // Finite probe bound even if index invariants ever change.
        for _ in 0..self.object_index.len() {
            self.budget.charge(1, check)?;
            let entry = self.object_index[slot];
            if entry.parent == NONE {
                self.object_index[slot] = IndexEntry {
                    parent,
                    hash,
                    text,
                    ordinal: 0,
                };
                return Ok(());
            }
            if entry.parent == parent
                && entry.hash == hash
                && text_equal(
                    &self.text[entry.text.range()],
                    &self.text[text.range()],
                    &mut self.budget,
                    check,
                )?
            {
                return Err(WireError::Invalid("duplicate decoded map key"));
            }
            slot = (slot + 1) & mask;
        }
        Err(WireError::Capacity)
    }
    fn link(&mut self, parent: u32, child: u32, key: TextRef) {
        let prior = self.nodes[parent as usize].last;
        if prior == NONE {
            self.nodes[parent as usize].child = child;
        } else {
            self.nodes[prior as usize].next = child;
        }
        self.nodes[parent as usize].last = child;
        self.nodes[parent as usize].count += 1;
        self.nodes[child as usize].parent = parent;
        self.nodes[child as usize].key = key;
    }
    pub(crate) fn decode(&mut self, bytes: &[u8]) -> Result<WireId, WireError> {
        self.decode_checked(bytes, &mut || Ok(()))
    }
    pub(crate) fn decode_checked(
        &mut self,
        bytes: &[u8],
        check: &mut Check<'_>,
    ) -> Result<WireId, WireError> {
        self.ready()?;
        let result = codec::Decoder::decode(self, bytes, false, check).map(|(root, _)| root);
        self.complete(result)
    }
    pub(crate) fn decode_outcome(&mut self, bytes: &[u8]) -> Result<WireOutcome, WireError> {
        self.decode_outcome_checked(bytes, &mut || Ok(()))
    }
    pub(crate) fn decode_outcome_checked(
        &mut self,
        bytes: &[u8],
        check: &mut Check<'_>,
    ) -> Result<WireOutcome, WireError> {
        self.ready()?;
        let result = codec::Decoder::decode(self, bytes, true, check).and_then(|(root, status)| {
            if status == SUCCESS {
                return Ok(WireOutcome::Success(root));
            }
            let value = self.value(root)?;
            if value.kind() != WireKind::Object {
                return Err(WireError::Invalid("failure is not a map"));
            }
            let mut code = None;
            let mut message = None;
            let mut details = None;
            for entry in value.iter()? {
                match entry.key {
                    Some("code") => code = Some(entry.value.id()),
                    Some("message") => message = Some(entry.value.id()),
                    Some("details") => details = Some(entry.value.id()),
                    _ => return Err(WireError::Invalid("unknown failure field")),
                }
            }
            let (Some(code), Some(message)) = (code, message) else {
                return Err(WireError::Invalid("failure needs code and message"));
            };
            if self.value(code)?.as_str().is_none() || self.value(message)?.as_str().is_none() {
                return Err(WireError::Invalid(
                    "failure code and message must be strings",
                ));
            }
            Ok(WireOutcome::Failure {
                code,
                message,
                details,
            })
        });
        self.complete(result)
    }
    pub(crate) fn value(&self, id: WireId) -> Result<WireValue<'_>, WireError> {
        Ok(WireValue {
            arena: self,
            index: self.valid(id)?,
        })
    }
    fn scalar(&mut self, kind: Kind) -> Result<WireId, WireError> {
        self.ready()?;
        let result = self
            .new_node(kind, &mut || Ok(()))
            .map(|index| self.id(index));
        self.complete(result)
    }
    pub(crate) fn null(&mut self) -> Result<WireId, WireError> {
        self.scalar(Kind::Null)
    }
    pub(crate) fn boolean(&mut self, value: bool) -> Result<WireId, WireError> {
        self.scalar(Kind::Bool(value))
    }
    pub(crate) fn integer(&mut self, value: i32) -> Result<WireId, WireError> {
        self.scalar(Kind::Integer(value))
    }
    pub(crate) fn real(&mut self, value: f64) -> Result<WireId, WireError> {
        if !value.is_finite() {
            return self.complete(Err(WireError::Invalid("number is not finite")));
        }
        self.scalar(Kind::Real(value))
    }
    pub(crate) fn text(&mut self, value: &str) -> Result<WireId, WireError> {
        self.text_checked(value, &mut || Ok(()))
    }
    pub(crate) fn text_checked(
        &mut self,
        value: &str,
        check: &mut Check<'_>,
    ) -> Result<WireId, WireError> {
        self.ready()?;
        let result = (|| {
            check()?;
            if self.node_len >= self.nodes.len() {
                return Err(WireError::Capacity);
            }
            let text = self.copy_text(value, check)?;
            self.new_node(Kind::Text(text), check)
                .map(|index| self.id(index))
        })();
        self.complete(result)
    }
    pub(crate) fn array(&mut self) -> Result<WireId, WireError> {
        self.scalar(Kind::Array)
    }
    pub(crate) fn object(&mut self) -> Result<WireId, WireError> {
        self.scalar(Kind::Object)
    }
    pub(crate) fn push(&mut self, parent: WireId, child: WireId) -> Result<(), WireError> {
        self.attach(parent, None, child, &mut || Ok(()))
    }
    pub(crate) fn insert(
        &mut self,
        parent: WireId,
        key: &str,
        child: WireId,
    ) -> Result<(), WireError> {
        self.insert_checked(parent, key, child, &mut || Ok(()))
    }
    pub(crate) fn insert_checked(
        &mut self,
        parent: WireId,
        key: &str,
        child: WireId,
        check: &mut Check<'_>,
    ) -> Result<(), WireError> {
        self.attach(parent, Some(key), child, check)
    }
    fn attach(
        &mut self,
        parent: WireId,
        key: Option<&str>,
        child: WireId,
        check: &mut Check<'_>,
    ) -> Result<(), WireError> {
        self.ready()?;
        let result = (|| {
            check()?;
            let p = self.valid(parent)?;
            let c = self.valid(child)?;
            if !matches!(
                (self.nodes[p as usize].kind, key),
                (Kind::Array, None) | (Kind::Object, Some(_))
            ) {
                return Err(WireError::Invalid("container/key mismatch"));
            }
            if self.nodes[c as usize].parent != NONE {
                return Err(WireError::Invalid("node already attached"));
            }
            // Preflight ancestors and subtree height before mutating any link.
            let mut cursor = p;
            let mut height = self.nodes[c as usize].height as usize;
            let mut depth = 0;
            while cursor != NONE {
                self.budget.charge(1, check)?;
                if cursor == c {
                    return Err(WireError::Invalid("wire builder cycle"));
                }
                height += 1;
                depth += 1;
                if height > self.limits.depth || depth > self.limits.depth {
                    return Err(WireError::Capacity);
                }
                height = height.max(self.nodes[cursor as usize].height as usize);
                cursor = self.nodes[cursor as usize].parent;
            }
            let text = if let Some(key) = key {
                self.key_use(key.len(), check)?;
                let text = self.copy_text(key, check)?;
                self.object_key(p, text, check)?;
                text
            } else {
                TextRef::default()
            };
            self.link(p, c, text);
            let mut cursor = p;
            let mut height = self.nodes[c as usize].height + 1;
            while cursor != NONE {
                self.nodes[cursor as usize].height = self.nodes[cursor as usize].height.max(height);
                height = self.nodes[cursor as usize].height + 1;
                cursor = self.nodes[cursor as usize].parent;
            }
            Ok(())
        })();
        self.complete(result)
    }
    pub(crate) fn encode(&mut self, id: WireId) -> Result<&[u8], WireError> {
        self.encode_checked(id, &mut || Ok(()))
    }
    pub(crate) fn encode_checked(
        &mut self,
        id: WireId,
        check: &mut Check<'_>,
    ) -> Result<&[u8], WireError> {
        let result = codec::Writer::encode(self, id, None, false, check);
        self.complete(result)?;
        Ok(&self.output[..self.output_len])
    }
    pub(crate) fn encode_outcome(&mut self, outcome: WireOutcome) -> Result<&[u8], WireError> {
        self.encode_outcome_checked(outcome, &mut || Ok(()))
    }
    pub(crate) fn encode_outcome_checked(
        &mut self,
        outcome: WireOutcome,
        check: &mut Check<'_>,
    ) -> Result<&[u8], WireError> {
        // Failures decoded by this arena have a transport object parent. For
        // constructed failures prefer failure(code,message,details) below.
        let result = (|| {
            let (id, status) = match outcome {
                WireOutcome::Success(id) => (id, SUCCESS),
                WireOutcome::Failure {
                    code,
                    message,
                    details,
                } => {
                    let c = self.valid(code)?;
                    let m = self.valid(message)?;
                    let parent = self.nodes[c as usize].parent;
                    if parent == NONE || self.nodes[m as usize].parent != parent {
                        return Err(WireError::Invalid(
                            "failure fields need their transport object",
                        ));
                    }
                    let root = self.id(parent);
                    let value = self.value(root)?;
                    if value.kind() != WireKind::Object
                        || value.len() != Some(2 + usize::from(details.is_some()))
                        || value.member("code").map(|v| v.id()) != Some(code)
                        || value.member("message").map(|v| v.id()) != Some(message)
                        || value.member("details").map(|v| v.id()) != details
                    {
                        return Err(WireError::Invalid("invalid failure fields"));
                    }
                    if self.value(code)?.as_str().is_none()
                        || self.value(message)?.as_str().is_none()
                    {
                        return Err(WireError::Invalid("failure strings required"));
                    }
                    (root, FAILURE)
                }
            };
            codec::Writer::encode(self, id, Some(status), false, check)
        })();
        self.complete(result)?;
        Ok(&self.output[..self.output_len])
    }
    pub(crate) fn failure(
        &mut self,
        code: &str,
        message: &str,
        details: Option<WireId>,
    ) -> Result<WireOutcome, WireError> {
        let root = self.object()?;
        let code_id = self.text(code)?;
        self.insert(root, "code", code_id)?;
        if let Some(details) = details {
            self.insert(root, "details", details)?;
        }
        let message_id = self.text(message)?;
        self.insert(root, "message", message_id)?;
        Ok(WireOutcome::Failure {
            code: code_id,
            message: message_id,
            details,
        })
    }
    pub(crate) fn json(&mut self, id: WireId) -> Result<&[u8], WireError> {
        self.json_checked(id, &mut || Ok(()))
    }
    pub(crate) fn json_checked(
        &mut self,
        id: WireId,
        check: &mut Check<'_>,
    ) -> Result<&[u8], WireError> {
        let result = codec::Writer::encode(self, id, None, true, check);
        self.complete(result)?;
        Ok(&self.output[..self.output_len])
    }
}
fn key_hash(
    parent: u32,
    bytes: &[u8],
    budget: &mut Budget,
    check: &mut Check<'_>,
) -> Result<u64, WireError> {
    let mut hash = 0xcbf29ce484222325u64 ^ u64::from(parent);
    for chunk in bytes.chunks(CHECK_INTERVAL) {
        budget.charge(chunk.len(), check)?;
        for byte in chunk {
            hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
        }
    }
    Ok(hash)
}
fn text_equal(
    left: &[u8],
    right: &[u8],
    budget: &mut Budget,
    check: &mut Check<'_>,
) -> Result<bool, WireError> {
    budget.charge(1, check)?;
    if left.len() != right.len() {
        return Ok(false);
    }
    for (left, right) in left
        .chunks(CHECK_INTERVAL)
        .zip(right.chunks(CHECK_INTERVAL))
    {
        budget.charge(left.len() + right.len(), check)?;
        if left != right {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy)]
pub(crate) struct WireValue<'a> {
    arena: &'a WireArena,
    index: u32,
}
impl<'a> WireValue<'a> {
    fn node(self) -> Node {
        self.arena.nodes[self.index as usize]
    }
    pub(crate) fn id(self) -> WireId {
        self.arena.id(self.index)
    }
    pub(crate) fn kind(self) -> WireKind {
        match self.node().kind {
            Kind::Null => WireKind::Null,
            Kind::Bool(_) => WireKind::Bool,
            Kind::Integer(_) => WireKind::Integer,
            Kind::Real(_) => WireKind::Real,
            Kind::Text(_) => WireKind::Text,
            Kind::Array => WireKind::Array,
            Kind::Object => WireKind::Object,
        }
    }
    pub(crate) fn as_bool(self) -> Option<bool> {
        if let Kind::Bool(v) = self.node().kind {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn as_i32(self) -> Option<i32> {
        if let Kind::Integer(v) = self.node().kind {
            Some(v)
        } else {
            None
        }
    }
    pub(crate) fn as_f64(self) -> Option<f64> {
        match self.node().kind {
            Kind::Integer(v) => Some(f64::from(v)),
            Kind::Real(v) => Some(v),
            _ => None,
        }
    }
    pub(crate) fn as_str(self) -> Option<&'a str> {
        if let Kind::Text(v) = self.node().kind {
            Some(self.arena.text_ref(v))
        } else {
            None
        }
    }
    pub(crate) fn len(self) -> Option<usize> {
        match self.node().kind {
            Kind::Array | Kind::Object => Some(self.node().count as usize),
            _ => None,
        }
    }
    /// Linear, allocation-free lookup. Accessors alone do not charge job work;
    /// callers must not repeatedly traverse untrusted trees without their own
    /// job budget/check. Decode/encode/build are cumulatively work-charged.
    pub(crate) fn member(self, key: &str) -> Option<Self> {
        if self.kind() != WireKind::Object {
            return None;
        }
        self.iter()
            .ok()?
            .find(|entry| entry.key == Some(key))
            .map(|entry| entry.value)
    }
    pub(crate) fn index(self, index: usize) -> Option<Self> {
        if self.kind() != WireKind::Array {
            return None;
        }
        self.iter().ok()?.nth(index).map(|entry| entry.value)
    }
    pub(crate) fn iter(self) -> Result<WireIter<'a>, WireError> {
        if !matches!(self.node().kind, Kind::Array | Kind::Object) {
            return Err(WireError::Invalid("value is not a container"));
        }
        Ok(WireIter {
            arena: self.arena,
            next: self.node().child,
            remaining: self.node().count,
            object: matches!(self.node().kind, Kind::Object),
        })
    }
}
pub(crate) struct WireEntry<'a> {
    pub key: Option<&'a str>,
    pub value: WireValue<'a>,
}
pub(crate) struct WireIter<'a> {
    arena: &'a WireArena,
    next: u32,
    remaining: u32,
    object: bool,
}
impl<'a> Iterator for WireIter<'a> {
    type Item = WireEntry<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.next == NONE {
            return None;
        }
        let index = self.next;
        let node = self.arena.nodes[index as usize];
        self.next = node.next;
        self.remaining -= 1;
        Some(WireEntry {
            key: self.object.then(|| self.arena.text_ref(node.key)),
            value: WireValue {
                arena: self.arena,
                index,
            },
        })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining as usize, Some(self.remaining as usize))
    }
}
impl ExactSizeIterator for WireIter<'_> {}
