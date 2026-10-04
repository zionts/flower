//! Allocation-free Flower byte-key reads. Never calls an ordinary reader.
use super::btree::Btree;
use super::btree_base::{BRANCH, BranchAccessor, Checksum, LEAF, LeafAccessor, MAX_BTREE_DEPTH};
use super::page_store::{Page, PageImpl, PageNumber};
use crate::resident::{charge, fault, require_active};
use crate::{AccessGuard, Key, ResidentReadFault, Result};
use core::cmp::Ordering;
use core::mem::size_of;
use core::ops::Bound;

/// Maximum requested size of either byte-key component.
pub const RESIDENT_COMPONENT_CAPACITY: usize = 4096;
/// Inline capacity (including tuple length prefix); no heap-backed keys.
pub const RESIDENT_KEY_CAPACITY: usize = 8202;

/// An encoded request key. Construct and pre-touch this outside the resident
/// scope when its native storage must be admitted before taking exclusion.
pub struct ResidentKey {
    bytes: [u8; RESIDENT_KEY_CAPACITY],
    length: usize,
    paired: bool,
}
impl ResidentKey {
    /// Encode a plain byte key, without allocation.
    pub fn plain(key: &[u8]) -> Result<Self> {
        Self::encode(None, key)
    }
    /// Encode exactly redb's two-variable-width-component tuple format.
    pub fn pair(partition: &[u8], key: &[u8]) -> Result<Self> {
        Self::encode(Some(partition), key)
    }
    fn encode(partition: Option<&[u8]>, key: &[u8]) -> Result<Self> {
        if key.len() > RESIDENT_COMPONENT_CAPACITY
            || partition.is_some_and(|p| p.len() > RESIDENT_COMPONENT_CAPACITY)
        {
            return Err(fault(ResidentReadFault::InvalidRequest));
        }
        let mut output = Self {
            bytes: [0; RESIDENT_KEY_CAPACITY],
            length: 0,
            paired: partition.is_some(),
        };
        if let Some(partition) = partition {
            let prefix = if partition.len() <= 253 {
                output.bytes[0] = u8::try_from(partition.len())
                    .map_err(|_| fault(ResidentReadFault::InvalidRequest))?;
                1
            } else {
                output.bytes[0] = 254;
                let length = u16::try_from(partition.len())
                    .map_err(|_| fault(ResidentReadFault::InvalidRequest))?;
                output.bytes[1..3].copy_from_slice(&length.to_le_bytes());
                3
            };
            output.bytes[prefix..prefix + partition.len()].copy_from_slice(partition);
            output.length = prefix + partition.len();
        }
        output.bytes[output.length..output.length + key.len()].copy_from_slice(key);
        output.length += key.len();
        Ok(output)
    }
    /// Write-touch the complete inline key storage before exclusion. This does
    /// not reserve memory or account for helper stack frames; the caller does.
    pub fn pre_touch(&mut self) {
        for byte in &mut self.bytes {
            // All bytes are initialized. A volatile store prevents dead-store
            // elimination of unused capacity in the native scratch reservation.
            unsafe {
                core::ptr::write_volatile(byte, *byte);
            }
        }
    }
    pub(crate) fn is_paired(&self) -> bool {
        self.paired
    }
    /// Inspect the exact encoded request bytes (not their tuple sort order).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum End {
    Unbounded,
    Included,
    Excluded,
}
/// Two fixed inline bounds. Partition bounds constrain only the second
/// component; even an unbounded upper end cannot escape the partition.
pub struct ResidentRangeBounds {
    lower: ResidentKey,
    upper: ResidentKey,
    lower_end: End,
    upper_end: End,
}
impl ResidentRangeBounds {
    /// Prepare plain byte-key bounds outside the resident scope.
    pub fn plain(lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Result<Self> {
        Self::encode(None, lower, upper)
    }
    /// Prepare bounds on the second component of a single partition.
    pub fn partition(partition: &[u8], lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Result<Self> {
        Self::encode(Some(partition), lower, upper)
    }
    fn encode(partition: Option<&[u8]>, lower: Bound<&[u8]>, upper: Bound<&[u8]>) -> Result<Self> {
        fn end(bound: Bound<&[u8]>) -> (End, &[u8]) {
            match bound {
                Bound::Unbounded => (End::Unbounded, &[]),
                Bound::Included(key) => (End::Included, key),
                Bound::Excluded(key) => (End::Excluded, key),
            }
        }
        let (mut lower_end, lower) = end(lower);
        let (upper_end, upper) = end(upper);
        // The minimum second component is the empty byte slice.
        if partition.is_some() && lower_end == End::Unbounded {
            lower_end = End::Included;
        }
        Ok(Self {
            lower: ResidentKey::encode(partition, lower)?,
            upper: ResidentKey::encode(partition, upper)?,
            lower_end,
            upper_end,
        })
    }
    /// Write-touch both complete inline key buffers before exclusion.
    pub fn pre_touch(&mut self) {
        self.lower.pre_touch();
        self.upper.pre_touch();
    }
    fn empty<K: Key>(&self) -> bool {
        if self.lower_end == End::Unbounded || self.upper_end == End::Unbounded {
            return false;
        }
        match K::compare(self.lower.as_bytes(), self.upper.as_bytes()) {
            Ordering::Greater => true,
            Ordering::Equal => self.lower_end == End::Excluded || self.upper_end == End::Excluded,
            Ordering::Less => false,
        }
    }
}

struct Branch {
    page: PageImpl,
    child: usize,
}
/// Reusable native page-reference scratch: exactly 128 inline parent slots and
/// one leaf slot. No allocator, transaction, table, or resolver is owned/cloned.
/// Construct before exclusion; drop all cursors/guards before ending exclusion
/// and the resident TLS scope. A cursor clears every slot when dropped.
pub struct ResidentRangeScratch {
    path: [Option<Branch>; MAX_BTREE_DEPTH],
    depth: usize,
    leaf: Option<PageImpl>,
    index: usize,
}
impl Default for ResidentRangeScratch {
    fn default() -> Self {
        Self::new()
    }
}
impl ResidentRangeScratch {
    /// Initialize fixed native scratch outside the scope, with no allocation.
    pub fn new() -> Self {
        Self {
            path: core::array::from_fn(|_| None),
            depth: 0,
            leaf: None,
            index: 0,
        }
    }
    /// Clear and write-touch the inline reference slots before exclusion. Never
    /// call this while a cursor/guard is alive (the mutable borrow prevents it).
    pub fn pre_touch(&mut self) {
        self.clear();
        for slot in &mut self.path {
            // Copying an Option value is valid even when its inactive payload
            // has padding; no uninitialized byte is read as a primitive value.
            unsafe {
                core::ptr::write_volatile(slot, None);
            }
        }
        unsafe {
            core::ptr::write_volatile(&raw mut self.leaf, None);
        }
    }
    fn clear(&mut self) {
        self.leaf = None;
        while self.depth > 0 {
            self.depth -= 1;
            self.path[self.depth] = None;
        }
        self.index = 0;
    }
}

type ResidentEntry<'a, K> = (AccessGuard<'a, K>, AccessGuard<'a, &'static [u8]>);

/// Forward-only borrowed byte/tuple cursor. Every step checks the active TLS
/// scope. The first failure is yielded once, then the iterator is fused.
/// It must not escape the resident scope or external mutation exclusion.
pub struct ResidentRange<'a, K: Key + 'static> {
    tree: &'a Btree<K, &'static [u8]>,
    bounds: &'a ResidentRangeBounds,
    scratch: &'a mut ResidentRangeScratch,
    done: bool,
}
impl<K: Key> Drop for ResidentRange<'_, K> {
    fn drop(&mut self) {
        self.scratch.clear();
    }
}
impl<'a, K: Key> ResidentRange<'a, K> {
    pub(crate) fn new(
        tree: &'a Btree<K, &'static [u8]>,
        bounds: &'a ResidentRangeBounds,
        scratch: &'a mut ResidentRangeScratch,
        paired: bool,
    ) -> Result<Self> {
        require_active()?;
        scratch.clear();
        if bounds.lower.paired != paired || bounds.upper.paired != paired {
            return Err(fault(ResidentReadFault::InvalidRequest));
        }
        let mut cursor = Self {
            tree,
            bounds,
            scratch,
            done: bounds.empty::<K>(),
        };
        if !cursor.done {
            if let Some(root) = tree.resident_root()? {
                cursor.descend(root, true)?;
            } else {
                cursor.done = true;
            }
        }
        Ok(cursor)
    }
    fn descend(&mut self, mut page: PageImpl, seek: bool) -> Result<()> {
        loop {
            match validate(&page, self.bounds.lower.paired)? {
                LEAF => {
                    let accessor = LeafAccessor::new(page.memory(), None, None);
                    self.scratch.index = if seek && self.bounds.lower_end != End::Unbounded {
                        let (index, found) = accessor.position::<K>(self.bounds.lower.as_bytes());
                        index + usize::from(found && self.bounds.lower_end == End::Excluded)
                    } else {
                        0
                    };
                    self.scratch.leaf = Some(page);
                    return Ok(());
                }
                BRANCH => {
                    if self.scratch.depth == MAX_BTREE_DEPTH {
                        return Err(fault(ResidentReadFault::Depth));
                    }
                    let accessor = BranchAccessor::new(&page, None);
                    let (child, number) = if seek && self.bounds.lower_end != End::Unbounded {
                        accessor.child_for_key::<K>(self.bounds.lower.as_bytes())
                    } else {
                        (0, accessor.child_page(0).unwrap())
                    };
                    self.scratch.path[self.scratch.depth] = Some(Branch { page, child });
                    self.scratch.depth += 1;
                    page = self.tree.resident_page(number)?;
                }
                _ => unreachable!(), // validate accepts only these two node types
            }
        }
    }
    fn advance_leaf(&mut self) -> Result<bool> {
        self.scratch.leaf = None;
        while self.scratch.depth > 0 {
            let parent = self.scratch.path[self.scratch.depth - 1].as_mut().unwrap();
            let accessor = BranchAccessor::new(&parent.page, None);
            if parent.child + 1 < accessor.count_children() {
                parent.child += 1;
                let number = accessor.child_page(parent.child).unwrap();
                let page = self.tree.resident_page(number)?;
                self.descend(page, false)?;
                return Ok(true);
            }
            self.scratch.depth -= 1;
            self.scratch.path[self.scratch.depth] = None;
        }
        Ok(false)
    }
    fn next_entry(&mut self) -> Result<Option<ResidentEntry<'a, K>>> {
        loop {
            let Some(leaf) = self.scratch.leaf.as_ref() else {
                return Ok(None);
            };
            let accessor = LeafAccessor::new(leaf.memory(), None, None);
            if self.scratch.index == accessor.num_pairs() {
                // A seek can land in the gap at a leaf end. Ascend to the next
                // sibling (possibly through many parents), then descend leftmost.
                if !self.advance_leaf()? {
                    return Ok(None);
                }
                continue;
            }
            let (key, value) = accessor.entry_ranges(self.scratch.index).unwrap();
            let encoded = &leaf.memory()[key.clone()];
            if self.bounds.lower.paired {
                let (partition, _) = split_pair(encoded)?;
                let (requested, _) = split_pair(self.bounds.lower.as_bytes())?;
                if partition != requested {
                    return Ok(None);
                }
            }
            let order = if self.bounds.upper_end == End::Unbounded {
                Ordering::Less
            } else {
                K::compare(encoded, self.bounds.upper.as_bytes())
            };
            if order.is_gt() || (order.is_eq() && self.bounds.upper_end == End::Excluded) {
                return Ok(None);
            }
            self.scratch.index += 1;
            return Ok(Some((
                AccessGuard::with_page(leaf.clone(), key),
                AccessGuard::with_page(leaf.clone(), value),
            )));
        }
    }
}
impl<'a, K: Key> Iterator for ResidentRange<'a, K> {
    type Item = Result<ResidentEntry<'a, K>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = require_active().and_then(|()| self.next_entry());
        match result {
            Ok(Some(entry)) => Some(Ok(entry)),
            Ok(None) => {
                self.done = true;
                self.scratch.clear();
                None
            }
            Err(error) => {
                self.done = true;
                self.scratch.clear();
                Some(Err(error))
            }
        }
    }
}
impl<K: Key> core::iter::FusedIterator for ResidentRange<'_, K> {}

pub(crate) fn get<'a, K: Key>(
    tree: &'a Btree<K, &'static [u8]>,
    query: &[u8],
    paired: bool,
) -> Result<Option<AccessGuard<'a, &'static [u8]>>> {
    require_active()?;
    let Some(mut page) = tree.resident_root()? else {
        return Ok(None);
    };
    for depth in 0..MAX_BTREE_DEPTH {
        match validate(&page, paired)? {
            LEAF => {
                let accessor = LeafAccessor::new(page.memory(), None, None);
                return Ok(accessor.find_key::<K>(query).map(|index| {
                    let (_, value) = accessor.entry_ranges(index).unwrap();
                    AccessGuard::with_page(page.clone(), value)
                }));
            }
            BRANCH => {
                if depth + 1 == MAX_BTREE_DEPTH {
                    break;
                }
                let number = BranchAccessor::new(&page, None).child_for_key::<K>(query).1;
                page = tree.resident_page(number)?;
            }
            _ => unreachable!(),
        }
    }
    Err(fault(ResidentReadFault::Depth))
}

// Safe before calling tuple Key::compare/from_bytes, which assume valid encoding.
fn split_pair(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let corrupt = || fault(ResidentReadFault::Corrupt);
    let first = *data.first().ok_or_else(corrupt)?;
    let (length, prefix): (usize, usize) = match first {
        0..=253 => (usize::from(first), 1),
        254 => (
            u16::from_le_bytes(data.get(1..3).ok_or_else(corrupt)?.try_into().unwrap()) as usize,
            3,
        ),
        255 => (
            u32::from_le_bytes(data.get(1..5).ok_or_else(corrupt)?.try_into().unwrap()) as usize,
            5,
        ),
    };
    let end = prefix.checked_add(length).ok_or_else(corrupt)?;
    Ok((
        data.get(prefix..end).ok_or_else(corrupt)?,
        data.get(end..).ok_or_else(corrupt)?,
    ))
}
fn offset(memory: &[u8], position: usize) -> Result<usize> {
    let bytes = memory
        .get(position..position + 4)
        .ok_or_else(|| fault(ResidentReadFault::Corrupt))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()) as usize)
}
// Both exposed table kinds have variable-width keys and values. Validate the
// complete pointer/header area and every offset/key before any raw accessor.
fn validate(page: &PageImpl, paired: bool) -> Result<u8> {
    validate_memory(page.memory(), paired)
}
fn validate_memory(memory: &[u8], paired: bool) -> Result<u8> {
    let corrupt = || fault(ResidentReadFault::Corrupt);
    let kind = *memory.first().ok_or_else(corrupt)?;
    let count =
        u16::from_le_bytes(memory.get(2..4).ok_or_else(corrupt)?.try_into().unwrap()) as usize;
    if count == 0 {
        return Err(corrupt());
    }
    let (pointers, start) = match kind {
        LEAF => (4, 4 + 8 * count),
        BRANCH => {
            let pointers =
                8 + (size_of::<Checksum>() + PageNumber::serialized_size()) * (count + 1);
            (pointers, pointers + 4 * count)
        }
        _ => return Err(corrupt()),
    };
    if start > memory.len() {
        return Err(corrupt());
    }
    let mut previous = start;
    for index in 0..count {
        let end = offset(memory, pointers + index * 4)?;
        if end < previous || end > memory.len() {
            return Err(corrupt());
        }
        if paired {
            split_pair(&memory[previous..end])?;
        }
        previous = end;
    }
    if kind == LEAF {
        for index in 0..count {
            let end = offset(memory, 4 + 4 * count + index * 4)?;
            if end < previous || end > memory.len() {
                return Err(corrupt());
            }
            previous = end;
        }
    }
    Ok(kind)
}

impl<K: Key> Btree<K, &'static [u8]> {
    pub(super) fn resident_root(&self) -> Result<Option<PageImpl>> {
        require_active()?;
        if let Some(root) = self.resident_cached_root() {
            // Cached roots bypass PageResolver. Charge their actual extent BEFORE cloning.
            charge(root.memory().len()).expect("active resident scope")?;
            Ok(Some(root.clone()))
        } else {
            Ok(None)
        }
    }
    pub(super) fn resident_page(&self, number: PageNumber) -> Result<PageImpl> {
        require_active()?;
        self.resident_resolver().get_page(number, self.hint())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::TransactionGuard;
    use crate::resident::test_support::probe;
    use crate::tree_store::btree_base::{BtreeHeader, RawBranchBuilder};
    use crate::tree_store::{
        AllocationPolicy, InMemoryBackend, PageAllocator, PageHint, PageResolver, PageTracker,
        TransactionalMemory,
    };
    use crate::{resident_read_fault, with_resident_reads};
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    fn memory() -> Arc<TransactionalMemory> {
        let (memory, _writer_lock) = TransactionalMemory::new(
            Box::new(InMemoryBackend::new()),
            true,
            512,
            None,
            4 * 1024 * 1024,
            false,
            crate::db::ConcurrencyMode::ExclusiveWriter,
        )
        .unwrap();
        memory.reset_allocator_state().unwrap();
        Arc::new(memory)
    }
    fn leaf_bytes(key: &[u8], value: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0; 512];
        bytes[0] = LEAF;
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        let key_end = 12 + key.len();
        let value_end = key_end + value.len();
        bytes[4..8].copy_from_slice(&(key_end as u32).to_le_bytes());
        bytes[8..12].copy_from_slice(&(value_end as u32).to_le_bytes());
        bytes[12..key_end].copy_from_slice(key);
        bytes[key_end..value_end].copy_from_slice(value);
        bytes
    }
    fn store(memory: &Arc<TransactionalMemory>, bytes: &[u8]) -> PageNumber {
        let allocator = PageAllocator::new(memory.clone(), AllocationPolicy::Default);
        let mut page = allocator
            .allocate(512, &PageTracker::new_tracking())
            .unwrap();
        page.memory_mut().copy_from_slice(bytes);
        page.get_page_number()
    }
    fn branch(
        memory: &Arc<TransactionalMemory>,
        left: PageNumber,
        right: PageNumber,
    ) -> PageNumber {
        let allocator = PageAllocator::new(memory.clone(), AllocationPolicy::Default);
        let mut page = allocator
            .allocate(512, &PageTracker::new_tracking())
            .unwrap();
        let mut builder = RawBranchBuilder::new(page.memory_mut(), 1, None);
        builder.write_first_page(left, 0);
        builder.write_nth_key(b"m", right, 0, 0);
        drop(builder);
        page.get_page_number()
    }
    fn tree<K: Key>(
        memory: &Arc<TransactionalMemory>,
        root: PageNumber,
    ) -> Btree<K, &'static [u8]> {
        Btree::new(
            Some(BtreeHeader::new(root, 0, 1)),
            PageHint::None,
            Arc::new(TransactionGuard::untracked()),
            PageResolver::new(memory.clone()),
        )
        .unwrap()
    }
    fn reason<T>(result: Result<T>) -> ResidentReadFault {
        resident_read_fault(&result.err().unwrap()).unwrap()
    }

    #[test]
    fn resident_validation_rejects_every_malformed_header_offset_and_pair_prefix() {
        for bytes in [vec![], vec![LEAF], vec![LEAF, 0, 1]] {
            assert_eq!(
                reason(validate_memory(&bytes, false)),
                ResidentReadFault::Corrupt
            );
        }
        let valid = leaf_bytes(b"a", b"v");
        assert_eq!(validate_memory(&valid, false).unwrap(), LEAF);
        for kind in [0, 3, 255] {
            let mut bytes = valid.clone();
            bytes[0] = kind;
            assert_eq!(
                reason(validate_memory(&bytes, false)),
                ResidentReadFault::Corrupt
            );
        }
        for count in [0u16, 65535] {
            let mut bytes = valid.clone();
            bytes[2..4].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                reason(validate_memory(&bytes, false)),
                ResidentReadFault::Corrupt
            );
        }
        for (position, end) in [(4, 11u32), (4, 513), (8, 12), (8, 513)] {
            let mut bytes = valid.clone();
            bytes[position..position + 4].copy_from_slice(&end.to_le_bytes());
            assert_eq!(
                reason(validate_memory(&bytes, false)),
                ResidentReadFault::Corrupt
            );
        }
        for key in [
            &[][..],
            &[1][..],
            &[254][..],
            &[254, 1][..],
            &[255, 1, 2, 3][..],
            &[255, 255, 255, 255, 255][..],
        ] {
            assert_eq!(
                reason(validate_memory(&leaf_bytes(key, b"v"), true)),
                ResidentReadFault::Corrupt
            );
        }
        // The historical 255+u32 form is accepted safely, not confused with
        // raw encoding-byte tuple ordering or a new on-disk format.
        assert_eq!(
            split_pair(&[255, 1, 0, 0, 0, b'p', b'k']).unwrap(),
            (&b"p"[..], &b"k"[..])
        );
    }

    #[test]
    fn resident_point_128_pages_range_128_parents_plus_leaf_limits_are_exact() {
        let memory = memory();
        let leaf = store(&memory, &leaf_bytes(b"a", b"v"));
        let mut root = leaf;
        let mut roots = vec![leaf];
        for _ in 0..129 {
            root = branch(&memory, root, root);
            roots.push(root);
        }
        let point_ok = tree::<&[u8]>(&memory, roots[127]);
        let point_deep = tree::<&[u8]>(&memory, roots[128]);
        let range_ok = tree::<&[u8]>(&memory, roots[128]);
        let range_deep = tree::<&[u8]>(&memory, roots[129]);
        let bounds = ResidentRangeBounds::plain(Bound::Unbounded, Bound::Unbounded).unwrap();
        let mut scratch = ResidentRangeScratch::new();
        probe(|| {
            with_resident_reads(usize::MAX, || {
                assert_eq!(get(&point_ok, b"a", false).unwrap().unwrap().value(), b"v");
                assert_eq!(
                    reason(get(&point_deep, b"a", false)),
                    ResidentReadFault::Depth
                );
                let mut range =
                    ResidentRange::new(&range_ok, &bounds, &mut scratch, false).unwrap();
                assert_eq!(range.next().unwrap().unwrap().1.value(), b"v");
                drop(range);
                assert_eq!(
                    reason(ResidentRange::new(
                        &range_deep,
                        &bounds,
                        &mut scratch,
                        false
                    )),
                    ResidentReadFault::Depth
                );
            })
        });
        assert_eq!(scratch.depth, 0);
        assert!(scratch.leaf.is_none());
        assert!(scratch.path.iter().all(Option::is_none));
    }

    #[test]
    fn resident_self_cycle_has_fixed_depth_fault_without_heap_or_backend_poison() {
        let memory = memory();
        let allocator = PageAllocator::new(memory.clone(), AllocationPolicy::Default);
        let mut page = allocator
            .allocate(512, &PageTracker::new_tracking())
            .unwrap();
        let root = page.get_page_number();
        let mut builder = RawBranchBuilder::new(page.memory_mut(), 1, None);
        builder.write_first_page(root, 0);
        builder.write_nth_key(b"m", root, 0, 0);
        drop(builder);
        drop(page);
        let tree = tree::<&[u8]>(&memory, root);
        let bounds = ResidentRangeBounds::plain(Bound::Unbounded, Bound::Unbounded).unwrap();
        let mut scratch = ResidentRangeScratch::new();
        probe(|| {
            with_resident_reads(usize::MAX, || {
                assert_eq!(reason(get(&tree, b"a", false)), ResidentReadFault::Depth);
                assert_eq!(
                    reason(ResidentRange::new(&tree, &bounds, &mut scratch, false)),
                    ResidentReadFault::Depth
                );
            })
        });
        assert_eq!(
            memory.get_page(root, PageHint::None).unwrap().memory()[0],
            BRANCH
        );
    }

    #[test]
    fn resident_bad_child_order_address_node_type_and_later_fault_are_fixed_nonpoisoning() {
        let memory = memory();
        let good_leaf = store(&memory, &leaf_bytes(b"a", b"v"));
        let bad_leaf = store(&memory, &vec![255; 512]);
        let bad_order = PageNumber {
            region: 0,
            page_index: 0,
            page_order: 31,
        };
        let bad_address = PageNumber {
            region: 0,
            page_index: 0x000f_ffff,
            page_order: 0,
        };
        let bounds = ResidentRangeBounds::plain(Bound::Unbounded, Bound::Unbounded).unwrap();
        let mut scratch = ResidentRangeScratch::new();
        for right in [bad_leaf, bad_order, bad_address] {
            let root = branch(&memory, good_leaf, right);
            let tree = tree::<&[u8]>(&memory, root);
            probe(|| {
                with_resident_reads(usize::MAX, || {
                    let mut range =
                        ResidentRange::new(&tree, &bounds, &mut scratch, false).unwrap();
                    assert_eq!(range.next().unwrap().unwrap().0.value(), b"a");
                    let refusal = reason(range.next().unwrap());
                    if right == bad_address {
                        // The highest on-format page index is valid, but absent.
                        assert!(matches!(refusal, ResidentReadFault::ColdPage { .. }));
                    } else {
                        assert_eq!(refusal, ResidentReadFault::Corrupt);
                    }
                    assert!(range.next().is_none());
                    assert!(range.next().is_none());
                    assert_eq!(get(&tree, b"a", false).unwrap().unwrap().value(), b"v");
                    let refusal = reason(get(&tree, b"z", false));
                    if right == bad_address {
                        assert!(matches!(refusal, ResidentReadFault::ColdPage { .. }));
                    } else {
                        assert_eq!(refusal, ResidentReadFault::Corrupt);
                    }
                })
            });
            // Ordinary page reads still work: refusal never sets io_failed.
            assert_eq!(
                memory.get_page(good_leaf, PageHint::None).unwrap().memory()[0],
                LEAF
            );
        }
        probe(|| {
            with_resident_reads(usize::MAX, || {
                let address = PageNumber {
                    region: 0,
                    page_index: u32::MAX,
                    page_order: 0,
                };
                assert_eq!(
                    reason(memory.get_page(address, PageHint::None)),
                    ResidentReadFault::Corrupt
                );
            })
        });
        let bad_pair = store(&memory, &leaf_bytes(&[255, 1], b"v"));
        let tree = tree::<(&[u8], &[u8])>(&memory, bad_pair);
        let query = ResidentKey::pair(b"p", b"k").unwrap();
        probe(|| {
            with_resident_reads(usize::MAX, || {
                assert_eq!(
                    reason(get(&tree, query.as_bytes(), true)),
                    ResidentReadFault::Corrupt
                );
            })
        });
    }
}
