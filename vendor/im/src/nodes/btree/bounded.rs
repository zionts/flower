// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Flower extension to the exact im 15.1.0 source. See the vendored FLOWER.md.
use super::{BTreeValue, Node};
use std::borrow::Borrow;

const MAX_NODE_VISITS: usize = 128;

/// A fixed-size failure from a bounded, borrowed ordered-map read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundedReadError {
    /// Following the selected child would require more than 128 node visits.
    Depth,
    /// A visited node has an invalid key/child count or lookup index.
    ///
    /// This is a local defensive check, not validation of the entire tree.
    InvalidNode,
}

impl<A: BTreeValue> Node<A> {
    /// Inclusive successor, with one borrowed candidate and no ancestor stack.
    pub(crate) fn lookup_next_bounded<BK>(&self, key: &BK) -> Result<Option<&A>, BoundedReadError>
    where
        BK: Ord + ?Sized,
        A::Key: Borrow<BK>,
    {
        let mut node = self;
        let mut candidate = None;
        for _ in 0..MAX_NODE_VISITS {
            // Ordinary safe writers preserve this invariant. Check before any
            // indexed child access so a malformed shape is not a panic path.
            if node.children.len() != node.keys.len() + 1 {
                return Err(BoundedReadError::InvalidNode);
            }
            match A::search_key(&node.keys, key) {
                Ok(index) => {
                    return node
                        .keys
                        .get(index)
                        .map(Some)
                        .ok_or(BoundedReadError::InvalidNode);
                }
                Err(index) => {
                    if index > node.keys.len() {
                        return Err(BoundedReadError::InvalidNode);
                    }
                    if let Some(entry) = node.keys.get(index) {
                        // Any candidate inside this selected subtree precedes
                        // the ancestor candidate. Keep the ancestor otherwise:
                        // exhaustion below a separator must not lose it.
                        candidate = Some(entry);
                    }
                    match node.children.get(index) {
                        Some(Some(child)) => node = child,
                        Some(None) => return Ok(candidate),
                        None => return Err(BoundedReadError::InvalidNode),
                    }
                }
            }
        }
        Err(BoundedReadError::Depth)
    }
}

#[cfg(test)]
mod tests {
    use super::{BoundedReadError, Node, MAX_NODE_VISITS};
    use crate::util::{Pool, PoolRef};
    use sized_chunks::Chunk;

    fn chain(visits: usize) -> Node<(usize, ())> {
        let pool = Pool::new(0);
        let mut node = Node::unit((1, ()));
        for key in 2..=visits {
            node = Node {
                keys: Chunk::unit((key, ())),
                children: Chunk::pair(Some(PoolRef::new(&pool, node)), None),
            };
        }
        node
    }

    #[test]
    fn empty_node_and_invalid_local_shape() {
        assert_eq!(
            Node::<(usize, ())>::default().lookup_next_bounded(&0),
            Ok(None)
        );
        let invalid = Node {
            keys: Chunk::unit((1, ())),
            children: Chunk::unit(None),
        };
        assert_eq!(
            invalid.lookup_next_bounded(&1),
            Err(BoundedReadError::InvalidNode)
        );
    }

    #[test]
    fn depth_limit_includes_the_terminal_node() {
        // Deliberately unbalanced synthetic shapes, impossible for ordinary
        // writers. The operation still has a hard node-visit bound.
        assert_eq!(
            chain(MAX_NODE_VISITS).lookup_next_bounded(&0),
            Ok(Some(&(1, ())))
        );
        let too_deep = chain(MAX_NODE_VISITS + 1);
        assert_eq!(
            too_deep.lookup_next_bounded(&0),
            Err(BoundedReadError::Depth)
        );
        // An exact match need not descend further into the malformed tree.
        assert_eq!(
            too_deep.lookup_next_bounded(&(MAX_NODE_VISITS + 1)),
            Ok(Some(&(MAX_NODE_VISITS + 1, ())))
        );
    }

    #[test]
    fn exhausted_child_retains_the_nearest_parent_candidate() {
        let pool = Pool::new(0);
        let child = Node::unit((10, ()));
        let root = Node {
            keys: Chunk::unit((20, ())),
            children: Chunk::pair(Some(PoolRef::new(&pool, child)), None),
        };
        assert_eq!(root.lookup_next_bounded(&15), Ok(Some(&(20, ()))));
        // Record the upstream bug without changing its existing semantics.
        assert_eq!(root.lookup_next(&15), None);
        assert_eq!(root.lookup_next_bounded(&20), Ok(Some(&(20, ()))));
        assert_eq!(root.lookup_next_bounded(&21), Ok(None));
    }
}
