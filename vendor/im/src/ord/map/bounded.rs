// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Flower extension to the exact im 15.1.0 source. See the vendored FLOWER.md.
use super::{BoundedReadError, OrdMap};
use std::borrow::Borrow;

impl<K: Ord, V> OrdMap<K, V> {
    /// Borrow the first entry whose key is greater than or equal to `key`.
    ///
    /// Available only with the `flower-bounded-reads` feature. The traversal
    /// visits at most 128 nodes, uses constant auxiliary space, and does not
    /// allocate or clone the map, its root, keys, or values. Each node has at
    /// most 64 keys. It retains a borrowed parent candidate when a selected
    /// child's search is exhausted, independently of the ordinary `get_next`.
    ///
    /// An empty map or a query beyond the largest key returns `Ok(None)`.
    /// Exceeding the visit limit returns [`BoundedReadError::Depth`]; a local
    /// key/child-count or lookup-index inconsistency returns
    /// [`BoundedReadError::InvalidNode`]. No partial candidate is returned on
    /// either error. Safe, balanced maps on 64-bit platforms fit below the
    /// visit limit (see the vendored `FLOWER.md` for the height bound).
    ///
    /// The bound covers traversal work, not arbitrary user-provided `Ord` or
    /// `Borrow` implementations. Callers must separately bound comparator
    /// cost, query/key representation, number of calls, and output storage.
    /// Flower uses `str` comparisons and a preallocated 4097-byte query buffer
    /// for forward range scans: begin with an inclusive lower bound, then
    /// append NUL to each returned key to obtain its strict UTF-8 successor.
    /// The caller, not this method, checks its upper range bound.
    ///
    /// ```
    /// use im::OrdMap;
    /// let map: OrdMap<i32, &str> = [(1, "first"), (3, "third")].iter().cloned().collect();
    /// assert_eq!(map.get_next_bounded(&2), Ok(Some((&3, &"third"))));
    /// assert_eq!(map.get_next_bounded(&3), Ok(Some((&3, &"third"))));
    /// assert_eq!(map.get_next_bounded(&4), Ok(None));
    /// ```
    pub fn get_next_bounded<BK>(&self, key: &BK) -> Result<Option<(&K, &V)>, BoundedReadError>
    where
        BK: Ord + ?Sized,
        K: Borrow<BK>,
    {
        self.root
            .lookup_next_bounded(key)
            .map(|entry| entry.map(|(key, value)| (key, value)))
    }
}
