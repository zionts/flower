// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Test-only inclusion of the *actual* vendored private node code. This avoids
// fetching upstream im's unrelated dev-dependencies. PoolRef uses the original
// Rc implementation here; the public API tests use im's original Arc build.
#![allow(dead_code, unused_macros)]

#[cfg(all(test, feature = "flower-bounded-reads"))]
#[path = "../../src/config.rs"]
mod config;
#[cfg(all(test, feature = "flower-bounded-reads"))]
#[path = "../../src/fakepool.rs"]
mod fakepool;
#[cfg(all(test, feature = "flower-bounded-reads"))]
#[path = "../../src/nodes/btree.rs"]
mod real_btree;
#[cfg(all(test, feature = "flower-bounded-reads"))]
#[path = "../../src/util.rs"]
mod util;

#[cfg(all(test, feature = "flower-bounded-reads"))]
mod nodes {
    pub(crate) mod chunk {
        pub(crate) type Chunk<A> = sized_chunks::Chunk<A, crate::config::VectorChunkSize>;
    }
}

#[cfg(all(test, feature = "flower-bounded-reads"))]
impl real_btree::BTreeValue for (usize, ()) {
    type Key = usize;

    fn ptr_eq(&self, _other: &Self) -> bool {
        false
    }

    fn search_key<BK>(slice: &[Self], key: &BK) -> Result<usize, usize>
    where
        BK: Ord + ?Sized,
        Self::Key: std::borrow::Borrow<BK>,
    {
        slice
            .binary_search_by(|value| <usize as std::borrow::Borrow<BK>>::borrow(&value.0).cmp(key))
    }

    fn search_value(slice: &[Self], value: &Self) -> Result<usize, usize> {
        slice.binary_search_by(|entry| entry.0.cmp(&value.0))
    }

    fn cmp_keys<BK>(&self, other: &BK) -> std::cmp::Ordering
    where
        BK: Ord + ?Sized,
        Self::Key: std::borrow::Borrow<BK>,
    {
        <usize as std::borrow::Borrow<BK>>::borrow(&self.0).cmp(other)
    }

    fn cmp_values(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

#[cfg(all(test, feature = "flower-bounded-reads"))]
mod tests {
    use im::OrdMap;
    use std::ops::Bound::{Excluded, Included, Unbounded};

    #[test]
    fn public_successors_match_multilevel_range_before_and_after_removals() {
        let mut map: OrdMap<usize, usize> = (0..10_000usize).map(|n| (n * 2, n)).collect();
        // Every exact key, every absent gap, before-minimum and after-maximum.
        for query in 0..=20_001 {
            assert_eq!(map.get_next_bounded(&query), Ok(map.range(query..).next()));
        }
        // Exercise original steal/merge/root-collapse writers without changing
        // them. Share a snapshot so their copy-on-write path is exercised too.
        let snapshot = map.clone();
        for n in 0..10_000 {
            if n % 3 != 0 {
                map.remove(&(n * 2));
            }
        }
        for query in 0..=20_001 {
            assert_eq!(map.get_next_bounded(&query), Ok(map.range(query..).next()));
            assert_eq!(
                snapshot.get_next_bounded(&query),
                Ok(snapshot.range(query..).next())
            );
        }
        for n in (0..10_000).step_by(3) {
            map.remove(&(n * 2));
        }
        assert_eq!(map.get_next_bounded(&0), Ok(None));
    }

    #[test]
    fn string_successors_empty_unicode_nul_and_maximum_length() {
        let keys = ["", "\0", "\0\0", "a", "a\0", "a\0x", "aa", "é", "🦀"];
        let mut map: OrdMap<String, usize> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| ((*k).to_owned(), i))
            .collect();
        let max_key = "z".repeat(4096);
        map.insert(max_key.clone(), 100);
        for key in keys
            .iter()
            .copied()
            .chain(std::iter::once(max_key.as_str()))
        {
            assert_eq!(
                map.get_next_bounded(key),
                Ok(map.range::<_, str>((Included(key), Unbounded)).next())
            );
            let mut query = [0u8; 4097];
            query[..key.len()].copy_from_slice(key.as_bytes());
            let strict = std::str::from_utf8(&query[..key.len() + 1]).unwrap();
            assert_eq!(
                map.get_next_bounded(strict),
                Ok(map.range::<_, str>((Excluded(key), Unbounded)).next())
            );
        }
        assert_eq!(
            OrdMap::<String, usize>::new().get_next_bounded(""),
            Ok(None)
        );
    }

    #[test]
    fn read_does_not_require_clone_on_keys_or_values() {
        #[derive(Eq, PartialEq, Ord, PartialOrd)]
        struct Key(usize);
        struct Value;
        // Cannot populate this map with ordinary writers, but the API itself
        // must not gain Clone bounds. Runtime clone traps are in the probe.
        let map = OrdMap::<Key, Value>::new();
        assert!(map.get_next_bounded(&Key(0)).unwrap().is_none());
    }

    #[test]
    fn balanced_height_arithmetic_on_supported_64_bit_target() {
        assert_eq!(std::mem::size_of::<usize>(), 8);
        // h visited levels; nonroot nodes have at least 31 keys / 32 children.
        // The minimum cardinality is 2 * 32^(h - 1) - 1.
        let at_13 = 2u128 * 32u128.checked_pow(12).unwrap() - 1;
        let at_14 = 2u128 * 32u128.checked_pow(13).unwrap() - 1;
        assert!(at_13 <= usize::MAX as u128);
        assert!(at_14 > usize::MAX as u128);
        // Even the weaker one-key/two-child balanced invariant caps h at 64.
        assert_eq!((1u128 << 64) - 1, usize::MAX as u128);
        assert!((1u128 << 65) - 1 > usize::MAX as u128);
    }
}
