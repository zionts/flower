// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Isolated, single-threaded executable: never install this allocator in Flower
// or in im's production library. Construct maps, reference ranges, queries and
// output reservations BEFORE enabling the allocation/clone counter.
#[cfg(feature = "flower-bounded-reads")]
mod probe {
    use im::{BoundedReadError, OrdMap};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::borrow::Borrow;
    use std::ops::Bound::{self, Excluded, Included, Unbounded};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering::Relaxed};

    static ENABLED: AtomicBool = AtomicBool::new(false);
    static ALLOC: AtomicUsize = AtomicUsize::new(0);
    static ZEROED: AtomicUsize = AtomicUsize::new(0);
    static REALLOC: AtomicUsize = AtomicUsize::new(0);
    static CLONES: AtomicUsize = AtomicUsize::new(0);

    struct Allocator;
    unsafe impl GlobalAlloc for Allocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if ENABLED.load(Relaxed) {
                ALLOC.fetch_add(1, Relaxed);
            }
            unsafe { System.alloc(layout) }
        }
        unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
            if ENABLED.load(Relaxed) {
                ZEROED.fetch_add(1, Relaxed);
            }
            unsafe { System.alloc_zeroed(layout) }
        }
        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
            if ENABLED.load(Relaxed) {
                REALLOC.fetch_add(1, Relaxed);
            }
            unsafe { System.realloc(ptr, layout, size) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
    #[global_allocator]
    static GLOBAL: Allocator = Allocator;

    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct Key(String);
    impl Borrow<str> for Key {
        fn borrow(&self) -> &str {
            &self.0
        }
    }
    impl Clone for Key {
        fn clone(&self) -> Self {
            if ENABLED.load(Relaxed) {
                CLONES.fetch_add(1, Relaxed);
            }
            Self(self.0.clone())
        }
    }
    #[derive(Debug, Eq, PartialEq)]
    struct Value(usize);
    impl Clone for Value {
        fn clone(&self) -> Self {
            if ENABLED.load(Relaxed) {
                CLONES.fetch_add(1, Relaxed);
            }
            Self(self.0)
        }
    }

    #[derive(Debug, Eq, PartialEq)]
    struct Counts {
        alloc: usize,
        alloc_zeroed: usize,
        realloc: usize,
        clones: usize,
    }
    fn measured<R>(read: impl FnOnce() -> R) -> (R, Counts) {
        ALLOC.store(0, Relaxed);
        ZEROED.store(0, Relaxed);
        REALLOC.store(0, Relaxed);
        CLONES.store(0, Relaxed);
        ENABLED.store(true, Relaxed);
        let result = read();
        ENABLED.store(false, Relaxed);
        let counts = Counts {
            alloc: ALLOC.load(Relaxed),
            alloc_zeroed: ZEROED.load(Relaxed),
            realloc: REALLOC.load(Relaxed),
            clones: CLONES.load(Relaxed),
        };
        (result, counts)
    }
    fn assert_zero(counts: Counts) {
        assert_eq!(
            counts,
            Counts {
                alloc: 0,
                alloc_zeroed: 0,
                realloc: 0,
                clones: 0
            }
        );
    }

    struct Query {
        bytes: [u8; 4097],
        len: usize,
    }
    impl Query {
        fn new(key: &str, strict: bool) -> Self {
            assert!(key.len() <= 4096);
            let mut bytes = [0u8; 4097];
            bytes[..key.len()].copy_from_slice(key.as_bytes());
            Self {
                bytes,
                len: key.len() + usize::from(strict),
            }
        }
        fn as_str(&self) -> &str {
            std::str::from_utf8(&self.bytes[..self.len]).unwrap()
        }
        fn after(&mut self, key: &str) {
            // All setup keys have already been validated as <= 4096 bytes.
            self.bytes[..key.len()].copy_from_slice(key.as_bytes());
            self.bytes[key.len()] = 0;
            self.len = key.len() + 1;
        }
    }

    fn check_query(map: &OrdMap<Key, Value>, query: Query) {
        let query = query.as_str();
        let expected = map.range::<_, str>((Included(query), Unbounded)).next();
        let (actual, counts) = measured(|| map.get_next_bounded(query));
        assert_zero(counts);
        assert_eq!(actual, Ok(expected));
        if let (Some((ek, ev)), Ok(Some((ak, av)))) = (expected, actual) {
            assert!(std::ptr::eq(ek, ak));
            assert!(std::ptr::eq(ev, av));
        }
    }

    fn scan<'a>(
        map: &'a OrdMap<Key, Value>,
        query: &mut Query,
        upper: Bound<&str>,
        output: &mut Vec<(&'a Key, &'a Value)>,
    ) -> Result<(), BoundedReadError> {
        while let Some((key, value)) = map.get_next_bounded(query.as_str())? {
            let in_range = match upper {
                Included(upper) => key.0.as_str() <= upper,
                Excluded(upper) => key.0.as_str() < upper,
                Unbounded => true,
            };
            if !in_range {
                break;
            }
            output.push((key, value));
            query.after(&key.0);
        }
        Ok(())
    }

    fn all_ranges(map: &OrdMap<Key, Value>, bounds: &[&str]) -> usize {
        let mut count = 0;
        // All inclusive/exclusive/unbounded combinations, including equal
        // endpoints and empty ranges, with valid nondecreasing endpoints.
        let candidates: Vec<_> = std::iter::once(Unbounded)
            .chain(
                bounds
                    .iter()
                    .flat_map(|&key| [Included(key), Excluded(key)]),
            )
            .collect();
        for &lower in &candidates {
            for &upper in &candidates {
                let lower_key = match lower {
                    Included(k) | Excluded(k) => Some(k),
                    Unbounded => None,
                };
                let upper_key = match upper {
                    Included(k) | Excluded(k) => Some(k),
                    Unbounded => None,
                };
                if matches!((lower_key, upper_key), (Some(l), Some(u)) if l > u) {
                    continue;
                }
                // The upstream range API rejects two equal exclusive bounds.
                if matches!((lower, upper), (Excluded(l), Excluded(u)) if l == u) {
                    continue;
                }
                let mut query = match lower {
                    Included(key) => Query::new(key, false),
                    Excluded(key) => Query::new(key, true),
                    Unbounded => Query::new("", false),
                };
                let expected: Vec<_> = map.range::<_, str>((lower, upper)).collect();
                let mut actual = Vec::with_capacity(map.len());
                let (result, counts) = measured(|| scan(map, &mut query, upper, &mut actual));
                assert_zero(counts);
                assert_eq!(result, Ok(()));
                assert_eq!(actual, expected);
                count += 1;
            }
        }
        count
    }

    pub fn run() {
        let mut map: OrdMap<Key, Value> = (0..10_000)
            .map(|n| (Key(format!("{:05}", n * 2)), Value(n)))
            .collect();
        for (n, key) in ["", "\0", "\0\0", "a", "a\0", "a\0x", "aa", "é", "🦀"]
            .iter()
            .enumerate()
        {
            map.insert(Key((*key).into()), Value(10_000 + n));
        }
        let max_key = "z".repeat(4096);
        map.insert(Key(max_key.clone()), Value(20_000));
        let snapshot = map.clone(); // Ensure reads borrow genuinely shared nodes.
        let mut fallback_count = 0;
        for n in 0..=20_001 {
            let key = format!("{n:05}");
            let expected = map
                .range::<_, str>((Included(key.as_str()), Unbounded))
                .next();
            if map.get_next(key.as_str()) != expected {
                fallback_count += 1;
                // Exact parent separator and separator+NUL queries as well.
                let parent = expected.unwrap().0 .0.as_str();
                check_query(&map, Query::new(parent, false));
                check_query(&map, Query::new(parent, true));
            }
            check_query(&map, Query::new(&key, false));
        }
        assert!(
            fallback_count > 0,
            "must exercise the upstream child-exhaustion bug"
        );
        for key in [
            "",
            "\0",
            "\0\0",
            "a",
            "a\0",
            "a\0x",
            "aa",
            "é",
            "🦀",
            max_key.as_str(),
        ] {
            check_query(&map, Query::new(key, false));
            check_query(&map, Query::new(key, true));
        }
        check_query(&OrdMap::new(), Query::new("", false));
        // Genuine after-maximum miss (4096-byte query, distinct from max_key).
        check_query(&map, Query::new(&"🦀".repeat(1024), false));
        let bounds = [
            "",
            "\0",
            "\0\0",
            "00000",
            "00063",
            "00064",
            "09999",
            "19998",
            "19999",
            "a",
            "a\0",
            "a\0x",
            "aa",
            "é",
            max_key.as_str(),
            "🦀",
        ];
        let range_count = all_ranges(&map, &bounds);
        // Repeat after original writers have rebalanced/deleted most entries.
        for n in 0..10_000 {
            if n % 3 != 0 {
                map.remove(format!("{:05}", n * 2).as_str());
            }
        }
        let removed_range_count = all_ranges(&map, &bounds);
        assert_eq!(snapshot.len(), 10_010);
        println!("PASS: 20002 preencoded numeric queries, {fallback_count} child-exhaustion queries plus exact-parent/NUL successors; {range_count} forward ranges and {removed_range_count} post-removal ranges; empty/Unicode/NUL/4096-byte keys; alloc=alloc_zeroed=realloc=key/value clones=0 in every measured lookup and scan");
    }
}

#[cfg(feature = "flower-bounded-reads")]
fn main() {
    probe::run();
}

#[cfg(not(feature = "flower-bounded-reads"))]
fn main() {
    // Feature-off build exercises upstream APIs without exposing the extension.
    let map: im::OrdMap<i32, i32> = [(1, 2)].into_iter().collect();
    assert_eq!(map.get_next(&1), Some((&1, &2)));
    println!("PASS: original APIs with flower-bounded-reads disabled");
}
