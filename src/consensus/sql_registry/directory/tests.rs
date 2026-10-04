use super::super::pool::{HARD_REGISTRY_POOL_BYTES, RegistryAdmission, RegistryPoolLimits};
use super::super::{RegistryIdentity, RegistryNamespace};
use super::*;
use crate::allocation_probe;
use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};

// This allocated, initialized test region is NOT an actual native node owner
// or combined pool mapping. No fixture scalar proves Store/source authority.
// All fixture allocation is finished before measured production operations.
struct Region {
    pointer: NonNull<u8>,
    layout: Layout,
}
impl Region {
    fn new(layout: DirectoryLayout) -> Self {
        let layout = layout.object_layout();
        let pointer = NonNull::new(unsafe { std::alloc::alloc_zeroed(layout) }).unwrap();
        Self { pointer, layout }
    }
    fn bytes(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size()) }
    }
}
impl Drop for Region {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.pointer.as_ptr(), self.layout) };
    }
}
// Mock private-source issuance. Real integration MUST use the already admitted
// pool.issue_namespace counter and actual native publication/epoch validation.
struct Issuer(Cell<u64>);
impl Issuer {
    fn new() -> Self {
        Self(Cell::new(1))
    }
    fn issue(&self) -> Result<u64, DirectoryError> {
        let uid = self.0.get();
        self.0
            .set(uid.checked_add(1).ok_or(DirectoryError::Capacity)?);
        Ok(uid)
    }
}
fn origin(key: NativeKey<'_>) -> NativeOrigin<'_> {
    NativeOrigin {
        store: 1,
        installation: 0,
        epoch: 0,
        key,
    }
}
fn scoped(name: &str) -> NativeOrigin<'_> {
    origin(NativeKey::Scoped(name))
}
fn code(registry: u64) -> NativeCode {
    NativeCode {
        registry,
        bundle: registry + 1,
        schema: registry + 2,
    }
}
fn register(directory: &Directory<'_>, issuer: &Issuer, name: &str) -> NativeHeadToken {
    directory
        .register_native(scoped(name), code(1), || issuer.issue())
        .unwrap()
}
fn assert_zero<T>(operation: impl FnOnce() -> T) -> T {
    let (result, operations, bytes) = allocation_probe::measure(operation);
    assert_eq!((operations, bytes), (0, 0));
    result
}

#[test]
fn directory_layout_counts_all_control_descriptors_arena_padding_and_has_no_page_claim() {
    let layout = DirectoryLayout::new(256, 8193).unwrap();
    assert_eq!(layout.control_bytes, std::mem::size_of::<Control>());
    assert_eq!(layout.head_bytes, std::mem::size_of::<Head>());
    assert_eq!(layout.head_bytes, std::mem::size_of::<UnsafeCell<Head>>());
    assert_eq!(layout.heads_offset % std::mem::align_of::<Head>(), 0);
    assert_eq!(layout.bytes % layout.alignment, 0);
    assert_eq!(
        layout.owner_bytes,
        std::mem::size_of::<Option<RegistryCell>>()
    );
    assert_eq!(
        layout.owner_bytes,
        std::mem::size_of::<UnsafeCell<Option<RegistryCell>>>()
    );
    assert_eq!(
        layout.owners_offset % std::mem::align_of::<Option<RegistryCell>>(),
        0
    );
    let (exact, heads_offset) = Layout::new::<Control>()
        .extend(Layout::array::<UnsafeCell<Head>>(256).unwrap())
        .unwrap();
    let (exact, owners_offset) = exact
        .extend(Layout::array::<UnsafeCell<Option<RegistryCell>>>(256).unwrap())
        .unwrap();
    let (exact, keys_offset) = exact.extend(Layout::array::<u8>(8193).unwrap()).unwrap();
    assert_eq!(layout.object_layout(), exact.pad_to_align());
    assert_eq!(
        (
            layout.heads_offset,
            layout.owners_offset,
            layout.keys_offset
        ),
        (heads_offset, owners_offset, keys_offset)
    );
    assert!(
        layout.bytes
            >= layout.control_bytes
                + (layout.head_bytes + layout.owner_bytes) * 256
                + layout.key_bytes
    );
    assert!(layout.bytes - (layout.keys_offset + layout.key_bytes) < layout.alignment);
    let (combined, directory_offset) = Layout::new::<[u64; 17]>()
        .extend(layout.object_layout())
        .unwrap();
    assert_eq!(directory_offset % layout.alignment, 0);
    assert_eq!(combined.size(), directory_offset + layout.bytes);
    println!(
        "directory layout control={} head={} owner={} heads={} keys={} heads_offset={} owners_offset={} keys_offset={} align={} object_bytes={} (not page-rounded / not combined native admission)",
        layout.control_bytes,
        layout.head_bytes,
        layout.owner_bytes,
        layout.heads,
        layout.key_bytes,
        layout.heads_offset,
        layout.owners_offset,
        layout.keys_offset,
        layout.alignment,
        layout.bytes,
    );
    assert_eq!(DirectoryLayout::new(0, 1), Err(DirectoryError::Invalid));
    assert_eq!(DirectoryLayout::new(257, 1), Err(DirectoryError::Invalid));
    assert_eq!(
        DirectoryLayout::new(1, usize::MAX),
        Err(DirectoryError::Capacity)
    );
    assert_eq!(
        DirectoryLayout::new(256, MAX_COMPONENT_BYTES),
        Err(DirectoryError::Capacity)
    );
    // Exact standalone component ceiling is arithmetic only, NOT a second
    // 16MiB allowance beside the cell/cancellation pool.
    let overhead = DirectoryLayout::new(256, 0).unwrap().bytes;
    assert_eq!(
        DirectoryLayout::new(256, MAX_COMPONENT_BYTES - overhead)
            .unwrap()
            .bytes,
        MAX_COMPONENT_BYTES
    );
}

#[test]
fn directory_initialization_rejects_bad_extent_alignment_and_mutated_accounting_before_writes() {
    let layout = DirectoryLayout::new(2, 17).unwrap();
    let mut region = Region::new(layout);
    region.bytes().fill(0x7f);
    let mut bad = layout;
    bad.heads = 256;
    assert!(matches!(
        Directory::initialize(region.bytes(), bad),
        Err(DirectoryError::Invalid)
    ));
    assert!(region.bytes().iter().all(|byte| *byte == 0x7f));
    let mut bad = layout;
    bad.alignment = 1;
    assert!(matches!(
        Directory::initialize(region.bytes(), bad),
        Err(DirectoryError::Invalid)
    ));
    assert!(matches!(
        Directory::initialize(&mut region.bytes()[1..], layout),
        Err(DirectoryError::Invalid)
    ));
    let mut larger = Region::new(DirectoryLayout::new(2, 33).unwrap());
    assert!(matches!(
        Directory::initialize(&mut larger.bytes()[1..1 + layout.bytes], layout),
        Err(DirectoryError::Invalid)
    ));
    let directory = assert_zero(|| Directory::initialize(region.bytes(), layout).unwrap());
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 0,
            key_bytes: 0
        }
    );
    assert_zero(|| drop(directory));
}

#[test]
fn directory_exact_utf8_nul_empty_and_root_same_fixture_epoch_are_distinct() {
    let names = ["", "α", "β", "a\0b", "a\0c", "é", "e\u{301}"];
    let key_bytes = names.iter().map(|name| name.len()).sum();
    let layout = DirectoryLayout::new(names.len() + 1, key_bytes).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let root = directory
        .register_native(origin(NativeKey::Root), code(1), || issuer.issue())
        .unwrap();
    let mut tokens = [root; 7];
    for (index, name) in names.iter().enumerate() {
        tokens[index] = register(&directory, &issuer, name);
        assert_ne!(tokens[index].uid(), root.uid());
        assert_eq!(
            directory
                .lookup_native(scoped(name), Some(tokens[index]))
                .unwrap()
                .token,
            tokens[index]
        );
    }
    assert_eq!(
        directory
            .lookup_native(origin(NativeKey::Root), Some(root))
            .unwrap()
            .token,
        root
    );
    assert_eq!(
        directory.lookup_native(scoped(""), Some(root)),
        Err(DirectoryError::Stale)
    );
    assert_eq!(
        directory.lookup_native(scoped("a\0c"), Some(tokens[3])),
        Err(DirectoryError::Stale)
    );
    assert_eq!(
        directory.lookup_native(scoped("e\u{301}"), Some(tokens[5])),
        Err(DirectoryError::Stale)
    );
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 8,
            key_bytes
        }
    );
}

#[test]
fn directory_native_name_above_4096_succeeds_iff_actual_total_arena_has_room() {
    let name = "λ".repeat(5000); // 10,000 exact UTF-8 bytes; no ordinary-name clamp.
    let layout = DirectoryLayout::new(2, name.len()).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let token = assert_zero(|| register(&directory, &issuer, &name));
    assert_eq!(
        assert_zero(|| directory.lookup_native(scoped(&name), Some(token)))
            .unwrap()
            .token,
        token
    );
    assert_eq!(
        directory.register_native(scoped("x"), code(1), || issuer.issue()),
        Err(DirectoryError::Capacity)
    );
    assert_eq!(
        issuer.0.get(),
        2,
        "capacity must refuse before UID issuance"
    );
    assert_zero(|| directory.retire_native(scoped(&name), token).unwrap());
    let replacement = assert_zero(|| register(&directory, &issuer, &name));
    assert_ne!(token.uid(), replacement.uid());
    assert_eq!(
        directory.lookup_native(scoped(&name), Some(token)),
        Err(DirectoryError::Stale)
    );
    let smaller = DirectoryLayout::new(1, name.len() - 1).unwrap();
    let mut other = Region::new(smaller);
    let too_small = Directory::initialize(other.bytes(), smaller).unwrap();
    assert_eq!(
        too_small.register_native(scoped(&name), code(1), || issuer.issue()),
        Err(DirectoryError::Capacity)
    );
    assert_eq!(
        too_small.usage().unwrap(),
        DirectoryUsage {
            heads: 0,
            key_bytes: 0
        }
    );
}

#[test]
fn directory_exact_head_and_key_refusals_have_no_effect_or_issuer_call() {
    let layout = DirectoryLayout::new(2, 5).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let one = register(&directory, &issuer, "abc");
    let two = register(&directory, &issuer, "de");
    let before = directory.usage().unwrap();
    assert_eq!(
        assert_zero(
            || directory.register_native(scoped(""), code(1), || panic!("head cap called issuer"))
        ),
        Err(DirectoryError::Capacity)
    );
    assert_eq!(directory.usage().unwrap(), before);
    assert_eq!(
        directory
            .lookup_native(scoped("abc"), Some(one))
            .unwrap()
            .code,
        code(1)
    );
    assert_eq!(
        directory.register_native(scoped("abc"), code(7), || panic!("duplicate called issuer")),
        Err(DirectoryError::AlreadyCurrent)
    );
    directory.retire_native(scoped("de"), two).unwrap();
    assert_eq!(
        assert_zero(|| directory
            .register_native(scoped("XYZ"), code(1), || panic!("key cap called issuer"))),
        Err(DirectoryError::Capacity)
    );
    let zero = register(&directory, &issuer, "");
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 2,
            key_bytes: 3
        }
    );
    directory.retire_native(scoped(""), zero).unwrap();
    let exact = register(&directory, &issuer, "XY");
    assert_eq!(directory.usage().unwrap(), before);
    directory.remove_native(scoped("XY"), exact).unwrap();
}

#[test]
fn directory_fragmentation_first_fit_free_and_slot_reuse_are_bounded_deterministic() {
    let layout = DirectoryLayout::new(6, 12).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let a = register(&directory, &issuer, "aaa");
    let b = register(&directory, &issuer, "bbb");
    let c = register(&directory, &issuer, "ccc");
    let d = register(&directory, &issuer, "ddd");
    directory.retire_native(scoped("bbb"), b).unwrap();
    directory.retire_native(scoped("ddd"), d).unwrap();
    assert_eq!(directory.usage().unwrap().key_bytes, 6);
    assert_eq!(
        directory.register_native(scoped("four"), code(1), || panic!(
            "fragmentation called issuer"
        )),
        Err(DirectoryError::Capacity)
    );
    let guard = directory.lock().unwrap();
    let fit = directory.first_fit(&guard, 3);
    assert_eq!(fit.offset, Some(3));
    assert!(fit.head_visits <= layout.heads * (layout.heads + 1));
    drop(guard);
    let e = register(&directory, &issuer, "eee");
    let guard = directory.lock().unwrap();
    let index = directory.find(&guard, scoped("eee")).index.unwrap();
    assert_eq!(directory.head(&guard, index).offset, 3);
    assert_eq!(
        index, 1,
        "fixed first vacant descriptor is reused, not history"
    );
    drop(guard);
    directory.retire_native(scoped("aaa"), a).unwrap();
    directory.retire_native(scoped("eee"), e).unwrap();
    let six = register(&directory, &issuer, "123456");
    assert_eq!(
        directory
            .lookup_native(scoped("ccc"), Some(c))
            .unwrap()
            .token,
        c
    );
    directory.remove_native(scoped("123456"), six).unwrap();
}

#[test]
fn directory_scan_total_comparison_bytes_cannot_exceed_used_disjoint_arena() {
    let layout = DirectoryLayout::new(256, 256 * 3).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    for index in 0..256u16 {
        // Three-byte stack names, no per-head heap keys even in this fixture.
        let name = [b'A', b'0' + (index / 16) as u8, b'0' + (index % 16) as u8];
        register(&directory, &issuer, std::str::from_utf8(&name).unwrap());
    }
    let guard = directory.lock().unwrap();
    let missing = directory.find(&guard, scoped("ZZZ"));
    assert_eq!(missing.index, None);
    assert_eq!(missing.head_visits, 256);
    assert_eq!(missing.comparison_bytes, 768);
    assert_eq!(missing.comparison_bytes, directory.counts(&guard).key_bytes);
    let fit = directory.first_fit(&guard, 1);
    assert_eq!(fit.offset, None);
    assert_eq!(fit.head_visits, 256 * 257);
}

#[test]
fn directory_updates_never_alias_old_code_and_unattached_heads_are_unavailable() {
    let layout = DirectoryLayout::new(1, 5).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let token = register(&directory, &issuer, "alpha");
    assert_eq!(
        directory
            .select_current_native(scoped("alpha"), token, code(1))
            .map(|_| ()),
        Err(DirectoryError::CurrentUnavailable)
    );
    let current = directory
        .update_code_native(scoped("alpha"), token, code(20))
        .unwrap();
    assert_eq!(current.code, code(20));
    assert_eq!(current.token, token);
    assert_eq!(
        directory
            .lookup_native(scoped("alpha"), Some(token))
            .unwrap(),
        current
    );
    for requested in [
        code(1),
        code(20),
        NativeCode {
            bundle: 100,
            ..code(20)
        },
        NativeCode {
            schema: 100,
            ..code(20)
        },
    ] {
        assert_eq!(
            assert_zero(|| directory
                .select_current_native(scoped("alpha"), token, requested)
                .map(|_| ())),
            Err(DirectoryError::CurrentUnavailable)
        );
    }
}

#[test]
fn directory_uid_store_install_epoch_key_correlation_and_reregister_are_not_aba() {
    let layout = DirectoryLayout::new(3, 10).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let token = register(&directory, &issuer, "alpha");
    for wrong in [
        NativeOrigin {
            store: 2,
            ..scoped("alpha")
        },
        NativeOrigin {
            installation: 1,
            ..scoped("alpha")
        },
        NativeOrigin {
            epoch: 1,
            ..scoped("alpha")
        },
    ] {
        assert_eq!(
            directory.lookup_native(wrong, Some(token)),
            Err(DirectoryError::Stale)
        );
        assert_eq!(
            directory.retire_native(wrong, token),
            Err(DirectoryError::Stale)
        );
        assert_eq!(
            directory.update_code_native(wrong, token, code(7)),
            Err(DirectoryError::Stale)
        );
    }
    // Even with space, newer installation/epoch cannot accumulate descriptor
    // history for the same actual Store/key. Retire the old current head first.
    let newer = NativeOrigin {
        installation: 1,
        epoch: 1,
        ..scoped("alpha")
    };
    assert_eq!(
        directory.register_native(newer, code(1), || panic!(
            "incarnation conflict called issuer"
        )),
        Err(DirectoryError::AlreadyCurrent)
    );
    assert_eq!(
        directory.lookup_native(scoped("bravo"), Some(token)),
        Err(DirectoryError::Missing)
    );
    let bravo = register(&directory, &issuer, "bravo");
    assert_eq!(
        directory.lookup_native(scoped("bravo"), Some(token)),
        Err(DirectoryError::Stale)
    );
    directory.retire_native(scoped("alpha"), token).unwrap();
    let replacement = directory
        .register_native(newer, code(1), || issuer.issue())
        .unwrap();
    assert_ne!(replacement.uid(), token.uid());
    assert_eq!(
        directory.retire_native(newer, token),
        Err(DirectoryError::Stale)
    );
    assert_eq!(
        directory
            .lookup_native(newer, Some(replacement))
            .unwrap()
            .token,
        replacement
    );
    assert_eq!(
        directory
            .lookup_native(scoped("bravo"), Some(bravo))
            .unwrap()
            .token,
        bravo
    );
}

#[test]
fn directory_busy_is_nonwaiting_and_distinct_from_actual_capacity() {
    let layout = DirectoryLayout::new(1, 1).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let token = register(&directory, &issuer, "x");
    let guard = directory.lock().unwrap();
    assert_eq!(
        assert_zero(
            || directory.register_native(scoped("y"), code(1), || panic!("Busy called issuer"))
        ),
        Err(DirectoryError::Busy)
    );
    assert_eq!(
        directory.lookup_native(scoped("x"), Some(token)),
        Err(DirectoryError::Busy)
    );
    assert_eq!(
        directory.retire_native(scoped("x"), token),
        Err(DirectoryError::Busy)
    );
    assert_eq!(
        directory.update_code_native(scoped("x"), token, code(2)),
        Err(DirectoryError::Busy)
    );
    assert_eq!(
        directory
            .select_current_native(scoped("x"), token, code(1))
            .map(|_| ()),
        Err(DirectoryError::Busy)
    );
    drop(guard);
    assert_eq!(
        directory.register_native(scoped("y"), code(1), || panic!("Capacity called issuer")),
        Err(DirectoryError::Capacity)
    );
    assert_eq!(
        directory
            .lookup_native(scoped("x"), Some(token))
            .unwrap()
            .token,
        token
    );
}

#[test]
fn directory_issuer_failure_invalid_duplicate_and_unwind_leave_no_key_or_head_effect() {
    let layout = DirectoryLayout::new(3, 12).unwrap();
    let mut region = Region::new(layout);
    let directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    let token = register(&directory, &issuer, "a");
    for result in [
        Err(DirectoryError::Capacity),
        Err(DirectoryError::Busy),
        Ok(0),
        Ok(token.uid()),
    ] {
        assert_eq!(
            directory.register_native(scoped("new"), code(1), || result),
            Err(match result {
                Err(error) => error,
                Ok(_) => DirectoryError::Invalid,
            })
        );
        assert_eq!(
            directory.usage().unwrap(),
            DirectoryUsage {
                heads: 1,
                key_bytes: 1
            }
        );
    }
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        directory.register_native(scoped("new"), code(1), || panic!("mock issuer failed"))
    }));
    assert!(panic.is_err());
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 1,
            key_bytes: 1
        }
    );
    let guard = directory.lock().unwrap();
    let keys = unsafe { std::slice::from_raw_parts(directory.keys(), layout.key_bytes) };
    assert_eq!(keys[0], b'a');
    assert!(keys[1..].iter().all(|byte| *byte == 0));
    drop(guard);
    register(&directory, &issuer, "new");
    for invalid in [
        NativeOrigin {
            store: 0,
            ..scoped("bad")
        },
        NativeOrigin {
            epoch: u64::MAX,
            ..scoped("bad")
        },
    ] {
        assert_eq!(
            directory.register_native(invalid, code(1), || panic!("invalid origin called issuer")),
            Err(DirectoryError::Invalid)
        );
    }
    assert_eq!(
        directory.register_native(
            scoped("bad"),
            NativeCode {
                registry: 0,
                ..code(1)
            },
            || panic!("invalid code called issuer")
        ),
        Err(DirectoryError::Invalid)
    );
}

#[test]
fn directory_register_copy_lookup_update_retire_clear_and_drop_have_zero_rust_allocation() {
    let name = "large-name-µ".repeat(600);
    let layout = DirectoryLayout::new(2, name.len()).unwrap();
    let mut region = Region::new(layout);
    let mut directory = Directory::initialize(region.bytes(), layout).unwrap();
    let issuer = Issuer::new();
    assert_zero(|| {
        let token = register(&directory, &issuer, &name);
        let copy = directory.lookup_native(scoped(&name), Some(token)).unwrap();
        assert_eq!(copy.token, token);
        directory
            .update_code_native(scoped(&name), token, code(2))
            .unwrap();
        assert_eq!(
            directory
                .select_current_native(scoped(&name), token, code(1))
                .map(|_| ()),
            Err(DirectoryError::CurrentUnavailable)
        );
        directory.retire_native(scoped(&name), token).unwrap();
        let new = register(&directory, &issuer, &name);
        assert_ne!(new.uid(), token.uid());
        directory.clear().unwrap();
        assert_eq!(
            directory.usage().unwrap(),
            DirectoryUsage {
                heads: 0,
                key_bytes: 0
            }
        );
    });
    assert_zero(|| drop(directory));
    assert!(
        region.bytes()[layout.keys_offset..layout.keys_offset + layout.key_bytes]
            .iter()
            .all(|byte| *byte == 0)
    );
}

#[test]
fn directory_scoped_parallel_one_shot_operations_are_safe_busy_or_success_and_zero_heap() {
    let layout = DirectoryLayout::new(4, 16).unwrap();
    let mut region = Region::new(layout);
    let mut directory = Directory::initialize(region.bytes(), layout).unwrap();
    // Fixture-only counter; deliberately not an assertion of source authority.
    let issuer = AtomicU64::new(1);
    let successes = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let handles = ["one", "two", "tri", "for"].map(|name| {
            scope.spawn(|| {
                let result = assert_zero(|| {
                    directory.register_native(scoped(name), code(1), || {
                        Ok(issuer.fetch_add(1, Ordering::Relaxed))
                    })
                });
                match result {
                    Ok(_) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(DirectoryError::Busy) => {}
                    other => panic!("unexpected one-shot result: {other:?}"),
                }
            })
        });
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert!(successes.load(Ordering::Relaxed) > 0);
    assert_eq!(
        directory.usage().unwrap().heads,
        successes.load(Ordering::Relaxed)
    );
    std::thread::scope(|scope| {
        let handles = ["one", "two", "tri", "for"].map(|name| {
            scope.spawn(|| {
                assert_zero(|| match directory.lookup_native(scoped(name), None) {
                    Ok(head) => assert!(matches!(
                        directory.retire_native(scoped(name), head.token),
                        Ok(()) | Err(DirectoryError::Busy)
                    )),
                    Err(DirectoryError::Busy | DirectoryError::Missing) => {}
                    other => panic!("unexpected lookup result: {other:?}"),
                });
            })
        });
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert_zero(|| directory.clear().unwrap());
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 0,
            key_bytes: 0
        }
    );
}

// One shared FIXTURE owner for actual pool admissions. Its Arc/control is
// allocated before probes, not a production node owner or source authority.
// Both byte and retained-slot quotas apply across ALL admitted fixture pools.
struct FixtureOwner {
    byte_limit: usize,
    cell_limit: usize,
    bytes: AtomicUsize,
    cells: AtomicUsize,
    drops: AtomicUsize,
    // Used ONLY with a standalone region which outlives the lease destructor.
    // Never point this at the combined pool tail (unmapped before lease Drop).
    standalone_gate: AtomicUsize,
    outside_gate_drops: AtomicUsize,
}
impl FixtureOwner {
    fn new(byte_limit: usize, cell_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            byte_limit,
            cell_limit,
            bytes: AtomicUsize::new(0),
            cells: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            standalone_gate: AtomicUsize::new(0),
            outside_gate_drops: AtomicUsize::new(0),
        })
    }
    fn observe_standalone_gate(&self, directory: &Directory<'_>) {
        self.standalone_gate.store(
            &directory.header().gate as *const AtomicBool as usize,
            Ordering::Release,
        );
    }
}
#[repr(align(64))]
struct FixtureLease {
    owner: Arc<FixtureOwner>,
    bytes: usize,
    cells: usize,
    metadata: [u8; 17],
}
impl RegistryAdmission for Arc<FixtureOwner> {
    type Lease = FixtureLease;
    fn try_reserve(&self, bytes: usize, cells: usize) -> Result<FixtureLease, RegistryError> {
        self.bytes
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|&sum| sum <= self.byte_limit)
            })
            .map_err(|_| RegistryError::Capacity)?;
        if self
            .cells
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(cells)
                    .filter(|&sum| sum <= self.cell_limit)
            })
            .is_err()
        {
            self.bytes.fetch_sub(bytes, Ordering::AcqRel);
            return Err(RegistryError::Capacity);
        }
        Ok(FixtureLease {
            owner: self.clone(),
            bytes,
            cells,
            metadata: [5; 17],
        })
    }
}
impl Drop for FixtureLease {
    fn drop(&mut self) {
        assert_eq!(self.metadata, [5; 17]);
        let gate = self.owner.standalone_gate.load(Ordering::Acquire);
        if gate != 0 {
            // Fixture-only observer, valid while its standalone region lives.
            assert!(!unsafe { &*(gate as *const AtomicBool) }.load(Ordering::Acquire));
            self.owner.outside_gate_drops.fetch_add(1, Ordering::AcqRel);
        }
        self.owner.bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        self.owner.cells.fetch_sub(self.cells, Ordering::AcqRel);
        self.owner.drops.fetch_add(1, Ordering::AcqRel);
    }
}
fn fixture_limits(cells: usize) -> RegistryPoolLimits {
    RegistryPoolLimits {
        bytes: HARD_REGISTRY_POOL_BYTES,
        cells,
    }
}
fn fixture_pool(cells: usize) -> (RegistryPool, Arc<FixtureOwner>) {
    let owner = FixtureOwner::new(HARD_REGISTRY_POOL_BYTES, 256);
    let pool = RegistryPool::admit(&owner, fixture_limits(cells), || Ok(())).unwrap();
    (pool, owner)
}
fn fixture_combined_pool(
    cells: usize,
    heads: usize,
    key_bytes: usize,
) -> (RegistryPool, Arc<FixtureOwner>) {
    let owner = FixtureOwner::new(HARD_REGISTRY_POOL_BYTES, 256);
    let pool = RegistryPool::admit_with_directory(
        &owner,
        fixture_limits(cells),
        super::super::pool::RegistryDirectoryLimits { heads, key_bytes },
        || Ok(()),
    )
    .unwrap();
    (pool, owner)
}
fn register_from_pool(
    directory: &Directory<'_>,
    pool: &RegistryPool,
    origin: NativeOrigin<'_>,
    code: NativeCode,
) -> (NativeHeadToken, RegistryNamespace) {
    let namespace = Cell::new(None);
    let token = directory
        .register_native(origin, code, || {
            let issued = pool
                .issue_namespace((origin.epoch != 0).then_some(origin.epoch))
                .map_err(|_| DirectoryError::Capacity)?;
            namespace.set(Some(issued));
            Ok(issued.uid)
        })
        .unwrap();
    (token, namespace.get().unwrap())
}
fn fixture_identity(
    origin: NativeOrigin<'_>,
    namespace: RegistryNamespace,
    code: NativeCode,
) -> RegistryIdentity {
    RegistryIdentity {
        store: origin.store,
        installation: origin.installation,
        registry: code.registry,
        bundle: code.bundle,
        schema: code.schema,
        namespace,
    }
}
fn seal_cell(pool: &RegistryPool, identity: RegistryIdentity, body: &[u8]) -> RegistryCell {
    pool.stage().unwrap().seal(identity, body).unwrap()
}
const OLD_BODY: &[u8] = br#"{"fixture":"old"}"#;
const NEW_BODY: &[u8] = br#"{"fixture":"new"}"#;

#[test]
fn directory_real_root_scoped_and_large_utf8_owners_select_exact_positive_bodies() {
    let large = "名λ".repeat(2000); // 10,000 exact UTF-8 bytes, no per-key cap.
    let (pool, owner) = fixture_combined_pool(3, 3, large.len());
    let directory = pool.directory().unwrap();
    let origins = [
        origin(NativeKey::Root),
        NativeOrigin {
            epoch: 7,
            ..scoped("")
        },
        NativeOrigin {
            store: 42,
            installation: 9,
            epoch: 31,
            key: NativeKey::Scoped(&large),
        },
    ];
    let tokens = origins.map(|origin| {
        assert_zero(|| {
            let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
            let cell = seal_cell(
                &pool,
                fixture_identity(origin, namespace, code(1)),
                OLD_BODY,
            );
            directory
                .attach_current_native(origin, token, code(1), cell)
                .unwrap();
            let selected = directory
                .select_current_native(origin, token, code(1))
                .unwrap();
            assert_eq!(selected.raw_json(), OLD_BODY);
            assert_eq!(selected.identity().namespace, namespace);
            drop(selected);
            token
        })
    });
    assert_eq!(pool.live_cells(), 3);
    assert_ne!(tokens[0].uid(), tokens[1].uid());
    // Returned metadata remains Copy; it does not duplicate/drop ownership.
    let metadata = directory
        .lookup_native(origins[2], Some(tokens[2]))
        .unwrap();
    let copy = metadata;
    assert_eq!(copy, metadata);
    assert_zero(|| drop(directory));
    let view = pool.directory().unwrap();
    assert_eq!(
        view.usage().unwrap().heads,
        3,
        "view Drop must not clear current owners"
    );
    assert_zero(|| {
        drop(
            view.select_current_native(origins[2], tokens[2], code(1))
                .unwrap(),
        )
    });
    drop(view);
    assert_zero(|| drop(pool));
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.cells.load(Ordering::Acquire), 0);
}

#[test]
fn directory_cell_identity_and_requested_code_mismatches_refuse_without_replacing_current() {
    let (pool, _) = fixture_combined_pool(2, 1, 5);
    let directory = pool.directory().unwrap();
    let origin = NativeOrigin {
        epoch: 11,
        installation: 8,
        ..scoped("alpha")
    };
    let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
    let identity = fixture_identity(origin, namespace, code(1));
    directory
        .attach_current_native(origin, token, code(1), seal_cell(&pool, identity, OLD_BODY))
        .unwrap();
    let busy_cell = seal_cell(&pool, identity, NEW_BODY);
    let guard = directory.lock().unwrap();
    assert_eq!(
        assert_zero(|| directory.attach_current_native(origin, token, code(1), busy_cell)),
        Err(DirectoryError::Busy)
    );
    assert_eq!(pool.live_cells(), 1);
    drop(guard);
    for wrong in [
        RegistryIdentity {
            store: identity.store + 1,
            ..identity
        },
        RegistryIdentity {
            installation: identity.installation + 1,
            ..identity
        },
        RegistryIdentity {
            registry: identity.registry + 1,
            ..identity
        },
        RegistryIdentity {
            bundle: identity.bundle + 1,
            ..identity
        },
        RegistryIdentity {
            schema: identity.schema + 1,
            ..identity
        },
        RegistryIdentity {
            namespace: RegistryNamespace {
                uid: namespace.uid + 1,
                ..namespace
            },
            ..identity
        },
        RegistryIdentity {
            namespace: RegistryNamespace {
                epoch: namespace.epoch + 1,
                ..namespace
            },
            ..identity
        },
    ] {
        assert_eq!(
            assert_zero(|| directory.attach_current_native(
                origin,
                token,
                code(1),
                seal_cell(&pool, wrong, NEW_BODY)
            )),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(pool.live_cells(), 1);
        assert_zero(|| {
            let selected = directory
                .select_current_native(origin, token, code(1))
                .unwrap();
            assert_eq!(selected.raw_json(), OLD_BODY);
            drop(selected);
        });
    }
    for requested in [
        code(2),
        NativeCode {
            bundle: 99,
            ..code(1)
        },
        NativeCode {
            schema: 99,
            ..code(1)
        },
    ] {
        assert_eq!(
            assert_zero(|| directory
                .select_current_native(origin, token, requested)
                .map(|_| ())),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(
            assert_zero(|| directory.attach_current_native(
                origin,
                token,
                requested,
                seal_cell(&pool, identity, NEW_BODY)
            )),
            Err(DirectoryError::CurrentUnavailable)
        );
    }
    for wrong in [
        NativeOrigin {
            store: origin.store + 1,
            ..origin
        },
        NativeOrigin {
            installation: origin.installation + 1,
            ..origin
        },
        NativeOrigin {
            epoch: origin.epoch + 1,
            ..origin
        },
        NativeOrigin {
            key: NativeKey::Root,
            ..origin
        },
    ] {
        assert_eq!(
            directory
                .select_current_native(wrong, token, code(1))
                .map(|_| ()),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(
            directory.attach_current_native(
                wrong,
                token,
                code(1),
                seal_cell(&pool, identity, NEW_BODY)
            ),
            Err(DirectoryError::Stale)
        );
    }
    let wrong_uid = NativeHeadToken {
        uid: token.uid + 1,
        ..token
    };
    assert_eq!(
        directory
            .select_current_native(origin, wrong_uid, code(1))
            .map(|_| ()),
        Err(DirectoryError::CurrentUnavailable)
    );
    assert_eq!(
        directory.attach_current_native(
            origin,
            wrong_uid,
            code(1),
            seal_cell(&pool, identity, NEW_BODY)
        ),
        Err(DirectoryError::Stale)
    );
    assert_eq!(pool.live_cells(), 1);
}

#[test]
fn directory_code_update_detaches_owner_old_witness_stays_charged_until_last_drop() {
    let (pool, _) = fixture_combined_pool(2, 1, 1);
    let directory = pool.directory().unwrap();
    let origin = scoped("x");
    let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
    assert_zero(|| {
        directory
            .attach_current_native(
                origin,
                token,
                code(1),
                seal_cell(
                    &pool,
                    fixture_identity(origin, namespace, code(1)),
                    OLD_BODY,
                ),
            )
            .unwrap();
        let old_witness = directory
            .select_current_native(origin, token, code(1))
            .unwrap();
        directory
            .update_code_native(origin, token, code(20))
            .unwrap();
        assert_eq!(pool.live_cells(), 1);
        assert_eq!(old_witness.raw_json(), OLD_BODY);
        for requested in [code(1), code(20)] {
            assert_eq!(
                directory
                    .select_current_native(origin, token, requested)
                    .map(|_| ()),
                Err(DirectoryError::CurrentUnavailable)
            );
        }
        let current = seal_cell(
            &pool,
            fixture_identity(origin, namespace, code(20)),
            NEW_BODY,
        );
        directory
            .attach_current_native(origin, token, code(20), current)
            .unwrap();
        assert_eq!(pool.live_cells(), 2);
        assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
        let selected = directory
            .select_current_native(origin, token, code(20))
            .unwrap();
        assert_eq!(selected.raw_json(), NEW_BODY);
        assert_eq!(old_witness.raw_json(), OLD_BODY);
        drop(old_witness);
        assert_eq!(pool.live_cells(), 1);
        drop(pool.stage().unwrap());
        // Equal-code update conservatively invalidates too, not an old alias.
        directory
            .update_code_native(origin, token, code(20))
            .unwrap();
        assert_eq!(
            directory
                .select_current_native(origin, token, code(20))
                .map(|_| ()),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(selected.raw_json(), NEW_BODY);
        drop(selected);
        assert_eq!(pool.live_cells(), 0);
    });
}

#[test]
fn directory_remove_and_retire_detach_but_old_owned_witnesses_are_not_aba() {
    let (pool, _) = fixture_combined_pool(2, 1, 1);
    let directory = pool.directory().unwrap();
    let origin = scoped("x");
    let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
    assert_zero(|| {
        directory
            .attach_current_native(
                origin,
                token,
                code(1),
                seal_cell(
                    &pool,
                    fixture_identity(origin, namespace, code(1)),
                    OLD_BODY,
                ),
            )
            .unwrap();
        let old = directory
            .select_current_native(origin, token, code(1))
            .unwrap();
        directory.remove_native(origin, token).unwrap();
        assert_eq!(pool.live_cells(), 1);
        assert_eq!(old.raw_json(), OLD_BODY);
        assert_eq!(
            directory
                .select_current_native(origin, token, code(1))
                .map(|_| ()),
            Err(DirectoryError::CurrentUnavailable)
        );
        let (replacement, new_namespace) = register_from_pool(&directory, &pool, origin, code(1));
        assert_ne!(replacement.uid(), token.uid());
        assert_eq!(
            directory.attach_current_native(origin, replacement, code(1), old.try_clone().unwrap()),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(
            directory
                .select_current_native(origin, token, code(1))
                .map(|_| ()),
            Err(DirectoryError::CurrentUnavailable)
        );
        directory
            .attach_current_native(
                origin,
                replacement,
                code(1),
                seal_cell(
                    &pool,
                    fixture_identity(origin, new_namespace, code(1)),
                    NEW_BODY,
                ),
            )
            .unwrap();
        let new = directory
            .select_current_native(origin, replacement, code(1))
            .unwrap();
        directory.retire_native(origin, replacement).unwrap();
        assert_eq!(pool.live_cells(), 2);
        assert_eq!(old.raw_json(), OLD_BODY);
        assert_eq!(new.raw_json(), NEW_BODY);
        drop(old);
        drop(new);
        assert_eq!(pool.live_cells(), 0);
        assert_eq!(
            directory.usage().unwrap(),
            DirectoryUsage {
                heads: 0,
                key_bytes: 0
            }
        );
    });
}

#[test]
fn directory_same_code_replacement_moves_owner_without_duplicating_or_reusing_live_slot() {
    let (pool, _) = fixture_combined_pool(2, 1, 0);
    let directory = pool.directory().unwrap();
    let origin = origin(NativeKey::Root);
    let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
    let identity = fixture_identity(origin, namespace, code(1));
    assert_zero(|| {
        directory
            .attach_current_native(origin, token, code(1), seal_cell(&pool, identity, OLD_BODY))
            .unwrap();
        let old = directory
            .select_current_native(origin, token, code(1))
            .unwrap();
        directory
            .attach_current_native(origin, token, code(1), seal_cell(&pool, identity, NEW_BODY))
            .unwrap();
        let new = directory
            .select_current_native(origin, token, code(1))
            .unwrap();
        assert_eq!(old.raw_json(), OLD_BODY);
        assert_eq!(new.raw_json(), NEW_BODY);
        assert_eq!(pool.live_cells(), 2);
        assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
        drop(old);
        assert_eq!(pool.live_cells(), 1);
        drop(new);
        directory.retire_native(origin, token).unwrap();
        assert_eq!(pool.live_cells(), 0);
    });
}

#[test]
fn directory_borrowed_views_cannot_clear_or_teardown_other_views_and_last_handle_breaks_cycle() {
    let (pool, owner) = fixture_combined_pool(1, 1, 0);
    let clone = pool.try_clone().unwrap();
    let origin = origin(NativeKey::Root);
    let token = {
        let mut one = pool.directory().unwrap();
        let two = clone.directory().unwrap();
        let (token, namespace) = register_from_pool(&one, &pool, origin, code(1));
        one.attach_current_native(
            origin,
            token,
            code(1),
            seal_cell(
                &pool,
                fixture_identity(origin, namespace, code(1)),
                OLD_BODY,
            ),
        )
        .unwrap();
        assert_eq!(assert_zero(|| one.clear()), Err(DirectoryError::Invalid));
        assert_zero(|| drop(one));
        assert_zero(|| drop(two.select_current_native(origin, token, code(1)).unwrap()));
        drop(two);
        token
    };
    assert_zero(|| drop(pool));
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    {
        let directory = clone.directory().unwrap();
        assert_eq!(directory.usage().unwrap().heads, 1);
        assert_zero(|| {
            drop(
                directory
                    .select_current_native(origin, token, code(1))
                    .unwrap(),
            )
        });
    }
    assert_zero(|| drop(clone));
    assert_eq!(
        owner.drops.load(Ordering::Acquire),
        1,
        "last external handle must clear current self-cycle"
    );
    assert_eq!(owner.bytes.load(Ordering::Acquire), 0);
    assert_eq!(owner.cells.load(Ordering::Acquire), 0);
}

#[test]
fn directory_last_pool_drop_detaches_current_but_old_cell_and_staging_keep_quota_live() {
    let (pool, owner) = fixture_combined_pool(2, 1, 0);
    let (witness, staging) = {
        let directory = pool.directory().unwrap();
        let origin = origin(NativeKey::Root);
        let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
        directory
            .attach_current_native(
                origin,
                token,
                code(1),
                seal_cell(
                    &pool,
                    fixture_identity(origin, namespace, code(1)),
                    OLD_BODY,
                ),
            )
            .unwrap();
        (
            directory
                .select_current_native(origin, token, code(1))
                .unwrap(),
            pool.stage().unwrap(),
        )
    };
    let reserved_bytes = owner.bytes.load(Ordering::Acquire);
    assert_zero(|| drop(pool));
    assert_eq!(owner.bytes.load(Ordering::Acquire), reserved_bytes);
    assert_eq!(owner.cells.load(Ordering::Acquire), 2);
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    assert_zero(|| {
        assert_eq!(witness.raw_json(), OLD_BODY);
        drop(witness);
    });
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    assert_zero(|| drop(staging));
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.bytes.load(Ordering::Acquire), 0);
}

#[test]
fn directory_current_old_replacement_share_one_fixture_global_byte_and_cell_quota() {
    let owner = FixtureOwner::new(HARD_REGISTRY_POOL_BYTES, 3);
    let dims = super::super::pool::RegistryDirectoryLimits {
        heads: 1,
        key_bytes: 0,
    };
    let pool =
        RegistryPool::admit_with_directory(&owner, fixture_limits(2), dims, || Ok(())).unwrap();
    let (old, current) = {
        let directory = pool.directory().unwrap();
        let origin = origin(NativeKey::Root);
        let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
        directory
            .attach_current_native(
                origin,
                token,
                code(1),
                seal_cell(
                    &pool,
                    fixture_identity(origin, namespace, code(1)),
                    OLD_BODY,
                ),
            )
            .unwrap();
        let old = directory
            .select_current_native(origin, token, code(1))
            .unwrap();
        directory
            .update_code_native(origin, token, code(2))
            .unwrap();
        directory
            .attach_current_native(
                origin,
                token,
                code(2),
                seal_cell(
                    &pool,
                    fixture_identity(origin, namespace, code(2)),
                    NEW_BODY,
                ),
            )
            .unwrap();
        (
            old,
            directory
                .select_current_native(origin, token, code(2))
                .unwrap(),
        )
    };
    let bytes = owner.bytes.load(Ordering::Acquire);
    assert_eq!(owner.cells.load(Ordering::Acquire), 2);
    assert!(matches!(
        RegistryPool::admit_with_directory(&owner, fixture_limits(2), dims, || Ok(())),
        Err(RegistryError::Capacity)
    ));
    assert_eq!(
        owner.bytes.load(Ordering::Acquire),
        bytes,
        "failed reservation rolls back byte charge"
    );
    assert_zero(|| drop(pool));
    assert_eq!(owner.cells.load(Ordering::Acquire), 2);
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    assert_zero(|| drop(old));
    assert_eq!(
        owner.cells.load(Ordering::Acquire),
        2,
        "whole mapping retains its exact lease until last cell"
    );
    assert_zero(|| {
        assert_eq!(current.raw_json(), NEW_BODY);
        drop(current);
    });
    assert_eq!(owner.cells.load(Ordering::Acquire), 0);
    assert_eq!(owner.bytes.load(Ordering::Acquire), 0);
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    let other =
        RegistryPool::admit_with_directory(&owner, fixture_limits(2), dims, || Ok(())).unwrap();
    assert_zero(|| drop(other));
}

#[test]
fn directory_refusal_update_remove_clear_and_drop_destroy_last_real_cell_outside_gate() {
    for operation in 0..9 {
        let layout = DirectoryLayout::new(1, 0).unwrap();
        let mut region = Region::new(layout);
        let mut directory = Directory::initialize(region.bytes(), layout).unwrap();
        let (pool, owner) = fixture_pool(1);
        owner.observe_standalone_gate(&directory);
        let origin = origin(NativeKey::Root);
        let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
        let mut identity = fixture_identity(origin, namespace, code(1));
        if operation == 8 {
            identity.store += 1;
        }
        let cell = seal_cell(&pool, identity, OLD_BODY);
        if matches!(operation, 0 | 6 | 7 | 8) {
            drop(pool);
            let (requested_origin, requested_token, requested_code, error) = match operation {
                0 => (origin, token, code(2), DirectoryError::CurrentUnavailable),
                6 => (
                    origin,
                    NativeHeadToken {
                        uid: token.uid + 1,
                        ..token
                    },
                    code(1),
                    DirectoryError::Stale,
                ),
                7 => (
                    NativeOrigin {
                        store: origin.store + 1,
                        ..origin
                    },
                    NativeHeadToken {
                        store: token.store + 1,
                        ..token
                    },
                    code(1),
                    DirectoryError::Missing,
                ),
                8 => (origin, token, code(1), DirectoryError::CurrentUnavailable),
                _ => unreachable!(),
            };
            assert_eq!(
                assert_zero(|| directory.attach_current_native(
                    requested_origin,
                    requested_token,
                    requested_code,
                    cell
                )),
                Err(error)
            );
        } else {
            directory
                .attach_current_native(origin, token, code(1), cell)
                .unwrap();
            drop(pool);
            assert_zero(|| match operation {
                1 => {
                    directory
                        .update_code_native(origin, token, code(2))
                        .unwrap();
                }
                2 => {
                    directory.remove_native(origin, token).unwrap();
                }
                3 => {
                    directory.retire_native(origin, token).unwrap();
                }
                4 => {
                    directory.clear().unwrap();
                }
                5 => {
                    drop(directory);
                }
                _ => unreachable!(),
            });
        }
        assert_eq!(owner.drops.load(Ordering::Acquire), 1);
        assert_eq!(owner.outside_gate_drops.load(Ordering::Acquire), 1);
        assert_eq!(owner.bytes.load(Ordering::Acquire), 0);
    }
}

#[test]
fn directory_current_owner_cross_thread_selection_and_cell_clone_are_safe_zero_heap() {
    let (pool, _) = fixture_combined_pool(1, 1, 0);
    let directory = pool.directory().unwrap();
    let origin = origin(NativeKey::Root);
    let (token, namespace) = register_from_pool(&directory, &pool, origin, code(1));
    directory
        .attach_current_native(
            origin,
            token,
            code(1),
            seal_cell(
                &pool,
                fixture_identity(origin, namespace, code(1)),
                OLD_BODY,
            ),
        )
        .unwrap();
    let witness = directory
        .select_current_native(origin, token, code(1))
        .unwrap();
    std::thread::scope(|scope| {
        let handles = std::array::from_fn::<_, 4, _>(|_| {
            scope.spawn(|| {
                assert_zero(|| {
                    let clone = witness.try_clone().unwrap();
                    assert_eq!(clone.raw_json(), OLD_BODY);
                    match directory.select_current_native(origin, token, code(1)) {
                        Ok(current) => {
                            assert_eq!(current.identity(), clone.identity());
                            assert_eq!(current.raw_json(), OLD_BODY);
                            drop(current);
                        }
                        Err(DirectoryError::Busy) => {}
                        Err(_) => panic!("unexpected current selection refusal"),
                    }
                    drop(clone);
                });
            })
        });
        for handle in handles {
            handle.join().unwrap();
        }
    });
    assert_eq!(pool.live_cells(), 1);
    assert_zero(|| drop(witness));
}
