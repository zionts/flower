use super::*;
use crate::allocation_probe;
use std::sync::Arc;

// This fixture owner is NOT the native node contract. It is deliberately an
// allocated test object created before probes; the concrete production owner
// must separately prove its own global backing and outside-control admission.
struct Owner {
    bytes: usize,
    cells: usize,
    leased: AtomicBool,
    reserved_bytes: AtomicUsize,
    reserved_cells: AtomicUsize,
    drops: AtomicUsize,
    address: AtomicUsize,
    unmapped_before_release: AtomicBool,
}
impl Owner {
    fn new(bytes: usize, cells: usize) -> Arc<Self> {
        Arc::new(Self {
            bytes,
            cells,
            leased: AtomicBool::new(false),
            reserved_bytes: AtomicUsize::new(0),
            reserved_cells: AtomicUsize::new(0),
            drops: AtomicUsize::new(0),
            address: AtomicUsize::new(0),
            unmapped_before_release: AtomicBool::new(false),
        })
    }
    fn remember(&self, pool: &RegistryPool) {
        self.address
            .store(pool.control.as_ptr() as usize, Ordering::Release);
    }
}
#[repr(align(64))]
struct Lease {
    owner: Arc<Owner>,
    bytes: usize,
    cells: usize,
    // The actual concrete lease size/alignment is part of the map, not an
    // uncharged Box/dyn object or a guessed Arc allocator header.
    inline_metadata: [u8; 65],
}
impl RegistryAdmission for Arc<Owner> {
    type Lease = Lease;
    fn try_reserve(&self, bytes: usize, cells: usize) -> Result<Lease, RegistryError> {
        if bytes > self.bytes || cells > self.cells {
            return Err(RegistryError::Capacity);
        }
        self.leased
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| RegistryError::Capacity)?;
        self.reserved_bytes.store(bytes, Ordering::Release);
        self.reserved_cells.store(cells, Ordering::Release);
        Ok(Lease {
            owner: self.clone(),
            bytes,
            cells,
            inline_metadata: [7; 65],
        })
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        assert_eq!(self.inline_metadata, [7; 65]);
        assert_eq!(
            self.owner.reserved_bytes.load(Ordering::Acquire),
            self.bytes
        );
        assert_eq!(
            self.owner.reserved_cells.load(Ordering::Acquire),
            self.cells
        );
        #[cfg(target_os = "linux")]
        {
            let address = self.owner.address.load(Ordering::Acquire);
            if address != 0 {
                let mut residency = 0u8;
                let result = unsafe {
                    libc::mincore(
                        address as *mut libc::c_void,
                        page_size().unwrap(),
                        &mut residency,
                    )
                };
                self.owner
                    .unmapped_before_release
                    .store(result == -1, Ordering::Release);
            }
        }
        self.owner.reserved_bytes.store(0, Ordering::Release);
        self.owner.reserved_cells.store(0, Ordering::Release);
        self.owner.drops.fetch_add(1, Ordering::AcqRel);
        self.owner.leased.store(false, Ordering::Release);
    }
}
fn limits(cells: usize) -> RegistryPoolLimits {
    RegistryPoolLimits {
        bytes: HARD_REGISTRY_POOL_BYTES,
        cells,
    }
}
fn pool(cells: usize) -> (RegistryPool, Arc<Owner>) {
    let owner = Owner::new(HARD_REGISTRY_POOL_BYTES, HARD_REGISTRY_POOL_CELLS);
    let pool = RegistryPool::admit(&owner, limits(cells), || Ok(())).unwrap();
    owner.remember(&pool);
    (pool, owner)
}
// Native-layout fixture scalar ONLY. This does not issue a Store registry
// witness or prove actual publication/binding semantics (not wired yet).
fn root_namespace() -> RegistryNamespace {
    RegistryNamespace { uid: 1, epoch: 0 }
}
fn identity(registry: u64) -> RegistryIdentity {
    RegistryIdentity {
        store: 1,
        installation: 0,
        registry,
        bundle: registry + 1,
        schema: registry + 2,
        namespace: root_namespace(),
    }
}
fn cell(pool: &RegistryPool, registry: u64) -> RegistryCell {
    pool.stage()
        .unwrap()
        .seal(identity(registry), br#"{"format":1,"methods":{}}"#)
        .unwrap()
}

#[test]
fn sql_registry_pool_layout_counts_actual_inline_header_lease_pages_and_effective_cells() {
    let layout = RegistryPool::reservation_layout::<Arc<Owner>>(RegistryPoolLimits::HARD).unwrap();
    assert_eq!(layout.payload_bytes, 32768);
    assert_eq!(layout.lease_bytes, std::mem::size_of::<Lease>());
    assert_eq!(layout.slot_bytes, std::mem::size_of::<RegistrySlot>());
    assert_eq!(
        layout.slot_header_bytes + layout.payload_bytes,
        layout.slot_bytes
    );
    assert!(layout.slot_header_bytes >= 7 * 8 + std::mem::size_of::<AtomicUsize>());
    assert_eq!(layout.lease_offset % std::mem::align_of::<Lease>(), 0);
    assert_eq!(
        layout.slots_offset % std::mem::align_of::<RegistrySlot>(),
        0
    );
    assert_eq!(layout.mapped_bytes % layout.page_bytes, 0);
    assert!(layout.mapped_bytes <= RegistryPoolLimits::HARD.bytes);
    assert_eq!(layout.cells, 256);
    let lower = RegistryPool::reservation_layout::<Arc<Owner>>(RegistryPoolLimits {
        bytes: layout.page_bytes * 11,
        cells: 256,
    })
    .unwrap();
    assert_eq!(
        lower.cells, 1,
        "lower byte budget must not advertise 256 usable slots"
    );
    assert!(lower.mapped_bytes <= layout.page_bytes * 11);
    println!(
        "registry layout page={} control={} lease={} slot={} header={} payload={} cells={} map={}",
        layout.page_bytes,
        layout.control_bytes,
        layout.lease_bytes,
        layout.slot_bytes,
        layout.slot_header_bytes,
        layout.payload_bytes,
        layout.cells,
        layout.mapped_bytes
    );
}

#[test]
fn sql_registry_pool_unapproved_higher_zero_tiny_and_overaligned_limits_refuse_before_mapping() {
    for limits in [
        RegistryPoolLimits { bytes: 0, cells: 1 },
        RegistryPoolLimits { bytes: 1, cells: 0 },
        RegistryPoolLimits {
            bytes: HARD_REGISTRY_POOL_BYTES + 1,
            cells: 1,
        },
        RegistryPoolLimits {
            bytes: HARD_REGISTRY_POOL_BYTES,
            cells: HARD_REGISTRY_POOL_CELLS + 1,
        },
    ] {
        assert_eq!(
            RegistryPool::reservation_layout::<Arc<Owner>>(limits),
            Err(RegistryError::Invalid)
        );
    }
    assert_eq!(
        RegistryPool::reservation_layout::<Arc<Owner>>(RegistryPoolLimits { bytes: 1, cells: 1 }),
        Err(RegistryError::Capacity)
    );
    #[repr(align(65536))]
    struct Overaligned;
    assert_eq!(
        RegistryPoolLayout::for_lease::<Overaligned>(limits(1)),
        Err(RegistryError::Unsupported)
    );
    let refused = Owner::new(1, 1);
    assert!(matches!(
        RegistryPool::admit(&refused, limits(1), || Ok(())),
        Err(RegistryError::Capacity)
    ));
    assert!(!refused.leased.load(Ordering::Acquire));
}

#[test]
fn sql_registry_pool_node_owner_is_required_and_shared_handles_do_not_create_new_reservations() {
    let (pool, owner) = pool(2);
    let sibling = pool.try_clone().unwrap();
    assert_eq!(sibling.control, pool.control);
    assert_eq!(
        sibling.mapped_bytes(),
        owner.reserved_bytes.load(Ordering::Acquire)
    );
    assert!(matches!(
        RegistryPool::admit(&owner, limits(2), || Ok(())),
        Err(RegistryError::Capacity)
    ));
    drop(pool);
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    drop(sibling);
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    #[cfg(target_os = "linux")]
    assert!(owner.unmapped_before_release.load(Ordering::Acquire));
}

#[test]
fn sql_registry_pool_current_old_witness_replacement_and_staging_all_consume_slots_until_last_owner()
 {
    let (pool, owner) = pool(3);
    let current = cell(&pool, 1);
    let old_witness = current.try_clone().unwrap();
    let replacement = cell(&pool, 10);
    let staging = pool.stage().unwrap();
    assert_eq!(pool.live_cells(), 3);
    assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
    drop(current);
    assert_eq!(
        pool.live_cells(),
        3,
        "old witness remains the actual backing owner"
    );
    assert_eq!(old_witness.identity(), identity(1));
    assert_eq!(old_witness.raw_json(), br#"{"format":1,"methods":{}}"#);
    drop(old_witness);
    assert_eq!(pool.live_cells(), 2);
    let newcomer = cell(&pool, 20);
    assert_eq!(pool.live_cells(), 3);
    drop(staging);
    drop(replacement);
    drop(pool);
    assert_eq!(
        owner.drops.load(Ordering::Acquire),
        0,
        "cell still owns pool mapping/lease"
    );
    assert_eq!(newcomer.identity(), identity(20));
    drop(newcomer);
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    #[cfg(target_os = "linux")]
    assert!(owner.unmapped_before_release.load(Ordering::Acquire));
}

#[test]
fn sql_registry_pool_payload_and_source_issued_namespace_uid_are_exact_not_name_hashes_or_empty_fallback()
 {
    let (pool, _) = pool(2);
    let namespace = pool.issue_namespace(Some(7)).unwrap();
    let other_same_epoch = pool.issue_namespace(Some(7)).unwrap();
    let next_epoch = pool.issue_namespace(Some(8)).unwrap();
    assert_ne!(namespace, other_same_epoch);
    assert_ne!(namespace, next_epoch);
    let body = vec![b' '; MAX_REGISTRY_BYTES];
    let bound = RegistryIdentity {
        namespace,
        ..identity(1)
    };
    let complete = pool.stage().unwrap().seal(bound, &body).unwrap();
    assert_eq!(complete.raw_json().len(), MAX_REGISTRY_BYTES);
    assert!(complete.matches_namespace(namespace));
    assert!(!complete.matches_namespace(root_namespace()));
    assert!(!complete.matches_namespace(other_same_epoch));
    assert!(!complete.matches_namespace(next_epoch));
    let other = cell(&pool, 9);
    assert!(other.matches_namespace(root_namespace()));
    assert!(!other.matches_namespace(namespace));
    drop(other);
    for body in [
        &b""[..],
        &b"\xff"[..],
        &vec![b' '; MAX_REGISTRY_BYTES + 1][..],
    ] {
        assert!(matches!(
            pool.stage().unwrap().seal(identity(2), body),
            Err(RegistryError::Invalid)
        ));
        assert_eq!(
            pool.live_cells(),
            1,
            "failed staging releases exactly its own slot"
        );
    }
    for invalid in [0, 9_007_199_254_740_992] {
        assert_eq!(
            pool.issue_namespace(Some(invalid)),
            Err(RegistryError::Invalid)
        );
    }
    let invalid = RegistryIdentity {
        registry: 0,
        ..identity(2)
    };
    assert!(matches!(
        pool.stage().unwrap().seal(invalid, b"{}"),
        Err(RegistryError::Invalid)
    ));
    assert_eq!(pool.live_cells(), 1);
}

#[test]
fn sql_registry_pool_cancelled_pretouch_releases_native_lease_without_publishing_pool() {
    let owner = Owner::new(HARD_REGISTRY_POOL_BYTES, HARD_REGISTRY_POOL_CELLS);
    let mut checks = 0;
    let result = RegistryPool::admit(&owner, limits(8), || {
        checks += 1;
        if checks == 4 {
            Err(RegistryError::Cancelled)
        } else {
            Ok(())
        }
    });
    assert!(matches!(result, Err(RegistryError::Cancelled)));
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.reserved_bytes.load(Ordering::Acquire), 0);
    assert!(!owner.leased.load(Ordering::Acquire));
    let admitted = RegistryPool::admit(&owner, limits(8), || Ok(())).unwrap();
    assert_eq!(admitted.live_cells(), 0);
}

#[test]
fn sql_registry_pool_native_namespace_issuance_is_checked_monotonic_and_in_admitted_control() {
    let (pool, _) = pool(1);
    let root = pool.issue_namespace(None).unwrap();
    let scoped = pool.issue_namespace(Some(7)).unwrap();
    let same_epoch = pool.issue_namespace(Some(7)).unwrap();
    assert_eq!(root.epoch, 0);
    assert_eq!(scoped.epoch, 7);
    assert!(root.uid > 0 && root.uid < scoped.uid && scoped.uid < same_epoch.uid);
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(next_namespace(&counter), Ok(u64::MAX - 1));
    assert_eq!(next_namespace(&counter), Err(RegistryError::Capacity));
    assert_eq!(counter.load(Ordering::Acquire), u64::MAX);
    assert_eq!(next_namespace(&counter), Err(RegistryError::Capacity));
}

#[test]
fn sql_registry_pool_native_slot_copy_clone_exhaustion_and_release_allocate_zero_heap() {
    let (pool, _) = pool(2);
    let namespace = pool.issue_namespace(Some(1)).unwrap();
    let ((), allocations, bytes) = allocation_probe::measure(|| {
        let gate = StageGuard::try_acquire(&pool.header().stage_gate).unwrap();
        assert!(matches!(pool.stage(), Err(RegistryError::Busy)));
        drop(gate);
        let one = pool
            .stage()
            .unwrap()
            .seal(
                RegistryIdentity {
                    namespace,
                    ..identity(1)
                },
                b"{}",
            )
            .unwrap();
        let witness = one.try_clone().unwrap();
        let two = cell(&pool, 4);
        assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
        assert!(witness.matches_namespace(namespace));
        assert_eq!(witness.raw_json(), b"{}");
        drop(one);
        drop(witness);
        drop(two);
        let empty = cell(&pool, 9);
        assert_eq!(empty.raw_json(), br#"{"format":1,"methods":{}}"#);
        drop(empty);
    });
    assert_eq!((allocations, bytes), (0, 0));
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn sql_registry_pool_parallel_producers_and_witnesses_never_reuse_live_bytes_or_exceed_slots() {
    let (pool, _) = pool(4);
    let handles: Vec<_> = (0..4).map(|_| pool.try_clone().unwrap()).collect();
    let threads: Vec<_> = handles
        .into_iter()
        .enumerate()
        .map(|(worker, handle)| {
            std::thread::spawn(move || {
                let mut accepted = 0;
                let mut busy = 0;
                for n in 0..1000 {
                    // Independent fresh operation per fixture iteration, no retry
                    // or polling of a refused request. Nonwaiting admission may be
                    // Busy; only one slot per other worker can be occupied, so
                    // genuine Capacity here would violate serialized admission.
                    let staging = match handle.stage() {
                        Ok(staging) => staging,
                        Err(RegistryError::Busy) => {
                            busy += 1;
                            continue;
                        }
                        Err(error) => panic!("unexpected admission result: {error:?}"),
                    };
                    let value = (worker * 1000 + n) as u64 + 1;
                    let one = staging
                        .seal(identity(value), br#"{"format":1,"methods":{}}"#)
                        .unwrap();
                    let witness = one.try_clone().unwrap();
                    std::thread::yield_now();
                    assert_eq!(witness.identity(), identity(value));
                    assert_eq!(one.raw_json(), br#"{"format":1,"methods":{}}"#);
                    assert!(handle.live_cells() <= handle.capacity());
                    drop(one);
                    assert_eq!(witness.identity(), identity(value));
                    drop(witness);
                    accepted += 1;
                }
                (accepted, busy)
            })
        })
        .collect();
    let (mut accepted, mut busy) = (0, 0);
    for thread in threads {
        let counts = thread.join().unwrap();
        accepted += counts.0;
        busy += counts.1;
    }
    assert_eq!(accepted + busy, 4000);
    assert!(
        accepted > 0,
        "useful operations must succeed, not only refuse"
    );
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn sql_registry_pool_moving_vacancy_cannot_be_claimed_behind_serialized_scan() {
    let (pool, _) = pool(2);
    let occupied = cell(&pool, 1);
    pool.header().next_slot.store(0, Ordering::Release);
    let gate = StageGuard::try_acquire(&pool.header().stage_gate).unwrap();
    // Reproduce the unsafe moving-scan interleaving: A observes slot0 occupied,
    // then B frees slot0 and wants to consume the formerly free slot1.
    assert_eq!(
        unsafe { occupied.slot.as_ref().references.load(Ordering::Acquire) },
        1
    );
    drop(occupied);
    assert_eq!(pool.live_cells(), 0);
    // B cannot move that vacancy while A owns admission. This is Busy (no
    // waiting/polling), NOT a false Capacity claim with available backing.
    assert!(matches!(pool.stage(), Err(RegistryError::Busy)));
    let a = pool.stage_locked(&gate).unwrap();
    assert_eq!(pool.live_cells(), 1);
    drop(gate);
    let b = pool.stage().unwrap();
    assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
    drop(a);
    drop(b);
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn sql_registry_pool_reference_exhaustion_is_fail_closed_not_wrapping_or_unaccounted() {
    let (pool, _) = pool(2);
    let one = cell(&pool, 1);
    let references = unsafe { &one.slot.as_ref().references };
    references.store(MAX_REFERENCES, Ordering::Release);
    assert!(matches!(one.try_clone(), Err(RegistryError::Capacity)));
    assert_eq!(references.load(Ordering::Acquire), MAX_REFERENCES);
    references.store(1, Ordering::Release);
    let owners = unsafe { &pool.control.as_ref().owners };
    owners.store(MAX_REFERENCES, Ordering::Release);
    assert!(matches!(pool.try_clone(), Err(RegistryError::Capacity)));
    assert!(matches!(pool.stage(), Err(RegistryError::Capacity)));
    assert_eq!(owners.load(Ordering::Acquire), MAX_REFERENCES);
    owners.store(2, Ordering::Release);
    drop(one);
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn sql_registry_pool_staging_unwind_returns_slot_and_preserves_current_witness() {
    let (pool, _) = pool(2);
    let current = cell(&pool, 1);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _staging = pool.stage().unwrap();
        panic!("expected isolated staging unwind");
    }));
    assert!(result.is_err());
    assert_eq!(pool.live_cells(), 1);
    assert_eq!(current.identity(), identity(1));
    assert!(pool.stage().is_ok());
}
