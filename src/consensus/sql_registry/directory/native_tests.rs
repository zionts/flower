//! Exact-production-file component fixtures, NOT actual Store/source/node,
//! publication guard, route activation or whole native stack proof.
use super::*;

fn published(
    directory: &Directory<'_>,
    pool: &RegistryPool,
    origin: NativeOrigin<'_>,
    expected: Option<NativeHeadToken>,
    code: NativeCode,
    bytes: &[u8],
) -> NativePublication {
    let body = assert_zero(|| pool.prepare_body(bytes).unwrap());
    assert_zero(|| {
        directory
            .publish_prepared_native(origin, expected, code, body)
            .unwrap()
    })
}
fn current_bytes(
    directory: &Directory<'_>,
    origin: NativeOrigin<'_>,
    metadata: HeadMetadata,
    bytes: &[u8],
) {
    assert_zero(|| {
        let current = directory
            .select_current_native(origin, metadata.token, metadata.code)
            .unwrap();
        assert_eq!(current.raw_json(), bytes);
        assert_eq!(current.identity().schema, metadata.code.schema);
        assert_eq!(current.identity().namespace.uid, metadata.token.uid());
        drop(current);
    });
}

#[test]
fn directory_native_layout_initializes_actual_status_and_owner_scratch_types() {
    let layout = DirectoryLayout::new(3, 17).unwrap();
    let mut region = Region::new(layout);
    region.bytes().fill(0xa5);
    let directory = assert_zero(|| Directory::initialize(region.bytes(), layout).unwrap());
    let guard = directory.lock().unwrap();
    for index in 0..layout.heads {
        assert_eq!(directory.status_slot(index).load(Ordering::Acquire), 0);
        assert!(unsafe { &*directory.owner_pointer(&guard, index) }.is_none());
        assert!(unsafe { &*(*directory.retired_pointer().as_ptr().add(index)).get() }.is_none());
        assert_eq!(directory.head(&guard, index).uid, 0);
    }
    assert_eq!(directory.counts(&guard).heads, 0);
    assert_eq!(directory.counts(&guard).key_bytes, 0);
    assert!(
        unsafe { std::slice::from_raw_parts(directory.keys(), layout.key_bytes) }
            .iter()
            .all(|&byte| byte == 0)
    );
    drop(guard);
    assert_zero(|| drop(directory));
}

#[test]
fn directory_native_store_slots_are_explicit_bounded_and_domain_exact_zero_heap() {
    let (pool, _) = fixture_combined_pool(1, 2, 0);
    let directory = pool.directory().unwrap();
    assert_zero(|| {
        assert_eq!(
            directory.store_status_native(1),
            Ok(SourceStatus::Unregistered)
        );
        assert_eq!(
            directory.require_ready_native(1),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(
            directory.ready_store_native(1),
            Err(DirectoryError::CurrentUnavailable)
        );
        for store in [0, MAX_NATIVE_STORE_ID + 1, u64::MAX] {
            assert_eq!(
                directory.prepare_store_native(store),
                Err(DirectoryError::Invalid)
            );
            assert_eq!(
                directory.store_status_native(store),
                Err(DirectoryError::Invalid)
            );
            assert_eq!(
                directory.fatal_store_native(store),
                Err(DirectoryError::Invalid)
            );
            assert_eq!(
                directory.retire_store_native(store),
                Err(DirectoryError::Invalid)
            );
            assert_eq!(
                directory.register_native(
                    NativeOrigin {
                        store,
                        ..origin(NativeKey::Root)
                    },
                    code(1),
                    || panic!("invalid native domain issued UID")
                ),
                Err(DirectoryError::Invalid)
            );
        }
        directory.prepare_store_native(MAX_NATIVE_STORE_ID).unwrap();
        assert_eq!(
            directory.store_status_native(MAX_NATIVE_STORE_ID),
            Ok(SourceStatus::Preparing)
        );
        assert_eq!(
            directory.require_ready_native(MAX_NATIVE_STORE_ID),
            Err(DirectoryError::CurrentUnavailable)
        );
        directory.ready_store_native(MAX_NATIVE_STORE_ID).unwrap();
        assert_eq!(
            directory.store_status_native(MAX_NATIVE_STORE_ID),
            Ok(SourceStatus::Ready)
        );
        assert_eq!(
            directory.prepare_store_native(MAX_NATIVE_STORE_ID),
            Err(DirectoryError::AlreadyCurrent)
        );
        assert_eq!(
            directory.ready_store_native(MAX_NATIVE_STORE_ID),
            Err(DirectoryError::CurrentUnavailable)
        );
        directory.prepare_store_native(1).unwrap();
        assert_eq!(
            directory.prepare_store_native(2),
            Err(DirectoryError::Capacity)
        );
        assert_eq!(directory.fatal_store_native(1), Ok(SourceStatus::Fatal));
        assert_eq!(
            directory.ready_store_native(1),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert_eq!(
            directory.prepare_store_native(1),
            Err(DirectoryError::AlreadyCurrent)
        );
        assert_eq!(directory.fatal_store_native(1), Ok(SourceStatus::Fatal));
        assert_eq!(directory.require_ready_native(MAX_NATIVE_STORE_ID), Ok(()));
        directory.retire_store_native(1).unwrap();
        assert_eq!(
            directory.store_status_native(1),
            Ok(SourceStatus::Unregistered)
        );
        directory.prepare_store_native(2).unwrap(); // NEW never-reused identity
        assert_eq!(
            directory.store_status_native(2),
            Ok(SourceStatus::Preparing)
        );
    });
    assert_eq!(directory.usage().unwrap().heads, 0);
}

#[test]
fn directory_native_upper_domain_store_publishes_exact_without_namespace_truncation() {
    let (pool, _) = fixture_combined_pool(1, 1, 0);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, MAX_NATIVE_STORE_ID);
    let origin = NativeOrigin {
        store: MAX_NATIVE_STORE_ID,
        installation: u64::MAX,
        ..origin(NativeKey::Root)
    };
    let publication = published(&directory, &pool, origin, None, code(1), OLD_BODY);
    let cell = directory
        .select_current_native(
            origin,
            publication.metadata.token,
            publication.metadata.code,
        )
        .unwrap();
    assert_eq!(cell.identity().store, MAX_NATIVE_STORE_ID);
    assert_eq!(cell.identity().installation, u64::MAX);
    assert_eq!(cell.raw_json(), OLD_BODY);
    assert_eq!(
        directory.status_slot(0).load(Ordering::Acquire),
        status_word(MAX_NATIVE_STORE_ID, READY)
    );
    drop(cell);
    assert_zero(|| directory.retire_store_native(MAX_NATIVE_STORE_ID).unwrap());
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn directory_native_unknown_preparing_fatal_refuse_and_unaffected_store_stays_useful() {
    let (pool, _) = fixture_combined_pool(4, 2, 2);
    let directory = pool.directory().unwrap();
    // Deliberate split fixture body; unknown source must NEVER become Ready by
    // virtue of a numerically plausible head or a real owned Cell.
    let one = scoped("a");
    let token = directory
        .register_native(one, code(1), || Ok(pool.issue_namespace(None).unwrap().uid))
        .unwrap();
    let cell = seal_cell(
        &pool,
        fixture_identity(
            one,
            RegistryNamespace {
                uid: token.uid(),
                epoch: 0,
            },
            code(1),
        ),
        OLD_BODY,
    );
    directory
        .attach_current_native(one, token, code(1), cell)
        .unwrap();
    for expected_status in [SourceStatus::Unregistered, SourceStatus::Preparing] {
        assert_eq!(directory.store_status_native(1), Ok(expected_status));
        assert_eq!(
            directory.lookup_native(one, Some(token)),
            Err(DirectoryError::CurrentUnavailable)
        );
        assert!(matches!(
            directory.select_current_native(one, token, code(1)),
            Err(DirectoryError::CurrentUnavailable)
        ));
        if expected_status == SourceStatus::Unregistered {
            directory.prepare_store_native(1).unwrap();
        }
    }
    directory.ready_store_native(1).unwrap();
    current_bytes(
        &directory,
        one,
        HeadMetadata {
            token,
            code: code(1),
        },
        OLD_BODY,
    );
    let two = NativeOrigin {
        store: 2,
        key: NativeKey::Scoped("b"),
        ..one
    };
    fixture_ready(&directory, 2);
    let other = published(&directory, &pool, two, None, code(20), NEW_BODY);
    let guard = directory.lock().unwrap();
    assert_zero(|| assert_eq!(directory.fatal_store_native(1), Ok(SourceStatus::Fatal)));
    assert_eq!(directory.ready_store_native(1), Err(DirectoryError::Busy));
    drop(guard);
    assert_eq!(
        directory.ready_store_native(1),
        Err(DirectoryError::CurrentUnavailable)
    );
    assert!(matches!(
        directory.select_current_native(one, token, code(1)),
        Err(DirectoryError::CurrentUnavailable)
    ));
    assert_eq!(
        directory.lookup_native(one, Some(token)),
        Err(DirectoryError::CurrentUnavailable)
    );
    let rejected = pool.prepare_body(NEW_BODY).unwrap();
    assert!(matches!(
        directory.publish_prepared_native(one, Some(token), code(20), rejected),
        Err(DirectoryError::CurrentUnavailable)
    ));
    current_bytes(&directory, two, other.metadata, NEW_BODY);
    assert_eq!(pool.live_cells(), 2);
}

#[test]
fn directory_native_atomic_prepared_present_absent_and_incarnations_are_complete() {
    let (pool, _) = fixture_combined_pool(4, 1, 5);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    let origin = NativeOrigin {
        epoch: 7,
        installation: 8,
        ..scoped("alpha")
    };
    let first = published(&directory, &pool, origin, None, code(1), OLD_BODY);
    assert!(first.detached.is_none());
    let witness = directory
        .select_current_native(origin, first.metadata.token, first.metadata.code)
        .unwrap();
    let absent = NativeCode {
        schema: SourceStamp::KnownAbsent,
        ..code(20)
    };
    let second = published(
        &directory,
        &pool,
        origin,
        Some(first.metadata.token),
        absent,
        NEW_BODY,
    );
    assert_eq!(second.metadata.token, first.metadata.token);
    assert_eq!(second.detached.as_ref().unwrap().raw_json(), OLD_BODY);
    assert_eq!(witness.raw_json(), OLD_BODY);
    current_bytes(&directory, origin, second.metadata, NEW_BODY);
    assert!(matches!(
        directory.select_current_native(origin, first.metadata.token, first.metadata.code),
        Err(DirectoryError::CurrentUnavailable)
    ));
    assert_zero(|| drop(second.detached));
    let third = published(
        &directory,
        &pool,
        origin,
        Some(second.metadata.token),
        code(1),
        OLD_BODY,
    );
    assert_eq!(third.metadata.token, first.metadata.token);
    assert_eq!(
        third.detached.as_ref().unwrap().identity().schema,
        SourceStamp::KnownAbsent
    );
    assert_zero(|| drop(third.detached));
    for next in [
        NativeOrigin {
            installation: 9,
            ..origin
        },
        NativeOrigin {
            installation: 9,
            epoch: 8,
            ..origin
        },
    ] {
        let old = directory
            .lookup_native(
                NativeOrigin {
                    installation: if next.epoch == 7 { 8 } else { 9 },
                    epoch: 7,
                    ..origin
                },
                None,
            )
            .unwrap();
        let replacement = published(&directory, &pool, next, Some(old.token), code(20), NEW_BODY);
        assert_ne!(replacement.metadata.token.uid(), old.token.uid());
        current_bytes(&directory, next, replacement.metadata, NEW_BODY);
        assert!(matches!(
            directory.select_current_native(next, old.token, code(20)),
            Err(DirectoryError::CurrentUnavailable)
        ));
        assert_zero(|| drop(replacement.detached));
    }
    assert_eq!(witness.raw_json(), OLD_BODY);
    assert_eq!(pool.live_cells(), 2); // current + old witness, not old heads
    drop(witness);
    assert_eq!(pool.live_cells(), 1);
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 1,
            key_bytes: 5
        }
    );
}

#[test]
fn directory_native_atomic_refusals_keep_complete_old_owner_metadata_and_key() {
    let (pool, _) = fixture_combined_pool(3, 1, 5);
    let (foreign, _) = fixture_combined_pool(1, 1, 5);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    let origin = NativeOrigin {
        epoch: 7,
        ..scoped("alpha")
    };
    let old = published(&directory, &pool, origin, None, code(1), OLD_BODY).metadata;
    let baseline = directory.usage().unwrap();
    let rejected = foreign.prepare_body(NEW_BODY).unwrap();
    assert!(matches!(
        assert_zero(|| directory.publish_prepared_native(
            origin,
            Some(old.token),
            code(20),
            rejected
        )),
        Err(DirectoryError::CurrentUnavailable)
    ));
    assert_eq!(foreign.live_cells(), 0);
    let body = pool.prepare_body(NEW_BODY).unwrap();
    let guard = directory.lock().unwrap();
    assert!(matches!(
        assert_zero(|| directory.publish_prepared_native(origin, Some(old.token), code(20), body)),
        Err(DirectoryError::Busy)
    ));
    drop(guard);
    for (next, expected, next_code, error) in [
        (origin, None, code(20), DirectoryError::AlreadyCurrent),
        (
            origin,
            Some(NativeHeadToken {
                uid: old.token.uid() + 1,
                ..old.token
            }),
            code(20),
            DirectoryError::Stale,
        ),
        (
            NativeOrigin {
                key: NativeKey::Scoped("bravo"),
                ..origin
            },
            Some(old.token),
            code(20),
            DirectoryError::Stale,
        ),
        (
            NativeOrigin {
                key: NativeKey::Root,
                ..origin
            },
            Some(old.token),
            code(20),
            DirectoryError::Stale,
        ),
        (
            NativeOrigin { store: 2, ..origin },
            Some(old.token),
            code(20),
            DirectoryError::CurrentUnavailable,
        ),
        (
            NativeOrigin {
                store: MAX_NATIVE_STORE_ID + 1,
                ..origin
            },
            Some(old.token),
            code(20),
            DirectoryError::Invalid,
        ),
        (
            origin,
            Some(old.token),
            NativeCode {
                registry: 0,
                ..code(20)
            },
            DirectoryError::Invalid,
        ),
        (
            NativeOrigin {
                key: NativeKey::Scoped("bravo"),
                ..origin
            },
            None,
            code(20),
            DirectoryError::Capacity,
        ),
    ] {
        let body = pool.prepare_body(NEW_BODY).unwrap();
        assert!(
            matches!(assert_zero(|| directory.publish_prepared_native(next, expected, next_code, body)), Err(actual) if actual == error)
        );
        assert_eq!(
            directory.lookup_native(origin, Some(old.token)).unwrap(),
            old
        );
        assert_eq!(directory.usage().unwrap(), baseline);
        assert_eq!(pool.live_cells(), 1);
        current_bytes(&directory, origin, old, OLD_BODY);
    }
    // Cell quota refusal occurs in preparation, also BEFORE namespace mutation.
    let a = pool.prepare_body(NEW_BODY).unwrap();
    let b = pool.prepare_body(NEW_BODY).unwrap();
    assert!(matches!(
        assert_zero(|| pool.prepare_body(NEW_BODY)),
        Err(RegistryError::Capacity)
    ));
    current_bytes(&directory, origin, old, OLD_BODY);
    assert_zero(|| {
        drop(a);
        drop(b);
    });
}

#[test]
fn directory_native_atomic_key_quota_and_fragmentation_refuse_before_live_mutation() {
    let (pool, _) = fixture_combined_pool(4, 4, 12);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    let metas = ["aaa", "bbb", "ccc"]
        .map(|name| published(&directory, &pool, scoped(name), None, code(1), OLD_BODY).metadata);
    directory
        .remove_native(scoped("bbb"), metas[1].token)
        .unwrap();
    let baseline = directory.usage().unwrap();
    for name in ["dddddd", "longer-than-total-arena"] {
        let body = pool.prepare_body(NEW_BODY).unwrap();
        assert!(matches!(
            assert_zero(|| directory.publish_prepared_native(scoped(name), None, code(20), body)),
            Err(DirectoryError::Capacity)
        ));
        assert_eq!(directory.usage().unwrap(), baseline);
        current_bytes(&directory, scoped("aaa"), metas[0], OLD_BODY);
        current_bytes(&directory, scoped("ccc"), metas[2], OLD_BODY);
    }
    let next = published(&directory, &pool, scoped("ddd"), None, code(20), NEW_BODY);
    current_bytes(&directory, scoped("ddd"), next.metadata, NEW_BODY);
}

#[test]
fn directory_native_final_retire_busy_next_lookup_reclaims_and_exact_cas_has_no_aba() {
    let (pool, _) = fixture_combined_pool(2, 1, 5);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    let one = scoped("alpha");
    let old = published(&directory, &pool, one, None, code(1), OLD_BODY).metadata;
    let witness = directory
        .select_current_native(one, old.token, old.code)
        .unwrap();
    let delayed_word = directory.status_slot(0).load(Ordering::Acquire);
    let guard = directory.lock().unwrap();
    assert_eq!(
        assert_zero(|| directory.retire_store_native(1)),
        Err(DirectoryError::Busy)
    );
    assert_eq!(directory.store_status_native(1), Ok(SourceStatus::Retiring));
    assert_eq!(
        directory.require_ready_native(1),
        Err(DirectoryError::CurrentUnavailable)
    );
    drop(guard);
    // The NEXT successful lookup gate does the real reclamation even though
    // this lookup fails. Old witness stays readable and charged, never current.
    assert_eq!(
        assert_zero(|| directory.lookup_native(one, Some(old.token))),
        Err(DirectoryError::Missing)
    );
    assert_eq!(
        directory.store_status_native(1),
        Ok(SourceStatus::Unregistered)
    );
    assert_eq!(
        directory.usage().unwrap(),
        DirectoryUsage {
            heads: 0,
            key_bytes: 0
        }
    );
    assert_eq!(pool.live_cells(), 1);
    assert_eq!(witness.raw_json(), OLD_BODY);
    let two = NativeOrigin { store: 2, ..one };
    fixture_ready(&directory, 2);
    let current = published(&directory, &pool, two, None, code(20), NEW_BODY).metadata;
    assert_ne!(current.token.uid(), old.token.uid());
    assert_eq!(
        directory.status_slot(0).compare_exchange(
            delayed_word,
            status_word(1, RETIRING),
            Ordering::AcqRel,
            Ordering::Acquire
        ),
        Err(status_word(2, READY))
    );
    assert_zero(|| directory.retire_store_native(1).unwrap()); // delayed old Drop
    current_bytes(&directory, two, current, NEW_BODY);
    assert!(matches!(
        directory.select_current_native(one, old.token, old.code),
        Err(DirectoryError::CurrentUnavailable)
    ));
    assert_eq!(witness.raw_json(), OLD_BODY);
    assert_eq!(pool.live_cells(), 2);
    drop(witness);
    assert_eq!(pool.live_cells(), 1);
}

#[test]
fn directory_native_every_preparation_reclaims_logically_retired_before_cell_exhaustion() {
    let (pool, _) = fixture_combined_pool(1, 1, 0);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    published(
        &directory,
        &pool,
        origin(NativeKey::Root),
        None,
        code(1),
        OLD_BODY,
    );
    assert_eq!(pool.live_cells(), 1);
    let guard = directory.lock().unwrap();
    assert_eq!(directory.retire_store_native(1), Err(DirectoryError::Busy));
    assert!(matches!(
        assert_zero(|| pool.prepare_body(NEW_BODY)),
        Err(RegistryError::Busy)
    ));
    drop(guard);
    assert_eq!(pool.live_cells(), 1); // no hidden destructor/worker/queue
    let staged = assert_zero(|| pool.prepare_body(NEW_BODY).unwrap());
    assert_eq!(
        directory.store_status_native(1),
        Ok(SourceStatus::Unregistered)
    );
    assert_eq!(pool.live_cells(), 1); // old real owner freed BEFORE cell scan
    assert_eq!(directory.usage().unwrap().heads, 0);
    assert_zero(|| drop(staged));
    assert_eq!(pool.live_cells(), 0);
}

#[test]
fn directory_native_retired_owner_destructor_runs_after_gate_release() {
    let layout = DirectoryLayout::new(1, 0).unwrap();
    let mut region = Region::new(layout);
    let directory = fixture_directory(region.bytes(), layout);
    let issuer = Issuer::new();
    let token = directory
        .register_native(origin(NativeKey::Root), code(1), || issuer.issue())
        .unwrap();
    let (pool, owner) = fixture_pool(1);
    owner.observe_standalone_gate(&directory);
    let cell = seal_cell(
        &pool,
        fixture_identity(
            origin(NativeKey::Root),
            RegistryNamespace {
                uid: token.uid(),
                epoch: 0,
            },
            code(1),
        ),
        OLD_BODY,
    );
    directory
        .attach_current_native(origin(NativeKey::Root), token, code(1), cell)
        .unwrap();
    drop(pool); // only the real directory Cell keeps the lease alive
    let guard = directory.lock().unwrap();
    assert_eq!(directory.retire_store_native(1), Err(DirectoryError::Busy));
    drop(guard);
    assert_zero(|| drop(directory.lock().unwrap()));
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.outside_gate_drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.bytes.load(Ordering::Acquire), 0);
}

#[test]
fn directory_native_cleanup_unwind_releases_gate_and_drains_remaining_scratch_gate_free() {
    // Deliberately panicking standalone FIXTURE lease, not a native node owner
    // or a production source/lifetime guard. Its map unmaps before Lease Drop.
    struct PanicAdmission(Arc<AtomicUsize>);
    struct PanicLease(Arc<AtomicUsize>);
    impl RegistryAdmission for PanicAdmission {
        type Lease = PanicLease;
        fn try_reserve(&self, _bytes: usize, _cells: usize) -> Result<PanicLease, RegistryError> {
            Ok(PanicLease(self.0.clone()))
        }
    }
    impl Drop for PanicLease {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
            std::panic::panic_any(());
        }
    }
    let layout = DirectoryLayout::new(2, 2).unwrap();
    let mut region = Region::new(layout);
    let directory = fixture_directory(region.bytes(), layout);
    let issuer = Issuer::new();
    let token_a = register(&directory, &issuer, "a");
    let token_b = register(&directory, &issuer, "b");
    let panics = Arc::new(AtomicUsize::new(0));
    let first_pool = RegistryPool::admit(
        &PanicAdmission(panics.clone()),
        fixture_limits(1),
        || Ok(()),
    )
    .unwrap();
    let (second_pool, owner) = fixture_pool(1);
    owner.observe_standalone_gate(&directory);
    for (pool, name, token) in [(&first_pool, "a", token_a), (&second_pool, "b", token_b)] {
        let cell = seal_cell(
            pool,
            fixture_identity(
                scoped(name),
                RegistryNamespace {
                    uid: token.uid(),
                    epoch: 0,
                },
                code(1),
            ),
            OLD_BODY,
        );
        directory
            .attach_current_native(scoped(name), token, code(1), cell)
            .unwrap();
    }
    drop(first_pool);
    drop(second_pool);
    let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        directory.retire_store_native(1)
    }));
    assert!(caught.is_err());
    assert_eq!(panics.load(Ordering::Relaxed), 1);
    assert!(!directory.header().gate.load(Ordering::Acquire));
    assert!(!directory.header().cleanup_gate.load(Ordering::Acquire));
    assert_eq!(owner.drops.load(Ordering::Acquire), 0); // remaining scratch owner
    // The next gate drains that owner BEFORE holding the main gate again.
    assert_eq!(
        assert_zero(|| directory.usage().unwrap()),
        DirectoryUsage {
            heads: 0,
            key_bytes: 0
        }
    );
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert_eq!(owner.outside_gate_drops.load(Ordering::Acquire), 1);
    assert_eq!(
        directory.store_status_native(1),
        Ok(SourceStatus::Unregistered)
    );
}

#[test]
fn directory_native_atomic_readers_observe_complete_old_or_new_never_partial() {
    // Fixture concurrent workload has NO real source Pub guards. It proves
    // only SAME Directory gate body/metadata coherence and owned-cell lifetime.
    let (pool, _) = fixture_combined_pool(8, 1, 0);
    let directory = pool.directory().unwrap();
    fixture_ready(&directory, 1);
    let origin = origin(NativeKey::Root);
    let first = published(&directory, &pool, origin, None, code(1), OLD_BODY).metadata;
    let successful = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        let writer = scope.spawn(|| {
            for turn in 0..200 {
                let (code, bytes) = if turn % 2 == 0 {
                    (code(20), NEW_BODY)
                } else {
                    (code(1), OLD_BODY)
                };
                assert_zero(|| {
                    let body = match pool.prepare_body(bytes) {
                        Ok(body) => body,
                        Err(RegistryError::Busy | RegistryError::Capacity) => return,
                        _ => panic!("unexpected preparation result"),
                    };
                    match directory.publish_prepared_native(origin, Some(first.token), code, body) {
                        Ok(result) => {
                            assert_eq!(result.metadata.token, first.token);
                            drop(result.detached);
                        }
                        Err(DirectoryError::Busy) => {}
                        _ => panic!("unexpected publication result"),
                    }
                });
            }
        });
        let readers = [0; 4].map(|_| {
            scope.spawn(|| {
                for _ in 0..400 {
                    assert_zero(|| {
                        let metadata = match directory.lookup_native(origin, Some(first.token)) {
                            Ok(metadata) => metadata,
                            Err(DirectoryError::Busy) => return,
                            _ => panic!("unexpected metadata result"),
                        };
                        match directory.select_current_native(origin, metadata.token, metadata.code)
                        {
                            Ok(cell) => {
                                assert_eq!(cell.identity().registry, metadata.code.registry);
                                assert_eq!(
                                    cell.raw_json(),
                                    if metadata.code.registry == 1 {
                                        OLD_BODY
                                    } else {
                                        NEW_BODY
                                    }
                                );
                                successful.fetch_add(1, Ordering::Relaxed);
                                drop(cell);
                            }
                            Err(DirectoryError::Busy | DirectoryError::CurrentUnavailable) => {}
                            _ => panic!("unexpected selection result"),
                        }
                    });
                }
            })
        });
        writer.join().unwrap();
        for reader in readers {
            reader.join().unwrap();
        }
    });
    assert!(successful.load(Ordering::Relaxed) > 0);
    assert_eq!(pool.live_cells(), 1);
}
