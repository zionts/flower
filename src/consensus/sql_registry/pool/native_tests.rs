//! Exact-production-file fixture tests only; no actual source/Store activation.
use super::*;
use crate::consensus::sql_registry::directory::{
    DirectoryError, NativeCode, NativeKey, NativeOrigin,
};

fn combined(cells: usize) -> (RegistryPool, Arc<Owner>) {
    let owner = Owner::new(HARD_REGISTRY_POOL_BYTES, HARD_REGISTRY_POOL_CELLS);
    let pool = RegistryPool::admit_with_directory(
        &owner,
        limits(cells),
        RegistryDirectoryLimits {
            heads: 1,
            key_bytes: 0,
        },
        || Ok(()),
    )
    .unwrap();
    owner.remember(&pool);
    (pool, owner)
}
fn native_root(installation: u64) -> NativeOrigin<'static> {
    NativeOrigin {
        store: 1,
        installation,
        epoch: 0,
        key: NativeKey::Root,
    }
}
fn native_code(version: u64) -> NativeCode {
    NativeCode {
        registry: version,
        bundle: version + 1,
        schema: SourceStamp::KnownAbsent,
    }
}
fn zero<T>(f: impl FnOnce() -> T) -> T {
    let (result, operations, bytes) = allocation_probe::measure(f);
    assert_eq!((operations, bytes), (0, 0));
    result
}

#[test]
fn sql_registry_prepared_body_checks_utf8_exact_bound_copies_before_identity_no_heap() {
    let (pool, _) = combined(2);
    let mut maximum = vec![b'x'; MAX_REGISTRY_BYTES];
    let oversized = vec![b'x'; MAX_REGISTRY_BYTES + 1];
    zero(|| {
        for invalid in [&[][..], &[0xff][..], oversized.as_slice()] {
            assert!(matches!(
                pool.prepare_body(invalid),
                Err(RegistryError::Invalid)
            ));
        }
        assert_eq!(pool.live_cells(), 0);
        assert_eq!(pool.header().next_namespace.load(Ordering::Acquire), 1);
    });
    let prepared = zero(|| pool.prepare_body(&maximum).unwrap());
    maximum.fill(b'y');
    assert_eq!(pool.header().next_namespace.load(Ordering::Acquire), 1);
    assert_eq!(
        unsafe {
            prepared
                .staging
                .slot
                .as_ref()
                .references
                .load(Ordering::Acquire)
        },
        STAGING
    );
    // Test-only observation of unique staging bytes, NOT a public accessor.
    let data = unsafe { &*prepared.staging.slot.as_ref().data.get() };
    assert_eq!(data.body_len as usize, MAX_REGISTRY_BYTES);
    assert!(data.body.iter().all(|&byte| byte == b'x'));
    let directory = pool.directory().unwrap();
    directory.prepare_store_native(1).unwrap();
    directory.ready_store_native(1).unwrap();
    let publication = zero(|| {
        directory
            .publish_prepared_native(native_root(0), None, native_code(1), prepared)
            .unwrap()
    });
    let selected = directory
        .select_current_native(
            native_root(0),
            publication.metadata.token,
            publication.metadata.code,
        )
        .unwrap();
    assert_eq!(selected.raw_json().len(), MAX_REGISTRY_BYTES);
    assert!(selected.raw_json().iter().all(|&byte| byte == b'x'));
    assert_eq!(pool.header().next_namespace.load(Ordering::Acquire), 2);
    drop(selected);
    let unicode = zero(|| pool.prepare_body("名λ\0".as_bytes()).unwrap());
    zero(|| drop(unicode));
    assert_eq!(pool.live_cells(), 1);
}

#[test]
fn sql_registry_prepared_counter_refusals_preserve_complete_current_and_no_uid_wrap() {
    let (pool, _) = combined(3);
    let directory = pool.directory().unwrap();
    directory.prepare_store_native(1).unwrap();
    directory.ready_store_native(1).unwrap();
    let first = directory
        .publish_prepared_native(
            native_root(0),
            None,
            native_code(1),
            pool.prepare_body(b"old complete").unwrap(),
        )
        .unwrap()
        .metadata;
    let witness = directory
        .select_current_native(native_root(0), first.token, first.code)
        .unwrap();
    let assert_old = || {
        assert_eq!(
            directory
                .lookup_native(native_root(0), Some(first.token))
                .unwrap(),
            first
        );
        assert_eq!(witness.raw_json(), b"old complete");
        assert_eq!(witness.identity().registry, 1);
    };
    let owners = pool.header().owners.load(Ordering::Acquire);
    pool.header()
        .owners
        .store(MAX_REFERENCES, Ordering::Release);
    assert!(matches!(
        zero(|| pool.prepare_body(b"new complete")),
        Err(RegistryError::Capacity)
    ));
    pool.header().owners.store(owners, Ordering::Release);
    assert_old();
    assert_eq!(pool.live_cells(), 1);
    let handles = pool.header().handles.load(Ordering::Acquire);
    pool.header()
        .handles
        .store(MAX_REFERENCES, Ordering::Release);
    assert!(matches!(
        zero(|| pool.try_clone()),
        Err(RegistryError::Capacity)
    ));
    pool.header().handles.store(handles, Ordering::Release);
    assert_eq!(pool.header().owners.load(Ordering::Acquire), owners);
    assert_old();
    let references = unsafe { &witness.slot.as_ref().references };
    let saved = references.load(Ordering::Acquire);
    references.store(MAX_REFERENCES, Ordering::Release);
    assert!(matches!(
        zero(|| directory.select_current_native(native_root(0), first.token, first.code)),
        Err(DirectoryError::Capacity)
    ));
    references.store(saved, Ordering::Release);
    assert_old();
    pool.header()
        .next_namespace
        .store(u64::MAX, Ordering::Release);
    let prepared = pool.prepare_body(b"new complete").unwrap();
    assert!(matches!(
        zero(|| directory.publish_prepared_native(
            native_root(1),
            Some(first.token),
            native_code(20),
            prepared
        )),
        Err(DirectoryError::Capacity)
    ));
    assert_eq!(
        pool.header().next_namespace.load(Ordering::Acquire),
        u64::MAX
    );
    assert_old();
    assert_eq!(pool.live_cells(), 1);
    let same = zero(|| {
        directory
            .publish_prepared_native(
                native_root(0),
                Some(first.token),
                native_code(20),
                pool.prepare_body(b"new complete").unwrap(),
            )
            .unwrap()
    });
    assert_eq!(same.metadata.token, first.token); // no new UID needed
    assert_eq!(same.detached.as_ref().unwrap().raw_json(), b"old complete");
    let current = directory
        .select_current_native(native_root(0), same.metadata.token, same.metadata.code)
        .unwrap();
    assert_eq!(current.raw_json(), b"new complete");
    assert_eq!(
        pool.header().next_namespace.load(Ordering::Acquire),
        u64::MAX
    );
    zero(|| {
        drop(current);
        drop(same.detached);
        drop(witness);
    });
    assert_eq!(pool.live_cells(), 1);
}

#[test]
fn sql_registry_prepared_body_keeps_mapping_and_lease_after_last_handle_cycle_clear() {
    let (pool, owner) = combined(2);
    let directory = pool.directory().unwrap();
    directory.prepare_store_native(1).unwrap();
    directory.ready_store_native(1).unwrap();
    let publication = directory
        .publish_prepared_native(
            native_root(0),
            None,
            native_code(1),
            pool.prepare_body(b"current complete").unwrap(),
        )
        .unwrap();
    assert!(publication.detached.is_none());
    let prepared = zero(|| pool.prepare_body(b"unsealed staged").unwrap());
    assert_eq!(pool.live_cells(), 2);
    drop(directory);
    zero(|| drop(pool));
    assert_eq!(owner.drops.load(Ordering::Acquire), 0);
    assert!(owner.leased.load(Ordering::Acquire));
    let data = unsafe { &*prepared.staging.slot.as_ref().data.get() };
    assert_eq!(&data.body[..data.body_len as usize], b"unsealed staged");
    zero(|| drop(prepared));
    assert_eq!(owner.drops.load(Ordering::Acquire), 1);
    assert!(!owner.leased.load(Ordering::Acquire));
    #[cfg(target_os = "linux")]
    assert!(owner.unmapped_before_release.load(Ordering::Acquire));
}
