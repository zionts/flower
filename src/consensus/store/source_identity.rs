//! The SINGLE process-global actual source Store identity issuer.
//! Always compiled for deny-only source/status/lifetime protection; SQL capture
//! reuses this same native identity, never a duplicate counter or feature flag.
use super::*;

static NEXT_IDENTITY: AtomicU64 = AtomicU64::new(1);
/// Native startup must include THIS actual counter's pages in the SAME unique
/// node baseline union. It need not share a page with the OnceLock bootstrap;
/// never assume sizeof8 or disjoint4096 are themselves backed reservations.
pub(super) fn identity_static_region() -> Result<
    crate::consensus::sql_registry::StaticRegion,
    crate::consensus::sql_registry::RegistryError,
> {
    crate::consensus::sql_registry::StaticRegion::of(&NEXT_IDENTITY)
}
impl Store {
    pub(in crate::consensus) fn identity_static_region() -> Result<
        crate::consensus::sql_registry::StaticRegion,
        crate::consensus::sql_registry::RegistryError,
    > {
        identity_static_region()
    }
}
#[cfg(test)]
#[test]
fn native_source_actual_identity_counter_region_uses_real_object_address_and_pages() {
    let region = identity_static_region().unwrap();
    assert_eq!(
        region.object_start,
        std::ptr::addr_of!(NEXT_IDENTITY) as usize
    );
    assert_eq!(region.object_bytes, std::mem::size_of::<AtomicU64>());
    assert_eq!(region.object_align, std::mem::align_of::<AtomicU64>());
    assert!(region.page_start <= region.object_start);
    assert!(region.page_end >= region.object_start + region.object_bytes);
    assert_eq!(region.page_start % region.page_bytes, 0);
    assert_eq!(region.page_end % region.page_bytes, 0);
    assert_eq!(region, identity_static_region().unwrap());
}

pub(super) fn next_identity() -> anyhow::Result<u64> {
    reserve_identity(&NEXT_IDENTITY)
        .ok_or_else(|| anyhow::anyhow!("native source store identity exhausted"))
}
fn reserve_identity(counter: &AtomicU64) -> Option<u64> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            // The same real issuer feeds the mapped Store lifecycle phase tag.
            // Reserve its two explicit phase bits; never truncate/hash/reuse a
            // previously issued identity or reset the process-global counter.
            (value != 0 && value <= crate::consensus::sql_registry::directory::MAX_NATIVE_STORE_ID)
                .then(|| value + 1)
        })
        .ok()
}
#[cfg(test)]
#[test]
fn native_source_actual_store_identity_issuer_refuses_phase_domain_exhaustion_without_wrap() {
    let max = crate::consensus::sql_registry::directory::MAX_NATIVE_STORE_ID;
    let counter = AtomicU64::new(max - 1);
    assert_eq!(reserve_identity(&counter), Some(max - 1));
    assert_eq!(reserve_identity(&counter), Some(max));
    assert_eq!(reserve_identity(&counter), None);
    assert_eq!(counter.load(Ordering::Acquire), max + 1);
    assert_eq!(reserve_identity(&AtomicU64::new(0)), None);
    assert_eq!(reserve_identity(&AtomicU64::new(u64::MAX)), None);
    assert_eq!(reserve_identity(&AtomicU64::new(1)), Some(1));
}
