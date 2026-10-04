//! Capture owns a barrier only while borrowing the current publication and
//! copying quota-first resident bytes. It returns no source reference/handle.
use super::*;
use crate::consensus::sql_capture::*;

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
fn sql_capture_actual_identity_counter_region_uses_real_object_address_and_pages() {
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
        .ok_or_else(|| anyhow::anyhow!("SQL capture store identity exhausted"))
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
fn sql_capture_actual_store_identity_issuer_refuses_phase_domain_exhaustion_without_wrap() {
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
impl Store {
    pub(crate) fn sql_capture_progress(&self) -> tokio::sync::futures::OwnedNotified {
        self.inner.shared.sql_capture_progress()
    }

    pub(crate) fn sql_capture_bind_fence(
        &self,
        fence: crate::consensus::read::ReadFence,
        partition: Option<&PartitionBinding>,
    ) -> SqlCaptureFence {
        SqlCaptureFence {
            fence,
            store: self.inner.capture_identity,
            partition: partition.cloned(),
        }
    }

    pub(crate) fn sql_capture_slice(
        &self,
        binding: Option<&PartitionBinding>,
        fence: &SqlCaptureFence,
        expected: Option<&SqlCaptureEpoch>,
        request: SqlCaptureRequest<'_>,
        mut buffer: SqlCaptureBuffer,
    ) -> Result<SqlCapturedSlice, SqlCaptureError> {
        request.validate()?;
        if fence.store != self.inner.capture_identity || fence.partition.as_ref() != binding {
            return Err(SqlCaptureError::SnapshotChanged);
        }
        if buffer.count != 0 || buffer.examined != 0 || !buffer.bytes().is_empty() {
            return Err(SqlCaptureError::InvalidRequest);
        }
        let mut scratch = SqlCaptureScratch::prepare(fence, &request)?;
        let (epoch, ()) =
            self.sql_current_capture(binding, fence, |data, installation, revision| {
                if expected.is_some_and(|expected| {
                    expected.store != self.inner.capture_identity
                        || expected.installation != installation
                        || expected.revision != revision
                        || expected.partition.as_ref() != binding
                }) {
                    return Err(SqlCaptureError::SnapshotChanged);
                }
                data.sql_capture_prepared(&request, &mut buffer, &mut scratch)
            })?;
        Ok(SqlCapturedSlice { epoch, buffer })
    }
}

mod history;
#[cfg(test)]
mod history_tests;
mod selective;

#[cfg(test)]
mod liveness_tests;
#[cfg(test)]
mod selective_tests;
#[cfg(test)]
mod tests;
