//! ONE process-lifetime source bootstrap. No defaults, reset or per-Store pool.
//!
//! Installation is a native attestation seam, NOT an admission verifier. The
//! constructor must charge this actual static span together with all other
//! registry/cancellation/control regions in the SAME node baseline before any
//! Store/Consensus opens. Overlapping system pages are counted once upstream.
use super::{RegistryError, RegistryPool};
use std::sync::OnceLock;

static SOURCE_REGISTRY: OnceLock<RegistryPool> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct StaticRegion {
    pub(crate) object_start: usize,
    pub(crate) object_bytes: usize,
    pub(crate) object_align: usize,
    pub(crate) page_start: usize,
    pub(crate) page_end: usize,
    pub(crate) page_bytes: usize,
}
impl StaticRegion {
    /// Actual object-address page coverage, not a sizeof-only reservation or
    /// a claim that it is disjoint from the cancellation/static owner spans.
    pub(crate) fn covered_bytes(self) -> usize {
        self.page_end - self.page_start
    }
}

pub(crate) fn bootstrap_required_layout() -> Result<StaticRegion, RegistryError> {
    let page = page_size()?;
    let address = std::ptr::addr_of!(SOURCE_REGISTRY) as usize;
    let object_bytes = std::mem::size_of::<OnceLock<RegistryPool>>();
    let end = address
        .checked_add(object_bytes)
        .ok_or(RegistryError::Capacity)?;
    let page_end = end
        .checked_add(page - 1)
        .map(|end| end / page * page)
        .ok_or(RegistryError::Capacity)?;
    Ok(StaticRegion {
        object_start: address,
        object_bytes,
        object_align: std::mem::align_of::<OnceLock<RegistryPool>>(),
        page_start: address / page * page,
        page_end,
        page_bytes: page,
    })
}

/// Installs the native-provided combined pool once. A duplicate refuses and
/// returns the rejected pool so its actual native owner/cleanup stays explicit.
/// Missing bootstrap never means a committed empty registry.
///
/// # Safety
/// Caller must have charged the ACTUAL unique page span returned by
/// bootstrap_required_layout, all owner/control/cancellation regions and the
/// exact combined Pool layout against the single approved node budget BEFORE
/// this call. The concrete provided owner must actually back those bytes; this
/// function does not authenticate an admission trait or a caller's scalar.
/// Install must precede EVERY production Store/Consensus open. The static
/// strong owner intentionally lives until process exit; no early budget credit
/// or reset is permitted. Tests use isolated processes for separate startups.
pub(crate) unsafe fn install_source_registry(
    pool: RegistryPool,
    charged_static: StaticRegion,
) -> Result<(), (RegistryError, RegistryPool)> {
    let actual = match bootstrap_required_layout() {
        Ok(actual) => actual,
        Err(error) => return Err((error, pool)),
    };
    if actual != charged_static {
        return Err((RegistryError::Invalid, pool));
    }
    // A bare cell arena is a component, not an ordinary-routing-ready source
    // bootstrap. Require the actual initialized current-head directory tail.
    let directory_ready = pool.directory().map(drop);
    if let Err(error) = directory_ready {
        return Err((error, pool));
    }
    SOURCE_REGISTRY
        .set(pool)
        .map_err(|pool| (RegistryError::Invalid, pool))
}

pub(in crate::consensus) fn source_registry() -> Result<&'static RegistryPool, RegistryError> {
    SOURCE_REGISTRY.get().ok_or(RegistryError::Unsupported)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn page_size() -> Result<usize, RegistryError> {
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 || !(page as usize).is_power_of_two() {
        return Err(RegistryError::Unsupported);
    }
    Ok(page as usize)
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn page_size() -> Result<usize, RegistryError> {
    Err(RegistryError::Unsupported)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sql_registry_bootstrap_layout_uses_actual_static_address_and_page_extent() {
        let layout = bootstrap_required_layout().unwrap();
        assert_eq!(
            layout.object_start,
            std::ptr::addr_of!(SOURCE_REGISTRY) as usize
        );
        assert_eq!(
            layout.object_bytes,
            std::mem::size_of::<OnceLock<RegistryPool>>()
        );
        assert_eq!(
            layout.object_align,
            std::mem::align_of::<OnceLock<RegistryPool>>()
        );
        assert_eq!(layout.page_start % layout.page_bytes, 0);
        assert_eq!(layout.page_end % layout.page_bytes, 0);
        assert!(layout.page_start <= layout.object_start);
        assert!(layout.page_end >= layout.object_start + layout.object_bytes);
        assert!(layout.covered_bytes() >= layout.object_bytes);
        assert_eq!(bootstrap_required_layout().unwrap(), layout);
    }
}
