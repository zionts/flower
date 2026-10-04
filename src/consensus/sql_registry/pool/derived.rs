//! Source-owned exact startup dimension derivation. No fractional key arena,
//! default key room, per-name cap, additional allowance or capacity grant.
use super::*;
use std::marker::PhantomData;

/// Only this checked source planner constructs a tuple. The actual native
/// owner MUST first derive `limits.bytes` from its unique-page/control baseline
/// remainder, then book the returned actual map extent. This is not admission.
pub(crate) struct RegistryDirectoryPlan<L> {
    pool: RegistryPoolLimits,
    directory: RegistryDirectoryLimits,
    layout: RegistryPoolLayout,
    _lease: PhantomData<fn() -> L>,
}
impl<L> RegistryDirectoryPlan<L> {
    pub(crate) fn pool_limits(&self) -> RegistryPoolLimits {
        self.pool
    }
    pub(crate) fn directory_limits(&self) -> RegistryDirectoryLimits {
        self.directory
    }
    pub(crate) fn layout(&self) -> RegistryPoolLayout {
        self.layout
    }
}

impl RegistryPool {
    /// MAX actual cells, then MAX exact key arena from the remaining complete
    /// layout bytes. Heads/lifecycle equal actual usable cells, never requested
    /// but unbacked256. ALL present/future fields in DirectoryLayout participate
    /// automatically before alignment and one system-page rounding.
    ///
    /// `limits.bytes` MUST be min(operator lower limit, SAME16MiB actually
    /// remaining AFTER node/cancel/global/owner/static UNIQUE covered pages).
    /// This pure calculation cannot authenticate that native backing grant.
    pub(crate) fn derive_directory_plan<A: RegistryAdmission>(
        limits: RegistryPoolLimits,
    ) -> Result<RegistryDirectoryPlan<A::Lease>, RegistryError> {
        if !limits.valid() {
            return Err(RegistryError::Invalid);
        }
        for cells in (1..=limits.cells).rev() {
            let effective = RegistryPoolLimits {
                bytes: limits.bytes,
                cells,
            };
            let directory = RegistryDirectoryLimits {
                heads: cells,
                key_bytes: 0,
            };
            let fits = |key_bytes| {
                RegistryPoolLayout::combined::<A::Lease>(
                    effective,
                    Some(RegistryDirectoryLimits {
                        key_bytes,
                        ..directory
                    }),
                )
                // combined's lower-cell fallback is NEVER a fit for this
                // candidate tuple: choosing C precedes maximizing K.
                .ok()
                .filter(|layout| layout.cells == cells)
            };
            if fits(0).is_none() {
                continue;
            }
            // Monotone complete checked Layout predicate. <=24 iterations for
            // the approved16MiB cap; no heap/IO/growable plan/counter issuance.
            let (mut low, mut high) = (0usize, limits.bytes);
            while low < high {
                let middle = low + (high - low).div_ceil(2);
                if fits(middle).is_some() {
                    low = middle;
                } else {
                    high = middle - 1;
                }
            }
            let directory = RegistryDirectoryLimits {
                key_bytes: low,
                ..directory
            };
            let layout = fits(low).ok_or(RegistryError::Capacity)?;
            debug_assert_eq!(layout.heads, cells);
            debug_assert_eq!(layout.key_bytes, low);
            return Ok(RegistryDirectoryPlan {
                pool: effective,
                directory,
                layout,
                _lease: PhantomData,
            });
        }
        Err(RegistryError::Capacity)
    }

    /// Construct exactly this derived tuple with the SAME concrete lease type;
    /// this calls real admission before mapping/touching and owns that lease
    /// through the last mapping owner. No fixture lease/native48 substitution.
    pub(crate) fn admit_directory_plan<A: RegistryAdmission>(
        admission: &A,
        plan: RegistryDirectoryPlan<A::Lease>,
        check: impl FnMut() -> Result<(), RegistryError>,
    ) -> Result<Self, RegistryError> {
        // Private typed plan fields cannot be changed by callers. Feed THIS
        // exact checked Layout to the existing real admission/map/pretouch
        // constructor, with the SAME associated lease type—not a recomputed
        // tuple that might silently choose fewer cells.
        Self::admit_layout(admission, plan.layout, check)
    }
}

#[cfg(test)]
#[path = "derived/tests.rs"]
mod tests;
