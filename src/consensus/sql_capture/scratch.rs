//! Root-free native scratch prepared/touched before physical exclusion.
use super::*;
use std::ops::Bound;

/// Fixed cursor/bounds objects, not a snapshot, database or iterator owner.
/// Native worker-stack provisioning remains additional to these object sizes.
pub struct SqlCaptureScratch {
    pub(in crate::consensus) bounds: redb::ResidentRangeBounds,
    pub(in crate::consensus) range: redb::ResidentRangeScratch,
}
impl SqlCaptureScratch {
    pub fn reservation_bytes() -> usize {
        std::mem::size_of::<Self>()
    }
    pub fn prepare(
        fence: &SqlCaptureFence,
        request: &SqlCaptureRequest<'_>,
    ) -> Result<Self, SqlCaptureError> {
        request.validate()?;
        Self::for_partition(
            fence.partition.as_ref().map(|p| p.partition.as_str()),
            request,
        )
    }
    pub(in crate::consensus) fn for_partition(
        partition: Option<&str>,
        request: &SqlCaptureRequest<'_>,
    ) -> Result<Self, SqlCaptureError> {
        request.validate()?;
        let (lower, upper) = match request.selection {
            SqlCaptureSelection::Range {
                lower,
                upper,
                after,
            } => (
                after.map_or(Bound::Included(lower.as_bytes()), |after| {
                    Bound::Excluded(after.as_bytes())
                }),
                upper.map_or(Bound::Unbounded, |upper| Bound::Excluded(upper.as_bytes())),
            ),
            _ => (Bound::Unbounded, Bound::Unbounded),
        };
        let mut bounds = match partition {
            Some(partition) => {
                redb::ResidentRangeBounds::partition(partition.as_bytes(), lower, upper)
            }
            None => redb::ResidentRangeBounds::plain(lower, upper),
        }
        .map_err(super::super::backing::sql_capture::capture_error)?;
        let mut range = redb::ResidentRangeScratch::new();
        bounds.pre_touch();
        range.pre_touch();
        Ok(Self { bounds, range })
    }
}
