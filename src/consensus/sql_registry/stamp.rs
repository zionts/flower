//! Semantic source presence, not a zero/guessed physical version.
//!
//! Actual empty-schema deployments remove the physical `schema` record. The
//! guarded source producer must distinguish this CHECKED absence from a failed
//! read/unknown publication, which remains an error and has no stamp here.
//! Registry and bundle presence remain independently mandatory for a usable
//! current registry. These component scalars are correlation, not provenance.
use super::RegistryError;
use std::num::NonZeroU64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SourceStamp {
    KnownAbsent,
    Present(NonZeroU64),
}
impl SourceStamp {
    pub(in crate::consensus) fn present(version: u64) -> Result<Self, RegistryError> {
        NonZeroU64::new(version)
            .map(Self::Present)
            .ok_or(RegistryError::Invalid)
    }

    pub(crate) fn version(self) -> Option<NonZeroU64> {
        match self {
            Self::KnownAbsent => None,
            Self::Present(version) => Some(version),
        }
    }

    // Only the admitted, initialized, owned map's internal scalar format uses
    // this word. Zero encodes the explicit KnownAbsent variant, NEVER an
    // unknown/default stamp or a Present(0). Empty/free heads have uid == 0 and
    // cannot be selected. No native Envelope exposes an untyped schema word.
    pub(super) fn stored_word(self) -> u64 {
        self.version().map_or(0, NonZeroU64::get)
    }
    pub(super) fn from_stored_word(word: u64) -> Self {
        match NonZeroU64::new(word) {
            Some(version) => Self::Present(version),
            None => Self::KnownAbsent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allocation_probe;

    #[test]
    fn sql_registry_source_stamp_present_is_positive_and_absence_has_no_invented_version() {
        assert_eq!(SourceStamp::present(0), Err(RegistryError::Invalid));
        assert_eq!(SourceStamp::KnownAbsent.version(), None);
        for actual in [1, 2, u64::MAX] {
            let stamp = SourceStamp::present(actual).unwrap();
            assert_eq!(stamp.version().unwrap().get(), actual);
            assert_ne!(stamp, SourceStamp::KnownAbsent);
            assert_eq!(SourceStamp::from_stored_word(stamp.stored_word()), stamp);
        }
        assert_eq!(
            SourceStamp::from_stored_word(SourceStamp::KnownAbsent.stored_word()),
            SourceStamp::KnownAbsent
        );
    }

    #[test]
    fn sql_registry_source_stamp_conversion_is_zero_heap_and_exact_actual_layout() {
        let ((absent, present), operations, bytes) = allocation_probe::measure(|| {
            (
                SourceStamp::from_stored_word(SourceStamp::KnownAbsent.stored_word()),
                SourceStamp::from_stored_word(SourceStamp::present(123).unwrap().stored_word()),
            )
        });
        assert_eq!((operations, bytes), (0, 0));
        assert_eq!(absent, SourceStamp::KnownAbsent);
        assert_eq!(present.version().unwrap().get(), 123);
        // Observed actual Rust type only, not a guessed native admission cost.
        let layout = std::alloc::Layout::new::<SourceStamp>();
        assert_eq!(layout.size(), std::mem::size_of::<SourceStamp>());
        assert_eq!(layout.align(), std::mem::align_of::<SourceStamp>());
    }
}
