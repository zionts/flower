//! Explicit ONE process-global cfg(test) source bootstrap for native storage
//! tests. NOT a native NodeAdmission/USER/kernel/physical/static-union proof.
//! Production never compiles this module and still refuses a missing bootstrap.
use super::*;
use crate::consensus::sql_registry::{
    RegistryAdmission, RegistryDirectoryLimits, RegistryError, RegistryPoolLimits,
    bootstrap_required_layout, install_source_registry,
};
use std::sync::{OnceLock, atomic::AtomicBool};

#[derive(Debug)]
struct FixtureLease {
    _actual_mapped_bytes: usize,
    _cells: usize,
}
struct FixtureAdmission {
    issued: AtomicBool,
}
impl RegistryAdmission for FixtureAdmission {
    type Lease = FixtureLease;
    fn try_reserve(&self, bytes: usize, cells: usize) -> Result<Self::Lease, RegistryError> {
        if bytes == 0 || bytes > 16 * 1024 * 1024 || cells == 0 || cells > 256 {
            return Err(RegistryError::Invalid);
        }
        if self.issued.swap(true, Ordering::AcqRel) {
            return Err(RegistryError::Invalid);
        }
        Ok(FixtureLease {
            _actual_mapped_bytes: bytes,
            _cells: cells,
        })
    }
}
static FIXTURE_INIT: OnceLock<Result<(), SourceError>> = OnceLock::new();

pub(super) fn bootstrap() -> Result<(), SourceError> {
    *FIXTURE_INIT.get_or_init(|| {
        // Explicit fixture limits, not production defaults/spare room. The
        // exact combined mapping includes its REAL16-byte inline fixture lease,
        // fixed256 cell/status/head slots and128KiB variable-key arena, all
        // pretouched before exposure. The pool enforces SAME<=16MiB extent.
        let admission = FixtureAdmission {
            issued: AtomicBool::new(false),
        };
        let pool = RegistryPool::admit_with_directory(
            &admission,
            RegistryPoolLimits {
                bytes: 16 * 1024 * 1024,
                cells: 256,
            },
            RegistryDirectoryLimits {
                heads: 256,
                key_bytes: 128 * 1024,
            },
            || Ok(()),
        )
        .map_err(|_| SourceError::Bootstrap)?;
        let region = bootstrap_required_layout().map_err(|_| SourceError::Bootstrap)?;
        // TEST-ONLY attestation seam, not a real native backing grant. No
        // resetting the real OnceLock or replacing any already supplied pool.
        unsafe { install_source_registry(pool, region) }.map_err(|_| SourceError::Bootstrap)
    })
}
