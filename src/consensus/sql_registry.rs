//! Always-built bounded deny-only source control and CURRENT registry storage.
//! It has no serving/source roots and does not activate optional SQL execution.
//!
//! This primitive is NOT wired into Store publication, persistence or routing.
//! Its mandatory provided admission lease is an interface, NOT evidence that a
//! caller owns a real process-global native budget. Native construction must
//! supply one shared node owner and approved finite limits before Store opens.
//! No default, per-Store pool or implicit spare capacity is provided here.
#[path = "sql_registry/bootstrap.rs"]
mod bootstrap;
#[path = "sql_registry/directory.rs"]
pub(in crate::consensus) mod directory;
pub(in crate::consensus) use bootstrap::source_registry;
pub(crate) use bootstrap::{StaticRegion, bootstrap_required_layout, install_source_registry};
#[path = "sql_registry/pool.rs"]
mod pool;
#[path = "sql_registry/stamp.rs"]
mod stamp;
pub(crate) use stamp::SourceStamp;

pub(crate) use pool::{
    RegistryAdmission, RegistryDirectoryLimits, RegistryDirectoryPlan, RegistryPool,
    RegistryPoolLayout, RegistryPoolLimits,
};
pub(in crate::consensus) use pool::{RegistryCell, RegistryStaging};

pub(crate) const MAX_REGISTRY_BYTES: usize = 32 * 1024;

/// Source-issued namespace identity, not a caller hash/name/sentinel. A current
/// publication adjunct must issue/store this under the native Store/partition
/// lifecycle and validate the actual binding there. No name is copied into a
/// cell, so existing ordinary namespaces gain no new 4KiB length restriction.
/// This primitive does not itself implement that publication/lifecycle wiring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct RegistryNamespace {
    uid: u64,
    epoch: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RegistryError {
    Busy,
    Capacity,
    Invalid,
    Unsupported,
    Cancelled,
}

/// Assigned by the actual native publication, not by a parsed guest registry.
/// Registry/bundle physical versions and explicit schema presence refer to the
/// same published code set. An empty schema can be native-certified absent;
/// missing/unknown registry is never an installed empty registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::consensus) struct RegistryIdentity {
    pub(in crate::consensus) store: u64,
    pub(in crate::consensus) installation: u64,
    pub(in crate::consensus) registry: u64,
    pub(in crate::consensus) bundle: u64,
    pub(in crate::consensus) schema: SourceStamp,
    pub(in crate::consensus) namespace: RegistryNamespace,
}

impl RegistryIdentity {
    fn valid(self) -> bool {
        self.store != 0 && self.registry != 0 && self.bundle != 0 && self.namespace.uid != 0
    }
}
