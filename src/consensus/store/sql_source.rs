//! The actual Store lifetime owns one mapped source-status slot.
//!
//! No source roots or namespace/cell owners are added to Store/Inner/Snapshot.
//! Startup transfers an armed scalar guard through the real blocking worker;
//! cancelling its waiter does not retire a worker still touching storage. This
//! module requires the ONE supplied process-global bootstrap, never a default.
use super::*;
use crate::consensus::sql_registry::{
    RegistryPool,
    directory::{DirectoryError, SourceStatus},
    source_registry,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceError {
    Bootstrap,
    Directory(DirectoryError),
}
impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bootstrap => f.write_str("SQL source bootstrap unavailable"),
            Self::Directory(_) => f.write_str("SQL source lifetime unavailable"),
        }
    }
}
impl std::error::Error for SourceError {}
fn pool() -> Result<&'static RegistryPool, SourceError> {
    source_registry().map_err(|_| SourceError::Bootstrap)
}

/// Private startup owner. The mapped slot stays Preparing until the complete
/// unexposed Store startup succeeds. Errors/unwind/cancelled-worker-output drop
/// retire the actual never-reused ID. No per-Store heap/native admission owner.
pub(super) struct PreparingStore {
    pool: &'static RegistryPool,
    identity: u64,
    armed: bool,
    #[cfg(test)]
    retired: Option<tokio::sync::oneshot::Sender<()>>,
}
impl PreparingStore {
    pub(super) fn begin() -> anyhow::Result<Self> {
        let pool = pool()?;
        let identity = sql_capture::next_identity()?;
        pool.directory()
            .map_err(|_| SourceError::Bootstrap)?
            .prepare_store_native(identity)
            .map_err(SourceError::Directory)?;
        Ok(Self {
            pool,
            identity,
            armed: true,
            #[cfg(test)]
            retired: None,
        })
    }
    #[cfg(test)]
    fn notify_retirement(&mut self, sender: tokio::sync::oneshot::Sender<()>) {
        self.retired = Some(sender);
    }
    pub(super) fn identity(&self) -> u64 {
        self.identity
    }

    /// Only after actual Inner construction. Keep the Store private until its
    /// bounded warm/recovery work is complete; Ready alone isn't a current
    /// registry or a terminal/ordinary dispatch permission.
    pub(super) fn finish(mut self, inner: &Inner) -> Result<(), SourceError> {
        if inner.capture_identity != self.identity {
            return Err(SourceError::Bootstrap);
        }
        self.pool
            .directory()
            .map_err(|_| SourceError::Bootstrap)?
            .ready_store_native(self.identity)
            .map_err(SourceError::Directory)?;
        self.armed = false;
        Ok(())
    }
}
impl Drop for PreparingStore {
    fn drop(&mut self) {
        if self.armed {
            retire(self.pool, self.identity);
            #[cfg(test)]
            if let Some(sender) = self.retired.take() {
                let _ = sender.send(());
            }
        }
    }
}

/// Used by final actual InnerDrop, never a cancelled waiter or ordinary Store
/// handle. Busy has already installed the sticky Retiring tag; a subsequent
/// bounded gate/preparation reclaims its owners. No polling/spawn/heap queue.
pub(super) fn retire(pool: &RegistryPool, identity: u64) {
    let result = pool
        .directory()
        .map_err(|_| SourceError::Bootstrap)
        .and_then(|directory| {
            directory
                .retire_store_native(identity)
                .map_err(SourceError::Directory)
        });
    match result {
        Ok(()) | Err(SourceError::Directory(DirectoryError::Busy)) => {}
        // Invalid/domain/bootstrap uncertainty cannot refund/serve. Only the
        // last invariant fallback is global: normal partial source failure
        // uses the affected Store's mapped sticky Fatal tag below.
        Err(_) => std::process::abort(),
    }
}

pub(super) fn require_ready(inner: &Inner) -> Result<(), SourceError> {
    pool()?
        .directory()
        .map_err(|_| SourceError::Bootstrap)?
        .require_ready_native(inner.capture_identity)
        .map_err(SourceError::Directory)
}

/// Own the SAME actual Published write guard, not an inert caller boolean or
/// a reference that can outlive an unlocked guard. Drop marks this affected
/// Store BEFORE Rust drops the real guard field, including during unwinding.
/// Every source/head mutation must be made while this private wrapper is armed.
pub(super) struct PublicationGuard<'a> {
    inner: &'a Inner,
    guard: std::sync::RwLockWriteGuard<'a, Published>,
    armed: bool,
}
impl<'a> PublicationGuard<'a> {
    pub(super) fn acquire(inner: &'a Inner) -> Result<Self, SourceError> {
        let guard = inner.published.write().expect("published state lock");
        require_ready(inner)?;
        Ok(Self {
            inner,
            guard,
            armed: true,
        })
    }
    pub(super) fn complete(mut self) {
        self.armed = false;
    }
}
impl std::ops::Deref for PublicationGuard<'_> {
    type Target = Published;
    fn deref(&self) -> &Published {
        &self.guard
    }
}
impl std::ops::DerefMut for PublicationGuard<'_> {
    fn deref_mut(&mut self) -> &mut Published {
        &mut self.guard
    }
}
impl Drop for PublicationGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mark = pool()
            .ok()
            .and_then(|pool| pool.directory().ok())
            .and_then(|directory| {
                directory
                    .fatal_store_native(self.inner.capture_identity)
                    .ok()
            });
        if !matches!(mark, Some(SourceStatus::Fatal | SourceStatus::Retiring)) {
            std::process::abort();
        }
    }
}

#[cfg(test)]
pub(super) mod fixture;
#[cfg(test)]
mod tests;

#[cfg(test)]
pub(super) fn test_bootstrap() -> Result<(), SourceError> {
    fixture::bootstrap()
}
