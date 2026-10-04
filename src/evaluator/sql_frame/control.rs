//! Primitive-only cancellation/deadline checks and cumulative arena work.
//! No source/provider/database callback is stored or invoked by this control.
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use super::FrameError;

/// Borrowed only while building/inspecting raw arenas. Never retained in the
/// builder or sealed frame. A caller supplies the same native job stop/deadline.
pub(crate) struct FrameControl<'a> {
    cancelled: &'a AtomicBool,
    deadline: Instant,
}
impl<'a> FrameControl<'a> {
    pub(crate) fn new(cancelled: &'a AtomicBool, deadline: Instant) -> Self {
        Self {
            cancelled,
            deadline,
        }
    }
    pub(super) fn check(&self) -> Result<(), FrameError> {
        if self.cancelled.load(Ordering::Acquire) {
            return Err(FrameError::Cancelled);
        }
        if Instant::now() >= self.deadline {
            return Err(FrameError::Deadline);
        }
        Ok(())
    }
}

pub(super) struct Budget {
    remaining: Cell<usize>,
    since_poll: Cell<usize>,
    failed: Cell<Option<FrameError>>,
}
impl Budget {
    pub(super) fn new(work: usize) -> Self {
        Self {
            remaining: Cell::new(work),
            since_poll: Cell::new(1024),
            failed: Cell::new(None),
        }
    }
    #[cfg(test)]
    pub(super) fn remaining_work(&self) -> usize {
        self.remaining.get()
    }
    pub(super) fn failure(&self) -> Option<FrameError> {
        self.failed.get()
    }
    pub(super) fn fail(&self, error: FrameError) -> FrameError {
        self.failed.set(Some(self.failed.get().unwrap_or(error)));
        self.failed.get().unwrap_or(error)
    }
    pub(super) fn check(&self, control: &FrameControl<'_>) -> Result<(), FrameError> {
        if let Some(error) = self.failed.get() {
            return Err(error);
        }
        control.check().map_err(|error| self.fail(error))?;
        self.since_poll.set(0);
        Ok(())
    }
    /// Debit before processing each bounded chunk/operation. Long byte loops
    /// call in chunks <=1024; initialization/text copies use <=64KiB chunks.
    pub(super) fn debit(&self, units: usize, control: &FrameControl<'_>) -> Result<(), FrameError> {
        if let Some(error) = self.failed.get() {
            return Err(error);
        }
        if units >= 1024 || self.since_poll.get() >= 1024 {
            self.check(control)?;
        }
        let remaining = self
            .remaining
            .get()
            .checked_sub(units)
            .ok_or_else(|| self.fail(FrameError::WorkLimit))?;
        self.remaining.set(remaining);
        self.since_poll
            .set(self.since_poll.get().saturating_add(units).min(1024));
        Ok(())
    }
}
