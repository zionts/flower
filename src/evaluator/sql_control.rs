//! One monotonic terminal-job budget, never renewed by callbacks/slices/retries.
//! This control holds no source, App/cache, provider, signer or snapshot handle.
use super::sqlite::SqlError;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub(crate) const MAX_JOB_TIME: Duration = Duration::from_secs(10);
pub(crate) const MAX_SQLITE_TIME: Duration = Duration::from_secs(2);

pub(crate) struct JobControl {
    admitted: Instant,
    deadline: Instant,
    cancellation: Arc<AtomicBool>,
    failed: Option<SqlError>,
}
impl JobControl {
    /// Call immediately after admission, BEFORE first fence/capture/encoding.
    /// Queue wait has a separate bound; compilation/prewarm must not hide an
    /// unlimited source-root or callback lifetime outside this admitted job.
    pub(crate) fn new(
        operator_limit: Duration,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, SqlError> {
        Self::at(Instant::now(), operator_limit, cancellation)
    }
    fn at(
        admitted: Instant,
        operator_limit: Duration,
        cancellation: Arc<AtomicBool>,
    ) -> Result<Self, SqlError> {
        let limit = operator_limit.min(MAX_JOB_TIME);
        if limit.is_zero() {
            return Err(SqlError::InvalidRequest);
        }
        let deadline = admitted
            .checked_add(limit)
            .ok_or(SqlError::InvalidRequest)?;
        Ok(Self {
            admitted,
            deadline,
            cancellation,
            failed: None,
        })
    }
    pub(crate) fn admitted(&self) -> Instant {
        self.admitted
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
    pub(crate) fn cancellation(&self) -> &Arc<AtomicBool> {
        &self.cancellation
    }
    pub(crate) fn check(&mut self) -> Result<(), SqlError> {
        self.check_at(Instant::now())
    }
    fn check_at(&mut self, now: Instant) -> Result<(), SqlError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let error = if self.cancellation.load(Ordering::Acquire) {
            Some(SqlError::Cancelled)
        } else if now >= self.deadline {
            Some(SqlError::Deadline)
        } else {
            None
        };
        if let Some(error) = error {
            self.failed = Some(error);
            return Err(error);
        }
        Ok(())
    }
    /// Create ONE operator subdeadline after seal. It never replaces/extends
    /// the job deadline, and the surrounding caller checks the original total
    /// before and after SQLite, fresh validation, finalizer and publication.
    pub(crate) fn sqlite_deadline(&mut self) -> Result<Instant, SqlError> {
        self.sqlite_deadline_at(Instant::now())
    }
    fn sqlite_deadline_at(&mut self, now: Instant) -> Result<Instant, SqlError> {
        self.check_at(now)?;
        Ok(now
            .checked_add(MAX_SQLITE_TIME)
            .ok_or(SqlError::InvalidRequest)?
            .min(self.deadline))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn total_is_operator_lowered_hard_capped_and_never_reset() {
        let start = Instant::now();
        let cancel = Arc::new(AtomicBool::new(false));
        assert!(JobControl::at(start, Duration::ZERO, cancel.clone()).is_err());
        let mut job = JobControl::at(start, Duration::from_secs(100), cancel.clone()).unwrap();
        assert_eq!(job.deadline(), start + MAX_JOB_TIME);
        for phase in [
            "capture", "compile", "auth", "provider", "seal", "sqlite", "finish", "sign",
        ] {
            job.check_at(start + Duration::from_secs(9)).unwrap();
            assert_eq!(job.deadline(), start + MAX_JOB_TIME, "{phase}");
        }
        assert_eq!(job.check_at(start + MAX_JOB_TIME), Err(SqlError::Deadline));
        assert_eq!(
            job.check_at(start),
            Err(SqlError::Deadline),
            "caught expiry never resumes work"
        );
        let lower = JobControl::at(start, Duration::from_secs(3), cancel).unwrap();
        assert_eq!(lower.deadline(), start + Duration::from_secs(3));
    }
    #[test]
    fn sqlite_two_seconds_is_clipped_to_original_total_and_cancellation_is_sticky() {
        let start = Instant::now();
        let cancel = Arc::new(AtomicBool::new(false));
        let mut job = JobControl::at(start, MAX_JOB_TIME, cancel.clone()).unwrap();
        assert_eq!(
            job.sqlite_deadline_at(start).unwrap(),
            start + MAX_SQLITE_TIME
        );
        assert_eq!(
            job.sqlite_deadline_at(start + Duration::from_secs(9))
                .unwrap(),
            job.deadline()
        );
        cancel.store(true, Ordering::Release);
        assert_eq!(job.sqlite_deadline_at(start), Err(SqlError::Cancelled));
        cancel.store(false, Ordering::Release);
        assert_eq!(job.check_at(start), Err(SqlError::Cancelled));
    }
}
