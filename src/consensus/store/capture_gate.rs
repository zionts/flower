//! Writer-priority exclusion for a physical database's native snapshot copy.
//!
//! Ordinary mutations may coexist. Capture never queues: it declines if a
//! mutation is active or waiting, another capture is active, or even the short
//! bookkeeping mutex is contended. A released capture wakes every queued
//! mutation before another capture can be admitted. No database, transaction,
//! guest code, or caller callback is retained or run under the bookkeeping lock.
use std::sync::{Arc, Condvar, Mutex, MutexGuard, TryLockError};
use std::time::{Duration, Instant};

// Give control/storage work at least nine times the preceding capture's time,
// even when callers alternate between replicas. Do not impose an arbitrary
// millisecond floor on tiny copies. The async controller must yield or await
// the returned deadline between slices; idle time never banks burst credit.
const MIN_COOLDOWN: Duration = Duration::from_nanos(1);
const COOLDOWN_MULTIPLIER: u32 = 9;

#[derive(Debug, Default)]
struct State {
    active_mutations: usize,
    waiting_mutations: usize,
    capture: bool,
    next_allowed: Option<Instant>,
    // An unrepresentable future deadline must fail closed, not reset pacing.
    // This cannot arise from a realistically bounded native copy.
    pacing_exhausted: bool,
}

#[derive(Debug, Default)]
pub(super) struct CaptureGate {
    state: Mutex<State>,
    mutations: Condvar,
    // Waiters own only Notify, not the gate/database/source. Enroll before
    // try-capture. Only ACTUAL mutation-job completion signals progress, never
    // a capture refusal/release that could wake itself into Busy polling.
    progress: Arc<tokio::sync::Notify>,
}

/// Why an immediate, nonwaiting capture attempt was declined.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaptureUnavailable {
    /// Storage is active/queued, another capture is active, or bookkeeping is
    /// contended. Do not poll this result; let the caller's deadline or an
    /// existing storage/progress notification govern any later attempt.
    Busy,
    /// Shared cumulative pacing. A caller may schedule one deadline wakeup at
    /// this instant, but still has to try admission again when it wakes.
    NextDue(Instant),
}

/// Shared-side permission for one actual blocking mutation job.
///
/// This owns only the gate, not the database. Keep it through physical commit
/// or abort/drop, and through any logical root mutation and publication. Drop
/// releases on success, error, cancellation of the job, and panic/unwind.
#[must_use = "the mutation permit must live until the mutation job finishes"]
#[derive(Debug)]
pub(crate) struct MutationPermit {
    gate: Arc<CaptureGate>,
}

/// Exclusive permission for the short, bounded native copy only.
///
/// This owns only the gate, not the database. It must not cover SQL evaluation,
/// guest/compiler execution, I/O, or an asynchronous wait. Dropping it releases
/// queued mutations and charges shared pacing, including on panic/unwind.
#[must_use = "the capture permit must live until the native copy finishes"]
#[derive(Debug)]
pub(crate) struct CapturePermit {
    gate: Option<Arc<CaptureGate>>,
    started: Instant,
}

impl MutationPermit {
    pub(super) fn belongs_to(&self, gate: &Arc<CaptureGate>) -> bool {
        Arc::ptr_eq(&self.gate, gate)
    }
}

impl CaptureGate {
    // No external work runs under this mutex, so recovering poison cannot hide
    // a partially applied storage operation. Permits are separate RAII objects.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }

    /// Blocking: call only in storage's spawn_blocking jobs, never on Tokio's
    /// executor. The returned permit has no borrow of this gate or database.
    pub(super) fn mutation_permit(self: &Arc<Self>) -> MutationPermit {
        let mut state = self.lock();
        state.waiting_mutations += 1;
        // Tests observe registration with a condition-variable wait, not by
        // polling thread scheduling. Production needs only the release wakeup.
        #[cfg(test)]
        self.mutations.notify_all();
        while state.capture {
            state = self
                .mutations
                .wait(state)
                .unwrap_or_else(|error| error.into_inner());
        }
        state.waiting_mutations -= 1;
        state.active_mutations += 1;
        drop(state);
        MutationPermit { gate: self.clone() }
    }

    pub(super) fn mutation_progress(&self) -> tokio::sync::futures::OwnedNotified {
        self.progress.clone().notified_owned()
    }

    pub(super) fn try_capture_permit(
        self: &Arc<Self>,
    ) -> Result<CapturePermit, CaptureUnavailable> {
        self.try_capture_at(Instant::now())
    }

    fn try_capture_at(self: &Arc<Self>, now: Instant) -> Result<CapturePermit, CaptureUnavailable> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::WouldBlock) => return Err(CaptureUnavailable::Busy),
            Err(TryLockError::Poisoned(error)) => error.into_inner(),
        };
        if state.capture
            || state.active_mutations != 0
            || state.waiting_mutations != 0
            || state.pacing_exhausted
        {
            return Err(CaptureUnavailable::Busy);
        }
        if let Some(due) = state.next_allowed.filter(|due| now < *due) {
            return Err(CaptureUnavailable::NextDue(due));
        }
        state.capture = true;
        drop(state);
        Ok(CapturePermit {
            gate: Some(self.clone()),
            started: now,
        })
    }
}

impl Drop for MutationPermit {
    fn drop(&mut self) {
        let mut state = self.gate.lock();
        state.active_mutations -= 1;
        drop(state);
        self.gate.progress.notify_waiters();
    }
}

impl CapturePermit {
    fn release(&mut self, finished: Option<Instant>) {
        let Some(gate) = self.gate.take() else {
            return;
        };
        let mut state = gate.lock();
        // Measure after taking the mutex: time spent waiting to release still
        // excluded mutations and must also be charged to pacing.
        let finished = finished.unwrap_or_else(Instant::now);
        let elapsed = finished.saturating_duration_since(self.started);
        let cooldown = elapsed
            .saturating_mul(COOLDOWN_MULTIPLIER)
            .max(MIN_COOLDOWN);
        state.next_allowed = finished.checked_add(cooldown);
        state.pacing_exhausted = state.next_allowed.is_none();
        state.capture = false;
        drop(state);
        // waiting_mutations remains nonzero until each awakened mutation has
        // atomically become active. There is no capture-admission gap here.
        gate.mutations.notify_all();
    }

    #[cfg(test)]
    fn finish_at(mut self, finished: Instant) {
        self.release(Some(finished));
    }
}

impl Drop for CapturePermit {
    fn drop(&mut self) {
        self.release(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    // No sleeps or polling: the timeout only bounds a failed test's channel
    // wait; ordering is established by gate registration and explicit signals.
    const TEST_DEADLINE: Duration = Duration::from_secs(5);

    fn receive<T>(receiver: &mpsc::Receiver<T>) -> T {
        receiver.recv_timeout(TEST_DEADLINE).unwrap()
    }

    fn wait_for_waiters(gate: &CaptureGate, count: usize) {
        let (state, timeout) = gate
            .mutations
            .wait_timeout_while(gate.lock(), TEST_DEADLINE, |state| {
                state.waiting_mutations < count
            })
            .unwrap_or_else(|error| error.into_inner());
        assert!(!timeout.timed_out(), "mutation did not register");
        assert!(state.waiting_mutations >= count);
    }

    #[test]
    fn ordinary_mutations_coexist_and_exclude_capture_until_the_last_drop() {
        let gate = Arc::new(CaptureGate::default());
        let one = gate.mutation_permit();
        let two = gate.mutation_permit();
        assert_eq!(gate.lock().active_mutations, 2);
        assert!(matches!(
            gate.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        drop(one);
        assert!(matches!(
            gate.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        drop(two);
        assert!(gate.try_capture_permit().is_ok());
    }

    #[test]
    fn capture_excludes_other_capture_and_mutations_then_wakes_all_waiters() {
        let gate = Arc::new(CaptureGate::default());
        let capture = gate.try_capture_permit().unwrap();
        assert!(matches!(
            gate.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        let (entered, entered_rx) = mpsc::channel();
        let (release_one, release_one_rx) = mpsc::channel();
        let (release_two, release_two_rx) = mpsc::channel();
        let mut jobs = Vec::new();
        for release in [release_one_rx, release_two_rx] {
            let gate = gate.clone();
            let entered = entered.clone();
            jobs.push(std::thread::spawn(move || {
                let _permit = gate.mutation_permit();
                entered.send(()).unwrap();
                receive(&release);
            }));
        }
        wait_for_waiters(&gate, 2);
        assert!(matches!(
            entered_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        drop(capture);
        receive(&entered_rx);
        receive(&entered_rx);
        assert_eq!(gate.lock().active_mutations, 2);
        release_one.send(()).unwrap();
        release_two.send(()).unwrap();
        for job in jobs {
            job.join().unwrap();
        }
        assert_eq!(gate.lock().active_mutations, 0);
    }

    #[test]
    fn queued_mutation_beats_next_capture_even_after_pacing_deadline() {
        let gate = Arc::new(CaptureGate::default());
        let now = Instant::now();
        let capture = gate.try_capture_at(now).unwrap();
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let writer = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                let _permit = gate.mutation_permit();
                entered.send(()).unwrap();
                receive(&release_rx);
            })
        };
        wait_for_waiters(&gate, 1);
        capture.finish_at(now);
        // The mutation is either still queued or already active. Neither state
        // admits capture; advancing the test clock rules out pacing as a cause.
        assert!(matches!(
            gate.try_capture_at(now + MIN_COOLDOWN),
            Err(CaptureUnavailable::Busy)
        ));
        receive(&entered_rx);
        release.send(()).unwrap();
        writer.join().unwrap();
        assert!(gate.try_capture_at(now + MIN_COOLDOWN).is_ok());
    }

    #[test]
    fn contended_bookkeeping_returns_busy_without_waiting_for_the_mutex() {
        let gate = Arc::new(CaptureGate::default());
        let locked = gate.lock();
        // A blocking lock here would deadlock on this thread's own guard.
        assert!(matches!(
            gate.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        drop(locked);
        assert!(gate.try_capture_permit().is_ok());
    }

    #[test]
    fn mutation_unwind_releases_without_poisoning_capture() {
        let gate = Arc::new(CaptureGate::default());
        let result = std::panic::catch_unwind(|| {
            let _permit = gate.mutation_permit();
            panic!("mutation job panic");
        });
        assert!(result.is_err());
        assert!(!gate.state.is_poisoned());
        assert_eq!(gate.lock().active_mutations, 0);
        assert!(gate.try_capture_permit().is_ok());
    }

    #[test]
    fn capture_unwind_releases_waiters_and_still_charges_pacing() {
        let gate = Arc::new(CaptureGate::default());
        let capture = gate.try_capture_permit().unwrap();
        let (entered, entered_rx) = mpsc::channel();
        let writer = {
            let gate = gate.clone();
            std::thread::spawn(move || {
                let _permit = gate.mutation_permit();
                entered.send(()).unwrap();
            })
        };
        wait_for_waiters(&gate, 1);
        let result = std::panic::catch_unwind(move || {
            let _permit = capture;
            panic!("native copy panic");
        });
        assert!(result.is_err());
        receive(&entered_rx);
        writer.join().unwrap();
        assert!(!gate.state.is_poisoned());
        let state = gate.lock();
        assert!(!state.capture);
        let due = state.next_allowed.unwrap();
        drop(state);
        assert!(matches!(
            gate.try_capture_at(due - Duration::from_nanos(1)),
            Err(CaptureUnavailable::NextDue(next)) if next == due
        ));
        assert!(gate.try_capture_at(due).is_ok());
    }

    #[test]
    fn bookkeeping_poison_does_not_poison_permit_release_or_admission() {
        let gate = Arc::new(CaptureGate::default());
        let mutation = gate.mutation_permit();
        let result = std::panic::catch_unwind(|| {
            let _locked = gate.lock();
            panic!("bookkeeping observer panic");
        });
        assert!(result.is_err());
        drop(mutation);
        let capture = gate.try_capture_permit().unwrap();
        drop(capture);
        let mutation = gate.mutation_permit();
        drop(mutation);
        assert!(!gate.lock().capture);
    }

    #[test]
    fn pacing_is_shared_cumulative_and_does_not_bank_idle_burst_credit() {
        let gate = Arc::new(CaptureGate::default());
        let other_replica = gate.clone();
        let now = Instant::now();
        let first_elapsed = Duration::from_millis(10);
        let first_finished = now + first_elapsed;
        gate.try_capture_at(now).unwrap().finish_at(first_finished);
        let first_due = first_finished + first_elapsed * COOLDOWN_MULTIPLIER;
        assert_eq!(gate.lock().next_allowed, Some(first_due));
        assert!(matches!(
            other_replica.try_capture_at(first_finished),
            Err(CaptureUnavailable::NextDue(due)) if due == first_due
        ));
        let second_elapsed = Duration::from_millis(20);
        let second_finished = first_due + second_elapsed;
        other_replica
            .try_capture_at(first_due)
            .unwrap()
            .finish_at(second_finished);
        let second_due = second_finished + second_elapsed * COOLDOWN_MULTIPLIER;
        assert_eq!(gate.lock().next_allowed, Some(second_due));
        assert_eq!(
            second_due.duration_since(now),
            (first_elapsed + second_elapsed) * (COOLDOWN_MULTIPLIER + 1)
        );
        let after_idle = second_due + Duration::from_secs(3600);
        gate.try_capture_at(after_idle)
            .unwrap()
            .finish_at(after_idle);
        assert!(matches!(
            other_replica.try_capture_at(after_idle),
            Err(CaptureUnavailable::NextDue(due)) if due == after_idle + MIN_COOLDOWN
        ));
    }

    #[test]
    fn capture_cooldown_never_blocks_ordinary_mutations() {
        let gate = Arc::new(CaptureGate::default());
        let now = Instant::now();
        gate.try_capture_at(now).unwrap().finish_at(now);
        let one = gate.mutation_permit();
        let two = gate.mutation_permit();
        assert_eq!(gate.lock().active_mutations, 2);
        drop(one);
        drop(two);
        assert!(matches!(
            gate.try_capture_at(now),
            Err(CaptureUnavailable::NextDue(due)) if due == now + MIN_COOLDOWN
        ));
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_drop_the_actual_blocking_jobs_guard() {
        let gate = Arc::new(CaptureGate::default());
        let (entered, entered_rx) = tokio::sync::oneshot::channel();
        let (release, release_rx) = mpsc::channel();
        let (finished, finished_rx) = tokio::sync::oneshot::channel();
        let job = {
            let gate = gate.clone();
            tokio::task::spawn_blocking(move || {
                let permit = gate.mutation_permit();
                entered.send(()).unwrap();
                receive(&release_rx);
                drop(permit);
                finished.send(()).unwrap();
            })
        };
        tokio::time::timeout(TEST_DEADLINE, entered_rx)
            .await
            .unwrap()
            .unwrap();
        // Once started, aborting/dropping the JoinHandle cannot cancel a
        // spawn_blocking job. Its permit must remain in that job's scope.
        job.abort();
        drop(job);
        assert!(matches!(
            gate.try_capture_permit(),
            Err(CaptureUnavailable::Busy)
        ));
        release.send(()).unwrap();
        tokio::time::timeout(TEST_DEADLINE, finished_rx)
            .await
            .unwrap()
            .unwrap();
        assert!(gate.try_capture_permit().is_ok());
    }
}
