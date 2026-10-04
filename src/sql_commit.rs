//! Mutation-only SQL temporal attenuation. Application proofs never enter here.
//! Admission is sampled in the ordered Raft core, not on replica application.
use crate::consensus::{CompactBatch, RaftCommand};
use crate::service::clock::Clock;
use openraft::{CommittedLeaderId, LogId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub(crate) const EXPIRED_MESSAGE: &str =
    "SQL completion authorization expired before ordered proposal";
pub(crate) const STALE_MESSAGE: &str =
    "SQL completion source authorization changed before ordered proposal";
pub(crate) const MAX_SAFE_MS: u64 = 9_007_199_254_740_991;

#[derive(Debug)]
pub(crate) struct Expired;
impl std::fmt::Display for Expired {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(EXPIRED_MESSAGE)
    }
}
impl std::error::Error for Expired {}

/// Only scalar native admission metadata is logged. The exact service clock is
/// an in-process capability removed by the core before assigning a log ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Admission {
    before: u64,
    at: Option<u64>,
    leader: Option<CommittedLeaderId<u64>>,
    previous: Option<LogId<u64>>,
    #[serde(skip)]
    basis: Option<Arc<crate::consensus::NativeWriteBasis>>,
    #[serde(skip)]
    clock: Option<Clock>,
    #[serde(skip)]
    max_bytes: Option<usize>,
}
impl PartialEq for Admission {
    fn eq(&self, other: &Self) -> bool {
        (self.before, self.at, self.leader, self.previous)
            == (other.before, other.at, other.leader, other.previous)
    }
}
impl Admission {
    fn pending(
        before: u64,
        clock: Clock,
        basis: Arc<crate::consensus::NativeWriteBasis>,
        max_bytes: usize,
    ) -> Self {
        Self {
            before,
            at: None,
            leader: None,
            previous: None,
            basis: Some(basis),
            clock: Some(clock),
            max_bytes: Some(max_bytes),
        }
    }
    fn prepare(
        &mut self,
        command: &RaftCommand,
        leader: CommittedLeaderId<u64>,
        previous: Option<LogId<u64>>,
    ) -> Result<usize, String> {
        if deadline(command) != Some(self.before)
            || self.before > MAX_SAFE_MS
            || self.at.is_some()
            || self.leader.is_some()
            || self.clock.is_none()
            || self.basis.is_none()
            || self.previous.is_some()
        {
            return Err("SQL commit admission is invalid".into());
        }
        let max_bytes = self
            .max_bytes
            .take()
            .ok_or("SQL commit admission has no native byte limit")?;
        // Size the complete scoped envelope at the maximum timestamp width
        // BEFORE the final clock decision. No private payload encoding follows
        // that fresh decision in this admission hook.
        self.at = Some(MAX_SAFE_MS);
        self.leader = Some(leader);
        self.previous = previous;
        Ok(max_bytes)
    }
    fn stamp(
        &mut self,
        expected_revision: u64,
        leader: CommittedLeaderId<u64>,
        previous: Option<LogId<u64>>,
    ) -> Result<(), String> {
        let clock = self
            .clock
            .take()
            .ok_or("SQL commit admission has no native clock")?;
        let basis = self
            .basis
            .take()
            .ok_or("SQL commit admission has no native source basis")?;
        basis.decide(expected_revision, leader, previous, || {
            let now = clock
                .sample_after(0)
                .map_err(|_| "SQL commit clock is unavailable")?;
            if now >= self.before {
                return Err(EXPIRED_MESSAGE.into());
            }
            self.at = Some(now);
            Ok(())
        })
    }
    /// Replay checks only logged scalar provenance and the actual log leader.
    /// Quorum/flush/application may happen later. No local replica clock branch.
    pub(crate) fn valid(&self, command: &RaftCommand, log_id: LogId<u64>) -> bool {
        deadline(command) == Some(self.before)
            && self.before <= MAX_SAFE_MS
            && self.at.is_some_and(|now| now < self.before)
            && self.leader == Some(log_id.leader_id)
            && self.previous.map_or(log_id.index == 0, |previous| {
                previous.index.checked_add(1) == Some(log_id.index)
            })
            && matches!(command, RaftCommand::Single(_) | RaftCommand::Batch { .. })
    }
}

pub(crate) fn batch_deadline(batch: &CompactBatch) -> Option<u64> {
    batch
        .items
        .iter()
        .filter_map(|item| item.sql_commit_before)
        .min()
}
pub(crate) fn deadline(command: &RaftCommand) -> Option<u64> {
    match command {
        RaftCommand::Single(commit) | RaftCommand::Fenced { commit, .. } => {
            commit.sql_commit_before
        }
        RaftCommand::Batch { batch } => batch_deadline(batch),
        RaftCommand::Scoped { command, .. } => deadline(command),
        RaftCommand::Sql { command, .. } => deadline(command),
        _ => None,
    }
}

pub(crate) fn wrap(
    command: RaftCommand,
    clock: Option<Clock>,
    basis: Option<Arc<crate::consensus::NativeWriteBasis>>,
    max_bytes: usize,
) -> anyhow::Result<RaftCommand> {
    let Some(before) = deadline(&command) else {
        return Ok(command);
    };
    anyhow::ensure!(before <= MAX_SAFE_MS, "SQL commit deadline is invalid");
    anyhow::ensure!(
        matches!(command, RaftCommand::Single(_) | RaftCommand::Batch { .. }),
        "SQL commit command is invalid"
    );
    let clock =
        clock.ok_or_else(|| anyhow::anyhow!("SQL commit requires native ordered admission"))?;
    let basis = basis
        .ok_or_else(|| anyhow::anyhow!("SQL commit requires its original native write basis"))?;
    Ok(RaftCommand::Sql {
        sql_admission: Admission::pending(before, clock, basis, max_bytes),
        command: Box::new(command),
    })
}

/// The generic Raft config invokes this before it can append any application
/// payload. Unwrapped fences and serialized/copied pending admissions fail closed.
fn prepare(
    command: &mut RaftCommand,
    leader: CommittedLeaderId<u64>,
    previous: Option<LogId<u64>>,
) -> Result<Option<usize>, String> {
    match command {
        RaftCommand::Scoped { command, .. } => prepare(command, leader, previous),
        RaftCommand::Sql {
            sql_admission,
            command,
        } => sql_admission.prepare(command, leader, previous).map(Some),
        command if deadline(command).is_some() => {
            Err("SQL commit requires native ordered admission".into())
        }
        _ => Ok(None),
    }
}
fn stamp(
    command: &mut RaftCommand,
    leader: CommittedLeaderId<u64>,
    previous: Option<LogId<u64>>,
) -> Result<(), String> {
    match command {
        RaftCommand::Scoped { command, .. } => stamp(command, leader, previous),
        RaftCommand::Sql {
            sql_admission,
            command,
        } => {
            let revision = match &**command {
                RaftCommand::Single(commit) => commit.expected_revision,
                RaftCommand::Batch { batch } => batch.expected_revision,
                _ => return Err("SQL commit command is invalid".into()),
            };
            sql_admission.stamp(revision, leader, previous)
        }
        _ => Ok(()),
    }
}

pub(crate) fn admit(
    command: &mut RaftCommand,
    leader: CommittedLeaderId<u64>,
    previous: Option<LogId<u64>>,
) -> Result<(), String> {
    if let Some(max_bytes) = prepare(command, leader, previous)? {
        let bytes = crate::consensus::encoded_json_len(command)
            .map_err(|_| "SQL commit encoding is invalid")?;
        if bytes > max_bytes {
            return Err("SQL commit exceeds native transaction byte limit".into());
        }
        // Last ordered decision, after all queued/structural/encoding work.
        stamp(command, leader, previous)?
    }
    Ok(())
}

pub(crate) fn is_expired(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Expired>().is_some() || error.chain().any(|error| {
        matches!(error.downcast_ref::<openraft::error::RaftError<u64, openraft::error::ClientWriteError<u64, openraft::BasicNode>>>(),
            Some(openraft::error::RaftError::APIError(openraft::error::ClientWriteError::AdmissionRejected(reason))) if reason == EXPIRED_MESSAGE)
    })
}

pub(crate) fn is_stale(error: &anyhow::Error) -> bool {
    error.chain().any(|error| matches!(error.downcast_ref::<openraft::error::RaftError<u64, openraft::error::ClientWriteError<u64, openraft::BasicNode>>>(),
        Some(openraft::error::RaftError::APIError(openraft::error::ClientWriteError::AdmissionRejected(reason))) if reason == STALE_MESSAGE))
}
