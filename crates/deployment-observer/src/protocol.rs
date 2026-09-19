// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const DEPLOYMENT_OBSERVER_PROTOCOL_VERSION: u32 = 2;
/// Opt-in three-snapshot recovery verification protocol. Protocol v2 remains
/// the stable one-shot READY/FINISH contract.
pub const DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION: u32 = 3;

const MAX_RECOVERY_IDENTIFIER_BYTES: usize = 128;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinishCommand {
    pub protocol_version: u32,
    pub command: String,
    pub run_id: String,
    pub finish_nonce: String,
}

impl FinishCommand {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != DEPLOYMENT_OBSERVER_PROTOCOL_VERSION {
            bail!("unsupported deployment-observer command protocol version");
        }
        if self.command != "FINISH" {
            bail!("deployment-observer accepts only a FINISH command after READY");
        }
        if self.run_id.is_empty() || self.run_id.contains('\0') || self.run_id.contains('\n') {
            bail!("FINISH run_id is invalid");
        }
        if self.finish_nonce.len() != 64
            || !self
                .finish_nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("FINISH nonce must be exactly 64 lowercase hexadecimal bytes");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProtocolState {
    Initialized,
    Ready,
    Finishing,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtocolMachine {
    state: ProtocolState,
    run_id: String,
    finish_nonce: String,
}

impl ProtocolMachine {
    pub fn new(run_id: impl Into<String>, finish_nonce: impl Into<String>) -> Result<Self> {
        let run_id = run_id.into();
        let finish_nonce = finish_nonce.into();
        let probe = FinishCommand {
            protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
            command: "FINISH".to_owned(),
            run_id: run_id.clone(),
            finish_nonce: finish_nonce.clone(),
        };
        probe.validate()?;
        Ok(Self {
            state: ProtocolState::Initialized,
            run_id,
            finish_nonce,
        })
    }

    pub fn state(&self) -> ProtocolState {
        self.state.clone()
    }

    pub fn mark_ready(&mut self) -> Result<()> {
        if self.state != ProtocolState::Initialized {
            bail!("READY is only legal from INITIALIZED");
        }
        self.state = ProtocolState::Ready;
        Ok(())
    }

    pub fn accept_finish(&mut self, command: &FinishCommand) -> Result<()> {
        if self.state != ProtocolState::Ready {
            bail!("FINISH is only legal after exactly one READY");
        }
        command.validate()?;
        if command.run_id != self.run_id {
            bail!("FINISH run_id does not match the active observation");
        }
        if command.finish_nonce != self.finish_nonce {
            bail!("FINISH nonce does not match the READY challenge");
        }
        self.state = ProtocolState::Finishing;
        Ok(())
    }

    pub fn mark_finished(&mut self) -> Result<()> {
        if self.state != ProtocolState::Finishing {
            bail!("FINISHED is only legal after an accepted FINISH");
        }
        self.state = ProtocolState::Finished;
        Ok(())
    }

    pub fn mark_failed(&mut self) {
        self.state = ProtocolState::Failed;
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryCommandKind {
    AgentStarted,
    PreRestore,
    Finish,
}

/// One externally supplied transition in the recovery protocol.
///
/// The nonce is a replay/correlation challenge only. Protocol v3 does not
/// authenticate the caller and must not be represented as an HMAC or signed
/// control channel.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "command",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum RecoveryControlCommand {
    AgentStarted {
        protocol_version: u32,
        run_id: String,
        epoch: u64,
        checkpoint_id: String,
        recovery_id: String,
        command_seq: u32,
        nonce: String,
    },
    PreRestore {
        protocol_version: u32,
        run_id: String,
        epoch: u64,
        checkpoint_id: String,
        recovery_id: String,
        command_seq: u32,
        nonce: String,
    },
    Finish {
        protocol_version: u32,
        run_id: String,
        epoch: u64,
        checkpoint_id: String,
        recovery_id: String,
        command_seq: u32,
        nonce: String,
    },
}

impl RecoveryControlCommand {
    pub fn kind(&self) -> RecoveryCommandKind {
        match self {
            Self::AgentStarted { .. } => RecoveryCommandKind::AgentStarted,
            Self::PreRestore { .. } => RecoveryCommandKind::PreRestore,
            Self::Finish { .. } => RecoveryCommandKind::Finish,
        }
    }

    pub fn validate(&self) -> Result<()> {
        let expected_seq = match self.kind() {
            RecoveryCommandKind::AgentStarted => 1,
            RecoveryCommandKind::PreRestore => 2,
            RecoveryCommandKind::Finish => 3,
        };
        let binding = self.binding();
        validate_recovery_binding(
            binding.protocol_version,
            binding.run_id,
            binding.epoch,
            binding.checkpoint_id,
            binding.recovery_id,
            binding.command_seq,
            binding.nonce,
            expected_seq,
        )
    }

    fn binding(&self) -> RecoveryCommandBinding<'_> {
        let (protocol_version, run_id, epoch, checkpoint_id, recovery_id, command_seq, nonce) =
            match self {
                Self::AgentStarted {
                    protocol_version,
                    run_id,
                    epoch,
                    checkpoint_id,
                    recovery_id,
                    command_seq,
                    nonce,
                }
                | Self::PreRestore {
                    protocol_version,
                    run_id,
                    epoch,
                    checkpoint_id,
                    recovery_id,
                    command_seq,
                    nonce,
                }
                | Self::Finish {
                    protocol_version,
                    run_id,
                    epoch,
                    checkpoint_id,
                    recovery_id,
                    command_seq,
                    nonce,
                } => (
                    *protocol_version,
                    run_id.as_str(),
                    *epoch,
                    checkpoint_id.as_str(),
                    recovery_id.as_str(),
                    *command_seq,
                    nonce.as_str(),
                ),
            };
        RecoveryCommandBinding {
            protocol_version,
            run_id,
            epoch,
            checkpoint_id,
            recovery_id,
            command_seq,
            nonce,
        }
    }
}

#[derive(Clone, Copy)]
struct RecoveryCommandBinding<'a> {
    protocol_version: u32,
    run_id: &'a str,
    epoch: u64,
    checkpoint_id: &'a str,
    recovery_id: &'a str,
    command_seq: u32,
    nonce: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryProtocolState {
    Initialized,
    ReadyACommitted,
    AgentRunning,
    PreRestoreAccepted,
    BCommitted,
    Restoring,
    RestoreComplete,
    CCommitted,
    Finalizing,
    Finished,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryProtocolMachine {
    state: RecoveryProtocolState,
    run_id: String,
    epoch: u64,
    checkpoint_id: String,
    recovery_id: String,
    expected_command_seq: u32,
    nonce: String,
}

impl RecoveryProtocolMachine {
    pub fn new(
        run_id: impl Into<String>,
        epoch: u64,
        checkpoint_id: impl Into<String>,
        recovery_id: impl Into<String>,
        ready_nonce: impl Into<String>,
    ) -> Result<Self> {
        let run_id = run_id.into();
        let checkpoint_id = checkpoint_id.into();
        let recovery_id = recovery_id.into();
        let ready_nonce = ready_nonce.into();
        validate_recovery_binding(
            DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            &run_id,
            epoch,
            &checkpoint_id,
            &recovery_id,
            1,
            &ready_nonce,
            1,
        )?;
        Ok(Self {
            state: RecoveryProtocolState::Initialized,
            run_id,
            epoch,
            checkpoint_id,
            recovery_id,
            expected_command_seq: 1,
            nonce: ready_nonce,
        })
    }

    pub fn state(&self) -> RecoveryProtocolState {
        self.state.clone()
    }

    pub fn expected_command_seq(&self) -> u32 {
        self.expected_command_seq
    }

    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    pub fn mark_ready_a_committed(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::Initialized,
            "READY_A_COMMITTED is only legal from INITIALIZED",
        )?;
        self.state = RecoveryProtocolState::ReadyACommitted;
        Ok(())
    }

    pub fn accept_agent_started(
        &mut self,
        command: &RecoveryControlCommand,
        pre_restore_nonce: impl Into<String>,
    ) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::ReadyACommitted,
            "AGENT_STARTED is only legal after READY_A_COMMITTED",
        )?;
        self.validate_command(command, RecoveryCommandKind::AgentStarted)?;
        let next_nonce = pre_restore_nonce.into();
        self.validate_next_nonce(&next_nonce)?;
        self.state = RecoveryProtocolState::AgentRunning;
        self.expected_command_seq = 2;
        self.nonce = next_nonce;
        Ok(())
    }

    pub fn accept_pre_restore(
        &mut self,
        command: &RecoveryControlCommand,
        finish_nonce: impl Into<String>,
    ) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::AgentRunning,
            "PRE_RESTORE is only legal while AGENT_RUNNING",
        )?;
        self.validate_command(command, RecoveryCommandKind::PreRestore)?;
        let next_nonce = finish_nonce.into();
        self.validate_next_nonce(&next_nonce)?;
        self.state = RecoveryProtocolState::PreRestoreAccepted;
        self.expected_command_seq = 3;
        self.nonce = next_nonce;
        Ok(())
    }

    pub fn mark_b_committed(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::PreRestoreAccepted,
            "B_COMMITTED is only legal after PRE_RESTORE_ACCEPTED",
        )?;
        self.state = RecoveryProtocolState::BCommitted;
        Ok(())
    }

    pub fn mark_restoring(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::BCommitted,
            "RESTORING is only legal after B_COMMITTED",
        )?;
        self.state = RecoveryProtocolState::Restoring;
        Ok(())
    }

    pub fn mark_restore_complete(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::Restoring,
            "RESTORE_COMPLETE is only legal while RESTORING",
        )?;
        self.state = RecoveryProtocolState::RestoreComplete;
        Ok(())
    }

    pub fn mark_c_committed(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::RestoreComplete,
            "C_COMMITTED is only legal after RESTORE_COMPLETE",
        )?;
        self.state = RecoveryProtocolState::CCommitted;
        Ok(())
    }

    pub fn accept_finish(&mut self, command: &RecoveryControlCommand) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::CCommitted,
            "FINISH is only legal after C_COMMITTED",
        )?;
        self.validate_command(command, RecoveryCommandKind::Finish)?;
        self.state = RecoveryProtocolState::Finalizing;
        Ok(())
    }

    pub fn mark_finished(&mut self) -> Result<()> {
        self.require_state(
            RecoveryProtocolState::Finalizing,
            "FINISHED is only legal after FINALIZING",
        )?;
        self.state = RecoveryProtocolState::Finished;
        Ok(())
    }

    pub fn mark_failed(&mut self) {
        self.state = RecoveryProtocolState::Failed;
    }

    fn validate_command(
        &self,
        command: &RecoveryControlCommand,
        expected_kind: RecoveryCommandKind,
    ) -> Result<()> {
        command.validate()?;
        let binding = command.binding();
        if command.kind() != expected_kind {
            bail!("recovery command kind is out of order");
        }
        if binding.run_id != self.run_id
            || binding.epoch != self.epoch
            || binding.checkpoint_id != self.checkpoint_id
            || binding.recovery_id != self.recovery_id
        {
            bail!("recovery command identity does not match the active run");
        }
        if binding.command_seq != self.expected_command_seq {
            bail!("recovery command sequence does not match the active transition");
        }
        if binding.nonce != self.nonce {
            bail!("recovery command nonce does not match the active challenge");
        }
        Ok(())
    }

    fn validate_next_nonce(&self, next_nonce: &str) -> Result<()> {
        validate_nonce(next_nonce, "next recovery command")?;
        if next_nonce == self.nonce {
            bail!("the next recovery command must use a fresh nonce");
        }
        Ok(())
    }

    fn require_state(&self, expected: RecoveryProtocolState, message: &str) -> Result<()> {
        if self.state != expected {
            bail!(message.to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReadyMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub snapshot_a_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStartedMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub agent_started_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotBMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub pre_restore_sha256: String,
    pub snapshot_b_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreCompleteMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub recovery_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotCMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub snapshot_c_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryTerminalMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub command_seq: u32,
    pub nonce: String,
    pub verdict_sha256: String,
    pub artifact_manifest_sha256: String,
}

#[allow(clippy::too_many_arguments)]
fn validate_recovery_binding(
    protocol_version: u32,
    run_id: &str,
    epoch: u64,
    checkpoint_id: &str,
    recovery_id: &str,
    command_seq: u32,
    nonce: &str,
    expected_seq: u32,
) -> Result<()> {
    if protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION {
        bail!("unsupported deployment-observer recovery protocol version");
    }
    validate_recovery_identifier(run_id, "run_id")?;
    validate_recovery_identifier(checkpoint_id, "checkpoint_id")?;
    validate_recovery_identifier(recovery_id, "recovery_id")?;
    if epoch == 0 {
        bail!("recovery protocol epoch must be nonzero");
    }
    if command_seq != expected_seq {
        bail!("recovery command has an invalid sequence number");
    }
    validate_nonce(nonce, "recovery command")
}

fn validate_recovery_identifier(value: &str, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_RECOVERY_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("{label} must contain 1..=128 conservative ASCII identity bytes");
    }
    Ok(())
}

fn validate_nonce(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} nonce must be exactly 64 lowercase hexadecimal bytes");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    pub epoch: u64,
    pub finish_nonce: String,
    pub deployment_scope_sha256: String,
    pub registration_cgroup_ids: Vec<u64>,
    pub cgroup_scope_capability_sha256: String,
    pub cgroup_scope_capability: crate::CgroupScopeCapability,
    pub deployment_manifest_sha256: String,
    pub ready_barrier_sha256: String,
    pub ready_validation_sha256: String,
    pub recorder_object_sha256: String,
    pub lifecycle_object_sha256: String,
    pub socket_state_enabled: bool,
    pub bpf_state_scope_sha256: Option<String>,
    pub bpf_state_s0_sha256: Option<String>,
    pub filesystem_state_scope_sha256: Option<String>,
    pub filesystem_state_s0_sha256: Option<String>,
    pub linux_state_scope_sha256: Option<String>,
    pub linux_state_s0_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalMessage {
    pub protocol_version: u32,
    pub status: String,
    pub run_id: String,
    /// Conservative overall status across all enabled evidence domains.
    pub evidence_status: String,
    pub report_sha256: String,
    pub artifact_manifest_sha256: String,
}
