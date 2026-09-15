// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

pub const DEPLOYMENT_OBSERVER_PROTOCOL_VERSION: u32 = 2;

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
