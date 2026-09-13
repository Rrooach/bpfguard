// SPDX-License-Identifier: GPL-2.0-only

//! Framework-independent evidence contract for brokered helper execution.
//!
//! This module validates a bounded execution-chain ledger. It deliberately
//! does not alter direct syscall attribution and does not authenticate the
//! ledger by itself. A trusted runner must bind the exact ledger artifact into
//! its finalized manifest or signed transcript before claiming a broker
//! request execution chain.

use crate::EffectOperation;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const DELEGATION_LEDGER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_DELEGATION_REQUESTS: usize = 4_096;
pub const MAX_DELEGATION_DEPTH: usize = 16;
pub const MAX_DELEGATION_TEXT_BYTES: usize = 128;
pub const MAX_DELEGATION_TTL_NS: u64 = 86_400_000_000_000;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationTransitionKind {
    Accepted,
    Registered,
    Started,
    Completed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DelegationExecutionClaim {
    BrokerRequestExecutionChainEstablished,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationTransition {
    pub sequence: u8,
    pub kind: DelegationTransitionKind,
    pub monotonic_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequestBinding {
    /// Fresh 16-byte identifier encoded as 32 lowercase hexadecimal bytes.
    pub request_id: String,
    pub parent_request_id: Option<String>,
    /// Canonical position in this ledger, starting at one.
    pub sequence: u64,
    pub source_cgroup_id: u64,
    pub helper_cgroup_id: u64,
    pub adapter_id: String,
    pub adapter_version: String,
    pub operation: EffectOperation,
    pub canonical_request_sha256: String,
    pub issued_monotonic_ns: u64,
    pub expires_monotonic_ns: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequestRecord {
    pub binding: DelegationRequestBinding,
    pub transitions: Vec<DelegationTransition>,
    pub claim: DelegationExecutionClaim,
}

/// Producer-side close boundary for one finalized delegation ledger. The
/// trusted producer must hold each request cgroup open until it has verified
/// that exact cgroup empty and frozen. These fields become evidence only when
/// the complete ledger is authenticated or digest-bound by an external trust
/// path.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLedgerClosure {
    pub finalized_monotonic_ns: u64,
    pub empty_frozen_helper_cgroup_ids: Vec<u64>,
    pub outstanding_request_count: u32,
    pub outstanding_token_count: u32,
    pub outstanding_helper_count: u32,
    pub outstanding_request_cgroup_count: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationLedger {
    pub protocol_version: u32,
    pub boot_id: String,
    pub run_id: String,
    pub run_epoch: u64,
    pub primary_cgroup_id: u64,
    pub requests: Vec<DelegationRequestRecord>,
    pub closure: DelegationLedgerClosure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DelegationValidationSummary {
    pub request_count: usize,
    pub completed_count: usize,
    pub failed_count: usize,
    pub maximum_depth: usize,
}

impl DelegationLedger {
    /// Validate structure and execution-domain linkage against values supplied
    /// by an external trust path. This is not a signature check.
    pub fn validate_against(
        &self,
        expected_boot_id: &str,
        expected_run_id: &str,
        expected_run_epoch: u64,
        expected_primary_cgroup_id: u64,
    ) -> Result<DelegationValidationSummary> {
        if self.protocol_version != DELEGATION_LEDGER_PROTOCOL_VERSION {
            bail!("unsupported delegation ledger protocol version");
        }
        validate_text(&self.boot_id, "delegation boot_id")?;
        validate_text(&self.run_id, "delegation run_id")?;
        if self.boot_id != expected_boot_id
            || self.run_id != expected_run_id
            || self.run_epoch != expected_run_epoch
            || self.primary_cgroup_id != expected_primary_cgroup_id
        {
            bail!("delegation ledger does not match its externally trusted run binding");
        }
        if self.run_epoch == 0 || self.primary_cgroup_id == 0 {
            bail!("delegation run epoch and primary cgroup ID must be nonzero");
        }
        if self.requests.is_empty() || self.requests.len() > MAX_DELEGATION_REQUESTS {
            bail!("delegation request count is outside the supported bound");
        }

        let mut request_ids = HashSet::with_capacity(self.requests.len());
        let mut helper_cgroups = HashSet::with_capacity(self.requests.len());
        let mut completed_count = 0usize;
        let mut failed_count = 0usize;
        let mut maximum_depth = 0usize;
        let mut established =
            HashMap::<String, (u64, usize, u64, u64, DelegationTransitionKind)>::new();
        let mut previous_issued_monotonic_ns = 0u64;

        for (index, request) in self.requests.iter().enumerate() {
            let expected_sequence =
                u64::try_from(index + 1).expect("bounded delegation count fits u64");
            let binding = &request.binding;
            if binding.sequence != expected_sequence {
                bail!("delegation requests are not in canonical sequence order");
            }
            validate_lower_hex(&binding.request_id, 16, "delegation request_id")?;
            if !request_ids.insert(binding.request_id.clone()) {
                bail!("delegation request_id is duplicated");
            }
            if binding.source_cgroup_id == 0
                || binding.helper_cgroup_id == 0
                || binding.source_cgroup_id == binding.helper_cgroup_id
                || binding.helper_cgroup_id == self.primary_cgroup_id
            {
                bail!("delegation source/helper cgroup binding is invalid");
            }
            if !helper_cgroups.insert(binding.helper_cgroup_id) {
                bail!("delegation helper cgroup ID is reused");
            }
            validate_identifier(&binding.adapter_id, "delegation adapter_id")?;
            validate_identifier(&binding.adapter_version, "delegation adapter_version")?;
            validate_lower_hex(
                &binding.canonical_request_sha256,
                32,
                "delegation canonical_request_sha256",
            )?;
            binding
                .expires_monotonic_ns
                .checked_sub(binding.issued_monotonic_ns)
                .filter(|ttl| *ttl != 0 && *ttl <= MAX_DELEGATION_TTL_NS)
                .ok_or_else(|| anyhow::anyhow!("delegation request TTL is invalid"))?;
            if binding.issued_monotonic_ns < previous_issued_monotonic_ns {
                bail!("delegation requests are not in monotonic issue-time order");
            }
            previous_issued_monotonic_ns = binding.issued_monotonic_ns;

            let terminal = validate_transitions(binding, &request.transitions)?;
            let started_monotonic_ns = request.transitions[2].monotonic_ns;
            let terminal_monotonic_ns = request.transitions[3].monotonic_ns;

            let depth = match binding.parent_request_id.as_deref() {
                None => {
                    if binding.source_cgroup_id != self.primary_cgroup_id {
                        bail!("root delegation request did not originate in the primary cgroup");
                    }
                    1usize
                }
                Some(parent_id) => {
                    validate_lower_hex(parent_id, 16, "delegation parent_request_id")?;
                    let (
                        parent_helper,
                        parent_depth,
                        parent_started_monotonic_ns,
                        parent_terminal_monotonic_ns,
                        parent_terminal,
                    ) = established.get(parent_id).copied().ok_or_else(|| {
                        anyhow::anyhow!("delegation parent is absent or not earlier")
                    })?;
                    if parent_terminal != DelegationTransitionKind::Completed {
                        bail!("nested delegation parent did not complete successfully");
                    }
                    if binding.source_cgroup_id != parent_helper {
                        bail!("nested delegation source is not its parent helper cgroup");
                    }
                    if binding.issued_monotonic_ns < parent_started_monotonic_ns
                        || terminal_monotonic_ns > parent_terminal_monotonic_ns
                    {
                        bail!("nested delegation lifetime is outside its parent execution");
                    }
                    parent_depth
                        .checked_add(1)
                        .ok_or_else(|| anyhow::anyhow!("delegation depth overflow"))?
                }
            };
            if depth > MAX_DELEGATION_DEPTH {
                bail!("delegation nesting exceeds the supported bound");
            }
            maximum_depth = maximum_depth.max(depth);

            match terminal {
                DelegationTransitionKind::Completed => completed_count += 1,
                DelegationTransitionKind::Failed => failed_count += 1,
                _ => unreachable!("transition validator returns only terminal states"),
            }
            if request.claim != DelegationExecutionClaim::BrokerRequestExecutionChainEstablished {
                bail!("delegation record declares an unsupported execution-chain claim");
            }
            established.insert(
                binding.request_id.clone(),
                (
                    binding.helper_cgroup_id,
                    depth,
                    started_monotonic_ns,
                    terminal_monotonic_ns,
                    terminal,
                ),
            );
        }

        let mut expected_closed_cgroups = helper_cgroups.into_iter().collect::<Vec<_>>();
        expected_closed_cgroups.sort_unstable();
        if self.closure.empty_frozen_helper_cgroup_ids != expected_closed_cgroups
            || self.closure.outstanding_request_count != 0
            || self.closure.outstanding_token_count != 0
            || self.closure.outstanding_helper_count != 0
            || self.closure.outstanding_request_cgroup_count != 0
        {
            bail!("delegation ledger lacks a complete empty/frozen close boundary");
        }
        let last_terminal_monotonic_ns = self
            .requests
            .iter()
            .map(|request| request.transitions[3].monotonic_ns)
            .max()
            .expect("a validated delegation ledger is nonempty");
        if self.closure.finalized_monotonic_ns < last_terminal_monotonic_ns {
            bail!("delegation ledger finalized before a request terminal transition");
        }

        Ok(DelegationValidationSummary {
            request_count: self.requests.len(),
            completed_count,
            failed_count,
            maximum_depth,
        })
    }
}

fn validate_transitions(
    binding: &DelegationRequestBinding,
    transitions: &[DelegationTransition],
) -> Result<DelegationTransitionKind> {
    if transitions.len() != 4 {
        bail!("delegation request does not contain the complete lifecycle");
    }
    let required = [
        DelegationTransitionKind::Accepted,
        DelegationTransitionKind::Registered,
        DelegationTransitionKind::Started,
    ];
    let mut previous_time = binding.issued_monotonic_ns;
    for (index, transition) in transitions.iter().enumerate() {
        if transition.sequence != (index + 1) as u8 {
            bail!("delegation transitions are not in canonical sequence order");
        }
        if transition.monotonic_ns < previous_time {
            bail!("delegation transition time moved backwards");
        }
        if index < required.len() && transition.kind != required[index] {
            bail!("delegation lifecycle prefix is invalid");
        }
        previous_time = transition.monotonic_ns;
    }
    if transitions[2].monotonic_ns > binding.expires_monotonic_ns {
        bail!("delegation helper started after request expiry");
    }
    let terminal = transitions[3].kind;
    if !matches!(
        terminal,
        DelegationTransitionKind::Completed | DelegationTransitionKind::Failed
    ) {
        bail!("delegation lifecycle has no terminal state");
    }
    Ok(terminal)
}

fn validate_identifier(value: &str, field: &str) -> Result<()> {
    validate_text(value, field)?;
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!("{field} contains a non-canonical character");
    }
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_DELEGATION_TEXT_BYTES || value.as_bytes().contains(&0)
    {
        bail!("{field} is empty, too long, or contains NUL");
    }
    Ok(())
}

fn validate_lower_hex(value: &str, bytes: usize, field: &str) -> Result<()> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{field} is not canonical lowercase hexadecimal data");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transition(sequence: u8, kind: DelegationTransitionKind, time: u64) -> DelegationTransition {
        DelegationTransition {
            sequence,
            kind,
            monotonic_ns: time,
        }
    }

    fn record(
        sequence: u64,
        request_id: &str,
        parent_request_id: Option<&str>,
        source_cgroup_id: u64,
        helper_cgroup_id: u64,
        times: [u64; 5],
    ) -> DelegationRequestRecord {
        DelegationRequestRecord {
            binding: DelegationRequestBinding {
                request_id: request_id.to_owned(),
                parent_request_id: parent_request_id.map(str::to_owned),
                sequence,
                source_cgroup_id,
                helper_cgroup_id,
                adapter_id: "test-adapter".to_owned(),
                adapter_version: "1.0.0".to_owned(),
                operation: EffectOperation::FileCreateOrTruncate,
                canonical_request_sha256: "ab".repeat(32),
                issued_monotonic_ns: times[0],
                expires_monotonic_ns: times[4],
            },
            transitions: vec![
                transition(1, DelegationTransitionKind::Accepted, times[0]),
                transition(2, DelegationTransitionKind::Registered, times[1]),
                transition(3, DelegationTransitionKind::Started, times[2]),
                transition(4, DelegationTransitionKind::Completed, times[3]),
            ],
            claim: DelegationExecutionClaim::BrokerRequestExecutionChainEstablished,
        }
    }

    fn ledger() -> DelegationLedger {
        DelegationLedger {
            protocol_version: DELEGATION_LEDGER_PROTOCOL_VERSION,
            boot_id: "boot-id".to_owned(),
            run_id: "run-id".to_owned(),
            run_epoch: 7,
            primary_cgroup_id: 41,
            requests: vec![
                record(
                    1,
                    "11".repeat(16).as_str(),
                    None,
                    41,
                    42,
                    [100, 110, 120, 200, 1_000],
                ),
                record(
                    2,
                    "22".repeat(16).as_str(),
                    Some("11".repeat(16).as_str()),
                    42,
                    43,
                    [125, 130, 140, 180, 900],
                ),
            ],
            closure: DelegationLedgerClosure {
                finalized_monotonic_ns: 210,
                empty_frozen_helper_cgroup_ids: vec![42, 43],
                outstanding_request_count: 0,
                outstanding_token_count: 0,
                outstanding_helper_count: 0,
                outstanding_request_cgroup_count: 0,
            },
        }
    }

    #[test]
    fn complete_nested_chain_is_valid() {
        let summary = ledger()
            .validate_against("boot-id", "run-id", 7, 41)
            .unwrap();
        assert_eq!(
            summary,
            DelegationValidationSummary {
                request_count: 2,
                completed_count: 2,
                failed_count: 0,
                maximum_depth: 2,
            }
        );
    }

    #[test]
    fn replay_and_helper_reuse_are_rejected() {
        let mut duplicated_request = ledger();
        duplicated_request.requests[1].binding.request_id =
            duplicated_request.requests[0].binding.request_id.clone();
        assert!(duplicated_request
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut reused_helper = ledger();
        reused_helper.requests[1].binding.helper_cgroup_id = 42;
        assert!(reused_helper
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());
    }

    #[test]
    fn wrong_parent_source_and_lifecycle_are_rejected() {
        let mut wrong_source = ledger();
        wrong_source.requests[1].binding.source_cgroup_id = 99;
        assert!(wrong_source
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut incomplete = ledger();
        incomplete.requests[0].transitions.pop();
        assert!(incomplete
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut expired = ledger();
        expired.requests[0].binding.expires_monotonic_ns = 115;
        assert!(expired
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut outside_parent_lifetime = ledger();
        outside_parent_lifetime.requests[1]
            .binding
            .issued_monotonic_ns = 115;
        outside_parent_lifetime.requests[1].transitions[0].monotonic_ns = 115;
        assert!(outside_parent_lifetime
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut failed_parent = ledger();
        failed_parent.requests[0].transitions[3].kind = DelegationTransitionKind::Failed;
        assert!(failed_parent
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());
    }

    #[test]
    fn external_run_binding_is_mandatory() {
        let ledger = ledger();
        assert!(ledger
            .validate_against("other-boot", "run-id", 7, 41)
            .is_err());
        assert!(ledger
            .validate_against("boot-id", "other-run", 7, 41)
            .is_err());
        assert!(ledger.validate_against("boot-id", "run-id", 8, 41).is_err());
        assert!(ledger.validate_against("boot-id", "run-id", 7, 44).is_err());
    }

    #[test]
    fn close_boundary_must_cover_every_helper_and_no_outstanding_state() {
        let mut missing_helper = ledger();
        missing_helper.closure.empty_frozen_helper_cgroup_ids.pop();
        assert!(missing_helper
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut outstanding_token = ledger();
        outstanding_token.closure.outstanding_token_count = 1;
        assert!(outstanding_token
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());

        let mut early_finalization = ledger();
        early_finalization.closure.finalized_monotonic_ns = 179;
        assert!(early_finalization
            .validate_against("boot-id", "run-id", 7, 41)
            .is_err());
    }
}
