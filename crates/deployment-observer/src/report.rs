// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::{
    DeploymentManifest, LiveIdentityValidation, RevalidationPhase, DEPLOYMENT_PROTOCOL_VERSION,
};
use bpf_observer_filesystem_confirmer::{
    CompletenessStatus as FilesystemCompletenessStatus, FilesystemVerdict,
};
use bpf_observer_schema::{
    CompletenessStatus as BpfCompletenessStatus, StateVerdict as BpfStateVerdict,
};
use bpf_observer_system_effects::lifecycle::{ProcessLifecycleHealth, ProcessLifecycleStatus};
use bpf_observer_system_effects::socket_state::{
    SocketStateHealth, SocketStateProducerSeal, SocketStateStatus, SOCKET_STATE_HEALTH_NAME,
    SOCKET_STATE_JSONL_NAME, SOCKET_STATE_SCHEMA_VERSION, SOCKET_STATE_WAL_NAME,
};
use bpf_observer_system_effects::{
    policy_sha256, CgroupMatchMode, SystemEffectHealth, TransportStatus,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::barrier::RootFreezeBarrier;
use crate::endpoint_state::{BpfStateReport, FilesystemStateReport};
use crate::linux_state::{LinuxStateEvidenceStatus, LinuxStateReport};
use crate::protocol::DEPLOYMENT_OBSERVER_PROTOCOL_VERSION;

pub const DIAGNOSTIC_TELEMETRY_PURPOSE: &str = "DIAGNOSTIC_ONLY_NOT_TRUSTED_EVIDENCE";
pub const DIAGNOSTIC_MONOTONIC_CLOCK: &str = "RUST_STD_INSTANT_MONOTONIC_V1";
const MAX_DIAGNOSTIC_DURATION_NS: u64 = 30 * 24 * 60 * 60 * 1_000_000_000;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointCaptureTelemetry {
    pub total_duration_ns: u64,
    pub bpf_duration_ns: Option<u64>,
    pub filesystem_duration_ns: Option<u64>,
    pub linux_duration_ns: Option<u64>,
}

impl EndpointCaptureTelemetry {
    pub fn new(
        bpf_duration_ns: Option<u64>,
        filesystem_duration_ns: Option<u64>,
        linux_duration_ns: Option<u64>,
    ) -> Result<Self> {
        let total_duration_ns = checked_optional_duration_sum([
            bpf_duration_ns,
            filesystem_duration_ns,
            linux_duration_ns,
        ])?;
        let telemetry = Self {
            total_duration_ns,
            bpf_duration_ns,
            filesystem_duration_ns,
            linux_duration_ns,
        };
        telemetry.validate(
            telemetry.bpf_duration_ns.is_some(),
            telemetry.filesystem_duration_ns.is_some(),
            telemetry.linux_duration_ns.is_some(),
        )?;
        Ok(telemetry)
    }

    fn validate(
        &self,
        bpf_enabled: bool,
        filesystem_enabled: bool,
        linux_enabled: bool,
    ) -> Result<()> {
        if self.bpf_duration_ns.is_some() != bpf_enabled
            || self.filesystem_duration_ns.is_some() != filesystem_enabled
            || self.linux_duration_ns.is_some() != linux_enabled
        {
            bail!("endpoint timing presence differs from the enabled confirmation domains");
        }
        if self
            .bpf_duration_ns
            .into_iter()
            .chain(self.filesystem_duration_ns)
            .chain(self.linux_duration_ns)
            .any(|duration| duration > MAX_DIAGNOSTIC_DURATION_NS)
        {
            bail!("endpoint timing exceeds its diagnostic shape bound");
        }
        if self.total_duration_ns
            != checked_optional_duration_sum([
                self.bpf_duration_ns,
                self.filesystem_duration_ns,
                self.linux_duration_ns,
            ])?
            || self.total_duration_ns > MAX_DIAGNOSTIC_DURATION_NS
        {
            bail!("endpoint timing total does not recompute within bounds");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ClosingDrainTelemetry {
    pub total_duration_ns: u64,
    /// Includes the exact asynchronous TCP producer detach plus every
    /// per-root system-effect drain and owner retirement.
    pub system_effects_duration_ns: u64,
    pub process_lifecycle_duration_ns: u64,
}

impl ClosingDrainTelemetry {
    pub fn new(
        system_effects_duration_ns: u64,
        process_lifecycle_duration_ns: u64,
    ) -> Result<Self> {
        let total_duration_ns = system_effects_duration_ns
            .checked_add(process_lifecycle_duration_ns)
            .context("closing-drain diagnostic duration overflow")?;
        let telemetry = Self {
            total_duration_ns,
            system_effects_duration_ns,
            process_lifecycle_duration_ns,
        };
        telemetry.validate()?;
        Ok(telemetry)
    }

    fn validate(&self) -> Result<()> {
        if self.system_effects_duration_ns > MAX_DIAGNOSTIC_DURATION_NS
            || self.process_lifecycle_duration_ns > MAX_DIAGNOSTIC_DURATION_NS
            || self.total_duration_ns > MAX_DIAGNOSTIC_DURATION_NS
            || self.total_duration_ns
                != self
                    .system_effects_duration_ns
                    .checked_add(self.process_lifecycle_duration_ns)
                    .context("closing-drain diagnostic duration overflow")?
        {
            bail!("closing-drain timing does not recompute within bounds");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiagnosticPerformanceTelemetry {
    pub purpose: String,
    pub clock: String,
    pub trusted_evidence: bool,
    pub affects_verdict: bool,
    pub s0_endpoint_capture: EndpointCaptureTelemetry,
    pub closing_drain: ClosingDrainTelemetry,
    pub s1_endpoint_capture: EndpointCaptureTelemetry,
}

impl DiagnosticPerformanceTelemetry {
    pub fn new(
        s0_endpoint_capture: EndpointCaptureTelemetry,
        closing_drain: ClosingDrainTelemetry,
        s1_endpoint_capture: EndpointCaptureTelemetry,
    ) -> Self {
        Self {
            purpose: DIAGNOSTIC_TELEMETRY_PURPOSE.to_owned(),
            clock: DIAGNOSTIC_MONOTONIC_CLOCK.to_owned(),
            trusted_evidence: false,
            affects_verdict: false,
            s0_endpoint_capture,
            closing_drain,
            s1_endpoint_capture,
        }
    }

    pub fn validate(
        &self,
        bpf_enabled: bool,
        filesystem_enabled: bool,
        linux_enabled: bool,
    ) -> Result<()> {
        if self.purpose != DIAGNOSTIC_TELEMETRY_PURPOSE
            || self.clock != DIAGNOSTIC_MONOTONIC_CLOCK
            || self.trusted_evidence
            || self.affects_verdict
        {
            bail!("diagnostic performance telemetry has an invalid trust/clock contract");
        }
        self.s0_endpoint_capture
            .validate(bpf_enabled, filesystem_enabled, linux_enabled)?;
        self.closing_drain.validate()?;
        self.s1_endpoint_capture
            .validate(bpf_enabled, filesystem_enabled, linux_enabled)
    }
}

fn checked_optional_duration_sum(values: [Option<u64>; 3]) -> Result<u64> {
    values
        .into_iter()
        .flatten()
        .try_fold(0_u64, |total, value| {
            total
                .checked_add(value)
                .context("endpoint diagnostic duration overflow")
        })
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregateTransportStatus {
    Complete,
    Incomplete,
    UnprovenNoEvents,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AggregateEvidenceStatus {
    Complete,
    Incomplete,
    UnprovenNoEvents,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WholeTreeCoverageStatus {
    /// Every selected hook uses `bpf_current_task_under_cgroup` against a
    /// bounded, FD-pinned cgroup-v2 root.  Descendants therefore remain in
    /// scope even when they are created and removed entirely between the
    /// userspace READY and FINISH barriers.
    DynamicAncestorComplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupRecorderOutcome {
    pub cgroup_id: u64,
    pub health: Option<SystemEffectHealth>,
    pub finalization_error: Option<String>,
    pub unregistered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupLifecycleOutcome {
    pub cgroup_id: u64,
    pub health: Option<ProcessLifecycleHealth>,
    pub finalization_error: Option<String>,
    pub unregistered: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateHealthArtifact {
    pub schema_version: u32,
    pub cgroup_match_mode: CgroupMatchMode,
    pub runs: Vec<SocketStateHealth>,
}

impl SocketStateHealthArtifact {
    pub(crate) fn from_outcomes(
        run_id: &str,
        boot_id: &str,
        epoch: u64,
        expected_cgroup_ids: &[u64],
        outcomes: &[CgroupRecorderOutcome],
    ) -> Result<Self> {
        if outcomes.len() != expected_cgroup_ids.len()
            || outcomes
                .iter()
                .map(|outcome| outcome.cgroup_id)
                .ne(expected_cgroup_ids.iter().copied())
        {
            bail!("socket-state outcomes do not exactly cover the registration plan");
        }
        let runs = outcomes
            .iter()
            .map(|outcome| {
                let health = outcome
                    .health
                    .as_ref()
                    .context("socket-state outcome has no finalized system health")?
                    .socket_state
                    .as_ref()
                    .context("expanded object mode has no socket-state health")?;
                if health.run_id != run_id
                    || health.boot_id != boot_id
                    || health.run_epoch != epoch
                    || health.cgroup_id != outcome.cgroup_id
                    || health.cgroup_match_mode != CgroupMatchMode::AncestorRoot
                {
                    bail!("socket-state health is not bound to the deployment run");
                }
                Ok(health.clone())
            })
            .collect::<Result<Vec<_>>>()?;
        let artifact = Self {
            schema_version: SOCKET_STATE_SCHEMA_VERSION,
            cgroup_match_mode: CgroupMatchMode::AncestorRoot,
            runs,
        };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != SOCKET_STATE_SCHEMA_VERSION
            || self.cgroup_match_mode != CgroupMatchMode::AncestorRoot
            || self.runs.is_empty()
            || !self
                .runs
                .windows(2)
                .all(|pair| pair[0].cgroup_id < pair[1].cgroup_id)
            || self.runs.iter().any(|health| {
                health.schema_version != SOCKET_STATE_SCHEMA_VERSION
                    || health.cgroup_match_mode != CgroupMatchMode::AncestorRoot
            })
        {
            bail!("deployment socket-state health artifact is noncanonical");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SocketStateReport {
    pub protocol_version: u32,
    pub cgroup_match_mode: CgroupMatchMode,
    pub wal_artifact: String,
    pub jsonl_artifact: String,
    pub health_artifact: String,
    pub health_sha256: String,
    pub status: SocketStateStatus,
    pub root_count: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub destroy_events_persisted: u64,
    pub owners_retired_at_barrier: u64,
    pub async_producer_seal: SocketStateProducerSeal,
    pub causal_attribution_established: bool,
}

impl SocketStateReport {
    pub(crate) fn from_health(
        health: &SocketStateHealthArtifact,
        health_sha256: String,
    ) -> Result<Self> {
        health.validate()?;
        let async_producer_seal = health
            .runs
            .first()
            .context("deployment socket-state health has no runs")?
            .async_producer_seal;
        let mut report = Self {
            protocol_version: SOCKET_STATE_SCHEMA_VERSION,
            cgroup_match_mode: CgroupMatchMode::AncestorRoot,
            wal_artifact: SOCKET_STATE_WAL_NAME.to_owned(),
            jsonl_artifact: SOCKET_STATE_JSONL_NAME.to_owned(),
            health_artifact: SOCKET_STATE_HEALTH_NAME.to_owned(),
            health_sha256,
            status: SocketStateStatus::Complete,
            root_count: health.runs.len() as u64,
            event_published: 0,
            event_dropped: 0,
            destroy_events_persisted: 0,
            owners_retired_at_barrier: 0,
            async_producer_seal,
            causal_attribution_established: false,
        };
        for run in &health.runs {
            if run.async_producer_seal != report.async_producer_seal {
                bail!("deployment roots disagree on the recorder-global async producer seal");
            }
            report.event_published = checked_sum(
                report.event_published,
                run.event_published,
                "socket-state event_published",
            )?;
            report.event_dropped = checked_sum(
                report.event_dropped,
                run.event_dropped,
                "socket-state event_dropped",
            )?;
            report.destroy_events_persisted = checked_sum(
                report.destroy_events_persisted,
                run.destroy_events_persisted,
                "socket-state destroy events",
            )?;
            report.owners_retired_at_barrier = checked_sum(
                report.owners_retired_at_barrier,
                run.owners_retired_at_barrier,
                "socket-state retired owners",
            )?;
            if run.status != SocketStateStatus::Complete {
                report.status = SocketStateStatus::Incomplete;
            }
        }
        report.validate()?;
        Ok(report)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != SOCKET_STATE_SCHEMA_VERSION
            || self.cgroup_match_mode != CgroupMatchMode::AncestorRoot
            || self.wal_artifact != SOCKET_STATE_WAL_NAME
            || self.jsonl_artifact != SOCKET_STATE_JSONL_NAME
            || self.health_artifact != SOCKET_STATE_HEALTH_NAME
            || self.root_count == 0
            || !self.async_producer_seal.has_required_shape()
            || (self.status == SocketStateStatus::Complete
                && !self.async_producer_seal.is_required_complete())
            || self.causal_attribution_established
        {
            bail!("deployment socket-state report has an invalid contract");
        }
        validate_sha256(&self.health_sha256, "socket-state health")
    }
}

fn checked_sum(left: u64, right: u64, label: &str) -> Result<u64> {
    left.checked_add(right)
        .with_context(|| format!("{label} counter overflow"))
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateLifecycleHealth {
    pub scope_root_count: u64,
    pub finalized_cgroup_count: u64,
    pub unregistered_cgroup_count: u64,
    pub complete_cgroup_count: u64,
    pub partial_cgroup_count: u64,
    pub unproven_no_event_cgroup_count: u64,
    pub incomplete_cgroup_count: u64,
    pub root_scope_status: ProcessLifecycleStatus,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub task_read_failed: u64,
    pub exec_path_read_failed: u64,
    pub exec_path_truncated: u64,
    pub poll_calls: u64,
    pub maximum_events_per_poll: u64,
    pub callback_queue_high_water: u64,
    pub reasons: Vec<String>,
}

pub fn aggregate_lifecycle_health(
    expected_cgroup_ids: &[u64],
    outcomes: &[CgroupLifecycleOutcome],
) -> Result<AggregateLifecycleHealth> {
    if expected_cgroup_ids.is_empty()
        || !expected_cgroup_ids.windows(2).all(|pair| pair[0] < pair[1])
        || outcomes.len() != expected_cgroup_ids.len()
        || outcomes
            .iter()
            .map(|outcome| outcome.cgroup_id)
            .ne(expected_cgroup_ids.iter().copied())
    {
        bail!("lifecycle outcomes do not exactly cover the registration plan");
    }
    let mut result = AggregateLifecycleHealth {
        scope_root_count: expected_cgroup_ids.len() as u64,
        finalized_cgroup_count: 0,
        unregistered_cgroup_count: 0,
        complete_cgroup_count: 0,
        partial_cgroup_count: 0,
        unproven_no_event_cgroup_count: 0,
        incomplete_cgroup_count: 0,
        root_scope_status: ProcessLifecycleStatus::Incomplete,
        event_attempted: 0,
        event_published: 0,
        event_dropped: 0,
        events_persisted: 0,
        task_read_failed: 0,
        exec_path_read_failed: 0,
        exec_path_truncated: 0,
        poll_calls: 0,
        maximum_events_per_poll: 0,
        callback_queue_high_water: 0,
        reasons: Vec::new(),
    };
    let mut reasons = BTreeSet::new();
    for outcome in outcomes {
        if outcome.unregistered {
            result.unregistered_cgroup_count += 1;
        }
        let outcome_failed = outcome.finalization_error.is_some();
        if let Some(error) = &outcome.finalization_error {
            reasons.insert(format!(
                "cgroup {} lifecycle finalization failed: {error}",
                outcome.cgroup_id
            ));
        }
        let Some(health) = &outcome.health else {
            result.incomplete_cgroup_count += 1;
            continue;
        };
        if health.cgroup_id != outcome.cgroup_id {
            bail!("lifecycle health is bound to a different cgroup ID");
        }
        health
            .validate_partial_enrollment_contract()
            .with_context(|| {
                format!(
                    "cgroup {} lifecycle health violates the partial-enrollment contract",
                    outcome.cgroup_id
                )
            })?;
        result.finalized_cgroup_count += 1;
        match (outcome_failed, health.status) {
            (true, _) => result.incomplete_cgroup_count += 1,
            (false, ProcessLifecycleStatus::Complete) => {
                result.incomplete_cgroup_count += 1;
                reasons.insert(format!(
                    "cgroup {} lifecycle health overclaims unsupported complete enrollment",
                    outcome.cgroup_id
                ));
            }
            (false, ProcessLifecycleStatus::Partial) => result.partial_cgroup_count += 1,
            (false, ProcessLifecycleStatus::UnprovenNoEvents) => {
                result.unproven_no_event_cgroup_count += 1
            }
            (false, ProcessLifecycleStatus::Incomplete) => result.incomplete_cgroup_count += 1,
        }
        checked_add(
            &mut result.event_attempted,
            health.event_attempted,
            "lifecycle event_attempted",
        )?;
        checked_add(
            &mut result.event_published,
            health.event_published,
            "lifecycle event_published",
        )?;
        checked_add(
            &mut result.event_dropped,
            health.event_dropped,
            "lifecycle event_dropped",
        )?;
        checked_add(
            &mut result.events_persisted,
            health.events_persisted,
            "lifecycle events_persisted",
        )?;
        checked_add(
            &mut result.task_read_failed,
            health.task_read_failed,
            "lifecycle task_read_failed",
        )?;
        checked_add(
            &mut result.exec_path_read_failed,
            health.exec_path_read_failed,
            "lifecycle exec_path_read_failed",
        )?;
        checked_add(
            &mut result.exec_path_truncated,
            health.exec_path_truncated,
            "lifecycle exec_path_truncated",
        )?;
        result.poll_calls = result.poll_calls.max(health.poll_calls);
        result.maximum_events_per_poll = result
            .maximum_events_per_poll
            .max(health.maximum_events_per_poll);
        result.callback_queue_high_water = result
            .callback_queue_high_water
            .max(health.callback_queue_high_water);
    }
    let all_finalized = result.finalized_cgroup_count == result.scope_root_count;
    let all_unregistered = result.unregistered_cgroup_count == result.scope_root_count;
    result.root_scope_status =
        if result.incomplete_cgroup_count != 0 || !all_finalized || !all_unregistered {
            ProcessLifecycleStatus::Incomplete
        } else if result.partial_cgroup_count != 0 {
            ProcessLifecycleStatus::Partial
        } else if result.complete_cgroup_count != 0 {
            ProcessLifecycleStatus::Complete
        } else {
            ProcessLifecycleStatus::UnprovenNoEvents
        };
    if !all_unregistered {
        reasons.insert("not every lifecycle cgroup registration was removed".to_owned());
    }
    result.reasons = reasons.into_iter().collect();
    Ok(result)
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AggregateHealth {
    pub scope_root_count: u64,
    pub finalized_cgroup_count: u64,
    pub unregistered_cgroup_count: u64,
    pub complete_cgroup_count: u64,
    pub unproven_no_event_cgroup_count: u64,
    pub incomplete_cgroup_count: u64,
    pub transport_status: AggregateTransportStatus,
    pub evidence_status: AggregateEvidenceStatus,
    pub operation_attempted: u64,
    pub operation_completed: u64,
    pub event_attempted: u64,
    pub event_published: u64,
    pub event_dropped: u64,
    pub events_persisted: u64,
    pub task_read_failed: u64,
    pub poll_calls: u64,
    pub maximum_events_per_poll: u64,
    pub callback_queue_high_water: u64,
    pub whole_tree_coverage_status: WholeTreeCoverageStatus,
    pub roots_frozen_at_finish: bool,
    pub deployment_identity_stable_at_finish: bool,
    pub root_scope_identity_stable_at_barriers: bool,
    pub reasons: Vec<String>,
}

pub fn aggregate_health(
    expected_cgroup_ids: &[u64],
    outcomes: &[CgroupRecorderOutcome],
    roots_frozen_at_finish: bool,
    deployment_identity_stable_at_finish: bool,
) -> Result<AggregateHealth> {
    if expected_cgroup_ids.is_empty()
        || !expected_cgroup_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        bail!("expected recorder cgroup IDs must be canonical sorted and unique");
    }
    if outcomes.len() != expected_cgroup_ids.len()
        || !outcomes
            .windows(2)
            .all(|pair| pair[0].cgroup_id < pair[1].cgroup_id)
        || outcomes
            .iter()
            .map(|outcome| outcome.cgroup_id)
            .ne(expected_cgroup_ids.iter().copied())
    {
        bail!("recorder outcomes do not exactly cover the registration plan");
    }

    let mut result = AggregateHealth {
        scope_root_count: expected_cgroup_ids.len() as u64,
        finalized_cgroup_count: 0,
        unregistered_cgroup_count: 0,
        complete_cgroup_count: 0,
        unproven_no_event_cgroup_count: 0,
        incomplete_cgroup_count: 0,
        transport_status: AggregateTransportStatus::Incomplete,
        evidence_status: AggregateEvidenceStatus::Incomplete,
        operation_attempted: 0,
        operation_completed: 0,
        event_attempted: 0,
        event_published: 0,
        event_dropped: 0,
        events_persisted: 0,
        task_read_failed: 0,
        poll_calls: 0,
        maximum_events_per_poll: 0,
        callback_queue_high_water: 0,
        whole_tree_coverage_status: WholeTreeCoverageStatus::DynamicAncestorComplete,
        roots_frozen_at_finish,
        deployment_identity_stable_at_finish,
        root_scope_identity_stable_at_barriers: deployment_identity_stable_at_finish,
        reasons: Vec::new(),
    };
    let mut reasons = BTreeSet::new();
    if !roots_frozen_at_finish {
        reasons.insert("caller-owned cgroup root freeze barrier was not established".to_owned());
    }
    if !deployment_identity_stable_at_finish {
        reasons.insert(
            "deployment closure revalidation found an added, removed, or replaced identity"
                .to_owned(),
        );
    }

    for outcome in outcomes {
        if outcome.unregistered {
            result.unregistered_cgroup_count += 1;
        }
        let outcome_failed = outcome.finalization_error.is_some();
        if let Some(error) = &outcome.finalization_error {
            reasons.insert(format!(
                "cgroup {} recorder finalization failed: {error}",
                outcome.cgroup_id
            ));
        }
        let Some(health) = &outcome.health else {
            result.incomplete_cgroup_count += 1;
            if !outcome_failed {
                reasons.insert(format!(
                    "cgroup {} has no recorder health result",
                    outcome.cgroup_id
                ));
            }
            continue;
        };
        if health.cgroup_id != outcome.cgroup_id {
            bail!("per-cgroup health is bound to a different cgroup ID");
        }
        result.finalized_cgroup_count += 1;
        match (outcome_failed, health.transport_status) {
            (true, _) => result.incomplete_cgroup_count += 1,
            (false, TransportStatus::Complete) => result.complete_cgroup_count += 1,
            (false, TransportStatus::UnprovenNoEvents) => {
                result.unproven_no_event_cgroup_count += 1
            }
            (false, TransportStatus::Incomplete) => result.incomplete_cgroup_count += 1,
        }
        checked_add(
            &mut result.operation_attempted,
            health.operation_attempted,
            "operation_attempted",
        )?;
        checked_add(
            &mut result.operation_completed,
            health.operation_completed,
            "operation_completed",
        )?;
        checked_add(
            &mut result.event_attempted,
            health.event_attempted,
            "event_attempted",
        )?;
        checked_add(
            &mut result.event_published,
            health.event_published,
            "event_published",
        )?;
        checked_add(
            &mut result.event_dropped,
            health.event_dropped,
            "event_dropped",
        )?;
        checked_add(
            &mut result.events_persisted,
            health.events_persisted,
            "events_persisted",
        )?;
        checked_add(
            &mut result.task_read_failed,
            health.task_read_failed,
            "task_read_failed",
        )?;
        result.poll_calls = result.poll_calls.max(health.poll_calls);
        result.maximum_events_per_poll = result
            .maximum_events_per_poll
            .max(health.maximum_events_per_poll);
        result.callback_queue_high_water = result
            .callback_queue_high_water
            .max(health.callback_queue_high_water);
    }

    let all_finalized = result.finalized_cgroup_count == result.scope_root_count;
    let all_unregistered = result.unregistered_cgroup_count == result.scope_root_count;
    result.transport_status = if result.incomplete_cgroup_count != 0 || !all_finalized {
        AggregateTransportStatus::Incomplete
    } else if result.complete_cgroup_count != 0 {
        // A single recorder/ring transports all exact-cgroup events. Quiet
        // registered cgroups retain their explicit UNPROVEN_NO_EVENTS result,
        // while successful traffic in another cgroup proves this shared
        // transport was live.
        AggregateTransportStatus::Complete
    } else {
        AggregateTransportStatus::UnprovenNoEvents
    };
    if !all_unregistered {
        reasons.insert("not every exact cgroup registration was cleanly removed".to_owned());
    }
    if result.unproven_no_event_cgroup_count != 0 {
        reasons.insert(format!(
            "{} exact cgroup(s) exercised no selected operation",
            result.unproven_no_event_cgroup_count
        ));
    }
    result.evidence_status = if result.incomplete_cgroup_count != 0
        || !all_finalized
        || !all_unregistered
        || !roots_frozen_at_finish
        || !deployment_identity_stable_at_finish
    {
        AggregateEvidenceStatus::Incomplete
    } else if result.complete_cgroup_count != 0 {
        AggregateEvidenceStatus::Complete
    } else {
        AggregateEvidenceStatus::UnprovenNoEvents
    };
    result.reasons = reasons.into_iter().collect();
    Ok(result)
}

fn checked_add(target: &mut u64, value: u64, label: &str) -> Result<()> {
    *target = target
        .checked_add(value)
        .with_context(|| format!("aggregate {label} counter overflow"))?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentObservationReport {
    pub protocol_version: u32,
    pub run_id: String,
    pub epoch: u64,
    pub deployment: DeploymentManifest,
    pub recorder_object_sha256: String,
    pub lifecycle_object_sha256: String,
    pub recorder_policy_sha256: String,
    pub registration_cgroup_ids: Vec<u64>,
    pub cgroup_scope_capability_sha256: String,
    pub cgroup_scope_capability: crate::CgroupScopeCapability,
    pub ready_barrier: RootFreezeBarrier,
    pub ready_validation: LiveIdentityValidation,
    pub pre_finish_barrier: RootFreezeBarrier,
    pub pre_finish_validation: IdentityAssessment,
    pub closure_barrier: RootFreezeBarrier,
    pub closure_validation: IdentityAssessment,
    pub cgroup_outcomes: Vec<CgroupRecorderOutcome>,
    pub aggregate_health: AggregateHealth,
    pub lifecycle_outcomes: Vec<CgroupLifecycleOutcome>,
    pub aggregate_lifecycle_health: AggregateLifecycleHealth,
    /// Conservative aggregate over every enabled evidence domain. This is not
    /// an attribution verdict: one incomplete configured domain makes the
    /// aggregate incomplete, and endpoint confirmation never upgrades an
    /// unproven operation stream.
    pub overall_evidence_status: AggregateEvidenceStatus,
    pub socket_state: Option<SocketStateReport>,
    pub bpf_state: Option<BpfStateReport>,
    pub filesystem_state: Option<FilesystemStateReport>,
    pub linux_state: Option<LinuxStateReport>,
    /// Process-local monotonic timings are diagnostics only. They are never
    /// inputs to evidence completeness, attribution, or state verdicts.
    pub diagnostic_performance: DiagnosticPerformanceTelemetry,
    pub kata_guest_entered: bool,
    pub observation_boundary: String,
}

impl DeploymentObservationReport {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != DEPLOYMENT_OBSERVER_PROTOCOL_VERSION
            || self.run_id.is_empty()
            || self.epoch == 0
        {
            bail!("deployment observation report header is invalid");
        }
        self.deployment.validate()?;
        validate_sha256(&self.recorder_object_sha256, "recorder object")?;
        validate_sha256(&self.lifecycle_object_sha256, "lifecycle object")?;
        validate_sha256(&self.recorder_policy_sha256, "recorder policy")?;
        validate_sha256(
            &self.cgroup_scope_capability_sha256,
            "cgroup scope capability",
        )?;
        self.cgroup_scope_capability.validate()?;
        if self.kata_guest_entered || self.deployment.coverage.kata_guest_entered {
            bail!("deployment observer report cannot claim entry into a Kata guest");
        }
        let mut expected_ids = self.deployment.registration_root_cgroup_ids();
        expected_ids.sort_unstable();
        expected_ids.dedup();
        if self.registration_cgroup_ids != expected_ids {
            bail!("report root-scope registration IDs differ from the deployment manifest");
        }
        if self.cgroup_scope_capability.root_cgroup_ids != self.registration_cgroup_ids
            || self.cgroup_scope_capability.sha256()? != self.cgroup_scope_capability_sha256
        {
            bail!("report cgroup-scope capability is not bound to its root registrations");
        }
        if self.ready_validation.scope_sha256 != self.deployment.scope_sha256 {
            bail!("report revalidation scope does not match the deployment manifest");
        }
        if self.ready_validation.protocol_version != DEPLOYMENT_PROTOCOL_VERSION
            || self.ready_validation.phase != RevalidationPhase::Ready
            || !self.ready_validation.is_stable()
        {
            bail!("report does not contain a stable READY identity validation");
        }
        validate_barrier(&self.ready_barrier, &self.deployment, true)?;
        validate_barrier(&self.pre_finish_barrier, &self.deployment, false)?;
        validate_barrier(&self.closure_barrier, &self.deployment, false)?;
        self.pre_finish_validation
            .validate_scope(&self.deployment.scope_sha256)?;
        self.closure_validation
            .validate_scope(&self.deployment.scope_sha256)?;
        if self.observation_boundary
            != "TARGET_LINUX_HOST_DIRECT_SYSCALLS_AND_DYNAMIC_CGROUP_ROOT_SUBTREES"
            || self.aggregate_health.whole_tree_coverage_status
                != WholeTreeCoverageStatus::DynamicAncestorComplete
        {
            bail!("report ambiguously describes its dynamic ancestor observation boundary");
        }
        let rebuilt_effects = aggregate_health(
            &self.registration_cgroup_ids,
            &self.cgroup_outcomes,
            self.pre_finish_barrier.all_roots_frozen && self.closure_barrier.all_roots_frozen,
            self.pre_finish_validation.stable && self.closure_validation.stable,
        )?;
        if rebuilt_effects != self.aggregate_health {
            bail!("report aggregate effects health does not recompute");
        }
        let rebuilt_lifecycle =
            aggregate_lifecycle_health(&self.registration_cgroup_ids, &self.lifecycle_outcomes)?;
        if rebuilt_lifecycle != self.aggregate_lifecycle_health {
            bail!("report aggregate lifecycle health does not recompute");
        }
        if overall_evidence_status(self) != self.overall_evidence_status {
            bail!("report overall evidence status does not recompute from its domain vector");
        }
        self.diagnostic_performance.validate(
            self.bpf_state.is_some(),
            self.filesystem_state.is_some(),
            self.linux_state.is_some(),
        )?;
        if let Some(linux_state) = &self.linux_state {
            linux_state.validate()?;
        }
        if let Some(bpf_state) = &self.bpf_state {
            bpf_state.validate()?;
        }
        if let Some(filesystem_state) = &self.filesystem_state {
            filesystem_state.validate()?;
        }
        match &self.socket_state {
            Some(socket_state) => {
                socket_state.validate()?;
                let health = SocketStateHealthArtifact::from_outcomes(
                    &self.run_id,
                    &self.deployment.boot_id,
                    self.epoch,
                    &self.registration_cgroup_ids,
                    &self.cgroup_outcomes,
                )?;
                let rebuilt =
                    SocketStateReport::from_health(&health, socket_state.health_sha256.clone())?;
                if &rebuilt != socket_state {
                    bail!("socket-state aggregate report does not recompute");
                }
            }
            None if self.cgroup_outcomes.iter().any(|outcome| {
                outcome
                    .health
                    .as_ref()
                    .and_then(|health| health.socket_state.as_ref())
                    .is_some()
            }) =>
            {
                bail!("socket-state health is present without an aggregate report")
            }
            None => {}
        }
        let mut profile = None;
        let mut object_resolution_mode = None;
        for outcome in &self.cgroup_outcomes {
            if let Some(health) = &outcome.health {
                if health.run_id != self.run_id
                    || health.run_epoch != self.epoch
                    || health.cgroup_id != outcome.cgroup_id
                {
                    bail!("effects health is not bound to the report run");
                }
                match profile {
                    Some(existing) if existing != health.profile => {
                        bail!("effects health contains multiple policy profiles")
                    }
                    None => profile = Some(health.profile),
                    _ => {}
                }
                match object_resolution_mode {
                    Some(existing) if existing != health.object_resolution_mode => {
                        bail!("effects health contains multiple object-resolution modes")
                    }
                    None => object_resolution_mode = Some(health.object_resolution_mode),
                    _ => {}
                }
            }
        }
        if let Some(profile) = profile {
            if self.recorder_policy_sha256 != policy_sha256(profile)? {
                bail!("report recorder policy SHA-256 does not match its health profile");
            }
        }
        for outcome in &self.lifecycle_outcomes {
            if let Some(health) = &outcome.health {
                if health.run_id != self.run_id
                    || health.run_epoch != self.epoch
                    || health.cgroup_id != outcome.cgroup_id
                {
                    bail!("lifecycle health is not bound to the report run");
                }
            }
        }
        Ok(())
    }
}

/// Compute the conservative run-level evidence status without collapsing the
/// per-domain vector carried by the report. Deployment always enables
/// process-lifecycle schema v2, whose missing S0/cgroup-entry enrollment proof
/// caps the run-level result below `COMPLETE`; collector-specific transport and
/// endpoint statuses remain independently useful.
pub fn overall_evidence_status(report: &DeploymentObservationReport) -> AggregateEvidenceStatus {
    let mut components = vec![report.aggregate_health.evidence_status];
    if report.deployment.deployment_kind == bpf_observer_deployment::DeploymentKind::KataHost
        && !report
            .deployment
            .coverage
            .kata_host_backend_namespace_pinned
    {
        components.push(AggregateEvidenceStatus::Incomplete);
    }
    components.push(match report.aggregate_lifecycle_health.root_scope_status {
        // Schema v2 has no S0 task/thread ledger or cgroup-entry stream.  A
        // forged/legacy COMPLETE lifecycle value must not lift the run-level
        // result to COMPLETE.
        ProcessLifecycleStatus::Complete => AggregateEvidenceStatus::Incomplete,
        ProcessLifecycleStatus::UnprovenNoEvents => AggregateEvidenceStatus::UnprovenNoEvents,
        ProcessLifecycleStatus::Incomplete | ProcessLifecycleStatus::Partial => {
            AggregateEvidenceStatus::Incomplete
        }
    });
    if let Some(state) = &report.socket_state {
        components.push(if state.status == SocketStateStatus::Complete {
            AggregateEvidenceStatus::Complete
        } else {
            AggregateEvidenceStatus::Incomplete
        });
    }
    if let Some(state) = &report.bpf_state {
        components.push(
            if state.contract_complete
                && state.state_completeness == BpfCompletenessStatus::Complete
                && state.evidence_status == BpfCompletenessStatus::Complete
            {
                AggregateEvidenceStatus::Complete
            } else {
                AggregateEvidenceStatus::Incomplete
            },
        );
    }
    if let Some(state) = &report.filesystem_state {
        components.push(
            if state.contract_complete
                && state.state_completeness == FilesystemCompletenessStatus::Complete
            {
                AggregateEvidenceStatus::Complete
            } else {
                AggregateEvidenceStatus::Incomplete
            },
        );
    }
    if let Some(state) = &report.linux_state {
        components.push(
            if state.evidence_status == LinuxStateEvidenceStatus::Complete {
                AggregateEvidenceStatus::Complete
            } else {
                AggregateEvidenceStatus::Incomplete
            },
        );
    }
    collapse_overall_evidence_status(&components)
}

pub(crate) fn collapse_overall_evidence_status(
    components: &[AggregateEvidenceStatus],
) -> AggregateEvidenceStatus {
    if components.contains(&AggregateEvidenceStatus::Incomplete) {
        AggregateEvidenceStatus::Incomplete
    } else if components.contains(&AggregateEvidenceStatus::UnprovenNoEvents) {
        AggregateEvidenceStatus::UnprovenNoEvents
    } else {
        AggregateEvidenceStatus::Complete
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityAssessment {
    pub stable: bool,
    pub validation: Option<LiveIdentityValidation>,
    pub error: Option<String>,
}

impl IdentityAssessment {
    pub fn from_result(result: Result<LiveIdentityValidation>) -> Self {
        match result {
            Ok(validation) => Self {
                stable: validation.is_stable(),
                validation: Some(validation),
                error: None,
            },
            Err(error) => Self {
                stable: false,
                validation: None,
                error: Some(format!("{error:#}")),
            },
        }
    }

    fn validate_scope(&self, expected_scope: &str) -> Result<()> {
        match (&self.validation, &self.error) {
            (Some(validation), None) => {
                if validation.scope_sha256 != expected_scope
                    || self.stable != validation.is_stable()
                    || validation.protocol_version != DEPLOYMENT_PROTOCOL_VERSION
                    || validation.phase != RevalidationPhase::Closure
                {
                    bail!("identity assessment disagrees with its validation report");
                }
            }
            (None, Some(error)) if !self.stable && !error.is_empty() => {}
            _ => bail!("identity assessment has an invalid success/error shape"),
        }
        Ok(())
    }
}

fn validate_barrier(
    barrier: &RootFreezeBarrier,
    deployment: &DeploymentManifest,
    require_complete: bool,
) -> Result<()> {
    if barrier.checked_unix_ns == 0
        || barrier.method != "CGROUP_V2_ROOT_SUBTREE_FREEZE"
        || barrier.roots.len() != deployment.root_cgroups.len()
    {
        bail!("cgroup freeze barrier envelope is invalid");
    }
    for (observed, expected) in barrier.roots.iter().zip(&deployment.root_cgroups) {
        if observed.path != expected.path || observed.expected_cgroup_id != expected.cgroup_id {
            bail!("cgroup freeze barrier is bound to a different root identity");
        }
        let recomputed = observed.observed_cgroup_id == Some(observed.expected_cgroup_id)
            && observed.freeze_requested == Some(true)
            && observed.frozen == Some(true);
        if observed.verified != recomputed
            || (observed.verified && observed.error.is_some())
            || (!observed.verified && observed.error.as_deref().unwrap_or("").is_empty())
        {
            bail!("cgroup freeze barrier root result is internally inconsistent");
        }
    }
    if barrier.all_roots_frozen != barrier.roots.iter().all(|root| root.verified)
        || (require_complete && !barrier.all_roots_frozen)
    {
        bail!("cgroup freeze barrier aggregate result is inconsistent");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} SHA-256 is not canonical lowercase hexadecimal");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDigest {
    pub relative_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

pub(crate) fn checked_artifact_total_bytes(artifacts: &[ArtifactDigest]) -> Result<u64> {
    artifacts.iter().try_fold(0_u64, |total, artifact| {
        total
            .checked_add(artifact.size_bytes)
            .context("committed artifact byte total overflow")
    })
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub protocol_version: u32,
    pub run_id: String,
    pub epoch: u64,
    pub deployment_scope_sha256: String,
    pub cgroup_scope_capability_sha256: String,
    /// Overall status recomputed from every enabled evidence domain. Recorder-
    /// only status remains in `DeploymentObservationReport.aggregate_health`.
    pub evidence_status: AggregateEvidenceStatus,
    pub socket_state_status: Option<SocketStateStatus>,
    pub bpf_state_scope_sha256: Option<String>,
    pub bpf_state_verdict: Option<BpfStateVerdict>,
    pub filesystem_state_scope_sha256: Option<String>,
    pub filesystem_state_verdict: Option<FilesystemVerdict>,
    pub linux_state_scope_sha256: Option<String>,
    pub linux_state_evidence_status: Option<LinuxStateEvidenceStatus>,
    /// Repeated from the report for convenient benchmark collection. It is
    /// diagnostic-only and is never an input to any verdict.
    pub diagnostic_performance: DiagnosticPerformanceTelemetry,
    /// Checked sum of every digest entry below. The manifest itself is not a
    /// committed artifact because a self-digest would be circular.
    pub committed_artifact_total_bytes: u64,
    pub artifacts: Vec<ArtifactDigest>,
}
