// SPDX-License-Identifier: GPL-2.0-only

//! One-shot, cooperative deployment observation for direct, Docker, and
//! Kata-host workloads.
//!
//! The caller freezes the committed cgroup-v2 roots before starting this
//! process, waits for the `READY` line, resumes the workload, freezes the same
//! roots again, and sends exactly one `FINISH` line. The observer never enters
//! a container or Kata guest and never mutates the target cgroups.

mod barrier;
mod endpoint_state;
mod linux_state;
mod protocol;
mod report;
mod scope;
mod session;
mod verify;

pub use barrier::{verify_frozen_roots, RootFreezeBarrier, RootFreezeIdentity};
pub use endpoint_state::{BpfStateReport, FilesystemStateReport};
pub use linux_state::{
    LinuxStateDomainSummary, LinuxStateDomainVector, LinuxStateEvidenceStatus, LinuxStateReport,
};
pub use protocol::{
    FinishCommand, ProtocolMachine, ProtocolState, ReadyMessage, TerminalMessage,
    DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
};
pub use report::{
    aggregate_health, aggregate_lifecycle_health, overall_evidence_status, AggregateEvidenceStatus,
    AggregateHealth, AggregateLifecycleHealth, AggregateTransportStatus, ArtifactDigest,
    ArtifactManifest, CgroupLifecycleOutcome, CgroupRecorderOutcome, ClosingDrainTelemetry,
    DeploymentObservationReport, DiagnosticPerformanceTelemetry, EndpointCaptureTelemetry,
    IdentityAssessment, SocketStateHealthArtifact, SocketStateReport, WholeTreeCoverageStatus,
    DIAGNOSTIC_MONOTONIC_CLOCK, DIAGNOSTIC_TELEMETRY_PURPOSE,
};
pub use scope::{
    CgroupScopeCapability, CgroupScopeMode, EventCgroupIdSemantics, CGROUP_SCOPE_PROTOCOL_VERSION,
    MAX_ANCESTOR_ROOTS,
};
pub use session::{run_stdio, DeploymentObserverConfig, DeploymentSession, RegistrationPlan};
pub use verify::{verify_artifacts, OfflineVerification, VerificationExpectation};

#[cfg(test)]
mod tests;
