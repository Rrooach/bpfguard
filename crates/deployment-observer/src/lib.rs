// SPDX-License-Identifier: GPL-2.0-only

//! One-shot, cooperative deployment observation for direct, Docker, and
//! Kata-host workloads.
//!
//! Protocol v2 waits for one `FINISH` after a frozen READY boundary. Opt-in
//! protocol v3 captures A/B/C around an externally supplied recovery helper
//! and requires distinct Agent-start, pre-restore, and finish commands. The
//! observer never enters a container or Kata guest and never mutates the
//! target cgroups.

mod barrier;
mod endpoint_state;
mod linux_state;
mod protocol;
mod recovery;
mod recovery_abort;
mod recovery_report;
mod recovery_session;
mod recovery_verify;
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
    AgentStartedMessage, FinishCommand, ProtocolMachine, ProtocolState, ReadyMessage,
    RecoveryCommandKind, RecoveryControlCommand, RecoveryProtocolMachine, RecoveryProtocolState,
    RecoveryReadyMessage, RecoveryTerminalMessage, RestoreCompleteMessage, SnapshotBMessage,
    SnapshotCMessage, TerminalMessage, DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
    DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
};
pub use recovery::{
    execute as execute_recovery, CapturedOutputEvidence, ExecutableIdentity,
    ForbiddenCgroupIdentity, HelperCgroupIdentity, RecoveryConfig, RecoveryEnvironmentIdentity,
    RecoveryEvidence, RECOVERY_EVIDENCE_SCHEMA_VERSION,
};
pub use recovery_abort::{RecoveryAbortEvidence, RECOVERY_ABORT_FILE};
pub use recovery_report::{
    build_recovery_pair_delta, build_recovery_verdict_report,
    build_recovery_verdict_report_with_raw, RecoveryChangeKind, RecoveryComparisonSet,
    RecoveryComparisonTriplet, RecoveryConsistencyVerdict, RecoveryDomain, RecoveryDomainOutcome,
    RecoveryDomainVector, RecoveryEndpointStatus, RecoveryObjectClassifications, RecoveryObjectRef,
    RecoveryPairDelta, RecoveryPairKind, RecoveryRawSnapshotSet, RecoveryRawSnapshotTriplet,
    RecoveryRootCgroupBinding, RecoverySnapshotEnvelope, RecoverySnapshotPhase,
    RecoverySnapshotTriplet, RecoveryVerdictReport, SnapshotDomainBinding,
    RECOVERY_REPORT_SCHEMA_VERSION,
};
pub use recovery_session::run_recovery_stdio;
pub use recovery_verify::{
    verify_recovery_artifacts, RecoveryArtifactManifest, RecoveryControlTranscript,
    RecoveryOfflineVerification, RecoveryVerificationExpectation,
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
