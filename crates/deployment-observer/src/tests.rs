// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use bpf_observer_deployment::{
    CgroupIdentity, DeploymentCoverage, DeploymentKind, DeploymentManifest,
    DescendantObservationRequirement, DiscoverySourceTrust, IdentityStrength,
    LiveIdentityValidation, ProcessIdentity, ProcessRole, RevalidationPhase, ValidationMismatch,
    DEPLOYMENT_PROTOCOL_VERSION, DEPLOYMENT_SCOPE_DOMAIN,
};
use bpf_observer_linux_state_confirmers::{
    encode_absolute_path, CaptureLimits, CausalAttributionStatus, Completeness, CompletenessStatus,
    DomainComparison, DomainKind, EndpointDifferenceStatus, MountScope, NamespaceTarget,
    NetworkCollectors, NetworkScope, StateComparison, StateDomainComparisons, StateScope,
    StateVerdict, SysctlScope, TerminalState, ValueEvidenceMode, LINUX_STATE_CONFIRMATION_DOMAIN,
    LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
};
use bpf_observer_system_effects::lifecycle::{
    ProcessEnrollmentSummary, ProcessLifecycleHealth, ProcessLifecycleStatus,
    ProcessLineageSummary, PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION,
    PROCESS_LIFECYCLE_SCHEMA_VERSION,
};
use bpf_observer_system_effects::socket_state::{
    SocketStateHealth, SocketStateProducerSeal, SocketStateStatus,
    SOCKET_STATE_ASYNC_PRODUCER_LINKS, SOCKET_STATE_SCHEMA_VERSION,
};
use bpf_observer_system_effects::{
    CgroupMatchMode, CoverageStatus, FileObjectResolutionMode, ObjectResolutionStatus,
    PolicyProfile, SystemEffectHealth, TransportStatus, EFFECT_EVENT_SCHEMA_VERSION,
};
use std::path::Path;
use std::path::PathBuf;

const NONCE: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RECOVERY_NONCE_2: &str = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const RECOVERY_NONCE_3: &str = "2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn filesystem_namespace_mode_config(
    protocol_version: u32,
    filesystem_state_scope: bool,
    filesystem_namespace_mode: FilesystemNamespaceMode,
) -> DeploymentObserverConfig {
    DeploymentObserverConfig {
        protocol_version,
        deployment: bpf_observer_deployment::DeploymentRequest::Direct(
            bpf_observer_deployment::DirectRequest::new(1234),
        ),
        recorder_object_path: "/opt/observer/system_effects.bpf.o".to_owned(),
        recorder_object_sha256: "a".repeat(64),
        lifecycle_object_path: "/opt/observer/process_lifecycle.bpf.o".to_owned(),
        lifecycle_object_sha256: "b".repeat(64),
        output_directory: "/var/lib/observer/test-artifacts".to_owned(),
        run_id: "test-run".to_owned(),
        epoch: 1,
        profile: PolicyProfile::Full,
        object_resolution_mode: FileObjectResolutionMode::KernelObjectExpandedPartial,
        bpf_state_scope: None,
        filesystem_state_scope: filesystem_state_scope.then(|| {
            bpf_observer_filesystem_confirmer::FilesystemScope::new(
                vec![PathBuf::from("/var/lib/allox/workspaces/test/current")],
                bpf_observer_filesystem_confirmer::FilesystemCapturePolicy::default(),
                bpf_observer_filesystem_confirmer::FilesystemCaptureLimits::default(),
            )
            .expect("filesystem scope")
        }),
        filesystem_namespace_mode,
        linux_state_scope: None,
        recovery: (protocol_version == DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION).then(|| {
            RecoveryConfig {
                checkpoint_id: "checkpoint-1".to_owned(),
                recovery_id: "recovery-1".to_owned(),
                executable_path: "/opt/observer/recover".to_owned(),
                expected_sha256: "c".repeat(64),
                argv: Vec::new(),
                timeout_ms: 10_000,
                max_output_bytes: 65_536,
            }
        }),
        poll_interval_ms: 20,
        drain_timeout_ms: 5_000,
    }
}

#[test]
fn filesystem_namespace_mode_defaults_to_deployment_and_is_v3_recovery_only() {
    let deployment = filesystem_namespace_mode_config(
        DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
        true,
        FilesystemNamespaceMode::Deployment,
    );
    deployment.validate_schema().expect("v2 deployment mode");

    let mut omitted = serde_json::to_value(&deployment).expect("serialize config");
    omitted
        .as_object_mut()
        .expect("config object")
        .remove("filesystem_namespace_mode");
    let decoded: DeploymentObserverConfig =
        serde_json::from_value(omitted).expect("deserialize omitted namespace mode");
    assert_eq!(
        decoded.filesystem_namespace_mode,
        FilesystemNamespaceMode::Deployment
    );
    decoded.validate_schema().expect("default deployment mode");

    let observer = filesystem_namespace_mode_config(
        DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        true,
        FilesystemNamespaceMode::Observer,
    );
    observer
        .validate_schema()
        .expect("v3 recovery observer mode");

    let v2_observer = filesystem_namespace_mode_config(
        DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
        true,
        FilesystemNamespaceMode::Observer,
    );
    assert!(v2_observer.validate_schema().is_err());

    let unscoped_observer = filesystem_namespace_mode_config(
        DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        false,
        FilesystemNamespaceMode::Observer,
    );
    assert!(unscoped_observer.validate_schema().is_err());
}

#[test]
fn initial_ready_failure_exposes_bounded_typed_mismatch_diagnostics() {
    let validation = LiveIdentityValidation {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        scope_sha256: "a".repeat(64),
        phase: RevalidationPhase::Ready,
        checked_unix_ns: 1,
        stable: false,
        expected_process_exits: Vec::new(),
        mismatches: vec![ValidationMismatch::NetworkBackendDescriptorChanged {
            owner_pid: 42,
            descriptor: 7,
            expected_interface_name: "tap-observer-test".to_owned(),
        }],
    };

    let diagnostic =
        crate::session::identity_mismatch_diagnostic("initial READY validation", &validation);
    assert!(diagnostic.contains("mismatch_count=1"));
    assert!(diagnostic.contains("NetworkBackendDescriptorChanged"));
    assert!(diagnostic.contains("owner_pid: 42"));
    assert!(diagnostic.contains("descriptor: 7"));
    assert!(diagnostic.contains("tap-observer-test"));
}

#[test]
fn protocol_accepts_exactly_one_bound_finish() {
    let mut machine = ProtocolMachine::new("run-1", NONCE).unwrap();
    machine.mark_ready().unwrap();
    let command = FinishCommand {
        protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
        command: "FINISH".to_owned(),
        run_id: "run-1".to_owned(),
        finish_nonce: NONCE.to_owned(),
    };
    machine.accept_finish(&command).unwrap();
    assert!(machine.accept_finish(&command).is_err());
    machine.mark_finished().unwrap();
    assert_eq!(machine.state(), ProtocolState::Finished);
}

#[test]
fn protocol_rejects_wrong_nonce_without_advancing() {
    let mut machine = ProtocolMachine::new("run-1", NONCE).unwrap();
    machine.mark_ready().unwrap();
    let command = FinishCommand {
        protocol_version: DEPLOYMENT_OBSERVER_PROTOCOL_VERSION,
        command: "FINISH".to_owned(),
        run_id: "run-1".to_owned(),
        finish_nonce: "f".repeat(64),
    };
    assert!(machine.accept_finish(&command).is_err());
    assert_eq!(machine.state(), ProtocolState::Ready);
}

fn recovery_command(
    kind: RecoveryCommandKind,
    run_id: &str,
    checkpoint_id: &str,
    recovery_id: &str,
    command_seq: u32,
    nonce: &str,
) -> RecoveryControlCommand {
    let protocol_version = DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION;
    let run_id = run_id.to_owned();
    let checkpoint_id = checkpoint_id.to_owned();
    let recovery_id = recovery_id.to_owned();
    let nonce = nonce.to_owned();
    match kind {
        RecoveryCommandKind::AgentStarted => RecoveryControlCommand::AgentStarted {
            protocol_version,
            run_id,
            epoch: 7,
            checkpoint_id,
            recovery_id,
            command_seq,
            nonce,
        },
        RecoveryCommandKind::PreRestore => RecoveryControlCommand::PreRestore {
            protocol_version,
            run_id,
            epoch: 7,
            checkpoint_id,
            recovery_id,
            command_seq,
            nonce,
        },
        RecoveryCommandKind::Finish => RecoveryControlCommand::Finish {
            protocol_version,
            run_id,
            epoch: 7,
            checkpoint_id,
            recovery_id,
            command_seq,
            nonce,
        },
    }
}

fn recovery_machine() -> RecoveryProtocolMachine {
    RecoveryProtocolMachine::new("run-abc", 7, "checkpoint-1", "recovery-1", NONCE).unwrap()
}

#[test]
fn recovery_protocol_accepts_only_complete_abc_sequence() {
    let mut machine = recovery_machine();
    assert_eq!(machine.state(), RecoveryProtocolState::Initialized);
    machine.mark_ready_a_committed().unwrap();
    assert_eq!(machine.state(), RecoveryProtocolState::ReadyACommitted);

    let agent_started = recovery_command(
        RecoveryCommandKind::AgentStarted,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        1,
        NONCE,
    );
    machine
        .accept_agent_started(&agent_started, RECOVERY_NONCE_2)
        .unwrap();
    assert_eq!(machine.state(), RecoveryProtocolState::AgentRunning);
    assert_eq!(machine.expected_command_seq(), 2);
    assert_eq!(machine.nonce(), RECOVERY_NONCE_2);

    let pre_restore = recovery_command(
        RecoveryCommandKind::PreRestore,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        2,
        RECOVERY_NONCE_2,
    );
    machine
        .accept_pre_restore(&pre_restore, RECOVERY_NONCE_3)
        .unwrap();
    machine.mark_b_committed().unwrap();
    machine.mark_restoring().unwrap();
    machine.mark_restore_complete().unwrap();
    machine.mark_c_committed().unwrap();

    let finish = recovery_command(
        RecoveryCommandKind::Finish,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        3,
        RECOVERY_NONCE_3,
    );
    machine.accept_finish(&finish).unwrap();
    machine.mark_finished().unwrap();
    assert_eq!(machine.state(), RecoveryProtocolState::Finished);
}

#[test]
fn recovery_protocol_rejects_out_of_order_and_duplicate_commands() {
    let mut machine = recovery_machine();
    let pre_restore = recovery_command(
        RecoveryCommandKind::PreRestore,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        2,
        RECOVERY_NONCE_2,
    );
    assert!(machine
        .accept_pre_restore(&pre_restore, RECOVERY_NONCE_3)
        .is_err());
    assert_eq!(machine.state(), RecoveryProtocolState::Initialized);

    machine.mark_ready_a_committed().unwrap();
    let agent_started = recovery_command(
        RecoveryCommandKind::AgentStarted,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        1,
        NONCE,
    );
    machine
        .accept_agent_started(&agent_started, RECOVERY_NONCE_2)
        .unwrap();
    assert!(machine
        .accept_agent_started(&agent_started, RECOVERY_NONCE_2)
        .is_err());
    assert_eq!(machine.state(), RecoveryProtocolState::AgentRunning);

    assert!(machine.mark_b_committed().is_err());
    let finish = recovery_command(
        RecoveryCommandKind::Finish,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        3,
        RECOVERY_NONCE_3,
    );
    assert!(machine.accept_finish(&finish).is_err());
    assert_eq!(machine.state(), RecoveryProtocolState::AgentRunning);
}

#[test]
fn recovery_protocol_rejects_wrong_nonce_ids_and_sequence_without_advancing() {
    let mut machine = recovery_machine();
    machine.mark_ready_a_committed().unwrap();

    for command in [
        recovery_command(
            RecoveryCommandKind::AgentStarted,
            "wrong-run",
            "checkpoint-1",
            "recovery-1",
            1,
            NONCE,
        ),
        recovery_command(
            RecoveryCommandKind::AgentStarted,
            "run-abc",
            "wrong-checkpoint",
            "recovery-1",
            1,
            NONCE,
        ),
        recovery_command(
            RecoveryCommandKind::AgentStarted,
            "run-abc",
            "checkpoint-1",
            "wrong-recovery",
            1,
            NONCE,
        ),
        recovery_command(
            RecoveryCommandKind::AgentStarted,
            "run-abc",
            "checkpoint-1",
            "recovery-1",
            1,
            RECOVERY_NONCE_2,
        ),
        recovery_command(
            RecoveryCommandKind::AgentStarted,
            "run-abc",
            "checkpoint-1",
            "recovery-1",
            2,
            NONCE,
        ),
    ] {
        assert!(machine
            .accept_agent_started(&command, RECOVERY_NONCE_2)
            .is_err());
        assert_eq!(machine.state(), RecoveryProtocolState::ReadyACommitted);
        assert_eq!(machine.expected_command_seq(), 1);
        assert_eq!(machine.nonce(), NONCE);
    }
}

#[test]
fn recovery_protocol_requires_fresh_next_nonce_and_rejects_unknown_fields() {
    let mut machine = recovery_machine();
    machine.mark_ready_a_committed().unwrap();
    let command = recovery_command(
        RecoveryCommandKind::AgentStarted,
        "run-abc",
        "checkpoint-1",
        "recovery-1",
        1,
        NONCE,
    );
    assert!(machine.accept_agent_started(&command, NONCE).is_err());
    assert_eq!(machine.state(), RecoveryProtocolState::ReadyACommitted);

    let encoded = format!(
        "{{\"command\":\"AGENT_STARTED\",\"protocol_version\":3,\"run_id\":\"run-abc\",\"epoch\":7,\"checkpoint_id\":\"checkpoint-1\",\"recovery_id\":\"recovery-1\",\"command_seq\":1,\"nonce\":\"{NONCE}\",\"unexpected\":true}}"
    );
    assert!(serde_json::from_str::<RecoveryControlCommand>(&encoded).is_err());
}

#[test]
fn registration_plan_registers_only_bounded_ancestor_roots() {
    let manifest = fixture_manifest();
    let plan = RegistrationPlan::from_manifest(&manifest).unwrap();
    assert_eq!(plan.root_cgroup_ids, vec![20]);
    assert_eq!(plan.deployment_scope_sha256, manifest.scope_sha256);
    assert_eq!(
        plan.dynamic_descendant_policy,
        "BPF_CURRENT_TASK_UNDER_CGROUP_CGROUP_ARRAY_BOUNDED_V1"
    );
}

#[test]
fn registration_plan_rejects_more_than_eight_roots() {
    let mut manifest = fixture_manifest();
    manifest.root_cgroups.clear();
    manifest.observed_cgroups.clear();
    for index in 0..=MAX_ANCESTOR_ROOTS {
        let root = CgroupIdentity {
            path: format!("/root-{index:02}"),
            cgroup_id: 100 + index as u64,
            parent_cgroup_id: Some(1),
            depth_from_root: 0,
            populated: index == 0,
        };
        manifest.root_cgroups.push(root.clone());
        manifest.observed_cgroups.push(root);
    }
    manifest.processes[0].cgroup_path = "/root-00".to_owned();
    manifest.processes[0].cgroup_id = 100;
    manifest.scope_sha256 = manifest.compute_scope_sha256().unwrap();
    manifest.validate().unwrap();
    assert!(RegistrationPlan::from_manifest(&manifest).is_err());
}

#[test]
fn registration_plan_rejects_overlapping_roots() {
    let mut manifest = fixture_manifest();
    manifest.root_cgroups = manifest.observed_cgroups.clone();
    manifest.root_cgroups[1].depth_from_root = 0;
    manifest.scope_sha256 = manifest.compute_scope_sha256().unwrap();
    manifest.validate().unwrap();
    assert!(RegistrationPlan::from_manifest(&manifest).is_err());
}

#[test]
fn ancestor_transport_covers_dynamic_and_ephemeral_descendants() {
    let ids = vec![20];
    let outcomes = vec![CgroupRecorderOutcome {
        cgroup_id: 20,
        health: Some(effect_health(20, TransportStatus::Complete, 2)),
        finalization_error: None,
        unregistered: true,
    }];
    let aggregate = aggregate_health(&ids, &outcomes, true, true).unwrap();
    assert_eq!(
        aggregate.transport_status,
        AggregateTransportStatus::Complete
    );
    assert_eq!(aggregate.evidence_status, AggregateEvidenceStatus::Complete);
    assert_eq!(
        aggregate.whole_tree_coverage_status,
        WholeTreeCoverageStatus::DynamicAncestorComplete
    );
    assert!(aggregate.reasons.is_empty());
}

#[test]
fn lifecycle_aggregate_rejects_unsupported_complete_enrollment() {
    let ids = vec![20];
    let outcomes = vec![CgroupLifecycleOutcome {
        cgroup_id: 20,
        health: Some(lifecycle_health(20, ProcessLifecycleStatus::Complete, 3)),
        finalization_error: None,
        unregistered: true,
    }];
    let error = aggregate_lifecycle_health(&ids, &outcomes).unwrap_err();
    assert!(format!("{error:#}").contains("partial-enrollment contract"));
}

#[test]
fn lifecycle_aggregate_caps_lossless_stream_at_partial() {
    let ids = vec![20];
    let outcomes = vec![CgroupLifecycleOutcome {
        cgroup_id: 20,
        health: Some(lifecycle_health(20, ProcessLifecycleStatus::Partial, 3)),
        finalization_error: None,
        unregistered: true,
    }];
    let aggregate = aggregate_lifecycle_health(&ids, &outcomes).unwrap();
    assert_eq!(aggregate.root_scope_status, ProcessLifecycleStatus::Partial);
    assert_eq!(aggregate.partial_cgroup_count, 1);
    assert_eq!(aggregate.complete_cgroup_count, 0);
    assert_eq!(aggregate.incomplete_cgroup_count, 0);
}

#[test]
fn linux_state_single_root_is_bound_to_recursive_deployment_residual_scope() {
    let manifest = fixture_manifest();
    let configured = fixture_linux_state_scope();
    let bound = crate::linux_state::bind_linux_state_scope(Some(&configured), &manifest)
        .unwrap()
        .unwrap();
    assert!(bound.forced_incomplete_reasons.is_empty());
    let sysctl = bound.sysctl_namespace_targets.as_ref().unwrap();
    assert_eq!(sysctl.network.expected_namespace_inode, 33);
    assert_eq!(sysctl.uts.expected_namespace_inode, 34);
    assert_eq!(sysctl.ipc.expected_namespace_inode, 35);
    let residual = bound.scope.process_residual.unwrap();
    assert_eq!(residual.expected_cgroup_id, 20);
    assert!(residual.additional_roots.is_empty());
    assert!(residual.recursive);
    assert!(residual.require_cgroup2);
    assert_eq!(
        hex::decode(residual.cgroup_path_bytes_hex).unwrap(),
        b"/sys/fs/cgroup/fixture"
    );
}

#[test]
fn linux_state_multi_root_binds_every_disjoint_deployment_root() {
    let manifest = fixture_multi_root_manifest();
    let configured = fixture_linux_state_scope();
    let bound = crate::linux_state::bind_linux_state_scope(Some(&configured), &manifest)
        .unwrap()
        .unwrap();
    let residual = bound.scope.process_residual.as_ref().unwrap();
    assert_eq!(residual.expected_cgroup_id, 20);
    assert_eq!(residual.additional_roots.len(), 1);
    assert_eq!(residual.additional_roots[0].expected_cgroup_id, 30);
    assert_eq!(
        hex::decode(&residual.additional_roots[0].cgroup_path_bytes_hex).unwrap(),
        b"/sys/fs/cgroup/fixture-other"
    );
    assert!(bound.forced_incomplete_reasons.is_empty());
    assert!(bound.sysctl_namespace_targets.is_some());

    let single = crate::linux_state::bind_linux_state_scope(
        Some(&fixture_linux_state_scope()),
        &fixture_manifest(),
    )
    .unwrap()
    .unwrap();
    assert!(crate::linux_state::bind_linux_state_scope(Some(&single.scope), &manifest).is_err());
}

#[test]
fn linux_state_namespaces_bind_to_nonzero_manifest_pid_for_every_deployment_kind() {
    for kind in [
        DeploymentKind::Direct,
        DeploymentKind::Docker,
        DeploymentKind::KataHost,
    ] {
        let manifest = fixture_manifest_for_kind(kind);
        let configured = fixture_namespace_state_scope(0, 31, 33);
        let bound = crate::linux_state::bind_linux_state_scope(Some(&configured), &manifest)
            .unwrap()
            .unwrap();
        let mount = &bound.scope.mounts.as_ref().unwrap().namespace;
        let network = &bound.scope.network.as_ref().unwrap().namespace;
        assert_ne!(mount.pid, 0);
        assert_ne!(network.pid, 0);
        assert_eq!(mount.expected_namespace_inode, 31);
        assert_eq!(network.expected_namespace_inode, 33);
        assert!(manifest
            .processes
            .iter()
            .any(|process| { process.pid == mount.pid && process.mount_namespace_id == 31 }));
        assert!(manifest
            .processes
            .iter()
            .any(|process| { process.pid == network.pid && process.net_namespace_id == 33 }));
    }
}

#[test]
fn linux_state_namespace_binding_rejects_observer_or_uncommitted_pid_fallback() {
    let manifest = fixture_manifest();
    let observer_namespace = fixture_namespace_state_scope(0, 999, 998);
    assert!(
        crate::linux_state::bind_linux_state_scope(Some(&observer_namespace), &manifest).is_err()
    );

    let foreign_pid = fixture_namespace_state_scope(999, 31, 33);
    assert!(crate::linux_state::bind_linux_state_scope(Some(&foreign_pid), &manifest).is_err());
}

#[test]
fn docker_filesystem_contract_requires_retained_container_mount_namespace_evidence() {
    let mut snapshot = bpf_observer_filesystem_confirmer::capture(
        &bpf_observer_filesystem_confirmer::FilesystemScope::new(
            vec![std::env::temp_dir().join(format!(
                "deployment-observer-docker-namespace-{}-not-present",
                std::process::id()
            ))],
            bpf_observer_filesystem_confirmer::FilesystemCapturePolicy::default(),
            bpf_observer_filesystem_confirmer::FilesystemCaptureLimits::default(),
        )
        .expect("filesystem scope"),
        &bpf_observer_filesystem_confirmer::CaptureRequest {
            snapshot_id: "docker-namespace-s0".to_owned(),
            phase: bpf_observer_filesystem_confirmer::SnapshotPhase::S0,
        },
    )
    .expect("filesystem capture");
    let namespace_inode = snapshot.mount_namespace_inode;
    let reasons = crate::endpoint_state::filesystem_namespace_reasons(
        &snapshot,
        &[namespace_inode],
        Some(namespace_inode),
        DeploymentKind::Docker,
    );
    assert!(reasons
        .iter()
        .any(|reason| reason.contains("required retained deployment mount namespace")));

    snapshot.mount_namespace_capture_source =
        bpf_observer_filesystem_confirmer::MountNamespaceCaptureSource::RetainedFileDescriptor;
    assert!(crate::endpoint_state::filesystem_namespace_reasons(
        &snapshot,
        &[namespace_inode],
        Some(namespace_inode),
        DeploymentKind::Docker,
    )
    .is_empty());
}

#[test]
fn filesystem_namespace_anchor_is_retained_for_direct_and_docker_but_not_kata() {
    for (kind, expected) in [
        (DeploymentKind::Direct, Some((123, 31))),
        (DeploymentKind::Docker, Some((123, 31))),
        (DeploymentKind::KataHost, None),
    ] {
        let manifest = fixture_manifest_for_kind(kind);
        let target = crate::endpoint_state::filesystem_mount_namespace_target(&manifest)
            .expect("filesystem namespace target")
            .map(|target| (target.pid, target.expected_namespace_inode));
        assert_eq!(target, expected);
    }

    let manifest = fixture_manifest_for_kind(DeploymentKind::Direct);
    assert!(crate::session::filesystem_mount_namespace_target_for_mode(
        &manifest,
        true,
        FilesystemNamespaceMode::Deployment,
    )
    .expect("deployment namespace mode")
    .is_some());
    assert!(crate::session::filesystem_mount_namespace_target_for_mode(
        &manifest,
        true,
        FilesystemNamespaceMode::Observer,
    )
    .expect("observer namespace mode")
    .is_none());
}

#[test]
fn linux_state_namespace_loss_is_reported_incomplete() {
    let comparison = StateComparison {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        domain: LINUX_STATE_CONFIRMATION_DOMAIN.to_owned(),
        scope_sha256: "a".repeat(64),
        s0_snapshot_id: "run-1:linux-state:s0".to_owned(),
        s1_snapshot_id: "run-1:linux-state:s1".to_owned(),
        domains: StateDomainComparisons {
            sysctl: domain_comparison(DomainKind::Sysctl, CompletenessStatus::Complete),
            mounts: domain_comparison(DomainKind::Mount, CompletenessStatus::Incomplete),
            network: domain_comparison(DomainKind::Network, CompletenessStatus::NotConfirmed),
            modules: domain_comparison(DomainKind::KernelModule, CompletenessStatus::NotConfirmed),
            process_residual: domain_comparison(
                DomainKind::ProcessResidual,
                CompletenessStatus::Complete,
            ),
        },
        limitations: Vec::new(),
    };
    let report = LinuxStateReport::from_comparison(
        &comparison,
        "b".repeat(64),
        "c".repeat(64),
        "d".repeat(64),
        &[],
    )
    .unwrap();
    assert_eq!(report.evidence_status, LinuxStateEvidenceStatus::Incomplete);
    assert!(report
        .reasons
        .iter()
        .any(|reason| reason.contains("MOUNT_ENDPOINT_STATE_V1")));
}

#[test]
fn endpoint_artifact_set_is_exactly_conditional() {
    let base = crate::verify::committed_artifacts(false, false, false, false);
    assert!(!base.iter().any(|name| name.starts_with("bpf-state-")));
    assert!(!base
        .iter()
        .any(|name| name.starts_with("filesystem-state-")));
    let all = crate::verify::committed_artifacts(true, true, true, true);
    for name in [
        "bpf-state-s0.json",
        "bpf-state-s1.json",
        "bpf-state-verdict.json",
        "filesystem-state-s0.json",
        "filesystem-state-s1.json",
        "filesystem-state-comparison.json",
        "linux-state-s0.json",
        "linux-state-s1.json",
        "linux-state-comparison.json",
        "socket-state.raw.bin",
        "socket-state.jsonl",
        "socket-state.health.json",
    ] {
        assert!(all.contains(&name));
    }
    assert!(all.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn diagnostic_performance_telemetry_is_closed_bounded_and_non_authoritative() {
    let s0 = EndpointCaptureTelemetry::new(Some(11), Some(13), Some(17)).unwrap();
    let drain = ClosingDrainTelemetry::new(19, 23).unwrap();
    let s1 = EndpointCaptureTelemetry::new(Some(29), Some(31), Some(37)).unwrap();
    let telemetry = DiagnosticPerformanceTelemetry::new(s0, drain, s1);
    telemetry.validate(true, true, true).unwrap();
    assert!(!telemetry.trusted_evidence);
    assert!(!telemetry.affects_verdict);
    assert_eq!(telemetry.s0_endpoint_capture.total_duration_ns, 41);
    assert_eq!(telemetry.closing_drain.total_duration_ns, 42);
    assert_eq!(telemetry.s1_endpoint_capture.total_duration_ns, 97);

    let mut forged = telemetry.clone();
    forged.affects_verdict = true;
    assert!(forged.validate(true, true, true).is_err());
    assert!(telemetry.validate(false, true, true).is_err());

    let mut json = serde_json::to_value(&telemetry).unwrap();
    json.as_object_mut()
        .unwrap()
        .insert("unknown".to_owned(), serde_json::json!(1));
    assert!(serde_json::from_value::<DiagnosticPerformanceTelemetry>(json).is_err());
}

#[test]
fn diagnostic_counters_reject_addition_overflow() {
    assert!(EndpointCaptureTelemetry::new(Some(u64::MAX), Some(1), None).is_err());
    assert!(ClosingDrainTelemetry::new(u64::MAX, 1).is_err());
    let artifacts = vec![
        ArtifactDigest {
            relative_path: "one".to_owned(),
            size_bytes: u64::MAX,
            sha256: "a".repeat(64),
        },
        ArtifactDigest {
            relative_path: "two".to_owned(),
            size_bytes: 1,
            sha256: "b".repeat(64),
        },
    ];
    assert!(crate::report::checked_artifact_total_bytes(&artifacts).is_err());
}

#[test]
fn socket_state_health_is_exactly_bound_and_aggregated() {
    let mut system_health = effect_health(20, TransportStatus::Complete, 2);
    system_health.object_resolution_mode = FileObjectResolutionMode::KernelObjectExpandedPartial;
    system_health.socket_state = Some(socket_state_health(20, 2));
    let outcomes = vec![CgroupRecorderOutcome {
        cgroup_id: 20,
        health: Some(system_health),
        finalization_error: None,
        unregistered: true,
    }];
    let health = SocketStateHealthArtifact::from_outcomes(
        "run-1",
        "12345678-1234-1234-1234-123456789abc",
        1,
        &[20],
        &outcomes,
    )
    .unwrap();
    let report = SocketStateReport::from_health(&health, "a".repeat(64)).unwrap();
    assert_eq!(report.status, SocketStateStatus::Complete);
    assert_eq!(report.root_count, 1);
    assert_eq!(report.event_published, 2);
    assert_eq!(report.destroy_events_persisted, 1);
    assert_eq!(report.owners_retired_at_barrier, 1);
    assert!(!report.causal_attribution_established);

    let mut wrong = outcomes;
    wrong[0]
        .health
        .as_mut()
        .unwrap()
        .socket_state
        .as_mut()
        .unwrap()
        .boot_id = "00000000-0000-0000-0000-000000000000".to_owned();
    assert!(SocketStateHealthArtifact::from_outcomes(
        "run-1",
        "12345678-1234-1234-1234-123456789abc",
        1,
        &[20],
        &wrong,
    )
    .is_err());
}

#[test]
fn multi_root_socket_state_requires_one_identical_complete_global_seal() {
    let outcomes = [20_u64, 30_u64]
        .into_iter()
        .map(|cgroup_id| {
            let mut health = effect_health(cgroup_id, TransportStatus::Complete, cgroup_id / 10);
            health.object_resolution_mode = FileObjectResolutionMode::KernelObjectExpandedPartial;
            health.socket_state = Some(socket_state_health(cgroup_id, cgroup_id / 10));
            CgroupRecorderOutcome {
                cgroup_id,
                health: Some(health),
                finalization_error: None,
                unregistered: true,
            }
        })
        .collect::<Vec<_>>();
    let roots = [20_u64, 30_u64];
    let health = SocketStateHealthArtifact::from_outcomes(
        "run-1",
        "12345678-1234-1234-1234-123456789abc",
        1,
        &roots,
        &outcomes,
    )
    .unwrap();
    let report = SocketStateReport::from_health(&health, "a".repeat(64)).unwrap();
    assert_eq!(report.root_count, 2);
    assert_eq!(report.event_published, 5);
    assert!(report.async_producer_seal.is_required_complete());

    let mut mismatched = outcomes;
    mismatched[1]
        .health
        .as_mut()
        .unwrap()
        .socket_state
        .as_mut()
        .unwrap()
        .async_producer_seal = SocketStateProducerSeal {
        complete: false,
        links_expected: SOCKET_STATE_ASYNC_PRODUCER_LINKS,
        links_detached: 1,
    };
    let mismatched_health = SocketStateHealthArtifact::from_outcomes(
        "run-1",
        "12345678-1234-1234-1234-123456789abc",
        1,
        &roots,
        &mismatched,
    )
    .unwrap();
    assert!(SocketStateReport::from_health(&mismatched_health, "a".repeat(64)).is_err());
}

#[test]
fn overall_evidence_status_is_conservative_across_domains() {
    use AggregateEvidenceStatus::{Complete, Incomplete, UnprovenNoEvents};

    assert_eq!(
        crate::report::collapse_overall_evidence_status(&[Complete, Complete]),
        Complete
    );
    assert_eq!(
        crate::report::collapse_overall_evidence_status(&[Complete, UnprovenNoEvents, Complete,]),
        UnprovenNoEvents
    );
    assert_eq!(
        crate::report::collapse_overall_evidence_status(&[UnprovenNoEvents, Incomplete, Complete,]),
        Incomplete
    );
}

#[test]
fn endpoint_snapshot_ids_are_bounded_and_run_bound() {
    let long_run = "r".repeat(128);
    let bpf_s0 = crate::endpoint_state::bpf_snapshot_id(&long_run, 7, "S0");
    let bpf_s1 = crate::endpoint_state::bpf_snapshot_id(&long_run, 7, "S1");
    let fs_s0 = crate::endpoint_state::filesystem_snapshot_id(&long_run, 7, "S0");
    assert!(bpf_s0.len() <= 128);
    assert!(fs_s0.len() <= 128);
    assert_ne!(bpf_s0, bpf_s1);
    assert_ne!(
        bpf_s0,
        crate::endpoint_state::bpf_snapshot_id(&long_run, 8, "S0")
    );
}

#[test]
fn filesystem_scope_cannot_contain_evidence_directory() {
    let scope = bpf_observer_filesystem_confirmer::FilesystemScope::new(
        vec![PathBuf::from("/tmp/deployment-state-scope")],
        bpf_observer_filesystem_confirmer::FilesystemCapturePolicy::default(),
        bpf_observer_filesystem_confirmer::FilesystemCaptureLimits::default(),
    )
    .unwrap();
    assert!(
        crate::endpoint_state::validate_filesystem_output_separation(
            &scope,
            Path::new("/tmp/deployment-state-scope/evidence")
        )
        .is_err()
    );
}

#[test]
fn deployment_endpoint_reports_reject_unchanged_or_causal_authority() {
    let system_exclusions = bpf_observer_schema::ObjectExclusions {
        program_ids: [1].into_iter().collect(),
        map_ids: [2].into_iter().collect(),
        link_ids: [3].into_iter().collect(),
    };
    let lifecycle_exclusions = bpf_observer_schema::ObjectExclusions {
        program_ids: [4].into_iter().collect(),
        map_ids: [5].into_iter().collect(),
        link_ids: [6].into_iter().collect(),
    };
    let mut combined_exclusions = system_exclusions.clone();
    crate::endpoint_state::merge_exclusions(&mut combined_exclusions, &lifecycle_exclusions);
    let mut bpf = BpfStateReport {
        protocol_version: crate::endpoint_state::BPF_STATE_CONFIRMATION_PROTOCOL_VERSION,
        domain: crate::endpoint_state::BPF_STATE_CONFIRMATION_DOMAIN.to_owned(),
        scope_sha256: "a".repeat(64),
        system_effect_recorder_exclusions: system_exclusions,
        lifecycle_recorder_exclusions: lifecycle_exclusions,
        observer_exclusions: combined_exclusions,
        s0_snapshot_id: "s0".to_owned(),
        s0_snapshot_sha256: "b".repeat(64),
        s1_snapshot_id: "s1".to_owned(),
        s1_snapshot_sha256: "c".repeat(64),
        verdict_sha256: "d".repeat(64),
        state_verdict: bpf_observer_schema::StateVerdict::UnchangedWithinScope,
        state_completeness: bpf_observer_schema::CompletenessStatus::Complete,
        evidence_status: bpf_observer_schema::CompletenessStatus::Complete,
        attribution: bpf_observer_schema::Attribution::NoStateChange,
        change_count: 0,
        contract_complete: true,
        contract_incomplete_reasons: Vec::new(),
        causal_attribution_established: false,
        operation_events_are_state_diff: false,
        atomic_with_other_confirmation_domains: false,
        unchanged_verdict_authorized: false,
    };
    assert!(bpf.validate().is_err());
    bpf.state_verdict = bpf_observer_schema::StateVerdict::Inconclusive;
    bpf.causal_attribution_established = true;
    assert!(bpf.validate().is_err());

    let filesystem = FilesystemStateReport {
        protocol_version:
            bpf_observer_filesystem_confirmer::FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
        domain: bpf_observer_filesystem_confirmer::FILESYSTEM_CONFIRMATION_DOMAIN.to_owned(),
        scope_sha256: "a".repeat(64),
        s0_snapshot_id: "s0".to_owned(),
        s0_snapshot_sha256: "b".repeat(64),
        s1_snapshot_id: "s1".to_owned(),
        s1_snapshot_sha256: "c".repeat(64),
        comparison_sha256: "d".repeat(64),
        endpoint_difference:
            bpf_observer_filesystem_confirmer::EndpointDifferenceStatus::ObservedIdentical,
        state_verdict: bpf_observer_filesystem_confirmer::FilesystemVerdict::UnchangedWithinScope,
        state_completeness: bpf_observer_filesystem_confirmer::CompletenessStatus::Complete,
        actor_contract_status: bpf_observer_filesystem_confirmer::ActorContractStatus::Missing,
        causal_attribution_status:
            bpf_observer_filesystem_confirmer::CausalAttributionStatus::NotEstablished,
        change_count: 0,
        contract_complete: true,
        contract_incomplete_reasons: Vec::new(),
        actor_contract_authenticated_by_observer: false,
        operation_events_are_state_diff: false,
        atomic_with_other_confirmation_domains: false,
        unchanged_verdict_authorized: false,
    };
    assert!(filesystem.validate().is_err());
}

fn fixture_manifest() -> DeploymentManifest {
    let root = CgroupIdentity {
        path: "/fixture".to_owned(),
        cgroup_id: 20,
        parent_cgroup_id: Some(1),
        depth_from_root: 0,
        populated: true,
    };
    let child = CgroupIdentity {
        path: "/fixture/child".to_owned(),
        cgroup_id: 10,
        parent_cgroup_id: Some(20),
        depth_from_root: 1,
        populated: true,
    };
    let mut manifest = DeploymentManifest {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        domain: DEPLOYMENT_SCOPE_DOMAIN.to_owned(),
        deployment_kind: DeploymentKind::Direct,
        source_trust: DiscoverySourceTrust::KernelFilesystemsVerified,
        identity_strength: IdentityStrength::KernelAnchored,
        subject_id: "direct:fixture".to_owned(),
        captured_unix_ns: 1,
        boot_id: "12345678-1234-1234-1234-123456789abc".to_owned(),
        root_cgroups: vec![root.clone()],
        observed_cgroups: vec![root, child],
        processes: vec![ProcessIdentity {
            pid: 123,
            role: ProcessRole::DirectRoot,
            start_time_ticks: 100,
            comm: "fixture".to_owned(),
            executable_path_bytes_hex: hex::encode("/bin/sh"),
            executable_device: 1,
            executable_inode: 2,
            cmdline_sha256: "a".repeat(64),
            cgroup_path: "/fixture/child".to_owned(),
            cgroup_id: 10,
            mount_namespace_id: 31,
            pid_namespace_id: 32,
            net_namespace_id: 33,
            uts_namespace_id: 34,
            ipc_namespace_id: 35,
            namespace_pid_chain: vec![123],
        }],
        mount_namespace_ids: vec![31],
        net_namespace_ids: vec![33],
        uts_namespace_ids: vec![34],
        ipc_namespace_ids: vec![35],
        kata_host_resources: Vec::new(),
        coverage: DeploymentCoverage {
            direct_syscall_attribution_only: true,
            whole_current_cgroup_subtree_enumerated: true,
            descendant_observation_requirement:
                DescendantObservationRequirement::CgroupV2AncestorMatchRequired,
            mount_namespaces_identified: true,
            network_namespaces_identified: true,
            uts_namespaces_identified: true,
            ipc_namespaces_identified: true,
            kata_guest_entered: false,
            kata_host_backends_discovered_from_qemu_argv: false,
            kata_host_backend_namespace_pinned: false,
            kata_tap_fdinfo_evidence_present: false,
            external_runtime_tool_used: false,
        },
        limitations: Vec::new(),
        scope_sha256: String::new(),
    };
    manifest.scope_sha256 = manifest.compute_scope_sha256().unwrap();
    manifest.validate().unwrap();
    manifest
}

fn fixture_multi_root_manifest() -> DeploymentManifest {
    let mut manifest = fixture_manifest();
    let extra = CgroupIdentity {
        path: "/fixture-other".to_owned(),
        cgroup_id: 30,
        parent_cgroup_id: Some(1),
        depth_from_root: 0,
        populated: false,
    };
    manifest.root_cgroups.push(extra.clone());
    manifest
        .root_cgroups
        .sort_by(|left, right| left.path.cmp(&right.path));
    manifest.observed_cgroups.push(extra);
    manifest
        .observed_cgroups
        .sort_by(|left, right| left.path.cmp(&right.path));
    manifest.scope_sha256 = manifest.compute_scope_sha256().unwrap();
    manifest.validate().unwrap();
    manifest
}

fn fixture_manifest_for_kind(kind: DeploymentKind) -> DeploymentManifest {
    let mut manifest = fixture_manifest();
    manifest.deployment_kind = kind;
    match kind {
        DeploymentKind::Direct => {}
        DeploymentKind::Docker => {
            manifest.subject_id = "d".repeat(64);
            manifest.processes[0].role = ProcessRole::DockerInit;
        }
        DeploymentKind::KataHost => {
            manifest.subject_id = "kata:fixture".to_owned();
            manifest.processes[0].role = ProcessRole::KataShim;
            let mut hypervisor = manifest.processes[0].clone();
            hypervisor.pid = 124;
            hypervisor.role = ProcessRole::KataHypervisor;
            hypervisor.start_time_ticks = 101;
            hypervisor.executable_inode = 3;
            hypervisor.cmdline_sha256 = "b".repeat(64);
            hypervisor.namespace_pid_chain = vec![124];
            manifest.processes.push(hypervisor);
        }
    }
    manifest.scope_sha256 = manifest.compute_scope_sha256().unwrap();
    manifest.validate().unwrap();
    manifest
}

fn fixture_namespace_state_scope(pid: u32, mount_inode: u64, net_inode: u64) -> StateScope {
    let limits = CaptureLimits::default();
    StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: None,
        mounts: Some(MountScope {
            namespace: NamespaceTarget {
                pid,
                expected_namespace_inode: mount_inode,
            },
            evidence: ValueEvidenceMode::Sha256Only,
            limits: limits.clone(),
        }),
        network: Some(NetworkScope {
            namespace: NamespaceTarget {
                pid,
                expected_namespace_inode: net_inode,
            },
            collectors: NetworkCollectors {
                addresses: true,
                routes: false,
                rules: false,
                traffic_control: false,
                nftables: false,
            },
            normalization:
                bpf_observer_linux_state_confirmers::NetworkNormalization::ConfigurationOnlyV1,
            ip_binary_bytes_hex: encode_absolute_path(Path::new("/usr/sbin/ip")).unwrap(),
            expected_ip_sha256: "a".repeat(64),
            tc_binary_bytes_hex: String::new(),
            expected_tc_sha256: String::new(),
            nft_binary_bytes_hex: String::new(),
            expected_nft_sha256: String::new(),
            tc_interfaces: Vec::new(),
            evidence: ValueEvidenceMode::Sha256Only,
            limits,
        }),
        modules: None,
        process_residual: None,
    }
}

fn fixture_linux_state_scope() -> StateScope {
    StateScope {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        sysctl: Some(
            SysctlScope::new(Path::new("/proc/sys"), vec!["kernel/ostype".to_owned()]).unwrap(),
        ),
        mounts: None,
        network: None,
        modules: None,
        process_residual: None,
    }
}

fn domain_comparison(kind: DomainKind, completeness: CompletenessStatus) -> DomainComparison {
    let enabled = completeness != CompletenessStatus::NotConfirmed;
    DomainComparison {
        domain: kind,
        protocol_domain: kind.protocol_name().to_owned(),
        endpoint_difference: if enabled {
            if completeness == CompletenessStatus::Complete {
                EndpointDifferenceStatus::ObservedIdentical
            } else {
                EndpointDifferenceStatus::Indeterminate
            }
        } else {
            EndpointDifferenceStatus::NotConfirmed
        },
        verdict: if enabled {
            StateVerdict::Inconclusive
        } else {
            StateVerdict::NotConfirmed
        },
        state_completeness: Completeness {
            status: completeness,
            reasons: if completeness == CompletenessStatus::Incomplete {
                vec!["namespace target disappeared".to_owned()]
            } else {
                Vec::new()
            },
        },
        terminal_state: if kind == DomainKind::ProcessResidual && enabled {
            TerminalState::EmptyWithinScope
        } else {
            TerminalState::NotApplicable
        },
        causal_attribution_status: CausalAttributionStatus::NotEstablished,
        changes: Vec::new(),
        limitations: Vec::new(),
    }
}

fn effect_health(
    cgroup_id: u64,
    transport_status: TransportStatus,
    events: u64,
) -> SystemEffectHealth {
    SystemEffectHealth {
        schema_version: EFFECT_EVENT_SCHEMA_VERSION,
        run_id: "run-1".to_owned(),
        run_epoch: 1,
        cgroup_id,
        profile: PolicyProfile::Balanced,
        object_resolution_mode: FileObjectResolutionMode::UserInput,
        transport_status,
        coverage_status: CoverageStatus::Partial,
        object_resolution_status: ObjectResolutionStatus::Partial,
        operation_attempted: events / 2,
        operation_completed: events / 2,
        event_attempted: events,
        event_published: events,
        event_dropped: 0,
        events_persisted: events,
        pending_insert_failed: 0,
        pending_missing: 0,
        pending_remaining: 0,
        userspace_failures: 0,
        fatal_kernel_flags: 0,
        capture_read_failures: 0,
        capture_truncations: 0,
        capture_invalid_lengths: 0,
        object_resolution_attempted: 0,
        object_resolution_resolved: 0,
        object_resolution_unresolved: 0,
        object_resolution_failed_syscalls: 0,
        object_join_missing: 0,
        object_join_ambiguous: 0,
        object_read_failed: 0,
        object_delete_failed: 0,
        object_path_unavailable: 0,
        object_pending_remaining: 0,
        task_read_failed: 0,
        object_unsupported: 0,
        socket_state: None,
        producer_barrier_complete: true,
        drain_completed: true,
        wal_durable: true,
        poll_calls: 1,
        maximum_events_per_poll: events,
        callback_queue_high_water: events,
        callback_queue_capacity: 4096,
        reasons: Vec::new(),
        coverage_gaps: Vec::new(),
    }
}

fn lifecycle_health(
    cgroup_id: u64,
    status: ProcessLifecycleStatus,
    events: u64,
) -> ProcessLifecycleHealth {
    ProcessLifecycleHealth {
        schema_version: PROCESS_LIFECYCLE_SCHEMA_VERSION,
        run_id: "run-1".to_owned(),
        run_epoch: 1,
        cgroup_id,
        status,
        event_attempted: events,
        event_published: events,
        event_dropped: 0,
        events_persisted: events,
        task_read_failed: 0,
        exec_path_read_failed: 0,
        exec_path_truncated: 0,
        userspace_failures: 0,
        producer_barrier_complete: true,
        drain_completed: true,
        wal_durable: true,
        poll_calls: 1,
        maximum_events_per_poll: events,
        callback_queue_high_water: events,
        callback_queue_capacity: 4096,
        lineage: Some(ProcessLineageSummary {
            event_count: events,
            task_identities: events / 3,
            exited_task_identities: events / 3,
            group_dead_exits: events / 3,
            enrollment: ProcessEnrollmentSummary {
                initial_task_ledger_present: false,
                initial_tasks_enrolled: 0,
                migration_hook_present: false,
                clone_into_cgroup_covered: false,
                migration_enrolled_task_identities: 0,
                fork_enrolled_task_identities: events / 3,
                exec_introduced_task_identities: 0,
                exit_introduced_task_identities: 0,
                forks_with_unenrolled_parent: events / 3,
                complete: false,
            },
            correlation: "PARTIAL_FORK_EXEC_EXIT_BY_BOOT_ID_PID_START_BOOTTIME_AND_EXEC_OLD_PID"
                .to_owned(),
        }),
        reasons: Vec::new(),
        limitations: vec![PROCESS_LIFECYCLE_ENROLLMENT_LIMITATION.to_owned()],
    }
}

fn socket_state_health(cgroup_id: u64, events: u64) -> SocketStateHealth {
    SocketStateHealth {
        schema_version: SOCKET_STATE_SCHEMA_VERSION,
        run_id: "run-1".to_owned(),
        boot_id: "12345678-1234-1234-1234-123456789abc".to_owned(),
        run_epoch: 1,
        cgroup_id,
        cgroup_match_mode: CgroupMatchMode::AncestorRoot,
        status: SocketStateStatus::Complete,
        event_attempted: events,
        event_published: events,
        event_dropped: 0,
        events_persisted: events,
        final_event_seq: events,
        destroy_events_persisted: 1,
        owner_insert_failed: 0,
        owner_conflict: 0,
        owner_delete_failed: 0,
        owner_remaining: 1,
        owners_retired_at_barrier: 1,
        state_read_failed: 0,
        unsupported_sockets: 0,
        userspace_failures: 0,
        async_producer_seal: SocketStateProducerSeal {
            complete: true,
            links_expected: SOCKET_STATE_ASYNC_PRODUCER_LINKS,
            links_detached: SOCKET_STATE_ASYNC_PRODUCER_LINKS,
        },
        producer_barrier_complete: true,
        drain_completed: true,
        wal_durable: true,
        callback_queue_high_water: events,
        callback_queue_capacity: 4096,
        reasons: Vec::new(),
        coverage_gaps: Vec::new(),
    }
}
