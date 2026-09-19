// SPDX-License-Identifier: GPL-2.0-only

//! Protocol v3: A -> Agent -> B -> external recovery -> C -> offline replay.
//! Endpoint capture is confined to three frozen boundaries, never the syscall
//! hot path. The external helper is a synchronous, content-bound executable;
//! this module does not implement or promise a universal Linux rollback.

use anyhow::{bail, Context, Result};
use bpf_observer_filesystem_confirmer::{
    compare_phases as compare_filesystem_phases, FilesystemComparison,
    SnapshotPhase as FilesystemPhase,
};
use bpf_observer_linux_state_confirmers::{
    compare_phases as compare_linux_phases, SnapshotPhase as LinuxPhase, StateComparison,
};
use bpf_observer_schema::Verdict as BpfVerdict;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, TryRecvError};

use crate::endpoint_state::compare_bpf_endpoints_with_phases;
use crate::protocol::{
    AgentStartedMessage, RecoveryControlCommand, RecoveryProtocolMachine, RecoveryReadyMessage,
    RecoveryTerminalMessage, RestoreCompleteMessage, SnapshotBMessage, SnapshotCMessage,
    DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
};
use crate::recovery::{
    execute as execute_recovery, ForbiddenCgroupIdentity, RecoveryEnvironmentIdentity,
    RecoveryEvidence,
};
use crate::recovery_abort::{RecoveryAbortEvidence, RECOVERY_ABORT_FILE};
use crate::recovery_report::{
    build_recovery_verdict_report_with_raw, RecoveryComparisonSet, RecoveryComparisonTriplet,
    RecoveryDomain, RecoveryRawSnapshotSet, RecoveryRawSnapshotTriplet, RecoverySnapshotEnvelope,
    RecoverySnapshotPhase, RecoverySnapshotTriplet, SnapshotDomainBinding,
};
use crate::recovery_verify::{
    recovery_committed_artifacts, RecoveryArtifactManifest, RecoveryControlTranscript,
    RECOVERY_AGENT_DELTA_FILE, RECOVERY_ARTIFACT_MANIFEST_FILE, RECOVERY_CONTROL_TRANSCRIPT_FILE,
    RECOVERY_EVIDENCE_FILE, RECOVERY_RECORDER_HEALTH_FILE, RECOVERY_RECOVERY_DELTA_FILE,
    RECOVERY_RESIDUAL_DELTA_FILE, RECOVERY_SNAPSHOT_A_FILE, RECOVERY_SNAPSHOT_B_FILE,
    RECOVERY_SNAPSHOT_C_FILE, RECOVERY_VERDICT_FILE,
};
use crate::report::{checked_artifact_total_bytes, ArtifactDigest};
use crate::session::{
    digest_file, emit_line, random_nonce, read_protocol_line, sync_directory,
    write_json_canonical_new, write_json_compact_new, write_json_new, DeploymentObserverConfig,
    DeploymentSession, RecoveryEndpointSnapshots,
};

const RECOVERY_READY_FILE: &str = "recovery-ready-message.json";
const AGENT_STARTED_FILE: &str = "agent-started.json";
const PRE_RESTORE_BARRIER_FILE: &str = "pre-restore-barrier.json";
const PRE_RESTORE_VALIDATION_FILE: &str = "pre-restore-validation.json";
const POST_RESTORE_BARRIER_FILE: &str = "post-restore-barrier.json";
const POST_RESTORE_VALIDATION_FILE: &str = "post-restore-validation.json";
const BPF_B_FILE: &str = "bpf-state-b.json";
const BPF_C_FILE: &str = "bpf-state-c.json";
const FS_B_FILE: &str = "filesystem-state-b.json";
const FS_C_FILE: &str = "filesystem-state-c.json";
const LINUX_B_FILE: &str = "linux-state-b.json";
const LINUX_C_FILE: &str = "linux-state-c.json";

pub fn run_recovery_stdio(config: DeploymentObserverConfig) -> Result<()> {
    if config.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION {
        bail!("recovery coordinator requires protocol v3");
    }
    let recovery = config
        .recovery
        .clone()
        .context("v3 recovery contract is missing")?;
    let output = PathBuf::from(&config.output_directory);
    let (mut session, ready_v2) = DeploymentSession::prepare(config.clone())?;
    let run_result: Result<()> = (|| {
        let mut machine = RecoveryProtocolMachine::new(
            &config.run_id,
            config.epoch,
            &recovery.checkpoint_id,
            &recovery.recovery_id,
            random_nonce()?,
        )?;
        let a_raw = session.baseline_endpoint_snapshots();
        let a = commit_envelope(
            &session,
            &output,
            RecoverySnapshotPhase::A,
            &a_raw,
            &ready_v2.ready_barrier_sha256,
            &ready_v2.ready_validation_sha256,
        )?;
        let a_digest = write_json_canonical_new(&output.join(RECOVERY_SNAPSHOT_A_FILE), &a)?;
        machine.mark_ready_a_committed()?;
        let ready = RecoveryReadyMessage {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: "READY".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id.clone(),
            command_seq: machine.expected_command_seq(),
            nonce: machine.nonce().to_owned(),
            snapshot_a_sha256: a_digest.sha256.clone(),
        };
        write_json_new(&output.join(RECOVERY_READY_FILE), &ready)?;
        sync_directory(&output)?;
        emit_line(&ready)?;

        let commands = spawn_command_reader();
        let agent_command = next_command(&mut session, &commands)?;
        let agent_nonce = random_nonce()?;
        machine.accept_agent_started(&agent_command, agent_nonce)?;
        let agent_started = AgentStartedMessage {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: "AGENT_STARTED".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id.clone(),
            command_seq: machine.expected_command_seq(),
            nonce: machine.nonce().to_owned(),
            agent_started_sha256: sha256_json(&agent_command)?,
        };
        write_json_new(&output.join(AGENT_STARTED_FILE), &agent_started)?;
        sync_directory(&output)?;
        emit_line(&agent_started)?;

        let pre_restore_command = next_command(&mut session, &commands)?;
        let pre_restore_nonce = machine.nonce().to_owned();
        machine.accept_pre_restore(&pre_restore_command, random_nonce()?)?;
        session.validate_recovery_boundary("PRE_RESTORE-before-B")?;
        session.drain_open_recorders_at_boundary()?;
        let b_raw = session.capture_recovery_endpoint_snapshots("B")?;
        let (b_barrier, b_validation) = session.validate_recovery_boundary("SNAPSHOT_B")?;
        let b_barrier_digest = write_json_new(&output.join(PRE_RESTORE_BARRIER_FILE), &b_barrier)?;
        let b_validation_digest =
            write_json_new(&output.join(PRE_RESTORE_VALIDATION_FILE), &b_validation)?;
        let b = commit_envelope(
            &session,
            &output,
            RecoverySnapshotPhase::B,
            &b_raw,
            &b_barrier_digest.sha256,
            &b_validation_digest.sha256,
        )?;
        let b_digest = write_json_canonical_new(&output.join(RECOVERY_SNAPSHOT_B_FILE), &b)?;
        sync_directory(&output)?;
        machine.mark_b_committed()?;
        let snapshot_b = SnapshotBMessage {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: "SNAPSHOT_B".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id.clone(),
            command_seq: 2,
            nonce: pre_restore_nonce.clone(),
            pre_restore_sha256: b_validation_digest.sha256,
            snapshot_b_sha256: b_digest.sha256.clone(),
        };
        emit_line(&snapshot_b)?;

        machine.mark_restoring()?;
        let forbidden = session
            .manifest()
            .root_cgroups
            .iter()
            .map(|root| ForbiddenCgroupIdentity {
                cgroup_path: root.path.clone(),
                cgroup_id: root.cgroup_id,
            })
            .collect::<Vec<_>>();
        let mut recovery_evidence = execute_recovery(&recovery, &forbidden)?;
        let (after_recovery_barrier, after_recovery_identity) =
            session.validate_recovery_boundary("RESTORE_COMPLETE-before-C")?;
        recovery_evidence.before_environment = Some(RecoveryEnvironmentIdentity {
            boot_id: session.manifest().boot_id.clone(),
            barrier: b_barrier,
            identity_assessment: b_validation,
        });
        recovery_evidence.after_environment = Some(RecoveryEnvironmentIdentity {
            boot_id: session.manifest().boot_id.clone(),
            barrier: after_recovery_barrier,
            identity_assessment: after_recovery_identity,
        });
        let recovery_digest =
            write_json_new(&output.join(RECOVERY_EVIDENCE_FILE), &recovery_evidence)?;
        sync_directory(&output)?;
        machine.mark_restore_complete()?;
        let restore_complete = RestoreCompleteMessage {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: "RESTORE_COMPLETE".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id.clone(),
            command_seq: 2,
            nonce: pre_restore_nonce,
            recovery_sha256: recovery_digest.sha256,
        };
        emit_line(&restore_complete)?;

        session.drain_open_recorders_at_boundary()?;
        let c_raw = session.capture_recovery_endpoint_snapshots("C")?;
        let (c_barrier, c_validation) = session.validate_recovery_boundary("SNAPSHOT_C")?;
        let c_barrier_digest = write_json_new(&output.join(POST_RESTORE_BARRIER_FILE), &c_barrier)?;
        let c_validation_digest =
            write_json_new(&output.join(POST_RESTORE_VALIDATION_FILE), &c_validation)?;
        let c = commit_envelope(
            &session,
            &output,
            RecoverySnapshotPhase::C,
            &c_raw,
            &c_barrier_digest.sha256,
            &c_validation_digest.sha256,
        )?;
        let c_digest = write_json_canonical_new(&output.join(RECOVERY_SNAPSHOT_C_FILE), &c)?;
        sync_directory(&output)?;
        machine.mark_c_committed()?;
        let snapshot_c = SnapshotCMessage {
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: "SNAPSHOT_C".to_owned(),
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id,
            command_seq: machine.expected_command_seq(),
            nonce: machine.nonce().to_owned(),
            snapshot_c_sha256: c_digest.sha256.clone(),
        };
        emit_line(&snapshot_c)?;

        let finish_command = next_command(&mut session, &commands)?;
        machine.accept_finish(&finish_command)?;
        finalize(
            &mut session,
            &config,
            &output,
            [&a_raw, &b_raw, &c_raw],
            [&a, &b, &c],
            [&a_digest, &b_digest, &c_digest],
            &recovery_evidence,
            RecoveryControlTranscript {
                schema_version: 1,
                ready,
                agent_started_command: agent_command,
                agent_started,
                pre_restore_command,
                snapshot_b,
                restore_complete,
                snapshot_c,
                finish_command,
            },
        )?;
        machine.mark_finished()?;
        Ok(())
    })();
    if let Err(error) = &run_result {
        // A missing endpoint cannot be fabricated as C. Preserve the
        // original error and mark this as partial, non-verifiable evidence;
        // the normal closed-set verifier must never accept this directory.
        if !output.join(RECOVERY_ARTIFACT_MANIFEST_FILE).exists() {
            let abort_result =
                RecoveryAbortEvidence::from_failure(&config, &output, &format!("{error:#}"))
                    .and_then(|abort| write_json_new(&output.join(RECOVERY_ABORT_FILE), &abort))
                    .and_then(|_| sync_directory(&output));
            if let Err(abort_error) = abort_result {
                eprintln!("deployment-observe: could not persist partial recovery failure: {abort_error:#}");
            }
        }
    }
    run_result
}

fn spawn_command_reader() -> Receiver<std::result::Result<Vec<u8>, String>> {
    let (sender, receiver) = mpsc::sync_channel(4);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut lock = stdin.lock();
        loop {
            let result = read_protocol_line(&mut lock).map_err(|error| format!("{error:#}"));
            let failed = result.is_err();
            if sender.send(result).is_err() || failed {
                break;
            }
        }
    });
    receiver
}

fn next_command(
    session: &mut DeploymentSession,
    receiver: &Receiver<std::result::Result<Vec<u8>, String>>,
) -> Result<RecoveryControlCommand> {
    loop {
        match receiver.try_recv() {
            Ok(Ok(line)) => {
                let command: RecoveryControlCommand =
                    serde_json::from_slice(&line).context("parse recovery control command")?;
                command.validate()?;
                return Ok(command);
            }
            Ok(Err(error)) => bail!("read recovery control command: {error}"),
            Err(TryRecvError::Disconnected) => bail!("recovery control reader terminated"),
            Err(TryRecvError::Empty) => {
                session.poll_once()?;
            }
        }
    }
}

fn sha256_json<T: Serialize>(value: &T) -> Result<String> {
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(value)?)))
}

fn snapshot_id(config: &DeploymentObserverConfig, phase: RecoverySnapshotPhase) -> Result<String> {
    let recovery = config
        .recovery
        .as_ref()
        .context("recovery config disappeared")?;
    let identity = (
        "DEPLOYMENT_RECOVERY_SNAPSHOT_V1",
        &config.run_id,
        config.epoch,
        &recovery.checkpoint_id,
        &recovery.recovery_id,
        phase.as_str(),
    );
    Ok(format!("{}-{}", phase.as_str(), sha256_json(&identity)?))
}

fn raw_name(domain: RecoveryDomain, phase: RecoverySnapshotPhase) -> &'static str {
    match (domain, phase) {
        (RecoveryDomain::Bpf, RecoverySnapshotPhase::A) => "bpf-state-s0.json",
        (RecoveryDomain::Bpf, RecoverySnapshotPhase::B) => BPF_B_FILE,
        (RecoveryDomain::Bpf, RecoverySnapshotPhase::C) => BPF_C_FILE,
        (RecoveryDomain::Filesystem, RecoverySnapshotPhase::A) => "filesystem-state-s0.json",
        (RecoveryDomain::Filesystem, RecoverySnapshotPhase::B) => FS_B_FILE,
        (RecoveryDomain::Filesystem, RecoverySnapshotPhase::C) => FS_C_FILE,
        (RecoveryDomain::Sysctl, RecoverySnapshotPhase::A) => "linux-state-s0.json",
        (RecoveryDomain::Sysctl, RecoverySnapshotPhase::B) => LINUX_B_FILE,
        (RecoveryDomain::Sysctl, RecoverySnapshotPhase::C) => LINUX_C_FILE,
        _ => unreachable!("raw artifact name requires BPF, filesystem, or Linux representative"),
    }
}

fn raw_digest<T: Serialize>(
    output: &Path,
    name: &str,
    phase: RecoverySnapshotPhase,
    snapshot: &T,
) -> Result<ArtifactDigest> {
    if phase == RecoverySnapshotPhase::A {
        digest_file(&output.join(name), name)
    } else {
        write_json_compact_new(&output.join(name), snapshot)
    }
}

fn commit_envelope(
    session: &DeploymentSession,
    output: &Path,
    phase: RecoverySnapshotPhase,
    raw: &RecoveryEndpointSnapshots,
    barrier_sha256: &str,
    validation_sha256: &str,
) -> Result<RecoverySnapshotEnvelope> {
    let expected_raw_phase = match phase {
        RecoverySnapshotPhase::A => "S0",
        RecoverySnapshotPhase::B => "B",
        RecoverySnapshotPhase::C => "C",
    };
    if raw.raw_phase != expected_raw_phase {
        bail!("recovery raw snapshot phase does not match the committed envelope phase");
    }
    let bpf = match (session.config().bpf_state_scope.as_ref(), raw.bpf.as_ref()) {
        (Some(_), Some(snapshot)) => {
            if snapshot.phase != raw.raw_phase {
                bail!("BPF raw snapshot has the wrong phase");
            }
            let name = raw_name(RecoveryDomain::Bpf, phase);
            let digest = raw_digest(output, name, phase, snapshot)?;
            Some(SnapshotDomainBinding::new(
                phase,
                &raw.raw_phase,
                name,
                digest.size_bytes,
                digest.sha256,
                &snapshot.snapshot_id,
                vec![RecoveryDomain::Bpf],
            )?)
        }
        (None, None) => None,
        _ => bail!("BPF raw snapshot presence differs from configured scope"),
    };
    let filesystem = match (
        session.config().filesystem_state_scope.as_ref(),
        raw.filesystem.as_ref(),
    ) {
        (Some(_), Some(snapshot)) => {
            let name = raw_name(RecoveryDomain::Filesystem, phase);
            let digest = raw_digest(output, name, phase, snapshot)?;
            Some(SnapshotDomainBinding::new(
                phase,
                &raw.raw_phase,
                name,
                digest.size_bytes,
                digest.sha256,
                &snapshot.snapshot_id,
                vec![RecoveryDomain::Filesystem],
            )?)
        }
        (None, None) => None,
        _ => bail!("filesystem raw snapshot presence differs from configured scope"),
    };
    let linux = match (
        session.config().linux_state_scope.as_ref(),
        raw.linux.as_ref(),
    ) {
        (Some(_), Some(snapshot)) => {
            let name = raw_name(RecoveryDomain::Sysctl, phase);
            let digest = raw_digest(output, name, phase, snapshot)?;
            let mut domains = Vec::new();
            if snapshot.sysctl.is_some() {
                domains.push(RecoveryDomain::Sysctl);
            }
            if snapshot.mounts.is_some() {
                domains.push(RecoveryDomain::Mount);
            }
            if snapshot.network.is_some() {
                domains.push(RecoveryDomain::Network);
            }
            if snapshot.modules.is_some() {
                domains.push(RecoveryDomain::Modules);
            }
            if snapshot.process_residual.is_some() {
                domains.push(RecoveryDomain::ProcessResidual);
            }
            Some(SnapshotDomainBinding::new(
                phase,
                &raw.raw_phase,
                name,
                digest.size_bytes,
                digest.sha256,
                &snapshot.snapshot_id,
                domains,
            )?)
        }
        (None, None) => None,
        _ => bail!("Linux raw snapshot presence differs from configured scope"),
    };
    RecoverySnapshotEnvelope::from_deployment_manifest(
        phase,
        &session.config().run_id,
        session.config().epoch,
        &session.config().recovery.as_ref().unwrap().checkpoint_id,
        &session.config().recovery.as_ref().unwrap().recovery_id,
        snapshot_id(session.config(), phase)?,
        raw.captured_started_unix_ns,
        raw.captured_completed_unix_ns,
        session.manifest(),
        session.cgroup_scope_capability().clone(),
        barrier_sha256,
        validation_sha256,
        bpf,
        filesystem,
        linux,
    )
}

struct PairComparisons {
    bpf: Option<BpfVerdict>,
    filesystem: Option<FilesystemComparison>,
    linux: Option<StateComparison>,
}

impl PairComparisons {
    fn borrowed(&self) -> RecoveryComparisonSet<'_> {
        RecoveryComparisonSet {
            bpf: self.bpf.as_ref(),
            filesystem: self.filesystem.as_ref(),
            linux: self.linux.as_ref(),
        }
    }
}

fn filesystem_phase(raw: &str) -> Result<FilesystemPhase> {
    match raw {
        "S0" => Ok(FilesystemPhase::S0),
        "B" => Ok(FilesystemPhase::B),
        "C" => Ok(FilesystemPhase::C),
        _ => bail!("unexpected filesystem raw phase in recovery pair"),
    }
}

fn linux_phase(raw: &str) -> Result<LinuxPhase> {
    match raw {
        "S0" => Ok(LinuxPhase::S0),
        "B" => Ok(LinuxPhase::B),
        "C" => Ok(LinuxPhase::C),
        _ => bail!("unexpected Linux raw phase in recovery pair"),
    }
}

fn compare_pair(
    before: &RecoveryEndpointSnapshots,
    after: &RecoveryEndpointSnapshots,
) -> Result<PairComparisons> {
    let bpf = match (&before.bpf, &after.bpf) {
        (Some(left), Some(right)) => Some(compare_bpf_endpoints_with_phases(
            left,
            right,
            &before.raw_phase,
            &after.raw_phase,
        )?),
        (None, None) => None,
        _ => bail!("BPF state enablement changed between recovery snapshots"),
    };
    let filesystem = match (&before.filesystem, &after.filesystem) {
        (Some(left), Some(right)) => Some(compare_filesystem_phases(
            left,
            right,
            filesystem_phase(&before.raw_phase)?,
            filesystem_phase(&after.raw_phase)?,
            None,
        )?),
        (None, None) => None,
        _ => bail!("filesystem state enablement changed between recovery snapshots"),
    };
    let linux = match (&before.linux, &after.linux) {
        (Some(left), Some(right)) => Some(compare_linux_phases(
            left,
            right,
            linux_phase(&before.raw_phase)?,
            linux_phase(&after.raw_phase)?,
        )?),
        (None, None) => None,
        _ => bail!("Linux state enablement changed between recovery snapshots"),
    };
    Ok(PairComparisons {
        bpf,
        filesystem,
        linux,
    })
}

fn raw_borrowed(raw: &RecoveryEndpointSnapshots) -> RecoveryRawSnapshotSet<'_> {
    RecoveryRawSnapshotSet {
        bpf: raw.bpf.as_ref(),
        filesystem: raw.filesystem.as_ref(),
        linux: raw.linux.as_ref(),
    }
}

#[allow(clippy::too_many_arguments)]
fn finalize(
    session: &mut DeploymentSession,
    config: &DeploymentObserverConfig,
    output: &Path,
    raw: [&RecoveryEndpointSnapshots; 3],
    envelopes: [&RecoverySnapshotEnvelope; 3],
    snapshot_digests: [&ArtifactDigest; 3],
    recovery: &RecoveryEvidence,
    transcript: RecoveryControlTranscript,
) -> Result<()> {
    let mut recorder_health = session.finalize_recovery_recorders()?;
    recorder_health.endpoint_capture_telemetry = raw
        .iter()
        .map(|snapshot| snapshot.telemetry.clone())
        .collect();
    write_json_new(
        &output.join(RECOVERY_RECORDER_HEALTH_FILE),
        &recorder_health,
    )?;

    let agent = compare_pair(raw[0], raw[1])?;
    let recovery_pair = compare_pair(raw[1], raw[2])?;
    let residual = compare_pair(raw[0], raw[2])?;
    let mut external_reasons = Vec::new();
    if !recovery.success {
        external_reasons.push("external recovery command did not complete successfully".to_owned());
    }
    if !recorder_health.complete {
        external_reasons.extend(recorder_health.reasons.iter().cloned());
    }
    external_reasons.sort();
    external_reasons.dedup();
    let verdict = build_recovery_verdict_report_with_raw(
        RecoverySnapshotTriplet {
            a: envelopes[0],
            b: envelopes[1],
            c: envelopes[2],
        },
        RecoveryRawSnapshotTriplet {
            a: raw_borrowed(raw[0]),
            b: raw_borrowed(raw[1]),
            c: raw_borrowed(raw[2]),
        },
        RecoveryComparisonTriplet {
            agent: agent.borrowed(),
            recovery: recovery_pair.borrowed(),
            residual: residual.borrowed(),
        },
        &external_reasons,
    )?;
    write_json_canonical_new(
        &output.join(RECOVERY_AGENT_DELTA_FILE),
        &verdict.agent_delta,
    )?;
    write_json_canonical_new(
        &output.join(RECOVERY_RECOVERY_DELTA_FILE),
        &verdict.recovery_delta,
    )?;
    write_json_canonical_new(
        &output.join(RECOVERY_RESIDUAL_DELTA_FILE),
        &verdict.residual_delta,
    )?;
    let verdict_digest = write_json_canonical_new(&output.join(RECOVERY_VERDICT_FILE), &verdict)?;
    write_json_canonical_new(&output.join(RECOVERY_CONTROL_TRANSCRIPT_FILE), &transcript)?;

    let names = recovery_committed_artifacts(config)?;
    let mut artifacts = names
        .iter()
        .map(|name| digest_file(&output.join(name), name))
        .collect::<Result<Vec<_>>>()?;
    artifacts.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let actual_names = fs::read_dir(output)?
        .map(|entry| {
            let entry = entry?;
            entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("recovery artifact name is not UTF-8"))
        })
        .collect::<Result<std::collections::BTreeSet<_>>>()?;
    let expected_names = names
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    if actual_names != expected_names {
        bail!("recovery evidence directory contains an unexpected or missing artifact");
    }
    let recovery_config = config
        .recovery
        .as_ref()
        .context("v3 recovery contract disappeared")?;
    let manifest = RecoveryArtifactManifest {
        protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        run_id: config.run_id.clone(),
        epoch: config.epoch,
        checkpoint_id: recovery_config.checkpoint_id.clone(),
        recovery_id: recovery_config.recovery_id.clone(),
        deployment_scope_sha256: session.manifest().scope_sha256.clone(),
        recovery_config_sha256: sha256_json(recovery_config)?,
        recovery_verdict_sha256: verdict_digest.sha256.clone(),
        snapshot_a_sha256: snapshot_digests[0].sha256.clone(),
        snapshot_b_sha256: snapshot_digests[1].sha256.clone(),
        snapshot_c_sha256: snapshot_digests[2].sha256.clone(),
        committed_artifact_total_bytes: checked_artifact_total_bytes(&artifacts)?,
        artifacts,
    };
    manifest.validate(config)?;
    let manifest_digest =
        write_json_canonical_new(&output.join(RECOVERY_ARTIFACT_MANIFEST_FILE), &manifest)?;
    sync_directory(output)?;
    let terminal = RecoveryTerminalMessage {
        protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
        status: "FINISHED".to_owned(),
        run_id: config.run_id.clone(),
        epoch: config.epoch,
        checkpoint_id: recovery_config.checkpoint_id.clone(),
        recovery_id: recovery_config.recovery_id.clone(),
        command_seq: 3,
        nonce: transcript.snapshot_c.nonce,
        verdict_sha256: verdict_digest.sha256,
        artifact_manifest_sha256: manifest_digest.sha256,
    };
    emit_line(&terminal)
}
