// SPDX-License-Identifier: GPL-2.0-only

use crate::{harness, run};
use anyhow::{bail, Context, Result};
use bpf_harness_auth::{
    canonical_json_sha256, AuthenticatedHarnessTranscript, ExpectedHarnessPolicy,
    HarnessPostEvidence, HarnessPreS1Evidence, HarnessRunBinding, HARNESS_PROTOCOL_VERSION,
};
use bpf_observer_comparator::compare;
use bpf_observer_oracle::{validate_claim_scope_exclusions, validate_snapshot_resource_bounds};
use bpf_observer_recorder::{
    recover_wal_reader, FLAG_COMMON_ATTRS, FLAG_PENDING_DELETE_FAILED, FLAG_PENDING_INSERT_FAILED,
    FLAG_PENDING_MISSING, FLAG_PENDING_POISONED,
};
use bpf_observer_schema::{
    ArtifactDigest, EnvironmentFingerprint, EventKind, EvidenceEvent, EvidenceHealth,
    QuiescenceReport, RunManifest, RunStatus, Snapshot, StateVerdict, Verdict,
    FINALIZED_RUN_ARTIFACTS_V1, MAX_HEALTH_JSON_BYTES, MAX_MANIFEST_JSON_BYTES,
    MAX_QUIESCENCE_JSON_BYTES, MAX_RAW_JSONL_BYTES, MAX_RAW_WAL_BYTES, MAX_RECORDED_EVENTS,
    MAX_SNAPSHOT_JSON_BYTES, MAX_VERDICT_JSON_BYTES, MAX_WORKLOAD_OUTPUT_BYTES, SCHEMA_VERSION,
};
use serde::{de::DeserializeOwned, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct HarnessVerificationPolicy {
    pub public_key: PathBuf,
    pub policy_id: String,
    pub expected_policy_sha256: String,
    pub kernel_identity: String,
}

#[derive(Debug, Serialize)]
pub struct VerificationReport {
    pub schema_version: u32,
    pub run_id: String,
    pub run_epoch: u64,
    pub manifest_sha256: String,
    pub artifacts_verified: usize,
    pub events_verified: usize,
    pub recorder_object_sha256: String,
    pub recorder_digest_policy_match: bool,
    pub harness_authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_public_key_fingerprint_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_policy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub harness_policy_sha256: Option<String>,
    pub evidence_complete: bool,
    pub state_verdict: StateVerdict,
}

pub fn verify_run(
    directory: &Path,
    expected_recorder_sha256: &str,
    harness_policy: Option<&HarnessVerificationPolicy>,
) -> Result<VerificationReport> {
    validate_sha256(expected_recorder_sha256, "trusted recorder policy")?;
    let (manifest, manifest_state, manifest_sha256): (RunManifest, _, _) =
        read_manifest(directory)?;
    validate_manifest(&manifest)?;
    let recorder_object_sha256 = manifest
        .environment
        .recorder_object_sha256
        .as_deref()
        .context("manifest omitted the loaded recorder digest")?;
    if recorder_object_sha256 != expected_recorder_sha256 {
        bail!("manifest recorder digest does not match trusted policy");
    }
    let recorder_object_sha256 = recorder_object_sha256.to_owned();
    let mut artifacts = VerifiedArtifacts::new(directory, &manifest)?;
    run::validate_observe_scope(&manifest.requested_scope)?;
    if manifest.requested_scope != manifest.effective_scope {
        bail!("this producer does not support requested/effective scope reduction");
    }

    let s0: Snapshot = artifacts.read_json("s0.json", MAX_SNAPSHOT_JSON_BYTES)?;
    validate_snapshot_binding(&manifest, &s0, "S0")?;
    validate_snapshot_resource_bounds(&s0).context("validate S0 producer snapshot contract")?;

    let s1: Snapshot = artifacts.read_json("s1.json", MAX_SNAPSHOT_JSON_BYTES)?;
    validate_snapshot_binding(&manifest, &s1, "S1")?;
    validate_snapshot_resource_bounds(&s1).context("validate S1 producer snapshot contract")?;

    let health: EvidenceHealth = artifacts.read_json("health.json", MAX_HEALTH_JSON_BYTES)?;
    let canary_health: EvidenceHealth =
        artifacts.read_json("canary-health.json", MAX_HEALTH_JSON_BYTES)?;
    let quiescence: QuiescenceReport =
        artifacts.read_json("quiescence.json", MAX_QUIESCENCE_JSON_BYTES)?;
    validate_canary_health(&canary_health)?;
    validate_finalized_health_shape(&health)?;
    let harness_identity = authenticate_harness_run(
        &manifest,
        &s0,
        &s1,
        &health,
        &canary_health,
        &quiescence,
        harness_policy,
    )?;
    let harness_authenticated = harness_identity.is_some();
    validate_producer_snapshot_modes(&manifest, &s0, harness_authenticated)?;
    validate_producer_snapshot_modes(&manifest, &s1, harness_authenticated)?;

    let events = artifacts.read_events("raw-events.jsonl", MAX_RAW_JSONL_BYTES)?;
    if events.len() as u64 > MAX_RECORDED_EVENTS {
        bail!("event stream exceeds the producer's hard event-count limit");
    }
    let recovered = artifacts.read_wal("raw-events.bin", MAX_RAW_WAL_BYTES)?;
    if recovered.truncated_tail {
        bail!("raw-events.bin has a truncated final frame");
    }
    if recovered.events.len() != events.len() {
        bail!(
            "WAL/JSONL event count mismatch: {} != {}",
            recovered.events.len(),
            events.len()
        );
    }
    for (index, (raw, json)) in recovered.events.iter().zip(&events).enumerate() {
        if raw.to_schema(&manifest.run_id) != *json {
            bail!("WAL/JSONL event mismatch at record {index}");
        }
    }

    {
        let canary_epoch = run::canary_epoch(manifest.run_epoch);
        let mut by_epoch: BTreeMap<u64, Vec<&EvidenceEvent>> = BTreeMap::new();
        for event in &events {
            if event.run_id != manifest.run_id || event.cgroup_id != manifest.cgroup_id {
                bail!("event is not bound to the finalized run ID/cgroup");
            }
            if event.run_epoch != manifest.run_epoch && event.run_epoch != canary_epoch {
                bail!("event has an unrecognized run epoch {}", event.run_epoch);
            }
            by_epoch.entry(event.run_epoch).or_default().push(event);
        }
        let formal_events = by_epoch.remove(&manifest.run_epoch).unwrap_or_default();
        let canary_events = by_epoch.remove(&canary_epoch).unwrap_or_default();
        if !by_epoch.is_empty() {
            bail!("event stream contains unexpected epochs");
        }
        validate_event_accounting(
            &formal_events,
            &health,
            &manifest.effective_scope.allowed_bpf_commands,
            false,
        )?;
        validate_event_accounting(
            &canary_events,
            &canary_health,
            &manifest.effective_scope.allowed_bpf_commands,
            true,
        )?;
    }
    let events_verified = events.len();
    drop(recovered);
    drop(events);

    let mut expected_verdict = compare(&s0, &s1, &health, quiescence)?;
    run::annotate_observe_verdict(&mut expected_verdict);
    drop(s0);
    drop(s1);

    // Load the potentially large derived verdict only after releasing the
    // endpoint snapshots and event streams. This keeps verifier peak memory
    // bounded by one comparison phase instead of all artifacts combined.
    let stored_verdict: Verdict = artifacts.read_json("verdict.json", MAX_VERDICT_JSON_BYTES)?;
    if stored_verdict.run_status != RunStatus::Provisional {
        bail!("verdict must remain PROVISIONAL; only manifest.json commits the run");
    }
    if stored_verdict != expected_verdict {
        bail!("verdict.json does not recompute from the bound S0/S1/health inputs");
    }
    let state_verdict = stored_verdict.state_verdict.clone();
    let evidence_complete = health.is_complete();
    drop(stored_verdict);
    drop(expected_verdict);

    artifacts.verify_only("workload.stdout", MAX_WORKLOAD_OUTPUT_BYTES)?;
    artifacts.verify_only("workload.stderr", MAX_WORKLOAD_OUTPUT_BYTES)?;
    artifacts.finish()?;
    verify_manifest_path(directory, manifest_state)?;

    Ok(VerificationReport {
        schema_version: SCHEMA_VERSION,
        run_id: manifest.run_id,
        run_epoch: manifest.run_epoch,
        manifest_sha256,
        artifacts_verified: FINALIZED_RUN_ARTIFACTS_V1.len(),
        events_verified,
        recorder_object_sha256,
        recorder_digest_policy_match: true,
        harness_authenticated,
        harness_public_key_fingerprint_sha256: harness_identity
            .as_ref()
            .map(|identity| identity.public_key_fingerprint_sha256.clone()),
        harness_policy_id: harness_identity
            .as_ref()
            .map(|identity| identity.policy_id.clone()),
        harness_policy_sha256: harness_identity
            .as_ref()
            .map(|identity| identity.policy_sha256.clone()),
        evidence_complete,
        state_verdict,
    })
}

fn validate_manifest(manifest: &RunManifest) -> Result<()> {
    if manifest.schema_version != SCHEMA_VERSION {
        bail!("unsupported manifest schema {}", manifest.schema_version);
    }
    if manifest.run_status != RunStatus::Finalized || manifest.finalized_unix_ns.is_none() {
        bail!("manifest is not a committed FINALIZED run");
    }
    run::validate_run_id(&manifest.run_id).context("validate manifest run_id")?;
    if manifest.run_id.is_empty()
        || manifest.run_epoch == 0
        || manifest.cgroup_id == 0
        || manifest.started_unix_ns == 0
        || manifest.finalized_unix_ns == Some(0)
        || manifest.environment.boot_id.is_empty()
        || manifest.environment.kernel_release.is_empty()
        || manifest.environment.observer_version != env!("CARGO_PKG_VERSION")
        || manifest.workload.first().map(String::is_empty) != Some(false)
        || manifest
            .workload
            .iter()
            .any(|argument| argument.contains('\0'))
    {
        bail!("manifest has an invalid run identity");
    }
    if manifest.finalized_unix_ns < Some(manifest.started_unix_ns) {
        bail!("manifest finalization time precedes its start time");
    }
    let cgroup_path = Path::new(&manifest.cgroup_path);
    run::validate_cgroup_root(cgroup_path).context("validate manifest cgroup_path")?;
    if cgroup_path.file_name().and_then(|name| name.to_str()) != Some(manifest.run_id.as_str()) {
        bail!("manifest cgroup_path is not bound to run_id");
    }
    let recorder_sha256 = manifest
        .environment
        .recorder_object_sha256
        .as_deref()
        .context("manifest omitted the loaded recorder digest")?;
    validate_sha256(recorder_sha256, "recorder object")?;
    if let Some(btf_sha256) = manifest.environment.kernel_btf_sha256.as_deref() {
        validate_sha256(btf_sha256, "kernel BTF")?;
    }
    validate_harness_environment(&manifest.environment)?;
    if !manifest.scope_accepted {
        bail!("manifest does not accept its effective claim scope");
    }
    validate_claim_scope_exclusions(&manifest.effective_scope, &manifest.observer_exclusions)
        .context("validate manifest scope exclusions")?;
    Ok(())
}

fn validate_harness_environment(environment: &EnvironmentFingerprint) -> Result<bool> {
    let presence = [
        environment.observer_executable_sha256.is_some(),
        environment.workload_executable_sha256.is_some(),
        environment.harness_kernel_identity.is_some(),
        environment.harness_policy_id.is_some(),
        environment.harness_policy_sha256.is_some(),
        environment.harness_public_key_fingerprint_sha256.is_some(),
    ];
    let present = presence.iter().filter(|value| **value).count();
    if present != 0 && present != presence.len() {
        bail!("authenticated harness environment fields must be all present or all absent");
    }
    if present == 0 {
        return Ok(false);
    }

    validate_sha256(
        environment
            .observer_executable_sha256
            .as_deref()
            .context("authenticated environment omitted Observer digest")?,
        "Observer executable",
    )?;
    validate_sha256(
        environment
            .workload_executable_sha256
            .as_deref()
            .context("authenticated environment omitted workload digest")?,
        "workload executable",
    )?;
    validate_sha256(
        environment
            .harness_policy_sha256
            .as_deref()
            .context("authenticated environment omitted policy digest")?,
        "harness policy",
    )?;
    validate_sha256(
        environment
            .harness_public_key_fingerprint_sha256
            .as_deref()
            .context("authenticated environment omitted public-key fingerprint")?,
        "harness public-key fingerprint",
    )?;
    validate_harness_text(
        environment
            .harness_kernel_identity
            .as_deref()
            .context("authenticated environment omitted kernel identity")?,
        "harness kernel identity",
    )?;
    validate_harness_text(
        environment
            .harness_policy_id
            .as_deref()
            .context("authenticated environment omitted policy ID")?,
        "harness policy ID",
    )?;
    Ok(true)
}

fn validate_harness_text(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        bail!("{label} must contain 1..=4096 non-NUL UTF-8 bytes");
    }
    Ok(())
}

fn manifest_artifact_sha256<'a>(manifest: &'a RunManifest, name: &str) -> Result<&'a str> {
    manifest
        .artifacts
        .get(name)
        .map(|artifact| artifact.sha256.as_str())
        .with_context(|| format!("manifest omitted authenticated artifact {name}"))
}

fn authenticate_harness_run(
    manifest: &RunManifest,
    s0: &Snapshot,
    s1: &Snapshot,
    health: &EvidenceHealth,
    _canary_health: &EvidenceHealth,
    quiescence: &QuiescenceReport,
    external_policy: Option<&HarnessVerificationPolicy>,
) -> Result<Option<harness::AuthenticatedHarnessIdentity>> {
    let manifest_has_authentication = validate_harness_environment(&manifest.environment)?;
    let report_has_authentication = quiescence.authentication.is_some();

    let policy = match (report_has_authentication, external_policy) {
        (false, Some(_)) => {
            bail!("an external harness policy was supplied but the run has no authenticated transcript")
        }
        (true, None) => {
            bail!("authenticated quiescence requires an external harness verification policy")
        }
        (false, None) => {
            if manifest_has_authentication {
                bail!("manifest claims authenticated harness metadata without a transcript");
            }
            harness::validate_persisted_safe_report(quiescence)
                .context("validate unauthenticated persisted quiescence report")?;
            return Ok(None);
        }
        (true, Some(policy)) => policy,
    };
    if !manifest_has_authentication {
        bail!("authenticated transcript has no complete manifest environment binding");
    }

    validate_harness_text(&policy.kernel_identity, "trusted harness kernel identity")?;
    let expected_policy = ExpectedHarnessPolicy {
        policy_id: policy.policy_id.clone(),
        policy_sha256: policy.expected_policy_sha256.clone(),
    };
    expected_policy
        .validate()
        .context("validate external harness policy identity")?;

    let environment = &manifest.environment;
    if environment.harness_kernel_identity.as_deref() != Some(policy.kernel_identity.as_str()) {
        bail!("manifest harness kernel identity does not match external policy");
    }
    if environment.harness_policy_id.as_deref() != Some(policy.policy_id.as_str()) {
        bail!("manifest harness policy ID does not match external policy");
    }
    if environment.harness_policy_sha256.as_deref() != Some(policy.expected_policy_sha256.as_str())
    {
        bail!("manifest harness policy digest does not match external policy");
    }

    // The nonce is the sole value recovered from the untrusted transcript.
    // Every other binding field is independently reconstructed from the
    // finalized manifest, canonical scope/exclusions, and endpoint snapshots.
    let transcript: AuthenticatedHarnessTranscript = serde_json::from_value(
        quiescence
            .authentication
            .as_ref()
            .context("authenticated quiescence omitted its transcript")?
            .clone(),
    )
    .context("decode persisted authenticated harness transcript")?;
    let binding = HarnessRunBinding {
        protocol_version: HARNESS_PROTOCOL_VERSION,
        nonce_hex: transcript.pre_s0.binding.nonce_hex,
        run_id: manifest.run_id.clone(),
        run_epoch: manifest.run_epoch,
        cgroup_id: manifest.cgroup_id,
        cgroup_path: manifest.cgroup_path.clone(),
        boot_id: manifest.environment.boot_id.clone(),
        kernel_identity: policy.kernel_identity.clone(),
        observer_sha256: environment
            .observer_executable_sha256
            .clone()
            .context("authenticated environment omitted Observer digest")?,
        recorder_sha256: environment
            .recorder_object_sha256
            .clone()
            .context("authenticated environment omitted recorder digest")?,
        scope_sha256: canonical_json_sha256(&manifest.effective_scope)
            .context("canonicalize authenticated claim scope")?,
        observer_exclusions_sha256: canonical_json_sha256(&manifest.observer_exclusions)
            .context("canonicalize authenticated observer exclusions")?,
        workload_argv: manifest.workload.clone(),
        workload_executable_sha256: environment
            .workload_executable_sha256
            .clone()
            .context("authenticated environment omitted workload digest")?,
        s0_snapshot_id: s0.snapshot_id.clone(),
        s1_snapshot_id: s1.snapshot_id.clone(),
    };

    let pre_s1 = HarnessPreS1Evidence {
        // The producer writes the final health bytes before PRE_S1 and refuses
        // any counter change across the frozen S1 capture boundary.
        pre_health_sha256: manifest_artifact_sha256(manifest, "health.json")?.to_owned(),
        cgroup_empty: true,
        cgroup_frozen: true,
    };
    let post = HarnessPostEvidence {
        s0_sha256: manifest_artifact_sha256(manifest, "s0.json")?.to_owned(),
        s1_sha256: manifest_artifact_sha256(manifest, "s1.json")?.to_owned(),
        health_sha256: manifest_artifact_sha256(manifest, "health.json")?.to_owned(),
        canary_health_sha256: manifest_artifact_sha256(manifest, "canary-health.json")?.to_owned(),
        raw_events_wal_sha256: manifest_artifact_sha256(manifest, "raw-events.bin")?.to_owned(),
        raw_events_jsonl_sha256: manifest_artifact_sha256(manifest, "raw-events.jsonl")?.to_owned(),
        workload_stdout_sha256: manifest_artifact_sha256(manifest, "workload.stdout")?.to_owned(),
        workload_stderr_sha256: manifest_artifact_sha256(manifest, "workload.stderr")?.to_owned(),
        workload_exit_code: manifest
            .workload_exit_code
            .context("authenticated manifest omitted normal workload exit code")?,
        workload_signal: manifest.workload_signal,
        outside_cgroup_syscall_attempted: health.outside_cgroup_syscall_attempted,
        recorder_drain_complete: health.drain_completed,
        producer_barrier_complete: health.producer_barrier_complete,
        wal_durable: health.wal_durable,
        in_flight_bpf_barrier_complete: true,
    };
    let identity = harness::validate_authenticated_report(
        quiescence,
        &policy.public_key,
        &expected_policy,
        &binding,
        manifest_artifact_sha256(manifest, "s0.json")?,
        &pre_s1,
        &post,
    )
    .context("authenticate finalized harness transcript")?;

    if environment.harness_public_key_fingerprint_sha256.as_deref()
        != Some(identity.public_key_fingerprint_sha256.as_str())
        || environment.harness_policy_id.as_deref() != Some(identity.policy_id.as_str())
        || environment.harness_policy_sha256.as_deref() != Some(identity.policy_sha256.as_str())
    {
        bail!("authenticated harness identity does not match manifest environment");
    }
    Ok(Some(identity))
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} digest is not canonical SHA-256");
    }
    Ok(())
}

fn verify_artifact_names(directory: &Path, manifest: &RunManifest) -> Result<()> {
    let expected = FINALIZED_RUN_ARTIFACTS_V1
        .iter()
        .map(|name| (*name).to_string())
        .collect::<BTreeSet<_>>();
    let actual = manifest.artifacts.keys().cloned().collect::<BTreeSet<_>>();
    if actual != expected {
        bail!("manifest artifact set is not the closed v1 set");
    }
    let mut allowed_directory_entries = expected;
    allowed_directory_entries.insert("manifest.json".into());
    for entry in fs::read_dir(directory)
        .with_context(|| format!("enumerate run directory {}", directory.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("run directory contains a non-UTF-8 entry name"))?;
        if !allowed_directory_entries.contains(&name) {
            bail!("run directory contains unbound entry {name:?}");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileState {
    dev: u64,
    ino: u64,
    len: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

struct ArtifactReader {
    name: String,
    file: File,
    before: fs::Metadata,
    expected: ArtifactDigest,
    hasher: Sha256,
    bytes_read: u64,
}

impl ArtifactReader {
    fn open(
        directory: &Path,
        name: &str,
        expected: &ArtifactDigest,
        max_bytes: u64,
    ) -> Result<Self> {
        if expected.sha256.len() != 64
            || !expected
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        {
            bail!("manifest has an invalid SHA-256 for {name}");
        }
        if expected.size_bytes > max_bytes {
            bail!("artifact {name} exceeds its {max_bytes}-byte verification limit");
        }
        let path = directory.join(name);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("open artifact {}", path.display()))?;
        let before = file
            .metadata()
            .with_context(|| format!("inspect artifact {}", path.display()))?;
        if !before.file_type().is_file() || before.nlink() != 1 {
            bail!("artifact {name} must be a singly linked regular file");
        }
        if before.len() != expected.size_bytes {
            bail!("artifact {name} size does not match manifest");
        }
        Ok(Self {
            name: name.into(),
            file,
            before,
            expected: expected.clone(),
            hasher: Sha256::new(),
            bytes_read: 0,
        })
    }

    fn finish(mut self) -> Result<FileState> {
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = self.read(&mut buffer)?;
            if count == 0 {
                break;
            }
        }
        let after = self.file.metadata()?;
        if !same_file_state(&self.before, &after) {
            bail!("artifact {} changed while it was consumed", self.name);
        }
        if self.bytes_read != self.expected.size_bytes {
            bail!("artifact {} byte count does not match manifest", self.name);
        }
        let actual = format!("{:x}", self.hasher.finalize());
        if actual != self.expected.sha256 {
            bail!("artifact {} SHA-256 does not match manifest", self.name);
        }
        Ok(file_state(&after))
    }
}

impl Read for ArtifactReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self.file.read(output)?;
        if count != 0 {
            self.bytes_read = self
                .bytes_read
                .checked_add(count as u64)
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "byte count overflow"))?;
            if self.bytes_read > self.expected.size_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "artifact grew beyond its manifest size",
                ));
            }
            self.hasher.update(&output[..count]);
        }
        Ok(count)
    }
}

struct VerifiedArtifacts<'a> {
    directory: &'a Path,
    manifest: &'a RunManifest,
    states: BTreeMap<String, FileState>,
}

impl<'a> VerifiedArtifacts<'a> {
    fn new(directory: &'a Path, manifest: &'a RunManifest) -> Result<Self> {
        verify_artifact_names(directory, manifest)?;
        Ok(Self {
            directory,
            manifest,
            states: BTreeMap::new(),
        })
    }

    fn open(&self, name: &str, max_bytes: u64) -> Result<ArtifactReader> {
        let expected = self
            .manifest
            .artifacts
            .get(name)
            .with_context(|| format!("manifest omitted artifact {name}"))?;
        ArtifactReader::open(self.directory, name, expected, max_bytes)
    }

    fn record(&mut self, name: &str, state: FileState) -> Result<()> {
        if self.states.insert(name.into(), state).is_some() {
            bail!("artifact {name} was consumed more than once");
        }
        Ok(())
    }

    fn read_json<T: DeserializeOwned>(&mut self, name: &str, max_bytes: u64) -> Result<T> {
        let mut artifact = self.open(name, max_bytes)?;
        let value = serde_json::from_reader(&mut artifact)
            .with_context(|| format!("parse JSON artifact {name}"))?;
        let identity = artifact.finish()?;
        self.record(name, identity)?;
        Ok(value)
    }

    fn read_events(&mut self, name: &str, max_bytes: u64) -> Result<Vec<EvidenceEvent>> {
        let mut artifact = self.open(name, max_bytes)?;
        let mut events = Vec::new();
        {
            let mut reader = BufReader::new(&mut artifact);
            let mut line = String::new();
            let mut index = 0usize;
            loop {
                line.clear();
                let count = reader.read_line(&mut line)?;
                if count == 0 {
                    break;
                }
                index += 1;
                if line.trim().is_empty() {
                    bail!("{name} contains a blank line at {index}");
                }
                let event = serde_json::from_str(&line)
                    .with_context(|| format!("parse {name} line {index}"))?;
                events.push(event);
            }
        }
        let identity = artifact.finish()?;
        self.record(name, identity)?;
        Ok(events)
    }

    fn read_wal(
        &mut self,
        name: &str,
        max_bytes: u64,
    ) -> Result<bpf_observer_recorder::WalRecovery> {
        let mut artifact = self.open(name, max_bytes)?;
        let recovered = recover_wal_reader(&mut artifact)?;
        let identity = artifact.finish()?;
        self.record(name, identity)?;
        Ok(recovered)
    }

    fn verify_only(&mut self, name: &str, max_bytes: u64) -> Result<()> {
        let artifact = self.open(name, max_bytes)?;
        let identity = artifact.finish()?;
        self.record(name, identity)
    }

    fn finish(self) -> Result<()> {
        let expected = FINALIZED_RUN_ARTIFACTS_V1
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        if self.states.keys().cloned().collect::<BTreeSet<_>>() != expected {
            bail!("not every finalized artifact was consumed and verified");
        }
        verify_artifact_names(self.directory, self.manifest)?;
        for (name, state) in self.states {
            let path = self.directory.join(&name);
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(&path)
                .with_context(|| format!("reopen verified artifact {}", path.display()))?;
            let metadata = file.metadata()?;
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || file_state(&metadata) != state
            {
                bail!("artifact {name} pathname changed during verification");
            }
        }
        Ok(())
    }
}

fn read_manifest<T: DeserializeOwned>(directory: &Path) -> Result<(T, FileState, String)> {
    let path = directory.join("manifest.json");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("open manifest {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("manifest must be a singly linked regular file");
    }
    if before.len() > MAX_MANIFEST_JSON_BYTES {
        bail!("manifest exceeds the {MAX_MANIFEST_JSON_BYTES}-byte verification limit");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut reader = BufReader::new(file);
    reader
        .by_ref()
        .take(MAX_MANIFEST_JSON_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANIFEST_JSON_BYTES {
        bail!("manifest grew beyond the {MAX_MANIFEST_JSON_BYTES}-byte verification limit");
    }
    let after = reader.get_ref().metadata()?;
    if !same_file_state(&before, &after) || bytes.len() as u64 != before.len() {
        bail!("manifest changed while it was read");
    }
    let value = serde_json::from_slice(&bytes).context("parse manifest.json")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    Ok((value, file_state(&after), digest))
}

fn verify_manifest_path(directory: &Path, state: FileState) -> Result<()> {
    let path = directory.join("manifest.json");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&path)
        .with_context(|| format!("reopen manifest {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || file_state(&metadata) != state {
        bail!("manifest pathname changed during verification");
    }
    Ok(())
}

fn file_state(metadata: &fs::Metadata) -> FileState {
    FileState {
        dev: metadata.dev(),
        ino: metadata.ino(),
        len: metadata.len(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn same_file_state(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn validate_snapshot_binding(
    manifest: &RunManifest,
    snapshot: &Snapshot,
    phase: &str,
) -> Result<()> {
    if snapshot.schema_version != SCHEMA_VERSION
        || snapshot.phase != phase
        || snapshot.snapshot_id != format!("{}-{phase}", manifest.run_id)
        || snapshot.boot_id != manifest.environment.boot_id
        || snapshot.kernel_release != manifest.environment.kernel_release
        || snapshot.claim_scope != manifest.effective_scope
        || snapshot.observer_exclusions != manifest.observer_exclusions
    {
        bail!("{phase} snapshot is not bound to manifest.json");
    }
    Ok(())
}

fn validate_producer_snapshot_modes(
    manifest: &RunManifest,
    snapshot: &Snapshot,
    harness_authenticated: bool,
) -> Result<()> {
    for map in snapshot.maps.iter().filter(|map| !map.excluded) {
        if manifest
            .effective_scope
            .samples_map(map.identity.id, map.metadata.map_type)
            && map.content.status == bpf_observer_schema::MapSampleStatus::CompleteQuiescent
            && !harness_authenticated
        {
            bail!(
                "snapshot {} claims trusted Map quiescence that this producer cannot establish",
                snapshot.phase
            );
        }
    }
    Ok(())
}

fn validate_canary_health(health: &EvidenceHealth) -> Result<()> {
    let exact = health.recorder_loaded
        && health.run_registered
        && health.producer_barrier_complete
        && health.drain_completed
        && health.wal_durable
        && health.native_transport_canary_passed
        && health.syscall_attempted == 1
        && health.syscall_completed == 1
        && health.last_event_seq == 2
        && health.event_attempted == 2
        && health.event_published == 2
        && health.event_dropped == 0
        && health.events_persisted == 2
        && health.pending_insert_failed == 0
        && health.pending_missing == 0
        && health.pending_remaining == 0
        && health.parse_failed == 0
        && health.reasons.is_empty();
    if !exact {
        bail!("canary-health.json does not prove one complete native bpf() round trip");
    }
    Ok(())
}

fn validate_finalized_health_shape(health: &EvidenceHealth) -> Result<()> {
    if !health.recorder_loaded
        || !health.run_registered
        || !health.producer_barrier_complete
        || !health.drain_completed
        || !health.wal_durable
        || !health.native_transport_canary_passed
    {
        bail!("finalized health is missing a required producer lifecycle barrier");
    }
    if health.last_event_seq != health.event_attempted
        || health
            .syscall_attempted
            .checked_add(health.syscall_completed)
            != Some(health.event_attempted)
        || health.event_published.checked_add(health.event_dropped) != Some(health.event_attempted)
        || health.event_published != health.events_persisted
        || health.pending_remaining != 0
    {
        bail!("finalized health violates recorder accounting invariants");
    }
    Ok(())
}

fn validate_event_accounting(
    events: &[&EvidenceEvent],
    health: &EvidenceHealth,
    allowed_commands: &BTreeSet<u32>,
    require_exact_canary: bool,
) -> Result<()> {
    if events.len() as u64 != health.event_published
        || events.len() as u64 != health.events_persisted
    {
        bail!("published/persisted counters do not match the bound event stream");
    }
    if events.len() as u64 > MAX_RECORDED_EVENTS {
        bail!("event stream exceeds the producer's hard event-count limit");
    }
    let mut sequences = BTreeSet::new();
    let mut attempts = BTreeMap::new();
    let mut completions = Vec::new();
    for event in events {
        if event.schema_version != SCHEMA_VERSION
            || event.event_seq == 0
            || event.event_seq > health.last_event_seq
            || !sequences.insert(event.event_seq)
        {
            bail!("event stream contains an invalid or duplicate sequence");
        }
        match event.kind {
            EventKind::SyscallAttempted => {
                let allowed_flags = u32::from(FLAG_COMMON_ATTRS | FLAG_PENDING_INSERT_FAILED);
                if event.related_attempt_seq != 0
                    || event.return_value.is_some()
                    || event.argument_provenance != "RAW_SYSCALL_REGISTERS"
                    || event.flags & !allowed_flags != 0
                    || attempts.insert(event.event_seq, *event).is_some()
                {
                    bail!("attempt event has invalid pairing metadata");
                }
            }
            EventKind::CommandCompleted => {
                let allowed_flags = u32::from(
                    FLAG_COMMON_ATTRS
                        | FLAG_PENDING_MISSING
                        | FLAG_PENDING_POISONED
                        | FLAG_PENDING_DELETE_FAILED,
                );
                if (event.related_attempt_seq == 0
                    && event.flags & u32::from(FLAG_PENDING_MISSING) == 0)
                    || event.return_value.is_none()
                    || event.argument_provenance != "PENDING_RAW_SYSCALL_CORRELATION"
                    || event.flags & !allowed_flags != 0
                    || (event.flags & u32::from(FLAG_PENDING_POISONED) != 0
                        && event.flags & u32::from(FLAG_PENDING_MISSING) == 0)
                {
                    bail!("completion event has invalid pairing metadata");
                }
                completions.push(*event);
            }
        }
    }
    let observed_unsupported = if require_exact_canary {
        BTreeSet::new()
    } else {
        events
            .iter()
            .filter(|event| {
                event.kind == EventKind::SyscallAttempted
                    && !allowed_commands.is_empty()
                    && !allowed_commands.contains(&event.command)
            })
            .map(|event| event.command)
            .collect::<BTreeSet<_>>()
    };
    if observed_unsupported != health.unsupported_commands {
        bail!("unsupported-command accounting does not match attempted events");
    }
    if completions
        .iter()
        .any(|event| event.flags & u32::from(FLAG_PENDING_DELETE_FAILED) != 0)
    {
        bail!("a finalized run cannot contain a pending-delete failure");
    }

    let complete_pairing = health.event_dropped == 0
        && health.pending_insert_failed == 0
        && health.pending_missing == 0
        && health.parse_failed == 0;
    if health.event_dropped == 0 {
        if attempts.len() as u64 != health.syscall_attempted
            || completions.len() as u64 != health.syscall_completed
        {
            bail!("syscall counters do not match the lossless event stream");
        }
        let flagged_insert_failures = attempts
            .values()
            .filter(|event| event.flags & u32::from(FLAG_PENDING_INSERT_FAILED) != 0)
            .count() as u64;
        let flagged_missing = completions
            .iter()
            .filter(|event| event.flags & u32::from(FLAG_PENDING_MISSING) != 0)
            .count() as u64;
        if flagged_insert_failures != health.pending_insert_failed
            || flagged_missing != health.pending_missing
        {
            bail!("pending-call flag counts do not match health counters");
        }
    }
    if complete_pairing {
        let mut used_attempts = BTreeSet::new();
        for completion in &completions {
            let attempt = attempts
                .get(&completion.related_attempt_seq)
                .context("completion has no matching attempted event")?;
            if !used_attempts.insert(completion.related_attempt_seq) {
                bail!("more than one completion refers to the same attempted event");
            }
            if completion.event_seq <= attempt.event_seq
                || completion.ktime_ns < attempt.ktime_ns
                || attempt.command != completion.command
                || attempt.attr_size != completion.attr_size
                || attempt.pid != completion.pid
                || attempt.tgid != completion.tgid
                || attempt.flags & u32::from(FLAG_COMMON_ATTRS)
                    != completion.flags & u32::from(FLAG_COMMON_ATTRS)
                || attempt.flags & !u32::from(FLAG_COMMON_ATTRS) != 0
                || completion.flags & !u32::from(FLAG_COMMON_ATTRS) != 0
            {
                bail!("completion does not match its attempted event");
            }
        }
        if used_attempts.len() != attempts.len() {
            bail!("one or more attempted events have no unique completion");
        }
    }
    if require_exact_canary {
        let attempt = attempts.get(&1);
        let completion = completions.iter().find(|event| event.event_seq == 2);
        let exact = events.len() == 2
            && attempts.len() == 1
            && completions.len() == 1
            && attempt.map(|event| {
                event.related_attempt_seq == 0
                    && event.command == 0
                    && event.attr_size == 0
                    && event.flags == 0
                    && event.return_value.is_none()
            }) == Some(true)
            && completion.map(|event| {
                event.related_attempt_seq == 1
                    && event.command == 0
                    && event.attr_size == 0
                    && event.flags == 0
                    && event.return_value.map(|value| value < 0) == Some(true)
            }) == Some(true);
        if !exact {
            bail!("native transport canary event pair is not exact");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{atomic_file, environment, harness};
    use bpf_harness_auth::{
        generate_keypair, public_key_fingerprint, read_public_key, write_keypair, AllowedWorkload,
        HarnessPolicy, HarnessRequest, HarnessServerSession, PolicyCheck, HARNESS_CONTRACT_ID,
        OBSERVER_EXCLUSIONS_DERIVATION_V1,
    };
    use bpf_observer_recorder::{KernelEvent, WalWriter};
    use bpf_observer_schema::{
        Attribution, Completeness, ContractCheck, EnvironmentFingerprint, ObjectExclusions,
        QuiescenceBasis, QuiescenceStatus,
    };
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn event(kind: EventKind, sequence: u64, related: u64) -> EvidenceEvent {
        let argument_provenance = match &kind {
            EventKind::SyscallAttempted => "RAW_SYSCALL_REGISTERS",
            EventKind::CommandCompleted => "PENDING_RAW_SYSCALL_CORRELATION",
        };
        EvidenceEvent {
            schema_version: SCHEMA_VERSION,
            run_id: "run".into(),
            run_epoch: 9,
            event_seq: sequence,
            related_attempt_seq: related,
            kind,
            ktime_ns: sequence,
            cgroup_id: 7,
            pid: 10,
            tgid: 10,
            command: 0,
            command_name: "BPF_MAP_CREATE".into(),
            attr_size: 0,
            return_value: None,
            argument_provenance: argument_provenance.into(),
            flags: 0,
        }
    }

    fn canary_health() -> EvidenceHealth {
        EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            native_transport_canary_passed: true,
            syscall_attempted: 1,
            syscall_completed: 1,
            last_event_seq: 2,
            event_attempted: 2,
            event_published: 2,
            events_persisted: 2,
            ..EvidenceHealth::default()
        }
    }

    #[test]
    fn exact_canary_pair_is_accepted() {
        let attempted = event(EventKind::SyscallAttempted, 1, 0);
        let mut completed = event(EventKind::CommandCompleted, 2, 1);
        completed.return_value = Some(-22);
        validate_event_accounting(
            &[&attempted, &completed],
            &canary_health(),
            &BTreeSet::from([5]),
            true,
        )
        .unwrap();
        validate_canary_health(&canary_health()).unwrap();
    }

    #[test]
    fn mismatched_completion_is_rejected() {
        let attempted = event(EventKind::SyscallAttempted, 1, 0);
        let mut completed = event(EventKind::CommandCompleted, 2, 1);
        completed.command = 5;
        assert!(validate_event_accounting(
            &[&attempted, &completed],
            &canary_health(),
            &BTreeSet::from([0]),
            true,
        )
        .is_err());
    }

    #[test]
    fn duplicate_completion_target_is_rejected() {
        let attempted_one = event(EventKind::SyscallAttempted, 1, 0);
        let attempted_two = event(EventKind::SyscallAttempted, 2, 0);
        let mut completed_one = event(EventKind::CommandCompleted, 3, 1);
        let mut completed_two = event(EventKind::CommandCompleted, 4, 1);
        completed_one.return_value = Some(0);
        completed_two.return_value = Some(0);
        let mut health = canary_health();
        health.syscall_attempted = 2;
        health.syscall_completed = 2;
        health.last_event_seq = 4;
        health.event_attempted = 4;
        health.event_published = 4;
        health.events_persisted = 4;
        assert!(validate_event_accounting(
            &[
                &attempted_one,
                &attempted_two,
                &completed_one,
                &completed_two,
            ],
            &health,
            &BTreeSet::from([0]),
            false,
        )
        .is_err());
    }

    #[test]
    fn finalized_fixture_verifies_end_to_end() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::var_os("TMPDIR")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "bpf-observer-verify-{}-{nonce}",
                std::process::id()
            ));
        fs::create_dir(&root).unwrap();

        let run_id = "fixture-run";
        let formal_epoch = 7;
        let canary_epoch = run::canary_epoch(formal_epoch);
        let cgroup_id = 99;
        let scope = bpf_observer_schema::ClaimScope::default();
        let environment = EnvironmentFingerprint {
            kernel_release: "fixture-kernel".into(),
            boot_id: "fixture-boot".into(),
            observer_version: env!("CARGO_PKG_VERSION").into(),
            recorder_object_sha256: Some("00".repeat(32)),
            kernel_btf_sha256: None,
            source_commit: None,
            ..EnvironmentFingerprint::default()
        };
        let snapshot = |phase: &str| Snapshot {
            schema_version: SCHEMA_VERSION,
            snapshot_id: format!("{run_id}-{phase}"),
            phase: phase.into(),
            boot_id: environment.boot_id.clone(),
            captured_unix_ns: 1,
            capture_duration_ns: 1,
            kernel_release: environment.kernel_release.clone(),
            byte_order: "little".into(),
            possible_cpu_ids: vec![0],
            claim_scope: scope.clone(),
            observer_exclusions: ObjectExclusions::default(),
            programs: vec![],
            maps: vec![],
            links: vec![],
            pin_roots: vec![],
            pins: vec![],
            read_failures: vec![],
            completeness: Completeness::complete(),
            notes: vec![],
        };
        let s0 = snapshot("S0");
        let s1 = snapshot("S1");
        let health = EvidenceHealth {
            recorder_loaded: true,
            run_registered: true,
            producer_barrier_complete: true,
            drain_completed: true,
            wal_durable: true,
            native_transport_canary_passed: true,
            ..EvidenceHealth::default()
        };
        let canary_health = canary_health();
        let quiescence = harness::observed_only(true, "fixture cgroup is empty");
        assert_eq!(quiescence.basis, QuiescenceBasis::ObservedOnly);
        let mut verdict = compare(&s0, &s1, &health, quiescence.clone()).unwrap();
        run::annotate_observe_verdict(&mut verdict);
        assert_eq!(verdict.attribution, Attribution::Unknown);

        atomic_file::write_json_atomic(&root.join("s0.json"), &s0).unwrap();
        atomic_file::write_json_atomic(&root.join("s1.json"), &s1).unwrap();
        atomic_file::write_json_atomic(&root.join("health.json"), &health).unwrap();
        atomic_file::write_json_atomic(&root.join("canary-health.json"), &canary_health).unwrap();
        atomic_file::write_json_atomic(&root.join("quiescence.json"), &quiescence).unwrap();
        atomic_file::write_json_atomic(&root.join("verdict.json"), &verdict).unwrap();
        File::create(root.join("workload.stdout")).unwrap();
        File::create(root.join("workload.stderr")).unwrap();

        let attempt = KernelEvent {
            schema_version: SCHEMA_VERSION,
            kind: 1,
            flags: 0,
            command: 0,
            attr_size: 0,
            run_epoch: canary_epoch,
            event_seq: 1,
            related_attempt_seq: 0,
            ktime_ns: 1,
            cgroup_id,
            pid_tgid: (10u64 << 32) | 10,
            return_value: 0,
        };
        let completion = KernelEvent {
            kind: 2,
            event_seq: 2,
            related_attempt_seq: 1,
            ktime_ns: 2,
            return_value: -22,
            ..attempt
        };
        let mut wal = WalWriter::create(&root.join("raw-events.bin")).unwrap();
        wal.append(&attempt).unwrap();
        wal.append(&completion).unwrap();
        wal.sync().unwrap();
        drop(wal);
        let mut jsonl = File::create(root.join("raw-events.jsonl")).unwrap();
        for event in [&attempt, &completion] {
            serde_json::to_writer(&mut jsonl, &event.to_schema(run_id)).unwrap();
            jsonl.write_all(b"\n").unwrap();
        }
        jsonl.sync_all().unwrap();

        let mut manifest = RunManifest {
            schema_version: SCHEMA_VERSION,
            run_id: run_id.into(),
            run_epoch: formal_epoch,
            run_status: RunStatus::Finalized,
            started_unix_ns: 1,
            finalized_unix_ns: Some(2),
            cgroup_path: "/sys/fs/cgroup/fixture-run".into(),
            cgroup_id,
            workload: vec!["fixture".into()],
            workload_exit_code: Some(0),
            workload_signal: None,
            requested_scope: scope.clone(),
            effective_scope: scope,
            scope_accepted: true,
            observer_exclusions: ObjectExclusions::default(),
            environment,
            artifacts: BTreeMap::new(),
            notes: vec![],
        };
        for name in FINALIZED_RUN_ARTIFACTS_V1 {
            let path = root.join(name);
            let metadata = fs::metadata(&path).unwrap();
            manifest.artifacts.insert(
                name.into(),
                ArtifactDigest {
                    sha256: environment::sha256_file(&path).unwrap(),
                    size_bytes: metadata.len(),
                },
            );
        }
        atomic_file::write_json_atomic(&root.join("manifest.json"), &manifest).unwrap();

        assert!(verify_run(&root, &"11".repeat(32), None).is_err());
        let report = verify_run(&root, &"00".repeat(32), None).unwrap();
        assert_eq!(report.run_id, run_id);
        assert_eq!(report.events_verified, 2);
        assert_eq!(report.state_verdict, StateVerdict::Inconclusive);
        assert_eq!(report.manifest_sha256.len(), 64);
        assert!(report.recorder_digest_policy_match);
        assert_eq!(report.recorder_object_sha256, "00".repeat(32));
        assert!(!report.harness_authenticated);
        assert!(report.harness_public_key_fingerprint_sha256.is_none());
        assert!(report.harness_policy_id.is_none());
        assert!(report.harness_policy_sha256.is_none());

        let policy_without_transcript = HarnessVerificationPolicy {
            public_key: root.join("missing-public-key"),
            policy_id: "fixture-policy".into(),
            expected_policy_sha256: "22".repeat(32),
            kernel_identity: "fixture-kernel-identity".into(),
        };
        let error =
            verify_run(&root, &"00".repeat(32), Some(&policy_without_transcript)).unwrap_err();
        assert!(error
            .to_string()
            .contains("external harness policy was supplied"));

        let trust_root = root.with_extension("trust");
        fs::create_dir(&trust_root).unwrap();
        let signing_secret_path = trust_root.join("signing.key");
        let signing_public_path = trust_root.join("signing.pub");
        let signing_key = generate_keypair().unwrap();
        write_keypair(&signing_key, &signing_secret_path, &signing_public_path).unwrap();
        let signing_public = read_public_key(&signing_public_path).unwrap();

        let observer_sha256 = "33".repeat(32);
        let workload_sha256 = "44".repeat(32);
        let kernel_identity = "fixture-kernel-identity".to_string();
        let policy_id = "fixture-policy".to_string();
        let scope_sha256 = canonical_json_sha256(&manifest.effective_scope).unwrap();
        let exclusions_sha256 = canonical_json_sha256(&manifest.observer_exclusions).unwrap();
        let policy_checks = bpf_harness_auth::EXCLUSIVE_VM_V1_CHECKS
            .iter()
            .map(|name| PolicyCheck {
                name: (*name).into(),
                passed: true,
                evidence: format!("fixture evidence for {name}"),
            })
            .collect::<Vec<_>>();
        let harness_policy = HarnessPolicy {
            protocol_version: HARNESS_PROTOCOL_VERSION,
            contract_id: HARNESS_CONTRACT_ID.into(),
            policy_id: policy_id.clone(),
            allowed_kernel_identities: [kernel_identity.clone()].into_iter().collect(),
            allowed_observer_sha256: [observer_sha256.clone()].into_iter().collect(),
            allowed_recorder_sha256: ["00".repeat(32)].into_iter().collect(),
            allowed_scope_sha256: [scope_sha256.clone()].into_iter().collect(),
            observer_exclusions_derivation: OBSERVER_EXCLUSIONS_DERIVATION_V1.into(),
            allowed_workloads: vec![AllowedWorkload {
                run_id: manifest.run_id.clone(),
                run_epoch: manifest.run_epoch,
                cgroup_path: manifest.cgroup_path.clone(),
                argv: manifest.workload.clone(),
                executable_sha256: workload_sha256.clone(),
            }],
            checks: policy_checks,
        };
        let policy_sha256 = harness_policy.canonical_sha256().unwrap();
        manifest.environment.observer_executable_sha256 = Some(observer_sha256.clone());
        manifest.environment.workload_executable_sha256 = Some(workload_sha256.clone());
        manifest.environment.harness_kernel_identity = Some(kernel_identity.clone());
        manifest.environment.harness_policy_id = Some(policy_id.clone());
        manifest.environment.harness_policy_sha256 = Some(policy_sha256.clone());
        manifest.environment.harness_public_key_fingerprint_sha256 =
            Some(public_key_fingerprint(&signing_public));

        let artifact_sha256 = |name: &str| manifest.artifacts.get(name).unwrap().sha256.clone();
        let binding = HarnessRunBinding {
            protocol_version: HARNESS_PROTOCOL_VERSION,
            nonce_hex: "55".repeat(32),
            run_id: manifest.run_id.clone(),
            run_epoch: manifest.run_epoch,
            cgroup_id: manifest.cgroup_id,
            cgroup_path: manifest.cgroup_path.clone(),
            boot_id: manifest.environment.boot_id.clone(),
            kernel_identity: kernel_identity.clone(),
            observer_sha256,
            recorder_sha256: "00".repeat(32),
            scope_sha256,
            observer_exclusions_sha256: exclusions_sha256,
            workload_argv: manifest.workload.clone(),
            workload_executable_sha256: workload_sha256,
            s0_snapshot_id: s0.snapshot_id.clone(),
            s1_snapshot_id: s1.snapshot_id.clone(),
        };
        let pre_s1 = HarnessPreS1Evidence {
            pre_health_sha256: artifact_sha256("health.json"),
            cgroup_empty: true,
            cgroup_frozen: true,
        };
        let post = HarnessPostEvidence {
            s0_sha256: artifact_sha256("s0.json"),
            s1_sha256: artifact_sha256("s1.json"),
            health_sha256: artifact_sha256("health.json"),
            canary_health_sha256: artifact_sha256("canary-health.json"),
            raw_events_wal_sha256: artifact_sha256("raw-events.bin"),
            raw_events_jsonl_sha256: artifact_sha256("raw-events.jsonl"),
            workload_stdout_sha256: artifact_sha256("workload.stdout"),
            workload_stderr_sha256: artifact_sha256("workload.stderr"),
            workload_exit_code: 0,
            workload_signal: None,
            outside_cgroup_syscall_attempted: 0,
            recorder_drain_complete: true,
            producer_barrier_complete: true,
            wal_durable: true,
            in_flight_bpf_barrier_complete: true,
        };
        let mut server = HarnessServerSession::new(harness_policy).unwrap();
        let pre_s0_response = server
            .handle(
                HarnessRequest::PreS0 {
                    binding: binding.clone(),
                },
                &signing_key,
            )
            .unwrap();
        let s0_committed_response = server
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding.clone(),
                    s0_sha256: post.s0_sha256.clone(),
                },
                &signing_key,
            )
            .unwrap();
        let pre_s1_response = server
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding.clone(),
                    evidence: pre_s1,
                },
                &signing_key,
            )
            .unwrap();
        let final_response = server
            .handle(
                HarnessRequest::Final {
                    binding,
                    evidence: post,
                },
                &signing_key,
            )
            .unwrap();
        let transcript = AuthenticatedHarnessTranscript {
            pre_s0: pre_s0_response,
            s0_committed: s0_committed_response,
            pre_s1: pre_s1_response,
            final_response,
        };
        let authenticated_quiescence = QuiescenceReport {
            status: QuiescenceStatus::QuiescentWithinModel,
            basis: QuiescenceBasis::HarnessEnforced,
            contract_id: Some(HARNESS_CONTRACT_ID.into()),
            checks: transcript
                .final_response
                .checks
                .iter()
                .map(|check| ContractCheck {
                    name: check.name.clone(),
                    passed: check.passed,
                    evidence: check.evidence.clone(),
                })
                .collect(),
            exclusive_actor_attribution: true,
            authentication: Some(serde_json::to_value(&transcript).unwrap()),
        };
        assert!(authenticated_quiescence.supports_unchanged());
        atomic_file::write_json_atomic(&root.join("quiescence.json"), &authenticated_quiescence)
            .unwrap();
        let mut authenticated_verdict =
            compare(&s0, &s1, &health, authenticated_quiescence.clone()).unwrap();
        run::annotate_observe_verdict(&mut authenticated_verdict);
        atomic_file::write_json_atomic(&root.join("verdict.json"), &authenticated_verdict).unwrap();
        manifest.artifacts.clear();
        for name in FINALIZED_RUN_ARTIFACTS_V1 {
            let path = root.join(name);
            let metadata = fs::metadata(&path).unwrap();
            manifest.artifacts.insert(
                name.into(),
                ArtifactDigest {
                    sha256: environment::sha256_file(&path).unwrap(),
                    size_bytes: metadata.len(),
                },
            );
        }
        atomic_file::write_json_atomic(&root.join("manifest.json"), &manifest).unwrap();

        let trusted_policy = HarnessVerificationPolicy {
            public_key: signing_public_path,
            policy_id: policy_id.clone(),
            expected_policy_sha256: policy_sha256.clone(),
            kernel_identity,
        };
        assert!(verify_run(&root, &"00".repeat(32), None).is_err());
        let authenticated_report =
            verify_run(&root, &"00".repeat(32), Some(&trusted_policy)).unwrap();
        assert!(authenticated_report.harness_authenticated);
        assert_eq!(
            authenticated_report.harness_policy_id.as_deref(),
            Some(policy_id.as_str())
        );
        assert_eq!(
            authenticated_report.harness_policy_sha256.as_deref(),
            Some(policy_sha256.as_str())
        );

        let missing_key_policy = HarnessVerificationPolicy {
            public_key: trust_root.join("missing.pub"),
            ..trusted_policy.clone()
        };
        assert!(verify_run(&root, &"00".repeat(32), Some(&missing_key_policy)).is_err());

        let wrong_secret_path = trust_root.join("wrong.key");
        let wrong_public_path = trust_root.join("wrong.pub");
        let wrong_key = generate_keypair().unwrap();
        write_keypair(&wrong_key, &wrong_secret_path, &wrong_public_path).unwrap();
        let wrong_key_policy = HarnessVerificationPolicy {
            public_key: wrong_public_path,
            ..trusted_policy.clone()
        };
        assert!(verify_run(&root, &"00".repeat(32), Some(&wrong_key_policy)).is_err());

        let wrong_policy = HarnessVerificationPolicy {
            expected_policy_sha256: "66".repeat(32),
            ..trusted_policy.clone()
        };
        assert!(verify_run(&root, &"00".repeat(32), Some(&wrong_policy)).is_err());

        let wrong_kernel = HarnessVerificationPolicy {
            kernel_identity: "wrong-kernel-identity".into(),
            ..trusted_policy.clone()
        };
        assert!(verify_run(&root, &"00".repeat(32), Some(&wrong_kernel)).is_err());

        let mut forged_transcript = transcript;
        let replacement = if forged_transcript
            .final_response
            .signature_hex
            .starts_with("00")
        {
            "01"
        } else {
            "00"
        };
        forged_transcript
            .final_response
            .signature_hex
            .replace_range(0..2, replacement);
        let mut forged_quiescence = authenticated_quiescence;
        forged_quiescence.authentication = Some(serde_json::to_value(forged_transcript).unwrap());
        atomic_file::write_json_atomic(&root.join("quiescence.json"), &forged_quiescence).unwrap();
        let quiescence_path = root.join("quiescence.json");
        let quiescence_metadata = fs::metadata(&quiescence_path).unwrap();
        manifest.artifacts.insert(
            "quiescence.json".into(),
            ArtifactDigest {
                sha256: environment::sha256_file(&quiescence_path).unwrap(),
                size_bytes: quiescence_metadata.len(),
            },
        );
        atomic_file::write_json_atomic(&root.join("manifest.json"), &manifest).unwrap();
        assert!(verify_run(&root, &"00".repeat(32), Some(&trusted_policy)).is_err());

        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(trust_root).unwrap();
    }

    #[test]
    fn authenticated_environment_fields_are_all_or_none_and_canonical() {
        let mut environment = EnvironmentFingerprint::default();
        assert!(!validate_harness_environment(&environment).unwrap());

        environment.observer_executable_sha256 = Some("00".repeat(32));
        assert!(validate_harness_environment(&environment).is_err());

        environment.workload_executable_sha256 = Some("11".repeat(32));
        environment.harness_kernel_identity = Some("fixture-kernel".into());
        environment.harness_policy_id = Some("fixture-policy".into());
        environment.harness_policy_sha256 = Some("22".repeat(32));
        environment.harness_public_key_fingerprint_sha256 = Some("33".repeat(32));
        assert!(validate_harness_environment(&environment).unwrap());

        environment.harness_policy_sha256 = Some("AA".repeat(32));
        assert!(validate_harness_environment(&environment).is_err());
    }
}
