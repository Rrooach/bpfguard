// SPDX-License-Identifier: GPL-2.0-only

//! Bounded diagnostic evidence for a v3 run that aborted after READY.
//!
//! This is deliberately *not* a recovery verdict or a substitute for the
//! closed A/B/C manifest. The normal offline verifier rejects partial runs.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::protocol::DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION;
use crate::recovery_report::RecoveryConsistencyVerdict;
use crate::session::DeploymentObserverConfig;

pub const RECOVERY_ABORT_FILE: &str = "recovery-abort.json";
pub const RECOVERY_ABORT_SCHEMA_VERSION: u32 = 1;

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_ARTIFACT_BYTES: u64 = 512 * 1024 * 1024;
const SNAPSHOT_A_FILE: &str = "snapshot-a.json";
const SNAPSHOT_B_FILE: &str = "snapshot-b.json";
const SNAPSHOT_C_FILE: &str = "snapshot-c.json";
const READY_FILE: &str = "recovery-ready-message.json";
const AGENT_STARTED_FILE: &str = "agent-started.json";
const RECOVERY_EVIDENCE_FILE: &str = "recovery.json";
const FINAL_MANIFEST_FILE: &str = "recovery-artifact-manifest.json";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryAbortStatus {
    AbortedPartialEvidence,
}

/// The last artifact-backed milestone, not proof that a control line was
/// emitted or that the corresponding snapshot was semantically verified.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryAbortPhase {
    SnapshotACommitted,
    AgentStartedRecorded,
    SnapshotBCommitted,
    RecoveryEvidenceCommitted,
    SnapshotCCommitted,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAbortEvidence {
    pub schema_version: u32,
    pub protocol_version: u32,
    pub status: RecoveryAbortStatus,
    pub run_id: String,
    pub epoch: u64,
    pub checkpoint_id: String,
    pub recovery_id: String,
    pub last_known_phase: RecoveryAbortPhase,
    /// A fixed, coarse category. The raw error can contain config, paths or
    /// helper output and is intentionally never copied to this artifact.
    pub error_reason: String,
    pub verdict: RecoveryConsistencyVerdict,
    pub snapshot_a_sha256: String,
    pub snapshot_b_sha256: Option<String>,
    pub snapshot_c_sha256: Option<String>,
    pub recorded_unix_ns: u128,
    /// Always false: this artifact has no closed A/B/C manifest or offline
    /// recovery verification, even if snapshot C happens to exist.
    pub complete_abc_report_available: bool,
}

impl RecoveryAbortEvidence {
    pub fn from_failure(
        config: &DeploymentObserverConfig,
        output: &Path,
        error: &str,
    ) -> Result<Self> {
        if config.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION {
            bail!("recovery abort evidence requires protocol v3");
        }
        let recovery = config
            .recovery
            .as_ref()
            .context("v3 recovery contract is missing")?;
        if present_regular(output, FINAL_MANIFEST_FILE)? {
            bail!("cannot emit abort evidence after final recovery manifest exists");
        }
        if !present_regular(output, READY_FILE)? {
            bail!("recovery abort evidence requires a committed READY artifact");
        }
        let a = existing_digest(output, SNAPSHOT_A_FILE)?
            .context("READY abort evidence lacks snapshot A artifact")?;
        let b = existing_digest(output, SNAPSHOT_B_FILE)?;
        let c = existing_digest(output, SNAPSHOT_C_FILE)?;
        let agent_started = present_regular(output, AGENT_STARTED_FILE)?;
        let recovery_evidence = present_regular(output, RECOVERY_EVIDENCE_FILE)?;
        if (b.is_some() && !agent_started)
            || (recovery_evidence && b.is_none())
            || (c.is_some() && (!recovery_evidence || b.is_none()))
        {
            bail!("recovery abort artifacts do not form a committed A/B/C prefix");
        }
        let last_known_phase = if c.is_some() {
            RecoveryAbortPhase::SnapshotCCommitted
        } else if recovery_evidence {
            RecoveryAbortPhase::RecoveryEvidenceCommitted
        } else if b.is_some() {
            RecoveryAbortPhase::SnapshotBCommitted
        } else if agent_started {
            RecoveryAbortPhase::AgentStartedRecorded
        } else {
            RecoveryAbortPhase::SnapshotACommitted
        };
        let recorded_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_nanos();
        let evidence = Self {
            schema_version: RECOVERY_ABORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: RecoveryAbortStatus::AbortedPartialEvidence,
            run_id: config.run_id.clone(),
            epoch: config.epoch,
            checkpoint_id: recovery.checkpoint_id.clone(),
            recovery_id: recovery.recovery_id.clone(),
            last_known_phase,
            error_reason: safe_error_category(error).to_owned(),
            verdict: RecoveryConsistencyVerdict::Inconclusive,
            snapshot_a_sha256: a,
            snapshot_b_sha256: b,
            snapshot_c_sha256: c,
            recorded_unix_ns,
            complete_abc_report_available: false,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema_version != RECOVERY_ABORT_SCHEMA_VERSION
            || self.protocol_version != DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION
            || self.status != RecoveryAbortStatus::AbortedPartialEvidence
            || self.verdict != RecoveryConsistencyVerdict::Inconclusive
            || self.complete_abc_report_available
        {
            bail!("abort evidence cannot claim complete recovery verification");
        }
        validate_identifier(&self.run_id)?;
        validate_identifier(&self.checkpoint_id)?;
        validate_identifier(&self.recovery_id)?;
        if self.epoch == 0 || self.recorded_unix_ns == 0 {
            bail!("abort evidence epoch or timestamp is invalid");
        }
        if !is_safe_error_category(&self.error_reason) {
            bail!("abort evidence contains an unapproved error category");
        }
        validate_sha256(&self.snapshot_a_sha256)?;
        if let Some(value) = &self.snapshot_b_sha256 {
            validate_sha256(value)?;
        }
        if let Some(value) = &self.snapshot_c_sha256 {
            validate_sha256(value)?;
        }
        let expected = match (
            self.snapshot_b_sha256.is_some(),
            self.snapshot_c_sha256.is_some(),
        ) {
            (false, false) => matches!(
                self.last_known_phase,
                RecoveryAbortPhase::SnapshotACommitted | RecoveryAbortPhase::AgentStartedRecorded
            ),
            (true, false) => matches!(
                self.last_known_phase,
                RecoveryAbortPhase::SnapshotBCommitted
                    | RecoveryAbortPhase::RecoveryEvidenceCommitted
            ),
            (true, true) => self.last_known_phase == RecoveryAbortPhase::SnapshotCCommitted,
            (false, true) => false,
        };
        if !expected {
            bail!("abort phase and committed snapshot digest prefix disagree");
        }
        Ok(())
    }
}

fn present_regular(output: &Path, name: &str) -> Result<bool> {
    match fs::symlink_metadata(output.join(name)) {
        Ok(metadata) => {
            if !metadata.file_type().is_file()
                || metadata.nlink() != 1
                || metadata.len() > MAX_ARTIFACT_BYTES
            {
                bail!("recovery abort milestone is not a bounded singly-linked regular file");
            }
            Ok(true)
        }
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("inspect recovery milestone {name}")),
    }
}

fn existing_digest(output: &Path, name: &str) -> Result<Option<String>> {
    if !present_regular(output, name)? {
        return Ok(None);
    }
    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(output.join(name))
        .with_context(|| format!("open recovery abort snapshot {name}"))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 || before.len() > MAX_ARTIFACT_BYTES {
        bail!("recovery abort snapshot is not a bounded singly-linked regular file");
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .context("recovery abort snapshot size overflow")?;
        if total > MAX_ARTIFACT_BYTES {
            bail!("recovery abort snapshot exceeds hard artifact bound while hashing");
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != total
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("recovery abort snapshot changed while hashing");
    }
    Ok(Some(hex::encode(hasher.finalize())))
}

fn safe_error_category(error: &str) -> &'static str {
    if error.contains("boot identity changed") {
        "BOOT_IDENTITY_CHANGED"
    } else if error.contains("deployment identity changed") {
        "DEPLOYMENT_IDENTITY_CHANGED"
    } else if error.contains("freeze") || error.contains("frozen") {
        "FREEZE_BARRIER_FAILED"
    } else if error.contains("capture") || error.contains("snapshot") {
        "ENDPOINT_CAPTURE_FAILED"
    } else if error.contains("recorder") {
        "RECORDER_FAILURE"
    } else if error.contains("evidence artifact") || error.contains("manifest") {
        "EVIDENCE_COMMIT_FAILED"
    } else {
        "RECOVERY_FLOW_FAILED"
    }
}

fn is_safe_error_category(value: &str) -> bool {
    matches!(
        value,
        "BOOT_IDENTITY_CHANGED"
            | "DEPLOYMENT_IDENTITY_CHANGED"
            | "FREEZE_BARRIER_FAILED"
            | "ENDPOINT_CAPTURE_FAILED"
            | "RECORDER_FAILURE"
            | "EVIDENCE_COMMIT_FAILED"
            | "RECOVERY_FLOW_FAILED"
    )
}

fn validate_identifier(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("abort evidence identity is empty or noncanonical");
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("abort snapshot digest is not canonical SHA-256");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::io::Write;

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn sample(phase: RecoveryAbortPhase, b: bool, c: bool) -> RecoveryAbortEvidence {
        RecoveryAbortEvidence {
            schema_version: RECOVERY_ABORT_SCHEMA_VERSION,
            protocol_version: DEPLOYMENT_OBSERVER_RECOVERY_PROTOCOL_VERSION,
            status: RecoveryAbortStatus::AbortedPartialEvidence,
            run_id: "run-1".to_owned(),
            epoch: 1,
            checkpoint_id: "checkpoint-1".to_owned(),
            recovery_id: "recovery-1".to_owned(),
            last_known_phase: phase,
            error_reason: "RECOVERY_FLOW_FAILED".to_owned(),
            verdict: RecoveryConsistencyVerdict::Inconclusive,
            snapshot_a_sha256: digest('a'),
            snapshot_b_sha256: b.then(|| digest('b')),
            snapshot_c_sha256: c.then(|| digest('c')),
            recorded_unix_ns: 1,
            complete_abc_report_available: false,
        }
    }

    #[test]
    fn abort_evidence_never_claims_complete_recovery() {
        let a = sample(RecoveryAbortPhase::SnapshotACommitted, false, false);
        a.validate().unwrap();
        let b = sample(RecoveryAbortPhase::SnapshotBCommitted, true, false);
        b.validate().unwrap();
        let c = sample(RecoveryAbortPhase::SnapshotCCommitted, true, true);
        c.validate().unwrap();
        let mut forged = c;
        forged.complete_abc_report_available = true;
        assert!(forged.validate().is_err());
        forged.complete_abc_report_available = false;
        forged.verdict = RecoveryConsistencyVerdict::ConsistentWithinScope;
        assert!(forged.validate().is_err());
        assert!(sample(RecoveryAbortPhase::SnapshotCCommitted, false, true)
            .validate()
            .is_err());
    }

    #[test]
    fn failure_reason_does_not_copy_secrets_or_unbounded_messages() {
        let secret = "API_KEY=do-not-leak";
        let reason = format!("{} {secret}", "capture failed ".repeat(100_000));
        assert_eq!(safe_error_category(&reason), "ENDPOINT_CAPTURE_FAILED");
        assert!(!safe_error_category(&reason).contains(secret));
        let encoded = serde_json::to_vec(&sample(
            RecoveryAbortPhase::SnapshotACommitted,
            false,
            false,
        ))
        .unwrap();
        let mut json: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        json["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RecoveryAbortEvidence>(json).is_err());
    }

    #[test]
    fn artifact_detection_is_prefix_only_and_rejects_symlinks() {
        let path = std::env::temp_dir().join(format!(
            "bpf-observer-abort-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        let a = path.join(SNAPSHOT_A_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&a)
            .unwrap();
        file.write_all(b"a").unwrap();
        drop(file);
        assert_eq!(
            existing_digest(&path, SNAPSHOT_A_FILE).unwrap(),
            Some(hex::encode(Sha256::digest(b"a")))
        );
        assert_eq!(existing_digest(&path, SNAPSHOT_B_FILE).unwrap(), None);
        std::os::unix::fs::symlink(&a, path.join(SNAPSHOT_B_FILE)).unwrap();
        assert!(existing_digest(&path, SNAPSHOT_B_FILE).is_err());
        fs::remove_file(path.join(SNAPSHOT_B_FILE)).unwrap();
        fs::remove_file(a).unwrap();
        fs::remove_dir(path).unwrap();
    }
}
