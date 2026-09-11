// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated four-phase protocol shared by the Observer and its external
//! VM harness.
//!
//! A signature covers a domain-separated, length-prefixed JSON encoding of a
//! fixed-field Rust struct. All collections that influence authorization are
//! either ordered or validated as unique. This deliberately avoids signing a
//! caller-provided JSON blob with ambiguous semantics.

use anyhow::{anyhow, bail, Context, Result};
use ed25519_dalek::{Keypair, SecretKey, Signature, Signer, Verifier};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub use bpf_observer_schema::EXCLUSIVE_VM_V1_CHECKS;
pub use ed25519_dalek::PublicKey;

pub const HARNESS_PROTOCOL_VERSION: u32 = 1;
pub const HARNESS_CONTRACT_ID: &str = "exclusive-vm-v1";
pub const OBSERVER_EXCLUSIONS_DERIVATION_V1: &str = "MEASURED_OBSERVER_RECORDER_OWNED_V1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_POLICY_BYTES: u64 = 1024 * 1024;
pub const MAX_CANONICAL_JSON_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_SERVER_SESSIONS: u32 = 1024;

const SIGNATURE_DOMAIN: &[u8] = b"BPF_STATE_OBSERVER_HARNESS_RESPONSE_V1\0";
const MAX_IDENTIFIER_BYTES: usize = 4096;
const MAX_POLICY_ITEMS: usize = 4096;
const MAX_WORKLOAD_ARGS: usize = 4096;
const MAX_WORKLOAD_ARG_BYTES: usize = 32 * 1024;
const MAX_WORKLOAD_TOTAL_BYTES: usize = 256 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessRunBinding {
    pub protocol_version: u32,
    /// Fresh 32-byte Observer nonce, encoded as 64 lowercase hexadecimal bytes.
    pub nonce_hex: String,
    pub run_id: String,
    pub run_epoch: u64,
    pub cgroup_id: u64,
    pub cgroup_path: String,
    pub boot_id: String,
    /// Exact policy identity for the running kernel. The orchestrator decides
    /// whether this is a measured image digest or another authenticated ID.
    pub kernel_identity: String,
    pub observer_sha256: String,
    pub recorder_sha256: String,
    pub scope_sha256: String,
    /// Digest of the recorder-owned Program/Map/Link exclusion IDs resolved
    /// only after the recorder is loaded. The Host signs the actual value in
    /// all four responses, but cannot pre-provision an allowlist for dynamic
    /// kernel IDs. Its legitimate derivation relies on the exact authorized
    /// Observer/recorder digests and the cooperative exclusive-VM trust model;
    /// an offline verifier must recompute it from the finalized manifest.
    pub observer_exclusions_sha256: String,
    /// Exact argv, including argv[0]. No wildcard or prefix semantics exist.
    pub workload_argv: Vec<String>,
    /// Digest of the exact executable bytes selected by argv[0].
    pub workload_executable_sha256: String,
    pub s0_snapshot_id: String,
    pub s1_snapshot_id: String,
}

impl HarnessRunBinding {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != HARNESS_PROTOCOL_VERSION {
            bail!(
                "unsupported harness protocol version {}",
                self.protocol_version
            );
        }
        validate_nonce(&self.nonce_hex)?;
        validate_text(&self.run_id, "run_id")?;
        validate_cgroup_path(&self.cgroup_path, &self.run_id)?;
        validate_text(&self.boot_id, "boot_id")?;
        validate_text(&self.kernel_identity, "kernel_identity")?;
        if self.run_epoch == 0 || self.cgroup_id == 0 {
            bail!("run_epoch and cgroup_id must both be nonzero");
        }
        validate_sha256(&self.observer_sha256, "observer_sha256")?;
        validate_sha256(&self.recorder_sha256, "recorder_sha256")?;
        validate_sha256(&self.scope_sha256, "scope_sha256")?;
        validate_sha256(
            &self.observer_exclusions_sha256,
            "observer_exclusions_sha256",
        )?;
        validate_workload_argv(&self.workload_argv)?;
        validate_sha256(
            &self.workload_executable_sha256,
            "workload_executable_sha256",
        )?;
        let expected_s0 = format!("{}-S0", self.run_id);
        let expected_s1 = format!("{}-S1", self.run_id);
        if self.s0_snapshot_id != expected_s0 || self.s1_snapshot_id != expected_s1 {
            bail!("snapshot IDs are not deterministically bound to run_id");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessPostEvidence {
    pub s0_sha256: String,
    pub s1_sha256: String,
    pub health_sha256: String,
    pub canary_health_sha256: String,
    /// Digest of the durable framed WAL. Signing only recorder counters would
    /// leave the event history replaceable by another stream with the same
    /// accounting totals.
    pub raw_events_wal_sha256: String,
    /// Digest of the derived JSONL event stream, independently bound from the
    /// WAL so offline verification can reject a rewritten representation.
    pub raw_events_jsonl_sha256: String,
    /// Digests of the exact bounded workload streams committed by the run.
    pub workload_stdout_sha256: String,
    pub workload_stderr_sha256: String,
    /// The closed contract accepts only a normally exited, successful
    /// workload. Persisting and signing both fields prevents an unsuccessful
    /// endpoint from being reinterpreted as a successful unchanged run.
    pub workload_exit_code: i32,
    pub workload_signal: Option<i32>,
    /// Raw-tracepoint count of bpf() attempts made during the authenticated
    /// window by a non-Observer TGID outside the registered workload cgroup.
    /// The Host refuses to sign FINAL unless this negative evidence is zero.
    pub outside_cgroup_syscall_attempted: u64,
    pub recorder_drain_complete: bool,
    pub producer_barrier_complete: bool,
    pub wal_durable: bool,
    pub in_flight_bpf_barrier_complete: bool,
}

impl HarnessPostEvidence {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.s0_sha256, "s0_sha256")?;
        validate_sha256(&self.s1_sha256, "s1_sha256")?;
        validate_sha256(&self.health_sha256, "health_sha256")?;
        validate_sha256(&self.canary_health_sha256, "canary_health_sha256")?;
        validate_sha256(&self.raw_events_wal_sha256, "raw_events_wal_sha256")?;
        validate_sha256(&self.raw_events_jsonl_sha256, "raw_events_jsonl_sha256")?;
        validate_sha256(&self.workload_stdout_sha256, "workload_stdout_sha256")?;
        validate_sha256(&self.workload_stderr_sha256, "workload_stderr_sha256")?;
        if self.workload_exit_code != 0 || self.workload_signal.is_some() {
            bail!("exclusive-vm-v1 requires a successful normal workload exit");
        }
        if self.outside_cgroup_syscall_attempted != 0 {
            bail!("exclusive-vm-v1 observed a bpf() attempt by an outside actor");
        }
        if !self.recorder_drain_complete
            || !self.producer_barrier_complete
            || !self.wal_durable
            || !self.in_flight_bpf_barrier_complete
        {
            bail!("POST_S1 evidence does not prove every required closing barrier");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessPreS1Evidence {
    pub pre_health_sha256: String,
    pub cgroup_empty: bool,
    pub cgroup_frozen: bool,
}

impl HarnessPreS1Evidence {
    pub fn validate(&self) -> Result<()> {
        validate_sha256(&self.pre_health_sha256, "pre_health_sha256")?;
        if !self.cgroup_empty || !self.cgroup_frozen {
            bail!("PRE_S1 evidence does not prove an empty, frozen cgroup");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum HarnessPhase {
    PreS0,
    S0Committed,
    PreS1,
    Final,
}

impl HarnessPhase {
    pub fn sequence(self) -> u8 {
        match self {
            Self::PreS0 => 1,
            Self::S0Committed => 2,
            Self::PreS1 => 3,
            Self::Final => 4,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(
    tag = "phase",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum HarnessRequest {
    PreS0 {
        binding: HarnessRunBinding,
    },
    S0Committed {
        binding: HarnessRunBinding,
        s0_sha256: String,
    },
    PreS1 {
        binding: HarnessRunBinding,
        evidence: HarnessPreS1Evidence,
    },
    Final {
        binding: HarnessRunBinding,
        evidence: HarnessPostEvidence,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum HarnessPhaseEvidence {
    None,
    S0Committed { s0_sha256: String },
    PreS1 { evidence: HarnessPreS1Evidence },
    Final { evidence: HarnessPostEvidence },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct PolicyCheck {
    pub name: String,
    pub passed: bool,
    /// Machine-produced or immutable policy evidence. It is covered by the
    /// signed response and must never be interpreted as an unsigned assertion.
    pub evidence: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct AllowedWorkload {
    pub run_id: String,
    pub run_epoch: u64,
    pub cgroup_path: String,
    /// Exact argv match, including argv[0]. Empty argv and wildcards are invalid.
    pub argv: Vec<String>,
    /// Exact digest of the executable bytes, independently of pathname reuse.
    pub executable_sha256: String,
}

impl AllowedWorkload {
    fn matches(&self, binding: &HarnessRunBinding) -> bool {
        self.run_id == binding.run_id
            && self.run_epoch == binding.run_epoch
            && self.cgroup_path == binding.cgroup_path
            && self.argv == binding.workload_argv
            && self.executable_sha256 == binding.workload_executable_sha256
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessPolicy {
    pub protocol_version: u32,
    pub contract_id: String,
    pub policy_id: String,
    pub allowed_kernel_identities: BTreeSet<String>,
    pub allowed_observer_sha256: BTreeSet<String>,
    pub allowed_recorder_sha256: BTreeSet<String>,
    pub allowed_scope_sha256: BTreeSet<String>,
    /// Declares why dynamic observer-owned kernel IDs may be trusted even
    /// though their digest cannot be known before recorder load.
    pub observer_exclusions_derivation: String,
    pub allowed_workloads: Vec<AllowedWorkload>,
    pub checks: Vec<PolicyCheck>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedHarnessPolicy {
    pub policy_id: String,
    pub policy_sha256: String,
}

impl ExpectedHarnessPolicy {
    pub fn validate(&self) -> Result<()> {
        validate_text(&self.policy_id, "expected_policy_id")?;
        validate_sha256(&self.policy_sha256, "expected_policy_sha256")
    }
}

impl HarnessPolicy {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != HARNESS_PROTOCOL_VERSION {
            bail!(
                "unsupported policy protocol version {}",
                self.protocol_version
            );
        }
        if self.contract_id != HARNESS_CONTRACT_ID {
            bail!("unsupported harness contract {:?}", self.contract_id);
        }
        validate_text(&self.policy_id, "policy_id")?;
        validate_nonempty_set(&self.allowed_kernel_identities, "allowed_kernel_identities")?;
        for identity in &self.allowed_kernel_identities {
            validate_text(identity, "allowed kernel identity")?;
        }
        validate_digest_set(&self.allowed_observer_sha256, "allowed_observer_sha256")?;
        validate_digest_set(&self.allowed_recorder_sha256, "allowed_recorder_sha256")?;
        validate_digest_set(&self.allowed_scope_sha256, "allowed_scope_sha256")?;
        if self.observer_exclusions_derivation != OBSERVER_EXCLUSIONS_DERIVATION_V1 {
            bail!("observer_exclusions_derivation must be {OBSERVER_EXCLUSIONS_DERIVATION_V1}");
        }
        if self.allowed_workloads.is_empty() || self.allowed_workloads.len() > MAX_POLICY_ITEMS {
            bail!("allowed_workloads must contain 1..={MAX_POLICY_ITEMS} entries");
        }
        let mut workloads = BTreeSet::new();
        let mut run_ids = BTreeSet::new();
        let mut run_epochs = BTreeSet::new();
        let mut cgroup_paths = BTreeSet::new();
        for workload in &self.allowed_workloads {
            validate_text(&workload.run_id, "allowed workload run_id")?;
            if workload.run_epoch == 0 {
                bail!("allowed workload run_epoch must be nonzero");
            }
            validate_cgroup_path(&workload.cgroup_path, &workload.run_id)?;
            validate_workload_argv(&workload.argv)?;
            validate_sha256(&workload.executable_sha256, "allowed workload executable")?;
            if !workloads.insert(workload) {
                bail!("allowed_workloads contains a duplicate exact run authorization");
            }
            if !run_ids.insert(&workload.run_id)
                || !run_epochs.insert(workload.run_epoch)
                || !cgroup_paths.insert(&workload.cgroup_path)
            {
                bail!("allowed_workloads must use unique run IDs, epochs, and cgroup paths");
            }
        }
        validate_contract_checks(&self.checks, false)
    }

    pub fn authorize(&self, binding: &HarnessRunBinding) -> Result<()> {
        self.validate()?;
        binding.validate()?;
        if !self
            .allowed_kernel_identities
            .contains(&binding.kernel_identity)
        {
            bail!("kernel identity is not allowed by harness policy");
        }
        if !self
            .allowed_observer_sha256
            .contains(&binding.observer_sha256)
        {
            bail!("Observer digest is not allowed by harness policy");
        }
        if !self
            .allowed_recorder_sha256
            .contains(&binding.recorder_sha256)
        {
            bail!("recorder digest is not allowed by harness policy");
        }
        if !self.allowed_scope_sha256.contains(&binding.scope_sha256) {
            bail!("scope digest is not allowed by harness policy");
        }
        // observer_exclusions_sha256 contains recorder-owned kernel IDs, which
        // do not exist until after BPF load. It is deliberately signed as run
        // binding, not compared with an impossible pre-boot policy allowlist.
        if !self
            .allowed_workloads
            .iter()
            .any(|allowed| allowed.matches(binding))
        {
            bail!("run identity, workload argv, or executable is not allowed by harness policy");
        }
        validate_contract_checks(&self.checks, true)
    }

    pub fn canonical_sha256(&self) -> Result<String> {
        canonical_json_sha256(self)
    }

    fn canonical_checks(&self) -> Vec<PolicyCheck> {
        EXCLUSIVE_VM_V1_CHECKS
            .iter()
            .map(|required| {
                self.checks
                    .iter()
                    .find(|check| check.name == *required)
                    .expect("validated policy has every required check")
                    .clone()
            })
            .collect()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedHarnessResponse {
    pub protocol_version: u32,
    pub phase: HarnessPhase,
    pub sequence: u8,
    pub binding: HarnessRunBinding,
    pub phase_evidence: HarnessPhaseEvidence,
    pub contract_id: String,
    pub policy_id: String,
    pub policy_sha256: String,
    pub checks: Vec<PolicyCheck>,
    pub key_fingerprint_sha256: String,
    /// 64-byte Ed25519 signature encoded as 128 lowercase hexadecimal bytes.
    pub signature_hex: String,
}

/// Guest-to-Host transport acknowledgement sent only after the Guest has
/// received, authenticated, and validated the complete FINAL transcript.
/// It is not part of the persisted quiescence proof; it closes the transport
/// reliability handshake so the Host cannot tear down a virtio-serial bridge
/// while the signed FINAL frame is still in flight.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HarnessFinalAck {
    pub protocol_version: u32,
    pub phase: HarnessPhase,
    pub nonce_hex: String,
    pub run_id: String,
    pub run_epoch: u64,
    pub final_response_sha256: String,
}

impl HarnessFinalAck {
    pub fn from_response(response: &SignedHarnessResponse) -> Result<Self> {
        if response.phase != HarnessPhase::Final {
            bail!("FINAL_ACK can only acknowledge a FINAL response");
        }
        let ack = Self {
            protocol_version: HARNESS_PROTOCOL_VERSION,
            phase: HarnessPhase::Final,
            nonce_hex: response.binding.nonce_hex.clone(),
            run_id: response.binding.run_id.clone(),
            run_epoch: response.binding.run_epoch,
            final_response_sha256: canonical_json_sha256(response)?,
        };
        ack.validate()?;
        Ok(ack)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != HARNESS_PROTOCOL_VERSION {
            bail!("FINAL_ACK has an unsupported protocol version");
        }
        if self.phase != HarnessPhase::Final {
            bail!("FINAL_ACK phase must be FINAL");
        }
        validate_nonce(&self.nonce_hex)?;
        validate_text(&self.run_id, "FINAL_ACK run_id")?;
        if self.run_epoch == 0 {
            bail!("FINAL_ACK run_epoch must be nonzero");
        }
        validate_sha256(&self.final_response_sha256, "FINAL_ACK response digest")
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedHarnessTranscript {
    pub pre_s0: SignedHarnessResponse,
    pub s0_committed: SignedHarnessResponse,
    pub pre_s1: SignedHarnessResponse,
    pub final_response: SignedHarnessResponse,
}

#[derive(Serialize)]
struct UnsignedHarnessResponse<'a> {
    protocol_version: u32,
    phase: HarnessPhase,
    sequence: u8,
    binding: &'a HarnessRunBinding,
    phase_evidence: &'a HarnessPhaseEvidence,
    contract_id: &'a str,
    policy_id: &'a str,
    policy_sha256: &'a str,
    checks: &'a [PolicyCheck],
    key_fingerprint_sha256: &'a str,
}

impl SignedHarnessResponse {
    fn signing_bytes(&self) -> Result<Vec<u8>> {
        signed_struct_bytes(&UnsignedHarnessResponse {
            protocol_version: self.protocol_version,
            phase: self.phase,
            sequence: self.sequence,
            binding: &self.binding,
            phase_evidence: &self.phase_evidence,
            contract_id: &self.contract_id,
            policy_id: &self.policy_id,
            policy_sha256: &self.policy_sha256,
            checks: &self.checks,
            key_fingerprint_sha256: &self.key_fingerprint_sha256,
        })
    }
}

pub fn sign_response(
    keypair: &Keypair,
    policy: &HarnessPolicy,
    phase: HarnessPhase,
    binding: HarnessRunBinding,
    phase_evidence: HarnessPhaseEvidence,
) -> Result<SignedHarnessResponse> {
    validate_keypair(keypair)?;
    policy.authorize(&binding)?;
    validate_phase_evidence(phase, &phase_evidence)?;
    let checks = if phase == HarnessPhase::Final {
        policy.canonical_checks()
    } else {
        Vec::new()
    };
    let mut response = SignedHarnessResponse {
        protocol_version: HARNESS_PROTOCOL_VERSION,
        phase,
        sequence: phase.sequence(),
        binding,
        phase_evidence,
        contract_id: policy.contract_id.clone(),
        policy_id: policy.policy_id.clone(),
        policy_sha256: policy.canonical_sha256()?,
        checks,
        key_fingerprint_sha256: public_key_fingerprint(&keypair.public),
        signature_hex: String::new(),
    };
    response.signature_hex = encode_hex(&keypair.sign(&response.signing_bytes()?).to_bytes());
    Ok(response)
}

pub fn verify_response(response: &SignedHarnessResponse, public_key: &PublicKey) -> Result<()> {
    if response.protocol_version != HARNESS_PROTOCOL_VERSION {
        bail!("signed response has an unsupported protocol version");
    }
    if response.sequence != response.phase.sequence() {
        bail!("signed response sequence does not match its phase");
    }
    response.binding.validate()?;
    validate_phase_evidence(response.phase, &response.phase_evidence)?;
    if response.contract_id != HARNESS_CONTRACT_ID {
        bail!("signed response has an unsupported contract");
    }
    validate_text(&response.policy_id, "signed policy_id")?;
    validate_sha256(&response.policy_sha256, "signed policy_sha256")?;
    if response.phase == HarnessPhase::Final {
        validate_contract_checks(&response.checks, true)?;
    } else if !response.checks.is_empty() {
        bail!("only FINAL may contain exclusive-vm-v1 policy checks");
    }
    let expected_fingerprint = public_key_fingerprint(public_key);
    if response.key_fingerprint_sha256 != expected_fingerprint {
        bail!("signed response key fingerprint does not match the trusted public key");
    }
    let signature_bytes = decode_fixed_hex::<64>(&response.signature_hex, "signature_hex")?;
    let signature = Signature::from_bytes(&signature_bytes).context("decode Ed25519 signature")?;
    public_key
        .verify(&response.signing_bytes()?, &signature)
        .context("verify harness response signature")
}

pub fn verify_transcript(
    transcript: &AuthenticatedHarnessTranscript,
    public_key: &PublicKey,
    expected_binding: &HarnessRunBinding,
    expected_s0_sha256: &str,
    expected_pre_s1_evidence: &HarnessPreS1Evidence,
    expected_post_evidence: &HarnessPostEvidence,
    expected_policy: &ExpectedHarnessPolicy,
) -> Result<()> {
    expected_binding.validate()?;
    validate_sha256(expected_s0_sha256, "expected_s0_sha256")?;
    expected_pre_s1_evidence.validate()?;
    expected_post_evidence.validate()?;
    expected_policy.validate()?;
    verify_response(&transcript.pre_s0, public_key).context("verify PRE_S0 response")?;
    verify_response(&transcript.s0_committed, public_key)
        .context("verify S0_COMMITTED response")?;
    verify_response(&transcript.pre_s1, public_key).context("verify PRE_S1 response")?;
    verify_response(&transcript.final_response, public_key).context("verify FINAL response")?;
    if transcript.pre_s0.phase != HarnessPhase::PreS0
        || transcript.s0_committed.phase != HarnessPhase::S0Committed
        || transcript.pre_s1.phase != HarnessPhase::PreS1
        || transcript.final_response.phase != HarnessPhase::Final
    {
        bail!("transcript phases are not exactly PRE_S0, S0_COMMITTED, PRE_S1, FINAL");
    }
    if transcript.pre_s0.binding != *expected_binding
        || transcript.s0_committed.binding != *expected_binding
        || transcript.pre_s1.binding != *expected_binding
        || transcript.final_response.binding != *expected_binding
    {
        bail!("transcript binding does not match the expected run");
    }
    if transcript.s0_committed.phase_evidence
        != (HarnessPhaseEvidence::S0Committed {
            s0_sha256: expected_s0_sha256.to_owned(),
        })
        || transcript.pre_s1.phase_evidence
            != (HarnessPhaseEvidence::PreS1 {
                evidence: expected_pre_s1_evidence.clone(),
            })
        || transcript.final_response.phase_evidence
            != (HarnessPhaseEvidence::Final {
                evidence: expected_post_evidence.clone(),
            })
    {
        bail!("transcript phase evidence does not match the expected run artifacts");
    }
    if expected_post_evidence.s0_sha256 != expected_s0_sha256 {
        bail!("FINAL S0 digest does not match S0_COMMITTED");
    }
    if transcript.pre_s0.policy_id != expected_policy.policy_id
        || transcript.s0_committed.policy_id != expected_policy.policy_id
        || transcript.pre_s1.policy_id != expected_policy.policy_id
        || transcript.final_response.policy_id != expected_policy.policy_id
    {
        bail!("transcript policy ID does not match trusted policy");
    }
    let responses = [
        &transcript.pre_s0,
        &transcript.s0_committed,
        &transcript.pre_s1,
        &transcript.final_response,
    ];
    if responses.iter().any(|response| {
        response.contract_id != transcript.pre_s0.contract_id
            || response.key_fingerprint_sha256 != transcript.pre_s0.key_fingerprint_sha256
            || response.policy_sha256 != expected_policy.policy_sha256
    }) {
        bail!("signed transcript policy identity or key is inconsistent");
    }
    Ok(())
}

fn validate_phase_evidence(phase: HarnessPhase, evidence: &HarnessPhaseEvidence) -> Result<()> {
    match (phase, evidence) {
        (HarnessPhase::PreS0, HarnessPhaseEvidence::None) => Ok(()),
        (HarnessPhase::S0Committed, HarnessPhaseEvidence::S0Committed { s0_sha256 }) => {
            validate_sha256(s0_sha256, "s0_sha256")
        }
        (HarnessPhase::PreS1, HarnessPhaseEvidence::PreS1 { evidence }) => evidence.validate(),
        (HarnessPhase::Final, HarnessPhaseEvidence::Final { evidence }) => evidence.validate(),
        _ => bail!("signed response phase and evidence variant disagree"),
    }
}

/// One fail-closed server-side state machine. A process may accept only one
/// connection, while this type additionally rejects repeated phases and nonce
/// replay within that connection.
pub struct HarnessServerSession {
    policy: HarnessPolicy,
    state: ServerState,
    seen_nonces: HashSet<String>,
    max_sessions: u32,
    completed_sessions: u32,
}

enum ServerState {
    AwaitingPre,
    AwaitingS0Commit(HarnessRunBinding),
    AwaitingPreS1 {
        binding: HarnessRunBinding,
        s0_sha256: String,
    },
    AwaitingFinal {
        binding: HarnessRunBinding,
        s0_sha256: String,
        pre_s1_evidence: HarnessPreS1Evidence,
    },
    AwaitingFinalAck(HarnessFinalAck),
    Complete,
    Failed,
}

impl HarnessServerSession {
    pub fn new(policy: HarnessPolicy) -> Result<Self> {
        Self::with_max_sessions(policy, 1)
    }

    pub fn with_max_sessions(policy: HarnessPolicy, max_sessions: u32) -> Result<Self> {
        policy.validate()?;
        if max_sessions == 0 || max_sessions > MAX_SERVER_SESSIONS {
            bail!("max_sessions must be in 1..={MAX_SERVER_SESSIONS}");
        }
        if usize::try_from(max_sessions).ok() != Some(policy.allowed_workloads.len()) {
            bail!("max_sessions must equal the exact ordered workload authorization count");
        }
        Ok(Self {
            policy,
            state: ServerState::AwaitingPre,
            seen_nonces: HashSet::new(),
            max_sessions,
            completed_sessions: 0,
        })
    }

    pub fn handle(
        &mut self,
        request: HarnessRequest,
        keypair: &Keypair,
    ) -> Result<SignedHarnessResponse> {
        let result = self.handle_inner(request, keypair);
        if result.is_err() {
            self.state = ServerState::Failed;
        }
        result
    }

    fn handle_inner(
        &mut self,
        request: HarnessRequest,
        keypair: &Keypair,
    ) -> Result<SignedHarnessResponse> {
        match request {
            HarnessRequest::PreS0 { binding } => {
                if self.seen_nonces.contains(&binding.nonce_hex) {
                    bail!("replayed harness nonce");
                }
                if !matches!(self.state, ServerState::AwaitingPre) {
                    bail!("PRE_S0 is out of order or a concurrent run is active");
                }
                let workload_index = usize::try_from(self.completed_sessions)
                    .context("completed session index overflow")?;
                let expected_workload = self
                    .policy
                    .allowed_workloads
                    .get(workload_index)
                    .context("policy has no remaining one-shot workload authorization")?;
                if !expected_workload.matches(&binding) {
                    bail!("PRE_S0 does not match the next ordered one-shot workload authorization");
                }
                self.policy.authorize(&binding)?;
                self.seen_nonces.insert(binding.nonce_hex.clone());
                let response = sign_response(
                    keypair,
                    &self.policy,
                    HarnessPhase::PreS0,
                    binding.clone(),
                    HarnessPhaseEvidence::None,
                )?;
                self.state = ServerState::AwaitingS0Commit(binding);
                Ok(response)
            }
            HarnessRequest::S0Committed { binding, s0_sha256 } => {
                let expected = match &self.state {
                    ServerState::AwaitingS0Commit(expected) => expected,
                    _ => bail!("S0_COMMITTED is out of order"),
                };
                if binding != *expected {
                    bail!("S0_COMMITTED binding differs from PRE_S0");
                }
                validate_sha256(&s0_sha256, "s0_sha256")?;
                let response = sign_response(
                    keypair,
                    &self.policy,
                    HarnessPhase::S0Committed,
                    binding.clone(),
                    HarnessPhaseEvidence::S0Committed {
                        s0_sha256: s0_sha256.clone(),
                    },
                )?;
                self.state = ServerState::AwaitingPreS1 { binding, s0_sha256 };
                Ok(response)
            }
            HarnessRequest::PreS1 { binding, evidence } => {
                let (expected, s0_sha256) = match &self.state {
                    ServerState::AwaitingPreS1 { binding, s0_sha256 } => (binding, s0_sha256),
                    _ => bail!("PRE_S1 is out of order"),
                };
                if binding != *expected {
                    bail!("PRE_S1 binding differs from PRE_S0");
                }
                evidence.validate()?;
                let response = sign_response(
                    keypair,
                    &self.policy,
                    HarnessPhase::PreS1,
                    binding.clone(),
                    HarnessPhaseEvidence::PreS1 {
                        evidence: evidence.clone(),
                    },
                )?;
                self.state = ServerState::AwaitingFinal {
                    binding,
                    s0_sha256: s0_sha256.clone(),
                    pre_s1_evidence: evidence,
                };
                Ok(response)
            }
            HarnessRequest::Final { binding, evidence } => {
                let (expected, s0_sha256, pre_s1_evidence) = match &self.state {
                    ServerState::AwaitingFinal {
                        binding,
                        s0_sha256,
                        pre_s1_evidence,
                    } => (binding, s0_sha256, pre_s1_evidence),
                    _ => bail!("FINAL is out of order"),
                };
                if binding != *expected {
                    bail!("FINAL binding differs from PRE_S0");
                }
                evidence.validate()?;
                if evidence.s0_sha256 != *s0_sha256 {
                    bail!("FINAL S0 digest differs from S0_COMMITTED");
                }
                // Reading this state is intentional: the lease remains bound
                // to the exact PRE_S1 barrier until FINAL succeeds.
                pre_s1_evidence.validate()?;
                let response = sign_response(
                    keypair,
                    &self.policy,
                    HarnessPhase::Final,
                    binding,
                    HarnessPhaseEvidence::Final { evidence },
                )?;
                self.state =
                    ServerState::AwaitingFinalAck(HarnessFinalAck::from_response(&response)?);
                Ok(response)
            }
        }
    }

    pub fn acknowledge_final(&mut self, ack: HarnessFinalAck) -> Result<()> {
        let result = self.acknowledge_final_inner(ack);
        if result.is_err() {
            self.state = ServerState::Failed;
        }
        result
    }

    fn acknowledge_final_inner(&mut self, ack: HarnessFinalAck) -> Result<()> {
        ack.validate()?;
        let expected = match &self.state {
            ServerState::AwaitingFinalAck(expected) => expected,
            _ => bail!("FINAL_ACK is out of order"),
        };
        if ack != *expected {
            bail!("FINAL_ACK does not match the signed FINAL response");
        }
        self.completed_sessions = self
            .completed_sessions
            .checked_add(1)
            .context("completed session count overflow")?;
        self.state = if self.completed_sessions == self.max_sessions {
            ServerState::Complete
        } else {
            ServerState::AwaitingPre
        };
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        matches!(self.state, ServerState::Complete)
    }

    pub fn completed_sessions(&self) -> u32 {
        self.completed_sessions
    }
}

pub fn generate_keypair() -> Result<Keypair> {
    let mut seed = random_32_bytes("Ed25519 seed")?;
    let secret = SecretKey::from_bytes(&seed).context("construct Ed25519 secret key")?;
    seed.fill(0);
    let public = PublicKey::from(&secret);
    Ok(Keypair { secret, public })
}

pub fn generate_nonce_hex() -> Result<String> {
    let bytes = random_32_bytes("harness nonce")?;
    Ok(encode_hex(&bytes))
}

pub fn sha256_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

/// Hash a deterministic JSON encoding. Object keys are recursively sorted;
/// array order is retained because it is part of the serialized protocol
/// semantics (notably exact workload argv).
pub fn canonical_json_sha256<T: Serialize>(value: &T) -> Result<String> {
    let value = serde_json::to_value(value).context("convert value to canonical JSON tree")?;
    let mut bytes = Vec::new();
    write_canonical_json(&value, &mut bytes)?;
    Ok(sha256_hex(&bytes))
}

pub fn write_keypair(
    keypair: &Keypair,
    secret_key_path: &Path,
    public_key_path: &Path,
) -> Result<()> {
    if secret_key_path == public_key_path {
        bail!("secret and public key paths must differ");
    }
    validate_keypair(keypair)?;
    write_new_file(secret_key_path, &keypair.to_bytes(), 0o600)
        .context("write private Ed25519 keypair")?;
    if let Err(error) = write_new_file(public_key_path, keypair.public.as_bytes(), 0o644) {
        let _ = remove_exact_regular_file(secret_key_path);
        return Err(error).context("write Ed25519 public key");
    }
    Ok(())
}

/// Read the 64-byte private keypair file created by [`write_keypair`].
pub fn read_secret_key(path: &Path) -> Result<Keypair> {
    let bytes = read_exact_regular_file(path, 64, true)?;
    let keypair = Keypair::from_bytes(&bytes).context("decode private Ed25519 keypair")?;
    validate_keypair(&keypair)?;
    Ok(keypair)
}

pub fn read_public_key(path: &Path) -> Result<PublicKey> {
    let bytes = read_exact_regular_file(path, 32, false)?;
    PublicKey::from_bytes(&bytes).context("decode Ed25519 public key")
}

pub fn public_key_fingerprint(public_key: &PublicKey) -> String {
    sha256_hex(public_key.as_bytes())
}

pub fn read_policy(path: &Path) -> Result<HarnessPolicy> {
    let policy: HarnessPolicy = read_json_bounded(path, MAX_POLICY_BYTES)?;
    policy.validate()?;
    Ok(policy)
}

pub fn read_json_value_bounded(path: &Path, limit: u64) -> Result<serde_json::Value> {
    if limit == 0 || limit > MAX_CANONICAL_JSON_BYTES {
        bail!("JSON input limit must be in 1..={MAX_CANONICAL_JSON_BYTES}");
    }
    read_json_bounded(path, limit)
}

pub fn read_frame<R: Read>(reader: &mut R) -> Result<Option<HarnessRequest>> {
    read_typed_frame(reader)
}

pub fn write_response_frame<W: Write>(
    writer: &mut W,
    response: &SignedHarnessResponse,
) -> Result<()> {
    write_typed_frame(writer, response)
}

pub fn read_response_frame<R: Read>(reader: &mut R) -> Result<Option<SignedHarnessResponse>> {
    read_typed_frame(reader)
}

pub fn write_request_frame<W: Write>(writer: &mut W, request: &HarnessRequest) -> Result<()> {
    write_typed_frame(writer, request)
}

pub fn read_final_ack_frame<R: Read>(reader: &mut R) -> Result<Option<HarnessFinalAck>> {
    read_typed_frame(reader)
}

pub fn write_final_ack_frame<W: Write>(writer: &mut W, ack: &HarnessFinalAck) -> Result<()> {
    ack.validate()?;
    write_typed_frame(writer, ack)
}

fn signed_struct_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = serde_json::to_vec(value).context("serialize deterministic signed payload")?;
    if body.len() > MAX_FRAME_BYTES {
        bail!("signed payload exceeds {MAX_FRAME_BYTES} bytes");
    }
    let body_len = u64::try_from(body.len()).context("signed payload length overflow")?;
    let mut framed = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 8 + body.len());
    framed.extend_from_slice(SIGNATURE_DOMAIN);
    framed.extend_from_slice(&body_len.to_be_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

fn read_typed_frame<R: Read, T: DeserializeOwned>(reader: &mut R) -> Result<Option<T>> {
    let mut length = [0_u8; 4];
    match reader.read(&mut length[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(error) => return Err(error).context("read harness frame prefix"),
    }
    reader
        .read_exact(&mut length[1..])
        .context("read harness frame length")?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        bail!("harness frame length {length} is outside 1..={MAX_FRAME_BYTES}");
    }
    let mut body = vec![0_u8; length];
    reader
        .read_exact(&mut body)
        .context("read harness frame body")?;
    serde_json::from_slice(&body).context("decode harness frame JSON")
}

fn write_typed_frame<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let body = serde_json::to_vec(value).context("encode harness frame JSON")?;
    if body.is_empty() || body.len() > MAX_FRAME_BYTES {
        bail!("harness frame length is outside 1..={MAX_FRAME_BYTES}");
    }
    let length = u32::try_from(body.len()).context("harness frame length overflow")?;
    writer
        .write_all(&length.to_be_bytes())
        .context("write harness frame length")?;
    writer
        .write_all(&body)
        .context("write harness frame body")?;
    writer.flush().context("flush harness frame")
}

fn validate_nonce(value: &str) -> Result<()> {
    let bytes = decode_fixed_hex::<32>(value, "nonce_hex")?;
    if bytes.iter().all(|byte| *byte == 0) {
        bail!("nonce_hex must not be all zero");
    }
    Ok(())
}

fn validate_sha256(value: &str, field: &str) -> Result<()> {
    let _ = decode_fixed_hex::<32>(value, field)?;
    Ok(())
}

fn validate_text(value: &str, field: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        bail!("{field} must contain 1..={MAX_IDENTIFIER_BYTES} non-NUL UTF-8 bytes");
    }
    Ok(())
}

fn validate_cgroup_path(path: &str, run_id: &str) -> Result<()> {
    validate_text(path, "cgroup_path")?;
    if run_id == "." || run_id == ".." || run_id.contains('/') {
        bail!("run_id is not safe as a cgroup path component");
    }
    if !path.starts_with('/') || path == "/" || path.ends_with('/') || path.contains("//") {
        bail!("cgroup_path must be a normalized non-root absolute path");
    }
    if path
        .split('/')
        .skip(1)
        .any(|component| component.is_empty() || component == "." || component == "..")
    {
        bail!("cgroup_path contains a non-canonical component");
    }
    if path.rsplit('/').next() != Some(run_id) {
        bail!("cgroup_path final component is not bound to run_id");
    }
    Ok(())
}

fn validate_workload_argv(argv: &[String]) -> Result<()> {
    if argv.is_empty() || argv.len() > MAX_WORKLOAD_ARGS {
        bail!("workload argv must contain 1..={MAX_WORKLOAD_ARGS} arguments");
    }
    let mut total = 0_usize;
    for argument in argv {
        if argument.is_empty() && total == 0 {
            bail!("workload argv[0] must not be empty");
        }
        if argument.len() > MAX_WORKLOAD_ARG_BYTES || argument.contains('\0') {
            bail!("workload argument exceeds its size limit or contains NUL");
        }
        total = total
            .checked_add(argument.len())
            .context("workload argv byte count overflow")?;
        if total > MAX_WORKLOAD_TOTAL_BYTES {
            bail!("workload argv exceeds {MAX_WORKLOAD_TOTAL_BYTES} bytes");
        }
    }
    Ok(())
}

fn validate_nonempty_set(values: &BTreeSet<String>, field: &str) -> Result<()> {
    if values.is_empty() || values.len() > MAX_POLICY_ITEMS {
        bail!("{field} must contain 1..={MAX_POLICY_ITEMS} entries");
    }
    Ok(())
}

fn validate_digest_set(values: &BTreeSet<String>, field: &str) -> Result<()> {
    validate_nonempty_set(values, field)?;
    for value in values {
        validate_sha256(value, field)?;
    }
    Ok(())
}

fn validate_contract_checks(checks: &[PolicyCheck], require_passed: bool) -> Result<()> {
    if checks.len() != EXCLUSIVE_VM_V1_CHECKS.len() {
        bail!(
            "exclusive-vm-v1 requires exactly {} policy checks",
            EXCLUSIVE_VM_V1_CHECKS.len()
        );
    }
    let mut names = BTreeSet::new();
    for check in checks {
        validate_text(&check.name, "policy check name")?;
        validate_text(&check.evidence, "policy check evidence")?;
        if !EXCLUSIVE_VM_V1_CHECKS.contains(&check.name.as_str()) {
            bail!("unknown exclusive-vm-v1 policy check {:?}", check.name);
        }
        if !names.insert(check.name.as_str()) {
            bail!("duplicate exclusive-vm-v1 policy check {:?}", check.name);
        }
        if require_passed && !check.passed {
            bail!("exclusive-vm-v1 policy check {:?} did not pass", check.name);
        }
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    encode_hex(&hasher.finalize())
}

fn write_canonical_json(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(true) => output.extend_from_slice(b"true"),
        serde_json::Value::Bool(false) => output.extend_from_slice(b"false"),
        serde_json::Value::Number(number) => {
            output.extend_from_slice(number.to_string().as_bytes())
        }
        serde_json::Value::String(string) => {
            serde_json::to_writer(&mut *output, string).context("encode canonical JSON string")?;
        }
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                serde_json::to_writer(&mut *output, key)
                    .context("encode canonical JSON object key")?;
                output.push(b':');
                write_canonical_json(
                    values
                        .get(key)
                        .expect("canonical JSON key came from the same object"),
                    output,
                )?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn random_32_bytes(purpose: &str) -> Result<[u8; 32]> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .context("open /dev/urandom")?
        .read_exact(&mut bytes)
        .with_context(|| format!("read {purpose} from /dev/urandom"))?;
    Ok(bytes)
}

fn validate_keypair(keypair: &Keypair) -> Result<()> {
    let derived_public = PublicKey::from(&keypair.secret);
    if derived_public != keypair.public {
        bail!("Ed25519 keypair contains a public key unrelated to its secret key");
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_fixed_hex<const N: usize>(value: &str, field: &str) -> Result<[u8; N]> {
    if value.len() != N * 2 {
        bail!(
            "{field} must contain exactly {} lowercase hexadecimal bytes",
            N * 2
        );
    }
    let mut output = [0_u8; N];
    let bytes = value.as_bytes();
    for index in 0..N {
        let high = decode_hex_nibble(bytes[index * 2])
            .with_context(|| format!("{field} is not lowercase hexadecimal"))?;
        let low = decode_hex_nibble(bytes[index * 2 + 1])
            .with_context(|| format!("{field} is not lowercase hexadecimal"))?;
        output[index] = (high << 4) | low;
    }
    Ok(output)
}

fn decode_hex_nibble(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(anyhow!("invalid hexadecimal nibble")),
    }
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u32) -> Result<()> {
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("create new key file {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write key file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("fsync key file {}", path.display()))?;
    Ok(())
}

fn read_exact_regular_file(path: &Path, expected: usize, private: bool) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("open key file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect key file {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() != expected as u64
    {
        bail!("key file must be a singly-linked regular file of exactly {expected} bytes");
    }
    if private && metadata.mode() & 0o077 != 0 {
        bail!("private key file must not be accessible by group or other users");
    }
    let mut bytes = vec![0_u8; expected];
    file.read_exact(&mut bytes)
        .with_context(|| format!("read key file {}", path.display()))?;
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .context("check key file trailing bytes")?
        != 0
    {
        bail!("key file changed while it was read");
    }
    Ok(bytes)
}

fn read_json_bounded<T: DeserializeOwned>(path: &Path, limit: u64) -> Result<T> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("open JSON file {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect JSON file {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 || metadata.len() > limit {
        bail!("JSON input must be a singly-linked regular file no larger than {limit} bytes");
    }
    let reader = file.take(limit + 1);
    serde_json::from_reader(reader).with_context(|| format!("decode JSON file {}", path.display()))
}

fn remove_exact_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.nlink() != 1 {
        bail!("refusing to remove a key path that is not a singly-linked regular file");
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn digest(byte: char) -> String {
        std::iter::repeat(byte).take(64).collect()
    }

    fn binding() -> HarnessRunBinding {
        HarnessRunBinding {
            protocol_version: HARNESS_PROTOCOL_VERSION,
            nonce_hex: digest('1'),
            run_id: "fixture-run".into(),
            run_epoch: 7,
            cgroup_id: 9,
            cgroup_path: "/sys/fs/cgroup/bpf-state-observer/fixture-run".into(),
            boot_id: "fixture-boot".into(),
            kernel_identity: "kernel-sha256:fixture".into(),
            observer_sha256: digest('2'),
            recorder_sha256: digest('3'),
            scope_sha256: digest('4'),
            observer_exclusions_sha256: digest('a'),
            workload_argv: vec!["/bin/true".into()],
            workload_executable_sha256: digest('b'),
            s0_snapshot_id: "fixture-run-S0".into(),
            s1_snapshot_id: "fixture-run-S1".into(),
        }
    }

    fn binding_for(run_id: &str, nonce_byte: char, cgroup_id: u64) -> HarnessRunBinding {
        let mut value = binding();
        value.nonce_hex = digest(nonce_byte);
        value.run_id = run_id.into();
        value.run_epoch = cgroup_id;
        value.cgroup_id = cgroup_id;
        value.cgroup_path = format!("/sys/fs/cgroup/bpf-state-observer/{run_id}");
        value.s0_snapshot_id = format!("{run_id}-S0");
        value.s1_snapshot_id = format!("{run_id}-S1");
        value
    }

    fn post_evidence() -> HarnessPostEvidence {
        HarnessPostEvidence {
            s0_sha256: digest('5'),
            s1_sha256: digest('6'),
            health_sha256: digest('7'),
            canary_health_sha256: digest('8'),
            raw_events_wal_sha256: digest('9'),
            raw_events_jsonl_sha256: digest('a'),
            workload_stdout_sha256: digest('b'),
            workload_stderr_sha256: digest('c'),
            workload_exit_code: 0,
            workload_signal: None,
            outside_cgroup_syscall_attempted: 0,
            recorder_drain_complete: true,
            producer_barrier_complete: true,
            wal_durable: true,
            in_flight_bpf_barrier_complete: true,
        }
    }

    fn pre_s1_evidence() -> HarnessPreS1Evidence {
        HarnessPreS1Evidence {
            pre_health_sha256: digest('d'),
            cgroup_empty: true,
            cgroup_frozen: true,
        }
    }

    fn checks() -> Vec<PolicyCheck> {
        EXCLUSIVE_VM_V1_CHECKS
            .iter()
            .map(|name| PolicyCheck {
                name: (*name).into(),
                passed: true,
                evidence: format!("fixture evidence for {name}"),
            })
            .collect()
    }

    fn policy() -> HarnessPolicy {
        let binding = binding();
        HarnessPolicy {
            protocol_version: HARNESS_PROTOCOL_VERSION,
            contract_id: HARNESS_CONTRACT_ID.into(),
            policy_id: "fixture-policy".into(),
            allowed_kernel_identities: [binding.kernel_identity].into_iter().collect(),
            allowed_observer_sha256: [binding.observer_sha256].into_iter().collect(),
            allowed_recorder_sha256: [binding.recorder_sha256].into_iter().collect(),
            allowed_scope_sha256: [binding.scope_sha256].into_iter().collect(),
            observer_exclusions_derivation: OBSERVER_EXCLUSIONS_DERIVATION_V1.into(),
            allowed_workloads: vec![AllowedWorkload {
                run_id: binding.run_id,
                run_epoch: binding.run_epoch,
                cgroup_path: binding.cgroup_path,
                argv: binding.workload_argv,
                executable_sha256: binding.workload_executable_sha256,
            }],
            checks: checks(),
        }
    }

    fn allowed_workload(binding: &HarnessRunBinding) -> AllowedWorkload {
        AllowedWorkload {
            run_id: binding.run_id.clone(),
            run_epoch: binding.run_epoch,
            cgroup_path: binding.cgroup_path.clone(),
            argv: binding.workload_argv.clone(),
            executable_sha256: binding.workload_executable_sha256.clone(),
        }
    }

    fn expected_policy() -> ExpectedHarnessPolicy {
        ExpectedHarnessPolicy {
            policy_id: "fixture-policy".into(),
            policy_sha256: policy().canonical_sha256().unwrap(),
        }
    }

    fn keypair(seed: u8) -> Keypair {
        let secret = SecretKey::from_bytes(&[seed; 32]).unwrap();
        let public = PublicKey::from(&secret);
        Keypair { secret, public }
    }

    fn transcript(keypair: &Keypair) -> AuthenticatedHarnessTranscript {
        transcript_for(keypair, binding())
    }

    fn transcript_for(
        keypair: &Keypair,
        binding: HarnessRunBinding,
    ) -> AuthenticatedHarnessTranscript {
        let policy = policy();
        let evidence = post_evidence();
        AuthenticatedHarnessTranscript {
            pre_s0: sign_response(
                keypair,
                &policy,
                HarnessPhase::PreS0,
                binding.clone(),
                HarnessPhaseEvidence::None,
            )
            .unwrap(),
            s0_committed: sign_response(
                keypair,
                &policy,
                HarnessPhase::S0Committed,
                binding.clone(),
                HarnessPhaseEvidence::S0Committed {
                    s0_sha256: evidence.s0_sha256.clone(),
                },
            )
            .unwrap(),
            pre_s1: sign_response(
                keypair,
                &policy,
                HarnessPhase::PreS1,
                binding.clone(),
                HarnessPhaseEvidence::PreS1 {
                    evidence: pre_s1_evidence(),
                },
            )
            .unwrap(),
            final_response: sign_response(
                keypair,
                &policy,
                HarnessPhase::Final,
                binding,
                HarnessPhaseEvidence::Final { evidence },
            )
            .unwrap(),
        }
    }

    fn complete_server_session(
        server: &mut HarnessServerSession,
        keypair: &Keypair,
        binding: HarnessRunBinding,
    ) {
        server
            .handle(
                HarnessRequest::PreS0 {
                    binding: binding.clone(),
                },
                keypair,
            )
            .unwrap();
        server
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding.clone(),
                    s0_sha256: post_evidence().s0_sha256,
                },
                keypair,
            )
            .unwrap();
        server
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding.clone(),
                    evidence: pre_s1_evidence(),
                },
                keypair,
            )
            .unwrap();
        let final_response = server
            .handle(
                HarnessRequest::Final {
                    binding,
                    evidence: post_evidence(),
                },
                keypair,
            )
            .unwrap();
        assert!(!server.is_complete());
        server
            .acknowledge_final(HarnessFinalAck::from_response(&final_response).unwrap())
            .unwrap();
    }

    #[test]
    fn signed_transcript_round_trip_and_determinism() {
        let keypair = keypair(11);
        let signed_transcript = transcript(&keypair);
        verify_transcript(
            &signed_transcript,
            &keypair.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy(),
        )
        .unwrap();
        let second = transcript(&keypair);
        assert_eq!(signed_transcript, second);
    }

    #[test]
    fn final_artifact_digests_and_exit_are_validated_and_transcript_bound() {
        let invalid_digest_mutations: [fn(&mut HarnessPostEvidence); 4] = [
            |evidence| evidence.raw_events_wal_sha256 = "not-a-digest".into(),
            |evidence| evidence.raw_events_jsonl_sha256 = "not-a-digest".into(),
            |evidence| evidence.workload_stdout_sha256 = "not-a-digest".into(),
            |evidence| evidence.workload_stderr_sha256 = "not-a-digest".into(),
        ];
        for mutate in invalid_digest_mutations {
            let mut evidence = post_evidence();
            mutate(&mut evidence);
            assert!(evidence.validate().is_err());
        }
        let mut failed_exit = post_evidence();
        failed_exit.workload_exit_code = 1;
        assert!(failed_exit.validate().is_err());
        let mut signaled_exit = post_evidence();
        signaled_exit.workload_signal = Some(libc::SIGKILL);
        assert!(signaled_exit.validate().is_err());

        let keypair = keypair(31);
        let signed_transcript = transcript(&keypair);
        let valid_digest_mutations: [fn(&mut HarnessPostEvidence); 4] = [
            |evidence| evidence.raw_events_wal_sha256 = digest('d'),
            |evidence| evidence.raw_events_jsonl_sha256 = digest('d'),
            |evidence| evidence.workload_stdout_sha256 = digest('d'),
            |evidence| evidence.workload_stderr_sha256 = digest('d'),
        ];
        for mutate in valid_digest_mutations {
            let mut expected_post = post_evidence();
            mutate(&mut expected_post);
            assert!(verify_transcript(
                &signed_transcript,
                &keypair.public,
                &binding(),
                &post_evidence().s0_sha256,
                &pre_s1_evidence(),
                &expected_post,
                &expected_policy(),
            )
            .is_err());
        }
        let mut mismatched_exit = post_evidence();
        mismatched_exit.workload_exit_code = 1;
        assert!(verify_transcript(
            &signed_transcript,
            &keypair.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &mismatched_exit,
            &expected_policy(),
        )
        .is_err());
    }

    #[test]
    fn wrong_signature_and_wrong_key_are_rejected() {
        let signing_key = keypair(12);
        let mut signed_transcript = transcript(&signing_key);
        let replacement = if signed_transcript
            .final_response
            .signature_hex
            .starts_with("00")
        {
            "01"
        } else {
            "00"
        };
        signed_transcript
            .final_response
            .signature_hex
            .replace_range(0..2, replacement);
        assert!(verify_transcript(
            &signed_transcript,
            &signing_key.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy()
        )
        .is_err());

        let signed_transcript = transcript(&signing_key);
        assert!(verify_transcript(
            &signed_transcript,
            &keypair(13).public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy()
        )
        .is_err());
    }

    #[test]
    fn phase_confusion_and_inconsistent_binding_are_rejected() {
        let keypair = keypair(14);
        let mut transcript = transcript(&keypair);
        std::mem::swap(&mut transcript.pre_s0, &mut transcript.s0_committed);
        assert!(verify_transcript(
            &transcript,
            &keypair.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy()
        )
        .is_err());

        let policy = policy();
        let mut session = HarnessServerSession::new(policy).unwrap();
        session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        let mut changed = binding();
        changed.run_epoch += 1;
        assert!(session
            .handle(
                HarnessRequest::S0Committed {
                    binding: changed,
                    s0_sha256: post_evidence().s0_sha256,
                },
                &keypair,
            )
            .is_err());
    }

    #[test]
    fn replayed_nonce_and_concurrent_pre_are_rejected() {
        let keypair = keypair(15);
        let mut session = HarnessServerSession::new(policy()).unwrap();
        session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        assert!(session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair,)
            .unwrap_err()
            .to_string()
            .contains("replayed"));

        let mut session = HarnessServerSession::new(policy()).unwrap();
        session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        let mut concurrent = binding();
        concurrent.nonce_hex = digest('9');
        assert!(session
            .handle(
                HarnessRequest::PreS0 {
                    binding: concurrent,
                },
                &keypair,
            )
            .unwrap_err()
            .to_string()
            .contains("concurrent"));
    }

    #[test]
    fn multi_session_server_is_sequential_and_rejects_cross_session_replay() {
        let keypair = keypair(21);
        let first = binding_for("fixture-first", '1', 10);
        let second = binding_for("fixture-second", '9', 11);
        let mut multi_policy = policy();
        multi_policy.allowed_workloads = vec![allowed_workload(&first), allowed_workload(&second)];
        let mut server = HarnessServerSession::with_max_sessions(multi_policy.clone(), 2).unwrap();
        complete_server_session(&mut server, &keypair, first.clone());
        assert_eq!(server.completed_sessions(), 1);
        assert!(!server.is_complete());
        complete_server_session(&mut server, &keypair, second.clone());
        assert_eq!(server.completed_sessions(), 2);
        assert!(server.is_complete());

        let mut replay_server = HarnessServerSession::with_max_sessions(multi_policy, 2).unwrap();
        complete_server_session(&mut replay_server, &keypair, first.clone());
        assert!(replay_server
            .handle(
                HarnessRequest::PreS0 {
                    binding: first.clone(),
                },
                &keypair,
            )
            .unwrap_err()
            .to_string()
            .contains("replayed"));

        let mut reversed = policy();
        reversed.allowed_workloads = vec![allowed_workload(&second), allowed_workload(&first)];
        let mut reversed_server = HarnessServerSession::with_max_sessions(reversed, 2).unwrap();
        assert!(reversed_server
            .handle(HarnessRequest::PreS0 { binding: first }, &keypair,)
            .unwrap_err()
            .to_string()
            .contains("ordered one-shot"));
    }

    #[test]
    fn final_ack_is_required_exact_and_fail_closed() {
        let keypair = keypair(30);
        let mut server = HarnessServerSession::new(policy()).unwrap();
        server
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        server
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding(),
                    s0_sha256: post_evidence().s0_sha256,
                },
                &keypair,
            )
            .unwrap();
        server
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding(),
                    evidence: pre_s1_evidence(),
                },
                &keypair,
            )
            .unwrap();
        let final_response = server
            .handle(
                HarnessRequest::Final {
                    binding: binding(),
                    evidence: post_evidence(),
                },
                &keypair,
            )
            .unwrap();
        assert_eq!(server.completed_sessions(), 0);
        assert!(!server.is_complete());

        let mut wrong = HarnessFinalAck::from_response(&final_response).unwrap();
        wrong.final_response_sha256 = digest('f');
        assert!(server
            .acknowledge_final(wrong)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        assert!(!server.is_complete());
        assert!(server
            .acknowledge_final(HarnessFinalAck::from_response(&final_response).unwrap())
            .unwrap_err()
            .to_string()
            .contains("out of order"));
    }

    #[test]
    fn session_count_and_workload_identities_are_closed() {
        let first = binding_for("fixture-first", '1', 10);
        let second = binding_for("fixture-second", '9', 11);
        let mut multi_policy = policy();
        multi_policy.allowed_workloads = vec![allowed_workload(&first), allowed_workload(&second)];
        assert!(
            HarnessServerSession::with_max_sessions(multi_policy.clone(), 1)
                .err()
                .unwrap()
                .to_string()
                .contains("authorization count")
        );

        let mut duplicate_run_id = allowed_workload(&second);
        duplicate_run_id.run_id = first.run_id.clone();
        duplicate_run_id.cgroup_path = first.cgroup_path.clone();
        multi_policy.allowed_workloads = vec![allowed_workload(&first), duplicate_run_id];
        assert!(multi_policy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unique run IDs"));
    }

    #[test]
    fn policy_rejects_every_bound_identity_class() {
        let fields: &[fn(&mut HarnessRunBinding)] = &[
            |value| value.kernel_identity.push_str("-wrong"),
            |value| value.observer_sha256 = digest('a'),
            |value| value.recorder_sha256 = digest('b'),
            |value| value.scope_sha256 = digest('c'),
            |value| value.workload_argv.push("unexpected".into()),
            |value| value.workload_executable_sha256 = digest('e'),
        ];
        for mutate in fields {
            let mut candidate = binding();
            mutate(&mut candidate);
            assert!(policy().authorize(&candidate).is_err());
        }
        let mut different_epoch = binding();
        different_epoch.run_epoch += 1;
        assert!(policy().authorize(&different_epoch).is_err());

        let mut different_path = binding();
        different_path.cgroup_path = "/alternate/cgroup/root/fixture-run".into();
        assert!(different_path.validate().is_ok());
        assert!(policy().authorize(&different_path).is_err());

        let different_run = binding_for("different-run", '9', 19);
        assert!(policy().authorize(&different_run).is_err());
        let mut failed_check = policy();
        failed_check.checks[0].passed = false;
        assert!(failed_check.validate().is_ok());
        assert!(failed_check.authorize(&binding()).is_err());

        let mut wrong_derivation = policy();
        wrong_derivation.observer_exclusions_derivation = "CALLER_ASSERTED".into();
        assert!(wrong_derivation.validate().is_err());
    }

    #[test]
    fn dynamic_exclusions_are_signed_but_not_preprovisioned() {
        let keypair = keypair(22);
        let mut actual_binding = binding();
        actual_binding.observer_exclusions_sha256 = digest('d');

        // Recorder-owned BPF IDs are allocated only after load. The measured
        // Observer/recorder policy may therefore authorize either valid
        // runtime digest, while the transcript binds the one actually used.
        policy().authorize(&actual_binding).unwrap();
        let signed_transcript = transcript_for(&keypair, actual_binding.clone());
        verify_transcript(
            &signed_transcript,
            &keypair.public,
            &actual_binding,
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy(),
        )
        .unwrap();

        // An offline verifier recomputing a different exclusions digest from
        // manifest data cannot accept the otherwise valid signed transcript.
        assert!(verify_transcript(
            &signed_transcript,
            &keypair.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &expected_policy(),
        )
        .is_err());
    }

    #[test]
    fn binding_rejects_unbound_or_noncanonical_cgroup_path() {
        let mut candidate = binding();
        candidate.cgroup_path = "/sys/fs/cgroup/other-run".into();
        assert!(candidate.validate().is_err());

        let mut candidate = binding();
        candidate.cgroup_path = "/sys/fs/cgroup/../fixture-run".into();
        assert!(candidate.validate().is_err());

        let mut candidate = binding();
        candidate.observer_exclusions_sha256 = "not-a-digest".into();
        assert!(candidate.validate().is_err());
    }

    #[test]
    fn transcript_requires_external_policy_digest() {
        let keypair = keypair(20);
        let signed_transcript = transcript(&keypair);
        let wrong_policy = ExpectedHarnessPolicy {
            policy_id: "fixture-policy".into(),
            policy_sha256: digest('f'),
        };
        assert!(verify_transcript(
            &signed_transcript,
            &keypair.public,
            &binding(),
            &post_evidence().s0_sha256,
            &pre_s1_evidence(),
            &post_evidence(),
            &wrong_policy
        )
        .is_err());
    }

    #[test]
    fn canonical_json_digest_recursively_sorts_object_keys() {
        let left: serde_json::Value =
            serde_json::from_str(r#"{"z":{"b":1,"a":2},"a":[{"y":1,"x":2}]}"#).unwrap();
        let right: serde_json::Value =
            serde_json::from_str(r#"{"a":[{"x":2,"y":1}],"z":{"a":2,"b":1}}"#).unwrap();
        let expected = sha256_bytes(br#"{"a":[{"x":2,"y":1}],"z":{"a":2,"b":1}}"#);
        assert_eq!(canonical_json_sha256(&left).unwrap(), expected);
        assert_eq!(canonical_json_sha256(&right).unwrap(), expected);

        let reordered_array: serde_json::Value = serde_json::from_str(r#"{"a":[2,1]}"#).unwrap();
        let original_array: serde_json::Value = serde_json::from_str(r#"{"a":[1,2]}"#).unwrap();
        assert_ne!(
            canonical_json_sha256(&reordered_array).unwrap(),
            canonical_json_sha256(&original_array).unwrap()
        );
    }

    #[test]
    fn failed_post_barrier_is_rejected() {
        let keypair = keypair(16);
        let mut session = HarnessServerSession::new(policy()).unwrap();
        session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        session
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding(),
                    s0_sha256: post_evidence().s0_sha256,
                },
                &keypair,
            )
            .unwrap();
        session
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding(),
                    evidence: pre_s1_evidence(),
                },
                &keypair,
            )
            .unwrap();
        let mut evidence = post_evidence();
        evidence.wal_durable = false;
        assert!(session
            .handle(
                HarnessRequest::Final {
                    binding: binding(),
                    evidence,
                },
                &keypair,
            )
            .is_err());
    }

    #[test]
    fn outside_cgroup_bpf_attempt_is_rejected() {
        let mut evidence = post_evidence();
        evidence.outside_cgroup_syscall_attempted = 1;
        assert!(evidence.validate().is_err());
    }

    #[test]
    fn final_digest_must_match_s0_commit() {
        let keypair = keypair(19);
        let mut session = HarnessServerSession::new(policy()).unwrap();
        session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        session
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding(),
                    s0_sha256: post_evidence().s0_sha256,
                },
                &keypair,
            )
            .unwrap();
        session
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding(),
                    evidence: pre_s1_evidence(),
                },
                &keypair,
            )
            .unwrap();
        let mut evidence = post_evidence();
        evidence.s0_sha256 = digest('e');
        assert!(session
            .handle(
                HarnessRequest::Final {
                    binding: binding(),
                    evidence,
                },
                &keypair,
            )
            .unwrap_err()
            .to_string()
            .contains("S0 digest"));
    }

    #[test]
    fn ordered_session_holds_lease_until_final() {
        let keypair = keypair(18);
        let mut session = HarnessServerSession::new(policy()).unwrap();
        let pre = session
            .handle(HarnessRequest::PreS0 { binding: binding() }, &keypair)
            .unwrap();
        assert_eq!(pre.sequence, 1);
        assert!(!session.is_complete());
        let s0 = session
            .handle(
                HarnessRequest::S0Committed {
                    binding: binding(),
                    s0_sha256: post_evidence().s0_sha256,
                },
                &keypair,
            )
            .unwrap();
        assert_eq!(s0.sequence, 2);
        assert!(!session.is_complete());
        let pre_s1 = session
            .handle(
                HarnessRequest::PreS1 {
                    binding: binding(),
                    evidence: pre_s1_evidence(),
                },
                &keypair,
            )
            .unwrap();
        assert_eq!(pre_s1.sequence, 3);
        assert!(!session.is_complete());
        let final_response = session
            .handle(
                HarnessRequest::Final {
                    binding: binding(),
                    evidence: post_evidence(),
                },
                &keypair,
            )
            .unwrap();
        assert_eq!(final_response.sequence, 4);
        assert_eq!(final_response.checks.len(), EXCLUSIVE_VM_V1_CHECKS.len());
        assert!(!session.is_complete());
        let ack = HarnessFinalAck::from_response(&final_response).unwrap();
        session.acknowledge_final(ack.clone()).unwrap();
        assert!(session.is_complete());
        assert!(session.acknowledge_final(ack).is_err());
    }

    #[test]
    fn framed_request_round_trip_and_oversize_rejection() {
        let request = HarnessRequest::PreS0 { binding: binding() };
        let mut bytes = Vec::new();
        write_request_frame(&mut bytes, &request).unwrap();
        assert_eq!(read_frame(&mut bytes.as_slice()).unwrap(), Some(request));

        let mut oversized = ((MAX_FRAME_BYTES as u32) + 1).to_be_bytes().to_vec();
        oversized.push(0);
        assert!(read_frame(&mut oversized.as_slice()).is_err());

        let response = sign_response(
            &keypair(29),
            &policy(),
            HarnessPhase::Final,
            binding(),
            HarnessPhaseEvidence::Final {
                evidence: post_evidence(),
            },
        )
        .unwrap();
        let ack = HarnessFinalAck::from_response(&response).unwrap();
        let mut ack_bytes = Vec::new();
        write_final_ack_frame(&mut ack_bytes, &ack).unwrap();
        assert_eq!(
            read_final_ack_frame(&mut ack_bytes.as_slice()).unwrap(),
            Some(ack)
        );
    }

    #[test]
    fn key_files_round_trip_with_strict_permissions() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("bpf-harness-auth-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let secret = root.join("key.secret");
        let public = root.join("key.public");
        let keypair = keypair(17);
        write_keypair(&keypair, &secret, &public).unwrap();
        let loaded_secret = read_secret_key(&secret).unwrap();
        let loaded_public = read_public_key(&public).unwrap();
        assert_eq!(loaded_secret.to_bytes(), keypair.to_bytes());
        assert_eq!(loaded_public, keypair.public);
        fs::remove_file(secret).unwrap();
        fs::remove_file(public).unwrap();
        fs::remove_dir(root).unwrap();
    }
}
