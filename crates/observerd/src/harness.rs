// SPDX-License-Identifier: GPL-2.0-only

use crate::input;
use anyhow::{bail, Context, Result};
use bpf_harness_auth::{
    read_public_key, read_response_frame, verify_response, verify_transcript,
    write_final_ack_frame, write_request_frame, AuthenticatedHarnessTranscript,
    ExpectedHarnessPolicy, HarnessFinalAck, HarnessPhase, HarnessPhaseEvidence,
    HarnessPostEvidence, HarnessPreS1Evidence, HarnessRequest, HarnessRunBinding, PublicKey,
    SignedHarnessResponse, HARNESS_CONTRACT_ID,
};
use bpf_observer_schema::{
    ContractCheck, QuiescenceBasis, QuiescenceReport, QuiescenceStatus, EXCLUSIVE_VM_V1_CHECKS,
    MAX_QUIESCENCE_JSON_BYTES,
};
use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct AuthenticatedHarnessConfig {
    pub channel: PathBuf,
    pub public_key: PathBuf,
    pub expected_policy: ExpectedHarnessPolicy,
    pub timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatedHarnessIdentity {
    pub public_key_fingerprint_sha256: String,
    pub policy_id: String,
    pub policy_sha256: String,
}

/// Stateful Guest-side client for the closed four-phase harness protocol.
/// The trusted public key is loaded before PRE_S0, and every response is
/// authenticated and matched to the complete binding before execution moves
/// to the next boundary.
pub struct AuthenticatedHarnessClient {
    channel: File,
    public_key: PublicKey,
    expected_policy: ExpectedHarnessPolicy,
    binding: HarnessRunBinding,
    timeout: Duration,
    pre_s0: Option<SignedHarnessResponse>,
    s0_committed: Option<SignedHarnessResponse>,
    pre_s1: Option<SignedHarnessResponse>,
}

impl AuthenticatedHarnessClient {
    pub fn begin(config: &AuthenticatedHarnessConfig, binding: HarnessRunBinding) -> Result<Self> {
        binding
            .validate()
            .context("validate authenticated harness binding")?;
        config
            .expected_policy
            .validate()
            .context("validate expected harness policy")?;
        if config.timeout.is_zero() {
            bail!("authenticated harness timeout must be nonzero");
        }
        let public_key = read_public_key(&config.public_key)
            .with_context(|| format!("load trusted harness key {}", config.public_key.display()))?;
        let channel = open_channel(&config.channel)?;
        let mut client = Self {
            channel,
            public_key,
            expected_policy: config.expected_policy.clone(),
            binding,
            timeout: config.timeout,
            pre_s0: None,
            s0_committed: None,
            pre_s1: None,
        };
        let response = client.exchange(
            HarnessRequest::PreS0 {
                binding: client.binding.clone(),
            },
            HarnessPhase::PreS0,
            HarnessPhaseEvidence::None,
        )?;
        client.pre_s0 = Some(response);
        Ok(client)
    }

    pub fn identity(&self) -> Result<AuthenticatedHarnessIdentity> {
        let response = self.pre_s0.as_ref().context("PRE_S0 response is absent")?;
        Ok(AuthenticatedHarnessIdentity {
            public_key_fingerprint_sha256: response.key_fingerprint_sha256.clone(),
            policy_id: response.policy_id.clone(),
            policy_sha256: response.policy_sha256.clone(),
        })
    }

    pub fn commit_s0(&mut self, s0_sha256: &str) -> Result<()> {
        if self.s0_committed.is_some() {
            bail!("authenticated S0 has already been committed");
        }
        let evidence = HarnessPhaseEvidence::S0Committed {
            s0_sha256: s0_sha256.to_owned(),
        };
        let response = self.exchange(
            HarnessRequest::S0Committed {
                binding: self.binding.clone(),
                s0_sha256: s0_sha256.to_owned(),
            },
            HarnessPhase::S0Committed,
            evidence,
        )?;
        self.s0_committed = Some(response);
        Ok(())
    }

    pub fn authorize_pre_s1(&mut self, evidence: HarnessPreS1Evidence) -> Result<()> {
        if self.pre_s1.is_some() {
            bail!("authenticated PRE_S1 has already been authorized");
        }
        let response = self.exchange(
            HarnessRequest::PreS1 {
                binding: self.binding.clone(),
                evidence: evidence.clone(),
            },
            HarnessPhase::PreS1,
            HarnessPhaseEvidence::PreS1 { evidence },
        )?;
        self.pre_s1 = Some(response);
        Ok(())
    }

    pub fn finish(mut self, evidence: HarnessPostEvidence) -> Result<QuiescenceReport> {
        let final_response = self.exchange(
            HarnessRequest::Final {
                binding: self.binding.clone(),
                evidence: evidence.clone(),
            },
            HarnessPhase::Final,
            HarnessPhaseEvidence::Final { evidence },
        )?;
        let transcript = AuthenticatedHarnessTranscript {
            pre_s0: self.pre_s0.take().context("PRE_S0 response is absent")?,
            s0_committed: self
                .s0_committed
                .take()
                .context("S0_COMMITTED response is absent")?,
            pre_s1: self.pre_s1.take().context("PRE_S1 response is absent")?,
            final_response,
        };
        let (s0_sha256, pre_s1_evidence, post_evidence) = transcript_evidence(&transcript)?;
        verify_transcript(
            &transcript,
            &self.public_key,
            &self.binding,
            &s0_sha256,
            &pre_s1_evidence,
            &post_evidence,
            &self.expected_policy,
        )
        .context("verify completed authenticated harness transcript")?;
        let final_ack = HarnessFinalAck::from_response(&transcript.final_response)
            .context("construct authenticated FINAL_ACK")?;
        let report = report_from_transcript(transcript)?;
        self.send_final_ack(&final_ack)?;
        Ok(report)
    }

    fn send_final_ack(&mut self, ack: &HarnessFinalAck) -> Result<()> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .context("authenticated FINAL_ACK timeout exceeds monotonic range")?;
        let mut transport = DeadlineTransport {
            file: &mut self.channel,
            deadline,
        };
        write_final_ack_frame(&mut transport, ack)
            .context("send authenticated FINAL_ACK after transcript validation")
    }

    fn exchange(
        &mut self,
        request: HarnessRequest,
        expected_phase: HarnessPhase,
        expected_evidence: HarnessPhaseEvidence,
    ) -> Result<SignedHarnessResponse> {
        let deadline = Instant::now()
            .checked_add(self.timeout)
            .context("authenticated harness timeout exceeds monotonic range")?;
        let mut transport = DeadlineTransport {
            file: &mut self.channel,
            deadline,
        };
        write_request_frame(&mut transport, &request)
            .with_context(|| format!("send authenticated {expected_phase:?} request"))?;
        let response = read_response_frame(&mut transport)
            .with_context(|| format!("read authenticated {expected_phase:?} response"))?
            .with_context(|| format!("harness channel closed before {expected_phase:?}"))?;
        verify_response(&response, &self.public_key)
            .with_context(|| format!("authenticate {expected_phase:?} response"))?;
        if response.phase != expected_phase
            || response.sequence != expected_phase.sequence()
            || response.binding != self.binding
            || response.phase_evidence != expected_evidence
            || response.contract_id != HARNESS_CONTRACT_ID
            || response.policy_id != self.expected_policy.policy_id
            || response.policy_sha256 != self.expected_policy.policy_sha256
        {
            bail!("authenticated {expected_phase:?} response is not bound to the exact request and trusted policy");
        }
        Ok(response)
    }
}

fn open_channel(path: &Path) -> Result<File> {
    // udev normally exposes a named virtio port as a symlink under
    // /dev/virtio-ports. Resolve it once, then open the resolved device with
    // O_NOFOLLOW; authenticity still comes from the Ed25519 response, not
    // from trusting the device pathname.
    let resolved = std::fs::canonicalize(path)
        .with_context(|| format!("resolve authenticated harness channel {}", path.display()))?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOCTTY | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&resolved)
        .with_context(|| format!("open authenticated harness channel {}", resolved.display()))?;
    let metadata = file.metadata().with_context(|| {
        format!(
            "inspect authenticated harness channel {}",
            resolved.display()
        )
    })?;
    if !metadata.file_type().is_char_device() {
        bail!("authenticated harness channel must be a character device");
    }
    Ok(file)
}

struct DeadlineTransport<'a> {
    file: &'a mut File,
    deadline: Instant,
}

impl DeadlineTransport<'_> {
    fn wait_ready(&self, events: libc::c_short) -> io::Result<()> {
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "authenticated harness exchange timed out",
                ));
            }
            let millis = remaining
                .as_millis()
                .saturating_add(u128::from(remaining.subsec_nanos() != 0))
                .min(i32::MAX as u128) as i32;
            let mut descriptor = libc::pollfd {
                fd: self.file.as_raw_fd(),
                events,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "authenticated harness exchange timed out",
                ));
            }
            if descriptor.revents & libc::POLLNVAL != 0
                || (descriptor.revents & libc::POLLERR != 0 && descriptor.revents & events == 0)
                || (descriptor.revents & libc::POLLHUP != 0 && descriptor.revents & events == 0)
            {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "authenticated harness channel failed",
                ));
            }
            if descriptor.revents & events != 0 {
                return Ok(());
            }
        }
    }
}

impl Read for DeadlineTransport<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            self.wait_ready(libc::POLLIN)?;
            match self.file.read(output) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }
}

impl Write for DeadlineTransport<'_> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        loop {
            self.wait_ready(libc::POLLOUT)?;
            match self.file.write(input) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) => {}
                result => return result,
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn transcript_evidence(
    transcript: &AuthenticatedHarnessTranscript,
) -> Result<(String, HarnessPreS1Evidence, HarnessPostEvidence)> {
    let s0_sha256 = match &transcript.s0_committed.phase_evidence {
        HarnessPhaseEvidence::S0Committed { s0_sha256 } => s0_sha256.clone(),
        _ => bail!("authenticated transcript lacks S0_COMMITTED evidence"),
    };
    let pre_s1 = match &transcript.pre_s1.phase_evidence {
        HarnessPhaseEvidence::PreS1 { evidence } => evidence.clone(),
        _ => bail!("authenticated transcript lacks PRE_S1 evidence"),
    };
    let post = match &transcript.final_response.phase_evidence {
        HarnessPhaseEvidence::Final { evidence } => evidence.clone(),
        _ => bail!("authenticated transcript lacks FINAL evidence"),
    };
    Ok((s0_sha256, pre_s1, post))
}

fn report_from_transcript(transcript: AuthenticatedHarnessTranscript) -> Result<QuiescenceReport> {
    let checks = transcript
        .final_response
        .checks
        .iter()
        .map(|check| ContractCheck {
            name: check.name.clone(),
            passed: check.passed,
            evidence: check.evidence.clone(),
        })
        .collect();
    let report = QuiescenceReport {
        status: QuiescenceStatus::QuiescentWithinModel,
        basis: QuiescenceBasis::HarnessEnforced,
        contract_id: Some(HARNESS_CONTRACT_ID.into()),
        checks,
        exclusive_actor_attribution: true,
        authentication: Some(
            serde_json::to_value(transcript)
                .context("serialize authenticated harness transcript")?,
        ),
    };
    if !report.supports_unchanged() {
        bail!("authenticated harness produced a report outside the closed contract");
    }
    Ok(report)
}

/// Authenticate a persisted HARNESS_ENFORCED report against an external
/// trust anchor and independently reconstructed run/artifact evidence.
pub fn validate_authenticated_report(
    report: &QuiescenceReport,
    public_key_path: &Path,
    expected_policy: &ExpectedHarnessPolicy,
    expected_binding: &HarnessRunBinding,
    expected_s0_sha256: &str,
    expected_pre_s1: &HarnessPreS1Evidence,
    expected_post: &HarnessPostEvidence,
) -> Result<AuthenticatedHarnessIdentity> {
    if report.status != QuiescenceStatus::QuiescentWithinModel
        || report.basis != QuiescenceBasis::HarnessEnforced
        || report.contract_id.as_deref() != Some(HARNESS_CONTRACT_ID)
        || !report.exclusive_actor_attribution
    {
        bail!("persisted authenticated quiescence shape is not exclusive-vm-v1");
    }
    let authentication = report
        .authentication
        .as_ref()
        .context("persisted authenticated quiescence omitted its transcript")?;
    let transcript: AuthenticatedHarnessTranscript = serde_json::from_value(authentication.clone())
        .context("decode persisted authenticated harness transcript")?;
    let public_key = read_public_key(public_key_path)
        .with_context(|| format!("load trusted harness key {}", public_key_path.display()))?;
    verify_transcript(
        &transcript,
        &public_key,
        expected_binding,
        expected_s0_sha256,
        expected_pre_s1,
        expected_post,
        expected_policy,
    )
    .context("authenticate persisted harness transcript")?;
    let expected_checks = transcript
        .final_response
        .checks
        .iter()
        .map(|check| ContractCheck {
            name: check.name.clone(),
            passed: check.passed,
            evidence: check.evidence.clone(),
        })
        .collect::<Vec<_>>();
    if report.checks != expected_checks || !report.supports_unchanged() {
        bail!("persisted quiescence checks differ from the signed FINAL response");
    }
    Ok(AuthenticatedHarnessIdentity {
        public_key_fingerprint_sha256: transcript.final_response.key_fingerprint_sha256,
        policy_id: transcript.final_response.policy_id,
        policy_sha256: transcript.final_response.policy_sha256,
    })
}

pub fn observed_only(cgroup_empty: bool, evidence: impl Into<String>) -> QuiescenceReport {
    QuiescenceReport {
        status: if cgroup_empty {
            QuiescenceStatus::Unknown
        } else {
            QuiescenceStatus::NotQuiescent
        },
        basis: QuiescenceBasis::ObservedOnly,
        contract_id: None,
        checks: vec![ContractCheck {
            name: "cgroup_empty".into(),
            passed: cgroup_empty,
            evidence: evidence.into(),
        }],
        exclusive_actor_attribution: false,
        authentication: None,
    }
}

/// Load caller-supplied harness claims conservatively.
///
/// A standalone JSON file never traverses the nonce-bound four-phase channel.
/// It can be useful as diagnostic context, but can never authorize `UNCHANGED`
/// or exclusive actor attribution: it may have been written before the run,
/// replayed, or edited by the workload.
pub fn load_and_validate(path: &Path) -> Result<QuiescenceReport> {
    let mut report: QuiescenceReport = input::read_json(path, MAX_QUIESCENCE_JSON_BYTES)
        .with_context(|| format!("load harness evidence {}", path.display()))?;

    if report.basis == QuiescenceBasis::HarnessEnforced
        && report.contract_id.as_deref() == Some("exclusive-vm-v1")
    {
        let mut names = BTreeSet::new();
        let invalid_check = report.checks.iter().any(|check| {
            check.evidence.trim().is_empty()
                || !EXCLUSIVE_VM_V1_CHECKS.contains(&check.name.as_str())
                || !names.insert(check.name.clone())
        });
        if invalid_check || report.checks.len() != EXCLUSIVE_VM_V1_CHECKS.len() {
            report.status = QuiescenceStatus::Unknown;
            report.exclusive_actor_attribution = false;
            report.checks.push(ContractCheck {
                name: "invalid:closed-check-set".into(),
                passed: false,
                evidence:
                    "checks must be the exact unique exclusive-vm-v1 set with non-empty evidence"
                        .into(),
            });
        }
        for required in EXCLUSIVE_VM_V1_CHECKS {
            if !report
                .checks
                .iter()
                .any(|check| check.name == *required && check.passed)
            {
                report.status = QuiescenceStatus::Unknown;
                report.exclusive_actor_attribution = false;
                report.checks.push(ContractCheck {
                    name: format!("missing:{required}"),
                    passed: false,
                    evidence: "required exclusive-vm-v1 check was absent or failed".into(),
                });
            }
        }
    } else if report.basis == QuiescenceBasis::HarnessEnforced {
        report.status = QuiescenceStatus::Unknown;
        report.exclusive_actor_attribution = false;
        report.checks.push(ContractCheck {
            name: "known_contract".into(),
            passed: false,
            evidence: "only exclusive-vm-v1 is accepted by this build".into(),
        });
    }
    reject_unbound_harness_claim(&mut report);
    Ok(report)
}

fn reject_unbound_harness_claim(report: &mut QuiescenceReport) {
    if report.basis != QuiescenceBasis::HarnessEnforced {
        // Observed/assumed caller input has no authority for exclusive actor
        // attribution even though it may remain useful diagnostic context.
        report.exclusive_actor_attribution = false;
        report.authentication = None;
        return;
    }
    report.status = QuiescenceStatus::Unknown;
    report.exclusive_actor_attribution = false;
    report.authentication = None;
    report
        .checks
        .retain(|check| check.name != "observer_binding");
    report.checks.push(ContractCheck {
        name: "observer_binding".into(),
        passed: false,
        evidence: "the supplied JSON did not traverse the authenticated run-bound four-phase harness channel and is diagnostic only"
            .into(),
    });
}

pub fn set_observed_check(
    report: &mut QuiescenceReport,
    name: &str,
    passed: bool,
    evidence: impl Into<String>,
) {
    report.checks.retain(|check| check.name != name);
    report.checks.push(ContractCheck {
        name: name.into(),
        passed,
        evidence: evidence.into(),
    });
    if !passed {
        report.status = QuiescenceStatus::NotQuiescent;
        report.exclusive_actor_attribution = false;
    }
}

pub fn validate_persisted_safe_report(report: &QuiescenceReport) -> Result<()> {
    if report.authentication.is_some() {
        bail!("authenticated quiescence requires external-key transcript verification");
    }
    if report.supports_unchanged() || report.exclusive_actor_attribution {
        bail!("persisted quiescence report exceeds this producer's trust boundary");
    }
    if report
        .checks
        .iter()
        .filter(|check| {
            check.name == "cgroup_empty" && check.passed && !check.evidence.trim().is_empty()
        })
        .count()
        != 1
    {
        bail!("persisted quiescence report lacks the exact observed cgroup_empty barrier");
    }
    if report.basis == QuiescenceBasis::HarnessEnforced
        && report
            .checks
            .iter()
            .filter(|check| {
                check.name == "observer_binding"
                    && !check.passed
                    && !check.evidence.trim().is_empty()
            })
            .count()
            != 1
    {
        bail!("unbound HARNESS_ENFORCED report lacks the mandatory downgrade marker");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_empty_cgroup_is_not_called_enforced() {
        let report = observed_only(true, "fixture");
        assert_eq!(report.status, QuiescenceStatus::Unknown);
        assert!(!report.supports_unchanged());
    }

    #[test]
    fn unbound_harness_claim_is_never_accepted() {
        let mut report = QuiescenceReport {
            status: QuiescenceStatus::QuiescentWithinModel,
            basis: QuiescenceBasis::HarnessEnforced,
            contract_id: Some("exclusive-vm-v1".into()),
            checks: EXCLUSIVE_VM_V1_CHECKS
                .iter()
                .map(|name| ContractCheck {
                    name: (*name).into(),
                    passed: true,
                    evidence: "fixture".into(),
                })
                .collect(),
            exclusive_actor_attribution: true,
            authentication: Some(serde_json::json!({"test_fixture": true})),
        };
        reject_unbound_harness_claim(&mut report);
        assert!(!report.supports_unchanged());
    }

    #[test]
    fn unbound_marker_is_canonicalized() {
        let mut report = QuiescenceReport {
            status: QuiescenceStatus::QuiescentWithinModel,
            basis: QuiescenceBasis::HarnessEnforced,
            contract_id: Some("exclusive-vm-v1".into()),
            checks: vec![
                ContractCheck {
                    name: "observer_binding".into(),
                    passed: true,
                    evidence: "caller-controlled".into(),
                },
                ContractCheck {
                    name: "observer_binding".into(),
                    passed: false,
                    evidence: "caller-controlled".into(),
                },
            ],
            exclusive_actor_attribution: true,
            authentication: Some(serde_json::json!({"test_fixture": true})),
        };
        reject_unbound_harness_claim(&mut report);
        assert_eq!(
            report
                .checks
                .iter()
                .filter(|check| check.name == "observer_binding")
                .count(),
            1
        );
        assert!(!report.exclusive_actor_attribution);
    }
}
