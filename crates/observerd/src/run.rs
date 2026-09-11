// SPDX-License-Identifier: GPL-2.0-only

use crate::{atomic_file, cgroup::ManagedCgroup, environment, harness, input};
use anyhow::{anyhow, bail, Context, Result};
use bpf_harness_auth::{
    canonical_json_sha256, generate_nonce_hex, ExpectedHarnessPolicy, HarnessPostEvidence,
    HarnessPreS1Evidence, HarnessRunBinding, HARNESS_PROTOCOL_VERSION,
};
use bpf_observer_comparator::compare;
use bpf_observer_oracle::{capture, CaptureOptions};
use bpf_observer_recorder::Recorder;
use bpf_observer_schema::{
    artifact_size_limit, ArtifactDigest, ClaimScope, EnvironmentFingerprint, EvidenceHealth,
    ObjectExclusions, QuiescenceReport, RunManifest, RunStatus, StateVerdict, Verdict,
    FINALIZED_RUN_ARTIFACTS_V1, MAX_MANIFEST_JSON_BYTES, MAX_VERDICT_JSON_BYTES,
    MAX_WORKLOAD_OUTPUT_BYTES, SCHEMA_VERSION,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(20);
const FAILURE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);
const CANARY_TIMEOUT: Duration = Duration::from_secs(2);
const CLOSING_BARRIER_TIMEOUT: Duration = Duration::from_secs(2);
const DRAIN_CHUNKS_PER_POLL: usize = 16;
const DRAIN_CHUNKS_AT_EOF: usize = 1024;
const BASELINE_EVENT_INTERFACE: &str = "BPF_USER_SYSCALL";
pub(crate) const S1_TEARDOWN_LIMITATION: &str =
    "S1 is the workload-end boundary before removal of the observer-owned cgroup; cgroup teardown can subsequently release cgroup-scoped BPF references";

#[derive(Debug)]
pub struct AuthenticatedHarnessRequest {
    pub channel: PathBuf,
    pub public_key: PathBuf,
    pub policy_id: String,
    pub expected_policy_sha256: String,
    pub kernel_identity: String,
    pub timeout_ms: u64,
}

#[derive(Debug)]
pub struct ObserveRequest {
    pub scope_path: PathBuf,
    pub recorder_object: PathBuf,
    pub expected_recorder_sha256: String,
    pub output_dir: PathBuf,
    pub cgroup_root: PathBuf,
    pub run_id: Option<String>,
    pub run_epoch: u64,
    pub timeout_ms: u64,
    pub drain_timeout_ms: u64,
    pub harness_evidence: Option<PathBuf>,
    pub authenticated_harness: Option<AuthenticatedHarnessRequest>,
    pub workload: Vec<OsString>,
}

#[derive(Debug, Serialize)]
pub struct ObserveOutcome {
    pub run_id: String,
    pub run_epoch: u64,
    pub workload_exit_code: Option<i32>,
    pub workload_signal: Option<i32>,
    pub state_verdict: StateVerdict,
    pub output_dir: String,
}

struct ActiveAuthenticatedHarness {
    client: harness::AuthenticatedHarnessClient,
    workload_path: PathBuf,
    workload_measurement: environment::FileMeasurement,
}

pub fn observe(request: ObserveRequest) -> Result<ObserveOutcome> {
    validate_request(&request)?;
    let requested_scope: ClaimScope =
        input::read_json(&request.scope_path, MAX_MANIFEST_JSON_BYTES)?;
    validate_observe_scope(&requested_scope)?;
    let effective_scope = requested_scope.clone();
    let run_id = request.run_id.clone().unwrap_or(environment::new_run_id()?);
    validate_run_id(&run_id)?;
    let started_unix_ns = environment::now_unix_ns();
    let workload_strings = request
        .workload
        .iter()
        .map(|argument| {
            let argument = argument
                .to_str()
                .map(str::to_owned)
                .context("workload argv contains non-UTF-8 bytes unsupported by manifest v1")?;
            if argument.contains('\0') {
                bail!("workload argv contains a NUL byte unsupported by exec and manifest v1");
            }
            Ok(argument)
        })
        .collect::<Result<Vec<_>>>()?;
    // Atomically claim the exact run directory only after every read-only
    // input check has passed. Requiring a new directory prevents two observer
    // processes from both accepting the same empty path and corrupting each
    // other's commit record.
    prepare_output_directory(&request.output_dir)?;
    let mut manifest = RunManifest {
        schema_version: SCHEMA_VERSION,
        run_id: run_id.clone(),
        run_epoch: request.run_epoch,
        run_status: RunStatus::Running,
        started_unix_ns,
        finalized_unix_ns: None,
        cgroup_path: request.cgroup_root.join(&run_id).display().to_string(),
        cgroup_id: 0,
        workload: workload_strings,
        workload_exit_code: None,
        workload_signal: None,
        requested_scope,
        effective_scope,
        scope_accepted: true,
        observer_exclusions: ObjectExclusions::default(),
        environment: EnvironmentFingerprint::default(),
        artifacts: BTreeMap::new(),
        notes: vec![
            "provisional RUNNING manifest; recorder and cgroup are not registered yet".into(),
        ],
    };
    let manifest_path = request.output_dir.join("manifest.json");
    atomic_file::write_json_atomic(&manifest_path, &manifest)?;

    let result = (|| -> Result<ObserveOutcome> {
        // Loading precedes S0 so every recorder-owned object can be excluded
        // from both endpoints. No run is active while Recorder::open creates
        // objects.
        let mut recorder = Recorder::open(
            &request.recorder_object,
            &request.expected_recorder_sha256,
            &request.output_dir,
            &run_id,
            &manifest.effective_scope.allowed_bpf_commands,
        )
        .context("load BPF syscall recorder")?;
        manifest.observer_exclusions = recorder.object_exclusions();
        validate_scope_exclusions(&manifest.effective_scope, &manifest.observer_exclusions)?;
        manifest.environment = environment::fingerprint(Some(recorder.object_sha256().to_owned()))?;

        let mut cgroup = ManagedCgroup::create(&request.cgroup_root, &run_id)?;
        manifest.cgroup_path = cgroup.path().display().to_string();
        manifest.cgroup_id = cgroup.id();
        manifest.notes.clear();
        atomic_file::write_json_atomic(&manifest_path, &manifest)?;

        match observe_inner(&request, &mut manifest, &mut recorder, &mut cgroup) {
            Ok(outcome) => Ok(outcome),
            Err(error) => match cgroup.abort_and_cleanup(FAILURE_CLEANUP_TIMEOUT) {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(anyhow!(
                    "{error:#}; failure cleanup is incomplete and the VM supervisor must fence the run: {cleanup_error:#}"
                )),
            },
        }
    })();
    match result {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            manifest.run_status = RunStatus::Failed;
            manifest.finalized_unix_ns =
                Some(environment::now_unix_ns().max(manifest.started_unix_ns));
            manifest.notes.push(format!("observer failure: {error:#}"));

            // verdict.json is derived evidence, while manifest.json is the
            // commit record. If finalizing the manifest failed after a verdict
            // was written, do not leave a standalone UNCHANGED result that a
            // caller could mistake for a successful run.
            if let Err(verdict_error) = mark_existing_verdict_failed(&request.output_dir) {
                manifest.notes.push(format!(
                    "failed to invalidate an existing verdict: {verdict_error:#}"
                ));
            }

            // write_json_atomic deliberately uses create_new. An interrupted
            // prior manifest write may therefore have left this process's
            // temporary file behind; remove only that exact per-process path
            // before making the FAILED commit-record attempt.
            let _ = remove_atomic_temporary(&manifest_path);
            if let Err(manifest_error) = atomic_file::write_json_atomic(&manifest_path, &manifest) {
                return Err(anyhow!(
                    "{error:#}; additionally failed to persist FAILED manifest: {manifest_error:#}"
                ));
            }
            Err(error)
        }
    }
}

fn prepare_authenticated_harness(
    request: &ObserveRequest,
    manifest: &mut RunManifest,
    recorder: &mut Recorder,
    cgroup: &ManagedCgroup,
) -> Result<Option<ActiveAuthenticatedHarness>> {
    let Some(auth) = &request.authenticated_harness else {
        return Ok(None);
    };
    let workload_argv0 = manifest
        .workload
        .first()
        .context("authenticated workload argv is empty")?;
    let workload_path = PathBuf::from(workload_argv0);
    let workload_text = workload_path
        .to_str()
        .context("authenticated workload path is not UTF-8")?;
    if !is_lexically_normal_absolute(workload_text.as_bytes()) || workload_text == "/" {
        bail!("authenticated workload argv[0] must be a normalized absolute path");
    }
    let canonical_workload = fs::canonicalize(&workload_path)
        .with_context(|| format!("canonicalize workload {}", workload_path.display()))?;
    if canonical_workload != workload_path {
        bail!("authenticated workload argv[0] must already be canonical");
    }
    let workload_measurement = environment::measure_regular_file(&workload_path)?;
    let observer_path = std::env::current_exe().context("resolve Observer executable")?;
    let canonical_observer = fs::canonicalize(&observer_path)
        .with_context(|| format!("canonicalize Observer {}", observer_path.display()))?;
    let observer_measurement = environment::measure_regular_file(&canonical_observer)?;
    let scope_sha256 = canonical_json_sha256(&manifest.effective_scope)
        .context("canonicalize authenticated claim scope")?;
    let exclusions_sha256 = canonical_json_sha256(&manifest.observer_exclusions)
        .context("canonicalize authenticated observer exclusions")?;

    manifest.environment.observer_executable_sha256 = Some(observer_measurement.sha256.clone());
    manifest.environment.workload_executable_sha256 = Some(workload_measurement.sha256.clone());
    manifest.environment.harness_kernel_identity = Some(auth.kernel_identity.clone());
    manifest.environment.harness_policy_id = Some(auth.policy_id.clone());
    manifest.environment.harness_policy_sha256 = Some(auth.expected_policy_sha256.clone());

    let binding = HarnessRunBinding {
        protocol_version: HARNESS_PROTOCOL_VERSION,
        nonce_hex: generate_nonce_hex().context("generate authenticated harness nonce")?,
        run_id: manifest.run_id.clone(),
        run_epoch: manifest.run_epoch,
        cgroup_id: cgroup.id(),
        cgroup_path: cgroup.path().display().to_string(),
        boot_id: manifest.environment.boot_id.clone(),
        kernel_identity: auth.kernel_identity.clone(),
        observer_sha256: observer_measurement.sha256,
        recorder_sha256: recorder.object_sha256().to_owned(),
        scope_sha256,
        observer_exclusions_sha256: exclusions_sha256,
        workload_argv: manifest.workload.clone(),
        workload_executable_sha256: workload_measurement.sha256.clone(),
        s0_snapshot_id: format!("{}-S0", manifest.run_id),
        s1_snapshot_id: format!("{}-S1", manifest.run_id),
    };
    let config = harness::AuthenticatedHarnessConfig {
        channel: auth.channel.clone(),
        public_key: auth.public_key.clone(),
        expected_policy: ExpectedHarnessPolicy {
            policy_id: auth.policy_id.clone(),
            policy_sha256: auth.expected_policy_sha256.clone(),
        },
        timeout: Duration::from_millis(auth.timeout_ms),
    };
    // Start the raw-tracepoint negative gate before asking the Host to sign
    // PRE_S0. From this point through the verified FINAL response, any bpf()
    // attempt outside this Observer TGID and a registered run cgroup makes the
    // authenticated result fail closed, including create-and-destroy activity
    // that endpoint snapshots alone cannot expose.
    recorder
        .begin_exclusive_window()
        .context("enable authenticated exclusive-actor observation")?;
    let client = harness::AuthenticatedHarnessClient::begin(&config, binding)
        .context("establish authenticated PRE_S0 boundary")?;
    Ok(Some(ActiveAuthenticatedHarness {
        client,
        workload_path,
        workload_measurement,
    }))
}

fn ensure_authenticated_workload_unchanged(active: &ActiveAuthenticatedHarness) -> Result<()> {
    let after = environment::measure_regular_file(&active.workload_path)?;
    if after != active.workload_measurement {
        bail!("authenticated workload executable changed during the run");
    }
    Ok(())
}

fn observe_inner(
    request: &ObserveRequest,
    manifest: &mut RunManifest,
    recorder: &mut Recorder,
    cgroup: &mut ManagedCgroup,
) -> Result<ObserveOutcome> {
    let mut quiescence = load_initial_quiescence(request.harness_evidence.as_deref())?;
    let mut authenticated = prepare_authenticated_harness(request, manifest, recorder, cgroup)?;
    if let Some(active) = &authenticated {
        let identity = active.client.identity()?;
        manifest.environment.harness_public_key_fingerprint_sha256 =
            Some(identity.public_key_fingerprint_sha256);
        atomic_file::write_json_atomic(&request.output_dir.join("manifest.json"), manifest)?;
    }
    let maps_quiescent = authenticated.is_some();

    let canary_epoch = canary_epoch(request.run_epoch);
    let canary_health = run_transport_canary(recorder, cgroup, canary_epoch)?;
    atomic_file::write_json_atomic(
        &request.output_dir.join("canary-health.json"),
        &canary_health,
    )?;
    manifest.notes.push(format!(
        "native recorder transport canary passed with reserved epoch {canary_epoch}"
    ));

    recorder
        .register_run(cgroup.id(), request.run_epoch)
        .context("register cgroup/run epoch with recorder")?;

    let s0_options = capture_options(
        &manifest.run_id,
        "S0",
        &manifest.observer_exclusions,
        maps_quiescent,
    );
    let s0 = capture(&manifest.effective_scope, &s0_options).context("capture S0")?;
    atomic_file::write_json_atomic(&request.output_dir.join("s0.json"), &s0)?;
    let s0_sha256 = environment::sha256_file(&request.output_dir.join("s0.json"))?;
    if let Some(active) = &mut authenticated {
        active
            .client
            .commit_s0(&s0_sha256)
            .context("commit authenticated S0 boundary")?;
    }

    let (workload_status, output_summary) = execute_workload(
        recorder,
        cgroup,
        &request.workload,
        Duration::from_millis(request.timeout_ms),
        Some(&request.output_dir),
    )?;
    manifest.workload_exit_code = workload_status.code();
    manifest.workload_signal = workload_status.signal();
    manifest.notes.push(format_exit_status(workload_status));
    if output_summary.stdout_truncated {
        manifest.notes.push(format!(
            "workload stdout exceeded {MAX_WORKLOAD_OUTPUT_BYTES} bytes and was truncated"
        ));
    }
    if output_summary.stderr_truncated {
        manifest.notes.push(format!(
            "workload stderr exceeded {MAX_WORKLOAD_OUTPUT_BYTES} bytes and was truncated"
        ));
    }

    // Freeze the empty cgroup before closing evidence. Tasks can be moved into
    // a frozen cgroup, but they cannot execute there, so the recorder remains
    // registered across the drain and S1 without a re-entry gap.
    cgroup
        .freeze_empty(CLOSING_BARRIER_TIMEOUT)
        .context("freeze empty workload cgroup for the closing barrier")?;
    if authenticated.is_none() {
        harness::set_observed_check(
            &mut quiescence,
            "cgroup_empty",
            true,
            format!(
                "{} cgroup.events reported populated=0 and frozen=1 after process-tree wait",
                cgroup.path().display()
            ),
        );
        harness::validate_persisted_safe_report(&quiescence)
            .context("validate producer-safe persisted quiescence report")?;
    }

    let mut pre_s1_health = recorder
        .finish_run(
            cgroup.id(),
            request.run_epoch,
            Duration::from_millis(request.drain_timeout_ms),
        )
        .context("close event production, drain, and fsync recorder WAL")?;
    pre_s1_health.producer_barrier_complete = true;
    pre_s1_health.native_transport_canary_passed = true;
    if let Some(active) = &mut authenticated {
        ensure_authenticated_workload_unchanged(active)?;
        atomic_file::write_json_atomic(&request.output_dir.join("health.json"), &pre_s1_health)?;
        let pre_health_sha256 = environment::sha256_file(&request.output_dir.join("health.json"))?;
        active
            .client
            .authorize_pre_s1(HarnessPreS1Evidence {
                pre_health_sha256,
                cgroup_empty: true,
                cgroup_frozen: true,
            })
            .context("authorize authenticated PRE_S1 boundary")?;
    }
    let s1_options = capture_options(
        &manifest.run_id,
        "S1",
        &manifest.observer_exclusions,
        maps_quiescent,
    );
    let s1 = capture(&manifest.effective_scope, &s1_options).context("capture S1")?;
    atomic_file::write_json_atomic(&request.output_dir.join("s1.json"), &s1)?;

    // Re-read and re-drain after S1 while the cgroup is still frozen and the
    // run remains registered. Any counter movement invalidates the boundary.
    let mut health = recorder
        .finish_run(
            cgroup.id(),
            request.run_epoch,
            Duration::from_millis(request.drain_timeout_ms),
        )
        .context("reconcile recorder state after S1")?;
    health.producer_barrier_complete = true;
    health.native_transport_canary_passed = true;
    if health != pre_s1_health {
        bail!("recorder state changed across the frozen S1 boundary");
    }
    if authenticated.is_none() {
        atomic_file::write_json_atomic(&request.output_dir.join("health.json"), &health)?;
    }
    if let Some(active) = authenticated.take() {
        ensure_authenticated_workload_unchanged(&active)?;
        recorder
            .assert_exclusive_window_clean()
            .context("check exclusive-actor evidence before FINAL")?;
        let post_evidence = HarnessPostEvidence {
            s0_sha256,
            s1_sha256: environment::sha256_file(&request.output_dir.join("s1.json"))?,
            health_sha256: environment::sha256_file(&request.output_dir.join("health.json"))?,
            canary_health_sha256: environment::sha256_file(
                &request.output_dir.join("canary-health.json"),
            )?,
            raw_events_wal_sha256: environment::sha256_file(
                &request.output_dir.join("raw-events.bin"),
            )?,
            raw_events_jsonl_sha256: environment::sha256_file(
                &request.output_dir.join("raw-events.jsonl"),
            )?,
            workload_stdout_sha256: environment::sha256_file(
                &request.output_dir.join("workload.stdout"),
            )?,
            workload_stderr_sha256: environment::sha256_file(
                &request.output_dir.join("workload.stderr"),
            )?,
            workload_exit_code: manifest
                .workload_exit_code
                .context("authenticated workload did not exit normally")?,
            workload_signal: manifest.workload_signal,
            outside_cgroup_syscall_attempted: health.outside_cgroup_syscall_attempted,
            recorder_drain_complete: health.drain_completed,
            producer_barrier_complete: health.producer_barrier_complete,
            wal_durable: health.wal_durable,
            in_flight_bpf_barrier_complete: true,
        };
        quiescence = active
            .client
            .finish(post_evidence)
            .context("complete authenticated FINAL boundary")?;
        // Keep the gate armed across the full request/response exchange. This
        // last read detects an outside caller racing the signed FINAL boundary.
        recorder
            .finish_exclusive_window()
            .context("close authenticated exclusive-actor observation")?;
    }
    recorder
        .unregister_run(cgroup.id(), request.run_epoch)
        .context("unregister completed recorder run")?;
    atomic_file::write_json_atomic(&request.output_dir.join("quiescence.json"), &quiescence)?;

    // Removing an empty owned cgroup is part of successful infrastructure
    // cleanup. Refuse to finalize if it unexpectedly became populated again.
    cgroup.cleanup()?;

    let mut verdict = compare(&s0, &s1, &health, quiescence).context("compare S0 and S1")?;
    annotate_observe_verdict(&mut verdict);
    atomic_file::write_json_atomic(&request.output_dir.join("verdict.json"), &verdict)?;

    // manifest.json is the commit record and is finalized last, after every
    // other artifact has been atomically written and fsynced.
    manifest.artifacts = collect_artifact_digests(&request.output_dir)?;
    manifest.run_status = RunStatus::Finalized;
    manifest.finalized_unix_ns = Some(environment::now_unix_ns().max(manifest.started_unix_ns));
    manifest.notes.push(
        "S1 was captured before owned-cgroup teardown; the cgroup was then removed before finalization"
            .into(),
    );
    atomic_file::write_json_atomic(&request.output_dir.join("manifest.json"), manifest)?;

    Ok(ObserveOutcome {
        run_id: manifest.run_id.clone(),
        run_epoch: manifest.run_epoch,
        workload_exit_code: workload_status.code(),
        workload_signal: workload_status.signal(),
        state_verdict: verdict.state_verdict,
        output_dir: request.output_dir.display().to_string(),
    })
}

pub(crate) fn annotate_observe_verdict(verdict: &mut Verdict) {
    verdict.limitations.push(S1_TEARDOWN_LIMITATION.into());
}

fn collect_artifact_digests(output_dir: &Path) -> Result<BTreeMap<String, ArtifactDigest>> {
    validate_finalization_directory(output_dir)?;
    let mut artifacts = BTreeMap::new();
    for name in FINALIZED_RUN_ARTIFACTS_V1 {
        let path = output_dir.join(name);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&path)
            .with_context(|| format!("open finalized artifact {}", path.display()))?;
        let before = file
            .metadata()
            .with_context(|| format!("inspect finalized artifact {}", path.display()))?;
        if !before.file_type().is_file() || before.nlink() != 1 {
            bail!(
                "finalized artifact {} must be a singly linked regular file",
                path.display()
            );
        }
        let limit = artifact_size_limit(name).context("finalized artifact has no size policy")?;
        if before.len() > limit {
            bail!("finalized artifact {name} exceeds its {limit}-byte hard limit");
        }
        let mut limited = Read::by_ref(&mut file).take(limit + 1);
        let (sha256, bytes_read) = environment::sha256_reader_counted(&mut limited)
            .with_context(|| format!("hash finalized artifact {}", path.display()))?;
        if bytes_read != before.len() {
            bail!("finalized artifact {name} changed size while it was hashed");
        }
        let digest = ArtifactDigest {
            sha256,
            size_bytes: before.len(),
        };
        let after = file
            .metadata()
            .with_context(|| format!("reinspect finalized artifact {}", path.display()))?;
        if !same_file_state(&before, &after) {
            bail!("finalized artifact {name} changed while it was hashed");
        }
        if artifacts.insert(name.to_string(), digest).is_some() {
            bail!("duplicate finalized artifact name {name}");
        }
    }
    validate_finalization_directory(output_dir)?;
    Ok(artifacts)
}

fn validate_finalization_directory(output_dir: &Path) -> Result<()> {
    let mut allowed = FINALIZED_RUN_ARTIFACTS_V1
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
    allowed.insert("manifest.json");
    for entry in fs::read_dir(output_dir)
        .with_context(|| format!("enumerate output directory {}", output_dir.display()))?
    {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("output directory contains a non-UTF-8 entry name"))?;
        if !allowed.contains(name.as_str()) {
            bail!("output directory contains unbound entry {name:?}");
        }
    }
    Ok(())
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

pub(crate) fn canary_epoch(formal_epoch: u64) -> u64 {
    if formal_epoch == u64::MAX {
        u64::MAX - 1
    } else {
        u64::MAX
    }
}

fn run_transport_canary(
    recorder: &mut Recorder,
    cgroup: &ManagedCgroup,
    epoch: u64,
) -> Result<EvidenceHealth> {
    recorder
        .register_canary_run(cgroup.id(), epoch)
        .context("register recorder transport canary")?;
    let executable = std::env::current_exe().context("resolve observer executable for canary")?;
    let command = vec![
        executable.into_os_string(),
        OsString::from("recorder-canary"),
    ];
    let (status, _) = execute_workload(recorder, cgroup, &command, CANARY_TIMEOUT, None)
        .context("execute native recorder transport canary")?;
    if !status.success() {
        bail!("native recorder transport canary exited with {status}");
    }

    let mut health = recorder
        .finish_run(cgroup.id(), epoch, CANARY_TIMEOUT)
        .context("drain native recorder transport canary")?;
    health.producer_barrier_complete = true;
    health.native_transport_canary_passed = true;
    recorder
        .validate_native_canary(cgroup.id(), epoch)
        .context("validate exact native recorder transport canary events")?;
    recorder
        .unregister_run(cgroup.id(), epoch)
        .context("unregister recorder transport canary")?;

    let exact_transport = health.syscall_attempted == 1
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
        && health.drain_completed
        && health.wal_durable
        && health.reasons.is_empty();
    if !exact_transport {
        bail!("native recorder transport canary accounting failed: {health:?}");
    }
    Ok(health)
}

#[derive(Clone, Copy, Debug, Default)]
struct OutputSummary {
    stdout_truncated: bool,
    stderr_truncated: bool,
}

struct BoundedCapture {
    reader: Box<dyn Read>,
    file: File,
    limit: u64,
    retained: u64,
    total: u64,
    eof: bool,
}

impl BoundedCapture {
    fn new<R: Read + AsRawFd + 'static>(reader: R, file: File) -> Result<Self> {
        let fd = reader.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error())
                .context("make workload output pipe nonblocking");
        }
        Ok(Self {
            reader: Box::new(reader),
            file,
            limit: MAX_WORKLOAD_OUTPUT_BYTES,
            retained: 0,
            total: 0,
            eof: false,
        })
    }

    fn drain(&mut self) -> Result<()> {
        self.drain_chunks(DRAIN_CHUNKS_PER_POLL)
    }

    fn drain_chunks(&mut self, max_chunks: usize) -> Result<()> {
        let mut buffer = [0u8; 64 * 1024];
        for _ in 0..max_chunks {
            match self.reader.read(&mut buffer) {
                Ok(0) => {
                    self.eof = true;
                    return Ok(());
                }
                Ok(count) => {
                    self.total = self.total.saturating_add(count as u64);
                    let remaining = self.limit.saturating_sub(self.retained);
                    let keep = usize::try_from(remaining.min(count as u64)).unwrap_or(0);
                    if keep > 0 {
                        self.file.write_all(&buffer[..keep])?;
                        self.retained += keep as u64;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error).context("read workload output pipe"),
            }
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<bool> {
        self.drain_chunks(DRAIN_CHUNKS_AT_EOF)?;
        if !self.eof {
            bail!("workload output pipe remained open after the workload cgroup became empty");
        }
        self.file.sync_all().context("fsync workload output")?;
        Ok(self.total > self.retained)
    }
}

enum OutputCaptures {
    Discard,
    Bounded {
        stdout: BoundedCapture,
        stderr: BoundedCapture,
    },
}

impl OutputCaptures {
    fn drain(&mut self) -> Result<()> {
        if let Self::Bounded { stdout, stderr } = self {
            stdout.drain()?;
            stderr.drain()?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<OutputSummary> {
        match self {
            Self::Discard => Ok(OutputSummary::default()),
            Self::Bounded { stdout, stderr } => Ok(OutputSummary {
                stdout_truncated: stdout.finish()?,
                stderr_truncated: stderr.finish()?,
            }),
        }
    }
}

fn open_capture_file(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("create workload output {}", path.display()))
}

fn execute_workload(
    recorder: &mut Recorder,
    cgroup: &ManagedCgroup,
    workload: &[OsString],
    timeout: Duration,
    capture_directory: Option<&Path>,
) -> Result<(ExitStatus, OutputSummary)> {
    let executable = workload.first().context("the workload command is empty")?;
    let mut command = Command::new(executable);
    command.args(&workload[1..]);
    let capture_files = if let Some(directory) = capture_directory {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
        Some((
            open_capture_file(&directory.join("workload.stdout"))?,
            open_capture_file(&directory.join("workload.stderr"))?,
        ))
    } else {
        command.stdout(Stdio::null()).stderr(Stdio::null());
        None
    };
    cgroup.configure_child(&mut command)?;
    let mut child = command
        .spawn()
        .with_context(|| format!("spawn workload {:?}", executable))?;
    let capture_setup = (|| -> Result<OutputCaptures> {
        if let Some((stdout_file, stderr_file)) = capture_files {
            let stdout = child
                .stdout
                .take()
                .context("workload stdout pipe is absent")?;
            let stderr = child
                .stderr
                .take()
                .context("workload stderr pipe is absent")?;
            Ok(OutputCaptures::Bounded {
                stdout: BoundedCapture::new(stdout, stdout_file)?,
                stderr: BoundedCapture::new(stderr, stderr_file)?,
            })
        } else {
            Ok(OutputCaptures::Discard)
        }
    })();
    let mut captures = match capture_setup {
        Ok(captures) => captures,
        Err(error) => {
            kill_and_reap_bounded(&mut child, cgroup);
            return Err(error).context("configure workload output capture");
        }
    };
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("workload timeout exceeds monotonic clock range")?;

    let monitored = (|| -> Result<ExitStatus> {
        let status = loop {
            recorder.poll(poll_duration(deadline))?;
            captures.drain()?;
            if let Some(status) = child.try_wait().context("wait for workload root")? {
                break status;
            }
            if Instant::now() >= deadline {
                bail!("workload root exceeded timeout of {timeout:?}");
            }
        };

        loop {
            recorder.poll(poll_duration(deadline))?;
            captures.drain()?;
            if !cgroup.populated()? {
                break;
            }
            if Instant::now() >= deadline {
                bail!("workload descendants exceeded timeout of {timeout:?}");
            }
            thread::yield_now();
        }
        Ok(status)
    })();

    if monitored.is_err() {
        kill_and_reap_bounded(&mut child, cgroup);
        let _ = captures.drain();
    }
    let status = monitored?;
    let output = captures.finish()?;
    Ok((status, output))
}

fn kill_and_reap_bounded(child: &mut std::process::Child, cgroup: &ManagedCgroup) {
    let _ = cgroup.kill_all();
    // Also target the root PID in case a cooperative-workload assumption was
    // violated and it migrated out of the owned cgroup. Never perform an
    // unbounded wait: a task in uninterruptible sleep must not wedge observerd.
    let _ = child.kill();
    let cleanup_deadline = Instant::now()
        .checked_add(FAILURE_CLEANUP_TIMEOUT)
        .unwrap_or_else(Instant::now);
    loop {
        if child.try_wait().ok().flatten().is_some() && matches!(cgroup.populated(), Ok(false)) {
            break;
        }
        if Instant::now() >= cleanup_deadline {
            break;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn poll_duration(deadline: Instant) -> Duration {
    deadline
        .saturating_duration_since(Instant::now())
        .min(POLL_INTERVAL)
}

fn capture_options(
    run_id: &str,
    phase: &str,
    exclusions: &ObjectExclusions,
    maps_quiescent: bool,
) -> CaptureOptions {
    CaptureOptions {
        snapshot_id: format!("{run_id}-{phase}"),
        phase: phase.to_string(),
        exclusions: exclusions.clone(),
        maps_quiescent,
    }
}

fn load_initial_quiescence(path: Option<&Path>) -> Result<QuiescenceReport> {
    match path {
        Some(path) => harness::load_and_validate(path),
        None => Ok(harness::observed_only(
            true,
            "no trusted harness evidence supplied; only the runtime cgroup will be observed",
        )),
    }
}

fn prepare_output_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("output directory has no parent component")?;
    if !parent.as_os_str().is_empty() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create output parent {}", parent.display()))?;
    }
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700).create(path).with_context(|| {
        format!(
            "atomically claim new output directory {}; it must not already exist",
            path.display()
        )
    })
}

fn validate_request(request: &ObserveRequest) -> Result<()> {
    if request.workload.is_empty() {
        bail!("workload command must not be empty");
    }
    if request.run_epoch == 0 {
        bail!("run_epoch must be non-zero");
    }
    if request.timeout_ms == 0 {
        bail!("timeout_ms must be non-zero");
    }
    if request.drain_timeout_ms == 0 {
        bail!("drain_timeout_ms must be non-zero");
    }
    validate_expected_recorder_sha256(&request.expected_recorder_sha256)?;
    if let Some(auth) = &request.authenticated_harness {
        if request.harness_evidence.is_some() {
            bail!("authenticated harness channel conflicts with unbound --harness-evidence");
        }
        if auth.timeout_ms == 0 {
            bail!("harness_timeout_ms must be non-zero");
        }
        validate_expected_recorder_sha256(&auth.expected_policy_sha256)
            .context("validate expected harness policy SHA-256")?;
        for (value, label) in [
            (&auth.policy_id, "harness_policy_id"),
            (&auth.kernel_identity, "harness_kernel_identity"),
        ] {
            if value.is_empty() || value.len() > 4096 || value.contains('\0') {
                bail!("{label} must contain 1..=4096 non-NUL UTF-8 bytes");
            }
        }
        for (path, label) in [
            (&auth.channel, "harness_channel"),
            (&auth.public_key, "harness_public_key"),
        ] {
            let text = path
                .to_str()
                .with_context(|| format!("{label} is not UTF-8"))?;
            if !is_lexically_normal_absolute(text.as_bytes()) {
                bail!("{label} must be a lexically normalized absolute path");
            }
        }
    }
    if !request.cgroup_root.is_absolute() {
        bail!("cgroup_root must be an absolute path");
    }
    validate_cgroup_root(&request.cgroup_root)?;
    Ok(())
}

fn validate_expected_recorder_sha256(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("expected_recorder_sha256 must be a canonical lowercase SHA-256");
    }
    Ok(())
}

pub(crate) fn validate_cgroup_root(path: &Path) -> Result<()> {
    let cgroup_root = path
        .to_str()
        .context("cgroup_root contains non-UTF-8 bytes unsupported by manifest v1")?;
    if !is_lexically_normal_absolute(cgroup_root.as_bytes()) {
        bail!("cgroup_root must be a lexically normalized absolute path");
    }
    Ok(())
}

fn is_lexically_normal_absolute(path: &[u8]) -> bool {
    if path.contains(&0) {
        return false;
    }
    if path == b"/" {
        return true;
    }
    path.first() == Some(&b'/')
        && path.last() != Some(&b'/')
        && path[1..]
            .split(|byte| *byte == b'/')
            .all(|component| !component.is_empty() && component != b"." && component != b"..")
}

pub(crate) fn validate_observe_scope(scope: &ClaimScope) -> Result<()> {
    bpf_observer_oracle::validate_claim_scope(scope)?;
    if scope.object_types.is_empty() {
        bail!("observe claim scope must include at least one endpoint object type");
    }
    if scope.event_interfaces.len() != 1
        || !scope.event_interfaces.contains(BASELINE_EVENT_INTERFACE)
    {
        bail!("this build requires event_interfaces to be exactly [{BASELINE_EVENT_INTERFACE:?}]");
    }
    if !scope.attachment_targets.is_empty() {
        bail!(
            "attachment_targets were requested, but this baseline has no target-specific attachment adapter"
        );
    }
    Ok(())
}

fn validate_scope_exclusions(scope: &ClaimScope, exclusions: &ObjectExclusions) -> Result<()> {
    bpf_observer_oracle::validate_claim_scope_exclusions(scope, exclusions)
}

pub(crate) fn validate_run_id(run_id: &str) -> Result<()> {
    if run_id.is_empty() || run_id.len() > 64 {
        bail!("run_id must contain between 1 and 64 bytes");
    }
    if !run_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || matches!(run_id, "." | "..")
    {
        bail!("run_id contains characters unsafe for a cgroup directory name");
    }
    Ok(())
}

fn format_exit_status(status: ExitStatus) -> String {
    match (status.code(), status.signal()) {
        (Some(code), _) => format!("workload root exited with code {code}"),
        (_, Some(signal)) => format!("workload root terminated by signal {signal}"),
        _ => "workload root exited with an unknown status".to_string(),
    }
}

fn mark_existing_verdict_failed(output_dir: &Path) -> Result<()> {
    let verdict_path = output_dir.join("verdict.json");
    if !verdict_path.exists() {
        return Ok(());
    }

    let result = (|| -> Result<()> {
        let mut verdict: Verdict = input::read_json(&verdict_path, MAX_VERDICT_JSON_BYTES)?;
        if verdict.state_verdict == StateVerdict::UnchangedWithinScope {
            verdict.state_verdict = StateVerdict::Inconclusive;
        }
        verdict.run_status = RunStatus::Failed;
        verdict
            .limitations
            .push("run finalization failed; this verdict is not a successful observation".into());
        remove_atomic_temporary(&verdict_path)?;
        atomic_file::write_json_atomic(&verdict_path, &verdict)
    })();

    if let Err(error) = result {
        // A malformed or non-durable derived verdict is less safe than no
        // verdict. The FAILED manifest retains the authoritative error.
        fs::remove_file(&verdict_path)
            .with_context(|| format!("remove unsafe verdict after: {error:#}"))?;
        return Err(error);
    }
    Ok(())
}

fn remove_atomic_temporary(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("observer-output");
    let temporary = path.with_file_name(format!(".{name}.tmp-{}", std::process::id()));
    match fs::remove_file(&temporary) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error)
            .with_context(|| format!("remove stale temporary file {}", temporary.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::io::Cursor;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_path_like_run_ids() {
        assert!(validate_run_id("../escape").is_err());
        assert!(validate_run_id("run/escape").is_err());
        assert!(validate_run_id("valid-run_1.2").is_ok());
    }

    #[test]
    fn cgroup_root_must_round_trip_through_manifest_v1() {
        assert!(validate_cgroup_root(Path::new("/sys/fs/cgroup/observer")).is_ok());
        assert!(validate_cgroup_root(Path::new("/sys/fs/cgroup/../escape")).is_err());
        assert!(validate_cgroup_root(Path::new("/sys/fs/cgroup/\0escape")).is_err());
        let non_utf8 = PathBuf::from(OsString::from_vec(vec![b'/', 0xff]));
        assert!(validate_cgroup_root(&non_utf8).is_err());
    }

    #[test]
    fn recorder_policy_digest_must_be_canonical() {
        assert!(validate_expected_recorder_sha256(&"00".repeat(32)).is_ok());
        assert!(validate_expected_recorder_sha256(&"AA".repeat(32)).is_err());
        assert!(validate_expected_recorder_sha256("short").is_err());
    }

    #[test]
    fn output_directory_is_claimed_exactly_once() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!(
                "bpf-observer-output-claim-{}-{nonce}",
                std::process::id()
            ));
        prepare_output_directory(&path).unwrap();
        assert!(prepare_output_directory(&path).is_err());
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn absent_harness_is_not_enforced() {
        let report = load_initial_quiescence(None).unwrap();
        assert!(!report.supports_unchanged());
    }

    #[test]
    fn rejects_scope_reduction_at_preflight() {
        let mut scope = ClaimScope::default();
        scope.event_interfaces.insert("UNIMPLEMENTED".into());
        assert!(validate_observe_scope(&scope).is_err());

        let mut scope = ClaimScope::default();
        scope
            .attachment_targets
            .push(serde_json::json!({"kind": "cgroup"}));
        assert!(validate_observe_scope(&scope).is_err());
    }

    #[test]
    fn rejects_explicit_observer_map_ids() {
        let mut scope = ClaimScope::default();
        scope.map_ids.insert(17);
        let mut exclusions = ObjectExclusions::default();
        exclusions.map_ids.insert(17);
        assert!(validate_scope_exclusions(&scope, &exclusions).is_err());
    }

    #[test]
    fn workload_capture_drains_after_retention_limit() {
        let name = CString::new("bpf-observer-output-test").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        let sink = unsafe { File::from_raw_fd(fd) };
        let mut capture = BoundedCapture {
            reader: Box::new(Cursor::new(b"0123456789".to_vec())),
            file: sink,
            limit: 4,
            retained: 0,
            total: 0,
            eof: false,
        };
        assert!(capture.finish().unwrap());
        assert_eq!(capture.retained, 4);
        assert_eq!(capture.total, 10);
        assert!(capture.eof);
    }
}
