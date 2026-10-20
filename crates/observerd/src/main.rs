// SPDX-License-Identifier: GPL-2.0-only

mod atomic_file;
mod cgroup;
mod doctor;
mod effects_run;
mod effects_supervisor;
mod effects_supervisor_protocol;
mod effects_verify;
mod environment;
mod harness;
mod input;
mod object_resolution;
mod run;
mod verification;

use anyhow::{bail, Context, Result};
use bpf_observer_comparator::compare;
use bpf_observer_oracle::{capture, validate_snapshot_resource_bounds, CaptureOptions};
use bpf_observer_schema::{
    ClaimScope, EvidenceHealth, QuiescenceReport, Snapshot, StateVerdict, MAX_HEALTH_JSON_BYTES,
    MAX_MANIFEST_JSON_BYTES, MAX_SNAPSHOT_JSON_BYTES,
};
use bpf_observer_system_effects::PolicyProfile;
use clap::{ArgEnum, Parser, Subcommand};
use object_resolution::ObjectResolutionMode;
use serde::Serialize;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[clap(
    name = "bpf-state-observer",
    version,
    about = "Scope-aware Linux BPF state and operation observer"
)]
struct Cli {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Internal no-side-effect syscall used to prove the recorder transport.
    #[clap(name = "recorder-canary", hide = true)]
    RecorderCanary,

    /// Check whether this machine has the minimum runtime prerequisites.
    Doctor {
        /// Recorder BPF object that will be used for an observed run.
        #[clap(long, parse(from_os_str))]
        recorder_object: Option<PathBuf>,

        /// Separate process-lifecycle BPF object required by expanded mode.
        #[clap(long, parse(from_os_str))]
        process_lifecycle_object: Option<PathBuf>,

        /// Cgroup subtree that observed runs will create.
        #[clap(
            long,
            parse(from_os_str),
            default_value = "/sys/fs/cgroup/bpf-state-observer"
        )]
        cgroup_root: PathBuf,

        /// Write the report atomically instead of printing it to stdout.
        #[clap(long, parse(from_os_str))]
        output: Option<PathBuf>,

        /// Required strength of object evidence. Both partial kernel modes
        /// fail closed unless their exact hook/WAL/verifier pipeline is available.
        #[clap(long, arg_enum, default_value = "user-input")]
        object_resolution: ObjectResolutionMode,
    },

    /// Capture one explicitly scoped state snapshot.
    Snapshot {
        /// JSON ClaimScope. Formal runs should never rely on an implicit scope.
        #[clap(long, parse(from_os_str))]
        scope: PathBuf,

        /// Snapshot boundary label.
        #[clap(long, arg_enum)]
        phase: SnapshotPhase,

        /// JSON ObjectExclusions, normally obtained from the loaded recorder.
        #[clap(long, parse(from_os_str))]
        exclusions: Option<PathBuf>,

        /// Unbound diagnostic report; it cannot authorize atomic Map reads.
        #[clap(long, parse(from_os_str))]
        quiescence: Option<PathBuf>,

        /// Destination JSON file.
        #[clap(long, parse(from_os_str))]
        output: PathBuf,
    },

    /// Compare two snapshots without running a workload.
    Compare {
        #[clap(long, parse(from_os_str))]
        before: PathBuf,

        #[clap(long, parse(from_os_str))]
        after: PathBuf,

        /// Final recorder accounting. Required so missing evidence is explicit.
        #[clap(long, parse(from_os_str))]
        health: PathBuf,

        /// Unbound diagnostic report; standalone compare never authorizes unchanged.
        #[clap(long, parse(from_os_str))]
        quiescence: Option<PathBuf>,

        #[clap(long, parse(from_os_str))]
        output: PathBuf,
    },

    /// Observe one command in a dedicated cgroup and emit a finalized run.
    Observe {
        #[clap(long, parse(from_os_str))]
        scope: PathBuf,

        #[clap(long, parse(from_os_str))]
        recorder_object: PathBuf,

        /// Trusted SHA-256 policy for the exact recorder object bytes.
        #[clap(long)]
        expected_recorder_sha256: String,

        #[clap(long, parse(from_os_str))]
        output_dir: PathBuf,

        #[clap(
            long,
            parse(from_os_str),
            default_value = "/sys/fs/cgroup/bpf-state-observer"
        )]
        cgroup_root: PathBuf,

        /// Optional caller correlation ID; defaults to a kernel-generated UUID.
        #[clap(long)]
        run_id: Option<String>,

        #[clap(long, default_value_t = 1)]
        run_epoch: u64,

        /// Maximum workload/process-tree lifetime.
        #[clap(long, default_value_t = 30_000)]
        timeout_ms: u64,

        /// Maximum recorder drain interval after the workload cgroup is empty.
        #[clap(long, default_value_t = 5_000)]
        drain_timeout_ms: u64,

        /// Unbound diagnostic report; file-supplied trust claims are always downgraded.
        #[clap(long, parse(from_os_str))]
        harness_evidence: Option<PathBuf>,

        /// Authenticated Host harness character device (for example a
        /// virtio-serial port). All authenticated-harness options are required
        /// together and conflict with --harness-evidence.
        #[clap(long, parse(from_os_str))]
        harness_channel: Option<PathBuf>,

        /// Raw 32-byte Ed25519 public key for the external Host harness.
        #[clap(long, parse(from_os_str))]
        harness_public_key: Option<PathBuf>,

        /// Exact policy identifier expected in every signed response.
        #[clap(long)]
        harness_policy_id: Option<String>,

        /// Canonical SHA-256 of the exact Host-side harness policy.
        #[clap(long)]
        expected_harness_policy_sha256: Option<String>,

        /// Host-authorized identity for this kernel/rootfs combination.
        #[clap(long)]
        harness_kernel_identity: Option<String>,

        /// End-to-end timeout for each authenticated protocol exchange.
        #[clap(long, default_value_t = 5_000)]
        harness_timeout_ms: u64,

        /// Workload and arguments. A `--` separator is required.
        #[clap(last = true, required = true)]
        workload: Vec<OsString>,
    },

    /// Record selected Agent system-effect operations from one exact cgroup.
    /// This is operation evidence, not a whole-kernel state diff.
    ObserveEffects {
        #[clap(long, parse(from_os_str))]
        recorder_object: PathBuf,

        #[clap(long)]
        expected_recorder_sha256: String,

        /// Separate fork/exec/exit BPF object; required only in expanded mode.
        #[clap(long, parse(from_os_str))]
        process_lifecycle_object: Option<PathBuf>,

        /// Trusted SHA-256 for the exact process-lifecycle object bytes.
        #[clap(long)]
        expected_process_lifecycle_sha256: Option<String>,

        /// New output directory; it must not already exist.
        #[clap(long, parse(from_os_str))]
        output_dir: PathBuf,

        #[clap(
            long,
            parse(from_os_str),
            default_value = "/sys/fs/cgroup/bpf-state-observer-effects"
        )]
        cgroup_root: PathBuf,

        #[clap(long)]
        run_id: Option<String>,

        #[clap(long, default_value_t = 1)]
        run_epoch: u64,

        /// control minimizes data-path events; balanced includes write/send;
        /// full also records noisy ambiguous interfaces such as ioctl/mmap.
        #[clap(long, default_value = "control")]
        profile: PolicyProfile,

        #[clap(long, default_value_t = 30_000)]
        timeout_ms: u64,

        #[clap(long, default_value_t = 5_000)]
        drain_timeout_ms: u64,

        /// `user-input` retains bounded syscall-entry bytes. The explicit
        /// `kernel-file-open-partial` mode resolves selected file opens;
        /// `kernel-file-open-write-partial` additionally resolves the VFS
        /// `struct file` for positive-byte write/pwrite/writev-family results
        /// observed by the hook, including pseudo-files but not socket
        /// endpoints. Kernel modes refuse to launch unless their exact
        /// BTF/BPF-LSM hook pipeline is available.
        #[clap(long, arg_enum, default_value = "user-input")]
        object_resolution: ObjectResolutionMode,

        /// Explicit BPF ClaimScope for optional S0/S1 final-state confirmation.
        /// Without this flag only operation history is collected.
        #[clap(long, parse(from_os_str))]
        bpf_state_scope: Option<PathBuf>,

        /// Explicit filesystem path-tree scope for optional bounded S0/S1
        /// endpoint confirmation. The scope is disabled when omitted.
        #[clap(long, parse(from_os_str))]
        filesystem_state_scope: Option<PathBuf>,

        /// Caller-supplied actor/quiescence contract, bound to this run,
        /// epoch, filesystem scope, and both filesystem snapshot IDs. The
        /// Observer checks exact binding but does not authenticate its issuer.
        #[clap(long, parse(from_os_str))]
        filesystem_actor_contract: Option<PathBuf>,

        /// Explicit bounded sysctl/mount/network/module Linux endpoint-state
        /// scope. Omit it to leave those domains unconfirmed.
        #[clap(long, parse(from_os_str))]
        linux_state_scope: Option<PathBuf>,

        /// Add an Observer-derived residual-process scope bound to the exact
        /// per-run cgroup path and kernel cgroup ID.
        #[clap(long)]
        confirm_process_residual: bool,

        /// Finalize diagnostic artifacts even when event transport is incomplete.
        #[clap(long)]
        allow_incomplete_transport: bool,

        /// Workload and arguments. A double-dash separator is required.
        #[clap(last = true, required = true)]
        workload: Vec<OsString>,
    },

    /// Validate a filesystem scope and derive its exact run/snapshot binding.
    #[clap(name = "filesystem-scope-info")]
    FilesystemScopeInfo {
        #[clap(long, parse(from_os_str))]
        scope: PathBuf,

        #[clap(long)]
        run_id: String,

        #[clap(long, default_value_t = 1)]
        run_epoch: u64,
    },

    /// Internal per-run recorder peer launched by the Allox daemon.
    #[clap(name = "supervise-effects")]
    SuperviseEffects {
        /// Trusted recorder object path. Digest and profile come only from START.
        #[clap(long, parse(from_os_str))]
        recorder_object: PathBuf,

        /// Maximum recorder drain interval after verified FINISH quiescence.
        #[clap(long, default_value_t = 5_000)]
        drain_timeout_ms: u64,
    },

    /// Summarize recorded file opens, bytes and per-call latency from a WAL.
    FileAccessReport {
        /// Existing system-effects.raw.bin (standalone or deployment run).
        #[clap(long, parse(from_os_str))]
        wal: PathBuf,

        /// Exact profile used during collection.
        #[clap(long, default_value = "file-access")]
        profile: PolicyProfile,

        /// Omit per-call rows, retaining totals and per-file accounting.
        #[clap(long)]
        summary_only: bool,
    },

    /// Verify a finalized system-effect run and its complete artifact set.
    VerifyEffects {
        #[clap(long, parse(from_os_str))]
        run_dir: PathBuf,

        /// Externally trusted recorder object SHA-256.
        #[clap(long)]
        expected_recorder_sha256: String,

        /// Externally trusted lifecycle object SHA-256, required for expanded runs.
        #[clap(long)]
        expected_process_lifecycle_sha256: Option<String>,

        /// Externally selected policy profile for this run.
        #[clap(long)]
        expected_profile: PolicyProfile,

        /// Externally selected object-evidence strength; never trusted from
        /// the run manifest alone.
        #[clap(long, arg_enum)]
        expected_object_resolution: ObjectResolutionMode,

        /// Externally trusted ClaimScope required when the run contains BPF
        /// state confirmation artifacts.
        #[clap(long, parse(from_os_str))]
        expected_bpf_state_scope: Option<PathBuf>,

        /// Externally trusted filesystem scope required when the run contains
        /// filesystem endpoint confirmation artifacts.
        #[clap(long, parse(from_os_str))]
        expected_filesystem_state_scope: Option<PathBuf>,

        /// Caller-supplied exact actor contract required when the run contains
        /// its corresponding artifact. Equality is checked, but the Observer
        /// does not authenticate its issuer.
        #[clap(long, parse(from_os_str))]
        expected_filesystem_actor_contract: Option<PathBuf>,

        /// Externally trusted Linux endpoint-state scope. For an automatically
        /// bound residual-process-only run this may be omitted.
        #[clap(long, parse(from_os_str))]
        expected_linux_state_scope: Option<PathBuf>,

        /// Require and independently reconstruct automatic residual-process
        /// confirmation from the finalized run cgroup binding.
        #[clap(long)]
        confirm_process_residual: bool,
    },

    /// Verify a finalized run manifest, artifact digests, event streams, and verdict.
    VerifyRun {
        #[clap(long, parse(from_os_str))]
        run_dir: PathBuf,

        /// Trusted SHA-256 policy for the recorder used by this run.
        #[clap(long)]
        expected_recorder_sha256: String,

        /// Raw Ed25519 public key required for an authenticated run.
        #[clap(long, parse(from_os_str))]
        harness_public_key: Option<PathBuf>,

        /// Exact signed harness policy ID.
        #[clap(long)]
        harness_policy_id: Option<String>,

        /// Canonical digest of the exact signed Host harness policy.
        #[clap(long)]
        expected_harness_policy_sha256: Option<String>,

        /// Exact Host-authorized kernel/rootfs identity.
        #[clap(long)]
        harness_kernel_identity: Option<String>,
    },
}

#[derive(Copy, Clone, Debug, ArgEnum)]
enum SnapshotPhase {
    S0,
    S1,
}

impl SnapshotPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::S0 => "S0",
            Self::S1 => "S1",
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::RecorderCanary => command_recorder_canary(),
        Commands::Doctor {
            recorder_object,
            process_lifecycle_object,
            cgroup_root,
            output,
            object_resolution,
        } => command_doctor(
            recorder_object.as_deref(),
            process_lifecycle_object.as_deref(),
            &cgroup_root,
            output.as_deref(),
            object_resolution,
        ),
        Commands::Snapshot {
            scope,
            phase,
            exclusions,
            quiescence,
            output,
        } => command_snapshot(
            &scope,
            phase,
            exclusions.as_deref(),
            quiescence.as_deref(),
            &output,
        ),
        Commands::Compare {
            before,
            after,
            health,
            quiescence,
            output,
        } => command_compare(&before, &after, &health, quiescence.as_deref(), &output),
        Commands::Observe {
            scope,
            recorder_object,
            expected_recorder_sha256,
            output_dir,
            cgroup_root,
            run_id,
            run_epoch,
            timeout_ms,
            drain_timeout_ms,
            harness_evidence,
            harness_channel,
            harness_public_key,
            harness_policy_id,
            expected_harness_policy_sha256,
            harness_kernel_identity,
            harness_timeout_ms,
            workload,
        } => {
            let authenticated_harness = match (
                harness_channel,
                harness_public_key,
                harness_policy_id,
                expected_harness_policy_sha256,
                harness_kernel_identity,
            ) {
                (None, None, None, None, None) => None,
                (Some(channel), Some(public_key), Some(policy_id), Some(policy_sha256), Some(kernel_identity)) => {
                    Some(run::AuthenticatedHarnessRequest {
                        channel,
                        public_key,
                        policy_id,
                        expected_policy_sha256: policy_sha256,
                        kernel_identity,
                        timeout_ms: harness_timeout_ms,
                    })
                }
                _ => bail!("--harness-channel, --harness-public-key, --harness-policy-id, --expected-harness-policy-sha256, and --harness-kernel-identity must be supplied together"),
            };
            let outcome = run::observe(run::ObserveRequest {
                scope_path: scope,
                recorder_object,
                expected_recorder_sha256,
                output_dir,
                cgroup_root,
                run_id,
                run_epoch,
                timeout_ms,
                drain_timeout_ms,
                harness_evidence,
                authenticated_harness,
                workload,
            })?;
            print_json(&outcome)
        }
        Commands::ObserveEffects {
            recorder_object,
            expected_recorder_sha256,
            process_lifecycle_object,
            expected_process_lifecycle_sha256,
            output_dir,
            cgroup_root,
            run_id,
            run_epoch,
            profile,
            timeout_ms,
            drain_timeout_ms,
            object_resolution,
            bpf_state_scope,
            filesystem_state_scope,
            filesystem_actor_contract,
            linux_state_scope,
            confirm_process_residual,
            allow_incomplete_transport,
            workload,
        } => {
            // Do this before effects_run creates an output directory or a
            // cgroup. Unsupported evidence strength must have no workload or
            // evidence-side effects.
            let capability = object_resolution::inspect_with_lifecycle(
                object_resolution,
                Some(&recorder_object),
                process_lifecycle_object.as_deref(),
            );
            object_resolution::require_available(&capability)?;
            let outcome = effects_run::observe(effects_run::ObserveRequest {
                recorder_object,
                expected_recorder_sha256,
                process_lifecycle_object,
                expected_process_lifecycle_sha256,
                output_dir,
                cgroup_root,
                run_id,
                run_epoch,
                profile,
                timeout_ms,
                drain_timeout_ms,
                object_resolution_mode: object_resolution,
                allow_incomplete_transport,
                bpf_state_scope,
                filesystem_state_scope,
                filesystem_actor_contract,
                linux_state_scope,
                confirm_process_residual,
                workload,
            })?;
            print_json(&outcome)
        }
        Commands::FilesystemScopeInfo {
            scope,
            run_id,
            run_epoch,
        } => {
            run::validate_run_id(&run_id)?;
            if run_epoch == 0 {
                anyhow::bail!("run_epoch must be nonzero");
            }
            let scope: bpf_observer_filesystem_confirmer::FilesystemScope = input::read_json(
                &scope,
                bpf_observer_filesystem_confirmer::HARD_MAX_SCOPE_JSON_BYTES,
            )
            .context("read filesystem scope")?;
            scope.validate().context("validate filesystem scope")?;
            print_json(&FilesystemScopeInfoReport {
                protocol_version:
                    bpf_observer_filesystem_confirmer::FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
                run_id: run_id.clone(),
                run_epoch,
                scope_sha256: scope.sha256()?,
                s0_snapshot_id: effects_run::filesystem_snapshot_id(&run_id, run_epoch, "S0"),
                s1_snapshot_id: effects_run::filesystem_snapshot_id(&run_id, run_epoch, "S1"),
                actor_contract_authentication: "EXTERNAL_TO_OBSERVER",
            })
        }
        Commands::SuperviseEffects {
            recorder_object,
            drain_timeout_ms,
        } => effects_supervisor::serve(effects_supervisor::ServeRequest {
            recorder_object,
            drain_timeout_ms,
        }),
        Commands::FileAccessReport {
            wal,
            profile,
            summary_only,
        } => {
            let recovery = bpf_observer_system_effects::recover_wal(&wal)?;
            print_json(&bpf_observer_system_effects::access::report(
                &recovery,
                profile,
                !summary_only,
            )?)
        }
        Commands::VerifyEffects {
            run_dir,
            expected_recorder_sha256,
            expected_process_lifecycle_sha256,
            expected_profile,
            expected_object_resolution,
            expected_bpf_state_scope,
            expected_filesystem_state_scope,
            expected_filesystem_actor_contract,
            expected_linux_state_scope,
            confirm_process_residual,
        } => {
            let expected_scope = expected_bpf_state_scope
                .as_deref()
                .map(|path| input::read_json(path, MAX_MANIFEST_JSON_BYTES))
                .transpose()
                .context("read externally trusted BPF state scope")?;
            let expected_filesystem_scope = expected_filesystem_state_scope
                .as_deref()
                .map(|path| {
                    input::read_json(
                        path,
                        bpf_observer_filesystem_confirmer::HARD_MAX_SCOPE_JSON_BYTES,
                    )
                })
                .transpose()
                .context("read externally trusted filesystem state scope")?;
            let expected_filesystem_contract = expected_filesystem_actor_contract
                .as_deref()
                .map(|path| {
                    input::read_json(
                        path,
                        bpf_observer_filesystem_confirmer::HARD_MAX_ACTOR_CONTRACT_JSON_BYTES,
                    )
                })
                .transpose()
                .context("read caller-supplied filesystem actor contract")?;
            let expected_linux_scope = expected_linux_state_scope
                .as_deref()
                .map(|path| {
                    input::read_json(
                        path,
                        bpf_observer_linux_state_confirmers::HARD_MAX_SCOPE_JSON_BYTES,
                    )
                })
                .transpose()
                .context("read externally trusted Linux endpoint-state scope")?;
            let report = effects_verify::verify_run_with_linux_state_and_lifecycle(
                &run_dir,
                &expected_recorder_sha256,
                expected_process_lifecycle_sha256.as_deref(),
                expected_profile,
                expected_object_resolution,
                expected_scope.as_ref(),
                expected_filesystem_scope.as_ref(),
                expected_filesystem_contract.as_ref(),
                expected_linux_scope.as_ref(),
                confirm_process_residual,
            )?;
            print_json(&report)
        }
        Commands::VerifyRun {
            run_dir,
            expected_recorder_sha256,
            harness_public_key,
            harness_policy_id,
            expected_harness_policy_sha256,
            harness_kernel_identity,
        } => {
            let harness_policy = match (
                harness_public_key,
                harness_policy_id,
                expected_harness_policy_sha256,
                harness_kernel_identity,
            ) {
                (None, None, None, None) => None,
                (Some(public_key), Some(policy_id), Some(expected_policy_sha256), Some(kernel_identity)) => {
                    Some(verification::HarnessVerificationPolicy {
                        public_key,
                        policy_id,
                        expected_policy_sha256,
                        kernel_identity,
                    })
                }
                _ => bail!("--harness-public-key, --harness-policy-id, --expected-harness-policy-sha256, and --harness-kernel-identity must be supplied together"),
            };
            let report = verification::verify_run(
                &run_dir,
                &expected_recorder_sha256,
                harness_policy.as_ref(),
            )?;
            print_json(&report)
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct FilesystemScopeInfoReport {
    protocol_version: u32,
    run_id: String,
    run_epoch: u64,
    scope_sha256: String,
    s0_snapshot_id: String,
    s1_snapshot_id: String,
    actor_contract_authentication: &'static str,
}

fn command_recorder_canary() -> Result<()> {
    // BPF_MAP_CREATE with a null attribute and zero size is rejected by the
    // kernel before it can create state, while still traversing the native
    // raw_syscalls enter/exit tracepoints with command number zero.
    let _ = unsafe { libc::syscall(libc::SYS_bpf, 0u32, std::ptr::null::<libc::c_void>(), 0u32) };
    Ok(())
}

fn command_doctor(
    recorder_object: Option<&Path>,
    process_lifecycle_object: Option<&Path>,
    cgroup_root: &Path,
    output: Option<&Path>,
    object_resolution_mode: ObjectResolutionMode,
) -> Result<()> {
    let report = doctor::inspect(
        recorder_object,
        process_lifecycle_object,
        cgroup_root,
        object_resolution_mode,
    );
    if let Some(path) = output {
        atomic_file::write_json_atomic(path, &report)?;
    } else {
        print_json(&report)?;
    }
    if !report.ready_for_runtime {
        bail!("runtime prerequisite check failed");
    }
    Ok(())
}

fn command_snapshot(
    scope_path: &Path,
    phase: SnapshotPhase,
    exclusions_path: Option<&Path>,
    quiescence_path: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let scope: ClaimScope = input::read_json(scope_path, MAX_MANIFEST_JSON_BYTES)?;
    let exclusions = exclusions_path
        .map(|path| input::read_json(path, MAX_MANIFEST_JSON_BYTES))
        .transpose()?
        .unwrap_or_default();
    let maps_quiescent = match quiescence_path {
        Some(path) => harness::load_and_validate(path)?.supports_unchanged(),
        None => false,
    };
    let snapshot_id = format!("manual-{}-{}", phase.as_str(), environment::now_unix_ns());
    let options = CaptureOptions {
        snapshot_id,
        phase: phase.as_str().to_string(),
        exclusions,
        maps_quiescent,
    };
    let snapshot = capture(&scope, &options)
        .with_context(|| format!("capture {} snapshot", phase.as_str()))?;
    atomic_file::write_json_atomic(output, &snapshot)
}

fn command_compare(
    before_path: &Path,
    after_path: &Path,
    health_path: &Path,
    quiescence_path: Option<&Path>,
    output: &Path,
) -> Result<()> {
    let before: Snapshot = input::read_json(before_path, MAX_SNAPSHOT_JSON_BYTES)?;
    let after: Snapshot = input::read_json(after_path, MAX_SNAPSHOT_JSON_BYTES)?;
    validate_snapshot_resource_bounds(&before).context("validate S0 producer snapshot contract")?;
    validate_snapshot_resource_bounds(&after).context("validate S1 producer snapshot contract")?;
    let health: EvidenceHealth = input::read_json(health_path, MAX_HEALTH_JSON_BYTES)?;
    let quiescence = load_quiescence_or_safe_default(quiescence_path)?;
    let mut verdict = compare(&before, &after, &health, quiescence)?;
    if verdict.state_verdict == StateVerdict::UnchangedWithinScope {
        verdict.state_verdict = StateVerdict::Inconclusive;
        if !health.is_complete() {
            verdict.limitations.push(
                "command-level safety gate: incomplete recorder health prevents an unchanged verdict"
                    .into(),
            );
        } else {
            verdict.limitations.push(
                "standalone compare inputs are not bound by one finalized run manifest; this diagnostic command cannot emit an unchanged verdict"
                    .into(),
            );
        }
    }
    atomic_file::write_json_atomic(output, &verdict)
}

fn load_quiescence_or_safe_default(path: Option<&Path>) -> Result<QuiescenceReport> {
    match path {
        Some(path) => harness::load_and_validate(path),
        None => Ok(harness::observed_only(
            true,
            "no harness evidence supplied; cgroup quiescence was not independently verified",
        )),
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value).context("serialize JSON to stdout")?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_harness_never_supports_unchanged() {
        let report = load_quiescence_or_safe_default(None).unwrap();
        assert!(!report.supports_unchanged());
    }
}
