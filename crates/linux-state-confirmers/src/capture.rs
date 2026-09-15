// SPDX-License-Identifier: GPL-2.0-only

use crate::command::{canonical_json, run_json_command};
use crate::namespace::{RetainedNamespace, RetainedNamespaces};
use crate::schema::*;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::CString;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROC_SUPER_MAGIC: i64 = 0x9fa0;
const SYSFS_MAGIC: i64 = 0x6265_6572;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const READ_BUFFER_BYTES: usize = 32 * 1024;
const HARD_MAX_CGROUP_DEPTH: u32 = 256;

pub fn capture(scope: &StateScope, request: &CaptureRequest) -> Result<StateSnapshot> {
    capture_internal(scope, request, None)
}

pub fn capture_with_retained_namespaces(
    scope: &StateScope,
    request: &CaptureRequest,
    retained: &RetainedNamespaces,
) -> Result<StateSnapshot> {
    retained.verify()?;
    capture_internal(scope, request, Some(retained))
}

fn capture_internal(
    scope: &StateScope,
    request: &CaptureRequest,
    retained: Option<&RetainedNamespaces>,
) -> Result<StateSnapshot> {
    scope.validate()?;
    request.validate()?;
    let boot_before = read_boot_id()?;
    let captured_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_nanos();

    let mut snapshot = StateSnapshot {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        snapshot_id: request.snapshot_id.clone(),
        phase: request.phase,
        captured_unix_ns,
        boot_id: boot_before.clone(),
        scope: scope.clone(),
        scope_sha256: scope.sha256()?,
        sysctl: scope
            .sysctl
            .as_ref()
            .map(|value| capture_sysctl(value, retained)),
        mounts: scope
            .mounts
            .as_ref()
            .map(|value| capture_mounts(value, retained.and_then(|set| set.mounts.as_ref()))),
        network: scope
            .network
            .as_ref()
            .map(|value| capture_network(value, retained.and_then(|set| set.network.as_ref()))),
        modules: scope.modules.as_ref().map(capture_modules),
        process_residual: scope
            .process_residual
            .as_ref()
            .map(capture_process_residual),
    };
    let boot_after = read_boot_id()?;
    if boot_before != boot_after {
        for domain in enabled_domains_mut(&mut snapshot) {
            domain.issues.push(CaptureIssue {
                key: "boot_id".to_owned(),
                kind: CaptureIssueKind::Race,
                errno: None,
                detail: "kernel boot identity changed during endpoint capture".to_owned(),
            });
            finalize_completeness(domain);
        }
    }
    validate_snapshot_shape(&snapshot)?;
    Ok(snapshot)
}

fn capture_sysctl(scope: &SysctlScope, retained: Option<&RetainedNamespaces>) -> DomainSnapshot {
    let Some(retained) = retained else {
        let context = match current_sysctl_namespace_context() {
            Ok(value) => value,
            Err(error) => {
                return DomainBuilder::new(DomainKind::Sysctl, scope.evidence, &scope.limits)
                    .finish_with_error("sysctl_namespaces", CaptureIssueKind::IdentityMismatch, error)
            }
        };
        return capture_sysctl_inner(scope, context);
    };
    let (Some(network), Some(uts), Some(ipc)) = (
        retained.sysctl_network.as_ref(),
        retained.sysctl_uts.as_ref(),
        retained.sysctl_ipc.as_ref(),
    ) else {
        return DomainBuilder::new(DomainKind::Sysctl, scope.evidence, &scope.limits)
            .finish_with_error(
                "sysctl_namespaces",
                CaptureIssueKind::IdentityMismatch,
                anyhow::anyhow!("retained sysctl namespace set is incomplete"),
            );
    };
    let context = vec![ipc.evidence(), network.evidence(), uts.evidence()];
    match network.run(|| uts.run(|| ipc.run(|| Ok(capture_sysctl_inner(scope, context))))) {
        Ok(snapshot) => snapshot,
        Err(error) => DomainBuilder::new(DomainKind::Sysctl, scope.evidence, &scope.limits)
            .finish_with_error(
                "sysctl_namespaces",
                CaptureIssueKind::IdentityMismatch,
                error,
            ),
    }
}

fn capture_sysctl_inner(
    scope: &SysctlScope,
    namespace_context: Vec<NamespaceCaptureEvidence>,
) -> DomainSnapshot {
    let mut builder = DomainBuilder::new(DomainKind::Sysctl, scope.evidence, &scope.limits);
    builder.namespace_context = namespace_context;
    let root = match scope.root() {
        Ok(value) => value,
        Err(error) => return builder.finish_with_error("scope", CaptureIssueKind::Parse, error),
    };
    match strict_proc_sys_root(&root) {
        Ok(identity) => builder.source_identity_sha256 = Some(identity),
        Err(error) => {
            return builder.finish_with_error("proc_sys_root", classify_io_error(&error), error)
        }
    }
    for key in &scope.keys {
        if builder.expired() {
            break;
        }
        let path = root.join(key);
        match read_bounded_anchored(&path, scope.limits.max_value_bytes, Some(PROC_SUPER_MAGIC)) {
            Ok(ReadObservation {
                bytes,
                stable: true,
                ..
            }) => builder.push_record(key.clone(), &bytes),
            Ok(_) => builder.issue(
                key,
                CaptureIssueKind::Race,
                None,
                "sysctl object changed while being read",
            ),
            Err(error) => builder.issue_error(key, classify_io_error(&error), &error),
        }
    }
    builder.finish()
}

fn capture_mounts(scope: &MountScope, retained: Option<&RetainedNamespace>) -> DomainSnapshot {
    if let Some(retained) = retained {
        let mut builder = DomainBuilder::new(DomainKind::Mount, scope.evidence, &scope.limits);
        if retained.kind() != LinuxNamespaceKind::Mount
            || retained.inode() != scope.namespace.expected_namespace_inode
        {
            return builder.finish_with_error(
                "mount_namespace",
                CaptureIssueKind::IdentityMismatch,
                anyhow::anyhow!("retained mount namespace does not match the bound scope"),
            );
        }
        builder.namespace_inode = Some(retained.inode());
        builder.namespace_context = vec![retained.evidence()];
        builder.source_identity_sha256 =
            Some(hex::encode(Sha256::digest(retained.inode().to_le_bytes())));
        match retained.read_mountinfo(scope.limits.max_total_value_bytes) {
            Ok(observation) => {
                record_mountinfo_observation(&mut builder, &observation.bytes, observation.stable)
            }
            Err(error) => {
                builder.issue_error("mountinfo", classify_io_error(&error), &error);
            }
        }
        return builder.finish();
    }
    let evidence = NamespaceCaptureEvidence {
        kind: LinuxNamespaceKind::Mount,
        inode: scope.namespace.expected_namespace_inode,
        source: target_capture_source(&scope.namespace),
    };
    capture_mounts_inner(scope, scope.namespace.clone(), evidence)
}

fn capture_mounts_inner(
    scope: &MountScope,
    namespace: NamespaceTarget,
    evidence: NamespaceCaptureEvidence,
) -> DomainSnapshot {
    let mut builder = DomainBuilder::new(DomainKind::Mount, scope.evidence, &scope.limits);
    let observed_before = match checked_namespace(&namespace, "mnt") {
        Ok(value) => value,
        Err(error) => {
            return builder.finish_with_error(
                "mount_namespace",
                CaptureIssueKind::IdentityMismatch,
                error,
            )
        }
    };
    builder.namespace_inode = Some(observed_before);
    builder.namespace_context = vec![evidence];
    builder.source_identity_sha256 =
        Some(hex::encode(Sha256::digest(observed_before.to_le_bytes())));
    let path = PathBuf::from(format!("/proc/{}/mountinfo", namespace.proc_component()));
    match read_bounded_anchored(
        &path,
        scope.limits.max_total_value_bytes,
        Some(PROC_SUPER_MAGIC),
    ) {
        Ok(observation) => {
            record_mountinfo_observation(&mut builder, &observation.bytes, observation.stable)
        }
        Err(error) => builder.issue_error("mountinfo", classify_io_error(&error), &error),
    }
    match checked_namespace(&namespace, "mnt") {
        Ok(after) if after == observed_before => {}
        Ok(_) => builder.issue(
            "mount_namespace",
            CaptureIssueKind::Race,
            None,
            "mount namespace identity changed during capture",
        ),
        Err(error) => builder.issue_error("mount_namespace", CaptureIssueKind::Race, &error),
    }
    builder.finish()
}

fn record_mountinfo_observation(builder: &mut DomainBuilder<'_>, bytes: &[u8], stable: bool) {
    if !stable {
        builder.issue(
            "mountinfo",
            CaptureIssueKind::Race,
            None,
            "mountinfo changed during capture",
        );
    }
    let mut seen = BTreeSet::new();
    for line in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if builder.expired() {
            break;
        }
        match validate_mountinfo_line(line) {
            Ok(mount_id) if seen.insert(mount_id) => {
                builder.push_record(format!("mount/{mount_id:020}"), line)
            }
            Ok(mount_id) => builder.issue(
                &format!("mount/{mount_id}"),
                CaptureIssueKind::Parse,
                None,
                "duplicate mount ID in mountinfo",
            ),
            Err(error) => builder.issue_error("mountinfo", CaptureIssueKind::Parse, &error),
        }
    }
}

fn capture_network(scope: &NetworkScope, retained: Option<&RetainedNamespace>) -> DomainSnapshot {
    let mut builder = DomainBuilder::new(DomainKind::Network, scope.evidence, &scope.limits);
    let observed_before = match retained {
        Some(namespace)
            if namespace.kind() == LinuxNamespaceKind::Network
                && namespace.inode() == scope.namespace.expected_namespace_inode =>
        {
            match namespace.verify() {
                Ok(()) => namespace.inode(),
                Err(error) => {
                    return builder.finish_with_error(
                        "network_namespace",
                        CaptureIssueKind::IdentityMismatch,
                        error,
                    )
                }
            }
        }
        Some(_) => {
            return builder.finish_with_error(
                "network_namespace",
                CaptureIssueKind::IdentityMismatch,
                anyhow::anyhow!("retained network namespace does not match the bound scope"),
            )
        }
        None => match checked_namespace(&scope.namespace, "net") {
            Ok(value) => value,
            Err(error) => {
                return builder.finish_with_error(
                    "network_namespace",
                    CaptureIssueKind::IdentityMismatch,
                    error,
                )
            }
        },
    };
    builder.namespace_inode = Some(observed_before);
    builder.namespace_context = vec![match retained {
        Some(namespace) => namespace.evidence(),
        None => NamespaceCaptureEvidence {
            kind: LinuxNamespaceKind::Network,
            inode: observed_before,
            source: target_capture_source(&scope.namespace),
        },
    }];
    let mut tool_identities = BTreeSet::new();
    let collection_context = NetworkCollectionContext {
        namespace: &scope.namespace,
        retained,
        normalization: scope.normalization,
    };

    if scope.collectors.addresses {
        collect_network_json(
            &mut builder,
            "ip/address",
            &scope.ip_binary(),
            &scope.expected_ip_sha256,
            &["-json", "-details", "address", "show"],
            collection_context,
            &mut tool_identities,
        );
    }
    if scope.collectors.routes {
        collect_network_json(
            &mut builder,
            "ip/route/ipv4",
            &scope.ip_binary(),
            &scope.expected_ip_sha256,
            &["-json", "-details", "-4", "route", "show", "table", "all"],
            collection_context,
            &mut tool_identities,
        );
        collect_network_json(
            &mut builder,
            "ip/route/ipv6",
            &scope.ip_binary(),
            &scope.expected_ip_sha256,
            &["-json", "-details", "-6", "route", "show", "table", "all"],
            collection_context,
            &mut tool_identities,
        );
    }
    if scope.collectors.rules {
        collect_network_json(
            &mut builder,
            "ip/rule/ipv4",
            &scope.ip_binary(),
            &scope.expected_ip_sha256,
            &["-json", "-details", "-4", "rule", "show"],
            collection_context,
            &mut tool_identities,
        );
        collect_network_json(
            &mut builder,
            "ip/rule/ipv6",
            &scope.ip_binary(),
            &scope.expected_ip_sha256,
            &["-json", "-details", "-6", "rule", "show"],
            collection_context,
            &mut tool_identities,
        );
    }
    if scope.collectors.traffic_control {
        collect_network_json(
            &mut builder,
            "tc/qdisc",
            &scope.tc_binary(),
            &scope.expected_tc_sha256,
            &["-json", "-details", "qdisc", "show"],
            collection_context,
            &mut tool_identities,
        );
        for interface in &scope.tc_interfaces {
            let class_args = [
                "-json",
                "-details",
                "class",
                "show",
                "dev",
                interface.as_str(),
            ];
            collect_network_json(
                &mut builder,
                &format!("tc/class/{interface}"),
                &scope.tc_binary(),
                &scope.expected_tc_sha256,
                &class_args,
                collection_context,
                &mut tool_identities,
            );
            for direction in ["ingress", "egress"] {
                let filter_args = [
                    "-json",
                    "-details",
                    "filter",
                    "show",
                    "dev",
                    interface.as_str(),
                    direction,
                ];
                collect_network_json(
                    &mut builder,
                    &format!("tc/filter/{interface}/{direction}"),
                    &scope.tc_binary(),
                    &scope.expected_tc_sha256,
                    &filter_args,
                    collection_context,
                    &mut tool_identities,
                );
            }
        }
    }
    if scope.collectors.nftables {
        collect_network_json(
            &mut builder,
            "nft/ruleset",
            &scope.nft_binary(),
            &scope.expected_nft_sha256,
            &["--json", "list", "ruleset"],
            collection_context,
            &mut tool_identities,
        );
    }
    if !tool_identities.is_empty() {
        tool_identities.insert(format!(
            "normalization:{}",
            scope.normalization.protocol_name()
        ));
        let joined = tool_identities.into_iter().collect::<Vec<_>>().join("\n");
        builder.source_identity_sha256 = Some(hex::encode(Sha256::digest(joined.as_bytes())));
    }
    let checked_after = match retained {
        Some(namespace) => namespace.verify().map(|()| namespace.inode()),
        None => checked_namespace(&scope.namespace, "net"),
    };
    match checked_after {
        Ok(after) if after == observed_before => {}
        Ok(_) => builder.issue(
            "network_namespace",
            CaptureIssueKind::Race,
            None,
            "network namespace identity changed during capture",
        ),
        Err(error) => builder.issue_error("network_namespace", CaptureIssueKind::Race, &error),
    }
    builder.finish()
}

#[derive(Clone, Copy)]
struct NetworkCollectionContext<'a> {
    namespace: &'a NamespaceTarget,
    retained: Option<&'a RetainedNamespace>,
    normalization: NetworkNormalization,
}

fn collect_network_json(
    builder: &mut DomainBuilder<'_>,
    key: &str,
    binary: &Result<PathBuf>,
    expected_sha256: &str,
    args: &[&str],
    context: NetworkCollectionContext<'_>,
    tool_identities: &mut BTreeSet<String>,
) {
    if builder.expired() {
        return;
    }
    let binary = match binary {
        Ok(value) => value,
        Err(error) => {
            builder.issue_error(key, CaptureIssueKind::Parse, error);
            return;
        }
    };
    let output = match run_json_command(
        binary,
        expected_sha256,
        args,
        context.namespace,
        context.retained,
        builder.limits.max_value_bytes,
        builder.deadline,
    ) {
        Ok(value) => value,
        Err(error) => {
            let kind = if error.to_string().contains("SHA-256")
                || error.to_string().contains("collector")
            {
                CaptureIssueKind::ToolIdentity
            } else {
                CaptureIssueKind::CommandFailure
            };
            builder.issue_error(key, kind, &error);
            return;
        }
    };
    tool_identities.insert(format!(
        "{}:{}:{}",
        binary.display(),
        output.tool_sha256,
        output.tool_object_identity_sha256
    ));
    if output.tool_changed_during_run {
        builder.issue(
            key,
            CaptureIssueKind::ToolIdentity,
            None,
            "collector object changed during execution",
        );
        return;
    }
    if output.timed_out {
        builder.issue(
            key,
            CaptureIssueKind::Deadline,
            None,
            "collector exceeded capture deadline",
        );
        return;
    }
    if output.output_exceeded || output.stderr_exceeded {
        builder.issue(
            key,
            CaptureIssueKind::Limit,
            None,
            "collector output exceeded a configured bound",
        );
        return;
    }
    if output.exit_code != Some(0) {
        builder.issue(
            key,
            CaptureIssueKind::CommandFailure,
            None,
            &format!(
                "collector exit {:?}: {}",
                output.exit_code,
                bounded_lossy(&output.stderr)
            ),
        );
        return;
    }
    match canonical_json(&output.stdout, key, context.normalization) {
        Ok(value) => builder.push_record(key.to_owned(), &value),
        Err(error) => builder.issue_error(key, CaptureIssueKind::Parse, &error),
    }
}

fn capture_modules(scope: &ModuleScope) -> DomainSnapshot {
    let mut builder = DomainBuilder::new(DomainKind::KernelModule, scope.evidence, &scope.limits);
    let proc_path = match scope.proc_modules_path() {
        Ok(value) => value,
        Err(error) => {
            return builder.finish_with_error("proc_modules", CaptureIssueKind::Parse, error)
        }
    };
    let sys_root = match scope.sys_module_root() {
        Ok(value) => value,
        Err(error) => {
            return builder.finish_with_error("sys_module", CaptureIssueKind::Parse, error)
        }
    };
    if let Err(error) = require_magic(&proc_path, PROC_SUPER_MAGIC) {
        return builder.finish_with_error("proc_modules", classify_io_error(&error), error);
    }
    if let Err(error) = require_magic(&sys_root, SYSFS_MAGIC) {
        return builder.finish_with_error("sys_module", classify_io_error(&error), error);
    }
    let proc_observation = match read_bounded_anchored(
        &proc_path,
        scope.limits.max_total_value_bytes,
        Some(PROC_SUPER_MAGIC),
    ) {
        Ok(value) => value,
        Err(error) => {
            return builder.finish_with_error("proc_modules", classify_io_error(&error), error)
        }
    };
    if !proc_observation.stable {
        builder.issue(
            "proc_modules",
            CaptureIssueKind::Race,
            None,
            "/proc/modules changed during capture",
        );
    }
    let mut loaded = BTreeMap::<String, Vec<u8>>::new();
    for line in proc_observation
        .bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        match parse_module_line(line) {
            Ok(name) if loaded.insert(name.clone(), line.to_vec()).is_none() => {}
            Ok(name) => builder.issue(
                &format!("module/{name}"),
                CaptureIssueKind::Parse,
                None,
                "duplicate module record",
            ),
            Err(error) => builder.issue_error("proc_modules", CaptureIssueKind::Parse, &error),
        }
    }
    let selected: Vec<String> = match &scope.selection {
        ModuleSelection::AllLoaded => loaded.keys().cloned().collect(),
        ModuleSelection::Explicit(names) => names.clone(),
    };
    for name in selected {
        if builder.expired() {
            break;
        }
        let Some(line) = loaded.get(&name) else { continue };
        builder.push_record(format!("module/{name}"), line);
        if scope.capture_parameters {
            capture_module_parameters(&mut builder, &sys_root, &name);
        }
    }
    let source = format!(
        "proc:{}:{}\nsys:{}:{}",
        proc_observation.metadata.dev,
        proc_observation.metadata.ino,
        fs::metadata(&sys_root).map(|m| m.dev()).unwrap_or(0),
        fs::metadata(&sys_root).map(|m| m.ino()).unwrap_or(0),
    );
    builder.source_identity_sha256 = Some(hex::encode(Sha256::digest(source.as_bytes())));
    builder.finish()
}

fn capture_module_parameters(builder: &mut DomainBuilder<'_>, sys_root: &Path, module: &str) {
    let root = sys_root.join(module).join("parameters");
    let entries = match fs::read_dir(root) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(error) => {
            builder.issue_error(
                &format!("module/{module}/parameters"),
                classify_io_error(&error),
                &error,
            );
            return;
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(value) => paths.push(value.path()),
            Err(error) => builder.issue_error(
                &format!("module/{module}/parameters"),
                classify_io_error(&error),
                &error,
            ),
        }
    }
    paths.sort_by(|left, right| {
        left.as_os_str()
            .as_bytes()
            .cmp(right.as_os_str().as_bytes())
    });
    for path in paths {
        if builder.expired() {
            break;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            builder.issue(&format!("module/{module}/parameters"), CaptureIssueKind::Parse, None, "non-UTF-8 module parameter name");
            continue;
        };
        match read_bounded_anchored(&path, builder.limits.max_value_bytes, Some(SYSFS_MAGIC)) {
            Ok(value) if value.stable => {
                builder.push_record(format!("module/{module}/parameter/{name}"), &value.bytes)
            }
            Ok(_) => builder.issue(
                &format!("module/{module}/parameter/{name}"),
                CaptureIssueKind::Race,
                None,
                "module parameter changed during capture",
            ),
            Err(error) => builder.issue_error(
                &format!("module/{module}/parameter/{name}"),
                classify_io_error(&error),
                &error,
            ),
        }
    }
}

fn capture_process_residual(scope: &ProcessResidualScope) -> DomainSnapshot {
    let mut builder =
        DomainBuilder::new(DomainKind::ProcessResidual, scope.evidence, &scope.limits);
    let roots = match scope.roots() {
        Ok(value) => value,
        Err(error) => return builder.finish_with_error("cgroup", CaptureIssueKind::Parse, error),
    };
    let multiple_roots = roots.len() > 1;
    let mut verified = Vec::with_capacity(roots.len());
    for (index, (root, expected_cgroup_id)) in roots.into_iter().enumerate() {
        let key = residual_root_key(multiple_roots, index, "cgroup");
        let metadata = match fs::symlink_metadata(&root) {
            Ok(value) => value,
            Err(error) => {
                return builder.finish_with_error(&key, classify_io_error(&error), error.into())
            }
        };
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return builder.finish_with_error(
                &key,
                CaptureIssueKind::IdentityMismatch,
                anyhow::anyhow!("tracked cgroup path is not an anchored directory"),
            );
        }
        if metadata.ino() != expected_cgroup_id {
            return builder.finish_with_error(
                &key,
                CaptureIssueKind::IdentityMismatch,
                anyhow::anyhow!(
                    "tracked cgroup ID {} != expected {expected_cgroup_id}",
                    metadata.ino()
                ),
            );
        }
        if scope.require_cgroup2 {
            if let Err(error) = require_magic(&root, CGROUP2_SUPER_MAGIC) {
                return builder.finish_with_error(&key, CaptureIssueKind::Unsupported, error);
            }
        } else {
            builder.issue(
                &key,
                CaptureIssueKind::Unsupported,
                None,
                "test-only scope disabled cgroup v2 filesystem enforcement",
            );
        }
        verified.push(VerifiedResidualRoot {
            index,
            path: root,
            expected_cgroup_id,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    builder.source_identity_sha256 = Some(residual_source_identity(&verified));

    let mut first_budget = ResidualScanBudget::default();
    let mut first = Vec::with_capacity(verified.len());
    for root in &verified {
        let key = residual_root_key(multiple_roots, root.index, "membership");
        let membership =
            match scan_cgroup_membership(&root.path, scope, builder.deadline, &mut first_budget) {
                Ok(value) => value,
                Err(error) => {
                    return builder.finish_with_error(&key, classify_io_error(&error), error)
                }
            };
        first.push(membership);
    }
    for (root, membership_by_cgroup) in verified.iter().zip(&first) {
        for (relative, membership) in membership_by_cgroup {
            for task_id in &membership.task_ids {
                if builder.expired() {
                    break;
                }
                let key = residual_membership_key(
                    multiple_roots,
                    root,
                    membership.kind,
                    relative,
                    *task_id,
                );
                match task_start_time(*task_id) {
                    Ok(start_time) => {
                        let value = format!(
                            "membership_kind={}\ntask_id={task_id}\nstart_time_ticks={start_time}\n",
                            membership.kind.as_str()
                        );
                        builder.push_record(key, value.as_bytes());
                    }
                    Err(error) => builder.issue_error(&key, CaptureIssueKind::Race, &error),
                }
            }
        }
    }

    let mut second_budget = ResidualScanBudget::default();
    for (root, expected) in verified.iter().zip(&first) {
        let key = residual_root_key(multiple_roots, root.index, "membership");
        match scan_cgroup_membership(&root.path, scope, builder.deadline, &mut second_budget) {
            Ok(observed) if &observed == expected => {}
            Ok(_) => builder.issue(
                &key,
                CaptureIssueKind::Race,
                None,
                "tracked cgroup membership or directory identity changed during capture",
            ),
            Err(error) => builder.issue_error(&key, CaptureIssueKind::Race, &error),
        }
    }
    for root in &verified {
        let key = residual_root_key(multiple_roots, root.index, "cgroup");
        match fs::symlink_metadata(&root.path) {
            Ok(after) if after.dev() == root.device && after.ino() == root.inode => {}
            Ok(_) => builder.issue(
                &key,
                CaptureIssueKind::Race,
                None,
                "tracked cgroup identity changed during capture",
            ),
            Err(error) => builder.issue_error(&key, CaptureIssueKind::Race, &error),
        }
    }
    builder.finish()
}

struct VerifiedResidualRoot {
    index: usize,
    path: PathBuf,
    expected_cgroup_id: u64,
    device: u64,
    inode: u64,
}

fn residual_root_key(multiple_roots: bool, index: usize, suffix: &str) -> String {
    if multiple_roots {
        format!("root/{index:02}/{suffix}")
    } else {
        suffix.to_owned()
    }
}

fn residual_membership_key(
    multiple_roots: bool,
    root: &VerifiedResidualRoot,
    kind: MembershipKind,
    relative: &str,
    task_id: u32,
) -> String {
    if multiple_roots {
        format!(
            "root/{:02}/{:020}/{}/{relative}/{task_id:010}",
            root.index,
            root.expected_cgroup_id,
            kind.record_prefix()
        )
    } else {
        format!("{}/{relative}/{task_id:010}", kind.record_prefix())
    }
}

fn residual_source_identity(roots: &[VerifiedResidualRoot]) -> String {
    if roots.len() == 1 {
        return hex::encode(Sha256::digest(
            format!("{}:{}", roots[0].device, roots[0].inode).as_bytes(),
        ));
    }
    let mut digest = Sha256::new();
    digest.update(b"PROCESS_RESIDUAL_MULTI_ROOT_SOURCE_V1\0");
    for root in roots {
        let path = root.path.as_os_str().as_bytes();
        digest.update((path.len() as u64).to_le_bytes());
        digest.update(path);
        digest.update(root.expected_cgroup_id.to_le_bytes());
        digest.update(root.device.to_le_bytes());
        digest.update(root.inode.to_le_bytes());
    }
    hex::encode(digest.finalize())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Membership {
    device: u64,
    inode: u64,
    kind: MembershipKind,
    task_ids: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MembershipKind {
    Process,
    Thread,
}

impl MembershipKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Process => "PROCESS",
            Self::Thread => "THREAD",
        }
    }

    fn record_prefix(self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::Thread => "thread",
        }
    }
}

fn scan_cgroup_membership(
    root: &Path,
    scope: &ProcessResidualScope,
    deadline: Instant,
    budget: &mut ResidualScanBudget,
) -> Result<BTreeMap<String, Membership>> {
    let root_metadata = fs::symlink_metadata(root).context("inspect tracked cgroup root")?;
    let root_device = root_metadata.dev();
    budget.add_directory(&scope.limits)?;
    let mut pending = VecDeque::from([(root.to_owned(), Vec::<u8>::new(), 0_u32)]);
    let mut result = BTreeMap::new();
    while let Some((path, relative, depth)) = pending.pop_front() {
        if Instant::now() >= deadline {
            bail!("cgroup membership capture deadline exceeded");
        }
        if depth > HARD_MAX_CGROUP_DEPTH || relative.len() > HARD_MAX_PATH_BYTES {
            bail!("cgroup tree exceeded the hard depth or relative-path bound");
        }
        let before = fs::symlink_metadata(&path).context("inspect cgroup directory")?;
        if !before.file_type().is_dir()
            || before.file_type().is_symlink()
            || before.dev() != root_device
        {
            bail!("cgroup tree contains a non-directory, symlink, or cross-device entry");
        }
        let cgroup_type = read_cgroup_type(&path)?;
        let (membership_kind, membership_file, descend) = match cgroup_type.as_deref() {
            Some("threaded") => (MembershipKind::Thread, "cgroup.threads", true),
            Some("domain threaded") => (MembershipKind::Process, "cgroup.procs", false),
            Some("domain") | None => (MembershipKind::Process, "cgroup.procs", true),
            Some("domain invalid") => {
                bail!("cgroup tree contains an invalid threaded-domain topology")
            }
            Some(other) => bail!("cgroup tree contains unknown cgroup.type {other:?}"),
        };
        let bytes = read_bounded_anchored(
            &path.join(membership_file),
            scope.limits.max_value_bytes,
            None,
        )?
        .bytes;
        budget.add_membership_bytes(bytes.len() as u64, &scope.limits)?;
        let task_ids = parse_cgroup_members(&bytes, membership_file)?;
        budget.add_tasks(task_ids.len() as u64, &scope.limits)?;
        let key = hex::encode(&relative);
        result.insert(
            key,
            Membership {
                device: before.dev(),
                inode: before.ino(),
                kind: membership_kind,
                task_ids,
            },
        );
        if scope.recursive && descend {
            let mut children = Vec::new();
            for entry in fs::read_dir(&path).context("enumerate cgroup descendants")? {
                let entry = entry.context("read cgroup descendant")?;
                let metadata = entry
                    .file_type()
                    .context("inspect cgroup descendant type")?;
                if metadata.is_dir() {
                    let name = entry.file_name();
                    let name_bytes = name.as_bytes();
                    if name_bytes.contains(&b'/') || name_bytes.contains(&0) {
                        bail!("invalid cgroup directory name");
                    }
                    let mut child_relative = relative.clone();
                    if !child_relative.is_empty() {
                        child_relative.push(b'/');
                    }
                    child_relative.extend_from_slice(name_bytes);
                    budget.add_directory(&scope.limits)?;
                    children.push((entry.path(), child_relative, depth.saturating_add(1)));
                }
            }
            children.sort_by(|left, right| left.1.cmp(&right.1));
            pending.extend(children);
        }
        let after = fs::symlink_metadata(&path).context("reinspect cgroup directory")?;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("cgroup directory identity changed during scan");
        }
    }
    Ok(result)
}

#[derive(Default)]
struct ResidualScanBudget {
    record_units: u64,
    membership_bytes: u64,
}

impl ResidualScanBudget {
    fn add_directory(&mut self, limits: &CaptureLimits) -> Result<()> {
        self.add_record_units(1, limits, "cgroup directory count")
    }

    fn add_tasks(&mut self, count: u64, limits: &CaptureLimits) -> Result<()> {
        self.add_record_units(count, limits, "cgroup task count")
    }

    fn add_record_units(&mut self, count: u64, limits: &CaptureLimits, label: &str) -> Result<()> {
        self.record_units = self
            .record_units
            .checked_add(count)
            .context("cgroup scan record-unit counter overflow")?;
        if self.record_units > limits.max_records {
            bail!("{label} exceeded aggregate max_records");
        }
        Ok(())
    }

    fn add_membership_bytes(&mut self, count: u64, limits: &CaptureLimits) -> Result<()> {
        self.membership_bytes = self
            .membership_bytes
            .checked_add(count)
            .context("cgroup membership byte count overflow")?;
        if self.membership_bytes > limits.max_total_value_bytes {
            bail!("cgroup membership input exceeded aggregate max_total_value_bytes");
        }
        Ok(())
    }
}

fn read_cgroup_type(path: &Path) -> Result<Option<String>> {
    let type_path = path.join("cgroup.type");
    if !type_path.exists() {
        // Unit-test fixtures predating threaded-cgroup support omit this
        // kernel-generated file. A real cgroup-v2 directory always exposes it.
        return Ok(None);
    }
    let bytes = read_bounded_anchored(&type_path, 64, None)?.bytes;
    let value = std::str::from_utf8(&bytes)
        .context("cgroup.type is not UTF-8")?
        .trim();
    if value.is_empty() {
        bail!("cgroup.type is empty");
    }
    Ok(Some(value.to_owned()))
}

fn parse_cgroup_members(bytes: &[u8], source: &str) -> Result<Vec<u32>> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("{source} is not UTF-8"))?;
    let mut task_ids = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let task_id: u32 = line
            .parse()
            .with_context(|| format!("parse task ID from {source}"))?;
        if task_id == 0 {
            bail!("{source} contains task ID zero");
        }
        task_ids.push(task_id);
    }
    task_ids.sort_unstable();
    task_ids.dedup();
    Ok(task_ids)
}

fn task_start_time(task_id: u32) -> Result<u64> {
    let path = PathBuf::from(format!("/proc/{task_id}/stat"));
    let value = read_bounded_anchored(&path, 64 * 1024, Some(PROC_SUPER_MAGIC))?.bytes;
    let close = value
        .iter()
        .rposition(|byte| *byte == b')')
        .context("process stat missing comm terminator")?;
    let rest = std::str::from_utf8(
        value
            .get(close + 2..)
            .context("process stat is truncated")?,
    )?;
    rest.split_whitespace()
        .nth(19)
        .context("process stat missing starttime")?
        .parse()
        .context("parse process starttime")
}

struct DomainBuilder<'a> {
    domain: DomainKind,
    mode: ValueEvidenceMode,
    limits: &'a CaptureLimits,
    deadline: Instant,
    total_value_bytes: u64,
    namespace_inode: Option<u64>,
    namespace_context: Vec<NamespaceCaptureEvidence>,
    source_identity_sha256: Option<String>,
    records: Vec<StateRecord>,
    issues: Vec<CaptureIssue>,
}

impl<'a> DomainBuilder<'a> {
    fn new(domain: DomainKind, mode: ValueEvidenceMode, limits: &'a CaptureLimits) -> Self {
        let deadline = Instant::now()
            .checked_add(Duration::from_millis(limits.deadline_ms))
            .unwrap_or_else(Instant::now);
        Self {
            domain,
            mode,
            limits,
            deadline,
            total_value_bytes: 0,
            namespace_inode: None,
            namespace_context: Vec::new(),
            source_identity_sha256: None,
            records: Vec::new(),
            issues: Vec::new(),
        }
    }

    fn expired(&mut self) -> bool {
        if Instant::now() < self.deadline {
            return false;
        }
        if !self
            .issues
            .iter()
            .any(|issue| issue.kind == CaptureIssueKind::Deadline)
        {
            self.issue(
                "deadline",
                CaptureIssueKind::Deadline,
                None,
                "domain capture deadline exceeded",
            );
        }
        true
    }

    fn push_record(&mut self, key: String, value: &[u8]) {
        if self.expired() {
            return;
        }
        if self.records.len() as u64 >= self.limits.max_records {
            self.issue(
                &key,
                CaptureIssueKind::Limit,
                None,
                "domain record count exceeded max_records",
            );
            return;
        }
        if value.len() as u64 > self.limits.max_value_bytes {
            self.issue(
                &key,
                CaptureIssueKind::Limit,
                None,
                "record value exceeded max_value_bytes",
            );
            return;
        }
        let Some(total) = self.total_value_bytes.checked_add(value.len() as u64) else {
            self.issue(&key, CaptureIssueKind::Limit, None, "domain value byte counter overflowed");
            return;
        };
        if total > self.limits.max_total_value_bytes {
            self.issue(
                &key,
                CaptureIssueKind::Limit,
                None,
                "domain values exceeded max_total_value_bytes",
            );
            return;
        }
        match StateRecord::new(key.clone(), value, self.mode) {
            Ok(record) => {
                self.records.push(record);
                self.total_value_bytes = total;
            }
            Err(error) => self.issue_error(&key, CaptureIssueKind::Parse, &error),
        }
    }

    fn issue(&mut self, key: &str, kind: CaptureIssueKind, errno: Option<i32>, detail: &str) {
        if self.issues.len() >= HARD_MAX_ISSUES_PER_DOMAIN {
            return;
        }
        self.issues.push(CaptureIssue {
            key: key.chars().take(HARD_MAX_ISSUE_KEY_CHARS).collect(),
            kind,
            errno,
            detail: detail.chars().take(HARD_MAX_ISSUE_DETAIL_CHARS).collect(),
        });
    }

    fn issue_error(&mut self, key: &str, kind: CaptureIssueKind, error: &dyn std::fmt::Display) {
        self.issue(key, kind, None, &error.to_string());
    }

    fn finish_with_error(
        mut self,
        key: &str,
        kind: CaptureIssueKind,
        error: anyhow::Error,
    ) -> DomainSnapshot {
        self.issue_error(key, kind, &error);
        self.finish()
    }

    fn finish(mut self) -> DomainSnapshot {
        self.records.sort_by(|left, right| left.key.cmp(&right.key));
        for pair in self.records.windows(2) {
            if pair[0].key == pair[1].key {
                self.issues.push(CaptureIssue {
                    key: pair[0].key.clone(),
                    kind: CaptureIssueKind::Parse,
                    errno: None,
                    detail: "duplicate canonical state record key".to_owned(),
                });
                break;
            }
        }
        let mut domain = DomainSnapshot {
            domain: self.domain,
            namespace_inode: self.namespace_inode,
            namespace_context: self.namespace_context,
            source_identity_sha256: self.source_identity_sha256,
            records: self.records,
            completeness: Completeness {
                status: CompletenessStatus::Complete,
                reasons: Vec::new(),
            },
            issues: self.issues,
        };
        finalize_completeness(&mut domain);
        domain
    }
}

fn finalize_completeness(domain: &mut DomainSnapshot) {
    domain.issues.sort_by(|left, right| {
        (&left.key, left.kind as u8, left.errno, &left.detail).cmp(&(
            &right.key,
            right.kind as u8,
            right.errno,
            &right.detail,
        ))
    });
    domain.issues.dedup();
    let mut reasons = domain
        .issues
        .iter()
        .map(|issue| format!("{}: {:?}", issue.key, issue.kind))
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    domain.completeness = Completeness {
        status: if reasons.is_empty() {
            CompletenessStatus::Complete
        } else {
            CompletenessStatus::Incomplete
        },
        reasons,
    };
}

#[derive(Clone)]
struct ReadMetadata {
    dev: u64,
    ino: u64,
}
struct ReadObservation {
    bytes: Vec<u8>,
    stable: bool,
    metadata: ReadMetadata,
}

fn read_bounded_anchored(
    path: &Path,
    maximum: u64,
    expected_magic: Option<i64>,
) -> Result<ReadObservation> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if let Some(magic) = expected_magic {
        require_fd_magic(&file, magic)?;
    }
    let before = file.metadata().context("fstat capture source")?;
    if !(before.is_file() || before.file_type().is_char_device()) {
        bail!("capture source is not a regular or proc/sysfs pseudo-file");
    }
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).context("read capture source")?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > maximum {
            bail!("capture source exceeded configured byte bound");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    let after = file.metadata().context("re-fstat capture source")?;
    let stable = metadata_identity(&before) == metadata_identity(&after);
    Ok(ReadObservation {
        bytes,
        stable,
        metadata: ReadMetadata {
            dev: before.dev(),
            ino: before.ino(),
        },
    })
}

fn metadata_identity(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn strict_proc_sys_root(root: &Path) -> Result<String> {
    let canonical = fs::canonicalize(root).context("canonicalize proc sys root")?;
    if canonical != root {
        bail!("proc sys root must be canonical and must not traverse a symlink");
    }
    if root.file_name().and_then(|v| v.to_str()) != Some("sys")
        || root
            .parent()
            .and_then(Path::file_name)
            .and_then(|v| v.to_str())
            != Some("proc")
    {
        bail!("sysctl root must identify an anchored proc/sys directory");
    }
    require_magic(root, PROC_SUPER_MAGIC)?;
    let metadata = fs::metadata(root).context("inspect proc sys root")?;
    Ok(hex::encode(Sha256::digest(
        format!("{}:{}", metadata.dev(), metadata.ino()).as_bytes(),
    )))
}

fn require_magic(path: &Path, expected: i64) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let path = CString::new(bytes).context("filesystem path contains NUL")?;
    let mut state = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::statfs(path.as_ptr(), &mut state) } != 0 {
        return Err(io::Error::last_os_error()).context("statfs capture source");
    }
    if state.f_type != expected {
        bail!(
            "filesystem magic {:#x} != required {expected:#x}",
            state.f_type
        );
    }
    Ok(())
}

fn require_fd_magic(file: &File, expected: i64) -> Result<()> {
    let mut state = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut state) } != 0 {
        return Err(io::Error::last_os_error()).context("fstatfs capture source");
    }
    if state.f_type != expected {
        bail!(
            "anchored filesystem magic {:#x} != required {expected:#x}",
            state.f_type
        );
    }
    Ok(())
}

fn checked_namespace(target: &NamespaceTarget, namespace: &str) -> Result<u64> {
    let observed = namespace_inode(target.pid, namespace)?;
    if observed != target.expected_namespace_inode {
        bail!(
            "{namespace} namespace inode {observed} != expected {}",
            target.expected_namespace_inode
        );
    }
    Ok(observed)
}

fn target_capture_source(target: &NamespaceTarget) -> NamespaceCaptureSource {
    if target.pid == 0 {
        NamespaceCaptureSource::CurrentProcess
    } else {
        NamespaceCaptureSource::LivePid
    }
}

fn current_sysctl_namespace_context() -> Result<Vec<NamespaceCaptureEvidence>> {
    let mut context = Vec::with_capacity(3);
    for kind in [
        LinuxNamespaceKind::Ipc,
        LinuxNamespaceKind::Network,
        LinuxNamespaceKind::Uts,
    ] {
        context.push(NamespaceCaptureEvidence {
            kind,
            inode: namespace_inode(0, kind.proc_name())?,
            source: NamespaceCaptureSource::CurrentProcess,
        });
    }
    Ok(context)
}

pub(crate) fn validate_mountinfo_line(line: &[u8]) -> Result<u64> {
    let text = std::str::from_utf8(line).context("mountinfo line is not UTF-8")?;
    let (left, right) = text
        .split_once(" - ")
        .context("mountinfo line lacks separator")?;
    let left_fields = left.split_whitespace().collect::<Vec<_>>();
    if left_fields.len() < 6 || right.split_whitespace().count() < 3 {
        bail!("mountinfo line has too few fields");
    }
    let mount_id: u64 = left_fields[0].parse().context("parse mount ID")?;
    let _: u64 = left_fields[1].parse().context("parse parent mount ID")?;
    if mount_id == 0 {
        bail!("mountinfo contains mount ID zero");
    }
    Ok(mount_id)
}

fn parse_module_line(line: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(line).context("module line is not UTF-8")?;
    let fields = text.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 6 {
        bail!("module line has too few fields");
    }
    let name = fields[0];
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    {
        bail!("module line contains invalid name");
    }
    let _: u64 = fields[1].parse().context("parse module size")?;
    let _: u64 = fields[2].parse().context("parse module refcount")?;
    Ok(name.to_owned())
}

fn classify_io_error(error: &dyn std::fmt::Display) -> CaptureIssueKind {
    let value = error.to_string();
    if value.contains("Permission denied") {
        CaptureIssueKind::Permission
    } else if value.contains("No such file") {
        CaptureIssueKind::Missing
    } else if value.contains("exceeded") {
        CaptureIssueKind::Limit
    } else {
        CaptureIssueKind::Io
    }
}

fn bounded_lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).chars().take(256).collect()
}

fn read_boot_id() -> Result<String> {
    let value = fs::read_to_string("/proc/sys/kernel/random/boot_id").context("read boot ID")?;
    let value = value.trim().to_owned();
    if value.is_empty() || value.len() > 128 {
        bail!("kernel returned invalid boot ID");
    }
    Ok(value)
}

fn enabled_domains_mut(snapshot: &mut StateSnapshot) -> Vec<&mut DomainSnapshot> {
    let mut domains = Vec::new();
    if let Some(value) = snapshot.sysctl.as_mut() {
        domains.push(value);
    }
    if let Some(value) = snapshot.mounts.as_mut() {
        domains.push(value);
    }
    if let Some(value) = snapshot.network.as_mut() {
        domains.push(value);
    }
    if let Some(value) = snapshot.modules.as_mut() {
        domains.push(value);
    }
    if let Some(value) = snapshot.process_residual.as_mut() {
        domains.push(value);
    }
    domains
}

fn validate_snapshot_shape(snapshot: &StateSnapshot) -> Result<()> {
    let bytes = serde_json::to_vec(snapshot).context("serialize Linux state snapshot")?;
    if bytes.len() as u64 > HARD_MAX_SNAPSHOT_JSON_BYTES {
        bail!("Linux state snapshot exceeds artifact size bound");
    }
    Ok(())
}
