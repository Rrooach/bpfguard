// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::*;
use anyhow::{anyhow, bail, Context, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const SYSFS_MAGIC: libc::c_long = 0x6265_6572;
const MAX_PROC_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TUN_FDINFO_BYTES: u64 = 64 * 1024;
const TUN_DEVICE_MAJOR: u32 = 10;
const TUN_DEVICE_MINOR: u32 = 200;

#[derive(Clone, Debug)]
pub(crate) struct DiscoveryRoots {
    pub procfs: PathBuf,
    pub cgroupfs: PathBuf,
    pub sysfs: PathBuf,
    pub source_trust: DiscoverySourceTrust,
}

impl DiscoveryRoots {
    pub(crate) fn live() -> Self {
        Self {
            procfs: PathBuf::from("/proc"),
            cgroupfs: PathBuf::from("/sys/fs/cgroup"),
            sysfs: PathBuf::from("/sys"),
            source_trust: DiscoverySourceTrust::KernelFilesystemsVerified,
        }
    }
}

pub(crate) struct CapturedProcess {
    pub(crate) identity: ProcessIdentity,
    pub(crate) cmdline: Vec<u8>,
    pub(crate) executable: PathBuf,
}

pub fn discover(request: &DeploymentRequest) -> Result<DeploymentManifest> {
    request.validate()?;
    let roots = DiscoveryRoots::live();
    validate_live_roots(&roots, request.kind())?;
    discover_with_roots(request, &roots)
}

pub(crate) fn discover_with_roots(
    request: &DeploymentRequest,
    roots: &DiscoveryRoots,
) -> Result<DeploymentManifest> {
    request.validate()?;
    let boot_id = read_bounded(&roots.procfs.join("sys/kernel/random/boot_id"), 4096)
        .context("read target Linux boot ID")?;
    let boot_id = String::from_utf8(boot_id)
        .context("target Linux boot ID is not UTF-8")?
        .trim()
        .to_owned();
    if !is_canonical_uuid(&boot_id) {
        bail!("target Linux boot ID is empty or invalid");
    }

    let captured_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();

    let parts = match request {
        DeploymentRequest::Direct(configuration) => {
            discover_direct(configuration, roots).context("discover direct deployment")?
        }
        DeploymentRequest::Docker(configuration) => {
            discover_docker(configuration, roots).context("discover Docker deployment")?
        }
        DeploymentRequest::KataHost(configuration) => {
            discover_kata(configuration, roots).context("discover Kata host deployment")?
        }
    };

    let mut manifest = DeploymentManifest {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        domain: DEPLOYMENT_SCOPE_DOMAIN.to_owned(),
        deployment_kind: request.kind(),
        source_trust: roots.source_trust,
        identity_strength: if roots.source_trust == DiscoverySourceTrust::FixtureUntrusted {
            IdentityStrength::FixtureOnly
        } else if parts
            .resources
            .iter()
            .any(|resource| resource.resolution == ResourceResolutionStatus::Unresolved)
        {
            IdentityStrength::KernelAnchoredWithUnresolvedResources
        } else {
            IdentityStrength::KernelAnchored
        },
        subject_id: parts.subject_id,
        captured_unix_ns,
        boot_id,
        root_cgroups: parts.root_cgroups,
        observed_cgroups: parts.cgroups,
        processes: parts
            .processes
            .into_iter()
            .map(|process| process.identity)
            .collect(),
        mount_namespace_ids: Vec::new(),
        net_namespace_ids: Vec::new(),
        uts_namespace_ids: Vec::new(),
        ipc_namespace_ids: Vec::new(),
        kata_host_resources: parts.resources,
        coverage: parts.coverage,
        limitations: parts.limitations,
        scope_sha256: String::new(),
    };
    manifest.processes.sort_by_key(|process| process.pid);
    manifest.mount_namespace_ids = manifest
        .processes
        .iter()
        .map(|process| process.mount_namespace_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    manifest.net_namespace_ids = manifest
        .processes
        .iter()
        .map(|process| process.net_namespace_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    manifest.uts_namespace_ids = manifest
        .processes
        .iter()
        .map(|process| process.uts_namespace_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    manifest.ipc_namespace_ids = manifest
        .processes
        .iter()
        .map(|process| process.ipc_namespace_id)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    manifest
        .root_cgroups
        .sort_by(|left, right| left.path.cmp(&right.path));
    manifest
        .observed_cgroups
        .sort_by(|left, right| left.path.cmp(&right.path));
    manifest.kata_host_resources.sort_by(resource_order);
    manifest.limitations.sort();
    manifest.limitations.dedup();
    manifest.scope_sha256 = manifest.compute_scope_sha256()?;
    manifest.validate()?;
    Ok(manifest)
}

struct DiscoveryParts {
    subject_id: String,
    root_cgroups: Vec<CgroupIdentity>,
    cgroups: Vec<CgroupIdentity>,
    processes: Vec<CapturedProcess>,
    resources: Vec<KataHostResource>,
    coverage: DeploymentCoverage,
    limitations: Vec<String>,
}

fn discover_direct(request: &DirectRequest, roots: &DiscoveryRoots) -> Result<DiscoveryParts> {
    let anchor = read_process_base(request.root_pid, ProcessRole::DirectRoot, roots)?;
    validate_expected_cgroup(&anchor.identity.cgroup_path, &request.expected_cgroup_path)?;
    if request.require_dedicated_cgroup {
        validate_direct_leaf_seal(&anchor.identity.cgroup_path, roots)?;
    }
    let (root_cgroup, cgroups) =
        enumerate_cgroup_subtree(&anchor.identity.cgroup_path, &request.limits, roots)?;
    let pids = enumerate_cgroup_processes(&cgroups, &request.limits, roots)?;
    if !pids.contains(&request.root_pid) {
        bail!("direct root PID moved out of its cgroup during discovery");
    }
    let mut processes = Vec::with_capacity(pids.len());
    for pid in pids {
        let role = if pid == request.root_pid {
            ProcessRole::DirectRoot
        } else {
            ProcessRole::DirectMember
        };
        processes.push(read_process_bound(pid, role, &cgroups, roots)?);
    }
    Ok(DiscoveryParts {
        subject_id: format!("direct-pid-{}", request.root_pid),
        root_cgroups: vec![root_cgroup],
        cgroups,
        processes,
        resources: Vec::new(),
        coverage: common_coverage(if request.require_dedicated_cgroup {
            DescendantObservationRequirement::ExactLeaf
        } else {
            DescendantObservationRequirement::CgroupV2AncestorMatchRequired
        }),
        limitations: vec![
            "direct deployment identity establishes cgroup membership, not that every member is Agent-authored code"
                .to_owned(),
            "delegated effects executed by processes outside the selected cgroup subtree are not attributed"
                .to_owned(),
        ],
    })
}

fn discover_docker(request: &DockerRequest, roots: &DiscoveryRoots) -> Result<DiscoveryParts> {
    let init_pid = match request.init_pid {
        Some(pid) => pid,
        None => find_docker_init_pid(request, roots)?,
    };
    let anchor = read_process_base(init_pid, ProcessRole::DockerInit, roots)?;
    if !docker_cgroup_matches(&anchor.identity.cgroup_path, &request.container_id) {
        bail!("Docker init PID is not in a cgroup bound to the full container ID");
    }
    if anchor.identity.namespace_pid_chain.last().copied() != Some(1) {
        bail!("Docker init PID is not PID 1 in its innermost PID namespace");
    }
    validate_expected_cgroup(&anchor.identity.cgroup_path, &request.expected_cgroup_path)?;
    let (root_cgroup, cgroups) =
        enumerate_cgroup_subtree(&anchor.identity.cgroup_path, &request.limits, roots)?;
    let pids = enumerate_cgroup_processes(&cgroups, &request.limits, roots)?;
    if !pids.contains(&init_pid) {
        bail!("Docker init PID moved out of its cgroup during discovery");
    }
    let mut processes = Vec::with_capacity(pids.len());
    for pid in pids {
        let role = if pid == init_pid {
            ProcessRole::DockerInit
        } else {
            ProcessRole::DockerMember
        };
        processes.push(read_process_bound(pid, role, &cgroups, roots)?);
    }
    Ok(DiscoveryParts {
        subject_id: request.container_id.clone(),
        root_cgroups: vec![root_cgroup],
        cgroups,
        processes,
        resources: Vec::new(),
        coverage: common_coverage(
            DescendantObservationRequirement::CgroupV2AncestorMatchRequired,
        ),
        limitations: vec![
            "Docker discovery observes the target Linux container cgroup and current namespaces; it does not trust Docker labels or a mutable container name"
                .to_owned(),
            "dynamic descendants are covered by the registered cgroup-v2 ancestor root, but lifecycle evidence remains PARTIAL without an authoritative S0 task ledger or migration/CLONE_INTO_CGROUP enrollment"
                .to_owned(),
            "delegated effects executed by Docker/container runtime daemons outside the container cgroup are not attributed"
                .to_owned(),
            "root-cgroup replacement, overlap, or identity drift after READY invalidates closure even though ordinary descendant-cgroup churn remains in scope"
                .to_owned(),
        ],
    })
}

fn discover_kata(request: &KataHostRequest, roots: &DiscoveryRoots) -> Result<DiscoveryParts> {
    let anchor = read_process_base(request.shim_pid, ProcessRole::KataShim, roots)?;
    if !is_kata_shim(&anchor.executable, &anchor.cmdline) {
        bail!("Kata anchor PID executable is not a supported Kata shim/runtime");
    }
    if !bytes_contain(&anchor.cmdline, request.sandbox_id.as_bytes())
        && !anchor.identity.cgroup_path.contains(&request.sandbox_id)
    {
        bail!("Kata sandbox ID is not bound to the shim command line or cgroup path");
    }
    validate_expected_cgroup(&anchor.identity.cgroup_path, &request.expected_cgroup_path)?;
    let mut root_paths = vec![anchor.identity.cgroup_path];
    let mut explicit_processes = BTreeSet::new();
    explicit_processes.insert(request.shim_pid);
    if let Some(pid) = request.expected_hypervisor_pid {
        let process = read_process_base(pid, ProcessRole::KataHypervisor, roots)?;
        if classify_kata_role(pid, request.shim_pid, &process.executable, &process.cmdline)
            != ProcessRole::KataHypervisor
        {
            bail!("expected Kata hypervisor PID is not a supported QEMU process");
        }
        add_disjoint_or_descendant_root(&mut root_paths, &process.identity.cgroup_path)?;
        explicit_processes.insert(pid);
    }
    for pid in &request.additional_host_pids {
        let process = read_process_base(*pid, ProcessRole::KataAuxiliary, roots)?;
        add_disjoint_or_descendant_root(&mut root_paths, &process.identity.cgroup_path)?;
        explicit_processes.insert(*pid);
    }
    root_paths.sort();
    root_paths.dedup();
    let mut root_cgroups = Vec::new();
    let mut cgroup_map = BTreeMap::new();
    for root_path in &root_paths {
        let (root_cgroup, subtree) = enumerate_cgroup_subtree(root_path, &request.limits, roots)?;
        root_cgroups.push(root_cgroup);
        for cgroup in subtree {
            if let Some(existing) = cgroup_map.insert(cgroup.path.clone(), cgroup.clone()) {
                if existing.cgroup_id != cgroup.cgroup_id {
                    bail!("overlapping Kata cgroup roots produced inconsistent identities");
                }
            }
        }
    }
    let cgroups = cgroup_map.into_values().collect::<Vec<_>>();
    let pids = enumerate_cgroup_processes(&cgroups, &request.limits, roots)?;
    if !pids.contains(&request.shim_pid) {
        bail!("Kata shim PID moved out of its cgroup during discovery");
    }
    if !explicit_processes.iter().all(|pid| pids.contains(pid)) {
        bail!("one or more explicitly bound Kata host PIDs moved outside their cgroup roots");
    }
    let mut processes = Vec::with_capacity(pids.len());
    for pid in pids {
        let mut process = read_process_bound(pid, ProcessRole::KataAuxiliary, &cgroups, roots)?;
        process.identity.role =
            classify_kata_role(pid, request.shim_pid, &process.executable, &process.cmdline);
        processes.push(process);
    }
    if processes
        .iter()
        .filter(|process| process.identity.role == ProcessRole::KataShim)
        .count()
        != 1
    {
        bail!("Kata cgroup subtree does not contain exactly the requested shim identity");
    }
    let hypervisors = processes
        .iter()
        .filter(|process| process.identity.role == ProcessRole::KataHypervisor)
        .collect::<Vec<_>>();
    if hypervisors.is_empty() {
        bail!("Kata cgroup subtree contains no supported QEMU hypervisor process");
    }
    if let Some(expected) = request.expected_hypervisor_pid {
        if !hypervisors
            .iter()
            .any(|process| process.identity.pid == expected)
        {
            bail!("expected Kata QEMU PID is absent from the shim cgroup subtree");
        }
    }
    for hypervisor in &hypervisors {
        if !bytes_contain(&hypervisor.cmdline, request.sandbox_id.as_bytes())
            && !hypervisor
                .identity
                .cgroup_path
                .contains(&request.sandbox_id)
            && request.expected_hypervisor_pid != Some(hypervisor.identity.pid)
        {
            bail!("Kata QEMU identity is not bound to the requested sandbox ID");
        }
    }
    let observer_netns = read_namespace_id(&roots.procfs.join("self/ns/net"), "net", roots)?;
    let mut resources = Vec::new();
    for hypervisor in hypervisors {
        resources.extend(discover_qemu_resources(
            hypervisor,
            observer_netns,
            request.limits.max_open_fds_per_process,
            roots,
        )?);
    }
    resources.sort_by(resource_order);
    resources.dedup_by(|left, right| resource_order(left, right).is_eq());
    let unresolved = resources
        .iter()
        .any(|resource| resource.resolution == ResourceResolutionStatus::Unresolved);
    let mut limitations = vec![
        "Kata scope intentionally ends at the target Linux host; no Kata guest syscall or guest-kernel state is claimed"
            .to_owned(),
        "Kata runtime processes that exited before S0 remain observable only through later recorder history, not this endpoint process snapshot"
            .to_owned(),
        "QEMU command-line discovery cannot prove dynamically hot-plugged or QMP-reconfigured backends; unresolved resources remain explicit"
            .to_owned(),
        "protocol v1 does not retain each QEMU backend owner mount namespace plus O_PATH object FD; private-mount backend identity after owner exit is fail-closed and cannot be COMPLETE"
            .to_owned(),
    ];
    if unresolved {
        limitations.push(
            "one or more Kata/QEMU host resource arguments could not be resolved to a stable host object"
                .to_owned(),
        );
    }
    let kata_tap_fdinfo_evidence_present = resources.iter().any(|resource| {
        resource.resolution == ResourceResolutionStatus::Resolved
            && matches!(
                resource.network_binding,
                Some(KataNetworkBinding::QemuFd | KataNetworkBinding::QemuFds)
            )
    });
    Ok(DiscoveryParts {
        subject_id: request.sandbox_id.clone(),
        root_cgroups,
        cgroups,
        processes,
        resources,
        coverage: DeploymentCoverage {
            kata_guest_entered: false,
            kata_host_backends_discovered_from_qemu_argv: true,
            kata_tap_fdinfo_evidence_present,
            ..common_coverage(DescendantObservationRequirement::CgroupV2AncestorMatchRequired)
        },
        limitations,
    })
}

fn add_disjoint_or_descendant_root(root_paths: &mut Vec<String>, candidate: &str) -> Result<()> {
    for existing in root_paths.iter() {
        if candidate == existing || is_cgroup_descendant(existing, candidate) {
            return Ok(());
        }
        if is_cgroup_descendant(candidate, existing) {
            bail!("explicit Kata host cgroup is an ancestor of an existing root; refusing an over-broad observation scope");
        }
    }
    root_paths.push(candidate.to_owned());
    Ok(())
}

fn is_cgroup_descendant(root: &str, candidate: &str) -> bool {
    root == "/"
        || candidate
            .strip_prefix(root)
            .map(|suffix| suffix.starts_with('/'))
            .unwrap_or(false)
}

fn common_coverage(requirement: DescendantObservationRequirement) -> DeploymentCoverage {
    DeploymentCoverage {
        direct_syscall_attribution_only: true,
        whole_current_cgroup_subtree_enumerated: true,
        descendant_observation_requirement: requirement,
        mount_namespaces_identified: true,
        network_namespaces_identified: true,
        uts_namespaces_identified: true,
        ipc_namespaces_identified: true,
        kata_guest_entered: false,
        kata_host_backends_discovered_from_qemu_argv: false,
        kata_tap_fdinfo_evidence_present: false,
        kata_host_backend_namespace_pinned: false,
        external_runtime_tool_used: false,
    }
}

pub(crate) fn validate_live_roots(roots: &DiscoveryRoots, kind: DeploymentKind) -> Result<()> {
    ensure_filesystem_magic(&roots.procfs, PROC_SUPER_MAGIC, "procfs")?;
    ensure_filesystem_magic(&roots.cgroupfs, CGROUP2_SUPER_MAGIC, "cgroup v2")?;
    if kind == DeploymentKind::KataHost {
        ensure_filesystem_magic(&roots.sysfs, SYSFS_MAGIC, "sysfs")?;
    }
    Ok(())
}

fn ensure_filesystem_magic(path: &Path, expected: libc::c_long, label: &str) -> Result<()> {
    let bytes = path.as_os_str().as_bytes();
    let path = std::ffi::CString::new(bytes).context("filesystem path contains NUL")?;
    let mut value = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::statfs(path.as_ptr(), value.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs {label}"));
    }
    let value = unsafe { value.assume_init() };
    if value.f_type != expected {
        bail!("deployment discovery root is not {label}");
    }
    Ok(())
}

fn find_docker_init_pid(request: &DockerRequest, roots: &DiscoveryRoots) -> Result<u32> {
    let mut inspected = 0u32;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(&roots.procfs).context("enumerate procfs for Docker init")? {
        let entry = entry.context("read procfs directory entry")?;
        let Some(pid) = parse_numeric_name(&entry.file_name()) else {
            continue;
        };
        inspected = inspected
            .checked_add(1)
            .context("procfs scan counter overflow")?;
        if inspected > request.limits.max_proc_entries {
            bail!("Docker procfs scan hit max_proc_entries before establishing a unique init PID");
        }
        let cgroup =
            match read_unified_cgroup_path(&roots.procfs.join(pid.to_string()).join("cgroup")) {
                Ok(value) => value,
                Err(_) => continue,
            };
        if !docker_cgroup_matches(&cgroup, &request.container_id) {
            continue;
        }
        let chain = match read_nspid_chain(&roots.procfs.join(pid.to_string()).join("status")) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if chain.last().copied() == Some(1) {
            candidates.push(pid);
        }
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [pid] => Ok(*pid),
        [] => bail!("no Docker init PID matched the full container ID"),
        _ => bail!("multiple Docker init PIDs matched the full container ID"),
    }
}

fn docker_cgroup_matches(path: &str, container_id: &str) -> bool {
    path.split('/').any(|component| {
        component == container_id
            || component == format!("docker-{container_id}.scope")
            || component == format!("cri-containerd-{container_id}.scope")
            || component == format!("crio-{container_id}.scope")
            || component == format!("libpod-{container_id}.scope")
    })
}

fn validate_expected_cgroup(actual: &str, expected: &Option<String>) -> Result<()> {
    if let Some(expected) = expected {
        if actual != expected {
            bail!("discovered cgroup path does not match expected_cgroup_path");
        }
    }
    Ok(())
}

fn validate_direct_leaf_seal(path: &str, roots: &DiscoveryRoots) -> Result<()> {
    if path == "/" {
        bail!("direct dedicated-cgroup mode refuses the cgroup hierarchy root");
    }
    let directory = cgroup_host_path(path, roots)?;
    for interface in ["cgroup.max.depth", "cgroup.max.descendants"] {
        let value = String::from_utf8(read_bounded(&directory.join(interface), 128)?)
            .with_context(|| format!("read {interface} as UTF-8"))?;
        if value.trim() != "0" {
            bail!("direct dedicated cgroup is not leaf-sealed: {interface} != 0");
        }
    }
    for entry in fs::read_dir(&directory).context("enumerate direct dedicated cgroup")? {
        let entry = entry.context("read direct cgroup entry")?;
        if entry
            .file_type()
            .context("inspect direct cgroup entry type")?
            .is_dir()
        {
            bail!("direct dedicated cgroup contains a child cgroup");
        }
    }
    Ok(())
}

pub(crate) fn enumerate_cgroup_subtree(
    root_path: &str,
    limits: &DiscoveryLimits,
    roots: &DiscoveryRoots,
) -> Result<(CgroupIdentity, Vec<CgroupIdentity>)> {
    validate_cgroup_path(root_path)?;
    let root_host = cgroup_host_path(root_path, roots)?;
    let root_metadata = fs::metadata(&root_host).context("inspect deployment cgroup root")?;
    if !root_metadata.is_dir() || root_metadata.ino() == 0 {
        bail!("deployment cgroup root is not a stable directory");
    }
    let parent_id = root_host
        .parent()
        .and_then(|parent| fs::metadata(parent).ok())
        .map(|value| value.ino());
    let mut pending = vec![(root_path.to_owned(), root_host, 0u32, parent_id)];
    let mut identities = Vec::new();
    while let Some((relative, host, depth, parent_cgroup_id)) = pending.pop() {
        if depth > limits.max_cgroup_depth {
            bail!("cgroup subtree exceeds max_cgroup_depth");
        }
        if identities.len() >= limits.max_cgroup_nodes as usize {
            bail!("cgroup subtree exceeds max_cgroup_nodes");
        }
        let metadata =
            fs::metadata(&host).with_context(|| format!("inspect cgroup node {relative}"))?;
        if !metadata.is_dir() || metadata.ino() == 0 {
            bail!("cgroup subtree contains a non-directory or zero identity");
        }
        let populated = read_cgroup_populated(&host.join("cgroup.events"))?;
        identities.push(CgroupIdentity {
            path: relative.clone(),
            cgroup_id: metadata.ino(),
            parent_cgroup_id,
            depth_from_root: depth,
            populated,
        });
        let mut children = Vec::new();
        for entry in
            fs::read_dir(&host).with_context(|| format!("enumerate cgroup node {relative}"))?
        {
            let entry = entry.context("read cgroup subtree entry")?;
            if !entry
                .file_type()
                .context("inspect cgroup subtree entry type")?
                .is_dir()
            {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow!("cgroup component is not UTF-8"))?;
            if name.is_empty() || name.contains('/') || name == "." || name == ".." {
                bail!("cgroup subtree contains an invalid component");
            }
            let child_relative = if relative == "/" {
                format!("/{name}")
            } else {
                format!("{relative}/{name}")
            };
            children.push((
                child_relative,
                entry.path(),
                depth + 1,
                Some(metadata.ino()),
            ));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        children.reverse();
        pending.extend(children);
    }
    identities.sort_by(|left, right| left.path.cmp(&right.path));
    for identity in &identities {
        let metadata = fs::metadata(cgroup_host_path(&identity.path, roots)?)
            .with_context(|| format!("reinspect cgroup node {}", identity.path))?;
        if metadata.ino() != identity.cgroup_id || !metadata.is_dir() {
            bail!("cgroup subtree identity changed during enumeration");
        }
    }
    let root = identities
        .iter()
        .find(|identity| identity.path == root_path)
        .context("enumerated cgroup root disappeared")?
        .clone();
    Ok((root, identities))
}

pub(crate) fn enumerate_cgroup_processes(
    cgroups: &[CgroupIdentity],
    limits: &DiscoveryLimits,
    roots: &DiscoveryRoots,
) -> Result<BTreeSet<u32>> {
    let mut pids = BTreeSet::new();
    for cgroup in cgroups {
        let path = cgroup_host_path(&cgroup.path, roots)?.join("cgroup.procs");
        let data = read_bounded(&path, MAX_PROC_FILE_BYTES)
            .with_context(|| format!("read {} process membership", cgroup.path))?;
        let text = String::from_utf8(data).context("cgroup.procs is not UTF-8")?;
        for line in text.lines() {
            if line.is_empty() {
                continue;
            }
            let pid = line.parse::<u32>().context("parse cgroup.procs PID")?;
            if pid == 0 || pid > i32::MAX as u32 {
                bail!("cgroup.procs contains an invalid PID");
            }
            pids.insert(pid);
            if pids.len() > limits.max_proc_entries as usize || pids.len() > HARD_MAX_PROCESSES {
                bail!("cgroup process set exceeds discovery bound");
            }
        }
    }
    Ok(pids)
}

fn read_process_bound(
    pid: u32,
    role: ProcessRole,
    cgroups: &[CgroupIdentity],
    roots: &DiscoveryRoots,
) -> Result<CapturedProcess> {
    let process = read_process_base(pid, role, roots)?;
    let cgroup = cgroups
        .iter()
        .find(|cgroup| cgroup.path == process.identity.cgroup_path)
        .context("process moved outside discovered cgroup subtree")?;
    if cgroup.cgroup_id != process.identity.cgroup_id {
        bail!("process cgroup ID changed during discovery");
    }
    Ok(process)
}

pub(crate) fn read_process_base(
    pid: u32,
    role: ProcessRole,
    roots: &DiscoveryRoots,
) -> Result<CapturedProcess> {
    let directory = roots.procfs.join(pid.to_string());
    let stat = read_bounded(&directory.join("stat"), MAX_PROC_FILE_BYTES)?;
    let start_time_ticks = parse_proc_stat_start_time(&stat, pid)?;
    let comm = String::from_utf8(read_bounded(&directory.join("comm"), 4096)?)
        .context("process comm is not UTF-8")?
        .trim_end_matches('\n')
        .to_owned();
    let cmdline = read_bounded(&directory.join("cmdline"), MAX_PROC_FILE_BYTES)?;
    let executable =
        fs::read_link(directory.join("exe")).context("read process executable link")?;
    let executable_metadata =
        fs::metadata(directory.join("exe")).context("inspect process executable identity")?;
    let cgroup_path = read_unified_cgroup_path(&directory.join("cgroup"))?;
    let cgroup_host = cgroup_host_path(&cgroup_path, roots)?;
    let cgroup_id = fs::metadata(cgroup_host)
        .context("inspect process cgroup identity")?
        .ino();
    if cgroup_id == 0 {
        bail!("process cgroup has a zero inode identity");
    }
    let mount_namespace_id = read_namespace_id(&directory.join("ns/mnt"), "mnt", roots)?;
    let pid_namespace_id = read_namespace_id(&directory.join("ns/pid"), "pid", roots)?;
    let net_namespace_id = read_namespace_id(&directory.join("ns/net"), "net", roots)?;
    let uts_namespace_id = read_namespace_id(&directory.join("ns/uts"), "uts", roots)?;
    let ipc_namespace_id = read_namespace_id(&directory.join("ns/ipc"), "ipc", roots)?;
    let namespace_pid_chain = read_nspid_chain(&directory.join("status"))?;
    let identity = ProcessIdentity {
        pid,
        role,
        start_time_ticks,
        comm,
        executable_path_bytes_hex: hex::encode(executable.as_os_str().as_bytes()),
        executable_device: executable_metadata.dev(),
        executable_inode: executable_metadata.ino(),
        cmdline_sha256: hex::encode(Sha256::digest(&cmdline)),
        cgroup_path,
        cgroup_id,
        mount_namespace_id,
        pid_namespace_id,
        net_namespace_id,
        uts_namespace_id,
        ipc_namespace_id,
        namespace_pid_chain,
    };
    identity.validate()?;
    let final_start_time = parse_proc_stat_start_time(
        &read_bounded(&directory.join("stat"), MAX_PROC_FILE_BYTES)?,
        pid,
    )?;
    let final_executable =
        fs::metadata(directory.join("exe")).context("reinspect process executable identity")?;
    let final_executable_path =
        fs::read_link(directory.join("exe")).context("reread process executable link")?;
    let final_cmdline = read_bounded(&directory.join("cmdline"), MAX_PROC_FILE_BYTES)?;
    let final_cgroup_path = read_unified_cgroup_path(&directory.join("cgroup"))?;
    let final_cgroup_id = fs::metadata(cgroup_host_path(&final_cgroup_path, roots)?)
        .context("reinspect process cgroup identity")?
        .ino();
    let final_mount_namespace_id = read_namespace_id(&directory.join("ns/mnt"), "mnt", roots)?;
    let final_pid_namespace_id = read_namespace_id(&directory.join("ns/pid"), "pid", roots)?;
    let final_net_namespace_id = read_namespace_id(&directory.join("ns/net"), "net", roots)?;
    let final_uts_namespace_id = read_namespace_id(&directory.join("ns/uts"), "uts", roots)?;
    let final_ipc_namespace_id = read_namespace_id(&directory.join("ns/ipc"), "ipc", roots)?;
    let final_namespace_pid_chain = read_nspid_chain(&directory.join("status"))?;
    if final_start_time != identity.start_time_ticks
        || final_executable.dev() != identity.executable_device
        || final_executable.ino() != identity.executable_inode
        || final_executable_path.as_os_str().as_bytes()
            != hex::decode(&identity.executable_path_bytes_hex)?.as_slice()
        || hex::encode(Sha256::digest(final_cmdline)) != identity.cmdline_sha256
        || final_cgroup_path != identity.cgroup_path
        || final_cgroup_id != identity.cgroup_id
        || final_mount_namespace_id != identity.mount_namespace_id
        || final_pid_namespace_id != identity.pid_namespace_id
        || final_net_namespace_id != identity.net_namespace_id
        || final_uts_namespace_id != identity.uts_namespace_id
        || final_ipc_namespace_id != identity.ipc_namespace_id
        || final_namespace_pid_chain != identity.namespace_pid_chain
    {
        bail!("process PID/exec/cgroup/namespace identity changed during discovery");
    }
    Ok(CapturedProcess {
        identity,
        cmdline,
        executable,
    })
}

fn read_unified_cgroup_path(path: &Path) -> Result<String> {
    let bytes = read_bounded(path, MAX_PROC_FILE_BYTES)?;
    let text = String::from_utf8(bytes).context("process cgroup file is not UTF-8")?;
    let mut unified = None;
    for line in text.lines() {
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields.next().context("cgroup line lacks hierarchy")?;
        let controllers = fields.next().context("cgroup line lacks controllers")?;
        let path = fields.next().context("cgroup line lacks path")?;
        if hierarchy == "0" && controllers.is_empty() && unified.replace(path.to_owned()).is_some()
        {
            bail!("process cgroup file contains duplicate unified entries");
        }
    }
    let path = unified.context("process has no cgroup v2 unified membership")?;
    validate_cgroup_path(&path)?;
    Ok(path)
}

fn read_nspid_chain(path: &Path) -> Result<Vec<u32>> {
    let bytes = read_bounded(path, MAX_PROC_FILE_BYTES)?;
    let text = String::from_utf8(bytes).context("process status is not UTF-8")?;
    let mut chain = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("NSpid:") {
            if chain.is_some() {
                bail!("process status contains duplicate NSpid fields");
            }
            let values = value
                .split_ascii_whitespace()
                .map(|value| value.parse::<u32>().context("parse NSpid value"))
                .collect::<Result<Vec<_>>>()?;
            if values.is_empty() || values.iter().any(|value| *value == 0) {
                bail!("process NSpid chain is empty or invalid");
            }
            chain = Some(values);
        }
    }
    chain.context("process status has no NSpid identity")
}

fn parse_proc_stat_start_time(bytes: &[u8], expected_pid: u32) -> Result<u64> {
    let text = std::str::from_utf8(bytes).context("process stat is not UTF-8")?;
    let open = text
        .find('(')
        .context("process stat lacks comm open delimiter")?;
    let close = text
        .rfind(") ")
        .context("process stat lacks comm close delimiter")?;
    let parsed_pid = text[..open]
        .trim()
        .parse::<u32>()
        .context("parse process stat PID")?;
    if parsed_pid != expected_pid || close <= open {
        bail!("process stat PID/comm framing mismatch");
    }
    let fields = text[close + 2..]
        .split_ascii_whitespace()
        .collect::<Vec<_>>();
    // Tail begins at field 3 (state); starttime is proc stat field 22.
    let value = fields
        .get(19)
        .context("process stat lacks starttime field")?
        .parse::<u64>()
        .context("parse process starttime")?;
    if value == 0 {
        bail!("process stat contains a zero starttime");
    }
    Ok(value)
}

pub(crate) fn read_namespace_id(
    path: &Path,
    expected_kind: &str,
    roots: &DiscoveryRoots,
) -> Result<u64> {
    let target =
        fs::read_link(path).with_context(|| format!("read {expected_kind} namespace link"))?;
    let target = target
        .to_str()
        .context("namespace link target is not UTF-8")?;
    let prefix = format!("{expected_kind}:[");
    let value = target
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(']'))
        .context("namespace link has unexpected kernel format")?
        .parse::<u64>()
        .context("parse namespace inode")?;
    if value == 0 {
        bail!("kernel returned a zero namespace identity");
    }
    if roots.source_trust == DiscoverySourceTrust::KernelFilesystemsVerified {
        let metadata = fs::metadata(path).context("inspect namespace inode identity")?;
        if metadata.ino() != value {
            bail!("namespace link text and inode identity disagree");
        }
    }
    Ok(value)
}

fn cgroup_host_path(path: &str, roots: &DiscoveryRoots) -> Result<PathBuf> {
    validate_cgroup_path(path)?;
    let relative = path.strip_prefix('/').unwrap_or(path);
    let candidate = roots.cgroupfs.join(relative);
    if !candidate.starts_with(&roots.cgroupfs) {
        bail!("cgroup path escaped cgroupfs root");
    }
    Ok(candidate)
}

fn read_cgroup_populated(path: &Path) -> Result<bool> {
    let bytes = read_bounded(path, 4096)?;
    let text = String::from_utf8(bytes).context("cgroup.events is not UTF-8")?;
    let mut populated = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let Some(name) = fields.next() else { continue };
        let Some(value) = fields.next() else {
            bail!("cgroup.events line lacks a value");
        };
        if fields.next().is_some() {
            bail!("cgroup.events line contains an extra field");
        }
        if name == "populated" {
            if populated.is_some() {
                bail!("cgroup.events contains duplicate populated fields");
            }
            populated = Some(match value {
                "0" => false,
                "1" => true,
                _ => bail!("cgroup.events populated value is invalid"),
            });
        }
    }
    populated.context("cgroup.events contains no populated field")
}

fn is_kata_shim(executable: &Path, cmdline: &[u8]) -> bool {
    let basename = executable.file_name().and_then(OsStr::to_str).unwrap_or("");
    matches!(
        basename,
        "containerd-shim-kata-v2" | "kata-shim" | "kata-runtime"
    ) || (basename == "containerd-shim-v2" && bytes_contain(cmdline, b"kata"))
}

fn classify_kata_role(pid: u32, shim_pid: u32, executable: &Path, cmdline: &[u8]) -> ProcessRole {
    if pid == shim_pid {
        return ProcessRole::KataShim;
    }
    let basename = executable.file_name().and_then(OsStr::to_str).unwrap_or("");
    if basename.starts_with("qemu-system-")
        || basename.starts_with("qemu-lite-system-")
        || basename == "qemu-kvm"
    {
        ProcessRole::KataHypervisor
    } else if basename.contains("kata") || bytes_contain(cmdline, b"kata") {
        ProcessRole::KataRuntime
    } else {
        ProcessRole::KataAuxiliary
    }
}

fn discover_qemu_resources(
    process: &CapturedProcess,
    observer_netns: u64,
    maximum_descriptor: u32,
    roots: &DiscoveryRoots,
) -> Result<Vec<KataHostResource>> {
    let argv = split_cmdline(&process.cmdline);
    let mut resources = Vec::new();
    let mut index = 1usize;
    while index < argv.len() {
        let argument = argv[index];
        let (option, inline_value) = split_option(argument);
        let needs_value = matches!(
            option,
            b"-drive"
                | b"-blockdev"
                | b"-hda"
                | b"-hdb"
                | b"-hdc"
                | b"-hdd"
                | b"-cdrom"
                | b"-netdev"
                | b"-nic"
                | b"-net"
        );
        if !needs_value {
            index += 1;
            continue;
        }
        let (value, consumed_next) = match inline_value {
            Some(value) => (value, false),
            None if index + 1 < argv.len() => (argv[index + 1], true),
            None => {
                resources.push(unresolved_resource(
                    process.identity.pid,
                    argument,
                    if matches!(option, b"-netdev" | b"-nic" | b"-net") {
                        KataResourceKind::UnresolvedNetworkArgument
                    } else {
                        KataResourceKind::UnresolvedDiskArgument
                    },
                    "QEMU option has no value",
                ));
                index += 1;
                continue;
            }
        };
        let mut source = Vec::with_capacity(argument.len() + value.len() + 1);
        source.extend_from_slice(argument);
        source.push(0);
        source.extend_from_slice(value);
        if matches!(option, b"-netdev" | b"-nic" | b"-net") {
            resources.push(resolve_network_argument(
                process,
                value,
                &source,
                observer_netns,
                maximum_descriptor,
                roots,
            ));
        } else {
            resources.push(resolve_disk_argument(
                process, option, value, &source, roots,
            ));
        }
        index += if consumed_next { 2 } else { 1 };
    }
    Ok(resources)
}

fn split_cmdline(cmdline: &[u8]) -> Vec<&[u8]> {
    let mut values = cmdline
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() && !cmdline.is_empty() {
        values.push(cmdline);
    }
    values
}

fn split_option(argument: &[u8]) -> (&[u8], Option<&[u8]>) {
    match argument.iter().position(|byte| *byte == b'=') {
        Some(index) => (&argument[..index], Some(&argument[index + 1..])),
        None => (argument, None),
    }
}

fn resolve_disk_argument(
    process: &CapturedProcess,
    option: &[u8],
    value: &[u8],
    source: &[u8],
    roots: &DiscoveryRoots,
) -> KataHostResource {
    let path = if matches!(option, b"-hda" | b"-hdb" | b"-hdc" | b"-hdd" | b"-cdrom") {
        Some(value.to_vec())
    } else if option == b"-blockdev" && value.first() == Some(&b'{') {
        extract_json_filename(value)
    } else {
        extract_qemu_key_value(value, &[b"filename", b"file", b"file.filename"])
    };
    let Some(path) = path else {
        return unresolved_resource(
            process.identity.pid,
            source,
            KataResourceKind::UnresolvedDiskArgument,
            "QEMU disk argument has no supported file/filename binding",
        );
    };
    if path.is_empty()
        || path.contains(&0)
        || path.starts_with(b"rbd:")
        || path.starts_with(b"nbd:")
    {
        return unresolved_resource(
            process.identity.pid,
            source,
            KataResourceKind::UnresolvedDiskArgument,
            "QEMU disk backend is empty, remote, or contains NUL",
        );
    }
    let path = PathBuf::from(OsString::from_vec(path));
    let process_directory = roots.procfs.join(process.identity.pid.to_string());
    let host_candidate = if path.is_absolute() {
        process_directory
            .join("root")
            .join(path.strip_prefix("/").unwrap_or(&path))
    } else {
        process_directory.join("cwd").join(path)
    };
    let canonical = match fs::canonicalize(host_candidate) {
        Ok(path) => path,
        Err(error) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedDiskArgument,
                &format!("cannot resolve QEMU disk in its mount namespace: {error}"),
            )
        }
    };
    let metadata = match fs::metadata(&canonical) {
        Ok(metadata) => metadata,
        Err(error) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedDiskArgument,
                &format!("cannot inspect QEMU disk object: {error}"),
            )
        }
    };
    let kind = if metadata.file_type().is_block_device() {
        KataResourceKind::VirtualBlockDevice
    } else if metadata.file_type().is_file() {
        KataResourceKind::VirtualDiskFile
    } else {
        return unresolved_resource(
            process.identity.pid,
            source,
            KataResourceKind::UnresolvedDiskArgument,
            "QEMU disk path is neither a regular file nor a block device",
        );
    };
    KataHostResource {
        kind,
        resolution: ResourceResolutionStatus::Resolved,
        owner_pid: process.identity.pid,
        source_argument_sha256: hex::encode(Sha256::digest(source)),
        path_bytes_hex: Some(hex::encode(canonical.as_os_str().as_bytes())),
        device: Some(metadata.dev()),
        inode: Some(metadata.ino()),
        rdev: Some(metadata.rdev()),
        size_bytes: Some(metadata.size()),
        interface_name: None,
        interface_index: None,
        net_namespace_id: None,
        network_binding: None,
        network_file_descriptors: Vec::new(),
        unresolved_reason: None,
    }
}

fn resolve_network_argument(
    process: &CapturedProcess,
    value: &[u8],
    source: &[u8],
    observer_netns: u64,
    maximum_descriptor: u32,
    roots: &DiscoveryRoots,
) -> KataHostResource {
    let fields = split_qemu_fields(value);
    if fields.first().map(Vec::as_slice) != Some(b"tap") {
        return unresolved_resource(
            process.identity.pid,
            source,
            KataResourceKind::UnresolvedNetworkArgument,
            "QEMU network argument is not an explicit tap backend",
        );
    }
    let ifname = match unique_qemu_field(&fields, b"ifname") {
        Ok(value) => value,
        Err(reason) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedNetworkArgument,
                reason,
            )
        }
    };
    let fd = match unique_qemu_field(&fields, b"fd") {
        Ok(value) => value,
        Err(reason) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedNetworkArgument,
                reason,
            )
        }
    };
    let fds = match unique_qemu_field(&fields, b"fds") {
        Ok(value) => value,
        Err(reason) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedNetworkArgument,
                reason,
            )
        }
    };
    if usize::from(ifname.is_some()) + usize::from(fd.is_some()) + usize::from(fds.is_some()) != 1 {
        return unresolved_resource(
            process.identity.pid,
            source,
            KataResourceKind::UnresolvedNetworkArgument,
            "QEMU tap argument must contain exactly one of ifname, fd, or fds",
        );
    }

    let (binding, descriptors, interface) = if let Some(interface) = ifname {
        let interface = match parse_interface_name(&interface) {
            Ok(value) => value,
            Err(reason) => {
                return unresolved_resource(
                    process.identity.pid,
                    source,
                    KataResourceKind::UnresolvedNetworkArgument,
                    reason,
                )
            }
        };
        (KataNetworkBinding::QemuIfname, Vec::new(), interface)
    } else {
        let (binding, descriptors) = if let Some(fd) = fd {
            let descriptor = match parse_qemu_descriptor(&fd, maximum_descriptor) {
                Ok(value) => value,
                Err(reason) => {
                    return unresolved_resource(
                        process.identity.pid,
                        source,
                        KataResourceKind::UnresolvedNetworkArgument,
                        &reason,
                    )
                }
            };
            (KataNetworkBinding::QemuFd, vec![descriptor])
        } else {
            let descriptors = match parse_qemu_descriptor_set(
                fds.as_deref().unwrap_or_default(),
                maximum_descriptor,
            ) {
                Ok(value) => value,
                Err(reason) => {
                    return unresolved_resource(
                        process.identity.pid,
                        source,
                        KataResourceKind::UnresolvedNetworkArgument,
                        &reason,
                    )
                }
            };
            (KataNetworkBinding::QemuFds, descriptors)
        };
        let mut interface = None;
        for descriptor in &descriptors {
            let observed = match inspect_tun_fd_interface(process.identity.pid, *descriptor, roots)
            {
                Ok(value) => value,
                Err(error) => {
                    return unresolved_resource(
                        process.identity.pid,
                        source,
                        KataResourceKind::UnresolvedNetworkArgument,
                        &format!("cannot bind QEMU TAP descriptor {descriptor}: {error:#}"),
                    )
                }
            };
            if interface
                .as_ref()
                .map_or(false, |expected| expected != &observed)
            {
                return unresolved_resource(
                    process.identity.pid,
                    source,
                    KataResourceKind::UnresolvedNetworkArgument,
                    "QEMU fds descriptor set refers to more than one tun interface",
                );
            }
            interface = Some(observed);
        }
        (
            binding,
            descriptors,
            interface.expect("validated descriptor list cannot be empty"),
        )
    };

    let ifindex = match inspect_tap_interface_in_namespace(
        process.identity.pid,
        process.identity.net_namespace_id,
        observer_netns,
        &interface,
        roots,
    ) {
        Ok(value) => value,
        Err(error) => {
            return unresolved_resource(
                process.identity.pid,
                source,
                KataResourceKind::UnresolvedNetworkArgument,
                &format!("cannot verify TAP in QEMU network namespace: {error:#}"),
            )
        }
    };
    KataHostResource {
        kind: KataResourceKind::TapInterface,
        resolution: ResourceResolutionStatus::Resolved,
        owner_pid: process.identity.pid,
        source_argument_sha256: hex::encode(Sha256::digest(source)),
        path_bytes_hex: None,
        device: None,
        inode: None,
        rdev: None,
        size_bytes: None,
        interface_name: Some(interface),
        interface_index: Some(ifindex),
        net_namespace_id: Some(process.identity.net_namespace_id),
        network_binding: Some(binding),
        network_file_descriptors: descriptors,
        unresolved_reason: None,
    }
}

fn split_qemu_fields(value: &[u8]) -> Vec<Vec<u8>> {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut index = 0usize;
    while index < value.len() {
        if value[index] == b',' && value.get(index + 1) == Some(&b',') {
            field.push(b',');
            index += 2;
        } else if value[index] == b',' {
            fields.push(std::mem::take(&mut field));
            index += 1;
        } else {
            field.push(value[index]);
            index += 1;
        }
    }
    fields.push(field);
    fields
}

fn unique_qemu_field(
    fields: &[Vec<u8>],
    key: &[u8],
) -> std::result::Result<Option<Vec<u8>>, &'static str> {
    let mut result = None;
    for field in fields {
        let Some(separator) = field.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if &field[..separator] == key && result.replace(field[separator + 1..].to_vec()).is_some() {
            return Err("QEMU tap argument contains a duplicate binding key");
        }
    }
    Ok(result)
}

fn parse_interface_name(value: &[u8]) -> std::result::Result<String, &'static str> {
    let interface =
        std::str::from_utf8(value).map_err(|_| "QEMU TAP interface name is not UTF-8")?;
    if interface.is_empty()
        || interface.len() >= libc::IFNAMSIZ
        || !interface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("QEMU TAP interface name is not a supported Linux interface name");
    }
    Ok(interface.to_owned())
}

pub(crate) fn parse_qemu_descriptor(
    value: &[u8],
    maximum: u32,
) -> std::result::Result<u32, String> {
    if value.is_empty()
        || !value.iter().all(u8::is_ascii_digit)
        || (value.len() > 1 && value[0] == b'0')
    {
        return Err("QEMU TAP descriptor is not canonical decimal".to_owned());
    }
    let descriptor = std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or_else(|| "QEMU TAP descriptor is outside u32".to_owned())?;
    if descriptor >= maximum || descriptor >= HARD_MAX_OPEN_FDS {
        return Err(format!(
            "QEMU TAP descriptor exceeds configured exclusive upper bound {maximum}"
        ));
    }
    Ok(descriptor)
}

pub(crate) fn parse_qemu_descriptor_set(
    value: &[u8],
    maximum: u32,
) -> std::result::Result<Vec<u32>, String> {
    if value.is_empty() {
        return Err("QEMU TAP fds set is empty".to_owned());
    }
    let mut descriptors = Vec::new();
    let mut unique = BTreeSet::new();
    for component in value.split(|byte| *byte == b':') {
        let descriptor = parse_qemu_descriptor(component, maximum)?;
        if !unique.insert(descriptor) {
            return Err("QEMU TAP fds set contains a duplicate descriptor".to_owned());
        }
        descriptors.push(descriptor);
        if descriptors.len() > 256 {
            return Err("QEMU TAP fds set exceeds 256 queues".to_owned());
        }
    }
    Ok(descriptors)
}

pub(crate) fn inspect_tun_fd_interface(
    pid: u32,
    descriptor: u32,
    roots: &DiscoveryRoots,
) -> Result<String> {
    if descriptor >= HARD_MAX_OPEN_FDS {
        bail!("descriptor exceeds the deployment hard bound");
    }
    let process = roots.procfs.join(pid.to_string());
    let descriptor_path = process.join("fd").join(descriptor.to_string());
    let metadata = fs::metadata(descriptor_path).context("inspect target process descriptor")?;
    // SAFETY: `rdev` is the kernel-provided `dev_t` returned by stat(2).  These
    // libc helpers only decode its major/minor bit fields.
    let (device_major, device_minor) =
        unsafe { (libc::major(metadata.rdev()), libc::minor(metadata.rdev())) };
    if roots.source_trust == DiscoverySourceTrust::KernelFilesystemsVerified
        && (!metadata.file_type().is_char_device()
            || device_major != TUN_DEVICE_MAJOR
            || device_minor != TUN_DEVICE_MINOR)
    {
        bail!("target process descriptor is not the Linux tun character device");
    }
    let fdinfo = read_bounded(
        &process.join("fdinfo").join(descriptor.to_string()),
        MAX_TUN_FDINFO_BYTES,
    )?;
    let text = std::str::from_utf8(&fdinfo).context("tun fdinfo is not UTF-8")?;
    let mut interface = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("iff:") {
            if interface.is_some() {
                bail!("tun fdinfo contains duplicate iff fields");
            }
            interface =
                Some(parse_interface_name(value.trim().as_bytes()).map_err(anyhow::Error::msg)?);
        }
    }
    interface.context("target process fdinfo has no tun iff identity")
}

pub(crate) fn inspect_tap_interface_in_namespace(
    pid: u32,
    expected_netns: u64,
    observer_netns: u64,
    interface: &str,
    roots: &DiscoveryRoots,
) -> Result<u32> {
    parse_interface_name(interface.as_bytes()).map_err(anyhow::Error::msg)?;
    if roots.source_trust == DiscoverySourceTrust::FixtureUntrusted {
        return inspect_fixture_namespace_tap(interface, &roots.sysfs);
    }
    if expected_netns == observer_netns {
        return inspect_current_namespace_tap(interface, &roots.sysfs);
    }

    let original_path = roots.procfs.join("self/ns/net");
    let target_path = roots.procfs.join(pid.to_string()).join("ns/net");
    let original = File::open(original_path).context("open Observer network namespace")?;
    let target = File::open(target_path).context("open QEMU network namespace")?;
    if original.metadata()?.ino() != observer_netns || target.metadata()?.ino() != expected_netns {
        bail!("network namespace FD identity disagrees with captured inode");
    }
    if unsafe { libc::setns(target.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        return Err(std::io::Error::last_os_error()).context("enter QEMU network namespace");
    }
    let result = inspect_current_namespace_tap(interface, &roots.sysfs);
    if unsafe { libc::setns(original.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
        // Continuing in the target namespace would invalidate every later
        // discovery assertion. A failed restore is therefore unrecoverable.
        std::process::abort();
    }
    result
}

fn inspect_current_namespace_tap(interface: &str, sysfs: &Path) -> Result<u32> {
    let c_name = CString::new(interface).context("TAP interface contains NUL")?;
    let ifindex = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if ifindex == 0 {
        return Err(std::io::Error::last_os_error()).context("resolve TAP ifindex");
    }
    let flags = read_bounded(
        &sysfs.join("class/net").join(interface).join("tun_flags"),
        128,
    )?;
    let flags = std::str::from_utf8(&flags)
        .context("TAP tun_flags is not UTF-8")?
        .trim()
        .strip_prefix("0x")
        .and_then(|value| u32::from_str_radix(value, 16).ok())
        .context("TAP tun_flags is not canonical hexadecimal")?;
    if flags & libc::IFF_TAP as u32 == 0 {
        bail!("tun interface is not a TAP device");
    }
    Ok(ifindex)
}

fn inspect_fixture_namespace_tap(interface: &str, sysfs: &Path) -> Result<u32> {
    let directory = sysfs.join("class/net").join(interface);
    let ifindex_bytes = read_bounded(&directory.join("ifindex"), 128)?;
    let ifindex = std::str::from_utf8(&ifindex_bytes)
        .context("fixture TAP ifindex is not UTF-8")?
        .trim()
        .parse::<u32>()
        .context("parse fixture TAP ifindex")?;
    if ifindex == 0 {
        bail!("fixture TAP ifindex is zero");
    }
    let flags_bytes = read_bounded(&directory.join("tun_flags"), 128)?;
    let flags = std::str::from_utf8(&flags_bytes)
        .context("fixture TAP tun_flags is not UTF-8")?
        .trim()
        .strip_prefix("0x")
        .and_then(|value| u32::from_str_radix(value, 16).ok())
        .context("fixture TAP tun_flags is not canonical hexadecimal")?;
    if flags & libc::IFF_TAP as u32 == 0 {
        bail!("fixture tun interface is not TAP");
    }
    Ok(ifindex)
}

fn extract_json_filename(value: &[u8]) -> Option<Vec<u8>> {
    fn visit(value: &Value) -> Option<String> {
        match value {
            Value::Object(map) => {
                for key in ["filename", "file"] {
                    if let Some(Value::String(value)) = map.get(key) {
                        return Some(value.clone());
                    }
                }
                map.values().find_map(visit)
            }
            Value::Array(values) => values.iter().find_map(visit),
            _ => None,
        }
    }
    serde_json::from_slice::<Value>(value)
        .ok()
        .as_ref()
        .and_then(visit)
        .map(String::into_bytes)
}

fn extract_qemu_key_value(value: &[u8], keys: &[&[u8]]) -> Option<Vec<u8>> {
    let mut fields = Vec::new();
    let mut field = Vec::new();
    let mut index = 0usize;
    while index < value.len() {
        if value[index] == b',' && value.get(index + 1) == Some(&b',') {
            field.push(b',');
            index += 2;
        } else if value[index] == b',' {
            fields.push(std::mem::take(&mut field));
            index += 1;
        } else {
            field.push(value[index]);
            index += 1;
        }
    }
    fields.push(field);
    for field in fields {
        let Some(separator) = field.iter().position(|byte| *byte == b'=') else {
            continue;
        };
        if keys.iter().any(|key| *key == &field[..separator]) {
            return Some(field[separator + 1..].to_vec());
        }
    }
    None
}

fn unresolved_resource(
    owner_pid: u32,
    source: &[u8],
    kind: KataResourceKind,
    reason: &str,
) -> KataHostResource {
    KataHostResource {
        kind,
        resolution: ResourceResolutionStatus::Unresolved,
        owner_pid,
        source_argument_sha256: hex::encode(Sha256::digest(source)),
        path_bytes_hex: None,
        device: None,
        inode: None,
        rdev: None,
        size_bytes: None,
        interface_name: None,
        interface_index: None,
        net_namespace_id: None,
        network_binding: None,
        network_file_descriptors: Vec::new(),
        unresolved_reason: Some(reason.chars().take(HARD_MAX_STRING_BYTES).collect()),
    }
}

fn resource_order(left: &KataHostResource, right: &KataHostResource) -> std::cmp::Ordering {
    format!("{:?}", left.kind)
        .cmp(&format!("{:?}", right.kind))
        .then(left.owner_pid.cmp(&right.owner_pid))
        .then(
            left.source_argument_sha256
                .cmp(&right.source_argument_sha256),
        )
        .then(left.path_bytes_hex.cmp(&right.path_bytes_hex))
        .then(left.interface_name.cmp(&right.interface_name))
        .then(left.network_binding.cmp(&right.network_binding))
        .then(
            left.network_file_descriptors
                .cmp(&right.network_file_descriptors),
        )
}

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn parse_numeric_name(name: &OsStr) -> Option<u32> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let limit = maximum
        .checked_add(1)
        .context("bounded input maximum cannot be u64::MAX")?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open bounded input {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect bounded input {}", path.display()))?;
    if !(metadata.is_file() || metadata.file_type().is_char_device()) {
        bail!(
            "bounded input {} is not a regular or kernel pseudo-file",
            path.display()
        );
    }
    // procfs and sysfs attributes commonly advertise page-sized st_size even
    // when their read payload is only a few bytes. Never trust that hint for
    // acceptance or allocation: anchor the opened object and cap the bytes
    // actually returned by read(2) to maximum + 1.
    let mut value = Vec::new();
    file.take(limit)
        .read_to_end(&mut value)
        .with_context(|| format!("read bounded input {}", path.display()))?;
    if value.len() as u64 > maximum {
        bail!("bounded input {} exceeds {maximum} bytes", path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod bounded_read_tests {
    use super::*;

    #[test]
    fn sysfs_advertised_size_does_not_override_actual_read_bound() {
        let path = Path::new("/sys/class/net/lo/ifindex");
        if !path.exists() {
            return;
        }
        let advertised = fs::metadata(path).expect("inspect loopback ifindex sysfs attribute");
        let value =
            read_bounded(path, 128).expect("read short sysfs attribute with bounded reader");
        assert!(value.len() <= 128);
        assert!(!value.is_empty());
        if advertised.len() > 128 {
            assert!(value.len() as u64 <= 128);
        }
    }

    #[test]
    fn bounded_reader_rejects_bytes_actually_returned_past_limit() {
        let path =
            std::env::temp_dir().join(format!("bpf-observer-bounded-read-{}", std::process::id()));
        fs::write(&path, [0x5a_u8; 129]).expect("write bounded-reader fixture");
        let result = read_bounded(&path, 128);
        fs::remove_file(&path).expect("remove bounded-reader fixture");
        assert!(result.is_err());
    }
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<DeploymentManifest>();
}
