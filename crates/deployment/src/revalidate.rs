// SPDX-License-Identifier: GPL-2.0-only

use crate::discover::{
    enumerate_cgroup_processes, enumerate_cgroup_subtree, inspect_tap_interface_in_namespace,
    inspect_tun_fd_interface, read_namespace_id, read_process_base, validate_live_roots,
    DiscoveryRoots,
};
use crate::schema::*;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::MetadataExt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RevalidationPhase {
    /// Before SIGCONT: every committed process and exact subtree must remain.
    Ready,
    /// After execution: a committed process may have exited, but PID reuse,
    /// residual/new processes, cgroup replacement, and backend replacement do
    /// not become expected merely because closure was requested.
    Closure,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ValidationMismatch {
    BootIdentityChanged {
        expected: String,
        observed: String,
    },
    CgroupMissing {
        path: String,
        expected_id: u64,
    },
    CgroupIdentityChanged {
        path: String,
        expected_id: u64,
        observed_id: u64,
    },
    CgroupSetChanged {
        added: Vec<String>,
        removed: Vec<String>,
    },
    ProcessMissingBeforeReady {
        pid: u32,
    },
    ProcessIdentityChanged {
        pid: u32,
        changed_fields: Vec<String>,
    },
    ProcessSetChanged {
        added: Vec<u32>,
        removed_unexpected: Vec<u32>,
    },
    BackendObjectMissing {
        owner_pid: u32,
        path_bytes_hex: String,
    },
    BackendObjectIdentityChanged {
        owner_pid: u32,
        path_bytes_hex: String,
        changed_fields: Vec<String>,
    },
    NetworkBackendMissing {
        owner_pid: u32,
        interface_name: String,
    },
    NetworkBackendIdentityChanged {
        owner_pid: u32,
        interface_name: String,
        expected_ifindex: u32,
        observed_ifindex: u32,
    },
    NetworkBackendDescriptorChanged {
        owner_pid: u32,
        descriptor: u32,
        expected_interface_name: String,
    },
    ResourceUnresolved {
        owner_pid: u32,
        source_argument_sha256: String,
        reason: String,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LiveIdentityValidation {
    pub protocol_version: u32,
    pub scope_sha256: String,
    pub phase: RevalidationPhase,
    pub checked_unix_ns: u128,
    pub stable: bool,
    pub expected_process_exits: Vec<u32>,
    pub mismatches: Vec<ValidationMismatch>,
}

impl LiveIdentityValidation {
    pub fn is_stable(&self) -> bool {
        self.stable && self.mismatches.is_empty()
    }
}

pub fn validate_against_live_procfs(
    manifest: &DeploymentManifest,
) -> Result<LiveIdentityValidation> {
    validate_against_live_procfs_for_phase(manifest, RevalidationPhase::Ready)
}

pub fn validate_against_live_procfs_for_phase(
    manifest: &DeploymentManifest,
    phase: RevalidationPhase,
) -> Result<LiveIdentityValidation> {
    manifest.validate()?;
    if manifest.source_trust != DiscoverySourceTrust::KernelFilesystemsVerified {
        bail!("fixture-derived deployment manifests cannot be revalidated as live evidence");
    }
    let roots = DiscoveryRoots::live();
    validate_live_roots(&roots, manifest.deployment_kind)?;
    validate_against_roots(manifest, phase, &roots)
}

pub(crate) fn validate_against_roots(
    manifest: &DeploymentManifest,
    phase: RevalidationPhase,
    roots: &DiscoveryRoots,
) -> Result<LiveIdentityValidation> {
    manifest.validate()?;
    let checked_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let mut mismatches = Vec::new();
    let mut expected_process_exits = Vec::new();
    let boot = String::from_utf8(fs::read(roots.procfs.join("sys/kernel/random/boot_id"))?)
        .context("live boot ID is not UTF-8")?
        .trim()
        .to_owned();
    if boot != manifest.boot_id {
        mismatches.push(ValidationMismatch::BootIdentityChanged {
            expected: manifest.boot_id.clone(),
            observed: boot,
        });
    }

    let limits = DiscoveryLimits {
        max_proc_entries: HARD_MAX_PROCESSES as u32,
        max_cgroup_nodes: HARD_MAX_CGROUP_NODES,
        max_cgroup_depth: HARD_MAX_CGROUP_DEPTH,
        max_open_fds_per_process: HARD_MAX_OPEN_FDS,
    };
    let expected_cgroups = manifest
        .observed_cgroups
        .iter()
        .map(|cgroup| (cgroup.path.clone(), cgroup.cgroup_id))
        .collect::<BTreeMap<_, _>>();
    let mut observed_cgroups = BTreeMap::new();
    let mut live_cgroups = Vec::new();
    for root in &manifest.root_cgroups {
        match enumerate_cgroup_subtree(&root.path, &limits, roots) {
            Ok((_, identities)) => {
                for identity in identities {
                    observed_cgroups.insert(identity.path.clone(), identity.cgroup_id);
                    live_cgroups.push(identity);
                }
            }
            Err(_) => {
                mismatches.push(ValidationMismatch::CgroupMissing {
                    path: root.path.clone(),
                    expected_id: root.cgroup_id,
                });
            }
        }
    }
    let cgroups_requiring_stable_identity = if phase == RevalidationPhase::Ready {
        expected_cgroups.clone()
    } else {
        manifest
            .root_cgroups
            .iter()
            .map(|root| (root.path.clone(), root.cgroup_id))
            .collect()
    };
    for (path, expected_id) in &cgroups_requiring_stable_identity {
        if let Some(observed_id) = observed_cgroups.get(path) {
            if observed_id != expected_id {
                mismatches.push(ValidationMismatch::CgroupIdentityChanged {
                    path: path.clone(),
                    expected_id: *expected_id,
                    observed_id: *observed_id,
                });
            }
        } else {
            mismatches.push(ValidationMismatch::CgroupMissing {
                path: path.clone(),
                expected_id: *expected_id,
            });
        }
    }
    let added_cgroups = observed_cgroups
        .keys()
        .filter(|path| !expected_cgroups.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>();
    let removed_cgroups = expected_cgroups
        .keys()
        .filter(|path| !observed_cgroups.contains_key(*path))
        .cloned()
        .collect::<Vec<_>>();
    if phase == RevalidationPhase::Ready
        && (!added_cgroups.is_empty() || !removed_cgroups.is_empty())
    {
        mismatches.push(ValidationMismatch::CgroupSetChanged {
            added: added_cgroups,
            removed: removed_cgroups,
        });
    }

    let mut observed_processes = BTreeSet::new();
    if mismatches.iter().all(|mismatch| {
        !matches!(
            mismatch,
            ValidationMismatch::CgroupMissing { .. }
                | ValidationMismatch::CgroupIdentityChanged { .. }
        )
    }) {
        let process_cgroups = if phase == RevalidationPhase::Closure {
            &live_cgroups
        } else {
            &manifest.observed_cgroups
        };
        if !process_cgroups.is_empty() {
            observed_processes = enumerate_cgroup_processes(process_cgroups, &limits, roots)?;
        }
    }

    let expected_processes = manifest
        .processes
        .iter()
        .map(|process| process.pid)
        .collect::<BTreeSet<_>>();
    for expected in &manifest.processes {
        match read_process_base(expected.pid, expected.role, roots) {
            Ok(observed) => {
                let fields = changed_process_fields(expected, &observed.identity);
                if !fields.is_empty() {
                    mismatches.push(ValidationMismatch::ProcessIdentityChanged {
                        pid: expected.pid,
                        changed_fields: fields,
                    });
                }
            }
            Err(_) if phase == RevalidationPhase::Closure => {
                expected_process_exits.push(expected.pid);
            }
            Err(_) => {
                mismatches.push(ValidationMismatch::ProcessMissingBeforeReady { pid: expected.pid })
            }
        }
    }
    let added_processes = observed_processes
        .difference(&expected_processes)
        .copied()
        .collect::<Vec<_>>();
    let removed_unexpected = if phase == RevalidationPhase::Ready {
        expected_processes
            .difference(&observed_processes)
            .copied()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if !added_processes.is_empty() || !removed_unexpected.is_empty() {
        mismatches.push(ValidationMismatch::ProcessSetChanged {
            added: added_processes,
            removed_unexpected,
        });
    }

    validate_resources(manifest, phase, roots, &mut mismatches)?;
    expected_process_exits.sort_unstable();
    Ok(LiveIdentityValidation {
        protocol_version: DEPLOYMENT_PROTOCOL_VERSION,
        scope_sha256: manifest.scope_sha256.clone(),
        phase,
        checked_unix_ns,
        stable: mismatches.is_empty(),
        expected_process_exits,
        mismatches,
    })
}

fn changed_process_fields(expected: &ProcessIdentity, observed: &ProcessIdentity) -> Vec<String> {
    let mut fields = Vec::new();
    if expected.start_time_ticks != observed.start_time_ticks {
        fields.push("START_TIME_TICKS".to_owned());
    }
    if expected.comm != observed.comm {
        fields.push("COMM".to_owned());
    }
    if expected.executable_path_bytes_hex != observed.executable_path_bytes_hex
        || expected.executable_device != observed.executable_device
        || expected.executable_inode != observed.executable_inode
    {
        fields.push("EXECUTABLE_IDENTITY".to_owned());
    }
    if expected.cmdline_sha256 != observed.cmdline_sha256 {
        fields.push("CMDLINE_SHA256".to_owned());
    }
    if expected.cgroup_path != observed.cgroup_path || expected.cgroup_id != observed.cgroup_id {
        fields.push("CGROUP_IDENTITY".to_owned());
    }
    if expected.mount_namespace_id != observed.mount_namespace_id {
        fields.push("MOUNT_NAMESPACE_ID".to_owned());
    }
    if expected.pid_namespace_id != observed.pid_namespace_id {
        fields.push("PID_NAMESPACE_ID".to_owned());
    }
    if expected.net_namespace_id != observed.net_namespace_id {
        fields.push("NET_NAMESPACE_ID".to_owned());
    }
    if expected.uts_namespace_id != observed.uts_namespace_id {
        fields.push("UTS_NAMESPACE_ID".to_owned());
    }
    if expected.ipc_namespace_id != observed.ipc_namespace_id {
        fields.push("IPC_NAMESPACE_ID".to_owned());
    }
    if expected.namespace_pid_chain != observed.namespace_pid_chain {
        fields.push("NAMESPACE_PID_CHAIN".to_owned());
    }
    fields
}

fn validate_resources(
    manifest: &DeploymentManifest,
    phase: RevalidationPhase,
    roots: &DiscoveryRoots,
    mismatches: &mut Vec<ValidationMismatch>,
) -> Result<()> {
    let observer_netns = if manifest.deployment_kind == DeploymentKind::KataHost {
        Some(read_namespace_id(
            &roots.procfs.join("self/ns/net"),
            "net",
            roots,
        )?)
    } else {
        None
    };
    for resource in &manifest.kata_host_resources {
        if resource.resolution == ResourceResolutionStatus::Unresolved {
            mismatches.push(ValidationMismatch::ResourceUnresolved {
                owner_pid: resource.owner_pid,
                source_argument_sha256: resource.source_argument_sha256.clone(),
                reason: resource
                    .unresolved_reason
                    .clone()
                    .unwrap_or_else(|| "unresolved resource lacks a reason".to_owned()),
            });
            continue;
        }
        match resource.kind {
            KataResourceKind::VirtualDiskFile | KataResourceKind::VirtualBlockDevice => {
                let encoded = resource
                    .path_bytes_hex
                    .as_deref()
                    .context("disk path missing")?;
                let path = std::path::PathBuf::from(OsString::from_vec(hex::decode(encoded)?));
                let metadata = match fs::metadata(path) {
                    Ok(metadata) => metadata,
                    Err(_) => {
                        mismatches.push(ValidationMismatch::BackendObjectMissing {
                            owner_pid: resource.owner_pid,
                            path_bytes_hex: encoded.to_owned(),
                        });
                        continue;
                    }
                };
                let mut fields = Vec::new();
                if Some(metadata.dev()) != resource.device {
                    fields.push("DEVICE".to_owned());
                }
                if Some(metadata.ino()) != resource.inode {
                    fields.push("INODE".to_owned());
                }
                if Some(metadata.rdev()) != resource.rdev {
                    fields.push("RDEV".to_owned());
                }
                if !fields.is_empty() {
                    mismatches.push(ValidationMismatch::BackendObjectIdentityChanged {
                        owner_pid: resource.owner_pid,
                        path_bytes_hex: encoded.to_owned(),
                        changed_fields: fields,
                    });
                }
            }
            KataResourceKind::TapInterface => {
                let interface = resource
                    .interface_name
                    .as_deref()
                    .context("TAP interface name missing")?;
                let owner_alive = roots.procfs.join(resource.owner_pid.to_string()).exists();
                if matches!(
                    resource.network_binding,
                    Some(KataNetworkBinding::QemuFd | KataNetworkBinding::QemuFds)
                ) && (phase == RevalidationPhase::Ready || owner_alive)
                {
                    for descriptor in &resource.network_file_descriptors {
                        if inspect_tun_fd_interface(resource.owner_pid, *descriptor, roots)
                            .map(|observed| observed != interface)
                            .unwrap_or(true)
                        {
                            mismatches.push(ValidationMismatch::NetworkBackendDescriptorChanged {
                                owner_pid: resource.owner_pid,
                                descriptor: *descriptor,
                                expected_interface_name: interface.to_owned(),
                            });
                        }
                    }
                }
                let expected_netns = resource
                    .net_namespace_id
                    .context("TAP network namespace missing")?;
                if phase == RevalidationPhase::Closure
                    && !owner_alive
                    && Some(expected_netns) != observer_netns
                {
                    // The current protocol intentionally does not retain a
                    // backend netns FD. An expected QEMU exit is therefore
                    // incomplete, but is not fabricated as identity drift.
                    continue;
                }
                let observed = match inspect_tap_interface_in_namespace(
                    resource.owner_pid,
                    expected_netns,
                    observer_netns.context("Observer network namespace missing")?,
                    interface,
                    roots,
                ) {
                    Ok(value) => value,
                    Err(_) => {
                        mismatches.push(ValidationMismatch::NetworkBackendMissing {
                            owner_pid: resource.owner_pid,
                            interface_name: interface.to_owned(),
                        });
                        continue;
                    }
                };
                let expected = resource.interface_index.context("TAP ifindex missing")?;
                if observed != expected {
                    mismatches.push(ValidationMismatch::NetworkBackendIdentityChanged {
                        owner_pid: resource.owner_pid,
                        interface_name: interface.to_owned(),
                        expected_ifindex: expected,
                        observed_ifindex: observed,
                    });
                }
            }
            KataResourceKind::UnresolvedDiskArgument
            | KataResourceKind::UnresolvedNetworkArgument => unreachable!(),
        }
    }
    Ok(())
}
