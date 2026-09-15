// SPDX-License-Identifier: GPL-2.0-only

//! Capability contract for system-effect object resolution.
//!
//! Raw syscall tracepoints can preserve user-supplied arguments, but they do
//! not expose the kernel objects selected by VFS or the socket layer.  The
//! `kernel-file-open-partial` and `kernel-file-open-write-partial` modes are
//! therefore closed, fail-closed capabilities: they may only be
//! enabled after the kernel, recorder object, userspace join/WAL producer, and
//! strict verifier all implement the same attested hook ABI.

use anyhow::{bail, Result};
use clap::ArgEnum;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

const CAPABILITY_SCHEMA_VERSION: u32 = 5;
const MAX_BPF_OBJECT_BYTES: u64 = 16 * 1024 * 1024;
const KERNEL_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const ACTIVE_LSMS_PATH: &str = "/sys/kernel/security/lsm";

// These build capabilities only say that this binary contains the narrow
// file-open producer, WAL ABI, and strict replay implementation. Runtime BTF,
// active BPF LSM, and recorder hook ABI remain independent prerequisites;
// libbpf load/attach is a second fail-closed gate before workload launch.
const KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED: bool = true;
const KERNEL_FILE_OBJECT_WAL_ABI_IMPLEMENTED: bool = true;
const KERNEL_FILE_OBJECT_STRICT_VERIFIER_IMPLEMENTED: bool = true;
const PROCESS_LIFECYCLE_PIPELINE_IMPLEMENTED: bool = true;

const REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS: [&[u8]; 5] = [
    b"effect_object_config\0",
    b"effect_file_objects\0",
    b"lsm.s/file_post_open\0",
    b"trace_effect_file_post_open_object\0",
    b"trace_effect_file_exit\0",
];

const REQUIRED_FILE_OPEN_WRITE_HOOK_ABI_SYMBOLS: [&[u8]; 7] = [
    b"effect_object_config\0",
    b"effect_file_objects\0",
    b"lsm.s/file_post_open\0",
    b"lsm/file_permission\0",
    b"trace_effect_file_post_open_object\0",
    b"trace_effect_file_permission\0",
    b"trace_effect_file_exit\0",
];

const REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS: [&[u8]; 29] = [
    b"effect_object_config\0",
    b"effect_file_objects\0",
    b"effect_socket_objects\0",
    b"effect_socket_state_runs\0",
    b"effect_socket_owners\0",
    b"effect_socket_state_events\0",
    b"trace_effect_expanded_exit\0",
    b"trace_effect_path_mkdir\0",
    b"trace_effect_path_symlink\0",
    b"trace_effect_path_mknod\0",
    b"trace_effect_path_unlink\0",
    b"trace_effect_path_rmdir\0",
    b"trace_effect_path_rename\0",
    b"trace_effect_path_link\0",
    b"trace_effect_path_chmod\0",
    b"trace_effect_path_chown\0",
    b"trace_effect_inode_setxattr\0",
    b"trace_effect_inode_removexattr\0",
    b"trace_effect_mmap_file\0",
    b"lsm/file_mprotect\0",
    b"trace_effect_file_mprotect\0",
    b"trace_effect_socket_connect\0",
    b"trace_effect_socket_bind\0",
    b"fexit/do_accept\0",
    b"trace_effect_do_accept_exit\0",
    b"tp_btf/inet_sock_set_state\0",
    b"trace_effect_inet_sock_set_state\0",
    b"tp_btf/tcp_destroy_sock\0",
    b"trace_effect_tcp_destroy_sock\0",
];

const REQUIRED_LIFECYCLE_HOOK_ABI_SYMBOLS: [&[u8]; 8] = [
    b"effect_lifecycle_runs\0",
    b"effect_lifecycle_events\0",
    b"tp_btf/sched_process_fork\0",
    b"tp_btf/sched_process_exec\0",
    b"tp_btf/sched_process_exit\0",
    b"trace_effect_process_fork\0",
    b"trace_effect_process_exec\0",
    b"trace_effect_process_exit\0",
];

const REQUIRED_KERNEL_CONFIG: [&str; 11] = [
    "CONFIG_BPF=y",
    "CONFIG_BPF_SYSCALL=y",
    "CONFIG_BPF_JIT=y",
    "CONFIG_BPF_EVENTS=y",
    "CONFIG_BPF_LSM=y",
    "CONFIG_CGROUPS=y",
    "CONFIG_SECURITY=y",
    "CONFIG_SECURITY_PATH=y",
    "CONFIG_SECURITYFS=y and securityfs mounted at /sys/kernel/security",
    "CONFIG_DEBUG_INFO_BTF=y",
    "CONFIG_LSM contains bpf (and any boot-time lsm= override retains bpf)",
];

const REQUIRED_BTF_TYPES_AND_FIELDS: [&str; 10] = [
    "struct file.f_path",
    "struct file.f_inode",
    "struct path.mnt",
    "struct mount.mnt",
    "struct mount.mnt_id_unique",
    "struct inode.i_ino",
    "struct inode.i_generation",
    "struct inode.i_sb",
    "struct super_block.s_dev",
    "struct super_block.s_magic",
];

const REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS: [&str; 41] = [
    "struct file.f_path",
    "struct file.f_inode",
    "struct path.mnt",
    "struct path.dentry",
    "struct mount.mnt",
    "struct mount.mnt_id_unique",
    "struct dentry.d_inode",
    "struct inode.i_ino",
    "struct inode.i_generation",
    "struct inode.i_sb",
    "struct super_block.s_dev",
    "struct super_block.s_magic",
    "struct vm_area_struct.vm_flags",
    "struct vm_area_struct.vm_file",
    "struct socket.type",
    "struct socket.sk",
    "struct sock.__sk_common",
    "struct sock.sk_protocol",
    "struct sock.sk_type",
    "struct sock_common.skc_family",
    "struct sock_common.skc_state",
    "struct sock_common.skc_num",
    "struct sock_common.skc_dport",
    "struct sock_common.skc_rcv_saddr",
    "struct sock_common.skc_daddr",
    "struct sock_common.skc_v6_rcv_saddr",
    "struct sock_common.skc_v6_daddr",
    "struct sock_common.skc_bound_dev_if",
    "struct sock_common.skc_net",
    "possible_net_t.net",
    "struct net.net_cookie",
    "struct task_struct.pid",
    "struct task_struct.tgid",
    "struct task_struct.start_boottime",
    "struct task_struct.real_parent",
    "struct task_struct.exit_code",
    "struct task_struct.comm",
    "struct linux_binprm.filename",
    "do_accept(struct file *, struct proto_accept_arg *, struct sockaddr *, int *, int)",
    "BTF typed tracepoint inet_sock_set_state(struct sock *, int, int)",
    "BTF typed tracepoint tcp_destroy_sock(struct sock *)",
];

const REQUIRED_FILE_OPEN_HOOK_FAMILIES: [&str; 3] = [
    "sleepable BPF LSM file_post_open hook for selected ordinary open/openat/openat2/creat calls; it runs after stackable-filesystem backing opens and records the final user-visible struct file, while O_PATH/O_TMPFILE, a missing hook, or a duplicate post-open hook fail evidence closed",
    "raw_syscalls/sys_enter and raw_syscalls/sys_exit correlation",
    "exact cgroup-v2 ID filtering before object reads or event publication",
];

const REQUIRED_FILE_OPEN_WRITE_HOOK_FAMILIES: [&str; 4] = [
    "sleepable BPF LSM file_post_open hook for selected ordinary open/openat/openat2/creat calls; it runs after stackable-filesystem backing opens and records the final user-visible struct file, while O_PATH/O_TMPFILE, a missing hook, or a duplicate post-open hook fail evidence closed",
    "non-sleepable BPF LSM file_permission(MAY_WRITE) hook for positive-byte native write/pwrite64/writev/pwritev/pwritev2 VFS struct file identity, including pipefs/socketfs pseudo-files; missing required hook evidence fails closed, this is not socket-endpoint or persistent-state evidence, and path rendering is not requested on this hook",
    "raw_syscalls/sys_enter and raw_syscalls/sys_exit correlation",
    "exact cgroup-v2 ID and selected resolver filtering before object reads or event publication",
];

const REQUIRED_EXPANDED_HOOK_FAMILIES: [&str; 7] = [
    "file_post_open resolves the final user-visible object after stackable-filesystem backing opens, while file_permission resolves selected positive-byte writes",
    "path/inode BPF LSM hooks for create, unlink, rename, setattr, and xattr evidence",
    "mmap_file BPF LSM hook for selected file-backed shared writable mappings and file_mprotect BPF LSM hook for single shared file-backed VMA write-permission requests; anonymous/private/multi-VMA cases fail closed or are explicitly unsupported",
    "socket_connect and socket_bind BPF LSM hooks with socket-cookie/netns/requested-endpoint evidence",
    "fexit/do_accept accepted-peer resolution plus inet_sock_set_state and tcp_destroy_sock BTF typed tracepoints in an independent fixed-frame TCP-state stream; missing ABI is refused rather than downgraded",
    "sched_process_fork/exec/exit tp_btf lifecycle hooks in a separately attested stream",
    "exact cgroup-v2 and selected resolver gating before object reads or publication",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, ArgEnum, Deserialize, Serialize)]
#[clap(rename_all = "kebab_case")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectResolutionMode {
    UserInput,
    KernelFileOpenPartial,
    KernelFileOpenWritePartial,
    KernelObjectExpandedPartial,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectResolutionCapability {
    pub schema_version: u32,
    pub selected_mode: ObjectResolutionMode,
    pub selected_mode_available: bool,
    pub user_input_only_available: bool,
    pub kernel_file_open_partial: KernelFileOpenPartialCapability,
    pub kernel_file_open_write_partial: KernelFileOpenPartialCapability,
    pub kernel_object_expanded_partial: KernelFileOpenPartialCapability,
}

#[derive(Clone, Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KernelFileOpenPartialCapability {
    pub available: bool,
    pub runtime_kernel_btf_path: String,
    pub runtime_kernel_btf_readable: bool,
    pub runtime_bpf_lsm_state_path: String,
    pub runtime_bpf_lsm_active: bool,
    pub recorder_hook_abi_present: bool,
    pub process_lifecycle_hook_abi_required: bool,
    pub process_lifecycle_hook_abi_present: bool,
    pub userspace_file_open_join_and_producer_implemented: bool,
    pub userspace_file_permission_write_join_and_producer_implemented: bool,
    pub userspace_process_lifecycle_pipeline_implemented: bool,
    pub authoritative_wal_abi_implemented: bool,
    pub strict_verifier_implemented: bool,
    pub required_kernel_config: Vec<String>,
    pub required_btf_types_and_fields: Vec<String>,
    pub required_hook_families: Vec<String>,
    pub blockers: Vec<String>,
}

#[allow(dead_code)]
pub fn inspect(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
) -> ObjectResolutionCapability {
    inspect_with_lifecycle(selected_mode, recorder_object, None)
}

pub fn inspect_with_lifecycle(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
    process_lifecycle_object: Option<&Path>,
) -> ObjectResolutionCapability {
    inspect_at_with_lifecycle(
        selected_mode,
        recorder_object,
        process_lifecycle_object,
        Path::new(KERNEL_BTF_PATH),
        Path::new(ACTIVE_LSMS_PATH),
    )
}

#[allow(dead_code)]
fn inspect_at(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
    kernel_btf_path: &Path,
    active_lsms_path: &Path,
) -> ObjectResolutionCapability {
    inspect_at_with_lifecycle(
        selected_mode,
        recorder_object,
        None,
        kernel_btf_path,
        active_lsms_path,
    )
}

fn inspect_at_with_lifecycle(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
    process_lifecycle_object: Option<&Path>,
    kernel_btf_path: &Path,
    active_lsms_path: &Path,
) -> ObjectResolutionCapability {
    inspect_impl(
        selected_mode,
        recorder_object,
        process_lifecycle_object,
        kernel_btf_path,
        active_lsms_path,
    )
}

pub fn require_available(capability: &ObjectResolutionCapability) -> Result<()> {
    if capability.selected_mode_available {
        return Ok(());
    }
    let blockers = match capability.selected_mode {
        ObjectResolutionMode::UserInput => &[][..],
        ObjectResolutionMode::KernelFileOpenPartial => {
            capability.kernel_file_open_partial.blockers.as_slice()
        }
        ObjectResolutionMode::KernelFileOpenWritePartial => capability
            .kernel_file_open_write_partial
            .blockers
            .as_slice(),
        ObjectResolutionMode::KernelObjectExpandedPartial => capability
            .kernel_object_expanded_partial
            .blockers
            .as_slice(),
    };
    bail!(
        "object-resolution mode {:?} is unavailable and was refused before workload launch: {}",
        capability.selected_mode,
        blockers.join("; ")
    )
}

pub fn selected_mode_detail(capability: &ObjectResolutionCapability) -> String {
    match capability.selected_mode {
        ObjectResolutionMode::UserInput => {
            "USER_INPUT records bounded syscall-entry memory only; it never claims a kernel object identity"
                .to_owned()
        }
        ObjectResolutionMode::KernelFileOpenPartial if capability.selected_mode_available => {
            "KERNEL_FILE_OPEN_PARTIAL prerequisites and its attested hook/WAL/verifier pipeline are available; selected ordinary opens receive the final user-visible file identity from file_post_open after stackable-filesystem backing opens complete; O_PATH/O_TMPFILE and missing or duplicate post-open hooks fail evidence closed; no other operation receives kernel-resolved identity"
                .to_owned()
        }
        ObjectResolutionMode::KernelFileOpenPartial => format!(
            "KERNEL_FILE_OPEN_PARTIAL mode is unavailable: {}",
            capability.kernel_file_open_partial.blockers.join("; ")
        ),
        ObjectResolutionMode::KernelFileOpenWritePartial
            if capability.selected_mode_available =>
        {
            "KERNEL_FILE_OPEN_WRITE_PARTIAL prerequisites and its attested file_post_open+file_permission/WAL/verifier pipeline are available; selected ordinary opens receive the final user-visible file after stackable-filesystem backing opens complete, and positive-byte selected writes seen by file_permission resolve to VFS FILE_OBJECT, including pipefs/socketfs pseudo-files; O_PATH/O_TMPFILE and every missing or duplicate required hook fail evidence closed, and none of this establishes socket endpoints or persistent state"
                .to_owned()
        }
        ObjectResolutionMode::KernelFileOpenWritePartial => format!(
            "KERNEL_FILE_OPEN_WRITE_PARTIAL mode is unavailable: {}",
            capability
                .kernel_file_open_write_partial
                .blockers
                .join("; ")
        ),
        ObjectResolutionMode::KernelObjectExpandedPartial if capability.selected_mode_available => {
            "KERNEL_OBJECT_EXPANDED_PARTIAL has the attested file_post_open/path/inode/mmap/mprotect/socket, accepted-socket/TCP-state, and separate fork/exec/exit lifecycle hook/WAL/verifier pipelines; selected ordinary opens receive the final user-visible file after stackable-filesystem backing opens complete, while O_PATH/O_TMPFILE fail evidence closed; lifecycle evidence is capped at PARTIAL because schema v2 has no authoritative S0 task ledger or cgroup-entry enrollment stream; create hooks identify only the parent (hard-link identifies its source inode in the destination mount), rename identifies only the source, mmap and single-shared-file-VMA mprotect identify permission channels rather than later dirty-page writes, bind/connect identify the kernel-copied requested endpoint, and accept identifies the post-do_accept peer endpoint for AF_INET/AF_INET6 TCP only"
                .to_owned()
        }
        ObjectResolutionMode::KernelObjectExpandedPartial => format!(
            "KERNEL_OBJECT_EXPANDED_PARTIAL mode is unavailable: {}",
            capability.kernel_object_expanded_partial.blockers.join("; ")
        ),
    }
}

fn inspect_impl(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
    process_lifecycle_object: Option<&Path>,
    kernel_btf_path: &Path,
    active_lsms_path: &Path,
) -> ObjectResolutionCapability {
    let runtime_kernel_btf_readable = readable_nonempty_regular_file(kernel_btf_path);
    let runtime_bpf_lsm_active = read_active_lsms(active_lsms_path)
        .map(|lsms| lsms.iter().any(|lsm| lsm == "bpf"))
        .unwrap_or(false);
    let recorder_bytes = recorder_object.and_then(read_bounded_regular_file);
    let file_open_hook_abi_present = recorder_bytes
        .as_deref()
        .map(|bytes| has_required_hook_abi(bytes, &REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS))
        .unwrap_or(false);
    let file_open_write_hook_abi_present = recorder_bytes
        .as_deref()
        .map(|bytes| has_required_hook_abi(bytes, &REQUIRED_FILE_OPEN_WRITE_HOOK_ABI_SYMBOLS))
        .unwrap_or(false);
    let expanded_hook_abi_present = recorder_bytes
        .as_deref()
        .map(|bytes| has_required_hook_abi(bytes, &REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS))
        .unwrap_or(false);
    let lifecycle_hook_abi_present = process_lifecycle_object
        .and_then(read_bounded_regular_file)
        .as_deref()
        .map(|bytes| has_required_hook_abi(bytes, &REQUIRED_LIFECYCLE_HOOK_ABI_SYMBOLS))
        .unwrap_or(false);

    let open_capability = build_kernel_file_capability(
        kernel_btf_path,
        active_lsms_path,
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_active,
        file_open_hook_abi_present,
        CapabilityRequirements {
            includes_file_permission_write: false,
            hook_families: &REQUIRED_FILE_OPEN_HOOK_FAMILIES,
            btf_types_and_fields: &REQUIRED_BTF_TYPES_AND_FIELDS,
            missing_recorder_hook_message:
                "the selected recorder ELF lacks the complete file_post_open object hook ABI",
            process_lifecycle_hook_abi_required: false,
            process_lifecycle_hook_abi_present: false,
        },
    );
    let open_write_capability = build_kernel_file_capability(
        kernel_btf_path,
        active_lsms_path,
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_active,
        file_open_write_hook_abi_present,
        CapabilityRequirements {
            includes_file_permission_write: true,
            hook_families: &REQUIRED_FILE_OPEN_WRITE_HOOK_FAMILIES,
            btf_types_and_fields: &REQUIRED_BTF_TYPES_AND_FIELDS,
            missing_recorder_hook_message:
                "the selected recorder ELF lacks the complete file_post_open+file_permission object hook ABI",
            process_lifecycle_hook_abi_required: false,
            process_lifecycle_hook_abi_present: false,
        },
    );
    let expanded_capability = build_kernel_file_capability(
        kernel_btf_path,
        active_lsms_path,
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_active,
        file_open_write_hook_abi_present && expanded_hook_abi_present,
        CapabilityRequirements {
            includes_file_permission_write: true,
            hook_families: &REQUIRED_EXPANDED_HOOK_FAMILIES,
            btf_types_and_fields: &REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS,
            missing_recorder_hook_message:
                "the selected recorder ELF lacks the complete expanded path/inode/mmap/mprotect/socket/accept/TCP-state hook ABI",
            process_lifecycle_hook_abi_required: true,
            process_lifecycle_hook_abi_present: lifecycle_hook_abi_present,
        },
    );
    let selected_mode_available = match selected_mode {
        ObjectResolutionMode::UserInput => true,
        ObjectResolutionMode::KernelFileOpenPartial => open_capability.available,
        ObjectResolutionMode::KernelFileOpenWritePartial => open_write_capability.available,
        ObjectResolutionMode::KernelObjectExpandedPartial => expanded_capability.available,
    };
    ObjectResolutionCapability {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        selected_mode,
        selected_mode_available,
        user_input_only_available: true,
        kernel_file_open_partial: open_capability,
        kernel_file_open_write_partial: open_write_capability,
        kernel_object_expanded_partial: expanded_capability,
    }
}

struct CapabilityRequirements<'a> {
    includes_file_permission_write: bool,
    hook_families: &'a [&'a str],
    btf_types_and_fields: &'a [&'a str],
    missing_recorder_hook_message: &'a str,
    process_lifecycle_hook_abi_required: bool,
    process_lifecycle_hook_abi_present: bool,
}

fn build_kernel_file_capability(
    kernel_btf_path: &Path,
    active_lsms_path: &Path,
    runtime_kernel_btf_readable: bool,
    runtime_bpf_lsm_active: bool,
    recorder_hook_abi_present: bool,
    requirements: CapabilityRequirements<'_>,
) -> KernelFileOpenPartialCapability {
    let mut blockers = Vec::new();
    if !runtime_kernel_btf_readable {
        blockers.push(format!(
            "runtime kernel BTF is absent, empty, non-regular, or unreadable at {}",
            kernel_btf_path.display()
        ));
    }
    if !runtime_bpf_lsm_active {
        blockers.push(format!(
            "the active LSM list at {} does not prove that bpf is active",
            active_lsms_path.display()
        ));
    }
    if !recorder_hook_abi_present {
        blockers.push(requirements.missing_recorder_hook_message.to_owned());
    }
    if requirements.process_lifecycle_hook_abi_required
        && !requirements.process_lifecycle_hook_abi_present
    {
        blockers.push(
            "the selected process-lifecycle ELF lacks the required fork/exec/exit hook ABI"
                .to_owned(),
        );
    }
    if !KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED {
        blockers.push(
            "this observer build has no kernel-object hook load/join/producer implementation"
                .to_owned(),
        );
    }
    if !KERNEL_FILE_OBJECT_WAL_ABI_IMPLEMENTED {
        blockers.push(
            "the authoritative binary WAL has no kernel-object evidence record ABI".to_owned(),
        );
    }
    if !KERNEL_FILE_OBJECT_STRICT_VERIFIER_IMPLEMENTED {
        blockers.push(
            "verify-effects cannot derive KERNEL_RESOLVED evidence from the authoritative WAL"
                .to_owned(),
        );
    }
    let available = runtime_kernel_btf_readable
        && runtime_bpf_lsm_active
        && recorder_hook_abi_present
        && (!requirements.process_lifecycle_hook_abi_required
            || requirements.process_lifecycle_hook_abi_present)
        && KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED
        && KERNEL_FILE_OBJECT_WAL_ABI_IMPLEMENTED
        && KERNEL_FILE_OBJECT_STRICT_VERIFIER_IMPLEMENTED;
    KernelFileOpenPartialCapability {
        available,
        runtime_kernel_btf_path: kernel_btf_path.display().to_string(),
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_state_path: active_lsms_path.display().to_string(),
        runtime_bpf_lsm_active,
        recorder_hook_abi_present,
        process_lifecycle_hook_abi_required: requirements.process_lifecycle_hook_abi_required,
        process_lifecycle_hook_abi_present: requirements.process_lifecycle_hook_abi_present,
        userspace_file_open_join_and_producer_implemented: KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED,
        userspace_file_permission_write_join_and_producer_implemented: requirements
            .includes_file_permission_write
            && KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED,
        userspace_process_lifecycle_pipeline_implemented: requirements
            .process_lifecycle_hook_abi_required
            && PROCESS_LIFECYCLE_PIPELINE_IMPLEMENTED,
        authoritative_wal_abi_implemented: KERNEL_FILE_OBJECT_WAL_ABI_IMPLEMENTED,
        strict_verifier_implemented: KERNEL_FILE_OBJECT_STRICT_VERIFIER_IMPLEMENTED,
        required_kernel_config: REQUIRED_KERNEL_CONFIG
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required_btf_types_and_fields: requirements
            .btf_types_and_fields
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required_hook_families: requirements
            .hook_families
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        blockers,
    }
}

fn readable_nonempty_regular_file(path: &Path) -> bool {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return false,
    };
    metadata.file_type().is_file() && metadata.len() != 0 && File::open(path).is_ok()
}

fn read_active_lsms(path: &Path) -> Option<Vec<String>> {
    let value = fs::read_to_string(path).ok()?;
    Some(
        value
            .trim()
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

fn read_bounded_regular_file(path: &Path) -> Option<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > MAX_BPF_OBJECT_BYTES
    {
        return None;
    }
    let file = File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(MAX_BPF_OBJECT_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() as u64 > MAX_BPF_OBJECT_BYTES {
        return None;
    }
    Some(bytes)
}

fn has_required_hook_abi(bytes: &[u8], required: &[&[u8]]) -> bool {
    required
        .iter()
        .all(|symbol| bytes.windows(symbol.len()).any(|window| window == *symbol))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_input_mode_remains_available_without_kernel_prerequisites() {
        let capability = inspect_at(
            ObjectResolutionMode::UserInput,
            None,
            Path::new("/definitely-absent/btf"),
            Path::new("/definitely-absent/lsm"),
        );
        assert!(capability.selected_mode_available);
        assert!(!capability.kernel_file_open_partial.available);
        assert!(require_available(&capability).is_ok());
    }

    #[test]
    fn kernel_mode_fails_closed_without_active_lsm_and_recorder_hook_abi() {
        let capability = inspect_at(
            ObjectResolutionMode::KernelFileOpenPartial,
            None,
            Path::new("/proc/self/status"),
            Path::new("/proc/self/status"),
        );
        assert!(!capability.selected_mode_available);
        let error = require_available(&capability).unwrap_err().to_string();
        assert!(error.contains("refused before workload launch"));
        assert!(error.contains("does not prove that bpf is active"));
        assert!(error.contains("lacks the complete file_post_open object hook ABI"));
        assert!(
            capability
                .kernel_file_open_partial
                .userspace_file_open_join_and_producer_implemented
        );
        assert!(
            capability
                .kernel_file_open_partial
                .authoritative_wal_abi_implemented
        );
        assert!(
            capability
                .kernel_file_open_partial
                .strict_verifier_implemented
        );
    }

    #[test]
    fn kernel_file_open_partial_is_available_only_with_all_static_prerequisites() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/object-resolution-capability-test")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let btf = root.join("vmlinux.btf");
        let lsms = root.join("lsm");
        let recorder = root.join("system_effects.bpf.o");
        fs::write(&btf, b"bounded fake BTF for prerequisite test").unwrap();
        fs::write(&lsms, b"lockdown,yama,bpf\n").unwrap();
        fs::write(&recorder, REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS.concat()).unwrap();

        let capability = inspect_at(
            ObjectResolutionMode::KernelFileOpenPartial,
            Some(&recorder),
            &btf,
            &lsms,
        );
        assert!(capability.selected_mode_available);
        assert!(capability.kernel_file_open_partial.available);
        assert!(capability.kernel_file_open_partial.blockers.is_empty());
        require_available(&capability).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hook_abi_requires_every_nul_terminated_symbol() {
        let complete = REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS.concat();
        assert!(has_required_hook_abi(
            &complete,
            &REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS
        ));
        assert!(!has_required_hook_abi(
            &REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS[..3].concat(),
            &REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS
        ));
    }

    #[test]
    fn write_mode_requires_file_permission_hook_in_addition_to_open_hooks() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/object-resolution-write-capability-test")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let btf = root.join("vmlinux.btf");
        let lsms = root.join("lsm");
        let recorder = root.join("system_effects.bpf.o");
        fs::write(&btf, b"bounded fake BTF for prerequisite test").unwrap();
        fs::write(&lsms, b"lockdown,yama,bpf\n").unwrap();
        fs::write(&recorder, REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS.concat()).unwrap();

        let open = inspect_at(
            ObjectResolutionMode::KernelFileOpenPartial,
            Some(&recorder),
            &btf,
            &lsms,
        );
        assert!(open.selected_mode_available);
        let write = inspect_at(
            ObjectResolutionMode::KernelFileOpenWritePartial,
            Some(&recorder),
            &btf,
            &lsms,
        );
        assert!(!write.selected_mode_available);
        assert!(write.kernel_file_open_write_partial.blockers[0]
            .contains("file_post_open+file_permission"));

        fs::write(
            &recorder,
            REQUIRED_FILE_OPEN_WRITE_HOOK_ABI_SYMBOLS.concat(),
        )
        .unwrap();
        let write = inspect_at(
            ObjectResolutionMode::KernelFileOpenWritePartial,
            Some(&recorder),
            &btf,
            &lsms,
        );
        assert!(write.selected_mode_available);
        assert!(
            write
                .kernel_file_open_write_partial
                .userspace_file_permission_write_join_and_producer_implemented
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expanded_mode_requires_its_exact_recorder_and_lifecycle_abis() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/object-resolution-expanded-capability-test")
            .join(std::process::id().to_string());
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let btf = root.join("vmlinux.btf");
        let lsms = root.join("lsm");
        let recorder = root.join("system_effects.bpf.o");
        let lifecycle = root.join("process_lifecycle.bpf.o");
        fs::write(&btf, b"bounded fake BTF for prerequisite test").unwrap();
        fs::write(&lsms, b"lockdown,yama,bpf\n").unwrap();
        fs::write(
            &recorder,
            [
                REQUIRED_FILE_OPEN_WRITE_HOOK_ABI_SYMBOLS.as_slice(),
                REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS.as_slice(),
            ]
            .concat()
            .concat(),
        )
        .unwrap();

        let missing_lifecycle = inspect_at_with_lifecycle(
            ObjectResolutionMode::KernelObjectExpandedPartial,
            Some(&recorder),
            None,
            &btf,
            &lsms,
        );
        assert!(!missing_lifecycle.selected_mode_available);
        assert!(
            missing_lifecycle
                .kernel_object_expanded_partial
                .recorder_hook_abi_present
        );
        assert!(missing_lifecycle
            .kernel_object_expanded_partial
            .blockers
            .iter()
            .any(|blocker| blocker.contains("process-lifecycle ELF")));
        assert!(!missing_lifecycle
            .kernel_object_expanded_partial
            .blockers
            .iter()
            .any(|blocker| blocker.contains("file_post_open+file_permission")));

        fs::write(&lifecycle, REQUIRED_LIFECYCLE_HOOK_ABI_SYMBOLS.concat()).unwrap();
        let complete = inspect_at_with_lifecycle(
            ObjectResolutionMode::KernelObjectExpandedPartial,
            Some(&recorder),
            Some(&lifecycle),
            &btf,
            &lsms,
        );
        assert!(complete.selected_mode_available);
        assert!(
            complete
                .kernel_object_expanded_partial
                .process_lifecycle_hook_abi_present
        );
        assert!(
            complete
                .kernel_object_expanded_partial
                .userspace_process_lifecycle_pipeline_implemented
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_lsm_matching_uses_whole_tokens() {
        let parse = |value: &str| {
            value
                .trim()
                .split(',')
                .map(str::trim)
                .any(|item| item == "bpf")
        };
        assert!(parse("lockdown,yama,bpf\n"));
        assert!(!parse("lockdown,notbpf,yama\n"));
    }

    #[test]
    fn capability_contract_lists_required_identity_fields() {
        assert!(REQUIRED_KERNEL_CONFIG.contains(&"CONFIG_DEBUG_INFO_BTF=y"));
        assert!(REQUIRED_KERNEL_CONFIG.contains(&"CONFIG_BPF_JIT=y"));
        assert!(REQUIRED_BTF_TYPES_AND_FIELDS.contains(&"struct mount.mnt_id_unique"));
        assert!(REQUIRED_BTF_TYPES_AND_FIELDS.contains(&"struct file.f_path"));
        assert!(REQUIRED_BTF_TYPES_AND_FIELDS.contains(&"struct inode.i_generation"));
        assert!(!REQUIRED_BTF_TYPES_AND_FIELDS
            .iter()
            .any(|item| item.contains("socket")));
        assert!(REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct socket.sk"));
        assert!(
            REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct sock.skc_family")
                || REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS
                    .contains(&"struct sock_common.skc_family")
        );
        assert!(
            REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct task_struct.start_boottime")
        );
        assert!(REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct linux_binprm.filename"));
        assert!(
            REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS.contains(&b"trace_effect_path_link\0".as_slice())
        );
        assert!(REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS
            .contains(&b"trace_effect_do_accept_exit\0".as_slice()));
        assert!(
            REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS.contains(&b"tp_btf/tcp_destroy_sock\0".as_slice())
        );
        assert!(REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct sock_common.skc_state"));
        assert!(REQUIRED_EXPANDED_BTF_TYPES_AND_FIELDS.contains(&"struct vm_area_struct.vm_file"));
        assert!(REQUIRED_EXPANDED_HOOK_ABI_SYMBOLS
            .contains(&b"trace_effect_file_mprotect\0".as_slice()));
    }
}
