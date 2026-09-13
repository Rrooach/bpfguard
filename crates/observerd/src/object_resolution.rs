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

const CAPABILITY_SCHEMA_VERSION: u32 = 2;
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

const REQUIRED_FILE_OPEN_HOOK_ABI_SYMBOLS: [&[u8]; 5] = [
    b"effect_object_config\0",
    b"effect_file_objects\0",
    b"lsm.s/file_open\0",
    b"trace_effect_file_object\0",
    b"trace_effect_file_exit\0",
];

const REQUIRED_FILE_OPEN_WRITE_HOOK_ABI_SYMBOLS: [&[u8]; 7] = [
    b"effect_object_config\0",
    b"effect_file_objects\0",
    b"lsm.s/file_open\0",
    b"lsm/file_permission\0",
    b"trace_effect_file_object\0",
    b"trace_effect_file_permission\0",
    b"trace_effect_file_exit\0",
];

const REQUIRED_KERNEL_CONFIG: [&str; 10] = [
    "CONFIG_BPF=y",
    "CONFIG_BPF_SYSCALL=y",
    "CONFIG_BPF_JIT=y",
    "CONFIG_BPF_EVENTS=y",
    "CONFIG_BPF_LSM=y",
    "CONFIG_CGROUPS=y",
    "CONFIG_SECURITY=y",
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

const REQUIRED_FILE_OPEN_HOOK_FAMILIES: [&str; 3] = [
    "sleepable BPF LSM file_open hook for selected open/openat/openat2/creat calls; a missing hook result (including unsupported O_PATH) or a duplicate stacked-filesystem hook fails evidence closed",
    "raw_syscalls/sys_enter and raw_syscalls/sys_exit correlation",
    "exact cgroup-v2 ID filtering before object reads or event publication",
];

const REQUIRED_FILE_OPEN_WRITE_HOOK_FAMILIES: [&str; 4] = [
    "sleepable BPF LSM file_open hook for selected open/openat/openat2/creat calls; a missing hook result (including unsupported O_PATH) or a duplicate stacked-filesystem hook fails evidence closed",
    "non-sleepable BPF LSM file_permission(MAY_WRITE) hook for positive-byte native write/pwrite64/writev/pwritev/pwritev2 VFS struct file identity, including pipefs/socketfs pseudo-files; missing required hook evidence fails closed, this is not socket-endpoint or persistent-state evidence, and path rendering is not requested on this hook",
    "raw_syscalls/sys_enter and raw_syscalls/sys_exit correlation",
    "exact cgroup-v2 ID and selected resolver filtering before object reads or event publication",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, ArgEnum, Deserialize, Serialize)]
#[clap(rename_all = "kebab_case")]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObjectResolutionMode {
    UserInput,
    KernelFileOpenPartial,
    KernelFileOpenWritePartial,
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
    pub userspace_file_open_join_and_producer_implemented: bool,
    pub userspace_file_permission_write_join_and_producer_implemented: bool,
    pub authoritative_wal_abi_implemented: bool,
    pub strict_verifier_implemented: bool,
    pub required_kernel_config: Vec<String>,
    pub required_btf_types_and_fields: Vec<String>,
    pub required_hook_families: Vec<String>,
    pub blockers: Vec<String>,
}

pub fn inspect(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
) -> ObjectResolutionCapability {
    inspect_at(
        selected_mode,
        recorder_object,
        Path::new(KERNEL_BTF_PATH),
        Path::new(ACTIVE_LSMS_PATH),
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
            "KERNEL_FILE_OPEN_PARTIAL prerequisites and its attested hook/WAL/verifier pipeline are available; selected opens that traverse exactly one file_open hook receive identity, while missing hooks (including unsupported O_PATH) and duplicate stacked-filesystem hooks fail evidence closed; no other operation receives kernel-resolved identity"
                .to_owned()
        }
        ObjectResolutionMode::KernelFileOpenPartial => format!(
            "KERNEL_FILE_OPEN_PARTIAL mode is unavailable: {}",
            capability.kernel_file_open_partial.blockers.join("; ")
        ),
        ObjectResolutionMode::KernelFileOpenWritePartial
            if capability.selected_mode_available =>
        {
            "KERNEL_FILE_OPEN_WRITE_PARTIAL prerequisites and its attested file_open+file_permission/WAL/verifier pipeline are available; selected opens that traverse exactly one file_open hook and positive-byte selected writes seen by file_permission resolve to VFS FILE_OBJECT, including pipefs/socketfs pseudo-files; every missing required hook (including unsupported O_PATH) and duplicate stacked-filesystem open hook fails evidence closed, and none of this establishes socket endpoints or persistent state"
                .to_owned()
        }
        ObjectResolutionMode::KernelFileOpenWritePartial => format!(
            "KERNEL_FILE_OPEN_WRITE_PARTIAL mode is unavailable: {}",
            capability
                .kernel_file_open_write_partial
                .blockers
                .join("; ")
        ),
    }
}

fn inspect_at(
    selected_mode: ObjectResolutionMode,
    recorder_object: Option<&Path>,
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

    let open_capability = build_kernel_file_capability(
        kernel_btf_path,
        active_lsms_path,
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_active,
        file_open_hook_abi_present,
        false,
        &REQUIRED_FILE_OPEN_HOOK_FAMILIES,
    );
    let open_write_capability = build_kernel_file_capability(
        kernel_btf_path,
        active_lsms_path,
        runtime_kernel_btf_readable,
        runtime_bpf_lsm_active,
        file_open_write_hook_abi_present,
        true,
        &REQUIRED_FILE_OPEN_WRITE_HOOK_FAMILIES,
    );
    let selected_mode_available = match selected_mode {
        ObjectResolutionMode::UserInput => true,
        ObjectResolutionMode::KernelFileOpenPartial => open_capability.available,
        ObjectResolutionMode::KernelFileOpenWritePartial => open_write_capability.available,
    };
    ObjectResolutionCapability {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        selected_mode,
        selected_mode_available,
        user_input_only_available: true,
        kernel_file_open_partial: open_capability,
        kernel_file_open_write_partial: open_write_capability,
    }
}

fn build_kernel_file_capability(
    kernel_btf_path: &Path,
    active_lsms_path: &Path,
    runtime_kernel_btf_readable: bool,
    runtime_bpf_lsm_active: bool,
    recorder_hook_abi_present: bool,
    includes_file_permission_write: bool,
    required_hook_families: &[&str],
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
        blockers.push(if includes_file_permission_write {
            "the selected recorder ELF lacks the complete file_open+file_permission object hook ABI"
                .to_owned()
        } else {
            "the selected recorder ELF lacks the complete file_open object hook ABI".to_owned()
        });
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
        userspace_file_open_join_and_producer_implemented: KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED,
        userspace_file_permission_write_join_and_producer_implemented:
            includes_file_permission_write && KERNEL_FILE_OBJECT_PIPELINE_IMPLEMENTED,
        authoritative_wal_abi_implemented: KERNEL_FILE_OBJECT_WAL_ABI_IMPLEMENTED,
        strict_verifier_implemented: KERNEL_FILE_OBJECT_STRICT_VERIFIER_IMPLEMENTED,
        required_kernel_config: REQUIRED_KERNEL_CONFIG
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required_btf_types_and_fields: REQUIRED_BTF_TYPES_AND_FIELDS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        required_hook_families: required_hook_families
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
        assert!(error.contains("lacks the complete file_open object hook ABI"));
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
        assert!(
            write.kernel_file_open_write_partial.blockers[0].contains("file_open+file_permission")
        );

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
    }
}
