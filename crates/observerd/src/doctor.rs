// SPDX-License-Identifier: GPL-2.0-only

use crate::{
    cgroup,
    object_resolution::{self, ObjectResolutionCapability, ObjectResolutionMode},
};

use serde::Serialize;
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Read;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

const MAX_RECORDER_OBJECT_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub ready_for_runtime: bool,
    pub checks: Vec<DoctorCheck>,
    pub object_resolution: ObjectResolutionCapability,
}

#[derive(Debug, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
}

pub fn inspect(
    bpf_object: Option<&Path>,
    cgroup_root: &Path,
    object_resolution_mode: ObjectResolutionMode,
) -> DoctorReport {
    let object_resolution = object_resolution::inspect(object_resolution_mode, bpf_object);
    let mut checks = vec![
        cgroup_v2_filesystem_check(Path::new("/sys/fs/cgroup")),
        any_exists_check(
            "raw_syscalls_sys_enter",
            &[
                Path::new("/sys/kernel/tracing/events/raw_syscalls/sys_enter/id"),
                Path::new("/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/id"),
            ],
            true,
        ),
        any_exists_check(
            "raw_syscalls_sys_exit",
            &[
                Path::new("/sys/kernel/tracing/events/raw_syscalls/sys_exit/id"),
                Path::new("/sys/kernel/debug/tracing/events/raw_syscalls/sys_exit/id"),
            ],
            true,
        ),
        exists_check("kernel_btf", Path::new("/sys/kernel/btf/vmlinux"), false),
        bpffs_check(),
        capability_check(),
        inventory_access_check(),
        tracepoint_perf_access_check(),
        cgroup_root_check(cgroup_root),
        object_resolution_mode_check(&object_resolution),
    ];
    if let Some(object) = bpf_object {
        checks.push(recorder_object_check(object));
    }
    let ready_for_runtime = checks.iter().all(|check| check.status != CheckStatus::Fail);
    DoctorReport {
        ready_for_runtime,
        checks,
        object_resolution,
    }
}

fn object_resolution_mode_check(capability: &ObjectResolutionCapability) -> DoctorCheck {
    DoctorCheck {
        name: "selected_object_resolution_mode".into(),
        status: if capability.selected_mode_available {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: object_resolution::selected_mode_detail(capability),
    }
}

fn recorder_object_check(path: &Path) -> DoctorCheck {
    let result = (|| -> Result<(), String> {
        let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
        if !metadata.file_type().is_file() {
            return Err("path is not a regular file".into());
        }
        if metadata.len() == 0 || metadata.len() > MAX_RECORDER_OBJECT_BYTES {
            return Err(format!(
                "file size must be in 1..={MAX_RECORDER_OBJECT_BYTES} bytes"
            ));
        }
        let file = File::open(path).map_err(|error| error.to_string())?;
        let mut bytes = Vec::new();
        file.take(MAX_RECORDER_OBJECT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_RECORDER_OBJECT_BYTES {
            return Err("file grew beyond the recorder-object size limit".into());
        }
        if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" || bytes[4] != 2 {
            return Err("not a 64-bit ELF object".into());
        }
        let machine = match bytes[5] {
            1 => u16::from_le_bytes([bytes[18], bytes[19]]),
            2 => u16::from_be_bytes([bytes[18], bytes[19]]),
            _ => return Err("ELF has an unsupported byte order".into()),
        };
        if machine != 247 {
            return Err(format!("ELF e_machine is {machine}, expected EM_BPF (247)"));
        }
        let bpf_state_symbols = [
            b"trace_bpf_enter\0".as_slice(),
            b"trace_bpf_exit\0".as_slice(),
            b"recorder_config\0".as_slice(),
            b"run_states\0".as_slice(),
            b"pending_calls\0".as_slice(),
            b"events\0".as_slice(),
        ];
        let system_effect_symbols = [
            b"trace_effect_enter\0".as_slice(),
            b"trace_effect_exit\0".as_slice(),
            b"effect_policy\0".as_slice(),
            b"effect_runs\0".as_slice(),
            b"effect_pending\0".as_slice(),
            b"effect_events\0".as_slice(),
        ];
        let has_all = |symbols: &[&[u8]]| {
            symbols
                .iter()
                .all(|symbol| bytes.windows(symbol.len()).any(|window| window == *symbol))
        };
        if has_all(&bpf_state_symbols) || has_all(&system_effect_symbols) {
            Ok(())
        } else {
            Err(
                "ELF has neither the complete BPF-state nor system-effect recorder symbol set"
                    .to_owned(),
            )
        }
    })();
    match result {
        Ok(()) => DoctorCheck {
            name: "recorder_object".into(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} is an EM_BPF ELF with a supported recorder symbol set",
                path.display()
            ),
        },
        Err(error) => DoctorCheck {
            name: "recorder_object".into(),
            status: CheckStatus::Fail,
            detail: format!("{}: {error}", path.display()),
        },
    }
}

#[repr(C)]
#[derive(Default)]
struct PerfEventAttrV0 {
    type_: u32,
    size: u32,
    config: u64,
    sample_period: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events: u32,
    bp_type: u32,
    config1: u64,
}

fn tracepoint_perf_access_check() -> DoctorCheck {
    const PERF_TYPE_TRACEPOINT: u32 = 2;
    const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;
    let id_path = [
        Path::new("/sys/kernel/tracing/events/raw_syscalls/sys_enter/id"),
        Path::new("/sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/id"),
    ]
    .into_iter()
    .find(|path| path.exists());
    let Some(id_path) = id_path else {
        return DoctorCheck {
            name: "raw_syscalls_perf_access".into(),
            status: CheckStatus::Fail,
            detail: "raw_syscalls/sys_enter tracepoint ID is unavailable".into(),
        };
    };
    let id_text = match fs::read_to_string(id_path) {
        Ok(text) => text,
        Err(error) => {
            return DoctorCheck {
                name: "raw_syscalls_perf_access".into(),
                status: CheckStatus::Fail,
                detail: format!(
                    "cannot read tracepoint ID from {}: {error}",
                    id_path.display()
                ),
            }
        }
    };
    let id = match id_text.trim().parse::<u64>() {
        Ok(id) => id,
        Err(error) => {
            return DoctorCheck {
                name: "raw_syscalls_perf_access".into(),
                status: CheckStatus::Fail,
                detail: format!(
                    "cannot parse tracepoint ID from {}: {error}",
                    id_path.display()
                ),
            }
        }
    };
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu < 0 {
        return DoctorCheck {
            name: "raw_syscalls_perf_access".into(),
            status: CheckStatus::Fail,
            detail: format!("sched_getcpu failed: {}", std::io::Error::last_os_error()),
        };
    }
    let attr = PerfEventAttrV0 {
        type_: PERF_TYPE_TRACEPOINT,
        size: mem::size_of::<PerfEventAttrV0>() as u32,
        config: id,
        // bit 0 is `disabled`; no samples are enabled by this smoke check.
        flags: 1,
        ..PerfEventAttrV0::default()
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_perf_event_open,
            &attr as *const PerfEventAttrV0,
            -1i32,
            cpu,
            -1i32,
            PERF_FLAG_FD_CLOEXEC,
        ) as libc::c_int
    };
    if fd < 0 {
        DoctorCheck {
            name: "raw_syscalls_perf_access".into(),
            status: CheckStatus::Fail,
            detail: format!(
                "system-wide tracepoint perf_event_open failed: {}",
                std::io::Error::last_os_error()
            ),
        }
    } else {
        unsafe { libc::close(fd) };
        DoctorCheck {
            name: "raw_syscalls_perf_access".into(),
            status: CheckStatus::Pass,
            detail: format!("disabled raw_syscalls tracepoint event opened on CPU {cpu}"),
        }
    }
}

fn cgroup_root_check(path: &Path) -> DoctorCheck {
    let mut existing = Some(path);
    while let Some(candidate) = existing {
        if candidate.exists() {
            let on_v2 = cgroup::is_cgroup2_filesystem(candidate).unwrap_or(false);
            let freezer = candidate.join("cgroup.freeze").exists();
            let kill = candidate.join("cgroup.kill").exists();
            let c_path = CString::new(candidate.as_os_str().as_bytes());
            let writable = c_path
                .ok()
                .map(|value| unsafe { libc::access(value.as_ptr(), libc::W_OK | libc::X_OK) == 0 })
                .unwrap_or(false);
            return DoctorCheck {
                name: "cgroup_root_access".into(),
                // cgroup.freeze/cgroup.kill availability is authoritative only
                // on the non-root run cgroup that observe creates. Some kernels
                // omit controllers from the hierarchy root, so this read-only
                // preflight reports the ancestor state but does not reject it.
                // ManagedCgroup::create checks both files on the actual child.
                status: if on_v2 && writable {
                    CheckStatus::Pass
                } else {
                    CheckStatus::Fail
                },
                detail: format!(
                    "requested root {}; nearest existing ancestor {} (cgroup_v2={on_v2}, writable={writable}, freezer={freezer}, kill={kill})",
                    path.display(),
                    candidate.display()
                ),
            };
        }
        existing = candidate.parent();
    }
    DoctorCheck {
        name: "cgroup_root_access".into(),
        status: CheckStatus::Fail,
        detail: format!("no existing ancestor for {}", path.display()),
    }
}

fn cgroup_v2_filesystem_check(path: &Path) -> DoctorCheck {
    let filesystem_is_v2 = cgroup::is_cgroup2_filesystem(path).unwrap_or(false);
    let controllers = path.join("cgroup.controllers").is_file();
    DoctorCheck {
        name: "cgroup_v2".into(),
        status: if filesystem_is_v2 && controllers {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: format!(
            "{} (cgroup2_statfs={filesystem_is_v2}, controllers_interface={controllers})",
            path.display()
        ),
    }
}

fn exists_check(name: &str, path: &Path, required: bool) -> DoctorCheck {
    if path.exists() {
        DoctorCheck {
            name: name.into(),
            status: CheckStatus::Pass,
            detail: path.display().to_string(),
        }
    } else {
        DoctorCheck {
            name: name.into(),
            status: if required {
                CheckStatus::Fail
            } else {
                CheckStatus::Warning
            },
            detail: format!("{} is absent", path.display()),
        }
    }
}

fn any_exists_check(name: &str, paths: &[&Path], required: bool) -> DoctorCheck {
    for path in paths {
        if path.exists() {
            return exists_check(name, path, required);
        }
    }
    DoctorCheck {
        name: name.into(),
        status: if required {
            CheckStatus::Fail
        } else {
            CheckStatus::Warning
        },
        detail: paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(" or "),
    }
}

fn bpffs_check() -> DoctorCheck {
    let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap_or_default();
    let mounted = mounts.lines().any(|line| {
        line.split_once(" - ")
            .and_then(|(_, tail)| tail.split_whitespace().next())
            == Some("bpf")
    });
    DoctorCheck {
        name: "bpffs".into(),
        status: if mounted {
            CheckStatus::Pass
        } else {
            CheckStatus::Warning
        },
        detail: if mounted {
            "at least one bpffs mount is visible".into()
        } else {
            "no bpffs mount is visible; pin scopes must remain empty".into()
        },
    }
}

fn capability_check() -> DoctorCheck {
    const CAP_SYS_ADMIN: u32 = 21;
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let effective = status
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|hex| u64::from_str_radix(hex.trim(), 16).ok())
        .unwrap_or(0);
    let has = |cap: u32| effective & (1u64 << cap) != 0;
    // The pinned experiment kernel guards global ID enumeration and
    // get-fd-by-id with capable(CAP_SYS_ADMIN); CAP_BPF+CAP_PERFMON alone is
    // insufficient for the State Oracle used by this build.
    let sufficient = has(CAP_SYS_ADMIN);
    DoctorCheck {
        name: "bpf_capabilities".into(),
        status: if sufficient {
            CheckStatus::Pass
        } else {
            CheckStatus::Fail
        },
        detail: format!(
            "CapEff=0x{effective:x}; this kernel/build requires effective CAP_SYS_ADMIN"
        ),
    }
}

fn inventory_access_check() -> DoctorCheck {
    match bpf_observer_oracle::probe_global_inventory_access() {
        Ok(()) => DoctorCheck {
            name: "global_bpf_inventory_access".into(),
            status: CheckStatus::Pass,
            detail: "BPF_{PROG,MAP,LINK}_GET_NEXT_ID read-only smoke checks succeeded".into(),
        },
        Err(error) => DoctorCheck {
            name: "global_bpf_inventory_access".into(),
            status: CheckStatus::Fail,
            detail: format!("global BPF enumeration smoke check failed: {error:#}"),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_has_required_checks() {
        let report = inspect(
            None,
            Path::new("/sys/fs/cgroup/bpf-state-observer"),
            ObjectResolutionMode::UserInput,
        );
        assert!(report.checks.iter().any(|check| check.name == "cgroup_v2"));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "bpf_capabilities"));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "global_bpf_inventory_access"));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "raw_syscalls_perf_access"));
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "selected_object_resolution_mode"));
        assert!(report.object_resolution.selected_mode_available);
    }

    #[test]
    fn kernel_object_resolution_makes_doctor_fail_closed() {
        for mode in [
            ObjectResolutionMode::KernelFileOpenPartial,
            ObjectResolutionMode::KernelFileOpenWritePartial,
        ] {
            let report = inspect(None, Path::new("/sys/fs/cgroup/bpf-state-observer"), mode);
            let check = report
                .checks
                .iter()
                .find(|check| check.name == "selected_object_resolution_mode")
                .unwrap();
            assert_eq!(check.status, CheckStatus::Fail);
            assert!(!report.ready_for_runtime);
            assert!(!report.object_resolution.kernel_file_open_partial.available);
            assert!(
                !report
                    .object_resolution
                    .kernel_file_open_write_partial
                    .available
            );
        }
    }

    #[test]
    fn rejects_a_regular_non_bpf_file_as_recorder() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert_eq!(recorder_object_check(&path).status, CheckStatus::Fail);
    }

    #[test]
    fn cgroup_preflight_does_not_trust_marker_names_on_a_normal_filesystem() {
        assert_eq!(
            cgroup_v2_filesystem_check(Path::new("/tmp")).status,
            CheckStatus::Fail
        );
        assert_eq!(
            cgroup_root_check(Path::new("/tmp/fake-cgroup")).status,
            CheckStatus::Fail
        );
    }
}
