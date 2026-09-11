// SPDX-License-Identifier: GPL-2.0-only

//! Privileged VM-only negative probe for the authenticated exclusive-actor
//! gate. It creates and destroys one HASH map from a forked TGID outside every
//! registered workload cgroup, then requires the recorder to reject the
//! otherwise endpoint-invisible operation.

use anyhow::{bail, Context, Result};
use bpf_observer_recorder::Recorder;
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

// Stable Linux UAPI values: enum bpf_cmd::BPF_MAP_CREATE and
// enum bpf_map_type::BPF_MAP_TYPE_HASH.
const BPF_MAP_CREATE: libc::c_long = 0;
const BPF_MAP_TYPE_HASH: u32 = 1;
const STRICT_UID: libc::uid_t = 65_534;
const STRICT_GID: libc::gid_t = 65_534;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON: u32 = 38;
const CAP_BPF: u32 = 39;
const EXPECTED_CAPABILITIES: u64 =
    (1_u64 << CAP_SYS_ADMIN) | (1_u64 << CAP_PERFMON) | (1_u64 << CAP_BPF);
const EXPECTED_SECUREBITS: libc::c_int = 0xef;

fn unique_status_hex(status: &str, field: &str) -> Result<u64> {
    let prefix = format!("{field}:");
    let values = status
        .lines()
        .filter_map(|line| line.strip_prefix(&prefix))
        .collect::<Vec<_>>();
    if values.len() != 1 {
        bail!(
            "/proc/self/status contains {} instances of {field}",
            values.len()
        );
    }
    u64::from_str_radix(values[0].trim(), 16)
        .with_context(|| format!("parse {field} from /proc/self/status"))
}

fn fdinfo_describes_bpf(contents: &str) -> bool {
    let object_id = contents.lines().any(|line| {
        line.starts_with("prog_id:")
            || line.starts_with("map_id:")
            || line.starts_with("link_id:")
            || line.starts_with("btf_id:")
    });
    let token_fields = [
        "allowed_cmds:",
        "allowed_maps:",
        "allowed_progs:",
        "allowed_attachs:",
    ];
    object_id
        || token_fields
            .iter()
            .all(|field| contents.lines().any(|line| line.starts_with(field)))
}

fn require_no_inherited_bpf_fd() -> Result<()> {
    for entry in fs::read_dir("/proc/self/fdinfo").context("list /proc/self/fdinfo")? {
        let entry = entry.context("read /proc/self/fdinfo entry")?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            continue;
        }
        let contents = fs::read_to_string(entry.path())
            .with_context(|| format!("read {}", entry.path().display()))?;
        if fdinfo_describes_bpf(&contents) {
            bail!("inherited BPF object or token FD {name}");
        }
    }
    Ok(())
}

fn assert_strict_execution_credentials() -> Result<()> {
    let mut real_uid = 0;
    let mut effective_uid = 0;
    let mut saved_uid = 0;
    let mut real_gid = 0;
    let mut effective_gid = 0;
    let mut saved_gid = 0;
    let uid_result = unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) };
    let gid_result = unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) };
    if uid_result != 0
        || gid_result != 0
        || [real_uid, effective_uid, saved_uid] != [STRICT_UID; 3]
        || [real_gid, effective_gid, saved_gid] != [STRICT_GID; 3]
        || unsafe { libc::getgroups(0, std::ptr::null_mut()) } != 0
    {
        bail!("outside-gate probe UID/GID contract is not exact");
    }

    let status =
        fs::read_to_string(Path::new("/proc/self/status")).context("read /proc/self/status")?;
    if unique_status_hex(&status, "CapEff")? != EXPECTED_CAPABILITIES
        || unique_status_hex(&status, "CapPrm")? != EXPECTED_CAPABILITIES
        || unique_status_hex(&status, "CapInh")? != 0
        || unique_status_hex(&status, "CapBnd")? != EXPECTED_CAPABILITIES
        || unique_status_hex(&status, "CapAmb")? != 0
    {
        bail!("outside-gate probe capability contract is not exact");
    }
    let securebits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    let no_new_privs = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if securebits != EXPECTED_SECUREBITS || no_new_privs != 0 {
        bail!("outside-gate probe secure-execution contract is not exact");
    }
    require_no_inherited_bpf_fd()
}

#[repr(C)]
struct MinimalMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
}

fn child_create_and_destroy_map() -> ! {
    // Do not inherit any recorder-owned BPF FD into the negative actor. This
    // probe is specifically a fresh outside syscall, not an FD-transfer case.
    let closed = unsafe { libc::syscall(libc::SYS_close_range, 3u32, u32::MAX, 0u32) };
    if closed != 0 {
        unsafe { libc::_exit(110) };
    }
    let attr = MinimalMapCreateAttr {
        map_type: BPF_MAP_TYPE_HASH,
        key_size: 4,
        value_size: 4,
        max_entries: 1,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_MAP_CREATE,
            &attr as *const MinimalMapCreateAttr,
            std::mem::size_of::<MinimalMapCreateAttr>(),
        )
    };
    if fd < 0 {
        unsafe { libc::_exit(111) };
    }
    let close_result = unsafe { libc::close(fd as libc::c_int) };
    unsafe { libc::_exit(if close_result == 0 { 0 } else { 112 }) }
}

fn run() -> Result<()> {
    let arguments = std::env::args_os().collect::<Vec<OsString>>();
    if arguments.len() != 4 {
        bail!(
            "usage: {} RECORDER_OBJECT EXPECTED_SHA256 OUTPUT_DIRECTORY",
            arguments
                .first()
                .map(|value| value.to_string_lossy())
                .unwrap_or_default()
        );
    }
    let recorder_object = PathBuf::from(&arguments[1]);
    let expected_sha256 = arguments[2]
        .to_str()
        .context("expected recorder digest is not UTF-8")?;
    let output_directory = PathBuf::from(&arguments[3]);
    assert_strict_execution_credentials()
        .context("validate outside-gate probe execution credentials")?;
    let mut recorder = Recorder::open(
        &recorder_object,
        expected_sha256,
        &output_directory,
        "outside-gate-probe",
        &BTreeSet::new(),
    )
    .context("load exact recorder for outside-actor negative probe")?;
    recorder
        .begin_exclusive_window()
        .context("arm outside-actor negative gate")?;

    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error()).context("fork outside BPF actor");
    }
    if child == 0 {
        child_create_and_destroy_map();
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        if waited < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if waited < 0 {
            return Err(std::io::Error::last_os_error()).context("wait outside BPF actor");
        }
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        bail!("outside actor could not create and destroy its transient HASH map");
    }

    let rejection = recorder
        .finish_exclusive_window()
        .expect_err("outside BPF actor was not detected at the synchronized recorder boundary");
    let message = format!("{rejection:#}");
    if !message.contains("outside") || !message.contains("1 bpf() attempt") {
        bail!("outside-actor gate returned an unexpected rejection: {message}");
    }
    drop(recorder);
    println!("OUTSIDE_BPF_ACTOR_GATE_REJECTED_TRANSIENT_MAP");
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("VM outside-actor gate assertion failed: {error:#}");
        std::process::exit(1);
    }
}
