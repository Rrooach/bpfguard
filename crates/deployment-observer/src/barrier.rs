// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment::DeploymentManifest;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
const MAX_INTERFACE_BYTES: u64 = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootFreezeIdentity {
    pub path: String,
    pub expected_cgroup_id: u64,
    pub observed_cgroup_id: Option<u64>,
    pub freeze_requested: Option<bool>,
    pub frozen: Option<bool>,
    pub populated: Option<bool>,
    pub verified: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootFreezeBarrier {
    pub checked_unix_ns: u128,
    pub method: String,
    pub all_roots_frozen: bool,
    pub roots: Vec<RootFreezeIdentity>,
}

pub fn verify_frozen_roots(manifest: &DeploymentManifest) -> Result<RootFreezeBarrier> {
    verify_frozen_roots_at(manifest, Path::new("/sys/fs/cgroup"))
}

pub(crate) fn verify_frozen_roots_at(
    manifest: &DeploymentManifest,
    cgroupfs: &Path,
) -> Result<RootFreezeBarrier> {
    manifest.validate()?;
    verify_cgroup2(cgroupfs)?;
    let checked_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let mut roots = Vec::with_capacity(manifest.root_cgroups.len());
    for expected in &manifest.root_cgroups {
        let mut result = RootFreezeIdentity {
            path: expected.path.clone(),
            expected_cgroup_id: expected.cgroup_id,
            observed_cgroup_id: None,
            freeze_requested: None,
            frozen: None,
            populated: None,
            verified: false,
            error: None,
        };
        match verify_one(cgroupfs, &expected.path, expected.cgroup_id) {
            Ok((observed_id, requested, frozen, populated)) => {
                result.observed_cgroup_id = Some(observed_id);
                result.freeze_requested = Some(requested);
                result.frozen = Some(frozen);
                result.populated = Some(populated);
                result.verified = requested && frozen && observed_id == expected.cgroup_id;
                if !result.verified {
                    result.error = Some(
                        "root cgroup has not completed the caller-owned freeze barrier".to_owned(),
                    );
                }
            }
            Err(error) => result.error = Some(format!("{error:#}")),
        }
        roots.push(result);
    }
    let all_roots_frozen = !roots.is_empty() && roots.iter().all(|root| root.verified);
    Ok(RootFreezeBarrier {
        checked_unix_ns,
        method: "CGROUP_V2_ROOT_SUBTREE_FREEZE".to_owned(),
        all_roots_frozen,
        roots,
    })
}

fn verify_cgroup2(path: &Path) -> Result<()> {
    let file = open_directory(path)?;
    let mut stat = unsafe { std::mem::zeroed::<libc::statfs>() };
    let rc = unsafe { libc::fstatfs(std::os::unix::io::AsRawFd::as_raw_fd(&file), &mut stat) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("fstatfs cgroup root");
    }
    if stat.f_type != CGROUP2_SUPER_MAGIC {
        bail!("deployment observer requires a verified cgroup v2 filesystem");
    }
    Ok(())
}

fn verify_one(cgroupfs: &Path, path: &str, expected_id: u64) -> Result<(u64, bool, bool, bool)> {
    if path == "/" {
        bail!("refusing to use the host cgroup-v2 root as a deployment freeze boundary");
    }
    let relative = Path::new(path)
        .strip_prefix("/")
        .context("deployment cgroup path is not absolute")?;
    let directory = cgroupfs.join(relative);
    let before =
        fs::symlink_metadata(&directory).with_context(|| format!("stat cgroup root {path}"))?;
    if !before.file_type().is_dir() || before.ino() != expected_id {
        bail!("cgroup root {path} was replaced or is not a directory");
    }
    let requested = read_small(&directory.join("cgroup.freeze"))?.trim() == "1";
    let events = read_small(&directory.join("cgroup.events"))?;
    let (populated, frozen) = parse_events(&events)?;
    let after =
        fs::symlink_metadata(&directory).with_context(|| format!("re-stat cgroup root {path}"))?;
    if !after.file_type().is_dir()
        || after.ino() != before.ino()
        || after.dev() != before.dev()
        || after.ino() != expected_id
    {
        bail!("cgroup root {path} changed while its freeze barrier was checked");
    }
    Ok((after.ino(), requested, frozen, populated))
}

fn open_directory(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open directory {}", path.display()))
}

fn read_small(path: &Path) -> Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open cgroup interface {}", path.display()))?;
    let mut bytes = Vec::new();
    file.take(MAX_INTERFACE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INTERFACE_BYTES {
        bail!("cgroup interface {} exceeds size bound", path.display());
    }
    String::from_utf8(bytes).context("cgroup interface is not UTF-8")
}

fn parse_events(text: &str) -> Result<(bool, bool)> {
    let mut populated = None;
    let mut frozen = None;
    for line in text.lines() {
        let mut fields = line.split_ascii_whitespace();
        let name = fields.next().context("empty cgroup.events line")?;
        let value = fields.next().context("cgroup.events field lacks value")?;
        if fields.next().is_some() {
            bail!("cgroup.events field contains trailing data");
        }
        let parsed = match value {
            "0" => false,
            "1" => true,
            _ => bail!("cgroup.events boolean is not 0 or 1"),
        };
        match name {
            "populated" => set_once(&mut populated, parsed, name)?,
            "frozen" => set_once(&mut frozen, parsed, name)?,
            _ => {}
        }
    }
    Ok((
        populated.context("cgroup.events has no populated field")?,
        frozen.context("cgroup.events has no frozen field")?,
    ))
}

fn set_once(slot: &mut Option<bool>, value: bool, name: &str) -> Result<()> {
    if slot.replace(value).is_some() {
        bail!("cgroup.events contains duplicate {name} fields");
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_pathbuf_is_used(_: PathBuf) {}
