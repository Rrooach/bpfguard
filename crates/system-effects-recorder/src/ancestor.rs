// SPDX-License-Identifier: GPL-2.0-only

use super::{check_rc, map_delete, map_lookup, map_update};
use anyhow::{bail, Context, Result};
use libbpf_sys as libbpf;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

pub(crate) const MAX_ANCESTOR_ROOTS: u32 = 8;
const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct AncestorConfig {
    pub root_count: u32,
    pub reserved: u32,
}

struct RootBinding {
    slot: u32,
    cgroup_id: u64,
    epoch: u64,
    path: PathBuf,
    device: u64,
    file: File,
}

/// Owns the kernel cgroup references used by `bpf_current_task_under_cgroup`.
///
/// The cgroup ARRAY and the parallel root-ID ARRAY are updated only while the
/// caller has frozen every root.  `seal` freezes the active slot count, and
/// retained directory FDs prevent userspace path replacement from being
/// confused with the object registered in the kernel map.
pub(crate) struct AncestorRootSet {
    cgroup_array_fd: i32,
    root_ids_fd: i32,
    config_fd: i32,
    bindings: BTreeMap<u64, RootBinding>,
    sealed: bool,
}

impl AncestorRootSet {
    pub(crate) fn new(cgroup_array_fd: i32, root_ids_fd: i32, config_fd: i32) -> Self {
        Self {
            cgroup_array_fd,
            root_ids_fd,
            config_fd,
            bindings: BTreeMap::new(),
            sealed: false,
        }
    }

    pub(crate) fn register(&mut self, path: &Path, cgroup_id: u64, epoch: u64) -> Result<u32> {
        if self.sealed {
            bail!("ancestor-root set was already sealed");
        }
        if cgroup_id == 0 || epoch == 0 {
            bail!("ancestor root cgroup ID and epoch must be nonzero");
        }
        if self.bindings.contains_key(&cgroup_id) {
            bail!("ancestor root cgroup ID is already registered");
        }
        let slot = u32::try_from(self.bindings.len()).context("ancestor root slot overflow")?;
        if slot >= MAX_ANCESTOR_ROOTS {
            bail!("ancestor-root count exceeds hard maximum {MAX_ANCESTOR_ROOTS}");
        }
        let file = open_cgroup2(path, cgroup_id)?;
        let metadata = file.metadata()?;
        let fd = file.as_raw_fd();
        map_update(self.cgroup_array_fd, &slot, &fd, libbpf::BPF_ANY as u64)
            .with_context(|| format!("register cgroup FD in ancestor slot {slot}"))?;
        if let Err(error) = map_update(self.root_ids_fd, &slot, &cgroup_id, libbpf::BPF_ANY as u64)
        {
            let _ = map_delete(self.cgroup_array_fd, &slot);
            return Err(error).context("bind ancestor slot to root cgroup ID");
        }
        self.bindings.insert(
            cgroup_id,
            RootBinding {
                slot,
                cgroup_id,
                epoch,
                path: path.to_path_buf(),
                device: metadata.dev(),
                file,
            },
        );
        Ok(slot)
    }

    pub(crate) fn seal(&mut self) -> Result<()> {
        if self.sealed || self.bindings.is_empty() {
            bail!("ancestor roots must be registered exactly once before sealing");
        }
        let config = AncestorConfig {
            root_count: u32::try_from(self.bindings.len())
                .context("ancestor root count overflow")?,
            reserved: 0,
        };
        map_update(self.config_fd, &0_u32, &config, libbpf::BPF_ANY as u64)
            .context("publish immutable ancestor-root count")?;
        check_rc(
            unsafe { libbpf::bpf_map_freeze(self.config_fd) },
            "freeze ancestor-root configuration",
        )?;
        self.sealed = true;
        self.verify()
    }

    pub(crate) fn verify(&self) -> Result<()> {
        if !self.sealed || self.bindings.is_empty() {
            bail!("ancestor-root set is not sealed");
        }
        let mut config = AncestorConfig::default();
        map_lookup(self.config_fd, &0_u32, &mut config)
            .context("read sealed ancestor-root configuration")?;
        if config.reserved != 0 || config.root_count as usize != self.bindings.len() {
            bail!("ancestor-root configuration changed or is inconsistent");
        }
        for binding in self.bindings.values() {
            if binding.epoch == 0 {
                bail!("ancestor-root binding lost its epoch");
            }
            let retained = binding.file.metadata()?;
            if !retained.file_type().is_dir()
                || retained.dev() != binding.device
                || retained.ino() != binding.cgroup_id
            {
                bail!("retained ancestor-root FD identity changed");
            }
            require_cgroup2(binding.file.as_raw_fd())?;
            let reopened = open_cgroup2(&binding.path, binding.cgroup_id)?;
            let reopened_metadata = reopened.metadata()?;
            if reopened_metadata.dev() != binding.device
                || reopened_metadata.ino() != retained.ino()
            {
                bail!("ancestor-root path no longer resolves to retained cgroup FD");
            }
            let mut root_id = 0_u64;
            map_lookup(self.root_ids_fd, &binding.slot, &mut root_id)
                .context("read ancestor root-ID slot")?;
            if root_id != binding.cgroup_id {
                bail!("ancestor root-ID slot changed after registration");
            }
        }
        Ok(())
    }

    pub(crate) fn unregister(&mut self, cgroup_id: u64, epoch: u64) -> Result<()> {
        if !self.sealed {
            bail!("cannot unregister an unsealed ancestor-root set");
        }
        self.verify()?;
        let binding = self
            .bindings
            .get(&cgroup_id)
            .context("ancestor root is not registered")?;
        if binding.epoch != epoch {
            bail!("ancestor root epoch changed before unregister");
        }
        let slot = binding.slot;
        // Disable the BPF-visible identity first.  The target root is required
        // to remain frozen, so no producer can race the following map cleanup.
        map_update(self.root_ids_fd, &slot, &0_u64, libbpf::BPF_ANY as u64)
            .context("disable ancestor root-ID slot")?;
        map_delete(self.cgroup_array_fd, &slot).context("remove ancestor cgroup FD slot")?;
        self.bindings.remove(&cgroup_id);
        Ok(())
    }
}

fn open_cgroup2(path: &Path, expected_cgroup_id: u64) -> Result<File> {
    if !path.is_absolute() {
        bail!("ancestor cgroup path must be absolute");
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("open ancestor cgroup root {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_dir() || metadata.ino() != expected_cgroup_id {
        bail!("ancestor cgroup path/ID binding does not match live cgroupfs");
    }
    require_cgroup2(file.as_raw_fd())?;
    Ok(file)
}

fn require_cgroup2(fd: i32) -> Result<()> {
    let mut status = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let rc = unsafe { libc::fstatfs(fd, status.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("fstatfs ancestor cgroup FD");
    }
    let status = unsafe { status.assume_init() };
    if status.f_type != CGROUP2_SUPER_MAGIC {
        bail!("ancestor root is not on a cgroup-v2 filesystem");
    }
    Ok(())
}
