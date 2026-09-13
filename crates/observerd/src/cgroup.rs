// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub struct ManagedCgroup {
    path: PathBuf,
    owned: bool,
    id: u64,
    identity_handle: Option<File>,
}

impl ManagedCgroup {
    pub fn create(root: &Path, run_id: &str) -> Result<Self> {
        ensure_cgroup_v2(root)?;
        fs::create_dir_all(root)
            .with_context(|| format!("create cgroup root {}", root.display()))?;
        let root_metadata = fs::symlink_metadata(root)
            .with_context(|| format!("inspect cgroup root {}", root.display()))?;
        if !root_metadata.file_type().is_dir() {
            bail!("cgroup root {} must be a real directory", root.display());
        }
        ensure_exact_cgroup_v2(root)
            .with_context(|| format!("validate cgroup root {}", root.display()))?;
        let path = root.join(run_id);
        fs::create_dir(&path).with_context(|| format!("create run cgroup {}", path.display()))?;
        if let Err(error) = ensure_exact_cgroup_v2(&path) {
            return Err(with_creation_cleanup(
                &path,
                error.context(format!(
                    "validate newly-created run cgroup {}",
                    path.display()
                )),
            ));
        }

        // The recorder currently matches one exact cgroup ID. Forbid a delegated
        // subtree so descendants cannot silently escape that filter.
        for interface in ["cgroup.max.depth", "cgroup.max.descendants"] {
            if let Err(error) = fs::write(path.join(interface), b"0\n") {
                let primary =
                    anyhow!(error).context(format!("set {interface}=0 for {}", path.display()));
                return Err(with_creation_cleanup(&path, primary));
            }
        }
        if !path.join("cgroup.freeze").is_file() || !path.join("cgroup.kill").is_file() {
            return Err(with_creation_cleanup(
                &path,
                anyhow!(
                    "cgroup v2 freezer or kill interface is unavailable for {}",
                    path.display()
                ),
            ));
        }

        let id = match fs::metadata(&path) {
            Ok(metadata) => metadata.ino(),
            Err(error) => {
                let primary = anyhow!(error).context(format!(
                    "inspect newly-created run cgroup {}",
                    path.display()
                ));
                return Err(with_creation_cleanup(&path, primary));
            }
        };
        if id == 0 {
            return Err(with_creation_cleanup(
                &path,
                anyhow!("kernel returned an invalid cgroup inode ID"),
            ));
        }
        let identity_handle = match OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(&path)
        {
            Ok(handle) => handle,
            Err(error) => {
                let primary = anyhow!(error).context(format!(
                    "anchor newly-created run cgroup {}",
                    path.display()
                ));
                return Err(with_creation_cleanup(&path, primary));
            }
        };
        if let Err(error) = ensure_cgroup_v2_handle(&identity_handle) {
            return Err(with_creation_cleanup(
                &path,
                error.context(format!("validate anchored run cgroup {}", path.display())),
            ));
        }
        let anchored = match identity_handle.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                let primary = anyhow!(error)
                    .context(format!("inspect anchored run cgroup {}", path.display()));
                return Err(with_creation_cleanup(&path, primary));
            }
        };
        let path_metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                let primary = anyhow!(error).context(format!(
                    "reinspect newly-created run cgroup {}",
                    path.display()
                ));
                return Err(with_creation_cleanup(&path, primary));
            }
        };
        if !anchored.file_type().is_dir()
            || anchored.dev() != path_metadata.dev()
            || anchored.ino() != path_metadata.ino()
            || anchored.ino() != id
        {
            return Err(with_creation_cleanup(
                &path,
                anyhow!("newly-created run cgroup changed while its identity was anchored"),
            ));
        }
        Ok(Self {
            path,
            owned: true,
            id,
            identity_handle: Some(identity_handle),
        })
    }

    pub fn open_existing(path: &Path) -> Result<Self> {
        if !path.is_absolute() || path.as_os_str().as_bytes().contains(&0) {
            bail!("existing cgroup path must be absolute and contain no NUL byte");
        }
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("inspect existing cgroup {}", path.display()))?;
        if !metadata.file_type().is_dir() {
            bail!(
                "existing cgroup {} must be a real directory",
                path.display()
            );
        }
        let canonical = fs::canonicalize(path)
            .with_context(|| format!("canonicalize existing cgroup {}", path.display()))?;
        if canonical != path {
            bail!("existing cgroup path {} is not canonical", path.display());
        }
        ensure_exact_cgroup_v2(path)?;
        if path
            .parent()
            .map(|parent| ensure_exact_cgroup_v2(parent).is_err())
            .unwrap_or(true)
        {
            bail!("refusing to supervise a cgroup v2 hierarchy root");
        }
        for interface in [
            "cgroup.events",
            "cgroup.procs",
            "cgroup.freeze",
            "cgroup.max.depth",
            "cgroup.max.descendants",
        ] {
            if !path.join(interface).is_file() {
                bail!(
                    "existing cgroup {} lacks required interface {interface}",
                    path.display()
                );
            }
        }
        let id = metadata.ino();
        if id == 0 {
            bail!("kernel returned an invalid existing cgroup inode ID");
        }
        let identity_handle = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
            .open(path)
            .with_context(|| format!("anchor existing cgroup {}", path.display()))?;
        let anchored = identity_handle.metadata()?;
        if !anchored.file_type().is_dir()
            || anchored.dev() != metadata.dev()
            || anchored.ino() != metadata.ino()
        {
            bail!("existing cgroup changed while its identity was anchored");
        }
        Ok(Self {
            path: path.to_path_buf(),
            owned: false,
            id,
            identity_handle: Some(identity_handle),
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Revalidate an externally-owned cgroup without mutating it. A trusted
    /// external runtime can use this at both registration and finalization so
    /// a removed/recreated path cannot silently inherit the accepted binding.
    pub fn verify_identity(&self, expected_id: u64) -> Result<()> {
        if expected_id == 0 || self.id != expected_id {
            bail!(
                "existing cgroup ID {} does not match expected ID {expected_id}",
                self.id
            );
        }
        let metadata = fs::symlink_metadata(&self.path)
            .with_context(|| format!("reinspect existing cgroup {}", self.path.display()))?;
        if !metadata.file_type().is_dir() || metadata.ino() != self.id {
            bail!(
                "existing cgroup path {} changed identity",
                self.path.display()
            );
        }
        if let Some(handle) = self.identity_handle.as_ref() {
            ensure_cgroup_v2_handle(handle).context("validate anchored cgroup filesystem")?;
            let anchored = handle
                .metadata()
                .context("reinspect anchored existing cgroup")?;
            if !anchored.file_type().is_dir()
                || anchored.dev() != metadata.dev()
                || anchored.ino() != metadata.ino()
            {
                bail!(
                    "existing cgroup path {} no longer matches its anchored identity",
                    self.path.display()
                );
            }
        }
        ensure_exact_cgroup_v2(&self.path)
    }

    /// Require the no-descendant leaf contract established by the external
    /// runtime before target code is resumed.
    pub fn verify_leaf_seal(&self) -> Result<()> {
        self.verify_identity(self.id)?;
        for name in ["cgroup.max.depth", "cgroup.max.descendants"] {
            let value = fs::read_to_string(self.path.join(name))
                .with_context(|| format!("read {}/{}", self.path.display(), name))?;
            if value.trim() != "0" {
                bail!(
                    "existing cgroup {} is not sealed: {name} is {:?}",
                    self.path.display(),
                    value.trim()
                );
            }
        }
        for entry in fs::read_dir(&self.path)
            .with_context(|| format!("enumerate cgroup leaf {}", self.path.display()))?
        {
            let entry = entry?;
            if entry
                .file_type()
                .with_context(|| format!("inspect cgroup leaf entry {}", entry.path().display()))?
                .is_dir()
            {
                bail!(
                    "existing cgroup {} contains child cgroup {} despite the leaf contract",
                    self.path.display(),
                    entry.path().display()
                );
            }
        }
        // Bind the seal reads and child enumeration to the same anchored
        // cgroup identity accepted at the start of this check.
        self.verify_identity(self.id)
    }

    /// Independently confirm the producer barrier claimed by FINISH.
    pub fn verify_empty_frozen(&self, expected_id: u64) -> Result<()> {
        self.verify_identity(expected_id)?;
        self.verify_leaf_seal()?;
        let events = self.events()?;
        if events.populated || !events.frozen {
            bail!(
                "existing cgroup {} is not empty and frozen (populated={}, frozen={})",
                self.path.display(),
                events.populated,
                events.frozen
            );
        }
        // Re-stat after reading cgroup.events to bind the barrier to the same
        // directory identity across the complete check.
        self.verify_identity(expected_id)
    }

    pub fn configure_child(&self, command: &mut Command) -> Result<()> {
        self.verify_identity(self.id)?;
        self.verify_leaf_seal()?;
        let procs = self.open_interface("cgroup.procs", libc::O_WRONLY)?;
        self.verify_identity(self.id)?;
        let expected_parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // Close the race in which the observer exits between fork and
                // PR_SET_PDEATHSIG. Returning from pre_exec with an error
                // terminates the child instead of launching an orphan root.
                if libc::getppid() != expected_parent {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                // No Observer/recorder descriptor, including a BPF object FD,
                // may cross exec into the workload. `CLOEXEC` is applied as
                // one atomic range operation so an accidentally non-CLOEXEC
                // library descriptor cannot silently violate the exclusive
                // harness contract.
                const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
                if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, CLOSE_RANGE_CLOEXEC) != 0 {
                    return Err(io::Error::last_os_error());
                }
                move_self_to_cgroup(procs.as_raw_fd())
            });
        }
        Ok(())
    }

    pub fn populated(&self) -> Result<bool> {
        Ok(self.events()?.populated)
    }

    /// Freeze an already-empty run cgroup and wait for the kernel's completed
    /// freezer state. A task moved into the cgroup after this barrier is
    /// stopped before it can execute there, closing the drain/S1 re-entry
    /// window. The caller keeps the recorder registration until after S1.
    pub fn freeze_empty(&self, timeout: Duration) -> Result<()> {
        self.verify_identity(self.id)?;
        self.verify_leaf_seal()?;
        self.write_interface("cgroup.freeze", b"1\n")?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("cgroup freeze timeout exceeds monotonic clock range")?;
        loop {
            let events = self.events()?;
            if events.frozen {
                if events.populated {
                    bail!(
                        "run cgroup {} became populated while closing the execution barrier",
                        self.path.display()
                    );
                }
                self.verify_identity(self.id)?;
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("timed out freezing run cgroup {}", self.path.display());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn events(&self) -> Result<CgroupEvents> {
        let events = self.read_interface("cgroup.events", 4096)?;
        parse_cgroup_events(&events)
    }

    pub fn kill_all(&self) -> Result<()> {
        self.write_interface("cgroup.kill", b"1\n")
    }

    /// Best-effort failure fencing with a bounded, reported result. Success
    /// means the owned cgroup was observed empty and removed; failure tells
    /// the caller that an external supervisor still has cleanup work to do.
    pub fn abort_and_cleanup(&mut self, timeout: Duration) -> Result<()> {
        if !self.owned {
            return Ok(());
        }
        if !self.owned_path_present()? {
            self.owned = false;
            return Ok(());
        }
        if matches!(self.populated(), Ok(false)) {
            return self.cleanup();
        }

        let kill_error = self.kill_all().err();
        let deadline = Instant::now()
            .checked_add(timeout)
            .context("cgroup cleanup timeout exceeds monotonic clock range")?;
        loop {
            let last_state_error = match self.populated() {
                Ok(false) => return self.cleanup(),
                Ok(true) => None,
                Err(error) => Some(error.to_string()),
            };
            if Instant::now() >= deadline {
                bail!(
                    "run cgroup {} did not become removable within {timeout:?} (kill_error={:?}, state_error={last_state_error:?})",
                    self.path.display(),
                    kill_error.map(|error| error.to_string())
                );
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn cleanup(&mut self) -> Result<()> {
        if self.owned {
            if !self.owned_path_present()? {
                self.owned = false;
                return Ok(());
            }
            if self.populated()? {
                bail!(
                    "refusing to remove populated cgroup {}",
                    self.path.display()
                );
            }
            fs::remove_dir(&self.path)
                .with_context(|| format!("remove run cgroup {}", self.path.display()))?;
            self.owned = false;
        }
        Ok(())
    }

    fn owned_path_present(&self) -> Result<bool> {
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) => {
                if !metadata.file_type().is_dir() || metadata.ino() != self.id {
                    bail!(
                        "owned cgroup path {} was replaced or changed identity",
                        self.path.display()
                    );
                }
                if let Some(handle) = self.identity_handle.as_ref() {
                    let anchored = handle.metadata().context("reinspect owned cgroup anchor")?;
                    if anchored.dev() != metadata.dev() || anchored.ino() != metadata.ino() {
                        bail!(
                            "owned cgroup path {} no longer matches its anchor",
                            self.path.display()
                        );
                    }
                }
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("inspect owned cgroup {}", self.path.display()))
            }
        }
    }

    fn open_interface(&self, name: &str, access: libc::c_int) -> Result<File> {
        let anchor = self
            .identity_handle
            .as_ref()
            .context("cgroup identity has no anchored directory handle")?;
        let name = CString::new(name).context("cgroup interface name contains NUL")?;
        let fd = unsafe {
            libc::openat(
                anchor.as_raw_fd(),
                name.as_ptr(),
                access | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!("open anchored cgroup interface {}", name.to_string_lossy())
            });
        }
        // SAFETY: openat returned a new owned descriptor on success.
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn read_interface(&self, name: &str, maximum_bytes: u64) -> Result<String> {
        let mut file = self.open_interface(name, libc::O_RDONLY | libc::O_NONBLOCK)?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(maximum_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .with_context(|| format!("read anchored cgroup interface {name}"))?;
        if bytes.len() as u64 > maximum_bytes {
            bail!("cgroup interface {name} exceeds its read bound");
        }
        String::from_utf8(bytes).with_context(|| format!("cgroup interface {name} is not UTF-8"))
    }

    fn write_interface(&self, name: &str, bytes: &[u8]) -> Result<()> {
        let mut file = self.open_interface(name, libc::O_WRONLY)?;
        file.write_all(bytes)
            .with_context(|| format!("write anchored cgroup interface {name}"))
    }
}

fn with_creation_cleanup(path: &Path, primary: anyhow::Error) -> anyhow::Error {
    match fs::remove_dir(path) {
        Ok(()) => primary,
        Err(cleanup) => anyhow!(
            "{primary:#}; additionally failed to remove newly-created cgroup {}: {cleanup}",
            path.display()
        ),
    }
}

#[derive(Clone, Copy, Debug)]
struct CgroupEvents {
    populated: bool,
    frozen: bool,
}

fn parse_cgroup_events(events: &str) -> Result<CgroupEvents> {
    let mut populated = None;
    let mut frozen = None;
    for line in events.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        if !matches!(name, "populated" | "frozen") {
            continue;
        }
        let value = match (fields.next(), fields.next()) {
            (Some("0"), None) => false,
            (Some("1"), None) => true,
            (value, extra) => {
                bail!("invalid cgroup.events {name} value: {value:?}, extra={extra:?}")
            }
        };
        let slot = if name == "populated" {
            &mut populated
        } else {
            &mut frozen
        };
        if slot.replace(value).is_some() {
            bail!("cgroup.events contains duplicate {name} fields");
        }
    }
    Ok(CgroupEvents {
        populated: populated.context("cgroup.events has no populated field")?,
        frozen: frozen.context("cgroup.events has no frozen field")?,
    })
}

impl Drop for ManagedCgroup {
    fn drop(&mut self) {
        if self.owned
            && self.owned_path_present().unwrap_or(false)
            && !self.populated().unwrap_or(true)
        {
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn ensure_cgroup_v2(path: &Path) -> Result<()> {
    let mut cursor = Some(path);
    while let Some(candidate) = cursor {
        if candidate.exists() {
            let metadata = fs::symlink_metadata(candidate)
                .with_context(|| format!("inspect cgroup ancestor {}", candidate.display()))?;
            if !metadata.file_type().is_dir() {
                bail!(
                    "nearest existing cgroup ancestor {} is not a real directory",
                    candidate.display()
                );
            }
            return ensure_exact_cgroup_v2(candidate).with_context(|| {
                format!(
                    "nearest existing ancestor {} is not on cgroup v2",
                    candidate.display()
                )
            });
        }
        cursor = candidate.parent();
    }
    bail!("{} is not on a cgroup v2 hierarchy", path.display())
}

fn ensure_exact_cgroup_v2(path: &Path) -> Result<()> {
    if !is_cgroup2_filesystem(path)? {
        bail!("existing path is not on a cgroup v2 filesystem");
    }
    Ok(())
}

pub(crate) fn is_cgroup2_filesystem(path: &Path) -> Result<bool> {
    let bytes = path.as_os_str().as_bytes();
    let path = CString::new(bytes).map_err(|_| anyhow!("cgroup path contains a NUL byte"))?;
    let mut status = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::statfs(path.as_ptr(), &mut status) } != 0 {
        return Err(io::Error::last_os_error()).context("statfs existing cgroup");
    }
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    Ok(status.f_type == CGROUP2_SUPER_MAGIC)
}

fn ensure_cgroup_v2_handle(handle: &File) -> Result<()> {
    let mut status = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(handle.as_raw_fd(), &mut status) } != 0 {
        return Err(io::Error::last_os_error()).context("fstatfs anchored cgroup");
    }
    const CGROUP2_SUPER_MAGIC: libc::c_long = 0x6367_7270;
    if status.f_type != CGROUP2_SUPER_MAGIC {
        bail!("anchored path is not on a cgroup v2 filesystem");
    }
    Ok(())
}

unsafe fn move_self_to_cgroup(fd: libc::c_int) -> io::Result<()> {
    let mut digits = [0u8; 32];
    let mut position = digits.len() - 1;
    digits[position] = b'\n';
    let mut pid = libc::getpid() as u32;
    loop {
        position -= 1;
        digits[position] = b'0' + (pid % 10) as u8;
        pid /= 10;
        if pid == 0 {
            break;
        }
    }
    let bytes = &digits[position..];
    let written = libc::write(fd, bytes.as_ptr().cast(), bytes.len());
    if written != bytes.len() as isize {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_cgroup_paths() {
        let error = ManagedCgroup::open_existing(Path::new("/tmp"))
            .err()
            .unwrap();
        assert!(error.to_string().contains("cgroup v2"));
    }

    #[test]
    fn create_preflight_rejects_fake_cgroup_markers_before_creating_a_child() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "bpf-observer-fake-cgroup-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        let markers = [
            "cgroup.controllers",
            "cgroup.events",
            "cgroup.freeze",
            "cgroup.kill",
            "cgroup.max.depth",
            "cgroup.max.descendants",
            "cgroup.procs",
        ];
        for marker in markers {
            fs::write(root.join(marker), b"0\n").unwrap();
        }

        let error = ManagedCgroup::create(&root, "must-not-be-created")
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("not on cgroup v2"));
        assert!(!root.join("must-not-be-created").exists());

        for marker in markers {
            fs::remove_file(root.join(marker)).unwrap();
        }
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn parses_required_cgroup_event_fields() {
        let events = parse_cgroup_events("populated 0\nfrozen 1\npressure 0\n").unwrap();
        assert!(!events.populated);
        assert!(events.frozen);
    }

    #[test]
    fn rejects_missing_or_ambiguous_cgroup_event_fields() {
        assert!(parse_cgroup_events("populated 0\n").is_err());
        assert!(parse_cgroup_events("populated 0\npopulated 1\nfrozen 1\n").is_err());
        assert!(parse_cgroup_events("populated maybe\nfrozen 1\n").is_err());
    }
}
