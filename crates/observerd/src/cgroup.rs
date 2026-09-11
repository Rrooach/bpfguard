// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

pub struct ManagedCgroup {
    path: PathBuf,
    owned: bool,
    id: u64,
}

impl ManagedCgroup {
    pub fn create(root: &Path, run_id: &str) -> Result<Self> {
        ensure_cgroup_v2(root)?;
        fs::create_dir_all(root)
            .with_context(|| format!("create cgroup root {}", root.display()))?;
        let path = root.join(run_id);
        fs::create_dir(&path).with_context(|| format!("create run cgroup {}", path.display()))?;

        // The recorder currently matches one exact cgroup ID. Forbid a delegated
        // subtree so descendants cannot silently escape that filter.
        if let Err(error) = fs::write(path.join("cgroup.max.depth"), b"0\n") {
            let primary =
                anyhow!(error).context(format!("set cgroup.max.depth=0 for {}", path.display()));
            return Err(with_creation_cleanup(&path, primary));
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
        Ok(Self {
            path,
            owned: true,
            id,
        })
    }

    #[cfg(test)]
    pub fn open_existing(path: &Path) -> Result<Self> {
        ensure_cgroup_v2(path)?;
        let id = fs::metadata(path)
            .with_context(|| format!("stat cgroup {}", path.display()))?
            .ino();
        Ok(Self {
            path: path.to_path_buf(),
            owned: false,
            id,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn configure_child(&self, command: &mut Command) -> Result<()> {
        let procs = CString::new(self.path.join("cgroup.procs").as_os_str().as_bytes())
            .map_err(|_| anyhow!("cgroup path contains a NUL byte"))?;
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
                move_self_to_cgroup(&procs)
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
        if self.populated()? {
            bail!("refusing to freeze a populated run cgroup");
        }
        fs::write(self.path.join("cgroup.freeze"), b"1\n")
            .with_context(|| format!("freeze run cgroup {}", self.path.display()))?;
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
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!("timed out freezing run cgroup {}", self.path.display());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn events(&self) -> Result<CgroupEvents> {
        let events = fs::read_to_string(self.path.join("cgroup.events"))
            .with_context(|| format!("read {}/cgroup.events", self.path.display()))?;
        parse_cgroup_events(&events)
    }

    pub fn kill_all(&self) -> Result<()> {
        fs::write(self.path.join("cgroup.kill"), b"1\n")
            .with_context(|| format!("kill tasks in cgroup {}", self.path.display()))
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
                Ok(true)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => {
                Err(error).with_context(|| format!("inspect owned cgroup {}", self.path.display()))
            }
        }
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
        if candidate.join("cgroup.controllers").exists() || candidate.join("cgroup.events").exists()
        {
            return Ok(());
        }
        cursor = candidate.parent();
    }
    bail!("{} is not on a cgroup v2 hierarchy", path.display())
}

unsafe fn move_self_to_cgroup(procs: &CString) -> io::Result<()> {
    let fd = libc::open(procs.as_ptr(), libc::O_WRONLY | libc::O_CLOEXEC);
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }

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
    let saved = io::Error::last_os_error();
    libc::close(fd);
    if written != bytes.len() as isize {
        return Err(saved);
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
