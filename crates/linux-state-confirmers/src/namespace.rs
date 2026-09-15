// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::{
    LinuxNamespaceKind, NamespaceCaptureEvidence, NamespaceCaptureSource, NamespaceTarget,
    StateScope,
};
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::sync::Mutex;

const NSFS_MAGIC: libc::c_long = 0x6e73_6673;
const PROC_SUPER_MAGIC: libc::c_long = 0x9fa0;
const MOUNTINFO_READ_BUFFER_BYTES: usize = 32 * 1024;

pub(crate) struct RetainedMountinfoObservation {
    pub(crate) bytes: Vec<u8>,
    pub(crate) stable: bool,
}

/// Runtime-only capability which pins a Linux namespace after its original
/// process exits. The inode is checked when opened and before every use.
pub struct RetainedNamespace {
    kind: LinuxNamespaceKind,
    inode: u64,
    file: File,
    mount_root: Option<File>,
    mount_root_identity: Option<(u64, u64)>,
    mountinfo: Option<Mutex<File>>,
}

impl RetainedNamespace {
    pub fn open(target: &NamespaceTarget, kind: LinuxNamespaceKind) -> Result<Self> {
        target.validate()?;
        let component = if target.pid == 0 {
            "thread-self".to_owned()
        } else {
            target.pid.to_string()
        };
        let path = format!("/proc/{component}/ns/{}", kind.proc_name());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path.as_str())
            .with_context(|| format!("open retained {} namespace {path}", kind.proc_name()))?;
        let mount_root = if kind == LinuxNamespaceKind::Mount {
            Some(open_directory_capability(Path::new(&format!(
                "/proc/{component}/root"
            )))?)
        } else {
            None
        };
        let mountinfo = if kind == LinuxNamespaceKind::Mount {
            Some(open_mountinfo_capability(Path::new(&format!(
                "/proc/{component}/mountinfo"
            )))?)
        } else {
            None
        };
        let retained = Self::from_file(file, kind, mount_root, mountinfo)?;
        if retained.inode != target.expected_namespace_inode {
            bail!(
                "retained {} namespace inode {} != expected {}",
                kind.proc_name(),
                retained.inode,
                target.expected_namespace_inode
            );
        }
        Ok(retained)
    }

    fn current(kind: LinuxNamespaceKind) -> Result<Self> {
        let path = format!("/proc/thread-self/ns/{}", kind.proc_name());
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)
            .with_context(|| format!("open current {} namespace", kind.proc_name()))?;
        let mount_root = if kind == LinuxNamespaceKind::Mount {
            Some(open_directory_capability(Path::new(
                "/proc/thread-self/root",
            ))?)
        } else {
            None
        };
        let mountinfo = if kind == LinuxNamespaceKind::Mount {
            Some(open_mountinfo_capability(Path::new(
                "/proc/thread-self/mountinfo",
            ))?)
        } else {
            None
        };
        Self::from_file(file, kind, mount_root, mountinfo)
    }

    fn from_file(
        file: File,
        kind: LinuxNamespaceKind,
        mount_root: Option<File>,
        mountinfo: Option<File>,
    ) -> Result<Self> {
        let metadata = file
            .metadata()
            .with_context(|| format!("fstat {} namespace FD", kind.proc_name()))?;
        if metadata.ino() == 0 {
            bail!("kernel returned zero {} namespace inode", kind.proc_name());
        }
        let mut statfs = unsafe { std::mem::zeroed::<libc::statfs>() };
        if unsafe { libc::fstatfs(file.as_raw_fd(), &mut statfs) } != 0 {
            return Err(io::Error::last_os_error())
                .with_context(|| format!("fstatfs {} namespace FD", kind.proc_name()));
        }
        if statfs.f_type != NSFS_MAGIC {
            bail!(
                "{} namespace FD is not backed by nsfs (magic {:#x})",
                kind.proc_name(),
                statfs.f_type
            );
        }
        let mount_root_identity = mount_root
            .as_ref()
            .map(|root| {
                let metadata = root.metadata().context("fstat retained mount root FD")?;
                if !metadata.is_dir() || metadata.ino() == 0 {
                    bail!("retained mount root FD is not a valid directory");
                }
                Ok((metadata.dev(), metadata.ino()))
            })
            .transpose()?;
        if (kind == LinuxNamespaceKind::Mount) != mount_root_identity.is_some() {
            bail!("mount root capability presence disagrees with namespace kind");
        }
        if (kind == LinuxNamespaceKind::Mount) != mountinfo.is_some() {
            bail!("mountinfo capability presence disagrees with namespace kind");
        }
        Ok(Self {
            kind,
            inode: metadata.ino(),
            file,
            mount_root,
            mount_root_identity,
            mountinfo: mountinfo.map(Mutex::new),
        })
    }

    pub fn kind(&self) -> LinuxNamespaceKind {
        self.kind
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }

    pub(crate) fn file(&self) -> &File {
        &self.file
    }

    pub fn evidence(&self) -> NamespaceCaptureEvidence {
        NamespaceCaptureEvidence {
            kind: self.kind,
            inode: self.inode,
            source: NamespaceCaptureSource::RetainedFileDescriptor,
        }
    }

    pub fn mount_root_identity(&self) -> Result<(u64, u64)> {
        if self.kind != LinuxNamespaceKind::Mount {
            bail!("mount root identity requested from a non-mount namespace");
        }
        self.mount_root_identity
            .context("retained mount namespace lacks a root capability")
    }

    pub fn verify(&self) -> Result<()> {
        let metadata = self
            .file
            .metadata()
            .with_context(|| format!("re-fstat retained {} namespace", self.kind.proc_name()))?;
        if metadata.ino() != self.inode {
            bail!(
                "retained {} namespace identity changed from {} to {}",
                self.kind.proc_name(),
                self.inode,
                metadata.ino()
            );
        }
        if let (Some(root), Some(expected)) = (&self.mount_root, self.mount_root_identity) {
            let metadata = root.metadata().context("re-fstat retained mount root FD")?;
            if (metadata.dev(), metadata.ino()) != expected || !metadata.is_dir() {
                bail!("retained mount root object identity changed");
            }
        }
        if let Some(mountinfo) = &self.mountinfo {
            let mountinfo = mountinfo
                .lock()
                .map_err(|_| anyhow::anyhow!("retained mountinfo lock is poisoned"))?;
            validate_mountinfo_capability(&mountinfo)?;
        }
        Ok(())
    }

    pub(crate) fn read_mountinfo(&self, maximum: u64) -> Result<RetainedMountinfoObservation> {
        if self.kind != LinuxNamespaceKind::Mount {
            bail!("mountinfo requested from a non-mount namespace capability");
        }
        self.verify()?;
        let mountinfo = self
            .mountinfo
            .as_ref()
            .context("retained mount namespace lacks mountinfo capability")?;
        let mut mountinfo = mountinfo
            .lock()
            .map_err(|_| anyhow::anyhow!("retained mountinfo lock is poisoned"))?;
        let before = read_mountinfo_once(&mut mountinfo, maximum)?;
        let after = read_mountinfo_once(&mut mountinfo, maximum)?;
        drop(mountinfo);
        self.verify()?;
        Ok(RetainedMountinfoObservation {
            stable: before == after,
            bytes: after,
        })
    }

    /// Execute on the calling thread in this namespace and restore the exact
    /// prior namespace before returning. Callers must not run concurrent work
    /// on this thread while the closure is active.
    pub fn run<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        self.verify()?;
        let original = Self::current(self.kind)?;
        if original.inode == self.inode {
            return action();
        }
        // Mount setns rejects a caller whose fs_struct is shared. Recorder
        // helper threads may exist, so detach this calling thread's fs_struct
        // first; namespace membership remains thread-local and the other
        // threads keep their original cwd/root/mount namespace.
        if self.kind == LinuxNamespaceKind::Mount && unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
            return Err(io::Error::last_os_error())
                .context("unshare calling thread filesystem state before mount setns");
        }
        setns(&self.file, self.kind)
            .with_context(|| format!("enter retained {} namespace", self.kind.proc_name()))?;
        let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        let restore_result = setns(&original.file, self.kind)
            .with_context(|| format!("restore original {} namespace", self.kind.proc_name()));
        if let Err(error) = restore_result {
            eprintln!(
                "fatal: failed to restore original {} namespace: {error:#}",
                self.kind.proc_name()
            );
            std::process::abort();
        }
        match action_result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }

    /// Enter both a retained mount namespace and the target process's retained
    /// root directory. Mount setns alone leaves the caller's fs_struct root in
    /// place and would therefore resolve absolute Docker/chroot paths against
    /// the observer root. The exact original namespace, root and cwd are
    /// restored even when the action returns an error or panics.
    pub fn run_with_mount_root<T>(&self, action: impl FnOnce() -> Result<T>) -> Result<T> {
        if self.kind != LinuxNamespaceKind::Mount {
            bail!("run_with_mount_root requires a mount namespace capability");
        }
        self.verify()?;
        let target_root = self
            .mount_root
            .as_ref()
            .context("retained mount namespace lacks target root FD")?;
        let original = Self::current(LinuxNamespaceKind::Mount)?;
        let original_root = original
            .mount_root
            .as_ref()
            .context("current mount namespace lacks root FD")?;
        let original_cwd = open_directory_capability(Path::new("/proc/thread-self/cwd"))?;
        let namespace_differs = original.inode != self.inode;
        // Always install the retained O_PATH root, even when stat(2) reports
        // the same dev/inode as our current root. The same inode can be
        // reached through distinct bind-mount contexts, and only the retained
        // descriptor preserves the target process's exact path-resolution
        // anchor.
        if unsafe { libc::unshare(libc::CLONE_FS) } != 0 {
            return Err(io::Error::last_os_error())
                .context("unshare calling thread filesystem state before target-root entry");
        }
        if namespace_differs {
            setns(&self.file, self.kind).context("enter retained mount namespace")?;
        }
        if let Err(error) = replace_process_root(target_root) {
            restore_mount_context(&original, original_root, &original_cwd);
            return Err(error).context("enter retained target process root");
        }
        let action_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(action));
        restore_mount_context(&original, original_root, &original_cwd);
        match action_result {
            Ok(result) => result,
            Err(payload) => std::panic::resume_unwind(payload),
        }
    }
}

fn open_directory_capability(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open directory capability {}", path.display()))
}

fn open_mountinfo_capability(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open retained mountinfo capability {}", path.display()))?;
    validate_mountinfo_capability(&file)?;
    Ok(file)
}

fn validate_mountinfo_capability(file: &File) -> Result<()> {
    let metadata = file.metadata().context("fstat retained mountinfo FD")?;
    if !metadata.is_file() || metadata.ino() == 0 {
        bail!("retained mountinfo FD is not a valid procfs file");
    }
    let mut statfs = unsafe { std::mem::zeroed::<libc::statfs>() };
    if unsafe { libc::fstatfs(file.as_raw_fd(), &mut statfs) } != 0 {
        return Err(io::Error::last_os_error()).context("fstatfs retained mountinfo FD");
    }
    if statfs.f_type != PROC_SUPER_MAGIC {
        bail!(
            "retained mountinfo FD is not backed by procfs (magic {:#x})",
            statfs.f_type
        );
    }
    Ok(())
}

fn read_mountinfo_once(file: &mut File, maximum: u64) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))
        .context("rewind retained mountinfo FD")?;
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; MOUNTINFO_READ_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .context("read retained mountinfo FD")?;
        if read == 0 {
            break;
        }
        if bytes.len() as u64 + read as u64 > maximum {
            bail!("retained mountinfo exceeded configured byte bound");
        }
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

fn replace_process_root(root: &File) -> Result<()> {
    if unsafe { libc::fchdir(root.as_raw_fd()) } != 0 {
        return Err(io::Error::last_os_error()).context("fchdir retained root");
    }
    let dot = b".\0";
    if unsafe { libc::chroot(dot.as_ptr().cast()) } != 0 {
        return Err(io::Error::last_os_error()).context("chroot retained root");
    }
    let slash = b"/\0";
    if unsafe { libc::chdir(slash.as_ptr().cast()) } != 0 {
        return Err(io::Error::last_os_error()).context("chdir retained root");
    }
    Ok(())
}

fn restore_mount_context(original: &RetainedNamespace, root: &File, cwd: &File) {
    let restored = (|| -> Result<()> {
        setns(&original.file, LinuxNamespaceKind::Mount)
            .context("restore original mount namespace")?;
        replace_process_root(root).context("restore original process root")?;
        if unsafe { libc::fchdir(cwd.as_raw_fd()) } != 0 {
            return Err(io::Error::last_os_error()).context("restore original cwd");
        }
        Ok(())
    })();
    if let Err(error) = restored {
        eprintln!("fatal: failed to restore original mount/root context: {error:#}");
        std::process::abort();
    }
}

fn setns(file: &File, kind: LinuxNamespaceKind) -> Result<()> {
    if unsafe { libc::setns(file.as_raw_fd(), kind.clone_flag()) } != 0 {
        return Err(io::Error::last_os_error()).context("setns");
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SysctlNamespaceTargets {
    pub network: NamespaceTarget,
    pub uts: NamespaceTarget,
    pub ipc: NamespaceTarget,
}

/// Runtime-only namespace closure for one deployment observation. It is
/// deliberately absent from the serializable scope: snapshots commit the
/// exact namespace evidence and the deployment manifest commits the owning
/// process identities.
pub struct RetainedNamespaces {
    pub(crate) mounts: Option<RetainedNamespace>,
    pub(crate) network: Option<RetainedNamespace>,
    pub(crate) sysctl_network: Option<RetainedNamespace>,
    pub(crate) sysctl_uts: Option<RetainedNamespace>,
    pub(crate) sysctl_ipc: Option<RetainedNamespace>,
}

impl RetainedNamespaces {
    pub fn open(scope: &StateScope, sysctl: Option<&SysctlNamespaceTargets>) -> Result<Self> {
        scope.validate()?;
        if scope.sysctl.is_some() != sysctl.is_some() {
            bail!(
                "sysctl namespace targets must be present exactly when sysctl capture is enabled"
            );
        }
        let mounts = scope
            .mounts
            .as_ref()
            .map(|value| RetainedNamespace::open(&value.namespace, LinuxNamespaceKind::Mount))
            .transpose()?;
        let network = scope
            .network
            .as_ref()
            .map(|value| RetainedNamespace::open(&value.namespace, LinuxNamespaceKind::Network))
            .transpose()?;
        let sysctl_network = sysctl
            .map(|value| RetainedNamespace::open(&value.network, LinuxNamespaceKind::Network))
            .transpose()?;
        let sysctl_uts = sysctl
            .map(|value| RetainedNamespace::open(&value.uts, LinuxNamespaceKind::Uts))
            .transpose()?;
        let sysctl_ipc = sysctl
            .map(|value| RetainedNamespace::open(&value.ipc, LinuxNamespaceKind::Ipc))
            .transpose()?;
        let retained = Self {
            mounts,
            network,
            sysctl_network,
            sysctl_uts,
            sysctl_ipc,
        };
        retained.verify()?;
        Ok(retained)
    }

    pub fn verify(&self) -> Result<()> {
        for namespace in [
            self.mounts.as_ref(),
            self.network.as_ref(),
            self.sysctl_network.as_ref(),
            self.sysctl_uts.as_ref(),
            self.sysctl_ipc.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            namespace.verify()?;
        }
        Ok(())
    }
}
