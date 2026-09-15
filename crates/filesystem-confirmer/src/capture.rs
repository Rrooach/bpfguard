// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::*;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::cmp;
use std::ffi::{CString, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read};
use std::mem::MaybeUninit;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const READ_BUFFER_BYTES: usize = 64 * 1024;
const DIRECTORY_BUFFER_BYTES: usize = 32 * 1024;
const LINUX_DIRENT64_NAME_OFFSET: usize = 19;

struct NoAtimeReadDir {
    directory: File,
    buffer: Vec<u8>,
    offset: usize,
    filled: usize,
    finished: bool,
}

impl NoAtimeReadDir {
    fn open(path: &Path) -> io::Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "directory path contains NUL")
        })?;
        let fd = unsafe {
            libc::open(
                path.as_ptr(),
                libc::O_RDONLY
                    | libc::O_CLOEXEC
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_NOATIME,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            directory: unsafe { File::from_raw_fd(fd) },
            buffer: vec![0; DIRECTORY_BUFFER_BYTES],
            offset: 0,
            filled: 0,
            finished: false,
        })
    }

    fn metadata(&self) -> io::Result<Metadata> {
        self.directory.metadata()
    }

    fn fail(&mut self, message: &'static str) -> Option<io::Result<OsString>> {
        self.finished = true;
        Some(Err(io::Error::new(io::ErrorKind::InvalidData, message)))
    }
}

impl Iterator for NoAtimeReadDir {
    type Item = io::Result<OsString>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            if self.offset == self.filled {
                let count = unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        self.directory.as_raw_fd(),
                        self.buffer.as_mut_ptr(),
                        self.buffer.len(),
                    )
                };
                if count < 0 {
                    self.finished = true;
                    return Some(Err(io::Error::last_os_error()));
                }
                if count == 0 {
                    self.finished = true;
                    return None;
                }
                let Ok(count) = usize::try_from(count) else {
                    return self.fail("getdents64 returned an invalid byte count");
                };
                if count > self.buffer.len() {
                    return self.fail("getdents64 exceeded its supplied buffer");
                }
                self.offset = 0;
                self.filled = count;
            }

            if self.filled - self.offset < LINUX_DIRENT64_NAME_OFFSET {
                return self.fail("getdents64 returned a truncated record header");
            }
            let record_length =
                u16::from_ne_bytes([self.buffer[self.offset + 16], self.buffer[self.offset + 17]])
                    as usize;
            if record_length <= LINUX_DIRENT64_NAME_OFFSET
                || record_length > self.filled - self.offset
            {
                return self.fail("getdents64 returned an invalid record length");
            }
            let name_start = self.offset + LINUX_DIRENT64_NAME_OFFSET;
            let record_end = self.offset + record_length;
            self.offset = record_end;
            let name_field = &self.buffer[name_start..record_end];
            let Some(nul) = name_field.iter().position(|byte| *byte == 0) else {
                return self.fail("getdents64 name is not NUL terminated");
            };
            let name = &name_field[..nul];
            if name.is_empty() {
                return self.fail("getdents64 returned an empty name");
            }
            if name == b"." || name == b".." {
                continue;
            }
            return Some(Ok(OsString::from_vec(name.to_vec())));
        }
    }
}

struct RootCaptureResult {
    status: RootCaptureStatus,
    filesystem_magic: Option<u64>,
    filesystem_class: RootFilesystemClass,
}

impl RootCaptureResult {
    fn missing() -> Self {
        Self {
            status: RootCaptureStatus::Missing,
            filesystem_magic: None,
            filesystem_class: RootFilesystemClass::Unavailable,
        }
    }

    fn incomplete_unavailable() -> Self {
        Self {
            status: RootCaptureStatus::Incomplete,
            filesystem_magic: None,
            filesystem_class: RootFilesystemClass::Unavailable,
        }
    }
}

pub fn capture(scope: &FilesystemScope, request: &CaptureRequest) -> Result<FilesystemSnapshot> {
    capture_internal(
        scope,
        request,
        MountNamespaceCaptureSource::CurrentProcess,
        None,
        None,
    )
}

/// Capture after a trusted caller entered a retained mount namespace. The
/// current namespace inode is checked here so provenance cannot be labelled
/// retained while resolving roots in a different namespace.
pub fn capture_in_retained_mount_namespace(
    scope: &FilesystemScope,
    request: &CaptureRequest,
    expected_mount_namespace_inode: u64,
    expected_mount_root_device: u64,
    expected_mount_root_inode: u64,
) -> Result<FilesystemSnapshot> {
    if expected_mount_namespace_inode == 0 || expected_mount_root_inode == 0 {
        bail!("expected retained mount namespace/root identity must be non-zero");
    }
    capture_internal(
        scope,
        request,
        MountNamespaceCaptureSource::RetainedFileDescriptor,
        Some(expected_mount_namespace_inode),
        Some((expected_mount_root_device, expected_mount_root_inode)),
    )
}

fn capture_internal(
    scope: &FilesystemScope,
    request: &CaptureRequest,
    mount_namespace_capture_source: MountNamespaceCaptureSource,
    expected_mount_namespace_inode: Option<u64>,
    expected_mount_root_identity: Option<(u64, u64)>,
) -> Result<FilesystemSnapshot> {
    scope.validate()?;
    request.validate()?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .context("read boot ID for filesystem snapshot")?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        bail!("kernel returned an empty boot ID");
    }
    let (mount_namespace_inode, mount_root_identity) = resolve_mount_capture_identity(
        mount_namespace_capture_source,
        expected_mount_namespace_inode,
        expected_mount_root_identity,
        current_process_mount_identity,
    )?;
    let captured_unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(scope.limits.deadline_ms))
        .context("filesystem capture deadline exceeds monotonic clock range")?;
    let mut state = CaptureState::new(scope, deadline);
    let mut roots = Vec::with_capacity(scope.roots.len());
    for (root_index, selected) in scope.roots.iter().enumerate() {
        let root_index = root_index as u32;
        let observation = if state.stop_all {
            RootCaptureResult::incomplete_unavailable()
        } else {
            let path = selected.path()?;
            state.capture_root(root_index, &path)
        };
        roots.push(RootObservation {
            root_index,
            absolute_path_bytes_hex: selected.path_bytes_hex.clone(),
            filesystem_magic: observation.filesystem_magic,
            filesystem_class: observation.filesystem_class,
            status: observation.status,
        });
    }
    state.canonicalize();
    let statistics = statistics(&state.entries)?;
    let mut reasons = Vec::new();
    if !state.errors.is_empty() {
        reasons.push("filesystem capture contains read or stability errors".to_owned());
    }
    if !state.limits_hit.is_empty() {
        reasons.push("filesystem capture hit a configured or hard resource limit".to_owned());
    }
    if roots
        .iter()
        .any(|root| root.status == RootCaptureStatus::Incomplete)
    {
        reasons.push("one or more filesystem roots are incomplete".to_owned());
    }
    if roots
        .iter()
        .any(|root| root.status == RootCaptureStatus::Missing)
    {
        reasons.push("one or more filesystem roots are missing".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    let completeness = Completeness {
        status: if reasons.is_empty() {
            CompletenessStatus::Complete
        } else {
            CompletenessStatus::Incomplete
        },
        reasons,
    };
    let snapshot = FilesystemSnapshot {
        protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
        snapshot_id: request.snapshot_id.clone(),
        phase: request.phase,
        captured_unix_ns,
        boot_id,
        mount_namespace_inode,
        mount_namespace_capture_source,
        mount_root_device: mount_root_identity.0,
        mount_root_inode: mount_root_identity.1,
        scope: scope.clone(),
        scope_sha256: scope.sha256()?,
        roots,
        entries: state.entries,
        errors: state.errors,
        limits_hit: state.limits_hit,
        statistics,
        completeness,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn current_process_mount_identity() -> Result<(u64, (u64, u64))> {
    let mount_namespace_inode = fs::metadata("/proc/thread-self/ns/mnt")
        .context("inspect mount namespace for filesystem snapshot")?
        .ino();
    let mount_root = fs::metadata("/proc/thread-self/root")
        .context("inspect root object for filesystem snapshot")?;
    Ok((mount_namespace_inode, (mount_root.dev(), mount_root.ino())))
}

fn resolve_mount_capture_identity<F>(
    source: MountNamespaceCaptureSource,
    expected_namespace_inode: Option<u64>,
    expected_root_identity: Option<(u64, u64)>,
    current_process_identity: F,
) -> Result<(u64, (u64, u64))>
where
    F: FnOnce() -> Result<(u64, (u64, u64))>,
{
    let identity = match source {
        MountNamespaceCaptureSource::CurrentProcess => {
            if expected_namespace_inode.is_some() || expected_root_identity.is_some() {
                bail!("current-process capture unexpectedly carries retained identities");
            }
            current_process_identity()?
        }
        MountNamespaceCaptureSource::RetainedFileDescriptor => {
            let namespace_inode = expected_namespace_inode
                .context("retained capture lacks its namespace capability identity")?;
            let expected_root = expected_root_identity
                .context("retained capture lacks its root capability identity")?;
            // The caller has already fstat/nsfs-validated the retained namespace
            // FD, entered it with setns(2), and chrooted through the retained
            // O_PATH root.  Do not consult /proc/thread-self here: a procfs
            // mounted for a child PID namespace cannot represent this Host-PID-
            // namespace observer thread.  stat("/") instead proves that chroot
            // installed the exact retained root object.
            let root = fs::metadata("/").context("inspect installed retained mount root")?;
            let observed_root = (root.dev(), root.ino());
            if observed_root != expected_root {
                bail!("current root object does not match retained target root capability");
            }
            (namespace_inode, observed_root)
        }
    };
    if identity.0 == 0 || (identity.1).1 == 0 {
        bail!("kernel returned an invalid mount namespace/root identity");
    }
    Ok(identity)
}

#[cfg(test)]
mod mount_identity_tests {
    use super::*;

    #[test]
    fn retained_identity_never_consults_proc_thread_self() {
        let root = fs::metadata("/").expect("stat current root");
        let expected_root = (root.dev(), root.ino());
        let identity = resolve_mount_capture_identity(
            MountNamespaceCaptureSource::RetainedFileDescriptor,
            Some(41),
            Some(expected_root),
            || panic!("retained capture must not consult current-process procfs identity"),
        )
        .expect("resolve retained identity without procfs self lookup");

        assert_eq!(identity, (41, expected_root));
    }
}

struct CaptureState<'a> {
    scope: &'a FilesystemScope,
    deadline: Instant,
    entries: Vec<FilesystemEntry>,
    errors: Vec<CaptureError>,
    limits_hit: Vec<LimitObservation>,
    content_bytes_reserved: u64,
    xattr_bytes_reserved: u64,
    xattrs_reserved: u64,
    path_bytes_reserved: u64,
    stop_all: bool,
    root_incomplete: Vec<bool>,
}

impl<'a> CaptureState<'a> {
    fn new(scope: &'a FilesystemScope, deadline: Instant) -> Self {
        Self {
            scope,
            deadline,
            entries: Vec::new(),
            errors: Vec::new(),
            limits_hit: Vec::new(),
            content_bytes_reserved: 0,
            xattr_bytes_reserved: 0,
            xattrs_reserved: 0,
            path_bytes_reserved: 0,
            stop_all: false,
            root_incomplete: vec![false; scope.roots.len()],
        }
    }

    fn capture_root(&mut self, root_index: u32, path: &Path) -> RootCaptureResult {
        if !self.check_deadline(root_index, &[]) {
            return RootCaptureResult::incomplete_unavailable();
        }
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return RootCaptureResult::missing()
            }
            Err(error) => {
                self.record_io_error(
                    root_index,
                    &[],
                    CaptureOperation::RootMetadata,
                    &error,
                    None,
                );
                return RootCaptureResult::incomplete_unavailable();
            }
        };
        let filesystem_magic = match filesystem_magic(path) {
            Ok(magic) => magic,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    &[],
                    CaptureOperation::InspectFilesystem,
                    &error,
                    None,
                );
                return RootCaptureResult::incomplete_unavailable();
            }
        };
        let filesystem_class = classify_root_filesystem(filesystem_magic);
        if filesystem_class.requires_domain_adapter() {
            self.record_synthetic_error(
                root_index,
                &[],
                CaptureOperation::InspectFilesystem,
                CaptureErrorClass::Unsupported,
                None,
            );
            return RootCaptureResult {
                status: RootCaptureStatus::Incomplete,
                filesystem_magic: Some(filesystem_magic),
                filesystem_class,
            };
        }
        let root_device = metadata.dev();
        self.walk_node(root_index, path, Vec::new(), 0, root_device, metadata);
        let status = if self.root_incomplete[root_index as usize] {
            RootCaptureStatus::Incomplete
        } else {
            RootCaptureStatus::Captured
        };
        RootCaptureResult {
            status,
            filesystem_magic: Some(filesystem_magic),
            filesystem_class,
        }
    }

    fn walk_node(
        &mut self,
        root_index: u32,
        path: &Path,
        relative: Vec<u8>,
        depth: u32,
        root_device: u64,
        metadata: Metadata,
    ) {
        if self.stop_all || !self.check_deadline(root_index, &relative) {
            return;
        }
        if !self.reserve_entry(root_index, &relative) {
            return;
        }
        let view_before = MetadataView::from_metadata(&metadata);
        let entry_type = classify_type(&metadata);
        let cross_device_directory = entry_type == FilesystemEntryType::Directory
            && depth > 0
            && metadata.dev() != root_device
            && self.scope.capture.cross_filesystems == CrossFilesystemPolicy::SameDeviceOnly;

        let content = if entry_type == FilesystemEntryType::RegularFile {
            self.capture_content(root_index, &relative, path, &view_before)
        } else {
            ContentObservation::not_applicable()
        };
        let symlink = if entry_type == FilesystemEntryType::Symlink {
            self.capture_symlink(root_index, &relative, path)
        } else {
            SymlinkObservation::not_applicable()
        };
        let xattrs = self.capture_xattrs(root_index, &relative, path);
        let traversal = if entry_type != FilesystemEntryType::Directory {
            TraversalStatus::NotDirectory
        } else if cross_device_directory {
            TraversalStatus::CrossDeviceExcluded
        } else {
            TraversalStatus::Traversed
        };
        let entry_index = self.entries.len();
        self.entries.push(FilesystemEntry {
            root_index,
            relative_path_bytes_hex: hex::encode(&relative),
            relative_path_display: display_relative_path(&relative),
            entry_type,
            device: metadata.dev(),
            inode: metadata.ino(),
            rdev: metadata.rdev(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            hard_link_count: metadata.nlink(),
            size_bytes: metadata.size(),
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
            traversal,
            content,
            symlink,
            xattrs,
        });

        if entry_type == FilesystemEntryType::Directory && !cross_device_directory {
            self.walk_directory(root_index, path, &relative, depth, root_device, entry_index);
        }

        match fs::symlink_metadata(path) {
            Ok(after) if MetadataView::from_metadata(&after) == view_before => {}
            Ok(_) => {
                self.record_synthetic_error(
                    root_index,
                    &relative,
                    CaptureOperation::StabilityCheck,
                    CaptureErrorClass::Other,
                    None,
                );
                self.mark_entry_unstable(entry_index);
            }
            Err(error) => {
                self.record_io_error(
                    root_index,
                    &relative,
                    CaptureOperation::StabilityCheck,
                    &error,
                    None,
                );
                self.mark_entry_unstable(entry_index);
            }
        }
    }

    fn walk_directory(
        &mut self,
        root_index: u32,
        path: &Path,
        relative: &[u8],
        depth: u32,
        root_device: u64,
        entry_index: usize,
    ) {
        let iterator = match NoAtimeReadDir::open(path) {
            Ok(iterator) => iterator,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::ReadDirectory,
                    &error,
                    None,
                );
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
        };
        match iterator.metadata() {
            Ok(metadata)
                if metadata.dev() == self.entries[entry_index].device
                    && metadata.ino() == self.entries[entry_index].inode => {}
            Ok(_) => {
                self.record_synthetic_error(
                    root_index,
                    relative,
                    CaptureOperation::StabilityCheck,
                    CaptureErrorClass::Other,
                    None,
                );
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::StabilityCheck,
                    &error,
                    None,
                );
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
        }
        let remaining = self
            .scope
            .limits
            .max_entries
            .saturating_sub(self.entries.len() as u64);
        let mut names = Vec::new();
        for item in iterator {
            if !self.check_deadline(root_index, relative) {
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
            let item = match item {
                Ok(item) => item,
                Err(error) => {
                    self.record_io_error(
                        root_index,
                        relative,
                        CaptureOperation::ReadDirectory,
                        &error,
                        None,
                    );
                    self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                    return;
                }
            };
            names.push(item);
            if names.len() as u64 > remaining {
                self.record_limit(
                    root_index,
                    relative,
                    LimitKind::EntryCount,
                    self.scope.limits.max_entries,
                    self.scope.limits.max_entries.saturating_add(1),
                );
                self.stop_all = true;
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
        }
        names.sort_by(|left, right| {
            left.as_os_str()
                .as_bytes()
                .cmp(right.as_os_str().as_bytes())
        });
        if !names.is_empty() && depth >= self.scope.limits.max_depth {
            self.record_limit(
                root_index,
                relative,
                LimitKind::Depth,
                u64::from(self.scope.limits.max_depth),
                u64::from(depth).saturating_add(1),
            );
            self.entries[entry_index].traversal = TraversalStatus::Incomplete;
            return;
        }
        for name in names {
            if self.stop_all {
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                return;
            }
            let child_relative = join_relative(relative, &name);
            let child_path = path.join(&name);
            let metadata = match fs::symlink_metadata(&child_path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.record_io_error(
                        root_index,
                        &child_relative,
                        CaptureOperation::EntryMetadata,
                        &error,
                        None,
                    );
                    self.entries[entry_index].traversal = TraversalStatus::Incomplete;
                    continue;
                }
            };
            self.walk_node(
                root_index,
                &child_path,
                child_relative,
                depth + 1,
                root_device,
                metadata,
            );
            if self.root_incomplete[root_index as usize] {
                self.entries[entry_index].traversal = TraversalStatus::Incomplete;
            }
        }
    }

    fn capture_content(
        &mut self,
        root_index: u32,
        relative: &[u8],
        path: &Path,
        expected: &MetadataView,
    ) -> ContentObservation {
        if self.scope.capture.regular_file_content == RegularFileContentMode::MetadataOnly {
            return ContentObservation {
                status: ContentCaptureStatus::NotRequested,
                size_bytes: None,
                sha256: None,
            };
        }
        let size = expected.size;
        if size > self.scope.limits.max_file_content_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::FileContentBytes,
                self.scope.limits.max_file_content_bytes,
                size,
            );
            return incomplete_content(ContentCaptureStatus::LimitExceeded, size);
        }
        let total = self.content_bytes_reserved.saturating_add(size);
        if total > self.scope.limits.max_total_content_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::TotalContentBytes,
                self.scope.limits.max_total_content_bytes,
                total,
            );
            return incomplete_content(ContentCaptureStatus::LimitExceeded, size);
        }
        self.content_bytes_reserved = total;
        let mut file = match open_regular_file(path) {
            Ok(file) => file,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::OpenContent,
                    &error,
                    None,
                );
                return incomplete_content(ContentCaptureStatus::ReadFailed, size);
            }
        };
        match file.metadata() {
            Ok(metadata) if MetadataView::from_metadata(&metadata) == *expected => {}
            Ok(_) => {
                self.record_synthetic_error(
                    root_index,
                    relative,
                    CaptureOperation::StabilityCheck,
                    CaptureErrorClass::Other,
                    None,
                );
                return incomplete_content(ContentCaptureStatus::Unstable, size);
            }
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::StabilityCheck,
                    &error,
                    None,
                );
                return incomplete_content(ContentCaptureStatus::ReadFailed, size);
            }
        }
        let mut hasher = Sha256::new();
        let mut read_total = 0u64;
        let mut buffer = [0u8; READ_BUFFER_BYTES];
        loop {
            if !self.check_deadline(root_index, relative) {
                return incomplete_content(ContentCaptureStatus::LimitExceeded, size);
            }
            let count = match file.read(&mut buffer) {
                Ok(count) => count,
                Err(error) => {
                    self.record_io_error(
                        root_index,
                        relative,
                        CaptureOperation::ReadContent,
                        &error,
                        None,
                    );
                    return incomplete_content(ContentCaptureStatus::ReadFailed, size);
                }
            };
            if count == 0 {
                break;
            }
            read_total = read_total.saturating_add(count as u64);
            if read_total > size {
                self.record_synthetic_error(
                    root_index,
                    relative,
                    CaptureOperation::StabilityCheck,
                    CaptureErrorClass::Other,
                    None,
                );
                return incomplete_content(ContentCaptureStatus::Unstable, size);
            }
            hasher.update(&buffer[..count]);
        }
        let stable = read_total == size
            && file
                .metadata()
                .map(|metadata| MetadataView::from_metadata(&metadata) == *expected)
                .unwrap_or(false);
        if !stable {
            self.record_synthetic_error(
                root_index,
                relative,
                CaptureOperation::StabilityCheck,
                CaptureErrorClass::Other,
                None,
            );
            return incomplete_content(ContentCaptureStatus::Unstable, size);
        }
        ContentObservation {
            status: ContentCaptureStatus::Captured,
            size_bytes: Some(size),
            sha256: Some(hex::encode(hasher.finalize())),
        }
    }

    fn capture_symlink(
        &mut self,
        root_index: u32,
        relative: &[u8],
        path: &Path,
    ) -> SymlinkObservation {
        if self.scope.capture.symlinks == SymlinkMode::MetadataOnly {
            return SymlinkObservation {
                status: SymlinkCaptureStatus::MetadataOnly,
                target_bytes_hex: None,
            };
        }
        let target = match fs::read_link(path) {
            Ok(target) => target,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::ReadSymlink,
                    &error,
                    None,
                );
                return SymlinkObservation {
                    status: SymlinkCaptureStatus::ReadFailed,
                    target_bytes_hex: None,
                };
            }
        };
        let bytes = target.as_os_str().as_bytes();
        if bytes.len() as u64 > self.scope.limits.max_symlink_target_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::SymlinkTargetBytes,
                self.scope.limits.max_symlink_target_bytes,
                bytes.len() as u64,
            );
            return SymlinkObservation {
                status: SymlinkCaptureStatus::LimitExceeded,
                target_bytes_hex: None,
            };
        }
        SymlinkObservation {
            status: SymlinkCaptureStatus::Captured,
            target_bytes_hex: Some(hex::encode(bytes)),
        }
    }

    fn capture_xattrs(
        &mut self,
        root_index: u32,
        relative: &[u8],
        path: &Path,
    ) -> XattrObservation {
        if self.scope.capture.xattrs == XattrMode::NotRequested {
            return XattrObservation {
                status: XattrCaptureStatus::NotRequested,
                attributes: Vec::new(),
            };
        }
        let list_size = match xattr_list_size(path) {
            Ok(size) => size,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::ListXattrs,
                    &error,
                    None,
                );
                return partial_xattrs();
            }
        };
        if list_size as u64 > self.scope.limits.max_xattr_list_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::XattrListBytes,
                self.scope.limits.max_xattr_list_bytes,
                list_size as u64,
            );
            return partial_xattrs();
        }
        let total = self.xattr_bytes_reserved.saturating_add(list_size as u64);
        if total > self.scope.limits.max_total_xattr_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::TotalXattrBytes,
                self.scope.limits.max_total_xattr_bytes,
                total,
            );
            return partial_xattrs();
        }
        self.xattr_bytes_reserved = total;
        let mut names = match read_xattr_names(path, list_size) {
            Ok(names) => names,
            Err(error) => {
                self.record_io_error(
                    root_index,
                    relative,
                    CaptureOperation::ListXattrs,
                    &error,
                    None,
                );
                return partial_xattrs();
            }
        };
        names.sort();
        if names.windows(2).any(|pair| pair[0] == pair[1]) {
            self.record_synthetic_error(
                root_index,
                relative,
                CaptureOperation::ListXattrs,
                CaptureErrorClass::InvalidData,
                None,
            );
            return partial_xattrs();
        }
        let mut partial = false;
        if names.len() as u32 > self.scope.limits.max_xattrs_per_entry {
            self.record_limit(
                root_index,
                relative,
                LimitKind::XattrCount,
                u64::from(self.scope.limits.max_xattrs_per_entry),
                names.len() as u64,
            );
            names.truncate(self.scope.limits.max_xattrs_per_entry as usize);
            partial = true;
        }
        let total_count = self.xattrs_reserved.saturating_add(names.len() as u64);
        if total_count > self.scope.limits.max_total_xattrs {
            self.record_limit(
                root_index,
                relative,
                LimitKind::TotalXattrCount,
                self.scope.limits.max_total_xattrs,
                total_count,
            );
            let remaining = self
                .scope
                .limits
                .max_total_xattrs
                .saturating_sub(self.xattrs_reserved) as usize;
            names.truncate(remaining);
            partial = true;
        }
        self.xattrs_reserved = self.xattrs_reserved.saturating_add(names.len() as u64);
        let mut attributes = Vec::with_capacity(names.len());
        for name in names {
            let size = match xattr_value_size(path, &name) {
                Ok(size) => size,
                Err(error) => {
                    self.record_io_error(
                        root_index,
                        relative,
                        CaptureOperation::ReadXattr,
                        &error,
                        Some(&name),
                    );
                    attributes.push(XattrValueObservation {
                        name_bytes_hex: hex::encode(&name),
                        value_size_bytes: None,
                        value_sha256: None,
                        status: XattrValueStatus::ReadFailed,
                    });
                    partial = true;
                    continue;
                }
            };
            if size as u64 > self.scope.limits.max_xattr_value_bytes {
                self.record_limit(
                    root_index,
                    relative,
                    LimitKind::XattrValueBytes,
                    self.scope.limits.max_xattr_value_bytes,
                    size as u64,
                );
                attributes.push(XattrValueObservation {
                    name_bytes_hex: hex::encode(&name),
                    value_size_bytes: Some(size as u64),
                    value_sha256: None,
                    status: XattrValueStatus::LimitExceeded,
                });
                partial = true;
                continue;
            }
            let total = self.xattr_bytes_reserved.saturating_add(size as u64);
            if total > self.scope.limits.max_total_xattr_bytes {
                self.record_limit(
                    root_index,
                    relative,
                    LimitKind::TotalXattrBytes,
                    self.scope.limits.max_total_xattr_bytes,
                    total,
                );
                attributes.push(XattrValueObservation {
                    name_bytes_hex: hex::encode(&name),
                    value_size_bytes: Some(size as u64),
                    value_sha256: None,
                    status: XattrValueStatus::LimitExceeded,
                });
                partial = true;
                continue;
            }
            self.xattr_bytes_reserved = total;
            match read_xattr_value(path, &name, size) {
                Ok(value) => attributes.push(XattrValueObservation {
                    name_bytes_hex: hex::encode(&name),
                    value_size_bytes: Some(value.len() as u64),
                    value_sha256: Some(hex::encode(Sha256::digest(&value))),
                    status: XattrValueStatus::Captured,
                }),
                Err(error) => {
                    self.record_io_error(
                        root_index,
                        relative,
                        CaptureOperation::ReadXattr,
                        &error,
                        Some(&name),
                    );
                    attributes.push(XattrValueObservation {
                        name_bytes_hex: hex::encode(&name),
                        value_size_bytes: Some(size as u64),
                        value_sha256: None,
                        status: XattrValueStatus::ReadFailed,
                    });
                    partial = true;
                }
            }
        }
        XattrObservation {
            status: if partial {
                XattrCaptureStatus::Partial
            } else {
                XattrCaptureStatus::Captured
            },
            attributes,
        }
    }

    fn reserve_entry(&mut self, root_index: u32, relative: &[u8]) -> bool {
        let observed_entries = self.entries.len() as u64 + 1;
        if observed_entries > self.scope.limits.max_entries {
            self.record_limit(
                root_index,
                relative,
                LimitKind::EntryCount,
                self.scope.limits.max_entries,
                observed_entries,
            );
            self.stop_all = true;
            return false;
        }
        let total_path_bytes = self
            .path_bytes_reserved
            .saturating_add(relative.len() as u64);
        if total_path_bytes > self.scope.limits.max_total_path_bytes {
            self.record_limit(
                root_index,
                relative,
                LimitKind::TotalPathBytes,
                self.scope.limits.max_total_path_bytes,
                total_path_bytes,
            );
            self.stop_all = true;
            return false;
        }
        self.path_bytes_reserved = total_path_bytes;
        true
    }

    fn check_deadline(&mut self, root_index: u32, relative: &[u8]) -> bool {
        if Instant::now() < self.deadline {
            return true;
        }
        if !self.stop_all {
            self.record_limit(
                root_index,
                relative,
                LimitKind::Deadline,
                self.scope.limits.deadline_ms,
                self.scope.limits.deadline_ms.saturating_add(1),
            );
        }
        self.stop_all = true;
        false
    }

    fn record_io_error(
        &mut self,
        root_index: u32,
        relative: &[u8],
        operation: CaptureOperation,
        error: &io::Error,
        subject: Option<&[u8]>,
    ) {
        let previous_error_count = self.errors.len();
        self.record_synthetic_error(
            root_index,
            relative,
            operation,
            error_class(error),
            error.raw_os_error(),
        );
        if self.errors.len() > previous_error_count {
            if let (Some(last), Some(subject)) = (self.errors.last_mut(), subject) {
                last.subject_bytes_hex = Some(hex::encode(subject));
            }
        }
    }

    fn record_synthetic_error(
        &mut self,
        root_index: u32,
        relative: &[u8],
        operation: CaptureOperation,
        class: CaptureErrorClass,
        errno: Option<i32>,
    ) {
        self.root_incomplete[root_index as usize] = true;
        if self.errors.len() >= HARD_MAX_CAPTURE_ERRORS {
            self.record_limit(
                root_index,
                relative,
                LimitKind::ErrorCount,
                HARD_MAX_CAPTURE_ERRORS as u64,
                HARD_MAX_CAPTURE_ERRORS as u64 + 1,
            );
            self.stop_all = true;
            return;
        }
        self.errors.push(CaptureError {
            root_index,
            relative_path_bytes_hex: hex::encode(relative),
            operation,
            class,
            errno,
            subject_bytes_hex: None,
        });
    }

    fn record_limit(
        &mut self,
        root_index: u32,
        relative: &[u8],
        kind: LimitKind,
        configured: u64,
        observed_at_least: u64,
    ) {
        self.root_incomplete[root_index as usize] = true;
        if self.limits_hit.len() >= HARD_MAX_LIMIT_OBSERVATIONS {
            self.stop_all = true;
            return;
        }
        self.limits_hit.push(LimitObservation {
            root_index,
            relative_path_bytes_hex: hex::encode(relative),
            kind,
            configured,
            observed_at_least: cmp::max(observed_at_least, configured.saturating_add(1)),
        });
    }

    fn mark_entry_unstable(&mut self, entry_index: usize) {
        let entry = &mut self.entries[entry_index];
        if entry.content.status == ContentCaptureStatus::Captured {
            entry.content.status = ContentCaptureStatus::Unstable;
            entry.content.sha256 = None;
        }
        if entry.symlink.status == SymlinkCaptureStatus::Captured {
            entry.symlink.status = SymlinkCaptureStatus::Unstable;
            entry.symlink.target_bytes_hex = None;
        }
        if entry.xattrs.status == XattrCaptureStatus::Captured {
            entry.xattrs.status = XattrCaptureStatus::Partial;
        }
        if entry.entry_type == FilesystemEntryType::Directory {
            entry.traversal = TraversalStatus::Incomplete;
        }
    }

    fn canonicalize(&mut self) {
        self.entries.sort_by(|left, right| {
            left.root_index.cmp(&right.root_index).then_with(|| {
                left.relative_path_bytes_hex
                    .cmp(&right.relative_path_bytes_hex)
            })
        });
        self.errors.sort_by(|left, right| {
            (
                left.root_index,
                &left.relative_path_bytes_hex,
                left.operation as u8,
                &left.subject_bytes_hex,
            )
                .cmp(&(
                    right.root_index,
                    &right.relative_path_bytes_hex,
                    right.operation as u8,
                    &right.subject_bytes_hex,
                ))
        });
        self.limits_hit.sort_by(|left, right| {
            (
                left.root_index,
                &left.relative_path_bytes_hex,
                left.kind as u8,
                left.observed_at_least,
            )
                .cmp(&(
                    right.root_index,
                    &right.relative_path_bytes_hex,
                    right.kind as u8,
                    right.observed_at_least,
                ))
        });
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MetadataView {
    entry_type: FilesystemEntryType,
    device: u64,
    inode: u64,
    rdev: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    hard_link_count: u64,
    size: u64,
    mtime_seconds: i64,
    mtime_nanoseconds: i64,
    ctime_seconds: i64,
    ctime_nanoseconds: i64,
}

impl MetadataView {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            entry_type: classify_type(metadata),
            device: metadata.dev(),
            inode: metadata.ino(),
            rdev: metadata.rdev(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            hard_link_count: metadata.nlink(),
            size: metadata.size(),
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
            ctime_seconds: metadata.ctime(),
            ctime_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn classify_type(metadata: &Metadata) -> FilesystemEntryType {
    let kind = metadata.file_type();
    if kind.is_file() {
        FilesystemEntryType::RegularFile
    } else if kind.is_dir() {
        FilesystemEntryType::Directory
    } else if kind.is_symlink() {
        FilesystemEntryType::Symlink
    } else if kind.is_fifo() {
        FilesystemEntryType::Fifo
    } else if kind.is_socket() {
        FilesystemEntryType::Socket
    } else if kind.is_block_device() {
        FilesystemEntryType::BlockDevice
    } else if kind.is_char_device() {
        FilesystemEntryType::CharacterDevice
    } else {
        FilesystemEntryType::Other
    }
}

fn open_regular_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        // Never silently turn observation into an atime mutation. If the
        // caller lacks permission for O_NOATIME, the content observation is
        // recorded incomplete by the existing open-error path.
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOATIME)
        .open(path)
}

fn incomplete_content(status: ContentCaptureStatus, size: u64) -> ContentObservation {
    ContentObservation {
        status,
        size_bytes: Some(size),
        sha256: None,
    }
}

fn partial_xattrs() -> XattrObservation {
    XattrObservation {
        status: XattrCaptureStatus::Partial,
        attributes: Vec::new(),
    }
}

fn join_relative(parent: &[u8], name: &OsString) -> Vec<u8> {
    let name = name.as_os_str().as_bytes();
    let mut result =
        Vec::with_capacity(parent.len() + usize::from(!parent.is_empty()) + name.len());
    result.extend_from_slice(parent);
    if !parent.is_empty() {
        result.push(b'/');
    }
    result.extend_from_slice(name);
    result
}

fn error_class(error: &io::Error) -> CaptureErrorClass {
    match error.kind() {
        io::ErrorKind::NotFound => CaptureErrorClass::NotFound,
        io::ErrorKind::PermissionDenied => CaptureErrorClass::PermissionDenied,
        io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput => CaptureErrorClass::InvalidData,
        io::ErrorKind::Interrupted => CaptureErrorClass::Interrupted,
        io::ErrorKind::WouldBlock => CaptureErrorClass::WouldBlock,
        _ => CaptureErrorClass::Other,
    }
}

fn xattr_path(path: &Path) -> io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains NUL"))
}

fn filesystem_magic(path: &Path) -> io::Result<u64> {
    let path = xattr_path(path)?;
    let mut information = MaybeUninit::<libc::statfs>::uninit();
    let result = unsafe { libc::statfs(path.as_ptr(), information.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok((information.f_type as u64) & 0xffff_ffff)
}

fn xattr_name(name: &[u8]) -> io::Result<CString> {
    CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "xattr name contains NUL"))
}

fn xattr_list_size(path: &Path) -> io::Result<usize> {
    let path = xattr_path(path)?;
    let result = unsafe { libc::llistxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(result).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xattr size"))
}

fn read_xattr_names(path: &Path, expected_size: usize) -> io::Result<Vec<Vec<u8>>> {
    if expected_size == 0 {
        return Ok(Vec::new());
    }
    let path = xattr_path(path)?;
    let mut bytes = vec![0u8; expected_size];
    let result = unsafe {
        libc::llistxattr(
            path.as_ptr(),
            bytes.as_mut_ptr().cast::<libc::c_char>(),
            bytes.len(),
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = usize::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xattr size"))?;
    if actual > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xattr list grew beyond allocated size",
        ));
    }
    bytes.truncate(actual);
    if bytes.last() != Some(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xattr list is not NUL terminated",
        ));
    }
    bytes.pop();
    let names = bytes
        .split(|byte| *byte == 0)
        .map(|name| name.to_vec())
        .collect::<Vec<_>>();
    if names.iter().any(|name| name.is_empty()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xattr list contains an empty name",
        ));
    }
    Ok(names)
}

fn xattr_value_size(path: &Path, name: &[u8]) -> io::Result<usize> {
    let path = xattr_path(path)?;
    let name = xattr_name(name)?;
    let result = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    usize::try_from(result).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xattr size"))
}

fn read_xattr_value(path: &Path, name: &[u8], expected_size: usize) -> io::Result<Vec<u8>> {
    let path = xattr_path(path)?;
    let name = xattr_name(name)?;
    let mut bytes = vec![0u8; expected_size];
    let pointer = if bytes.is_empty() {
        std::ptr::null_mut()
    } else {
        bytes.as_mut_ptr().cast::<libc::c_void>()
    };
    let result = unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), pointer, bytes.len()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = usize::try_from(result)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "xattr size"))?;
    if actual != expected_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "xattr value changed while being captured",
        ));
    }
    bytes.truncate(actual);
    Ok(bytes)
}

fn statistics(entries: &[FilesystemEntry]) -> Result<CaptureStatistics> {
    let mut statistics = CaptureStatistics::default();
    for entry in entries {
        let path = hex::decode(&entry.relative_path_bytes_hex)
            .context("decode captured path for statistics")?;
        statistics.entries_captured += 1;
        statistics.path_bytes_captured = statistics
            .path_bytes_captured
            .checked_add(path.len() as u64)
            .context("filesystem path statistics overflow")?;
        if entry.content.status == ContentCaptureStatus::Captured {
            statistics.regular_files_hashed += 1;
            statistics.content_bytes_hashed = statistics
                .content_bytes_hashed
                .checked_add(entry.content.size_bytes.unwrap_or(0))
                .context("filesystem content statistics overflow")?;
        }
        for attribute in &entry.xattrs.attributes {
            statistics.xattrs_observed += 1;
            let name = hex::decode(&attribute.name_bytes_hex)
                .context("decode captured xattr name for statistics")?;
            statistics.xattr_name_bytes_captured = statistics
                .xattr_name_bytes_captured
                .checked_add(name.len() as u64 + 1)
                .context("filesystem xattr-name statistics overflow")?;
            if attribute.status == XattrValueStatus::Captured {
                statistics.xattrs_hashed += 1;
                statistics.xattr_bytes_hashed = statistics
                    .xattr_bytes_hashed
                    .checked_add(attribute.value_size_bytes.unwrap_or(0))
                    .context("filesystem xattr statistics overflow")?;
            }
        }
    }
    Ok(statistics)
}
