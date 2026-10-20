// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

pub const FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION: u32 = 1;
pub const HARD_MAX_ROOTS: usize = 32;
pub const HARD_MAX_ENTRIES: u64 = 65_536;
pub const HARD_MAX_CHANGES: usize = HARD_MAX_ENTRIES as usize * 2 + HARD_MAX_ROOTS;
pub const HARD_MAX_TOTAL_PATH_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_FILE_CONTENT_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_TOTAL_CONTENT_BYTES: u64 = 256 * 1024 * 1024;
pub const HARD_MAX_XATTR_LIST_BYTES: u64 = 1024 * 1024;
pub const HARD_MAX_XATTRS_PER_ENTRY: u32 = 1024;
pub const HARD_MAX_TOTAL_XATTRS: u64 = 262_144;
pub const HARD_MAX_XATTR_NAME_BYTES: usize = 255;
pub const HARD_MAX_XATTR_VALUE_BYTES: u64 = 4 * 1024 * 1024;
pub const HARD_MAX_TOTAL_XATTR_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_SYMLINK_TARGET_BYTES: u64 = 4096;
pub const HARD_MAX_DEPTH: u32 = 256;
pub const HARD_MAX_DEADLINE_MS: u64 = 10 * 60 * 1000;
pub const HARD_MAX_CAPTURE_ERRORS: usize = 4096;
pub const HARD_MAX_LIMIT_OBSERVATIONS: usize = 4096;
pub const HARD_MAX_COMPLETENESS_REASONS: usize = 16;
/// Conservative pre-parse limits for closed JSON artifacts produced by v1;
/// they include worst-case JSON escaping and fixed-vector overhead.
pub const HARD_MAX_SCOPE_JSON_BYTES: u64 = 1024 * 1024;
pub const HARD_MAX_SNAPSHOT_JSON_BYTES: u64 = 512 * 1024 * 1024;
pub const HARD_MAX_ACTOR_CONTRACT_JSON_BYTES: u64 = 64 * 1024;
pub const HARD_MAX_COMPARISON_JSON_BYTES: u64 = 512 * 1024 * 1024;
pub const HARD_MAX_ANY_FILESYSTEM_JSON_BYTES: u64 = HARD_MAX_SNAPSHOT_JSON_BYTES;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_ABSOLUTE_PATH_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RegularFileContentMode {
    MetadataOnly,
    Sha256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SymlinkMode {
    MetadataOnly,
    TargetBytes,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum XattrMode {
    NotRequested,
    NamesAndValueSha256,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CrossFilesystemPolicy {
    SameDeviceOnly,
    Include,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemCapturePolicy {
    pub regular_file_content: RegularFileContentMode,
    pub symlinks: SymlinkMode,
    pub xattrs: XattrMode,
    pub cross_filesystems: CrossFilesystemPolicy,
}

impl Default for FilesystemCapturePolicy {
    fn default() -> Self {
        Self {
            regular_file_content: RegularFileContentMode::Sha256,
            symlinks: SymlinkMode::TargetBytes,
            xattrs: XattrMode::NamesAndValueSha256,
            cross_filesystems: CrossFilesystemPolicy::SameDeviceOnly,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemCaptureLimits {
    pub max_entries: u64,
    pub max_total_path_bytes: u64,
    pub max_file_content_bytes: u64,
    pub max_total_content_bytes: u64,
    pub max_xattr_list_bytes: u64,
    pub max_xattrs_per_entry: u32,
    pub max_total_xattrs: u64,
    pub max_xattr_value_bytes: u64,
    /// Global transient/evidence budget for xattr name-list bytes plus values.
    pub max_total_xattr_bytes: u64,
    pub max_symlink_target_bytes: u64,
    pub max_depth: u32,
    pub deadline_ms: u64,
}

impl Default for FilesystemCaptureLimits {
    fn default() -> Self {
        Self {
            max_entries: 16_384,
            max_total_path_bytes: 16 * 1024 * 1024,
            max_file_content_bytes: 4 * 1024 * 1024,
            max_total_content_bytes: 64 * 1024 * 1024,
            max_xattr_list_bytes: 256 * 1024,
            max_xattrs_per_entry: 128,
            max_total_xattrs: 65_536,
            max_xattr_value_bytes: 1024 * 1024,
            max_total_xattr_bytes: 16 * 1024 * 1024,
            max_symlink_target_bytes: 4096,
            max_depth: 64,
            deadline_ms: 30_000,
        }
    }
}

impl FilesystemCaptureLimits {
    pub fn validate(&self) -> Result<()> {
        validate_limit("max_entries", self.max_entries, HARD_MAX_ENTRIES)?;
        validate_limit(
            "max_total_path_bytes",
            self.max_total_path_bytes,
            HARD_MAX_TOTAL_PATH_BYTES,
        )?;
        validate_limit(
            "max_file_content_bytes",
            self.max_file_content_bytes,
            HARD_MAX_FILE_CONTENT_BYTES,
        )?;
        validate_limit(
            "max_total_content_bytes",
            self.max_total_content_bytes,
            HARD_MAX_TOTAL_CONTENT_BYTES,
        )?;
        validate_limit(
            "max_xattr_list_bytes",
            self.max_xattr_list_bytes,
            HARD_MAX_XATTR_LIST_BYTES,
        )?;
        validate_limit(
            "max_xattrs_per_entry",
            u64::from(self.max_xattrs_per_entry),
            u64::from(HARD_MAX_XATTRS_PER_ENTRY),
        )?;
        validate_limit(
            "max_total_xattrs",
            self.max_total_xattrs,
            HARD_MAX_TOTAL_XATTRS,
        )?;
        validate_limit(
            "max_xattr_value_bytes",
            self.max_xattr_value_bytes,
            HARD_MAX_XATTR_VALUE_BYTES,
        )?;
        validate_limit(
            "max_total_xattr_bytes",
            self.max_total_xattr_bytes,
            HARD_MAX_TOTAL_XATTR_BYTES,
        )?;
        validate_limit(
            "max_symlink_target_bytes",
            self.max_symlink_target_bytes,
            HARD_MAX_SYMLINK_TARGET_BYTES,
        )?;
        validate_limit(
            "max_depth",
            u64::from(self.max_depth),
            u64::from(HARD_MAX_DEPTH),
        )?;
        validate_limit("deadline_ms", self.deadline_ms, HARD_MAX_DEADLINE_MS)?;
        Ok(())
    }
}

fn validate_limit(name: &str, value: u64, hard_maximum: u64) -> Result<()> {
    if value == 0 || value > hard_maximum {
        bail!("filesystem scope {name} must be in 1..={hard_maximum}");
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemRootScope {
    /// Canonical lowercase hex of one absolute Linux pathname. This is the
    /// authoritative representation and can preserve non-UTF-8 bytes.
    pub path_bytes_hex: String,
}

impl FilesystemRootScope {
    pub fn from_path(path: &Path) -> Result<Self> {
        let root = Self {
            path_bytes_hex: hex::encode(path.as_os_str().as_bytes()),
        };
        root.validate()?;
        Ok(root)
    }

    pub fn path(&self) -> Result<PathBuf> {
        let bytes = decode_lower_hex(&self.path_bytes_hex, "filesystem root path")?;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }

    fn validate(&self) -> Result<()> {
        let bytes = decode_lower_hex(&self.path_bytes_hex, "filesystem root path")?;
        validate_absolute_path(&bytes)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemScope {
    pub protocol_version: u32,
    pub roots: Vec<FilesystemRootScope>,
    pub capture: FilesystemCapturePolicy,
    pub limits: FilesystemCaptureLimits,
}

impl FilesystemScope {
    pub fn new(
        roots: Vec<PathBuf>,
        capture: FilesystemCapturePolicy,
        limits: FilesystemCaptureLimits,
    ) -> Result<Self> {
        let mut roots = roots
            .iter()
            .map(|path| FilesystemRootScope::from_path(path))
            .collect::<Result<Vec<_>>>()?;
        roots.sort_by(|left, right| left.path_bytes_hex.cmp(&right.path_bytes_hex));
        let scope = Self {
            protocol_version: FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION,
            roots,
            capture,
            limits,
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION {
            bail!(
                "filesystem scope protocol {} != supported protocol {}",
                self.protocol_version,
                FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION
            );
        }
        if self.roots.is_empty() || self.roots.len() > HARD_MAX_ROOTS {
            bail!("filesystem scope must contain 1..={HARD_MAX_ROOTS} explicit roots");
        }
        if self.capture.cross_filesystems != CrossFilesystemPolicy::SameDeviceOnly {
            bail!("filesystem confirmation protocol v1 requires SAME_DEVICE_ONLY traversal");
        }
        self.limits.validate()?;
        let mut decoded = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            root.validate()?;
            decoded.push(decode_lower_hex(
                &root.path_bytes_hex,
                "filesystem root path",
            )?);
        }
        for pair in decoded.windows(2) {
            if pair[0] >= pair[1] {
                bail!("filesystem roots must be unique and sorted by exact path bytes");
            }
        }
        for (index, root) in decoded.iter().enumerate() {
            for other in decoded.iter().skip(index + 1) {
                if path_is_ancestor(root, other) {
                    bail!("filesystem roots must not overlap or nest");
                }
            }
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).context("encode canonical filesystem scope")?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }

    /// Decode the exact, externally selected roots without resolving symlinks.
    pub fn decoded_roots(&self) -> Result<Vec<PathBuf>> {
        self.validate()?;
        self.roots.iter().map(FilesystemRootScope::path).collect()
    }

    /// Return whether `path` is equal to, below, or above any selected root.
    ///
    /// This is a lexical exact-byte check, not a filesystem lookup. Callers can
    /// use it to keep observer outputs outside the state being confirmed. Both
    /// directions matter: an output directory must neither live inside a root
    /// nor contain a root.
    pub fn overlaps_path(&self, path: &Path) -> Result<bool> {
        self.validate()?;
        let candidate = FilesystemRootScope::from_path(path)?;
        let candidate = decode_lower_hex(&candidate.path_bytes_hex, "candidate path")?;
        for root in &self.roots {
            let root = decode_lower_hex(&root.path_bytes_hex, "filesystem root path")?;
            if root == candidate
                || path_is_ancestor(&root, &candidate)
                || path_is_ancestor(&candidate, &root)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn path_is_ancestor(parent: &[u8], child: &[u8]) -> bool {
    child.starts_with(parent)
        && child
            .get(parent.len())
            .map_or(false, |separator| *separator == b'/')
}

fn validate_absolute_path(bytes: &[u8]) -> Result<()> {
    if bytes.is_empty()
        || bytes.len() > MAX_ABSOLUTE_PATH_BYTES
        || bytes[0] != b'/'
        || bytes == b"/"
        || bytes.ends_with(b"/")
        || bytes.contains(&0)
        || bytes.windows(2).any(|pair| pair == b"//")
    {
        bail!("filesystem root must be a bounded, non-root absolute Linux path");
    }
    for component in bytes[1..].split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            bail!("filesystem root contains a non-canonical path component");
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SnapshotPhase {
    S0,
    S1,
    A,
    B,
    C,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MountNamespaceCaptureSource {
    CurrentProcess,
    RetainedFileDescriptor,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureRequest {
    pub snapshot_id: String,
    pub phase: SnapshotPhase,
}

impl CaptureRequest {
    pub fn validate(&self) -> Result<()> {
        validate_identifier("snapshot_id", &self.snapshot_id)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CompletenessStatus {
    Complete,
    Incomplete,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Completeness {
    pub status: CompletenessStatus,
    pub reasons: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootCaptureStatus {
    Captured,
    Missing,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RootFilesystemClass {
    GenericPathTree,
    Procfs,
    Sysfs,
    CgroupV1,
    CgroupV2,
    Bpffs,
    Debugfs,
    Tracefs,
    Securityfs,
    Configfs,
    Unavailable,
}

impl RootFilesystemClass {
    pub fn requires_domain_adapter(self) -> bool {
        !matches!(self, Self::GenericPathTree | Self::Unavailable)
    }
}

pub(crate) fn classify_root_filesystem(magic: u64) -> RootFilesystemClass {
    match magic & 0xffff_ffff {
        0x0000_9fa0 => RootFilesystemClass::Procfs,
        0x6265_6572 => RootFilesystemClass::Sysfs,
        0x0027_e0eb => RootFilesystemClass::CgroupV1,
        0x6367_7270 => RootFilesystemClass::CgroupV2,
        0xcafe_4a11 => RootFilesystemClass::Bpffs,
        0x6462_6720 => RootFilesystemClass::Debugfs,
        0x7472_6163 => RootFilesystemClass::Tracefs,
        0x7363_6673 => RootFilesystemClass::Securityfs,
        0x6265_6570 => RootFilesystemClass::Configfs,
        _ => RootFilesystemClass::GenericPathTree,
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RootObservation {
    pub root_index: u32,
    pub absolute_path_bytes_hex: String,
    /// Low 32 bits of Linux `statfs.f_type` for a present root.
    pub filesystem_magic: Option<u64>,
    pub filesystem_class: RootFilesystemClass,
    pub status: RootCaptureStatus,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemEntryType {
    RegularFile,
    Directory,
    Symlink,
    Fifo,
    Socket,
    BlockDevice,
    CharacterDevice,
    Other,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TraversalStatus {
    NotDirectory,
    Traversed,
    CrossDeviceExcluded,
    Incomplete,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContentCaptureStatus {
    NotApplicable,
    NotRequested,
    Captured,
    LimitExceeded,
    ReadFailed,
    Unstable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContentObservation {
    pub status: ContentCaptureStatus,
    pub size_bytes: Option<u64>,
    pub sha256: Option<String>,
}

impl ContentObservation {
    pub(crate) fn not_applicable() -> Self {
        Self {
            status: ContentCaptureStatus::NotApplicable,
            size_bytes: None,
            sha256: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SymlinkCaptureStatus {
    NotApplicable,
    MetadataOnly,
    Captured,
    LimitExceeded,
    ReadFailed,
    Unstable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SymlinkObservation {
    pub status: SymlinkCaptureStatus,
    pub target_bytes_hex: Option<String>,
}

impl SymlinkObservation {
    pub(crate) fn not_applicable() -> Self {
        Self {
            status: SymlinkCaptureStatus::NotApplicable,
            target_bytes_hex: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum XattrCaptureStatus {
    NotRequested,
    Captured,
    Partial,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum XattrValueStatus {
    Captured,
    LimitExceeded,
    ReadFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XattrValueObservation {
    pub name_bytes_hex: String,
    pub value_size_bytes: Option<u64>,
    pub value_sha256: Option<String>,
    pub status: XattrValueStatus,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct XattrObservation {
    pub status: XattrCaptureStatus,
    pub attributes: Vec<XattrValueObservation>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemEntry {
    pub root_index: u32,
    /// Exact path bytes relative to the selected root. Empty means the root.
    pub relative_path_bytes_hex: String,
    /// Lossy display derived from `relative_path_bytes_hex`; never identity.
    pub relative_path_display: String,
    pub entry_type: FilesystemEntryType,
    pub device: u64,
    pub inode: u64,
    /// `st_rdev`; meaningful for device nodes and zero on ordinary filesystems.
    pub rdev: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub hard_link_count: u64,
    pub size_bytes: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
    pub ctime_seconds: i64,
    pub ctime_nanoseconds: i64,
    pub traversal: TraversalStatus,
    pub content: ContentObservation,
    pub symlink: SymlinkObservation,
    pub xattrs: XattrObservation,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureOperation {
    RootMetadata,
    InspectFilesystem,
    ClassifyFilesystem,
    EntryMetadata,
    ReadDirectory,
    OpenContent,
    ReadContent,
    ReadSymlink,
    ListXattrs,
    ReadXattr,
    StabilityCheck,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CaptureErrorClass {
    NotFound,
    PermissionDenied,
    InvalidData,
    Interrupted,
    WouldBlock,
    Unsupported,
    Other,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureError {
    pub root_index: u32,
    pub relative_path_bytes_hex: String,
    pub operation: CaptureOperation,
    pub class: CaptureErrorClass,
    pub errno: Option<i32>,
    /// For xattr failures this is the exact xattr name; otherwise absent.
    pub subject_bytes_hex: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LimitKind {
    EntryCount,
    TotalPathBytes,
    FileContentBytes,
    TotalContentBytes,
    XattrListBytes,
    XattrCount,
    TotalXattrCount,
    XattrValueBytes,
    TotalXattrBytes,
    SymlinkTargetBytes,
    Depth,
    Deadline,
    ErrorCount,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LimitObservation {
    pub root_index: u32,
    pub relative_path_bytes_hex: String,
    pub kind: LimitKind,
    pub configured: u64,
    pub observed_at_least: u64,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureStatistics {
    pub entries_captured: u64,
    pub path_bytes_captured: u64,
    pub regular_files_hashed: u64,
    pub content_bytes_hashed: u64,
    pub xattrs_hashed: u64,
    pub xattrs_observed: u64,
    /// Exact xattr-list bytes retained in entries, including one NUL per name.
    pub xattr_name_bytes_captured: u64,
    pub xattr_bytes_hashed: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemSnapshot {
    pub protocol_version: u32,
    pub snapshot_id: String,
    pub phase: SnapshotPhase,
    pub captured_unix_ns: u128,
    pub boot_id: String,
    pub mount_namespace_inode: u64,
    pub mount_namespace_capture_source: MountNamespaceCaptureSource,
    /// Root directory object used for absolute path resolution after entering
    /// the retained mount namespace. This prevents setns with a host root from
    /// being mislabeled as container-root coverage.
    pub mount_root_device: u64,
    pub mount_root_inode: u64,
    pub scope: FilesystemScope,
    pub scope_sha256: String,
    pub roots: Vec<RootObservation>,
    pub entries: Vec<FilesystemEntry>,
    pub errors: Vec<CaptureError>,
    pub limits_hit: Vec<LimitObservation>,
    pub statistics: CaptureStatistics,
    pub completeness: Completeness,
}

impl FilesystemSnapshot {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION {
            bail!("unsupported filesystem snapshot protocol");
        }
        validate_identifier("snapshot_id", &self.snapshot_id)?;
        if self.captured_unix_ns == 0
            || self.boot_id.is_empty()
            || self.boot_id.len() > MAX_IDENTIFIER_BYTES
            || self.boot_id.contains('\0')
            || self.mount_namespace_inode == 0
            || self.mount_root_inode == 0
        {
            bail!("filesystem snapshot has invalid environment identity");
        }
        self.scope.validate()?;
        if self.scope_sha256 != self.scope.sha256()? {
            bail!("filesystem snapshot scope digest mismatch");
        }
        if self.roots.len() != self.scope.roots.len() {
            bail!("filesystem snapshot root observations are incomplete");
        }
        for (index, root) in self.roots.iter().enumerate() {
            if root.root_index != index as u32
                || root.absolute_path_bytes_hex != self.scope.roots[index].path_bytes_hex
            {
                bail!("filesystem snapshot roots are not canonical");
            }
            match root.filesystem_magic {
                Some(magic)
                    if root.filesystem_class == classify_root_filesystem(magic)
                        && root.filesystem_class != RootFilesystemClass::Unavailable => {}
                None if root.filesystem_class == RootFilesystemClass::Unavailable => {}
                _ => bail!("filesystem root class disagrees with statfs magic"),
            }
            match root.status {
                RootCaptureStatus::Captured
                    if root.filesystem_magic.is_none()
                        || root.filesystem_class != RootFilesystemClass::GenericPathTree =>
                {
                    bail!("captured filesystem root lacks generic path-tree semantics")
                }
                RootCaptureStatus::Missing
                    if root.filesystem_magic.is_some()
                        || root.filesystem_class != RootFilesystemClass::Unavailable =>
                {
                    bail!("missing filesystem root unexpectedly has filesystem identity")
                }
                RootCaptureStatus::Captured
                | RootCaptureStatus::Missing
                | RootCaptureStatus::Incomplete => {}
            }
        }
        if self.entries.len() as u64 > self.scope.limits.max_entries
            || self.errors.len() > HARD_MAX_CAPTURE_ERRORS
            || self.limits_hit.len() > HARD_MAX_LIMIT_OBSERVATIONS
        {
            bail!("filesystem snapshot exceeds a bound from its scope or protocol");
        }

        let mut previous_key: Option<(u32, Vec<u8>)> = None;
        let mut decoded_keys = Vec::with_capacity(self.entries.len());
        let mut computed = CaptureStatistics::default();
        for entry in &self.entries {
            let path = decode_lower_hex(
                &entry.relative_path_bytes_hex,
                "filesystem entry relative path",
            )?;
            validate_relative_path(&path)?;
            if entry.root_index as usize >= self.scope.roots.len()
                || entry.relative_path_display != display_relative_path(&path)
                || entry.inode == 0
                || !(0..1_000_000_000).contains(&entry.mtime_nanoseconds)
                || !(0..1_000_000_000).contains(&entry.ctime_nanoseconds)
            {
                bail!("filesystem entry has invalid identity or metadata");
            }
            let key = (entry.root_index, path.clone());
            if previous_key.as_ref().map_or(false, |old| old >= &key) {
                bail!("filesystem entries are duplicate or non-canonical");
            }
            previous_key = Some(key);
            decoded_keys.push((entry.root_index, path.clone()));
            validate_entry_observations(entry, &self.scope.capture, &self.scope.limits)?;
            computed.entries_captured += 1;
            computed.path_bytes_captured = computed
                .path_bytes_captured
                .checked_add(path.len() as u64)
                .context("filesystem path statistics overflow")?;
            if entry.content.status == ContentCaptureStatus::Captured {
                computed.regular_files_hashed += 1;
                computed.content_bytes_hashed = computed
                    .content_bytes_hashed
                    .checked_add(entry.content.size_bytes.unwrap_or(0))
                    .context("filesystem content statistics overflow")?;
            }
            for attribute in &entry.xattrs.attributes {
                let name = decode_lower_hex(&attribute.name_bytes_hex, "xattr name")?;
                if name.len() > HARD_MAX_XATTR_NAME_BYTES {
                    bail!("filesystem xattr name exceeds the Linux protocol bound");
                }
                computed.xattrs_observed += 1;
                computed.xattr_name_bytes_captured = computed
                    .xattr_name_bytes_captured
                    .checked_add(name.len() as u64 + 1)
                    .context("filesystem xattr-name statistics overflow")?;
                if attribute.status == XattrValueStatus::Captured {
                    computed.xattrs_hashed += 1;
                    computed.xattr_bytes_hashed = computed
                        .xattr_bytes_hashed
                        .checked_add(attribute.value_size_bytes.unwrap_or(0))
                        .context("filesystem xattr statistics overflow")?;
                }
            }
        }
        for (entry_index, (root_index, path)) in decoded_keys.iter().enumerate() {
            if path.is_empty() {
                continue;
            }
            let parent = path
                .iter()
                .rposition(|byte| *byte == b'/')
                .map_or(&[][..], |separator| &path[..separator]);
            let parent_index = decoded_keys
                .binary_search_by(|(candidate_root, candidate_path)| {
                    candidate_root
                        .cmp(root_index)
                        .then_with(|| candidate_path.as_slice().cmp(parent))
                })
                .map_err(|_| {
                    anyhow::anyhow!(
                        "filesystem entry {} lacks its immediate parent entry",
                        self.entries[entry_index].relative_path_display
                    )
                })?;
            let parent_entry = &self.entries[parent_index];
            if parent_entry.entry_type != FilesystemEntryType::Directory
                || !matches!(
                    parent_entry.traversal,
                    TraversalStatus::Traversed | TraversalStatus::Incomplete
                )
            {
                bail!(
                    "filesystem entry {} has a non-directory or untraversed immediate parent",
                    self.entries[entry_index].relative_path_display
                );
            }
        }
        let total_xattr_bytes = computed
            .xattr_name_bytes_captured
            .checked_add(computed.xattr_bytes_hashed)
            .context("filesystem total xattr statistics overflow")?;
        if computed != self.statistics
            || computed.path_bytes_captured > self.scope.limits.max_total_path_bytes
            || computed.content_bytes_hashed > self.scope.limits.max_total_content_bytes
            || computed.xattrs_observed > self.scope.limits.max_total_xattrs
            || total_xattr_bytes > self.scope.limits.max_total_xattr_bytes
        {
            bail!("filesystem snapshot statistics do not match its entries");
        }
        for (index, root) in self.roots.iter().enumerate() {
            let has_root_entry = self.entries.iter().any(|entry| {
                entry.root_index == index as u32 && entry.relative_path_bytes_hex.is_empty()
            });
            match root.status {
                RootCaptureStatus::Captured if !has_root_entry => {
                    bail!("captured filesystem root lacks its root entry")
                }
                RootCaptureStatus::Missing if has_root_entry => {
                    bail!("missing filesystem root unexpectedly has a root entry")
                }
                RootCaptureStatus::Captured
                | RootCaptureStatus::Missing
                | RootCaptureStatus::Incomplete => {}
            }
        }
        validate_diagnostics(self)?;
        Ok(())
    }
}

fn validate_entry_observations(
    entry: &FilesystemEntry,
    policy: &FilesystemCapturePolicy,
    limits: &FilesystemCaptureLimits,
) -> Result<()> {
    match entry.entry_type {
        FilesystemEntryType::RegularFile => {
            if entry.traversal != TraversalStatus::NotDirectory
                || entry.symlink != SymlinkObservation::not_applicable()
            {
                bail!("regular file carries directory or symlink evidence");
            }
            match (policy.regular_file_content, entry.content.status) {
                (RegularFileContentMode::MetadataOnly, ContentCaptureStatus::NotRequested)
                | (RegularFileContentMode::Sha256, ContentCaptureStatus::Captured)
                | (RegularFileContentMode::Sha256, ContentCaptureStatus::LimitExceeded)
                | (RegularFileContentMode::Sha256, ContentCaptureStatus::ReadFailed)
                | (RegularFileContentMode::Sha256, ContentCaptureStatus::Unstable) => {}
                _ => bail!("regular file content evidence disagrees with scope"),
            }
        }
        FilesystemEntryType::Directory => {
            if !matches!(
                entry.traversal,
                TraversalStatus::Traversed
                    | TraversalStatus::CrossDeviceExcluded
                    | TraversalStatus::Incomplete
            ) || entry.content != ContentObservation::not_applicable()
                || entry.symlink != SymlinkObservation::not_applicable()
            {
                bail!("directory carries invalid observation state");
            }
        }
        FilesystemEntryType::Symlink => {
            if entry.traversal != TraversalStatus::NotDirectory
                || entry.content != ContentObservation::not_applicable()
            {
                bail!("symlink carries invalid content or traversal state");
            }
            match (policy.symlinks, entry.symlink.status) {
                (SymlinkMode::MetadataOnly, SymlinkCaptureStatus::MetadataOnly)
                | (SymlinkMode::TargetBytes, SymlinkCaptureStatus::Captured)
                | (SymlinkMode::TargetBytes, SymlinkCaptureStatus::LimitExceeded)
                | (SymlinkMode::TargetBytes, SymlinkCaptureStatus::ReadFailed)
                | (SymlinkMode::TargetBytes, SymlinkCaptureStatus::Unstable) => {}
                _ => bail!("symlink evidence disagrees with scope"),
            }
        }
        _ => {
            if entry.traversal != TraversalStatus::NotDirectory
                || entry.content != ContentObservation::not_applicable()
                || entry.symlink != SymlinkObservation::not_applicable()
            {
                bail!("special file carries invalid content, symlink, or traversal state");
            }
        }
    }
    match (policy.xattrs, entry.xattrs.status) {
        (XattrMode::NotRequested, XattrCaptureStatus::NotRequested)
            if entry.xattrs.attributes.is_empty() => {}
        (XattrMode::NamesAndValueSha256, XattrCaptureStatus::Captured)
        | (XattrMode::NamesAndValueSha256, XattrCaptureStatus::Partial) => {
            if entry.xattrs.attributes.len() as u32 > limits.max_xattrs_per_entry {
                bail!("filesystem entry exceeds its xattr-count bound");
            }
            let mut previous = None;
            for attribute in &entry.xattrs.attributes {
                let name = decode_lower_hex(&attribute.name_bytes_hex, "xattr name")?;
                if name.is_empty() || name.contains(&0) {
                    bail!("filesystem xattr has an invalid name");
                }
                if previous
                    .as_ref()
                    .map_or(false, |old: &Vec<u8>| old >= &name)
                {
                    bail!("filesystem xattrs are duplicate or non-canonical");
                }
                previous = Some(name);
                match attribute.status {
                    XattrValueStatus::Captured => {
                        if attribute.value_size_bytes.is_none()
                            || !is_sha256(attribute.value_sha256.as_deref())
                        {
                            bail!("captured xattr lacks size or digest");
                        }
                    }
                    XattrValueStatus::LimitExceeded | XattrValueStatus::ReadFailed => {
                        if attribute.value_sha256.is_some() {
                            bail!("incomplete xattr unexpectedly contains a digest");
                        }
                    }
                }
            }
        }
        _ => bail!("xattr evidence disagrees with scope"),
    }
    match entry.content.status {
        ContentCaptureStatus::Captured => {
            if entry.content.size_bytes != Some(entry.size_bytes)
                || !is_sha256(entry.content.sha256.as_deref())
            {
                bail!("captured regular-file content lacks exact size or digest");
            }
        }
        ContentCaptureStatus::LimitExceeded
        | ContentCaptureStatus::ReadFailed
        | ContentCaptureStatus::Unstable => {
            if entry.content.sha256.is_some() {
                bail!("incomplete regular-file content unexpectedly has a digest");
            }
        }
        ContentCaptureStatus::NotApplicable | ContentCaptureStatus::NotRequested => {
            if entry.content.size_bytes.is_some() || entry.content.sha256.is_some() {
                bail!("uncaptured content unexpectedly has size or digest");
            }
        }
    }
    match entry.symlink.status {
        SymlinkCaptureStatus::Captured => {
            let target = entry
                .symlink
                .target_bytes_hex
                .as_deref()
                .context("captured symlink lacks target bytes")?;
            let target = decode_lower_hex(target, "symlink target")?;
            if target.len() as u64 > limits.max_symlink_target_bytes {
                bail!("captured symlink target exceeds its configured bound");
            }
        }
        _ if entry.symlink.target_bytes_hex.is_some() => {
            bail!("uncaptured symlink unexpectedly has target bytes")
        }
        _ => {}
    }
    Ok(())
}

fn validate_diagnostics(snapshot: &FilesystemSnapshot) -> Result<()> {
    for error in &snapshot.errors {
        if error.root_index as usize >= snapshot.scope.roots.len() {
            bail!("filesystem capture error refers to an unknown root");
        }
        let path = decode_lower_hex(&error.relative_path_bytes_hex, "error path")?;
        validate_relative_path(&path)?;
        if let Some(subject) = error.subject_bytes_hex.as_deref() {
            decode_lower_hex(subject, "error subject")?;
        }
    }
    for limit in &snapshot.limits_hit {
        if limit.root_index as usize >= snapshot.scope.roots.len()
            || limit.configured == 0
            || limit.observed_at_least <= limit.configured
        {
            bail!("filesystem limit observation is invalid");
        }
        let path = decode_lower_hex(&limit.relative_path_bytes_hex, "limit path")?;
        validate_relative_path(&path)?;
    }
    let observations_incomplete = snapshot.entries.iter().any(entry_is_incomplete)
        || snapshot
            .roots
            .iter()
            .any(|root| root.status != RootCaptureStatus::Captured);
    let expected_incomplete =
        !snapshot.errors.is_empty() || !snapshot.limits_hit.is_empty() || observations_incomplete;
    match (snapshot.completeness.status, expected_incomplete) {
        (CompletenessStatus::Complete, false) if snapshot.completeness.reasons.is_empty() => Ok(()),
        (CompletenessStatus::Incomplete, true) if !snapshot.completeness.reasons.is_empty() => {
            if snapshot
                .completeness
                .reasons
                .iter()
                .any(|reason| reason.is_empty() || reason.len() > MAX_IDENTIFIER_BYTES)
            {
                bail!("filesystem completeness contains an invalid reason");
            }
            Ok(())
        }
        _ => bail!("filesystem completeness status does not match capture diagnostics"),
    }
}

fn entry_is_incomplete(entry: &FilesystemEntry) -> bool {
    matches!(entry.traversal, TraversalStatus::Incomplete)
        || matches!(
            entry.content.status,
            ContentCaptureStatus::LimitExceeded
                | ContentCaptureStatus::ReadFailed
                | ContentCaptureStatus::Unstable
        )
        || matches!(
            entry.symlink.status,
            SymlinkCaptureStatus::LimitExceeded
                | SymlinkCaptureStatus::ReadFailed
                | SymlinkCaptureStatus::Unstable
        )
        || entry.xattrs.status == XattrCaptureStatus::Partial
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActorQuiescenceContract {
    pub protocol_version: u32,
    pub contract_id: String,
    pub evidence_sha256: String,
    pub scope_sha256: String,
    pub s0_snapshot_id: String,
    pub s1_snapshot_id: String,
    pub exclusive_writer_enforced: bool,
    pub s0_quiescent: bool,
    pub s1_quiescent: bool,
}

impl ActorQuiescenceContract {
    pub fn validate(&self) -> Result<()> {
        if self.protocol_version != FILESYSTEM_CONFIRMATION_PROTOCOL_VERSION {
            bail!("unsupported filesystem actor contract protocol");
        }
        validate_identifier("contract_id", &self.contract_id)?;
        validate_identifier("s0_snapshot_id", &self.s0_snapshot_id)?;
        validate_identifier("s1_snapshot_id", &self.s1_snapshot_id)?;
        if !is_sha256(Some(&self.evidence_sha256)) || !is_sha256(Some(&self.scope_sha256)) {
            bail!("filesystem actor contract has an invalid digest");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemVerdict {
    ChangedWithinScope,
    UnchangedWithinScope,
    Inconclusive,
}

/// Endpoint evidence, deliberately separate from actor attribution.
///
/// `ObservedDifferent` is positive evidence that at least one captured field
/// differs. It does not by itself establish who caused that difference.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EndpointDifferenceStatus {
    ObservedDifferent,
    ObservedIdentical,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActorContractStatus {
    Missing,
    Incomplete,
    /// The exact caller-supplied JSON is bound to the snapshots, but this
    /// protocol has no signature, freshness proof, or enforcement evidence.
    AssertedNotAuthenticated,
    /// Reserved for a future signed supervisor/harness protocol. The v1
    /// static actor contract can never produce this status.
    AuthenticatedAndEnforced,
}

/// This endpoint confirmer never establishes generic causal provenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalAttributionStatus {
    NotEstablished,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FilesystemChangeKind {
    Added,
    Removed,
    Modified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangedField {
    RootCaptureStatus,
    RootFilesystemMagic,
    RootFilesystemClass,
    Type,
    Device,
    Inode,
    Rdev,
    Mode,
    Uid,
    Gid,
    HardLinkCount,
    Size,
    Mtime,
    Ctime,
    Traversal,
    Content,
    Symlink,
    Xattrs,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemChange {
    pub root_index: u32,
    pub relative_path_bytes_hex: String,
    pub kind: FilesystemChangeKind,
    pub changed_fields: Vec<ChangedField>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemComparison {
    pub protocol_version: u32,
    pub domain: String,
    pub scope_sha256: String,
    /// Legacy wire name retained for compatibility. Generic pair comparisons
    /// store the before-snapshot identifier here.
    pub s0_snapshot_id: String,
    /// Legacy wire name retained for compatibility. Generic pair comparisons
    /// store the after-snapshot identifier here.
    pub s1_snapshot_id: String,
    pub endpoint_difference: EndpointDifferenceStatus,
    pub verdict: FilesystemVerdict,
    pub state_completeness: Completeness,
    pub actor_contract_status: ActorContractStatus,
    pub causal_attribution_status: CausalAttributionStatus,
    pub changes: Vec<FilesystemChange>,
    pub limitations: Vec<String>,
}

pub(crate) fn decode_lower_hex(value: &str, label: &str) -> Result<Vec<u8>> {
    if value.len() % 2 != 0
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')))
    {
        bail!("{label} is not canonical lowercase hex");
    }
    hex::decode(value).with_context(|| format!("decode {label}"))
}

pub(crate) fn display_relative_path(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        ".".to_owned()
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

pub(crate) fn validate_relative_path(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_ABSOLUTE_PATH_BYTES
        || bytes.starts_with(b"/")
        || bytes.ends_with(b"/")
        || bytes.contains(&0)
        || bytes.windows(2).any(|pair| pair == b"//")
    {
        bail!("filesystem relative path is not canonical");
    }
    for component in bytes.split(|byte| *byte == b'/') {
        if (!bytes.is_empty() && component.is_empty()) || component == b"." || component == b".." {
            bail!("filesystem relative path contains a forbidden component");
        }
    }
    Ok(())
}

pub(crate) fn is_sha256(value: Option<&str>) -> bool {
    value.map_or(false, |value| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn validate_identifier(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        bail!("filesystem {name} must be a bounded non-NUL string");
    }
    Ok(())
}
