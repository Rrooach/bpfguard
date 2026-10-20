// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::str::FromStr;

pub const POLICY_MAP_ENTRIES: u32 = 1024;
// Linux UAPI number from the architecture-independent post-asm-generic range.
// Some supported experiment-host libc headers predate SYS_fchmodat2.
const SYS_FCHMODAT2: libc::c_long = 452;

pub const CAPTURE_NONE: u8 = 0;
pub const CAPTURE_USER_STRING: u8 = 1;
pub const CAPTURE_SOCKADDR: u8 = 2;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u8)]
pub enum KernelObjectResolver {
    None = 0,
    FileOpen = 1,
    FilePermissionWrite = 2,
    PathCreateParent = 3,
    PathUnlink = 4,
    PathRenameSource = 5,
    PathSetattr = 6,
    InodeXattr = 7,
    MmapFileWrite = 8,
    SocketConnect = 9,
    SocketBind = 10,
    PathLinkSource = 11,
    SocketAccept = 12,
    MprotectFileWrite = 13,
    FilePermissionRead = 14,
}

impl KernelObjectResolver {
    pub const fn for_operation(operation: EffectOperation) -> Self {
        match operation {
            EffectOperation::FileCreateOrTruncate | EffectOperation::FileOpenRequest => {
                Self::FileOpen
            }
            EffectOperation::FdWrite => Self::FilePermissionWrite,
            EffectOperation::FdRead => Self::FilePermissionRead,
            EffectOperation::DirectoryCreate
            | EffectOperation::SymlinkCreate
            | EffectOperation::DeviceNodeCreate => Self::PathCreateParent,
            EffectOperation::FileUnlink
            | EffectOperation::DirectoryRemove
            | EffectOperation::PathEntryRemove => Self::PathUnlink,
            EffectOperation::FileRename => Self::PathRenameSource,
            EffectOperation::HardLinkCreate => Self::PathLinkSource,
            EffectOperation::PermissionsChange | EffectOperation::OwnershipChange => {
                Self::PathSetattr
            }
            EffectOperation::ExtendedAttributeSet | EffectOperation::ExtendedAttributeRemove => {
                Self::InodeXattr
            }
            EffectOperation::MemoryWriteChannel => Self::MmapFileWrite,
            EffectOperation::SocketConnect => Self::SocketConnect,
            EffectOperation::SocketBind => Self::SocketBind,
            EffectOperation::SocketAccept => Self::SocketAccept,
            _ => Self::None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u16)]
pub enum EffectDomain {
    Filesystem = 1,
    Network = 2,
    Namespace = 3,
    KernelControl = 4,
    Security = 5,
    AsyncIo = 6,
    Io = 7,
}

impl EffectDomain {
    pub fn from_raw(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Filesystem,
            2 => Self::Network,
            3 => Self::Namespace,
            4 => Self::KernelControl,
            5 => Self::Security,
            6 => Self::AsyncIo,
            7 => Self::Io,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u32)]
pub enum EffectOperation {
    FileCreateOrTruncate = 1,
    FileOpenRequest = 2,
    FdWrite = 3,
    FileTruncate = 4,
    FileRename = 5,
    FileUnlink = 6,
    DirectoryCreate = 7,
    DirectoryRemove = 8,
    HardLinkCreate = 9,
    SymlinkCreate = 10,
    PermissionsChange = 11,
    OwnershipChange = 12,
    DeviceNodeCreate = 13,
    ExtendedAttributeSet = 14,
    ExtendedAttributeRemove = 15,
    FileAllocate = 16,
    FdRangeTransfer = 17,
    FileSync = 18,
    MemoryWriteChannel = 19,
    /// Conservative classification for unlinkat(2): arg2 decides whether the
    /// removed directory entry names a non-directory or a directory, and the
    /// fixed ARRAY policy ABI deliberately does not fabricate one answer.
    PathEntryRemove = 20,
    FdRead = 21,
    SocketCreate = 100,
    SocketConnect = 101,
    SocketBind = 102,
    SocketListen = 103,
    NetworkSend = 104,
    SocketConfigure = 105,
    SocketAccept = 106,
    Mount = 200,
    Unmount = 201,
    PivotRoot = 202,
    Chroot = 203,
    NamespaceUnshare = 204,
    NamespaceJoin = 205,
    MountApi = 206,
    BpfCommand = 300,
    KernelModuleLoad = 301,
    KernelModuleUnload = 302,
    PerfEventOpen = 303,
    Ptrace = 304,
    KexecLoad = 305,
    Reboot = 306,
    SwapChange = 307,
    GenericIoctl = 308,
    ProcessControl = 309,
    SeccompChange = 310,
    KernelKeyChange = 311,
    HostIdentityChange = 312,
    SystemTimeChange = 313,
    CredentialChange = 400,
    QuotaChange = 401,
    ProcessAccounting = 402,
    Userfaultfd = 403,
    IoUring = 500,
    Landlock = 501,
}

impl EffectOperation {
    pub fn from_raw(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::FileCreateOrTruncate,
            2 => Self::FileOpenRequest,
            3 => Self::FdWrite,
            4 => Self::FileTruncate,
            5 => Self::FileRename,
            6 => Self::FileUnlink,
            7 => Self::DirectoryCreate,
            8 => Self::DirectoryRemove,
            9 => Self::HardLinkCreate,
            10 => Self::SymlinkCreate,
            11 => Self::PermissionsChange,
            12 => Self::OwnershipChange,
            13 => Self::DeviceNodeCreate,
            14 => Self::ExtendedAttributeSet,
            15 => Self::ExtendedAttributeRemove,
            16 => Self::FileAllocate,
            17 => Self::FdRangeTransfer,
            18 => Self::FileSync,
            19 => Self::MemoryWriteChannel,
            20 => Self::PathEntryRemove,
            21 => Self::FdRead,
            100 => Self::SocketCreate,
            101 => Self::SocketConnect,
            102 => Self::SocketBind,
            103 => Self::SocketListen,
            104 => Self::NetworkSend,
            105 => Self::SocketConfigure,
            106 => Self::SocketAccept,
            200 => Self::Mount,
            201 => Self::Unmount,
            202 => Self::PivotRoot,
            203 => Self::Chroot,
            204 => Self::NamespaceUnshare,
            205 => Self::NamespaceJoin,
            206 => Self::MountApi,
            300 => Self::BpfCommand,
            301 => Self::KernelModuleLoad,
            302 => Self::KernelModuleUnload,
            303 => Self::PerfEventOpen,
            304 => Self::Ptrace,
            305 => Self::KexecLoad,
            306 => Self::Reboot,
            307 => Self::SwapChange,
            308 => Self::GenericIoctl,
            309 => Self::ProcessControl,
            310 => Self::SeccompChange,
            311 => Self::KernelKeyChange,
            312 => Self::HostIdentityChange,
            313 => Self::SystemTimeChange,
            400 => Self::CredentialChange,
            401 => Self::QuotaChange,
            402 => Self::ProcessAccounting,
            403 => Self::Userfaultfd,
            500 => Self::IoUring,
            501 => Self::Landlock,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyProfile {
    Control,
    Balanced,
    Full,
    FileAccess,
}

impl PolicyProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Balanced => "balanced",
            Self::Full => "full",
            Self::FileAccess => "file-access",
        }
    }
}

impl fmt::Display for PolicyProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PolicyProfile {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "control" => Ok(Self::Control),
            "balanced" => Ok(Self::Balanced),
            "full" => Ok(Self::Full),
            "file-access" => Ok(Self::FileAccess),
            _ => bail!("unknown system-effect profile {value:?}; use control, balanced, full, or file-access"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct CapturePolicy {
    pub kind: u8,
    pub arg_index: u8,
    pub length_arg_index: u8,
    pub reserved: u8,
}

impl CapturePolicy {
    const NONE: Self = Self {
        kind: CAPTURE_NONE,
        arg_index: 0,
        length_arg_index: 0,
        reserved: 0,
    };

    const fn path(arg_index: u8) -> Self {
        Self {
            kind: CAPTURE_USER_STRING,
            arg_index,
            length_arg_index: 0,
            reserved: 0,
        }
    }

    const fn sockaddr(arg_index: u8, length_arg_index: u8) -> Self {
        Self {
            kind: CAPTURE_SOCKADDR,
            arg_index,
            length_arg_index,
            reserved: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub(crate) struct KernelPolicy {
    pub enabled: u32,
    pub domain: u16,
    pub operation: u16,
    pub capture: [CapturePolicy; 2],
    pub filter_mask: u64,
    pub filter_arg_index: u8,
    pub object_resolver: u8,
    pub reserved: [u8; 6],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyDescription {
    pub syscall_nr: i32,
    pub syscall_name: String,
    pub domain: EffectDomain,
    pub operation: EffectOperation,
    /// Frozen kernel resolver selection. This is authenticated as part of the
    /// policy digest and lets offline replay distinguish syscalls which share
    /// one public operation class (notably mmap and mprotect).
    pub object_resolver: KernelObjectResolver,
    pub capture: Vec<CaptureDescription>,
    pub kernel_filter: Option<FilterDescription>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDescription {
    pub kind: String,
    pub argument_index: u8,
    pub length_argument_index: Option<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilterDescription {
    pub kind: String,
    pub argument_index: u8,
    pub mask: u64,
}

#[derive(Clone, Copy)]
struct Spec {
    nr: libc::c_long,
    name: &'static str,
    domain: EffectDomain,
    operation: EffectOperation,
    object_resolver: KernelObjectResolver,
    capture: [CapturePolicy; 2],
    filter: Option<(u8, u64)>,
    minimum_profile: PolicyProfile,
}

impl Spec {
    const fn new(
        nr: libc::c_long,
        name: &'static str,
        domain: EffectDomain,
        operation: EffectOperation,
        minimum_profile: PolicyProfile,
    ) -> Self {
        let object_resolver = KernelObjectResolver::for_operation(operation);
        Self {
            nr,
            name,
            domain,
            operation,
            object_resolver,
            capture: [CapturePolicy::NONE; 2],
            filter: None,
            minimum_profile,
        }
    }

    const fn paths(mut self, first: u8, second: Option<u8>) -> Self {
        self.capture[0] = CapturePolicy::path(first);
        if let Some(index) = second {
            self.capture[1] = CapturePolicy::path(index);
        }
        self
    }

    const fn sockaddr(mut self, address: u8, length: u8) -> Self {
        self.capture[0] = CapturePolicy::sockaddr(address, length);
        self
    }

    const fn any_bits(mut self, argument: u8, mask: u64) -> Self {
        self.filter = Some((argument, mask));
        self
    }

    const fn resolver(mut self, resolver: KernelObjectResolver) -> Self {
        self.object_resolver = resolver;
        self
    }

    fn enabled_for(self, profile: PolicyProfile) -> bool {
        rank(profile) >= rank(self.minimum_profile)
    }

    fn kernel(self) -> Result<(u32, KernelPolicy)> {
        let nr = u32::try_from(self.nr).map_err(|_| anyhow::anyhow!("negative syscall number"))?;
        if nr >= POLICY_MAP_ENTRIES {
            bail!("syscall {} number {nr} exceeds policy map", self.name);
        }
        let (filter_arg_index, filter_mask) = match self.filter {
            Some((index, mask)) => (index, mask),
            None => (0, 0),
        };
        Ok((
            nr,
            KernelPolicy {
                enabled: 1,
                domain: self.domain as u16,
                operation: self.operation as u16,
                capture: self.capture,
                filter_mask,
                filter_arg_index,
                object_resolver: self.object_resolver as u8,
                reserved: [0; 6],
            },
        ))
    }

    fn describe(self) -> Result<PolicyDescription> {
        let (nr, _) = self.kernel()?;
        let capture = self
            .capture
            .iter()
            .filter(|capture| capture.kind != CAPTURE_NONE)
            .map(|capture| CaptureDescription {
                kind: match capture.kind {
                    CAPTURE_USER_STRING => "USER_SUPPLIED_STRING",
                    CAPTURE_SOCKADDR => "RAW_USER_SOCKADDR",
                    _ => "UNKNOWN",
                }
                .to_owned(),
                argument_index: capture.arg_index,
                length_argument_index: (capture.kind == CAPTURE_SOCKADDR)
                    .then_some(capture.length_arg_index),
            })
            .collect();
        let kernel_filter = self.filter.map(|(argument_index, mask)| FilterDescription {
            kind: "ARG_ANY_BITS".to_owned(),
            argument_index,
            mask,
        });
        Ok(PolicyDescription {
            syscall_nr: nr as i32,
            syscall_name: self.name.to_owned(),
            domain: self.domain,
            operation: self.operation,
            object_resolver: self.object_resolver,
            capture,
            kernel_filter,
        })
    }
}

const fn rank(profile: PolicyProfile) -> u8 {
    match profile {
        PolicyProfile::Control => 0,
        PolicyProfile::Balanced => 1,
        PolicyProfile::Full => 2,
        PolicyProfile::FileAccess => 3,
    }
}

pub(crate) fn kernel_policies(profile: PolicyProfile) -> Result<Vec<(u32, KernelPolicy)>> {
    let specs = specs_for(profile);
    let mut seen = BTreeSet::new();
    let mut output = Vec::new();
    for spec in specs.into_iter().filter(|spec| spec.enabled_for(profile)) {
        let (nr, policy) = spec.kernel()?;
        if !seen.insert(nr) {
            bail!("duplicate native syscall policy number {nr}");
        }
        output.push((nr, policy));
    }
    Ok(output)
}

pub fn describe_policy(profile: PolicyProfile) -> Result<Vec<PolicyDescription>> {
    specs_for(profile)
        .into_iter()
        .filter(|spec| spec.enabled_for(profile))
        .map(Spec::describe)
        .collect()
}

pub fn policy_sha256(profile: PolicyProfile) -> Result<String> {
    let bytes = serde_json::to_vec(&describe_policy(profile)?)?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct EventPolicyIdentity {
    pub syscall_name: &'static str,
    pub domain: EffectDomain,
    pub operation: EffectOperation,
    pub capture: [CapturePolicy; 2],
    pub object_resolver: KernelObjectResolver,
    pub filter: Option<(u8, u64)>,
}

pub(crate) fn event_policy_identities(
    profile: PolicyProfile,
) -> Result<HashMap<i32, EventPolicyIdentity>> {
    let mut identities = HashMap::new();
    for spec in specs_for(profile)
        .into_iter()
        .filter(|spec| spec.enabled_for(profile))
    {
        let (number, _) = spec.kernel()?;
        let identity = EventPolicyIdentity {
            syscall_name: spec.name,
            domain: spec.domain,
            operation: spec.operation,
            capture: spec.capture,
            object_resolver: spec.object_resolver,
            filter: spec.filter,
        };
        if identities.insert(number as i32, identity).is_some() {
            bail!("duplicate native syscall identity number {number}");
        }
    }
    Ok(identities)
}

fn specs_for(profile: PolicyProfile) -> Vec<Spec> {
    let mut list = specs();
    if profile == PolicyProfile::FileAccess {
        for spec in &mut list {
            if matches!(spec.name, "open" | "openat") {
                spec.filter = None;
                spec.operation = EffectOperation::FileOpenRequest;
            }
        }
    }
    list
}

fn specs() -> Vec<Spec> {
    use EffectDomain::*;
    use EffectOperation::*;
    use PolicyProfile::*;

    // O_CREAT | O_TRUNC | O_TMPFILE. O_TMPFILE includes O_DIRECTORY on Linux;
    // matching either bit is conservative and may include a few non-mutating
    // open failures, which remain operation attempts rather than state claims.
    const TMPFILE_BIT: u64 = (libc::O_TMPFILE & !libc::O_DIRECTORY) as u64;
    const EFFECT_OPEN_FLAGS: u64 = libc::O_CREAT as u64 | libc::O_TRUNC as u64 | TMPFILE_BIT;
    const NAMESPACE_FLAGS: u64 = 0x00000080
        | 0x00000200
        | 0x00000400
        | 0x00020000
        | 0x00040000
        | 0x02000000
        | 0x04000000
        | 0x08000000
        | 0x10000000
        | 0x20000000
        | 0x40000000;
    let mut list = vec![
        Spec::new(
            libc::SYS_openat,
            "openat",
            Filesystem,
            FileCreateOrTruncate,
            Control,
        )
        .paths(1, None)
        .any_bits(2, EFFECT_OPEN_FLAGS),
        Spec::new(
            libc::SYS_openat2,
            "openat2",
            Filesystem,
            FileOpenRequest,
            Control,
        )
        .paths(1, None),
        Spec::new(libc::SYS_read, "read", Io, FdRead, FileAccess),
        Spec::new(libc::SYS_pread64, "pread64", Io, FdRead, FileAccess),
        Spec::new(libc::SYS_readv, "readv", Io, FdRead, FileAccess),
        Spec::new(libc::SYS_preadv, "preadv", Io, FdRead, FileAccess),
        Spec::new(libc::SYS_preadv2, "preadv2", Io, FdRead, FileAccess),
        Spec::new(libc::SYS_write, "write", Io, FdWrite, Balanced),
        Spec::new(libc::SYS_pwrite64, "pwrite64", Io, FdWrite, Balanced),
        Spec::new(libc::SYS_writev, "writev", Io, FdWrite, Balanced),
        Spec::new(libc::SYS_pwritev, "pwritev", Io, FdWrite, Balanced),
        Spec::new(libc::SYS_pwritev2, "pwritev2", Io, FdWrite, Balanced),
        Spec::new(
            libc::SYS_truncate,
            "truncate",
            Filesystem,
            FileTruncate,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_ftruncate,
            "ftruncate",
            Filesystem,
            FileTruncate,
            Control,
        ),
        Spec::new(
            libc::SYS_renameat,
            "renameat",
            Filesystem,
            FileRename,
            Control,
        )
        .paths(1, Some(3)),
        Spec::new(
            libc::SYS_renameat2,
            "renameat2",
            Filesystem,
            FileRename,
            Control,
        )
        .paths(1, Some(3)),
        Spec::new(
            libc::SYS_unlinkat,
            "unlinkat",
            Filesystem,
            PathEntryRemove,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_mkdirat,
            "mkdirat",
            Filesystem,
            DirectoryCreate,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_linkat,
            "linkat",
            Filesystem,
            HardLinkCreate,
            Control,
        )
        .paths(1, Some(3)),
        Spec::new(
            libc::SYS_symlinkat,
            "symlinkat",
            Filesystem,
            SymlinkCreate,
            Control,
        )
        .paths(0, Some(2)),
        Spec::new(
            libc::SYS_fchmodat,
            "fchmodat",
            Filesystem,
            PermissionsChange,
            Control,
        )
        .paths(1, None),
        Spec::new(
            SYS_FCHMODAT2,
            "fchmodat2",
            Filesystem,
            PermissionsChange,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_fchownat,
            "fchownat",
            Filesystem,
            OwnershipChange,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_fchmod,
            "fchmod",
            Filesystem,
            PermissionsChange,
            Control,
        ),
        Spec::new(
            libc::SYS_fchown,
            "fchown",
            Filesystem,
            OwnershipChange,
            Control,
        ),
        Spec::new(
            libc::SYS_mknodat,
            "mknodat",
            Filesystem,
            DeviceNodeCreate,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_setxattr,
            "setxattr",
            Filesystem,
            ExtendedAttributeSet,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(
            libc::SYS_lsetxattr,
            "lsetxattr",
            Filesystem,
            ExtendedAttributeSet,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(
            libc::SYS_fsetxattr,
            "fsetxattr",
            Filesystem,
            ExtendedAttributeSet,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_removexattr,
            "removexattr",
            Filesystem,
            ExtendedAttributeRemove,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(
            libc::SYS_lremovexattr,
            "lremovexattr",
            Filesystem,
            ExtendedAttributeRemove,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(
            libc::SYS_fremovexattr,
            "fremovexattr",
            Filesystem,
            ExtendedAttributeRemove,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_fallocate,
            "fallocate",
            Filesystem,
            FileAllocate,
            Balanced,
        ),
        Spec::new(
            libc::SYS_sendfile,
            "sendfile",
            Io,
            FdRangeTransfer,
            Balanced,
        ),
        Spec::new(libc::SYS_splice, "splice", Io, FdRangeTransfer, Balanced),
        Spec::new(
            libc::SYS_copy_file_range,
            "copy_file_range",
            Io,
            FdRangeTransfer,
            Balanced,
        ),
        Spec::new(libc::SYS_fsync, "fsync", Filesystem, FileSync, Full),
        Spec::new(libc::SYS_fdatasync, "fdatasync", Filesystem, FileSync, Full),
        Spec::new(libc::SYS_mmap, "mmap", Filesystem, MemoryWriteChannel, Full)
            .any_bits(2, libc::PROT_WRITE as u64),
        Spec::new(
            libc::SYS_mprotect,
            "mprotect",
            Filesystem,
            MemoryWriteChannel,
            Full,
        )
        .any_bits(2, libc::PROT_WRITE as u64)
        .resolver(KernelObjectResolver::MprotectFileWrite),
        Spec::new(libc::SYS_socket, "socket", Network, SocketCreate, Control),
        Spec::new(
            libc::SYS_socketpair,
            "socketpair",
            Network,
            SocketCreate,
            Control,
        ),
        Spec::new(
            libc::SYS_connect,
            "connect",
            Network,
            SocketConnect,
            Control,
        )
        .sockaddr(1, 2),
        Spec::new(libc::SYS_bind, "bind", Network, SocketBind, Control).sockaddr(1, 2),
        // accept/accept4 sockaddr buffers are kernel outputs. Reading them at
        // syscall entry would fabricate input evidence; the expanded resolver
        // instead joins successful do_accept return state before fd install.
        Spec::new(libc::SYS_accept, "accept", Network, SocketAccept, Control),
        Spec::new(libc::SYS_accept4, "accept4", Network, SocketAccept, Control),
        Spec::new(libc::SYS_listen, "listen", Network, SocketListen, Control),
        Spec::new(libc::SYS_sendto, "sendto", Network, NetworkSend, Balanced).sockaddr(4, 5),
        Spec::new(libc::SYS_sendmsg, "sendmsg", Network, NetworkSend, Balanced),
        Spec::new(
            libc::SYS_sendmmsg,
            "sendmmsg",
            Network,
            NetworkSend,
            Balanced,
        ),
        Spec::new(
            libc::SYS_setsockopt,
            "setsockopt",
            Network,
            SocketConfigure,
            Full,
        ),
        Spec::new(libc::SYS_mount, "mount", Namespace, Mount, Control).paths(0, Some(1)),
        Spec::new(libc::SYS_umount2, "umount2", Namespace, Unmount, Control).paths(0, None),
        Spec::new(
            libc::SYS_pivot_root,
            "pivot_root",
            Namespace,
            PivotRoot,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(libc::SYS_chroot, "chroot", Namespace, Chroot, Control).paths(0, None),
        Spec::new(
            libc::SYS_unshare,
            "unshare",
            Namespace,
            NamespaceUnshare,
            Control,
        )
        .any_bits(0, NAMESPACE_FLAGS),
        Spec::new(libc::SYS_setns, "setns", Namespace, NamespaceJoin, Control),
        Spec::new(libc::SYS_fsopen, "fsopen", Namespace, MountApi, Control).paths(0, None),
        Spec::new(libc::SYS_fsconfig, "fsconfig", Namespace, MountApi, Control),
        Spec::new(libc::SYS_fsmount, "fsmount", Namespace, MountApi, Control),
        Spec::new(
            libc::SYS_move_mount,
            "move_mount",
            Namespace,
            MountApi,
            Control,
        )
        .paths(1, Some(3)),
        Spec::new(
            libc::SYS_open_tree,
            "open_tree",
            Namespace,
            MountApi,
            Control,
        )
        .paths(1, None),
        Spec::new(
            libc::SYS_mount_setattr,
            "mount_setattr",
            Namespace,
            MountApi,
            Control,
        )
        .paths(1, None),
        Spec::new(libc::SYS_fspick, "fspick", Namespace, MountApi, Control).paths(1, None),
        Spec::new(libc::SYS_bpf, "bpf", KernelControl, BpfCommand, Control),
        Spec::new(
            libc::SYS_init_module,
            "init_module",
            KernelControl,
            KernelModuleLoad,
            Control,
        ),
        Spec::new(
            libc::SYS_finit_module,
            "finit_module",
            KernelControl,
            KernelModuleLoad,
            Control,
        ),
        Spec::new(
            libc::SYS_delete_module,
            "delete_module",
            KernelControl,
            KernelModuleUnload,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_perf_event_open,
            "perf_event_open",
            KernelControl,
            PerfEventOpen,
            Control,
        ),
        Spec::new(libc::SYS_ptrace, "ptrace", KernelControl, Ptrace, Control),
        Spec::new(
            libc::SYS_kexec_load,
            "kexec_load",
            KernelControl,
            KexecLoad,
            Control,
        ),
        Spec::new(
            libc::SYS_kexec_file_load,
            "kexec_file_load",
            KernelControl,
            KexecLoad,
            Control,
        ),
        Spec::new(libc::SYS_reboot, "reboot", KernelControl, Reboot, Control),
        Spec::new(
            libc::SYS_swapon,
            "swapon",
            KernelControl,
            SwapChange,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_swapoff,
            "swapoff",
            KernelControl,
            SwapChange,
            Control,
        )
        .paths(0, None),
        Spec::new(libc::SYS_ioctl, "ioctl", KernelControl, GenericIoctl, Full),
        Spec::new(
            libc::SYS_prctl,
            "prctl",
            KernelControl,
            ProcessControl,
            Full,
        ),
        Spec::new(
            libc::SYS_seccomp,
            "seccomp",
            Security,
            SeccompChange,
            Control,
        ),
        Spec::new(
            libc::SYS_add_key,
            "add_key",
            Security,
            KernelKeyChange,
            Control,
        ),
        Spec::new(
            libc::SYS_keyctl,
            "keyctl",
            Security,
            KernelKeyChange,
            Control,
        ),
        Spec::new(
            libc::SYS_sethostname,
            "sethostname",
            KernelControl,
            HostIdentityChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setdomainname,
            "setdomainname",
            KernelControl,
            HostIdentityChange,
            Control,
        ),
        Spec::new(
            libc::SYS_settimeofday,
            "settimeofday",
            KernelControl,
            SystemTimeChange,
            Control,
        ),
        Spec::new(
            libc::SYS_clock_settime,
            "clock_settime",
            KernelControl,
            SystemTimeChange,
            Control,
        ),
        Spec::new(
            libc::SYS_adjtimex,
            "adjtimex",
            KernelControl,
            SystemTimeChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setuid,
            "setuid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setgid,
            "setgid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setreuid,
            "setreuid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setregid,
            "setregid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setresuid,
            "setresuid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setresgid,
            "setresgid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setfsuid,
            "setfsuid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_setfsgid,
            "setfsgid",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_capset,
            "capset",
            Security,
            CredentialChange,
            Control,
        ),
        Spec::new(
            libc::SYS_quotactl,
            "quotactl",
            KernelControl,
            QuotaChange,
            Control,
        ),
        Spec::new(
            libc::SYS_acct,
            "acct",
            KernelControl,
            ProcessAccounting,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_userfaultfd,
            "userfaultfd",
            AsyncIo,
            Userfaultfd,
            Control,
        ),
        Spec::new(
            libc::SYS_io_uring_setup,
            "io_uring_setup",
            AsyncIo,
            IoUring,
            Control,
        ),
        Spec::new(
            libc::SYS_io_uring_register,
            "io_uring_register",
            AsyncIo,
            IoUring,
            Control,
        ),
        Spec::new(
            libc::SYS_io_uring_enter,
            "io_uring_enter",
            AsyncIo,
            IoUring,
            Control,
        ),
        Spec::new(
            libc::SYS_landlock_create_ruleset,
            "landlock_create_ruleset",
            Security,
            Landlock,
            Control,
        ),
        Spec::new(
            libc::SYS_landlock_add_rule,
            "landlock_add_rule",
            Security,
            Landlock,
            Control,
        ),
        Spec::new(
            libc::SYS_landlock_restrict_self,
            "landlock_restrict_self",
            Security,
            Landlock,
            Control,
        ),
    ];

    #[cfg(target_arch = "x86_64")]
    list.extend([
        Spec::new(
            libc::SYS_pkey_mprotect,
            "pkey_mprotect",
            Filesystem,
            MemoryWriteChannel,
            Full,
        )
        .any_bits(2, libc::PROT_WRITE as u64)
        .resolver(KernelObjectResolver::MprotectFileWrite),
        Spec::new(
            libc::SYS_open,
            "open",
            Filesystem,
            FileCreateOrTruncate,
            Control,
        )
        .paths(0, None)
        .any_bits(1, EFFECT_OPEN_FLAGS),
        Spec::new(
            libc::SYS_creat,
            "creat",
            Filesystem,
            FileCreateOrTruncate,
            Control,
        )
        .paths(0, None),
        Spec::new(libc::SYS_rename, "rename", Filesystem, FileRename, Control).paths(0, Some(1)),
        Spec::new(libc::SYS_unlink, "unlink", Filesystem, FileUnlink, Control).paths(0, None),
        Spec::new(
            libc::SYS_mkdir,
            "mkdir",
            Filesystem,
            DirectoryCreate,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_rmdir,
            "rmdir",
            Filesystem,
            DirectoryRemove,
            Control,
        )
        .paths(0, None),
        Spec::new(libc::SYS_link, "link", Filesystem, HardLinkCreate, Control).paths(0, Some(1)),
        Spec::new(
            libc::SYS_symlink,
            "symlink",
            Filesystem,
            SymlinkCreate,
            Control,
        )
        .paths(0, Some(1)),
        Spec::new(
            libc::SYS_chmod,
            "chmod",
            Filesystem,
            PermissionsChange,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_chown,
            "chown",
            Filesystem,
            OwnershipChange,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_lchown,
            "lchown",
            Filesystem,
            OwnershipChange,
            Control,
        )
        .paths(0, None),
        Spec::new(
            libc::SYS_mknod,
            "mknod",
            Filesystem,
            DeviceNodeCreate,
            Control,
        )
        .paths(0, None),
    ]);

    list
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_profile_preserves_existing_operation_and_policy_map_abi() {
        assert_eq!(EffectOperation::FdWrite as u32, 3);
        assert_eq!(EffectOperation::FdRead as u32, 21);
        assert_eq!(KernelObjectResolver::MprotectFileWrite as u8, 13);
        assert_eq!(KernelObjectResolver::FilePermissionRead as u8, 14);
        assert_eq!(std::mem::size_of::<KernelPolicy>(), 32);
        assert_eq!(
            PolicyProfile::from_str("file-access").unwrap(),
            PolicyProfile::FileAccess
        );
        assert!(PolicyProfile::from_str("file_access").is_err());
        for profile in [
            PolicyProfile::Control,
            PolicyProfile::Balanced,
            PolicyProfile::Full,
        ] {
            let direct = specs()
                .into_iter()
                .filter(|spec| spec.enabled_for(profile))
                .map(Spec::describe)
                .collect::<Result<Vec<_>>>()
                .unwrap();
            assert_eq!(describe_policy(profile).unwrap(), direct);
            assert!(!direct
                .iter()
                .any(|policy| policy.operation == EffectOperation::FdRead));
        }
    }

    #[test]
    fn file_access_captures_ordinary_opens_and_all_read_variants() {
        let access = describe_policy(PolicyProfile::FileAccess).unwrap();
        for name in ["openat", "openat2"] {
            let open = access
                .iter()
                .find(|policy| policy.syscall_name == name)
                .unwrap();
            assert_eq!(open.operation, EffectOperation::FileOpenRequest);
            assert_eq!(open.kernel_filter, None);
        }
        for name in ["read", "pread64", "readv", "preadv", "preadv2"] {
            let read = access
                .iter()
                .find(|policy| policy.syscall_name == name)
                .unwrap();
            assert_eq!(read.operation, EffectOperation::FdRead);
            assert_eq!(
                read.object_resolver,
                KernelObjectResolver::FilePermissionRead
            );
        }
        let full = describe_policy(PolicyProfile::Full).unwrap();
        assert!(!full
            .iter()
            .any(|policy| policy.operation == EffectOperation::FdRead));
        assert!(full
            .iter()
            .find(|policy| policy.syscall_name == "openat")
            .unwrap()
            .kernel_filter
            .is_some());
        kernel_policies(PolicyProfile::FileAccess).unwrap();
    }

    #[test]
    fn profiles_are_ordered_and_have_unique_native_numbers() {
        let control = kernel_policies(PolicyProfile::Control).unwrap();
        let balanced = kernel_policies(PolicyProfile::Balanced).unwrap();
        let full = kernel_policies(PolicyProfile::Full).unwrap();
        assert!(!control.is_empty());
        assert!(control.len() < balanced.len());
        assert!(balanced.len() < full.len());
    }

    #[test]
    fn openat_is_filtered_before_cgroup_and_event_work() {
        let openat = specs()
            .into_iter()
            .find(|spec| spec.name == "openat")
            .unwrap();
        assert_eq!(
            openat.filter,
            Some((
                2,
                libc::O_CREAT as u64
                    | libc::O_TRUNC as u64
                    | (libc::O_TMPFILE & !libc::O_DIRECTORY) as u64
            ))
        );
        assert_eq!(openat.capture[0], CapturePolicy::path(1));
        assert_eq!(openat.object_resolver, KernelObjectResolver::FileOpen);
    }

    #[test]
    fn write_family_uses_file_permission_resolver_and_other_fd_ops_do_not() {
        let specs = specs();
        for name in ["write", "pwrite64", "writev", "pwritev", "pwritev2"] {
            let spec = specs.iter().find(|spec| spec.name == name).unwrap();
            assert_eq!(
                spec.object_resolver,
                KernelObjectResolver::FilePermissionWrite
            );
        }
        let ftruncate = specs.iter().find(|spec| spec.name == "ftruncate").unwrap();
        assert_eq!(ftruncate.object_resolver, KernelObjectResolver::None);
    }

    #[test]
    fn memory_write_channels_are_filtered_before_cgroup_and_event_work() {
        let policies = specs();
        let mmap = policies
            .iter()
            .find(|policy| policy.name == "mmap")
            .unwrap();
        let mprotect = policies
            .iter()
            .find(|policy| policy.name == "mprotect")
            .unwrap();
        for policy in [mmap, mprotect] {
            assert_eq!(policy.filter, Some((2, libc::PROT_WRITE as u64)));
            assert_eq!(policy.operation, EffectOperation::MemoryWriteChannel);
        }
        assert_eq!(mmap.object_resolver, KernelObjectResolver::MmapFileWrite);
        assert_eq!(
            mprotect.object_resolver,
            KernelObjectResolver::MprotectFileWrite
        );
        #[cfg(target_arch = "x86_64")]
        {
            let pkey_mprotect = policies
                .iter()
                .find(|policy| policy.name == "pkey_mprotect")
                .unwrap();
            assert_eq!(
                pkey_mprotect.object_resolver,
                KernelObjectResolver::MprotectFileWrite
            );
            assert_eq!(pkey_mprotect.filter, Some((2, libc::PROT_WRITE as u64)));
        }
    }

    #[test]
    fn unlinkat_does_not_fabricate_file_or_directory_type() {
        let unlinkat = specs()
            .into_iter()
            .find(|spec| spec.name == "unlinkat")
            .unwrap();
        assert_eq!(unlinkat.operation, EffectOperation::PathEntryRemove);
        assert_eq!(unlinkat.object_resolver, KernelObjectResolver::PathUnlink);
    }

    #[test]
    fn xattr_policy_captures_the_attribute_name() {
        let policies = specs();
        for (name, path_argument) in [
            ("setxattr", Some(0)),
            ("lsetxattr", Some(0)),
            ("fsetxattr", None),
            ("removexattr", Some(0)),
            ("lremovexattr", Some(0)),
            ("fremovexattr", None),
        ] {
            let policy = policies.iter().find(|policy| policy.name == name).unwrap();
            let expected = match path_argument {
                Some(index) => [CapturePolicy::path(index), CapturePolicy::path(1)],
                None => [CapturePolicy::path(1), CapturePolicy::NONE],
            };
            assert_eq!(policy.capture, expected, "{name}");
            assert_eq!(policy.object_resolver, KernelObjectResolver::InodeXattr);
        }
    }

    #[test]
    fn fchmodat2_is_observed_with_path_setattr_resolution() {
        let policy = specs()
            .into_iter()
            .find(|policy| policy.name == "fchmodat2")
            .unwrap();
        assert_eq!(policy.nr, SYS_FCHMODAT2);
        assert_eq!(policy.capture[0], CapturePolicy::path(1));
        assert_eq!(policy.object_resolver, KernelObjectResolver::PathSetattr);
    }

    #[test]
    fn hard_link_uses_source_object_resolver() {
        let linkat = specs()
            .into_iter()
            .find(|spec| spec.name == "linkat")
            .unwrap();
        assert_eq!(linkat.object_resolver, KernelObjectResolver::PathLinkSource);
        assert_eq!(linkat.capture[0], CapturePolicy::path(1));
        assert_eq!(linkat.capture[1], CapturePolicy::path(3));
    }

    #[test]
    fn accept_output_buffers_are_not_captured_and_use_post_accept_resolver() {
        let policies = specs();
        for number in [libc::SYS_accept as i32, libc::SYS_accept4 as i32] {
            let policy = policies
                .iter()
                .find(|policy| policy.nr == libc::c_long::from(number))
                .expect("native accept syscall is in the frozen policy");
            assert_eq!(policy.domain, EffectDomain::Network);
            assert_eq!(policy.operation, EffectOperation::SocketAccept);
            assert_eq!(policy.object_resolver, KernelObjectResolver::SocketAccept);
            assert_eq!(policy.capture, [CapturePolicy::NONE; 2]);
        }
    }

    #[test]
    fn policy_digest_is_stable_hex() {
        let digest = policy_sha256(PolicyProfile::Balanced).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
}
