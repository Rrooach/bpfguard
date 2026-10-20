// SPDX-License-Identifier: GPL-2.0-only

use crate::policy::{event_policy_identities, EventPolicyIdentity};
use crate::protocol::{EVENT_OPERATION_ATTEMPT, EVENT_OPERATION_RESULT};
use crate::{
    validate_boot_id, CgroupMatchMode, EffectProcessIdentityAuthority, FileObjectResolutionMode,
    KernelEvent, KernelObjectResolver, PolicyProfile, SystemEffectEvent, FLAG_OBJECT_DELETE_FAILED,
    FLAG_OBJECT_JOIN_AMBIGUOUS, FLAG_OBJECT_JOIN_MISSING, FLAG_OBJECT_PATH_UNAVAILABLE,
    FLAG_OBJECT_READ_FAILED, FLAG_OBJECT_UNSUPPORTED, FLAG_PENDING_DELETE_FAILED,
    FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING, FLAG_PENDING_POISONED, FLAG_POLICY_INVALID,
    FLAG_SYSCALL_MISMATCH, FLAG_TASK_READ_FAILED,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_JSONL_BYTES: u64 = 512 * 1024 * 1024;

const OBJECT_FLAGS: u32 = FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED
    | FLAG_OBJECT_PATH_UNAVAILABLE
    | FLAG_OBJECT_UNSUPPORTED;

const OBJECT_FAILURE_FLAGS: u32 = FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED;

const FATAL_CORRELATION_FLAGS: u32 = FLAG_PENDING_INSERT_FAILED
    | FLAG_PENDING_MISSING
    | FLAG_PENDING_POISONED
    | FLAG_PENDING_DELETE_FAILED
    | FLAG_POLICY_INVALID
    | FLAG_SYSCALL_MISMATCH
    | FLAG_OBJECT_JOIN_MISSING
    | FLAG_OBJECT_JOIN_AMBIGUOUS
    | FLAG_OBJECT_READ_FAILED
    | FLAG_OBJECT_DELETE_FAILED
    | FLAG_TASK_READ_FAILED;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectRunVerification {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub published: u64,
    pub dropped: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectVerificationBinding {
    pub run_id: String,
    pub boot_id: String,
    pub profile: PolicyProfile,
    pub object_resolution_mode: FileObjectResolutionMode,
    pub cgroup_match_mode: CgroupMatchMode,
    pub runs: Vec<SystemEffectRunVerification>,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectProcessReference {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub event_seq: u64,
    pub ktime_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub start_boottime_ns: u64,
    pub stable_key: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectRunVerificationResult {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub published: u64,
    pub dropped: u64,
    pub recovered: u64,
    pub pairing_complete: bool,
    pub fatal_correlation_events: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemEffectArtifactVerification {
    pub schema_version: u32,
    pub wal_event_count: u64,
    pub jsonl_projection_verified: bool,
    pub policy_sha256: String,
    pub runs: Vec<SystemEffectRunVerificationResult>,
    pub process_references: Vec<SystemEffectProcessReference>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttemptIdentity {
    pid_tgid: u64,
    syscall_nr: i32,
    domain: u16,
    operation: u32,
    ktime_ns: u64,
    args: [u64; 6],
    task_start_boottime_ns: u64,
}

#[derive(Default)]
struct RunReplay {
    seen_sequences: BTreeSet<u64>,
    attempts: HashMap<u64, AttemptIdentity>,
    related_results: BTreeSet<u64>,
    recovered: u64,
    missing_pairs: u64,
    fatal_correlation_events: u64,
}

/// Rebuild the canonical public event solely from a validated binary frame and
/// the frozen policy. This deliberately does not accept any JSON-derived field.
pub fn canonical_system_effect_projection(
    event: &KernelEvent,
    run_id: &str,
    boot_id: &str,
    profile: PolicyProfile,
) -> Result<SystemEffectEvent> {
    if run_id.is_empty() || run_id.contains('\0') {
        bail!("run_id must be nonempty and contain no NUL bytes");
    }
    validate_boot_id(boot_id)?;
    event.validate()?;
    let policies = event_policy_identities(profile)?;
    let policy = policies
        .get(&event.syscall_nr)
        .copied()
        .context("event syscall is absent from the frozen policy")?;
    validate_policy_selection(event, policy)?;
    event.to_schema(run_id, boot_id, policy)
}

/// Verify the CRC-framed authoritative WAL and prove that JSONL is its exact
/// canonical projection. All cgroup/epoch identities and transport counters
/// come from an external trusted binding. A JSON field is never trusted.
pub fn verify_system_effect_artifacts(
    wal_path: &Path,
    jsonl_path: &Path,
    binding: &SystemEffectVerificationBinding,
) -> Result<SystemEffectArtifactVerification> {
    if binding.run_id.is_empty() || binding.run_id.contains('\0') {
        bail!("run_id must be nonempty and contain no NUL bytes");
    }
    validate_boot_id(&binding.boot_id)?;
    if binding.runs.is_empty() {
        bail!("system-effect verification requires at least one bound run");
    }

    let mut bound = BTreeMap::new();
    for run in &binding.runs {
        if run.cgroup_id == 0 || run.run_epoch == 0 {
            bail!("bound system-effect cgroup and epoch must be nonzero");
        }
        if run.published.checked_add(run.dropped).is_none() {
            bail!("bound system-effect transport counters overflow");
        }
        if bound
            .insert((run.cgroup_id, run.run_epoch), run.clone())
            .is_some()
        {
            bail!("duplicate bound system-effect cgroup/epoch identity");
        }
    }

    let recovery = crate::recover_wal(wal_path)?;
    if recovery.truncated_tail {
        bail!("system-effect WAL has a truncated tail");
    }
    let policies = event_policy_identities(binding.profile)?;
    let mut replay: BTreeMap<(u64, u64), RunReplay> = bound
        .keys()
        .copied()
        .map(|key| (key, RunReplay::default()))
        .collect();
    let mut projected = Vec::with_capacity(recovery.events.len());
    let mut process_references = Vec::with_capacity(recovery.events.len());

    for event in &recovery.events {
        let key = (event.cgroup_id, event.run_epoch);
        let run = bound
            .get(&key)
            .context("WAL event is outside the externally bound cgroup/epoch set")?;
        let state = replay.get_mut(&key).expect("bound run has replay state");
        if !state.seen_sequences.insert(event.event_seq) {
            bail!("duplicate system-effect event sequence in bound run");
        }
        let attempted = run
            .published
            .checked_add(run.dropped)
            .context("bound transport counters overflow")?;
        if event.event_seq > attempted {
            bail!("system-effect event sequence exceeds bound event-attempt count");
        }
        let policy = policies
            .get(&event.syscall_nr)
            .copied()
            .context("event syscall is absent from the frozen policy")?;
        event.validate()?;
        validate_policy_selection(event, policy)?;
        validate_object_mode(
            event,
            policy.object_resolver,
            binding.object_resolution_mode,
        )?;
        if event.flags & FLAG_TASK_READ_FAILED != 0 {
            bail!("system-effect WAL contains a task identity read failure");
        }
        if event.flags & FATAL_CORRELATION_FLAGS != 0 {
            state.fatal_correlation_events = state.fatal_correlation_events.saturating_add(1);
        }
        replay_pair(event, state)?;

        let schema = event.to_schema_with_cgroup_match(
            &binding.run_id,
            &binding.boot_id,
            policy,
            binding.cgroup_match_mode,
        )?;
        if schema.process_identity.authority
            != EffectProcessIdentityAuthority::KernelTaskStartBoottimeAtSyscallEntry
        {
            bail!("system-effect event lacks authoritative task start identity");
        }
        process_references.push(SystemEffectProcessReference {
            cgroup_id: event.cgroup_id,
            run_epoch: event.run_epoch,
            event_seq: event.event_seq,
            ktime_ns: event.ktime_ns,
            pid: event.pid_tgid as u32,
            tgid: (event.pid_tgid >> 32) as u32,
            start_boottime_ns: event.task_start_boottime_ns,
            stable_key: schema
                .process_identity
                .stable_key
                .clone()
                .context("authoritative process identity has no stable key")?,
        });
        projected.push(schema);
        state.recovered = state.recovered.saturating_add(1);
    }

    verify_jsonl(jsonl_path, &projected)?;

    let mut runs = Vec::with_capacity(bound.len());
    for (key, expected) in bound {
        let state = replay.remove(&key).expect("bound run has replay state");
        if state.recovered != expected.published {
            bail!(
                "system-effect recovered count for cgroup {} epoch {} is {} but bound published is {}",
                expected.cgroup_id,
                expected.run_epoch,
                state.recovered,
                expected.published
            );
        }
        if expected.dropped == 0 {
            let expected_sequences: BTreeSet<u64> = (1..=expected.published).collect();
            if state.seen_sequences != expected_sequences {
                bail!("loss-free system-effect stream has a sequence gap");
            }
            if state.missing_pairs != 0 || !state.attempts.is_empty() {
                bail!("loss-free system-effect stream has an incomplete attempt/result pair");
            }
        }
        runs.push(SystemEffectRunVerificationResult {
            cgroup_id: expected.cgroup_id,
            run_epoch: expected.run_epoch,
            published: expected.published,
            dropped: expected.dropped,
            recovered: state.recovered,
            pairing_complete: state.missing_pairs == 0 && state.attempts.is_empty(),
            fatal_correlation_events: state.fatal_correlation_events,
        });
    }
    process_references.sort();

    Ok(SystemEffectArtifactVerification {
        schema_version: crate::EFFECT_EVENT_SCHEMA_VERSION,
        wal_event_count: recovery.events.len() as u64,
        jsonl_projection_verified: true,
        policy_sha256: crate::policy_sha256(binding.profile)?,
        runs,
        process_references,
    })
}

pub(crate) fn validate_policy_selection(
    event: &KernelEvent,
    policy: EventPolicyIdentity,
) -> Result<()> {
    if event.domain != policy.domain as u16 || event.operation != policy.operation as u32 {
        bail!("system-effect event identity disagrees with frozen policy");
    }
    if let Some((argument_index, mask)) = policy.filter {
        let argument = event.args[usize::from(argument_index)];
        if argument & mask == 0 {
            bail!("system-effect event does not satisfy its frozen kernel filter");
        }
    }
    Ok(())
}

fn validate_object_mode(
    event: &KernelEvent,
    resolver: KernelObjectResolver,
    mode: FileObjectResolutionMode,
) -> Result<()> {
    let enabled = match mode {
        FileObjectResolutionMode::UserInput => false,
        FileObjectResolutionMode::KernelFileOpenPartial => {
            resolver == KernelObjectResolver::FileOpen
        }
        FileObjectResolutionMode::KernelFileOpenWritePartial => matches!(
            resolver,
            KernelObjectResolver::FileOpen
                | KernelObjectResolver::FilePermissionWrite
                | KernelObjectResolver::FilePermissionRead
        ),
        FileObjectResolutionMode::KernelObjectExpandedPartial => {
            resolver != KernelObjectResolver::None
        }
    };
    let is_result = event.kind == EVENT_OPERATION_RESULT;
    let applicable = enabled
        && is_result
        && match resolver {
            KernelObjectResolver::None => false,
            KernelObjectResolver::FilePermissionWrite
            | KernelObjectResolver::FilePermissionRead => event.return_value > 0,
            KernelObjectResolver::MmapFileWrite => mmap_object_eligible(event),
            KernelObjectResolver::FileOpen
            | KernelObjectResolver::PathCreateParent
            | KernelObjectResolver::PathUnlink
            | KernelObjectResolver::PathRenameSource
            | KernelObjectResolver::PathSetattr
            | KernelObjectResolver::InodeXattr
            | KernelObjectResolver::SocketConnect
            | KernelObjectResolver::SocketBind
            | KernelObjectResolver::PathLinkSource
            | KernelObjectResolver::SocketAccept
            | KernelObjectResolver::MprotectFileWrite => true,
        };
    if !applicable {
        if event.file_object.is_some()
            || event.socket_object.is_some()
            || event.flags & OBJECT_FLAGS != 0
        {
            bail!("system-effect WAL claims object evidence outside the bound mode and eligible result set");
        }
        return Ok(());
    }

    let socket_resolver = matches!(
        resolver,
        KernelObjectResolver::SocketConnect
            | KernelObjectResolver::SocketBind
            | KernelObjectResolver::SocketAccept
    );
    if event.file_object.is_some() && socket_resolver {
        bail!("socket resolver produced a file-object frame");
    }
    if event.socket_object.is_some() && !socket_resolver {
        bail!("non-socket resolver produced a socket-object frame");
    }

    let unsupported = event.flags & FLAG_OBJECT_UNSUPPORTED != 0;
    if unsupported {
        if !matches!(
            resolver,
            KernelObjectResolver::SocketAccept | KernelObjectResolver::MprotectFileWrite
        ) || event.file_object.is_some()
            || event.socket_object.is_some()
        {
            bail!("unsupported object result has an impossible resolver or retained identity");
        }
        return Ok(());
    }

    // An explicitly disclosed resolver failure is valid incomplete evidence.
    // Verify its canonical UNRESOLVED projection and count the raw fatal flag;
    // the enclosing report must retain the same failure count and health.
    // Missing identities without such a flag remain an invalid downgrade.
    if event.flags & OBJECT_FAILURE_FLAGS != 0 {
        if event.file_object.is_some() || event.socket_object.is_some() {
            bail!("failed object resolution retained kernel object evidence");
        }
        return Ok(());
    }

    // Path/inode/file hooks do not publish an identity for a failed operation.
    // bind/connect are different: their LSM hook can resolve the kernel-copied
    // request before the protocol implementation returns an error.
    if event.return_value < 0 && !socket_resolver {
        if event.file_object.is_some() || event.socket_object.is_some() {
            bail!("failed non-socket operation retained kernel object evidence");
        }
        return Ok(());
    }
    if event.return_value < 0 && socket_resolver && event.socket_object.is_none() {
        // The socket LSM hook may not have been reached (bad fd/address or a
        // prior denial). This is a truthful failed-syscall resolution result.
        return Ok(());
    }
    if socket_resolver {
        if event.socket_object.is_none() {
            bail!("eligible socket result silently downgraded without SOCKET_OBJECT evidence");
        }
    } else if event.file_object.is_none() {
        bail!("eligible file result silently downgraded without FILE_OBJECT evidence");
    }
    Ok(())
}

fn mmap_object_eligible(event: &KernelEvent) -> bool {
    const PROT_WRITE: u64 = libc::PROT_WRITE as u64;
    const MAP_SHARED: u64 = libc::MAP_SHARED as u64;
    const MAP_ANONYMOUS: u64 = libc::MAP_ANONYMOUS as u64;

    event.args[2] & PROT_WRITE != 0
        && event.args[3] & MAP_SHARED != 0
        && event.args[3] & MAP_ANONYMOUS == 0
}

fn replay_pair(event: &KernelEvent, state: &mut RunReplay) -> Result<()> {
    if event.kind == EVENT_OPERATION_ATTEMPT {
        let identity = AttemptIdentity {
            pid_tgid: event.pid_tgid,
            syscall_nr: event.syscall_nr,
            domain: event.domain,
            operation: event.operation,
            ktime_ns: event.ktime_ns,
            args: event.args,
            task_start_boottime_ns: event.task_start_boottime_ns,
        };
        if state.attempts.insert(event.event_seq, identity).is_some() {
            bail!("duplicate system-effect attempt sequence");
        }
    } else if event.kind == EVENT_OPERATION_RESULT {
        if event.related_attempt_seq == 0 {
            state.missing_pairs = state.missing_pairs.saturating_add(1);
            return Ok(());
        }
        if !state.related_results.insert(event.related_attempt_seq) {
            bail!("multiple system-effect results reference the same attempt");
        }
        let Some(attempt) = state.attempts.remove(&event.related_attempt_seq) else {
            state.missing_pairs = state.missing_pairs.saturating_add(1);
            return Ok(());
        };
        if attempt.pid_tgid != event.pid_tgid
            || attempt.syscall_nr != event.syscall_nr
            || attempt.domain != event.domain
            || attempt.operation != event.operation
            || attempt.args != event.args
            || attempt.task_start_boottime_ns != event.task_start_boottime_ns
            || event.event_seq <= event.related_attempt_seq
            || event.ktime_ns < attempt.ktime_ns
        {
            bail!("system-effect result does not match its referenced attempt");
        }
    } else {
        unreachable!("KernelEvent::validate closed the event kind");
    }
    Ok(())
}

fn verify_jsonl(path: &Path, projected: &[SystemEffectEvent]) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open system-effect JSONL {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("system-effect JSONL must be a singly linked regular file");
    }
    if before.len() > MAX_JSONL_BYTES {
        bail!("system-effect JSONL exceeds its verification byte limit");
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    let mut limited = file.take(MAX_JSONL_BYTES + 1);
    limited.read_to_end(&mut bytes)?;
    let after = limited.get_ref().metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || bytes.len() as u64 != before.len()
    {
        bail!("system-effect JSONL changed while it was verified");
    }
    if (!projected.is_empty() && !bytes.ends_with(b"\n"))
        || (projected.is_empty() && !bytes.is_empty())
    {
        bail!("system-effect JSONL has a noncanonical terminator");
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    let lines: Vec<&[u8]> = if body.is_empty() {
        Vec::new()
    } else {
        let lines: Vec<&[u8]> = body.split(|byte| *byte == b'\n').collect();
        if lines.iter().any(|line| line.is_empty()) {
            bail!("system-effect JSONL contains an empty line");
        }
        lines
    };
    if lines.len() != projected.len() {
        bail!("system-effect JSONL/WAL event counts disagree");
    }
    for (index, (line, expected)) in lines.iter().zip(projected).enumerate() {
        let decoded: SystemEffectEvent = serde_json::from_slice(line)
            .with_context(|| format!("decode system-effect JSONL line {}", index + 1))?;
        decoded.validate_object_resolution()?;
        decoded.validate_attribution()?;
        decoded.validate_process_identity()?;
        if &decoded != expected || serde_json::to_vec(expected)?.as_slice() != *line {
            bail!(
                "system-effect JSONL line {} is not the canonical WAL projection",
                index + 1
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        KernelFileObject, KernelSocketObject, EFFECT_EVENT_SCHEMA_VERSION,
        MAX_SOCKET_ENDPOINT_BYTES, PAYLOAD_NONE, SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE,
        SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT,
    };
    use crate::wal::WalWriter;
    use crate::ObjectRole;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    const BOOT_ID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    #[test]
    fn read_permission_identity_requires_positive_result_and_enabled_mode() {
        let mut result = event(EVENT_OPERATION_RESULT, 2);
        result.domain = crate::EffectDomain::Io as u16;
        result.operation = crate::EffectOperation::FdRead as u32;
        result.syscall_nr = libc::SYS_read as i32;
        result.return_value = 5;
        result.args[2] = 5;
        result.file_object = Some(file_object(100));
        result.validate().unwrap();
        let resolver = KernelObjectResolver::FilePermissionRead;
        for mode in [
            FileObjectResolutionMode::KernelFileOpenWritePartial,
            FileObjectResolutionMode::KernelObjectExpandedPartial,
        ] {
            validate_object_mode(&result, resolver, mode).unwrap();
        }
        for mode in [
            FileObjectResolutionMode::UserInput,
            FileObjectResolutionMode::KernelFileOpenPartial,
        ] {
            assert!(validate_object_mode(&result, resolver, mode).is_err());
        }
        for value in [0, -libc::EACCES as i64] {
            result.return_value = value;
            assert!(result.validate().is_err());
        }
        result.file_object = None;
        result.return_value = 5;
        result.flags = FLAG_OBJECT_JOIN_MISSING;
        result.validate().unwrap();
        validate_object_mode(
            &result,
            resolver,
            FileObjectResolutionMode::KernelFileOpenWritePartial,
        )
        .unwrap();
        assert!(
            validate_object_mode(&result, resolver, FileObjectResolutionMode::UserInput).is_err()
        );
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "bpf-observer-effect-verify-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn event(kind: u16, sequence: u64) -> KernelEvent {
        KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind,
            domain: crate::EffectDomain::KernelControl as u16,
            operation: crate::EffectOperation::BpfCommand as u32,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: 7,
            event_seq: sequence,
            related_attempt_seq: u64::from(kind == EVENT_OPERATION_RESULT),
            ktime_ns: 100 + sequence,
            cgroup_id: 9,
            pid_tgid: (22u64 << 32) | 22,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            task_start_boottime_ns: 44,
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; crate::protocol::CAPTURE_BYTES]; 2],
            file_object: None,
            socket_object: None,
        }
    }

    fn selected_pair(syscall_nr: i32, attempt_seq: u64) -> [KernelEvent; 2] {
        let policy = event_policy_identities(PolicyProfile::Full).unwrap()[&syscall_nr];
        let mut attempt = event(EVENT_OPERATION_ATTEMPT, attempt_seq);
        attempt.domain = policy.domain as u16;
        attempt.operation = policy.operation as u32;
        attempt.syscall_nr = syscall_nr;
        attempt.ktime_ns = 100 + attempt_seq;
        if let Some((argument_index, mask)) = policy.filter {
            attempt.args[usize::from(argument_index)] = mask;
        }
        for (slot, capture) in policy.capture.iter().enumerate() {
            attempt.payload_kinds[slot] = capture.kind;
            attempt.payload_arg_indices[slot] = capture.arg_index;
            match capture.kind {
                PAYLOAD_NONE => {}
                crate::protocol::PAYLOAD_USER_STRING => {
                    let bytes = b"/tmp/effect\0";
                    attempt.payload_lens[slot] = bytes.len() as u16;
                    attempt.payloads[slot][..bytes.len()].copy_from_slice(bytes);
                    attempt.flags |= crate::protocol::FLAG_USER_MEMORY_SNAPSHOT;
                }
                crate::protocol::PAYLOAD_SOCKADDR => {
                    let family = (libc::AF_INET as u16).to_ne_bytes();
                    let mut sockaddr = [0u8; 16];
                    sockaddr[..2].copy_from_slice(&family);
                    sockaddr[2..4].copy_from_slice(&443u16.to_be_bytes());
                    sockaddr[4..8].copy_from_slice(&[192, 0, 2, 9]);
                    attempt.payload_lens[slot] = sockaddr.len() as u16;
                    attempt.payloads[slot][..sockaddr.len()].copy_from_slice(&sockaddr);
                    attempt.args[usize::from(capture.length_arg_index)] = sockaddr.len() as u64;
                    attempt.flags |= crate::protocol::FLAG_USER_MEMORY_SNAPSHOT;
                }
                _ => panic!("unknown test capture kind"),
            }
        }
        let mut result = attempt.clone();
        result.kind = EVENT_OPERATION_RESULT;
        result.event_seq = attempt_seq + 1;
        result.related_attempt_seq = attempt_seq;
        result.ktime_ns += 1;
        result.flags = 0;
        result.payload_lens = [0; 2];
        result.payload_kinds = [PAYLOAD_NONE; 2];
        result.payload_arg_indices = [0; 2];
        result.payloads = [[0; crate::protocol::CAPTURE_BYTES]; 2];
        [attempt, result]
    }

    fn file_object(inode: u64) -> KernelFileObject {
        KernelFileObject {
            mount_id_unique: 11,
            inode,
            filesystem_magic: 0xef53,
            device_major: 8,
            device_minor: 1,
            inode_generation: 3,
            path_len: 0,
            generation_valid: 1,
            path_quality: crate::protocol::FILE_PATH_NOT_REQUESTED,
            path: [0; crate::protocol::KERNEL_FILE_PATH_BYTES],
        }
    }

    fn socket_object(operation: crate::EffectOperation) -> KernelSocketObject {
        let mut endpoint = [0u8; MAX_SOCKET_ENDPOINT_BYTES];
        endpoint[..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
        endpoint[2..4].copy_from_slice(&443u16.to_be_bytes());
        endpoint[4..8].copy_from_slice(&[192, 0, 2, 9]);
        let accepted = operation == crate::EffectOperation::SocketAccept;
        let local = operation == crate::EffectOperation::SocketBind;
        KernelSocketObject {
            network_namespace_cookie: 21,
            socket_cookie: 22,
            address_family: libc::AF_INET as u32,
            socket_type: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
            endpoint_address_family: libc::AF_INET as u32,
            endpoint_len: 16,
            endpoint_role: if local { 1 } else { 2 },
            endpoint_quality: 1,
            endpoint,
            endpoint_authority: if accepted {
                SOCKET_ENDPOINT_AUTHORITY_KERNEL_STATE
            } else {
                SOCKET_ENDPOINT_AUTHORITY_LSM_ARGUMENT
            },
        }
    }

    fn write_artifacts(
        directory: &TestDirectory,
        events: &[KernelEvent],
    ) -> (
        PathBuf,
        PathBuf,
        SystemEffectVerificationBinding,
        Vec<SystemEffectEvent>,
    ) {
        let wal_path = directory.0.join("system-effects.raw.bin");
        let jsonl_path = directory.0.join("system-effects.jsonl");
        let mut wal = WalWriter::create(&wal_path).unwrap();
        let mut json = Vec::new();
        let mut projected = Vec::new();
        for event in events {
            wal.append(event).unwrap();
            let event =
                canonical_system_effect_projection(event, "run", BOOT_ID, PolicyProfile::Full)
                    .unwrap();
            json.extend_from_slice(&serde_json::to_vec(&event).unwrap());
            json.push(b'\n');
            projected.push(event);
        }
        wal.sync().unwrap();
        std::fs::write(&jsonl_path, json).unwrap();
        let binding = SystemEffectVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            profile: PolicyProfile::Full,
            object_resolution_mode: FileObjectResolutionMode::KernelObjectExpandedPartial,
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            runs: vec![SystemEffectRunVerification {
                cgroup_id: 9,
                run_epoch: 7,
                published: events.len() as u64,
                dropped: 0,
            }],
        };
        (wal_path, jsonl_path, binding, projected)
    }

    #[test]
    fn accept_is_a_socket_object_resolver() {
        let mut accepted = event(EVENT_OPERATION_RESULT, 1);
        accepted.socket_object = Some(KernelSocketObject {
            network_namespace_cookie: 1,
            socket_cookie: 2,
            address_family: libc::AF_INET as u32,
            socket_type: libc::SOCK_STREAM as u32,
            protocol: libc::IPPROTO_TCP as u32,
            endpoint_address_family: libc::AF_INET as u32,
            endpoint_len: 16,
            endpoint_role: 2,
            endpoint_quality: 1,
            endpoint: [0; MAX_SOCKET_ENDPOINT_BYTES],
            endpoint_authority: 2,
        });

        assert!(validate_object_mode(
            &accepted,
            KernelObjectResolver::SocketAccept,
            FileObjectResolutionMode::KernelObjectExpandedPartial,
        )
        .is_ok());
    }

    #[test]
    fn expanded_wal_rebuilds_parent_source_primary_and_peer_roles() {
        let mut events = Vec::new();
        let cases = [
            (libc::SYS_mkdirat as i32, ObjectRole::Parent),
            (libc::SYS_renameat2 as i32, ObjectRole::Source),
            (libc::SYS_linkat as i32, ObjectRole::Source),
        ];
        let mut expected_roles = Vec::new();
        for (index, (syscall, role)) in cases.into_iter().enumerate() {
            let mut pair = selected_pair(syscall, events.len() as u64 + 1);
            pair[1].file_object = Some(file_object(100 + index as u64));
            events.extend(pair);
            expected_roles.push(role);
        }
        for syscall in [
            libc::SYS_bind as i32,
            libc::SYS_connect as i32,
            libc::SYS_accept as i32,
        ] {
            let mut pair = selected_pair(syscall, events.len() as u64 + 1);
            let operation = crate::EffectOperation::from_raw(pair[1].operation).unwrap();
            if operation == crate::EffectOperation::SocketAccept {
                pair[1].return_value = 7;
            }
            pair[1].socket_object = Some(socket_object(operation));
            events.extend(pair);
            expected_roles.push(if operation == crate::EffectOperation::SocketBind {
                ObjectRole::Primary
            } else {
                ObjectRole::Peer
            });
        }

        let directory = TestDirectory::new();
        let (wal, jsonl, binding, projected) = write_artifacts(&directory, &events);
        let verified = verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();
        assert_eq!(verified.wal_event_count, events.len() as u64);
        let actual_roles = projected
            .iter()
            .filter(|event| event.kind == crate::EventKind::OperationResult)
            .map(|event| event.object_resolution.objects[0].role)
            .collect::<Vec<_>>();
        assert_eq!(actual_roles, expected_roles);
    }

    #[test]
    fn expanded_wal_fails_closed_on_missing_wrong_or_forged_object_join() {
        let directory = TestDirectory::new();
        let mut pair = selected_pair(libc::SYS_mkdirat as i32, 1);

        let (wal, jsonl, binding, _) = write_artifacts(&directory, &pair);
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        pair[1].file_object = Some(file_object(101));
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &pair);
        std::fs::remove_file(&wal).unwrap();
        pair[1].file_object = None;
        pair[1].socket_object = Some(socket_object(crate::EffectOperation::SocketBind));
        let mut forged_wal = WalWriter::create(&wal).unwrap();
        for event in &pair {
            forged_wal.append(event).unwrap();
        }
        forged_wal.sync().unwrap();
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        pair[1].socket_object = None;
        pair[1].flags = FLAG_OBJECT_PATH_UNAVAILABLE;
        assert!(validate_object_mode(
            &pair[1],
            KernelObjectResolver::PathCreateParent,
            FileObjectResolutionMode::KernelObjectExpandedPartial,
        )
        .is_err());
    }

    #[test]
    fn disclosed_object_failures_replay_as_unresolved_and_count_once_per_event() {
        for syscall in [libc::SYS_setxattr as i32, libc::SYS_openat as i32] {
            for flags in [
                FLAG_OBJECT_JOIN_MISSING,
                FLAG_OBJECT_JOIN_AMBIGUOUS,
                FLAG_OBJECT_READ_FAILED,
                FLAG_OBJECT_DELETE_FAILED,
                FLAG_OBJECT_JOIN_MISSING | FLAG_OBJECT_JOIN_AMBIGUOUS,
            ] {
                let mut pair = selected_pair(syscall, 1);
                pair[1].flags = flags;
                if syscall == libc::SYS_openat as i32 {
                    pair[1].return_value = 6;
                }
                let directory = TestDirectory::new();
                let (wal, jsonl, binding, projected) = write_artifacts(&directory, &pair);
                let verified = verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();
                assert!(verified.jsonl_projection_verified);
                assert!(verified.runs[0].pairing_complete);
                assert_eq!(verified.runs[0].fatal_correlation_events, 1);
                let resolution = serde_json::to_value(&projected[1].object_resolution).unwrap();
                assert_eq!(resolution["quality"], "UNRESOLVED");
                assert_eq!(resolution["objects"], serde_json::json!([]));
            }
        }
    }

    #[test]
    fn disclosed_failure_cannot_be_promoted_in_json_or_keep_an_object_identity() {
        let mut pair = selected_pair(libc::SYS_setxattr as i32, 1);
        pair[1].flags = FLAG_OBJECT_JOIN_AMBIGUOUS;
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, projected) = write_artifacts(&directory, &pair);
        let mut forged = projected
            .iter()
            .map(|event| serde_json::to_value(event).unwrap())
            .collect::<Vec<_>>();
        forged[1]["object_resolution"]["quality"] = serde_json::json!("KERNEL_RESOLVED");
        let mut json = Vec::new();
        for value in forged {
            json.extend_from_slice(&serde_json::to_vec(&value).unwrap());
            json.push(b'\n');
        }
        std::fs::write(&jsonl, json).unwrap();
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        pair[1].file_object = Some(file_object(101));
        assert!(pair[1].validate().is_err());
        assert!(validate_object_mode(
            &pair[1],
            KernelObjectResolver::InodeXattr,
            FileObjectResolutionMode::KernelObjectExpandedPartial,
        )
        .is_err());

        pair[1].file_object = None;
        assert!(validate_object_mode(
            &pair[1],
            KernelObjectResolver::InodeXattr,
            FileObjectResolutionMode::UserInput,
        )
        .is_err());
    }

    #[test]
    fn failed_socket_disclosed_resolution_failure_stays_unresolved_and_mode_bound() {
        let mut pair = selected_pair(libc::SYS_connect as i32, 1);
        pair[1].return_value = -i64::from(libc::EACCES);
        pair[1].flags = FLAG_OBJECT_JOIN_MISSING;
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, projected) = write_artifacts(&directory, &pair);
        let verified = verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();
        assert_eq!(verified.runs[0].fatal_correlation_events, 1);
        let resolution = serde_json::to_value(&projected[1].object_resolution).unwrap();
        assert_eq!(resolution["quality"], "UNRESOLVED");
        assert_eq!(resolution["objects"], serde_json::json!([]));
        assert!(validate_object_mode(
            &pair[1],
            KernelObjectResolver::SocketConnect,
            FileObjectResolutionMode::KernelFileOpenPartial,
        )
        .is_err());
        pair[1].socket_object = Some(socket_object(crate::EffectOperation::SocketConnect));
        assert!(pair[1].validate().is_err());
        assert!(validate_object_mode(
            &pair[1],
            KernelObjectResolver::SocketConnect,
            FileObjectResolutionMode::KernelObjectExpandedPartial,
        )
        .is_err());
    }

    #[test]
    fn expanded_wal_fails_closed_on_duplicate_or_mismatched_pairs_and_json_role() {
        let mut pair = selected_pair(libc::SYS_renameat2 as i32, 1);
        pair[1].file_object = Some(file_object(200));

        let mut mismatched = pair.clone();
        mismatched[1].args[0] ^= 1;
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &mismatched);
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        let mut duplicate = pair.to_vec();
        let mut second_result = pair[1].clone();
        second_result.event_seq = 3;
        second_result.ktime_ns += 1;
        duplicate.push(second_result);
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &duplicate);
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        let directory = TestDirectory::new();
        let (wal, jsonl, binding, mut projected) = write_artifacts(&directory, &pair);
        projected[1].object_resolution.objects[0].role = ObjectRole::Primary;
        let mut forged_json = Vec::new();
        for event in &projected {
            forged_json.extend_from_slice(&serde_json::to_vec(event).unwrap());
            forged_json.push(b'\n');
        }
        std::fs::write(&jsonl, forged_json).unwrap();
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());
    }

    #[test]
    fn expanded_wal_replays_mmap_eligibility_and_mprotect_unsupported_exactly() {
        let mut mmap_shared = selected_pair(libc::SYS_mmap as i32, 1);
        mmap_shared[0].args[3] = libc::MAP_SHARED as u64;
        mmap_shared[1].args[3] = libc::MAP_SHARED as u64;
        mmap_shared[1].return_value = 0x1_0000;
        mmap_shared[1].file_object = Some(file_object(301));
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &mmap_shared);
        verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();

        let mut mmap_private = selected_pair(libc::SYS_mmap as i32, 1);
        mmap_private[0].args[3] = libc::MAP_PRIVATE as u64;
        mmap_private[1].args[3] = libc::MAP_PRIVATE as u64;
        mmap_private[1].return_value = 0x2_0000;
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &mmap_private);
        verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();

        mmap_private[1].file_object = Some(file_object(302));
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &mmap_private);
        assert!(verify_system_effect_artifacts(&wal, &jsonl, &binding).is_err());

        let mut mprotect = selected_pair(libc::SYS_mprotect as i32, 1);
        mprotect[1].file_object = Some(file_object(303));
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, _) = write_artifacts(&directory, &mprotect);
        verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();

        mprotect[1].file_object = None;
        mprotect[1].flags = FLAG_OBJECT_UNSUPPORTED;
        let directory = TestDirectory::new();
        let (wal, jsonl, binding, projected) = write_artifacts(&directory, &mprotect);
        verify_system_effect_artifacts(&wal, &jsonl, &binding).unwrap();
        assert_eq!(
            projected[1].object_resolution.quality,
            crate::ObjectResolutionQuality::Unresolved
        );
        assert!(projected[1].object_resolution.objects.is_empty());
    }

    #[test]
    fn strict_verifier_rebuilds_projection_and_rejects_tampering() {
        let directory = TestDirectory::new();
        let wal_path = directory.0.join("system-effects.raw.bin");
        let jsonl_path = directory.0.join("system-effects.jsonl");
        let events = [
            event(EVENT_OPERATION_ATTEMPT, 1),
            event(EVENT_OPERATION_RESULT, 2),
        ];
        let mut wal = WalWriter::create(&wal_path).unwrap();
        let mut json = Vec::new();
        for event in &events {
            wal.append(event).unwrap();
            let projected =
                canonical_system_effect_projection(event, "run", BOOT_ID, PolicyProfile::Control)
                    .unwrap();
            json.extend_from_slice(&serde_json::to_vec(&projected).unwrap());
            json.push(b'\n');
        }
        wal.sync().unwrap();
        std::fs::write(&jsonl_path, &json).unwrap();
        let binding = SystemEffectVerificationBinding {
            run_id: "run".to_owned(),
            boot_id: BOOT_ID.to_owned(),
            profile: PolicyProfile::Control,
            object_resolution_mode: FileObjectResolutionMode::UserInput,
            cgroup_match_mode: CgroupMatchMode::ExactCurrent,
            runs: vec![SystemEffectRunVerification {
                cgroup_id: 9,
                run_epoch: 7,
                published: 2,
                dropped: 0,
            }],
        };
        let verified = verify_system_effect_artifacts(&wal_path, &jsonl_path, &binding).unwrap();
        assert_eq!(verified.wal_event_count, 2);
        assert!(verified.runs[0].pairing_complete);
        assert_eq!(verified.process_references.len(), 2);

        let last = json.len() - 2;
        json[last] ^= 1;
        std::fs::write(&jsonl_path, json).unwrap();
        assert!(verify_system_effect_artifacts(&wal_path, &jsonl_path, &binding).is_err());
    }
}
