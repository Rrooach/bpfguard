// SPDX-License-Identifier: GPL-2.0-only
//! Diagnostic file access accounting from the existing CRC-framed WAL.
use crate::policy::{event_policy_identities, EffectOperation, EventPolicyIdentity, PolicyProfile};
use crate::protocol::{
    KernelEvent, KernelFileObject, ResolvedPath, EVENT_OPERATION_ATTEMPT,
    FILE_PATH_RESOLVED_AT_HOOK, FLAG_OBJECT_DELETE_FAILED, FLAG_OBJECT_JOIN_AMBIGUOUS,
    FLAG_OBJECT_JOIN_MISSING, FLAG_OBJECT_READ_FAILED, FLAG_PENDING_DELETE_FAILED,
    FLAG_PENDING_INSERT_FAILED, FLAG_PENDING_MISSING, FLAG_PENDING_POISONED, FLAG_POLICY_INVALID,
    FLAG_SYSCALL_MISMATCH, FLAG_TASK_READ_FAILED,
};
use crate::verify::validate_policy_selection;
use crate::wal::WalRecovery;
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct FileIdentity {
    pub mount_id_unique: u64,
    pub device_major: u32,
    pub device_minor: u32,
    pub inode: u64,
    pub inode_generation: Option<u32>,
    pub filesystem_magic: u64,
}
impl FileIdentity {
    fn anonymous_pseudo_file(&self) -> bool {
        // Linux UAPI PIPEFS_MAGIC, SOCKFS_MAGIC and ANON_INODE_FS_MAGIC.
        matches!(
            self.filesystem_magic,
            0x5049_5045 | 0x534f_434b | 0x0904_1934
        )
    }
}
impl From<&KernelFileObject> for FileIdentity {
    fn from(object: &KernelFileObject) -> Self {
        Self {
            mount_id_unique: object.mount_id_unique,
            device_major: object.device_major,
            device_minor: object.device_minor,
            inode: object.inode,
            inode_generation: (object.generation_valid == 1).then_some(object.inode_generation),
            filesystem_magic: object.filesystem_magic,
        }
    }
}
#[derive(Debug, Default, Serialize)]
pub struct AccessTotals {
    /// Normalized recorded segments: paired calls plus unmatched attempts/results.
    pub calls: u64,
    pub attempted_calls: u64,
    pub orphan_result_calls: u64,
    pub completed_calls: u64,
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub restart_results: u64,
    pub open_calls: u64,
    pub read_calls: u64,
    pub write_calls: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    /// Sum of paired syscall wall times; concurrent calls can overlap.
    pub total_duration_ns: u64,
}
#[derive(Debug, Serialize)]
pub struct FileAccess {
    pub identity: FileIdentity,
    pub anonymous_pseudo_file: bool,
    /// Open-hook path observations, never used for identity.
    pub observed_paths: Vec<ResolvedPath>,
    pub totals: AccessTotals,
}
#[derive(Debug, Serialize)]
pub struct AccessCall {
    pub cgroup_id: u64,
    pub run_epoch: u64,
    pub attempt_seq: u64,
    pub result_seq: Option<u64>,
    pub pid: u32,
    pub tgid: u32,
    pub task_start_boottime_ns: u64,
    pub comm: String,
    pub syscall: String,
    pub operation: EffectOperation,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub duration_ns: Option<u64>,
    /// Scalar I/O only; vector arg2 is iovcnt, not bytes.
    pub requested_bytes: Option<u64>,
    /// Nonnegative I/O return value; null for opens/failures/missing exits.
    pub actual_bytes: Option<u64>,
    pub return_value: Option<i64>,
    /// Index in FileAccessReport.files; null means unresolved identity.
    pub file_index: Option<usize>,
    pub flags: u32,
}
#[derive(Debug, Serialize)]
pub struct FileAccessReport {
    pub schema_version: u32,
    pub profile: PolicyProfile,
    pub source: &'static str,
    pub run_verification: &'static str,
    pub boot_binding: &'static str,
    pub recorded_pairing_status: &'static str,
    pub truncated_wal_tail: bool,
    pub unmatched_attempts: u64,
    pub unmatched_results: u64,
    pub event_sequence_gap_runs: u64,
    pub disclosed_correlation_failure_events: u64,
    pub disclosed_object_failure_events: u64,
    /// Kernel-resolved VFS identities, including directories/pseudo-files.
    pub unique_file_objects: usize,
    /// Excludes pipefs/socketfs/anon_inodefs; still includes named directories,
    /// devices and proc/sysfs files. Unresolved identities are not guessed.
    pub unique_files: usize,
    pub unique_files_definition: &'static str,
    pub unique_anonymous_pseudo_files: usize,
    pub unresolved_successful_calls: u64,
    pub unresolved_positive_byte_io_calls: u64,
    pub totals: AccessTotals,
    pub resolved_file_totals: AccessTotals,
    pub anonymous_file_totals: AccessTotals,
    pub files: Vec<FileAccess>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub calls: Option<Vec<AccessCall>>,
    pub limitations: Vec<&'static str>,
}
fn selected(operation: EffectOperation) -> bool {
    matches!(
        operation,
        EffectOperation::FileCreateOrTruncate
            | EffectOperation::FileOpenRequest
            | EffectOperation::FdRead
            | EffectOperation::FdWrite
    )
}
fn account(totals: &mut AccessTotals, call: &AccessCall) -> Result<()> {
    totals.calls += 1;
    if call.start_ns.is_some() {
        totals.attempted_calls += 1;
    } else {
        totals.orphan_result_calls += 1;
    }
    match call.operation {
        EffectOperation::FdRead => totals.read_calls += 1,
        EffectOperation::FdWrite => totals.write_calls += 1,
        _ => totals.open_calls += 1,
    }
    if let Some(value) = call.return_value {
        totals.completed_calls += 1;
        if value >= 0 {
            totals.successful_calls += 1;
        } else if matches!(value, -512 | -513 | -514 | -516) {
            totals.restart_results += 1;
        } else {
            totals.failed_calls += 1;
        }
    }
    let bytes = call.actual_bytes.unwrap_or(0);
    if call.operation == EffectOperation::FdRead {
        totals.bytes_read = totals
            .bytes_read
            .checked_add(bytes)
            .context("read byte total overflow")?;
    } else if call.operation == EffectOperation::FdWrite {
        totals.bytes_written = totals
            .bytes_written
            .checked_add(bytes)
            .context("write byte total overflow")?;
    }
    totals.total_duration_ns = totals
        .total_duration_ns
        .checked_add(call.duration_ns.unwrap_or(0))
        .context("duration total overflow")?;
    Ok(())
}
/// Checksums establish frame integrity only; use verify-effects or the
/// deployment verifier separately for manifest and transport closure.
pub fn report(
    recovery: &WalRecovery,
    profile: PolicyProfile,
    include_calls: bool,
) -> Result<FileAccessReport> {
    let policies = event_policy_identities(profile)?;
    let mut seen = BTreeSet::new();
    let mut attempts = BTreeMap::new();
    let mut results = BTreeMap::new();
    let mut orphan_results = Vec::new();
    let mut run_sequences = BTreeMap::<(u64, u64), (u64, u64, u64)>::new();
    let mut correlation_failure_events = 0;
    let mut object_failure_events = 0;
    for event in &recovery.events {
        event.validate()?;
        let policy = *policies
            .get(&event.syscall_nr)
            .context("WAL syscall absent from report profile")?;
        validate_policy_selection(event, policy)?;
        if !seen.insert((event.cgroup_id, event.run_epoch, event.event_seq)) {
            bail!("duplicate WAL event sequence");
        }
        let sequence = run_sequences
            .entry((event.cgroup_id, event.run_epoch))
            .or_insert((0, event.event_seq, event.event_seq));
        sequence.0 += 1;
        sequence.1 = sequence.1.min(event.event_seq);
        sequence.2 = sequence.2.max(event.event_seq);
        if event.flags
            & (FLAG_PENDING_INSERT_FAILED
                | FLAG_PENDING_MISSING
                | FLAG_PENDING_POISONED
                | FLAG_PENDING_DELETE_FAILED
                | FLAG_SYSCALL_MISMATCH
                | FLAG_TASK_READ_FAILED
                | FLAG_POLICY_INVALID)
            != 0
        {
            correlation_failure_events += 1;
        }
        if event.flags
            & (FLAG_OBJECT_JOIN_MISSING
                | FLAG_OBJECT_JOIN_AMBIGUOUS
                | FLAG_OBJECT_READ_FAILED
                | FLAG_OBJECT_DELETE_FAILED)
            != 0
        {
            object_failure_events += 1;
        }
        if !selected(policy.operation) {
            continue;
        }
        let key = (event.cgroup_id, event.run_epoch, event.event_seq);
        if event.kind == EVENT_OPERATION_ATTEMPT {
            attempts.insert(key, event);
        } else if event.related_attempt_seq == 0 {
            orphan_results.push(event);
        } else {
            let key = (event.cgroup_id, event.run_epoch, event.related_attempt_seq);
            if results.insert(key, event).is_some() {
                bail!("duplicate access result for attempt");
            }
        }
    }
    let mut report = FileAccessReport {
        schema_version: 1, profile, source: "CRC_VALIDATED_WAL_DIAGNOSTIC_NOT_RUN_VERIFICATION",
        run_verification: "NOT_PERFORMED; USE_VERIFY_EFFECTS_WITH_MANIFEST_AND_TRANSPORT_EVIDENCE",
        boot_binding: "NOT_PRESENT_IN_WAL; ONE_BOOT_PER_INPUT_MUST_BE_ESTABLISHED_EXTERNALLY",
        recorded_pairing_status: "PAIRED_RECORDED_EVENTS_ONLY_NOT_COVERAGE_PROOF",
        truncated_wal_tail: recovery.truncated_tail, unmatched_attempts: 0, unmatched_results: 0,
        event_sequence_gap_runs: run_sequences.values().filter(|(count, first, last)| *first != 1 || *last != *count).count() as u64,
        disclosed_correlation_failure_events: correlation_failure_events,
        disclosed_object_failure_events: object_failure_events,
        unique_file_objects: 0, unique_files: 0, unique_anonymous_pseudo_files: 0, unresolved_successful_calls: 0,
        unique_files_definition: "RESOLVED_NON_PIPEFS_NON_SOCKFS_NON_ANON_INODEFS_OBJECTS; INCLUDES_OPEN_ONLY_DIRECTORY_DEVICE_PROC_SYSFS; NOT_DISTINCT_REGULAR_FILES_READ",
        unresolved_positive_byte_io_calls: 0,
        totals: AccessTotals::default(), resolved_file_totals: AccessTotals::default(), anonymous_file_totals: AccessTotals::default(), files: Vec::new(), calls: include_calls.then(Vec::new),
        limitations: vec![
            "Counts cover recorded open/read/write families only; run verification is required for transport closure. Older profiles omit reads and ordinary opens.",
            "calls counts paired segments plus unmatched attempt/result segments; attempted_calls requires a recorded entry. Missing results do not imply zero bytes or latency.",
            "Bytes are syscall return values, including cached I/O, not physical disk bytes. Failed/missing results have null actual_bytes. Vector requested bytes are unknown.",
            "duration_ns is syscall entry-to-exit CLOCK_MONOTONIC wall time including blocking; summed durations may overlap across threads.",
            "unique_file_objects uses boot-local mount/device/inode/generation identity, includes directories and pseudo-files, distinguishes bind mounts, and cannot rule out inode reuse without a generation. Use one boot per WAL.",
            "Zero-byte/failed I/O have no permission-resolver identity. Inherited FDs can have identities without paths. Paths are mutable open-time observations.",
            "Per-file totals contain only resolved successful opens and resolved positive-byte I/O; EOF/failures remain in global calls and cannot be assigned to the last observed fd or path.",
            "mmap page access, access/stat/getdents, io_uring and range-transfer bytes are outside this report. Kernel restarts are separate syscall segments.",
        ],
    };
    let mut file_indices = BTreeMap::new();
    for (key, attempt) in attempts {
        let result = results.remove(&key);
        if result.is_none() {
            report.unmatched_attempts += 1;
        }
        append_call(
            &mut report,
            &mut file_indices,
            Some(attempt),
            result,
            &policies,
        )?;
    }
    orphan_results.extend(results.into_values());
    for result in orphan_results {
        report.unmatched_results += 1;
        append_call(
            &mut report,
            &mut file_indices,
            None,
            Some(result),
            &policies,
        )?;
    }
    report.unique_file_objects = report.files.len();
    report.unique_anonymous_pseudo_files = report
        .files
        .iter()
        .filter(|file| file.anonymous_pseudo_file)
        .count();
    report.unique_files = report.unique_file_objects - report.unique_anonymous_pseudo_files;
    if report.truncated_wal_tail
        || report.unmatched_attempts != 0
        || report.unmatched_results != 0
        || report.event_sequence_gap_runs != 0
        || report.disclosed_correlation_failure_events != 0
        || report.disclosed_object_failure_events != 0
    {
        report.recorded_pairing_status = "INCOMPLETE_RECORDED_EVIDENCE";
    }
    if let Some(calls) = &mut report.calls {
        calls.sort_by_key(|call| {
            (
                call.start_ns.or(call.end_ns),
                call.cgroup_id,
                call.run_epoch,
                call.attempt_seq,
            )
        });
    }
    Ok(report)
}
fn append_call(
    report: &mut FileAccessReport,
    file_indices: &mut BTreeMap<FileIdentity, usize>,
    attempt: Option<&KernelEvent>,
    result: Option<&KernelEvent>,
    policies: &HashMap<i32, EventPolicyIdentity>,
) -> Result<()> {
    let event = attempt.or(result).expect("at least one access event");
    let policy = policies[&event.syscall_nr];
    if let (Some(attempt), Some(result)) = (attempt, result) {
        if attempt.pid_tgid != result.pid_tgid
            || attempt.syscall_nr != result.syscall_nr
            || attempt.task_start_boottime_ns != result.task_start_boottime_ns
            || attempt.args != result.args
            || attempt.domain != result.domain
            || attempt.operation != result.operation
            || result.event_seq <= attempt.event_seq
            || result.ktime_ns < attempt.ktime_ns
        {
            bail!("access attempt/result identity or timestamp mismatch");
        }
    }
    let file_index = result
        .and_then(|result| result.file_object.as_ref())
        .map(|object| {
            let identity = FileIdentity::from(object);
            let index = *file_indices.entry(identity.clone()).or_insert_with(|| {
                let index = report.files.len();
                report.files.push(FileAccess {
                    anonymous_pseudo_file: identity.anonymous_pseudo_file(),
                    identity,
                    observed_paths: Vec::new(),
                    totals: AccessTotals::default(),
                });
                index
            });
            if object.path_quality == FILE_PATH_RESOLVED_AT_HOOK {
                let bytes = &object.path[..usize::from(object.path_len)];
                let path = ResolvedPath {
                    display: String::from_utf8_lossy(bytes).into_owned(),
                    raw_hex: bytes.iter().map(|byte| format!("{byte:02x}")).collect(),
                };
                if !report.files[index].observed_paths.contains(&path) {
                    report.files[index].observed_paths.push(path);
                }
            }
            index
        });
    let value = result.map(|result| result.return_value);
    let io = matches!(
        policy.operation,
        EffectOperation::FdRead | EffectOperation::FdWrite
    );
    let scalar_io = io
        && matches!(
            policy.syscall_name,
            "read" | "write" | "pread64" | "pwrite64"
        );
    if scalar_io && value.map_or(false, |value| value >= 0 && value as u64 > event.args[2]) {
        bail!("scalar I/O returned bytes exceed requested bytes");
    }
    let comm_len = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    let call = AccessCall {
        cgroup_id: event.cgroup_id,
        run_epoch: event.run_epoch,
        attempt_seq: attempt.map_or(event.related_attempt_seq, |attempt| attempt.event_seq),
        result_seq: result.map(|result| result.event_seq),
        pid: event.pid_tgid as u32,
        tgid: (event.pid_tgid >> 32) as u32,
        task_start_boottime_ns: event.task_start_boottime_ns,
        comm: String::from_utf8_lossy(&event.comm[..comm_len]).into_owned(),
        syscall: policy.syscall_name.to_owned(),
        operation: policy.operation,
        start_ns: attempt.map(|attempt| attempt.ktime_ns),
        end_ns: result.map(|result| result.ktime_ns),
        duration_ns: attempt
            .zip(result)
            .map(|(attempt, result)| result.ktime_ns - attempt.ktime_ns),
        requested_bytes: scalar_io.then_some(event.args[2]),
        actual_bytes: value
            .filter(|value| io && *value >= 0)
            .map(|value| value as u64),
        return_value: value,
        file_index,
        flags: attempt.map_or(0, |event| event.flags) | result.map_or(0, |event| event.flags),
    };
    if value.map_or(false, |value| value >= 0) && file_index.is_none() {
        report.unresolved_successful_calls += 1;
    }
    if io && value.map_or(false, |value| value > 0) && file_index.is_none() {
        report.unresolved_positive_byte_io_calls += 1;
    }
    account(&mut report.totals, &call)?;
    if let Some(index) = file_index {
        account(&mut report.files[index].totals, &call)?;
        if report.files[index].anonymous_pseudo_file {
            account(&mut report.anonymous_file_totals, &call)?;
        } else {
            account(&mut report.resolved_file_totals, &call)?;
        }
    }
    if let Some(calls) = &mut report.calls {
        calls.push(call);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        EFFECT_EVENT_SCHEMA_VERSION, EVENT_OPERATION_RESULT, FILE_PATH_NOT_REQUESTED,
    };

    fn pair(
        nr: libc::c_long,
        seq: u64,
        ret: i64,
        object: Option<KernelFileObject>,
    ) -> Vec<KernelEvent> {
        let policy = event_policy_identities(PolicyProfile::FileAccess).unwrap()[&(nr as i32)];
        let attempt = KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_OPERATION_ATTEMPT,
            domain: policy.domain as u16,
            operation: policy.operation as u32,
            flags: 0,
            syscall_nr: nr as i32,
            run_epoch: 1,
            event_seq: seq,
            related_attempt_seq: 0,
            ktime_ns: 100 * seq,
            cgroup_id: 3,
            pid_tgid: (4 << 32) | 5,
            return_value: 0,
            args: [7, 0, 100, 0, 0, 0],
            comm: [0; 16],
            task_start_boottime_ns: 9,
            payload_lens: [0; 2],
            payload_kinds: [0; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; crate::protocol::CAPTURE_BYTES]; 2],
            file_object: None,
            socket_object: None,
        };
        let mut result = attempt.clone();
        result.kind = EVENT_OPERATION_RESULT;
        result.event_seq += 1;
        result.related_attempt_seq = seq;
        result.ktime_ns += 25;
        result.return_value = ret;
        result.file_object = object;
        vec![attempt, result]
    }
    fn object(inode: u64) -> KernelFileObject {
        KernelFileObject {
            mount_id_unique: 11,
            inode,
            filesystem_magic: 0xef53,
            device_major: 8,
            device_minor: 0,
            inode_generation: 2,
            path_len: 0,
            generation_valid: 1,
            path_quality: FILE_PATH_NOT_REQUESTED,
            path: [0; crate::KERNEL_FILE_PATH_BYTES],
        }
    }
    fn recovery(events: Vec<KernelEvent>) -> WalRecovery {
        WalRecovery {
            events,
            truncated_tail: false,
        }
    }
    #[test]
    fn bytes_latency_and_file_identity_use_results_not_fd_or_request_size() {
        let mut events = pair(libc::SYS_read, 1, 4, Some(object(100)));
        events.extend(pair(libc::SYS_pwrite64, 3, 7, Some(object(100))));
        // Same fd, different inode: reuse is not deduplicated as one file.
        events.extend(pair(libc::SYS_readv, 5, 9, Some(object(200))));
        events.extend(pair(libc::SYS_read, 7, 0, None));
        events.extend(pair(libc::SYS_write, 9, -libc::EBADF as i64, None));
        let report = report(&recovery(events), PolicyProfile::FileAccess, true).unwrap();
        assert_eq!(report.unique_file_objects, 2);
        assert_eq!(report.totals.bytes_read, 13);
        assert_eq!(report.totals.bytes_written, 7);
        assert_eq!(report.totals.total_duration_ns, 125);
        assert_eq!(report.totals.successful_calls, 4);
        assert_eq!(report.totals.failed_calls, 1);
        assert_eq!(report.files[0].totals.calls, 2);
        let calls = report.calls.unwrap();
        assert_eq!(calls[0].requested_bytes, Some(100));
        assert_eq!(calls[0].actual_bytes, Some(4));
        assert_eq!(calls[2].requested_bytes, None);
        assert_eq!(calls[2].actual_bytes, Some(9));
        assert_eq!(calls[3].actual_bytes, Some(0));
        assert_eq!(calls[4].actual_bytes, None);
    }
    #[test]
    fn anonymous_pipes_are_separate_from_named_file_counts_and_bytes() {
        let mut pipe = object(200);
        pipe.filesystem_magic = 0x5049_5045;
        let mut events = pair(libc::SYS_write, 1, 7, Some(object(100)));
        events.extend(pair(libc::SYS_write, 3, 23, Some(pipe)));
        let report = report(&recovery(events), PolicyProfile::FileAccess, false).unwrap();
        assert_eq!(report.unique_file_objects, 2);
        assert_eq!(report.unique_files, 1);
        assert_eq!(report.unique_anonymous_pseudo_files, 1);
        assert_eq!(report.totals.bytes_written, 30);
        assert_eq!(report.resolved_file_totals.bytes_written, 7);
        assert_eq!(report.anonymous_file_totals.bytes_written, 23);
    }

    #[test]
    fn missing_pairs_and_truncated_tail_preserve_unknown_measurements() {
        let mut events = vec![pair(libc::SYS_read, 1, 1, None).remove(0)];
        events.push(pair(libc::SYS_write, 3, 2, None).remove(1));
        let mut input = recovery(events);
        input.truncated_tail = true;
        let report = report(&input, PolicyProfile::FileAccess, true).unwrap();
        assert!(report.truncated_wal_tail);
        assert_eq!(report.unmatched_attempts, 1);
        assert_eq!(report.unmatched_results, 1);
        let calls = report.calls.unwrap();
        assert_eq!(calls[0].duration_ns, None);
        assert_eq!(calls[0].actual_bytes, None);
        assert_eq!(calls[1].duration_ns, None);
        assert_eq!(calls[1].actual_bytes, Some(2));
    }
    #[test]
    fn duplicate_mismatched_and_reversed_pairs_are_rejected() {
        for field in 0..4 {
            let mut events = pair(libc::SYS_read, 1, 1, None);
            match field {
                0 => events.push(events[1].clone()),
                1 => events[1].pid_tgid += 1,
                2 => events[1].args[0] += 1,
                _ => events[1].ktime_ns = 1,
            }
            assert!(report(&recovery(events), PolicyProfile::FileAccess, true).is_err());
        }
    }
    #[test]
    fn read_objects_round_trip_wal_and_public_projection() {
        let events = pair(libc::SYS_preadv2, 1, 8, Some(object(100)));
        let mut bytes = Vec::new();
        for event in events {
            let frame = event.encode_le();
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&frame);
            bytes.extend_from_slice(&crc32fast::hash(&frame).to_le_bytes());
        }
        let input = crate::recover_wal_reader(bytes.as_slice()).unwrap();
        let projected = crate::canonical_system_effect_projection(
            &input.events[1],
            "access-test",
            "01234567-89ab-cdef-0123-456789abcdef",
            PolicyProfile::FileAccess,
        )
        .unwrap();
        projected.validate_object_resolution().unwrap();
        let report = report(&input, PolicyProfile::FileAccess, false).unwrap();
        assert!(report.calls.is_none());
        assert_eq!(report.totals.bytes_read, 8);
        assert_eq!(report.unique_file_objects, 1);
    }
    #[test]
    fn separate_cgroups_do_not_collide_on_attempt_sequences() {
        let mut events = pair(libc::SYS_read, 1, 4, Some(object(100)));
        let mut second = pair(libc::SYS_read, 1, 8, Some(object(100)));
        for event in &mut second {
            event.cgroup_id += 1;
        }
        events.extend(second);
        let report = report(&recovery(events), PolicyProfile::FileAccess, false).unwrap();
        assert_eq!(report.unique_file_objects, 1);
        assert_eq!(report.totals.bytes_read, 12);
        assert_eq!(report.unmatched_results, 0);
    }

    #[test]
    fn scalar_byte_bounds_are_checked_but_iovcnt_is_not_a_byte_limit() {
        for syscall in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_pread64,
            libc::SYS_pwrite64,
        ] {
            assert!(report(
                &recovery(pair(syscall, 1, 101, None)),
                PolicyProfile::FileAccess,
                true
            )
            .is_err());
        }
        let result = report(
            &recovery(pair(libc::SYS_readv, 1, 101, None)),
            PolicyProfile::FileAccess,
            true,
        )
        .unwrap();
        assert_eq!(result.totals.bytes_read, 101);
        assert_eq!(result.calls.unwrap()[0].requested_bytes, None);
    }

    #[test]
    fn scalar_read_byte_bound_is_also_enforced_by_raw_wal_decode() {
        let mut bytes = Vec::new();
        for event in pair(libc::SYS_pread64, 1, 101, None) {
            let frame = event.encode_le();
            bytes.extend_from_slice(&(frame.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&frame);
            bytes.extend_from_slice(&crc32fast::hash(&frame).to_le_bytes());
        }
        assert!(crate::recover_wal_reader(bytes.as_slice()).is_err());
    }

    #[test]
    fn attempted_and_orphan_results_are_not_confused_with_completed_calls() {
        let mut events = vec![pair(libc::SYS_read, 1, 1, None).remove(0)];
        events.push(pair(libc::SYS_write, 3, 2, None).remove(1));
        let result = report(&recovery(events), PolicyProfile::FileAccess, false).unwrap();
        assert_eq!(result.totals.calls, 2);
        assert_eq!(result.totals.attempted_calls, 1);
        assert_eq!(result.totals.completed_calls, 1);
        assert_eq!(result.totals.orphan_result_calls, 1);
        assert_eq!(result.totals.bytes_read, 0);
        assert_eq!(result.totals.bytes_written, 2);
        assert_eq!(result.event_sequence_gap_runs, 1);
        assert_eq!(
            result.recorded_pairing_status,
            "INCOMPLETE_RECORDED_EVIDENCE"
        );
    }

    #[test]
    fn missing_non_access_events_still_disclose_sequence_gaps() {
        let mut events = pair(libc::SYS_read, 1, 4, None);
        events.extend(pair(libc::SYS_read, 5, 4, None));
        let result = report(&recovery(events), PolicyProfile::FileAccess, false).unwrap();
        assert_eq!(result.unmatched_attempts, 0);
        assert_eq!(result.unmatched_results, 0);
        assert_eq!(result.event_sequence_gap_runs, 1);
        assert_eq!(
            result.recorded_pairing_status,
            "INCOMPLETE_RECORDED_EVIDENCE"
        );
    }

    #[test]
    fn restart_and_eof_segments_are_not_errors_or_positive_byte_file_accesses() {
        let mut events = pair(libc::SYS_read, 1, -512, None);
        events.extend(pair(libc::SYS_read, 3, 0, None));
        let result = report(&recovery(events), PolicyProfile::FileAccess, true).unwrap();
        assert_eq!(result.totals.restart_results, 1);
        assert_eq!(result.totals.failed_calls, 0);
        assert_eq!(result.totals.successful_calls, 1);
        assert_eq!(result.unresolved_successful_calls, 1);
        assert_eq!(result.unresolved_positive_byte_io_calls, 0);
        assert_eq!(result.unique_file_objects, 0);
        let calls = result.calls.unwrap();
        assert_eq!(calls[0].actual_bytes, None);
        assert_eq!(calls[1].actual_bytes, Some(0));
    }

    #[test]
    fn disclosed_failures_keep_bytes_but_never_invent_file_identity_or_completeness() {
        let mut events = pair(libc::SYS_read, 1, 4, None);
        events[1].flags = FLAG_OBJECT_JOIN_MISSING | FLAG_OBJECT_READ_FAILED;
        let result = report(&recovery(events), PolicyProfile::FileAccess, true).unwrap();
        assert_eq!(result.totals.bytes_read, 4);
        assert_eq!(result.disclosed_object_failure_events, 1);
        assert_eq!(result.unique_file_objects, 0);
        assert_eq!(result.unresolved_positive_byte_io_calls, 1);
        assert_eq!(
            result.recorded_pairing_status,
            "INCOMPLETE_RECORDED_EVIDENCE"
        );
        assert!(result.run_verification.starts_with("NOT_PERFORMED"));
    }

    #[test]
    fn legacy_profiles_are_explicit_and_read_events_cannot_be_mislabelled() {
        let input = recovery(pair(libc::SYS_read, 1, 4, None));
        for profile in [
            PolicyProfile::Control,
            PolicyProfile::Balanced,
            PolicyProfile::Full,
        ] {
            assert!(report(&input, profile, false).is_err());
        }
        let input = recovery(pair(libc::SYS_write, 1, 4, None));
        let result = report(&input, PolicyProfile::Full, false).unwrap();
        assert_eq!(result.totals.bytes_written, 4);
        assert_eq!(result.profile, PolicyProfile::Full);
    }
}
