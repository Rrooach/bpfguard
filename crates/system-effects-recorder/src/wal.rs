// SPDX-License-Identifier: GPL-2.0-only

use crate::protocol::{
    KernelEvent, KERNEL_EVENT_HEADER_SIZE, KERNEL_EVENT_SIZE, KERNEL_FILE_EVENT_SIZE,
};
use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const MAX_WAL_BYTES: u64 = 384 * 1024 * 1024;
const MAX_WAL_EVENTS: usize = 1_000_000;

pub struct WalWriter {
    writer: BufWriter<File>,
}

impl WalWriter {
    pub fn create(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("create system-effect WAL {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn append(&mut self, event: &KernelEvent) -> Result<()> {
        let payload = event.encode_le();
        let frame_length = payload.len() as u32;
        let checksum = crc32fast::hash(&payload);
        self.writer.write_all(&frame_length.to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.writer.write_all(&checksum.to_le_bytes())?;
        Ok(())
    }

    pub fn sync(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WalRecovery {
    pub events: Vec<KernelEvent>,
    pub truncated_tail: bool,
}

pub fn recover(path: &Path) -> Result<WalRecovery> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open system-effect WAL {}", path.display()))?;
    let before = file.metadata()?;
    if !before.file_type().is_file() || before.nlink() != 1 {
        bail!("system-effect WAL must be a singly linked regular file");
    }
    if before.len() > MAX_WAL_BYTES {
        bail!("system-effect WAL exceeds the {MAX_WAL_BYTES}-byte recovery limit");
    }
    let recovery = recover_reader(&mut file)?;
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("system-effect WAL changed while it was recovered");
    }
    Ok(recovery)
}

pub fn recover_reader(reader: impl Read) -> Result<WalRecovery> {
    let mut reader = BufReader::new(reader);
    let mut events = Vec::new();
    let mut consumed = 0u64;
    loop {
        let mut length_bytes = [0u8; 4];
        match read_part(&mut reader, &mut length_bytes)? {
            ReadPart::Eof => {
                return Ok(WalRecovery {
                    events,
                    truncated_tail: false,
                })
            }
            ReadPart::Truncated => {
                return Ok(WalRecovery {
                    events,
                    truncated_tail: true,
                })
            }
            ReadPart::Complete => {}
        }
        let length = u32::from_le_bytes(length_bytes);
        if !matches!(
            length as usize,
            KERNEL_EVENT_HEADER_SIZE | KERNEL_FILE_EVENT_SIZE | KERNEL_EVENT_SIZE
        ) {
            bail!("unsupported system-effect WAL frame length {length}");
        }
        consumed = consumed
            .checked_add(8 + u64::from(length))
            .context("system-effect WAL byte count overflow")?;
        if consumed > MAX_WAL_BYTES {
            bail!("system-effect WAL exceeds the {MAX_WAL_BYTES}-byte recovery limit");
        }
        if events.len() >= MAX_WAL_EVENTS {
            bail!("system-effect WAL exceeds the {MAX_WAL_EVENTS}-event recovery limit");
        }
        let mut payload = vec![0u8; length as usize];
        if read_part(&mut reader, &mut payload)? != ReadPart::Complete {
            return Ok(WalRecovery {
                events,
                truncated_tail: true,
            });
        }
        let mut checksum = [0u8; 4];
        if read_part(&mut reader, &mut checksum)? != ReadPart::Complete {
            return Ok(WalRecovery {
                events,
                truncated_tail: true,
            });
        }
        if crc32fast::hash(&payload) != u32::from_le_bytes(checksum) {
            bail!("system-effect WAL checksum mismatch");
        }
        events.push(KernelEvent::decode_le(&payload)?);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadPart {
    Eof,
    Truncated,
    Complete,
}

fn read_part(reader: &mut impl Read, output: &mut [u8]) -> Result<ReadPart> {
    let mut offset = 0;
    while offset < output.len() {
        match reader.read(&mut output[offset..]) {
            Ok(0) if offset == 0 => return Ok(ReadPart::Eof),
            Ok(0) => return Ok(ReadPart::Truncated),
            Ok(count) => offset += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(ReadPart::Complete)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EffectDomain, EffectOperation};
    use crate::protocol::{EFFECT_EVENT_SCHEMA_VERSION, EVENT_OPERATION_ATTEMPT, PAYLOAD_NONE};

    fn event(sequence: u64) -> KernelEvent {
        KernelEvent {
            schema_version: EFFECT_EVENT_SCHEMA_VERSION,
            kind: EVENT_OPERATION_ATTEMPT,
            domain: EffectDomain::KernelControl as u16,
            operation: EffectOperation::BpfCommand as u32,
            flags: 0,
            syscall_nr: libc::SYS_bpf as i32,
            run_epoch: 1,
            event_seq: sequence,
            related_attempt_seq: 0,
            ktime_ns: sequence,
            cgroup_id: 2,
            pid_tgid: 3,
            return_value: 0,
            args: [0; 6],
            comm: [0; 16],
            payload_lens: [0; 2],
            payload_kinds: [PAYLOAD_NONE; 2],
            payload_arg_indices: [0; 2],
            payloads: [[0; crate::protocol::CAPTURE_BYTES]; 2],
            file_object: None,
        }
    }

    #[test]
    fn framed_wal_round_trip_and_truncation() {
        let mut bytes = Vec::new();
        {
            let first = event(1).encode_le();
            bytes.extend_from_slice(&(first.len() as u32).to_le_bytes());
            bytes.extend_from_slice(&first);
            bytes.extend_from_slice(&crc32fast::hash(&first).to_le_bytes());
            bytes.extend_from_slice(&(KERNEL_EVENT_HEADER_SIZE as u32).to_le_bytes());
            bytes.extend_from_slice(&[0; 7]);
        }
        let recovery = recover_reader(bytes.as_slice()).unwrap();
        assert_eq!(recovery.events, vec![event(1)]);
        assert!(recovery.truncated_tail);
    }
}
