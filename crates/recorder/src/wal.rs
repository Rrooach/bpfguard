// SPDX-License-Identifier: GPL-2.0-only

use crate::protocol::{KernelEvent, KERNEL_EVENT_SIZE};
use anyhow::{bail, Context, Result};
use crc32fast::Hasher;
use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const FRAME_LENGTH: u32 = KERNEL_EVENT_SIZE as u32;

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
            .with_context(|| format!("create recorder WAL {}", path.display()))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn append(&mut self, event: &KernelEvent) -> Result<()> {
        let payload = event.encode_le();
        let checksum = crc32fast::hash(&payload);
        self.writer.write_all(&FRAME_LENGTH.to_le_bytes())?;
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalRecovery {
    pub events: Vec<KernelEvent>,
    pub truncated_tail: bool,
}

pub fn recover(path: &Path) -> Result<WalRecovery> {
    let file = File::open(path).with_context(|| format!("open recorder WAL {}", path.display()))?;
    recover_reader(BufReader::new(file))
}

pub fn recover_reader(reader: impl Read) -> Result<WalRecovery> {
    let mut reader = BufReader::new(reader);
    let mut events = Vec::new();
    loop {
        let mut length_bytes = [0u8; 4];
        match read_frame_part(&mut reader, &mut length_bytes)? {
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
        if length != FRAME_LENGTH {
            bail!("unsupported recorder WAL frame length {length}");
        }
        let mut payload = [0u8; KERNEL_EVENT_SIZE];
        if read_frame_part(&mut reader, &mut payload)? != ReadPart::Complete {
            return Ok(WalRecovery {
                events,
                truncated_tail: true,
            });
        }
        let mut checksum_bytes = [0u8; 4];
        if read_frame_part(&mut reader, &mut checksum_bytes)? != ReadPart::Complete {
            return Ok(WalRecovery {
                events,
                truncated_tail: true,
            });
        }
        let expected = u32::from_le_bytes(checksum_bytes);
        let mut hasher = Hasher::new();
        hasher.update(&payload);
        let actual = hasher.finalize();
        if actual != expected {
            bail!("recorder WAL checksum mismatch");
        }
        events.push(KernelEvent::decode_le(&payload)?);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadPart {
    Eof,
    Truncated,
    Complete,
}

fn read_frame_part(reader: &mut impl Read, output: &mut [u8]) -> Result<ReadPart> {
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
    use bpf_observer_schema::SCHEMA_VERSION;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn path(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "bpf-observer-recorder-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn event(sequence: u64) -> KernelEvent {
        KernelEvent {
            schema_version: SCHEMA_VERSION,
            kind: crate::protocol::EVENT_SYSCALL_ATTEMPTED,
            flags: 0,
            command: 0,
            attr_size: 144,
            run_epoch: 1,
            event_seq: sequence,
            related_attempt_seq: 0,
            ktime_ns: sequence,
            cgroup_id: 2,
            pid_tgid: 3,
            return_value: 0,
        }
    }

    #[test]
    fn framed_wal_round_trip() {
        let path = path("round-trip");
        let mut writer = WalWriter::create(&path).unwrap();
        writer.append(&event(1)).unwrap();
        writer.append(&event(2)).unwrap();
        writer.sync().unwrap();
        drop(writer);

        let recovered = recover(&path).unwrap();
        assert_eq!(recovered.events, vec![event(1), event(2)]);
        assert!(!recovered.truncated_tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn incomplete_last_frame_is_not_accepted() {
        let path = path("truncated");
        let mut writer = WalWriter::create(&path).unwrap();
        writer.append(&event(1)).unwrap();
        writer.sync().unwrap();
        drop(writer);
        let file = OpenOptions::new().append(true).open(&path).unwrap();
        let mut file = BufWriter::new(file);
        file.write_all(&FRAME_LENGTH.to_le_bytes()).unwrap();
        file.write_all(&[0u8; 5]).unwrap();
        file.flush().unwrap();

        let recovered = recover(&path).unwrap();
        assert_eq!(recovered.events, vec![event(1)]);
        assert!(recovered.truncated_tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn checksum_corruption_is_an_error() {
        let path = path("checksum");
        let mut writer = WalWriter::create(&path).unwrap();
        writer.append(&event(1)).unwrap();
        writer.sync().unwrap();
        drop(writer);
        let mut bytes = fs::read(&path).unwrap();
        bytes[8] ^= 0xff;
        fs::write(&path, bytes).unwrap();
        assert!(recover(&path).is_err());
        fs::remove_file(path).unwrap();
    }
}
