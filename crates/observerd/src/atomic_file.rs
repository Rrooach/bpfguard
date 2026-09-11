// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_schema::{artifact_size_limit, MAX_GENERIC_JSON_BYTES};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create output directory {}", parent.display()))?;

    let temporary = temporary_path(path);
    let result = (|| -> Result<()> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .with_context(|| format!("create temporary file {}", temporary.display()))?;
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .context("JSON output filename is not valid UTF-8")?;
        let limit = artifact_size_limit(name).unwrap_or(MAX_GENERIC_JSON_BYTES);
        let mut writer = LimitedWriter::new(BufWriter::new(file), limit);
        serde_json::to_writer_pretty(&mut writer, value)
            .with_context(|| format!("serialize {}", path.display()))?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.inner.get_ref().sync_all()?;
        if writer.written > limit {
            bail!("JSON output {} exceeded {limit} bytes", path.display());
        }
        Ok(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }

    fs::rename(&temporary, path)
        .with_context(|| format!("atomically replace {}", path.display()))?;
    sync_directory(parent)?;
    Ok(())
}

struct LimitedWriter<W> {
    inner: W,
    written: u64,
    limit: u64,
}

impl<W> LimitedWriter<W> {
    fn new(inner: W, limit: u64) -> Self {
        Self {
            inner,
            written: 0,
            limit,
        }
    }
}

impl<W: Write> Write for LimitedWriter<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let requested = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.written.checked_add(requested).unwrap_or(u64::MAX) > self.limit {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "JSON artifact size limit exceeded",
            ));
        }
        let count = self.inner.write(bytes)?;
        self.written = self.written.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("observer-output");
    path.with_file_name(format!(".{name}.tmp-{}", std::process::id()))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("open directory {} for fsync", path.display()))?
        .sync_all()
        .with_context(|| format!("fsync directory {}", path.display()))
}
