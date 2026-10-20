// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment_observer::{
    verify_recovery_artifacts, RecoveryVerificationExpectation,
};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_EXPECTATION_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("deployment-observe-recovery-verify: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut directory: Option<PathBuf> = None;
    let mut expectation: Option<PathBuf> = None;
    while let Some(argument) = arguments.next() {
        if argument == "--help" || argument == "-h" {
            println!(
                "usage: deployment-observe-recovery-verify --artifacts DIR --expectation EXPECTATION.json"
            );
            return Ok(());
        }
        let slot = match argument.to_str() {
            Some("--artifacts") => &mut directory,
            Some("--expectation") => &mut expectation,
            _ => bail!("unknown deployment-observe-recovery-verify argument"),
        };
        if slot.is_some() {
            bail!("duplicate deployment-observe-recovery-verify argument");
        }
        *slot = Some(PathBuf::from(
            arguments.next().context("argument requires a value")?,
        ));
    }
    let directory = directory.context("--artifacts is required")?;
    let expectation_path = expectation.context("--expectation is required")?;
    let expectation: RecoveryVerificationExpectation = read_expectation(&expectation_path)?;
    let result = verify_recovery_artifacts(&directory, &expectation)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &result)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn read_expectation(path: &Path) -> Result<RecoveryVerificationExpectation> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > MAX_EXPECTATION_BYTES
    {
        bail!("recovery expectation must be a bounded singly-linked regular file");
    }
    let mut bytes = Vec::new();
    let mut bounded = file.take(MAX_EXPECTATION_BYTES + 1);
    bounded.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EXPECTATION_BYTES {
        bail!("recovery expectation is too large");
    }
    let after = bounded.get_ref().metadata()?;
    if metadata.dev() != after.dev()
        || metadata.ino() != after.ino()
        || metadata.len() != after.len()
        || metadata.mtime() != after.mtime()
        || metadata.mtime_nsec() != after.mtime_nsec()
        || metadata.ctime() != after.ctime()
        || metadata.ctime_nsec() != after.ctime_nsec()
    {
        bail!("recovery expectation changed while it was read");
    }
    serde_json::from_slice(&bytes).context("parse recovery verification expectation")
}
