// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment_observer::{verify_artifacts, VerificationExpectation};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_EXPECTATION_BYTES: u64 = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("deployment-observe-verify: {error:#}");
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
                "usage: deployment-observe-verify --artifacts DIR --expectation EXPECTATION.json"
            );
            return Ok(());
        }
        let slot = match argument.to_str() {
            Some("--artifacts") => &mut directory,
            Some("--expectation") => &mut expectation,
            _ => bail!("unknown deployment-observe-verify argument"),
        };
        if slot.is_some() {
            bail!("duplicate deployment-observe-verify argument");
        }
        *slot = Some(PathBuf::from(
            arguments.next().context("argument requires a value")?,
        ));
    }
    let directory = directory.context("--artifacts is required")?;
    let expectation_path = expectation.context("--expectation is required")?;
    let expectation: VerificationExpectation = read_expectation(&expectation_path)?;
    let result = verify_artifacts(&directory, &expectation)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &result)?;
    lock.write_all(b"\n")?;
    Ok(())
}

fn read_expectation(path: &Path) -> Result<VerificationExpectation> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.nlink() != 1
        || metadata.len() > MAX_EXPECTATION_BYTES
    {
        bail!("verification expectation must be a bounded singly-linked regular file");
    }
    let mut bytes = Vec::new();
    let mut bounded = file.take(MAX_EXPECTATION_BYTES + 1);
    bounded.read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_EXPECTATION_BYTES {
        bail!("verification expectation is too large");
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
        bail!("verification expectation changed while it was read");
    }
    let expectation = serde_json::from_slice(&bytes)?;
    Ok(expectation)
}
