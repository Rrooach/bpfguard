// SPDX-License-Identifier: GPL-2.0-only

use anyhow::{bail, Context, Result};
use bpf_observer_deployment_observer::{run_stdio, DeploymentObserverConfig};
use std::path::Path;

fn main() {
    if let Err(error) = run() {
        eprintln!("deployment-observe: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let first = arguments
        .next()
        .context("usage: deployment-observe --config PATH")?;
    if first == "--help" || first == "-h" {
        println!("usage: deployment-observe --config PATH");
        return Ok(());
    }
    if first != "--config" {
        bail!("usage: deployment-observe --config PATH");
    }
    let path = arguments.next().context("--config requires PATH")?;
    if arguments.next().is_some() {
        bail!("unexpected trailing deployment-observe arguments");
    }
    let config = DeploymentObserverConfig::from_path(Path::new(&path))?;
    run_stdio(config)
}
