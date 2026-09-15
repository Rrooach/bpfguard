// SPDX-License-Identifier: GPL-2.0-only

//! Strict Linux deployment discovery for direct, Docker, and Kata-host scopes.
//!
//! This crate discovers *where* an already stopped/cooperative workload runs.
//! It does not launch a container, enter a Kata guest, or claim delegated
//! causality.  Discovery is an endpoint operation: no polling and no external
//! runtime CLI are used on the hot path.

mod discover;
mod revalidate;
mod schema;

pub use discover::discover;
pub use revalidate::{
    validate_against_live_procfs, validate_against_live_procfs_for_phase, LiveIdentityValidation,
    RevalidationPhase, ValidationMismatch,
};
pub use schema::*;

#[cfg(test)]
mod tests;
