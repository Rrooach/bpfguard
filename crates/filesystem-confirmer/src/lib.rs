// SPDX-License-Identifier: GPL-2.0-only

//! Bounded, framework-independent Linux filesystem endpoint confirmation.
//!
//! This crate deliberately separates three facts:
//!
//! * a canonical S0/S1 tree snapshot can be structurally complete;
//! * the snapshots can contain a typed endpoint difference;
//! * attributing that difference, or authorizing an unchanged verdict, needs
//!   an external exclusive-writer and quiescence contract.
//!
//! [`capture`] never walks an implicit root. Every root and every resource
//! budget comes from a validated [`FilesystemScope`]. [`compare`] returns
//! [`FilesystemVerdict::Inconclusive`] when either snapshot is incomplete,
//! the endpoint environments differ, or the external actor contract is
//! absent/incomplete.

mod capture;
mod compare;
mod schema;

pub use capture::{capture, capture_in_retained_mount_namespace};
pub use compare::{compare, FILESYSTEM_CONFIRMATION_DOMAIN};
pub use schema::*;

#[cfg(test)]
mod tests;
