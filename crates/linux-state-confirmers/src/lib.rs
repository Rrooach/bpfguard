// SPDX-License-Identifier: GPL-2.0-only

//! Bounded endpoint-state confirmation for selected Linux kernel-facing domains.
//!
//! Every domain is opt-in and explicitly scoped.  Complete means only that the
//! selected sources were read within their declared bounds.  Identical S0/S1
//! snapshots never prove that all Linux state was unchanged and never establish
//! causal attribution.  Positive, complete differences are reported as
//! `CHANGED_WITHIN_SCOPE`; negative results remain `INCONCLUSIVE` until an
//! authenticated external exclusive-writer/quiescence contract exists.

mod capture;
mod command;
mod compare;
mod namespace;
mod schema;

pub use capture::{capture, capture_with_retained_namespaces};
pub use command::trusted_collector_sha256;
pub use compare::compare;
pub use namespace::{RetainedNamespace, RetainedNamespaces, SysctlNamespaceTargets};
pub use schema::*;

#[cfg(test)]
mod tests;
