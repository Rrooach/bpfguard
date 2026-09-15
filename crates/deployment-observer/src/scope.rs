// SPDX-License-Identifier: GPL-2.0-only

//! Closed capability contract for dynamic cgroup-v2 subtree membership.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CGROUP_SCOPE_PROTOCOL_VERSION: u32 = 1;
pub const MAX_ANCESTOR_ROOTS: usize = 8;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CgroupScopeMode {
    CgroupV2AncestorRoot,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventCgroupIdSemantics {
    MatchedScopeRoot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupScopeCapability {
    pub protocol_version: u32,
    pub mode: CgroupScopeMode,
    pub membership_authority: String,
    pub root_map_type: String,
    pub supported_program_families: Vec<String>,
    pub maximum_roots: u32,
    pub root_cgroup_ids: Vec<u64>,
    pub event_cgroup_id_semantics: EventCgroupIdSemantics,
    pub leaf_cgroup_id_retained: bool,
    pub dynamic_descendants_including_ephemeral: bool,
    pub readiness_basis: String,
}

impl CgroupScopeCapability {
    pub fn for_roots(root_cgroup_ids: &[u64]) -> Result<Self> {
        let capability = Self {
            protocol_version: CGROUP_SCOPE_PROTOCOL_VERSION,
            mode: CgroupScopeMode::CgroupV2AncestorRoot,
            membership_authority: "BPF_CURRENT_TASK_UNDER_CGROUP".to_owned(),
            root_map_type: "BPF_MAP_TYPE_CGROUP_ARRAY".to_owned(),
            supported_program_families: vec![
                "BPF_PROG_TYPE_LSM".to_owned(),
                "BPF_PROG_TYPE_TRACEPOINT".to_owned(),
                "BPF_PROG_TYPE_TRACING_TP_BTF".to_owned(),
            ],
            maximum_roots: MAX_ANCESTOR_ROOTS as u32,
            root_cgroup_ids: root_cgroup_ids.to_vec(),
            event_cgroup_id_semantics: EventCgroupIdSemantics::MatchedScopeRoot,
            leaf_cgroup_id_retained: false,
            dynamic_descendants_including_ephemeral: true,
            readiness_basis:
                "BOTH_BPF_OBJECTS_LOADED_VERIFIER_ACCEPTED_MAP_ABI_VALIDATED_ROOT_FDS_PINNED"
                    .to_owned(),
        };
        capability.validate()?;
        Ok(capability)
    }

    pub fn validate(&self) -> Result<()> {
        let mut roots = self.root_cgroup_ids.clone();
        roots.sort_unstable();
        roots.dedup();
        if self.protocol_version != CGROUP_SCOPE_PROTOCOL_VERSION
            || self.mode != CgroupScopeMode::CgroupV2AncestorRoot
            || self.membership_authority != "BPF_CURRENT_TASK_UNDER_CGROUP"
            || self.root_map_type != "BPF_MAP_TYPE_CGROUP_ARRAY"
            || self.supported_program_families
                != [
                    "BPF_PROG_TYPE_LSM",
                    "BPF_PROG_TYPE_TRACEPOINT",
                    "BPF_PROG_TYPE_TRACING_TP_BTF",
                ]
            || self.maximum_roots != MAX_ANCESTOR_ROOTS as u32
            || self.root_cgroup_ids != roots
            || roots.is_empty()
            || roots.len() > MAX_ANCESTOR_ROOTS
            || roots.iter().any(|id| *id == 0)
            || self.event_cgroup_id_semantics != EventCgroupIdSemantics::MatchedScopeRoot
            || self.leaf_cgroup_id_retained
            || !self.dynamic_descendants_including_ephemeral
            || self.readiness_basis
                != "BOTH_BPF_OBJECTS_LOADED_VERIFIER_ACCEPTED_MAP_ABI_VALIDATED_ROOT_FDS_PINNED"
        {
            bail!("unsupported or overstated dynamic cgroup-scope capability");
        }
        Ok(())
    }

    pub fn sha256(&self) -> Result<String> {
        self.validate()?;
        let encoded = serde_json::to_vec(self).context("encode cgroup-scope capability")?;
        Ok(hex::encode(Sha256::digest(encoded)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_is_canonical_and_does_not_claim_leaf_identity() {
        let mut capability = CgroupScopeCapability::for_roots(&[10, 20]).unwrap();
        assert!(!capability.leaf_cgroup_id_retained);
        assert!(capability.dynamic_descendants_including_ephemeral);
        assert_eq!(capability.sha256().unwrap().len(), 64);
        capability.leaf_cgroup_id_retained = true;
        assert!(capability.validate().is_err());
    }

    #[test]
    fn capability_rejects_too_many_or_noncanonical_roots() {
        assert!(CgroupScopeCapability::for_roots(&[2, 1]).is_err());
        assert!(CgroupScopeCapability::for_roots(&[1; MAX_ANCESTOR_ROOTS + 1]).is_err());
    }
}
