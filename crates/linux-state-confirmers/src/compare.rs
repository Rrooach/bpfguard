// SPDX-License-Identifier: GPL-2.0-only

use crate::schema::*;
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;

pub fn compare(before: &StateSnapshot, after: &StateSnapshot) -> Result<StateComparison> {
    validate_snapshot(before)?;
    validate_snapshot(after)?;
    if before.phase != SnapshotPhase::S0 || after.phase != SnapshotPhase::S1 {
        bail!("Linux state comparison requires S0 followed by S1");
    }
    if before.scope != after.scope || before.scope_sha256 != after.scope_sha256 {
        bail!("Linux state comparison scope mismatch");
    }
    let same_boot = before.boot_id == after.boot_id;
    let comparison = StateComparison {
        protocol_version: LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION,
        domain: LINUX_STATE_CONFIRMATION_DOMAIN.to_owned(),
        scope_sha256: before.scope_sha256.clone(),
        s0_snapshot_id: before.snapshot_id.clone(),
        s1_snapshot_id: after.snapshot_id.clone(),
        domains: StateDomainComparisons {
            sysctl: compare_domain(DomainKind::Sysctl, before.sysctl.as_ref(), after.sysctl.as_ref(), same_boot)?,
            mounts: compare_domain(DomainKind::Mount, before.mounts.as_ref(), after.mounts.as_ref(), same_boot)?,
            network: compare_domain(DomainKind::Network, before.network.as_ref(), after.network.as_ref(), same_boot)?,
            modules: compare_domain(DomainKind::KernelModule, before.modules.as_ref(), after.modules.as_ref(), same_boot)?,
            process_residual: compare_domain(
                DomainKind::ProcessResidual, before.process_residual.as_ref(), after.process_residual.as_ref(), same_boot,
            )?,
        },
        limitations: vec![
            "results are an explicit per-domain vector and must never be collapsed into an all-Linux unchanged claim".to_owned(),
            "endpoint comparison does not establish causal attribution; operation history is separate evidence".to_owned(),
            "an identical endpoint remains INCONCLUSIVE without authenticated exclusive-writer and S0/S1 quiescence evidence".to_owned(),
            "remote service or database effects are not confirmable by this target-Linux endpoint confirmer".to_owned(),
        ],
    };
    let encoded = serde_json::to_vec(&comparison).context("serialize Linux state comparison")?;
    if encoded.len() as u64 > HARD_MAX_COMPARISON_JSON_BYTES {
        bail!("Linux state comparison exceeds artifact size bound");
    }
    Ok(comparison)
}

fn compare_domain(
    kind: DomainKind,
    before: Option<&DomainSnapshot>,
    after: Option<&DomainSnapshot>,
    same_boot: bool,
) -> Result<DomainComparison> {
    let limitations = limitations(kind);
    let (Some(before), Some(after)) = (before, after) else {
        if before.is_some() != after.is_some() {
            bail!("enabled domain presence differs across snapshots");
        }
        return Ok(DomainComparison {
            domain: kind,
            protocol_domain: kind.protocol_name().to_owned(),
            endpoint_difference: EndpointDifferenceStatus::NotConfirmed,
            verdict: StateVerdict::NotConfirmed,
            state_completeness: Completeness { status: CompletenessStatus::NotConfirmed, reasons: vec!["domain was not enabled in the explicit scope".to_owned()] },
            terminal_state: TerminalState::NotApplicable,
            causal_attribution_status: CausalAttributionStatus::NotEstablished,
            changes: Vec::new(),
            limitations,
        });
    };
    if before.domain != kind || after.domain != kind {
        bail!("domain snapshot type does not match its envelope");
    }
    let changes = compare_records(&before.records, &after.records);
    if changes.len() > HARD_MAX_RECORDS_PER_DOMAIN.saturating_mul(2) {
        bail!("domain change set exceeds hard bound");
    }
    let mut reasons = Vec::new();
    if before.completeness.status != CompletenessStatus::Complete {
        reasons.push("S0 domain snapshot is incomplete".to_owned());
    }
    if after.completeness.status != CompletenessStatus::Complete {
        reasons.push("S1 domain snapshot is incomplete".to_owned());
    }
    if !same_boot {
        reasons.push("S0 and S1 kernel boot identities differ".to_owned());
    }
    if before.namespace_inode != after.namespace_inode {
        reasons.push("S0 and S1 namespace identities differ".to_owned());
    }
    if before.namespace_context != after.namespace_context {
        reasons.push("S0 and S1 namespace capture contexts differ".to_owned());
    }
    if before.source_identity_sha256 != after.source_identity_sha256 {
        reasons.push("S0 and S1 capture source/tool identities differ".to_owned());
    }
    reasons.sort();
    reasons.dedup();
    let complete = reasons.is_empty();
    let endpoint_difference = if !complete {
        EndpointDifferenceStatus::Indeterminate
    } else if changes.is_empty() {
        EndpointDifferenceStatus::ObservedIdentical
    } else {
        EndpointDifferenceStatus::ObservedDifferent
    };
    let verdict = if complete && !changes.is_empty() {
        StateVerdict::ChangedWithinScope
    } else {
        StateVerdict::Inconclusive
    };
    let terminal_state = if kind != DomainKind::ProcessResidual {
        TerminalState::NotApplicable
    } else if !complete {
        TerminalState::Indeterminate
    } else if after
        .records
        .iter()
        .any(|record| is_process_residual_record_key(&record.key))
    {
        TerminalState::NonEmptyWithinScope
    } else {
        TerminalState::EmptyWithinScope
    };
    Ok(DomainComparison {
        domain: kind,
        protocol_domain: kind.protocol_name().to_owned(),
        endpoint_difference,
        verdict,
        state_completeness: Completeness {
            status: if complete {
                CompletenessStatus::Complete
            } else {
                CompletenessStatus::Incomplete
            },
            reasons,
        },
        terminal_state,
        causal_attribution_status: CausalAttributionStatus::NotEstablished,
        changes,
        limitations,
    })
}

fn is_process_residual_record_key(key: &str) -> bool {
    key.starts_with("process/")
        || key.starts_with("thread/")
        || (key.starts_with("root/") && (key.contains("/process/") || key.contains("/thread/")))
}

fn compare_records(before: &[StateRecord], after: &[StateRecord]) -> Vec<StateChange> {
    let mut changes = Vec::new();
    let mut left = 0;
    let mut right = 0;
    while left < before.len() || right < after.len() {
        match (before.get(left), after.get(right)) {
            (Some(old), Some(new)) => match old.key.cmp(&new.key) {
                Ordering::Less => {
                    changes.push(StateChange {
                        key: old.key.clone(),
                        kind: ChangeKind::Removed,
                        before_sha256: Some(old.value_sha256.clone()),
                        after_sha256: None,
                    });
                    left += 1;
                }
                Ordering::Greater => {
                    changes.push(StateChange {
                        key: new.key.clone(),
                        kind: ChangeKind::Added,
                        before_sha256: None,
                        after_sha256: Some(new.value_sha256.clone()),
                    });
                    right += 1;
                }
                Ordering::Equal => {
                    if old.value_sha256 != new.value_sha256 || old.value_size != new.value_size {
                        changes.push(StateChange {
                            key: old.key.clone(),
                            kind: ChangeKind::Modified,
                            before_sha256: Some(old.value_sha256.clone()),
                            after_sha256: Some(new.value_sha256.clone()),
                        });
                    }
                    left += 1;
                    right += 1;
                }
            },
            (Some(old), None) => {
                changes.push(StateChange {
                    key: old.key.clone(),
                    kind: ChangeKind::Removed,
                    before_sha256: Some(old.value_sha256.clone()),
                    after_sha256: None,
                });
                left += 1;
            }
            (None, Some(new)) => {
                changes.push(StateChange {
                    key: new.key.clone(),
                    kind: ChangeKind::Added,
                    before_sha256: None,
                    after_sha256: Some(new.value_sha256.clone()),
                });
                right += 1;
            }
            (None, None) => break,
        }
    }
    changes
}

fn validate_snapshot(snapshot: &StateSnapshot) -> Result<()> {
    if snapshot.protocol_version != LINUX_STATE_CONFIRMATION_PROTOCOL_VERSION {
        bail!("unsupported Linux state snapshot protocol");
    }
    snapshot.scope.validate()?;
    CaptureRequest {
        snapshot_id: snapshot.snapshot_id.clone(),
        phase: snapshot.phase,
    }
    .validate()?;
    if snapshot.captured_unix_ns == 0 || snapshot.boot_id.is_empty() {
        bail!("Linux state snapshot lacks capture time or boot identity");
    }
    if snapshot.scope.sha256()? != snapshot.scope_sha256 {
        bail!("Linux state snapshot scope digest mismatch");
    }
    validate_domain(
        snapshot.sysctl.as_ref(),
        DomainKind::Sysctl,
        snapshot.scope.sysctl.as_ref().map(|scope| scope.evidence),
        snapshot.scope.sysctl.as_ref().map(|scope| &scope.limits),
    )?;
    validate_domain(
        snapshot.mounts.as_ref(),
        DomainKind::Mount,
        snapshot.scope.mounts.as_ref().map(|scope| scope.evidence),
        snapshot.scope.mounts.as_ref().map(|scope| &scope.limits),
    )?;
    validate_domain(
        snapshot.network.as_ref(),
        DomainKind::Network,
        snapshot.scope.network.as_ref().map(|scope| scope.evidence),
        snapshot.scope.network.as_ref().map(|scope| &scope.limits),
    )?;
    validate_domain(
        snapshot.modules.as_ref(),
        DomainKind::KernelModule,
        snapshot.scope.modules.as_ref().map(|scope| scope.evidence),
        snapshot.scope.modules.as_ref().map(|scope| &scope.limits),
    )?;
    validate_domain(
        snapshot.process_residual.as_ref(),
        DomainKind::ProcessResidual,
        snapshot
            .scope
            .process_residual
            .as_ref()
            .map(|scope| scope.evidence),
        snapshot
            .scope
            .process_residual
            .as_ref()
            .map(|scope| &scope.limits),
    )?;
    if let (Some(domain), Some(scope)) = (&snapshot.sysctl, &snapshot.scope.sysctl) {
        validate_sysctl_records(domain, scope)?;
    }
    if let (Some(domain), Some(scope)) = (&snapshot.mounts, &snapshot.scope.mounts) {
        validate_mount_records(domain, scope)?;
    }
    if let (Some(domain), Some(scope)) = (&snapshot.network, &snapshot.scope.network) {
        validate_network_records(domain, scope)?;
    }
    if let (Some(domain), Some(scope)) = (&snapshot.modules, &snapshot.scope.modules) {
        validate_module_records(domain, scope)?;
    }
    if let (Some(domain), Some(scope)) =
        (&snapshot.process_residual, &snapshot.scope.process_residual)
    {
        validate_process_records(domain, scope)?;
    }
    let encoded = serde_json::to_vec(snapshot).context("serialize Linux state snapshot")?;
    if encoded.len() as u64 > HARD_MAX_SNAPSHOT_JSON_BYTES {
        bail!("Linux state snapshot exceeds artifact size bound");
    }
    Ok(())
}

fn validate_domain(
    snapshot: Option<&DomainSnapshot>,
    kind: DomainKind,
    evidence_mode: Option<ValueEvidenceMode>,
    limits: Option<&CaptureLimits>,
) -> Result<()> {
    if snapshot.is_some() != evidence_mode.is_some() || snapshot.is_some() != limits.is_some() {
        bail!("domain snapshot presence does not match scope");
    }
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let evidence_mode = evidence_mode.context("enabled domain has no evidence mode")?;
    let limits = limits.context("enabled domain has no capture limits")?;
    if snapshot.domain != kind {
        bail!("domain kind mismatch");
    }
    if snapshot.records.len() > HARD_MAX_RECORDS_PER_DOMAIN
        || snapshot.issues.len() > HARD_MAX_ISSUES_PER_DOMAIN
        || snapshot.records.len() as u64 > limits.max_records
    {
        bail!("domain snapshot exceeds record or issue hard bound");
    }
    let mut previous: Option<&str> = None;
    let mut total_value_bytes = 0_u64;
    for record in &snapshot.records {
        if record.key.is_empty() || record.key.len() > HARD_MAX_KEY_BYTES {
            bail!("invalid state record key");
        }
        if previous.map_or(false, |key| key >= record.key.as_str()) {
            bail!("state records must be strictly sorted and unique");
        }
        validate_digest(&record.value_sha256)?;
        if record.value_size > HARD_MAX_RECORD_VALUE_BYTES
            || record.value_size > limits.max_value_bytes
        {
            bail!("state record value exceeds hard bound");
        }
        total_value_bytes = total_value_bytes
            .checked_add(record.value_size)
            .context("state record value-byte total overflow")?;
        match (evidence_mode, &record.value_bytes_hex) {
            (ValueEvidenceMode::BytesAndSha256, None) => {
                bail!("BYTES_AND_SHA256 state record is missing value bytes")
            }
            (ValueEvidenceMode::Sha256Only, Some(_)) => {
                bail!("SHA256_ONLY state record unexpectedly carries value bytes")
            }
            (ValueEvidenceMode::Sha256Only, None) => {}
            (ValueEvidenceMode::BytesAndSha256, Some(bytes)) => {
                if bytes.len() % 2 != 0
                    || bytes.len() as u64 > HARD_MAX_RECORD_VALUE_BYTES.saturating_mul(2)
                {
                    bail!("invalid state record evidence length");
                }
                let decoded = hex::decode(bytes).context("decode state record evidence")?;
                if decoded.len() as u64 != record.value_size
                    || hex::encode(Sha256::digest(&decoded)) != record.value_sha256
                {
                    bail!("state record evidence digest/size mismatch");
                }
            }
        }
        previous = Some(&record.key);
    }
    if total_value_bytes > limits.max_total_value_bytes {
        bail!("domain snapshot exceeds configured total value-byte bound");
    }
    let mut previous_issue: Option<(&str, u8, Option<i32>, &str)> = None;
    for issue in &snapshot.issues {
        if issue.key.is_empty()
            || issue.key.contains('\0')
            || issue.key.chars().count() > HARD_MAX_ISSUE_KEY_CHARS
            || issue.detail.is_empty()
            || issue.detail.contains('\0')
            || issue.detail.chars().count() > HARD_MAX_ISSUE_DETAIL_CHARS
            || matches!(issue.errno, Some(errno) if !(1..=4095).contains(&errno))
        {
            bail!("capture issue contains an invalid or out-of-bounds field");
        }
        let current = (
            issue.key.as_str(),
            issue.kind as u8,
            issue.errno,
            issue.detail.as_str(),
        );
        if matches!(previous_issue, Some(previous) if previous >= current) {
            bail!("capture issues must be strictly sorted and unique");
        }
        previous_issue = Some(current);
    }
    let mut expected_reasons = snapshot
        .issues
        .iter()
        .map(|issue| format!("{}: {:?}", issue.key, issue.kind))
        .collect::<Vec<_>>();
    expected_reasons.sort();
    expected_reasons.dedup();
    let expected_status = if expected_reasons.is_empty() {
        CompletenessStatus::Complete
    } else {
        CompletenessStatus::Incomplete
    };
    if snapshot.completeness.status != expected_status
        || snapshot.completeness.reasons != expected_reasons
    {
        bail!("domain completeness is not the canonical projection of capture issues");
    }
    validate_namespace_context(snapshot, kind)?;
    match &snapshot.source_identity_sha256 {
        Some(value) => validate_digest(value)?,
        None if snapshot.completeness.status == CompletenessStatus::Complete => {
            bail!("complete domain snapshot lacks capture source identity")
        }
        None => {}
    }
    Ok(())
}

fn validate_sysctl_records(snapshot: &DomainSnapshot, scope: &SysctlScope) -> Result<()> {
    let expected = scope.keys.iter().cloned().collect::<BTreeSet<_>>();
    validate_closed_record_set(snapshot, &expected, "sysctl")
}

fn validate_mount_records(snapshot: &DomainSnapshot, scope: &MountScope) -> Result<()> {
    if snapshot.namespace_inode != Some(scope.namespace.expected_namespace_inode) {
        bail!("mount snapshot namespace does not match its scope");
    }
    for record in &snapshot.records {
        let suffix = record
            .key
            .strip_prefix("mount/")
            .context("mount snapshot contains a non-mount record")?;
        if suffix.len() != 20
            || !suffix.bytes().all(|byte| byte.is_ascii_digit())
            || suffix.parse::<u64>().unwrap_or(0) == 0
        {
            bail!("mount snapshot contains a malformed mount record key");
        }
    }
    if snapshot.completeness.status == CompletenessStatus::Complete && snapshot.records.is_empty() {
        bail!("complete mount snapshot contains no root mount record");
    }
    Ok(())
}

fn validate_network_records(snapshot: &DomainSnapshot, scope: &NetworkScope) -> Result<()> {
    if snapshot.namespace_inode != Some(scope.namespace.expected_namespace_inode) {
        bail!("network snapshot namespace does not match its scope");
    }
    let mut expected = BTreeSet::new();
    if scope.collectors.addresses {
        expected.insert("ip/address".to_owned());
    }
    if scope.collectors.routes {
        expected.insert("ip/route/ipv4".to_owned());
        expected.insert("ip/route/ipv6".to_owned());
    }
    if scope.collectors.rules {
        expected.insert("ip/rule/ipv4".to_owned());
        expected.insert("ip/rule/ipv6".to_owned());
    }
    if scope.collectors.traffic_control {
        expected.insert("tc/qdisc".to_owned());
        for interface in &scope.tc_interfaces {
            expected.insert(format!("tc/class/{interface}"));
            expected.insert(format!("tc/filter/{interface}/egress"));
            expected.insert(format!("tc/filter/{interface}/ingress"));
        }
    }
    if scope.collectors.nftables {
        expected.insert("nft/ruleset".to_owned());
    }
    validate_closed_record_set(snapshot, &expected, "network")
}

fn validate_closed_record_set(
    snapshot: &DomainSnapshot,
    expected: &BTreeSet<String>,
    label: &str,
) -> Result<()> {
    let observed = snapshot
        .records
        .iter()
        .map(|record| record.key.clone())
        .collect::<BTreeSet<_>>();
    if !observed.is_subset(expected) {
        bail!("{label} snapshot contains a record outside its explicit scope");
    }
    if snapshot.completeness.status == CompletenessStatus::Complete && observed != *expected {
        bail!("complete {label} snapshot does not contain its exact required record set");
    }
    Ok(())
}

fn validate_module_records(snapshot: &DomainSnapshot, scope: &ModuleScope) -> Result<()> {
    let explicit = match &scope.selection {
        ModuleSelection::AllLoaded => None,
        ModuleSelection::Explicit(names) => {
            Some(names.iter().map(String::as_str).collect::<BTreeSet<_>>())
        }
    };
    let base_records = snapshot
        .records
        .iter()
        .filter_map(|record| {
            let parts = record.key.split('/').collect::<Vec<_>>();
            (parts.len() == 2 && parts[0] == "module").then_some(parts[1])
        })
        .collect::<BTreeSet<_>>();
    for record in &snapshot.records {
        let parts = record.key.split('/').collect::<Vec<_>>();
        let valid_shape = match parts.as_slice() {
            ["module", module] => valid_module_record_name(module),
            ["module", module, "parameter", parameter] => {
                scope.capture_parameters
                    && valid_module_record_name(module)
                    && !parameter.is_empty()
                    && base_records.contains(module)
            }
            _ => false,
        };
        if !valid_shape {
            bail!("module snapshot contains a malformed or unauthorized record key");
        }
        if explicit
            .as_ref()
            .map(|names| !names.contains(parts[1]))
            .unwrap_or(false)
        {
            bail!("module snapshot contains a module outside its explicit selection");
        }
    }
    Ok(())
}

fn valid_module_record_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn validate_process_records(snapshot: &DomainSnapshot, scope: &ProcessResidualScope) -> Result<()> {
    let roots = scope.roots()?;
    for record in &snapshot.records {
        if roots.len() == 1 {
            if !(record.key.starts_with("process/") || record.key.starts_with("thread/")) {
                bail!("process-residual snapshot contains a record outside its single root");
            }
            continue;
        }
        let allowed = roots.iter().enumerate().any(|(index, (_, cgroup_id))| {
            let process = format!("root/{index:02}/{cgroup_id:020}/process/");
            let thread = format!("root/{index:02}/{cgroup_id:020}/thread/");
            record.key.starts_with(&process) || record.key.starts_with(&thread)
        });
        if !allowed {
            bail!("process-residual snapshot contains a record outside its bound root set");
        }
    }
    Ok(())
}

fn validate_namespace_context(snapshot: &DomainSnapshot, kind: DomainKind) -> Result<()> {
    let expected: &[LinuxNamespaceKind] = match kind {
        DomainKind::Sysctl => &[
            LinuxNamespaceKind::Ipc,
            LinuxNamespaceKind::Network,
            LinuxNamespaceKind::Uts,
        ],
        DomainKind::Mount => &[LinuxNamespaceKind::Mount],
        DomainKind::Network => &[LinuxNamespaceKind::Network],
        DomainKind::KernelModule | DomainKind::ProcessResidual => &[],
    };
    let observed = snapshot
        .namespace_context
        .iter()
        .map(|value| value.kind)
        .collect::<Vec<_>>();
    if observed != expected {
        bail!("domain namespace context does not match its closed protocol model");
    }
    if snapshot
        .namespace_context
        .iter()
        .any(|value| value.inode == 0)
    {
        bail!("domain namespace context contains inode zero");
    }
    match kind {
        DomainKind::Mount | DomainKind::Network => {
            if snapshot.namespace_inode
                != snapshot.namespace_context.first().map(|value| value.inode)
            {
                bail!("legacy namespace inode disagrees with namespace context evidence");
            }
        }
        DomainKind::Sysctl | DomainKind::KernelModule | DomainKind::ProcessResidual => {
            if snapshot.namespace_inode.is_some() {
                bail!("domain carries an unexpected legacy namespace inode");
            }
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        bail!("digest is not canonical lowercase SHA-256");
    }
    Ok(())
}

fn limitations(kind: DomainKind) -> Vec<String> {
    match kind {
        DomainKind::Sysctl => vec![
            "confirmation covers only explicitly listed procfs sysctl keys".to_owned(),
            "a textual sysctl endpoint does not prove persistence across reboot".to_owned(),
        ],
        DomainKind::Mount => vec![
            "confirmation covers one explicitly bound mount namespace and mountinfo endpoint".to_owned(),
            "mountinfo does not hash mounted filesystem contents or storage durability".to_owned(),
        ],
        DomainKind::Network => vec![
            "confirmation is local to one network namespace and the enabled address/route/rule/tc/nft collectors".to_owned(),
            "tc class/filter confirmation is limited to explicitly listed interfaces".to_owned(),
            "trusted command output does not cover conntrack, transient packets, sockets, or remote endpoint state".to_owned(),
        ],
        DomainKind::KernelModule => vec![
            "confirmation covers selected loaded-module records and, when requested, readable sysfs parameters".to_owned(),
            "it does not attest kernel text integrity, built-in feature state, firmware, or module persistence across reboot".to_owned(),
        ],
        DomainKind::ProcessResidual => vec![
            "confirmation covers only processes remaining in the exact tracked cgroup tree".to_owned(),
            "escaped processes, delegated daemon work, kernel workers, and work outside the cgroup are not attributed".to_owned(),
        ],
    }
}
