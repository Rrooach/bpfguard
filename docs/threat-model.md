# Threat model and non-goals

## Security statement

The MVP observes a cooperative workload inside a trusted, controlled VM. It is
not an enforcement mechanism and is not designed to remain correct when the
workload attacks the Observer.

## Trusted computing base

The following are trusted:

- the target kernel and boot identity;
- the Observer daemon and recorder program;
- the Host signer, exact policy, VM launcher, and static strict PID 1 when the
  authenticated harness is used;
- claim-scope configuration supplied before the run;
- the artifact directory and durability mechanism;
- the mechanism that records Observer-owned BPF object IDs;
- target-specific attachment and bpffs adapters when selected.

The workload must not be able to write these components or their configuration.
The daemon requires an externally supplied recorder SHA-256 and compares it
with the exact byte buffer before load; `verify-run` repeats that policy match.
The trusted VM orchestrator must authenticate and distribute that expected
value. Kernel, BTF, source, and probe-matrix policy matching remains external.

The general integrated coordinator does not itself make the artifact directory
unwritable to the workload, create a mount/user namespace, or drop inherited
credentials before executing it. Those are external launch-policy
requirements. If they are not enforced, the run satisfies only the cooperative
workload assumption and cannot produce authenticated unchanged evidence. The
repository's strict VM acceptance launcher supplies a read-only root, separate
`nosuid,nodev,noexec` evidence disk, capability-checked workloads, and a
minimal measured PID 1; those controls are specific to that launcher.

## Workload assumptions

During an `exclusive-vm-v1` run, the workload is assumed or enforced to:

- remain in the registered cgroup for its entire process-tree lifetime;
- use ordinary userspace `bpf(2)` for effects covered by the event channel;
- not tamper with recorder maps, links, Ring Buffer, or output artifacts;
- not retain work through external processes, writable shared Map mappings,
  `SCM_RIGHTS`, `pidfd_getfd`, io_uring, BPF timers/workqueues, or another VM;
- not create an unobserved writer outside the registered process tree;
- terminate before S1.

An implementation that merely assumes these properties must report
`basis=ASSUMED`, not `HARNESS_ENFORCED`.

## What is observed

The State Oracle compares only the effective `ClaimScope` at S0 and S1. The
event recorder provides causal evidence for the declared event interfaces.
These channels complement each other but are not interchangeable:

- an event can be present while no object remains at S1;
- state can differ even when event evidence is incomplete;
- state equality does not disprove transient activity;
- system state difference does not itself prove workload attribution.

## Explicit non-goals

The MVP does not claim:

- resistance to a malicious Agent or privileged workload;
- complete coverage of netlink, ioctl, VFS unlink/close, perf-event, or
  kernel-internal BPF effect paths;
- complete attachment inventory when no target adapter is declared;
- canonical raw-byte content capture for Map types other than ARRAY, HASH,
  PERCPU_ARRAY, and PERCPU_HASH, or semantic decoding of kernel-managed fields
  in any Map value;
- atomic global snapshots;
- detection of every BPF object-ID ABA sequence;
- history reconstruction from JSONL or endpoint snapshots;
- network, mount, process, filesystem, device, or host-side effect coverage;
- checkpoint/restore or rollback correctness;
- a global statement that the system is clean.

## Safe verdict rules

`CHANGED_WITHIN_SCOPE` may be returned for a deterministic typed difference
even when event evidence is incomplete. Attribution must still remain separate.

The comparator's abstract `UNCHANGED_WITHIN_SCOPE` rule requires all of the
following:

1. S0 and S1 have the same boot identity and effective scope.
2. Every requested state adapter reports complete coverage.
3. All selected Map samples are semantically complete and within budget.
4. The harness reports `QUIESCENT_WITHIN_MODEL` with
   `basis=HARNESS_ENFORCED`.
5. Every required contract check has machine-produced evidence and passed.

Any failure or unknown produces `INCONCLUSIVE` for an empty diff. No MVP verdict
may be translated to rollback `CLEAN`.

The integrated CLI rejects every caller-supplied static `HARNESS_ENFORCED`
report as unbound. `UNCHANGED_WITHIN_SCOPE` is reachable only through the
live, authenticated four-phase `--harness-channel` exchange, a verified final
delivery ACK, the kernel-side outside-cgroup negative counter, and all normal
snapshot/event completeness gates. A controlled VM does not satisfy those
conditions merely by being called exclusive.

## Artifact integrity boundary

Individual JSON files are not run commits. `verdict.json` is
`PROVISIONAL`. A consumer must run `verify-run`, which requires a `FINALIZED`
manifest, verifies the closed SHA-256/size set, checks WAL/JSONL and run
identity, matches the recorder digest supplied by trusted policy, and
recomputes the verdict. For authenticated runs it additionally reconstructs
and verifies all four Ed25519-signed responses against an external public key,
policy ID/digest, and kernel identity. The launcher and measured cooperative
Observer remain trusted: this is not remote attestation against a malicious
Guest.

The direct child is configured with `PR_SET_PDEATHSIG(SIGKILL)`. Descendants do
not automatically inherit that guarantee, and an uncatchable daemon death can
leave a populated cgroup. Recovery/cleanup is a VM or service-manager duty in
this release.
