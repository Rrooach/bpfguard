# Terminal-Bench + Docker deployment Observer validation (2026-09-15)

## Result

The manifest-pinned `pilot-20260915-c` campaign completed successfully in the
dedicated QEMU guest. All four Harbor Oracle trials earned reward `1.0`, all
four Docker workloads crossed the Observer READY/FINISH barriers, and all four
copied evidence bundles independently verify with
`deployment-observe-verify`.

This establishes the small-scale integration path. It does not establish that
all Linux state domains are complete, nor does it measure causal effects of a
delegated daemon.

## Environment and pinned inputs

- Guest kernel: `7.3.0-rc2-00100-g519a81750493-dirty`, x86-64, BPF LSM/BTF.
- Docker: `26.1.5+dfsg1`, `overlay2`, systemd cgroup driver, cgroup v2.
- Harbor: `0.23.0`, source revision
  `26f5d8f423786d55a25c5ef4f0eb5869e93ad2df`.
- Terminal-Bench: v4.0.0 selection recorded at commit
  `452bf305c6daa62fc59061d22133a7cbc7c1572e`.
- Selection manifest SHA-256:
  `0c7ac6d0c450a03d8ff4cca081296cda4964d912c73af76170b1b62ccdd20c20`.
- `deployment-observe` SHA-256:
  `56a7c7485e14079f607d1f595ee3fe1db2921a25ab101f6e605da1ee0016f8ba`.
- `deployment-observe-verify` SHA-256:
  `77ac2dd9593d760b50cc685d485d940ed85c3ea5fea8c96a0713e3f7e77b75b8`.
- `system_effects.bpf.o` SHA-256:
  `1ef3ee4bf53497d09c556ed38a4c70c5d8e89b84f377581a0f04174a6a17acf8`.
- `process_lifecycle.bpf.o` SHA-256:
  `7392a29cd0237759085c312d4205e8310dba0b1cd05a289b302d0f4f4f57bada`.
- `bridge.py` SHA-256:
  `efc12f3e5abc28b7f70efa764043224e38be7c480e539c0010c5cf061c15a3da`.

The bridge requires the expected selection-manifest digest, verifies it before
JSON parsing and again after task-input hashing, and refuses a nonempty output
root. Harbor image construction and the separate verifier run outside the
Agent observation interval.

## Per-task result

`System W/J` and `Lifecycle W/J` are authoritative WAL/projected-JSONL event
counts. `S0`, `drain`, and `S1` are diagnostic-only monotonic timings from the
Observer report; they are not a paired overhead benchmark.

| Task | Reward | Offline verified | System W/J | Lifecycle W/J | Drops system/lifecycle/socket | Filesystem changes | S0 ms | Drain ms | S1 ms |
| --- | ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| photonic-waveguide-routing | 1.0 | true | 644/644 | 21/21 | 0/0/0 | 4 | 0.666 | 102.699 | 0.956 |
| cargo-flight-dispatch | 1.0 | true | 1146/1146 | 37/37 | 0/0/0 | 9 | 0.815 | 227.879 | 1.185 |
| bun-sourcemap-leak | 1.0 | true | 556/556 | 27/27 | 0/0/0 | 3 | 1.195 | 103.843 | 0.976 |
| html-js-filter | 1.0 | true | 520/520 | 20/20 | 0/0/0 | 2 | 0.504 | 120.065 | 0.696 |

In total, the recorder retained 2,866 system-effect records representing
1,433 completed operations, plus 105 lifecycle records. The committed Observer
artifacts occupy 5,291,997 bytes. Because this campaign has no unobserved A/B
control and no repetitions, neither the READY-to-FINISH envelope difference
nor the single-run Harbor wall times support a slowdown percentage.

The `/app` endpoint confirmer found the expected durable-in-scope outputs:

- photonic added `routing_result_1.json` (plus Python cache entries);
- cargo modified `aircraft.py`, `dispatch.py`, and `navigation.py`, and added
  the declared package files and Python cache entries;
- bun modified `scripts/release.ts`;
- html added `filter.py`.

All filesystem comparisons are `CHANGED_WITHIN_SCOPE` with state completeness
`COMPLETE` for the explicit `/app` scope.

## Overlayfs object-resolution regression proof

The earlier pilot exposed `OBJECT_JOIN_AMBIGUOUS`: `file_open` observed both an
overlayfs outer file and its backing file. The recorder now uses sleepable BPF
LSM `file_post_open` for ordinary opens, after a stackable filesystem has
finished its backing opens.

In this campaign:

- all 51 successful selected `FILE_CREATE_OR_TRUNCATE` results obtained a
  `FILE_OBJECT` (`3 + 44 + 2 + 2` by task);
- 47 of those objects have overlayfs magic `0x794c7630`;
- `OBJECT_JOIN_AMBIGUOUS`, `OBJECT_JOIN_MISSING`, object-read failure, and
  object-unsupported flags are all zero;
- the single replay-level unresolved eligible operation is a failed cargo
  `mkdir` returning `-EEXIST`, not a successful operation missing its object.

The bounded input-capture truncations (6, 6, 6, and 4) are all the 96-byte raw
Unix-socket argument for `/var/run/nscd/socket`; no kernel-resolved file path is
truncated.

## Evidence boundary

Every offline verifier returned `verified: true`, but every run's
`overall_evidence_status` is deliberately `INCOMPLETE`. The lifecycle stream is
`PARTIAL` because schema v2 does not yet have an authoritative S0 task ledger
or cgroup-entry enrollment stream. The operation recorder transport and `/app`
filesystem endpoint evidence are complete within their contracts.

For this pilot, BPF endpoint state, sysctl, local network configuration, and
kernel-module confirmers were not enabled. Mount state was captured; residual
process state is inconclusive because S1 is taken while the frozen Docker
container is intentionally still alive. Attribution proves direct entry-time
cgroup membership, not generic causal attribution. The filesystem actor
contract is absent. Consequently this result must not be described as “the
entire Linux system is unchanged/fully explained.”

This is an Oracle integration baseline, not a Codex/DeepSeek quality or cost
experiment. Successful `O_PATH` and `O_TMPFILE` opens are also outside the
current `file_post_open` resolver contract and fail evidence closed. The
sleepable hook requires a compatible kernel (upstream Linux 6.11 or newer);
the tested guest is compatible.

## Artifacts and verification

The local copied archive is under:

```text
.output/validation/terminal-bench-docker/pilot-20260915-c/campaign/
```

The campaign summary SHA-256 is
`c74cf282c341487cf1c199611a3e5cb3f9e90017cab5d457fa3d691b85289bfc`.
After copying, the same pinned `deployment-observe-verify` binary was run once
against each of the four `observer/` directories and their corresponding
`control/verification-expectation.json`; all four returned `verified: true`.

Post-campaign checks found no Docker containers or volumes, campaign cgroups,
campaign bpffs entries, or live Observer/bridge processes. The prewarmed Docker
images and build cache remain intentionally reusable; they are not live
workload state. The guest has no `bpftool`, so the residue check is not a full
enumeration of unpinned kernel BPF IDs. `make check-all` also passed, including
all Rust tests, Clippy with warnings denied, BPF builds, the BPF fast-path
instruction budget, shell syntax checks, and experiment self-tests.

## Expanded endpoint-domain rerun (`pilot-20260915-d`)

The same four pinned tasks were rerun after the bridge began supplying the
following explicit scopes:

- BPF Program and Map metadata, with Map contents, Links, pins, and attachment
  targets outside the claim;
- eight named sysctls;
- the frozen Docker network namespace's addresses, routes, rules, qdiscs,
  classes, filters, and nftables ruleset;
- all loaded host kernel modules, without module parameters;
- container mounts and recursive process residuals.

The network scope retained the target namespace file descriptor and bound the
initial `eth0`/`lo` interface set while the container was frozen. The `ip`,
`tc`, and `nft` binaries were independently path- and digest-pinned. The bridge
SHA-256 for this run is
`0045a4051b65adcc8392a2a0c95e25719321770f6692b8d852374168029c3f3c`.

All four Harbor rewards were `1.0`; all four Observer runs independently
verified. No system-effect, lifecycle, or socket record was dropped.

| Task | System W/J | Operations | Lifecycle W/J | Filesystem changes | Offline verified |
| --- | ---: | ---: | ---: | ---: | --- |
| photonic-waveguide-routing | 644/644 | 322 | 21/21 | 4 | true |
| cargo-flight-dispatch | 1146/1146 | 573 | 36/36 | 9 | true |
| bun-sourcemap-leak | 556/556 | 278 | 27/27 | 3 | true |
| html-js-filter | 520/520 | 260 | 20/20 | 2 | true |

Each S0 and S1 BPF snapshot was `COMPLETE` and contained 33 Programs, 20 Maps,
zero Links, and no pins. All 20 Map contents were explicitly
`OUTSIDE_CLAIM_SCOPE`; Observer-owned IDs were marked excluded. The external
Program/Map endpoint sets were identical and the comparison contained no
changes. The resulting verdict is nevertheless `INCONCLUSIVE`, with BPF
evidence `INCOMPLETE`: this deployment campaign does not provide the exclusive
global BPF actor/quiescence contract required for a negative state claim, nor
does it bind the deployment WAL as the BPF oracle's own complete
`BPF_USER_SYSCALL` event stream. A positive endpoint delta would still be
reported, but would be unattributed.

Every Linux-domain snapshot completed with no collection issues. Per snapshot,
the recorder retained 8 sysctl, 26 mount, 13 network, 0 module, and 2 residual
process records. S0 and S1 were byte-identical in every one of these domains.
They are therefore reported as `OBSERVED_IDENTICAL` with `INCONCLUSIVE`
verdicts, not `UNCHANGED_WITHIN_SCOPE`: there is no exclusive-writer contract,
and endpoint snapshots cannot rule out a change that was reverted between S0
and S1. The module inventory is empty because this test kernel had no loaded
modules; the `ALL_LOADED` collection path still completed successfully. The
residual process terminal state is `NON_EMPTY_WITHIN_SCOPE`, as expected,
because S1 is intentionally taken while the Docker container remains frozen
and alive.

The `/app` filesystem comparisons were all complete and
`CHANGED_WITHIN_SCOPE`, matching the expected task outputs. Object resolution
resolved 182 of 183 eligible operations; the sole unresolved operation was a
failed cargo `mkdir` returning `EEXIST`. There were no missing or ambiguous
object joins.

Diagnostic-only endpoint timings averaged 50.684 ms for S0 and 52.641 ms for
S1, or 103.325 ms across both boundaries per task. Program/Map enumeration
accounted for about 1.712 ms of that total. Compared with the earlier
mount-only campaign, the new combined sysctl/network/module collectors add
about 100 ms per task. These confirmers execute only at S0/S1 and do not enter
the syscall hot path. This is a one-run boundary-latency observation, not a
repeated A/B workload-overhead measurement.

The copied archive is under:

```text
.output/validation/terminal-bench-docker/pilot-20260915-d/campaign/
```

It contains all 153 evidence files and 55 Harbor trial files. The local and VM
copies of `campaign-summary.json` both have SHA-256
`d96bceda1c3ef5f862f5b7e7981428eaf3027966a099abe3253939b9cdb44d78`.
After copying, the pinned verifier with SHA-256
`77ac2dd9593d760b50cc685d485d940ed85c3ea5fea8c96a0713e3f7e77b75b8`
was rerun locally against every bundle; all four again returned
`verified: true`.
Post-run checks found no containers, volumes, campaign cgroups, Observer/bridge
processes, or bpffs pins.
