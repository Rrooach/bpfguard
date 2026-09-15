# Terminal-Bench / Harbor Docker bridge

This experiment runs local, single-step Harbor tasks with the built-in Oracle
agent while `deployment-observe` records the exact Agent phase of Harbor's real
Docker `main` container.

The bridge does not patch Harbor. It creates one programmatic `Trial`, then
registers `AGENT_START` and `AGENT_END` hooks whose closures retain the Trial's
live Docker environment:

```text
Harbor environment + Oracle setup
  -> AGENT_START
  -> find exactly one Compose main container by exact labels
  -> require full container ID, live host PID, matching cgroup-v2 component
  -> docker pause + wait for cgroup.events frozen=1
  -> bind mount/net namespace identities and the complete initial interface set
  -> deployment-observe S0 + READY
  -> docker unpause
  -> Oracle solution (the measured Agent phase)
  -> AGENT_END (also runs on Agent failure/timeout)
  -> docker pause + FINISH + S1 + offline verify
  -> docker unpause
  -> Harbor verifier and teardown
```

The Observer's closed artifact directory is kept separate from bridge control
records. Every successful task has both Harbor reward data and an independently
verified Observer summary. The deployment-level evidence status is expected to
remain `INCOMPLETE` while lifecycle schema v2 lacks an authoritative S0 task
ledger and cgroup-migration/`CLONE_INTO_CGROUP` enrollment hooks; individual
system-effect, socket, filesystem, and Linux-state results remain usable.

## Pinned pilot inputs

The initial four small Terminal-Bench 4 tasks selected for this pilot are:

- `photonic-waveguide-routing`
- `cargo-flight-dispatch`
- `bun-sourcemap-leak`
- `html-js-filter`

All four are single-container, single-step tasks with `WORKDIR /app` and an
Oracle `solution/solve.sh`. The selection is pinned to Terminal-Bench tag
`v4.0.0`, commit `452bf305c6daa62fc59061d22133a7cbc7c1572e`.

The bridge currently targets Harbor `0.23.0`; record and pin the exact installed
Harbor package/source revision for every experiment. It requires Python 3.12+.

## Preconditions

- Run inside the disposable target Linux VM, not against remote Docker or
  Docker Desktop. The Observer and Docker daemon must share this kernel and
  host PID/cgroup namespaces.
- Run as root. The kernel must pass the Observer expanded-object `doctor`
  preflight and have cgroup v2, BTF, BPF LSM, and `cgroup.freeze`.
- Distribute the selection manifest, two BPF objects, Rust binaries, and exact
  `ip`/`tc`/`nft` ELF collectors through trusted paths. Pass all eight expected
  SHA-256 values explicitly. The bridge requires each collector to be a
  singly-linked, executable, root-owned ELF file that is not group/other
  writable; both the bridge and confirmer independently hash it.
- Use an empty evidence root and an empty Harbor trials directory.
- The selected task must expose `/app`. The bridge deliberately refuses other
  filesystem scopes rather than silently observing the wrong tree.
- This v1 bridge refuses multi-step tasks and observes only Compose service
  `main`; do not use it for sidecar/multi-container claims.
- Use Harbor's normal public network policy for this Oracle pilot. Harbor's
  `AGENT_START` hook fires before a dynamic phase network-policy transition, so
  such a transition would be inside the endpoint interval and must not be
  misattributed to the Oracle.

## Build and preflight

From `tools/bpf/bpf-state-observer`:

```sh
make release system-effects-bpf process-lifecycle-bpf

BIN=.output/cargo-target/release/bpf-state-observer
EFFECT_OBJECT=$(realpath .output/system_effects.bpf.o)
LIFECYCLE_OBJECT=$(realpath .output/process_lifecycle.bpf.o)

sudo "$BIN" doctor \
  --recorder-object "$EFFECT_OBJECT" \
  --process-lifecycle-object "$LIFECYCLE_OBJECT" \
  --object-resolution kernel-object-expanded-partial
```

Provision the eight expected digests independently. The literal values below are
the exact 2026-09-15 pilot artifact set; rebuilding any binary or BPF object
requires recording a new value. In particular, do not calculate an "expected"
digest from the same untrusted file immediately before execution.

## Run the four-task Oracle pilot

Assuming the immutable tasks are under `/opt/terminal-bench-v4/tasks`:

```sh
PROJECT=$(pwd)
RELEASE="$PROJECT/.output/cargo-target/release"
EFFECT="$PROJECT/.output/system_effects.bpf.o"
LIFECYCLE="$PROJECT/.output/process_lifecycle.bpf.o"
SELECTION="$PROJECT/experiments/terminal-bench/selected-tasks.json"
IP=/usr/bin/ip
TC=/usr/sbin/tc
NFT=/usr/sbin/nft
RUN_LABEL=pilot-20260915-d

SELECTION_SHA256=0c7ac6d0c450a03d8ff4cca081296cda4964d912c73af76170b1b62ccdd20c20
OBSERVER_SHA256=56a7c7485e14079f607d1f595ee3fe1db2921a25ab101f6e605da1ee0016f8ba
VERIFIER_SHA256=77ac2dd9593d760b50cc685d485d940ed85c3ea5fea8c96a0713e3f7e77b75b8
EFFECT_SHA256=1ef3ee4bf53497d09c556ed38a4c70c5d8e89b84f377581a0f04174a6a17acf8
LIFECYCLE_SHA256=7392a29cd0237759085c312d4205e8310dba0b1cd05a289b302d0f4f4f57bada
IP_SHA256=024784c6d16b183dc7c97d93a943a9270976f167f95f771e14d72442dc657f0c
TC_SHA256=ffc2020f041201283931835bbba41611b286f72f1c606565593b95957450b863
NFT_SHA256=57bdb96c8a48844ddd6dd469c267cda951b9a466be93d254c928891ed8c3b7f0

sudo /opt/harbor-venv/bin/python experiments/terminal-bench/bridge.py \
  --task /opt/terminal-bench-v4/tasks/photonic-waveguide-routing \
  --task /opt/terminal-bench-v4/tasks/cargo-flight-dispatch \
  --task /opt/terminal-bench-v4/tasks/bun-sourcemap-leak \
  --task /opt/terminal-bench-v4/tasks/html-js-filter \
  --selection-manifest "$SELECTION" \
  --selection-manifest-sha256 "$SELECTION_SHA256" \
  --trials-dir "/var/lib/bpf-observer/tbench-trials/$RUN_LABEL" \
  --evidence-root "/var/lib/bpf-observer/tbench-evidence/$RUN_LABEL" \
  --run-label "$RUN_LABEL" \
  --expected-harbor-version 0.23.0 \
  --harbor-source-revision 26f5d8f423786d55a25c5ef4f0eb5869e93ad2df \
  --expected-reward 1.0 \
  --observer-binary "$RELEASE/deployment-observe" \
  --observer-sha256 "$OBSERVER_SHA256" \
  --verifier-binary "$RELEASE/deployment-observe-verify" \
  --verifier-sha256 "$VERIFIER_SHA256" \
  --recorder-object "$EFFECT" \
  --recorder-sha256 "$EFFECT_SHA256" \
  --lifecycle-object "$LIFECYCLE" \
  --lifecycle-sha256 "$LIFECYCLE_SHA256" \
  --ip-binary "$IP" \
  --ip-sha256 "$IP_SHA256" \
  --tc-binary "$TC" \
  --tc-sha256 "$TC_SHA256" \
  --nft-binary "$NFT" \
  --nft-sha256 "$NFT_SHA256" \
  --ready-timeout 180 \
  --finish-timeout 300 \
  --docker-timeout 60 \
  --no-fail-fast
```

Both destination directories must be absent or empty. Choose a new, explicit
`RUN_LABEL` for a subsequent campaign instead of overwriting this pilot.

The process prints one compact campaign JSON object. The durable copy is:

```text
<evidence-root>/campaign-summary.json
```

Each task additionally contains:

```text
<evidence-root>/tbench-<task>-<trial-id>/
  control/
    config.json
    target.json
    ready.external.json
    finish.external.json
    finished.external.json
    verification-expectation.json
    offline-verification.json
    observer-summary.json
    observer.stderr
    verifier.stdout
    verifier.stderr
  observer/
    observation-contract.json
    deployment-manifest.json
    system-effects.raw.bin
    system-effects.jsonl
    process-lifecycle.raw.bin
    process-lifecycle.jsonl
    socket-state.raw.bin
    socket-state.jsonl
    bpf-state-s0.json
    bpf-state-s1.json
    bpf-state-verdict.json
    filesystem-state-s0.json
    filesystem-state-s1.json
    filesystem-state-comparison.json
    linux-state-s0.json
    linux-state-s1.json
    linux-state-comparison.json
    deployment-observation-report.json
    artifact-manifest.json
```

## Unit tests

The pure parsing, cgroup binding, protocol validation, Compose-name, and config
generation logic needs neither Docker nor Harbor:

```sh
python3 experiments/terminal-bench/test_bridge.py
```

## Interpretation

The Oracle is used first because its task solution is deterministic and gives a
known-success baseline. A detected change is not automatically suspicious: it
may be required by the task. Compare Agent runs with this Oracle effect profile,
and retain the raw WAL plus offline-verifier result.

The bridge observes direct callers in the Docker cgroup. Host daemon work,
remote API state, compat/x32, decoded io_uring, delegated effects, and the
Observer's documented partial object cases remain outside the claim. The `/app`
S0/S1 snapshots are sequential endpoint observations, not an atomic whole-Linux
snapshot; identical endpoints remain inconclusive without an exclusive-writer
contract.

Each run also inventories target-Linux BPF Programs and Maps as metadata only,
with Observer-owned objects explicitly excluded. BPF Links, Map contents,
bpffs pins, and attachment targets are not claimed by this campaign. Each run
also confirms eight explicitly named sysctls, the container network
namespace's addresses/routes/rules/qdiscs/classes/filters/nftables state, the
target Linux's complete loaded-module inventory (without module parameters),
mounts, and recursive process residuals. The Docker container is frozen before
the bridge parses bounded `/proc/<init-pid>/net/dev`; its PID, cgroup, mount
namespace, and network namespace are revalidated before that interface set is
committed. Traffic-control class/filter coverage is limited to this initial
explicit interface set; qdiscs are collected namespace-wide. Module state is
host-global, so a delta alone does not establish that the container caused it.

The fully enabled four-task validation for this configuration is recorded in
`../../docs/system-effects-validation-2026-09-15.md` under
`pilot-20260915-d`. Its copied evidence is under
`.output/validation/terminal-bench-docker/pilot-20260915-d/campaign/` from the
Observer project root. All four offline verifications passed. Identical
sysctl/network/module/BPF endpoints are intentionally reported as
`INCONCLUSIVE`, not as proof that no transient or unrelated-host change
occurred.
