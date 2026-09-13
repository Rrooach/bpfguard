# System-effects observer overhead benchmark

This experiment measures the system-effects event collector through a small
wrapper contract rather than coupling the runner to one command-line layout.
It is intentionally
separate from `experiments/overhead`, which measures the current BPF-state
snapshot and raw `bpf(2)` recorder pipeline.

## What is compared

Each block runs four treatments for every offered-load point:

| Treatment | Workload | Collector |
|---|---|---|
| `quiet-direct` | five harmless `getpid(2)` calls per iteration | off |
| `quiet-observed` | the identical quiet workload | on |
| `effect-direct` | create, write, close, rename, and unlink in tmpfs | off |
| `effect-observed` | the identical effect workload | on |

The direct effect arm controls for the cost of producing the effects.  The
primary event-pipeline contrast is the paired difference in differences:

```text
[(effect-observed - effect-direct) -
 (quiet-observed - quiet-direct)] at N
minus the same contrast at N=0
```

Dividing that contrast by the collector-reported increase in persisted events
gives a full-pipeline cost per event.  It includes matching, transport,
userspace decoding, output, drain, and finalization.  It is not the cost of an
individual kernel probe instruction.  The quiet contrast is reported
separately as the attached-but-no-event cost.

The file workload uses two fixed names in a private tmpfs directory, leaves no
file behind, performs no `fsync(2)`, and pauses between batches.  This keeps the
offered load controlled and avoids storage latency and unbounded inode growth.
Five quiet syscalls are issued per iteration so the empty-hit arm has the same
syscall count as the effect arm.  The syscall types necessarily differ; this
limitation must be retained in any result report.

## Build and local smoke check

No existing Makefile is changed.  Run:

```sh
bash experiments/system-effects-overhead/check.sh
bash experiments/system-effects-overhead/check-bpf-fast-path.sh \
  .output/system_effects.bpf.o
```

The check compiles the two small C helpers in a temporary directory and tests
the workload and wrapper protocol.  `passthrough-wrapper.sh` is only a wiring
fixture: it reports zero events and therefore cannot produce an accepted
event-cost result.

The compiled-BPF check pins two low-cost global off-path invariants for the
project's clang/LLVM 14 build: `file_permission` remains a 12-instruction
filtering wrapper with no stack work on the read/off path, and `sys_enter`
performs its policy-Map lookup before any wide event-structure initialization.
It is a regression gate, not a runtime latency measurement; the paired VM
benchmark below remains authoritative for end-to-end overhead.

## Collector wrapper contract

Pass an executable adapter with `--observer-wrapper`.  The runner invokes it
as:

```text
WRAPPER --result-dir DIR \
        --workload-stdout FILE --workload-stderr FILE -- COMMAND ARG...
```

The wrapper must:

1. start and fully initialize the collector before `COMMAND` executes;
2. run exactly that command and preserve its exit status;
3. place the command's stdout and stderr at the requested paths;
4. finish/drain the collector before returning;
5. create `DIR/metrics.json` as exactly one JSON object with these fields:

```json
{
  "schema_version": 1,
  "collector_identity": "build-and-scope-digest-or-equivalent",
  "evidence_status": "complete",
  "events_persisted": 0,
  "events_dropped": 0,
  "bytes_persisted": 0
}
```

`collector_identity` must bind the collector build and effective scope and must
be identical throughout the batch.  Counters must describe only the formal
workload window, excluding canaries, warm-up traffic, and setup.
`events_persisted` is the denominator used by the analysis.  A dropped event,
incomplete evidence, malformed metric, non-zero command status, or missing
sample invalidates the entire batch.  Raw collector evidence should remain
below `DIR`; the benchmark never rewrites it.

The wrapper and collector must run outside the workload cgroup if termination
of that cgroup is one of the effects under test.  The result tree must not be
visible or writable by the workload.  If the collector has a global singleton
recorder, serialize batches outside this runner.

`observer-wrapper.sh` implements this contract for `observe-effects`. It
requires these environment variables:

```text
BPF_STATE_OBSERVER_BIN                 absolute Observer binary
BPF_STATE_OBSERVER_EFFECTS_OBJECT      absolute system_effects.bpf.o
BPF_STATE_OBSERVER_EFFECTS_SHA256      trusted lowercase object SHA-256
BPF_STATE_OBSERVER_EFFECTS_PROFILE     control|balanced|full (default balanced)
BPF_STATE_OBSERVER_EFFECTS_OBJECT_RESOLUTION
                                        user-input|kernel-file-open-partial|
                                        kernel-file-open-write-partial
                                        (default user-input)
```

That `balanced` default belongs to this benchmark adapter, not to the Observer
CLI (whose low-overhead default is `control`). The file-effect benchmark needs
`balanced` so its write operations create the event-count denominator.
Object-resolution mode is part of `collector_identity`, so results from the
raw syscall path, the global BPF-LSM file-open hook, and the additional global
`file_permission` hook cannot be mixed in one batch. Each partial-kernel mode
must first pass `doctor` on a BTF+BPF-LSM kernel. In particular, an open-only
result is not evidence for write-partial overhead; run and report that mode as
a separate experiment.

The optional `BPF_STATE_OBSERVER_EFFECTS_CGROUP_ROOT`,
`BPF_STATE_OBSERVER_EFFECTS_TIMEOUT_MS`, and
`BPF_STATE_OBSERVER_EFFECTS_DRAIN_TIMEOUT_MS` variables override the runtime
defaults. The adapter accepts only `COMPLETE`, lossless, drained evidence. Its
event count includes both attempt and result records; `bytes_persisted` is the
combined WAL and JSONL size. It retains the unchanged Observer evidence below
`DIR/evidence` and writes benchmark-only `metrics.json` beside it.

The adapter does not add a UID, user namespace, or mount namespace before the
Observer starts the command. The supplied benchmark workload is a fixed,
cooperative fixture; for any adversarial workload, the VM launcher must also
make the result tree inaccessible and drop workload privilege. Do not treat a
successful benchmark batch as evidence that this isolation exists.

## Run

Build the helpers into a disposable directory, then run a batch.  Both helper
paths and the wrapper must be absolute so the recorded configuration is
unambiguous.

```sh
cc -O2 -std=c11 -Wall -Wextra -Werror \
  experiments/system-effects-overhead/system-effects-workload.c \
  -o /tmp/system-effects-workload
cc -O2 -std=c11 -Wall -Wextra -Werror \
  experiments/system-effects-overhead/measure-command.c \
  -o /tmp/system-effects-measure

export BPF_STATE_OBSERVER_BIN="$(realpath .output/cargo-target/release/bpf-state-observer)"
export BPF_STATE_OBSERVER_EFFECTS_OBJECT="$(realpath .output/system_effects.bpf.o)"
# For a local smoke test only. Publish this value from a trusted build manifest
# for a real measurement.
export BPF_STATE_OBSERVER_EFFECTS_SHA256="$(sha256sum "$BPF_STATE_OBSERVER_EFFECTS_OBJECT" | awk '{print $1}')"
export BPF_STATE_OBSERVER_EFFECTS_PROFILE=balanced

# Run the whole collection at one privilege level so the direct and observed
# arms remain comparable.
sudo --preserve-env=BPF_STATE_OBSERVER_BIN,BPF_STATE_OBSERVER_EFFECTS_OBJECT,BPF_STATE_OBSERVER_EFFECTS_SHA256,BPF_STATE_OBSERVER_EFFECTS_PROFILE \
  bash experiments/system-effects-overhead/run.sh \
  --output /var/lib/system-effects-overhead/run-001 \
  --workload /tmp/system-effects-workload \
  --measure /tmp/system-effects-measure \
  --observer-wrapper "$(realpath experiments/system-effects-overhead/observer-wrapper.sh)" \
  --scratch-parent /dev/shm \
  --repetitions 12 \
  --iterations 0,256,1024,4096

node experiments/system-effects-overhead/analyze.js \
  /var/lib/system-effects-overhead/run-001 \
  /var/lib/system-effects-overhead/run-001/report.json \
  /var/lib/system-effects-overhead/run-001/REPORT.md
```

Measured repetitions must be a multiple of four (4 through 48).  Four Williams-order rows
balance first-order carryover among the four treatments.  Load-point order is
rotated by block.  One four-block warm-up cycle is excluded by default.  Use
at least 12 measured blocks; increase to 20 or 24 if the interval gate rejects
the result.  Do not silently discard outliers or failed samples.

Pinning is deliberately optional because CPU topology and the collector's
threading model belong to the eventual integration.  For publishable results,
pin the controller/collector and workload to separate Guest vCPUs in the
adapter or VM harness, record that policy alongside the batch, and use the same
disposable KVM for all treatments.

## Acceptance and claims

The analyzer reports medians and an exact distribution-free 95% median
interval.  A per-event estimate is accepted only when all samples are complete
and lossless, at least 12 paired blocks exist, at least 80% of block slopes are
positive, the interval excludes zero, its width is no more than the estimate,
median persisted event count increases at every offered-load point, and each
block's quiet-event count is invariant with load.  The latter gate checks that
the nominal empty-hit workload did not silently become an event source.

An accepted result applies only to the named effect workload, collector build,
scope, output durability policy, Guest kernel, vCPU layout, and tested load
range.  It is not a maximum-throughput result and does not establish overhead
for process, network, mount, or device events.

The benchmark workload is intentionally compatible with the `balanced`
profile. Changing to `control` removes the write-event denominator; changing
to `full` changes both the selected syscall set and startup noise. Treat either
as a different experiment, not as a directly comparable configuration.
