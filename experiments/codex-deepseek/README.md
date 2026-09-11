# Codex + DeepSeek agent collection VM

This experiment deploys a pinned Codex CLI into a disposable, networked QEMU
Guest, uses DeepSeek's Responses API as the model provider, and wraps each
non-interactive Codex task in one `bpf-state-observer observe` run.

It is intentionally separate from the authenticated `exclusive-vm-v1`
acceptance gate. The strict Guest has no NIC and admits only measured fixture
executables. This collection Guest has outbound networking, systemd, SSH, and
an API-driven Agent. Therefore its claim mode is
`DIAGNOSTIC_OBSERVED_ONLY`: a persistent, verified BPF endpoint difference is
useful evidence, but an equal S0/S1 result remains `INCONCLUSIVE` and must not
be reported as `UNCHANGED_WITHIN_SCOPE`.

## What is collected

Each task gets a new Observer cgroup and a closed `observer-run/` directory.
The workload root is Codex, so normal descendants used by its shell and patch
tools inherit the same cgroup. The batch keeps:

- Codex `--json` events in the Observer's `workload.stdout`;
- Codex diagnostics in `workload.stderr` and its final message separately;
- attributed `bpf(2)` attempts/completions in `raw-events.jsonl` and the binary
  WAL;
- BPF Program/Map/Link S0 and S1 inventories, evidence health, verdict, and a
  finalized manifest;
- an independent `verify-run` result made again on the Host after extraction;
- root-generated workspace inventories, a before/after diff, and a tar capture
  copied out of the volatile workspace before it is unmounted;
- exact prompts, kernel/Codex/Observer/catalog identities, QEMU argv, and VM
  console logs.

This Observer does not claim to observe ordinary file, process, or network
effects. The workspace diff is separate experiment metadata; it does not
extend the formal BPF claim scope.

The suite admits exactly four fixed task files: two BPF-negative samples
(text-only and a file write) and two transient BPF-positive samples (ephemeral
Map and modify/restore/destroy). Missing, extra, renamed, linked, or writable
task entries fail the suite before authenticated model execution.
`task-contract.txt` binds the ordered names and prompt digests. Before reading
the real credential, the suite sends one invalid-key provider request and runs
a deterministic calibration of the credential launcher and Map fixture.

For a task to pass, `verify-run` must succeed and the additional task validator
must establish all of the following:

- complete transport evidence and complete endpoint state, with no
  completeness reasons or output truncation;
- a finalized zero-exit workload whose bound argv, run ID, epoch, scope, and
  diagnostic `INCONCLUSIVE` verdict match the task contract;
- exactly the expected successful formal BPF command sequence (none for the
  two negative tasks, create/update for the ephemeral task, and
  create/update/update/update for the restore task), plus the native canary;
- a well-formed successful Codex JSONL lifecycle with no error event; and
- no tool item for the text-only task, at least one successful local tool for
  the file task, and exactly one successful shell tool whose parsed argv is the
  requested fixture command for each Map task.

The validator parses JSON with duplicate-key rejection. It does not infer tool
behavior from text searches or accept an event-count match as proof of the BPF
command sequence.

## Security and reproducibility decisions

- Codex is pinned to `0.154.0`; all six files in its Linux x86-64 vendor tree
  are digest checked before the VM starts.
- The DeepSeek setup source and extracted model catalog are fetched over HTTPS
  but accepted only at pinned SHA-256 digests. Their exact bytes are frozen in
  every batch.
- The raw root image is never written. QEMU uses a new qcow2 overlay retained
  with the batch. The runner pins and revalidates both QEMU executables and all
  Host inputs, verifies the exact two-entry overlay-to-raw backing chain, and
  records the final overlay size and SHA-256 in the batch checksum set.
- Codex runs with real/effective/saved UID 65534 and deliberately split group
  IDs: real GID 65534, effective/saved GID 65533. It has no effective,
  permitted, inheritable, or ambient capabilities. Its exact bounding set
  contains only
  `CAP_SYS_ADMIN`, `CAP_PERFMON`, and `CAP_BPF`; the measured Map fixture gains
  only `CAP_BPF` from its file capability and installs its own strict seccomp
  contract before calling `bpf(2)`. Before any deployed payload executes, a
  root-filesystem capability census rejects any other executable that could
  acquire one of those retained capabilities.
- `fs.suid_dumpable=0`, a permanently zero core-size limit, and the split GID
  force Codex to remain nondumpable across its ordinary binary `exec`; this
  avoids relying on `PR_SET_DUMPABLE(0)`, which an ordinary same-credential
  `exec` would reset. A mandatory VM startup test performs that post-`exec`
  transition, starts a real non-privileged Bash child, verifies Bash normalized
  the tool-side IDs to UID/GID 65534, and requires opening the credential-bearing
  parent's `/proc/<pid>/environ` to fail with `EACCES`/`EPERM`.
- `shell_environment_policy` starts from the core environment and enables the
  default secret-name exclusions, so model-launched commands do not receive
  `DEEPSEEK_API_KEY`; an explicit filter excludes that exact name as well.
  Built-in web search is disabled. Codex uses strict config parsing so an
  obsolete or misspelled security setting fails the sample.
- Provider and stream retries are disabled. A failed request remains an
  explicit failed sample instead of silently duplicating a potentially billed
  model call.
- The caller's exported key is copied into a non-exported shell variable and
  removed from the Host environment before QEMU and build tools start. It is
  sent only through encrypted SSH stdin. Each batch gets a distinct tmpfs
  mount below `/run` with `nosuid,nodev,noexec`; the launcher verifies the
  filesystem type, mount identity, ownership, permissions, and flags before
  accepting a key. Swap and core dumps are rejected, the tmpfs is emptied and
  unmounted at suite exit, and an unmount failure fails the suite.
- Every provider-probe and task workspace is a separate 16 MiB tmpfs limited
  to 256 inodes, owned by UID/GID 65534 with mode `0700` and mounted
  `nosuid,nodev,noexec`. Both the runner and credential launcher validate the
  dedicated mount, capacity, inode bound, owner, mode, and flags before Codex
  starts. After validation and postcondition checks it writes a regular
  `workspace.tar` plus checksum into
  the persistent result tree, then requires a successful unmount before
  proceeding. This keeps the workspace bounded without hiding its artifacts
  from the later Host SCP step.

These controls reduce accidental key disclosure; they are not a proof against
a malicious Codex client binary, kernel, root process, or hostile model. This
profile retains the project's cooperative-workload assumption.

## Build and deployment check

From the Observer project directory:

```sh
make agent-collection-check

experiments/codex-deepseek/vm/run-collection.sh \
  --kernel /disk/bpfguard/linux/.output/vm-kernel-script/arch/x86/boot/bzImage \
  --rootfs /disk/zhongxing/images/trixie.img \
  --ssh-key /disk/zhongxing/images/trixie.id_rsa \
  --ssh-port 10042 \
  --deploy-only
```

`--deploy-only` needs no real API key and performs no authenticated inference,
but it does send one request carrying a fixed invalid key. It boots the real
VM, installs Codex and the Observer payload, validates the model catalog,
checks DNS/TCP reachability to `api.deepseek.com:443`, confirms that the
invalid-key Codex request reaches DeepSeek and receives an authentication
rejection, runs `doctor`, runs the six-event BPF calibration, extracts the
result, powers off cleanly, and verifies the copied calibration again on the
Host. The authentication probe is accepted only when strict duplicate-key
JSON parsing finds exactly `thread.started`, `turn.started`, `error`, and
`turn.failed`, in that order, with both failures bound to HTTP 401 and the
DeepSeek Responses endpoint and with no extra retry/error event. The
invalid-key probe has no associated account and incurs no model usage.

## Run the DeepSeek task suite

Do not paste the key into a command-line argument or this repository. The
following block uses Bash; from zsh, enter `bash` first. Read the key silently,
expose it only to the runner process, then unset it:

```bash
cd /disk/bpfguard/linux/tools/bpf/bpf-state-observer

read -rsp 'DeepSeek API key: ' DEEPSEEK_API_KEY
echo

DEEPSEEK_API_KEY="$DEEPSEEK_API_KEY" \
  experiments/codex-deepseek/vm/run-collection.sh \
  --kernel /disk/bpfguard/linux/.output/vm-kernel-script/arch/x86/boot/bzImage \
  --rootfs /disk/zhongxing/images/trixie.img \
  --ssh-key /disk/zhongxing/images/trixie.id_rsa \
  --ssh-port 10042 \
  --model deepseek-flash

unset DEEPSEEK_API_KEY
```

The default is `deepseek-flash`; use `--model deepseek-v4-pro` for the option
the fixed catalog labels as more capable. The runner allows up to ten minutes
per Agent task and retains failed and partial evidence for diagnosis.

## Result layout

The runner prints the exact batch path. By default it is:

```text
.output/agent-collection/<UTC-timestamp>-<pid>/
├── host-summary.txt
├── host-input-identities.txt
├── host-input-revalidation.txt
├── overlay-identity.txt
├── overlay-validation.txt
├── inputs/                         frozen Observer/catalog/task inputs
├── collection-root-overlay.qcow2  deployed disposable Guest
├── guest-results/
│   ├── collection-contract.txt
│   ├── task-contract.txt
│   ├── doctor.json
│   ├── calibration/observer-run/
│   ├── summary.tsv
│   └── tasks/<task>/
│       ├── prompt.txt
│       ├── workspace.before
│       ├── workspace.after
│       ├── workspace.diff
│       ├── workspace.mountinfo
│       ├── workspace.tar
│       ├── workspace.tar.sha256
│       ├── last-message.txt
│       ├── verify.json
│       ├── task-validation.json
│       ├── host-verify.json
│       └── observer-run/
└── BATCH_SHA256SUMS
```

`summary.tsv` always contains one header and the four fixed task rows. Consume
it only after `guest_status=0`, `host_verify_status=0`, `overlay_status=0`, and
`host_input_status=0` in `host-summary.txt`. The formal source of truth for
one observation remains its finalized manifest plus a successful
`verify-run`, not `verdict.json` by itself. A row is accepted only when its
`task_status` is `PASS`; this includes the explicit `workspace_capture` gate,
and the preceding columns retain each individual gate for diagnosis.
`summary.tsv` and `tasks/` are created only in live `run` mode; a
`--deploy-only` batch ends after the calibration and provider-authentication
probe.

The latest real-VM deployment/calibration result is recorded in
[VALIDATION.md](VALIDATION.md).
