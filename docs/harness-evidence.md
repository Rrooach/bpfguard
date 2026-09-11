# Authenticated harness evidence

`exclusive-vm-v1` is implemented as an authenticated, run-bound, four-phase
protocol. It is the only input that can turn a complete, empty S0/S1 diff into
`UNCHANGED_WITHIN_SCOPE`. It does not turn the Observer into a sandbox and it
does not make an unenforced Host policy true.

There are two intentionally different input paths:

- `observe --harness-channel ...` uses the authenticated protocol. The Host
  keeps the Ed25519 private key and an exclusive harness lease; the Guest
  receives only the public key and reaches `bpf-harnessd` through a QEMU
  virtio-serial character device.
- `observe --harness-evidence FILE` and `snapshot --quiescence FILE` accept
  static JSON only for diagnosis. Even a well-shaped caller claim with
  `basis=HARNESS_ENFORCED` is given a failed `observer_binding` check,
  downgraded to `status=UNKNOWN`, and stripped of exclusive attribution. A
  hand-authored, replayed, or pre-run file cannot unlock `UNCHANGED`.

The two paths conflict on `observe`; they must not be combined.

## Trust and protocol boundary

`bpf-harnessd` listens on a create-new, mode-0600 Host Unix socket. QEMU joins
that socket to the Guest port `/dev/virtio-ports/org.allox.harness`. The
private key never enters the Guest. The daemon accepts one transport
connection, keeps a lease from `PRE_S0` through the verified `FINAL_ACK`,
rejects an overlapping session and nonce replay, and serves the policy's exact
ordered one-shot workload list with `--max-sessions`.

That lease serializes authenticated sessions; it does not by itself prevent an
unmanaged Host or Guest actor from executing. The VM/orchestrator controls
represented by the signed checks must provide that isolation.

Every response is Ed25519-signed over a domain-separated, length-prefixed,
deterministic representation. All four responses repeat the exact run binding,
key fingerprint, policy ID, and canonical policy SHA-256:

1. `PRE_S0` (sequence 1) authorizes the measured run before S0.
2. `S0_COMMITTED` (sequence 2) signs the exact `s0.json` SHA-256.
3. `PRE_S1` (sequence 3) requires the workload cgroup to be empty and frozen
   and signs the pre-S1 `health.json` SHA-256.
4. `FINAL` (sequence 4) signs S0, S1, final health, canary health, raw WAL,
   derived JSONL, and the retained (possibly truncated) workload stdout and
   stderr SHA-256 values; the successful normal workload exit; the closing
   barrier booleans; the kernel-side count of `bpf()` attempts outside the
   exact Observer TGID and registered workload cgroup (which must be zero);
   and exactly the 12 passing contract checks.

After validating the complete signed transcript, the Guest sends one bounded
`FINAL_ACK` containing the nonce, run identity, and canonical SHA-256 of the
signed `FINAL` response. The Host does not consume that one-shot workload
authorization or start the next ordered session before the exact ACK arrives.
This closes transport truncation at the virtio-serial boundary; it is not an
additional trust claim or a Guest signature.

The shared binding includes a fresh 32-byte nonce; run ID and epoch; cgroup ID
and canonical path; boot ID; Host-authorized kernel/rootfs identity; exact
Observer, recorder, effective-scope, and workload-executable SHA-256 values;
exact workload argv; the Observer-owned exclusion-set digest; and deterministic
S0/S1 snapshot IDs. No prefix, wildcard, or pathname-only workload
authorization exists. A Host policy authorizes the exact
`{run_id, run_epoch, cgroup_path, argv, executable_sha256}` tuple.

The exclusion IDs are necessarily dynamic: recorder-owned BPF Program/Map/Link
IDs do not exist until the recorder is loaded. Therefore a policy cannot
pre-list their digest. It must declare
`observer_exclusions_derivation=MEASURED_OBSERVER_RECORDER_OWNED_V1`, authorize
the exact Observer and recorder bytes, and rely on that measured cooperative
Observer to derive the set. The Host nevertheless signs the exact dynamic
digest in all four phases, and `verify-run` recomputes it from the finalized
manifest. This is an explicit trust step, not proof against a malicious Guest.

The canonical name list and protocol summary are in
[`../config/exclusive-vm-v1.json`](../config/exclusive-vm-v1.json). The old
static diagnostic shape remains in
[`../config/harness-evidence.schema.json`](../config/harness-evidence.schema.json);
it is not the authenticated wire protocol.

## Required Host policy checks

A signed `FINAL` response contains exactly one passing, non-empty-evidence
entry for every name below:

| Check | Required meaning |
|---|---|
| `exclusive_vm` | VM/image policy prevents a second workload actor |
| `no_other_bpf_actors` | no background BPF manager can mutate the scope |
| `no_external_bpf_fds` | no inherited or retained external BPF FDs |
| `scm_rights_blocked` | BPF FD transfer over Unix sockets is enforced away |
| `pidfd_getfd_blocked` | pidfd-based FD duplication is enforced away |
| `writable_map_mmap_blocked` | retained writable Map mappings are excluded |
| `cgroup_empty` | recursive `cgroup.events` says `populated 0` before S1 |
| `attachment_dependency_closure_complete` | every declared target and writer dependency is covered |
| `special_map_values_excluded` | timers, workqueues, locks, kptr/uptr and similar semantics are excluded or understood |
| `prog_test_run_blocked` | program test-run interfaces are blocked during the interval |
| `new_bpf_loaders_blocked` | actors outside the workload cannot load BPF state |
| `in_flight_bpf_barrier_complete` | relevant BPF execution has drained before S1 |

For the repository VM acceptance suite, the recorder's raw-syscall programs
remain armed from before authenticated `PRE_S0` through receipt of `FINAL`.
They count every `bpf()` attempt outside the exact Observer TGID and currently
registered run cgroup. Closing the window first detaches both tracepoint links
(the kernel synchronization barrier) and only then reads the monotonically
increasing counter. A real negative probe creates and destroys a transient
HASH Map from another TGID and must be rejected at that production boundary.

The signature proves that the holder of the trusted Host key signed these
claims and exact bindings. The VM launcher still has to enforce the claims.
The strict suite does that with a measured static PID 1, a read-only
provisioned root disk, a separate fresh evidence disk, no NIC/SSH/systemd, an
exact process and BPF-FD census, irreversibly disabled unprivileged BPF, and
capability-checked workloads. A policy containing optimistic prose is not
equivalent to those controls.

## Step-by-step CLI

Build both binaries first:

```sh
make release
OBSERVER=.output/cargo-target/release/bpf-state-observer
HARNESSD=.output/cargo-target/release/bpf-harnessd
```

On the trusted Host, generate a key once for the test authority. Both output
paths must be new; keep the secret path outside the Guest and workload trust
domains:

```sh
install -d -m 0700 /var/lib/bpf-observer/harness
"$HARNESSD" keygen \
  --secret-key /var/lib/bpf-observer/harness/host.secret \
  --public-key /var/lib/bpf-observer/harness/host.public
```

Measure the exact files that will be copied into the Guest. Use the same
canonical JSON algorithm as the Observer for parsed scope inputs:

```sh
RECORDER=.output/recorder.bpf.o
WORKLOAD_IMAGE=.output/workloads/exclusive-noop
OBSERVER_SHA256=$(sha256sum "$OBSERVER" | awk '{print $1}')
RECORDER_SHA256=$(sha256sum "$RECORDER" | awk '{print $1}')
WORKLOAD_SHA256=$(sha256sum "$WORKLOAD_IMAGE" | awk '{print $1}')
SCOPE_SHA256=$("$HARNESSD" canonical-json-digest \
  --input config/exclusive-vm-scope.json)
```

Create a typed harness policy containing those digests, the 12 checks, exact
measured kernel/rootfs identity, and one or more exact run/workload
authorizations. It must also set
`observer_exclusions_derivation` to
`MEASURED_OBSERVER_RECORDER_OWNED_V1`. Then validate and digest the complete
policy:

```sh
POLICY=/var/lib/bpf-observer/harness/policy.json
POLICY_SHA256=$("$HARNESSD" policy-digest --policy "$POLICY")
```

`config/exclusive-vm-v1.json` describes the contract; it is not itself a
serve-ready policy. The [reproducible E2E runner](../vm/run-e2e.sh) shows a
complete exact policy with three authorized runs.

Start the Host signer in a dedicated terminal before QEMU. One Guest run
consumes one four-phase session:

```sh
HARNESS_SOCKET=/var/lib/bpf-observer/harness/channel.sock
"$HARNESSD" serve \
  --socket "$HARNESS_SOCKET" \
  --secret-key /var/lib/bpf-observer/harness/host.secret \
  --policy "$POLICY" \
  --max-sessions 1
```

Connect QEMU's Host socket to the Guest virtio-serial port with a chardev named
`harness` and a virtserialport named `org.allox.harness` by including:

```text
-chardev socket,id=harness,path=/var/lib/bpf-observer/harness/channel.sock
-device virtio-serial-pci
-device virtserialport,chardev=harness,name=org.allox.harness
```

See the
[VM E2E instructions](../vm/README.md) for the full
QEMU command, image requirements, policy generation, and cleanup rules.

Copy only `host.public`, the Observer inputs, and the externally obtained
policy ID, policy digest, and kernel identity into the trusted Guest launcher.
The authenticated workload path must already be canonical, and every option in
the following group is mandatory:

```sh
GUEST_OBSERVER=/opt/bpf-state-observer/bpf-state-observer
WORKLOAD=$(realpath /opt/bpf-state-observer/exclusive-noop)
sudo "$GUEST_OBSERVER" observe \
  --scope /opt/bpf-state-observer/exclusive-vm-scope.json \
  --recorder-object /opt/bpf-state-observer/recorder.bpf.o \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256" \
  --output-dir /var/lib/bpf-observer/runs/exclusive-1 \
  --run-id exclusive-1 \
  --run-epoch 1101 \
  --harness-channel /dev/virtio-ports/org.allox.harness \
  --harness-public-key /opt/bpf-state-observer/host.public \
  --harness-policy-id "$HARNESS_POLICY_ID" \
  --expected-harness-policy-sha256 "$POLICY_SHA256" \
  --harness-kernel-identity "$HARNESS_KERNEL_IDENTITY" \
  -- \
  "$WORKLOAD" --exclusive-contract
```

The run ID, epoch, resulting cgroup path, argv, and executable digest must
exactly match one `allowed_workloads` policy entry. The policy also has to
authorize the actual Observer, recorder, scope, and kernel identity.

Offline verification of an authenticated run fails closed unless all four
external trust inputs are supplied together. Do not recover these values from
the run directory being verified:

```sh
"$OBSERVER" verify-run \
  --run-dir /var/lib/bpf-observer/runs/exclusive-1 \
  --expected-recorder-sha256 "$TRUSTED_RECORDER_SHA256" \
  --harness-public-key /var/lib/bpf-observer/harness/host.public \
  --harness-policy-id "$HARNESS_POLICY_ID" \
  --expected-harness-policy-sha256 "$POLICY_SHA256" \
  --harness-kernel-identity "$HARNESS_KERNEL_IDENTITY"
```

`verify-run` verifies the full artifact set, reconstructs the binding and phase
evidence from the manifest and artifacts, authenticates all four signatures,
and compares the external key, policy ID/digest, and kernel identity. Supplying
only a public key is not sufficient.

## Meaning of `UNCHANGED_WITHIN_SCOPE`

Authenticated evidence makes `UNCHANGED_WITHIN_SCOPE` reachable only when all
other inventory, content, transport, health, and comparison completeness gates
also pass. It means no endpoint delta was confirmed between S0 and S1 within
the declared observation scope and closed model.

It does **not** mean "the workload performed no BPF operation." A workload can
create, use, and destroy transient state between the two snapshots. Native
`bpf(2)` events expose some such activity, but they do not cover non-`bpf(2)`
paths or state outside the selected scope. Never translate `UNCHANGED` directly
into rollback `CLEAN`.

## Static diagnostic example

```json
{
  "status": "UNKNOWN",
  "basis": "OBSERVED_ONLY",
  "contract_id": null,
  "checks": [
    {
      "name": "cgroup_empty",
      "passed": true,
      "evidence": "diagnostic observation supplied by caller"
    }
  ],
  "exclusive_actor_attribution": false
}
```

`basis=ASSUMED` records an assumption. `basis=OBSERVED_ONLY` records an
observation without enforcement. Neither supports `UNCHANGED`. The fixture
[`../tests/fixtures/quiescence-observed-only.json`](../tests/fixtures/quiescence-observed-only.json)
shows this safe diagnostic default.
