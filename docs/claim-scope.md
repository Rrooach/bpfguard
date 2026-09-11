# Claim-scope semantics

The claim scope is a closed declaration of what the caller asks the Observer to
measure. It is not a best-effort filter and must not be silently narrowed.

The serialized shape is defined by `bpf-observer-schema::ClaimScope`; the
repository's default CLI scope file is
[`../config/default-scope.json`](../config/default-scope.json). Rust's
`ClaimScope::default()` is a library-safe empty-command baseline, not a
byte-for-byte copy of that file.

## Requested and effective scope

Every run should persist both:

- `requested_scope`: the caller's immutable request;
- `effective_scope`: the adapters that passed startup self-check;
- `scope_accepted`: explicit confirmation of the effective scope.

The current manifest records both scopes. This baseline implements no scope
downgrade negotiation: they are equal, `scope_accepted=true`, or startup
fails. S0/S1 also embed the effective scope and `verify-run` binds them back to
the finalized manifest.

## Field meanings

### `event_interfaces`

Declares causal evidence channels. `BPF_USER_SYSCALL` covers only userspace
`bpf(2)` calls from tasks attributed to the registered cgroup/run epoch. It does
not cover VFS, netlink, ioctl, FD lifecycle, or kernel-internal operations.

### `allowed_bpf_commands`

Numeric UAPI commands for which the run expects event coverage. An empty set
means no command-specific evidence guarantee, not all commands. Every observed
command outside a non-empty allowed set must be persisted and reported as
unsupported; the implementation may not ignore it.

### `object_types`

Selects endpoint inventory classes: `PROGRAM`, `MAP`, and `LINK`. Identity is
`{boot_id, object_type, id}`. IDs are only meaningful within one boot and do not
fully solve rapid delete/recreate ABA.

### `map_content_types`

The default scope leaves this set empty and is therefore metadata-only. The
four values below are supported only when a caller explicitly opts in.

Only the following types have content semantics in the MVP:

| Scope value | Kernel type | Canonical representation |
|---|---:|---|
| `HASH` | 1 | entries sorted by raw key bytes |
| `ARRAY` | 2 | every index, including zero-valued entries |
| `PERCPU_HASH` | 5 | sorted key plus value for every possible CPU |
| `PERCPU_ARRAY` | 6 | every index and possible CPU value |

For per-CPU Maps, kernel buffers use an eight-byte-aligned stride, but only
`value_size` semantic bytes per CPU are hashed. Padding must be discarded.
Possible CPU IDs, byte order, key/value sizes, and budgets belong to the
snapshot.

Map types outside these four remain in object inventory when `MAP` is selected,
but their content state is `OUTSIDE_CLAIM_SCOPE`. `UNSUPPORTED_TYPE` is reserved
for a selected type that this sampler cannot implement. HASH batch rejection
alone is not such a case: the implementation falls back to `GET_NEXT_KEY`.
Neither status can support an unchanged content claim.

### `map_ids`

A non-empty set restricts content sampling to the listed IDs. An empty set
selects every Map whose type is in a non-empty `map_content_types`; when
`map_content_types` is also empty, no contents are sampled. Wildcard content
sampling can be expensive, so production callers should normally supply
explicit IDs and budgets. The repository's
`config/map-content-scope.example.json` contains a placeholder ID that must be
replaced.

Observer-owned Maps remain in raw inventory with `excluded=true` but their
contents are not sampled. If an explicit `map_ids` request contains one of
those IDs, `observe` fails instead of silently narrowing the request.

### `bpffs_roots`

Only declared, lexically normalized canonical roots are traversed (no `.`,
`..`, duplicate separator, trailing separator, symlink resolution, or
overlapping roots). Every successfully opened root is retained in the
snapshot with its canonical path, mount-namespace inode, and root
`statx(STATX_MNT_ID)`, even when it contains no pins. Each pin identity uses
exact absolute path bytes (`path_bytes_hex`) and a per-entry mount ID; `path`
is a lossy display field only. Empty means no pin claim. Symlinks, nested/bind
mounts, unavailable mount IDs, unreadable entries, or the hard traversal cap
make that adapter incomplete.

### `attachment_targets`

A global link list is not a substitute for target attachment state. Empty means
no attachment claim. The integrated `observe` command currently rejects any
non-empty list. Standalone capture records the request, and the comparator
marks a comparison using it incomplete because no target adapter exists.

### `budget`

- `max_map_entries`: maximum semantic entries sampled per Map;
- `max_map_bytes`: maximum semantic key/value bytes retained per Map;
- `per_map_deadline_ms`: elapsed-time deadline for one Map.

Exceeding a budget returns `TRUNCATED_RESOURCE_LIMIT`. Partial data may be kept
for diagnostics but is never semantically complete.

Configuration is rejected unless entries are in `1..=65536`, bytes in
`1..=64 MiB`, and the per-Map deadline is in `1..=60000 ms`. Independent hard
caps bound each object-type inventory to 65536 IDs, the possible-CPU topology
to 8192 CPUs, all Program-to-Map reference edges to 262144, each pin inventory
scan across all configured roots to 65536 visited items and 64 MiB of
traversal/stored path representation, total Map content to 131072 entries/128
MiB of logical bytes/64 MiB of conservatively estimated retained
representation, and aggregate Map sampling time to 60 seconds. Scope
collections and diagnostic output are bounded too. A caller cannot disable
these caps with enormous JSON values.

## Stable comparison fields

The comparator includes stable identity and configuration fields and excludes
volatile counters such as program run time/run count. Map content is compared
using canonical raw bytes. A nonzero map-local or vmlinux BTF value type is
currently returned as `OPAQUE_VALUE`; the implementation does not claim to understand timers, locks,
kptrs, or other kernel-managed fields. It also compares `frozen` obtained
from `/proc/self/fdinfo/<map-fd>` because `bpf_map_info` does not expose it.

Temporary `GET_FD_BY_ID` descriptors are closed immediately after reading.
The snapshot records only the overall capture duration; it does not record
per-FD hold intervals. These temporary references can perturb reference-based
metadata, which is why such counters are excluded from stable comparison.

## Completeness rules

The following are not equivalent to absence:

- permission denied;
- object disappeared during enumeration;
- unsupported object or link type;
- unresolved target or mount identity;
- resource truncation;
- concurrent mutation;
- missing `frozen` state for a selected Map.

Each produces a typed status/read failure and taints completeness. Double
inventory can detect some concurrent changes but cannot prove that ABA did not
occur; this release has no dedicated runtime classification for undetected ID
reuse.
