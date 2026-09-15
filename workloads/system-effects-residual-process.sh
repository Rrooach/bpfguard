#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only

# Negative fixture: the root exits successfully while a descendant remains in
# the run cgroup.  The runner must time out/fence and must not finalize a false
# empty-process confirmation.

set -euo pipefail

/usr/bin/setsid /usr/bin/sleep 300 </dev/null >/dev/null 2>&1 &
printf '%s\n' '{"system_effects_residual_process":"spawned"}'
