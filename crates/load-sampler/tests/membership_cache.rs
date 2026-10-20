// SPDX-License-Identifier: GPL-2.0-only
//! Native replay of the actual task-state transition function. The ancestor
//! resolver is stubbed; this test proves cache use and migration invalidation,
//! not that procfs path depth proves an initial cgroup namespace.
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn actual_task_state_cache_rechecks_leaf_identity_and_invalidates_cross_domain_spans() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("bpf/kernel_hist.bpf.c")).unwrap();
    let structure = source
        .split_once("struct kh_task {")
        .unwrap()
        .1
        .split_once("};")
        .unwrap()
        .0;
    let task_function = source
        .split_once("static __always_inline struct kh_task *kh_task(struct task_struct *task)")
        .unwrap()
        .1
        .split_once("static __always_inline struct kh_task *kh_current_task(void)")
        .unwrap()
        .0;
    let harness = format!(
        r#"
#include <linux/types.h>
#include <assert.h>
#include <string.h>
#include "kernel_hist.h"
#undef __always_inline
#define __always_inline inline __attribute__((always_inline))
#define BPF_CORE_READ(task, ...) ((task)->leaf_id)
#define BPF_LOCAL_STORAGE_GET_F_CREATE 1
struct kh_task {{{structure}}};
struct task_struct {{ __u64 leaf_id; }};
static struct kh_task storage;
static int kh_tasks, allocated, fail_storage, resolver_calls;
static __u64 counters[KH_MAX_DOMAINS][KH_COUNTERS];
static int kh_cfg(void) {{ return 1; }}
static void kh_count(__u32 mask, __u64 counter) {{
    for (unsigned int i = 0; i < KH_MAX_DOMAINS; i++)
        if (mask & (1U << i)) counters[i][counter]++;
}}
static struct kh_task *bpf_task_storage_get(void *map, struct task_struct *task, void *value, int flags) {{
    (void)task; (void)value; assert(map == &kh_tasks);
    if (fail_storage) return 0;
    if (!allocated && flags == BPF_LOCAL_STORAGE_GET_F_CREATE) {{
        allocated = 1; memset(&storage, 0, sizeof(storage));
    }}
    return allocated ? &storage : 0;
}}
static __u32 kh_task_matches(struct task_struct *task) {{
    resolver_calls++;
    return task->leaf_id == 1 ? 3 : task->leaf_id == 2 ? 5 : 0;
}}
static __always_inline struct kh_task *kh_task(struct task_struct *task)
{task_function}
int main(void) {{
    struct task_struct task = {{ .leaf_id = 1 }};
    assert(kh_task(&task) == &storage && storage.domain_mask == 3);
    assert(resolver_calls == 1 && counters[0][KH_C_TASK_ENROLLED] == 1 && counters[1][KH_C_TASK_ENROLLED] == 1);
    storage.syscall_ts = 123; storage.fault_ts = 456; storage.oncpu_ts = 789;
    for (int i = 0; i < 1000; i++) assert(kh_task(&task) == &storage);
    assert(resolver_calls == 1 && storage.syscall_ts == 123);
    task.leaf_id = 2;
    assert(kh_task(&task) == &storage && storage.cgroup_id == 2 && storage.domain_mask == 5);
    assert(resolver_calls == 2 && !storage.syscall_ts && !storage.fault_ts && !storage.oncpu_ts);
    assert(counters[0][KH_C_TASK_ENROLLED] == 1 && counters[2][KH_C_TASK_ENROLLED] == 1);
    for (int i = 0; i < 3; i++) assert(counters[i][KH_C_DOMAIN_CHANGE] == 1);
    storage.lock_ts = 100;
    task.leaf_id = 3;
    assert(!kh_task(&task) && !storage.cgroup_id && !storage.domain_mask && !storage.lock_ts);
    assert(counters[0][KH_C_DOMAIN_CHANGE] == 2 && counters[2][KH_C_DOMAIN_CHANGE] == 2);
    task.leaf_id = 2; assert(kh_task(&task) == &storage);
    assert(counters[0][KH_C_TASK_ENROLLED] == 2 && counters[2][KH_C_TASK_ENROLLED] == 2);
    storage.exited = 1; int before = resolver_calls;
    assert(!kh_task(&task) && before == resolver_calls);
    allocated = 0; fail_storage = 1; task.leaf_id = 1;
    assert(!kh_task(&task) && counters[0][KH_C_STORAGE_MISS] == 1 && counters[1][KH_C_STORAGE_MISS] == 1);
    return 0;
}}
"#
    );
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("kh-membership-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("replay.c");
    let binary = dir.join("replay");
    fs::write(&path, harness).unwrap();
    let compile = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("bpf"))
        .arg(&path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    fs::remove_dir_all(dir).unwrap();
}
