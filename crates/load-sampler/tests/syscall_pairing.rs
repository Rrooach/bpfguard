// SPDX-License-Identifier: GPL-2.0-only
//! Replay the exact selected-syscall transition functions, not a reimplementation.
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

#[test]
fn actual_syscall_functions_only_censor_proven_initial_successful_child_return() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("bpf/kernel_hist.bpf.c")).unwrap();
    let state = source
        .split_once("struct kh_task {")
        .unwrap()
        .1
        .split_once("};")
        .unwrap()
        .0;
    let funcs = source
        .split_once("static __always_inline void kh_sys_enter_value")
        .unwrap()
        .1
        .split_once("SEC(\"tp_btf/sys_enter\")")
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
struct kh_task {{{state}}};
static struct kh_task task;
static struct kh_config cfg = {{ .enabled = 1 }};
static __u32 classes[KH_SYSCALL_SLOTS];
static int kh_syscall_class;
static __u64 counters[KH_COUNTERS], hist_count, timestamp = 100;
static struct kh_config *kh_cfg(void) {{ return &cfg; }}
static struct kh_task *kh_current_task(void) {{ return &task; }}
static struct kh_task *kh_task(void *ignored) {{ (void)ignored; return &task; }}
static void *bpf_get_current_task_btf(void) {{ return 0; }}
static __u32 *bpf_map_lookup_elem(void *map, __u32 *key) {{ assert(map == &kh_syscall_class); return &classes[*key]; }}
static __u64 bpf_ktime_get_ns(void) {{ return ++timestamp; }}
static void kh_count(__u32 mask, __u64 counter) {{ assert(mask == 1); counters[counter]++; }}
static void kh_record(__u32 mask, __u64 metric, __u64 begin, __u64 end) {{
    assert(mask == 1 && metric == KH_SYSCALL_OTHER && end > begin); hist_count++;
}}
static __always_inline void kh_sys_enter_value{funcs}
int main(void) {{
    task.domain_mask = 1;
    for (unsigned int i = 0; i < KH_SYSCALL_SLOTS; i++) classes[i] = KH_SYSCALL_CLASSES - 1;
    task.newborn = 1; kh_sys_exit_value(56, 0);
    assert(counters[KH_C_INITIAL_CHILD_RETURN_CENSORED] == 1 && !counters[KH_C_UNPAIRED] && !task.newborn);
    kh_sys_exit_value(56, 0);
    assert(counters[KH_C_UNPAIRED] == 1);
    task.newborn = 1; kh_sys_exit_value(56, -1);
    assert(counters[KH_C_UNPAIRED] == 2 && !task.newborn);
    task.newborn = 1; kh_sys_exit_value(39, 0);
    assert(counters[KH_C_UNPAIRED] == 3 && !task.newborn);
    kh_sys_exit_value(56, 0); assert(counters[KH_C_UNPAIRED] == 4);
    task.newborn = 1; kh_sys_enter_value(39); assert(!task.newborn && task.syscall_ts);
    kh_sys_exit_value(39, 100); assert(!task.syscall_ts && hist_count == 1);
    kh_sys_enter_value(39); kh_sys_enter_value(39);
    assert(counters[KH_C_UNPAIRED] == 5);
    kh_sys_exit_value(39, 100); assert(hist_count == 2);
    classes[56] = 0xffffffffU; cfg.enabled = 3;
    kh_sys_enter_value(56); kh_sys_exit_value(56, 0);
    kh_sys_enter_value(600); kh_sys_exit_value(600, 0);
    assert(counters[KH_C_UNPAIRED] == 5 && hist_count == 2 && !task.syscall_ts);
    return 0;
}}
"#
    );
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("kh-syscall-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    let path = dir.join("replay.c");
    let binary = dir.join("replay");
    fs::write(&path, harness).unwrap();
    let result = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("bpf"))
        .arg(&path)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    fs::remove_dir_all(dir).unwrap();
}
