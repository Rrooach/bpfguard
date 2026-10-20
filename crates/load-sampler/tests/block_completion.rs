// SPDX-License-Identifier: GPL-2.0-only
//! Exercise the exact pure completion helper used by the BPF program.
use std::{
    fs,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn compile_and_run(source_text: &str) {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("kh-completion-{}-{nonce}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let source = directory.join("test.c");
    let binary = directory.join("test");
    fs::write(&source, source_text).unwrap();
    let compilation = Command::new("cc")
        .args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(root.join("bpf"))
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        compilation.status.success(),
        "{}",
        String::from_utf8_lossy(&compilation.stderr)
    );
    assert!(Command::new(&binary).status().unwrap().success());
    fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn real_bpf_completion_helper_preserves_partial_bytes_until_terminal() {
    compile_and_run(
        r#"
#include <linux/types.h>
#include <assert.h>
#include "kernel_hist.h"
int main(void) {
    unsigned long long remaining = 8192;
    assert(kh_completion_kind(remaining, 4096) == KH_COMPLETION_PARTIAL);
    remaining -= 4096;
    assert(kh_completion_kind(remaining, 1024) == KH_COMPLETION_PARTIAL);
    remaining -= 1024;
    assert(kh_completion_kind(remaining, 3072) == KH_COMPLETION_FINAL);
    assert(kh_completion_kind(remaining, 4096) == KH_COMPLETION_INVALID);
    assert(kh_completion_kind(remaining, 0) == KH_COMPLETION_INVALID);
    assert(kh_completion_kind(0, 0) == KH_COMPLETION_ZERO_LENGTH);
    assert(kh_completion_kind(0, 512) == KH_COMPLETION_ZERO_LENGTH);
    assert(kh_service_eligible(0, 0, KH_COMPLETION_FINAL));
    assert(!kh_service_eligible(1, 0, KH_COMPLETION_FINAL));
    assert(!kh_service_eligible(0, 1, KH_COMPLETION_FINAL));
    assert(!kh_service_eligible(0, 0, KH_COMPLETION_PARTIAL));
    assert(!kh_service_eligible(0, 0, KH_COMPLETION_ZERO_LENGTH));
    return 0;
}
"#,
    );
}

#[test]
fn actual_block_hook_source_replays_partial_requeue_errors_and_capacity_failures() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let source = fs::read_to_string(root.join("bpf/kernel_hist.bpf.c")).unwrap();
    let structure = source
        .split_once("struct kh_blk {")
        .unwrap()
        .1
        .split_once("};")
        .unwrap()
        .0;
    let hooks = source
        .split_once("/* ---- Block layer (system-wide) ---- */")
        .unwrap()
        .1
        .split_once("/* ---- Softirq (system-wide) ---- */")
        .unwrap()
        .0;
    let harness = format!(
        r#"
#include <linux/types.h>
#include <assert.h>
#include <string.h>
#include "kernel_hist.h"
#define SEC(name)
#define BPF_PROG(name, ...) name(void *ctx, __VA_ARGS__)
#define BPF_CORE_READ(object, field) ((object)->field)
#define bpf_core_enum_value(type, value) (value)
#define BPF_NOEXIST 1
struct kh_blk {{{structure}}};
enum req_op {{ REQ_OP_FLUSH = 2 }};
struct request {{ unsigned int __data_len, cmd_flags, rq_flags; }};
static int kh_blk_inflight, kh_block_diagnostics, active, update_error, delete_error, read_error;
static __u64 key_value, now = 10, counts[KH_COUNTERS], recorded[KH_METRICS];
static struct kh_blk slot;
static struct kh_block_diag diagnostics;
static int kh_cfg(void) {{ return 1; }}
static __u64 bpf_ktime_get_ns(void) {{ return ++now; }}
static __u32 kh_log2(__u64 value) {{ __u32 n=0; while (value > 1) {{ value >>= 1; n++; }} return n; }}
static int bpf_core_read(void *destination, unsigned int size, const void *source) {{
    if (read_error) return -1;
    memcpy(destination, source, size); return 0;
}}
static void kh_count(__u32 mask, __u32 counter) {{ assert(mask == 0); counts[counter]++; }}
static void kh_record(__u32 mask, __u32 metric, __u64 start, __u64 end) {{
    assert(mask == 0); if (start && end >= start) recorded[metric]++;
}}
static void *bpf_map_lookup_elem(void *map, const void *raw_key) {{
    if (map == &kh_block_diagnostics) {{ assert(*(__u32 *)raw_key == 0); return &diagnostics; }}
    const __u64 *key = raw_key;
    assert(map == &kh_blk_inflight); return active && key_value == *key ? &slot : 0;
}}
static int bpf_map_update_elem(void *map, __u64 *key, struct kh_blk *value, int flag) {{
    assert(map == &kh_blk_inflight && flag == BPF_NOEXIST);
    if (update_error || active) return -1;
    key_value = *key; slot = *value; active = 1; return 0;
}}
static int bpf_map_delete_elem(void *map, __u64 *key) {{
    assert(map == &kh_blk_inflight);
    if (delete_error || !active || key_value != *key) return -1;
    active = 0; return 0;
}}
{hooks}
static void reset(void) {{
    active = update_error = delete_error = read_error = 0;
    memset(counts, 0, sizeof(counts)); memset(recorded, 0, sizeof(recorded));
    memset(&diagnostics, 0, sizeof(diagnostics));
}}
int main(void) {{
    assert(sizeof(struct kh_block_sample) == 48 && sizeof(struct kh_block_diag) == 728);
    struct request request = {{ .__data_len = 8192 }};
    reset(); kh_blk_insert(0, &request); kh_blk_issue(0, &request);
    kh_blk_complete(0, &request, 0, 4096);
    assert(active && slot.remaining_bytes == 4096 && counts[KH_C_BLK_PARTIAL] == 1);
    assert(recorded[KH_BLK_SERVICE] == 0);
    kh_blk_complete(0, &request, 0, 4096);
    assert(!active && recorded[KH_BLK_SERVICE] == 1);
    reset(); kh_blk_insert(0, &request); kh_blk_issue(0, &request);
    kh_blk_requeue(0, &request); kh_blk_insert(0, &request); kh_blk_issue(0, &request);
    kh_blk_complete(0, &request, 0, 8192);
    assert(!active && counts[KH_C_BLK_REQUEUE] == 1 && recorded[KH_BLK_SERVICE] == 0);
    reset(); kh_blk_issue(0, &request); kh_blk_complete(0, &request, -5, 4096);
    assert(active && slot.had_error && counts[KH_C_BLK_COMPLETE_ERROR] == 1);
    kh_blk_complete(0, &request, 0, 4096);
    assert(!active && recorded[KH_BLK_SERVICE] == 0);
    reset(); kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 8192);
    assert(counts[KH_C_BLK_ISSUE_WITHOUT_INSERT] == 1 && recorded[KH_BLK_SERVICE] == 1);
    reset(); kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 0);
    assert(!active && counts[KH_C_BLK_BYTE_MISMATCH] == 1 && recorded[KH_BLK_SERVICE] == 0);
    reset(); request.__data_len = 0; kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 0);
    assert(!active && counts[KH_C_BLK_ZERO_LENGTH] == 1 && recorded[KH_BLK_SERVICE] == 0);
    assert(diagnostics.counter[KH_BD_ZERO_NONFLUSH] == 1);
    reset(); request.cmd_flags = REQ_OP_FLUSH; request.rq_flags = 2;
    kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 0);
    assert(!active && counts[KH_C_BLK_ZERO_LENGTH] == 0 && recorded[KH_BLK_SERVICE] == 0);
    assert(diagnostics.counter[KH_BD_FLUSH_ISSUED] == 1 && diagnostics.counter[KH_BD_FLUSH_COMPLETED] == 1);
    assert(diagnostics.counter[KH_BD_QUEUE_UNKNOWN] == 1 && diagnostics.flush_sum_ns > 0);
    __u64 flush_count = 0; for (int i=0; i<KH_BUCKETS; i++) flush_count += diagnostics.flush_count[i];
    assert(flush_count == 1 && diagnostics.samples[0].cmd_flags == REQ_OP_FLUSH);
    assert(diagnostics.samples[1].reason == KH_BD_ZERO_FLUSH_COMPLETE);
    kh_blk_complete(0, &request, 0, 0);
    assert(counts[KH_C_BLK_UNTRACKED] == 1 && diagnostics.counter[KH_BD_UNTRACKED_COMPLETE] == 1);
    assert(diagnostics.samples[2].reason == KH_BD_UNTRACKED_END); /* never claim the second completion is definitely sequencing */
    reset(); kh_blk_issue(0, &request); kh_blk_complete(0, &request, -5, 0);
    assert(diagnostics.counter[KH_BD_FLUSH_ERROR] == 1 && diagnostics.flush_sum_ns == 0);
    reset(); kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 512);
    assert(counts[KH_C_BLK_ZERO_LENGTH] == 1 && diagnostics.counter[KH_BD_ZERO_FLUSH_BAD_BYTES] == 1);
    reset(); kh_blk_issue(0, &request); kh_blk_requeue(0, &request); kh_blk_issue(0, &request);
    kh_blk_complete(0, &request, 0, 0);
    assert(diagnostics.counter[KH_BD_FLUSH_COMPLETED] == 1 && diagnostics.flush_sum_ns == 0);
    reset(); for (int i=0; i<KH_BLOCK_DIAG_SAMPLES + 3; i++) kh_blk_complete(0, &request, 0, 0);
    assert(diagnostics.counter[KH_BD_SAMPLE_ATTEMPTS] == KH_BLOCK_DIAG_SAMPLES + 3);
    assert(diagnostics.samples[KH_BLOCK_DIAG_SAMPLES - 1].reason == KH_BD_UNTRACKED_END);
    reset(); read_error = 1; kh_blk_issue(0, &request); kh_blk_complete(0, &request, 0, 0);
    assert(diagnostics.counter[KH_BD_READ_FAILED] == 1 && diagnostics.counter[KH_BD_FLUSH_COMPLETED] == 0);
    assert(diagnostics.samples[0].reason == KH_BD_OBJECT_READ_ERROR && diagnostics.samples[0].reserved == 0);
    assert(counts[KH_C_BLK_ZERO_LENGTH] == 1); /* unresolved fields cannot authorize FLUSH classification */
    request.cmd_flags = request.rq_flags = 0;
    reset(); kh_blk_complete(0, &request, 0, 4096); kh_blk_requeue(0, &request);
    assert(counts[KH_C_BLK_UNTRACKED] == 2);
    reset(); update_error = 1; kh_blk_issue(0, &request);
    assert(!active && counts[KH_C_BLK_UPDATE_FAILED] == 1);
    reset(); request.__data_len = 8192; kh_blk_issue(0, &request); delete_error = 1;
    kh_blk_complete(0, &request, 0, 8192);
    assert(active && counts[KH_C_BLK_DELETE_FAILED] == 1);
    reset(); kh_blk_insert(0, &request); kh_blk_insert(0, &request);
    assert(active && counts[KH_C_BLK_INSERT_COLLISION] == 1);
    return 0;
}}
"#
    );
    compile_and_run(&harness);
}
