#pragma once
// Optional llama.cpp b4514 runtime events. CPU backend instrumentation only.
#include "json.hpp"
#include "llama.h"
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

using observer_json = nlohmann::ordered_json;

static std::string observer_text(const std::string & path) {
    std::ifstream stream(path);
    std::stringstream result;
    result << stream.rdbuf();
    std::string value = result.str();
    while (!value.empty() && (value.back() == '\n' || value.back() == '\r')) value.pop_back();
    return value;
}

static uint64_t observer_start_ticks(const std::string & path) {
    const std::string raw = observer_text(path);
    const size_t end = raw.rfind(')');
    if (end == std::string::npos) std::abort();
    std::istringstream fields(raw.substr(end + 2));
    std::string value;
    for (int i = 0; i <= 19; ++i) if (!(fields >> value)) std::abort();
    return std::stoull(value);
}

static observer_json observer_actor() {
    const pid_t pid = getpid(), tid = static_cast<pid_t>(syscall(SYS_gettid));
    const std::string proc = "/proc/" + std::to_string(pid);
    // Boot and start ticks cannot change within one process/thread instance.
    // Cache only these stable fields, never cgroup/namespace or Agent ownership.
    static const std::string boot_id = observer_text("/proc/sys/kernel/random/boot_id");
    static const pid_t original_pid = getpid();
    static const uint64_t original_process_start = observer_start_ticks("/proc/" + std::to_string(original_pid) + "/stat");
    struct stable_thread_identity { pid_t pid = 0, tid = 0; uint64_t process_start = 0, thread_start = 0; };
    static thread_local stable_thread_identity stable;
    if (stable.pid != pid || stable.tid != tid) {
        stable.pid = pid;
        stable.tid = tid;
        stable.process_start = pid == original_pid ? original_process_start : observer_start_ticks(proc + "/stat");
        stable.thread_start = observer_start_ticks(proc + "/task/" + std::to_string(tid) + "/stat");
    }
    const std::string membership = observer_text(proc + "/cgroup");
    const size_t start = membership.find("0::");
    if (start == std::string::npos) std::abort();
    const std::string path = membership.substr(start + 3, membership.find('\n', start) - (start + 3));
    struct stat group{}, pid_ns{}, cg_ns{};
    if (stat(("/sys/fs/cgroup" + path).c_str(), &group) ||
        stat((proc + "/ns/pid").c_str(), &pid_ns) || stat((proc + "/ns/cgroup").c_str(), &cg_ns)) std::abort();
    return {{"boot_id", boot_id},
            {"pid", pid}, {"tid", tid},
            {"process_start_ticks", stable.process_start},
            {"thread_start_ticks", stable.thread_start},
            {"cgroup_path", path}, {"cgroup_inode", group.st_ino}, {"cgroup_device", group.st_dev},
            {"pid_namespace_inode", pid_ns.st_ino}, {"cgroup_namespace_inode", cg_ns.st_ino}};
}

static bool observer_native_enabled() {
    return std::getenv("OBSERVER_NATIVE_EVENTS") != nullptr;
}

static uint64_t observer_monotonic_ns() {
    struct timespec stamp{};
    if (clock_gettime(CLOCK_MONOTONIC, &stamp)) std::abort();
    return static_cast<uint64_t>(stamp.tv_sec) * 1000000000ULL + stamp.tv_nsec;
}

static observer_json observer_logical_kv(const llama_context * ctx, const llama_model * model) {
    // b4514's public token-count API scans cache cells (debug/slow API).
    // Invoke ONCE per completion, never per token/worker/scheduler hook.
    const uint64_t started = observer_monotonic_ns();
    const int32_t tokens = llama_get_kv_cache_token_count(ctx);
    const int32_t used = llama_get_kv_cache_used_cells(ctx);
    const uint32_t capacity = llama_n_ctx(ctx);
    const bool recurrent = llama_model_is_recurrent(model);
    observer_json result = {
        {"schema_version", 1}, {"status", tokens >= 0 && used >= 0 ? "OBSERVED_LOGICAL_KV" : "UNKNOWN_API_COUNTER_INVALID"},
        {"scope", "SHARED_LLAMA_CONTEXT_LOGICAL_NOT_REQUEST_ALLOCATION"},
        {"captured_at", "ENGINE_COMPLETE_HANDLER_ENTRY"},
        {"token_sequence_associations", tokens >= 0 ? observer_json(tokens) : observer_json(nullptr)},
        {"used_cells", used >= 0 ? observer_json(used) : observer_json(nullptr)},
        {"context_capacity_tokens", capacity},
        {"capacity_cells", recurrent ? observer_json(nullptr) : observer_json(capacity)},
        {"capacity_cells_basis", recurrent ? "UNKNOWN_RECURRENT_MODEL_LAYOUT" : "PUBLIC_CONTEXT_CAPACITY_NONRECURRENT_MODEL"},
        {"sequence_capacity", llama_n_seq_max(ctx)},
        {"batch_capacity_tokens", llama_n_batch(ctx)}, {"microbatch_capacity_tokens", llama_n_ubatch(ctx)},
        {"model_recurrent", recurrent},
        {"allocated_bytes", nullptr}, {"allocated_bytes_status", "UNKNOWN_PUBLIC_API_NOT_EXPOSED"},
        {"gpu_memory", {{"status", "UNKNOWN_NO_GPU_BACKEND"}, {"framework_allocated_bytes", nullptr},
            {"framework_reserved_bytes", nullptr}, {"device_used_bytes", nullptr}}},
        {"source_apis", {"llama_get_kv_cache_token_count", "llama_get_kv_cache_used_cells", "llama_n_ctx",
            "llama_n_seq_max", "llama_n_batch", "llama_n_ubatch", "llama_model_is_recurrent"}},
        {"collection_start_ns", started}};
    result["collection_end_ns"] = observer_monotonic_ns();
    return result;
}

static bool observer_forensic() {
    static const bool detailed = [] {
        const char * profile = std::getenv("OBSERVER_NATIVE_PROFILE");
        if (!profile || std::string(profile) == "FORENSIC") return true;
        if (std::string(profile) == "LIGHT") return false;
        std::abort(); // Unknown configured coverage must not silently downgrade.
    }();
    return detailed;
}

static bool observer_select_batch(const observer_json & details) {
    if (!observer_native_enabled()) return false;
    if (observer_forensic()) return true;
    // LIGHT logs actual membership-change batches, not all decode graphs.
    // A selected boundary represents only that batch. Never call it full
    // per-token coverage or split its cost among request members.
    static observer_json previous_members = observer_json::array();
    const observer_json members = details["members"];
    const bool selected = members != previous_members;
    previous_members = members;
    return selected;
}

static void observer_native(const char * kind, const nlohmann::ordered_json & context,
                            const observer_json & details = observer_json::object()) {
    if (!observer_native_enabled()) return;
    static std::mutex mutex;
    static uint64_t sequence = 0;
    static int fd = -2;
    // cgroup and namespace identities are mutable. Refresh them at every
    // selected processing marker; no thread is permanently assigned to an Agent.
    const observer_json actor = observer_actor();
    std::lock_guard<std::mutex> lock(mutex);
    if (fd == -2) {
        fd = open(std::getenv("OBSERVER_NATIVE_EVENTS"), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0) std::abort();
    }
    if (++sequence > 200000) std::abort();
    struct timespec stamp{};
    if (clock_gettime(CLOCK_MONOTONIC, &stamp)) std::abort();
    observer_json event = {{"schema_version", 1}, {"seq", sequence}, {"kind", kind},
        {"monotonic_ns", static_cast<uint64_t>(stamp.tv_sec) * 1000000000ULL + stamp.tv_nsec},
        {"actor", actor}, {"context", context}, {"details", details},
        {"backend", "CPU"}, {"authority", "INSTRUMENTED_LLAMA_CPP_SOURCE"},
        {"native_profile", observer_forensic() ? "FORENSIC" : "LIGHT"}};
    const std::string encoded = event.dump() + "\n";
    size_t written = 0;
    while (written < encoded.size()) {
        const ssize_t count = write(fd, encoded.data() + written, encoded.size() - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) std::abort();
        written += static_cast<size_t>(count);
    }
}

static std::mutex observer_batch_mutex;
static observer_json observer_active_batch = observer_json::object();
static std::atomic<int> observer_active_workers{0};
static thread_local observer_json observer_worker_batch = observer_json::object();

static void observer_set_batch(const observer_json & details) {
    std::lock_guard<std::mutex> lock(observer_batch_mutex);
    observer_active_batch = details;
}

extern "C" void observer_ggml_worker_begin(int worker_index) {
    if (!observer_native_enabled() || !observer_forensic()) return;
    {
        std::lock_guard<std::mutex> lock(observer_batch_mutex);
        observer_worker_batch = observer_active_batch;
        if (observer_worker_batch.empty()) return;
        ++observer_active_workers;
    }
    observer_worker_batch["worker_index"] = worker_index;
    observer_native("ENGINE_WORKER_BEGIN", observer_json::object(), observer_worker_batch);
}

extern "C" void observer_ggml_worker_end(int worker_index) {
    if (!observer_native_enabled() || !observer_forensic() || observer_worker_batch.empty()) return;
    observer_worker_batch["worker_index"] = worker_index;
    observer_native("ENGINE_WORKER_END", observer_json::object(), observer_worker_batch);
    observer_worker_batch = observer_json::object();
    --observer_active_workers;
}

static void observer_finish_batch_workers() {
    // Decode completion's graph barrier guarantees all participating workers
    // have entered; wait only for their diagnostic END records to flush.
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (observer_active_workers.load() != 0) {
        if (std::chrono::steady_clock::now() > end) std::abort();
        std::this_thread::yield();
    }
    observer_set_batch(observer_json::object());
}
