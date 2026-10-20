"""Shared admission queue in front of one real resident llama.cpp CPU slot."""
from __future__ import annotations

import concurrent.futures
import dataclasses
import hashlib
import heapq
import json
import threading
import time
import urllib.request

from semantic import Context


def validate_logical_kv(value, marker_ns):
    """Logical shared-context occupancy only, never RSS or GPU byte estimates."""
    if value is None:
        return {"status": "UNKNOWN_LEGACY_NATIVE_TRACE_DID_NOT_COLLECT", "scope": "SHARED_LLAMA_CONTEXT_LOGICAL_NOT_REQUEST_ALLOCATION"}
    if not isinstance(value, dict) or type(value.get("schema_version")) is not int or value.get("schema_version") != 1 or value.get("scope") != "SHARED_LLAMA_CONTEXT_LOGICAL_NOT_REQUEST_ALLOCATION" or value.get("captured_at") != "ENGINE_COMPLETE_HANDLER_ENTRY":
        raise ValueError("logical KV schema/scope/capture point forged")
    for name in ("context_capacity_tokens", "sequence_capacity", "batch_capacity_tokens", "microbatch_capacity_tokens"):
        if type(value[name]) is not int or value[name] <= 0:
            raise ValueError("invalid logical KV capacity")
    if type(value["model_recurrent"]) is not bool:
        raise ValueError("logical KV model kind invalid")
    if value["model_recurrent"]:
        if value["capacity_cells"] is not None or value["capacity_cells_basis"] != "UNKNOWN_RECURRENT_MODEL_LAYOUT":
            raise ValueError("recurrent KV cell capacity was guessed")
    elif type(value["capacity_cells"]) is not int or value["capacity_cells"] != value["context_capacity_tokens"] or value["capacity_cells_basis"] != "PUBLIC_CONTEXT_CAPACITY_NONRECURRENT_MODEL":
        raise ValueError("KV capacity/context basis mismatch")
    status = value["status"]
    if status == "OBSERVED_LOGICAL_KV":
        for name in ("token_sequence_associations", "used_cells"):
            if type(value[name]) is not int or value[name] < 0:
                raise ValueError("invalid observed logical KV count")
        if value["token_sequence_associations"] < value["used_cells"] or (not value["model_recurrent"] and value["used_cells"] > value["capacity_cells"]):
            raise ValueError("logical KV counter/capacity inconsistency")
    elif status == "UNKNOWN_API_COUNTER_INVALID":
        if value["token_sequence_associations"] is not None and value["used_cells"] is not None:
            raise ValueError("unknown KV failure did not expose a failed counter")
        if any(value[name] is not None and (type(value[name]) is not int or value[name] < 0)
               for name in ("token_sequence_associations", "used_cells")):
            raise ValueError("unknown KV counter is not valid/null")
    else:
        raise ValueError("unknown logical KV status")
    if value["allocated_bytes"] is not None or value["allocated_bytes_status"] != "UNKNOWN_PUBLIC_API_NOT_EXPOSED":
        raise ValueError("logical KV was fabricated as allocation bytes")
    gpu = value["gpu_memory"]
    if not isinstance(gpu, dict) or gpu["status"] != "UNKNOWN_NO_GPU_BACKEND" or any(gpu[field] is not None for field in ("framework_allocated_bytes", "framework_reserved_bytes", "device_used_bytes")):
        raise ValueError("CPU KV/RSS was fabricated as GPU memory")
    if not (type(value["collection_start_ns"]) is int and type(value["collection_end_ns"]) is int and
            0 < value["collection_start_ns"] <= value["collection_end_ns"] <= marker_ns):
        raise ValueError("logical KV collection clock invalid")
    expected_apis = ["llama_get_kv_cache_token_count", "llama_get_kv_cache_used_cells", "llama_n_ctx", "llama_n_seq_max",
                     "llama_n_batch", "llama_n_ubatch", "llama_model_is_recurrent"]
    if value["source_apis"] != expected_apis:
        raise ValueError("logical KV source API contract changed")
    return value


class SharedInference:
    def __init__(self, recorder, endpoint, priority_scheduling=False):
        self.recorder, self.endpoint = recorder, endpoint
        self.priority_scheduling = priority_scheduling
        self.queue, self.sequence = [], 0
        self.condition = threading.Condition()
        self.closing = False
        self.requests, self.results = {}, {}
        self.worker = threading.Thread(target=self._run, name="inference-admission-worker")
        self.worker.start()

    def submit(self, context, prompt, tokens=64):
        if not isinstance(prompt, str) or not 1 <= len(prompt.encode()) <= 8192 or not 1 <= tokens <= 256:
            raise ValueError("bounded fixed inference input required")
        with self.condition:
            if self.closing or context.request_id in self.requests:
                raise ValueError("queue closed or duplicate request")
            future = concurrent.futures.Future()
            self.sequence += 1
            submitted = time.monotonic_ns()
            self.recorder.request(context, "ACCEPTED", {"prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
                                                       "output_token_limit": tokens})
            self.recorder.request(context, "QUEUED", {"queue": "SHARED_ADMISSION", "sequence": self.sequence})
            priority = -self.recorder.current(context).priority if self.priority_scheduling else 0
            item = [priority, self.sequence, context, prompt, tokens, future, submitted]
            self.requests[context.request_id] = item
            heapq.heappush(self.queue, item)
            self.condition.notify()
            return future

    def reprioritize(self):
        with self.condition:
            if self.priority_scheduling:
                for item in self.queue:
                    item[0] = -self.recorder.current(item[2]).priority
                heapq.heapify(self.queue)

    def cancel(self, request_id):
        with self.condition:
            item = self.requests.get(request_id)
            if item is None or item not in self.queue:
                return False  # Running decode is never falsely claimed preempted.
            self.queue.remove(item)
            heapq.heapify(self.queue)
            self.recorder.request(item[2], "CANCELLED", {"basis": "REMOVED_BEFORE_ADMISSION"})
            item[5].cancel()
            return True

    def _run(self):
        while True:
            with self.condition:
                while not self.queue and not self.closing:
                    self.condition.wait()
                if not self.queue:
                    return
                item = heapq.heappop(self.queue)
            _, _, original, prompt, tokens, future, submitted = item
            with self.recorder.lock:
                context = self.recorder.current(original)
                self.recorder.request(context, "SCHEDULED", {"queue": "SHARED_ADMISSION",
                          "queue_wait_ns": time.monotonic_ns() - submitted,
                          "engine_actual_scheduling": "RECORDED_SEPARATELY_BY_NATIVE_HOOK"})
            started = time.monotonic_ns()
            try:
                with self.recorder.thread_processing(context, "handler-" + context.request_id):
                    result = self._infer(context, prompt, tokens)
                result.update({"submitted_ns": submitted, "admitted_ns": started,
                               "completed_ns": time.monotonic_ns(), "request_id": context.request_id,
                               "task_id": context.task_id, "agent_id": context.agent_id,
                               "queue_wait_ns": started - submitted})
                self.results[context.request_id] = result
                future.set_result(result)
            except BaseException as error:
                self.recorder.request(context, "FAILED", {"error": str(error)[:2048]})
                future.set_exception(error)

    def _infer(self, context, prompt, tokens):
        payload = {"prompt": prompt, "n_predict": tokens, "seed": 1234, "temperature": 0,
                   "cache_prompt": False, "ignore_eos": True, "stream": True,
                   "observer_context": dataclasses.asdict(context)}
        request = urllib.request.Request(self.endpoint.rstrip("/") + "/completion",
             data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"}, method="POST")
        content, chunks, first_ns, final, total_bytes = [], 0, None, None, 0
        with urllib.request.urlopen(request, timeout=120) as response:
            for raw in response:
                total_bytes += len(raw)
                if total_bytes > 1024 * 1024 or len(raw) > 64 * 1024:
                    raise ValueError("engine response exceeds bounds")
                if not raw.startswith(b"data: "):
                    continue
                data = json.loads(raw[6:])
                if data.get("error"):
                    raise RuntimeError("real engine returned an error")
                text = data.get("content", "")
                if not isinstance(text, str):
                    raise ValueError("invalid engine content")
                content.append(text)
                if not data.get("stop"):
                    chunks += 1
                    if first_ns is None:
                        first_ns = time.monotonic_ns()
                        self.recorder.request(context, "FIRST_TOKEN", {"basis": "FIRST_STREAMED_TOKEN_CHUNK",
                                                                      "client_received_ns": first_ns})
                else:
                    final = data
        if final is None or first_ns is None:
            raise RuntimeError("real engine did not provide a complete streamed inference")
        predicted = final.get("tokens_predicted")
        if predicted != tokens:
            raise RuntimeError("engine performed a different output token workload")
        text = "".join(content)
        result = {"output_sha256": hashlib.sha256(text.encode()).hexdigest(), "output": text,
                  "wire_context": json.loads(json.dumps(dataclasses.asdict(context))),
                  "output_tokens": predicted, "input_tokens": final.get("tokens_evaluated"),
                  "first_token_ns": first_ns, "engine_timings": final.get("timings"),
                  "stream_chunks": chunks, "engine_slot_id": final.get("id_slot"),
                  "backend": "CPU", "gpu_execution": "NOT_AVAILABLE_NO_COMPUTE_DEVICE"}
        self.recorder.request(context, "COMPLETE", {key: value for key, value in result.items() if key != "output"})
        return result

    def close(self):
        with self.condition:
            self.closing = True
            self.condition.notify_all()
        self.worker.join(timeout=180)
        if self.worker.is_alive():
            raise TimeoutError("shared inference worker did not finalize")


def verify_native(path, expected_requests):
    """Native queue, shared dispatch TID and actual batch members; no GPU inference."""
    events = []
    errors, states, batches, thread_intervals, first, completed = [], {}, {}, [], {}, {}
    workers, worker_intervals, request_started, request_intervals, native_profile = {}, [], {}, [], None
    logical_kv, slot_bindings = {}, {}
    process_instance = None
    try:
        if not expected_requests:
            raise ValueError("no expected native requests; zero is not real inference proof")
        for request_id, context in expected_requests.items():
            parsed = Context(**{**context, "dependencies": tuple(context["dependencies"])}).validate()
            if parsed.request_id != request_id:
                raise ValueError("expected native request key/context mismatch")
        with open(path) as stream:
            for line in stream:
                if len(line.encode()) > 1024 * 1024 or len(events) >= 200_000:
                    raise ValueError("native evidence exceeds verifier budget")
                events.append(json.loads(line))
        last_ns, boot_id, process_instance, native_profile = 0, None, None, None
        for sequence, event in enumerate(events, 1):
            if type(event["schema_version"]) is not int or event["schema_version"] != 1 or type(event["seq"]) is not int or event["seq"] != sequence or type(event["monotonic_ns"]) is not int or event["monotonic_ns"] <= 0 or event["monotonic_ns"] < last_ns or event["backend"] != "CPU":
                raise ValueError("native sequence/time/backend invalid")
            last_ns = event["monotonic_ns"]
            profile = event.get("native_profile", "FORENSIC")
            if profile not in {"LIGHT", "FORENSIC"} or (native_profile is not None and profile != native_profile):
                raise ValueError("native profile changed or unknown")
            native_profile = profile
            actor = event["actor"]
            for name in ("pid", "tid", "cgroup_inode", "process_start_ticks", "thread_start_ticks",
                         "pid_namespace_inode", "cgroup_namespace_inode"):
                if type(actor[name]) is not int or actor[name] <= 0:
                    raise ValueError("native process/thread/namespace identity invalid")
            instance = (actor["boot_id"], actor["pid"], actor["process_start_ticks"], actor["cgroup_inode"], actor["cgroup_device"])
            if process_instance is None:
                process_instance, boot_id = instance, actor["boot_id"]
            if instance != process_instance:
                raise ValueError("native service process identity changed")
            kind, details, context = event["kind"], event["details"], event["context"]
            if kind.startswith("ENGINE_WORKER_"):
                if native_profile != "FORENSIC":
                    raise ValueError("LIGHT unexpectedly claims full worker coverage")
                batch_id = details["batch_id"]
                ids = [member["context"]["request_id"] for member in details["members"]]
                if any(expected_requests.get(member["context"]["request_id"]) != member["context"]
                       for member in details["members"]):
                    raise ValueError("ggml worker full request membership forged")
                if batch_id not in batches or ids != batches[batch_id][0] or details["members"] != batches[batch_id][3]:
                    raise ValueError("ggml worker interval has no matching active batch")
                key = (batch_id, actor["tid"], actor["thread_start_ticks"], details["worker_index"])
                if kind == "ENGINE_WORKER_BEGIN":
                    if key in workers:
                        raise ValueError("ggml worker processing interval is duplicated")
                    workers[key] = (event["monotonic_ns"], actor, ids)
                elif kind == "ENGINE_WORKER_END":
                    begin = workers.pop(key)
                    if actor != begin[1] or ids != begin[2]:
                        raise ValueError("ggml worker identity or batch membership changed")
                    worker_intervals.append({"batch_id": batch_id, "requests": ids,
                        "start_ns": begin[0], "end_ns": event["monotonic_ns"], "actor": actor,
                        "worker_index": details["worker_index"], "scope": "GGML_GRAPH_COMPUTE_THREAD_INTERVAL",
                        "shared_members_not_divided_into_agent_cpu_cost": True})
                else:
                    raise ValueError("unknown ggml worker event")
            elif kind.startswith("ENGINE_BATCH_"):
                if kind not in {"ENGINE_BATCH_BEGIN", "ENGINE_BATCH_END"}:
                    raise ValueError("unknown native batch transition")
                batch_id, members = details["batch_id"], details["members"]
                ids = [member["context"]["request_id"] for member in members]
                if not ids or len(set(ids)) != len(ids):
                    raise ValueError("native batch has invalid members")
                for member in members:
                    ctx = member["context"]
                    if ctx["request_id"] not in expected_requests or ctx != expected_requests[ctx["request_id"]]:
                        raise ValueError("native batch member provenance changed")
                    if states.get(ctx["request_id"]) not in {"ENGINE_SCHEDULED", "ENGINE_FIRST_TOKEN"}:
                        raise ValueError("native batch member has no active scheduled request")
                    if (member["native_task_id"], member["slot_id"]) != slot_bindings.get(ctx["request_id"]):
                        raise ValueError("native batch slot/native-task binding forged")
                if kind == "ENGINE_BATCH_BEGIN":
                    if batch_id in batches:
                        raise ValueError("native batch duplicate begin")
                    batches[batch_id] = (ids, event["monotonic_ns"], actor, members)
                else:
                    if any(key[0] == batch_id for key in workers):
                        raise ValueError("native batch ended before graph workers")
                    original = batches.pop(batch_id)
                    if ids != original[0] or actor != original[2] or details["return_code"] != 0:
                        raise ValueError("native batch identities changed or decode failed")
                    thread_intervals.append({"batch_id": batch_id, "requests": ids, "start_ns": original[1],
                                             "end_ns": event["monotonic_ns"], "actor": actor,
                                             "interval_kind": "SINGLE_ACTUAL_LLAMA_DECODE_CALL",
                                             "selection": "ALL_CALLS" if native_profile == "FORENSIC" else "MEMBERSHIP_CHANGE_SELECTED_CALL_ONLY",
                                             "scope": "INSTRUMENTED_DISPATCH_THREAD_DECODE_INTERVAL",
                                             "ggml_additional_worker_request_ownership": "SEPARATE_SCOPED_WORKER_EVENTS"})
            else:
                request_id = context["request_id"]
                if expected_requests.get(request_id) != context:
                    raise ValueError("native request is unknown or context forged")
                before = states.get(request_id)
                allowed = {None: "ENGINE_ACCEPTED", "ENGINE_ACCEPTED": "ENGINE_QUEUED",
                           "ENGINE_QUEUED": "ENGINE_SCHEDULED", "ENGINE_SCHEDULED": "ENGINE_FIRST_TOKEN",
                           "ENGINE_FIRST_TOKEN": "ENGINE_COMPLETE"}
                if allowed.get(before) != kind:
                    raise ValueError("native inference state skipped or duplicated")
                states[request_id] = kind
                if kind == "ENGINE_SCHEDULED":
                    for name in ("native_task_id", "slot_id"):
                        if type(details[name]) is not int or details[name] < 0:
                            raise ValueError("native scheduled slot/task identity invalid")
                    slot_bindings[request_id] = (details["native_task_id"], details["slot_id"])
                    request_started[request_id] = (event["monotonic_ns"], actor)
                if kind == "ENGINE_FIRST_TOKEN":
                    first[request_id] = event["monotonic_ns"]
                if kind == "ENGINE_COMPLETE":
                    logical_kv[request_id] = validate_logical_kv(details.get("logical_kv"), event["monotonic_ns"])
                    started, scheduled_actor = request_started[request_id]
                    if actor != scheduled_actor:
                        raise ValueError("native request dispatch thread instance changed")
                    request_intervals.append({"request_id": request_id, "context": context,
                        "start_ns": started, "end_ns": event["monotonic_ns"], "actor": actor,
                        "scope": "REQUEST_SCOPED_NATIVE_DISPATCH_INTERVAL_NOT_EXCLUSIVE_ONCPU"})
                    completed[request_id] = details
        if batches or workers or set(states) != set(expected_requests) or any(state != "ENGINE_COMPLETE" for state in states.values()):
            raise ValueError("native evidence has unfinished or missing inference/batch")
    except (OSError, KeyError, ValueError, TypeError) as error:
        errors.append(str(error))
    return {"verified": not errors, "status": "INVALID" if errors else "COMPLETE_WITH_DECLARED_SCOPE",
            "event_count": len(events), "request_count": len(states), "batch_count": len(thread_intervals),
            "batch_count_compatibility_meaning": "OBSERVED_SINGLE_DECODE_CALLS_NOT_TOTAL_WHEN_LIGHT",
            "observed_actual_batch_count": len(thread_intervals),
            "total_actual_batch_count": len(thread_intervals) if native_profile == "FORENSIC" else None,
            "selected_membership_change_batch_count": len(thread_intervals) if native_profile == "LIGHT" else None,
            "membership_epoch_count": None,
            "thread_processing_intervals": thread_intervals, "first_token_ns": first,
            "ggml_worker_processing_intervals": worker_intervals,
            "request_dispatch_processing_intervals": request_intervals,
            "completed": completed, "process_instance": process_instance, "errors": errors,
            "logical_kv_by_request_completion": logical_kv,
            "logical_kv_scope": "SHARED_CONTEXT_SNAPSHOT_NOT_PER_REQUEST_ALLOCATION_OR_RSS",
            "native_profile": native_profile,
            "batch_coverage": "EVERY_DECODE_GRAPH" if native_profile == "FORENSIC" else "MEMBERSHIP_CHANGE_BATCHES_ONLY_NOT_FULL_GRAPH_HISTORY",
            "worker_coverage": "SCOPED_NATIVE_EVENTS" if native_profile == "FORENSIC" else "NOT_COLLECTED_LIGHT",
            "maximum_observed_batch_members": max((len(interval["requests"]) for interval in thread_intervals), default=0),
            "multi_member_actual_batch_count": sum(len(interval["requests"]) > 1 for interval in thread_intervals),
            "gpu_status": "NOT_AVAILABLE", "dynamic_multi_member_batch_e2e":
                "OBSERVED_REAL_MULTI_MEMBER_DECODE" if any(len(interval["requests"]) > 1 for interval in thread_intervals)
                else "NOT_OBSERVED_ACTUAL_SINGLETON_BATCHES_ONLY"}
