#!/usr/bin/env python3
"""Guest-local Responses transport timing, without persisting model content.

The upstream budget broker may run on another boot/clock and buffer the entire
provider SSE. This loopback relay measures the wait on the Agent's own clock.
It forwards the original request body once and relays the response body bytes
unchanged; it does not execute tools, retry, or bypass the budget broker.
"""
from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import threading
import time
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 192 * 1024
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_LEDGER_BYTES = 32 * 1024 * 1024
TIMING_FILENAME = "model-request-timing.jsonl"
SUMMARY_FILENAME = "model-transport-summary.json"
OPAQUE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,256}\Z")


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode() + b"\n"


def _response_metadata(body):
    """Only bounded opaque identifiers and numeric usage may leave memory."""
    terminals = []
    try:
        for event in body.replace(b"\r\n", b"\n").split(b"\n\n"):
            data = b"\n".join(line[5:].lstrip(b" ") for line in event.splitlines()
                              if line.startswith(b"data:"))
            if not data or data == b"[DONE]":
                continue
            row = json.loads(data)
            if row.get("type") in ("response.completed", "response.incomplete", "response.failed"):
                if isinstance(row.get("response"), dict):
                    terminals.append(row["response"])
        if len(terminals) != 1:
            raise ValueError("one terminal response required")
        response = terminals[0]
        response_id = response.get("id")
        valid_id = isinstance(response_id, str) and bool(OPAQUE_ID.fullmatch(response_id))
        output = response.get("output")
        complete = valid_id and isinstance(output, list)
        calls = []
        for item in output if isinstance(output, list) else []:
            if not isinstance(item, dict):
                complete = False
                continue
            if item.get("type") not in ("function_call", "custom_tool_call"):
                continue
            call_id = item.get("call_id")
            if isinstance(call_id, str) and OPAQUE_ID.fullmatch(call_id) and len(calls) < 256:
                calls.append(call_id)
            else:
                complete = False
        raw_usage = response.get("usage")
        usage = {key: value for key in ("input_tokens", "output_tokens", "total_tokens")
                 if isinstance(raw_usage, dict) and type(value := raw_usage.get(key)) is int
                 and 0 <= value <= 10**12}
        return {"provider_response_id": response_id if valid_id else None,
                "output_tool_call_ids": calls, "output_link_status": "COMPLETE" if complete else "PARTIAL",
                "usage": usage or None}
    except (ValueError, TypeError, AttributeError):
        return {"provider_response_id": None, "output_tool_call_ids": [],
                "output_link_status": "PARTIAL", "usage": None}


class _Timing:
    def __init__(self, owner):
        self.owner = owner
        self.request_id = "mrq-" + secrets.token_hex(16)
        self.timestamps = {}
        self.fields = {"outcome": "INTERRUPTED", "error_class": None, "http_status": None,
                       "upstream_http_status": None, "budget_status": None, "usage": None,
                       "provider_response_id": None, "output_tool_call_ids": [],
                       "output_link_status": "NOT_RECEIVED"}
        self.mark("MODEL_REQUEST_ACCEPTED", "accepted")

    def base(self, event, timestamp):
        return {"schema_version": 1, "kind": "MODEL_REQUEST_TIMING", "event": event,
                "request_id": self.request_id, "task_label": self.owner.task_label,
                "budget_request_id": None, "clock": "CLOCK_MONOTONIC",
                "boot_id": self.owner.boot_id, "timestamp_ns": timestamp,
                "source": "AGENT_LOCAL_TRANSPORT_PROXY"}

    def mark(self, event, stage):
        timestamp = time.monotonic_ns()
        self.timestamps[stage] = timestamp
        self.owner._append(self.base(event, timestamp))

    def finish(self):
        timestamp = time.monotonic_ns()
        self.timestamps["request_end"] = timestamp
        pairs = {"request_total": ("accepted", "request_end"),
                 "local_before_dispatch": ("accepted", "upstream_dispatch"),
                 "upstream_total": ("upstream_dispatch", "upstream_end"),
                 "time_to_headers": ("upstream_dispatch", "upstream_headers"),
                 "time_to_first_byte": ("upstream_dispatch", "upstream_first_byte"),
                 "first_byte_to_end": ("upstream_first_byte", "upstream_end"),
                 "delivery": ("response_delivery_start", "response_delivery_end")}
        durations = {key: self.timestamps[end] - self.timestamps[start]
                     if start in self.timestamps and end in self.timestamps else None
                     for key, (start, end) in pairs.items()}
        durations["settle_and_validate"] = None  # settlement belongs to the Host broker
        self.owner._append({**self.base("MODEL_REQUEST_FINISHED", timestamp), **self.fields,
            "timestamps_ns": dict(self.timestamps), "durations_ns": durations,
            "upstream_timing_scope": "AGENT_LOCAL_TRANSPORT_TO_BUDGET_BROKER; INCLUDES_HOST_BUFFERED_PROVIDER_RESPONSE",
            "first_byte_timing_scope": "FIRST_BROKER_BODY_BYTE; HOST_BUFFERING_PREVENTS_PROVIDER_FIRST_TOKEN_MEASUREMENT",
            "delivery_timing_scope": "LOCAL_SOCKET_WRITE_AND_FLUSH; MAY_OVERLAP_UPSTREAM; NOT_CLIENT_RECEIPT",
            "sse_delivery": "BYTE_IDENTICAL_RELAY_OF_HOST_BUDGET_BUFFERED_SSE"})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False
    request_queue_size = 8

    def __init__(self, owner):
        self.owner = owner
        self.slots = threading.BoundedSemaphore(4)
        super().__init__(("127.0.0.1", 0), _Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.close_request(request)
            return
        self.owner._track(request)
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.owner._untrack(request)
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.owner._untrack(request)
            self.slots.release()

    def handle_error(self, request, client_address):
        # Errors enter the sanitized timing ledger; traceback text could expose
        # an exception's provider payload or local credential-bearing headers.
        with self.owner._lock:
            self.owner.metadata["collection_errors"] += 1


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(15)

    def log_message(self, *args):
        pass

    def _error(self, status, code):
        body = _canonical({"error": code, "retry_allowed": False})
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()
        self.close_connection = True

    def do_POST(self):
        owner = self.server.owner
        if self.path != "/v1/responses":
            return self._error(404, "RESPONSES_ONLY")
        if (len(self.headers.get_all("Authorization", [])) != 1
                or not secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + owner._token)):
            return self._error(401, "LOCAL_PROXY_CREDENTIAL_REQUIRED")
        if (len(self.headers.get_all("X-Benchmark-Task", [])) != 1
                or self.headers.get("X-Benchmark-Task") != owner.task_label):
            return self._error(400, "EXACT_REGISTERED_TASK_LABEL_REQUIRED")
        timing = _Timing(owner)
        connection = None
        upstream_socket = None
        delivered_headers = False
        try:
            if len(self.headers.get_all("Content-Length", [])) != 1 or self.headers.get("Transfer-Encoding"):
                raise ValueError("unambiguous content length required")
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_REQUEST_BYTES:
                raise ValueError("request exceeds bound")
            payload = self.rfile.read(length)
            if len(payload) != length:
                raise ValueError("incomplete request")
            connection = http.client.HTTPConnection("127.0.0.1", owner._upstream_port, timeout=180)
            timing.mark("MODEL_UPSTREAM_DISPATCHED", "upstream_dispatch")
            connection.connect()
            upstream_socket = connection.sock
            owner._track(upstream_socket)
            connection.request("POST", "/v1/responses", body=payload,
                headers={"Authorization": self.headers["Authorization"],
                         "X-Benchmark-Task": self.headers["X-Benchmark-Task"],
                         "Content-Type": self.headers.get("Content-Type", "application/json"),
                         "Accept": self.headers.get("Accept", "text/event-stream"),
                         "Connection": "close"})
            with connection.getresponse() as response:
                timing.fields["upstream_http_status"] = response.status
                timing.mark("MODEL_UPSTREAM_HEADERS", "upstream_headers")
                content_length = response.getheader("Content-Length")
                if content_length is not None and not 0 <= int(content_length) <= MAX_RESPONSE_BYTES:
                    raise ValueError("response exceeds bound")
                timing.fields["http_status"] = response.status
                timing.mark("MODEL_RESPONSE_DELIVERY_STARTED", "response_delivery_start")
                self.send_response(response.status)
                self.send_header("Content-Type", response.getheader("Content-Type", "application/octet-stream"))
                if content_length is not None:
                    self.send_header("Content-Length", content_length)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.flush()
                delivered_headers = True
                chunks, size = [], 0
                while size <= MAX_RESPONSE_BYTES:
                    chunk = response.read1(min(65536, MAX_RESPONSE_BYTES + 1 - size))
                    if not chunk:
                        break
                    if not chunks:
                        timing.mark("MODEL_UPSTREAM_FIRST_BYTE", "upstream_first_byte")
                    size += len(chunk)
                    if size > MAX_RESPONSE_BYTES:
                        raise ValueError("response exceeds bound")
                    chunks.append(chunk)
                    self.wfile.write(chunk)
                    self.wfile.flush()
                timing.mark("MODEL_UPSTREAM_END", "upstream_end")
                if content_length is not None and size != int(content_length):
                    raise ValueError("truncated upstream response")
                timing.mark("MODEL_RESPONSE_DELIVERY_END", "response_delivery_end")
                timing.fields.update(_response_metadata(b"".join(chunks)))
                timing.fields["outcome"] = "DELIVERED" if response.status == 200 else "UPSTREAM_HTTP_ERROR"
        except Exception as error:
            timing.fields["error_class"] = type(error).__name__
            timing.fields["outcome"] = "TRANSPORT_OR_DELIVERY_FAILED"
            if "upstream_dispatch" in timing.timestamps and "upstream_end" not in timing.timestamps:
                timing.mark("MODEL_UPSTREAM_END", "upstream_end")
            if not delivered_headers:
                status = 400 if "upstream_dispatch" not in timing.timestamps else 502
                timing.fields["http_status"] = status
                timing.mark("MODEL_RESPONSE_DELIVERY_STARTED", "response_delivery_start")
                self._error(status, "MODEL_TRANSPORT_FAILED")
                timing.mark("MODEL_RESPONSE_DELIVERY_END", "response_delivery_end")
        finally:
            self.close_connection = True
            if connection is not None:
                connection.close()
            if upstream_socket is not None:
                owner._untrack(upstream_socket)
            timing.finish()


class ModelTransportProxy:
    """One bounded, loopback-only proxy per Agent run; start returns self."""
    def __init__(self, directory, upstream_base_url, token, task_label):
        endpoint = urlsplit(upstream_base_url)
        if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1" or endpoint.port is None
                or endpoint.path != "/v1" or endpoint.username or endpoint.password
                or endpoint.query or endpoint.fragment):
            raise ValueError("explicit loopback HTTP budget broker /v1 endpoint required")
        if not isinstance(token, str) or not 1 <= len(token) <= 512 or any(c.isspace() for c in token):
            raise ValueError("bounded local broker token required")
        if not isinstance(task_label, str) or not OPAQUE_ID.fullmatch(task_label):
            raise ValueError("bounded task label required")
        self.directory = Path(directory)
        self.path = self.directory / TIMING_FILENAME
        self.task_label = task_label
        self._token = token
        self._upstream_port = endpoint.port
        self._lock = threading.Lock()
        self._stop_lock = threading.Lock()
        self._socket_condition = threading.Condition()
        self._sockets = set()
        self._server = self._thread = None
        self._base_url = None
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if not re.fullmatch(r"[0-9a-f-]{36}", self.boot_id):
            raise ValueError("Linux boot identity required")
        self.metadata = {"schema_version": 1, "status": "NOT_STARTED", "clock": "CLOCK_MONOTONIC",
                         "boot_id": self.boot_id, "task_label": task_label, "file": TIMING_FILENAME,
                         "source": "AGENT_LOCAL_TRANSPORT_PROXY", "requests_started": 0,
                         "requests_finished": 0, "collection_errors": 0,
                         "upstream_timing_scope": "AGENT_LOCAL_TRANSPORT_TO_BUDGET_BROKER; INCLUDES_HOST_BUFFERED_PROVIDER_RESPONSE",
                         "privacy": "IDENTIFIERS_TIMESTAMPS_COUNTS_STATUS_ONLY; NO_PROMPTS_OR_SSE"}

    @property
    def base_url(self):
        if self._base_url is None:
            raise RuntimeError("model transport proxy has not started")
        return self._base_url

    def _append(self, record):
        encoded = _canonical(record)
        with self._lock:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                info = os.fstat(descriptor)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_mode & 0o077 or info.st_size + len(encoded) > MAX_LEDGER_BYTES):
                    raise ValueError("owned private bounded timing ledger required")
                offset = 0
                while offset < len(encoded):
                    written = os.write(descriptor, encoded[offset:])
                    if written <= 0:
                        raise OSError("short timing append")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if record["event"] == "MODEL_REQUEST_FINISHED":
                self.metadata["requests_finished"] += 1
            elif record["event"] == "MODEL_REQUEST_ACCEPTED":
                self.metadata["requests_started"] += 1

    def _track(self, connection):
        with self._socket_condition:
            self._sockets.add(connection)

    def _untrack(self, connection):
        with self._socket_condition:
            self._sockets.discard(connection)
            self._socket_condition.notify_all()

    def start(self):
        if self._server is not None:
            return self
        self.directory.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._server = _Server(self)
        self._base_url = f"http://127.0.0.1:{self._server.server_port}/v1"
        self._thread = threading.Thread(target=self._server.serve_forever,
            kwargs={"poll_interval": .05}, name="model-transport-timing", daemon=True)
        self.metadata["status"] = "RUNNING"
        self._thread.start()
        return self

    def stop(self):
        with self._stop_lock:
            return self._stop()

    def _stop(self):
        if self._server is None:
            return dict(self.metadata)
        stop_begin = time.monotonic_ns()
        self._server.shutdown()
        self._server.server_close()
        with self._socket_condition:
            for connection in tuple(self._sockets):
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            deadline = time.monotonic() + 2
            while self._sockets and time.monotonic() < deadline:
                self._socket_condition.wait(max(0, deadline - time.monotonic()))
            active_connections = len(self._sockets)
        self._thread.join(timeout=2)
        self._server = None
        with self._lock:
            reasons = []
            if active_connections:
                reasons.append("INFLIGHT_CONNECTIONS_REMAIN_AFTER_STOP_TIMEOUT")
            if self.metadata["collection_errors"]:
                reasons.append("COLLECTION_ERRORS")
            if self.metadata["requests_started"] != self.metadata["requests_finished"]:
                reasons.append("REQUEST_COUNT_MISMATCH")
            self.metadata.update(status="PARTIAL" if reasons else "STOPPED",
                artifact=TIMING_FILENAME, summary_artifact=SUMMARY_FILENAME,
                active_connections_at_stop=active_connections, reason_flags=reasons,
                stop_begin_ns=stop_begin, stop_end_ns=time.monotonic_ns(),
                inflight_stop_timeout_seconds=2)
            summary = dict(self.metadata)
        # Every execution adapter closes this proxy in a finally/context
        # manager. Persist the completeness receipt here so failures cannot
        # disappear merely because no MODEL_REQUEST_FINISHED row was emitted.
        # Run manifests bind this sibling file along with the timing journal.
        descriptor = os.open(self.directory / SUMMARY_FILENAME,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(summary))
            stream.flush()
            os.fsync(stream.fileno())
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return summary

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.stop()
