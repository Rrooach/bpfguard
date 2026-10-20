"""One-shot, bounded model calls with durable application-level wait evidence.

No provider credential is accepted here: only the private token for the shared
budget broker. Client waits are not model-server/GPU or kernel causal evidence.
"""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

MODEL = "deepseek-flash"
LABEL = re.compile(r"model-(?:swe|terminal)-c(?:2|4|6|8)-[0-9]{2}\Z")
MAX_RESPONSE = 4 * 1024 * 1024
MAX_REQUEST = 192 * 1024


class ModelRequestError(RuntimeError):
    def __init__(self, kind, request_id, status=None):
        self.kind, self.request_id, self.status = kind, request_id, status
        super().__init__(kind + (" HTTP " + str(status) if status is not None else ""))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def private_token(path):
    fd = os.open(Path(path), os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    with os.fdopen(fd, "r", encoding="utf-8") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("broker token must be an owned private regular file")
        token = stream.read(513).strip()
    if not token or len(token) > 512 or any(char.isspace() for char in token):
        raise ValueError("invalid private broker credential")
    return token


def strict_json(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


class ModelClient:
    def __init__(self, base_url, token_file, budget_label, evidence_directory, *, model=MODEL,
                 max_output=1024, request_timeout=180, boot_id=None, transport=None,
                 clock=time.monotonic_ns):
        parsed = urllib.parse.urlsplit(base_url)
        if (parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "localhost", "10.0.2.2")
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path.rstrip("/") != "/v1" or parsed.port is None):
            raise ValueError("only an explicit local budget-broker HTTP /v1 endpoint is allowed")
        if not LABEL.fullmatch(budget_label) or model != MODEL:
            raise ValueError("explicit campaign job label and fixed model are required")
        if type(max_output) is not int or not 1 <= max_output <= 1024 or request_timeout != 180:
            raise ValueError("model output must be within 1..1024 and request timeout exactly 180 seconds")
        self.base_url, self.model = base_url.rstrip("/"), model
        self.budget_label, self.max_output, self.request_timeout = budget_label, max_output, request_timeout
        self._token = private_token(token_file)
        self.directory = Path(evidence_directory)
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.directory.is_symlink():
            raise ValueError("model evidence directory cannot be a symlink")
        self.boot_id = boot_id or Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.clock, self.transport = clock, transport or self._transport
        self.events, self.steps = [], set()
        self.usage = {"prompt_tokens": 0, "completion_tokens": 0}
        # SWE invokes one client through successive asyncio.run loops; this
        # nonblocking guard is loop-independent and never blocks the loop.
        self._lock = threading.Lock()
        self._paths = {name: self.directory / name for name in ("model-requests.jsonl", "model-transcript.jsonl")}
        for path in self._paths.values():
            with path.open("xb"):
                pass

    def _append(self, name, value):
        raw = json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False).encode() + b"\n"
        with self._paths[name].open("ab") as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())

    def _transport(self, request):
        # No environment proxy or redirect may move a private broker token or
        # a request outside the explicitly configured budget endpoint.
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        with opener.open(request, timeout=self.request_timeout) as response:
            raw = response.read(MAX_RESPONSE + 1)
            if len(raw) > MAX_RESPONSE:
                raise ValueError("model response exceeds bound")
            return strict_json(raw)

    @asynccontextmanager
    async def _one_request(self):
        if not self._lock.acquire(blocking=False):
            raise ValueError("one request per model job may be active at a time")
        try:
            yield
        finally:
            self._lock.release()

    async def request(self, messages, tools, step):
        async with self._one_request():
            if type(step) is not int or not 0 <= step < 4 or step in self.steps:
                raise ValueError("one non-retried request per step 0..3 is permitted")
            self.steps.add(step)
            request_id = self.budget_label + "-step-" + str(step)
            payload = {"model": self.model, "messages": messages, "tools": tools,
                       "max_tokens": self.max_output, "temperature": 0, "stream": False, "n": 1,
                       "thinking": {"type": "disabled"}}
            raw = json.dumps(payload, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()
            if len(raw) > MAX_REQUEST:
                raise ModelRequestError("REQUEST_BOUNDS", request_id)
            request = urllib.request.Request(self.base_url + "/chat/completions", data=raw,
                headers={"Authorization": "Bearer " + self._token, "Content-Type": "application/json",
                         "X-Benchmark-Task": self.budget_label, "X-Request-ID": request_id})
            start = {"schema_version": 1, "event": "MODEL_REQUEST_START", "request_id": request_id,
                     "budget_label": self.budget_label, "model": self.model, "step": step,
                     "boot_id": self.boot_id, "clock": "CLOCK_MONOTONIC", "begin_ns": self.clock(),
                     "request_sha256": hashlib.sha256(raw).hexdigest(), "max_output_tokens": self.max_output,
                     "scope": "APPLICATION_CLIENT_WAIT_NOT_GPU_EXECUTION_OR_CONTAINER_SYSCALL_ATTRIBUTION"}
            self._append("model-transcript.jsonl", {"event": "REQUEST", "request_id": request_id, "payload": payload})
            self._append("model-requests.jsonl", start)
            result, failure, status = None, None, "UNKNOWN"
            try:
                try:
                    result = await asyncio.get_running_loop().run_in_executor(None, self.transport, request)
                except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, socket.timeout):
                    raise
                except OSError:
                    status = "NETWORK_ERROR_UNKNOWN_CHARGE"
                    failure = ModelRequestError(status, request_id)
                    raise failure from None
                self._append("model-transcript.jsonl", {"event": "RESPONSE", "request_id": request_id, "response": result})
                if not isinstance(result, dict) or not isinstance(result.get("choices"), list) or not result["choices"]:
                    raise ValueError("missing choices")
                message = result["choices"][0].get("message")
                if not isinstance(message, dict):
                    raise ValueError("missing model message")
                usage = result.get("usage")
                if not isinstance(usage, dict) or any(type(usage.get(key)) is not int or usage[key] < 0 for key in self.usage):
                    raise ValueError("missing or invalid usage")
                for key in self.usage:
                    self.usage[key] += usage[key]
                status = "RECEIVED"
                return result
            except urllib.error.HTTPError as error:
                status = "BUDGET_OR_REQUEST_LIMIT" if error.code == 429 else "BROKER_HTTP_ERROR"
                failure = ModelRequestError(status, request_id, error.code)
                raise failure from None
            except (TimeoutError, socket.timeout):
                status = "TIMEOUT_UNKNOWN_CHARGE"
                failure = ModelRequestError(status, request_id)
                raise failure from None
            except urllib.error.URLError:
                status = "NETWORK_ERROR_UNKNOWN_CHARGE"
                failure = ModelRequestError(status, request_id)
                raise failure from None
            except ValueError:
                status = "MALFORMED_RESPONSE"
                failure = ModelRequestError(status, request_id)
                raise failure from None
            except asyncio.CancelledError:
                status = "CANCELLED_REQUEST_MAY_STILL_BE_BILLED"
                raise
            finally:
                end = {**start, "event": "MODEL_REQUEST_END", "end_ns": self.clock(), "status": status,
                       "usage": result.get("usage") if isinstance(result, dict) else None,
                       "response_model": result.get("model") if isinstance(result, dict) else None,
                       "failure_kind": failure.kind if failure else None}
                self._append("model-requests.jsonl", end)
                self.events.append(end)

    def artifacts(self):
        return {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                           "size_bytes": path.stat().st_size} for path in self._paths.values()}
