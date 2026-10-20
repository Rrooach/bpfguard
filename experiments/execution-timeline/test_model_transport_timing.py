"""Actual local HTTP transport tests; no external network or paid model calls."""
from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from urllib.parse import urlsplit

import model_transport_timing as M


def terminal_sse():
    response = {"id": "resp-local-fixture", "model": "fixture-model",
        "output": [{"type": "function_call", "call_id": "call-local-fixture",
                    "name": "observer_bash", "arguments": "private-output-arguments"}],
        "usage": {"input_tokens": 37, "output_tokens": 9, "total_tokens": 46}}
    return b"event: response.completed\r\ndata: " + json.dumps(
        {"type": "response.completed", "response": response}).encode() + b"\r\n\r\n"


class _UpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_POST(self):
        test = self.server.test
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        test.received.append({"path": self.path, "payload": payload,
                              "auth": self.headers.get("Authorization"),
                              "label": self.headers.get("X-Benchmark-Task")})
        time.sleep(test.delay_headers)
        self.send_response(test.upstream_status)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(test.body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.flush()
        time.sleep(test.delay_body)
        split = len(test.body) // 2
        try:
            self.wfile.write(test.body[:split]); self.wfile.flush()
            time.sleep(test.delay_tail)
            self.wfile.write(test.body[split:]); self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class ModelTransportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.received = []
        self.delay_headers = self.delay_body = self.delay_tail = 0
        self.upstream_status = 200
        self.body = terminal_sse()
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _UpstreamHandler)
        self.server.test = self
        self.thread = threading.Thread(target=self.server.serve_forever,
            kwargs={"poll_interval": .01}, daemon=True)
        self.thread.start()
        self.proxy = M.ModelTransportProxy(Path(self.temp.name) / "app",
            f"http://127.0.0.1:{self.server.server_port}/v1", "local-dummy-secret", "fixture-task")
        self.proxy.start()

    def tearDown(self):
        self.proxy.stop()
        self.server.shutdown(); self.server.server_close(); self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, body=b'{"input":"private-input-prompt"}', token="local-dummy-secret", label="fixture-task"):
        endpoint = urlsplit(self.proxy.base_url)
        connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=3)
        try:
            connection.request("POST", "/v1/responses", body=body,
                headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                         "X-Benchmark-Task": label, "Accept": "text/event-stream"})
            with connection.getresponse() as response:
                return response.status, response.read()
        finally:
            connection.close()

    def finished(self):
        deadline = time.monotonic() + 2
        while True:
            rows = [json.loads(line) for line in self.proxy.path.read_bytes().splitlines()]
            final = [row for row in rows if row["event"] == "MODEL_REQUEST_FINISHED"]
            if final:
                return rows, final[0]
            if time.monotonic() >= deadline:
                self.fail("final local model transport timing was not committed")
            time.sleep(.005)

    def test_delayed_local_transport_is_byte_exact_and_measured_on_agent_clock(self):
        self.delay_headers, self.delay_body, self.delay_tail = .025, .030, .020
        before = time.monotonic_ns()
        payload = b'{"input":"private-input-prompt","tools":[{"arguments":"private-input-arguments"}]}'
        status, received = self.request(payload)
        self.assertEqual(status, 200)
        self.assertEqual(received, self.body)
        rows, final = self.finished()
        after = time.monotonic_ns()
        self.assertEqual(self.received, [{"path": "/v1/responses", "payload": payload,
            "auth": "Bearer local-dummy-secret", "label": "fixture-task"}])
        self.assertEqual(final["boot_id"], Path("/proc/sys/kernel/random/boot_id").read_text().strip())
        self.assertEqual(final["clock"], "CLOCK_MONOTONIC")
        self.assertEqual(final["source"], "AGENT_LOCAL_TRANSPORT_PROXY")
        self.assertEqual(final["task_label"], "fixture-task")
        self.assertEqual(final["outcome"], "DELIVERED")
        self.assertEqual(final["http_status"], 200)
        self.assertEqual(final["provider_response_id"], "resp-local-fixture")
        self.assertEqual(final["output_tool_call_ids"], ["call-local-fixture"])
        self.assertEqual(final["output_link_status"], "COMPLETE")
        self.assertEqual(final["usage"], {"input_tokens": 37, "output_tokens": 9, "total_tokens": 46})
        stamps, durations = final["timestamps_ns"], final["durations_ns"]
        self.assertLessEqual(before, stamps["accepted"])
        self.assertLessEqual(stamps["request_end"], after)
        self.assertGreaterEqual(durations["time_to_headers"], 20_000_000)
        self.assertGreaterEqual(stamps["upstream_first_byte"] - stamps["upstream_headers"], 25_000_000)
        self.assertGreaterEqual(durations["first_byte_to_end"], 15_000_000)
        self.assertGreaterEqual(durations["request_total"], 65_000_000)
        self.assertIsNone(durations["settle_and_validate"])
        self.assertIn("HOST_BUFFER", final["upstream_timing_scope"])
        self.assertEqual(len({row["request_id"] for row in rows}), 1)
        exported = self.proxy.path.read_text()
        for secret in ("private-input-prompt", "private-input-arguments", "private-output-arguments", "local-dummy-secret"):
            self.assertNotIn(secret, exported)
        self.assertEqual(self.proxy.path.stat().st_mode & 0o077, 0)
        metadata = self.proxy.stop()
        self.assertEqual(metadata["status"], "STOPPED")
        self.assertEqual(metadata["requests_finished"], 1)
        summary = json.loads((self.proxy.directory / M.SUMMARY_FILENAME).read_text())
        self.assertEqual(summary, metadata)
        self.assertEqual(summary["reason_flags"], [])
        self.assertEqual(summary["artifact"], M.TIMING_FILENAME)
        self.assertEqual(summary["summary_artifact"], M.SUMMARY_FILENAME)
        self.assertLessEqual(summary["stop_begin_ns"], summary["stop_end_ns"])
        self.assertEqual(self.proxy.stop(), summary)  # repeated finally cleanup is idempotent

    def test_unfinished_request_is_persisted_as_partial_even_without_final_timing_row(self):
        M._Timing(self.proxy)
        summary = self.proxy.stop()
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["requests_started"], 1)
        self.assertEqual(summary["requests_finished"], 0)
        self.assertIn("REQUEST_COUNT_MISMATCH", summary["reason_flags"])
        persisted = json.loads((self.proxy.directory / M.SUMMARY_FILENAME).read_text())
        self.assertEqual(summary, persisted)
        self.assertNotIn(b"MODEL_REQUEST_FINISHED", self.proxy.path.read_bytes())

    def test_failed_timing_finalization_is_not_hidden_after_delivered_model_output(self):
        original = self.proxy._append
        def interrupted(record):
            if record["event"] == "MODEL_REQUEST_FINISHED":
                raise OSError("private-error-details-must-not-be-exported")
            return original(record)
        with mock.patch.object(self.proxy, "_append", side_effect=interrupted):
            self.assertEqual(self.request(), (200, self.body))
            deadline = time.monotonic() + 2
            while not self.proxy.metadata["collection_errors"] and time.monotonic() < deadline:
                time.sleep(.005)
            summary = self.proxy.stop()
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["collection_errors"], 1)
        self.assertEqual(summary["requests_started"], 1)
        self.assertEqual(summary["requests_finished"], 0)
        self.assertEqual(set(summary["reason_flags"]), {"COLLECTION_ERRORS", "REQUEST_COUNT_MISMATCH"})
        exported = (self.proxy.directory / M.SUMMARY_FILENAME).read_text()
        self.assertNotIn("private-error-details", exported)
        self.assertNotIn("local-dummy-secret", exported)

    def test_stop_timeout_keeps_a_durable_partial_receipt(self):
        class UnfinishedConnection:
            def shutdown(self, how):
                pass
        active = UnfinishedConnection()
        self.proxy._track(active)
        begin = time.monotonic()
        summary = self.proxy.stop()
        elapsed = time.monotonic() - begin
        self.assertGreaterEqual(elapsed, 1.9)
        self.assertLess(elapsed, 3)
        self.assertEqual(summary["status"], "PARTIAL")
        self.assertEqual(summary["active_connections_at_stop"], 1)
        self.assertIn("INFLIGHT_CONNECTIONS_REMAIN_AFTER_STOP_TIMEOUT", summary["reason_flags"])
        self.assertEqual(json.loads((self.proxy.directory / M.SUMMARY_FILENAME).read_text()), summary)
        self.proxy._untrack(active)

    def test_auth_and_exact_task_label_are_checked_before_upstream(self):
        self.assertEqual(self.request(token="wrong")[0], 401)
        self.assertEqual(self.request(label="other-task")[0], 400)
        self.assertEqual(self.received, [])
        self.assertEqual(self.proxy.path.read_bytes(), b"")

    def test_oversize_request_is_rejected_without_forwarding(self):
        status, body = self.request(b"x" * (M.MAX_REQUEST_BYTES + 1))
        self.assertEqual(status, 400)
        self.assertEqual(self.received, [])
        _, final = self.finished()
        self.assertIsNone(final["durations_ns"]["upstream_total"])
        self.assertEqual(final["error_class"], "ValueError")
        self.assertFalse(json.loads(body)["retry_allowed"])

    def test_oversize_response_is_not_retried_or_persisted(self):
        with mock.patch.object(M, "MAX_RESPONSE_BYTES", 32):
            status, _ = self.request()
            self.assertEqual(status, 502)
            _, final = self.finished()
        self.assertEqual(len(self.received), 1)
        self.assertEqual(final["outcome"], "TRANSPORT_OR_DELIVERY_FAILED")
        self.assertEqual(final["upstream_http_status"], 200)
        self.assertNotIn("upstream_first_byte", final["timestamps_ns"])
        self.assertEqual(list((Path(self.temp.name) / "app").iterdir()), [self.proxy.path])

    def test_upstream_error_is_forwarded_once_without_following_redirect(self):
        self.upstream_status = 302
        status, received = self.request()
        self.assertEqual(status, 302)
        self.assertEqual(received, self.body)
        _, final = self.finished()
        self.assertEqual(final["outcome"], "UPSTREAM_HTTP_ERROR")
        self.assertEqual(final["http_status"], 302)
        self.assertEqual(len(self.received), 1)

    def test_proxy_will_not_overwrite_existing_timing_evidence(self):
        other = M.ModelTransportProxy(Path(self.temp.name) / "app",
            f"http://127.0.0.1:{self.server.server_port}/v1", "local-dummy-secret", "fixture-task")
        with self.assertRaises(FileExistsError):
            other.start()

    def test_upstream_endpoint_must_be_the_explicit_local_budget_broker(self):
        for url in ("https://127.0.0.1:1/v1", "http://example.com:80/v1", "http://127.0.0.1/v1",
                    "http://127.0.0.1:1/other", "http://user:key@127.0.0.1:1/v1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                M.ModelTransportProxy(self.temp.name, url, "dummy-token", "fixture-task")


if __name__ == "__main__":
    unittest.main()
