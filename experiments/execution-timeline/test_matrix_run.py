"""Offline-only matrix contract checks: no Docker, cgroup, BPF, or API use."""
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import tempfile
import unittest
from unittest import mock

from common import digest, write_new
import matrix_run as matrix
from test_kprobe_contract import fixture as hook_fixture


class MatrixTests(unittest.TestCase):
    def test_explicit_next_requires_correct_boot_group_and_sealed_receipt(self):
        for mode in ("correct", "boot", "group", "digest", "symlink", "timeout"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                completed = root / "sealed-completed.json"
                write_new(completed, {"synthetic_only": True})
                acknowledgment = root / "00-swe-c6-r001-next.json"
                value = {"schema_version": 1, "event": "NEXT", "boot_id": "synthetic-boot",
                         "group_name": "swe-c6-r001", "completed_receipt_identity": digest(completed)}
                if mode == "boot":
                    value["boot_id"] = "other-boot"
                elif mode == "group":
                    value["group_name"] = "other-group"
                elif mode == "digest":
                    value["completed_receipt_identity"] = {"sha256": "0" * 64, "size_bytes": 0}
                if mode == "symlink":
                    target = root / "untrusted"
                    write_new(target, value)
                    acknowledgment.symlink_to(target)
                elif mode != "timeout":
                    write_new(acknowledgment, value)
                if mode == "correct":
                    result = matrix.await_next(root, 0, "swe-c6-r001", completed, "synthetic-boot", 0.01)
                    self.assertEqual(result["status"], "EXPLICIT_NEXT_OBSERVED")
                else:
                    with self.assertRaises((ValueError, TimeoutError)):
                        matrix.await_next(root, 0, "swe-c6-r001", completed, "synthetic-boot", 0.01)
                waiting = json.loads((root / "00-swe-c6-r001-awaiting-next.json").read_text())
                self.assertEqual(waiting["expected_acknowledgment"]["completed_receipt_identity"], digest(completed))

    def test_root_only_absent_limits_are_explicit_not_guessed_unlimited(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "cgroup.controllers").write_text("cpu cpuset memory pids\n")
            (root / "cgroup.subtree_control").write_text("\n")
            (root / "cpuset.cpus.effective").write_text("0-15\n")
            (root / "cpuset.mems.effective").write_text("0\n")
            limits = matrix.cgroup_limits(root, root)["hierarchy"][0]["limits"]
            self.assertEqual(limits["cpu.max"], {"status": "NOT_EXPOSED_AT_CGROUP_ROOT", "value": None})
            self.assertEqual(limits["cpuset.cpus.effective"], {"status": "EXPOSED", "value": "0-15"})
            child = root / "child"
            child.mkdir()
            (child / "cgroup.controllers").write_text("\n")
            (child / "cgroup.subtree_control").write_text("\n")
            chain = matrix.cgroup_limits(child, root)["hierarchy"]
            self.assertEqual(chain[0]["limits"]["cpuset.cpus.effective"],
                             {"status": "NOT_EXPOSED_CONTROLLER_DISABLED_IN_PARENT", "value": None})
            self.assertEqual(chain[1]["limits"]["cpuset.cpus.effective"]["value"], "0-15")
            (root / "cgroup.subtree_control").write_text("cpu cpuset memory pids\n")
            with self.assertRaisesRegex(ValueError, "enabled parent controller"):
                matrix.cgroup_limits(child, root)
            (root / "cpuset.mems.effective").unlink()
            with self.assertRaisesRegex(ValueError, "root effective"):
                matrix.cgroup_limits(root, root)

    def inputs(self, root, label="terminal"):
        sources = root / "sources"
        sources.mkdir(exist_ok=True)
        names = ("common.py", "parallel_run.py", "phase_control.py", "parallel_terminal.py", "parallel_swe.py", "terminal_validate.py")
        for name in names:
            if not (sources / name).exists():
                (sources / name).write_text("synthetic source " + name)
        native = root / "collect"
        bpf = root / "execution_timeline.bpf.o"
        if not native.exists():
            native.write_bytes(b"synthetic not executable collector")
            bpf.write_bytes(b"synthetic not loadable BPF")
        config = {"inference_api_calls": 0, "total_preloaded_collectors": 8, "ring_bytes_per_collector": 67108864,
                  "vcpus": 16, "memory_mib": 65536, "source_identities": {name: digest(sources / name) for name in names},
                  "collector_identity": digest(native), "bpf_object_identity": digest(bpf),
                  "original_task_cpu_memory_quotas_preserved": True, "sampler_interval_ms": 100,
                  "sampler_process_polling": False, "read_hook_backend": "OWNED_TRACEFS_KPROBE_KRETPROBE"}
        command = [sys.executable, "-B", str(sources / ("parallel_terminal.py" if label == "terminal" else "parallel_swe.py")),
                   "--collector", str(native), "--object", str(bpf), "--output", "@JOB_OUTPUT@",
                   "--control-dir", "@CONTROL_DIR@", "--job-id", "@JOB_ID@", "--capture-only"]
        if label == "swe":
            directory = root / "inputs"
            directory.mkdir(exist_ok=True)
            for name in ("task.json", "provenance.json"):
                (directory / name).write_text("{}")
            command.extend(["--inputs", str(directory)])
        plan = {"schema_version": 1, "benchmark": matrix.BENCHMARKS[label],
                "scope": "OFFICIAL_ORACLE_REFERENCE_8_REPLICAS_NOT_MODEL_SCORE", "resource_configuration": config,
                "jobs": [{"job_id": label + f"-{number:02d}", "task_id": "synthetic-task",
                          "command": list(command)} for number in range(8)]}
        path = root / (label + "-plan.json")
        write_new(path, plan)
        return path, plan, sources

    def test_pin_plan_native_sources_and_no_paid_or_probe_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, plan, sources = self.inputs(root)
            plans, pins, resources = matrix.prepare_plans(["terminal=" + str(path)], sources)
            self.assertEqual(len(plans[0]["plan"]["jobs"]), 8)
            self.assertEqual(resources["by_benchmark"]["terminal"], plan["resource_configuration"])
            matrix.check_pins(pins)
            (root / "collect").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "changed"):
                matrix.check_pins(pins)

    def test_fixed_plan_and_reference_requirements_fail_closed(self):
        changes = [lambda p: p["resource_configuration"].update(inference_api_calls=1),
                   lambda p: p["resource_configuration"].update(total_preloaded_collectors=2),
                   lambda p: p.update(scope="unlabelled model score"),
                   lambda p: p["jobs"][0]["command"].append("--search-probe"),
                   lambda p: p["jobs"][0]["command"].extend(["--model", "remote-model"]),
                   lambda p: p["jobs"][0]["command"].extend(["--collector", "/unexpected"]),
                   lambda p: p["resource_configuration"]["collector_identity"].update(sha256="0" * 64)]
        for change in changes:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                path, plan, sources = self.inputs(Path(directory))
                change(plan)
                path.write_text(json.dumps(plan))
                with self.assertRaises(ValueError):
                    matrix.prepare_plans(["terminal=" + str(path)], sources)

    def test_benchmark_specific_config_is_preserved_but_common_resources_and_labels_must_match(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            terminal, _plan, sources = self.inputs(root)
            swe, plan, _sources = self.inputs(root, "swe")
            matrix.prepare_plans(["terminal=" + str(terminal), "swe=" + str(swe)], sources)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                matrix.prepare_plans(["terminal=" + str(terminal)] * 2, sources)
            plan["resource_configuration"]["collector_cpus"] = "UNBOUND_WITHIN_16_VCPUS"
            plan["resource_configuration"]["official_evaluation"] = "UNCHANGED_RUN_INSTANCE_TESTS_INSIDE_MEASURED_EPISODE"
            del plan["resource_configuration"]["original_task_cpu_memory_quotas_preserved"]
            swe.write_text(json.dumps(plan))
            _, _, configurations = matrix.prepare_plans(["terminal=" + str(terminal), "swe=" + str(swe)], sources)
            self.assertEqual(configurations["by_benchmark"]["swe"]["collector_cpus"], "UNBOUND_WITHIN_16_VCPUS")
            plan["resource_configuration"]["sampler_interval_ms"] = 200
            swe.write_text(json.dumps(plan))
            with self.assertRaises(ValueError):
                matrix.prepare_plans(["terminal=" + str(terminal), "swe=" + str(swe)], sources)

    def test_quiet_check_is_read_only_and_blocks_workers_containers_or_hooks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trace = root / "trace"
            trace.mkdir()
            (trace / "kprobe_events").write_text("")
            proc = root / "proc"
            proc.mkdir()
            with mock.patch.object(matrix, "docker_value", return_value="") as docker:
                self.assertEqual(matrix.assert_quiet(proc, trace)["docker_containers"], [])
                docker.assert_called_once_with("ps", "--all", "--quiet", "--no-trunc")
            with mock.patch.object(matrix, "docker_value", return_value="existing-container"):
                with self.assertRaisesRegex(ValueError, "manual scoped"):
                    matrix.assert_quiet(proc, trace)
            (trace / "kprobe_events").write_text("p:allox_execution_timeline/owned vfs_read\n")
            with mock.patch.object(matrix, "docker_value", return_value=""):
                with self.assertRaisesRegex(ValueError, "kprobes remain"):
                    matrix.assert_quiet(proc, trace)
            (proc / "999999").mkdir()
            (proc / "999999/cmdline").write_bytes(b"python3\0/opt/execution-timeline/parallel_swe.py\0")
            with self.assertRaisesRegex(ValueError, "worker/controller/collector conflict"):
                matrix.assert_quiet(proc, trace)
            self.assertTrue((proc / "999999/cmdline").exists())
            self.assertIn("owned", (trace / "kprobe_events").read_text())

    def group_fixture(self, root):
        path, plan, _sources = self.inputs(root)
        entry = {"path": str(path), "identity": digest(path), "benchmark": plan["benchmark"], "plan": plan}
        output = root / "group"
        output.mkdir()
        campaign = {"status": "WORKERS_COMPLETED", "total_jobs": 8, "concurrency": 4,
                    "boot_id": "synthetic-boot", "plan_identity": entry["identity"],
                    "resource_configuration": plan["resource_configuration"], "jobs": plan["jobs"]}
        write_new(output / "campaign.json", campaign)
        for spec in plan["jobs"]:
            job = output / "jobs" / spec["job_id"]
            timeline = job / "timeline"
            capture = timeline / "capture"
            capture.mkdir(parents=True)
            receipt, meta, health = hook_fixture()
            health["records"] = 10
            write_new(job / "worker-result.json", {"job_id": spec["job_id"], "mode": "ORACLE_REFERENCE",
                "official_passed": True, "benchmark": plan["benchmark"], "task_id": spec["task_id"],
                "timeline_directory": "timeline"})
            for name, value in (("health.json", health), ("meta.json", meta), ("kprobe-hooks.json", receipt)):
                write_new(capture / name, value)
            write_new(timeline / "manifest.json", {"boot_id": "synthetic-boot", "capture_directory": "capture",
                "collector_identity": plan["resource_configuration"]["collector_identity"],
                "bpf_object_identity": plan["resource_configuration"]["bpf_object_identity"],
                "artifacts": {"capture/" + name: digest(capture / name)
                              for name in ("health.json", "meta.json", "kprobe-hooks.json")}})
        return output, entry

    def test_native_misses_official_failure_and_unsafe_paths_stop_group(self):
        for failure in ("native-miss", "official", "path", "wrong-job", "wrong-boot"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                output, entry = self.group_fixture(Path(directory))
                value = matrix.validate_group(output, entry, 4, "synthetic-boot")
                self.assertEqual(len(value["jobs"]), 8)
                self.assertEqual(value["jobs"][0]["independent_raw_replay"], "PENDING_SEPARATE_VERIFICATION")
                job = output / "jobs/terminal-00"
                if failure == "native-miss":
                    path = job / "timeline/capture/health.json"
                    row = json.loads(path.read_text())
                    row["recursion_misses"] = 1
                elif failure == "wrong-boot":
                    path = job / "timeline/manifest.json"
                    row = json.loads(path.read_text())
                    row["boot_id"] = "different"
                else:
                    path = job / "worker-result.json"
                    row = json.loads(path.read_text())
                    row[{"official": "official_passed", "path": "timeline_directory", "wrong-job": "job_id"}[failure]] = \
                        {"official": False, "path": "../../outside", "wrong-job": "other"}[failure]
                path.write_text(json.dumps(row))
                with self.assertRaises(ValueError):
                    matrix.validate_group(output, entry, 4, "synthetic-boot")

    def options(self, root):
        sampler = root / "sampler"
        sampler.write_bytes(b"not executed synthetic sampler")
        return SimpleNamespace(plans=["synthetic mocked plan"], concurrencies=[6, 8, 4], output=root / "matrix",
            output_prefix="r001", sampler=sampler, expected_boot_id="synthetic-boot", group_timeout=60,
            setup_timeout=1, task_timeout=1, finalize_timeout=1)

    def run_mocked(self, root, *, fail_at=None, changed_identity=False, paused=False):
        args = self.options(root)
        args.pause_between_groups, args.pause_timeout = paused, 1
        plans = [{"label": name, "path": str(root / (name + ".json")), "identity": {"synthetic": True},
                  "benchmark": matrix.BENCHMARKS[name], "scope": "SYNTHETIC_ONLY", "plan": {}}
                 for name in ("terminal", "swe")]
        calls, identity_calls = [], []

        def identity():
            identity_calls.append(None)
            return {"boot_id": "synthetic-boot", "stable": not (changed_identity and len(identity_calls) > 1)}

        def spawn(command, **kwargs):
            calls.append(command)
            row = mock.Mock(pid=1000 + len(calls))
            row.wait.return_value = int(fail_at == len(calls))
            row.poll.return_value = row.wait.return_value
            return row

        with mock.patch.object(matrix, "prepare_plans", return_value=(plans, {}, {})), \
             mock.patch.object(matrix, "guest_identity", side_effect=identity), \
             mock.patch.object(matrix, "assert_quiet", return_value={"synthetic_only": True}), \
             mock.patch.object(matrix, "validate_group", return_value={"synthetic_only": True}), \
             mock.patch.object(matrix, "await_next", return_value={"status": "SYNTHETIC_ACK_ONLY"}) as gate, \
             mock.patch.object(matrix.subprocess, "Popen", side_effect=spawn):
            code = matrix.run(args)
        self.assertEqual(gate.call_count, 5 if paused and not fail_at and not changed_identity else 0)
        return code, calls, json.loads((args.output / "matrix.json").read_text())

    def test_serial_order_and_separate_group_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            code, calls, receipt = self.run_mocked(Path(directory))
            self.assertEqual(code, 0)
            self.assertEqual([int(command[command.index("--concurrency") + 1]) for command in calls], [6, 6, 8, 8, 4, 4])
            outputs = [command[command.index("--output") + 1] for command in calls]
            self.assertEqual(len(set(outputs)), 6)
            self.assertTrue(all("r001" in path for path in outputs))
            self.assertEqual(receipt["paid_api_calls"], 0)
            self.assertFalse(receipt["automatic_cleanup"])

    def test_optional_next_gate_is_used_between_groups_not_after_final(self):
        with tempfile.TemporaryDirectory() as directory:
            code, calls, receipt = self.run_mocked(Path(directory), paused=True)
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 6)
            self.assertIn("next_barrier", receipt["groups"][0])
            self.assertNotIn("next_barrier", receipt["groups"][-1])

    def test_first_failure_stops_later_groups_and_retains_receipt(self):
        with tempfile.TemporaryDirectory() as directory:
            code, calls, receipt = self.run_mocked(Path(directory), fail_at=2)
            self.assertEqual(code, 1)
            self.assertEqual(len(calls), 2)
            self.assertEqual(receipt["status"], "STOPPED_ON_FAILURE")
            self.assertEqual(receipt["groups"][1]["status"], "FAILED_OR_INCOMPLETE_RETAINED")
            self.assertEqual(receipt["groups"][0]["status"], "REFERENCE_AND_TRANSPORT_PASSED_PENDING_INDEPENDENT_REPLAY")

    def test_changed_guest_blocks_before_any_subprocess(self):
        with tempfile.TemporaryDirectory() as directory:
            code, calls, receipt = self.run_mocked(Path(directory), changed_identity=True)
            self.assertEqual(code, 1)
            self.assertEqual(calls, [])
            self.assertIn("identity changed", receipt["error"])

    def test_fresh_output_guard_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.options(root)
            args.output.mkdir()
            original = args.output / "keep"
            original.write_bytes(b"must retain")
            with self.assertRaisesRegex(ValueError, "fresh"):
                matrix.run(args)
            self.assertEqual(original.read_bytes(), b"must retain")


if __name__ == "__main__":
    unittest.main()
