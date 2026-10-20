#!/usr/bin/env python3

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import AsyncMock, patch

import bridge


HEX_A = "a" * 64
HEX_B = "b" * 64


class ComposeNameTests(unittest.TestCase):
    def test_matches_harbor_sanitizer_contract(self) -> None:
        self.assertEqual(bridge.sanitize_compose_project_name("Trial.Name"), "trial-name")
        self.assertEqual(bridge.sanitize_compose_project_name("_Trial"), "0_trial")
        self.assertEqual(bridge.sanitize_compose_project_name("A/B:C"), "a-b-c")


class ComposeOverlayTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_trials_passes_campaign_overlay_to_harbor(self) -> None:
        modules = {
            name: ModuleType(name)
            for name in (
                "harbor", "harbor.models", "harbor.models.environment_type",
                "harbor.models.trial", "harbor.models.trial.config",
                "harbor.trial", "harbor.trial.hooks", "harbor.trial.trial",
            )
        }
        modules["harbor.models.environment_type"].EnvironmentType = SimpleNamespace(
            DOCKER="docker"
        )
        for name in ("AgentConfig", "EnvironmentConfig", "TaskConfig", "TrialConfig"):
            setattr(modules["harbor.models.trial.config"], name, SimpleNamespace)
        modules["harbor.trial.hooks"].TrialEvent = SimpleNamespace()
        # Stop at Harbor's creation boundary: this test only exercises config
        # preparation, and must never launch a container or observer process.
        create = AsyncMock(side_effect=RuntimeError("stop after configuration"))
        modules["harbor.trial.trial"].Trial = SimpleNamespace(create=create)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            task = root / "task"
            task.mkdir()
            arguments = SimpleNamespace(
                expected_harbor_version=bridge.SUPPORTED_HARBOR_VERSION,
                harbor_source_revision=bridge.SUPPORTED_HARBOR_SOURCE_REVISION,
                selection_manifest=root / "selection.json",
                selection_manifest_sha256=HEX_A,
                task=[task],
                evidence_root=root / "campaign",
                trials_dir=root / "trials",
                run_label="compose-test",
                expected_reward=1.0,
                ready_timeout=1.0,
                finish_timeout=1.0,
                docker_timeout=1.0,
                fail_fast=True,
            )
            for name in ("observer", "verifier", "recorder", "lifecycle", "ip", "tc", "nft"):
                suffix = "object" if name in ("recorder", "lifecycle") else "binary"
                setattr(arguments, f"{name}_{suffix}", root / name)
                setattr(arguments, f"{name}_sha256", HEX_A)
            docker = AsyncMock(return_value={"OSType": "linux"})
            mocks = (
                patch.dict(sys.modules, modules),
                patch.object(bridge.os, "geteuid", return_value=0),
                patch.object(
                    bridge, "version", return_value=bridge.SUPPORTED_HARBOR_VERSION
                ),
                patch.object(bridge, "validate_selection_manifest", return_value={}),
                patch.object(
                    bridge, "validate_trusted_file", side_effect=lambda path, *_: path
                ),
                patch.object(
                    bridge, "validate_network_collector", side_effect=lambda path, *_: path
                ),
                patch.object(bridge, "docker_json", new=docker),
                patch("builtins.print"),
            )
            with ExitStack() as stack:
                for mocked in mocks:
                    stack.enter_context(mocked)
                self.assertEqual(await bridge.run_trials(arguments), 1)

            create.assert_awaited_once()
            config = create.await_args.args[0]
            overlay = arguments.evidence_root / "observer-compose.yaml"
            self.assertEqual(config.environment.extra_docker_compose, [overlay])
            self.assertEqual(config.environment.type, "docker")
            self.assertTrue(config.environment.delete)
            self.assertEqual(overlay.read_bytes(), b"services:\n  main: {}\n")
            self.assertEqual(config.task.path, task)
            self.assertEqual(list(task.iterdir()), [])
            docker.assert_awaited_once_with("info", "--format", "{{json .}}", timeout=30)


class CgroupTests(unittest.TestCase):
    def test_parses_unified_membership(self) -> None:
        self.assertEqual(
            bridge.parse_proc_cgroup(f"0::/system.slice/docker-{HEX_A}.scope\n"),
            f"/system.slice/docker-{HEX_A}.scope",
        )

    def test_rejects_root_and_hybrid_membership(self) -> None:
        with self.assertRaises(bridge.BridgeError):
            bridge.parse_proc_cgroup("0::/\n")
        with self.assertRaises(bridge.BridgeError):
            bridge.parse_proc_cgroup("0::/one\n0::/two\n")

    def test_container_binding_requires_full_component(self) -> None:
        self.assertTrue(
            bridge.cgroup_binds_container(f"/docker/{HEX_A}", HEX_A)
        )
        self.assertTrue(
            bridge.cgroup_binds_container(
                f"/system.slice/docker-{HEX_A}.scope", HEX_A
            )
        )
        self.assertFalse(
            bridge.cgroup_binds_container(f"/docker-{HEX_A}-suffix.scope", HEX_A)
        )
        self.assertFalse(bridge.cgroup_binds_container(f"/docker/{HEX_A}", "abcd"))


class NetworkInterfaceTests(unittest.TestCase):
    def test_parses_and_canonically_sorts_proc_net_dev(self) -> None:
        header = (
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
        )
        counters = " ".join(str(value) for value in range(16))
        observed = bridge.parse_proc_net_dev(
            f"{header}    lo: {counters}\n  eth0: {counters}\n"
        )
        self.assertEqual(observed, ("eth0", "lo"))

    def test_rejects_malformed_or_duplicate_proc_net_dev(self) -> None:
        header = (
            "Inter-|   Receive | Transmit\n"
            " face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
        )
        counters = " ".join("0" for _ in range(16))
        with self.assertRaises(bridge.BridgeError):
            bridge.parse_proc_net_dev(f"{header}lo: {counters}\nlo: {counters}\n")
        with self.assertRaises(bridge.BridgeError):
            bridge.parse_proc_net_dev(f"{header}eth0: 0 0\n")

    def test_interface_scope_requires_strict_order_and_ascii(self) -> None:
        self.assertEqual(
            bridge.validate_network_interfaces(("eth0", "lo")),
            ("eth0", "lo"),
        )
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_network_interfaces(("lo", "eth0"))
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_network_interfaces(("éth0",))


class SelectionManifestTests(unittest.TestCase):
    def fixture(self, root: Path) -> tuple[Path, Path, str]:
        task = root / "sample-task"
        environment = task / "environment"
        environment.mkdir(parents=True)
        (task / "instruction.md").write_text("do the small thing\n", encoding="utf-8")
        (task / "task.toml").write_text(
            '[task]\nname = "terminal-bench/sample-task"\n', encoding="utf-8"
        )
        (environment / "Dockerfile").write_text("FROM scratch\n", encoding="utf-8")

        relative_paths = ["environment/Dockerfile", "instruction.md", "task.toml"]
        source_inputs = []
        aggregate_input = bytearray()
        for relative in relative_paths:
            digest = bridge.sha256_file(task / relative)
            source_inputs.append({"path": relative, "sha256": digest})
            aggregate_input.extend(f"{digest}  {relative}\n".encode())
        aggregate = hashlib.sha256(aggregate_input).hexdigest()
        manifest_value = {
            "schema_version": 1,
            "selection_id": "unit-test-selection",
            "dataset": {"git_commit": "1" * 40},
            "planned_count_assertion": {
                "mode": "EXACT_COUNT_SET_AND_ORDER",
                "planned_count": 1,
                "resolved_task_count_must_equal": 1,
                "resolved_task_names_must_equal_in_order": [
                    "terminal-bench/sample-task"
                ],
                "resolved_task_names_must_be_unique": True,
                "reject_additional_tasks": True,
            },
            "tasks": [
                {
                    "order": 1,
                    "name": "terminal-bench/sample-task",
                    "directory": "sample-task",
                    "source_input_manifest_sha256": aggregate,
                    "source_inputs": source_inputs,
                }
            ],
        }
        manifest = root / "selected-tasks.json"
        manifest.write_text(
            json.dumps(manifest_value, sort_keys=True), encoding="utf-8"
        )
        return task, manifest, bridge.sha256_file(manifest)

    def test_accepts_exact_manifest_digest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task, manifest, digest = self.fixture(Path(directory))
            selection = bridge.validate_selection_manifest(
                manifest, digest, [task]
            )
        self.assertEqual(selection["selection_manifest_sha256"], digest)

    def test_rejects_mismatched_manifest_digest_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            task, manifest, _digest = self.fixture(Path(directory))
            manifest.write_bytes(b"not valid JSON\n")
            with self.assertRaisesRegex(bridge.BridgeError, "SHA-256 mismatch"):
                bridge.validate_selection_manifest(manifest, HEX_A, [task])


class ProtocolTests(unittest.TestCase):
    def ready(self) -> dict:
        return {
            "protocol_version": 2,
            "status": "READY",
            "run_id": "run-1",
            "epoch": 1,
            "finish_nonce": HEX_A,
            "deployment_scope_sha256": HEX_A,
            "cgroup_scope_capability_sha256": HEX_A,
            "deployment_manifest_sha256": HEX_A,
            "ready_barrier_sha256": HEX_A,
            "ready_validation_sha256": HEX_A,
            "recorder_object_sha256": HEX_A,
            "lifecycle_object_sha256": HEX_B,
            "socket_state_enabled": True,
            "bpf_state_scope_sha256": HEX_A,
            "bpf_state_s0_sha256": HEX_A,
            "filesystem_state_scope_sha256": HEX_A,
            "filesystem_state_s0_sha256": HEX_A,
            "linux_state_scope_sha256": HEX_A,
            "linux_state_s0_sha256": HEX_A,
            "registration_cgroup_ids": [42],
            "cgroup_scope_capability": {
                "mode": "CGROUP_V2_ANCESTOR_ROOT",
                "membership_authority": "BPF_CURRENT_TASK_UNDER_CGROUP",
                "dynamic_descendants_including_ephemeral": True,
                "root_cgroup_ids": [42],
            },
        }

    def test_ready_accepts_strict_shape(self) -> None:
        nonce = bridge.validate_ready(
            self.ready(),
            run_id="run-1",
            epoch=1,
            effect_sha256=HEX_A,
            lifecycle_sha256=HEX_B,
            expected_cgroup_id=42,
        )
        self.assertEqual(nonce, HEX_A)

    def test_ready_rejects_weaker_cgroup_mode(self) -> None:
        ready = copy.deepcopy(self.ready())
        ready["cgroup_scope_capability"]["dynamic_descendants_including_ephemeral"] = False
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_ready(
                ready,
                run_id="run-1",
                epoch=1,
                effect_sha256=HEX_A,
                lifecycle_sha256=HEX_B,
                expected_cgroup_id=42,
            )

    def test_ready_rejects_different_live_cgroup(self) -> None:
        with self.assertRaises(bridge.BridgeError):
            bridge.validate_ready(
                self.ready(),
                run_id="run-1",
                epoch=1,
                effect_sha256=HEX_A,
                lifecycle_sha256=HEX_B,
                expected_cgroup_id=43,
            )

    def test_finished_binds_run_and_digests(self) -> None:
        self.assertEqual(
            bridge.validate_finished(
                {
                    "protocol_version": 2,
                    "status": "FINISHED",
                    "run_id": "run-1",
                    "report_sha256": HEX_A,
                    "artifact_manifest_sha256": HEX_B,
                },
                run_id="run-1",
            ),
            (HEX_A, HEX_B),
        )


class ConfigTests(unittest.TestCase):
    def test_builds_explicit_app_and_linux_state_scopes(self) -> None:
        config = bridge.build_observer_config(
            container_id=HEX_A,
            init_pid=123,
            cgroup_path=f"/system.slice/docker-{HEX_A}.scope",
            mount_namespace_inode=456,
            network_namespace_inode=789,
            network_interfaces=("eth0", "lo"),
            ip_binary=Path("/usr/sbin/ip"),
            ip_sha256=HEX_A,
            tc_binary=Path("/usr/sbin/tc"),
            tc_sha256=HEX_B,
            nft_binary=Path("/usr/sbin/nft"),
            nft_sha256="c" * 64,
            recorder_object=Path("/opt/system_effects.bpf.o"),
            recorder_sha256=HEX_A,
            lifecycle_object=Path("/opt/process_lifecycle.bpf.o"),
            lifecycle_sha256=HEX_B,
            output_directory=Path("/evidence/run/observer"),
            run_id="run-1",
            epoch=1,
        )
        self.assertEqual(config["profile"], "full")
        self.assertEqual(
            config["object_resolution_mode"], "KERNEL_OBJECT_EXPANDED_PARTIAL"
        )
        self.assertEqual(
            config["filesystem_state_scope"]["roots"],
            [{"path_bytes_hex": "2f617070"}],
        )
        self.assertEqual(config["bpf_state_scope"], bridge.bpf_program_map_scope())
        self.assertEqual(
            config["bpf_state_scope"]["object_types"], ["PROGRAM", "MAP"]
        )
        self.assertEqual(config["bpf_state_scope"]["map_content_types"], [])
        self.assertNotIn("LINK", config["bpf_state_scope"]["object_types"])
        linux = config["linux_state_scope"]
        self.assertEqual(linux["mounts"]["namespace"]["pid"], 123)
        self.assertEqual(
            linux["mounts"]["namespace"]["expected_namespace_inode"], 456
        )
        self.assertEqual(linux["sysctl"]["keys"], list(bridge.SYSCTL_KEYS))
        network = linux["network"]
        self.assertEqual(network["namespace"], {
            "pid": 123,
            "expected_namespace_inode": 789,
        })
        self.assertEqual(
            network["collectors"],
            {
                "addresses": True,
                "routes": True,
                "rules": True,
                "traffic_control": True,
                "nftables": True,
            },
        )
        self.assertEqual(network["tc_interfaces"], ["eth0", "lo"])
        self.assertEqual(
            bytes.fromhex(network["ip_binary_bytes_hex"]), b"/usr/sbin/ip"
        )
        self.assertEqual(network["expected_ip_sha256"], HEX_A)
        self.assertEqual(network["expected_tc_sha256"], HEX_B)
        self.assertEqual(network["expected_nft_sha256"], "c" * 64)
        self.assertEqual(
            linux["modules"]["selection"], {"mode": "ALL_LOADED"}
        )
        self.assertFalse(linux["modules"]["capture_parameters"])
        self.assertIsNone(linux["process_residual"])

    def test_config_rejects_unbound_network_inputs(self) -> None:
        arguments = {
            "container_id": HEX_A,
            "init_pid": 123,
            "cgroup_path": f"/docker/{HEX_A}",
            "mount_namespace_inode": 456,
            "network_namespace_inode": 789,
            "network_interfaces": ("eth0", "lo"),
            "ip_binary": Path("/usr/sbin/ip"),
            "ip_sha256": HEX_A,
            "tc_binary": Path("/usr/sbin/tc"),
            "tc_sha256": HEX_B,
            "nft_binary": Path("/usr/sbin/nft"),
            "nft_sha256": "c" * 64,
            "recorder_object": Path("/opt/system_effects.bpf.o"),
            "recorder_sha256": HEX_A,
            "lifecycle_object": Path("/opt/process_lifecycle.bpf.o"),
            "lifecycle_sha256": HEX_B,
            "output_directory": Path("/evidence/run/observer"),
            "run_id": "run-1",
            "epoch": 1,
        }
        with self.assertRaises(bridge.BridgeError):
            bridge.build_observer_config(
                **{**arguments, "network_namespace_inode": 0}
            )
        with self.assertRaises(bridge.BridgeError):
            bridge.build_observer_config(
                **{**arguments, "network_interfaces": ("lo", "eth0")}
            )
        with self.assertRaises(bridge.BridgeError):
            bridge.build_observer_config(
                **{**arguments, "ip_sha256": "not-a-digest"}
            )


class RewardTests(unittest.TestCase):
    def test_oracle_reward_must_equal_expected(self) -> None:
        self.assertTrue(bridge.reward_matches({"reward": 1}, 1.0))
        self.assertFalse(bridge.reward_matches({"reward": 0}, 1.0))
        self.assertFalse(bridge.reward_matches({}, 1.0))
        self.assertFalse(bridge.reward_matches(None, 1.0))
        self.assertFalse(bridge.reward_matches({"reward": True}, 1.0))


class VerifierEvidenceTests(unittest.TestCase):
    def test_nonzero_verifier_result_is_persisted_before_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            control = Path(directory)
            with self.assertRaisesRegex(bridge.BridgeError, "offline verifier failed"):
                bridge.persist_verifier_result(
                    control,
                    17,
                    b'{"verified":false}\n',
                    b"strict verification failure\n",
                )
            self.assertEqual(
                (control / "verifier.stdout").read_bytes(),
                b'{"verified":false}\n',
            )
            self.assertEqual(
                (control / "verifier.stderr").read_bytes(),
                b"strict verification failure\n",
            )


if __name__ == "__main__":
    unittest.main()
