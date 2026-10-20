#!/usr/bin/env python3
"""Execute the actual standalone browser script with Node's vm (no fake parser)."""
import copy
import json
import re
import shutil
import subprocess
import unittest

from runtime_memory_ui import SCRIPT


@unittest.skipUnless(shutil.which("node"), "Node required to execute browser JavaScript")
class RuntimeMemoryUITests(unittest.TestCase):
    def story(self):
        return {"agent_wall_ms": 1000, "memory": {"interval_ms": 100,
            "capture_begin_ms": -200, "capture_end_ms": 1500,
            "targets": [{"target": {"name": "tool-1", "role": "TOOL_ROOT", "pid": 123,
                "cgroup": "/sys/fs/cgroup/agent/tool-1", "cgroup_scope": "PRIVATE_TOOL_CGROUP",
                "cgroup_identity": {"path": "/sys/fs/cgroup/agent/tool-1", "device": 28, "inode": 4003}},
                "sampled_rss_peak_bytes": 1000, "sampled_process_rss_anon_peak_bytes": 600,
                "sampled_process_rss_file_peak_bytes": 350, "sampled_process_rss_shmem_peak_bytes": 50,
                "sampled_cgroup_memory_peak_bytes": 3000, "cgroup_lifetime_memory_peak_bytes": 4000,
                "sampled_cgroup_anon_peak_bytes": 1000, "sampled_cgroup_file_peak_bytes": 1500,
                "process_sample_count": 2, "cgroup_sample_count": 2, "memory_metrics": {},
                "lifecycle": {"status": "EXIT_CONFIRMED", "confirmed_exit": True, "exit_returncode": 0}}],
            "capture_series": [{"name": "tool-1", "at_ms": -100,
                "rss_bytes": 800, "rss_anon_bytes": 500, "rss_file_bytes": 250, "rss_shmem_bytes": 50,
                "cgroup_current_bytes": 2000, "cgroup_anon_bytes": 1000, "cgroup_file_bytes": 800},
                {"name": "tool-1", "at_ms": 0, "rss_bytes": 1000, "rss_anon_bytes": 600,
                "rss_file_bytes": 350, "rss_shmem_bytes": 50, "cgroup_current_bytes": 3000,
                "cgroup_anon_bytes": 1000, "cgroup_file_bytes": 1500}],
            "lifecycle_markers": [{"name": "tool-1", "at_ms": 1400,
                "status": "EXIT_CONFIRMED", "confirmed_exit": True}]}}

    def render(self, story=None, mode="pid", index=0):
        setup = r'''
const fs=require('node:fs'),vm=require('node:vm'),input=JSON.parse(fs.readFileSync(0,'utf8'));
const elements={'#memory-plot':{innerHTML:''},'#memory-target':{value:String(input.index)},'#memory-accounting':{value:input.mode,options:[]}};
const context={story:input.story,console,document:{querySelector:q=>elements[q]||null}};
vm.createContext(context);
vm.runInContext(`const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const fmt=n=>n==null?'—':Number(n).toLocaleString();
const ms=n=>n==null?'—':Number(n).toFixed(3)+' ms';
const bytes=n=>n==null?'—':Number(n).toFixed(1)+' B';
const roleNames={TOOL_ROOT:'工具 root 进程',AGENT_RUNTIME:'Codex 运行时'};
function memoryTargets(){return story.memory?.targets||[]}`,context);
const before=JSON.stringify(input.story);
vm.runInContext(input.script,context);
const panel=vm.runInContext('memoryDetailsPanel()',context);
vm.runInContext('memoryAccountingChanged()',context);
const groups=vm.runInContext('memoryCgroups(memoryTargets()).map(g=>({count:g.items.length,identity_complete:g.identity_complete,peak:g.aggregate.sampled_cgroup_memory_peak_bytes,anon:g.aggregate.sampled_cgroup_anon_peak_bytes,file:g.aggregate.sampled_cgroup_file_peak_bytes,lifetime:g.aggregate.cgroup_lifetime_memory_peak_bytes}))',context);
process.stdout.write(JSON.stringify({panel,plot:elements['#memory-plot'].innerHTML,mode:elements['#memory-accounting'].value,groups,unchanged:before===JSON.stringify(input.story)}));
'''
        result = subprocess.run([shutil.which("node"), "-e", setup], text=True, capture_output=True,
            input=json.dumps({"script": SCRIPT, "story": story or self.story(), "mode": mode, "index": index}), timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_separate_pid_and_cgroup_tables_with_lifecycle_and_samples(self):
        result = self.render()
        panel = result["panel"]
        self.assertIn("RSS 采样峰值", panel)
        self.assertIn("文件映射驻留页", panel)
        self.assertIn("文件缓存采样峰值", panel)
        self.assertIn("共享内存驻留页", panel)
        self.assertIn("内核 memory.peak", panel)
        self.assertIn("已确认进程退出", panel)
        self.assertIn("退出码 0", panel)
        self.assertIn("本次工具专用", panel)
        self.assertTrue(result["unchanged"])

    def test_capture_window_and_real_samples_not_synthetic_zero(self):
        result = self.render()
        self.assertIn("-0.200 s", result["plot"])
        self.assertIn("1.500 s", result["plot"])
        self.assertIn("Agent 开始", result["plot"])
        self.assertIn("Agent 结束", result["plot"])
        self.assertIn("进程已退出（地址空间结束）", result["plot"])
        self.assertIn("退出标线不是采集到 RSS=0", result["plot"])
        self.assertTrue(result["unchanged"])
        self.assertNotIn("NaN", result["plot"])
        self.assertNotIn("Infinity", result["plot"])

    def test_cgroup_chart_does_not_imply_zero_after_pid_exit(self):
        result = self.render(mode="cgroup")
        self.assertIn('data-memory-field="cgroup_current_bytes"', result["plot"])
        self.assertNotIn('data-memory-field="rss_bytes"', result["plot"])
        self.assertIn("本组采样结束（不代表内存归零）", result["plot"])
        self.assertNotIn("进程已退出（地址空间结束）", result["plot"])

    def test_pid_only_target_explains_missing_group_without_empty_columns(self):
        story = self.story()
        target = story["memory"]["targets"][0]
        target["target"]["cgroup"] = None
        result = self.render(story, "cgroup")
        self.assertEqual(result["mode"], "pid")
        self.assertIn("本次只登记了 PID", result["panel"])
        self.assertNotIn("总用量采样峰值</th>", result["panel"])
        self.assertIn("切回单 PID", result["plot"])

    def test_cgroup_only_target_switches_mode_and_explains_pid_scope(self):
        story = self.story()
        target = story["memory"]["targets"][0]
        target["target"]["pid"] = None
        target["sampled_rss_peak_bytes"] = None
        target["lifecycle"] = {"status": "CGROUP_OBSERVATION_ENDED", "confirmed_exit": False}
        result = self.render(story)
        self.assertEqual(result["mode"], "cgroup")
        self.assertIn("这次没有登记单独 PID", result["panel"])

    def test_missing_exit_proof_is_not_presented_as_confirmed_exit(self):
        story = self.story()
        story["memory"]["targets"][0]["lifecycle"] = {"status": "END_NOT_RECORDED", "confirmed_exit": False}
        story["memory"]["lifecycle_markers"] = []
        result = self.render(story)
        self.assertIn("未记录进程结束事件", result["panel"])
        self.assertNotIn("已确认进程退出", result["panel"])
        self.assertNotIn("进程已退出（地址空间结束）", result["plot"])

    def test_sample_limit_and_failed_fields_are_readable(self):
        story = self.story()
        story["memory"]["sample_limit_reached"] = True
        item = story["memory"]["targets"][0]
        item["sampled_cgroup_file_peak_bytes"] = None
        item["memory_metrics"]["cgroup_file"] = {"peak_bytes": None,
            "reason": "CGROUP_CONTROLLER_OR_FILE_UNAVAILABLE_SEE_COLLECTION_ERRORS"}
        item["collection_errors"] = {"cgroup:memory.stat": "PermissionError denied"}
        result = self.render(story)
        self.assertIn("已达到采样上限", result["panel"])
        self.assertIn("内存控制器或采集文件不可读", result["panel"])
        self.assertIn("PermissionError denied", result["panel"])

    def test_all_dynamic_labels_and_errors_are_escaped(self):
        story = self.story()
        item = story["memory"]["targets"][0]
        item["target"]["name"] = '<img src=x onerror="bad()">'
        item["collection_errors"] = {"<script>": "<iframe>"}
        story["memory"]["capture_series"][0]["name"] = item["target"]["name"]
        story["memory"]["capture_series"][1]["name"] = item["target"]["name"]
        result = self.render(story)
        for output in (result["panel"], result["plot"]):
            self.assertNotIn("<img", output)
            self.assertNotIn("<iframe", output)
            self.assertNotIn("<script>", output)
        self.assertIn("&lt;img", result["panel"])

    def test_long_gaps_disconnect_line_instead_of_implying_continuous_measurement(self):
        story = self.story()
        point = copy.deepcopy(story["memory"]["capture_series"][1])
        point["at_ms"] = 1200
        story["memory"]["capture_series"].append(point)
        plot = self.render(story)["plot"]
        path = re.search(r'data-memory-field="rss_bytes" d="([^"]+)"', plot).group(1)
        self.assertEqual(path.count("M"), 2)
        self.assertEqual(path.count("L"), 1)

    def test_no_samples_does_not_draw_zero_curve(self):
        story = self.story()
        story["memory"]["capture_series"] = []
        plot = self.render(story)["plot"]
        self.assertIn("没有绘制虚构的 0 曲线", plot)
        self.assertNotIn("<path", plot)

    def test_no_resource_artifacts_explains_not_zero(self):
        story = {"memory": {"status": "NOT_COLLECTED", "targets": [],
            "reason": "RESOURCE_SAMPLER_NOT_ENABLED_OR_ARTIFACTS_NOT_PROVIDED"}}
        panel = self.render(story)["panel"]
        self.assertIn("这次没有保存内存采样文件", panel)
        self.assertIn("不能据此判断内存用量为 0", panel)

    def shared_group_story(self):
        story = self.story()
        original = story["memory"]["targets"][0]
        original["target"].update(name="observer-supervisor", role="OBSERVER_SUPERVISOR")
        other = copy.deepcopy(original)
        other["target"].update(name="observer-native-collector", role="OBSERVER_COLLECTOR", pid=124)
        other.update(sampled_cgroup_memory_peak_bytes=5000, sampled_cgroup_anon_peak_bytes=700,
            sampled_cgroup_file_peak_bytes=1900, cgroup_lifetime_memory_peak_bytes=6000)
        story["memory"]["targets"].append(other)
        return story

    def test_strict_shared_group_identity_deduplicates_group_not_pids(self):
        result = self.render(self.shared_group_story())
        self.assertEqual(result["panel"].count('data-memory-cgroup-row="1"'), 1)
        self.assertEqual(result["panel"].count('data-memory-pid-row="1"'), 2)
        self.assertEqual(result["groups"], [{"count": 2, "identity_complete": True,
            "peak": 5000, "anon": 1000, "file": 1900, "lifetime": 6000}])
        group_table = result["panel"].split("执行组：包含后代、缓存与内核记账", 1)[1]
        self.assertIn("observer-supervisor", group_table)
        self.assertIn("observer-native-collector", group_table)
        self.assertIn("整组用量只列一次", group_table)
        self.assertIn("各观察取最大值，不相加", group_table)
        self.assertNotIn("8000.0 B", group_table)
        self.assertTrue(result["unchanged"])

    def test_zero_group_readings_are_observed_not_missing(self):
        story = self.shared_group_story()
        for item in story["memory"]["targets"]:
            item.update(sampled_cgroup_memory_peak_bytes=0, sampled_cgroup_anon_peak_bytes=0,
                sampled_cgroup_file_peak_bytes=0, cgroup_lifetime_memory_peak_bytes=0)
        result = self.render(story)
        self.assertEqual(result["groups"][0], {"count": 2, "identity_complete": True,
            "peak": 0, "anon": 0, "file": 0, "lifetime": 0})
        group_table = result["panel"].split("执行组：包含后代、缓存与内核记账", 1)[1]
        self.assertGreaterEqual(group_table.count("0.0 B"), 4)

    def test_missing_or_invalid_identity_never_merges_by_path(self):
        cases = (None, {"path": "/sys/fs/cgroup/agent/tool-1", "device": 28},
            {"path": "/sys/fs/cgroup/agent/tool-1", "device": 28, "inode": 0},
            {"path": "/sys/fs/cgroup/agent/tool-1", "device": 28, "inode": 2**53+1},
            {"path": "/different/path", "device": 28, "inode": 4003})
        for identity in cases:
            with self.subTest(identity=identity):
                story = self.shared_group_story()
                for item in story["memory"]["targets"]:
                    item["target"]["cgroup_identity"] = identity
                result = self.render(story)
                self.assertEqual(result["panel"].count('data-memory-cgroup-row="1"'), 2)
                self.assertTrue(all(not group["identity_complete"] for group in result["groups"]))
                self.assertIn("cgroup 身份记录不完整", result["panel"])
                self.assertTrue(result["unchanged"])

    def test_same_path_different_inode_or_device_are_distinct_groups(self):
        for field in ("inode", "device"):
            with self.subTest(field=field):
                story = self.shared_group_story()
                story["memory"]["targets"][1]["target"]["cgroup_identity"][field] += 1
                result = self.render(story)
                self.assertEqual(result["panel"].count('data-memory-cgroup-row="1"'), 2)
                self.assertTrue(all(group["identity_complete"] for group in result["groups"]))

    def test_collector_rss_note_does_not_equate_mmap_to_incremental_private_ram(self):
        panel = self.render(self.shared_group_story())["panel"]
        self.assertIn("采集器 RSS 包含 ring buffer 的 mmap", panel)
        self.assertIn("RSS 不等于新增的私有物理内存", panel)
        self.assertIn("不能把各进程 RSS 峰值相加", panel)
        self.assertIn("不能再加上共享 cgroup 的峰值", panel)


if __name__ == "__main__":
    unittest.main()
