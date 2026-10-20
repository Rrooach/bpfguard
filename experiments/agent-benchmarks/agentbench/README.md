# AgentBench：先跑 OS 子集

这里接入 THUDM 的 AgentBench FC，不是同名的其他软件测试项目。
当前选取 3 个 OS 任务：查询 CPU 数、递归统计 `.tep` 文件、把找到的可执行文件目录加入 PATH。
其中既有读取，也有文件修改。固定源码 revision 和输入文件哈希保存在结果中。

运行使用原仓库的任务加载器、提示、工具定义和检查器。为减少首次部署的服务数量，传输层用本地 Docker exec。
它没有启动原项目的 Redis、controller 和常驻终端栈。选取的 3 个任务不依赖跨轮保留 cwd 或 shell 环境；因此这是明确声明的 OS 子集接入，不是整个 AgentBench 标准管线的完成证明。

`example-control` 执行官方示例，确认检查器能正常判分；`model` 才让真实模型执行任务。
模型只看到官方任务说明和工具结果，示例与检查脚本留在评测端。
每个样本最多 8 轮；共享预算服务限制 API 总费用。

Guest 准备：

```sh
python3 -m venv /opt/agentbench-venv
/opt/agentbench-venv/bin/pip install agentrl-worker==0.4.0 pyyaml docker==7.2.0

docker build -t local-os/default \
  -f /opt/agent-benchmarks/agentbench-upstream/data/os_interaction/res/dockerfiles/default \
  /opt/agent-benchmarks/agentbench-upstream/data/os_interaction/res/dockerfiles
```

运行参考解控制：

审计复用同组 SWE 接入中的 `Session` 协调器，需要将 `experiments/agent-benchmarks/swe/run.py` 安装到 `/opt/agent-benchmarks/swe/run.py`。
该 helper 的审计部分只依赖标准库和 Docker SDK，不需要在本组环境中安装 SWE-bench harness。

```sh
/opt/agentbench-venv/bin/python /opt/agent-benchmarks/agentbench/run.py \
  --source /opt/agent-benchmarks/agentbench-upstream \
  --sampler /opt/bpf-observer/allox-load-sampler \
  --artifacts /opt/agent-benchmarks/artifacts.json \
  --agent example-control \
  --output /opt/agent-benchmarks/results/agentbench-control
```

运行真实模型时换成 `--agent model` 和新的 output 目录。
默认使用 `http://10.0.2.2:10090/v1` 的实验预算服务；用 `--broker-url` 可以指定地址。
API key 由预算服务保管，Guest 只有受限客户端令牌。

每个样本记录：

- `result.json`：官方检查器的结果、容器/进程/cgroup 身份和运行错误。
- `agent-transcript.json`：实际多轮任务与工具返回。
- `tool-intervals.json`：执行命令及检查器脚本的区间；以 `phase` 区分 Agent 和 judge，不能把检查器工作归给 Agent。
- `model-requests.json`：模型请求区间和 token 使用。
- `audit/load/`：声明 Agent 执行窗口的 cgroup/系统 CPU、内存、I/O、PSI 和进程采样。
- `audit/observer/`：实际 eBPF 事件 WAL、对象信息与 BPF/文件/Linux 状态快照。
- `audit/verification.json`：独立 Observer verifier 的复算结果。

初始化脚本在采样窗口之前运行，检查器在采样窗口之后运行。
传入 `--artifacts` 时，先冻结容器、启动 Observer、采集 A 和验证 sampler READY，再运行 Agent；结束后冻结容器、确认实际末次采样、采集 B 并独立验证。
不传 `--artifacts` 的早期版本仅做资源采样，保存为 `audit_enabled: false`，不可声称 Observer 审计通过。
模型请求由容器外的受信任 runner 发出，记录的是应用层关联时间；eBPF 的直接归因范围是执行 shell 工具的容器 cgroup。
现有 lifecycle/独占合同的完整性限制继续保留，因此 `verified: true` 与全域 `INCOMPLETE/INCONCLUSIVE` 可以同时出现。
没有配对无观测运行，不从这些单次记录推导 overhead，也不把 3 个样本的结果称为整个基准分数。

官方来源与部署说明：[THUDM/AgentBench](https://github.com/THUDM/AgentBench)。

本次实际任务和验证结果见 [VALIDATION.md](VALIDATION.md)。
