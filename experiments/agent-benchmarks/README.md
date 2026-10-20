# 正式 Agent benchmark 的小规模观测验证

## 非 GPU 性能补验（2026-10-15）

已完成两套 benchmark 的补验：[本轮结果与未消除的限制](PROFILE-VALIDATION-20261015.md)。SWE 25 次、Terminal 50 次官方参考解测试通过；复制回 Host 后，75 份证据独立重放通过。逐查询、线程等待、静态配置调优、优先级对照和附加诊断开销均有真实数据。**参考解通过不等于模型解题率，也不等于采集完整。**

这轮把“采集代码有了”和“在真实任务上测过”分开，使用三条互不冒充的验证路径：

| 路径 | 实际做什么 | 不代表什么 |
|---|---|---|
| 官方任务控制 | SWE-bench Verified 的 `psf__requests-1142`、Terminal-Bench 的 `html-js-filter` / `bun-sourcemap-leak`，执行固定参考解并由官方检查器评分 | 不是新模型的解题率，也不是全量题集成绩 |
| 逐查询计时 | 从上述固定 Docker 镜像复制原始源码，重复执行相同 GNU grep，逐次记录真实扫描/缓存命中及开始、结束、耗时；重新核对输出 | 不是让模型每轮自己生成不同查询后比较快慢 |
| CPU 联合实验 | 搜索上述真实源码，再执行固定本地 CPU GGUF 推理，同时保留相同编译与竞争请求；比较静态分配、按阶段分配和请求优先级 | 不是直接测自主修复任务的加速，也不代表 GPU 或生产大模型 |

本轮不调用付费模型 API。每个官方任务的配对组都使用相同 Observer 与 100 ms sampler，然后分别增加线程采样、全六组内核诊断、文件 profiler 或 perf；每种条件运行 5 个随机重复块。`kernel / baseline` 包含线程轮询和探针两部分，另报 `kernel / threads` 隔离探针增量。所有组均启用 `schedstats`，因此这轮线程增量不包含从关闭到开启内核统计的成本。快照/启动/结束和 verifier 不混入任务执行窗口；完整协调时间仍单独保留。

线程等待必须先在**本轮独占实验 Guest** 中开启，不能改物理服务器的 sysctl：

```sh
sysctl -w kernel.sched_schedstats=1
```

`Diagnostics` 会在 READY 和结束时实际检查这一设置，未开启就拒绝线程档，不会把 `null` 补成 0。线程轮询仍可能漏掉短命线程；有效等待区间不是独占的请求成本，更不是完整线程生命周期证明。新增混合分析器也会把新 I/O 设备的缺失前值、计数回退和缺字段保留为未知。

准备原有 benchmark 镜像、Observer、sampler、固定 BPF object、文件 profiler、perf 后，在 Guest 建立一个新目录，例如 `/opt/benchmark-profile-new`，将这些程序放入其 `bin/`。使用新输出目录，不能覆盖旧实验：

```sh
python3 -B /opt/agent-benchmarks/prepare_profiles.py \
  --root /opt/benchmark-profile-new \
  --artifacts /opt/agent-benchmarks/artifacts-corrected.json

python3 -B /opt/agent-benchmarks/paired_profiles.py \
  --benchmark swe \
  --artifacts /opt/benchmark-profile-new/artifacts.json \
  --diagnostic-assets /opt/benchmark-profile-new/diagnostic-assets.json \
  --output /opt/benchmark-profile-new/paired-swe --repetitions 5

python3 -B /opt/agent-benchmarks/paired_profiles.py \
  --benchmark terminal \
  --artifacts /opt/benchmark-profile-new/artifacts.json \
  --diagnostic-assets /opt/benchmark-profile-new/diagnostic-assets.json \
  --output /opt/benchmark-profile-new/paired-terminal --repetitions 5
```

`prepare_profiles.py` 为现有固定 pilot 镜像生成路径和 SHA 配置、复制未运行的原始源码，不负责安装系统或下载新任务。它预期 `bin/allox-load-sampler`、`bin/kernel_hist.bpf.o`、`bin/allox-file-profiler`、`bin/file_profile.bpf.o` 和已安装 `/usr/bin/perf`。详细内核离线分析复用同级 `search-profile/analyze.py`；Guest 未部署时会明确标 `NOT_EVALUATED`，可复制完整证据回 Host 后重算。

逐查询实验另行运行，避免和官方任务计时互相干扰：

```sh
python3 -B /opt/agent-benchmarks/source_queries.py \
  --root /opt/benchmark-profile-new --benchmark swe \
  --output /opt/benchmark-profile-new/queries-swe
```

将 `swe` 换成 `terminal` 并使用新 output 可运行另一套源码。它需要把 `experiments/search-profile/` 部署到实验根目录的 `search/`，并复制这里的 `profile-queries-*.json`。输出包括每次查询的原始统计、`report.html` 和 `timeline.json`，不是把任务总耗时除以查询数。`none/reuse` 分别运行独立 campaign，其内部模式/并发顺序随机，但两种干预没有交错随机；复用时间差只能作为这次机制观察，不能冒充完整随机因果收益。小源码也不能代表大仓库或冷读压力。

CPU 配置调优使用 [执行实验说明](../execution-profile/README.md) 中的 `tune_static.py`，传入 `--search-corpus` 和 `--search-query`。先比较预声明的 CPU/编译并发候选，再冻结选择，用另一组重复实验验证 G0–G4；同时报告 A 延迟、B 最大等待/吞吐和全部工作完成时间。优先级让 A 更快但整体更慢也是有效的负面结果，不能只挑 A 的数字。

结果首先读 `paired-report.json`：任务通过、计时与采集健康分别保存。探针漏测、对象解析失败和存储队列未知仍保留为 `INCOMPLETE`，不会因为官方测试通过就改绿。`thread_wait_report.py` 重建线程计数；复制后的完整 Observer 证据再由 `benchmark_replay.py` 调用固定摘要的 Host verifier 独立重放。完整 Guest 原始树（包含失败尝试及固定二进制）封存在 `.output/benchmark-profile-export-20261015/`；Host 重放及清理回执在 `.output/benchmark-profile-20261015/`，不随 Git 提交。

## 历史单次接入（2026-10-14）

以下记录上一轮的真实模型/API 接入，不与上面的固定工作开销试验合并计分。这组实验在新的目标 Linux Guest 中运行正式任务，记录工具执行、资源等待、系统操作和文件变化。任务得分、观测证据验证、采集完整度和性能收益分别报告。

当前接入范围：

- SWE-bench Verified：固定官方数据、评分代码与容器镜像的一项修复任务，分别运行参考补丁控制、受限模型尝试和官方补丁评测。
- AgentBench FC：三个官方 OS 样本，使用原 task loader 和 judge；Docker exec 作为本地传输，仅覆盖所选不依赖持久 shell 状态的任务。
- Terminal-Bench：固定版本的两个正式任务，通过 Harbor 0.23.0、Docker 和官方 verifier，分别运行 Oracle 控制与受限模型 Agent。

这次使用 `deepseek-flash` 的远端 API。请求起止时间反映客户端等待，无法给出模型服务内部 GPU 排队或执行时间。没有跑全量题集，也没有用这些单次接入结果声称 A/B slowdown 或调度优化收益。

## 运行位置

```text
物理服务器
  ├─ API 预算入口：只转发受限请求，不执行任务
  └─ 独立实验 QEMU
       └─ 目标 Linux，PSI + BTF + BPF LSM
            ├─ benchmark 协调器、Observer、sampler、官方检查器
            └─ 被测 Docker 容器：实际工具命令和任务文件
```

使用新建 Guest，保留原 VM 与原始磁盘。现有实验的基盘摘要、实际内核、镜像和程序摘要保存在 `.output/agent-benchmarks*` 的运行记录中。任务开始前暂停容器并注册观测，首个样本可见后放行；结束后检查真正的后置样本，提交证据并独立验证，最后销毁本轮容器。

PSI 内核通过 `vm/build-profile-kernel.sh` 构建。通用搜索 VM 默认要求 PSI；旧内核仅能显式选择缺项诊断。benchmark Guest 还需要 Docker、相应 Python 环境及固定的任务依赖。

## 预算入口

在服务器上启动一次共享入口，再把它生成的受限客户端凭证交给 Guest。真正的 API key 留在服务器的私有文件中：

```sh
python3 -B experiments/agent-benchmarks/model_budget.py \
  --output-dir .output/agent-benchmarks/model-budget-new \
  --api-key-file /absolute/path/to/private-deepseek-key \
  --port 10090 --limit-rmb 4.8
```

默认 QEMU 网络下，Guest 使用 `http://10.0.2.2:10090/v1`。只允许 `deepseek-flash`、非流式请求、每次最多 2048 输出 token，关闭 thinking。每次先预留成本，再按实际 usage 结算；网络结果不明时保留预留费用，重启同一 ledger 后继续计费。按照官方高峰价格、所有输入均按缓存未命中计算上界，额外保留 0.1 元覆盖历史试验。

`client-token` 是仅供此入口使用的私有凭证，不能写入模型提示或公开结果。`budget-ledger.jsonl` 不保存提示或 key，只保存请求摘要、标签、token 数及成本上界；`budget-summary.json` 保存终态。

## 各 benchmark 的命令与结果

- [SWE-bench Verified 接入与命令](swe/README.md)，[实测记录](swe/VALIDATION.md)
- [AgentBench OS 接入与命令](agentbench/README.md)，[实测记录](agentbench/VALIDATION.md)
- [Terminal-Bench 接入与命令](terminal/README.md)，[实测记录](terminal/VALIDATION.md)
- [附件增量逐项审计](../search-profile/increment-audit.json)

判断结果时先区分：

| 结果 | 能说明什么 |
|---|---|
| 官方测试通过或 reward=1 | 本轮任务输出满足所选 benchmark 检查 |
| 官方测试失败或 reward=0 | 模型本轮未完成任务；执行轨迹仍有观测价值 |
| `verified: true` | 独立 verifier 按绑定的原始证据复算通过 |
| `INCOMPLETE/INCONCLUSIVE` | 某些覆盖或归因条件不足，不能声明全部系统影响完整 |
| 明确文件或对象差异 | 范围内有已确定变化；不因其他域未知而删除 |

若某个 kernel object hook 明确记录关联缺失或歧义，结果保留为 `UNRESOLVED` 并降低完整度。修复后的 verifier 能验证这类已声明缺项；没有原始失败标志而丢失对象、虚构对象或把 JSON 擅自改为 resolved 仍会被拒绝。旧失败产物保留，重跑使用新的输出目录和固定程序摘要。

## 2026-10-14 的完成结果

PSI 已开启并完成真实校准。三套 benchmark 的正式选定任务均已执行：SWE-bench Verified 1 个任务的模型补丁通过；AgentBench OS 3 个任务的模型检查通过；Terminal-Bench 2 个任务的模型 reward 为 0，参考解 reward 为 1。模型没有解出任务的结果仍保留。

对应的 Agent 执行和官方检查区间均保存实际 Observer/PSI 证据，并在 Guest 和复制后的服务器上独立重放；证据完整度的原有缺项没有提升为 COMPLETE。SWE 首轮发现了“已声明对象解析失败却被 verifier 拒绝”的问题，修复后重放通过但继续保留 INCOMPLETE，实际 overlayfs 解析歧义仍存在。

本轮预算账本上界为 0.368350 元，含历史 0.1 元预留为 0.468350 元。模型调用入口和本次 Guest 已关闭，原始基盘及其他 VM 未改变，新 rootfs 与所有证据保留。

[完整 campaign 索引、成本与清理记录](../../.output/agent-benchmarks/campaign-summary-20261014.json)；`.output` 不随 Git 提交。`make check-all` 已通过，包括 356 项 Rust、81 项性能分析、9 项预算入口、9 项 SWE adapter 和 1 项错误 JSON 防护测试。
