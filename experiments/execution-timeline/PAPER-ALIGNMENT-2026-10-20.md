# 对齐论文：把“任务、工具、系统行为和内存”真正连起来

## 先解释旧页面的问题

“尚未细分”不是不知道任务用了多久，而是知道这段墙钟的开始／结束，却没有更细的内部执行事件。
不能自动叫作模型思考、V8 执行或等磁盘。新版按原始 RPC ID 进一步分出 Codex 初始化、创建会话和提交任务；
其余空档显示具体时间窗，仍然不猜内部原因。

“未标注任务”用词不准确。Agent、task、tool、command 都可能已知，缺的是“定位问题／修改／测试”这样的步骤标签。
新版改成“未提供步骤标签（任务与命令已知）”。先前的 Agent 公开说明可以辅助阅读，但不证明真实意图或隐藏思维。

旧 `runtime-metrics-complete-20261020-003` 的问题有两种：

- 确实没有注册专用 cgroup，不能事后补出整组用量和页缓存；不是机器完全不支持。
- 原始 PID 样本已经有 RssAnon/RssFile，旧摘要和页面没展示，属于展示缺口，已经修复。

旧原始数据可复算出：Codex 匿名驻留页峰值 22.03 MiB、文件映射驻留页峰值 99.60 MiB；
工具进程相应为 36.24 MiB、45.06 MiB。这不是新采到的历史 cgroup 数据。

## 三篇论文／作者代码实际提供什么

核查了主文及作者源码，代码版本固定为 AgentSight/AgentPProf `85bdb152653999bb5bf24a5b13c863bf8c949581`、
AgentCgroup `551ca1689b7d2d30db6b8a8613414750103cc68b`。没有把“读过源码”写成“已运行作者全部实验”。
ACM PDF 访问受限，AgentSight 使用作者公开的同名 arXiv 版本。

| 工作 | 应对齐的能力 | 不应误解为 |
|---|---|---|
| [AgentSight](https://arxiv.org/pdf/2508.02736) | 上层模型／工具活动与系统行为联系；当前作者采集器也有 PID RSS／进程树资源信息 | 自动读取真实隐藏意图、所有 delegated effect 都能归因，或已经给出匿名／页缓存完整拆分 |
| [AgentPProf](https://arxiv.org/pdf/2609.20301) | 统一 operation、任务／子任务语义栈、可换权重、标准 pprof | 截图是原生 CPU 调用栈，或已经自动精确分开 V8／模型推理／内存 |
| [AgentCgroup](https://arxiv.org/pdf/2602.09345) | Agent／容器与工具级资源边界，临时工具 cgroup 的记账 | PID RSS、整容器内存和工具独占内存是一回事，或工具结束后整组页缓存必须为零 |

实际参考源码：

- [AgentSight PID／进程树采样](https://github.com/eunomia-bpf/agentsight/blob/85bdb152653999bb5bf24a5b13c863bf8c949581/agentsight-capture/src/sources/proc.rs)：读取进程内存并保留 PID 启动身份。
- [AgentPProf 标准 profile 生成](https://github.com/eunomia-bpf/agentsight/blob/85bdb152653999bb5bf24a5b13c863bf8c949581/ext/pprof/src/profile.rs)：统一 operation 到 profile；核查版本的粗时间视图不是实际 V8 执行边界。
- [AgentCgroup 临时工具 cgroup](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/agentcg/bash_wrapper.sh)：按工具调用创建组并读取 memory.peak/current。
- [作者资源曲线绘制](https://github.com/eunomia-bpf/agentcgroup/blob/551ca1689b7d2d30db6b8a8613414750103cc68b/scripts/plot_resources.py)：画已有采样，不为每条末尾补零。

## 为什么内存不一定归零

必须分清三件事：

1. Agent 任务完成：运行时可能仍活着，保留框架基线内存。
2. 某个 PID 已退出：地址空间终止；这是生命周期事实，不是假装 `/proc` 采到了 RSS=0。
3. 整个 cgroup 已空：没有活进程，但文件缓存、内核记账及异步回收仍可能不为零。

新版曲线展示完整采集窗，而不是在 Agent 的应用 end 提前截断；标出 Agent 开始／结束、PID 退出或停止观测。
没有退出证明就说明“未确认”，不补零。cgroup 曲线保留真实读数，不跟着 PID 退出强制清零。

内存分两张表：

| 单 PID | 整个 cgroup |
|---|---|
| RSS、RssAnon、RssFile、RssShmem | memory.current、memory.peak、memory.stat 的 anon/file |
| 文件映射驻留页不等于整个页缓存 | 包括后代和内核记账；共享页按其记账归属 |
| 不包含全部后代 | 父组包含子组，不能重复相加 |

文件页可能由其他组首次加载／写入，工具读它不会自动把记账转到工具组。因此“读了 4 MiB”不要求工具的 cgroup file 增加 4 MiB。
PID 共享映射也可能使 RSS 比该组独占记账更高。各列是不同口径、各自峰值，不能简单相加。

## AgentSight 的“联系”目前到哪一步

新增 `decision_evidence.py`，把联系本身变成可检查数据：

```text
Agent 公开说明（有则显示，同 thread/turn 的先前消息，不是因果证明）
  → 原始 Codex 工具请求与 call_id
  → 工具生命周期账本
  → stopped launch 绑定的 PID/start_ticks、cgroup、boot 和执行边界
  → 同一 Observer tool_call_id 的内核线程生命周期
  → 实际 syscall、返回值、已有内核对象／路径记录
```

每条边显示匹配、缺失、冲突或截断，并提供原始 RPC／report JSON 位置。原始应用重放会实际执行；
native verifier 的历史回执单独展示，不假装页面重新做了内核重放。

已有真实 Terminal 样本可以明确关联 7 次工具调用、19,491 条 syscall、7 条先前公开说明。
该运行的 timeline 仍为 `INCOMPLETE`；联系存在不等于所有短线程、接口或对象都完整覆盖。
历史导出缺少部分 raw 文件，不能用这个目录重新声明一次 native verifier 通过。

对于没有执行门的 Codex 内建／MCP／内部 V8 工具，目前可能只有应用报告，没有 Linux 强绑定。
补齐方法是让实际有副作用的执行入口传播相同 call_id，登记其进程／cgroup 或请求专用 helper；
共享事件循环、远端服务不能靠时间接近来认领 syscall。公开说明的完整语义分段也仍需独立实现。

## 已落地的增量

- PID 内存组成、cgroup 记账和每项缺失原因。
- wait/pidfd 支持的退出证据；采样上限和身份变化保留告警。
- 明确 owned、初始空且身份稳定的专用 runtime／tool cgroup；只允许在本轮新建组内清理。
- 原始 RPC ID 配对的初始化阶段，不用粗估时间填满 unknown。
- 显式的应用→内核证据链，不把说明文本当作真正因果。
- Code Mode 真实 JS/await 分段放进同一工具层级；内存按明确工具 ID 归属。
- 标准 gzip pprof protobuf 导出，Go pprof 独立解析验证；不是仅画一张类似火焰图的图片。
- HTML 不再重复内嵌所有 profile operations 和执行链 syscall 副本；完整 JSON 单独保留，逐工具 syscall 查看不删。

尚未完成 AgentPProf 的递归语义分段、跨运行稳定子任务名称生成，也没有实现通用委托因果归因。
不把这些列成已经“全面对齐”。

## 本地复现与打开

HTTP 当前入口为 `http://服务器地址:18080/start.html`，推荐打开同一次 Guest 联合采集。
较早 Host 内存验证与 Terminal 历史证据仍分开保存，不混成一个 run。

### 严格 Guest 联合验证（最终采用）

目录为 `.output/runtime-paper-alignment-20261020-002/guest-native-read/`。
真实 Codex 0.154 启动已经接入计时适配器的 Node/V8 工具，其子进程显式按 128 KiB 循环读取文件。
模型端为本地 fake Responses，2 次请求、0 付费 API；不是 DeepSeek 实际推理，不是 benchmark 正确率。

同一个 Guest boot/run/工具根身份下：

- 5,312 条真实内核事件、10 个线程、1,654 次 syscall、34 个解析对象路径。
- 191 个资源样本，与模型／V8／执行门处于同一 Guest 时钟。
- input.bin 真实 VFS 返回 **4,194,304 B**，32 次 128 KiB 正数读取＋1 次 EOF；管道 19 B 另列，不混为该文件内容。
- Host 从已复制且哈希匹配的 collector、原始 WAL、Codex RPC、工具生命周期和 function binding 完整重放通过。
- 所选 hooks 为 `COMPLETE_FOR_SELECTED_HOOKS`，ring/path/object/stack/identity 错误为 0、findings 为空；只适用于本合作样例和声明 hooks。
- 私有组最终没有进程、anon 为 0，但 file 仍保留；图上按退出证据结束 PID 曲线，不伪造采样值为 0。

| 对象 | PID RSS 采样峰值 | PID 匿名驻留页峰值 | PID 文件映射峰值 | cgroup 总用量采样峰值 |
|---|---:|---:|---:|---:|
| Codex | 125.80 MiB | 21.87 MiB | 105.37 MiB | 47.35 MiB |
| V8 工具 root | 78.08 MiB | 32.47 MiB | 45.61 MiB | 36.95 MiB |
| Observer 管理进程 | 37.00 MiB | 24.97 MiB | 12.03 MiB | 与采集器共享同一组 |
| Observer 采集器 | 132.05 MiB | 1.81 MiB | 130.24 MiB | 共享 Observer 组为 121.57 MiB，只记一次 |

本轮详细诊断保持 **64 MiB ring**。采集器 RSS 包含 ring 的共享／别名 mmap，不等于新增私有物理内存，
不据此宣称 Observer 额外开销就是 132 MiB，也没有宣称本轮已完成 ring 大小调优。
同一对象各列峰值可能发生在不同时刻。相关额外开销仍需同任务开／关配对测量。

两个细节必须保留：V8 是该外部工具的实际插桩，不是自动抓到 Codex 内部 Code Mode；
native scope 只有工具及后代，Codex runtime 只采集应用／内存／HTTP 请求，未冒充也有 runtime syscall。

原先只用 `wc -c` 的 `guest-native/` 记录继续保留；它的内核记录有效，但 wc 可以借助文件大小优化，
不能据其输出声称读了 4 MiB。最终 `guest-native-read/` 加入实际 VFS 字节强断言，避免用 workload 输出代替内核证据。
实验 VM 都经 PID/start_ticks/完整 argv 核验后正常关闭，旧 backing 哈希不变，overlay 与证据保留。

主要工件：`input-file-read-proof.json`、`host-input-read-verification.json`、`host-full-report.json`、
`host-full-verification.json`、`app/resource-samples.jsonl`、`private-cgroup-receipt.json` 和 `vm-shutdown-receipt.json`。

零付费 API 的专用 cgroup 内存验证：

```sh
python3 experiments/execution-timeline/validate_runtime_metrics.py \
  --codex .output/codex-0.154.0/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex \
  --catalog .output/runtime-metrics-complete-20261020-003/app/model-catalog.json \
  --private-cgroups --output .output/my-new-private-runtime-validation
```

需要已委派的 memory controller；不会为此修改共享父组配置、清理共享 cgroup 或全局回收缓存。
新 Host 记录 `.output/runtime-paper-alignment-20261020-002/` 中，Codex root 退出后确实还有 git 后代；
`app/runtime-cgroup-cleanup.json` 保存清理前身份和真实内存，清理后确认组空，文件缓存仍保留。
这说明“root 已退出”不等于“树已清空”，不单凭这一瞬间就认定永久泄漏。

新页面／完整执行链／标准 pprof：

```sh
python3 experiments/execution-timeline/render_agent_story.py \
  --report /absolute/run/report.json \
  --application /absolute/run/app/steps.json \
  --rpc-events /absolute/run/app/rpc.jsonl \
  --code-mode-events /absolute/run/app/code-mode-events.jsonl \
  --profile-output /absolute/new/profile.json \
  --evidence-output /absolute/new/evidence-links.json \
  --pprof-directory /absolute/new/pprof \
  --output /absolute/new/view.html

go tool pprof -top /absolute/new/pprof/wall_ms.pb.gz
```

有合适内核、BTF/BPF LSM 和已经构建的 collector/object 时，在上述 fixture 命令附加
`--collector /absolute/collect --object /absolute/execution_timeline.bpf.o`，可启用本轮同样的真实内核联合采集。
Host 上完整重放 Guest 导出时，显式提供复制后且哈希匹配的 collector：

```sh
python3 experiments/execution-timeline/verify_codex_benchmark_smoke.py \
  --run-dir /absolute/guest-native-read --application-prefix app \
  --collector /absolute/guest-native-read/pinned-artifacts/collect \
  --output /absolute/new/host-verification.json \
  --report-output /absolute/new/host-report.json
```

没有 Code Mode 事件的运行省略该参数。新文件／目录必须不存在。
时间导出为 ns；RSS 积分使用自定义 `byte_milliseconds`，不是内存分配量或峰值。
