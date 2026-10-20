# Agent → 工具 → 线程：解释一次搜索为什么慢

## 新入口：正常 Codex + DeepSeek，按任务看交互火焰图

本轮新增的 `codex_native_run.py` 不再用 `observer_bash` 代替原生工具，也不关闭原生
shell 和 Code Mode。它在 Codex 启动前创建独立 cgroup、装好探针，再放行整个运行时，
因此 Codex、原生 Code Mode host、工具子进程及其后代均进入本轮 Linux 采集范围。
这是合作型实验范围，不是让有特权的恶意进程无法逃逸的安全承诺。

真实例子：Codex + DeepSeek 完成 Requests 的公开历史任务，实际查看代码、使用原生
`apply_patch` 修改实现和测试、执行回归测试。页面默认看“复现问题 → 检查实现 → 修改
→ 验证”，再点击下钻；不会先把几万条 syscall 摊给读者。
本轮是公开 SWE 问题的工作区验证，不是完整官方 SWE-bench 成绩；历史代码在 Python 3.13
下使用事先提供的 collections 兼容别名和历史标准库 `cgi.py`，没有把这些环境适配冒充
模型修复内容。`prepare_native_requests.py --help` 提供可重建的准备入口。

- 点击火焰块放大，面包屑返回，支持搜索、返回上一层、重置、键盘操作和 SVG/JSON 下载。
- 切换墙钟、调用数、token、CPU/等待及文件指标；不同单位不混成同一宽度。
- 点击查看真实命令、修改内容、退出码、输出和原始来源；文件/syscall 按页加载。
- 查看运行时和 Observer 的内存曲线；RSS、cgroup 用量、匿名内存、页缓存含义分开。
- 任务阶段来自有版本的规则或明确标记的人工复核，可回到原始证据；不是读取模型隐含意图。

真实付费任务与保存响应的回放实验分开：后者仍运行同一个 Codex/V8 和原生工具，但模型
决策来自原始 SSE，不再调用 API，不能把它写成新一轮模型推理或生产端到端 SLA。

### 采集、打开和复核

在独占实验 Guest 内，用已配置的本地预算代理接 DeepSeek（密钥不传入工具命令）：

```sh
python3 experiments/execution-timeline/codex_native_run.py \
  --codex /absolute/path/codex \
  --catalog /absolute/path/model-catalog.json \
  --collector /absolute/path/collect \
  --object /absolute/path/execution_timeline.bpf.o \
  --broker-base-url http://127.0.0.1:10093/v1 \
  --broker-token-file /absolute/private/client-token \
  --budget-label codex-native-final-001 --model deepseek-flash \
  --workspace /absolute/task-workspace --prompt /absolute/public-task.txt \
  --output /absolute/new-run

python3 experiments/execution-timeline/native_agent_profile.py \
  --run /absolute/new-run --public-directory /absolute/new-public

python3 -m http.server 18080 --bind 127.0.0.1 --directory /absolute/new-public
```

远程电脑执行 `ssh -L 18080:127.0.0.1:18080 用户@服务器`，浏览器打开
`http://127.0.0.1:18080/`。`--public-directory` 只导出白名单文件，不能把保存预算、
代理凭证的整个实验目录当 HTTP 根。自由文本命令和输出仍可能含业务信息，应限制访问。
预算 label 必须是代理实际分配的 label，示例不是可无限重用的公开 API 配额。

同一轮独立验收：

```sh
python3 experiments/execution-timeline/verify_native_acceptance.py \
  --run /absolute/new-run --provider-directory /absolute/private-provider-receipts \
  --label codex-native-final-001 --output /absolute/new-acceptance.json
```

它从原始二进制重放内核记录，从原始 RPC 重放工具和 Code Mode 调用，并核对同一模型
response ID、token、协议转换、资源采集 boot/cgroup。通过表示证据绑定和复算通过，
不等于整个 Linux 已全覆盖，也不替代测试判题。

### 原生工具与 syscall 的连接边界

原生工具的 `processId` 通常只是运行时句柄，不能直接当 Linux PID。
接入按 [Codex App Server 原生接口](https://developers.openai.com/codex/app-server)处理工具
事件和可选 OS PID，而不是给原生调用套一个替代执行器。
支持两种独立补证：原生接口提供的 `osPid` 加进程出生身份核验；或可选的 exec 参数探针：

```sh
bash experiments/execution-timeline/build-exec-args.sh /absolute/new-exec-build
# 在上述 codex_native_run.py 命令中额外传入：
# --exec-args-collector /absolute/new-exec-build/exec-args-collect
# --exec-args-object /absolute/new-exec-build/native_exec_args.bpf.o
```

后者按精确 cgroup 采集有界 argv，并结合成功 exec 和进程生命周期核对。
只有完整、唯一匹配才可标成“内核参数精确相关”，它不是 dispatcher 传递 call ID 的强绑定。
重复相同命令、截断、丢失、迁移到未注册子 cgroup 等情况保留歧义；未绑定的系统活动留在
运行时节点，不凭时间相近分配给工具。Code Mode 的请求到输出墙钟可以测，V8 内部每段
JS CPU/await 尚未由原生接口暴露，不会把整个区间冒充 JS CPU 时间。

跨运行按同一任务分类比较使用 `profile_query.py`；Observer 开／关配对使用
`native_agent_replay_overhead.py --help`。后者至少五对，随机化开／关顺序、固定同一
工作区和真实原生工具序列，核对业务输出和最终文件；只对明确列出的运行器时间、目录恢复
时间和 timestamp-pyc 头时间字段使用版本化比较规则，同时保留全部原始值。
任何业务结果不一致都会禁止输出 slowdown。旧的失败尝试也保留，不用新成功记录覆盖。

### 2026-10-20 实际验收结果

[交互总入口](../../.output/codex-native-profile-20261020-001/public-campaign/index.html)
分成三个明确的视图：真实模型任务、跨运行对照、零 API 的原生轨迹回放。
[使用说明](../../.output/codex-native-profile-20261020-001/public-campaign/README.html)
与[同轮独立验收](../../.output/codex-native-profile-20261020-001/acceptance004-final.json)同时保留。

- **真实任务 run004**：8 次 DeepSeek 请求，7 次原生 Code Mode `exec`，6 次命令和 1 次
  原生文件修改。实际修改实现和测试，两组命令分别运行 2/5 项测试并成功返回；之后独立
  重跑其中 5 项离线测试通过，最终代码摘要与真实模型留下的文件相同。这不是官方全量
  SWE-bench 成绩。
- **同轮证据**：原始 provider SSE 与协议转换、原生 RPC/工具账本、149,957 个选定内核
  事件、53,731 条 syscall、149 个线程以及 RSS/cgroup 资源记录通过绑定和独立复算。
  这些计数不等于整个 Linux 的全部效果均已覆盖。
- **工具下钻**：另一次明确标为零 API 的完整原生回放，6 条命令经版本化 Codex snapshot
  `-lc → -c` 参数投影、脚本逐字节比较、成功 exec 序列和 fork 生命周期核验，关联到
  32 个线程范围、13,272 条已有 syscall。原始 argv 完全相同的匹配仍是 0/6，没有改写
  这个事实；1 次 `fileChange` 的系统调用归属仍未知，不把这些回放关联补写进真实 run004。
- **交互验收**：真实 Chromium 检查了放大/返回、搜索、键盘、工具/文件下钻、200 行
  syscall 分页、内存曲线及私密路径 404。相关执行时间线回归 845 项，11 项按环境跳过，
  其余通过；预算/协议测试另行通过。

最终开销实验是 `native-replay-overhead-004`：五组随机开／关配对，每臂使用全新 Python
CLI，运行同一真实 Codex/V8 和原生工具，但只回放先前保存的模型响应，**不含真实模型
推理/远程等待**。证据写入有容量保护的 Guest tmpfs；OFF 禁用 BPF、资源/进程采样及
主动 PID 查询，双方仍有最小的被动 RPC/HTTP 正确性记录。

| 墙钟范围 | OFF 中位数 | FULL 中位数 |
|---|---:|---:|
| Agent 执行窗口 | 0.926 s | 1.187 s |
| CLI 启动、采集、导出、独立复算与页面生成 | 5.448 s | 19.239 s |
| 上一项再加证据压缩归档 | 5.493 s | 25.070 s |

逐对计算的 Agent 窗增量中位数为 28.64%（bootstrap 95% 区间 22.51–33.29%）；完整
采集 CLI 增量为 253.45%（240.36–259.45%）。逐对比率不等于上表两个中位数直接相除。
**详细诊断有明显成本，后处理尤其贵，不能称为低开销生产 SLA。**工作区恢复和最终内容
hash 另计；[完整开销摘要](../../.output/codex-native-profile-20261020-001/public-campaign/perf-summary.json)
保留范围、正确性规则和限制。

此前 001 的不一致结果、002 的磁盘容量/VM 暂停中断、003 长驻实验进程的堆保留参考数据
都未改绿，也不混入上述 004 数字。磁盘不足时仅在无损归档、逐内容比对后释放本轮重复
解压副本；完整原始内容可从归档恢复。部分压缩证据移至 `/root/observer-native-archive.JwkoXR/`，
项目内保留索引或软链。付费 API 已停止，跨历史账本的保守预算上限约 4.760922 元；
后续回放 API 费用为零。实验 VM 已关闭，其本轮磁盘已无损压缩到
`vm/rootfs-overlay.qcow2.tar.gz`，内容逐项比对后才释放解压副本，恢复方法和原始/归档摘要见
`vm/vm-archive.json`；未动其他 VM 或底层镜像。HTTP 结果服务独立保留。

更新：[论文／作者仓库对齐、内存缺项与结束状态说明](PAPER-ALIGNMENT-2026-10-20.md)。
HTTP 新入口为 `http://服务器地址:18080/start.html`，分别展示专用 cgroup 内存实测和真实 Terminal 工具→syscall 证据。
新增标准 pprof 导出与逐边证据链；不是把“步骤未标注”或“进程已退出”补成猜测标签／零样本。

新增：[模型等待、真实 V8 执行与内存页面](../../.output/runtime-metrics-complete-20261020-003/profile-final.html)
及[验证和复现说明](RUNTIME-METRICS-VALIDATION-2026-10-20.md)。这份示例用真实 Codex/Node 及本地模拟模型服务，
不代表付费模型或 benchmark 成绩；旧 benchmark 数据不会因此补出不存在的 V8/内存记录。

先打开[真正 Codex + DeepSeek 的可读任务页](../../.output/codex-readable-20261019-001/view-002/index.html)，
从实际命令、文件操作和结果开始看；启动与复核方式见[中文小任务教程](CODEX-DEMO-2026-10-19.md)。

最新的 [Codex + DeepSeek：Terminal-Bench 2/4/6/8 并发总页](../../.output/terminal-codex-2468-20261019-002/readable-final-001/index.html)
提供四组对比、32 次尝试的命令与输出、文件操作、逐次读取 CSV 和资源图。
**本轮没有题目通过，不能用这些耗时宣称任务完成加速**；原因和原始失败均保留，见本文末尾。

这项功能回答：一次工具调用用了多久？哪些线程正在运行，哪些已经就绪但拿不到 CPU，哪些在读取具体文件时阻塞？哪些已证明的子进程／线程完成依赖出现在最终完成路径上？

它是 Observer 中**单独启用的详细诊断功能**，不替换原有状态确认器、恢复协议或默认低频 sampler。不需要 Allox 或 GPU；当前提供直接命令 runner，以及 Harbor/Docker 的逐工具接入。

真实验证记录、测量数字和保留的失败样本见 [2026-10-17 验证报告](VALIDATION-2026-10-17.md)。

## Agent 调用了哪些工具

工具调用现在有独立的应用层证据，不靠 eBPF 从 syscall 名称反推语义。每次调用按明确
`call_id` 记录四个阶段：

```text
TOOL_REQUESTED → TOOL_DISPATCHED → TOOL_COMPLETED → TOOL_RESULT_DELIVERED
```

`app/tool-events.jsonl` 是追加式原始记录，`app/steps.json` 的 `tool_calls` 是对它严格重放
得到的逐调用摘要。记录包含 Agent／任务／thread／turn、工具名称、经过策略处理的参数、
请求时刻、派发时刻、实际执行边界、结果交回时刻、退出码、超时／取消／通信失败分类和
完整输出工件位置。可读页面首先展示这些信息，进程、文件和 syscall 只作为诊断下钻。

工具状态与任务正确性分开：`SUCCEEDED` 只表示工具接口或命令正常返回，不表示代码修改
正确、测试通过或远端系统确实产生预期效果；后者仍由官方判题、状态 confirmer 或专用
verifier 判断。支持的终态为 `SUCCEEDED`、`FAILED`、`TIMED_OUT`、`CANCELLED`、
`TRANSPORT_ERROR` 和 `UNKNOWN`。

当前 Codex app-server 适配器已经接入 `commandExecution`、`fileChange`、`mcpToolCall`、
`collabAgentToolCall`、`webSearch`、`imageView`、`imageGeneration` 和 `sleep` 的
started/completed 事件。
事件使用 Codex item ID，不按时间猜调用；离线 verifier 还会从 manifest 绑定的原始
`app/rpc.jsonl` 重建来源并核对 `tool-events.jsonl`。这一级证据标成
`CODEX_REPORTED_TOOL_CALL`：能回答 Codex 报告调用了什么、应用状态和应用报告的时长，不能
单独证明远端效果或对应的 Linux syscall。

受控 `observer_bash` 再多一层 stopped-process gate：同一个 call ID 明确绑定真实 PID、cgroup
和 Observer `tool_call_id`，标成 `TOOL_GATE_EXECUTION_BOUND`，原始内核记录重放通过后才能
继续解释文件和 syscall。没有独立执行门的内建／MCP／V8 工具保持
`NOT_BOUND_TO_LINUX_EXECUTION`；不会把同一 V8 事件循环附近的 syscall 猜给它。

历史 Terminal-Bench 的安全配置只开放 `observer_bash`，内建 shell、Code Mode、MCP 和网络工具
默认关闭，避免它们绕过任务容器。如果另一部署显式启用了这些工具，当前适配器会记录其
app-server 事件，但不会自动获得 Linux 强绑定。要获得强绑定，需让有副作用的工具经过同一
执行门并传播 `call_id`；纯 V8 内部且 app-server 不报告的函数仍需在实际 dispatcher 增加
事件或 USDT 探针。

结构化参数会按字段名遮盖 token、password、authorization 等常见秘密，并限制大小。
`observer_bash` 的 command 是自由文本，无法可靠识别嵌在命令中的秘密；当前实验只接受有界
公开任务命令，并在证据中明确标记这一限制。生产接入应在工具网关先做参数白名单和脱敏，
完整 stdout/stderr 继续作为受访问控制的独立工件保存。

## 打开结果后看什么

面向 Agent 用户的默认入口应使用 `render_agent_story.py` 生成。它不按采集器类型拆页，而是按
真实执行顺序展示一条纵向关系：

```text
Agent workload
  → 工具请求和命令
    → Observer 绑定的 Linux root
      → 实际进程／线程和 exec
        → 该工具对应的 syscall 与文件对象
  → Agent 结束和官方判题
```

每个工具先显示命令、返回码、请求到执行、Linux 执行、结果返回三段时间，再显示 syscall
汇总和文件对象。逐次 syscall 使用惰性分页，默认只显示文件、进程、网络、权限和失败调用；
可以切换到全部调用，并按 syscall、路径、进程或 TID 搜索。页面只纳入应用账本中有明确
Observer root 绑定的工具，不会混入 benchmark verifier、清理命令或时间相近的其他线程。

生成新的 Agent 主页面：

```sh
python3 experiments/execution-timeline/render_agent_story.py \
  --report /absolute/path/run/report.json \
  --application /absolute/path/run/app/steps.json \
  --rpc-events /absolute/path/run/app/rpc.jsonl \
  --official-result /absolute/path/official-result.json \
  --verification /absolute/path/run/verification.json \
  --profile-output /absolute/path/new-semantic-profile.json \
  --output /absolute/path/new-agent-story.html
```

需要研究调度和采集细节时，再使用 `render.py` 生成 forensic 页面。该页面包含原来的线程、
CPU、完成路径和高级筛选：

1. **执行了什么命令**：按执行顺序查看命令文字、实际起止、退出码和墙钟耗时。完整 argv 折叠保留；Codex 管理进程与它启动的 shell 工具分开命名，管理进程的时间包含工具，不应重复相加。
2. **启动了什么程序**：新版本从成功的内核 EXEC 事件展示文件名、PID/TID 和文件对象；不是只画 fork 树。文件名不是规范路径，可能对应脚本解释器；argv 没有采集。旧报告缺少这些证据时显示 `NOT_CAPTURED`，不把线程 `comm` 猜成可执行路径。
3. **文件操作 / syscall**：可直接搜索 `read`、`openat`、`rename`、路径或 TID；可看全部系统调用、只看文件相关调用，或只看逐次 VFS 读取。每页最多 100 行，支持成功/失败筛选、按耗时排序、点击查看原始参数，以及导出当前筛选 CSV。syscall 耗时和 VFS 读取耗时是两列，不混加。
4. 需要解释等待时，再展开底部**线程 / CPU / 完成路径**，点击区间查看等待栈、对象和证据。

操作表默认展示已归属工具的执行窗口；要查看派发期间加载库等启动操作，可切换“全部生命周期”，包括未归属进程则选“包括未归属线程”。跨窗口及缺失时间保留标记，不猜测字节应分摊到哪个阶段。

当前路径解析主要覆盖选定的读取路径。能看到 `write/rename/chmod` 调用及返回值，不意味着已解析其目标文件，更不证明最终文件状态改变：没有对象证据的路径明确写“未解析”。展示名称来自本地 Linux x86_64 syscall 表，不增加探针覆盖。完整 JSON 和原始完整性结论始终保留。

仅重新生成 forensic 页面、不重跑任务或 API：

```sh
python3 experiments/execution-timeline/render.py \
  --report /absolute/path/run/report.json \
  --output /absolute/path/new-readable-timeline.html
```

输出必须是新文件。单独部署 viewer 时，保留同目录的 `render_agent_story.py`、`render.py`、
`semantic_profile.py`、`execution_metrics.py`、`runtime_metrics_panel.py`、`runtime_resources.py`、
`resource_accounting.py`、`code_mode_timing.py`、`summarize.py` 和 `syscall_catalog.py`。
页面生成在离线阶段执行。

### 模型等待、Code Mode 执行与内存

新运行会自动在应用目录生成 `model-request-timing.jsonl`、`model-transport-summary.json`、
`resource-samples.jsonl` 和 `resource-summary.json`。普通的 `render_agent_story.py` 命令会发现这些文件，主页面直接显示
“时间花在哪里，内存用了多少”。Direct runner 的资源文件放在同次运行的 `resources/`，也能自动发现。

模型请求在 Agent 所在 Linux 的本地 HTTP 入口计时，分为请求派发、首个响应 body 字节等待、
后续响应接收和本地返回。Host 的模型网关仍负责原有预算；Agent 侧转发原始请求及响应字节，
不添加模型调用、不重试。这样即使模型网关在 Host，计时也能与 Guest 的工具和线程放在同一时钟下。
首个 body 字节可能是 SSE 元数据；使用缓冲网关时，等待还包含网关缓冲，不能称为 provider 的
首 token 延迟、排队时间或 GPU 执行时间。
请求有开始无结束、采集写入失败或停止超时，页面会标为不完整，不会把缺失请求算成零等待。

内存每 100 ms 采样，分别展示 Codex RSS、工具 root 进程 RSS、容器 cgroup 用量、匿名内存和文件
页缓存。Direct runner 还保留独立工具 cgroup 的 `memory.peak`。Docker 共用容器 cgroup 的值标为
整个容器，不分摊给某个工具。Observer 管理进程、采集器自身也单列；这些是占用量，Observer
增加了多少内存或 slowdown 需要同任务关闭/开启的配对测量。

V8 内部执行需要在真正的 Code Mode dispatcher 增加边界。现有受控 benchmark 关闭了 Code Mode，
旧结果不会突然出现 V8 时间。外部 Node/V8 dispatcher 可直接使用现成适配器：

```javascript
import {runObservedCodeMode, closeCodeModeLedgers} from './observer-code-mode.mjs';

const result = await runObservedCodeMode({
  run_id, agent_id, task_id, call_id,
  ledgerPath: '/absolute/new/code-mode-events.jsonl',
}, async ({runJS, awaitTool}) => {
  const query = runJS('准备输入', () => prepareInput());
  const answer = await awaitTool('搜索工具', () => gateway.search(query), {
    call_id: actualToolCallId,
  });
  return runJS('处理结果', () => formatAnswer(answer));
});
closeCodeModeLedgers();
```

`runJS` 测量明确的同步 JavaScript 执行段，排除记账和内存采集本身的耗时；`awaitTool` 保留实际
子工具 ID，并把 `fn()` 同步派发计入 JS 段，返回 Promise 后才开始计等待；同步返回没有等待。
并行等待按区间并集计算，等待与 JS 重叠时单独处理。JS 段是墙钟，不等于线程 CPU 时间；
支持时单独记录主线程 CPU。适配器同时记录 V8 heap、external、
arrayBuffers 和进程 RSS 的边界样本。未被标记的 async continuation 保留为“其余时间”；缺少
`runJS` 时显示“JS 未采集”，不会用父调用总时间减去等待来冒充执行时间。

将 Code Mode 数据放进同一页面：

```sh
python3 experiments/execution-timeline/render_agent_story.py \
  --report /absolute/run/report.json \
  --application /absolute/run/app/steps.json \
  --rpc-events /absolute/run/app/rpc.jsonl \
  --code-mode-events /absolute/run/app/code-mode-events.jsonl \
  --output /absolute/new-profile.html
```

run/Agent/task 身份必须匹配。同一 Linux boot 的执行必须处于该 Agent 时间窗内，才能进入墙钟分解；来自其他 boot 的数据只显示
各自测得的时长。多个工具/请求并行时，墙钟区间只记一次，并保留并行标记。

### Agent 语义火焰图

`render_agent_story.py` 的主视图现在是时间/内存摘要和语义 profile，而不是 syscall 列表。纵向固定解释为：

```text
Agent → benchmark/task → Agent 报告的计划段 → 工具 → 进程/线程或 syscall/文件
```

同一批 operation 可以切换以下横向权重：Agent 墙钟、线程 ONCPU、等待 CPU、睡眠/阻塞、
syscall 时间/次数、文件返回字节/访问数、每工具内存峰值、工具 cgroup CPU、minor/major
fault、块 I/O 和工具次数。逐工具故事与逐次 syscall 仍保留在折叠区中，作为点击下钻后的证据，
不再作为默认主视图。

语义层当前使用 Codex 明确输出且在步骤顺序中位于工具之前的计划文本，质量标记为
`AGENT_REPORTED_PLAN_STEP_ORDER`。它不是独立验证的真实意图，也没有完成 AgentPProf 式的
跨运行稳定名称归一；没有计划文本时明确显示 `UNANNOTATED`，不会从 shell 命令猜意图。

新建独立工具 cgroup 的 direct/Codex runner 会在 SIGCONT 前和 cgroup 清空后读取
`cpu.stat`、`memory.peak`、`memory.stat`、`memory.events` 和 `io.stat`。因此新运行可以把 CPU、
内存峰值、fault 和块 I/O 归到具体工具。旧证据或共享 Docker 容器没有这组工具级边界时，
相关 profile 显示 `NOT_COLLECTED`；不会用整个容器的 lifetime peak 冒充某个工具的峰值。

完整的数据模型、论文能力对照和剩余边界见 [语义 Profiler 设计与差距](SEMANTIC-PROFILER.md)。

真正 Codex + DeepSeek 的受控命令工具运行完成后，还可以生成更简单的任务首页：

```sh
python3 experiments/execution-timeline/codex_view.py \
  --run-dir /absolute/path/codex-run \
  --output /absolute/path/new-codex-readable-view
```

打开新目录的 `index.html`，直接看本次指令、执行的命令、退出码、输出和 Codex 回答。每条命令可一键进入已经按该工具筛选的文件操作或线程页。首页核对 manifest 绑定的应用步骤与实际 PID/cgroup；不会按时间相近猜归属，也不替代原始重放。该接入只开放 `observer_bash`，不等同于 Codex 默认全内建工具；Agent 循环仍由真正的 Codex app-server 负责。模型/协议失败和未完成日志原样保留，不补造步骤。

| 颜色对应的状态 | 含义 |
|---|---|
| ONCPU | 被目标 Linux 调度执行的区间；不是指令级 CPU 计量，可能夹杂中断和 Host 对 vCPU 的停调 |
| RUNNABLE | 已就绪，等待目标 Linux 的 CPU 调度 |
| SLEEP | 睡眠／阻塞；不能仅凭这个状态说在等磁盘 |
| WAKING | 已记录源线程发起唤醒，到目标 CPU 完成入队的区间；与磁盘等待、入队后的 CPU 等待分开 |
| NEWBORN | 已创建，但还未观察到首次唤醒或运行 |
| RUNTIME_RETURN | 工作线程最终 TASK_DEAD 切出到运行时确认结果之间的尾段，不算线程 CPU／I/O 等待；早期 EXIT hook 不代表线程已经停止 |
| UNKNOWN | 事件或关联不足，不能解释；不会画成“通过” |

文件读取耗时是选定 VFS 调用的入口到出口，包含该调用中发生的执行和等待，不是纯磁盘服务时间。只有实际阻塞区间才列为等待；每次读取的返回字节与请求字节分开，EOF=0，失败保留负返回值和错误，不当作 EOF 或成功读取。

一次工具调用还会分成两段：产品发起调用到实际放行进程的“派发／登记前段”，以及放行到取回结果的“执行窗口”。完成路径只分解后者；总墙钟时间会同时展示，不能把 Docker 派发和返回的时间藏起来。

“派生完成路径”从完成端点向前追踪，只采用内核记录能证明的关系：

- `wait4`：已记录的 fork 父调用引用、父 clone/fork 返回的 namespace PID、子进程退出，以及明确关联的源头唤醒。
- 线程退出 join：同一个进程生命周期、futex WAIT/WAIT_BITSET 成功、退出线程登记的 `clear_child_tid` 地址相同，以及该线程发起的唤醒。
- 跨 CPU 唤醒：用 `sched_waking` 到 `sched_wakeup` 的明确引用，避免把 IPI 上下文里的 idle 线程错认成发起者。

多个线程同时运行，**不能把它们的耗时加起来当墙钟耗时**。父进程先等 A、再等并行的 B 时，反向路径可以排除被 B 掩盖的那段 A 等待。但它不是通用因果／反事实证明：普通 futex 锁的持有者、共享内存数据依赖、任意异步 I/O 和外部服务仍可能未知；不能直接由此宣称“优化这个等待必定提速多少”。

## 直接运行一个工具

在项目根目录编译和检查：

```sh
make execution-timeline-check
```

编译脚本复用项目已经构建的 `libbpf.a`。若构建目录不同，用 `LIBBPF_ARCHIVE=/absolute/path/libbpf.a` 指定；不会自动安装系统依赖。实际记录需要 root、cgroup v2、BTF、启用的 BPF LSM、`bpf_path_d_path` kfunc，以及已挂载、可写且暴露 `kprobe_profile` 的 tracefs。路径来自只观测的 LSM hook，原权限返回值始终保留；不改变系统抢占配置。缺少所需能力会在 READY 前失败，不会静默降级。

VFS 入口／返回使用四个本次采集专属的 tracefs kprobe/kretprobe，返回探针显式设置 `maxactive=4096`。`capture/kprobe-hooks.json` 保存其名称、定义、事件 ID、目录身份、初末命中／漏测计数和清理回执，并绑定到 manifest。任何漏测、身份变化、未知计数或清理失败都会保留为不完整。Verifier 也会检查这些证据、READY 和 BPF 对象摘要；复制证据后，请把同次采集的 `collect` 与 `execution_timeline.bpf.o` 放在同一目录。

请优先在独立实验 VM 运行，**不要把未信任 Agent 当普通命令直接放到物理服务器上**。这个 runner 不是 sandbox。

```sh
python3 -B experiments/execution-timeline/run.py \
  --collector .output/execution-timeline-native/collect \
  --object .output/execution-timeline-native/execution_timeline.bpf.o \
  --output /absolute/path/new-search-run \
  --agent-id agent-A \
  -- /usr/bin/grep -R -n -F -- 'search text' /path/to/repository
```

流程是：先挂载采集器并等待 READY → 为工具创建独立 cgroup → 子进程进入 cgroup 后 SIGSTOP → 登记身份 → 记录起点并 SIGCONT → 等待整组退出 → 停采和落盘 → 从原始记录独立重建 → 生成 HTML。

`--tools tools.json` 可以并发运行多个工具，配置是数组，每项包含 `agent_id`、`task_id`、`tool_call_id`、`command`（argv 数组），以及可选 `cwd`／`env`。每项拥有独立 cgroup；不会凭时间相近或共享 cgroup 猜归属。

输出目录必须是新的，已有证据不会覆盖。主要文件：

| 文件 | 用途 |
|---|---|
| `manifest.json`、`enrollment.json` | 本次运行、工具身份和证据摘要 |
| `capture/events.bin` | 固定 ABI 的原始记录 |
| `capture/events.jsonl` | 从原始记录投影的可读事件；默认在停采后生成 |
| `capture/health.json` | 丢失、错配、逐程序漏测和边界删失统计 |
| `capture/censored-*.json` | 停采时仍在途的实际上下文，不伪造完成事件 |
| `capture/kprobe-hooks.json` | 本次专属 VFS 探针身份、初末漏测计数及清理回执 |
| `report.json`、`timeline.html` | 重建后的完整数据与离线泳道图 |
| `tool-*/stdout`、`tool-*/stderr` | 工具输出，和观测证据分开 |

推荐阅读顺序：先看工具总墙钟 → 查看完成路径上最长的 CPU／文件等待 → 点击区间检查线程、文件和等待栈 → 切到其他线程看哪些工作同时发生。普通并行等待仍保留在各线程泳道中，但不会重复加到完成路径。

复核已有结果，不重新运行工作负载：

```sh
python3 -B experiments/execution-timeline/replay.py \
  --run-dir /absolute/path/new-search-run \
  --check-report /absolute/path/new-search-run/report.json

python3 -B experiments/execution-timeline/summarize.py \
  --report /absolute/path/new-search-run/report.json \
  --output /absolute/path/new-search-run/summary.json

python3 -B experiments/execution-timeline/export_reads.py \
  --report /absolute/path/new-search-run/report.json \
  --output /absolute/path/new-search-run/read-tables
```

`read-tables/reads.csv` 保留每次读取的线程、文件、精确起止时间、请求／实际字节和错误；`files.csv` 按工具及对象身份汇总次数、字节、累计／平均／最长耗时。`excluded-reads.csv` 单列已归属线程的窗外／跨窗读取；`unassigned-reads.csv` 保留无法归属到具体工具的线程读取，不补造 Agent 身份。receipt 核对三个读取分区与报告内全部选定 VFS 读取记录闭合。CSV 只派生已重建报告，不能代替 raw 验证；累计调用耗时不是墙钟。路径保留原文，用电子表格打开时按文本导入，避免公式解释。

工具放行前已退出的运行时辅助线程保留为采集上下文，明确标记 `EMPTY_PRE_EXEC_TOOL_SETUP`；fork 祖先关系不意味着其时间属于工具执行。父进程的 clone 入口在观测范围外时，若只有 fork 时寄存器证据，只证明调用号，不虚构父入口、耗时或 wait4 依赖。

## 固定工作量的 2/4/6/8 并发验证

`parallel_run.py` 每组执行同一份计划中的 **8 个任务实例**，仅改变同时放行的上限。全部环境与 8 个采集器 READY 后才开始；全部任务返回并冻结后才允许 JSON 投影和 Terminal 官方判题。SWE 参考流程中的官方测试属于其执行阶段，两种 benchmark 的耗时不能直接互比。

`matrix_run.py` 在指定独占实验 Guest 内串行执行多组，检查 boot、配置、代码／镜像输入、采集健康与官方结果；任一组失败就停止，不调用模型 API，不自动删除容器或旧证据。计划里必须明确列出参考解／模型模式、真实不同任务数与副本数。重复同一个任务不是新增一个 benchmark 题目。

离线导出每组结果：

```sh
python3 -B experiments/execution-timeline/parallel_report.py \
  --campaign /path/to/completed-group \
  --collector /path/to/same-native/collect \
  --output /path/to/new-report

python3 -B experiments/execution-timeline/load_view.py \
  --campaign /path/to/completed-group --output /path/to/new-resource-view
```

八组均完成原始重放和导出核对后，再生成一个总入口。每个 `--group` 的两个目录分别是该组的重放报告和资源图；必须同时提供两类 benchmark 的 2/4/6/8，正式模式不接受缺组。`--selection` 绑定事先选定的八组，防止混进旧试跑；`--context-receipt` 只附带回执，不代替原始证据验证。

```sh
python3 -B experiments/execution-timeline/matrix_summary.py \
  --group /reports/swe-c2 /resources/swe-c2 \
  --group /reports/swe-c4 /resources/swe-c4 \
  --group /reports/swe-c6 /resources/swe-c6 \
  --group /reports/swe-c8 /resources/swe-c8 \
  --group /reports/terminal-c2 /resources/terminal-c2 \
  --group /reports/terminal-c4 /resources/terminal-c4 \
  --group /reports/terminal-c6 /resources/terminal-c6 \
  --group /reports/terminal-c8 /resources/terminal-c8 \
  --selection /evidence/formal-selection.json \
  --context-receipt /evidence/validation-receipt.json \
  --output /reports/new-matrix-summary
```

报告 `index.html` 链接多 Agent 总览、各任务完整时间线、JSON、四份读取 CSV 和资源边界数据。大合成图使用显式有界显示投影；省略数量和完整数据链接都保留，不裁剪原始证据或完整 JSON。资源图覆盖 CPU、内存／页缓存、PSI、磁盘、网络、上下文切换、进程创建与缺页；计数器缺失或回退显示 UNKNOWN。100ms 采样不是逐调用计量，Guest 网络包含环境服务和 SSH，缺页总数也不能直接归给某个文件。

主要墙钟是首个任务放行到最后一个任务组静止；同时另列最后 Agent 返回时间、静止尾段和含准备／判题的全流程时间。线程／VFS 累计耗时、PSI 都不能相加冒充墙钟。这里的详细诊断也不是默认低开销模式，未做同任务开关配对时不能声称 Observer slowdown。正式计时期间不要导出证据或运行其他 benchmark。

复制证据到另一台机器后，可用 `--collector` 指定**采集时同一摘要的 decoder**。Verifier 检查所读工件必须绑定、原始 bytes → JSON 的投影一致，再独立重建状态、对象及完成依赖，不直接相信已有 report。可额外提供外部保存的 `--expected-manifest-sha256`；仅把哈希和证据放在一起，不能抵抗能重写全部证据的攻击者。

## 本轮实际验证：2/4/6/8 并发（2026-10-18，Asia/Singapore）

先打开[全部结果总入口](../../.output/benchmark-timeline-2468-20261018-001/matrix-summary-final-001/index.html)。里面有八组对比、全部64个任务副本、逐次／逐文件CSV、资源图、原始manifest、重放回执和文件读取等待示例，不是只展示部分成功样本。

环境是独立实验QEMU中的目标Linux，16 vCPU、64 GiB内存；Observer在目标Linux内采集，任务在真实Docker容器内运行。不把QEMU对物理服务器的影响当成研究对象。本轮使用官方reference/oracle固定工作量，不调用模型API，不提供新模型解题成绩。SWE-bench Verified为`psf__requests-1142`的8个独立副本；Terminal-Bench为`bun-sourcemap-leak`、`html-js-filter`各4个副本。每组均完成同样8个job，仅改变并发上限；每个条件只有一轮，缓存不是受控冷／热条件。

下表单位为秒，两个数字依次是**首任务释放到最后执行返回 / 到最后任务组静止**。SWE参考流程的官方测试在执行窗口内，Terminal官方判题在执行窗口外，因此只在同一benchmark内部看并发变化。

| 并发上限 | SWE-bench Verified：返回 / 静止 | Terminal-Bench：返回 / 静止 |
|---|---:|---:|
| 2 | 22.602 / 22.726 | 4.384 / 4.499 |
| 4 | 12.368 / 12.608 | 3.271 / 3.379 |
| 6 | 13.046 / 13.180 | 3.689 / 3.841 |
| 8 | 8.478 / 8.764 | 2.628 / 2.996 |

64/64官方任务通过，64/64原始记录独立重放通过；八组选定工具时间线通过。72个任务／合成页面完成JS语法和DOM-stub运行检查，不能称为人工视觉检查。完整`make check-all`通过；最终时间线源码另用同摘要native021执行363项回归测试，均通过，见[测试回执](../../.output/benchmark-timeline-2468-20261018-001/tests-final-001.json)。

一个本轮的[真实文件读取等待示例](../../.output/benchmark-timeline-2468-20261018-001/matrix-021-fsync-swe8-r001/swe-c8-r001/report-final-021-001/reports/swe-02/timeline.html)：SWE八并发组的`swe-02-reference-0002`，线程365388，读取`/tmp/patch.diff`请求8192 B、返回743 B；选定VFS读取区间27.079 ms，其中27.022 ms是同一调用与完成路径重合的SLEEP区间。等待栈包含`io_schedule`、`jbd2_journal_get_write_access`、`ext4_reserve_inode_write`，说明应该检查文件系统／日志等待，不能直接说物理SSD带宽不足。顶部动态帧仍标UNRESOLVED。总入口的`file_wait_example`保存精确时间、对象、栈、JSON定位与源摘要。

这些“通过”不等于整个capture没有缺口：未归属线程／读取、资源边界缺项仍保留，whole-capture状态仍可能为`INCOMPLETE`。采样器缺少运行时schedstats启用声明，因此相应已验证调度延迟图保持UNKNOWN；原生线程调度事件与其重建时间线单独验收。两组各一次采样missed tick也保留在资源报告中。

读取字节是选定VFS调用的实际返回字节，不是物理磁盘读取量；对象数先在每job按内核身份去重再相加，不是整个仓库的不同源码文件数。普通fault／major fault来自任务组边界计数，不伪装成逐文件缺页归因。一次观察不能证明优化收益、确定瓶颈或Observer overhead。

正式来源与顺序见[八组选定及持久化回执](../../.output/benchmark-timeline-2468-20261018-001/formal-selection-021-fsync-001.json)。正式窗口之间先暂停放行、导出并逐文件校验／fsync，之后才启动下一组；早期缺少这一屏障的运行保留为额外控制，不混入本表。64份正式原始证据已导出，实验VM已正常关闭，旧backing摘要未变，见[关机回执](../../.output/benchmark-timeline-2468-20261018-001/vm-stop-001.json)。旧实验记录未删除；只清理可重建编译缓存约46.7 GiB及本次中止运行留下的8个已核身份容器，未清理其他Host工作负载或全局页缓存。

## Terminal-Bench 验证方式

`terminal_validate.py` 使用固定 Harbor 0.23.0 的真正 Oracle 和官方 verifier。Docker Exec API 先启动 stopped gate，取得目标 Linux 上的 PID、进程出生时间、pidfd 和 cgroup，绑定工具后才放行。不是把 `docker` 客户端的进程树当成容器工具。

容器本来的 shell／sleep 会在冻结时单独登记；采集结束再冻结检查剩余线程。工具返回不等于其后台后代全部退出；后代仍然显示，未知或异常不会当作已清理。

运行参数见：

```sh
python3 -B experiments/execution-timeline/terminal_validate.py --help
python3 -B experiments/execution-timeline/terminal_validate.py check --help
```

需要已有的任务选择清单、固定任务目录、预构建镜像以及原项目 `experiments/terminal-bench/bridge.py`。`--search-probe` 会另外注入两项同容器、并行只读搜索，每项固定 64 次查询并核对输出；**它是明确标记的关联校准，不冒充原始 Oracle 行为或模型解题成绩**。

官方 reward、原始证据重放、逐工具时间线验收分开报告。Oracle 通过不是模型解题率；零 diff、零事件、重放通过，也不自动证明观测完整。

## 开销与边界

先过滤 cgroup，再处理选定任务；缓冲区、上下文 Map、事件数和原始字节都有上限。默认在停采后转换 JSON，避免在任务窗口做大量文本转换。`--no-kernel-stacks` 可关闭栈诊断；`--live-json` 仅用于对照；`--no-trace` 是明确标记的 Observer-OFF 基线，不生成时间线结论。

详细逐调用观测**不是免费的**。CPU 主导的大块搜索和大量小 `read()` 的成本可能非常不同，不能把一次低开销外推到所有 Agent。`bench.py` 在同一 stopped-launch/cgroup 合同下交错测 off／timeline／带栈／实时 JSON，保留每次墙钟与配对比值；图和 verifier 的后处理时间不塞进工具运行时间。

完整度针对声明的 hooks、cgroup、生命周期和时间窗口。mmap page fault、io_uring、未注册共享服务、恶意迁移 cgroup、内核被攻破、Kata Guest 内部事件及物理 SSD 根因不在本版完整性承诺内。非主线程 exec 会改变 TID 和出生身份，目前明确降级为 `IDENTITY_TRANSITION_UNRESOLVED`，不猜测连续关系。源头丢失、hook 漏测、缺失唤醒、身份冲突、对象失败、未完成工具调用等仍应明确保留，不能为了得到绿色结果而忽略。

## 真正 Codex 小任务实测（2026-10-19）

已用官方 Codex 0.154.0 + DeepSeek 完成一次真实小任务：创建、写入、读取、改名、
chmod、stat、删除文件，再正常返回最终回答。不是自写 Agent 循环或 benchmark 成绩。
54,620 条事件、68 个重建线程；Guest 与 Host 原始重放通过，命令与 Agent 均成功。
见[简短使用说明与实际结果路径](CODEX-DEMO-2026-10-19.md)，或直接打开
[任务首页](../../.output/codex-readable-20261019-001/view-001/index.html)。

## Codex + DeepSeek：Terminal-Bench 并发实测（2026-10-19，UTC）

这是官方 Codex 0.154.0 app-server 驱动真实 DeepSeek 模型，通过受控的
`observer_bash` 在真实 Docker 任务容器内执行，不是 Oracle／参考解，也不是自写模型循环。
只开放这一种命令工具，不等同于 Codex 默认全部内建工具或 V8 Code Mode。
Codex 管理进程位于容器外；内核时间线覆盖登记的任务容器，不覆盖管理进程的全部执行。

每组固定 **8 次任务尝试**：`bun-sourcemap-leak`、`html-js-filter` 各 4 次，
仅改变同时放行上限 2/4/6/8。不是 8 个不同题目，也不是完整测试集成绩。
四组使用同一个 16 vCPU／64 GiB Guest、内核、镜像、任务内容和采集配置。
每次最多 8 条工具命令、12 次模型请求，单次响应最多 4096 输出 token；
模型为 `deepseek-flash`、reasoning 为 `none`，单任务预算 0.2 元，正式共享预算 4 元。
实际命令由模型选择，因此固定尝试次数**不等于完成了相同工作**。

| 并发上限 | 批次墙钟（秒） | 实际工具命令 | 官方通过／已判题 | 未评分 |
|---|---:|---:|---:|---:|
| 2 | 85.156 | 55 | 0/8 | 0 |
| 4 | 44.662 | 49 | 0/7 | 1（官方判题 1800 秒超时） |
| 6 | 38.162 | 59 | 0/8 | 0 |
| 8 | 23.040 | 46 | 0/8 | 0 |

批次墙钟从首任务放行到最后任务组冻结静止，不包含环境准备、后处理、官方判题与导出。
四并发的 1800 秒是 **Agent 结束后的官方判题超时**，不是 Agent 用了 1800 秒；
原始 campaign 的 `ABORTED` 和未评分记录都保留，没有改成得分 0 或成功。
每档仅一批，模型动作和远程服务耗时也不同，不能据此判断最佳并发或 CPU／磁盘瓶颈。

**此次发现接入缺陷，性能结论暂不能成立。** Codex 的 `thread/start.cwd`
被设为容器外的私有临时目录，而命令工具实际在容器内 `/app` 执行。
证据中有命令尝试 `cd /tmp/observer-codex-terminal-private-...` 并报目录不存在；
另有预算／工具次数上限导致的提前结束。这些都会影响解题和运行时间。
没有在四组中途修改配置、替换模型命令或隐藏错误；正式性能比较应先修复命名空间／工作目录映射，
并在能够完成任务的统一预算下重新测量。本轮较短的时间不能称为完成任务更快。

观测链路结果与解题结果分开：1,648,724 条原始事件、3,761 个登记／重建线程身份，
32/32 原始重放通过、32/32 选定 hook 的传输健康完整；只有 21/32 完成路径达到当前模型内重建，
其余仍是 `INCOMPLETE`。重放通过不补齐对象、异步路径或因果关系。
原始选定证据约 4.57 GB，已逐文件核对 Guest／Host SHA、落盘并保留。

从 [可读总页](../../.output/terminal-codex-2468-20261019-002/readable-final-001/index.html)
先看失败说明和四档表格，再点击具体 Agent 看按顺序执行的命令、stdout/stderr、成功 EXEC、
文件 syscall 和逐次 VFS 读取。短命令保留真实比例，用细线标出开始位置。
工具根进程窗口之外的时间可能包括模型通信、控制面和后台后代执行，不能全部叫 API 等待。

- [完整四档 CSV](../../.output/terminal-codex-2468-20261019-002/readable-final-001/comparison.csv)：墙钟、命令、读取、CPU、缺页、PSI、完整度。
- [完整结构化结果](../../.output/terminal-codex-2468-20261019-002/readable-final-001/data.json)：32 次尝试、逐命令与原始证据链接。
- 资源图：[2 并发](../../.output/terminal-codex-2468-20261019-002/resources/terminal-c2-r001/index.html)、[4 并发](../../.output/terminal-codex-2468-20261019-002/resources/terminal-c4-r001/index.html)、[6 并发](../../.output/terminal-codex-2468-20261019-002/resources/terminal-c6-r001/index.html)、[8 并发](../../.output/terminal-codex-2468-20261019-002/resources/terminal-c8-r001/index.html)。

读取数和字节只覆盖选定 VFS 路径；对象数是各任务内去重后求和，包含库、管道和设备，
不是全局不同源码文件数，也不是物理磁盘读取量。各任务 CPU／缺页／PSI 来自实际 cgroup 边界；
Guest 全机磁盘、网络等背景指标另行展示，不强行归给某个 Agent。
各线程、各工具累计值和 PSI 都不能相加当作批次墙钟。

正式四组共 216 次模型请求，费用保守上界约 2.834490 元；
连同校准与此前已记费用，累计约 3.727180 元，未超过 5 元。
全部请求已结算，没有未知费用；模型代理已正常关闭，离线查看结果不调用 API。
账本是保守估算而非供应商账单。早期失败校准保留在 `terminal-codex-2468-20261019-001`，不混入上表。

最终冻结源码的 573 项时间线／真实 Codex 本地假服务回归检查全部通过（假服务测试不产生付费请求），
另有 83 项预算测试通过。四组真实 provider 请求与工具绑定均已独立核对，
见[费用与继承账本封账回执](../../.output/terminal-codex-2468-20261019-002/provider-budget-final-seal-002.json)。
[真实浏览器验收回执](../../.output/viewer-browser-20261019-001/terminal-codex-formal-final-browser-003/browser-verification.json)
记录四组、32 条泳道、官方超时未评分、命令比例／跳转、syscall 和 CSV 的实际检查；
这不代替内核原始重放，也不表示题目通过。

实验 Guest 已正常关机，原始证据和磁盘镜像未删除，见
[精确身份核对与关机回执](../../.output/terminal-codex-2468-20261019-002/vm-stop-001.json)。
退出监测曾触发一次身份保护而停止；该事件和后续独立确认 PID 消失、端口关闭、串口正常卸载关机的记录均保留，
没有强杀 Host 进程，也没有把监测异常改写成成功退出码。
