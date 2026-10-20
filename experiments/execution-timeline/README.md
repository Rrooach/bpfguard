# Agent → 工具 → 线程：解释一次搜索为什么慢

先打开[真正 Codex + DeepSeek 的可读任务页](../../.output/codex-readable-20261019-001/view-002/index.html)，
从实际命令、文件操作和结果开始看；启动与复核方式见[中文小任务教程](CODEX-DEMO-2026-10-19.md)。

最新的 [Codex + DeepSeek：Terminal-Bench 2/4/6/8 并发总页](../../.output/terminal-codex-2468-20261019-002/readable-final-001/index.html)
提供四组对比、32 次尝试的命令与输出、文件操作、逐次读取 CSV 和资源图。
**本轮没有题目通过，不能用这些耗时宣称任务完成加速**；原因和原始失败均保留，见本文末尾。

这项功能回答：一次工具调用用了多久？哪些线程正在运行，哪些已经就绪但拿不到 CPU，哪些在读取具体文件时阻塞？哪些已证明的子进程／线程完成依赖出现在最终完成路径上？

它是 Observer 中**单独启用的详细诊断功能**，不替换原有状态确认器、恢复协议或默认低频 sampler。不需要 Allox 或 GPU；当前提供直接命令 runner，以及 Harbor/Docker 的逐工具接入。

真实验证记录、测量数字和保留的失败样本见 [2026-10-17 验证报告](VALIDATION-2026-10-17.md)。

## 打开结果后看什么

打开生成的 `timeline.html`，先看默认展开的几部分，不需要先读懂线程图：

1. **执行了什么命令**：按执行顺序查看命令文字、实际起止、退出码和墙钟耗时。完整 argv 折叠保留；Codex 管理进程与它启动的 shell 工具分开命名，管理进程的时间包含工具，不应重复相加。
2. **启动了什么程序**：新版本从成功的内核 EXEC 事件展示文件名、PID/TID 和文件对象；不是只画 fork 树。文件名不是规范路径，可能对应脚本解释器；argv 没有采集。旧报告缺少这些证据时显示 `NOT_CAPTURED`，不把线程 `comm` 猜成可执行路径。
3. **文件操作 / syscall**：可直接搜索 `read`、`openat`、`rename`、路径或 TID；可看全部系统调用、只看文件相关调用，或只看逐次 VFS 读取。每页最多 100 行，支持成功/失败筛选、按耗时排序、点击查看原始参数，以及导出当前筛选 CSV。syscall 耗时和 VFS 读取耗时是两列，不混加。
4. 需要解释等待时，再展开底部**线程 / CPU / 完成路径**，点击区间查看等待栈、对象和证据。

操作表默认展示已归属工具的执行窗口；要查看派发期间加载库等启动操作，可切换“全部生命周期”，包括未归属进程则选“包括未归属线程”。跨窗口及缺失时间保留标记，不猜测字节应分摊到哪个阶段。

当前路径解析主要覆盖选定的读取路径。能看到 `write/rename/chmod` 调用及返回值，不意味着已解析其目标文件，更不证明最终文件状态改变：没有对象证据的路径明确写“未解析”。展示名称来自本地 Linux x86_64 syscall 表，不增加探针覆盖。完整 JSON 和原始完整性结论始终保留。

仅重新生成可读页面、不重跑任务或 API：

```sh
python3 experiments/execution-timeline/render.py \
  --report /absolute/path/run/report.json \
  --output /absolute/path/new-readable-timeline.html
```

输出必须是新文件。单独部署 viewer 时，保留同目录的 `render.py`、`summarize.py` 和 `syscall_catalog.py`；新视图只影响离线展示，不增加 eBPF 热路径开销。

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
