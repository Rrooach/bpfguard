# 一次搜索为什么慢：实现与真实验证

这轮完成了可单独启用的详细诊断：把 Agent、工具调用、进程、线程、每次选定 VFS 读取和调度等待放到同一条时间轴上。**先看工具墙钟，再看经过验证的完成依赖，不把并行线程时长相加。** 没有使用 GPU，也没有调用付费模型 API。

## 1. 直接打开结果

本机证据根目录：

```text
/disk/bpfguard/linux/tools/bpf/bpf-state-observer/.output/execution-timeline-validation-20261017-001
```

- [双 Agent 搜索时间线，第 1 轮](../../.output/execution-timeline-validation-20261017-001/terminal-search-probe-018-r001/timelines/bun-sourcemap-leak/timeline-final.html)
- [文件读取确实延迟主线程完成的时间线](../../.output/execution-timeline-validation-20261017-001/timeline-join-018/timeline-final.html)
- [第 1 轮逐次读取 CSV](../../.output/execution-timeline-validation-20261017-001/terminal-search-probe-018-r001/timelines/bun-sourcemap-leak/read-tables-final/reads.csv)
- [第 1 轮逐文件汇总 CSV](../../.output/execution-timeline-validation-20261017-001/terminal-search-probe-018-r001/timelines/bun-sourcemap-leak/read-tables-final/files.csv)
- [全部六个搜索工具的工作目录文件明细](../../.output/execution-timeline-validation-20261017-001/file-read-crosscheck-002/result-001/app-files-all6agents.csv)
- [独立的 report→CSV 交叉核验](../../.output/execution-timeline-validation-20261017-001/file-read-crosscheck-002/result-001/receipt.json)

HTML 不依赖外部网站。先选 Agent／工具，再点线程区间，查看 TID、syscall、文件对象、实际返回字节、读取耗时、等待栈和关联证据。完整 JSON、CSV 不因画面显示预算而裁掉记录。

每份最终结果包含 `report-final.json`、`summary-final.json`、`timeline-final.html`；Terminal 记录另有 `goal-final-host.json`。原始 `capture/events.bin`、逐事件 JSON、健康计数、工具登记、基线与结束线程名单、manifest 都保留。CSV 导出不替代原始证据重放。

## 2. 目标到底验证到了什么

| 问题 | 已实现、已验证的证据 |
|---|---|
| 哪个 Agent 的哪次工具调用？ | 运行时显式登记 ID；进程先 SIGSTOP，绑定真实 PID、出生时间、cgroup 后才放行 |
| 哪个进程／线程实际执行？ | 内核 fork／exec／调度／最终退出事件；出生身份防止仅凭 PID 合并 |
| 哪个线程等 CPU？ | 从实际唤醒入队到调度执行的 RUNNABLE 区间 |
| 读取哪个文件，多少字节，多久？ | 同线程、同 syscall 引用、同 mount/device/inode/generation 的实际 VFS 读取和路径候选；请求字节、返回字节和 EOF 分开 |
| 在哪里阻塞？ | 实际切出／唤醒事件、当时 syscall／文件、同一轮内核等待栈 |
| 哪些等待位于完成依赖上？ | 从结束向前重建：显式 fork、成功 wait4 的子进程与源唤醒、满足 clear_child_tid 条件的线程退出 join |
| 哪些时间不是工具线程的 CPU／I/O？ | 派发登记前段、唤醒递送、最终退出到控制面取回结果的尾段分别展示 |

完成路径只是**在声明模型内可验证的依赖路径**。它不是“删掉这段等待必定等量提速”的反事实证明，也不证明任意普通 futex 的锁持有者。

## 3. 真实 Terminal-Bench 验证

使用 Harbor 0.23.0、真实 Docker 26.1.5、固定任务选择与预构建镜像。运行官方 Oracle 参考解和原官方 verifier，没有修改判题。**这些是集成正确性验证，不是模型解题率或完整 Terminal-Bench 成绩。**

| 运行 | 官方 reward | 记录事件数 | Guest／Host 独立重放与目标验收 |
|---|---:|---:|---|
| `terminal-control-006`：bun-sourcemap-leak | 1 | 7,086 | 通过 |
| `terminal-control-006`：html-js-filter | 1 | 4,378 | 通过 |
| `terminal-search-probe-018-r001` | 1 | 69,276 | 通过 |
| `terminal-search-probe-018-r002` | 1 | 69,257 | 通过 |
| `terminal-search-probe-018-r003` | 1 | 71,278 | 通过 |

后三轮在同一个真实任务容器里另外启动两个**明确标记的只读搜索校准工具**，每个固定执行 64 次 GNU grep，再运行不变的官方参考解／判题；不能把校准工具说成原参考解或模型自己发起的搜索。两项搜索每轮都有真实重叠，分别约 93.34、20.27、80.51 ms。

每个搜索工具都严格验收：1 个根 shell＋64 个 grep，共 65 个线程身份；64 个经过验证的 wait4 完成依赖＋64 个 fork 前缀，共 128 条依赖。不能只看到几个文件或一条唤醒就算通过。所有所属线程都记录到最终 TASK_DEAD 切出，完成路径 UNKNOWN=0。

五份最终采集的丢失、探针递归漏测、CPU 序列缺口、解析／写盘错误、身份／对象／路径错误等健康计数为零。容器既有线程和未分配活动仍留在单独泳道及 findings 中，不按时间猜成 Agent 的工作。`selected_tool_timeline_status` 为选定工具完整；`whole_capture_attribution_status` 仍是 `UNASSIGNED_EVENTS_PRESENT`，旧保守合并状态也不改绿。

观测窗口针对经过接口派发的工具及后代，**不宣称任务准备、Docker 守护进程、官方判题全流程或整个 Linux 都完成了归因**。

### 每次搜索究竟读了多少

以下每行都是一个工具执行固定 64 次查询，而不是单次 grep：

| 轮次／工具 | 完整调用墙钟 ms | 其中派发登记 ms | 放行至取回结果 ms | 完成路径 ONCPU ms | 完成路径等 CPU ms |
|---|---:|---:|---:|---:|---:|
| r001 / Agent 1 | 206.214 | 75.238 | 130.976 | 121.226 | 5.716 |
| r001 / Agent 2 | 245.724 | 112.788 | 132.935 | 123.632 | 5.939 |
| r002 / Agent 1 | 222.883 | 95.337 | 127.547 | 120.147 | 3.375 |
| r002 / Agent 2 | 326.242 | 202.537 | 123.705 | 117.242 | 2.412 |
| r003 / Agent 1 | 201.973 | 72.588 | 129.385 | 120.951 | 5.229 |
| r003 / Agent 2 | 238.451 | 121.373 | 117.078 | 111.542 | 2.645 |

每个工具的读取计量都相同：

- `/app` 工作目录：11 个实际文件对象，704 次正返回＋704 次 EOF，实际返回 254,016 B。
- 加上加载器、库和特殊文件等选定读取：80 个对象、1,799 次读取（1,030 次正返回＋769 次 EOF）、实际 649,016 B，读取错误 0。
- 总 VFS 读取累计耗时分别约 8.684／8.874、7.738／7.428、9.015／8.480 ms；这是调用累计值，**不是墙钟，也不是磁盘服务时间**。
- 各工具放行前还有 24 或 25 次读取，完整保存在 `excluded-reads.csv`；没有静默丢掉或塞进执行窗口。

输出内容和字节数逐轮一致。实际返回字节绝不拿请求 buffer 大小代替。

第 1 轮 Agent 1 的全部工作目录文件如下。每个文件均有 128 次读取＝64 次正返回＋64 次 EOF；耗时含这 128 次调用：

| 文件（相对 `/app`） | 实际累计 B | 累计读取 μs | 平均 μs | 最长 μs |
|---|---:|---:|---:|---:|
| src/generated/prompt-template.ts | 9,408 | 714.922 | 5.585 | 32.230 |
| src/server-entry.ts | 5,504 | 508.010 | 3.969 | 13.300 |
| src/client/render.ts | 14,144 | 570.164 | 4.454 | 43.710 |
| src/client/format.ts | 6,144 | 533.647 | 4.169 | 11.700 |
| src/server/secret.ts | 4,672 | 586.604 | 4.583 | 18.391 |
| src/server/handler.ts | 47,936 | 500.612 | 3.911 | 11.840 |
| src/client-entry.ts | 11,456 | 506.160 | 3.954 | 22.520 |
| scripts/release.ts | 114,368 | 487.903 | 3.812 | 11.440 |
| package.json | 13,504 | 538.790 | 4.209 | 15.530 |
| visibility.json | 16,704 | 504.342 | 3.940 | 15.270 |
| tsconfig.json | 10,176 | 503.994 | 3.937 | 12.570 |

结论很窄但明确：**这六次固定搜索没有 `/app` 文件关联的 SLEEP 证据，不能说磁盘拖慢了搜索。** 完成路径主要是调度执行；派发登记本身也占明显墙钟。ONCPU 包含搜索、遍历、运行时和探针开销，不等于字符串匹配 CPU 时间，尚不能据此单独认定匹配函数是瓶颈。

例如最长一次工作目录读取实际仅返回 147 B、请求 98,304 B、耗时 68.590 μs，期间是 ONCPU，不能叫“磁盘等待”。独立核验的 `examples.json` 保存精确线程／调用／原报告索引。

## 4. 文件阻塞真的能解释主线程完成吗

另外运行了两种真实受控程序，不靠伪造 trace 验收：

- **6 线程／进程竞争场景**：有约 1 ms 短线程、CPU 竞争者、64 MiB 文件读和管道阻塞。全部身份保留，观察到 49 段文件阻塞和 1 段管道阻塞。最终完成路径约 502.720 ms，其中等 CPU 164.780 ms；文件读已经被较晚完成的竞争者掩盖，不能把全部文件等待再加到最终路径。
- **2 线程 join 场景**：主线程等待读线程退出。实际读取 67,108,864 B，观察到 134 段文件阻塞；完成路径约 144.331 ms，其中 30.947 ms 是实际文件关联睡眠，30.689 ms 是等 CPU。另外约 20.050 ms 是实验故意安排的定时睡眠，没有算成读盘。

第二例读线程 TID=55805，主线程 TID=55804。通过同进程出生身份、实际 futex 等待地址、读线程 `clear_child_tid`、退出事件与源头唤醒，证明主线程的完成依赖这条读线程。文件对象为 `/opt/execution-timeline/cold-source-001`，mount/inode 等身份和原始调用引用都在结果内。

一次具体读取返回 16,384 B，调用约 1.088 ms，其中有 0.787 ms 的阻塞区间，栈包含 `io_schedule → blk_mq_get_tag` 等实际帧。**这证明该文件读取中的等待，不证明物理 SSD 服务了多久。** 当前没有逐请求建立文件→block request→Host SSD 的完整因果链。

等待栈仅对已保存符号作保守解析。挂载前的 kallsyms 不能证明后来加载的 BPF JIT／模块函数范围；这类帧保留原始地址与 UNRESOLVED 标记，不能错误标成旧 BPF 程序，更不能据此宣称“BPF 导致等待”。

## 5. 开销：不能只报一个低百分比

最终 native018；同一 64 MiB 热文件、相同命令／输出／stopped-launch／cgroup；每种模式 5 次，按配对 block 随机交错顺序（seed=1017）。计时为放行至根进程结果和整组退出确认；READY、重放、绘图、CSV 导出不在这个计时内。没有把它冒充完整 Agent 端到端开销。

| 工作负载／模式 | 墙钟中位数 ms | 最小–最大 ms | 每 block 配对 slowdown 的中位数 |
|---|---:|---:|---:|
| grep，Observer 关闭 | 117.073 | 114.597–135.833 | 基线 |
| grep，时间线不带栈 | 121.985 | 116.986–126.091 | +1.12% |
| grep，时间线带栈 | 122.742 | 115.890–127.769 | +3.07% |
| grep，带栈＋实时 JSON | 119.509 | 119.234–127.674 | +2.26% |
| 16 KiB 连续 read，Observer 关闭 | 10.179 | 10.108–12.335 | 基线 |
| 16 KiB 连续 read，不带栈 | 46.662 | 45.515–56.843 | +351.84% |
| 16 KiB 连续 read，带栈 | 45.908 | 45.616–49.055 | +349.85% |
| 16 KiB 连续 read，带栈＋实时 JSON | 27.288 | 26.308–29.392 | +162.00% |

配对比值的中位数不等于两个墙钟中位数直接相除。40 次运行的输入／输出都一致，30 次启用观测的运行均有原始证据和成功重放；全体单次值保存在两个 `timeline-overhead-018-*/overhead.json` 中。物理 Host 噪声未消除，样本小，不提供生产 SLA。

**高频小读取开销显著，这项详细诊断不能默认常开。** 延迟 JSON 能把转换移出任务窗口，但本轮小读取测试反而是实时 JSON 更快；不能宣称这个优化在所有负载上已提速。当前采用按需启用、先过滤 cgroup、有界缓冲／Map／输出和停采后处理；没有降低查询次数或偷偷省略读取来“降低开销”。

## 6. 反复验收时修了什么，失败证据在哪里

保留 `terminal-search-probe-011`：原来环形缓冲丢了 20,860 条、还出现探针漏测，该次仍是 INCOMPLETE。增大有界 ring、缓冲 raw 写入和停采后投影后，`terminal-search-probe-015` 不再丢事件，但仍发现两次 fentry 递归漏测，仍未通过。

随后改为保留原权限返回值的只观测 BPF LSM 路径 hook，没有修改系统抢占设置或隐藏计数。native018 又补齐身份读取失败计数。最后三轮密集搜索才均通过。

重放器同时修正／验收了：跨 CPU 源唤醒、namespace 内 clone 返回 PID、rt_sigreturn、基线线程右删失、wait4 提前唤醒误归因、64 级以上依赖链、早期 EXIT 后仍可能抢占／阻塞、动态 JIT 符号误标。单元测试含篡改绑定、跨 Agent／PID 重用、缺事件和错误依赖等反例；没有用时间接近或容许“很小误差”把 UNKNOWN 抹平。

## 7. 版本、复查与明确边界

环境是物理服务器上的独立 QEMU 实验 VM，6 vCPU／12 GiB，Guest kernel `7.3.0-rc2` 实验构建；boot_id=`b7a9fbd2-14fd-4105-9381-8a064a9088be`，BPF LSM／BTF 启用。观测对象是这个 Guest Linux，不是 QEMU 对物理服务器的影响。VM 使用独立 qcow2 overlay，没有在物理 Host 挂这组探针。

最终 collector SHA256=`7a5d96b2a179c5fc6a8aa1c7fa41ad60259612530f93cbed68a2ec32da4e0a4f`；BPF SHA256=`7df809d44e1f26a49447bd5c29019a7d4794bbf56c20965fa78c3eb93e3da691`。每个 campaign 固定了自己的副本，离线解析不用重新挂 eBPF。

复查命令见 [使用说明](README.md)。回归入口为 `make execution-timeline-check` 和 `make check-all`。哈希检查、Guest／Host 重算通过，不等于已受控内核给出的信息必然真实；Agent ID 也仍是受信运行时登记的语义。

最终时间线专项 190 项测试通过，`make check-all` 整体通过，日志为 `.output/execution-timeline-check-all-004.log`。所有最终 CSV 又与符号修复前的 CSV 逐字节比较一致，原始计量没有变化；新的独立审计使用 final 输入，旧审计也保留。

验证后已确认没有运行中的采集器或测试容器，再只关闭专属 QEMU（PID 975753、端口 10431），其他 VM 未动。32 GiB 基础镜像 SHA256 复查与启动前一致：`30c9efb1ed33e265e784cc52d67e211845d1191ada5621237d3c9d16173e6715`。overlay、原始证据和旧失败均未删除。

本版不把普通锁持有者、共享服务委托、mmap 缺页、io_uring、恶意 cgroup 逃逸、Kata Guest 内部或物理设备因果链说成已完成。非主线程 exec 缺少显式旧生命周期桥接时会明确降级，不错误合并成完整线程。它是合作型、选定范围的诊断工具，不是 sandbox 或任意 Linux 工作负载的通用因果证明器。
