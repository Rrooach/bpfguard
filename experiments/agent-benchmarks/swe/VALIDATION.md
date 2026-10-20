# SWE-bench Verified 实际验证记录：2026-10-14

已在新建的 PSI QEMU Guest 中完成 **1 个真实 Verified 任务**
`psf__requests-1142`。参考补丁对照通过；DeepSeek Flash 的真实 shell Agent
生成了 489 字节补丁，官方 harness 判定 `resolved: true`，1 个 fail-to-pass
和 5 个 pass-to-pass 用例均通过。Agent 没有收到参考补丁或新增测试补丁。

这是单任务接入验证，不是 Verified 全部 500 个任务的成绩。官方用例通过
也不表示已经审查补丁的所有行为：该 Agent 补丁仅删除原来的默认
`Content-Length: 0` 赋值，与参考补丁并不完全相同。

## 实际观测结果

三个阶段均由独立容器执行，启用 `balanced` 系统效果 recorder 和 100 ms
资源采样；绑定容器 ID、PID + 启动时间、cgroup、boot ID 和 namespace。
结束前必须实际看到执行结束后的已落盘资源样本，然后才关闭采样器。

| 阶段 | 官方结果 | 系统效果事件 | 资源样本 | Guest 和 Host 独立验证 | 证据完整度 |
|---|---|---:|---:|---|---|
| 参考补丁对照 | 通过 | 5702 | 39 | 通过 | INCOMPLETE |
| 真实 Agent 执行 | 完成并生成补丁 | 1560 | 181 | 通过 | INCOMPLETE |
| Agent 补丁官方评测 | 通过 | 5702 | 36 | 通过 | INCOMPLETE |

全部阶段事件丢失数为 0。资源采样的读取错误、错过 tick、进程消失和
遍历截断均为 0。每个样本中都存在系统级和任务 cgroup 的 CPU、memory、I/O
PSI。进程生命周期事件分别为 106、464、106；这些事件与资源采样是独立通道。

文件状态比较分别发现 30、35、30 项变化；sysctl、mount、网络配置、模块
及残留进程的声明字段端点相同，BPF Program/Map 端点没有差异。
任务容器的初始 idle 进程仍在，不能把它当作 Agent 泄漏。
这些端点结果保留 `INCONCLUSIVE` 等原有合同结论，不从零 diff 推导全部系统
未改变，也不把所有工作区差异都称作 Agent 自己的修改。

## 这次发现并修正的问题

首轮真实 pytest 触发了对象解析歧义：160 次 `setxattr` 标记
`JOIN_AMBIGUOUS`，另有 2 次 `openat` 标记 `JOIN_MISSING`。旧 verifier
把明确声明的未解析对象误判为“没有声明原因就缺失对象”，因此拒绝整个证据。

修正后的部署 verifier 会验证这些失败标志、原始事件、JSON 和健康计数
是否一致，并继续保留 `INCOMPLETE`。没有失败标志却缺少对象，或者持有对象
同时声称解析失败，仍然拒绝。严格要求 `COMPLETE` 的 standalone 路径未放宽。

这只修正了不完整证据的独立重放，**没有解决 overlayfs 对象解析歧义本身**。
新运行三个阶段的对象关联失败事件分别为 162、4、162。旧失败证据也独立保存。

## 模型与时间

Agent 调用了 12 次模型：11 次 shell 命令决策，最后一次完成标记。
执行窗口约 17.969 秒，其中模型请求区间累计约 13.047 秒；12 个工具区间
累计约 4.871 秒，包含末尾协调器提取 patch 的工具调用。它们是阶段计时，
不是 CPU 时间分账，也不是 Observer 开销测量。

usage 合计为 23,756 输入 token、728 输出 token。共同预算 broker 按峰值
价格结算的本任务保守费用估计为 **0.053336 元**；这是预算账本估计，不是
provider 发票金额。模型请求通过统一 broker，Guest 没有 provider API key。

本次使用远端 API，无法分解本地 GPU 排队和执行。所有实验运行在目标
Linux 中；物理服务器只下载/复制实验输入并离线重放，不运行这些任务容器。
部分其他 benchmark 准备工作在同一 Guest 内并行，故不据此作性能因果或
开销百分比声明。

## 固定输入与结果位置

官方 harness 为 `3.0.17`，commit
`3f01bd622c0a22c00406139f69a234ef08225f22`。安装后的 53 个 Python 源文件
均逐个核对，与固定源码 archive 的 SHA-256 相同；未打包的辅助脚本另列。

镜像固定为：

```text
swebench/sweb.eval.x86_64.psf_1776_requests-1142
manifest sha256:fa9c859412109d003a68c2bbe3c65541ca4714526afeb6906fe589c18af0b30d
image ID sha256:ebfed0b9a44723b3ab1e934f0b040f843abf01e1a3a8b248e150d314e949cfaa
```

实际独立重放使用保留的版本化 verifier，SHA-256：
`571c79d8b60c5bb86728e8f9a26fa9feca959f31905702ba3bea6bbaaa3f99c9`。
三个 Host 重放均返回 `verified: true` 和 `evidence_status: INCOMPLETE`。

- [完整结果摘要](../../../.output/agent-benchmarks/swe-corrected-20261014/swe-verified-corrected-20261014/benchmark-summary.json)
- [模型和工具记录](../../../.output/agent-benchmarks/swe-corrected-20261014/swe-verified-corrected-20261014/agent-attempt/agent-transcript.json)
- [工具与模型时间标记](../../../.output/agent-benchmarks/swe-corrected-20261014/swe-verified-corrected-20261014/agent-attempt/observation/phase-events.jsonl)
- [实际补丁](../../../.output/agent-benchmarks/swe-corrected-20261014/swe-verified-corrected-20261014/agent-attempt/agent.patch)
- [Host 对 Agent 阶段的独立重放](../../../.output/agent-benchmarks/swe-corrected-20261014/host-verification-agent-attempt.json)
- [初次失败的证据](../../../.output/agent-benchmarks/swe-failed-gold-20261014/swe-verified-20261014/benchmark-summary.json)

这些 `.output` 产物不随 Git 提交，复制完整目录后可重新验证。源代码的
9 项单元检查通过，包括协议超时、输入身份、来源篡改，以及 verifier 通过
不能提升证据完整度等检查。
