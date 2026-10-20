# 真正 Codex + DeepSeek：一个小任务的执行时间线

这次不是自写 Agent 循环，也不是 benchmark。使用真正的 Codex CLI 0.154.0
app-server，由 DeepSeek 返回下一步操作；Observer 记录 Codex 和实际命令进程。

## 已经做成什么

Codex 调用一次 `observer_bash`，实际启动 Bash → Python，完成：

```text
创建 demo.txt → 写入 hello-observer → 读取并打印
→ 改名 result.txt → 设置 0600 → 打印大小与权限 → 删除
```

命令退出码为 0，输出大小 15 bytes、权限 `-rw------- (0o600)`。
命令及导出时的检查均确认 `demo.txt`、`result.txt` 不存在。随后 Codex 正常给出最终回答。

本次记录有 54,620 条事件、68 个重建线程。选定 hooks 的采集健康为
`COMPLETE_FOR_SELECTED_HOOKS`；Guest 和 Host 独立原始重放均通过，重建报告一致。
这不是“整个系统没有变化”的证明，也不代表所有接口均已覆盖。

## 在哪里看

打开[任务首页](../../.output/codex-readable-20261019-001/view-002/index.html)。
先看指令、命令、退出码、输出和最终回答，再进入文件操作或线程时间线。

完整结果在
`tools/bpf/bpf-state-observer/.output/codex-readable-20261019-001/run002/`：

| 文件 | 用途 |
|---|---|
| `app/steps.json`、`app/steps.csv` | Codex 消息、实际工具步骤和返回值 |
| `app/function-bindings.jsonl` | Codex 请求 ID → 工具 ID → 根 PID 与 cgroup |
| `tool-0001/stdout` | 实际命令输出，不是模型转述 |
| `report.json`、`timeline.html` | 逐线程执行、等待、选定文件读取等详细记录 |
| `capture/events.bin`、`manifest.json` | 原始记录及文件摘要绑定 |

[Host 导出与重放回执](../../.output/codex-readable-20261019-001/run002-export-replay-receipt.json)
记录逐文件 SHA256、fsync、源文件复核和独立重放结果。导出不包含私有 Codex home 或 token；Guest 原件保留。

第一次真实尝试单独保存在 `attempt001-run/`：命令成功，但模型续聊失败。
它没有被修改成成功，也没有混入最终 `run002`。`codex-readable-fake-*` 是零付费协议校准，不是真模型结果。

首页优先展示工作目录内的读取，运行库与系统文件放在可展开的详情里。
这次可直接看到 `demo.txt` 请求 16 bytes、返回 15 bytes、VFS 读取约 4.08 微秒，
以及成功的 `rename`、`chmod`、`unlink`；写入及改名等目标路径未解析的部分仍明确标出，
不会从模型命令文本补成内核证据。全部读取和 syscall 仍保留在详细页。

## 真实 API 与费用核查

[提供方证据核查](../../.output/codex-readable-20261019-001/provider-validation-002.json)
把保存的原始 Responses SSE 中的调用 ID、命令和最终回答，与本次 Codex 的实际
请求／进程绑定逐项核对。它还独立复算预算账本；配置了模型名本身不算真实调用证明。
这是基于可信本地代理的记录，不是提供方签名或被攻破内核的真实性证明。

成功这轮使用 2 次真实请求，费用上界约 **0.011272 元**；连同前一份失败尝试，
本次 3 次请求上界约 **0.017012 元**。滚入此前历史后的累计上界约 **0.770680 元**，
没有超出 5 元限制。估算按已保存价格和 usage 计算，不是账单发票。
API 代理与实验 VM 已正常停止，镜像和原始证据保留；没有重跑 benchmark。

## 不调用模型，重新核查现有记录

从 Observer 项目目录执行：

```sh
python3 -B experiments/execution-timeline/replay.py \
  --run-dir .output/codex-readable-20261019-001/run002 \
  --collector .output/execution-timeline-native023/collect \
  --expected-manifest-sha256 a12ede63f5406203d300816ebfd23e1f0ad92c8292d6a61f24cf5685a5dd1215 \
  --check-report .output/codex-readable-20261019-001/run002/report.json
```

## 再运行一个任务

先在目标 Linux 准备可写 cgroup v2、同版 native collector、Codex、模型 catalog，
以及已经设好总费用／请求数上限的本地 Responses 代理。只把代理凭证交给 runner，
不要把真实模型 API key 交给命令进程。参数见：

```sh
python3 -B experiments/execution-timeline/codex_run.py --help
```

入口为 `codex_run.py`，传入工作目录、指令文件、全新的输出目录、Codex/catalog/native
路径和本地代理地址。它先启动 Observer，再启动 Codex；每次动态命令先登记进程和
cgroup，再放行。结束后确认进程组清空，停采并重放。

这是 **Codex 受控命令工具模式**：代理只向模型开放、交付 `observer_bash`，不是
Codex 默认全部内建工具。Codex 的普通工具日志没有可靠的 OS PID，因此这里使用
明确请求映射，不按时间相近猜进程。运行时总时间含思考、协调、工具和清理，不能
等同于纯模型 API 时间，也不能再与工具时间相加。当前边界仍是合作型工作负载，
不是恶意 Agent 的强隔离方案。
