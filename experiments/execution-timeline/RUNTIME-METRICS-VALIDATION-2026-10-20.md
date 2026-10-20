# 模型等待、V8 执行和内存：实现与验证

勘误：旧 003 示例的 `wc -c` 验证了文件长度，可能通过元数据／seek 得到结果，并不证明真的读取了 4 MiB 内容。
下列时间／内存原始数值仍有效；此前“读取 4 MiB”的表述不严谨。后续严格 Guest 验证要求按完整文件路径和内核对象
从 VFS read 返回记录复算 4 MiB，见 [论文对齐与后续验证](PAPER-ALIGNMENT-2026-10-20.md)。

## 现在能看到什么

在同一个 Agent 页面中，分开看：

- 模型请求：每次请求总耗时、等待首个响应 body 字节、接收后续响应。
- V8/Code Mode：明确标记的 JavaScript 执行段、等待子工具、尚未细分时间。
- 内存：Codex 和工具进程 RSS 曲线；声明 cgroup 的总用量、匿名内存、文件页缓存；V8 heap 边界样本。
- Observer 自己的进程内存：单列，不算作 Agent 内存。

墙钟分解不重复计入父工具和它内部的 V8 执行，也不重复相加并行工具等待。
JS 段是墙钟时间，线程 CPU 时间在运行时支持时另列。没有明确边界的间隙仍是“尚未细分”，不能自动算模型等待。
`awaitTool` 的同步派发属于 JS，只有返回 Promise 后才开始等待；同步返回的等待是零。

首 body 字节可能是 SSE 元数据。当前 Host 模型网关会缓冲响应，因此这个指标不是
provider 的首 token 延迟，也不能拆成 provider 排队和推理耗时。

## 本轮实际验证

结果目录：`.output/runtime-metrics-complete-20261020-003/`。

打开[完整页面](../../.output/runtime-metrics-complete-20261020-003/profile-final.html)，先看“时间花在哪里，内存用了多少”，
再切换火焰图指标、内存对象，展开请求明细。

实际执行链为：官方 Codex 0.154 → stopped shell → Node 22/V8 → 分配及准备数据 → shell 查询 4 MiB 文件长度并等待 → JS 处理结果。
模型端是本地确定性 Responses fixture：两次 HTTP 请求，零付费 API，不是实际模型推理。

| 指标 | 本轮记录 |
|---|---:|
| Agent 端到端墙钟 | 1292.041 ms |
| 两次模型 HTTP 请求总耗时 | 309.933 ms |
| 模型首 body 字节等待累计 | 195.168 ms |
| V8 明确 JS 执行段墙钟 | 78.517 ms |
| 这些 JS 段的主线程 CPU | 72.932 ms |
| Code Mode 等待子工具 | 253.334 ms |
| Code Mode 其余时间 | 0.981 ms |
| Codex 采集窗 RSS 已观察峰值 | 127,537,152 B |
| V8 进程 RSS 已观察峰值 | 85,250,048 B |
| V8 heap 已观察最大值 | 15,676,496 B |
| Observer 管理进程 RSS 已观察峰值 | 26,267,648 B |
| 资源样本 | 37 |

V8 的 JS、等待和其余时间相加等于其总墙钟 332.832 ms。Agent 墙钟还包括 runtime 启动/收尾、
工具派发/返回等，不能只相加表中三个重点时间就当作 Agent 总时间。

这些数值仅用于验证分开计量是否有效，不用于声明性能优化、生产开销或 benchmark 正确率。
本轮没有加载 eBPF recorder，syscall 和内核事件数为零；页面保留 `NOT_COLLECTED_PROTOCOL_VALIDATION`，
官方判题为 `NOT_PROVIDED`，没有用应用事件冒充内核证据。

## 原始数据在哪里

| 工件 | 含义 |
|---|---|
| `app/model-request-timing.jsonl` | 同一 Linux 时钟上的模型请求阶段边界 |
| `app/model-transport-summary.json` | 采集收尾回执；开始/结束计数、错误、停止超时 |
| `app/code-mode-events.jsonl` | 实际 V8 的 JS、等待和内存边界 |
| `app/resource-samples.jsonl` | PID/cgroup 内存、CPU、缺页采样 |
| `app/resource-summary.json` | 每个采样对象的峰值与覆盖限制 |
| `app/child-process-events.jsonl` | 实际子工具 PID/start_ticks、退出和返回的文件长度；应用证据而非内核 trace |
| `story.json` / `semantic-profile.json` | 页面数据和可加权 profile |
| `validation.json` / `validation-manifest.json` | 验证范围和工件摘要绑定 |

`profile-final.html` 和 `semantic-profile-final.json` 是从这批已绑定原始证据重新导出的展示；
原始 `index.html`、profile 和 validation manifest 保持不变。

采样约 100 ms，可能漏掉短进程和瞬时峰值。PID RSS 不包含全部后代；容器共享 cgroup 不冒充某个工具的独占用量。
进程 RSS、V8 heap 和 cgroup 用量存在包含/共享关系，不能直接相加。
Observer 的 RSS 说明自身占用；“额外增加多少内存和耗时”仍需相同任务关闭/开启的配对实验。

## 如何复现

在 Observer 根目录运行，输出目录必须是新目录：

```sh
python3 experiments/execution-timeline/validate_runtime_metrics.py \
  --codex .output/codex-0.154.0/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex \
  --catalog .output/runtime-metrics-complete-20261020-003/app/model-catalog.json \
  --output .output/my-new-runtime-metrics-validation
```

需要 Linux `/proc`、Node 和现有 Codex 二进制/公开模型目录。它仅启动本机 fixture，不读取 DeepSeek 密钥，不访问付费模型。

正常 Direct/Harbor Codex runner 已接入模型计时和资源采样。V8 内部边界仍需在真实 Code Mode dispatcher
使用 [observer-code-mode.mjs](observer-code-mode.mjs)，示例见 [README](README.md#模型等待code-mode-执行与内存)。
当前受控 Terminal/SWE benchmark 配置关闭 Code Mode；这次真实 Node/V8 验证不代表已经自动观测了 Codex 内部的所有 JS。

## 自查覆盖

- 同一 run/Agent/task/boot 绑定；其他 run 的 V8 数据拒绝混入。
- 不同 boot 的请求只显示各自时长，不拿两个 monotonic 时钟直接相减。
- 请求没有结束、写入失败、停止超时保留不完整；不伪造零等待。
- 同步工具派发、同步返回、异常、并行 await 都有真实 Node 回归。
- PID 重用、cgroup 身份变化、计数回退、样本上限保留覆盖限制。
- 页面 JavaScript 实际执行测试覆盖缺失值、内存曲线、火焰图和不完整告警；不是只检查 HTML 字符串。
