# Agent 语义 Profiler：论文能力对照与本地实现

## 用户问题

默认页面要直接回答：Agent 在完成什么任务，花费在哪里，调用了什么工具，哪些进程和线程
实际执行，访问了哪些文件，最后对应哪些 syscall；而不是先展示互不关联的采集器面板。

目标图采用 profiler 语义：纵向是责任层级，横向是一个可切换的可加权指标。原始事件仍是证据，
profile 是可重新生成的展示投影。

## 三篇工作的分工

- [AgentSight](https://arxiv.org/pdf/2508.02736) 提供跨层边界观测：把模型/工具活动与进程、文件、
  网络等系统效果联系起来。
- [AgentPProf](https://arxiv.org/pdf/2609.20301) 提供 profile 抽象：统一 operation、语义 operation
  stack，以及按 token、时间、文件或网络等权重折叠的 flamegraph。
- [AgentCgroup](https://arxiv.org/pdf/2602.09345) 把资源域细化到工具调用：Agent cgroup 下再创建
  tool cgroup，用于工具级资源记账和后续控制。

本项目保留自身更严格的部分：显式 call ID 到 stopped root/cgroup 的绑定、原始 WAL 离线重放、
对象解析质量、丢失证据和 syscall 下钻。论文中的语义层不能代替这些证据合同。

## 当前实现

`semantic_profile.py` 把 `render_agent_story.py` 已验证的故事编译为统一 operation。每条 operation
包含 stack、非负 measures 和 evidence。stack 共享前缀如下：

```text
Agent
└── task
    └── semantic segment
        └── tool
            ├── process → thread
            ├── process → syscall category → syscall
            ├── process → file
            └── tool cgroup resource
```

当前 profile 视图包括：

| 视图 | 来源 | 口径 |
|---|---|---|
| Agent 墙钟 | Codex/工具/模型/Code Mode 边界 | 同一 boot 的区间按墙钟划分；并行单独标记；尚未细分的 runtime 时间保留 |
| 模型等待/接收/请求总耗时 | Agent 侧本地 HTTP 计时 | 首 body 字节不等于首 token；Host 缓冲、传输和 provider 均可能包含在等待内 |
| V8 JS/工具等待 | 实际 V8 dispatcher 适配器 | 显式同步 JS body 与子工具等待并集；没有 hook 不推断 |
| RSS 曲线与内存积分 | 每 100 ms PID/cgroup 采样 | PID 生命周期、Agent、boot、cgroup 身份检查；采样覆盖有限 |
| ONCPU / RUNNABLE / SLEEP | eBPF scheduler 事件 | 线程时间之和，可因并行超过墙钟；sleep 不自动等于磁盘等待 |
| syscall 次数/时间 | eBPF syscall 配对 | 已选择接口；时间为入口到返回，可能包含执行与等待 |
| 文件操作/返回字节 | 内核文件对象与 VFS read | 实际返回字节，不是源文件大小或块设备字节 |
| 工具 cgroup CPU/内存/fault/I/O | 新建工具 cgroup 边界 | 新运行可用；memory.peak 是该工具 cgroup 生命周期高水位 |
| token | provider/Codex usage | 当前没有绑定 usage 时为 `NOT_COLLECTED` |

页面默认只显示 profile。逐工具命令、程序、文件和逐次 syscall 位于同页的下钻折叠区。

## 仍然存在的差距

1. 当前 semantic segment 来自 Agent 自己输出的计划文本，只能用于单次运行阅读；尚未实现
   AgentPProf 的递归分段、短稳定名称和跨运行折叠。
2. 模型请求已经在 Agent 所在 Linux 的本地转发入口独立计时；Code Mode 已有可用的 Node/V8
   dispatcher 适配器和实际验证。现有 benchmark 关闭 Code Mode，接入未加 hook 的内部 V8 实现时仍需
   在其真实 dispatch/continuation 位置使用该适配器；无法仅靠 Linux syscall 还原 JS 函数。
3. Terminal-Bench 的 Docker Exec 共用容器 cgroup。旧 campaign 没有每工具资源采样，因此只能用
   scheduler 事件给出进程/线程 CPU 状态，不能追溯工具级内存峰值。新的 direct runner 已有工具级
   cgroup 边界；Docker 路径已经采样工具 root RSS 和共享容器 cgroup，但短进程可能漏采，工具独占
   内存峰值仍需工具子 cgroup。旧 campaign 的资源数据无法事后补采。
4. token usage 和模型请求等待已进入 profile；通用网络 operation 和自动稳定语义分段仍待完善。
5. 已新增 `pprof_export.py` 输出标准 gzip pprof protobuf，并由 Go pprof 独立解析验证。
   语义分段仍不是递归模型归一的跨运行稳定标签；尚未完成对应的多运行语义 differential 流程。
6. 新增 `decision_evidence.py` 把应用调用、执行门、PID/cgroup、内核线程和 syscall/对象逐边列出。
   公开说明仅是同轮次上下文；LINKED 不意味着隐藏思维／完整因果或全部接口覆盖。

论文与作者仓库的逐项核查、PID/cgroup 内存口径、结束状态及新验证见
[2026-10-20 对齐说明](PAPER-ALIGNMENT-2026-10-20.md)。

## 验收原则

- 主视图必须从 Agent/task 开始，不能从 syscall 开始。
- 切换指标只改变宽度和叶子证据，不改变已经确认的语义责任前缀。
- 墙钟、CPU core-time、sleep、内存峰值、字节和次数不相互混加。
- 缺失资源必须显示 `NOT_COLLECTED`，不得用容器级值冒充工具级值。
- 点击/下钻最终能够回到明确 call ID、PID/TID、文件对象和 syscall；profile 本身不替代 verifier。
