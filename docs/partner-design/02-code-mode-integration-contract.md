# Allox + Observer 接入说明

本方案要解决的是：Code Mode 中的操作可能分散在 V8、工具进程和共享服务中，难以完整观察、归属到具体 Agent，并在恢复后清理干净。通过管理实际执行位置、明确任务结束条件，再结合 Allox 和 Observer，建立可检查的执行范围。

这里的“执行范围”，就是明确哪些进程、工具和工作目录属于这次任务，哪些操作仍在范围之外。目标不只是给 shell 加一份日志，而是让产品能够回答：这次任务实际在哪里执行、做了什么、是否已经结束、恢复后还留下什么。

本文先讲 V8 接入的问题和方案，再给出现有 Allox 接口的使用步骤。前半部分包含待实现的产品适配；后半部分的命令接口来自已有代码。下文按采用 V8 的 Code Mode 产品分析，不假定所有 Codex 产品都使用相同进程模型，也不把可能的问题写成已经发现的漏洞。

## 1 V8 接入为什么不能只看 shell

### 问题一 修改文件不一定经过 shell

以“Agent 修改代码并运行测试”为例，产品可能提供两条执行路径：

```text
路径一  JavaScript 调用命令工具 → 启动 shell → 修改文件
路径二  JavaScript 调用文件工具 → 产品的文件处理代码直接修改文件
```

两条路径都能改变文件，但第二条可能完全不启动 shell。网络工具也一样，实际请求可能由 V8 所在进程、独立工具进程或远程服务发出。

V8 负责执行 JavaScript，读写文件和联网等能力由周围的运行环境提供。因此问题不是“eBPF 看不见 V8”，而是只登记 shell 的执行范围，会漏掉在其他进程里完成的操作。

解决办法是把接入点扩大到有系统影响的工具执行层。先列出文件、网络、命令等工具真正在哪里执行，再将需要观测的本地操作放进 Allox 管理范围。不是把所有工具都改写成 shell。

### 问题二 多个 Agent 共用一个进程时不好区分

假设 Agent A 和 Agent B 的 JavaScript 共用一个 V8 进程。内核看到这个进程写了文件，但不会自动知道是谁的工具调用触发了写入。

V8 isolate 可以隔开 JavaScript 执行环境，但不等于独立 Linux 进程。只给应用日志加上 agent_id，也不会改变真正执行操作的进程。

解决办法分两层：

- 产品记录 Agent、任务和工具调用的关系，解释“谁请求了什么”。
- 需要独立观察和恢复的任务使用独立操作系统进程、工作目录和受管理的进程分组，让 Observer 更明确地识别这次运行的直接操作。

同一个 worker 内的多个工具如果并行执行，进程归属只能直接支持运行级判断，不能仅按时间接近把每条系统操作分配给某个工具调用。

### 问题三 JavaScript 返回了 后台操作可能还没结束

例如 JavaScript 发起一个异步写入后返回，真正的写入仍在工具队列里等待。如果产品立刻采集“执行后状态”，可能采早了；如果立即回滚，稍后完成的写入还可能再次改变文件。

解决办法是在产品运行层登记未完成的工具请求。收尾时停止接收新操作，再等待或取消已有请求，并检查实际执行进程是否停止，最后才采集执行后状态。

“取消请求已发送”不等于“操作已经停止”，“未完成请求计数为零”也不能代替进程检查。无法确认结束的操作应在报告中保留为未完成或范围外影响，不能直接记成没有残留。Observer 本身也无法知道未接入的产品队列里还有哪些请求。

### 问题四 文件恢复了 V8 内存没有恢复

例如文件已经恢复旧版本，但 V8 内存仍缓存着新内容。旧 worker 继续执行时，可能又把新内容写回文件。

Allox 文件回滚不会恢复 V8 的全局变量、缓存、异步任务和网络连接。第一版建议恢复前结束旧 worker 及其受管后代，恢复和检查结束后，只有会话允许继续使用时才启动新 worker。

这里的 worker 指独立操作系统进程，不是 JavaScript 线程或 isolate。重建 worker 得到的是新的运行环境，不是回到原来 JavaScript 执行中的某一行；已经发送到远端的请求也不会因此撤销。

## 2 推荐怎样组织执行

建议第一版为每个需要独立观察和恢复的任务安排独立 worker。下面是目标结构：

```text
产品后端
  保存 Agent 和任务身份
  校验工具请求和访问权限
       ↓
Allox 管理的一次执行
  ├── 独立 V8 worker
  ├── 在该范围内运行的本地工具及其子进程
  └── 独立会话工作目录
       ↓
Observer
  记录受支持的系统操作
  比较执行前后和恢复后的状态
       ↓
产品报告
  把工具请求和实际系统记录放在一起查看
```

关键条件是：真正执行文件、网络操作的工具代码也要进入对应范围。如果 worker 只是把请求发给外面的共享服务代做，独立 worker 仍不能让 Observer 自动获得那个服务的操作归属。

第一阶段不实现任意共享服务的因果追踪。不能迁入范围的共享服务、远端工具，需要在报告中单独列出：可以保留请求记录，但不承诺已经观察到其内部效果或最终状态。

### 整个 worker 作为一次受管理执行

第一版可以把 worker 从启动到退出作为一次观测运行，初始化也包含在这个窗口内。产品需准备 worker 的可执行程序、依赖和任务输入通道，再交给 Allox 启动；现有 shell 示例不会自动完成这些适配。

如果要让一个长期存活的 V8 进程处理多个回合，并只比较其中某一回合，需要额外实现“本轮何时开始、何时完成”的通知和等待机制，不能直接把现有命令接口当作已经支持这项能力。

需要恢复时，建议的业务收尾顺序是：

```text
停止接受新的工具请求
  → 等待或取消已有请求并核实实际执行结果
  → 结束旧 worker 及其受管后代
  → 记录执行后 B
  → Allox 恢复工作区文件
  → 记录恢复后 C 并复核报告
  → 清理完成且会话允许继续使用后 才启动新 worker
```

上述产品队列管理和 V8 重建需要新增适配；Allox 插件已有的是受管理进程的收尾、B/C 采集、文件恢复和结果复核。涉及内核异步操作或外部服务时，进程退出仍不等于所有外部效果已经结束，报告继续保留相关限制。

### 现有 V8 必须共享时怎么办

可以保留共享 V8，让它只负责计算和发出工具请求，把有系统影响的操作转给按任务隔离的执行进程。所有这类接口都必须走受控入口；留在共享 V8 或共享服务里直接执行的操作不能算作已纳入独立观测范围。

这个方案减少了拆分 V8 的改动，但需要逐一检查工具有没有绕过入口。一个所有 Agent 共用的工具进程，同样不能自然解决逐 Agent 的内核归因。

### 后续放进 Kata 时移动什么

需要移动的是 V8 worker 和真正执行本地操作的工具，不是仅移动 JavaScript 引擎。若 V8 在 Guest、文件工具却仍在 Host 操作文件，那些文件操作仍然影响 Host。部署位置详见 [Kata 部署说明](03-codex-kata-architecture.md)。

## 3 具体需要新增哪些组件

| 改动位置 | 需要新增的产品逻辑 | 现有基础与边界 |
|---|---|---|
| 工具调度和执行代码 | 列出各工具的真实执行位置，把选定本地操作送入受管理范围，范围外请求单独标记 | Allox 可启动和停止受管理命令；不会自动迁移所有工具实现 |
| V8 worker 启动和收尾代码 | 独立进程启动、传入任务、登记异步请求、取消或等待、恢复后重建 | 复用 Allox 进程管理；V8 专用通信和结束条件仍需实现 |
| 产品任务记录 | 保存 Agent、工具调用与 Allox 执行编号的对应关系 | Allox 生成 run_id；新增业务字段由产品记录 |
| 报告查询与展示 | 把工具请求、实际操作、状态差异和检查失败原因关联展示 | 复用 Observer 结果文件；不是每条内核事件都能精确对应工具调用 |

run_id 就是“一次实际执行的编号”。一个 Agent 任务可能调用多次工具，因此要保存“业务任务 → 工具调用 → 实际执行”的关系。独立 worker 方案下，多个工具调用也可能属于同一次 Allox 执行。

管理 token 由可信产品后端保管，不能交给运行 Agent 代码的 worker。工具授权应由可信执行层检查，不能让 Agent 自己填写身份或权限后就直接接受；已有的审批和沙箱限制也不能因为改走 Allox 而被绕过。

### V8 指标和系统指标分别从哪里来

| 要回答的问题 | 主要由谁提供 |
|---|---|
| 哪个 Agent 调用了哪个工具，工具等待了多久，还有多少请求未结束 | 产品运行层新增记录 |
| V8 堆内存用了多少，垃圾回收耗时多少 | V8 运行时接口和产品采样，需新增接入 |
| 记录到哪些文件、网络和进程操作，最终状态怎样变化 | Observer 已有能力，按所选范围采集 |
| 命令是否结束，返回码是什么，会话能否继续使用 | Allox 和插件运行结果 |

eBPF 看到的是 Linux 层行为，不会自动理解 JavaScript 变量、工具名或异步任务。这些应用记录应与 Observer 的执行编号关联，而不是把它们伪装成内核直接提供的事实。

### 怎样控制新增开销

先在任务和工具调用边界记录身份与状态，不追踪每一行 JavaScript。V8 内存和垃圾回收指标按需要采样，Observer 继续按任务范围过滤事件，文件和配置检查只在阶段边界执行。

独立 worker 的启动成本、Observer 的记录成本和状态检查耗时分别测量。是否复用 worker 或采用进程池，应在清理和隔离测试通过后再决定，不能为了减少启动时间而把不同任务的未完成操作混在一起。

## 4 分两步完成接入

第一步先跑通现有命令路径：

```text
产品命令工具 → Allox 启动命令 → Observer 记录 → 产品读取报告
```

这一步用 effect.txt 这样的简单文件验证接口、权限、结果路径和恢复流程。它只证明命令工具接通，不代表 V8 本身及所有其他工具都已接入。

第二步再完成 V8 专项适配：实现前面的工具执行层、worker 生命周期和业务关联记录，补测不经过 shell 的文件操作、异步请求收尾及恢复后的 worker 重建。

后面的接口教程用于第一步，也可作为第二步启动实际进程的基础。通常先修改产品的工具执行和 worker 管理代码，不需要先修改 V8 引擎内部。

## 5 运行示例之前要准备什么

在目标 Linux 上准备好以下内容：

- Allox core、system-effects 插件，以及 Observer 和报告复核程序。
- Observer 使用的 BPF 文件，以及配置中要求的内核能力。
- Btrfs 工作盘，用于 Allox 的会话目录和文件检查点。
- 要检查的目录和系统配置，以及需要记录的操作类型。

例如要验证 effect.txt 的创建和写入，应把对应工作目录纳入文件检查范围，并选用包含普通写入操作的记录策略。只开启操作记录，不等于已经开启文件前后比较。

现成安装与启动步骤见本地参考仓库的 [插件中文教程](../../../../../../allox-os-observer-plugin/plugins/system-effects/README.zh-CN.md)。启用 system-effects 时需要关闭旧的 process-tree provider；教程中的 `--process-tracking disabled` 关闭的是旧插件，不是禁用 `process.start`。

这一步先在已有直接执行环境中跑通，不要求先完成 Kata 部署。

## 6 用现有接口跑一条命令

Allox 的管理接口是 `POST /v1/rpc`，请求格式为 `action` 加 `params`，并携带 Bearer token。

按现有教程部署时，本机示例地址是 `http://127.0.0.1:8092/v1/rpc`。这是 Allox 所在 Linux 的本机地址；如果 Allox 在虚拟机内，不能直接把它当成宿主机的访问地址。

### 第一步 创建 Agent 和会话

Agent 表示工作身份，Session 表示一次任务的工作空间。初始化时分别提交：

```json
{"action":"agent.create","params":{"agent_id":"agent-a"}}
```

```json
{"action":"session.create","params":{"agent_id":"agent-a","session_id":"session-1"}}
```

这是新任务的初始化示例，不是每次查询时都重复创建。会话已存在时应复用正确的会话，而不是反复发送创建请求。

### 第二步 提交命令

先用一个容易检查的命令验证接入：创建 effect.txt。

```json
{
  "action": "process.start",
  "params": {
    "agent_id": "agent-a",
    "session_id": "session-1",
    "argv": ["/bin/sh", "-c", "printf hello > /workspace/effect.txt"],
    "timeout": 60
  }
}
```

这里的 `/workspace` 是命令看到的会话工作目录，`timeout` 单位是秒。

成功响应外层为 `{"ok": true, "result": ...}`。保存 `result.run_id`，后续用它查询或停止这次执行。

start 返回表示已完成观测准备并放行命令，不表示命令已经结束。如果提交超时，不要直接重发同一命令：当前接口没有工具调用去重键，需要先核对是否已经启动，避免执行两次。

### 第三步 查询执行结果

```json
{
  "action": "process.get",
  "params": {
    "agent_id": "agent-a",
    "session_id": "session-1",
    "run_id": "<替换为 start 返回的 run_id>"
  }
}
```

产品重复查询，直到 `result.state` 为 `completed`、`failed` 或 `stopped`。查询失败、超时和用户取消也需要处理，不能一直只等 completed。

结束后分别看：

- `root_exit_code`：命令的返回码，通常 0 表示命令成功。
- `feature_runs["system-effects"]`：观测结果及报告位置。
- `session_fenced`：这个会话是否被暂停继续使用。

“执行结束”“命令成功”“观测报告复核通过”是三件不同的事，不能只看 completed 就全部显示成功。

### 第四步 支持取消

取消时提交 `process.stop`，参数与上面的查询相同：

```json
{
  "action": "process.stop",
  "params": {
    "agent_id": "agent-a",
    "session_id": "session-1",
    "run_id": "<替换为 start 返回的 run_id>"
  }
}
```

之后仍需查询最终状态和已有报告，不能把发送停止请求当成收尾已经完成。

## 7 输出和观测结果在哪里

`process.get` 返回状态和文件位置，不直接返回完整日志内容。产品后端需要读取当前执行对应的服务端文件。

| 用户要看什么 | 从哪里取 |
|---|---|
| 命令输出和错误 | `audit_directory` 下的 `stdout.log`、`stderr.log` |
| Observer 的报告入口 | `feature_runs["system-effects"]` 中的路径 |
| 普通执行的汇总 | 插件结果里的 `report_path` |
| 受支持的系统操作 | `evidence_directory` 下的 `system-effects.jsonl` |
| 进程创建和退出 | 同目录下的 `process-lifecycle.jsonl`，需启用相应采集模式 |
| 报告复核结果 | 插件结果里的 `offline_verification` 和 `verification_result_path` |

`audit_directory` 是这次运行的日志目录，`evidence_directory` 是观测记录目录。优先使用接口返回的路径，不要自己根据任务编号猜路径。

这些文件位于 Allox 所在服务器，浏览器不能直接读取。第一版可由产品后端读取并返回整理后的结果；跨机器部署时，需要另接带权限检查的报告下载或回传功能。

当前 `process.events` 不是读取 system-effects 记录的接口，不应拿它代替上述文件读取。

## 8 需要恢复实验时怎么接

普通 `process.start` 只观察执行前后，不回滚任务成果。

要专门测试“执行后能否恢复”，在启动请求的 `params` 中增加 `recovery`，其值为：

```json
{
  "scrub_runtime": true,
  "require_consistent": true
}
```

完整含义是：执行结束后处理任务进程、恢复会话文件，并且只有恢复结论满足严格条件才允许继续使用该会话。

未指定 `checkpoint_id` 时，Allox 自动创建基线检查点；也可以在 recovery 中指定已有的完整检查点编号。要验证“回到执行前”，该检查点的文件状态需要与执行前一致。

部署时还必须准备受信任的恢复程序及其文件摘要，并让恢复报告复核程序可用。只增加请求字段，不能代替这一步配置。

已有插件会完成：

```text
记录执行前 A
  → 运行命令
  → 处理进程并记录执行后 B
  → Allox 恢复会话文件
  → 记录恢复后 C
  → 复核报告
  → 清理旧工作区并决定能否继续运行
```

产品读取三类结果：

| 结果文件 | 告诉用户什么 |
|---|---|
| `agent-delta.json` | 执行期间改变了什么 |
| `recovery-delta.json` | 恢复过程撤销或新增了什么 |
| `residual-delta.json` | 恢复后还有什么不同 |

最终结论在 `recovery-verdict.json`，插件结果也提供 `recovery_verdict`、`release_allowed` 和 `fence_required`。

fence 的意思是“暂停这个会话的新任务，等待处理”。产品应保留已有报告供排查；这不表示进程和文件仍保持出错时的原样。严格模式下，即使 effect.txt 已经消失，只要总结果仍是“暂时无法下完整结论”，会话也可能被暂停。

Allox 恢复的是当前 Session 的文件，不是整个 Linux，也不恢复 Agent shared 目录、V8 内存和远端服务。不要给正常工具调用默认添加 recovery，否则任务成果也会被撤销。

## 9 第一轮怎样判断接入成功

按下面顺序做，失败时直接查看对应阶段：

1. 普通执行：创建 effect.txt，查询到正确返回码和执行编号。
2. 读取报告：找到已配置的写入记录和文件新增差异。
3. 恢复实验：看到执行时新增、恢复时删除，以及实际总结论。
4. 异常处理：取消任务或让检查失败，产品展示原因，不继续误报成功。

以上四项用于验证已有命令路径，不表示已经完成 V8 接入。V8 专项适配后还需要增加：

| 验收场景 | 要检查的问题 |
|---|---|
| JavaScript 通过文件工具写 effect.txt 不启动 shell | 实际写入仍进入对应执行范围，而不是只留下工具调用日志 |
| Agent A 和 B 分别执行任务 | 执行编号、工作目录和报告不串线；当前插件先按串行方式验收，不冒充并发已通过 |
| JavaScript 已返回 但工具里还有延迟写入 | 任务不能提前完成采集或回滚；未结束操作应被明确显示 |
| 文件恢复后启动新的 worker | 旧进程不能继续使用缓存或文件句柄修改工作区，新 worker 不沿用旧的易失内存状态 |
| 调用范围外的共享服务或远端工具 | 报告只说明已知请求，不把服务内部效果写成已完整观测 |
| 相同任务开启和关闭新增适配及采集 | 分别报告 worker 启动、运行时记录和边界检查的开销 |

这些是待执行的验收用例，不是新增测试结果。一个 Agent 回合包含多次工具调用时，第一版可将完整独立 worker 作为一次运行；长期复用 worker 的逐回合观测，需要另外实现任务开始和结束通知。

## 附录 实现时再查的组件和限制

### 代码位置

下表中的 Allox 链接指向本地参考工作树 `allox-os-observer-plugin`。

| 文件 | 工程上用来做什么 |
|---|---|
| [Allox daemon.py](../../../../../../allox-os-observer-plugin/src/allox/workspace/daemon.py) | 查启动、查询和停止接口的参数 |
| [Allox service.py](../../../../../../allox-os-observer-plugin/src/allox/runtime/process_tracking/service.py) | 查运行状态、返回码、进程管理和日志目录 |
| [插件 plugin.py](../../../../../../allox-os-observer-plugin/plugins/system-effects/src/allox_system_effects/plugin.py) | 查普通观测和恢复模式的选择 |
| [插件 runner.py](../../../../../../allox-os-observer-plugin/plugins/system-effects/src/allox_system_effects/runner.py) | 查普通执行报告和收据 |
| [插件 recovery_runner.py](../../../../../../allox-os-observer-plugin/plugins/system-effects/src/allox_system_effects/recovery_runner.py) | 查恢复流程、清理和会话是否允许继续使用 |
| [Observer 采集入口](../../crates/deployment-observer/src/bin/deployment-observe.rs) | 查实际采集程序 |
| [Observer 恢复报告复核](../../crates/deployment-observer/src/recovery_verify.rs) | 查如何从原始记录重新计算结果 |

当前插件调用的是 `deployment-observe`。接入已有 Allox RPC 不需要另外实现 PrepareObservation 等新协议接口。

### 配置和文件名

部署配置需要指定 Observer、复核程序、BPF 文件和摘要；另外配置记录策略、对象解析方式和检查范围。恢复模式再配置固定的恢复程序。完整参数以 [插件教程](../../../../../../allox-os-observer-plugin/plugins/system-effects/README.zh-CN.md) 和 [配置代码](../../../../../../allox-os-observer-plugin/plugins/system-effects/src/allox_system_effects/config.py) 为准。

“收据”就是插件保存的一份运行汇总和结果索引。外层文件名需要区分：

- 普通执行：`system-effects-receipt.json`、`system-effects-verification.json`。
- 恢复执行：`system-effects-recovery-receipt.json`、`system-effects-recovery-verification.json`。

参考教程中部分恢复文件名仍沿用旧写法；产品优先按实际返回的路径读取。

### 需要保留的接入边界

- 多个 Agent 如果共用一个 V8 进程，不能仅靠该进程的系统操作分清每个 Agent。后续可把 worker 作为独立操作系统进程管理；只创建 V8 isolate 或线程不等价。
- 当前插件把参与其主机锁的观测任务串行执行。这个锁不阻止其他系统服务修改全局配置，也不代表已经支持并发全域归因。
- 观测记录不能代替权限控制。Agent 不能修改观测配置、管理 token、进程分组和原始证据。
- 原始记录必须放在回滚范围之外。报告复核通过不等于采集范围完整，也不等于系统恢复成功。
- 当前示例是已有直接执行路径；完整权限监测、产品 Code Mode 适配和 Kata 联合验证需要单独实现与验收。

功能解释见 [观测功能说明](01-system-observability-spec.md)。把执行环境放进虚拟机的方案见 [Kata 部署说明](03-codex-kata-architecture.md)。
