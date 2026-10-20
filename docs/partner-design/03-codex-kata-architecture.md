# Kata 部署说明

这份文档说明：把 Agent 的执行环境放进 Kata 虚拟机后，Allox 和 Observer 放在哪里、按什么顺序启动、产品怎样提交任务和取回报告。

先区分当前能力和目标方案：Allox + Observer 已有直接执行的接入基础，但完整的 Kata 部署、跨虚拟机通信和两侧联合观测仍需接入验证。本文是部署设计，不是一套已经验证完成的一键安装教程。

第一步可以先按 [Allox + Observer 接入说明](02-code-mode-integration-contract.md) 跑通命令工具，再把同样的执行能力放进 Kata。

## 1 为什么还需要 Kata

Allox 管工作目录和任务执行，Observer 管记录和检查，但它们本身不是独立虚拟机。

Kata 增加一层虚拟机边界，让任务运行在自己的 Guest Linux 中，而不是直接共享宿主 Linux 内核。这能增加隔离，但不能承诺绝对不会影响宿主机；开放的目录、设备、网络和管理接口仍需要限制。[Kata 官方架构](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)

本文只用两个位置名称：

- Host：运行 Kata 的目标 Linux。
- Guest：Kata 虚拟机内部的 Linux。

## 2 各组件放在哪里

下面是建议的部署位置，不表示这些连接已经全部实现：

```text
Host 目标 Linux
├── 产品后端                 提交任务和展示报告
├── Kata 运行组件             创建和关闭虚拟机
├── Host Observer            检查虚拟机对 Host 的影响
├── 报告存储                  在虚拟机关闭后保留记录
└── Kata 虚拟机
    └── Guest Linux
        ├── kata-agent        Kata 自带的管理组件
        ├── Allox             管理工作区和工具执行
        ├── Observer          由 Allox 插件按任务启动
        ├── V8 worker 和工具   执行 Agent 的本地任务
        └── Btrfs 工作盘        保存会话文件和检查点
```

这里的 kata-agent 是 Kata 的系统组件，不是调用模型、执行业务任务的 AI Agent。它的职责是管理虚拟机里的容器。[Kata 组件说明](https://github.com/kata-containers/kata-containers/blob/main/docs/design/architecture/README.md)

Allox 和 Observer 作为受保护的 Guest 服务和程序部署，不放进 Agent 可以任意改写的工作目录。任务只能得到所需的工作目录和权限。

产品的模型调用、调度和鉴权可以留在 Host。要隔离的本地文件、网络和命令执行必须真正进入 Guest；只把 shell 放进去，不能自动隔离仍在 Host 执行的 V8 回调。

## 3 为什么虚拟机内外都可能需要 Observer

两个 Observer 回答的是不同问题：

| 位置 | 回答的问题 | 看不到什么 |
|---|---|---|
| Guest Observer | Agent 在虚拟机里做了哪些操作，留下哪些变化 | 不能证明 Host 没受影响 |
| Host Observer | 虚拟机进程和已纳入范围的后端，对目标 Linux 做了什么 | 看不到 Guest 内每一次文件写入或程序执行 |

如果研究问题是“Agent 有没有影响目标 Linux”，重点看 Host 报告。Guest 报告用于了解任务内部发生了什么，不能拿它代替 Host 检查。

在 Guest 内，工具和 Observer 使用同一个 Guest 内核，因此可复用已有直接执行路径的思路。但创建虚拟机、关联两侧任务和回传报告仍需要新增接入。

## 4 启动之前准备哪些东西

部署需要准备四类材料：

| 材料 | 具体用途 |
|---|---|
| Host 的 Kata 运行环境 | 创建虚拟机，限制 CPU、内存、磁盘、网络和设备 |
| 定制 Guest 内核和系统镜像 | 运行 Allox、Bubblewrap 和所选 eBPF 采集功能 |
| Guest 内的 Btrfs 工作盘 | 支持 Allox 创建文件检查点和恢复会话 |
| 管理连接和报告存储 | 产品能提交任务，报告能在关闭虚拟机前传出来 |

默认 Kata 镜像不能直接假定具备所有 Observer 能力。需要实际检查 Linux 进程分组管理（cgroup v2）、内核类型信息（BTF）、所选 BPF 程序和对象解析功能；缺少必需能力时，不放行任务并给出原因。Kata 提供定制 Guest 内核的构建说明。[Kata 内核构建](https://github.com/kata-containers/kata-containers/blob/main/tools/packaging/kernel/README.md)

Allox 的工作区需要 Guest 内的 Btrfs 子卷操作，不能用普通 Host 共享目录替代这个工作盘。现有约定路径为 `/var/lib/allox/workspaces`，详见 [Allox 部署要求](../../../../../../allox-os-observer-plugin/deploy/README.md)。

记录目录放在任务不能修改、会话回滚不会删除的位置。生产部署还应把记录回传 Host，不能只保存在即将销毁的虚拟机里。

## 5 按什么顺序启动

下面是需要落地的启动顺序。已有命令会标出名称，尚未实现的连接不会写成可以直接复制的命令。

### 第一步 Host 创建虚拟机

部署层为 Kata 指定固定版本的内核、系统镜像、工作盘和资源配置，然后创建 Guest。

初期建议把不互信的任务来源放进不同虚拟机。需要比较 Guest 全局系统状态时，同一 Guest 内先一次只运行一个受测任务；即便如此，也要注意其他系统服务可能修改配置。

### 第二步 Guest 准备 Allox

Guest 的开机初始化完成工作盘挂载，然后先运行 `allox-guest-bootstrap`，准备 Allox 所需的进程管理目录和能力；再启动配置好 system-effects 插件的 `allox-workspace-daemon`。

这两个名称来自已有 Allox 命令入口。具体参数沿用 [插件中文教程](../../../../../../allox-os-observer-plugin/plugins/system-effects/README.zh-CN.md)，镜像构建和开机服务配置需要在 Kata 环境中接入验证。

### 第三步 接通产品到 Allox 的管理连接

产品后端通过经过认证的连接访问 Guest Allox。连接建立后，先检查服务、工作盘和任务配置是否可用，再接受用户任务。

这个跨虚拟机连接仍是需要实现的部分，不是 Kata 启动后就会自动出现。

### 第四步 提交任务并启动观测

产品调用 Allox 的 `process.start`。插件启动 Observer，等待它完成所需检查和执行前记录，再允许命令开始执行。

因此当前接法不是“开机时手动挂一次 eBPF，以后所有任务自动被记录”。Observer 的启动与一次受管理执行绑定。

### 第五步 取回结果 再关闭环境

任务结束后，Allox 和 Observer 完成执行后检查及报告复核。产品读取结果，并把需要保留的记录传到 Host。

如需恢复实验，在提交任务时就启用 recovery，插件会在收尾时完成文件回滚和恢复后检查。关闭 Guest 前，应先完成正常情况下的报告回传；异常关闭时明确记录哪些证据没能取得。

## 6 产品怎样连进去

已有 Allox 接口是 HTTP 的 `POST /v1/rpc`。本地教程使用 `127.0.0.1:8092`，但 Guest 的这个地址只指 Guest 自己，不是 Host 上的 Allox 地址。

建议增加一个受保护的管理转发层：

```text
产品后端
  → 检查用户和任务权限
  → 经过认证的 Host 与 Guest 连接
  → Guest 内的转发服务
  → 本机 Allox HTTP 接口
```

连接可采用受控网络或 vsock。vsock 可以理解为宿主机与虚拟机之间的一条通信通道，但有通道不等于有鉴权；还需要校验连接的是哪台虚拟机、哪个任务，以及请求是否来自可信管理服务。

该转发层、认证和报告回传都是待接入组件。当前 Allox HTTP 接口不能直接当成已有的 vsock 服务。

任务提交后仍使用第二篇文档中的 `agent.create`、`session.create`、`process.start` 和 `process.get`。产品另外保存“业务任务对应哪台虚拟机、哪次 Allox 执行”，避免多个 Guest 的报告混在一起。

报告读取同样需要权限检查。Agent 不应获得管理 token，也不能任意读取其他任务的证据文件。

## 7 回滚和关闭虚拟机有什么区别

Allox 回滚文件，解决的是“这个工作区能否恢复”。

关闭虚拟机，解决的是“终止这个 Guest 的运行”。它们不是同一件事：

- 文件回滚不会恢复 V8 内存、已建立的网络连接和远端服务。
- 仅替换工作目录，旧进程仍可能通过已打开的文件继续使用旧目录。因此恢复前要处理任务进程，恢复后重新启动 worker。
- 关闭虚拟机不会撤销已经写到 Host 持久存储或远端 API 的效果。
- 虚拟机关闭后，还要检查相关进程、网络接口、磁盘和进程分组是否按策略回收。

遇到恢复失败或证据不足时，先暂停该会话的新任务并保留报告。怀疑 Guest 已受损时，由 Host 按策略终止环境，不能仅凭 Guest 自报“恢复成功”就继续复用。

## 8 第一轮部署怎样验收

先跑少量简单任务，不从并发和全量功能开始。

| 验收步骤 | 应该看到什么 |
|---|---|
| 启动一个 Guest | Allox 可用，工作盘可用，必需观测能力检查通过 |
| 通过产品创建 effect.txt | 能找到正确执行编号、命令结果和 Guest 文件变化 |
| 做一次文件恢复实验 | 有执行前、执行后、恢复后三次记录，实际结论被正确展示 |
| 加入 Host 观测 | Host 与 Guest 报告分开，且关联到同一台虚拟机 |
| 模拟取消或采集失败 | 不把缺失结果当成功，已有记录仍可查询 |
| 关闭虚拟机 | 记录已经保存，并检查运行资源是否残留 |

先验证 Guest 内功能，再接 Host 观测和故障处理。完整 Kata 联合测试通过之前，已有 QEMU + Allox 直接执行测试不能替代这份验收。

开销分开测：Kata 自身增加多少、Guest Observer 增加多少、Host Observer 和记录回传增加多少。所有比较使用相同任务和相同资源配置，不给未经测试的性能承诺。

## 9 目前能复用什么 还要补什么

| 部分 | 当前状态 |
|---|---|
| Allox 工作区和任务管理 | 可以复用 |
| system-effects 插件的直接执行和恢复检查 | 已有接入基础，可作为 Guest 内适配起点 |
| Observer 的 Kata Host 身份发现 | 已有代码，不等于完成真实 Kata 联合验证 |
| 定制镜像和开机服务的 Observer 配置 | 需要在选定 Kata 环境中部署和验证 |
| 产品到 Guest 的认证连接和报告回传 | 需要接入 |
| Host 与 Guest 任务关联及完整验收 | 需要接入和测试 |
| 完整动态权限监测 | 仍在扩展，不作为本轮已有功能 |

## 附录 部署实现时注意

### 实验环境的层次

实验中可能在一台 QEMU 虚拟机里再运行 Kata：

```text
物理服务器
└── 实验 QEMU
    └── 目标 Linux 即 Kata Host
        └── Kata Guest
            └── Allox 和 Agent 工具
```

外层 QEMU 是实验环境，不是这里要研究的 Agent 观测对象。目标 Linux 与 Kata Guest 的报告必须分别标明位置。

采用嵌套 KVM 加速路径时，需要检查物理平台和外层 VM 是否开放相应虚拟化能力。若只能使用仿真运行，测试结果不能作为硬件加速部署的性能数据。安装条件按选定版本的 [Kata 安装说明](https://github.com/kata-containers/kata-containers/blob/main/docs/install/README.md) 检查。

### 不要让两个组件同时管理同一任务

Kata 负责虚拟机和其容器生命周期；本方案让 Allox 管理被明确交给它的工具执行。部署层需确定进程由谁创建、谁停止、谁回收。

把 Allox 放入受保护的 Guest 系统镜像，与在一个普通应用容器里安装 Allox 不是同一回事。也不能通过给应用容器加 privileged，就假定工作盘、观测能力和管理权限都已经正确配置。

### 身份和可信度

记录至少要分清虚拟机编号、Linux 启动身份和 Allox 执行编号。虚拟机重启后重新建立对应关系，不能把重启前后的状态拼成一次完整恢复检查。

Host 与 Guest 的进程编号和时钟各自独立。共享网络服务等组件的变化也不能仅按发生时间归到某个 Agent。

认证、摘要和 Host 保存可以保护传输和记录，但不能让已被攻破的 Guest 内核重新变成可信采集源。网络访问限制、管理接口保护和任务权限需要由部署层执行，Observer 负责记录，不替代这些控制。

具体观测结果见 [观测功能说明](01-system-observability-spec.md)，已有 RPC 和结果读取方法见 [Allox + Observer 接入说明](02-code-mode-integration-contract.md)。
