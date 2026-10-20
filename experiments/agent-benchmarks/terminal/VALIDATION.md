# Terminal-Bench 实际验证，2026-10-14

真实 Harbor 0.23.0、Docker 和 PSI Guest 的接入已经运行。最终可用的 Oracle 控制为两个任务，另有真实 DeepSeek agent 的失败样本；失败样本也完整保存并验证了观测证据。

| 运行 | 官方 reward | Agent/评测异常 | Observer 独立验证 |
|---|---:|---|---|
| bun Oracle 控制 | 1.0 | 无 | 通过，556 条 WAL |
| html Oracle 控制 | 1.0 | 无 | 通过，520 条 WAL |
| bun 模型第一次 | 0.0 | 无，模型未解出 | 通过 |
| html 模型第一次 | 未生成 | 模型工具 JSON 被输出长度限制截断 | 通过 |
| html 模型修复后重跑 | 0.0 | 无，模型未解出 | 通过，4,138 条 WAL |

所有这些运行均采集到了 system/cgroup PSI、容器资源和进程信息。
实际检查确认 sampler 的 boot/run/cgroup 绑定与开始/结束采样边界正确。
模型修复后重跑有 324 个采样，read_errors/missed_ticks 均为 0。
执行窗口为 32.265 s，其中 8 次模型请求合计 30.305 s，实际工具调用合计 1.883 s。
1 次被截断的工具 JSON 被拒绝并回报模型，没有执行其中的部分命令。

相同任务的官方参考解通过，说明最终预构建环境与官方检查器可用。
模型结果为 0 必须保留，不可把“Observer 审计验证通过”写成“模型任务成功”。

两份 Oracle 控制使用已经预构建的 agent/verifier 镜像，按 exact image ID 指定。
运行通过新任务副本中的 `docker_image` 设置使用 Harbor 官方预构建路径；说明、问题程序、参考解和检查器不修改。
原始输入仍按固定 v4.0.0 selection 的 source digest 验证。运行报告保留实际副本路径和 image ID；最新运行也记录原始/执行 task.toml 的 SHA-256 与 Harbor checksum。

固定版本为 Terminal-Bench v4.0.0、commit `452bf305c6daa62fc59061d22133a7cbc7c1572e`。
Guest 为独立新建的 6 vCPU/12 GiB/32 GiB QEMU，PSI 内核 SHA-256 为 `fde3b67703baa643d3751340a010111e115566bb3b754caa1b8eff8a2f515201`。
Docker 为 26.1.5、cgroup v2，Python 3.13.5。

原始四任务冷构建尝试也保留：photonic 受到调试时 SIGINT 中断；cargo 的 verifier 构建无法从 GitHub 下载 uv；bun/html 的冷 verifier 构建超时。
其中后三个 Agent 区间的 Observer 验证完成，但四任务 campaign 整体失败。
这些失败没有被改写成成功，也没有删除；通过两个预构建控制避开相同的依赖下载问题。

结果目录：

```text
.output/agent-benchmarks/terminal-20261014/
  terminal-control-20261014/                # 原始冷构建失败尝试
  terminal-prebuilt-bun-control-20261014/   # bun 官方控制通过
  terminal-prebuilt-control-20261014/       # html 官方控制通过
  terminal-model-20261014/                  # 第一次真实模型结果
  terminal-model-retry-20261014/            # JSON 防护后 html 重跑
  *-measurement-check.json                 # 采样绑定与区间检查
  host-independent-verification.json       # 复制后重新运行 verifier
  pinned-artifacts/                        # 本次实际使用的固定程序
```

服务器上的独立重放再次通过上述 5 份闭合 Observer 证据，并同时通过 AgentBench 的 6 份。
本次不构成全量 Terminal-Bench 得分、模型能力通过证明、无观测配对 slowdown 或优化收益实验。
既有 lifecycle/actor 合同限制继续保留；全局 BPF 清单有其他 actor 时，差异没有被直接归因给 Agent。
