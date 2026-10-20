# AgentBench FC OS 实际验证，2026-10-14

已运行 3 个官方 OS 样本，分别执行参考示例控制和真实 DeepSeek agent。
最终这 6 次运行均启用真实 Observer 和 PSI sampler，官方检查器全部通过，独立证据 verifier 全部通过。

| 样本 | 控制/模型官方检查 | 控制/模型 WAL 记录数 | 模型请求数 | 模型执行窗口 | 等待模型请求 |
|---|---|---:|---:|---:|---:|
| CPU 数量，`3/ac.json#0` | 通过 / 通过 | 22 / 22 | 2 | 2.705 s | 2.651 s |
| `.tep` 文件数量，`3/ac.json#2` | 通过 / 通过 | 24 / 24 | 2 | 2.129 s | 2.071 s |
| 加入 PATH，`2/environment.json#4` | 通过 / 通过 | 28 / 438 | 6 | 9.188 s | 8.780 s |

WAL 数量包含 syscall 入口和结果记录，不能直接叫作 syscall 次数。
PATH 修改的文件系统边界差分为 `CHANGED_WITHIN_SCOPE`。
所有采样器正常退出，system/cgroup CPU、memory、I/O PSI 均可读取；首个采样已落盘且身份绑定通过，末个采样位于执行结束之后。

原仓库 revision 为 `d1e4a10db08c87075c78972e48ecc182be03e2d5`。
`local-os/default` 使用原仓库未修改的 Dockerfile 构建，实际 image ID 为 `sha256:9f65c0feb9d7c2156d8512d35265e9e180c7c48ade0158a1dec1e04accb80573`。
Guest 使用 PSI+BTF+BPF LSM 内核、Docker 26.1.5、Python 3.13.5、agentrl-worker 0.4.0；6 vCPU、12 GiB RAM、32 GiB 私有 rootfs。

复制回服务器的结果在：

```text
.output/agent-benchmarks/agentbench-20261014/
  agentbench-audit-control-20261014/
  agentbench-audit-model-20261014/
```

早期 `agentbench-control-20261014` 和 `agentbench-model-20261014` 也保留，其中只有 sampler，没有 Observer 审计。
它们不可混入上表的 6 次审计通过结果。

复制后使用测试时固定的 verifier，在服务器上重新验证了每份 audit。
结果保存在 `.output/agent-benchmarks/terminal-20261014/host-independent-verification.json`，包含本组 6 次以及 Terminal-Bench 的 5 次验证。

研究结论仍有限：这说明小规模 OS benchmark 的执行、归属、采样、审计和检查器接入可用。
没有跑整个 AgentBench、多 Agent 并发或 A/B overhead；这些任务也不能代表大仓库搜索瓶颈。
任务窗口主要花在远程模型请求上，不能据此推断模型服务内部 GPU 排队时间。

当前 Observer lifecycle 证据仍是部分覆盖，独占 actor 合同也没有建立，所以 verifier `verified: true` 时，全域证据仍可能是 `INCOMPLETE/INCONCLUSIVE`。
部分模型窗口中其他 Terminal-Bench Observer 启停改变了 Guest 的全局 BPF 清单，因此报告了 `CHANGED_WITHIN_SCOPE`；该变化没有被归因给本 Agent。
这个例子进一步说明：任务 cgroup 内的直接 syscall 证据与全局状态差分需要分别解释。
