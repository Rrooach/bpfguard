# Terminal-Bench：真实任务、Observer 和 PSI

这一组实验使用已有固定版本的 Terminal-Bench 四个任务和 Harbor 0.23.0。
运行位置是新建的目标 Linux QEMU Guest；Docker、Observer、sampler 共享这个 Guest 内核。

实验分两种运行：

- `oracle`：执行官方参考解，并运行官方 verifier。用于确认环境、任务和观测接入正常，不计算模型能力。
- `budget-shell`：把任务说明交给 DeepSeek，由模型调用 shell 工具，最后仍由官方 verifier 判分。模型不读取参考解或测试代码；最多 8 轮请求，费用由全实验共享的预算服务限制。

每个任务在 Harbor 的 Agent 开始/结束钩子上接入已有 Observer bridge。
Observer 保留 syscall/对象事件、生命周期和启用域的边界状态；独立 verifier 检查原始证据。
Sampler 同时采集该容器 cgroup 的 CPU、内存、I/O 和 PSI。模型运行另外记录请求和工具的开始、结束、返回值。
因此可以查看“等待模型多久、执行工具多久、当时容器是否等待 CPU、内存或 I/O”。

准备好 Guest 内的程序、固定任务、Harbor 环境和 `/opt/agent-benchmarks/artifacts.json` 后，例如运行：

```sh
/opt/harbor-venv/bin/python /opt/agent-benchmarks/terminal/run.py \
  --bridge /opt/bpf-observer/bridge.py \
  --bridge-config /opt/agent-benchmarks/artifacts.json \
  --selection /opt/bpf-observer/selected-tasks.json \
  --selection-sha256 0c7ac6d0c450a03d8ff4cca081296cda4964d912c73af76170b1b62ccdd20c20 \
  --tasks-dir /opt/terminal-bench-v4/tasks \
  --task photonic-waveguide-routing --task cargo-flight-dispatch \
  --task bun-sourcemap-leak --task html-js-filter \
  --sampler /opt/bpf-observer/allox-load-sampler \
  --agent oracle --output /opt/agent-benchmarks/results/terminal-control
```

模型测试换成 `--agent budget-shell`，先只保留一个 `--task`，使用新的 output 目录。
预算服务地址是实验配置，不是 DeepSeek 的公网地址。Guest 仅持有预算服务客户端令牌，原始 API key 不进入容器或记录。
真实部署可修改 `budget_agent.py` 中预算服务地址，并维持统一费用上限。

结果位置：

| 文件/目录 | 看什么 |
|---|---|
| `campaign-summary.json` | 实际任务、agent 类型、官方 reward、运行错误和证据状态 |
| `harbor-trials/*/result.json` | Harbor 官方判分和异常 |
| `harbor-trials/*/agent/tool-intervals.json` | 模型请求和实际 shell 调用的耗时 |
| `profiles/<task>/load-samples.jsonl` | 容器与整个 Guest 的资源采样；两者归因范围不同 |
| `evidence/*/observer/` | Observer 原始 WAL、状态快照、差分及 manifest |
| `evidence/*/control/offline-verification.json` | 独立证据 verifier 的结果 |

Sampler READY 在任务实际执行前完成。Agent 结束后保留最后一个采样，再停止采样。
镜像构建、官方 verifier 执行、容器清理均在声明的 Agent 窗口之外。
READY 时核对 boot/run/cgroup 身份和已落盘的首个采样；结束时等待一个时间戳晚于 Agent 结束的实际采样，而不是用固定 sleep 推测其存在。

冷构建若因 registry 或 GitHub 网络失败，可以使用 `--prebuilt-images` 指定已检查的本地 agent/verifier image ID。
程序创建新任务副本，只在 task.toml 加入 Harbor 官方支持的 `docker_image` 设置；原始任务、说明、程序和检查器保持不动。
报告保留原始和执行路径、确切 image ID 及运行配置差异，不能把这个部署选择隐去。
提供的 `prebuilt-images.example.json` 对应本次已预构建的 bun/html 镜像；重新构建后的 image ID 需要重新记录。

模型 HTTP 请求在容器外的受信任 runner 中完成，记录应用层请求时间；Observer 直接观测的是实际执行工具的容器 cgroup。
模型服务内部排队/GPU 时间不在这些记录中，不能从请求往返时间直接推导出来。

本组运行是小规模集成验证。单次任务通过不等于完整 benchmark 分数，单次耗时也不用于宣称 slowdown 或优化收益。
若只有几十毫秒的工具操作，100 ms 采样可能无法解释其中每个步骤；原始边界和这一限制应保留。
Observer 现有生命周期及独占合同限制仍适用，verifier 通过不能改写为“全 Linux 证据完整”。

固定任务来源：[Terminal-Bench 官方仓库](https://github.com/harbor-framework/terminal-bench/tree/v4.0.0)。
Harbor 任务及 agent 接口：[Harbor 官方仓库](https://github.com/harbor-framework/harbor)。

本次成功控制、失败模型样本、采样检查和独立重放见 [VALIDATION.md](VALIDATION.md)。
