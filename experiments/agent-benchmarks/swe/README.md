# SWE-bench Verified 的真实任务试跑

这里用一个真实的代码修复任务检查：模型执行搜索、修改和测试时，能否将
工具阶段对应到目标 Linux 中的 Docker 进程、cgroup、Observer 事件和资源采样。

预先选择 `psf__requests-1142`：修复 Requests 自动为 GET 请求添加
`Content-Length` 的问题。任务来自官方 `princeton-nlp/SWE-bench_Verified`
的 test split。正式评测仍由官方 SWE-bench `3.0.17` 的 `run_instance`
执行，源码固定到 `3f01bd622c0a22c00406139f69a234ef08225f22`。

一次运行分为三段：

1. **参考补丁对照**：官方 harness 应用官方补丁并运行该任务的官方测试，
   检查环境和评测路径是否能工作。
2. **真实 Agent 尝试**：模型只看到 issue，使用一个有步骤上限的 shell
   Agent 在原始仓库中搜索、修改和测试；不会得到参考补丁或新增测试补丁。
3. **Agent 补丁评测**：提取 Agent 的 diff，放入一个新容器，由相同官方
   harness 测试它。没有产生补丁会明确记录失败，不伪造测试通过。

每段容器都先启动为 idle，随后暂停并绑定完整 Docker ID、PID + 启动时间、
cgroup、boot ID、mount/net namespace。Observer 和 sampler READY 后再恢复
执行；执行结束后再次暂停、采集端点并独立验证，然后才销毁容器。
模型请求本身运行在协调器中，记录的是应用请求关联；不会把协调器的网络
syscall 冒充为容器内 syscall。
本次模型通过远端 DeepSeek API 调用。请求区间包含网络与服务端处理，
不能用它分解本地 GPU 排队或推理时间；编译与本地模型混合负载仍需单独实验。

这是 **1 个任务的接入试验**，不是全部 500 个任务的通过率评测，也不是
并发性能优化对照。参考补丁成功不能算作 Agent 解题成功。

## 准备任务

这一步只下载一个官方任务和约 0.7 MB 的固定 harness 源码，不调用模型：

```sh
python3 experiments/agent-benchmarks/swe/prepare.py \
  --output-dir .output/agent-benchmarks/swe-inputs-new
```

保留 `dataset-response.json`、`task.json` 和 `provenance.json`。
后者记录官方来源、下载字节摘要、任务和 harness 版本。数据服务器行内容
与读取前后的稳定数据集 revision 一起保存，不把服务器缓存响应说成 Git
revision 的密码学认证证明。

## 在目标 Linux Guest 中安装

需要 root、Python 3.10+、Docker、启用了 BTF/BPF LSM/cgroup v2 的目标内核，
以及已经构建的 Observer、verifier、sampler、两个 BPF 对象和 ip/tc/nft。
在本试验中使用新建的 QEMU Guest，所有 Docker 操作均在 Guest 内进行。

将 inputs、adapter 和现有 `experiments/terminal-bench/bridge.py` 复制进 Guest。
在新的 venv 中安装准备好的官方源码 archive；保存 pip freeze：

```sh
python3 -m venv /opt/swe-venv
/opt/swe-venv/bin/pip install /opt/agent-benchmarks/swe-inputs/harness.tar.gz
/opt/swe-venv/bin/pip freeze > /var/tmp/swe-pip-freeze.txt
```

只拉取一个任务镜像。首次拉取前会读取 Docker Hub 的公开 manifest，
拒绝超过 4 GiB 的压缩层下载；拉取后保存实际 image ID 和 registry digest。
宿主机无需启动 Docker。

若 Guest 无法连接 registry，可在 Host 用 `export_image.py` 下载 Docker archive，
再通过 SSH 复制进 Guest 执行 `docker load`。它使用固定版本的官方 `crane`，
先检查 manifest、固定 digest，并限制压缩下载和 archive 大小。文件旁的
`.tar.json` 保存 registry manifest、image config 和 archive 摘要。运行时增加
`--image-import-provenance /opt/agent-benchmarks/swe-image-requests-1142.tar.json`；
adapter 会核对实际 Docker image ID，拒绝来源不明的本地导入镜像。

## 启动

`artifacts.json` 由实验部署阶段生成，包含可信组件的 Guest 绝对路径和
事先记录的 SHA-256。字段是 `observer_binary/observer_sha256`、
`verifier_binary/verifier_sha256`、`sampler_binary/sampler_sha256`、
`recorder_object/recorder_sha256`、`lifecycle_object/lifecycle_sha256`，以及
`ip`、`tc`、`nft` 各自的 `_binary` 和 `_sha256`。

```sh
/opt/swe-venv/bin/python /opt/agent-benchmarks/swe/run.py \
  --inputs /opt/agent-benchmarks/swe-inputs \
  --output-dir /var/lib/observer-benchmarks/swe-new \
  --artifacts /opt/agent-benchmarks/artifacts.json \
  --bridge /opt/agent-benchmarks/terminal-bridge.py \
  --model-base-url http://10.0.2.2:10090/v1 \
  --broker-token-file /opt/agent-benchmarks/private/model-broker-token \
  --model deepseek-flash --steps 12 --tool-timeout 60 --test-timeout 300
```

模型请求必须经过具有共同预算上限的 broker，Guest 只持有 broker 专用
临时凭据，provider API key 留在 Host。省略 `--model-base-url` 只运行参考
补丁对照，此时结果明确标为未运行模型。

## 看结果

先读 `benchmark-summary.json`，再查看各段的文件：

| 文件 | 作用 |
|---|---|
| `gold-control/official-result.json` | 环境与官方参考补丁对照结果 |
| `agent-attempt/agent-transcript.json` | 模型每步命令、输出、usage |
| `agent-attempt/agent.patch` | Agent 实际生成的补丁 |
| `agent-evaluation/official-result.json` | 官方测试对 Agent 补丁的判定 |
| 各段 `observation/phase-events.jsonl` | 工具、模型请求、测试的开始结束 |
| 各段 `observation/target.json` | 本段完整容器与进程/cgroup/namespace 身份 |
| 各段 `observation/load/` | 原始资源与 PSI 采样 |
| 各段 `observation/observer/` | 系统效果事件、快照与 manifest |
| 各段 `observation/verification.json` | 独立 verifier 的结果 |

系统效果默认使用 `balanced` profile，资源采样为 100 ms。短命命令可能在
两次进程采样之间结束；阶段时间仍保留，但不能据此伪造逐命令 CPU/等待
分解。原有 Observer 的生命周期完整度与各状态域结论原样保留。

## 本地检查

```sh
python3 -B experiments/agent-benchmarks/swe/test_swe.py
```

上述检查覆盖任务身份、官方数据集绑定、模型响应解析和协议超时等失败
情况。真实 Docker/内核验证结果保存在独立 campaign 目录中。

本轮已经完成真实模型尝试和官方评测，见 [实际验证记录](VALIDATION.md)。

官方参考：[SWE-bench harness](https://www.swebench.com/SWE-bench/reference/harness/)、
[固定源码](https://github.com/SWE-bench/SWE-bench/tree/3f01bd622c0a22c00406139f69a234ef08225f22)、
[Verified 数据集](https://huggingface.co/datasets/princeton-nlp/SWE-bench_Verified)。
