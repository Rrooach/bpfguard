# 2026-10-14 执行关联与真实 CPU 推理验证

## 现在做到了什么

不是只记录“CPU 忙”。现在能把一次工具执行拆成搜索、输入准备、推理排队、实际调度、首 token 和完成，并绑定到明确的 Agent/Task/Request。共享服务的 dispatch 与真正 GGML worker 都有进程/TID 实例和处理区间；同一个线程可先后处理不同 Agent，不永久归属其中一位。

固定真实引擎是 llama.cpp b4514 (`ec7f3ac9ab33e46b136eb5ab6a76c4d81f57c7f1`) + 官方 15M `stories15M-q4_0.gguf`。没有付费模型调用，没有伪造 GPU/token。实验只在独立 PSI-enabled QEMU Guest 中运行（6 vCPU/12 GiB；被测工作竞争同四核），没有在物理服务器上运行模型或编译 benchmark。

## 主要结果：低频 LIGHT 的最终矩阵

G0/G1/G2/G3 各 5 次，按固定 seed 随机顺序；16 个相同 g++ 编译单元、2 个 B 推理请求与 A 请求，每请求 256 个真实输出 token。复用旧 campaign 的 immutable assets 原路径，新旧 binary 的 20 个对应试验输入、真实模型输出 token/哈希和编译产物逐项完全一致；不减少 B 工作量。

| 条件 | A 完成时间中位数 | 全部工作完成时间中位数 | A admission 排队中位数 |
|---|---:|---:|---:|
| G0：A 独立运行 | 0.962 s | 0.963 s（工作量不同，不能与 A+B 直接比较） | 0.001 s |
| G1：编译与模型竞争 CPU | 2.978 s | 2.979 s | 1.879 s |
| G2：A/引擎静态保留两核 | 1.574 s | 2.557 s | 0.597 s |
| G3：按 A 已知阶段分配 CPU | 1.792 s | 2.597 s | 0.629 s |

G1→G2 的逐重复配对变化：A **−47.57%**，95% bootstrap 区间 `[−52.20%, −44.45%]`；整体 makespan **−15.50%**，区间 `[−18.66%, −14.17%]`。B 编译吞吐中位配对变化 **−6.78%**，但包括 B 推理在内的 B 总完成时间 **−3.21%**，区间 `[−7.27%, −1.48%]`。不能只展示 A 而隐藏 B 的编译代价。

G2→G3：A 反而慢 **14.38%**；makespan 变化中位 `+1.77%`，区间 `[−3.76%, +4.17%]`，不能声称改进。这个阴性结果保留：A 正在搜索时，共享服务仍在处理 B 的模型请求；只按 A 的阶段安排 CPU，可能与共享服务争抢资源。

这支持一个有限结论：**这个固定 CPU 场景中，编译造成的 CPU 竞争拖慢共享推理与排队；静态保留 CPU 有可复验的端到端收益。** 不支持“GPU 协同调度已验证”，也不等于生产大模型性能结论。

## 原生记录开销：必须分档

相同 patched binary、相同输入/输出/token、5 个随机顺序 on/off 配对；不包括整个 Observer 和未插桩引擎的总成本。

| 版本/档位 | 256 token 的原生事件 | 增量耗时配对中位 | 95% bootstrap 区间 | 用法 |
|---|---:|---:|---:|---|
| 原始 FORENSIC v1 | 1541 | +31.07% | `[+11.19%, +43.92%]` | 原始数据保留，不包装成低开销 |
| 稳定身份缓存后的 FORENSIC v3 | 1541 | +27.25% | `[+22.63%, +29.52%]` | 明显高开销，只显式诊断 |
| LIGHT v3 | 7 | −2.76% | `[−8.65%, +3.76%]` | 区间跨零，只能说本小试验未分辨出增量，不能说“变快/零成本” |

未设置 `OBSERVER_NATIVE_EVENTS` 时日志默认 **OFF**。LIGHT 默认候选只记录五个 request 阶段，外加成员集合变化时选中的**单次真实 `llama_decode()`** 前后两条；这不是覆盖后续 256 次 decode 的 membership epoch。`observed_actual_batch_count` 是所采次数，`total_actual_batch_count=null`，不记录 worker。FORENSIC 才有全量 decode/worker 区间。boot/PID/TID/start 可缓存；cgroup/namespace 每个选定 marker 都重新读取。

## 严格验证情况

- 最终 LIGHT 矩阵 20/20、旧 FORENSIC 矩阵 20/20、sched-only 三域诊断 6/6：Host 独立重放 `VALIDATED_WITH_DECLARED_SCOPE`，无发现问题；各启用 cgroup CPU/memory/I/O PSI 和 metadata/stats/身份/计数回退均检查。
- sched-only 诊断只加载一套探针注册 A/B/shared-engine，相关程序 `recursion_misses=0`。示例 A inference 阶段 shared-engine 完成的 runqueue 累计跨度：G1 约 `1.10–1.35 s`，G2 约 `0.07–0.12 s`。这是采样包围窗口内多线程累计跨度，不是可以与 wall time 相加的百分比。
- procfs TID polling 始终是 `PARTIAL`；短命 worker 未采到就标未解析。高频 FORENSIC 源码 hook 可直接记录其处理区间，但该区间仍包含线程等待，不是纯 on-CPU 成本。
- 30 个新旧开销 trial 和两个真实两 Agent queue control 均在 Host 重放通过。新 binary 的队列实测：`B-running → A-priority → B-queued`；`A-cancelled` 在进入 native 引擎前取消，优先级更新带新 effective version；没有声称抢占正在生成的 B。
- `verify_campaigns.py` 重放 receipt：46 个矩阵/diagnostic trial + 32 个 overhead/queue trial，20 个跨 binary 精确工作/输出匹配，`PASS_WITH_DECLARED_SCOPE`。
- 22 个模块单元测试，包括缺 PSI、read error、计数回退、身份/请求/批次/slot 伪造、优先级版本、DAG、共享线程重叠、LIGHT 覆盖缩减、逻辑 KV 的容量/时钟/RSS 冒充 GPU 拒绝和 GPU clock/correlation/memcpy fixture。

首次 smoke 的 tuple/JSON array 归一化错误、非计时 queue 初始单核同步等待和原始高开销日志均保留，未删除或改写成成功性能试验。最终两线程引擎至少保留两核；没有用降低 B 工作量修补结果。

## 仍不能声称完成的事情

GPU 计算设备不存在；NVTX 入口、Nsight SQLite kernel/memcpy、显式 globalPid/globalTid 实例映射和三点时钟校准只有 fixture 验证，**没有 GPU E2E**。CUDA Graph node、缺表、未知 copyKind、缺显式上下文均返回未支持/未知，不能按 GPU utilization 推测归属。上述 78 个性能/queue trial 使用单 slot，不能借后面的独立两 slot 功能校准宣称这些试验使用了动态多成员 batch。

## 独立 v4 功能补验：两请求真实 batch 与 KV

未改写 v3 binary 或 78 个历史 trial。独立 v4 引擎仅在原有 `ENGINE_COMPLETE` marker 加一次公开 API KV 查询，不增加逐 token 查询，也没有把新旧性能结果混合。

两位显式 Agent/Request 同时向真实 CPU llama.cpp 的两 slot 发起各 32 token 请求。原始源码 batch 成员来自实际 `batch_view.seq_id`；Host 独立重放通过：35 次真实 decode，32 次包含两位请求，70 个实际 GGML worker 处理区间。记录的是多对多成员关系，不把共享 CPU 平分成每位 Agent 的成本。

完成 B/A 时共享 context 的 `used_cells` 和 token-sequence associations 分别是 508/510；capacity 为 1024 cells，batch/microbatch 为 128。这些是固定 b4514 公开 API 返回的**整个 context 逻辑占用**，不是请求分配字节、进程 RSS、GPU 显存或“输入 token + 输出 token”的估算。`llama_n_seq_max()` 在此固定源码返回 KV sequence-ID capacity 1024，不是两个 server slot 数。一次查询约 18.48/33.52 µs，只是该两次边界调用的观察，不是 overhead SLA；KV 全局扫描 API 只在完成边界使用。

首次 smoke 因错误地假设 API sequence capacity 等于 slot 数而失败；保留 `multibatch-kv-v4-20261014/`。校正 API 含义后的独立试验为 `multibatch-kv-v4-corrected-20261014/`，原始/Host 重放都通过。GPU allocation/reserved/device 字节和 KV allocation 字节继续明确 UNKNOWN，不用 RSS 冒充。

v4 binary SHA：`b04757f4ccc497a1dee3eba626e89213d1dc964821b1295e8219e1f58c3f9979`。轻量独立 receipt 为 `evidence/multibatch-kv-v4-host-replay-final.json`，绑定 verifier 源码 SHA 并校验 worker 完整 slot/task 成员；与以前的 `campaign-summary-final.json` 分开保存。历史 78 个 trial 使用新 parser 再次重放仍全部通过，receipt 为 `campaign-validation-v4-parser-worker-binding-78.json`，没有回填旧 KV 数据。

这里没有修改产品 V8 runtime，没有声称接入生产 GPU 服务；runtime/API 关联也不是内核因果证明，不取代 Observer 审计 WAL。共享引擎 cgroup 的总 CPU 不会平均摊给请求。最新 sampler 对 syscall/fault/lock 等的更多校准属于另外的增量，不能把本报告仅通过的 sched-only 当全部子系统已通过。

## 原始证据与复算命令

根目录（未提交二进制/运行数据）：`tools/bpf/bpf-state-observer/.output/execution-profile/`。

- 主要最终结果：`evidence/mixed-light-v3-20261014/analysis-host.json`。
- 所有 campaign 独立复算：`evidence/campaign-validation.json`。
- 最终轻量索引（约20 KiB）：`evidence/campaign-summary-final.json`，绑定详细 `campaign-validation-final.json` 的 SHA；追加更严格 admission/输出内容核验 receipt：`campaign-validation-bound-admission.json`（同样78个通过）。
- 原始完整矩阵：`evidence/mixed-20261014/`；sched 诊断：`evidence/sched-diagnostic-20261014/`。
- 三档开销：`evidence/overhead-20261014/`、`overhead-light-v3-20261014/`、`overhead-forensic-v3-20261014/`。
- 新旧 queue：`evidence/queue2-20261014/`、`queue-v3-20261014/`。
- 原 binary SHA：`81147b30815479709c0f45a92ee1304696fc551a04d2137d08412b4b6eb142f6`，保存在 `engine-v1/`。
- 最终 binary SHA：`0620622aa4f91499dfc3b725b9a02b3524f5cbb0f2b69f08bb7913928f13c84f`，保存在 `engine-v3/`。
- 模型 SHA：`66967fbece6dbe97886593fdbb73589584927e29119ec31f08090732d1861739`，固定源码归档和模型亦保留。

```bash
python3 experiments/execution-profile/verify_campaigns.py \
  .output/execution-profile/evidence \
  --output .output/execution-profile/replay-new.json
python3 -m unittest discover -s experiments/execution-profile -p 'test_*.py' -v
```

不同档位/版本的性能数值分开报告，不 pool。所有源 marker 和采样时间均为同一 Guest 的 CLOCK_MONOTONIC；GPU 跨时钟必须另做有界校准，本机没有该硬件结果。
