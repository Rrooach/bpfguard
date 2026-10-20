# 执行阶段关联与真实本地推理实验

这部分回答“搜索、准备模型输入、排队和真正推理，究竟哪一步慢”。它不调用付费模型 API，也不把 `sleep`、矩阵运算或伪造 token 当作推理。

## 组件分别做什么

| 组件 | 作用 |
|---|---|
| `semantic.py` | 上层 runtime 显式声明 Agent、Task、Tool、Request、依赖和开始/完成/失败/取消；资源策略变更带递增的 effective version |
| `local_inference.py` | 两个 Agent 共享一个常驻 llama.cpp 服务；记录接收、排队、实际 admission、首 token、完成；只允许取消尚未进入引擎的请求 |
| `native_events.hpp` + `llama-runtime-hooks.patch` | 对固定版本的真正 llama.cpp 源码做可选插桩，记录实际引擎队列、decode batch 成员、dispatch TID 和实际 GGML worker TID 处理区间 |
| `run.py` | 在实验 Guest 中用 cgroup v2、stopped launch、CPU affinity 运行同量真实搜索、输入准备、g++ 编译和 GGUF 推理 |
| `analyze.py` | 重新读取原始日志验证关联；核对工作量和输出哈希；解释各阶段资源采样；生成配对变化及置信区间 |
| `multibatch_kv_smoke.py` / `verify_multibatch_kv.py` | 独立的真实两 slot/两请求功能校准与 Host 重放；验证多成员 decode 和完成边界的逻辑 KV，不与历史性能矩阵混合 |
| `gpu_adapter.py` | 可选 NVTX 入口、Nsight SQLite kernel/memcpy 显式关联和时钟校准；仅 fixture 验证，当前没有 GPU 硬件 E2E |

runtime 声明不是内核因果证明，不取代原有 Observer WAL、恢复协议或权限监测。共享服务的总 CPU 不按请求数平分给 Agent；同一个线程今天处理 A、随后处理 B，只有明确的处理区间绑定到对应请求。实际 decode batch 的成员由引擎传递，不从 GPU 利用率猜测。

这里用固定工作负载代表两位 Agent 的工具阶段，不启动两个自主决策 Agent。真实 Agent 的接入入口是 `Context` + `Recorder`：创建任务时 `declare()`，工具前后 `begin()/end()`，共享推理时携带唯一 `request_id`。当前是可运行的独立 Linux 接口与实验 adapter，不声称已修改 V8 产品或完成生产 GPU 服务接入。

## 固定真实引擎

- llama.cpp `b4514`，commit `ec7f3ac9ab33e46b136eb5ab6a76c4d81f57c7f1`，CPU backend，两个计算线程、一个 slot。
- 官方 `ggml-org/models-moved` 的 `tinyllamas/stories15M-q4_0.gguf`，revision `499bc8821c6b12b4e53c5bffcb21ec206f212d81`，19,077,344 字节。
- 模型 SHA256：`66967fbece6dbe97886593fdbb73589584927e29119ec31f08090732d1861739`。
- 这是小模型机制验收，不能用它推断生产大模型或 GPU 吞吐。

官方来源：[llama.cpp b4514](https://github.com/ggml-org/llama.cpp/tree/b4514)、[官方 GGUF 模型仓库](https://huggingface.co/ggml-org/models-moved/tree/499bc8821c6b12b4e53c5bffcb21ec206f212d81/tinyllamas)、[Nsight SQLite schema](https://docs.nvidia.com/nsight-systems/AnalysisGuide/)。

## 四组实验

每个 A 都执行相同的“GNU grep 搜索 → 固定 SHA256 输入准备 → 固定 token 数的真实推理”。B 的编译单元、编译选项和推理请求数在 G1/G2/G3 完全相同，编译产物和模型输出必须逐项哈希相同。

| 条件 | CPU 分配 | 目的 |
|---|---|---|
| G0 | A 独立运行，使用四核 | 测 A 无 B 干扰的基线；不拿其总时间与 A+B 总工作量直接比较 |
| G1 | A、B、共享引擎竞争同四核 | 测实际干扰 |
| G2 | A/引擎默认保留两核，B 用另外两核；A 结束后 B 释放到四核 | 静态保留对照；可调保留核数和编译并发，不能仅凭默认配置宣称已调优 |
| G3 | 搜索/准备给 A 一核、B 三核；推理给引擎两核、B 两核；A 结束 B 四核 | 只按已知阶段改变 CPU，不改工作量、不同时偷偷改变请求顺序 |
| G4（另选） | 与 G3 相同，加显式 priority admission | 与 G3 配对区分请求安排的增量；记录 A 到达时是否真的还有 B 请求排队 |

G3 是否比 G2 好是待测假设，不是必须得到的绿色结论。报告同时给 A 延迟、B 吞吐/等待、整体完成时间及随机重复的配对区间。

G3 在 A 搜索/准备时仍允许共享引擎使用两核：B 此时也可能正在推理，不能因为 A 尚未推理就假设共享服务空闲；A 的一核可能与服务重叠，B 仍按三核配置。固定版本的两线程 GGML 若被压到单核，会产生明显同步等待，该配置错误已在正式试验前修正，旧非计时证据保留。

原生插桩有明确档位：未设置 `OBSERVER_NATIVE_EVENTS` 时为 OFF。`LIGHT` 记录五个 request 阶段和“成员集合变化时选中的单次真实 decode 调用”的 BEGIN/END，**不记录中间其他调用或 worker**，不是覆盖整个 membership epoch 的区间。`FORENSIC` 才逐 decode、逐实际 GGML worker 记录。CLI 默认为 LIGHT；`--native-profile FORENSIC` 是显式诊断选择。LIGHT 的 `total_actual_batch_count` 为 `null`，保留 observed/selected count，不能把选中次数当完整 batch 总数。

## 怎么运行

只在独占、合作型的实验 Linux Guest 中执行。需要 cgroup v2 的 cpuset/cpu/memory/io/pids、四个可用 CPU、Python≥3.8、g++、cmake、make；PSI 须启用。不要在物理服务器上运行被测工作负载。

将固定源码归档、模型、这里的源码和 patch 放到 `/opt/profile-validation/inference/`，执行 `bash build-llama-guest.sh`。它检查源码及模型 SHA，拒绝覆盖已有 source/build，产物位于 `build/bin/llama-server`。源码归档下载地址为 `https://codeload.github.com/ggml-org/llama.cpp/tar.gz/ec7f3ac9ab33e46b136eb5ab6a76c4d81f57c7f1`，文件名 `llama-b4514.tar.gz`；模型使用上述固定 revision 下的 GGUF。

```bash
cd /opt/profile-validation/inference
python3 run.py \
  --engine build/bin/llama-server \
  --model stories15M-q4_0.gguf \
  --output /opt/profile-validation/inference/mixed-run-001 \
  --cgroup-parent /sys/fs/cgroup/mixed-run-001 \
  --sampler /path/to/allox-load-sampler \
  --kernel-hist-object /path/to/kernel_hist.bpf.o \
  --kernel-hist-groups sched --native-profile LIGHT \
  --conditions G0,G1,G2,G3 --repetitions 5 --tokens 256
python3 analyze.py /opt/profile-validation/inference/mixed-run-001 \
  --output /opt/profile-validation/inference/mixed-run-001/analysis.json
```

`--kernel-hist-object` 使用已校准的多域 ABI2 object；采样器要支持 `--kernel-hist-cgroup` 和 `--sample-threads`。它只加载一套探针，分别注册 A、B、shared-engine。`analyze.py` 复用 `experiments/search-profile/analyze.py` 的严格 kernel health helper；Guest 将该文件放在相邻的 `/opt/profile-validation/search/analyze.py`，报告保存 helper SHA。

## 去哪里看

- `campaign.json`：固定版本/哈希、机器身份、随机试验顺序和工作量。
- `trial-*/semantic-events.jsonl`：上层 Agent/Task/阶段/request 关联和资源策略版本。
- `trial-*/native-events.jsonl`：真实引擎 request、batch、worker 区间。
- `trial-*/semantic-verdict.json`、`native-verdict.json`：独立重放关联是否有效，不代表 Agent “安全”。
- `trial-*/load/`：原始 system/cgroup/TID/PSI/调度诊断样本和 collector health。
- `trial-*/trial.json`：任务耗时、真实 token 数、每个编译产物及模型输出哈希。
- `analysis.json`：跨组比较和各阶段资源证据。语义完整、资源采样完整、TID polling 完整度分别报告。

资源采样不是原子快照。每阶段同时保存采样边界误差；相邻阶段的 envelope 可能重叠，不能把它们相加为任务耗时。CPU/memory/io PSI 不能相加。TID polling 可能遗漏短命 worker，明确保留 `PARTIAL`/无边界样本，不能填零。原生 worker 区间包含该线程在区间里的等待，不等于纯 on-CPU 时间。GPU parser 需要显式 boot/PID/start/TID 注册映射和三个时钟锚点，未知/缺失/CUDA Graph 不会被猜成已归因。

本地测试：`python3 -m unittest discover -s experiments/execution-profile -p 'test_*.py' -v`。

## 先比较静态配置，再用新一轮重复实验验证

`run.py --static-cpus N --compile-workers M` 分别设置静态保留核数和编译并发。保留核数限 1–3，默认仍为两核／四编译并发，不改变历史配置；全部编译单元和真实推理请求仍必须完成。G3/G4 推理阶段沿用选中的保留核数，搜索／准备阶段仍只给 A 一核。引擎计算线程数保持两个，不能把一核候选误解成也改成单计算线程。

`tune_static.py` 自动执行两段**互不混用计时样本**的实验：先用声明好的候选跑 G2；按预先选择的目标选中配置并冻结文件摘要；随后使用新的随机运行顺序重复 G0/G1/G2/G3/G4。默认目标是总完成时间的中位数，也可以事先选 `--objective a_seconds`。只能称为“所测候选中按该目标最好”，不能称为全局最优。

以下命令只在合作型 Guest 内运行，调度统计必须实际开启。它不修改物理服务器，不调用模型 API，也不测试 GPU：

```bash
sysctl -w kernel.sched_schedstats=1
python3 -B tune_static.py \
  --engine build/bin/llama-server --model stories15M-q4_0.gguf \
  --sampler /path/to/allox-load-sampler \
  --kernel-hist-object /path/to/kernel_hist.bpf.o \
  --output /opt/profile-validation/inference/tuned-new \
  --cgroup-parent /sys/fs/cgroup/tuned-new \
  --candidates 2:2,2:4,3:2,3:4 \
  --tuning-repetitions 2 --evaluation-repetitions 3 \
  --tokens 256 --b-requests 4 --compile-units 8 --functions-per-unit 96 \
  --search-repeats 1 --prepare-rounds 128 --native-profile LIGHT
```

候选 `2:4` 表示 A／引擎保留两核、B 最多四个编译进程。上述最小验收包含 8 次调优、15 次新评估；较少重复的区间可能很宽，不应包装成稳定收益。所有混合组编译产物、真实模型输出和工作量必须相同；G0 只比较 A，不能拿 G0 总时间和 A+B 总时间直接比较。

这里固定使用两个 GGML 计算线程。实跑中把它们同时限制到一核产生明显同步病态，并出现真实请求超时；这一核候选是**已尝试的失败配置**，不是未测，更不能从历史记录中删除。失败目录和异常日志应保留。后续独立 campaign 在运行前声明“至少两核”的候选族，`tune_static.py` 会拒绝一核候选；不能把新 campaign 描述成“一至三核全部通过”。若专门研究超额订阅失败，仍可显式运行 `run.py --static-cpus 1`，但不混入当前候选族的成功结果。

要把 A 的搜索替换成真实 Terminal-Bench 或 SWE-bench 任务的固定源码树，在命令末尾加 `--search-corpus /absolute/fixed-task-source --search-query 'literal'`。所有条件必须查询同一个绝对路径，不允许一组用不同副本路径改变 grep 输出。B 的固定编译与推理工作量不变。这是在真实任务源码上施加可控 CPU 干扰的机制实验，不表示小模型正在自主解该 benchmark，也不替代官方 judge 得分。

外部源码保存独立的 `external-search-inventory.json`，绑定普通文件内容摘要、符号链接本身和 query 摘要；忽略 `.git`，不跟随符号链接。每个 campaign 结束重新检查源码，变化就拒绝声称等量工作。扫描哈希会预热 page cache，因此报告明确标记“不是冷读实验”。`trial.json` 的 `tools.search.queries[]` 保存每次真正 grep 的起止、耗时、返回值和输出摘要；零匹配是合法搜索结果，不当成执行故障。

结果查看 `selection.json` 和 `verdict.json`：后者同时保存 A 延迟、总完成时间、B 编译吞吐、B 总完成时间、B 最大编译排队和最大请求排队，既有绝对变化也有配对百分比。G4 必须真正遇到已排队 B 请求，并按优先级先服务 A；没有这个机会就标为未验收，而不是因为无错误退出就声称优先级有效。G4 仍不抢占正在推理的请求，也不保证比 G2/G3 更快，负收益照常保留。

复制全部原始目录到 Host 后独立重算，不读取已经生成的 verdict 作为结论：

```bash
python3 -B experiments/execution-profile/verify_campaigns.py \
  /copied/tuned-new --tuned-static --output /new/tuned-host-replay.json
```

Host 重放检查冻结选择、未参与选择的评估样本、相同二进制和工作量，以及原始语义／引擎／资源证据。资源缺失仍为 `INCOMPLETE`。这组是固定 CPU 机制实验，不是 Terminal-Bench/SWE-bench 任务得分；真实任务上的搜索／工具观测和开销需要在各自 adapter 中另行验证，不能用这里的加速数字替代。

完成边界的 `logical_kv` 通过固定 b4514 公开 API 获取共享 context 的 used cells、token-sequence associations、context/sequence-ID/batch/microbatch capacity。多个序列可共享一个 cell，因此 association 数不是唯一 token 数；sequence-ID capacity 也不是 server 并发 slot 数。进程 RSS/cgroup memory 仍来自独立 sampler，GPU allocated/reserved/device bytes 无硬件时明确 UNKNOWN。不要把这些维度互相替代，也不宣称得到每请求 KV 分配字节。

独立两 slot 功能校准（仅 Guest，不替换四组性能试验）及 Host 复算：

```bash
python3 multibatch_kv_smoke.py --engine build/bin/llama-server \
  --model stories15M-q4_0.gguf --native-header native_events.hpp \
  --native-patch llama-runtime-hooks.patch \
  --output /opt/profile-validation/inference/multibatch-kv-new \
  --cgroup-parent /sys/fs/cgroup/multibatch-kv-new
python3 experiments/execution-profile/verify_multibatch_kv.py \
  .output/execution-profile/evidence/multibatch-kv-v4-corrected-20261014 \
  --engine-directory .output/execution-profile/engine-v4 \
  --output .output/execution-profile/evidence/multibatch-kv-v4-host-replay-new.json
```

`queue_smoke.py` 在真实引擎运行期间测试“低优先级排队→更新版本→改 admission 顺序”和入引擎前取消；不声称抢占正在 decode 的请求。`engine_overhead.py --native-profile LIGHT|FORENSIC` 对同一个 patched binary 做五次随机顺序 on/off 配对，固定输入/token/输出哈希；这是原生日志增量，不是未插桩引擎或整个 Observer 的总成本。历史详细档约 +31% 和优化后约 +27% 的 tiny CPU 模型成本很高，因此不能默认开启高频 worker 日志；LIGHT 的区间跨零也不能叫“零开销”。实际数值、限制和证据见 [VALIDATION.md](VALIDATION.md)。
