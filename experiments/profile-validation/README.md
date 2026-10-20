# 性能增量的真实验证

本轮结果、收益、开销与尚未覆盖项先看 [验收报告](ACCEPTANCE.md)。机器可读轻量索引在项目 `.output/profile-validation-20261014/iteration-summary-final.json`；它分别指向性能结果、独立重放、校准和VM清理回执，不把这些PASS解释为完整Linux观测。

这不是“跑几条命令看看有无数据”。它用固定 Linux 源码搜索检查三件事：数据能否解释压力、单因素结果复用有没有收益、Observer 和 sampler 各自增加多少成本。

只在专属可丢弃的 QEMU Guest 中运行；不要在物理服务器运行 `guest-cold`。工具不调用模型/API。

## 需要准备什么

Guest 内放置 Python、GNU grep、启用 PSI/BTF/BPF LSM 的内核、cgroup v2 委托，以及可信且 SHA256 固定的 Observer、verifier、system_effects/process_lifecycle BPF 对象、sampler。`artifacts.json` 使用已有 Agent benchmark 的同名字段。`/opt/profile-validation/search/` 包含 runner、analyzer、campaign.py、queries.json、固定版本 `lib/` 语料。

```sh
# 下列命令全部在新建的实验 Guest 内执行。
python3 -B /opt/profile-validation/search/campaign.py \
  --suite matrix --root /opt/profile-validation/search \
  --artifacts /opt/profile-validation/artifacts.json \
  --output /var/lib/profile-validation/search-matrix \
  --repository-version <linux-commit> --repetitions 5 --passes 8

python3 -B /opt/profile-validation/search/campaign.py \
  --suite overhead --root /opt/profile-validation/search \
  --artifacts /opt/profile-validation/artifacts.json \
  --output /var/lib/profile-validation/overhead \
  --repository-version <linux-commit> --repetitions 5 --passes 8
```

`matrix` 在每个重复块里随机轮换冷/热、共享/独立副本和 none/exact-reuse，再随机运行 1/2/4/8 并发。`overhead` 分别使用 100、500、1000 ms 采样间隔，比较相同工作量的 baseline、Observer、Observer+sampler；不启用内核直方图诊断。`diagnostic` 单列 kernel-hist 记录，不混入常态组；该单组记录本身不能算配对增量开销。

需要 50 ms 档位时使用 `--suite overhead --intervals 50`，放到新的输出目录。详细诊断额外提供 `--hist-object /trusted/kernel_hist.bpf.o --hist-sha256 <固定摘要>`；它用一套 ABI2 探针观察根域和 8 个任务域，启用 `sched,syscall,mem,lock,blk,irq` 与线程采样。syscall 显式选择 kprobe，memory 显式选择 kprobe-tracefs；后者需要 Guest 已挂载且有权创建动态 kprobe 的 tracefs。旧 raw-BTF/fentry 的失败资料保留，启动失败不会静默切换后端。

`pressure` 需要预先准备有界的 `pressure-corpus/`，对同样的读取量比较 memory.high=0 与 192 MiB（两组 memory.max 都为 512 MiB）。限制在 worker 初始化完毕后生效；低于准备后的驻留集合会拒绝启动，避免把解释器初始化卡死当作工作集实验。它是静态受限内存校准，不是对实际搜索的因果结论。

## 在哪里看结果

先看输出目录 `validation-campaign.json`：所有跨条件输出必须一致；配对变化小于零表示更快，CI 上界仍小于零才标记 benefit_supported。CI 以独立随机块为单位，不能拿同一轮 8 个 Agent 当 8 个独立重复。所有原始 trial、任务事件、采样、Observer WAL、verifier 及错误日志保留。

每轮 `profile-run.json` 将热路径时长与准备/结束/验证成本分开，并保留 collector 的全生命周期 CPU/RSS。冷缓存只指 Guest，Host/物理存储缓存状态未知。shared-leaf cgroup 资源是全组总量；wait4 的任务 CPU 按进程实例保存。已知不完整的短进程采样、递归漏采等不会因输出一致或 verifier 成功被改成完整。

复制整个实验目录后可以分别独立复算：

```sh
# 检查原始 stdout 字节、版本、退出和清理；不替代审计验证。
python3 -B experiments/profile-validation/replay.py /copied/campaign \
  --output /copied/performance-replay.json

# 只针对真实 Observer 的组，从原始 WAL 重放；固定可信 verifier 摘要。
python3 -B experiments/profile-validation/audit_replay.py \
  /copied/overhead-100-500-1000 /copied/overhead-50 \
  --verifier /trusted/deployment-observe-verify \
  --verifier-sha256 <固定摘要> --output /copied/host-wal-replay
```

两个 PASS 含义不同：第一个是实验输出一致，第二个是绑定与证据重放通过。第二个仍会原样保存 `evidence_status=INCOMPLETE`，不能据此声称所有系统调用、所有 Linux 状态都已完整覆盖。

v8 的两轮非性能诊断复验使用 `run.py --concurrency 1,8 --repetitions 1 --warmups 0`，单列目录，不并入配对开销矩阵。`block_replay.py --help` 给出离线复算入口；它核对保留的 sampler/BPF 摘要、原始 stdout 和重新计算的诊断。block 没有 insert 或未追踪 completion 时保留 UNKNOWN；合法的成功零字节 FLUSH 单独给服务片段。每 CPU 首8个提示样本有明确截断计数，提示截断不等于基础直方图丢失。所有数据都是全系统 block 背景，不直接归给 Agent。
