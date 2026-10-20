# 多执行域与线程诊断验证

普通 sampler 默认不加载 eBPF 诊断，也不遍历每个线程。额外能力必须显式启用：

```bash
allox-load-sampler --output-dir ./new-evidence \
  --cgroup /sys/fs/cgroup/experiment/agent-a \
  --cgroup /sys/fs/cgroup/experiment/agent-b \
  --sample-threads \
  --kernel-hist-object ./kernel_hist.bpf.o \
  --kernel-hist-sha256 <该文件的实际SHA256> \
  --kernel-hist-groups sched,syscall \
  --kernel-hist-syscall-backend kprobe
```

同一个 sampler 加载一套选定探针，默认给每个 `--cgroup` 分别累计；最多 16 个域。`--kernel-hist-cgroup` 可选择其中一部分做详细诊断。父 cgroup 包含子 cgroup，因此父子结果不能相加。块设备和 softirq 数据放在独立的 `SYSTEM_UNATTRIBUTED` 槽，不能冒充某个 Agent 的效果。

`--sample-threads` 记录 boot、进程/线程 ID、两者的启动 ticks、CPU 与调度计数。它是有界轮询，不是完整线程生命周期；线程正常退出、采样时消失、身份重用和预算截断分别记录。`--thread-tid` 可选择关键线程，`--max-thread-samples` 限制每轮扫描量。内核调度统计没有开启时，等待计数返回空值并说明原因，不把零当作没有等待。

## 本地只读回归

```bash
cargo test --locked -p allox-load-sampler
cargo clippy --locked -p allox-load-sampler --all-targets -- -D warnings
make kernel-hist-bpf
```

这里不会在物理服务器上创建 cgroup 或加载探针。Native replay 编译并执行实际 BPF 源码中的 block hooks、任务迁组和 syscall 配对函数，检查部分完成、requeue、错误、容量失败、身份变更以及初生子线程返回的处理。

## 真实 Guest 校准

**以下脚本只用于新建、可丢弃的实验 VM，不要在物理服务器运行。** 它创建自己的 cgroup，临时开启 Guest 的 schedstats，并在退出时恢复配置、清理自己的进程和 cgroup。原始证据保留在新的输出目录中。

先准备 release sampler、BPF object 和 C fixture：

```bash
cargo build --locked --release -p allox-load-sampler
make kernel-hist-bpf
cc -std=c11 -O2 -Wall -Wextra -Werror -pthread \
  crates/load-sampler/tests/pthread_calibration.c -o pthread-calibration
```

在 Guest 中运行（实际二进制路径按打包位置填写）：

```bash
python3 guest_multidomain.py --sampler ./allox-load-sampler \
  --object ./kernel_hist.bpf.o --workload ./pthread-calibration \
  --output ./new-calibration --syscall-stress --empty-domains 13
```

该正对照在一个 CPU 上启动 4 个线程，每线程固定执行 100000 次 `getpid`。仅选择 x86-64 syscall 39，避免把启动、输出等其他调用混入真值。检查实际计量次数恰好为 400000、空域为零、父域与子域一致、计量探针无 recursion miss 且无未配对事件。

其他正对照可使用 `--workload-mode fault|lock|reclaim`，搭配对应诊断组和 `--require-metric mem_fault_minor|lock_rwsem|mem_memcg_reclaim`。文件和回收操作仅作用于 fixture 自己创建的文件或 cgroup；不执行全局 drop_caches。它们验证对应路径可观测，不代表每种硬件 I/O、锁类型或内存分配情况都已穷举。

内存详细诊断默认使用 `--kernel-hist-memory-backend kprobe-tracefs`：创建自有 UUID 名字的入口/返回探针，返回探针 `maxactive=1024`，保存 tracefs 原始定义、event ID、目录 inode、起止 profile hits/misses 和采集时间。tracefs 未挂载或不能读写、BTF ABI 不满足时拒绝 READY。显式 `fentry` 是保留旧证据的兼容诊断，在当前内核的高频并发缺页实验中已发现明显丢失。

结束时先关闭自己的 perf handlers，再检查原始定义和身份，最后只删除自己的事件并保存清理回执；不会清空全局 `kprobe_events`。某次返回探针容量不足或 profile 无法读取也必须降低诊断健康，不能仅看 BPF program 的 recursion 计数。动态 kprobe 的 BPF callback 使用内核全局 `prog_array`，只附着一次；跨 CPU fixture 另行校准，不为每个 Agent 复制一套全局探针。

`mem_fault_minor` 保留历史字段名，实际表示 `handle_mm_fault` 完成后没有 `VM_FAULT_MAJOR` 的返回，可能包含 retry/error；它不自动等于 `getrusage` 的成功缺页次数。校准分别保留受控工作量、rusage 真值和 hook 完成次数，不修改原始统计来强求两者相等。

## 如何判断结果

`validation.json` 分开保存功能断言与诊断健康：已知次数/归属正确可以 `PASS`，但发现计量丢失时仍是 `INCOMPLETE`。计量 hook 的 recursion miss 是缺口，不能因 `run_cnt=0` 或未打开全局运行统计就忽略。

`kprobe` 后端在 `trace_syscall_enter/exit` 上计量；两个零 payload 的 raw callback 仅维持内核 syscall dispatcher 的注册。注册 callback 的 misses 单独保留，不等同于计量丢失；计量次数仍必须独立校准。加载前检查两个内核 anchor 的 BTF ABI，失败就拒绝 READY，没有静默降级。`raw-btf` 保留为显式兼容诊断，在当前可抢占 syscall dispatcher 内核上已经观察到丢失，不作为完整性结论。

注册表在 READY 前冻结，选定 cgroup FD 持有至 detach。4096 项 LRU membership cache 按带 generation 的 leaf cgroup ID 缓存正负结果；驱逐或缓存失败只导致重算。每次使用 task storage 都重新核对实际 cgroup，迁组会丢弃跨域未结束区间并计数。进程残留和域变更不是按 PID 或时间接近程度猜测的因果归因。

所有区间可能重叠，不能把 syscall、调度、缺页和锁等待时长相加当作任务 wall time。校准耗时也不是 Observer 的 A/B slowdown；性能实验必须把这个详细诊断档单独计量。

## 块请求边界与零字节 FLUSH

ABI2 的原始 histogram/counter 布局保留。新版本另外保存 `block_diagnostics` 扩展：请求 opcode、原始 `rq_flags`、每 CPU 最多 8 个特殊请求样本，以及零字节 `REQ_OP_FLUSH` 的独立 service histogram。样本容量用尽会保存 `samples_truncated`；这不是完整请求日志。请求地址只输出摘要，也不把同一地址当作不会重用的生命周期身份。

没有 `block_rq_insert` 不意味着 hook 丢了：Linux 的直接发出路径和 FLUSH 可以绕过它。因此排队时长是 `UNKNOWN`，不能补成零；只要观察到完整 issue/completion，数据 service 仍可记录。成功的零字节 FLUSH 另行记录，不混入数据 service。其他零字节请求、读取失败、错误和 requeue 不伪装成完整 service。

`untracked_complete` 仍保留 `UNKNOWN`。它可能涉及开始采集前在途请求、flush sequencing 的再次完成通知或真正的缺口；仅凭 opcode/flags 无法证明是哪一个。旧版本没有这些字段，不能用新样本替旧证据补猜。

在可丢弃 Guest 运行小正对照：

```bash
python3 guest_block.py --sampler ./allox-load-sampler \
  --object ./kernel_hist.bpf.o --output ./new-block-control
```

脚本只向自己创建的文件执行 8 次 32 KiB write 和 8 次 fdatasync，检查内容、FLUSH hook 和采集器计数。块 hook 是全系统范围，不宣称每个请求由这个子进程造成。2026-10-14 的 v8 控制观察到 18 个成功 FLUSH service、18 个未知 queue span、9 个未知 completion；计量 recursion 和请求读取失败均为零。有界样本截断 37 次，原样保留。功能正对照通过并不等于块层总体完整，也不证明掉电后的持久性。

`collect_receipt.py --frozen-version <新目录> --expected-cells <数量>` 可以独立重放新版本。历史源码已经变化时使用 `--source-binding frozen`，只对保留源码和原始数据进行重放，并在回执中明确该模式；不修改旧回执或冒称与当前工作区源码相同。
