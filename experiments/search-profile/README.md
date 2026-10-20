# 多 Agent 并发搜索：任务级性能实验

这部分回答：**同样的搜索工作，并发执行时慢在哪里？减少同时搜索的数量，全部任务会不会更早完成？**

用固定的 GNU grep 命令代表 Agent 的搜索工具调用，不调用大模型、不消耗 API token。性能数据复用 `allox-load-sampler`。`observer` / `observer-sampler` 模式另外启动真实 Observer 并独立验证 WAL；原有审计、状态快照和回滚协议不改写。

新增的逐次读取、文件缺页与 2／4／6／8 并发实验见[专门说明](FILE_ACCESS_2468.md)。下文已有的 1／2／4／8 实验是历史 campaign，不能把新六并发样本直接拼进旧表。

离线批处理使用 `--resume` 后，失败轮次的新结果可能位于 `analyses/retries/`。此时汇总时使用 `access_comparison.py --matrix MAIN/matrix.json --file-analysis-receipt analyses/attempt-UUID.json --output-dir NEW_REPORT`，不要只按旧目录名找结果。报告按照该终态回执的逐轮路径取 `summary.json`，核对其 SHA256、run、profile 和 capture；回执本身的 SHA256 也保留在报告中，可用 `--expected-file-analysis-receipt-sha256 HEX` 额外固定。该选项与 `--file-analysis-root` 互斥；缺失、失败和 `INCOMPLETE` 均原样保留，不自动回退到旧结果。

## 大仓库墙钟实验入口

`large_search.py` 专门用于“存储加载、文件遍历、匹配 CPU、内存压力，究竟哪个限制了整批搜索”的实验，不运行模型，也不调整推理请求优先级。

主指标只有一个：**同一批固定搜索任务，从统一放行到全部退出，共花多少秒**。累计 user/system CPU、逐查询延迟、CPU/memory/I/O PSI、逐设备读取、refault 和回收量用于解释，不能相加成墙钟时间分账。

先由 `prepare_large_corpus.py` 从固定 Git commit 导出 tracked 普通文件，排除并记录符号链接／子模块，不把工作区改动、`.git` 或构建产物混进来。再在独占 Guest 内准备共享只读仓库和八份内容、权限相同但 inode 不同的副本。

本轮输入为 Linux `519a81750493f6fb35ee282ba3ff5bafdd58b81b` 的 95,989 个普通文件，共 1,641,397,655 字节。固定八个任务，每个执行一次固定查询（四种查询各由两个任务执行）；固定四个 workload CPU，协调器和 sampler 使用另外两个 Guest CPU。比较冷／热 × 共享／独立 × 并发 1/2/4/8，正式五个随机重复块。

缓存顺序为：准备并核对文件内容／权限 → 固定文件身份 → 建立冷／热数据页条件 → 非触页 `mincore` 检查 → 立即放行 → 全任务退出 → 保存证明和校验结果。完整内容复核在整个 campaign 之后，证明压缩和 hash 不插在缓存检查与放行之间。

注意：`mincore` 检查本身会遍历 metadata，所以这里是 **data-cold / metadata-probed**，不是目录项、inode 或物理 SSD 全冷；Guest 冷不等于 Host 冷。warm 预读在 workload cgroup 外首次触碰，cold 则在内部首次读，不能直接拿两者的 `memory.file/current` 比较全部工作集。每轮保存真实驻留量、采样边界误差和这项限制。

Guest 内示例（固定输入已复制到 `/opt/large-search`）：

```sh
python3 -B /opt/large-search/runtime/large_search.py \
  --corpus /opt/large-search/corpus \
  --source-manifest /opt/large-search/inputs/source.json \
  --prepared /opt/large-search/prepared --prepare-only

python3 -B /opt/large-search/runtime/large_search.py \
  --corpus /opt/large-search/corpus \
  --source-manifest /opt/large-search/inputs/source.json \
  --prepared /opt/large-search/prepared \
  --queries /opt/large-search/runtime/queries.large.json \
  --sampler /opt/large-search/runtime/allox-load-sampler \
  --output /opt/large-search/results/matrix-new \
  --concurrency 1,2,4,8 --repetitions 5

python3 -B /opt/large-search/runtime/wallclock_report.py \
  --matrix /opt/large-search/results/matrix-new/matrix.json \
  --output-dir /opt/large-search/results/report-new
```

当前大仓库入口只用于其专用 QEMU 实验 Guest：它显式对 `/dev/vda` 数据盘和 `/dev/sda` 系统盘做计时前 4 KiB 只读 direct-I/O，以建立真实 `io.stat` 前值；不能把这两个设备名照抄到其他环境。准备目录、结果目录必须新建，数据盘应有足够空间，普通语料大小与数量仍有边界。准备阶段创建只读 bind mounts，随实验 VM 生命周期管理。

报告输出 `wallclock.md` 和 `wallclock.json`。热点诊断另用 `diagnose.py`，不能与正式轮混算：它按相同查询运行 perf 或单独的文件 profiler，未知符号和缺失计数不猜测；有 `--reference-campaign` 时还核对正式轮的原始输出。复用干预可用 `--intervention paired`，会把 none/reuse 交错放进相同随机块；它只是可消除重复工作的候选上界，不直接称为文件系统创新。

### 本轮实测结果：先回答究竟卡在哪里

80 轮主实验已完成：16 种条件，每种五次。下面全部是**同一批八个搜索任务全部完成的墙钟秒数，中位数**，不是累计 CPU 秒数。正式计时只启用资源 sampler；perf 热点／阻塞栈另跑六个诊断窗口，不混入下表，也不宣称这是完整 Observer 审计或 Observer 开销测试。

| 数据缓存／文件布局 | 并发 1 | 并发 2 | 并发 4 | 并发 8 |
|---|---:|---:|---:|---:|
| 热缓存，共享仓库 | 6.006 | 3.190 | 1.636 | 1.581 |
| 热缓存，独立副本 | 5.932 | 3.102 | 1.589 | 1.650 |
| Guest 数据冷缓存，共享仓库 | 10.769 | 8.225 | 7.124 | 7.248 |
| Guest 数据冷缓存，独立副本 | 39.228 | 22.358 | 11.926 | 7.242 |

当前能支持的解释是：

- **热缓存主要是 CPU 侧重复工作。** 并发八时接近用满给定的四个 CPU，两块 Guest 设备读取量均为零。单独的 CPU 采样中，匹配约占 32%，内核读／拷贝约 28%，路径打开／属性／关闭约 20%，目录遍历约 6%，另约 14% 未解析。这些是被观测 CPU 样本的分类，绝不能改写成“1.58 秒中的各项耗时”。因此也不是只有字符串匹配需要优化。
- **冷缓存增加了读取与页面就绪等待。** 并发八、共享仓库的 I/O PSI some 中位数约 5.32 秒；单独的阻塞诊断在真实 grep 栈中观察到 `filemap_read → filemap_get_pages → folio_wait_bit_common → io_schedule`。这证明读路径会阻塞，不证明物理 SSD 带宽已满，也没有把阻塞次数换算为等待秒数。独立副本读取量约为共享的八倍，并发八时总耗时却接近，不能用单一“读了多少 GB／磁盘带宽”解释全部现象。
- **本轮没有内存容量不足的证据。** 内存 PSI、file refault、回收扫描／回收页、high/max/OOM 事件均未增加。但 Guest 硬件 PMU 校准失败，cycles/instructions/cache-miss 等计数不可用，所以 CPU cache 争用和内存带宽瓶颈仍未判定，不能说“已经排除一切内存问题”。

最小干预另做 20 轮：只在共享仓库、并发八时复用完全相同的查询结果，none/reuse 在五个块中交错随机运行。首次扫描仍在计时内，八个任务输出全部相同；记录的实际扫描从八次变四次。

| 八个任务全部完成，中位数 n=5 | 不复用 | 复用 |
|---|---:|---:|
| 热缓存 | 1.622 秒 | 0.851 秒 |
| Guest 数据冷缓存 | 7.174 秒 | 6.072 秒 |

这支持“完全重复的扫描值得合并”，不代表真实 Agent 总有一半查询重复，也未实现跨版本／跨权限的生产缓存。并发上限同样不能一刀切：热缓存四并发已接近八并发，冷缓存独立副本则八并发明显更快。

原始证据和可复算报告位于 `../../.output/large-search-wallclock-20261015/`：

- [主实验秒数、逐次查询与资源报告](../../.output/large-search-wallclock-20261015/main-report-002/wallclock.md)，机器数据为同目录 `wallclock.json`。
- [重复查询复用对照](../../.output/large-search-wallclock-20261015/reuse-report-002/wallclock.md)。独立核对主实验与复用对照共 800 个 stdout，逐查询结果一致，见 `reuse-verification-001.json`。
- [热缓存 CPU 栈分析](../../.output/large-search-wallclock-20261015/warm-callchains-001.json)、[冷缓存阻塞栈分析](../../.output/large-search-wallclock-20261015/blocked-stacks-001.json)。`analyze_blocked_stacks.py` 只解析专用 D-state 导出，并按整数纳秒裁切实际执行窗口；窗口外 dd/Python 预热记录排除，窗口内 launcher 单列。
- `final-export-001/` 保留原始 trial、实际执行版本、配置和诊断；`main-verification-001.json` 独立检查 80 个 run 的顺序、身份、原始任务／查询区间和 stdout。核验通过不等于内核传感器可信或全部接口观测完整。

保留的缺口：主实验一轮 sampler 漏了一个 tick，资源完整度仍为不完整，但墙钟／输出保留；80 轮中有一个块跨越用户暂停，排除整个跨暂停块的 64 轮敏感性结果与主结论一致。缓存证明在 Host 侧只核对摘要与 gzip 哈希，没有逐文件独立重建；顺序 mincore 检查也不是原子快照。数据冷不等于目录 metadata 冷，更不等于 Host／SSD 冷。本轮没有 Observer 开／关配对，不能由此报告 Observer slowdown；也不使用旧的编译／推理实验成绩替代本结果。

从项目根目录离线重算（所有输出路径都使用新名字，不覆盖原始结果）：

```sh
python3 -B experiments/search-profile/wallclock_report.py \
  --matrix .output/large-search-wallclock-20261015/final-export-001/matrix-all-001.json \
  --output-dir /var/tmp/large-search-wallclock-replay-new

python3 -B experiments/search-profile/analyze_blocked_stacks.py \
  --diagnosis .output/large-search-wallclock-20261015/final-export-001/perf-blocked-001 \
  --output /var/tmp/large-search-blocked-replay-new.json
```

本轮 `make check-all` 通过，其中 search-profile 共 309 项测试。实验 VM 已正常关闭，基础镜像前后 SHA256 相同；48 GiB 专用数据盘和导出的原始证据保留，没有清除旧失败轮或中断轮。最终导出目录的逐文件摘要与复核结果保存为同级 `export-inventory-001.json`／`export-verification-001.json`；它们只检查文件字节是否一致，不是对采集源的签名认证。

### 中途暂停后如何继续

`large_search.py` 默认只接受新输出目录，不会覆盖旧轮次。专用的 `resume_large_search.py` 可以接上本次被用户暂停的 80 轮设计：先核对原 schedule、已完成的连续前缀、同一 Guest boot，以及冻结的 runner、sampler、grep、cache probe 和分析器，再只运行剩余部分。它使用原目录中的计时代码，不把后来修改过的诊断代码混进主实验。

例如，原来已经完成前 55 轮时，在恢复原实验 Guest 后运行：

```sh
python3 -B /opt/large-search/resume_large_search.py \
  --original-matrix /opt/large-search/results/matrix-001/matrix.json \
  --expected-completed 55 --runtime /opt/large-search/runtime \
  --corpus /opt/large-search/corpus --prepared /opt/large-search/prepared \
  --source-manifest /opt/large-search/inputs/source.json \
  --queries /opt/large-search/runtime/queries.large.json \
  --sampler /opt/large-search/runtime/allox-load-sampler \
  --output /opt/large-search/results/matrix-resume-001 \
  --combined /opt/large-search/results/matrix-all-001.json
```

这是针对本次固定五块设计的续跑适配器，不是任意失败实验的自动恢复功能。它不会修改原来记录为 `FAILED` 的中断证据，也不把取消的一轮算作成功。剩余轮次完成、九个源目录的内容和权限复核通过后，才生成新的合并索引。若一个重复块跨越暂停，还另存 `*-continuous-blocks.json`，便于检查排除跨暂停块后结论是否变化。

导出结果后，用 `verify_large_matrix.py` 独立复核 schedule、完整固定配置、任务／查询时间、实际 stdout 和暂停前后的证据关联；再用 `wallclock_report.py` 计算秒数、采样指标和缓存摘要绑定。两者分别输出新回执，不修改原始结果。缓存摘要＋压缩文件哈希核对不等于逐文件重新计算全部驻留观测；这个范围在报告中保留。

## 已经能做什么

- 给每次搜索分配 task/agent/tool ID、独立 cgroup、进程 PID + 启动时间，绑定同一 boot ID。
- 先暂停子进程、放入 cgroup；完成 Python 初始化后再次暂停，等待采样器首个样本落盘后再开始搜索。
- 固定总搜索次数，改变并发上限；区分排队时间、工具运行时间、从统一放行点到完成的延迟。
- 每个任务内部的每次查询也独立计时，保存开始、结束、耗时、实际 grep／缓存命中和等待缓存锁的时间，不再用任务总时间代表单次查询。
- 按实际采样间隔计算 CPU 使用、独立的 CPU/内存/I/O PSI、逐设备 I/O、内存和 refault；对齐任务阶段。
- 保存中文 HTML 报告、JSON 数据和 Chrome Trace 格式任务时间线。
- 比较不同并发上限和采样开关，检查所有条件下搜索结果一致。

这还不是自动根因诊断器。报告给出可检查的数据和候选线索；“为什么慢”还需要受控诊断或单变量干预验证。

## 在哪里运行

```text
物理服务器
  └─ 新建的实验 QEMU（snapshot=on）
       └─ 目标 Linux
            ├─ 实验协调器 + sampler（不放进被测 cgroup）
            └─ 本轮 cgroup
                 ├─ task-0000：搜索及其子进程
                 ├─ task-0001：搜索及其子进程
                 └─ ...
```

需要 Linux cgroup v2，向实验目录委托 cpu/memory/io 控制器，以及 Python 3.8+、GNU grep。新的 VM 入口默认使用 PSI 内核并要求系统与各任务 cgroup 的 CPU/memory/io PSI 都可用。旧内核只能通过显式 `--allow-missing-psi` 做缺项诊断；缺失显示为未知。可选 kernel-hist 还需要匹配的内核 BTF/探针支持。

## 最简单的开始方式：新建一次性 VM

从 Observer 项目目录执行：

```sh
make all kernel-hist-bpf

# 输出目录必须不存在或为空；已有构建可直接复用。
bash vm/build-profile-kernel.sh --jobs 16

bash vm/run-search-profile-e2e.sh \
  --rootfs /absolute/path/to/unused-rootfs.raw \
  --ssh-key /absolute/path/to/guest.id_rsa \
  --queries-file "$PWD/experiments/search-profile/queries.example.json" \
  --kernel-build-dir "$PWD/.output/vm-kernel-profile-psi" --require-psi \
  --corpus /absolute/path/to/a/source-directory \
  --concurrency 1,2,4,8 --jobs 8 --passes 50 \
  --repetitions 5 --warmups 1
```

用 `--help` 查看 VM 脚本的可用参数。原始镜像不能被其他 VM 占用；脚本使用临时磁盘写层，核对镜像前后哈希，退出只停止自己启动的 VM。Python 可以从 Host 离线打包进 Guest，不联网安装依赖。

先选一个**边界明确的源码子目录**，不要把含 `.output`、虚拟机镜像或私钥的整个实验工作目录当作搜索语料。语料中的 `.git` 不参与搜索；符号链接和特殊文件拒绝，普通文件有数量/总大小上限。

## 在已经准备好的目标 Linux 中运行

查询配置是 JSON 字符串数组，例如：

```json
["EXPORT_SYMBOL", "unlikely_profile_absent_937", "spin_lock"]
```

每个任务按编号循环选择查询，运行 `grep -r -l -Z -F`。搜索输出为匹配文件名，不是匹配行全文。`--passes` 指每个任务执行同一查询的次数；所有实验条件保持不变。

小语料可先用 50 次重复，让运行时间覆盖多个采样周期；先试跑检查实际时长，再固定参数开始全部对照。它测的是这组重复工具调用，不是单次搜索的纯扫描耗时。只做功能冒烟时可以减小 passes，短任务仍保留，但资源分解会更不确定。

```sh
python3 experiments/search-profile/run.py \
  --corpus /opt/profile-corpus \
  --queries-file experiments/search-profile/queries.example.json \
  --output-dir /var/tmp/search-profile-new \
  --sampler "$PWD/.output/cargo-target/debug/allox-load-sampler" \
  --cgroup-parent /sys/fs/cgroup/search-profile \
  --concurrency 1,2,4,8 --jobs 8 --passes 50 \
  --repetitions 5 --warmups 1 --seed 1 \
  --cpus 0,1 --cache warm \
  --interval-ms 100 --process-interval-ms 500 \
  --modes baseline,sampler
```

CPU 编号必须在当前允许集合内。只限制被测任务，不限制采样器。cgroup 父目录必须已获得 cpu/memory/io 委托且没有直接驻留进程；runner 不在物理服务器根 cgroup 自动开启控制器。

各条件以固定 seed 随机轮换，先预热，再进入正式重复。每个条件都完成相同任务数、查询、passes 和结果处理。结果哈希在全部任务退出及采样器结束后计算，不占用下一批搜索的放行时间。语料先哈希、再准备缓存、最后计时；最后还会重新哈希检查语料未变。

## 怎样看结果

首先打开 `campaign-report.html`（若只需机器数据则读 `campaign.json`），再打开某轮的 `trials/<轮次>/report.html`。

| 文件 | 用途 |
|---|---|
| `campaign.json` / `campaign-report.html` / `campaign-report.json` | 原始实验索引及派生条件比较、重复次数、采样增量开销、结果一致性 |
| `corpus-inventory.json` | 这次实际搜索的文件版本 |
| `trials/.../profile-run.json` | 本轮任务身份、配置、退出码、排队/执行时间、wait4 CPU 计量 |
| `trials/.../task-events.jsonl` | 搜索起止与 Agent/工具/进程/cgroup 的对应关系 |
| `trials/.../task-*-statistics.json` | 原始逐查询区间 `query_spans`、实际 grep 次数、缓存命中次数；每个区间绑定任务身份和查询摘要 |
| `trials/.../report.html` | 中文阶段报告和资源曲线，含缺失项 |
| `trials/.../report.json` | 可重新分析的数据，不是安全 verdict |
| `trials/.../timeline.json` | 可导入 Chrome Trace / Perfetto 的任务区间 |
| `trials/.../load/` | sampler 原始计数、进程采样、配置和健康信息 |

单轮可以离线重算：

```sh
python3 experiments/search-profile/analyze.py /var/tmp/search-profile-new/trials/某一轮
```

任务开始时间是协调器向已初始化的 worker 发出 SIGCONT 前的时间，结束时间是协调器通过 wait4 发现退出的时间。Python 解释器启动、导入和任务配置读取在计时前完成；计时仍包含 grep 启动、worker 调用开销和退出轮询误差，不是精确的内核 exec/exit 时间。

任务 CPU 时间用 wait4 的最终累计值减去 worker 暂停前的 CPU 基线，包含它等待回收的 grep 子进程 CPU，也包含基线之后写 ready 文件和暂停的少量握手成本，因此不是精确裁剪到计时窗口的 CPU 时间。原始全生命周期 CPU 也单独保留。RSS 峰值、缺页和上下文切换仍是全生命周期统计，包含准备阶段，不能直接当作计时窗口内增量。上述范围会写入 JSON 的 `timing_scope`、`cpu_time_scope` 和 `other_rusage_scope`。

阶段事件数量有任务上限，结束后补入结果摘要再落盘；它不是崩溃安全的审计 WAL。

### 怎样看某一次查询花了多久

新结果的 `report.json → query_measurements.queries` 每一项就是一次逻辑查询：`query_ordinal` 是任务内部从 0 开始的查询序号；`query_index` 是固定查询列表中的分配编号，两者不要混淆。`begin_ns` / `end_ns` 为同一 boot 的单调时钟，`duration_ns` 必须由两者相减得到。`execution_kind=SCAN` 表示实际运行 grep；`CACHE_HIT` 表示复用本轮结果。后者的耗时仍包括等候首次扫描完成的锁等待，`lock_wait_ns` 不是可以另外加到总耗时上的一段。

例如，一个任务执行 8 次查询，会保存 8 个区间，而不是把任务耗时除以 8。HTML 单列“每个搜索任务”和“逐次查询延迟”；时间线把查询画在所属任务内部。campaign-report.json 的 `logical_query_duration_seconds` 汇总经过离线校验的逐次延迟，不按相关的任务内查询伪造独立样本置信区间。历史 `query_completion_seconds` 名称保留兼容，但它一直是任务从统一放行点到完成的延迟，不是单次查询耗时。

分析器重新读取原始 `task-*-job.json` 和 `task-*-statistics.json`，检查查询数量、顺序、查询摘要、run/Agent/tool/boot/进程 birth/cgroup、区间包含关系和扫描／命中计数。缺失、时间倒退、重叠、身份不符均标为 `INCOMPLETE`；旧版本没有逐次采集时标为 `NOT_COLLECTED_LEGACY`，绝不通过平均任务时长补造。CPU/read/sleep 校准标为 `NOT_APPLICABLE_CALIBRATION`。

这些区间测的是 worker 发起的一次工具调用，包含子进程启动／回收、缓存处理和结果输出，不是 grep 的纯扫描 CPU 时间；身份属于调用 worker，grep 后代仍由 Observer 自己的进程证据解析。记录先在内存缓冲，查询路径不额外序列化、hash 或读取 `/proc`；统计在 worker 退出前落盘，因此整体任务耗时仍包含这些计量及写盘成本。所有开／关采样对照都必须使用相同版本的查询计量。

其他 benchmark 适配器可复用 `run.py` 的 `QueryMeasurements(identity, query_sha256, query_index, mode)`：在任务开始前构造，使用 `with measurements.span(ordinal) as row:` 包住一次真实工具调用，填入 `execution_kind` 和 `returncode`，任务结束后保存 `measurements.rows`。适配器负责提供可验证的任务身份、结束屏障和原始调用记录；仅调用这个计时类不等于完成 Observer 审计或 benchmark 官方验收。

采样器给的是离散样本。对于落在两个样本之间的短任务，报告保留任务时长，并标出包围采样窗口及边界不确定性，不会伪造毫秒级资源分解。父 cgroup 与子 cgroup 的计数包含关系明确，不能相加。

## 两条测量路径不要混淆

| 模式 | 启用什么 |
|---|---|
| `baseline` | 同样的任务协调/身份/计时，但不运行 sampler |
| `sampler` | 加上 `/proc` 和 cgroup 资源采样 |
| `kernel-hist` | sampler 加一套绑定本轮根 cgroup 的内核直方图探针 |
| `observer` | 真实系统效果 recorder + lifecycle，结束后运行独立 verifier，不启用 sampler |
| `observer-sampler` | 与 `observer` 相同的审计配置，再加 sampler |

三组真实开销对照必须使用同一 `--cgroup-layout shared-leaf`，并提供 `--observer-binary`、`--verifier-binary`、`--recorder-object/--recorder-sha256`、`--lifecycle-object/--lifecycle-sha256`。所有任务进同一个封闭 cgroup，Observer 只加载一次；因此 cgroup 用量是全组总量，不能当每任务独占资源。Observer 使用 balanced profile 和部分内核对象解析，未开启最终状态 confirmer，不能声称全系统状态完整覆盖。审计完整度与 sampler 完整度分开保存。

无 Observer 的 baseline 也使用相同共享叶子布局、相同任务及相同结果处理。JSON 分别记录运行窗口 `makespan_ns`、Observer 准备、结束边界及 verifier 耗时、自身 CPU/RSS 和证据字节。只有前者用于热路径 slowdown，边界成本不得藏起来，也不得和热路径相加后仍称纯 syscall overhead。

开销比值只比较统一放行到全部 worker 退出的运行窗口，不包含 VM 启动、cgroup 准备、worker 预启动、探针装载和报告生成，不能当作完整冷启动成本。sampler 的 `loop_cost` 是采集循环耗时，也不能替代这个配对运行对照；BPF 执行的成本可能发生在被测进程上下文中。

启用内核诊断需要显式增加：

```sh
--modes baseline,sampler,kernel-hist \
--kernel-hist-object /trusted/kernel_hist.bpf.o \
--kernel-hist-sha256 <事先记录的构建SHA256> \
--kernel-hist-groups sched,syscall
```

最终诊断后端默认显式选择 syscall `kprobe`；选择 memory 组时默认 `kprobe-tracefs`。可用 `--kernel-hist-syscall-backend raw-btf` 或 `--kernel-hist-memory-backend fentry` 复查旧后端，但不会静默降级或隐藏漏采。全组的实际名称是 `sched,syscall,mem,lock,blk,irq`。sampler 与 BPF 对象必须固定为匹配的 ABI/摘要。

旧 ABI 的 kernel-hist 只加载一套，以第一个 cgroup（本轮公共父目录）聚合全部任务；旧数据不能把父目录等待总量分摊成每个 Agent 的精确等待。默认不启用全局 BPF 运行时间计费；`--kernel-hist-runtime-stats` 是 sampler 独立 CLI 的诊断选项，不在此实验默认启用。

新 ABI2 在一套探针中注册多个域，`khist.domains` 按 path/inode/device/index 单独保存，`khist.system` 单列全机 block/softirq。分析器按任务实际 cgroup 选择匹配的域；不把第一个域的数据分配给其他 sibling。父域包含子域，不能求和。相应数据仍是整个采集窗口的完成 span，不是精确裁剪到每个任务阶段的等待分账。

报告分别展示普通资源采样和内核探针的健康状态。探针递归漏采、未配对事件、存储不足和计数异常均保留；`recursion_misses` 是对应探针的全局计数，不能直接解释成某个 Agent 丢失了多少事件。直方图总量和均值只描述已记录并完成的 span，漏采时不能拿来证明完整等待时间。

## 校准与解读边界

相同入口可用 `--calibration-kind cpu`、`sleep` 或 `read` 替代 grep，报告明确标注为校准。CPU 默认执行约 0.4 秒进程 CPU 时间；sleep 睡眠约 0.4 秒；read 按固定文件列表及 passes 读取语料。这些用于核对 CPU 计量、短时等待和读路径，不是搜索优化结果。两个 CPU 校准任务固定到一个 CPU，可为 runqueue 直方图提供受控竞争。

- `warm` 是先读一遍语料，不保证大工作集全程驻留内存。
- `guest-cold` 还要求 `--allow-guest-drop-caches` 和 QEMU/KVM 身份检查；只清 Guest 缓存，不证明物理服务器缓存冷。不要在物理服务器运行这个模式。
- PSI 的 some 比例不是每个任务的损失；CPU/内存/I/O PSI 不能相加。
- 内核直方图含跨窗口完成、相互嵌套的 span，不能相加成墙钟耗时。
- 块设备/softirq 诊断是全系统范围，不能归给某个 Agent。ABI2 按 `nr_bytes` 保留部分完成，并处理 requeue/error；真实源代码的请求状态机重放通过，但不声称所有硬件的合并/写回/重排均完成 E2E。默认只启用 sched/syscall。
- 缺少 PSI、样本丢失、计数回退、身份不匹配、进程采样截断都会保留为未知/不完整；不影响已测事实仍然显示。
- 小样本的 median/区间不是生产 SLA，不报告看似精确的 p99。找不到稳定加速也是有效结果，不能为了得到正结果改变总工作量。

## 单因素干预：复用完全等价查询

`--intervention exact-reuse` 会让同一轮任务复用相同结果。**第一次 grep 仍在计时窗口实际执行**；其他任务等待这次扫描，随后读取结果缓存。每个任务仍完成同样的逻辑查询次数、产生完全相同的 NUL 分隔文件名输出。统计同时给出逻辑查询数、实际 grep 次数、缓存命中数，不能把减少的物理扫描伪装成工作量没变。

缓存 key 不只包含查询文字，还绑定：`--repository-version`、内容清单、文件/目录 RWX 与 owner/xattr、grep 二进制与固定选项、UID/GID/groups/capabilities、user/mount namespace、可读取的 LSM label 与 seccomp 模式。先验证独立 workspace 副本内容和权限完全相等，结束后再检查语料及权限未变；不满足就整轮失败。每轮用新缓存，不跨轮偷用预计算结果。它仍是合作型、静态语料实验，不能证明任意 Landlock/LSM 隐藏策略等价，也不是安全隔离机制。

`--workspace-layout independent` 为每个 Agent 创建内容和权限一致的独立目录；`shared` 共用同一个目录。`--memory-high-mb` / `--memory-max-mb` 仅限制本轮新建的 cgroup，可用于验证 reclaim/压力，OOM、超时和缺失会保留为失败。冷缓存只允许明确授权的新 QEMU Guest。

完整实验编排见 [profile-validation](../profile-validation/README.md)：冷/热 × 共享/独立 × 1/2/4/8 并发、5 个随机化重复块、结果复用干预，以及 100/500/1000 ms 三组 Observer 开销。它不测 GPU、真实模型质量或自动调度。

## 本地验证结果（2026-10-14）

### 新 PSI Guest：冷/热、独立副本和等价查询复用

新增实验已实跑 **160 轮、1280 个逻辑任务**，每轮固定 8 tasks × 8 次查询；16 个 cache/layout/concurrency 条件各做 5 个随机化重复块。语料为固定版本 Linux `lib/`（commit `519a8175…`，实际内容和权限清单另存），worker 只使用 Guest 的 2 个 CPU。Observer 在这条机制矩阵中未启用，sampler 精确版本单独固定；真实 Observer 三组开销是另一个实验，不能混算。

| 条件例子 | 不复用：总时间中位数 | 等价复用：总时间中位数 | 配对变化中位数 | 均值变化 95% bootstrap 区间 |
|---|---|---|---|---|
| warm / shared / 8 并发 | 0.2321 秒 | 0.0494 秒 | −79.30% | [−80.36%, −77.77%] |
| Guest-cold / shared / 8 并发 | 0.4279 秒 | 0.2175 秒 | −49.81% | [−50.54%, −48.23%] |

所有任务完成同样的 **64 次逻辑查询**，无复用每轮实际运行 64 次 grep，复用每轮实际运行 1 次 grep + 63 次缓存读取；首次扫描没有在计时前偷跑。16 个条件的区间都支持本场景下的端到端收益。独立 Host replay 检查 1280 份原始 stdout 的字节摘要完全相同。这个结果支持“相同静态权限视图下的重复查询可复用”，不证明任意真实 Agent 搜索都有这么高重复率，也不证明通用自动调度已经完成。

PSI 本次可用。仍有 148 条 `MISSING_COUNTER`：设备第一次出现在后一个 `io.stat` 样本时，前值未知（37 个边界 × 4 个 I/O 字段）；保留为 UNKNOWN，未为了采样完整度补零。它们不推翻输出一致性及计时时长，但不能据此给完整物理 I/O 分账。

证据：`.output/profile-validation-20261014/matrix-basic-20261014/validation-campaign.json`、`matrix-basic-replay.json`，原始 runner/analyzer 与 artifacts 版本放在同级 `matrix-source-original/`。当前程序后续改进不会覆写这份历史数据。

### 真 Observer 三组开销与内存压力校准

同一 shared-leaf、同样 8×8 次查询、5 个随机重复块，分别测了 **100/500/1000 ms**；每个间隔测并发1/8和三组，共90 trials、720 tasks。60 个有 Observer 的 trial 全部独立 verifier 通过，但审计 `evidence_status` 仍为 INCOMPLETE（当前 selected profile/部分对象解析的边界），不是全接口、全状态覆盖。性能采样本组没有已报告异常；诊断 kernel-hist 没有加载。

| 间隔 | 并发 | Observer vs 无 Observer：热路径中位增量 | sampler vs 同一个 Observer：中位增量 | sampler 增量均值的 95% 区间 |
|---|---|---|---|---|
| 50 ms | 1 | +13.01% | −1.12% | [−1.89%, +2.15%] |
| 50 ms | 8 | +12.97% | −0.15% | [−0.63%, +0.84%] |
| 100 ms | 1 | +11.83% | +1.37% | [−0.44%, +3.81%] |
| 100 ms | 8 | +11.72% | +2.22% | [−4.11%, +7.56%] |
| 500 ms | 8 | +11.67% | +0.30% | [−0.32%, +0.39%] |
| 1000 ms | 8 | +11.44% | +0.13% | [−1.43%, +1.24%] |

小样本的 sampler 增量区间都跨0，不能宣称它显著拖慢或加速。100 ms 下其全生命周期 CPU 中位约5.5–6.2 ms、RSS约29 MiB、采集循环均值约0.47–0.50 ms；**这些不是任务热路径 slowdown**。准备、sampler 末尾等待、Observer结束及 verifier 成本另存，500/1000 ms 对短任务的末尾等待尤其不能藏起来。实验未启用状态 confirmer，不能把此表当开启所有功能的生产成本。

受限内存校准另跑20 trials、160 tasks：每轮同样读取8×320 MiB，两组都使用 memory.max=512 MiB，只改 memory.high=0/192 MiB。对照组 memory PSI、high、scan/steal/refault 增量都为0；受限组出现明确 memory PSI 和 reclaim/refault，任务总时间在串行/2并发分别配对增加约436%/227%。这证明采样能观察人为制造的内存瓶颈，不是优化收益。最初64 MiB high小于解释器驻留集合的试验在任务开始前超时，失败证据保留；修正后限制在 worker 初始化后才生效。

证据目录：`overhead-abi2-v2-20261014/`、`pressure-abi2-v2-corrected-20261014/`（同级于前述矩阵）。两组使用冻结 release sampler `c3583a7e…`，不与旧 matrix 或后续不同 BPF 对象的诊断混合统计。

50 ms 另跑30 trials、240 tasks，总开销组为120 trials、960 tasks。复制回 Host 后，用 SHA固定为 `571c79d8…` 的独立 verifier 重放全部 **80/80** Observer trial（12800 条 syscall-effect、15992 条 lifecycle WAL 事件），全部验证通过，但 **80份审计完整度仍为 INCOMPLETE**。主实验合计300 trials、2400 tasks，原始 stdout 字节一致性在 Host 复查通过。

最终 v7 详细诊断另跑6 trials、48 tasks，注册9个 cgroup 域并启用全6组与TID；它不是三组增量开销对照。任务和输出通过，但全系统 block 记录出现 `blk_untracked`、`blk_issue_without_insert` 和 `blk_zero_length_unsupported`，保留19条累计边界告警，诊断总体仍为 INCOMPLETE。线程轮询标为 PARTIAL_POLLED，短命 grep 的单样本差值仍是 UNKNOWN。受限内存试验另有92条首次设备前值未知；加上矩阵的148条，共240条 MISSING_COUNTER，均未补零。校准通过不等于真实工作负载所有域都完整。

紧凑总览和全部独立回执：`.output/profile-validation-20261014/campaign-summary.json`、`host-wal-replay/summary.json`；全组诊断原始证据在 `rich-diagnostic-abi2-v7-20261014/`。旧失败 profile、最初 memory.high 初始化超时和新诊断缺口均保留。

随后 v8 只做2轮真实搜索诊断复验（1/8并发各一，16 tasks），不用于性能增量结论。新 collector 额外保存有界的 request opcode/flags 与原因提示，成功零字节 FLUSH 单独记服务片段；两轮各观察2个 FLUSH，queue 未知3、untracked completion 未知1，测量探针递归/内核返回 probe miss/对象字段读取失败均为0。Host 从原始计数重新分析与原报告完全一致，但整体仍 INCOMPLETE：没有 insert 可以是直接分发，queue 是 UNKNOWN，不是零；untracked 不能仅靠 flags 解释成合法或丢失。v8不用于追溯重解释v7的未类型化证据。回执：`block-v8-review-receipt.json`，原始目录：`rich-v8-block-review-20261014/`。

### 较早的单一 warm-cache 试验（无 PSI）

修复版在新的 QEMU 中完成了 **48 轮、384 个工具任务**（包含预热）。每轮固定 8 个任务，每任务重复同一查询 50 次；语料为 Linux `lib/`，预读缓存，任务只使用 Guest 的 2 个 CPU。每种配置预热 1 轮、正式重复 3 轮，顺序随机轮换。这里的 Agent ID 代表模拟的工具任务，不是接入了 8 个真实模型会话。

最终 `make check-all` 通过：353 项 Rust 测试、72 项本实验 Python 测试（含实际 wakeup helper 的本机 C 重放），以及原有构建、格式和脚本检查。

全部任务身份绑定、退出、搜索结果一致性和清理检查通过；底层镜像前后哈希一致，没有修改其他 VM。使用的是修复后能记录 worker 首次恢复排队等待的 BPF 对象。较早的修复前试验独立保存，不与下表混合统计。

| 同时搜索的任务数 | 不开启采样：全部任务完成时间中位数 | 轻量 sampler：配对运行开销中位数 | sampler + sched/syscall 探针：配对运行开销中位数 |
|---|---|---|---|
| 1 | 2.747 秒 | +1.09% | +15.05% |
| 2 | 1.444 秒 | +1.64% | +12.36% |
| 4 | 1.442 秒 | +2.27% | +14.73% |
| 8 | 1.465 秒 | −0.82% | +11.83% |

**这轮的结论是：从 1 路增加到 2 路明显缩短了总时间，再增加并发没有明显提升。还没有证明“限制并发”是一项稳定有效的优化。** 例如 8→2 路的配对中位变化，在 baseline 为 −1.47%，在 sampler 档却约为 +0.07%。这只是共享物理服务器上、暖缓存、2 CPU、小语料和少量重复的结果，不是生产性能保证。负开销不意味着采样器能够加速搜索。

详细探针记录的累计排队等待随并发增加，但这是多个任务相加的已观测等待，不是总墙钟时间；详细探针本身也明显增加开销，因此保持显式启用。轻量 sampler 每轮自身 CPU 约 0.098–0.178 秒，RSS 峰值约 16.7–17.9 MiB；自身 CPU 包含启动过程，不能和只覆盖任务运行窗口的 slowdown 混用。

同时做了两组真实内核校准：

- 两个各消耗约 0.4 秒 CPU 的任务，只允许使用一个 CPU：总 CPU 记账约 0.813–0.815 秒；并发不会让总时间减半，累计 runqueue 等待明显增加。
- 两个各睡眠 0.4 秒的任务：串行约 0.81 秒，并行约 0.41 秒；总 CPU 约 13–15 毫秒，已记录的睡眠时间合计约 0.801 秒。

**仍有采集边界：** 该 Guest 未提供 PSI；部分短命子进程在采样时已退出；syscall 探针出现程序级 recursion misses，已列入报告，不能把它当成完整 syscall 时间分账。本次 `io.stat` 没有逐设备记录，不能据此宣称所有磁盘等待为零；这轮也没有验证内存压力瓶颈。`PASS` 指实验执行、结果和身份检查通过，不表示所有性能数据完整。

本机产物（不随 Git 提交；复制实验目录后可离线查看）：

- [正式搜索对照报告](../../.output/search-profile-e2e/run-5e8Kgogo/guest-evidence/campaign/campaign-report.html)
- [CPU 校准报告](../../.output/search-profile-e2e/run-aoC7ZisA/guest-evidence/campaign/campaign-report.html)
- [睡眠校准报告](../../.output/search-profile-e2e/run-kUBdPuGY/guest-evidence/campaign/campaign-report.html)
- [验证汇总与原始产物索引](../../.output/search-profile-e2e/final-validation-2026-10-14.json)

## PSI 补齐后的验证与附件增量核对

上面的历史试验使用未启用 PSI 的内核。现在已在独立构建中启用 `CONFIG_PSI=y`，重新启动 QEMU，并检查 `/proc/pressure/{cpu,memory,io}` 和每个被采样 cgroup 的 pressure 文件。CPU 忙循环、单 CPU 竞争和 sleep 控制均通过；带 PSI 的最终搜索也通过任务身份、计数单调及输出一致性检查。

两个各需约 0.8 秒 CPU 的任务争抢同一 CPU 时，CPU PSI 等待中位数从串行约 0.0005 秒升到并发约 1.61 秒；两个 sleep 任务的 CPU PSI 等待仍很低。这说明该环境已经能提供资源等待证据。

最终暖缓存搜索仍是 914 个文件、约 10 MB 的 GNU grep 微基准：并发 1/2/4/8 时，无采样总耗时中位数为 2.654/1.455/1.489/1.494 秒。带采样的 CPU PSI 等待中位数约为 0.0068/0.1836/1.2087/1.4133 秒。小语料暖缓存下 memory/io PSI 中位数为零；这没有覆盖冷读取、大工作集或受限内存。部分短 grep 在 procfs 读取期间退出，逐轮进程采样仍有不完整状态，不能把 PSI 补齐描述为所有观测都已完整。

- [PSI 构建与校准记录](../../.output/search-profile-psi-e2e/psi-validation-summary.json)
- [带 PSI 的最终搜索报告](../../.output/search-profile-psi-e2e/run-3KdeIvs9/guest-evidence/campaign/campaign-report.html)

### 上一轮的审计与本轮补齐

上一轮停在 PSI 和小规模 benchmark 接入；下面是按附件继续实现和反复实测后的状态。不要把上面的历史报告当成本轮实现上限。

| 附件中的增量 | 状态 | 已完成与剩余范围 |
|---|---|---|
| P0 任务关联接口 | 实现并实测 | 两个 Agent、依赖/优先级版本、工具和推理请求、共享 dispatch/真实 GGML worker 区间；未宣称生产 V8 已接入 |
| P0 离线分析与校准 | 实现并实测 | CPU/排队/sleep、Guest 冷读、内存压力、缺页/回收/锁诊断；300 轮搜索/压力/三组开销对照 |
| P1 细化归因与诊断 | CPU/文件路径实现并实测 | 一套探针最多16域、TID 身份、工具/实际文件/VFS 字节、独立 perf；GPU 接口有测试，但 GPU 硬件 E2E 缺失 |
| P1 推理适配与混合实验 | 真实 CPU 推理实现并实测 | 固定 llama.cpp、请求阶段和批次关系、G0–G3、优先级/取消控制及轻重插桩开销；GPU 调度/显存实测未完成 |

[本轮通俗验收报告](../profile-validation/ACCEPTANCE.md)说明测到了什么、优化是否有效和实际开销。[完整增量审计](increment-audit.json)保留每项的源码、实验依据和未覆盖处。GPU 不能用 CPU 或远端 API 等待代替，当前硬件缺口保持显式未完成。
