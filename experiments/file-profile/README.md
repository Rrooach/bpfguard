# 文件对象读取诊断

这个显式诊断工具回答：“两个工具读到了哪些实际文件？分别返回了多少字节？VFS 调用累计花了多久？”

它是性能 side channel，不替代 Observer 的 WAL、manifest 和独立安全 verifier，也不默认加载。下面先介绍原有的 Map 聚合器；新增的逐次读取和缺页诊断见文末，两种模式不能混为同一种开销。

## 启动

在 PSI 实验 Guest 中，先创建不同任务的 cgroup，并暂停进程。构建：

```bash
make release file-profile-bpf
sha256sum .output/file_profile.bpf.o
```

使用实际摘要启动；等待标准输出 `READY` 再恢复任务：

```bash
.output/cargo-target/release/allox-file-profiler \
  --output-dir /var/tmp/new-file-profile \
  --bpf-object .output/file_profile.bpf.o \
  --bpf-sha256 <实际 SHA256> \
  --cgroup /sys/fs/cgroup/experiment/agent-a \
  --cgroup /sys/fs/cgroup/experiment/agent-b \
  --label <run_id>
```

任务树结束后，给这个 collector 发送 `SIGTERM`，等待它正常退出。不要在任务仍读文件时强行结束后声称完整。最多 16 个非重叠根；默认 8192 个进程/线程/文件版本聚合项，显式 `--max-file-records` 可在 1024–131072 内调整，绝不自动无界扩容。更大预算会增加内核内存；容量、payload 预算会记录在 meta。溢出、配对丢失、BPF recursion miss 都保留计数并使完整度下降。BTF、hook 或字段不兼容会拒绝加载，不静默退成路径猜测。

本版要求采集器看到目标 Linux 的 host-view cgroup 层级；不能在私有 cgroup namespace 内直接用可见路径深度当内核全局层级。容器接入需要在外层定位执行域。本工具不提供容器权限/enforcement；零记录也不是“任务没有读取”或“系统没有变化”的证明。

结果：

- `file-profile-meta.json`：boot、cgroup 身份、BPF 摘要、时钟及配置。
- `file-profile.json`：域、进程实例、TID 实例、mount/device/inode、元数据版本提示、调用数、返回字节、累计 VFS 时间、健康计数。

离线汇总：

```bash
python3 experiments/file-profile/analyze.py \
  --profile /var/tmp/new-file-profile/file-profile.json \
  --meta /var/tmp/new-file-profile/file-profile-meta.json \
  --task-events /path/search-trial/task-events.jsonl \
  --output /var/tmp/new-file-report.json
```

`objects_by_cost` 显示单个工具与对象成本；`shared_file_access` 显示跨域的读取量。只有同 boot、同注册域、完整包含全部累计调用区间且没有其他候选任务时，才接受 runtime 声明关联。共享线程先后服务多个请求或域内任务重叠时，累计值不能准确拆账，会标 `UNRESOLVED`。可传 `--inventory` 关联同 boot、前后内容和元数据一致的只读语料；这些路径标为用户态静止目录匹配，不冒充内核当时的路径快照。

## 覆盖与解释

| 操作 | 计量内容 |
|---|---|
| 原生 x86-64 `read/pread64` | 最外层 `vfs_read` 的实际文件、返回字节和区间 |
| `readv/preadv/preadv2` | 最外层 `vfs_readv` 的实际文件、返回字节和区间 |
| `getdents/getdents64` | 实际目录的 `iterate_dir` 区间，不把返回码算成目录字节 |
| 文件 `mmap` | 能解析实际文件的映射尝试及调用时间，成功/失败分开；实际访问字节未知 |

schema2仅支持原生 x86-64；非 x86-64 构建拒绝加载，实际syscall入口检查TS_COMPAT/x32，遇到选定编号的兼容ABI时跳过并计`unsupported_syscall_abi`，不会误当原生操作或返回完整。未选定的compat接口不承诺检测。schema1历史数据保留，但不回填新ABI保证。

启动时先附着禁用的探针、保存metadata与起始下界，再启用并发READY；任务必须等待READY才放行。这个时间下界不是原子的全系统快照。离线器对固定版本的全部健康字段、9个hook、注册域、程序身份和范围做一致性检查；缺字段、未知状态或矛盾不能算COMPLETE。`--meta`绑定声明的boot/start/domains/budget/label，但仍不是签名或安全审计认证。

返回字节包含页缓存命中，不等于磁盘读取量。多个线程的累计 VFS 时间不是任务墙钟时间。嵌套 VFS 调用只统计最外层，避免 overlay 等路径重复计数。`io_uring`、splice/sendfile、mmap fault 的文件分账不在当前覆盖中。

mount/device/inode/generation 是启动范围内身份；ctime/mtime/size 只是 `METADATA_VERSION_HINT`，不是内容 hash，也不能防止所有 inode 重用。`byte_volume_over_object_size` 是读取量与文件大小的比值，不证明重复范围、无效工作或可消除成本；结果复用仍必须另行校验仓库内容版本、查询、参数和权限。

Linux multigrain ctime 的 bit 31 是内部 `I_CTIME_QUERIED` 标志，不是纳秒。JSON 同时保留 `raw_ctime_nsec` 和解码后的 `ctime_nsec`，不删除内部原始证据。

## 确定性校准

```bash
python3 experiments/file-profile/run.py \
  --output /var/tmp/new-file-calibration \
  --profiler .output/cargo-target/release/allox-file-profiler \
  --bpf-object .output/file_profile.bpf.o \
  --workload .output/workloads/file-profile-calibration
```

runner 拒绝在物理服务器运行。两组工作负载各执行 read/pread、三种向量读、mmap 和两个工作线程；最终按实际 inode 与每组精确返回字节校验，任何缺口都不算 PASS。真实测试记录单独保存在验证报告中，不用单元测试冒充内核 hook 已通过。

另有 `search.py` 用两组真实 GNU grep、前后只读目录 hash、任务事件和独立 `perf CPU-clock` 诊断。perf 默认只在这个显式诊断中运行；不用于常态，也不把它的热点样本当精确 CPU 分账。

本轮实测见 [VALIDATION.md](VALIDATION.md)。

## 新增：逐次读取与缺页诊断

新增 `allox-file-access` 把每次选定调用写入 `events.bin`，可以回答“实际读了几个文件、每次请求和返回多少字节、开始和结束是什么时间”。不采文件内容，也不在内核维护无界的逐文件表。它是按需启用的详细诊断，会增加开销，不能把它的运行时间当成不开探针时的时间。

| 想看的结果 | 文件／字段 |
|---|---|
| 实际读取的不同源码文件数 | `summary.json` 的 `metrics.source_unique_regular_files_read_attempted` |
| 包括解释器和动态库在内的普通文件数 | `metrics.unique_regular_files_read_attempted`，与源码数分开 |
| 每个对象读了多少次、请求／返回多少字节、累计／平均／最大读取耗时 | `per-file.csv` |
| 每次调用的字节数、offset、开始／结束、PID／TID | `events.sqlite`；可按文件、线程或时间导出 JSONL |
| 可直接打开的少量逐次读取例子 | `read-samples.csv`；`source-read-samples.csv` 只取源码，各最多 100 条，不代表全量 |
| 文件映射缺页处理 | `metrics.mm_file_backed_fault_attempts`，通过实际 VMA 的文件对象关联 |
| 没有文件后备的 VMA 缺页处理 | `metrics.mm_no_file_vma_fault_attempts`；不能给它编一个文件路径 |

“没有文件后备”严格表示成功读取到 `vma->vm_file == NULL`，不保证都是普通堆／栈，也不等价于内核的 `vma_is_anonymous()` 判断。`filemap_fault_attempts` 另外记录文件页面补入的子路径；它可能嵌套在 `handle_mm_fault` 里，两个数不能相加。返回 `RETRY` 表示需要重试，不是又成功访问了一页。错误标志、MAJOR、RETRY 分开保留，这些调用次数不应强行与进程的 major/minor faults 相等。`read()` 冷读通常不走进程的文件映射缺页路径。

普通文件类型来自内核 inode 类型位；路径来自同 boot、前后检查一致的只读 inode 清单。路径标为静态匹配，不冒充内核当时解析的路径。本版不带实时 mtime/ctime，因而清单不能提供运行时内容版本证明。源码和系统运行库要在清单中分别标 `SOURCE_CORPUS`、`SYSTEM_RUNTIME`。未匹配对象保留 mount/device/inode/generation，路径显示未知，不能把 95,989 个输入文件直接当成访问数。

### 采集

`fentry` 与 `kprobe-tracefs` 必须显式选择，不自动切换。前者需要检查 BPF recursion miss；后者另外检查每个独占 tracefs 挂点的命中／遗漏计数、定义和身份，以及结束后的清理结果。全局挂点命中量不能当作 Agent 调用量。

```bash
make release file-access-kprobe-bpf
```

`allox-file-access` 的必需参数是 `--output-dir`、`--bpf-object`、`--bpf-sha256`、`--cgroup`、`--run-id`；`--backend kprobe-tracefs` 要使用 `file_access_kprobe.bpf.o`，`fentry` 要使用 `file_access.bpf.o`。等待 JSON `READY` 后才能放行任务，任务树退出后发 `SIGTERM` 并等待 collector 正常结束。`meta.json`、`final.json`、`events.bin` 都必须保留。

`--ring-bytes` 显式设置 16–512 MiB 范围内的二次幂缓冲容量；例如 256 MiB 是 `268435456`。更大缓冲会占用更多内核内存，不保证不丢事件，也不会自动扩容。必须检查实际 ring drops、序号范围和终态健康。较新采集器在停用、排空并同步事件文件后再计算大块 SHA256，避免每条 192 字节事件都做哈希；哈希失败同样不能算完整。

并发搜索请使用 [access_search.py](../search-profile/access_search.py) 的生命周期封装；它额外保存 `capture.json`，把 READY、实际计时窗口、cgroup、执行结果和 collector 终态绑定起来。文件读取、快照哈希、SQLite 转换和路径映射都不应插入已经准备好的冷缓存与任务计时之间。

### 离线查看

每轮用新的输出目录，不能覆盖旧证据：

```bash
python3 -B experiments/file-profile/access_analyze.py \
  --collector-dir /path/to/trial/file-access \
  --profile-run /path/to/actual-search-trial/profile-run.json \
  --inventory /path/to/verified-file-inventory.json \
  --output-dir /path/to/new-analysis
```

`--inventory` 可重复。正式映射必须在前后 inode 清单比较通过后使用，不能提前把 `pre_post_identical` 改成 `true`。分析器流式核对原始二进制 SHA256、记录数、CPU 序号唯一性／范围、hook 健康、boot/cgroup、READY 和精确 release/end 时间。乱序本身不是丢失；序号重复或缺口、pending、容量耗尽、遗漏或解析失败会保留为 `INCOMPLETE`。跨越计时边界的调用单独列出，不能把整个调用耗时悄悄记到窗口内。

离线导入每 4096 条有界批量写入，在整次导入及检查正常结束后提交一次事务，减少频繁同步磁盘的成本；SQLite 仍使用 DELETE journal 和 FULL 同步。读取或数据库运行失败时整体回滚，不生成成功 summary。被正常解析为坏记录的原始字节仍保存并标记不完整；不能将“异常回滚”和“观测到不完整证据”混为一谈。中断留下的派生目录不能直接拿来当结果，应由批处理重验或在新目录重做。

多轮实验可以先把已验证的清单建成一次性只读索引：

```bash
python3 -B experiments/file-profile/access_analyze.py \
  --build-inventory-index /path/to/new-inventory.sqlite \
  --boot-id ACTUAL_GUEST_BOOT_ID \
  --inventory /path/to/verified-source-inventory.json \
  --inventory /path/to/verified-runtime-inventory.json
```

后续分析将 `--inventory` 换为 `--inventory-database /path/to/new-inventory.sqlite`，可加 `--expected-inventory-sha256` 绑定建索引时输出的摘要。索引只读共享，不在每轮数据库复制所有未访问文件；逐轮只保存实际匹配对象。

查看某个文件的全部逐次记录，从 `per-file.csv` 复制 `object_key`：

```bash
python3 -B experiments/file-profile/access_analyze.py \
  --database /path/to/new-analysis/events.sqlite \
  --object-key 'ACTUAL_OBJECT_KEY' \
  --detail-output /path/to/new-file-calls.jsonl
```

也可使用 `--device` 加 `--inode`，或 `--tid` 加可选 `--thread-birth-ns`，再用 `--start-ns`／`--end-ns` 过滤。同一 PID/TID 可能重用，因此需要精确实例时不要省略 birth。每行保留原始字段、结果、所用时钟和区间类型。open 的区间是 syscall，确实进入并解析对象的读取区间是最外层 VFS；VFS 前失败的读取保留为区间未知，不伪装成 VFS 延迟。

**累计读取耗时允许大于墙钟时间**，因为多个线程可以同时读取；它也不等于磁盘服务时间。直方图为 log2 桶，p50/p95/p99 给的是桶范围，不冒充精确原始分位数。当前仍不覆盖 `io_uring`、splice/sendfile 等异步／其他读取路径，不统计 mmap 映射调用数量，也不推算 mmap 读取字节。

### 多轮实验结束后的批处理

`access_batch.py` 只用于全部实验结束后的 Host 离线转换。不要在测墙钟时间的同时跑它。必须重新完成正式实验之后的 inode 清单检查、建立新的只读索引；同 boot 的早先预检清单也不能代替正式实验的后检查。

```bash
python3 -B experiments/file-profile/access_batch.py \
  --matrix /path/to/formal-campaign/matrix.json \
  --inventory-database /path/to/formal-post-inventory.sqlite \
  --expected-inventory-sha256 ACTUAL_INDEX_SHA256 \
  --output-dir /path/to/new-file-analysis \
  --workers 2
```

默认两个进程，显式允许 `--workers 1` 到 `8`。先在正式实验结束后，用 `--limit 4` 和不同的新输出目录比较两／四进程的实际转换时间与磁盘占用，再决定是否增加并行度；不要从 CPU 数量直接推断八进程一定最快。`--limit` 的结果明确标为只分析部分轮次，不是全部实验完成。

每轮输出到 `new-file-analysis/001-r0/` 等目录。`progress.jsonl` 追加记录提交、成功、失败和恢复校验；`attempt-*.json` 保存每次批处理终态、耗时、每轮结果路径和失败原因。即使某轮 kernel 记录不完整，转换器仍保存它的真实数值和 `INCOMPLETE`，不会重标为成功。

中断后，用相同参数加 `--resume`。它会检查原 matrix、索引、配置和源码摘要，并重新检查已经完成轮次的 summary、原始事件和输出文件摘要，不把“目录存在”当作完成。失败或不匹配的旧文件不覆盖，新尝试放在 `retries/`；此时以最新 `attempt-*.json` 的 `results` 路径映射取结果。只有一份批处理能持有同一个输出目录。损坏的 progress 日志会明确报错并保留，不会悄悄跳过。

### 可选：有界临时分析与无损归档

磁盘空间不足时，可以显式选择归档模式。默认仍是原来的 schema 1、五个普通文件，不自动压缩或删除它们。归档模式只改变**实验完成后的离线存储**，不改变 eBPF、计时窗口或原始 `events.bin`。

先准备一个属于当前用户、权限为 0700 的新临时目录，再给批处理增加：

```text
--archive-codec gzip
--scratch-root /dev/shm/NEW_PRIVATE_CAMPAIGN
--scratch-per-case-bytes 8589934592
--min-output-free-bytes 8589934592
```

本版仅显式支持标准库 gzip level 1，不依赖 zstd，也不静默切换 codec。每个工作进程只在自己新建的临时子目录分析一轮；SQLite 的 `TMPDIR`/`SQLITE_TMPDIR` 也限制到该子目录。五个原始派生工件先照常生成并计算摘要，然后：

- `summary.json`、`read-samples.csv`、`source-read-samples.csv` 以原字节保存为普通文件。
- `events.sqlite` 和 `per-file.csv` 保存为同名 `.gz`，分别绑定压缩前／后的字节数和 SHA256。
- 每份 gzip 都重新有界流式解压，复算原字节摘要与长度，成功后才允许写入 RESULT。
- 全部归档已验证后，仅清理程序刚创建的本轮临时派生副本；失败的 scratch、旧输出和原始记录全部保留。

归档 plan/attempt 为 schema 2，case 标记 `artifact_storage_schema: 2`。压缩工件顶层是 `logical_name`、逻辑 `bytes`/`sha256`；真正存在的文件由 `storage.path`/`codec`/`bytes`/`sha256` 指明，不会伪装成仍有一个普通 SQLite 文件。summary 保留分析器原字节，因此其中历史 sample 路径仍是 producer scratch 的来源记录；**当前结果位置以 attempt 的 artifacts 映射为准**。

空间预检按“工作进程数 × 每轮 reservation”检查 scratch 可用空间及真实 `MemAvailable`，并保留持久盘空闲预算；不能把 `/dev/shm` 标出的容量当作可用物理内存。每轮还设置单文件 `RLIMIT_FSIZE` 并检查生成后的总 footprint。它们是准入预算和单文件限制，**不是文件系统总 quota**；需要硬总上限时应另外提供限容的独立 scratch 文件系统。保留失败 scratch 会消耗预算，必须先检查失败原因，不能无限重试。

归档续跑仍需相同 plan、源码和参数。它会逐份重新解压验证五个逻辑工件、重新哈希原始记录，不只是检查 `.gz` 摘要；已确认的 INCOMPLETE 仍保持 INCOMPLETE。终态 verifier 可以绑定这份已完成的逻辑重放证明，但不能把“只检查最终小回执”写成“再次解压了全部证据”。

单独核验或恢复一轮的数据库（只读源，恢复目标必须全新）：

```bash
python3 -B experiments/file-profile/access_artifacts.py verify \
  --receipt /path/to/analyses/attempt-ACTUAL.json --case 001-r0 \
  --artifact events.sqlite

python3 -B experiments/file-profile/access_artifacts.py restore \
  --receipt /path/to/analyses/attempt-ACTUAL.json --case 001-r0 \
  --artifact events.sqlite --output /path/to/FRESH-events.sqlite
```

恢复后可用前述 `access_analyze.py --database` 查询。解压限制、未知 codec、CRC／摘要错误、尾随／拼接 gzip、目录穿越、symlink 和已有恢复目标均明确拒绝。压缩和复算会增加离线 CPU／延迟；正式大样本压缩率需实际测量，不能用微型测试样本预测磁盘预算。
