# 2／4／6／8 并发搜索：文件读取与缺页明细

这组实验回答两个问题：同样的一批搜索全部完成需要几秒；过程中实际读了哪些文件、每次返回多少字节、耗时多久。

不是重新跑模型，也不是改变总搜索次数。每轮都是八个 GNU grep 任务，分别限制最多 2、4、6、8 个同时运行。

## 本次同步后的新结果（2026-10-17）

本节只使用新 campaign `allox-observer-sync-20261017-001`，下节保留的是上一批历史数据，不能混用。

### 同步了什么

对照 `Rrooach/allox-observer` 的 main 提交 `175db4cf69b2c6b7051da69998056d20466b3e07`，补入本地缺少的通用 WAL `file-access` profile、`file-access-report`、读取对象关联及真实 VM 验证用例；保留本地较新的 A/B/C 恢复验证、线程和文件诊断能力，没有整仓覆盖。

新 profile 显式启用普通只读 open 和选定 read/pread/readv 路径，默认 profile 不变。逐调用报告包含请求／返回字节、syscall 起止时间、对象身份和可解析路径；向量请求量未知、EOF、失败和对象解析缺口明确保留。报告本身不是独立验证，仍需 `verify-effects`。四种对象解析模式的真实 VM E2E、Guest/Host 独立重放和完整 `make check-all` 均通过，使用方式见[项目 README](../../README.md)。

大仓库实验继续使用已有专用 192 B 事件采集器，**不是用新 WAL profile 跑完了大规模矩阵**。通用 WAL 有容量上限，不能为了装下整批记录而静默放宽。本次另补充压缩证据存储：80 轮 SQLite／per-file CSV 的逻辑数据共 194,962,727,405 B，无损 gzip 后为 30,416,878,918 B，减少约 84.4%；逐份校验了压缩数据和解压内容摘要，原始事件未删除。这是存储节省，不是搜索加速。

### 八项搜索全部完成需要几秒

每轮完成同样的八项搜索，改变的只是同时运行数量。共有四种查询，每种分配给两个任务；每任务执行一次，不减少工作量，不复用查询结果。仓库固定为 Linux commit `519a81750493f6fb35ee282ba3ff5bafdd58b81b`，每份 95,989 个普通文件、1,641,397,655 B。VM 为 6 vCPU／24 GiB，任务使用其中四个核。

以下为 `sampler` 资源采样组，单位秒，每格为五个随机区组的中位数：

| 同时运行数 | 热／共享 | 冷／共享 | 热／独立 | 冷／独立 |
|---|---:|---:|---:|---:|
| 2 | 3.210 | 8.593 | 3.099 | 22.788 |
| 4 | 1.653 | 7.313 | 2.164 | 12.134 |
| 6 | 1.824 | 7.735 | 1.764 | 12.339 |
| 8 | 1.618 | 7.715 | 1.600 | 7.441 |

开启逐次文件探针的 `access` 组单独列出，同样为五轮墙钟中位数：

| 同时运行数 | 热／共享 | 冷／共享 | 热／独立 | 冷／独立 |
|---|---:|---:|---:|---:|
| 2 | 6.464 | 12.095 | 6.321 | 28.478 |
| 4 | 3.113 | 9.062 | 3.035 | 14.524 |
| 6 | 3.650 | 9.588 | 4.045 | 15.216 |
| 8 | 3.053 | 8.666 | 3.052 | 8.782 |

同一区组配对的详细探针耗时增幅，中位数随条件约为 **13%–130%**。这只是相对常态资源采样的增量，不能叫作相对“完全关闭 Observer”的开销；不宜默认开启全量逐次诊断。离线重放和压缩时间不混入上面的任务墙钟。

### 实际访问了多少文件

下面是新 campaign 热／冷共享八并发的两轮真实 `access` 记录，均按“最接近同条件五轮中位数”选取，不拼接不同轮次。

| 源码访问指标 | 热 `096-r3` | 冷 `000-r0` |
|---|---:|---:|
| 尝试读取的不同源码对象 | 95,989 | 95,989 |
| 至少返回过正字节的对象 | 95,949 | 95,949 |
| 未返回正字节的对象 | 40 | 40 |
| 其中观测大小为零／读取错误 | 40／0 | 40／0 |
| 源码读取调用次数，含 EOF | 1,572,616 | 1,572,616 |
| 源码累计返回字节 | 13,058,942,714 | 13,058,942,714 |

全部 80 轮详细记录的源码读取次数和返回字节均与表中相同。40 轮共享条件各实际访问 95,989 个源码对象，40 轮独立条件各访问 767,912 个对象；独立工作区是八份不同 inode 的副本，并非多做了八倍查询。累计业务返回字节不是独特内容量，也不是设备读盘量。

同一个 `samples/kprobes/kretprobe_example.c` 文件大小 3,133 B，两轮均成功打开 8 次、读取 16 次、累计返回 25,064 B：

| 缓存 | VFS 累计耗时 | 平均 | 最大 |
|---|---:|---:|---:|
| 热 | 41.850 µs | 2.616 µs | 6.480 µs |
| 冷 | 1,582.482 µs | 98.905 µs | 1,382.001 µs |

每例完整保留 24 条 open/read 事件，包括 8 次返回 3,133 B 的读取和 8 次 EOF。请求字节分别为 98,304 B 和 94,208 B，不能用请求量代替返回量。VFS 区间包含执行和等待，不是纯磁盘服务时间，并发区间也不能相加分摊墙钟。

缺页样例能关联到真实 `/usr/bin/grep` 对象；没有文件后备的 `NO_FILE_VMA` 保留空对象和空路径。冷样例选中的 grep 记录是一次 `RETRY_ATTEMPT`，不能叫作已完成一次缺页。上述小源码文件的映射缺页计数为零，不能把它的冷读等待解释为该文件发生了映射缺页；普通 `read()` 冷读不要求源码产生 major fault。

### 这轮能解释到哪里

- 热共享没有数据盘读取，I/O PSI 为零，四／八并发接近用满四个工作核；支持成本主要在 CPU／VFS／遍历一侧，尚不能细分字符串匹配、元数据操作、CPU cache 或 DRAM 带宽。
- 冷共享每轮数据盘读取约 1.871 GB，冷独立约 14.965 GB，并有明显 I/O 等待。冷独立从二并发的 22.788 s 降至八并发的 7.441 s；冷共享的中位耗时则没有随四到八并发继续下降，不能说八并发总是最佳。
- 全部 160 轮未见目标组内存 PSI、refault、回收或 OOM 压力证据；这不排除带宽／缓存争用，也不是内存压力实验。
- 热预加载的页缓存可能记在任务 cgroup 之外；图中 cgroup 缓存 charge 小，不意味着整个工作集小或热缓存更省内存。资源曲线是约 100 ms 的包围采样，不能与逐次调用计量混为一种精度。
- **逐 task／逐 Agent 文件归因本轮未建立。** 八个任务共享一个 cgroup，离线关联器拒绝猜测所属任务，所以 `task_id=null`，并保留 `unresolved_task_events`。事件本身、调用者 PID/TID 和任务组归属仍保存；选定 hook 完整不等于每个 Agent 的所有接口都完整覆盖。单独打开进程采样也不会自动补上进程树关联器。
- 冷缓存只指目标 Guest；Guest 虚拟盘吞吐不能当物理 SSD 速度。新 campaign 的结果盘由 Host RAM 支撑，旧 campaign 使用 HDD 结果路径，**不能用新旧耗时差宣称代码优化提速**。

### 完成证据和查看入口

本次完整执行 160 轮，核对 1,280 份真实 stdout；160 份缓存证据和 80 份原始记录全部重放通过。共 203,714,896 条原始事件、39,113,260,032 B，选定 hook 无已记录丢失或解析问题；32 张时间线按冻结代码复算一致，独立墙钟／资源检查 17,034 项无差异。最终完整回归通过，两份基础镜像完整 SHA256 未变，实验 VM 已正常关闭，旧证据未删除。

- [新完整对照表：墙钟、配对探针开销及资源指标](../../.output/allox-observer-sync-20261017-001/postprocess-001/comparison/comparison.md)
- [新 32 张真实资源时间线](../../.output/allox-observer-sync-20261017-001/postprocess-001/timelines/index.html)；[热八并发预览](../../.output/allox-observer-sync-20261017-001/previews-001/warm-shared-c8-sampler.png)、[冷八并发预览](../../.output/allox-observer-sync-20261017-001/previews-001/guest-cold-shared-c8-sampler.png)，这两张已实际打开检查可读性
- [热文件样例及完整 16 次读取表](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/warm-shared-c8-access/example.zh-CN.md)、[冷文件样例及完整 16 次读取表](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/guest-cold-shared-c8-access/example.zh-CN.md)
- [热逐次 CSV](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/warm-shared-c8-access/source-file-reads.csv)、[冷逐次 CSV](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/guest-cold-shared-c8-access/source-file-reads.csv)；[热完整 open/read JSONL](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/warm-shared-c8-access/source-file-all-events.jsonl)、[冷真实缺页对象](../../.output/allox-observer-sync-20261017-001/file-examples-001/rendered-001/guest-cold-shared-c8-access/fault-examples.json)
- [热全部文件 CSV.gz](../../.output/allox-observer-sync-20261017-001/postprocess-001/analyses/096-r3/per-file.csv.gz)、[冷全部文件 CSV.gz](../../.output/allox-observer-sync-20261017-001/postprocess-001/analyses/000-r0/per-file.csv.gz)；其他完整数据库／文件表的实际存储位置以[本次 attempt 回执](../../.output/allox-observer-sync-20261017-001/postprocess-001/analyses/attempt-8140f194027745e2b28a7a1045f9b0cb.json)为准，不能链接不存在的未压缩文件
- [实验最终收尾回执](../../.output/allox-observer-sync-20261017-001/completion-001.json)、[独立数值核对](../../.output/allox-observer-sync-20261017-001/wall-audit-001/comparison-verification.json)、[32 图复算](../../.output/allox-observer-sync-20261017-001/postprocess-001/timeline-verification.json)、[两图人工可读性检查](../../.output/allox-observer-sync-20261017-001/previews-001/visual-review.json)

本次正式矩阵为 `export-001/main-001/matrix.json`，同一 boot 下直接完成全部五个区组，没有沿用旧 campaign 的暂停／拼接回执。原始证据及压缩结果已导出到 HDD 持久保留；原 RAM 传输镜像和恢复出的数据库副本也保留，但它们本身不能抵抗 Host 重启。

## 上一批历史结果（file-access-2468-20261016，2026-10-17 验收）

160 轮实验中，同一查询在各条件下的结果一致，共核对 1,280 份真实 stdout；80 轮详细采集的 203,724,519 条原始事件已全部重放，所选探针范围内无丢失、遗漏或解析失败。32 张真实时间线重建一致，独立墙钟／资源核对共 7,786 项无差异；完整 `make check-all` 回归通过。这不是模型任务正确率评测，也不代表所有 Linux 文件接口均被覆盖。

### 八项搜索全部完成需要几秒

下面是资源采样组，每格为五轮中位数。八个任务共用四个工作核；“并发 2”也必须完成全部八项任务。

| 同时运行数 | 热／共享 | 冷／共享 | 热／独立 | 冷／独立 |
|---|---:|---:|---:|---:|
| 2 | 3.192 | 8.476 | 3.135 | 23.081 |
| 4 | 1.638 | 7.351 | 2.107 | 12.093 |
| 6 | 1.799 | 7.623 | 1.781 | 12.511 |
| 8 | 1.596 | 7.758 | 1.644 | 7.407 |

热共享组没有数据盘读取，四／八并发时接近用满四个工作核，支持瓶颈在 CPU 侧执行／竞争；尚不能细分为字符串匹配、目录遍历或内存带宽。冷共享每轮数据盘读取约 1.871 GB，冷独立约 14.965 GB，同时出现明显 I/O 等待。本轮未见内存容量回收压力，不能据此排除内存带宽或 CPU 缓存争用。并发 6 还有“先六项、再补两项”的尾批影响，不能直接解释为缓存竞争。

逐次文件探针会增加运行成本：相对资源采样组，同一随机区组配对的耗时增幅中位数约为 11%–115%（随条件变化）。因此性能比较以资源采样组为主，详细诊断组另表报告。这不是相对“完全关闭 Observer”的开销测试；离线 SQLite 事务优化也不改变已测得的运行开销。

### 实际读了多少文件、多少字节

下面两列是八并发热缓存的两份明确样本，不是用输入文件清单代替访问计数。

| 内核事件／只读 SQL 核对 | 共享 `020-r0` | 独立 `013-r0` |
|---|---:|---:|
| 尝试读取的不同源码对象 | 95,989 | 767,912 |
| 曾返回正字节的源码对象 | 95,949 | 767,592 |
| 源码读取次数（含 EOF） | 1,572,616 | 1,572,616 |
| 实际返回字节 | 13,058,942,714 | 13,058,942,714 |

独立工作区是八份不同 inode 的副本，因此不同对象数是八倍；并没有多做查询。两份样本中差值 40／320 都已逐对象核查为空文件、读取错误为零。全部 80 轮详细记录的源码读取次数与返回字节均与表中相同。返回的业务字节不是物理磁盘读取量。

例如，共享样本中的 `samples/kprobes/kretprobe_example.c` 大小 3,133 B，被打开 8 次、读取 16 次，累计返回 25,064 B。选定 VFS 读取区间的累计／平均／最大耗时分别为 40.620／2.539／7.270 µs。一条实际记录请求 98,304 B、返回 3,133 B；后续 EOF 返回 0。这个对象的全部 24 条事件（含 16 次读取）均已导出，不是只取 100 条预览。

文件映射缺页已有实际对象例子 `/usr/bin/grep`；没有文件后备的 VMA 不编造文件名。GNU grep 的普通 `read()` 冷读并不要求源码发生文件映射缺页，不能用 major fault 少来否定读盘。

### 打开结果

- [完整对比表、资源及逐文件指标](../../.output/file-access-2468-20261016/final-postprocess-003/comparison/comparison.md)
- [全部 32 张真实时间线](../../.output/file-access-2468-20261016/final-postprocess-003/timelines/index.html)；[热共享八并发预览](../../.output/file-access-2468-20261016/timeline-preview-001/warm-shared-c8-sampler.png)、[冷共享八并发预览](../../.output/file-access-2468-20261016/timeline-preview-001/guest-cold-shared-c8-sampler.png)
- [单文件每次读取的字节与耗时](../../.output/file-access-2468-20261016/file-examples-001/shared-warm-c8-020-r0/source-file-reads.json)、[全部事件 JSONL](../../.output/file-access-2468-20261016/file-examples-001/shared-warm-c8-020-r0/source-file-all-events.jsonl)、[真实缺页对象](../../.output/file-access-2468-20261016/file-examples-001/shared-warm-c8-020-r0/fault-examples.json)
- [共享样本全部文件汇总 CSV](../../.output/file-access-2468-20261016/final-postprocess-003/analyses/020-r0/per-file.csv)、[独立样本汇总 CSV](../../.output/file-access-2468-20261016/final-postprocess-003/analyses/013-r0/per-file.csv)；其他轮次在同级 `analyses/<case>/`，每轮 SQLite 保存全量逐次记录和原始字节
- [最终验收](../../.output/file-access-2468-20261016/final-acceptance-003.json)、[32 图复算](../../.output/file-access-2468-20261016/timeline-verification-003.json)、[独立数值复核](../../.output/file-access-2468-20261016/wall-audit-002/comparison-verification.json)

这些 `.output` 链接指向本工作区保存的真实工件，不随源码仓库自动分发。独立工作区 CSV 有数百 MB，建议先看小型 JSON 示例，再按对象查询 SQLite。曲线是约 100 ms 的包围采样，文件调用是逐次事件；精度和归因范围不同。冷缓存仅指目标 Guest，不能外推物理服务器／SSD。只读清单和缓存证据仍是合作型实验中的声明及复算，没有新增认证来源或运行瞬间原子缓存快照的保证。

## 看哪些结果

| 想知道什么 | 看哪里 |
|---|---|
| 全部八个任务多久完成 | `comparison.md` 的墙钟时间表，单位秒 |
| 热／冷、共享／独立工作区有什么区别 | 同一表里的四种条件，不能混算 |
| 文件明细探针增加多少时间 | 资源采样和详细文件诊断两组的配对比较 |
| 对多少个不同源码文件尝试过读取 | `summary.json` 的 `metrics.source_unique_regular_files_read_attempted`；包括空文件和 EOF，不代表每个文件都返回了内容 |
| 每文件的读取次数、字节、累计／平均／最长耗时 | 每轮 `per-file.csv`；显式 archive 模式为 `per-file.csv.gz` |
| 某一次选定 read/readv 路径的请求／返回字节、offset、起止时间、PID/TID | 每轮 `events.sqlite`；archive 模式先按回执恢复 `.gz`。按对象或线程导出 JSONL；耗时为选定最外层 VFS 区间，并非纯磁盘耗时，readv 请求字节可能未知 |
| 哪个实际文件发生映射缺页处理 | MM fault 记录中的 mount/device/inode 和静态匹配路径 |
| CPU、内存、页缓存、PSI、调度、磁盘、网络、上下文切换、任务创建和缺页曲线 | `access_timeline.py` 生成的真实单轮 SVG |

`read-samples.csv` 和 `source-read-samples.csv` 是最多 100 条的方便预览，不是全量。全量原始记录保留在 `events.bin`，离线数据库保留全部逐次字段和原始字节。

## 两种采集方式为什么要分开

- `sampler`：约每 100 ms 读一次资源计数，作为主要性能比较。
- `access`：在相同资源采样之外，启用逐次文件和缺页探针。可以查每次调用，但有额外运行成本和证据落盘量。

两组单独列出。采集器加载、任务结束后的排空／同步／哈希，以及离线数据库转换也单独报告，不能藏在“探针开销很小”的说法里。

## 缓存与文件布局

热缓存表示要搜索的数据页已在目标 Linux 的内存中。冷缓存表示在这个 Guest 内先清掉数据页，再用不触碰文件内容的检查核实驻留情况。这里不保证物理服务器或 SSD 缓存也冷；检查目录和 inode 本身也会碰元数据。

共享仓库是八个任务读取同一组文件对象。独立工作区是八份内容、权限和版本相同、inode 不同的副本。独立副本中同一个相对路径可对应八个不同对象，因此“实际不同文件数”必须结合布局解释。

本轮 VM 为 6 vCPU／24 GiB：全部搜索任务共用 CPU 0–3 这四个核，协调、采样和记录使用 CPU 4–5。因此并发 8 不是给每个任务分配一个独立核。每轮固定八项任务，并发 6 会先启动六项、再补两项，尾批也可能影响总完成时间，不能单凭它较慢就归因为缓存争用。

顺序是：校验内容和权限 → 准备并检查缓存 → 开始计时 → 完成八个任务。不能在准备冷缓存之后又扫描、哈希所有文件。

## 运行与离线查看

编译详细探针：

```sh
make release file-access-kprobe-bpf
```

`access_search.py` 只允许在专用 root QEMU Guest 中运行。需要同一 boot 的只读输入准备目录、匹配的 collector/BPF、至少一个工作负载 CPU 和另外的采集 CPU。默认矩阵是 2/4/6/8 × 热/冷 × 共享/独立 × 两种采集 × 五轮，共 160 次。

重要参数：

```text
--concurrency 2,4,6,8 --jobs 8 --passes 1 --repetitions 5
--caches warm,guest-cold --layouts shared,independent --modes sampler,access
--file-access-backend kprobe-tracefs --collector-ring-bytes 268435456
```

其他必需输入用 `python3 -B experiments/search-profile/access_search.py --help` 查看。输出必须是新目录。设备名必须按实验 VM 实际磁盘填写，不能在物理服务器照抄冷缓存操作。

采集结束后，先用 `verify_access_inputs.py` 复核同 boot、只读文件的 inode 和元数据映射；不能预先把 `pre_post_identical` 改成 `true`。再按[文件诊断说明](../file-profile/README.md#离线查看)建立只读索引并转换各轮记录。

可以批量转换详细采集轮次。这里的索引必须来自整批实验结束后的检查；同 boot 的早期预检回执也不能代替正式结束后的检查。`--workers` 默认为 2，支持 1–8，应按主机资源选择，并且只在计时结束后运行：

```sh
python3 -B experiments/file-profile/access_batch.py \
  --matrix /path/to/exported/main/matrix.json \
  --inventory-database /path/to/post-verified-inventory.sqlite \
  --expected-inventory-sha256 ACTUAL_INDEX_SHA256 \
  --output-dir /path/to/analyses --workers 4
```

如需续跑，使用同一输出目录并加 `--resume`；程序先校验已有原始数据和输出摘要，不盲目跳过。已完整记录的丢失历史仍保持不完整，不会反复重放直到“变绿”。失败重试使用新路径，查看每次 attempt 回执中的实际输出位置。

以上 `/path/to/exported/main/matrix.json` 是通用示例。上一批历史 campaign 的正式矩阵为 `final-export-001/selected-001/matrix.json`，不是其中保留为 FAILED 的旧 `main-001`。那批实验暂停时保留了完整区组 0，恢复后完整重跑区组 1–4；最终五个随机区组使用固定 seed 101646，并保存了暂停、续跑和选样验证回执，不混入被暂停的半个区组。本次新 campaign 则使用上文的 `export-001/main-001/matrix.json`，两批回执不可互换。

汇总和画图也使用新目录：

```sh
python3 -B experiments/search-profile/access_comparison.py \
  --matrix /path/to/exported/main/matrix.json \
  --file-analysis-root /path/to/analyses \
  --output-dir /path/to/new-comparison

python3 -B experiments/search-profile/access_timeline.py \
  --comparison /path/to/new-comparison/comparison.json \
  --output-dir /path/to/new-timelines --device vda --interface eth0
```

每个条件的曲线选取最接近该条件中位墙钟时间的一轮真实运行，不是把不同轮次拼成一条“中位曲线”。

如果批处理中发生重试，将汇总命令的 `--file-analysis-root` 换成 `--file-analysis-receipt /path/to/analyses/attempt-UUID.json`，使用最终 attempt 回执定位实际结果。可再提供 `--expected-file-analysis-receipt-sha256` 固定这份回执的摘要；缺失或失败不会回退到陈旧目录。

`verify_access_matrix.py` 另外独立核对全部真实 stdout、查询时间段、并发上限及采集元数据绑定；原始事件仍由文件分析器重放。`verify_cache_proof.py` 可在计时结束后重算保存的逐文件缓存检查记录，但不能把这些记录当成实时缓存真相证明：旧 runner 未保存完整原始 pin，只读状态也只是声明，这些限制仍明确保留。

## 不要误读数字

- 输入清单数量不是访问数量；实际访问数来自内核对象事件。
- 请求字节是调用允许的最大返回量，实际返回字节可能更少或为零。两者都不等于磁盘物理读取量。
- 多线程累计读取时间可以超过墙钟时间；CPU、PSI 和累计调用时间不能相加当作任务耗时。
- 文件映射缺页与 `filemap_fault` 子路径分别记录，后者可能嵌套，不能相加。重试也不等于又完成一页。
- GNU grep 主要用 `read()`；冷读源码并不要求每个源码文件都有 major fault。映射缺页也可能来自动态库，而没有文件后备的 VMA 不能编造文件名。
- 目标 cgroup 的 CPU/内存/I/O 压力与全 Guest 的网络、调度队列、上下文切换、创建任务数分开标记。本轮不采进程/线程级调度等待。
- 路径是同 boot、前后检查一致的只读清单匹配，不是内核当时路径的完整快照。未匹配对象保留原始身份，不猜路径。
- 只覆盖声明的原生 x86-64 read/readv、目录遍历、打开和选定 MM 缺页路径；不覆盖所有 io_uring、splice/sendfile 或 mmap 读取字节。
- 任何环形缓冲丢失、挂点遗漏、配对错误、容量耗尽或解析失败都保留为不完整，不因输出正确而改为完整。
