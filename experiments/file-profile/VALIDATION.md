# 实际校准与迭代记录（2026-10-14）

运行位置为专属 QEMU 目标 Linux，PSI 开启，6 vCPU / 12 GiB；不在物理服务器运行被测 workload。所有失败和旧证据保留。

1. `file-object-001`：两个执行域，每域 800 字节，实际总 1600。成功解析 read/pread64、readv/preadv/preadv2、主线程与两个工作线程；文件 mmap 只记录身份，访问字节为未知，绝不计入读字节。
2. `file-search-001`：大量短命 grep 的进程/文件键超过默认 8192 上限，正确标记 INCOMPLETE；99 Hz 软件 CPU-clock 仅 3 个样本，不能据此解释热点。
3. `file-search-002`：显式有界 32768 项、4 次搜索/Agent 避免容量溢出；发现 fexit/vfs_read 的 1 次 recursion miss 对应缺失返回区间，仍标 INCOMPLETE，不补造 VFS 时间。
4. 实现把 fexit 仅作实际 return/end 时间捕获，聚合移到 syscall exit；不将 syscall 时长冒充 VFS 时长。`file-object-003` 再次精确返回 1600 字节；`file-search-003` 8184 个记录、健康计数和 recursion miss 均为 0。perf 改为显式诊断 999 Hz，62 样本、0 lost。
5. 调整 ctime 的内部 queried 位投影并保留 raw 值，`file-search-004` 再次通过：8184 条记录，任务关联无歧义，914 个只读语料对象匹配到相应文件路径和内容 hash；1053 个对象被两个域共同访问。未匹配的 interpreter/library/proc 等对象仍不强行关联到语料路径。
6. 独立收尾检查增加进程身份读取失败计数、非 x86-64 门禁；`file-final/file-object-final` 再次精确返回1600字节。离线检查额外验证boot、采集窗口、TID出生身份和健康声明矛盾；有界outermost覆盖的主动nested跳过保留计数但不误判丢失。
7. 独立perf-only延长到64次搜索，使用原 `grep 3.11-4` 精确 build-id `b1c639c3724b99f5e502ce5bb35bbf99872e8a67` 对应的官方Debian调试信息，未替换二进制。442个CPU-clock样本、0lost，`bmexec_trans`约22.85%、内核复制`rep_movs_alternative`约18.55%、`__d_lookup_rcu`约2.04%；这些是该诊断含启动/遍历的样本占比，不是独占墙钟耗时或磁盘等待证明。原始未符号化报告、调试文件、perf.data与重新符号化报告均保留。Host旧binutils解析DWARF有错误，未把其行号当权威；Guest新工具的符号/行号解析无错误。
8. 独立审查发现过早enable、compat编号别名和健康字段缺失问题，升级到schema2：先禁用attach→保存metadata/start→enable→READY；入口检查实际TS_COMPAT/x32；离线器要求全部版本化健康字段和9个hook/程序身份，并绑定meta/domain/窗口。`file-v2/positive`再次精确1600字节，含每域成功mmap1次/已解析对象EACCES1次与目录hook；`unsupported-abi`准确保留两域共4次不支持ABI并为INCOMPLETE，其余健康为0。`file-v2/search`真实两域GNUgrep仍通过；Host从raw+meta+任务+inventory独立重算绑定通过。旧schema1不追认ABI保证，最旧缺hook健康表的历史数据不能包装成COMPLETE。

证据在 `.output/profile-validation-20261014/file-object-*` 和 `file-search-*`。最后一轮原始 JSON、目录 inventory、任务事件、独立 perf.data 和符号报告均保留。perf 是有界热点抽样，stripped/未知符号仍未知，不从少量样本推断精确函数占比。没有把这一诊断的耗时混入三组正式 overhead。

这些结果只验证当前声明的 native x86-64 hooks 与合作型只读任务；不证明 mmap 实际读字节、io_uring、任意内核读取、完整请求分账或因果归因。`COMPLETE_FOR_SELECTED_HOOKS` 不是全系统安全 verdict。
