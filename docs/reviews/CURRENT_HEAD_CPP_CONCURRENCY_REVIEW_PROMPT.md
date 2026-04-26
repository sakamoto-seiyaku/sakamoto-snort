你是一个资深 C++20 / Android daemon / NFQUEUE / 并发内存安全 code reviewer。请对当前仓库 HEAD 做一次 review-only 专项审查，重点发现内存、并发、死锁、UAF、数据竞争、退出卡死、热路径阻塞等问题。

重要约束：
1. 只审当前代码事实，不修代码、不重构、不提交 patch。
2. `docs/reference/SNORT_SUCRE_IODE_DIFF.md` 只能作为“历史风险类型词典”参考，禁止沿用旧行号、旧结论，禁止默认认为旧 bug 仍存在。
3. smoke/host/ASAN 已通过不代表没有并发 bug；请重新从当前源码推导锁、生命周期和所有权关系。
4. 只报告能从当前代码推导的风险；不确定项放入“需动态验证”，不要臆测。
5. 每个 finding 必须给出当前文件位置、触发 interleaving、失败模式、影响、最小修复方向和验证建议。

请优先审查这些区域：
- 全局生命周期：启动、detached threads、SIGTERM/SIGINT、周期 `snortSave()`、`RESETALL`、退出时 socket/线程/FD 状态。
- 热路径边界：`PacketListener` 锁外准备与 `mutexListeners` 共享锁内判决，确认没有阻塞 I/O、同步 socket write、重锁链或可能饿死 exclusive lock 的路径。
- Conntrack/IPRULES：`Conntrack` lockless lookup、epoch/retire/free、`inspectForPolicy()` 与 `commitAccepted()` 分离、snapshot/cache 与 `ct.state` 的一致性。
- Manager 并发：`DomainList` 聚合快照、`DomainManager` domain/IP 锁序、`BlockingListManager` snapshot/save、`AppManager`/`HostManager` 返回 shared_ptr 后的生命周期。
- Control/stream：legacy/vNext 命令的 shared/exclusive lock 分流、stream ring/pending、慢读客户端、同步 write 背压、session detach/resetAll FD 生命周期。
- 持久化与 reset：save/restore/reset 与控制面 mutate、DNS/packet 热路径之间是否存在撕裂、死锁或迭代器失效。

审查方法：
1. 先画出锁图：`mutexListeners`、各 manager mutex/shared_mutex、stream mutex、conntrack shard mutex、socket write mutex。
2. 再画所有权图：全局单例、shared_ptr 快照、raw pointer/Entry、FD/session key、thread_local cache。
3. 搜索并分类所有 `std::thread(...).detach()`、`shared_lock`、`lock_guard`、`unique_lock`、`atomic_*`、`new/delete`、`write/read/poll/accept`。
4. 对每个疑点给出最小 interleaving，例如：control mutate vs packet hot path、save vs reset、slow stream reader vs RESETALL、conntrack expire/free vs lockless lookup。
5. 最后给出动态验证建议，优先复用现有入口：host gtest/ASAN、TSan 专项、dx-smoke、IP matrix/stress/perf；不要新造大测试框架。

输出格式：
- `CRITICAL`：可导致崩溃/UAF/数据竞争/永久死锁/错误放行或错误拦截。
- `HIGH`：可导致退出卡死、热路径长时间阻塞、状态表污染、严重观测撕裂。
- `MEDIUM`：低概率 race、背压风险、锁序脆弱、异常路径资源泄漏。
- `LOW`：可维护性风险、缺少断言/注释/测试但当前未能证明会出错。
- `Needs Dynamic Verification`：静态无法确认但值得用 sanitizer/stress 验证的项。
- `No Finding Areas`：说明你检查过但未发现问题的关键区域。

每条 finding 模板：
- 标题：`[Severity] 一句话问题`
- 位置：当前文件和函数
- 当前代码事实：引用关键逻辑，不要引用旧文档行号
- 触发 interleaving：线程 A / 线程 B / 资源顺序
- 失败模式：deadlock / data race / UAF / leak / hot-path stall / wrong verdict
- 影响面：控制面、DNS、NFQUEUE、conntrack、stream、保存/退出
- 最小修复方向：只描述方向，不实现
- 验证建议：最小 host/device/sanitizer/stress 入口

参考准则：
- C++ Core Guidelines CP 并发规则：避免 data races、固定锁顺序、不要在持锁时调用未知代码。
- SEI CERT CON53-CPP：多锁必须有预定义顺序。
- Clang ThreadSanitizer：用于数据竞争验证。
- Clang AddressSanitizer/UBSan：用于内存错误和 UB 验证。

请开始 review。