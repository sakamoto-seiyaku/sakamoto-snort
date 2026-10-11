# DNS 关联使用范围：原设计与 Portmaster 核对

研究日期：2026-10-08。针对用户否定“已知 App 的 DNS 记录只供该 App 使用”的新建议，
核对当前已接受语义与 Safing Portmaster 官方源码。这是参考证据，不新增关联范围决策。

固定快照为 `13a86a43cc6cee592395fcddc8387178f290f144`。
本日复核官方主干 HEAD 为 `882d900dadb6df91150cf87f0a12706d29172586`（2026-10-06 提交）；
下面涉及的 `dns.go`、`connection.go`、`ipinfo.go`、Linux 监听四个文件与固定快照逐字节一致。[当前源码][S7]

## 核对结论

Portmaster 使用 **profile 关联优先、global 关联回退**。
已识别普通调用者的记录只写入其 profile；系统 resolver／未识别调用者的记录写入 global。
后续连接先查自身 profile，查询出错再查 global，不遍历其他普通 profile。[保存范围][S1]、[连接查询][S2]

因此，刚才建议的“已知调用者隔离、系统代查共享”大方向与这份源码接近，
但需要说明 profile 身份与查询顺序，不能将其直接等同于 Android 的“同一 App 才能使用”。
我们原设计尚未选定这一范围划分；用户否定新建议，也没有选定把所有已知 App 记录写入 global。

## Portmaster 的具体行为

### 1. 关联按 profile 保存，不按 PID 保存

`IPInfo` 的 `ProfileID` 注释明确称其用途为 process group 的范围；
数据库键为 `cache:intel/ipInfo/<profileID>/<ip>`，不包含 PID。
进程通过匹配取得 profile，profile ID 与进程 PID 是不同身份。[关联键][S3]、[进程取得 profile][S4]

同一 profile 下的进程能够使用同一组关联。
这个机制不能直接等同于 Android package／UID，也不能把 Sakamoto 的 Runtime Profile 当成该 profile。

### 2. 普通调用者不会顺便写一份到 global

`UpdateIPsAndCNAMEs` 对 `UnidentifiedProfileID`、`SystemResolverProfileID` 选择 global，
其他情况选择 `localProfile.ID`。`SaveIPsInCache` 只读写传入的这一范围。
所以普通 profile A 的答案不会由该函数同时进入 global。[范围选择与写入][S1]

Linux 的 systemd-resolved 结果监听另有明确路径：`processAnswer` 调用
`saveDomain(..., IPInfoProfileScopeGlobal)`；`saveDomain` 把该范围传给关联保存函数。
这条路径没有把结果还原为原调用应用。[Linux 监听][S5]、[监听结果保存][S6]

### 3. 连接查自身 profile，查询失败才查 global

连接已有域名时跳过该关联回退；没有域名且具有 local profile 时，先查该 profile＋目标 IP。
第一次 `GetIPInfo` 返回任何错误，才查 global＋目标 IP；源码条件并不限于 `ErrNotFound`。
成功取得 profile 记录后直接使用它，不合并 global，不扫描其他 profile。[连接查询][S2]

若成功取得的 profile 记录没有域名，`MostRecentDomain()` 返回 nil；
这不是一次查询错误，因此该分支也不会因此再查 global。[连接查询][S2]、[域名选择][S3]

以下为这组函数推出的行为，假设连接无直接域名、具备 profile，并且相应查询没有其他错误：

| 已有记录 | 后续连接 | Portmaster 查询结果 |
| --- | --- | --- |
| 仅 profile A 有 `a.example → IP` | profile A 连接 IP | 使用 A 的记录 |
| 仅 profile A 有该记录 | 不同 profile B 连接 IP | 不取 A；B／global 都无记录时无关联域名 |
| 仅 global 有系统解析记录 | profile B 连接 IP | B 查询失败后使用 global |
| B 与 global 对 IP 各有记录 | profile B 连接 IP | 使用 B，不合并 global |

### 4. 范围选择与多域名选择是两个问题

`AddDomain` 把更新的同名记录移到末尾；`MostRecentDomain` 取末尾的一条，
没有要求候选唯一，也没有在该函数逐条检查 DNS TTL。[域名选择][S3]
Sakamoto 已接受“只有一个有效候选才提供回退域名，多候选则不可用”。
这是明确保留的差异，不因参考 Portmaster 而改成取最近域名。[ADR-0011][L1]

## 原设计已接受什么、仍未接受什么

原用户方向是：系统代查无法确定原 App 时，保留真实 IP—域名证据；
实际业务连接再按自身应用与可用域名证据判断。DNS 查询阶段与业务连接阶段分别作决定。
当前 ADR 同样要求系统答案不虚构原调用 App，并保留来源与解析上下文。[ADR-0011][L1]

已接受的关联约束还有唯一有效候选、暂定两小时窗口，以及换网重置受影响路径的活跃关联。
当前定义保留“已知或未知应用来源”，没有直接规定已知来源记录仅能被同一 App 查询；
具体关联准入／上下文合同仍待明确。[ADR-0011][L1]、[Domain-IP Association 定义][L2]

刚才的同 App 使用限制是新的建议，已被用户否定；本次核对只纠正其依据。
Portmaster 的两级范围是可讨论的参考，Android 身份映射与 Sakamoto 是否采用该范围仍未定案。
本次只静态阅读官方源码与当前领域文档，没有导入参考代码、查阅已删除 C++ 产品源码或运行产品验收。

## 用户随后暂缓此项

用户要求先不纠结应用／profile分组与跨应用使用的IP—域名关联范围，
等实际数据后再讨论，继续其他DNS行为设计。此项没有选定同App专用或全部已知记录全局共享；
此前确认的查询过滤、直接域名来源、唯一候选回退、临时两小时窗口与换网重置保留。

[S1]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/dns.go#L230-L342
[S2]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/network/connection.go#L561-L609
[S3]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/resolver/ipinfo.go#L103-L205
[S4]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/process/profile.go#L17-L41
[S5]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/interception/dnsmonitor/eventlistener_linux.go#L121-L145
[S6]: https://github.com/safing/portmaster/blob/13a86a43cc6cee592395fcddc8387178f290f144/service/firewall/interception/dnsmonitor/module.go#L64-L79
[S7]: https://github.com/safing/portmaster/tree/882d900dadb6df91150cf87f0a12706d29172586/service
[L1]: ../adr/0011-application-dns-filtering-root-and-vpn.md
[L2]: ../../CONTEXT.md#domain-policy
