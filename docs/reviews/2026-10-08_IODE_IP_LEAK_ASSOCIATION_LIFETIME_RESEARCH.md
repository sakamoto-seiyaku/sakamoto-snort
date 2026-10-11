# iodé ip leak：IP—域名关联的有效期

2026-10-08。回答用户关于短 DNS TTL 与连接域名回退的疑问。本记录调查官方外部上游，不恢复或引用本项目已移除的 Snort C++ 源码；文末记录用户随后确认的临时关联期限。

## 来源与版本

官方项目为 [os/public/blocker/iode-snort](https://gitlab.iode.tech/os/public/blocker/iode-snort)。本次通过官方 GitLab REST API 核对 `staging`，固定提交为 [`ed728a4918511afe844dd391b130e587f0cc9459`](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/commit/ed728a4918511afe844dd391b130e587f0cc9459)，提交时间为 2026-09-17。

此前研究使用的 `5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9` 不是本次观察到的分支头。两版本的 `Domain.cpp/.hpp` 相同，Settings 的变化没有修改下面的 4 小时默认值。这是固定源码证据，没有核验实际设备的配置或发行构建。

## 结论：有有效期，但独立于 DNS TTL

`Settings::reset()` 设置 `maxAgeIP = 3600 * 4`，即默认 **14,400 秒／4 小时**。`Domain::validIP()` 检查当前 Unix 时间与 `_timestampIP` 的差是否小于等于这个值；它不读取 DNS RR TTL。[默认值][settings]、[有效判断][validity]

```text
可用于 ip leak = 当前时间 − 该域名的地址更新时间 ≤ maxAgeIP
```

`MAXAGEIP` 控制命令可读取或设置此值，帮助文本明确单位是秒。setter 保存配置，启动恢复可以覆盖源码默认值，所以不能声称每台设备必定使用 4 小时。[控制命令][control]、[配置 setter][settings-setter]、[保存与恢复][settings-save]

## 哪些事件刷新期限

| 事件 | 源码行为 |
| --- | --- |
| 收到解析返回的 IPv4／IPv6 地址 | `Domain::addIP()` 把 `_timestampIP` 更新为当前时间 |
| 再次收到相同地址 | 时间仍会更新；更新时间在集合插入之前，不要求地址是新成员 |
| 普通业务包使用该关联 | 只检查 `validIP()`，不刷新地址时间 |
| DNS 记录的 TTL 到期 | 这个 daemon 的关联判断没有 RR TTL 输入，不能据此触发 TTL 失效 |

这些结论来自 [Domain 的地址插入][add-ip]、[DNS 地址接收][dns]与[包层使用][packet]。时间戳是 **整个 Domain 共用一个**，不是每个 IP、每个 RR 或每个 App 各自一份。[Domain 字段][domain-fields]

DNS `getips` 分支会先移除该域名原有地址集合及反向索引，再接收新的地址。每个收到的地址进入 `addIP()`，因此更新时间指收到解析结果的时刻，不证明发生了新一次上游查询。IPC 只传 hostname、UID、地址 family 与地址，没有 TTL 字段；原 Android resolver 的答案缓存仍是另一项职责。[DNS consumer][dns]、[移除地址][remove-ip]、[既有系统集成调查](2026-10-04_IODE_DNS_REFERENCE_ASSESSMENT.md#原resolver缓存地址映射与上游不是同一职责)

## 过期停止使用，不等于立即删除

包层取得 Host 关联的 Domain 后检查 `validIP()`；过期时只将本次判断的局部 `domain` 置空。`ip leak` 阻断需要同时满足开启 `blockIPLeaks`、政策判断为 blocked、关联仍有效；过期后这个阻断分支不成立，接口等其他判断仍执行。[PacketManager][packet]

`validIP()` 本身没有删除地址或索引，也不清空 Host 中缓存的 Domain 指针。明确的地址删除发生在 `removeIPs()` 等调用中，不能把年龄失效说成刚到时限就物理清理所有关系。[有效判断][validity]、[删除][remove-ip]、[Host 缓存][host]

保存 Domain 时也保存原 `_timestampIP`；当前保存格式在恢复地址后读回这个原时间，DomainManager 随后重建地址索引。因此普通保存／恢复不是从启动时重新赠送 4 小时。较旧保存格式的兼容分支不同，本轮没有进行强杀或掉电持久性验收。[时间保存与恢复][domain-save]、[索引恢复][manager-restore]

## 用短 TTL 举例

假设 10:00 收到 `a.example → 203.0.113.10`，DNS TTL 是 60 秒，且未修改默认 `maxAgeIP`。iodé 的关联年龄判断仍可持续到约 14:00；普通业务流量不会把这个截止时间往后推。如果 11:00 再收到该域名的解析地址，域名级时间重新更新，默认年龄窗口计算到约 15:00。

这只是上述代码的时间线推演，还需满足实际 Host 绑定与政策分支。它不意味着 DNS 答案可以按 4 小时缓存，也不证明每个关联 IP 在这 4 小时内始终属于该域名。

## 对当前设计的启示与限制

- DNS 答案缓存用于回答查询，其 TTL 与连接用的 Domain-IP Association 保留窗口可以分开。上游采用独立年龄窗口，说明后者不必直接跟随短 RR TTL。
- 上游反向 IP 索引是单值 `try_emplace`；已有 Host 又缓存 Domain 指针。这不等于保留全部候选或证实唯一域名，地址更新也不能直接解释成所有已存在 Host 的绑定已同步更新。[反向索引][reverse-index]、[Host 创建／复用][host-manager]
- 本产品仍保留已经选择的唯一有效候选才回退、多个候选只观察、直接协议名字优先等约束。调查阶段没有改变这些规则或决定照搬上游的 4 小时，用户随后确认的独立临时窗口见下文。[当前决策](../adr/0011-application-dns-filtering-root-and-vpn.md#association-ambiguity-choice-2026-10-08)

## 用户随后确认：独立临时窗口为 2 小时

用户接受将 DNS 答案缓存 TTL 与 IP—域名关联有效期分开，暂用 **2 小时（7200 秒）**作为关联过期窗口，后续可优化或重新设计。过期关联退出后续域名回退查找，没有其他有效候选时域名保持不可用，其他规则照常执行；历史记录可保留。答案缓存继续遵循 TTL，详细刷新与已有 Flow 事实存续仍待定义。[正式记录](../adr/0011-application-dns-filtering-root-and-vpn.md#provisional-association-age-choice-2026-10-08)

[settings]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Settings.hpp#L95
[validity]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Domain.cpp#L18
[control]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Control.cpp#L385
[settings-setter]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Settings.hpp#L174
[settings-save]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Settings.cpp#L21
[add-ip]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Domain.hpp#L81
[dns]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/DnsListener.cpp#L46
[packet]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/PacketManager.hpp#L43
[domain-fields]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Domain.hpp#L24
[remove-ip]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/DomainManager.cpp#L67
[host]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Host.cpp#L11
[domain-save]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/Domain.cpp#L20
[manager-restore]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/DomainManager.cpp#L120
[reverse-index]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/DomainManager.hpp#L111
[host-manager]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/ed728a4918511afe844dd391b130e587f0cc9459/src/HostManager.hpp#L73
