# 域名匹配研究：iodé 上游与 Sakamoto 最后旧实现

Date: 2026-09-15. Read-only research for Sakamoto design discussion; no source restored, ported, or implemented. This is durable supporting evidence, with revisable conclusions, not a product specification.

关联：[完整讨论记录](2026-09-14_RULE_ENGINE_DISCUSSION_TMP.md)、[后续候选调查与当前收敛结论](2026-09-15_DOMAIN_MATCHER_RESEARCH.md)。下文“候选方向”保留历史调查时的推导；当前已收敛为暂定短名单，最终库选择等待真机数据，不把较早的哈希 / trie 建议当作最终决策。

## Identity and evidence scope

The official project is [os/public/blocker/iode-snort](https://gitlab.iode.tech/os/public/blocker/iode-snort), GitLab project 142. The official [source-location documentation](https://iode.tech/documentation/gitlab-projects/) identifies iodé’s self-hosted GitLab. The project README describes the daemon as the system component of the iodé blocker for iodéOS. This establishes provenance and intended deployment, not measured performance or proof that every current device runs the inspected revision.

Pinned revisions:

- Historical fork point from the local lineage record: [e84f6faa19e3f4e152ff84709a90a1e6ce1250af](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/commit/e84f6faa19e3f4e152ff84709a90a1e6ce1250af), committed 2024-05-10.
- Public default `staging` observed during this review: [5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/commit/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9), committed 2026-03-27. The DomainList.cpp, Rule.cpp, and CustomRules.cpp content inspected at this revision matches the historical implementations described below.
- Official prepared lists are in vendor_extra, project 345, pinned to [187ec0ba3b9d3a8b0c762653c8e9a375632d548a](https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/commit/187ec0ba3b9d3a8b0c762653c8e9a375632d548a), committed 2026-08-26.

All source observations were obtained from official public GitLab REST API file/raw endpoints because the web renderer could not fetch the self-hosted source pages. Links below point to immutable source revisions.

## What the matcher actually is

The large built-in domain list uses `std::unordered_map<std::string, uint8_t>`. It is not a specialized domain automaton, trie, Aho–Corasick library, or regex-per-list-entry engine. Each key owns a hostname; the value is a category/protection mask. The query takes a shared mutex lock. [DomainList.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainList.hpp)

Lookup tries the complete name first, then strips successive leftmost labels and probes the hash table. It returns at the first matching key. For `a.b.example.com`, the candidates are the full name, `b.example.com`, and `example.com`; the bare `com` fallback is excluded. A more specific match therefore prevents consulting less specific entries. The query does not OR masks from all matching ancestors. Duplicate occurrences of the exact same stored hostname do have masks ORed during loading. [DomainList.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainList.cpp)

This gives built-in entries apex-plus-subdomains behavior with label boundaries: `example.com` can match itself and `a.example.com`, but not `notexample.com`. This is a source-derived interpretation; it is not a proposed Sakamoto default. The source does not implement case-folding, terminal-dot trimming, or IDNA conversion in this matcher.

The built-in whitelist is checked before the blacklist when DomainManager initializes a domain’s mask/color. Thus its allow/block precedence is its own product model, and must not replace Sakamoto’s already agreed full Rank rule selection. [DomainManager.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainManager.cpp)

## Exact custom entries versus wildcard and regex rules

There are separate custom-domain sets and custom-rule expressions. CustomList stores `Domain::Ptr` values in a set and checks membership; DomainManager interns domains by name. This custom-list path does not perform the built-in list’s suffix walk. [CustomList.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/CustomList.hpp), [CustomList.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/CustomList.cpp), [DomainManager.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainManager.cpp).

Rule declares DOMAIN, WILDCARD and REGEX types. WILDCARD translates `*` to `.*` and `?` to `.`, and escapes a selected set of regex metacharacters. Both other types pass their text unchanged into POSIX extended `std::regex`. Therefore DOMAIN in this particular Rule implementation is not guaranteed to be literal matching: an unescaped dot still has regex meaning. The historical wildcard escaping is less complete than the locally retained descendant reviewed by the root agent. [Rule.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/Rule.hpp), [Rule.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/Rule.cpp).

CustomRules combines valid regex text with alternation into one POSIX extended regex and calls `regex_match` on the complete domain. This is full-string matching, not substring search. Wildcards can cross dots: `*.example.com` matches nested subdomains but does not match the apex `example.com`. There is no label-aware wildcard policy encoded here. No `icase` flag is used. These are distinctions to specify deliberately, not accidental compatibility promises to copy. [CustomRules.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/CustomRules.cpp).

## Download/import formats: prepared input, not arbitrary subscriptions

The upstream daemon reads two whitespace-separated tokens repeatedly: hostname and integer mask. It is not line-based and does not parse comments, hosts address columns, Adblock network anchors/options, cosmetic rules, or arbitrary URL lists. A malformed mask stops the extraction loop. The daemon expects externally prepared hostname-mask data. [DomainList.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainList.cpp).

A bounded raw sample of official [domains-black](https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/blob/187ec0ba3b9d3a8b0c762653c8e9a375632d548a/iode-snort/domains-black) confirms hostname-mask pairs. The small [domains-white](https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/blob/187ec0ba3b9d3a8b0c762653c8e9a375632d548a/iode-snort/domains-white) also uses this format. [Android.mk](https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/blob/187ec0ba3b9d3a8b0c762653c8e9a375632d548a/iode-snort/Android.mk) installs them as prebuilt data under system_ext/etc/iode-snort; [Settings.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/Settings.hpp) selects those paths.

The official [Blocking Databases](https://iode.tech/documentation/blocking-databases/) page names Energized Protection, StevenBlack, OISD and The Blocklist Project as aggregate inputs. That does not demonstrate that the daemon parses each source’s native syntax. No aggregator/preparation script was found in the inspected iode-snort tree or its vendor_extra/iode-snort directory. Exact upstream aggregation and normalization rules remain unverified.

## Memory/copy and performance limits of the evidence

The large-list structure holds all entries in memory, with hash buckets, node/string storage and one-byte masks. No defensible per-million-host memory number can be inferred without the actual C++ library, allocator, load factor and name distribution. No benchmark was run. A query probes at most the relevant label suffix count rather than scanning the entire list; hashing still reads each candidate’s bytes. The upstream suffix walk constructs `domain.substr(...)`, so it copies suffix text and can allocate for longer suffixes. Shared query locking also differs from the planned immutable shared matcher with owner-local flow state. [DomainList.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainList.hpp), [DomainList.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/DomainList.cpp).

The regex path stores original and translated pattern strings, builds an aggregate string and a compiled regex representation, and uses a separate matching path. The source provides no fixed execution/memory bound for arbitrary regexes and no comparison against a domain-specific automaton. It should not be described as proven fastest because it is deployed in a product. [Rule.hpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/Rule.hpp), [CustomRules.cpp](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/e84f6faa19e3f4e152ff84709a90a1e6ce1250af/src/CustomRules.cpp).

Independent local history inspection identifies the last retained descendant at commit 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2, archive/current-head/src. That descendant added per-list ownership and an immutable aggregate hash snapshot, with lookup improvements; this must be distinguished from the original upstream’s shared-mutex table. This is a historical path; the archive was subsequently deleted, and it is not the current VPP-native C runtime.

## License metadata, without a compatibility conclusion

The inspected matcher source files use SPDX `AGPL-3.0-or-later`; the repository contains [GNU AGPL v3 LICENSE](https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/LICENSE). This is metadata verification, not a legal conclusion about another project.

Official vendor list attribution files separately state: iodé aggregate domains-black under AGPL v3, OISD input under GPL v3, Energized and StevenBlack inputs under MIT, Blocklist Project input under Unlicense. These are the pinned vendor repository’s recorded notices, not a guarantee that every input’s latest licensing remains unchanged. [License directory](https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/tree/187ec0ba3b9d3a8b0c762653c8e9a375632d548a/iode-snort/licenses).

## Narrow design takeaway

The reusable lesson is the separation between large prepared hostname sets and smaller expressive custom rules, and the need for explicit exact-versus-subdomain semantics. The observed upstream does not supply a universal downloaded-list parser or a specialized state machine to transplant. Sakamoto still needs its own explicit import semantics and domain predicate contract; immutable C runtime representation can then be chosen independently. This note does not propose restoring or porting the removed C++ system, adopting upstream allow/block precedence, or freezing an automaton implementation.


## 本项目最后保留版本的只读核对（主会话补充）

本次用户在 2026-09-15 明确要求参考迁移 VPP 前的最后 C++ 域名匹配。核对范围仅为历史域名匹配及上游出处；没有恢复、移植或修改旧产品实现。当前产品仍为 VPP-native C，新的匹配模块必须服从现有 owner-local 与统一规则语义。

历史对象固定为删除提交 `291da69` 的父提交 `969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2`。相关文件当时位于 `archive/current-head/src/`。这是最后保留的旧域名实现，不表示当时重建中的新主线已接入域名功能。路径追溯显示 DomainList 在 2026-06-20 随 `52dc093` 移入档案，此前 2026-04-30 的 `8ee18ae` 加入 importAtomic 等能力。

可复验入口：

```sh
rtk proxy git show 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/DomainList.cpp
rtk proxy git show 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/DomainList.hpp
rtk proxy git show 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/CustomRules.cpp
rtk proxy git show 969b19be3f37b6febcf2eb2f56fcd8ba79b14ae2:archive/current-head/src/Rule.cpp
```

### 旧版本的实际匹配语义

- DomainList 的每个列表保存 `unordered_map<string,uint8_t>`，另构建所有启用列表的聚合只读哈希快照。同一完整名称跨列表的 mask 按位 OR。
- 查询先去除一个尾点，再查完整名称；未命中时按点分隔依次查父域。实现循环不查最后的单标签后缀：例如 `a.b.example.com` 依次可查自身、`b.example.com`、`example.com`，不会以 `com` 兜底。
- 查询在首次命中时返回。因此“同名跨列表 OR”不等于“所有匹配的祖先名称都 OR”。完整名称或更近的祖先可能遮住更远祖先对应的 mask。
- 存有 `example.com` 时，列表匹配也可命中 `a.example.com`；不匹配 `badexample.com`。这属于该列表的后缀语义，不能据此把本产品所有精确域名条件都定义为包含子域名。
- 查询使用 `substr` 创建后缀字符串；是否产生堆分配取决于字符串长度与标准库的小字符串优化，不能声称每次 substr 都必然堆分配。
- read/enable 逐空白读取 hostname，并使用列表级 mask；importAtomic 接收已经准备好的域名字符串数组。这里没有完整的 hosts、Adblock 或 DNS filter 语法解析。
- CustomRules 将多条表达式合并为 POSIX extended `std::regex`，使用整个名称的 `regex_match`。为归因还保存每条正则，并按 ruleId 顺序扫描。
- Rule::WILDCARD 把星号转为任意长度、问号转为任意单字符，其他正则特殊字符转义；这种 glob 的星号可以跨点。Rule::DOMAIN 与 Rule::REGEX 都把原文本当正则。不能把历史的 type=domain 直接解释成新的字面量精确匹配。
- DomainList/Domain/CustomRules 中本次查看的匹配入口没有统一的大小写或 IDNA 归一化；这不是对所有历史输入路径的完整审计结论。
- DomainManager 的白名单优先、来源 mask 和最小 ruleId 归因，属于旧产品裁决语义，不能代替本轮已定的完整 Rank。

以上是源码分析，不是性能测量或旧验收重跑；没有验证旧实现对任意恶意正则、名单格式或输入规模的性能界限。

### 网络名单的输入语义

[AdGuard 官方 DNS filtering syntax](https://adguard-dns.io/kb/general/dns-filtering-syntax/) 明确区分纯域名、hosts 和 Adblock 风格语法。其 `example.org` 是精确名称，`||example.org^` 覆盖自身及子域；修饰符还可以增加条件或改变行为。因此导入必须声明支持范围，不能剥掉不理解的条件后扩大规则。

[DNS 大小写规范 RFC 4343](https://www.rfc-editor.org/rfc/rfc4343.html) 支持统一处理 ASCII 大小写；国际化域名、尾点和非法输入仍需要明确一致的入口契约。SNI 与 DNS 请求可共享域名匹配，但后者一般的 DNS 名称范围并不自动等同于合法 TLS 主机名范围。

### 对新设计的推导与候选方向（尚未冻结）

1. 共享域名规范化、精确/后缀等明确的名称谓词、列表标识、不可变匹配产物；DNS 请求和 VPP 数据包分别使用各自适用的规则。
2. VPP 中的应用、设备方向、src/dst、端口与 CT/LPI 等条件完整保留。域名表命中只是条件成立，不直接产生跨功能的 ALLOW/DROP。
3. 普通大量域名项适合优先考虑紧凑的只读哈希表 + 字符串存储 + 不分配后缀视图；反向标签 trie 是值得比较的另一布局。没有测量，不能声称任何一种在目标设备上最快或最省内存。
4. 普通域名名单不应先变成一个巨大正则。确实需要的 glob/regex 应保留明确语法和有界执行要求，不能因实现方便静默扩大或删减条件。
5. 去重可以共享名称存储，但必须保留名单归属、精确/后缀模式及逻辑来源。不能机械继承旧版“第一个更具体的名称命中就终止整个策略竞争”。
6. 对不同名单的命中仍由通用引擎按 `priority -> order -> ruleId`、完整表达式决定逻辑赢家，不引入域名精度或白名单的隐藏优先权。
7. 大名单产物共享不可变存储，不能每个 worker 复制全部字典。需核算字符串、索引、来源引用，以及构建/发布期间旧新产物同时存在的峰值；缓存继续以完整快照身份守卫。
8. 此轮宜先明确网络名单支持哪些语义，再选择索引布局；详细可观测性按用户指示留在域名匹配讨论之后。

## 当前相邻范围决定（防止回到中途方案）

- 本版 SNI 覆盖 TLS 与 QUIC；隧道内解析暂不支持，新增场景以后再讨论。
- DNS 请求过滤是与 VPP 平行的后续功能；DNS-IP 关联采集也是后续能力，不依赖启用 DNS 过滤。
- VPP 域名条件本版默认来自 SNI。将来可通过显式开关加入 DNS-IP 候选关联，需解释共享 IP 造成误拦等影响。
- TCP 流数据按缓存字节数有界存储，数量受已有 Flow 容量约束；不另设 32 个 SNI 解析名额。
- 流还原拥有一份解析数据拷贝，TLS/SNI 引用它，不再各自保存完整握手副本。
- 最新决定为不因等待 SNI 扣住原包：复制必要字节后，原包按当前事实正常完成。先前讨论过的 fork detain 采用方案已被这一决定取代。
- 已明确没有本版后续消费者，或 SNI 解析结束时，释放流缓存；不能把暂时未知当成确定非目标协议。
- JA3/JA4 留扩展空间，本版不实现。可观测性待域名匹配讨论完成后专门设计。
