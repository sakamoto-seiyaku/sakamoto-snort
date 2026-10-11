# iodéOS 系统 DNS 改造：ROM 接入、同步判定与启动边界

2026-10-04。用户明确授权研究外部官方 iodéSnort 及关联组件；本轮只读官方源码、manifest和文档。
未操作设备、执行模块/部署脚本、安装、编译、导入或移植上游代码，未修改产品/ADR/Plane；未读取本仓库被ADR-0008删除的Snort C++、archive或POC。
上游C++仅用于说明其机制，不能作为当前VPP-native C产品模板。组件/App/政策消费者的补充见[组件研究](2026-10-04_IODE_COMPONENTS_DNS_RESEARCH.md)。

## 仓库身份与固定范围

iodé官网正式把源码入口指向 `gitlab.iode.tech`，并说明当前为自托管GitLab；旧 `gitlab.com/iode/...public_archive` 不能作为当前源码身份。[官方入口][O1]
本轮使用公开GitLab REST API读取固定commit，无token/登录cookie；网页首页遇访问限制不代表下面的公开API不可读取。

| 官方仓库（均位于`gitlab.iode.tech/os/public/`） | 本轮分支 → 固定commit |
| --- | --- |
| `manifests/android`（project206） | `v7-staging` → `48e5b5689047e9077523f98b23efa5d838a13d2a` |
| `lineage/packages_modules_DnsResolver`（86） | `v7-staging` → `8cc3ff9369c49107a030ea9ed17cedf7816db342` |
| `blocker/iode-snort`（142） | `staging` → `5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9` |
| `lineage/frameworks_base`（147） | `v7-staging` → `1afa96acf6f82188159d31d863ca5dbe8dbdaab6` |
| `lineage/system_sepolicy`（146） | `v7-staging` → `8e5a217307b1e1c67fbd3f6a722363627894c367` |
| `lineage/vendor_extra`（345） | `staging` → `187ec0ba3b9d3a8b0c762653c8e9a375632d548a` |

固定manifest声明AOSP `android-16.0.0_r4`、默认LineageOS `lineage-23.2`、iodé remote `v7-staging`；DnsResolver重定向iodé仓库，而system/netd仍取默认LineageOS仓库。[manifest][M1]
snippet把daemon放进 `system/iode-snort`，另列NFQUEUE等关联组件；没有把上述分支头冻结为一个已发布设备build。[组件manifest][M2]
因此这些是可复查源码快照，**不是某台量产设备或完整生产release的二进制闭包**。分支名、default_branch和文件更新时间都不能替代实际release身份。

## 实际系统解析通路

官网机制说明称在系统发出DNS前过滤，并明确App自带DoH绕过系统resolver时不覆盖；“MITM”宣传措辞不能据此推断TLS解密。[官方机制说明][O2]
固定源码中的核心改造位于 `DnsProxyListener::GetAddrInfoHandler::run`，新增通往 `/dev/socket/iode-snort-netd` 的Unix `SOCK_SEQPACKET` 同步事务。[resolver改造][R1]

```text
App系统getaddrinfo → netd内DnsProxyListener
  → 原网络blocked检查 → iodéSnort同步verdict/getips
  → 如需解析：原evaluate callback → 原resolver/cache/PrivateDNS上游
  → 可回传IP给iodéSnort → 如政策拒绝则不给App成功答案
```

这不是“把每次RPC塞进evaluate_domain_name callback”的实现；RPC写在handler中，调用原callback以前。
同一固定头文件仍要求evaluate callback不得sleep/RPC；该合同不证明新增handler IPC非阻塞，也不能把这两处接点混为一谈。[callback合同][R2]

| 固定代码位置 | 源码事实 |
| --- | --- |
| R1:942–950 | `maybeFixupNetContext`后先检查原网络blocked，禁止时返回EAI_FAIL，不向iodéSnort请求放行 |
| R1:943、967–971 | 发送hostname长度（含NUL）、hostname和`mClient->getUid()`；随后同步读取两个bool：verdict、getips |
| R1:978–985 | sock无效、verdict允许或getips要求取地址时，才调用原evaluate callback和`resolv_getaddrinfo`/DNS64 |
| R1:990–1018 | getips时回传family与IPv4/IPv6原地址，末尾family=-1；不是daemon向resolver直接提供DNS答案 |
| R1:1020–1025 | 若解析成功但verdict拒绝，释放结果并返回EAI_NODATA |

允许分支继续原callback链；产品不能从这套模式推导可以删除系统/OEM网络权限检查。直接政策拒绝时无需再执行lookup，也不会把原deny改成allow。
UID来自实际DNS客户端socket，不是前台Activity UID。IPC没有发送netId、dns/app mark、flags、RR TTL或完整CNAME链；不能补造这些上下文。
resolver仍保留完整 `mNetContext` 供原解析/权限判断使用；daemon仅靠这条消息取得hostname/客户端UID和随后可选地址。

## cache 与 getips 的真实含义

新增判断发生在调用原lookup之前；原 `res_send.cpp` 仍先查resolver cache，命中直接返回，未命中走其原PrivateDNS/普通上游并保存结果。[cache/传输][R3]
因此系统resolver cache命中并不绕过这次handler判定；App自身cache/已持有地址不产生新的系统调用，不能据此承诺会重新判定它们。
消费者计算 `getips = verdict || settings.getBlackIPs()`：允许请求通常需要回收地址；拒绝请求在getBlackIPs开启时也要求解析地址。[DNS消费者][S1]
所以**部分被拒域名仍会执行原lookup，可能触达上游**，再阻止把成功结果交给App；“拒绝都在发上游前终止”不是这个固定实现的完整描述。
getips没有绕过原cache，也没有新建iodéSnort DNS/TLS客户端；DoT/DoH继续属于系统resolver。[R1][R1]、[R3][R3]
回传的是地址列表，不是wire答案cache；政策、IP关联与cache职责须区分。本文不从这一协议推导可供产品复用的完整TTL缓存。

## 真实入口覆盖边界

本轮同一文件中，raw `ResNSendHandler`、`GetHostByNameHandler`、`GetHostByAddrHandler` 保留原evaluate/lookup，但没有R1这一段iodéSnort socket事务。[其他入口][R4]
因此只能确认**此改造的getaddrinfo入口**，不能仅因它在DnsResolver内就宣称每种系统解析API都经过相同前置iodé判定。
这也不等于整个iodéOS没有其他包层控制；其daemon另有NFQUEUE组件，其他通路的端到端阻断应分别取证，不能拿其存在填补此处源码缺口。[daemon构建][S2]、[组件manifest][M2]
App自带DoH/自发DNS、直接IP及内部cache仍是另外的入口；官网也明确自带DoH的限制。[O2][O2]

framework补丁是另一条 `Activity → IActivityManager → ActivityManagerService → iode-snort-control` 的TOPACTIVITY通知。[Activity][F1]、[AMS][F2]
它用于前台活动状态，不是该DNS请求的UID来源，不应拿它替代R1里读取的实际客户端UID。

## ROM 如何把依赖装在一起

daemon `Android.bp` 是 `system_ext_specific` 的系统binary，并声明 `init_rc:iode-snort.rc`；vendor product.mk同时打入daemon、名单、默认App数据及Iode App。[daemon构建][S2]、[产品构建][V1]
RC由init创建root所属的control/seqpacket socket，daemon为class main、disabled，再于early-boot enable；不是等待用户UI启动后才创建DNS消费者。[启动RC][S3]
系统sepolicy建立iodesnort domain，并允许netd连接专门DNS socket、system_server/platform_app连接control socket。[访问规则][P1]
文件contexts指定binary、配置、`/data/snort`及两种socket标签，private policy用init_daemon_domain完成ROM内的启动domain过渡。[标签][P2]、[domain][P3]
这套源码、打包、init和SELinux一起发布，解释了它如何不要求用户App通过su授权获得系统能力；不等于把同一个.so挂到任意ROM即可复现。

README明确这是作为iodéOS组成部分使用的系统部分；官网发行材料是ROM/OTA/fastboot镜像。[项目用途][S4]、[发行入口][O1]
在本轮核查的官方manifest、构建文件、项目用途和发行文档中，未找到官方通用KSU/Magisk整库替换发行的证据；这是有限检索结果，不是宣称此类第三方项目不存在。
此前本机Sucré模块属于另一份历史材料，不能借此叫作iodé官方模块或把其单机声明外推为官方跨ROM支持。

## IPC故障与ready：事实、推断和撤回

verdict初始true、getips初始false；创建/setsockopt/connect失败且保留默认值时，原callback与resolver继续执行。[R1][R1]
普通r/w失败会关闭sock并令其为-1，触发原lookup；**最终结果仍受已读到的verdict影响**：若先读false、再读getips失败，最后仍可能EAI_NODATA，不能概括为任意通信错误最终放行。
resolver socket没有NONBLOCK、SO_RCVTIMEO或显式deadline；consumer直接read/write，也没有本条事务的超时机制。[R1][R1]、[S1][S1]
connect失败的恢复分支不能处理“peer已accept却不回答”；这是同步等待的具体边界，未证明实机发生卡住。

main初始化时持mutexListeners独占锁，并等待初始化线程join；DNS消费者取得该锁的共享模式后才读取/判定请求。[main初始化][S5]、[消费者锁][S1]
因此listener开始listen不等于policy ready；初始化尚未释放锁时，已连接查询可以等待。是否存在实际长等待、资源上限或完整恢复，未做设备验证。
之前把“packages.list缺失/EOF必然触发无限retry并阻碍ready”作为故障推导，**本轮撤回**：读代码时遗漏了ifstream move assignment对exception mask的影响。
LLVM libc++的ifstream move assignment经base swap交换exceptions；新ifstream默认mask会换入，不能仅看旧exceptions设置和catch循环就证明缺失/EOF进入该重试。[标准库实现][L1]、[mask交换][L2]
这不是对目标ROM实际libc++的运行验证；保留的确定边界是初始化锁等待和同步IPC无显式deadline，不以未证包列表失败链强化风险结论。

R1把mHost的`^`转换为nullptr后，新增RPC段使用 `strlen(host)`而无同处null guard；应核对输入可达性和相关特殊入口处理，不能声称本轮已观察到崩溃。
这些具体代码边界不否认ROM集成方案的成熟价值；也不构成“ROM能用，所以所有Root模块安全”的证据。

## 对当前讨论的启示，尚未进入实现合同

可借鉴的分工是：以实际请求UID/名字做政策判断，放行保留系统resolver的cache、DNS64、PrivateDNS与原上游，不在这一职责中重造DNS客户端。
iodé提供的是“ROM内handler同步询问独立daemon”的现成机制证据；我们此前“晚启用的小shim只读本地DNS投影”是不同部署/同步合同，不能说已由iodé源码证明实现。
若比较部署，需同时比较resolver构建、IPC消费者ready、原callback、init、SELinux和实际入口覆盖；仅搬库或搬socket名字不闭合这些条件。
源码分支随Android/LineageOS线维护，当前manifest已明确16/23.2；这支持按对应ROM源码维护，不支持无验证的通用二进制模块。
当前产品仍由VPP管理active配置/统一政策；上游源码只作外部机制参考，不复制其规则引擎、C++daemon或数据模型。

[O1]: https://iode.tech/documentation/gitlab-projects/
[O2]: https://blog.iode.tech/how-does-the-iode-blocker-work/
[M1]: https://gitlab.iode.tech/os/public/manifests/android/-/blob/48e5b5689047e9077523f98b23efa5d838a13d2a/default.xml#L8
[M2]: https://gitlab.iode.tech/os/public/manifests/android/-/blob/48e5b5689047e9077523f98b23efa5d838a13d2a/snippets/iode.xml#L3
[R1]: https://gitlab.iode.tech/os/public/lineage/packages_modules_DnsResolver/-/blob/8cc3ff9369c49107a030ea9ed17cedf7816db342/DnsProxyListener.cpp#L937
[R2]: https://gitlab.iode.tech/os/public/lineage/packages_modules_DnsResolver/-/blob/8cc3ff9369c49107a030ea9ed17cedf7816db342/include/netd_resolv/resolv.h#L109
[R3]: https://gitlab.iode.tech/os/public/lineage/packages_modules_DnsResolver/-/blob/8cc3ff9369c49107a030ea9ed17cedf7816db342/res_send.cpp#L508
[R4]: https://gitlab.iode.tech/os/public/lineage/packages_modules_DnsResolver/-/blob/8cc3ff9369c49107a030ea9ed17cedf7816db342/DnsProxyListener.cpp#L1231
[S1]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/DnsListener.cpp#L46
[S2]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/Android.bp#L6
[S3]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/iode-snort.rc#L6
[S4]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/README.md#L3
[S5]: https://gitlab.iode.tech/os/public/blocker/iode-snort/-/blob/5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9/src/iode-snort.cpp#L49
[F1]: https://gitlab.iode.tech/os/public/lineage/frameworks_base/-/blob/1afa96acf6f82188159d31d863ca5dbe8dbdaab6/core/java/android/app/Activity.java#L2350
[F2]: https://gitlab.iode.tech/os/public/lineage/frameworks_base/-/blob/1afa96acf6f82188159d31d863ca5dbe8dbdaab6/services/core/java/com/android/server/am/ActivityManagerService.java#L19950
[V1]: https://gitlab.iode.tech/os/public/lineage/vendor_extra/-/blob/187ec0ba3b9d3a8b0c762653c8e9a375632d548a/product.mk#L43
[P1]: https://gitlab.iode.tech/os/public/lineage/system_sepolicy/-/blob/8e5a217307b1e1c67fbd3f6a722363627894c367/public/iode-snort.te#L25
[P2]: https://gitlab.iode.tech/os/public/lineage/system_sepolicy/-/blob/8e5a217307b1e1c67fbd3f6a722363627894c367/private/file_contexts#L974
[P3]: https://gitlab.iode.tech/os/public/lineage/system_sepolicy/-/blob/8e5a217307b1e1c67fbd3f6a722363627894c367/private/iode-snort.te#L1
[L1]: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxx/include/fstream#L1135
[L2]: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxx/src/ios.cpp#L337
