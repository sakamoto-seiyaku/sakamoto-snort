# iodé组件：DNS消费者、地址归因与App职责

2026-10-04。只调查官方公开上游机制；承接[总评](2026-10-04_IODE_DNS_REFERENCE_ASSESSMENT.md)，与[系统补丁／部署研究](2026-10-04_IODE_DNS_SYSTEM_INTEGRATION_RESEARCH.md)分工。
本轮没有编译、安装、设备操作或产品改造；不读取或恢复本仓库被ADR-0008删除的C++／archive／POC实现。

**结论：iodéSnort是系统DNS政策消费者、地址归因和包阻断守护进程；App负责配置与展示。它没有提供可移入HEV的DoT／DoH客户端或完整DNS回答缓存。** 系统resolver仍执行解析，daemon只接主机名／UID并接收地址；公开App明确依赖iodéOS。[daemon说明][snort-readme]、[DNS消费者][dns]、[App说明][app-readme]

## 官方仓库与固定身份

官方[About页](https://iode.tech/about/)指向自有GitLab。README中的旧gitlab.com链接保留历史身份；本轮取证使用gitlab.iode.tech官方项目API。

| 组件 | 本轮固定身份 | 实际职责 |
| --- | --- | --- |
| iodéOS manifest，project206 | `v7-staging`，`48e5b5689047e9077523f98b23efa5d838a13d2a` | ROM项目地图；README称v7为活跃开发线，不能当某台设备稳定OTA源码闭包 |
| `os/public/blocker/iode-snort`，project142 | `staging`，`5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9` | C++20 system_ext daemon、DNS／packet监听、政策、状态与control API |
| `os/public/blocker/iode`，project295 | `main`，`86a593ae35fd46a8ef0482b64a435dc9da2f8992` | Flutter App，版本字段`3.1.8+72`；系统控制与统计消费者 |
| `lineage/packages_modules_DnsResolver` | manifest指向iodé remote的`v7-staging` | 系统解析补丁；固定源码与部署见系统报告 |
| `system/netd` | manifest仍指向GitHub `LineageOS/android_system_netd`，默认`lineage-23.2` | 不能因socket名含netd就把修改位置认作此repo |
| NFQUEUE配套库 | snippet显式`staging`的libnetfilter_queue／libnfnetlink／libmnl等 | 包监听依赖，不是DNS加密传输依赖 |

依据：[固定manifest][manifest]、[iodé snippet][snippet]、[构建说明][manifest-readme]、[daemon构建][bp]、[App manifest][pubspec]。
`v7`地图使用AOSP `android-16.0.0_r4`与Lineage `23.2`；project206默认分支仍为旧`v5-staging`，不能只查默认分支就断言当前Android版本。[manifest][manifest]
manifest本身固定不等于所有子项目固定：不少revision仍为branch，源码身份也不证明设备预装二进制一致。

## DNS通路：政策询问，解析仍留在系统

```text
系统DnsResolver → iode-snort-netd：hostname长度／hostname／调用UID
               ← daemon：verdict／getips
getips=true → 系统resolver实际lookup → family／IPv4或IPv6地址／-1结束符
               → daemon：更新域名地址映射与政策统计
App → iode-snort-control：规则、设置、统计查询／事件订阅
```

两条socket不是同一个API：init配置为`netd seqpacket 0600`与`control stream 0666`，具体SELinux和系统调用覆盖另见系统报告。[init配置][rc]
消费者只读长度、hostname和UID，调用`appManager.make(uid)`、`domManager.make(hostname)`及同一`App::blocked`，写出两个bool。**没有netID、网络类型、DNS type/class、完整wire、TTL或HTTP信息字段。** [DnsListener 46–76][dns]

| verdict | getBlackIPs | getips | 后续行为 |
| --- | --- | --- | --- |
| allow | 任意 | true | 系统正常解析并回传地址，daemon更新映射 |
| deny | false | false | 不为这次请求取得地址；系统拒绝处理见系统报告 |
| deny | true | true | 系统仍解析以取得地址，随后按deny拒绝向调用App交付结果 |

公式就是`getips = verdict || settings.getBlackIPs()`，默认getBlackIPs=false。拒绝时继续lookup取决于开关；不能写成所有拒绝查询都不出网，或所有拒绝查询都出网。[DnsListener][dns]、[默认设置][settings]
这也不是“仅第一次看见域名才获取IP”：所有allow都要求回传，本轮源码没有依据已有地址跳过系统解析的分支；getips=true时先删除该domain旧IP再填入新地址。
App开发设置直接发`GETBLACKIPS`、`BLOCKIPLEAKS`和`MAXAGEIP`命令，其说明把这些选项定义为对解析所得地址的泄漏阻断。[App开发设置][dev-settings]

## 地址映射不等于DNS回答缓存

`Domain`保存IPv4／IPv6集合与一个`timestampIP`；加入地址时更新时间。`DomainManager`保存名字→Domain及IP→Domain索引，并持久化域名、地址、时间和统计。[Domain][domain-h]、[保存／有效期][domain-cpp]、[索引][domain-manager]
`validIP`比较当前时间与`maxAgeIP`，默认4小时；这是地址归因的产品年龄限制，**没有来自每个DNS RR的TTL**。过期判断供packet-policy使用，不是构造缓存DNS答案。[有效期][domain-cpp]、[默认值][settings]、[packet消费者][packet-manager]

| 要求 | 本轮iodé源码情况 |
| --- | --- |
| 完整响应、问题／flags／EDNS上下文 | daemon IPC未接收；Domain只存名字和地址 |
| RR TTL递减、CNAME／附加记录寿命 | 无完整RR对象或TTL位置；maxAgeIP不能替代 |
| NXDOMAIN／NODATA与SOA负TTL | 无此回答cache合同；DNS事件只记录政策结果 |
| DoH HTTP Age与缓存键 | 没有HTTP响应输入；也没有逐查询netID／epoch |
| 命中后直接答客户端 | daemon不返回DNS答案或已有地址；系统仍解析 |
| 同问题合并与硬字节容量 | 本轮接口／地址store中未找到此合同，不能冒领 |

IP索引为单一`IP→Domain`，使用`try_emplace`；它不是同地址多域名的完整证据集合。共享IP／上下文丢失限制也说明，映射适合有限归因，不能证明某packet唯一属于某查询名。[索引声明与插入][domain-manager]
`HostManager`还建立host对象，可选`getnameinfo`反查；此举使用系统API，不是自建DoT／DoH。默认reverseDns=false。[HostManager][host-manager]、[默认值][settings]

## 规则、网络条件与遥测分别在哪里

`DomainList`读ROM名单文件的hostname／bitmask，并沿点分边界查父域。`Rule`将wildcard转为正则，`CustomRules`合并并用`std::regex_match`；这不是Snort规则语言或完整DNS引擎。[名单][domain-list]、[Rule][rule]、[自定义匹配][custom-rules]
`App::blocked`按本App白名单、黑名单、白规则、黑规则、全局白／黑规则和名单mask顺序判定；daemon拥有运行政策，App不逐查询作出判定。[政策函数][app-policy]
UID与package关系由`PackageListener`读取`/data/system/packages.list`并监视更新；不是由UI实时上传本次调用身份。[PackageListener][packages]
网络接口条件在**另一路NFQUEUE packet事实**：`PacketManager::make`收到iface索引，再读`/sys/class/net`的type／wireless分类Wi-Fi／DATA／VPN。该路径不能补成DNS IPC里本不存在的逐查询网络上下文。[packet事实][packet-manager]、[接口分类][packet-cpp]

DNS遥测是在getips协议完成后、blockEnabled且App tracked时增加`Stats::DNS`并输出`DnsRequest`。事件字段为App、domain、domMask、appMask、blocked、timestamp；没有RCODE、回答RR、上游传输、延迟或解析成功状态。[DnsListener][dns]、[DnsRequest][dns-request]
`dnsstream`的保存／horizon是事件历史；名字包含DNS不使它成为回答cache，blocked也是政策决定而非网络交换成功与否。

## App／control边界

`SnortControl`连接`/dev/socket/iode-snort-control`，失败间隔200ms重试；使用mutex串行发文本命令，读NUL结尾结果并映射JSON。App关闭连接或尚未启动，不会使daemon自动失去已保存规则。[Dart socket][app-socket]、[daemon启动][main]、[设置保存][settings-cpp]
设置库发`BLOCK`／`BLOCKMASK`／`BLOCKIFACE`；自定义库发`RULES.ADD/UPDATE`和黑白名单命令；统计读取`APP.DNS`等，实时页另开socket发`DNSSTREAM.START`。这些是配置和观察接口，不是DNS查询转发。[配置][app-config]、[control分派][control]、[实时页][app-live]
control由daemon解析并修改自身结构，再保存到`/data/snort`；这与Sakamoto的VPP政策所有权不是同一个执行实现，不能直接移入当前Product。

App的pubspec存在`http`库，但实际账户文件调用`api.iode.tech`的connect／access等HTTP API；地图使用tile cache。它们不证明App提供DNS-over-HTTPS。[账户API][account]、[App依赖][pubspec]
App README明确它为iodéOS内置组件、不能直接用于其他系统；普通安装此App不提供所需系统socket、daemon、resolver补丁或SELinux集成。[App说明][app-readme]

## 未就绪、EOF与不回答的peer

daemon main在初始化期间持`mutexListeners`独占锁，完成名单／packages恢复等工作后才释放；DNS client全程取得其shared锁。因此**开始listen与可以回答verdict并不等价**。[main 51–101][main]、[DNS client][dns]
`Settings::start`仅建目录和恢复设置；DefaultAppsManager的boot_completed等待位于detach线程。本轮不据此制造“daemon必须等UI或boot_completed”的循环。[Settings][settings-cpp]、[默认App管理][default-apps]
PackageListener虽有catch重试，读取前却以新ifstream作move assignment；libc++会连exception mask一起交换，故“缺文件／EOF必然无限重试”的先前推论撤回，不作为已知启动故障。[PackageListener][packages]、[libc++赋值][fstream]、[mask交换][ios-swap]
DNS read/write要求一次返回恰好请求长度；EOF／错误进入日志与close路径。本文件没有recv deadline、nonblocking状态机或取消／generation协议；peer保持连接却不发送下一段时，阻塞read没有可见有界结束。[DnsListener 94–104][dns]
每accept创建detach线程；listen backlog取1000，不等于active请求／线程硬限。地址回传途中还持shared初始化锁，不能把此同步RPC照搬进VPP worker。[accept与client][dns]、[设置][settings]
真实resolver的断连fallback、覆盖范围与加载风险以系统报告为准；本轮没有制造挂起peer或声称已测设备启动失败。

## 依赖、许可证与证据边界

daemon Android.bp只列libmnl／libnetfilter_queue／libnfnetlink及Android cutils／log／base；公开src未提供TLS握手、HTTP客户端、DNS wire relay／answer cache模块。其职责闭环依赖ROM DnsResolver，而非某个隐藏的daemon DoH库。[构建闭包][bp]、[DNS接口][dns]
daemon和App的LICENSE为AGPLv3正文，文件SPDX为AGPL-3.0-or-later；不将外部机制研究写成直接导入源码的授权。[daemon许可证][license]、[App许可证][app-license]
App `pubspec.lock`固定iodé自有`iode_utils`与`flutter_background_service` Git依赖；前者公开项目为492、固定`aed3bb4f826b12e5988e96c90841ebdb47eb4bca`。其Kotlin插件只提供App版本、device／IMEI／serial与启动App，未提供DNS查询；DNS socket实现就在Dart App源码里。[lockfile][lock]、[辅助项目元数据][utils-meta]、[固定插件][utils-plugin]、[socket][app-socket]
公开源码足以核对上述交互；不能进一步断言某个完整ROM／商业服务／预装APK可复现。manifest构建说明还依赖vendor/extra的Git LFS预编译App，且App README与pubspec的Flutter版本不同；本轮没有构建消解它们。[构建说明][manifest-readme]、[App说明][app-readme]、[pubspec][pubspec]

## 对当前Sakamoto问题的价值

可借鉴的是**原系统解析前作本地UID／域名政策决定，并把政策、实际解析与观察分开**；不是获得现成轻量加密DNS客户端或wire TTL cache。
系统组件替换仍要独立解决安装、版本身份和生命周期；上游整合到ROM不证明KSU挂库的通用安全性，详见系统报告。
已确认的VPN方向仍是[HEV原owner与c-ares窄改](2026-10-03_HEV_DNS_REUSE_AND_CARES_FORK_RESEARCH.md)、同Mbed TLS完整能力和小型DNS模块；本轮不重排客户端、不加入Rust运行时／DoQ或新性能方案。
产品实现仍遵守[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)、[ADR-0008](../adr/0008-remove-snort-cpp-mainline.md)：不移植iodé C++ daemon，不让packet worker同步等待App／系统RPC。
本轮在`/tmp/iode_components_dns_research`读取固定ref：daemon全部70个blob及App lib／指定metadata，再以Git blob SHA核对取得内容；只读取证，无构建、资源测量或设备覆盖证明。

[manifest]: https://gitlab.iode.tech/api/v4/projects/206/repository/files/default.xml/raw?ref=48e5b5689047e9077523f98b23efa5d838a13d2a
[snippet]: https://gitlab.iode.tech/api/v4/projects/206/repository/files/snippets%2Fiode.xml/raw?ref=48e5b5689047e9077523f98b23efa5d838a13d2a
[manifest-readme]: https://gitlab.iode.tech/api/v4/projects/206/repository/files/README.md/raw?ref=48e5b5689047e9077523f98b23efa5d838a13d2a
[snort-readme]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/README.md/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[bp]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/Android.bp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[rc]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/iode-snort.rc/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[dns]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDnsListener.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[domain-h]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDomain.hpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[domain-cpp]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDomain.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[domain-manager]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDomainManager.hpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[settings]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FSettings.hpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[settings-cpp]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FSettings.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[packet-manager]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FPacketManager.hpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[packet-cpp]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FPacketManager.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[host-manager]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FHostManager.hpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[domain-list]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDomainList.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[rule]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FRule.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[custom-rules]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FCustomRules.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[app-policy]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FApp.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[packages]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FPackageListener.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[dns-request]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDnsRequest.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[main]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2Fiode-snort.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[default-apps]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FDefaultAppsManager.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[control]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/src%2FControl.cpp/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[license]: https://gitlab.iode.tech/api/v4/projects/142/repository/files/LICENSE/raw?ref=5fc8fabc9f49587bf59a4a687f76ee4f6d15a1b9
[app-license]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/LICENSE/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[app-readme]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/README.md/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[pubspec]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/pubspec.yaml/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[lock]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/pubspec.lock/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[utils-meta]: https://gitlab.iode.tech/api/v4/projects/492
[utils-plugin]: https://gitlab.iode.tech/api/v4/projects/492/repository/files/android%2Fsrc%2Fmain%2Fkotlin%2Fcom%2Fiode%2Futils%2FIodeUtilsPlugin.kt/raw?ref=aed3bb4f826b12e5988e96c90841ebdb47eb4bca
[dev-settings]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/lib%2Ffeatures%2Fdevelopment_settings%2Fdata%2Fdev_settings_data.dart/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[app-socket]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/lib%2Fservices%2Fsocket.dart/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[app-config]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/lib%2Ffeatures%2Fcustomization%2Fdata%2Fcustomization_repository.dart/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[app-live]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/lib%2Ffeatures%2Flive_info%2Fview%2Flive_provider.dart/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[account]: https://gitlab.iode.tech/api/v4/projects/295/repository/files/lib%2Ffeatures%2Faccount%2Fdata%2Fiode_account_api.dart/raw?ref=86a593ae35fd46a8ef0482b64a435dc9da2f8992
[fstream]: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxx/include/fstream#L1135
[ios-swap]: https://github.com/llvm/llvm-project/blob/llvmorg-18.1.8/libcxx/src/ios.cpp#L337
