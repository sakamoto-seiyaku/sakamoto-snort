# TRex实际模板与Pixel 6a TCP/TLS/QUIC基准

日期：2026-10-08。状态：源码/工具适配研究，不是新的性能实测或已建立的B0。用户优先级：**实际Pixel 6a上的TCP为主，同时覆盖TLS/QUIC/SNI；Root、普通VPN分开比较。Linux只作为可选对端/辅助，不能替代Android性能曲线。**

## 1. 结论

**找到了用户所指的一组实际模板，主要在相邻的`trex-helper`与`benchmarkServer`仓库，而不在VPP fork主源码。** 其中确有TLS1.3、SSL跨TCP段、QUIC等PCAP与STF模板；也有真实TCP栈驱动的ASTF连接率和大flow模板。但这些模板的执行模式与目标路径不同，不能统一称为“可直接拿来测手机App的真实TLS/QUIC负载”。

TRex可以作为受控TCP对端、外部连接压力发生器或packet corpus工具，**不是Pixel当前快速可重复主基准的必备前置依赖**。主基准应先把手机App发起的TCP bulk、fresh TLS/SNI连接及完整QUIC会话收口；如果手机测量需要更强对端，或对端已成为瓶颈，再接TRex对应模式。不能为了沿用路由器测试拓扑而把App原始socket路径换成直接NIC/TUN/graph注入。

本次完成本地源码、YAML、PCAP的只读核对，以及官方TRex/Android文档查阅；没有安装、编译、运行TRex/服务器/设备、修改外部仓库、调整网卡/hugepages、生成新性能数据或建立B0。

## 2. 搜索范围与源码身份

| 仓库/位置 | 固定身份与工作区 | 本次用途 |
| --- | --- | --- |
| `/home/js/backup/backup/Git/vpp` | HEAD `837432be3b6cf496755cfa27b7cca439734eb726`；src无tracked diff；test/Makefile与untracked复制树另列 | VPP内找到的是tracked `docs/usecases/simpleperf/trex{,1,2,3}.rst`；四份逐字节与HEAD相同。引用的TRex发行包profile不在VPP tracked树内 |
| `../trex-helper` | HEAD `c3ee051a37a67d92cd850bdfd0a0b144d0db4cee`；clean | 实际自定义ASTF/STF/STL模板、wrapper与PCAP；本次重点引用文件均核对HEAD字节一致 |
| `../trex-core` | HEAD `7f7ae22ce77b0b650a3ae4a04627eeae0cdf7071`；VERSION `v3.06`；两个driver.cpp已有修改 | 实际ASTF profile compiler/cap处理；所引Python/docs/VERSION均与HEAD一致，不把dirty driver环境称为冻结运行artifact |
| `../benchmarkServer` | HEAD `0053207cb95e9e35624e887d89235b3d0bdcaa82`；有既有文档/测试等修改 | tracked `src/trex_module.py`、`assets/*.py`和配置的实际调用链；另有untracked `trex-helper/`复制目录 |
| `../tsg-dev-docs` | HEAD `0a706373e5c39463e1a2bd30c30c3ca10018d2a0`；clean | 明确TRex配置所对应的PCI/core/hugepages服务器部署模型，所引文档与HEAD一致 |

对`benchmarkServer/trex-helper/`副本不能整体赋予standalone身份：三份`stf/{ssl-fragment,https-tls1.3-3000cps-1Gbps,mix-pkt}/template.yaml`与standalone逐字节相同，但三个ASTF脚本及主wrapper不同。ASTF副本去掉了standalone的`/etc/trex-helper/conf/astf-conf.yaml`优先覆盖；这是运行配置来源的真实区别。VPP的`test/docs`复制树同样untracked，不作为VPP固定HEAD实现证据。

扩大搜索后按文件路径及`rg -l`定位，再限定读取Python/YAML/docs与PCAP，避免展开含base64的大JSON。身份与模板判断使用对应源码/PCAP，不依赖大JSON内容；没有访问远程机器。

## 3. 找到的模板及实际执行模式

### 3.1 standalone trex-helper

| 模板/入口 | 实际调用 | 真实提供的工作 | 关键边界 |
| --- | --- | --- | --- |
| `connection --protocol tcp` → `astf/tcp_cps.py` | wrapper以`--astf -f`启动 | ASTF真TCP连接；client发送固定HTTP request bytes，server按长度接收并返回固定bytes；IP/port范围与CPS配置 | 没有TLS库、证书验证或fresh SNI协商；不是HTTP协议实现。CPS是提供目标，需核实际连接成功率 |
| `tcp-active-flows` → `astf/tcp_active_flows.py` | 同为ASTF | client循环发送约10MB的`C`buffer；server发送一次约10MB`S`；有limit/cont与TCP状态 | 属于plaintext TCP负载；不能由文件名推出无限持续双向吞吐或exact实际并发数 |
| `mix-traffic -f stf/https-tls1.3-3000cps-1Gbps/template.yaml` | wrapper只有`-f YAML`，没有`--astf` | STF smart replay：30个cap_info条目引用10份TLS capture | 是模板重播，不与fresh Android TLS client协商新会话 |
| `mix-traffic -f stf/ssl-fragment/template.yaml` | 同为STF | 28条cap_info重用一个ClientHello跨TCP段capture | 下面的PCAP审查证明它不包含完整TLS握手，SNI字节自身也未跨段 |
| `mix-traffic -f stf/mix-pkt/template.yaml` | 同为STF | 28条cap_info包含TLS/HTTP/DNS等及3份QUIC capture | QUIC packet形状重播，不等同新QUIC连接/TLS握手与应用stream交付 |
| `pkt-replay` → `stl/template_client/pkt_replay.py` | `STLClient.push_pcap` | 原包顺序/IPG/speedup/count/duration重播 | STL没有该TCP/QUIC会话的真实反馈状态 |
| `pkt-generator --protocol tcp` | 构造`Ether()/IP()/TCP()`与padding、field VM、`STLTXCont` | TCP格式packet streams、多tuple/多包长 | 选择TCP header不等于建立TCP连接；与ASTF CPS必须分开 |

调用者见[trex-helper:448](/home/js/backup/backup/Git/trex-helper/trex-helper:448)，476–502；TCP程序见[tcp_cps.py:48](/home/js/backup/backup/Git/trex-helper/astf/tcp_cps.py:48)，99–112；[tcp_active_flows.py:40](/home/js/backup/backup/Git/trex-helper/astf/tcp_active_flows.py:40)，72–98；STL见[pkt_replay.py:20](/home/js/backup/backup/Git/trex-helper/stl/template_client/pkt_replay.py:20)、[dyn_pkt_len.py:35](/home/js/backup/backup/Git/trex-helper/stl/template_client/dyn_pkt_len.py:35)。

实际CLI是`mix-traffic`、`connection`、`tcp-active-flows`等，额外TRex参数通过`--args`传递；部分模板README还写旧`stf ... args`，不能直接照抄。`connection`先写ASTF conf，global conf可能优先；STF模板占位符替换写入固定`/tmp/template.yaml`。新的可重复campaign需显式冻结配置、profile、PCAP、工具版本及run目录，避免不同轮共享配置或临时文件。[parser:776](/home/js/backup/backup/Git/trex-helper/trex-helper:776)、[conf写入:410](/home/js/backup/backup/Git/trex-helper/trex-helper:410)、[占位替换:438](/home/js/backup/backup/Git/trex-helper/trex-helper:438)。

TLS1.3模板的基础cap_info CPS合计为67，`-m45`给出3015的目标重播flow/s；其目录名“3000cps/1Gbps”是模型，不能视为Pixel已测出的能力或固定带宽。当前用户指南也明确`-m`只是倍率。[TLS YAML:431](/home/js/backup/backup/Git/trex-helper/stf/https-tls1.3-3000cps-1Gbps/template.yaml:431)、[USER_GUIDE:183](/home/js/backup/backup/Git/trex-helper/docs/USER_GUIDE.md:183)。

### 3.2 benchmarkServer：必须区分实际ASTF caller与旁边的STF资产

tracked配置实际选择`max-throughput/profile.py`与`mixed-traffic/emix2.py`；`TRexASTFClient`从assets目录解析并`load_profile`。因此这条调用链是ASTF，不是上面的STF YAML。[config:37](/home/js/backup/backup/Git/benchmarkServer/config/config.yaml:37)、[config:59](/home/js/backup/backup/Git/benchmarkServer/config/config.yaml:59)、[trex_module.py:192](/home/js/backup/backup/Git/benchmarkServer/src/trex_module.py:192)，209–223。

`max-throughput/profile.py`是plaintext大TCPflow：client发固定request并等bytes，server按loop发送buffer；profile调MSS/initwnd/tx/rx窗口。wrapper实际设置size3000KiB、loop100、MSS1460。可参考大flow和TCPtunables，但不是TLS throughput模板。[profile.py:26](/home/js/backup/backup/Git/benchmarkServer/assets/max-throughput/profile.py:26)，37–57、74–84；[caller:219](/home/js/backup/backup/Git/benchmarkServer/src/trex_module.py:219)。

`mixed-traffic/emix2.py`实际cap列表在134–163行，引用avl目录HTTP/HTTPS/mail/RTP等旧captures，没有使用同目录`pcap/quic`三份capture或`ssl/1..10.pcap`。那些PCAP由保留的`assets/mixed-traffic/config.yaml` STF配方引用。**目录包含QUIC素材，不证明当前ASTF混合profile真实覆盖QUIC。** [emix2.py:134](/home/js/backup/backup/Git/benchmarkServer/assets/mixed-traffic/emix2.py:134)、[STF config:506](/home/js/backup/backup/Git/benchmarkServer/assets/mixed-traffic/config.yaml:506)。

benchmarkServer的现有stats是TRex generator CPU、ports0/1累计bytes及latency probe histogram，不能当Pixel VPP/`:runtime` CPU或App RTT。异常时getstats返回零值，缺测不能视为零成本；正增量累计`opackets-ipackets`也不是App序号/字节交付oracle，可能混入in-flight。[trex_module.py:267](/home/js/backup/backup/Git/benchmarkServer/src/trex_module.py:267)，290–321、330–340。

## 4. SSL fragment与TLS/QUIC素材的包级证据

本次用只读`tshark -n -r ... -T fields`及独立PCAP/TCP/TLSheader解析交叉核对：[ssl-fragment.pcap](/home/js/backup/backup/Git/trex-helper/stf/ssl-fragment/ssl-fragment.pcap)共8个TCP包；所有IPv4MF/fragment offset为0，**不是IP分片**。ClientHello TLSrecord总长1818B，分别由1300B与518B两段client TCPpayload承载。消息本身是1813B（含4Bhandshake头；Hello body1809B）；server最后RST，capture没有完成TLS握手。

SNI extension在client stream offset439..460，hostname在448..460，全部落于第一段1300B之内。因此这个素材确实覆盖“完整ClientHello跨TCP段”，但**不覆盖SNI字符串本身跨段**；两者不能混说。PCAP SHA-256 `b422489f42b517bb5117113a2d894eb4cf2d48cc3a1c90abfa5d24d42321f764`，与standalone HEAD一致。

TLS1.3目录10份PCAP都能看到ClientHello/SNI以及supported_versions；抽查`1.pcap`的ServerHello选择`0x0304`，说明源capture是真TLS1.3轨迹。**capture的协议真实，不代表重播时与新的真实client执行了同样的密码学握手。** [1.pcap](/home/js/backup/backup/Git/trex-helper/stf/https-tls1.3-3000cps-1Gbps/1.pcap) SHA-256 `450aa57cd0a8882471a409801c8b83429c047ec4b19e5923fd94139f4300526a`；本文未解密应用data、检查每份完整会话或证明这些捕获没有缺包。

本地TRex-core的ASTF PCAP转换还有一项直接限制：对TCP先`cap.condense_pkt_data()`，将同方向连续payload合并，再生成`send(payload)`与`recv(累计bytes)`命令。所以把此ssl-fragment素材改成ASTF也不能自动保留原1300+518分段。SNI跨segment/record测试需另定MSS、发送/延迟、记录布局，并核实际手机wire结果，而非只选择PCAP名。[trex_astf_profile.py:391](/home/js/backup/backup/Git/trex-core/scripts/automation/trex_control_plane/interactive/trex/astf/trex_astf_profile.py:391)，1008–1028；[cap_handling.py:54](/home/js/backup/backup/Git/trex-core/scripts/automation/trex_control_plane/interactive/trex/astf/cap_handling.py:54)。

官方当前`http_https.py`同样是`ASTFCapInfo`加载HTTP/HTTPS静态captures；官方ASTF说明一方面讨论TLS目标，一方面仍把TLS支持列在on-radar。本次没有找到版本固定、与真实AndroidTLS1.3client互通的TRex TLS配置证据，不能将“HTTPS模板存在”当作已验证freshTLS能力。这里只判断审查到的模板，不断言TRex扩展/未来版本永远不能实现。[官方HTTP/HTTPS profile](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/scripts/astf/http_https.py)、[官方ASTF源码文档](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/doc/trex_astf.asciidoc)。

## 5. TRex如何接入Pixel才保持产品路径

Android的`VpnService`通过本地TUNfd读取被路由的outgoingIPpacket、写入返回packet；被测App的socket、VPN路由与protected underlay不是NIC旁路的一回事。[Android VPN官方说明](https://developer.android.com/develop/connectivity/vpn)。Sakamoto对应当前Root捕获与VPN owner-local两腿合同见[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md)、[ADR-0007](../adr/0007-owner-local-lwip-direct-egress.md)。

| 集成方式 | 可支持的测量 | 需要的路径证明 |
| --- | --- | --- |
| Pixel真实App发起TCPsocket → Root/VPN → LAN普通受控TCP/TLS/QUICserver | 主Android用户路径；最容易复用现有phone helper和原采集 | UID、profile、实际捕获/admit/terminal、两端交付、ordinaryVPN启动、无unexpected bypass |
| Pixel真实App发起TCPsocket → Root/VPN → TRex ASTF server-only | **可行的可选受控TCP对端方案**，可做plaintext bulk/约定request-response | profile正确关联dstport并匹配真实client byte程序；IP/MAC/路由及success/EOF核验；TLS/QUIC另需真正协议对端 |
| 外部TRex ASTF client → Pixel App监听socket | 可用于Root可达inbound/accept/连接压力子项 | 真实App接收与捕获范围；不自动代表普通VPN App发起的TUN/HEV路径，需单列route/provenance证明 |
| TRex/STF/STL直接打网卡、内存接口、测试TUN或graph injection | packet/parser/fragment/排序/极端压力的辅助测试 | 明标输入源及覆盖node；不能计入原始App UID capture/VPN主性能曲线 |

第二行是由官方ASTFserver-only能力、TCPassociation与本产品路径推导的适配方案，**尚未部署验证**。官方允许分开client/server运行，server依据进入流的destinationport关联L7模板；并不要求所有场景使用同一机器模拟两端。STL则是packet streams，无对应真实TCP状态。[官方ASTF client/server模式](https://trex-tgn.cisco.com/trex/doc/trex_astf.html#_client_server_only_mode)、[官方STL执行机制](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/doc/trex_stateless.asciidoc)。

VPP自带旧usecase明确是两台机器、双NIC，TRex同时模拟client/server，中间VPP转发；16/48地址池路由和ports不能直接套成手机endpoint配置。相邻benchmarkServer的memif/vhost内部链文档也属于此类受控EthernetDUT组织；不是手机App原始socket验收。[VPP trex.rst:6](/home/js/backup/backup/Git/vpp/docs/usecases/simpleperf/trex.rst:6)，61、96–97。

TRex未必要求购置物理双10G口：官方有Linux AF_PACKET/virtual接口路径、可免hugepages；但rawsocket需要superuser，文档明确L3TUN不属于其L2接口适配。DPDK路径另有NIC/core/memory配置成本；本地helper本身还会管理1Ghugepages，不能当普通无副作用python launcher。本次没有配置或执行它。[官方运行模型](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/doc/trex_book.asciidoc)、[helper:878](/home/js/backup/backup/Git/trex-helper/trex-helper:878)、[部署schema:38](/home/js/backup/backup/Git/tsg-dev-docs/docs/api-docs/os/Restconf/trex.md:38)。

官方server LICENSE为Apache2.0，Python Client单列GPLv2-or-later；本研究只读引用，不导入到产品或安排分发。[server license](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/LICENSE)、[client license](https://raw.githubusercontent.com/cisco-system-traffic-generator/trex-core/master/LICENSE_Python_Client)。

## 6. 对TCP为主的新基准意味着什么

建议主campaign按以下不同成本形状建case，**全部在同一实际Pixel6a上产生App流量，Root/VPN各自保留B0/B1/B2…曲线**：

1. **TCP bulk主项**：upload/download分别计量，必要时duplex单列；一个大flow与固定多个flow。保留25s历史模型作起点，但正式packet/CPS/Owner/frame分布读取设备事实，不能把send call当packet。Root必须先通过全路径核账，历史557/333及恢复后混合bypass轮不能升格为B0。
2. **Fresh TLS/SNI主项**：固定TLS版本、certificate、SNI/name集合；以新连接/s、完整握手成功数、post-handshakepayload交付与握手分位计量。full handshake与session resumption分开，不能让重复连接全部变成恢复命中后声称测了freshSNI。named/absence/deny是分开的语义case；跨record/segment布局另用受控输入验证实际边界。
3. **真实QUIC主项**：手机运行完整QUICclient状态机，与受控QUICserver完成TLS1.3握手及encryptedstream/HTTP3交付；记录实际协商协议，HTTP3→TCP fallback不能算QUIC成绩。新QUIC连接与established传输分别计量。协议能力可以从test-only Android HttpEngine/Cronet或经验证的QUIC库选择，不将TRex静态QUICcapture当成该能力。[Android Cronet说明](https://developer.android.com/develop/connectivity/cronet)、[HttpEngine QUIC开关](https://developer.android.com/reference/android/net/http/HttpEngine.Builder#setEnableQuic(boolean))。
4. **代表性组合**：TCP/TLS为主、QUIC占明确固定份额；zero-rule用于执行组织成本，另一组固定代表性rule/domain/LPI/SNI组合用于实际识别/查询。逐项曲线与混合曲线并存，不能由一个总体Mbps掩盖handshake/规则成本。普通UDP可保留交付回归或辅助压力，不是主基准先导。

当前Sakamoto确实已有手机真实TLS1.2基座：`ProtocolFactsProbe`使用certificate pin、`SSLSocket.startHandshake()`及加密echo。它可以作为freshTLS负载实施起点，但当前固定TLS1.2、gate/25echo/30ms间隔是语义探针，不是已存在的可定速TLS1.3CPSbenchmark。[ProtocolFactsProbe.java:121](/home/js/Git/sakamoto/sakamoto-snort/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolFactsProbe.java:121)，137–178；[t13_tls_peer.py:22](/home/js/Git/sakamoto/sakamoto-snort/tests/device/helpers/t13_tls_peer.py:22)。

当前T16/T29的QUIC证据需准确保留：server确用aioquic处理Initial并发出serverflight，手机却发送预生成Initial序列，随后使用`T15-`plainUDPecho；helper自己明确“not a completed handshake”。这是有价值的QUICInitial/SNI/CRYPTO装配与真实UDPcapture证据，**尚不是完整QUICsession/HTTP3performance基准**。[t16_quic_peer.py:1](/home/js/Git/sakamoto/sakamoto-snort/tests/device/helpers/t16_quic_peer.py:1)，129–141、145–176；[ProtocolFactsProbe.java:465](/home/js/Git/sakamoto/sakamoto-snort/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProtocolFactsProbe.java:465)，477–500、529–548。

无论使用普通peer还是TRexpeer，手机VPP/`:runtime`/负载App成本、temperature与路径有效性从Pixel采集；generatorCPU、端口latencyprobe、offeredCPS只作负载/对端上下文。总吞吐、有效交付、handshake/CPS、p50/p95/p99及CPU/资源成本分别画，不能混用取代。每轮profiling图必须绑定该轮AndroidAPK/native/symbol identity，主测与profiling扰动仍需区分，详见[临时基准讨论稿](2026-10-08_VPP_OPTIMIZATION_BASELINE_DISCUSSION_TMP.md)。

## 7. 采用判断与未完成项

已有模板已经回答“有没有参考”：**有，而且可以从TCP bulk/CPS、TLScapture、Hello跨段、mixedcorpus分别取其合适的负载组织。** 当前最快的主链不必先移植serverNICDUT拓扑；先补齐当前手机sender/真实TLS循环、完整QUICclient、统一路径oracle和轮次/symbol/曲线工具。若普通peer不能稳定提供目标负载、需要更大的可控连接压力或保留独立router/parser压力档，TRex ASTF/STF/STL各自接入对应辅助或server角色。

仍未完成的是新Pixel重复B0、Root全路径TCP有效性、真正TLS1.3CPS/完整QUIC负载及其控制工具、TRexserver-only与手机的实际互通、PCAP分段/字段组合覆盖和profiler扰动测量。源码与素材发现没有将上述项目自动变成PASS，也没有新速度/功耗承诺。
