# Pixel 6a：VPP admit frame 与 owner 批量发布实验

**结果：机制已生效，有效性门槛未通过，实验实现已撤回。**
Root 和普通 VPN 均实际执行 whole-frame 输入准备、四包前瞻和 native owner
批量发布。VPN 的 admit 节点 clocks/包下降 37.85%，但整体 VPP CPU/包增加
0.36%；Root 的整体 CPU/包下降 1.75%，节点 clocks/包增加 8.93%。没有一个
profile 同时达到事前要求的两项 10% 降幅，因此停止后续 packet-path 优化。
源码与 Pixel APK 已恢复到实验入口版本；两次普通启动／停止验证通过。

后续用户要求延长测量。上面的 FAIL 仅指事前 CPU／入图包门槛，不能概括成
“交付吞吐没有改善”：五秒 VPN 端点交付增加约 13.6%。
[两对 30 秒复测](2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_LONG.md)改以交付和 CPU／交付量为主，
出现对照方向相反及明显时间漂移，没有稳定复现该短窗涨幅。原始五秒结果不改写。

这是一次快速筛查。此前 [B1／B2／B3 的撤回记录](2026-10-11_PIXEL6A_INCREMENTAL_BATCH.md)
和本次实验分别保留；本次不将调用组织变化本身认定为整体收益。

## 入口、实现与判定约束

用户要求先清理工作区、提交，再开始实验，并先验证有效才能继续。
开始前，既有工作完整提交为 `6c5a6c8b`（runtime）、`4b16b3a9`（benchmark）和
`09f494b7`（文档及既有证据），确认工作区干净，然后建立
`experiment/vpp-admit-owner-batch-20261011`。实验的基点为
`09f494b7ae46bbe69c442acb44580d712990f43e`。

本次只覆盖一段连贯路径：Root／TUN 本回调形成 VLIB frame → admit frame
输入准备与四包前瞻 → primary owner native bulk publication。

- 使用 `vlib_get_buffers` 取得整个 frame 的 native buffer 指针；前瞻下一组四包
  的 header/data，预先计算不依赖 Flow／CT 状态的解析、canonical key 和 owner。
- 原 admit 的状态更新和存活包处理仍按 packet 顺序执行。fragment／特殊包进入
  原路径前先 flush，避免把其 side event 跨过尚未发布的普通包。
- 每包沿用原有 credit 预留，保存本地 lease／metadata 快照，在本 frame 结束时
  调用 retained native bulk API。成功发布后不再访问其 native buffer；部分拒绝
  按返回的失败索引处理，归还原 owner 的 credit，并沿用 Root typed bypass 或
  VPN runtime drop。
- scratch 每 worker 私有且有界，总计 259,584 字节；没有跨回调 backlog。
  所有回调返回路径 flush。HEV return、policy、Flow／CT、LPI、completion return、
  两份 payload copy、kernel I/O 方式、两 worker 和原有容量限制不在本次变更范围。

实现由 compile-time opt-in `SAKAMOTO_PRODUCT_ADMIT_BATCH_EXPERIMENT=ON` 启用。
同一个 instrumented ELF 的 runtime selector `product admit-batch baseline|batch`
只在 active、empty graph 和 CLI worker barrier 下切换；默认为 baseline。
实验没有以编译配置不同的两个 ELF 作性能比较。

完整 [实验 patch 压缩件](../evidence/2026-10-11-vpp-admit-owner-batch/experiment.patch.gz) 和
[构建 manifest](../evidence/2026-10-11-vpp-admit-owner-batch/build-manifest.json) 已留存。
独立 build 目录强制重新编译改变的输入，核对 compile definitions、native symbols、
1,213 个源码输入 hash、匹配的 unstripped ELF 和 APK。APK 的 `classes.dex` 与
其余 11 个 native library 保持一致，仅 Product plugin 改变。
本次没有使用或恢复已移除的 Snort C++ product，也没有导入 C/VPP POC 实现。

事前 [判定文件](../evidence/2026-10-11-vpp-admit-owner-batch/pre-registered-gate.json)
要求 batch 的 vectors/call ≥4、remote packets/实际物理发布 ≥4、四包前瞻确实执行；
至少一个 profile 的 admit clocks/包与整体 VPP CPU/包必须同时下降 ≥10%。
另一个 profile 的 CPU/包最多恶化 5%，两者 admission pps 最多下降 5%，remote
share 相差最多 5 个百分点，bypass／rejection share 最多恶化 3 个百分点。
identity、capture progress、资源归还和普通 lifecycle 必须通过。

## 固定流量与一次工作负载修正

Pixel 6a `28201JEGR0XPAJ`；LAN peer `192.168.4.5:41320`；Root helper UID 12632，
VPN helper UID 2000。规则文件 hash 在安装、测量和撤回期间不变。
每 profile 只有 baseline 和 batch 两个 5 秒 UDP-fixed 窗口；4 I/O threads ×
16 sockets，1,200-byte datagram，全速发送。两个条件重放同一组 64 个输入五元组。
CPU monitor 相同，未运行 simpleperf；这属于独立配置，不与此前 profiled B0 混比。
同一 profile 的两个窗口共享普通 lifetime、generation 和 PID，Root／VPN 之间正常
停止再启动。每轮含诊断与 teardown 的入口上限仍为 120 秒。

首轮固定源端口 `42000+i`、目标端口 `41320+i`，两个端口同步递增。
在现有 owner hash 和两-worker 布局下，两端低位的影响抵消，这 64 个数据流实际
落在同一个 owner。CLI 的 primary remote share 接近零，实际 primary 发布仅为
背景流量的一两包。该轮 **61.178 秒、4 窗口完成**，确认了 frame 聚合，却不足以
验证 primary bulk 发布。原数据 [完整保留](../evidence/2026-10-11-vpp-admit-owner-batch/run/result.json)，
没有将它改名为跨 worker 的成功结果或作为有效性通过证据。

随后仅在测试 helper 增加显式 source-port stride，改为 `42000+2*i`；目标端口保持
`41320+i`，四个 latency probe 使用后续四个固定源端口。改动没有触及产品 hash。
在再次测量前冻结 [修正说明、helper hash 和同一门槛](../evidence/2026-10-11-vpp-admit-owner-batch/pre-registered-balanced-cohort.json)，
额外要求实际 primary remote share 位于 10%～90%，以确认工作负载覆盖 handoff。
新 helper 的四种原工作负载、stride 1／2 的五元组重放、duplicate accounting 和
peer reset 均通过 loopback 验证，再上传并替换唯一受控 peer。没有重复原生优化、
调整 capacity 或放宽性能门槛。

均衡轮 **61.131 秒、4 窗口完成**，所有窗口 capture progress、相同 generation、
worker layout、credits=32、helper／APK／UID／rules identity 均通过。真正的 remote
share 为 49.65%～50.04%，条件间最大差异 0.264 个百分点。

## 均衡轮结果

以下是 native counter delta 和同时段 CPU 样本。负号表示成本下降。

| 指标 | Root baseline | Root batch | VPN baseline | VPN batch |
| --- | ---: | ---: | ---: | ---: |
| admit vectors | 143,457 | 141,669 | 311,622 | 310,566 |
| admit node calls | 143,457 | 4,009 | 311,622 | 6,964 |
| vectors/call | 1.00 | 35.34 | 1.00 | 44.60 |
| 成功 remote packets | 70,584 | 68,604 | 148,753 | 146,552 |
| 实际 primary queue publications | 70,584 | 3,918 | 148,753 | 6,691 |
| remote packets/实际 publication | 1.00 | 17.51 | 1.00 | 21.90 |
| 四包前瞻执行次数 | 0 | 30,034 | 0 | 69,472 |
| admit clocks/包 | 137.74 | 150.04 | 37.70 | 23.43 |
| 整体 VPP CPU µs/包 | 34.833 | 34.222 | 30.963 | 31.076 |
| admission kpps | 28.689 | 28.325 | 62.312 | 62.101 |
| primary rejection share | 0.714% | 1.228% | 2.306% | 2.822% |
| Root ingress unadmitted accept share | 32.718% | 32.929% | — | — |
| 对端 UDP delivery Mbps | 407.24 | 540.05 | 215.33 | 244.55 |

| 门槛相关变化（batch 对 baseline） | Root | VPN |
| --- | ---: | ---: |
| admit clocks/包 | **+8.93%** | **−37.85%** |
| 整体 VPP CPU/包 | **−1.75%** | **+0.36%** |
| admission pps | −1.27% | −0.34% |
| primary rejection share 增量 | +0.513 个百分点 | +0.516 个百分点 |
| ingress bypass share 增量 | +0.211 个百分点 | — |

两个 profile 的实际批量机制和退化限制均通过。唯一失败项是：没有一个 profile
同时达到节点成本和整体 CPU/包的 10% 降幅。
[原始结果](../evidence/2026-10-11-vpp-admit-owner-batch/run-balanced/result.json) 与
[事前门槛判定](../evidence/2026-10-11-vpp-admit-owner-batch/run-balanced/gate-result.json)
包含全部比较和逐项检查。

物理发布数来自各 worker primary frame queue 的 **tail delta**；未用调用数冒充
真实发布次数。admit clocks 是 VPP `stats_total.clocks` delta，不是额外的每包
计时器。整体 CPU 汇总 VPP PID 所有线程的 `/proc` utime+stime，包括 kernel CPU，
仅选 helper monotonic 窗口内样本，再按实际覆盖时长折算到完整窗口，并除以该窗口
bracket 的 admit vectors。primary remote share 包含 credit 失败的 remote eligible
包，即 transferred + graph primary rejected；不能只统计成功预留的包。

对端 delivery 两种模式都有上升，但 admission pps 没有提高，Root 仍有约三分之一
已观测入口包未进入该节点，且 kernel bypass／网络交付不等于 policy-path goodput。
这次每条件只有一个 5 秒窗口、固定 baseline→batch 顺序，没有统计置信区间、
热稳态或功耗测量。latency samples 每窗口只有 2～8 个，不作 p99 改善判断。
未改变门槛，也未把局部节点改善或端点交付变化写成整体 CPU／能耗收益。

instrumented baseline 和 batch 都有诊断计数；primary/external 调用变少也减少了这些
计数的更新次数。本轮结论限于这个筛查配置，不能直接推导无仪表产品的精确差值。
既有 [热点证据](2026-10-09_PIXEL6A_QUICK_BASELINE_AND_HOTSPOTS.md) 可提供后续讨论
背景，本次未追加 profiler，也不据此归因具体剩余热点。

## 正确性、撤回与可复核证据

发布 seam 测试抽取 **实际实验 helper bodies**，链接当前 `product_packet.c`，
覆盖 frame size 0／1／4／64／256、全部失败和无可用 credit，以及 Root／VPN 的
部分失败。native queue seam 模拟立即接管成功 buffer，禁止发布后再次读取；失败
索引故意反序返回，验证失败映射、输入顺序、原 owner credit 归还和一次 settlement。
AddressSanitizer／UBSan 通过；该测试是 queue seam proof，不是完整内核故障注入。
LeakSanitizer 因本地 ptrace 环境禁用，tested helpers 没有 heap allocation。

均衡轮 Root 正常停止的 native zero witness 包含 buffers／obligations／handoffs／
completion frames 全零，hook／queue residue clean。VPN 停止前 CLI 的 pending／
frames／buffers／obligations 全零；随后普通停止完成、VPP 退出。

失败判定后保存完整实验 patch，恢复五个被修改的 tracked product 文件至基点，移除
product 路径中的实验 include 和 runtime selector。确认 product diff 为空，并核对
R0 的 build source hash；benchmark helper 的可选固定端口功能作为测试工具保留。

Pixel 恢复 APK SHA-256：
`d4aab5dbeecab3cfabc204de29212da45f78be65227abfea4201df6b88228974`。
恢复安装保留 UID 12632、rules hash 和 KernelSU grant。独立 Root／普通 VPN
启动／停止各一次通过，最终 stopped、mayBeActive=false、无 VPP process，Root
native debts 全零、residue clean；唯一受控 LAN peer 已终止。
[源码撤回证明](../evidence/2026-10-11-vpp-admit-owner-batch/rollback-source-proof.json) 与
[恢复运行验证](../evidence/2026-10-11-vpp-admit-owner-batch/rollback-runtime-result.json) 已留存。

Git 内的 [证据目录](../evidence/2026-10-11-vpp-admit-owner-batch/) 保存两轮 JSON、
CLI／CPU／client／peer 原始压缩档、构建 manifest、事前门槛、实验 patch、匹配的
helper include 和 seam test。APK、匹配的 unstripped ELF、完整 source snapshot 及
构建日志另留在 `build-output/vpp-admit-owner-batch-20261011/instrumented/`。
这些 native 源码属于已撤回的证据，不是当前产品实现。
原始 patch／CLI 的空白及传输字符通过压缩保留，不作格式清洗。
恢复后的 Root SO_ERROR progress seam、Product VPP build/allowlist contract，以及
全部保留文件 hash 和文档链接检查通过。

可在不操作手机、不覆盖冻结证据的情况下复核：

```sh
rtk proxy python3 docs/evidence/2026-10-11-vpp-admit-owner-batch/evaluate-gate.py \
  --output /tmp/vpp-admit-owner-gate-recheck.json
rtk proxy python3 docs/evidence/2026-10-11-vpp-admit-owner-batch/transfer-ownership-check.py
```

复核脚本直接读取压缩原始 CLI 和 CPU 样本，重算 node counters、actual queue
publications 和 CPU summary，检查一致后重新应用事前门槛；重算判定仍为 FAIL。
seam test 使用保留的实际 helper，不会重新启用产品实验。
