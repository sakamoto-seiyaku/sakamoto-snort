# Pixel 6a：admit／owner 批量路径的 30 秒复测

**长测完成，没有稳定复现此前的交付吞吐涨幅。** 两对比较的方向相反，
原路径自身也有明显时间漂移，因此本轮不能证明稳定提升或稳定退化。
“CPU／入图包没有下降”也不能概括成“吞吐没有改善”：
[此前五秒测量](2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_BATCH.md)中 VPN 的交付确实增加了约 13.6%。
本次按用户要求延长测量，并把交付吞吐与 CPU／交付量作为主要指标。

## 测量配置与耗时

Root、普通 VPN 各采用 `原→批→批→原`，每窗口 **30 秒**，每条件累计 60 秒。
8 窗口累计采样 240 秒，包含暖机、诊断和正常清理的整轮耗时 **323.289 秒**。
本次是单独长测，deadline 为 600 秒；既有日常 quick entry 的 120 秒限制不变。

两种路径使用同一个 opt-in Native APK `26938cd5…`，核对原始 1,213 文件 source
snapshot、匹配 ELF、APK、UID、rules、两个 worker、credits=32。
4 I/O threads ×16 个固定 UDP 流，1,200-byte datagram；源端口 `42000+2*i`、
目标端口 `41320+i`。相同 profile 的四窗共享 generation／PID，Profile 之间正常停止。
产品源码全程保持恢复后的基点，没有重新修改 Native 实现或容量。

helper 延长 client／monitor 时限，并把有界 sequence bitmap 从 2²⁴ 扩为 2²⁷，
以保持长窗口的 duplicate accounting。原四类 socket workload、固定五元组重放、
duplicate／reset 和新边界检查通过；两种路径使用同一新 helper。
首次 250ms 冷 TCP 暖机收到零字节，尚未产生任何计分窗口；正常清理后，
在计分前将两个 profile 的初始暖机统一延长为 3 秒。该失败记录完整保留。

## 实际交付结果

| 模式／对照 | 原路径 Mbps | 批量 Mbps | 批量变化 |
| --- | ---: | ---: | ---: |
| Root 第一对（原→批） | 542.36 | 552.70 | +1.91% |
| Root 第二对（批→原） | 517.44 | 452.07 | −12.63% |
| VPN 第一对（原→批） | 95.84 | 71.63 | −25.26% |
| VPN 第二对（批→原） | 69.88 | 76.46 | +9.42% |

以下按累计交付字节、累计窗口时长和累计 VPP CPU 加权，CPU/GiB 越低越好。

| 指标 | Root 原 | Root 批 | VPN 原 | VPN 批 |
| --- | ---: | ---: | ---: | ---: |
| 交付 Mbps | 529.90 | 502.38 | 82.86 | 74.05 |
| VPP CPU seconds／交付 GiB | 16.113 | 16.878 | 197.245 | 220.747 |
| admission kpps | 19.977 | 20.491 | 35.955 | 33.490 |
| admit clocks／包 | 123.63 | 126.72 | 51.99 | 45.47 |
| primary rejection share | 0.696% | 1.238% | 1.710% | 2.245% |

累计交付变化 Root **−5.19%**、VPN **−10.64%**；CPU／交付 GiB 变化
Root **+4.75%**、VPN **+11.91%**。VPN 的局部 admit clocks／包仍下降 **12.54%**，
但这没有构成两对一致的交付改善。

## 漂移与下游证据

VPN 原路径两个窗口从 95.84 降到 69.88 Mbps，自身下降约 27.1%；两个 worker
仍接近满载，每个 30 秒窗口记录约 56.5～56.7 CPU seconds。电池温度由 33.5°C
升到 35.4°C；这不是 CPU die 温度或降频证明。本次没有采集 CPU frequency／thermal
throttling，也不能把漂移直接归因于温度、网络或某一段代码。

去除前 3 秒和尾部后，VPN 四窗的逐秒交付中位数依次约为 **94.51、65.67、
66.49、63.04 Mbps**。这些是 host receive interval，不是与手机时钟精确同步的接收窗。
两个反序对照仍受时间漂移影响，累计均值不能单独确定批量改动的因果效果。

VPN Flow Stack 四窗的 accepted originals 分别为 299,533／223,862／238,975／218,371；
rejected originals 为 849,991／742,015／759,559／752,609。本轮增长的 failure reason
全部为 `PACKET_CREDIT`。这证明满压配置存在下游 credit 拒收，不能只用 admit 节点
节省或 CPU 利用率判断整体处理效率。

Root 可见 ingress bypass share 为原 32.756%、批 33.187%，且 admission pps
按窗口明显变化。端点交付仍不能当作全部经过策略的 goodput。Peer CPU 最高约
14% 单核，未见 peer CPU 打满；没有观察到 duplicate、malformed、sequence／tuple
overflow、Flow capacity miss 或 owner failure。

## 证据与收尾

[完整结果与比较](../evidence/2026-10-11-vpp-admit-owner-long/run-warmed/comparison.json)、
[逐秒交付 CSV](../evidence/2026-10-11-vpp-admit-owner-long/run-warmed/peer-rates.csv)、
[原始 CLI／CPU／client／peer／温度记录](../evidence/2026-10-11-vpp-admit-owner-long/raw.tar.gz)、
[事前协议及暖机修正](../evidence/2026-10-11-vpp-admit-owner-long/pre-registered-long-protocol.json)、
[零计分暖机失败](../evidence/2026-10-11-vpp-admit-owner-long/zero-score-warmup-failure.json)
均保留。原五秒证据没有覆盖。

原始 node counter、实际 queue tail、同窗 CPU、capture progress 独立重算通过。
两种 profile 正常清理，Root native debts 全零、residue clean；受控 peer 已关闭。
手机已恢复进入实验前的 R0 APK `d4aab5db…`，UID／rules 不变，普通 Root／VPN
启动停止各一次通过；产品源码始终未改变。
[恢复验证](../evidence/2026-10-11-vpp-admit-owner-long/rollback-runtime-result.json)已留存。

离线复核使用新的输出目录，不操作手机、不改写冻结输入：

```sh
rtk proxy python3 docs/evidence/2026-10-11-vpp-admit-owner-long/analyze-long.py \
  --output /tmp/vpp-admit-owner-long-recheck-<unique>
```

结论限于这两对 30 秒窗口。数据支持“此前短窗涨幅尚未稳定复现”，不支持
“局部成本降低所以一定有整体收益”或“CPU 利用率不降所以一定没有收益”。
