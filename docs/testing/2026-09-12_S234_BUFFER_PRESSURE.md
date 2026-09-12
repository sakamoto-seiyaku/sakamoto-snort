# S234 END buffer pressure：登记与证据

2026-09-12，在采集压力结果前登记。任务状态以 Plane SAKAMOTO-234 为准。
本实验不修改 allocator 返回值，不申请整机级 OOM，不添加 pending/retry/emergency
pool。压力来自真实 UDP 创建的 owner-local entries 在同一次受控 input 调用中依次
close，每次照常申请一个 native END；graph 在该次调用返回后才消费这些 END。

## 固定输入与边界

- 同源 Linux/Pixel source A：
  `ac9cfc6384f317e590ad7356fdb26bef272d4cbe91f9455517357a73ac1a5a5f`。
  VPP pin、双 worker、Root 四 lane、64+8/lane 固定接收池及原 API 保持不变。
- `buffers { buffers-per-numa 512 }` 为实验启动值，不是产品默认值；实际 pool
  total/available/per-thread cache、映射字节、buffer/data/entry sizeof 和进程 RSS
  都从本次进程读取。VPP 对齐/页映射造成的实际数量不能用 512 替代。
- FlowRuntime 仍为 1024 entries/owner、预分配且不 resize。批量 close 的独立实验
  命令最多 1024 次，按指定 UDP endpoint port 过滤，不触碰其他 flow；这不是自动
  expiry scheduler 的 batch 参数或产品流容量上限。
- Pixel 开始前必须 stopped、无旧 native，MemAvailable 至少 512 MiB；APK/native
  hashes 读回一致。使用 `./dev/adb`，保留 KernelSU grant，结束后由 app STOP 清理。
  Linux 只运行在 disposable user/network namespace，不修改 host 网络。
- Android 的 debug-only startup 输入只在新的 runtime 生效；normal START/RESUME
  清除该实验配置，release app 忽略它。退出后 Root 原始 native 日志在清 profile 前
  保留，不能依靠 collector 抢读来制造已观测 fatal 的假象。

## 分阶段判据

1. 正常：少量真实双栈 UDP entry 的批量 END 全部到达 consumer、terminal、free
   callback；没有额外 verdict。流池/END debt 归零后仍能重新建流；orderly stop
   逐项 drain 的证据与 fatal 分开。
2. 临界：在无其他待处理包时，根据实际可供目标 owner 申请的 global available +
   own cached，关闭到只余 1 个可申请 buffer。记录 batch return 前的真实计数，
   不是 free 完后的宽裕水位；所有 END 最终回收，再发送新包成功。
3. 耗尽：同样的实际池与真实 entries，预排队 close 数量比目标 owner 可申请数量多
   至少 1，使用该 owner 的真实触发包驱动。必须观察 allocator 返回 0、明确 fatal
   reason 与该进程退出；没有 batch_end/正常 finalize 冒充成功。已分配 END、仍
   linked entry、未完成触发包分别计入进程终止后的 OS reclaim。
4. 恢复：fatal 后、任何新 generation 启动前，用新 UDP/TCP 请求证明系统连接恢复。
   Root queue-bypass 允许失去 listener 后的新包通过；仍须核验 supervisor 撤销本
   产品 hooks/queues/FD、保护停止。旧 queued packet 不承诺送达、不物理重发 verdict。
   Linux native-only 对应只声称该平台实际可见的退出/新流恢复与本测试私有 hooks 清理。
5. Pixel 受监督的显式新 START 必须新 generation、新 FD/池，重新捕获并执行策略，
   再正常 STOP。Root 当前没有自动重启循环，不把显式重启宣传为 automatic recovery。

本轮连接恢复目标：fatal 后首个**新请求**在 2 秒内成功；平台清理完成的观测上界
5 秒。记录 native CLOCK_MONOTONIC 与同设备 endpoint/control clock，外部采样只给出
上界、不宣称精确 callback 时间。若不满足，结果 HOLD 并检查有限范围原因，不以调大
阈值或“重启后成功”覆盖。native orderly drain 沿用既有 2 秒预算。

## 独立证据要求

保存原始 startup/memory/RSS/pool、NFQ packet bytes、端点 nonce、consumer/free
序列、实际 allocator pressure 记录、process/FD/queue/hook 与 app state 时间线。
verifier 自行核对 tuple/owner/entry/END 与 terminal conservation，不信 collector 的
PASS 字符串；fatal 未完成部分不要求伪造零计数。语义反例修改 raw 并重算 hashes，
覆盖假 allocator failure、绕图 release、临界水位不成立、漏清理、旧代重用和假端点恢复。

容量结果只适用于这台设备、这次 pool/entry 配置与流量形态。此实验不会将启动的空闲
内存估计升级为运行期保证，也不定义发行默认容量或整体性能结论。

## 首次运行后的窄范围修正

source A 的 normal/near 在 Linux 和 Pixel 均完成。Linux 的第 86 次 END allocation
实际返回 0：85 个 END 已分配、尚未进入 consumer，pool global/own cached 均为 0。
随后的 `clib_panic` 经 pinned VPP abort/SIGABRT 路径进入系统崩溃转储；两个新 UDP
请求仍分别超时。该机 `core_pattern` 为 WSL crash-capture pipe；本实验不修改它。
原始失败保留于 `linux-a-1`，不能记为 PASS。Pixel A 的同类 fatal 与新 LAN 请求能
恢复，但不推翻 Linux 的失败。

source B：`63d1f51527799baed13e42f51ad20f4595069335d7e700b8f49715b29b4f377f`。
只把**已明确检查的 END allocation failure**改为记录 `exit_code=70` 后 `_exit(70)`，
不经过 abort/core dump。这仍是已接受的 runtime 退出策略，由 OS 回收未完成 native
所有权，supervisor 撤销平台接管；不增加补偿池/重试、不声称 orderly drain。其他
identity/corruption panic 不改。后续复测使用 source B，预登记的池/流量/时间判据不变。

## Source B 主验收结果

独立 verifier 已通过 `build-output/s234-20260912/linux-b-2/verified.json` 和
`pixel-app-b-2/verified.json`。原始 source/native/APK、编译器、dirty diff 和 helpers
分别记录在 `{linux,pixel}-build-b/build.json` 及其 `helpers/helpers.json`；原 build
witness 未被测试 helper 改写。

```text
source_sha256=63d1f51527799baed13e42f51ad20f4595069335d7e700b8f49715b29b4f377f
api=product_core.api/1.0.0@7477ac3b
Linux plugin=7ae012a49b89cbdbb85dfa695b2f6f58081d1e4b499897f436104a9bcab075f2
Pixel plugin=415318a061b870b3a39a9db33a62cfe76d8b6532ac64960bdc0821b2932721de
Pixel APK=3d5f880e4351a8bfa572f1a21986dd93c18977ed901f297837e7de069789bcdd
```

| 预算/观测 | Linux | Pixel |
| --- | ---: | ---: |
| 配置 buffers-per-numa | 512 | 512 |
| 真实 native pool total | 373 | 350 |
| Root 四 lane 固定占用 | 288 | 288 |
| 目标 owner 初始可申请 | 85 | 62 |
| 每 owner FlowRuntime 预分配 | 237888 B | 237888 B |
| sizeof FlowEntry / END overlay | 216 / 56 B | 216 / 56 B |
| sizeof native buffer / data room | 256 / 2048 B | 256 / 2048 B |
| 正常阶段建流前 VmRSS | 199016 KiB | 66664 KiB |

两端 buffer arena 实际映射均 2 MiB：Linux 为一个 2M arena page、4K subpage；
Pixel 为 512 个 4K pages。buffer 的 alignment/page holes 解释配置数量不等于实际
可分配数量的边界，不能按 512 个 usable buffers 计算。END 零 payload 仍消耗完整
native buffer 的物理槽；56-byte overlay 不是额外 heap allocation。
Pixel 运行前 MemAvailable 为 2473060 KiB；建流前 RSS 不是批量 END 的精确峰值。

每阶段重新启动，先创建真实双栈 UDP flows；目标 owner 0 的 close 按 test port
筛选，owner 1 的两条对照流不被批量关闭。production INPUT 偶发的其他应用流不被
屏蔽或当作跨代残留：verifier 要求它们在本代 raw 中有真实 creation 证据。

| 阶段 | Linux | Pixel |
| --- | --- | --- |
| normal | g23410，8 END，28 capture/terminal，正常 drain | g1346，8 END，56 capture/terminal，正常 drain |
| near | g23411，84 END，batch 返回前仅余 1 buffer | g1347，61 END，batch 返回前仅余 1 buffer |
| fatal | g23412，第 86 次 allocation 返回 0，85 END 尚未消费 | g1348，第 63 次 allocation 返回 0，62 END 尚未消费 |
| recovery | g23413，重新建流/8 END/正常 drain | g1349，新的 RuntimeService START、重新建流/8 END/正常 drain |

同一 UDP echo 在私有 hook 的 Linux 有 2 次 capture；Pixel 的生产 OUTPUT/INPUT
规则对 app-UID 客户端及 echo 服务双方共捕获 4 次，不能按 nonce 数直接误判重复 verdict。
每个实际 queue/packet/token 仍只有自己的唯一 syscall 和 buffer return。

fatal 时，Linux 最后快照的 88 个 entries、85 个 END，Pixel 的 65 个 entries、
62 个 END，均由 OS 随该进程退出回收；不是 native free callbacks 已运行。每端还有
1 个已 capture 的触发包未得到 native verdict，该次 UDP echo 超时，不承诺旧包送达。
没有重试该 packet ID、借用首包或偷偷调用直接正常 finalize。

同一目标设备命令在触发包的 200 ms 接收等待后立即创建全新 TCP/UDP IPv4/6 socket，
无需 host 轮询或新 VPP generation。首个新 echo 距实际 allocator failure 的上界为
Linux **214.821 ms**、Pixel **272.722 ms**；包含实验主动等待，不是固有 dataplane 延迟。
Linux native 已退出的观测上界 266.132 ms，此时私有 hooks 仍在、queue-bypass 生效；
之后测试移除其私有规则。Pixel supervisor 保护停止/清理后 state 的观测上界
**1281.071 ms**，随后核验生产 hooks/queues/FD 已消失，才显式 START 新 generation。
Pixel 四个新请求来自真实 app UID，端点在独立 LAN 主机，不是设备 loopback；未绑定
旧 VPN 或用新 VPP 转发来掩盖故障。两项预登记时间目标均满足。

Linux 的重启由独立 native collector 发起，不冒称 Linux 已有 Android supervisor；
Pixel Root 当前保留显式重启，不引入自动崩溃循环。平台强制 VPN lockdown 未被改变。

`test_s234_buffer_pressure_negatives.py` 的 Linux 23、Pixel 24 个语义反例全部拒绝，
各自 `negative.json` 保存原因；变更 raw 后先重算 hashes，不能只靠 hash 不一致拒绝。
覆盖假 allocator failure、仍有可申请缓存、abort 路径、fatal 后伪造 orderly free、
临界水位、owner/generation、entry 变更、普通 END、端点恢复时间和 queue/hook/protection
残留。生产退出码 70 另由实际进程退出结果/RuntimeService 错误投影核对。

Linux B 首次 collector 把旧 CLI 名写成 `product root-nfqueue stop`，实际返回
unknown input；独立 verifier 因缺 native orderly drain 拒绝。改为当前 `product root
stop`、显式核验 stopped 与 native pools 全归还后重采 B-2。该原始失败保留，不伪装为
产品已走过 orderly drain。Pixel B-1 中其他应用的本代正常 INPUT flow 则按真实 creation
核验，不通过清空设备其他流量来满足错误的“启动快照必须永远空表”假设。

## 回归与结论范围

- Source B 的 S225 Linux/Pixel 各两代 normal/early-free/same-tuple-new-slot 完整
  验收均 PASS，目录 `end-{linux,pixel}-b/verified.json`。
- 30 个适用 host contracts 与 Android host contract PASS；S225 已说明的五个
  历史文本断言失败仍保留，没有恢复旧行为或声称全套通过。
- Source B 的 Pixel VPN active-stop/外部 native-exit 回归 `vpn-b` PASS：
  g1350→1351、g1352→1353 每代都有两个 owner × TCP/UDP × IPv4/6 的 8 条真实
  TUN/Direct flow；正常三代 orderly drain，外部退出代明确 OS reclaim，恢复代成功。
  这是受影响 supervisor/网络退出路径回归，不冒充 VPN 的真实 allocator 耗尽矩阵。

最终 Pixel 为 g1353、VPN stopped、`mayBeActive=false`、`pid=-1`，error 为空。
本轮端点、测试地址、native processes、queues 及本产品 hooks 已清理，未清除应用数据。

结论：在上述 Pixel/Root 与 Linux 条件下，checked allocation failure 的退出与
恢复可接受；原 abort/core 路径不可作为及时释放 NFQUEUE 的保证。512 的实验配置
只有很小 END headroom，不能充当发行推荐值；本次不选择正式 VPP/flow 容量，不证明
整机 OOM、任意后台流量/批量、长期内存稳定性或所有平台的 release readiness。
