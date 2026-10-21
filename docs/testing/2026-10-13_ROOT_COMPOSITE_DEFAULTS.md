# Root 组合参数默认采用与真机回归

日期：2026-10-13。用户在[容量实验](2026-10-13_ROOT_NFQUEUE_CAPACITY_TUNING.md)之后确认“按照组合参数来吧”。本次将五项数值落实为启动默认值，并安装默认 batch＋packed APK；这是用户选择扩大容量后的实现记录，不将此前未通过的整链 CPU 或完整吞吐资格改成通过。

## 当前默认值

| 项目 | 新默认值 | 实际边界 |
| --- | --- | --- |
| 每 lane 普通接收槽／pending 身份 | 128 | 另有8个 reserve 槽；启动预分配，包路径不增长 |
| Root 每目标 owner primary credits | 48 | VPN仍为32；每次启动恢复对应 profile 的默认值 |
| readiness read budget | 16 | 每次 callback 最多读取16个 datagram，已有子集立即提交 |
| `SO_RCVBUF` 请求 | 1 MiB | 普通 socket option；Pixel 实际返回2 MiB，其他内核可能限额，记录真实返回值 |
| NFQUEUE maxlen | 4096 | 四条原生队列；flags仍为9 |

集中定义见 [`product_root_defaults.h`](../../src/product/vpp/product_root_defaults.h)。primary/completion ring 仍为64/128 slots，Flow仍为每worker1024；W2、canonical FlowOwner和immutable origin completion保持原合同。socket配置或读取有效值失败时，启动不注册可用listener。

Android与Linux构建入口、插件CMake默认启用现有batch实现和packed独立verdict窗口，默认构建不再需要环境变量选择；Root资格计数随batch启用。Android默认构建证据已核对这三个开关及packed模式。历史显式OFF／scalar／sendmmsg对照入口保留。

**产品采用现有连接稳定的队列分配。** 原实验Z通过固定测试端口规则让UDP实际进入两条lane，该夹具不能直接用于所有应用。本轮没有把夹具规则变成默认hook，也没有实现通用按端口分流器；因此五项数值采用不等于在任意连接上复现Z的双lane吞吐。下面的正确性案例明确使用双lane夹具，两个吞吐启动检查使用原产品hook。

## 实现与构建身份

Product源码闭包 `d223ea615269219020ac076cf96838403a5048e9dd983b76fda204f443a204e2`，共1339个文件。APK SHA256 `844b339d7d848dee854ffc54b9e685bdf158f52f8d9720ef088c45ddc4531a03`。对应unstripped插件重新strip后与APK插件逐字节一致；安装的全部12个原生载荷、UID12632和KernelSU grant均核对。

[`product_root_defaults_test.py`](../../tests/host/product_root_defaults_test.py)编译实际adapter及共享graph启动方法，覆盖默认启动、16-read callback、池守恒、重启清除诊断值、Root48／VPN32、socket限额返回和listener注册前失败。13项相关Host检查首轮11项通过，pending/capacity两项遇到ASan启动异常。独立空程序16次中PIE崩溃5次，no-PIE全部通过；这两项fixture改用no-PIE，保留ASan/UBSan，四项相关检查随后全部通过。首轮失败与空程序结果保留，不计为产品正确性通过。

[构建与全部源码hash](../../build-output/root-composite-defaults-20261013/android-current/build.json) · [APK](../../build-output/root-composite-defaults-20261013/android-current/apk/sakamoto-runtime-debug.apk) · [默认启动Host检查](../../build-output/root-composite-defaults-20261013/defaults-test-final.log) · [初次Host结果](../../build-output/root-composite-defaults-20261013/host-tests.log) · [ASan运行器检查](../../build-output/root-composite-defaults-20261013/asan-empty-runtime-probe.json) · [修正后的四项检查](../../build-output/root-composite-defaults-20261013/host-tests-asan-corrected.log)

## Pixel 实际回归

generation2059直接启动取得五项默认值，没有数值调参命令。wire-only固定双lane夹具发送512包，256 ALLOW全部到达，256 DROP均未到达，Q=512；两条lane分别捕获并结算256包，内核ID缺口0。一次判决故障仍只尝试一次并进入失败结算，正常停止的原生债务、hook和队列检查通过。先前generation2057在实际发包前因旧peer PID准备失败，原结果保留；更新夹具身份后的2059是单独记录。

[完整ALLOW/DROP与故障检查](../../build-output/root-composite-defaults-20261013/semantic-android-current-fresh-peer/result.json) · [保留的准备失败](../../build-output/root-composite-defaults-20261013/semantic-android-current/result.json)

原产品hook下预注册两个6秒窗口，预热1秒、固定排空1秒、4线程×16连接、1200B payload、burst16；无重试，启动前先证明原生退出再force-stop测试app。默认值在两次独立启动中均生效。

| 档位／generation | payload发送／送达 | 端点 Mbps | Q／native成功 | primary拒绝 | 入口旁路／乱序／内核ID缺口 | 完整策略资格 |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| 8kpps／2060 | 47992／47992 | 76.66 | 50168／50168 | 0 | 全为0 | 通过 |
| 16kpps／2061 | 95856／95856 | 153.03 | 97986／97990 | 4 | 全为0 | 未通过 |

Q包含延迟探针，不等于payload数量。两个采集结果均为COMPLETE、原生停止清理均通过；16k的4次primary拒绝仍是未完整判定的包，Q/native为99.995918%，不能将无丢包解释为完整策略吞吐。两个短启动检查没有建立稳定16k容量或整链CPU收益，也不是原双lane Z的重复对照。

[冻结协议](../../build-output/root-composite-defaults-20261013/smoke-protocol.json) · [两个窗口汇总](../../build-output/root-composite-defaults-20261013/smoke-summary.json) · [8k原始结果](../../build-output/root-composite-defaults-20261013/smoke/udp8000/result.json) · [16k原始结果](../../build-output/root-composite-defaults-20261013/smoke/udp16000/result.json)

普通VPN generation2062实际仍采用32 credits，6000包全部收发，停止后原生进程消失。原collector因停止日志审计失败保留INCOMPLETE；VPN专用日志在停止后不可用，Root的s242归档属于generation2061，不能代替VPN的native-zero证据。补充审计仅确认收发、Stopped和进程消失，不声称VPN原生债务日志已核实。

[VPN原始结果与错误](../../build-output/root-composite-defaults-20261013/vpn-regression/result.json) · [VPN证据范围](../../build-output/root-composite-defaults-20261013/vpn-regression-audit/result.json)

## 安装后状态

保留用户选择的新APK，通过正常配置API恢复测试前完整空配置，original revision970推进到saved/active976，retained history1907；未回写旧二进制配置。generation2063为Stopped，Root原生债务0、产品hook／queue不存在，UID与Root grant保持。核对独占peer的exe／argv／hash后退出，peer PID及本次VPP／generator／monitor／simpleperf均不存在，Openwrt_5G及192.168.4.151保持。

[原规则恢复](../../build-output/root-composite-defaults-20261013/final-restoration/result.json) · [最终只读设备检查](../../build-output/root-composite-defaults-20261013/final-device-readonly/result.json) · [peer退出](../../build-output/root-composite-defaults-20261013/peer-cleanup.json) · [实现与证据闭包核对](../../build-output/root-composite-defaults-20261013/final-proof.json)
