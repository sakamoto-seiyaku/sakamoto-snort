# VPP NFQUEUE POC 实验原始记录

状态：按时间顺序追加的实验流水。这里记录真实执行路径、问题和当前进度，避免后续重复踩坑。

## 2026-06-26

### 01. Docker IPv6 NFQUEUE plain smoke

问题：不涉及 VPP 时，当前 Docker/netns NFQUEUE harness 能不能稳定 queue 和 verdict IPv6 包？

最小改动：

- `setup-netns.sh` 增加 `IP_FAMILY=inet6` 分支。
- IPv6 地址固定为 `fd00:42::1/64 -> fd00:42::2/64`。
- IPv6 规则使用 `ip6tables OUTPUT -p ipv6-icmp -d fd00:42::2 -j NFQUEUE --queue-num 42`。
- 增加 `smoke-ipv6-accept` / `smoke-ipv6-drop` / `smoke-ipv6-ratio` 入口。

命令：

```sh
./scripts/run-container.sh make smoke-ipv6-accept
./scripts/run-container.sh make smoke-ipv6-drop
```

结果：

```text
smoke-ipv6-accept: 20 transmitted, 20 received
smoke-ipv6-drop:   20 transmitted, 0 received
```

观察：

```text
hwproto=0x86dd
payload_len=104
hook=3
uid=0 gid=0 present
timestamp absent
```

结论：Docker IPv6 NFQUEUE 基线可用。下一步把同一条 IPv6 accept/drop 路径接到 VPP `nfqueue_poc`。

### 02. VPP IPv6 NFQUEUE accept/drop

问题：VPP `nfqueue_poc` 能不能绑定 IPv6 NFQUEUE 并返回 IPv6 verdict？

最小改动：

- `nfqueue_poc` CLI 增加 `family ip4|ip6`。
- `family ip6` 时使用 `nfq_bind_pf(AF_INET6)`。
- `run-vpp-nfqueue-smoke.sh` 跟随 `IP_FAMILY=inet6` 调用 `nfqueue-poc enable ... family ip6`。
- 增加 `vpp-nfqueue-ipv6-accept` / `vpp-nfqueue-ipv6-drop` / `vpp-nfqueue-ipv6-ratio` 入口。

构建：

```sh
./scripts/apply-vpp-overlay.sh
DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env TARGET=nfqueue_poc_plugin ./scripts/build-vpp-plugin.sh
```

宿主机直接构建失败一次，原因是 `work/vpp` build tree 由容器创建，宿主机 CMake 写入时遇到权限和 git safe.directory 问题。结论：这个 lane 继续在 Docker 里构建插件。

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-ipv6-accept
./scripts/run-container.sh make vpp-nfqueue-ipv6-drop
```

结果：

```text
vpp-nfqueue-ipv6-accept: ping 20/20, seen=20 accept=20 drop=0
vpp-nfqueue-ipv6-drop:   ping 0/20,  seen=20 accept=0  drop=20
handle-errors=0 recv-errors=0 enobufs=0
```

结论：VPP 侧 IPv6 NFQUEUE verdict 路径可用。下一步可以在 VPP callback 中解析 IPv6 dst，先做 hardcoded `/128` exact block。

### 03. VPP IPv6 `/128` exact dst block

问题：不做 JSON/规则系统，只在 VPP callback 里解析 IPv6 payload dst，能不能完成 exact `/128` block？

最小改动：

- `nfqueue_poc` 增加 throwaway 模式：`mode block-ip6-dst <addr>`。
- 只检查 IPv6 header destination address：payload offset 24，长度 16。
- 命中时 `NF_DROP`，未命中/default allow。
- `show nfqueue-poc` 增加 `payload-missing`、`parse-errors`、`rule-match`、`rule-miss`。
- 增加 `vpp-nfqueue-ipv6-block-peer` 和 `vpp-nfqueue-ipv6-block-miss`。

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-ipv6-block-peer
./scripts/run-container.sh make vpp-nfqueue-ipv6-block-miss
```

结果：

```text
block fd00:42::2:  ping 0/20,  seen=20 accept=0  drop=20 rule-match=20 rule-miss=0
block fd00:42::99: ping 20/20, seen=20 accept=20 drop=0  rule-match=0  rule-miss=20
```

小故障：

- 第一次 miss 验证成功但脚本打印 `integer expression expected`，原因是 VPP CLI 输出带 CR，shell 解析 `rule_miss` 时未清理。
- 已在 runner 里对解析出的 counter 做数字过滤后重跑通过。

结论：VPP callback 层可以完成最小 IPv6 exact `/128` 判定。下一步再做可加载规则文件或事件输出。

### 04. VPP NFQUEUE NDJSON event output

问题：VPP callback 返回 verdict 的同时，能不能输出足够给 Activity/Cockpit 使用的 packet event？

最小改动：

- `nfqueue-poc enable` 增加 `event-log <path>`。
- callback 中收集最小 packet facts：family、proto、payloadLen、UID、dstIp、verdict、reason、ruleId。
- 每个包写一行 NDJSON，并立即 flush。
- runner 增加 `EVENT_LOG=<path>` 和 `EXPECT_EVENTS=1` 断言。
- 增加 `vpp-nfqueue-ipv6-events` 入口，复用 `block-ip6-dst=fd00:42::2`。

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-ipv6-events
```

结果：

```text
ping 0/20
seen=20 accept=0 drop=20
rule-match=20 rule-miss=0
event-write-errors=0
event_count=20
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":20,"family":"ipv6","proto":58,"payloadLen":104,"uidKnown":true,"uid":0,"dstIp":"fd00:42::2","verdict":"block","reason":"exact_ip6_dst","ruleId":"block-ip6-dst"}
```

结论：VPP POC 可以产出基础 Activity 事件。下一步可以做最小 `rules` 加载，或先把 Android root NFQ 也验证到 UID/event。

### 05. Pixel 6a Android preflight

问题：当前连接的 Pixel 6a 是否可以继续 Android root / NFQUEUE / VPP POC？

命令：

```sh
make android-preflight
```

结果：

```text
adb_serial=28201JEGR0XPAJ
root: uid=0(root) gid=0(root) context=u:r:ksu:s0
abi: arm64-v8a
sdk/release/model: 36 / 16 / Pixel 6a
selinux: Enforcing
iptables: v1.8.11 legacy
ip6tables: v1.8.11 legacy
NFQUEUE target help: present
remote_root: /data/local/tmp/vpp-nfq-poc prepared
```

重要观察：

- 设备上已经存在 `sucre-snort_INPUT` / `sucre-snort_OUTPUT` NFQUEUE chains。
- IPv4 queue balance: `0:1` input, `2:3` output。
- IPv6 queue balance: `4:5` input, `6:7` output。
- 下一步 Android NFQ POC 应使用不冲突的窄队列，或先显式记录/清理旧链，避免误判。

结论：Pixel 6a root/NFQUEUE lane 可继续。下一步优先验证 Android 上的 VPP binary/plugin 仍可启动，再接 Android IPv6 NFQUEUE。

### 06. Pixel 6a Android VPP minimal startup

问题：现有 Android stage artifact 是否还能在 Pixel 6a 上启动 VPP，并通过 `vppctl` 控制？

命令：

```sh
make android-vpp-minimal-release-no-multiarch-no-ipsec-idle
```

使用 stage：

```text
work/android-vpp-release-no-multiarch-no-ipsec-idle-stage
```

推送后远端体积：

```text
bin/vpp: 101K
bin/vppctl: 10K
lib/libvnet.so: 7.6M
plugins/nfqueue_poc_plugin.so: 51K
plugins/tun_poc_plugin.so: 18K
stage total: 9.4M
```

结果：

```text
remote_root=/data/local/tmp/vpp-nfq-poc
process: root ... S vpp
vpp log: ***** Start: PID 3702 *****
vppctl show version: vpp v26.02-release built by js on Main at 2026-06-22T13:45:00
vppctl_rc=0
```

结论：Pixel 6a 上的 trimmed/no-IPsec idle VPP stage 仍可启动并接受 CLI。下一步可以用这个 remote root 继续 Android NFQUEUE POC。

### 07. Android nfqueue_poc family/event rebuild + CLI check

问题：今天新增的 `family ip6` 和 `event-log` 代码能否交叉编译到 Android，并在 Pixel 6a 上被 VPP CLI 接受？

构建：

```sh
./scripts/apply-vpp-overlay.sh
./scripts/apply-vpp-android-overlay.sh
make android-vpp-build-release-no-multiarch-no-ipsec-idle
```

结果：

```text
target=vpp build_rc=0
target=nfqueue_poc_plugin build_rc=0
Android nfqueue_poc_plugin.so linked
```

推送/启动：

```sh
BUILD_DIR=work/vpp-android-release-no-multiarch-no-ipsec-idle \
STAGE_DIR=work/android-vpp-release-no-multiarch-no-ipsec-idle-stage \
STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
```

更新后远端插件：

```text
/data/local/tmp/vpp-nfq-poc/plugins/nfqueue_poc_plugin.so: 55K
```

CLI 验证：

```sh
vppctl nfqueue-poc enable queue 42 family ip6 mode accept-all event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-events.ndjson
vppctl show nfqueue-poc
cat /proc/net/netfilter/nfnetlink_queue
vppctl nfqueue-poc disable
```

结果：

```text
enabled 1 queue 42 family ip6 mode accept-all drop-ratio 50 fd 12
event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-events.ndjson event-write-errors 0
/proc/net/netfilter/nfnetlink_queue: 42 ... pid 3777 ...
```

结论：Android 侧更新后的 `nfqueue_poc` 可以绑定 IPv6 NFQUEUE queue 并打开 event log。下一步插入一条不冲突的窄 `ip6tables` OUTPUT rule，验证真实 IPv6 包进入 VPP。

### 08. Android IPv6 loopback NFQUEUE exact block

问题：Pixel 6a 上真实 IPv6 包能不能进入 VPP NFQUEUE，并由 VPP exact `/128` 规则 drop，同时输出事件？

选择：

- 使用 loopback `::1`，避免依赖外部 IPv6 网络。
- 临时规则插入 OUTPUT 顶部，只匹配 `-o lo -p ipv6-icmp -d ::1`。
- 使用 queue 42，避开 preflight 看到的现有 `sucre-snort` queue `0:7`。

命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip6 mode block-ip6-dst ::1 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip6-loopback.ndjson
ip6tables -w -I OUTPUT 1 -o lo -p ipv6-icmp -d ::1 -j NFQUEUE --queue-num 42 --queue-bypass
/system/bin/ping6 -c 3 -W 1 ::1
```

第一次小故障：

- 用 `ping -6` 时 Android/system ping 报 `invalid option -- 6`，VPP `seen=0`。
- 改用 `/system/bin/ping6` 后重跑。

结果：

```text
ping: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event-write-errors=0
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv6","proto":58,"payloadLen":104,"uidKnown":true,"uid":0,"dstIp":"::1","verdict":"block","reason":"exact_ip6_dst","ruleId":"block-ip6-dst"}
```

清理验证：

```text
no vpp process
no temporary --queue-num 42 ip6tables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：Android root + VPP NFQUEUE 可以拦截真实 IPv6 包，执行 exact `/128` block，并产出 NDJSON 事件。下一步可以验证 Android app UID 维度，或先做可加载规则文件。

### 09. Android IPv6 NFQUEUE shell UID metadata

问题：Android NFQUEUE metadata 能否为非 root 进程提供 UID，作为 app-first policy 的基础？

选择：

- 仍使用 loopback `::1` 和临时 queue 42。
- VPP 用 `accept-all`，避免 block 干扰 UID 观察。
- 流量由非 root `shell` 用户执行 `/system/bin/ping6`。

命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip6 mode accept-all event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip6-shell-uid.ndjson
ip6tables -w -I OUTPUT 1 -o lo -p ipv6-icmp -d ::1 -j NFQUEUE --queue-num 42 --queue-bypass
adb shell /system/bin/ping6 -c 3 -W 1 ::1
```

结果：

```text
adb shell id: uid=2000(shell)
ping: 3 transmitted, 3 received
seen=6 accept=6 drop=0
event-write-errors=0
```

事件观察：

```json
{"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"allow"}
{"uidKnown":false,"uid":null,"dstIp":"::1","verdict":"allow"}
{"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"allow"}
{"uidKnown":false,"uid":null,"dstIp":"::1","verdict":"allow"}
{"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"allow"}
{"uidKnown":false,"uid":null,"dstIp":"::1","verdict":"allow"}
```

判断：

- shell 发起的 IPv6 loopback 请求有 UID=2000。
- 同一次 loopback ping 产生 6 个 OUTPUT 事件，3 个有 UID、3 个无 UID；后者大概率是 loopback paired direction/artifact，需要后续按 direction/hook/iface 做更清晰区分。

结论：Android root NFQUEUE 可以提供 UID metadata，足够继续 app UID policy POC；但 loopback 场景会混入 uidUnknown 包，真实 app/Wi-Fi/Mobile 规则要单独验证。

### 10. Android IPv6 NFQUEUE shell UID block

问题：用 UID 作为 app-first policy key 时，VPP 能不能按 UID 直接 block Android 流量？

最小改动：

- `nfqueue_poc` 增加 throwaway 模式：`mode block-uid <uid>`。
- 命中 `uidKnown && uid == block_uid` 时 drop，reason=`uid_block`，ruleId=`block-uid`。
- 未命中或 UID unknown 时 default allow。

构建：

```sh
./scripts/apply-vpp-overlay.sh
./scripts/apply-vpp-android-overlay.sh
BUILD_DIR=work/vpp-android-release-no-multiarch-no-ipsec-idle \
TARGET=nfqueue_poc_plugin ./scripts/android-build-vpp-probe.sh
```

结果：

```text
target=nfqueue_poc_plugin build_rc=0
```

命令要点：

```sh
STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip6 mode block-uid 2000 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip6-block-uid-shell.ndjson
ip6tables -w -I OUTPUT 1 -o lo -p ipv6-icmp -d ::1 -j NFQUEUE --queue-num 42 --queue-bypass
adb shell /system/bin/ping6 -c 3 -W 1 ::1
```

结果：

```text
adb shell id: uid=2000(shell)
ping: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event-write-errors=0
```

事件样例：

```json
{"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no vpp process
no temporary --queue-num 42 ip6tables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：Android root NFQUEUE + VPP 可以实现最小 UID-level block。这是 0.2 app 默认 block/allow 的核心可行性信号；下一步应把临时 CLI mode 替换为可加载 policy 文件，或用真实 app UID 验证非 shell app 流量。

### 11. JSON policy helper -> VPP CLI -> Android UID block

问题：不先在 VPP 插件里嵌 JSON parser，只用 host-side helper 把最小 policy 文件转成现有 `nfqueue-poc` CLI，能不能完成一次可记录的规则文件闭环？

最小改动：

- 增加 `configs/rules-block-shell-uid.json`，描述 queue 42 / ip6 / block uid 2000。
- 增加 `scripts/poc-rules-to-vppctl.py`，只支持 POC 单条 enabled block rule。
- 增加 `make poc-rules-cli-check`，先验证 JSON -> CLI 输出稳定。

本地 helper 验证：

```sh
make poc-rules-cli-check
```

输出：

```text
nfqueue-poc enable queue 42 family ip6 mode block-uid 2000 event-log /tmp/sakamoto-events.ndjson
```

Android 实跑命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
./scripts/poc-rules-to-vppctl.py configs/rules-block-shell-uid.json \
  --event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-json-block-uid-shell.ndjson
vppctl <generated_cli>
ip6tables -w -I OUTPUT 1 -o lo -p ipv6-icmp -d ::1 -j NFQUEUE --queue-num 42 --queue-bypass
adb shell /system/bin/ping6 -c 3 -W 1 ::1
```

结果：

```text
generated_cli=nfqueue-poc enable queue 42 family ip6 mode block-uid 2000 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-json-block-uid-shell.ndjson
adb shell id: uid=2000(shell)
ping: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event-write-errors=0
event_count=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv6","proto":58,"payloadLen":104,"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no vpp process
no temporary --queue-num 42 ip6tables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：当前不用改 VPP policy loader，也可以先把 “规则文件 -> VPP CLI -> NFQUEUE verdict -> NDJSON event” 串起来。这个 POC 足够支撑下一步继续做更像 app policy 的文件形状，或者换成真实 app UID / Wi-Fi 路径验证。

### 12. Android ip6tables owner UID -> NFQUEUE narrow queue

问题：Android root 模式下，能不能先用 `ip6tables -m owner --uid-owner` 在内核侧按 UID 收窄进入 NFQUEUE 的流量，减少 VPP 需要处理的包，并避开 loopback accept-all 时出现的 uidUnknown paired packets？

命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip6 mode accept-all event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip6-owner-shell-uid.ndjson
ip6tables -w -I OUTPUT 1 -o lo -p ipv6-icmp -d ::1 -m owner --uid-owner 2000 -j NFQUEUE --queue-num 42 --queue-bypass
adb shell /system/bin/ping6 -c 3 -W 1 ::1
adb_su /system/bin/ping6 -c 2 -W 1 ::1
```

结果：

```text
shell ping: 3 transmitted, 3 received, shell_ping_rc=0
root ping:  2 transmitted, 2 received, root_ping_rc=0
seen=3 accept=3 drop=0
event_count=3
uid2000_count=3
uid_unknown_count=0
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv6","proto":58,"payloadLen":104,"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
```

清理验证：

```text
no vpp process
no temporary --queue-num 42 ip6tables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：Android `ip6tables` legacy 路径支持 `owner --uid-owner` 和 NFQUEUE 组合。root 模式 POC 可以先用 UID owner rule 做 app selector，让 VPP 只处理目标 app/UID 的包；这比把所有 OUTPUT 包都送进 VPP 更接近第一版 app-first policy。

### 13. Android IPv4 owner UID -> NFQUEUE narrow queue

问题：同样的 UID owner prefilter 在 Android IPv4 `iptables` 路径是否成立，并且 VPP event 是否能正确输出 IPv4 facts？

命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip4 mode accept-all event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip4-owner-shell-uid.ndjson
iptables -w -I OUTPUT 1 -o lo -p icmp -d 127.0.0.1 -m owner --uid-owner 2000 -j NFQUEUE --queue-num 42 --queue-bypass
adb shell /system/bin/ping -c 3 -W 1 127.0.0.1
adb_su /system/bin/ping -c 2 -W 1 127.0.0.1
```

结果：

```text
shell IPv4 ping: 3 transmitted, 3 received, shell_ping_rc=0
root IPv4 ping:  2 transmitted, 2 received, root_ping_rc=0
seen=3 accept=3 drop=0
event_count=3
uid2000_count=3
uid_unknown_count=0
ipv4_count=3
dst_count=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":2000,"dstIp":"127.0.0.1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
```

清理验证：

```text
no vpp process
no temporary --queue-num 42 iptables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：Android root 模式下 IPv4 和 IPv6 都可以用 owner UID rule 先收窄到 NFQUEUE。当前插件一次只启用一个 `family ip4|ip6`，因此真正 dual-stack app policy 还需要下一步验证双队列/双 family 方案，或把插件扩展为同时绑定 AF_INET 和 AF_INET6。

### 14. 当前 nfqueue_poc dual-family 限制

问题：当前单实例 `nfqueue_poc` 能不能同时处理 IPv4 和 IPv6 queue？如果不能，系统行为是什么？

实测方法：

- VPP 先 `nfqueue-poc enable queue 42 family ip4 mode accept-all`。
- 之后再尝试 `nfqueue-poc enable queue 43 family ip6 mode accept-all`。
- 同时插入两条 owner UID 规则：
  - IPv4: `iptables ... --uid-owner 2000 --queue-num 42 --queue-bypass`
  - IPv6: `ip6tables ... --uid-owner 2000 --queue-num 43 --queue-bypass`
- 分别执行 shell IPv4 ping 和 shell IPv6 ping。

结果：

```text
second enable output: nfqueue-poc enable: nfqueue_poc already enabled on queue 42
second_enable_rc=0
ping4_rc=0
ping6_rc=0
/proc/net/netfilter/nfnetlink_queue: queue 42 only
seen=3 accept=3 drop=0
event_count=3
ipv4_count=3
ipv6_count=0
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":2000,"dstIp":"127.0.0.1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
```

小故障：

- 第一次脚本把 `second_enable_rc != 0` 当成断言，结果失败。
- 实际 VPP CLI 已打印错误，但 `vppctl` 返回码仍是 0；后续自动化不要只靠 `vppctl` rc 判断 CLI 命令是否成功。

清理验证：

```text
no vpp process
no temporary queue 42/43 iptables/ip6tables rules
empty /proc/net/netfilter/nfnetlink_queue
```

结论：当前 POC 插件只有一个全局 queue/family state，dual-stack app policy 不能靠连续两次 `enable` 达成。下一步需要选一个最小方案：扩展插件为两个 nfqueue handles，或者先启动两个 VPP/插件实例，或者根模式临时分阶段只验证单 family。

### 15. 两个 VPP 进程分别处理 IPv4/IPv6 queue

问题：不改 `nfqueue_poc` 插件的情况下，能否临时启动两个 VPP 进程，一个 bind IPv4 queue 42，一个 bind IPv6 queue 43，从而完成 dual-stack root-mode POC？

做法：

- 生成两份临时 startup config：
  - `ip4`: runtime/log/cli/statseg/api prefix/shm dir 全部独立。
  - `ip6`: runtime/log/cli/statseg/api prefix/shm dir 全部独立。
- 两个进程都只加载 `nfqueue_poc_plugin.so`。
- `SAKAMOTO_ANDROID_SHM_DIR` 分别指向不同目录，避免 Android shm backend 冲突。
- `ip4` 进程：`nfqueue-poc enable queue 42 family ip4 mode accept-all`。
- `ip6` 进程：`nfqueue-poc enable queue 43 family ip6 mode accept-all`。
- 插入 IPv4/IPv6 owner UID 规则后分别跑 shell ping。

第一次小故障：

```text
environment: line 55: $!: unbound variable
```

原因：远端启动命令里的 `echo $!` 被本地 `set -u` shell 提前展开。修正为在本地双引号里使用 `\$!` 后重跑通过。

结果：

```text
processes: two vpp pids, 5197 and 5211
vppctl show version: both OK
ping4_rc=0
ping6_rc=0
/proc/net/netfilter/nfnetlink_queue:
  queue 42 pid 5197 queued 3
  queue 43 pid 5211 queued 3
ip4 counters: seen=3 accept=3 drop=0
ip6 counters: seen=3 accept=3 drop=0
ip4 events: count4=3
ip6 events: count6=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":2000,"dstIp":"127.0.0.1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
{"type":"packet","mode":"nfq","queue":43,"packetId":1,"family":"ipv6","proto":58,"payloadLen":104,"uidKnown":true,"uid":2000,"dstIp":"::1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
```

清理验证：

```text
no vpp process
no temporary queue 42/43 iptables/ip6tables rules
empty /proc/net/netfilter/nfnetlink_queue
```

结论：双 VPP 进程 workaround 在 Pixel 6a 上可行，可以作为不改插件时的 dual-stack POC 方案。但它会带来两个进程、两套 CLI/event/runtime 管理，长期更合理的方向仍然是扩展插件支持多个 queue/family handle。

### 16. 已安装 package UID block POC

问题：不再使用 `shell` UID，而是从 Android package manager 取一个真实已安装 app 的 UID，能否作为 app-first policy key 被 owner rule 和 VPP `block-uid` 同时识别？

选择：

```text
package=com.sakamoto.snort.vpnlite
uid=12540
appId=12540
android.permission.INTERNET: granted=true
```

注意：本轮 traffic generator 是 `su 12540 -c /system/bin/ping ...`，UID 来自已安装 package，但进程不是这个 app 自身的 Activity/Service，SELinux context 仍是 KernelSU 相关上下文。这个 POC 验证 UID policy key，不等价于真实 app 发包。

命令要点：

```sh
SKIP_PUSH=1 STOP_AFTER=0 ./scripts/android-run-vpp-minimal.sh
vppctl nfqueue-poc enable queue 42 family ip4 mode block-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-ip4-vpnlite-uid-block.ndjson
iptables -w -I OUTPUT 1 -o lo -p icmp -d 127.0.0.1 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
su 12540 -c /system/bin/ping -c 3 -W 1 127.0.0.1
```

结果：

```text
baseline before NFQUEUE: su 12540 ping 127.0.0.1 succeeds
blocked run: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event_count=3
uid_count=3
block_count=3
reason_count=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":12540,"dstIp":"127.0.0.1","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no vpp process
no temporary --uid-owner 12540 iptables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：Android package UID 可以作为 root-mode app policy 的最小 key：package manager 能提供 UID，iptables owner rule 能按 UID queue，VPP NFQUEUE metadata 能看到同一个 UID，`block-uid` verdict 能阻断。下一步要验证真实 app 进程发包，或做从 package name 到 UID/rule 的自动化。

### 17. package name -> rules JSON -> VPP CLI -> UID block

问题：用户选择的是 app/package，不是 UID。能不能先做一个薄的 host-side helper，把 Android package name 解析成当前 POC JSON policy，再复用 `poc-rules-to-vppctl.py` 生成 VPP CLI 并完成阻断？

最小改动：

- 增加 `scripts/android-package-rules-json.sh PACKAGE [OUT_JSON]`。
- 增加 `make android-package-rules-json PACKAGE=...`。
- helper 通过 `cmd package list packages -U` 取 UID，通过 `dumpsys package` 标记 `INTERNET` 是否 granted。
- 输出仍是现有 POC schema，VPP 侧不新增 JSON parser。

小故障和修正：

```text
1. Make target 默认 echo recipe，导致重定向出的 JSON 第一行是命令文本。
   修正：target recipe 改为 @./scripts/android-package-rules-json.sh ...

2. 脚本用 dumpsys | tr | grep -q，在 set -o pipefail 下被 grep -q 的提前退出影响，
   INTERNET granted 被误判为 false。
   修正：先收完整 dumpsys 到变量，再用 shell pattern 判断。
```

本地输出：

```json
{
  "schema": "sakamoto-vpp-poc-rules-v0",
  "source": {
    "type": "android-package",
    "package": "com.sakamoto.snort.vpnlite",
    "uid": 12540,
    "internetGranted": true
  },
  "queue": 42,
  "family": "ip4",
  "rules": [
    {
      "id": "block-com-sakamoto-snort-vpnlite",
      "enabled": true,
      "action": "block",
      "uid": 12540,
      "package": "com.sakamoto.snort.vpnlite"
    }
  ]
}
```

生成的 VPP CLI：

```text
nfqueue-poc enable queue 42 family ip4 mode block-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-package-json-vpnlite.ndjson
```

Android 实跑结果：

```text
ping as uid 12540: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event_count=3
uid_count=3
block_count=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":12540,"dstIp":"127.0.0.1","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no vpp process
no temporary --uid-owner 12540 iptables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：现在已有最小控制面闭环：`package name -> UID -> JSON rule -> VPP CLI -> NFQUEUE verdict -> event`。这还不是正式 app UI，但足够支撑下一步做“列出用户应用/付费应用、选择一个 package、下发 UID 规则”的 POC。

### 18. third-party package inventory JSON

问题：app-first control plane 需要先列出“用户安装应用”。能不能用 Android package manager 输出第三方 package、UID 和 INTERNET 权限，供后续选择 app 下发规则？

最小改动：

- 增加 `scripts/android-list-user-packages-json.sh`。
- 增加 `make android-list-user-packages-json`。
- 数据源是 `cmd package list packages -3 -U`，逐包用 `dumpsys package` 标记 `android.permission.INTERNET: granted=true`。

命令：

```sh
make android-list-user-packages-json > /tmp/sakamoto-user-packages.json
python3 -m json.tool /tmp/sakamoto-user-packages.json
```

结果：

```text
package_count=11
internet_count=10
```

样例输出：

```json
{
  "schema": "sakamoto-android-user-packages-v0",
  "source": {
    "type": "android-package-manager",
    "thirdPartyOnly": true
  },
  "packages": [
    {"package": "com.celzero.bravedns", "uid": 12526, "internetGranted": true},
    {"package": "com.emanuelef.remote_capture", "uid": 12532, "internetGranted": true},
    {"package": "com.js.nowakelock", "uid": 12206, "internetGranted": false},
    {"package": "com.sakamoto.snort.vpnlite", "uid": 12540, "internetGranted": true}
  ]
}
```

结论：root-mode POC 的 app selector 已有最小数据源：能列出第三方包、UID、网络权限。下一步可以把这个列表和第 17 步的 package->rule helper 连接起来，做“选择一个 package 生成规则并下发”的更完整控制面 POC。

### 19. one-command package block POC runner

问题：能不能把前几步手动流程收敛成一个可重复命令，验证“选择 package -> 生成规则 -> 启动 VPP -> 安装 owner rule -> 阻断 UID 流量 -> 清理”的闭环？

最小改动：

- 增加 `scripts/android-run-package-block-poc.sh PACKAGE`。
- 增加 `make android-package-block-poc PACKAGE=...`。
- runner 内部复用：
  - `android-package-rules-json.sh`
  - `poc-rules-to-vppctl.py`
  - `android-run-vpp-minimal.sh`
  - `iptables -m owner --uid-owner <uid> -j NFQUEUE`
  - `su <uid> -c /system/bin/ping ...`

命令：

```sh
make android-package-block-poc PACKAGE=com.sakamoto.snort.vpnlite
```

结果：

```text
app_uid=12540
generated_cli=nfqueue-poc enable queue 42 family ip4 mode block-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-package-block-poc.ndjson
ping as uid 12540: 3 transmitted, 0 received
ping_rc=1
seen=3 accept=0 drop=3
rule-match=3 rule-miss=0
event_count=3 uid_count=3 block_count=3
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":12540,"dstIp":"127.0.0.1","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no vpp process
no temporary --uid-owner 12540 iptables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：现在 root-mode app UID block POC 可以一条命令复现。它仍是 throwaway runner，但已经足够作为后续快速验证入口：换不同 package，就能验证 UID 选择、规则生成、VPP verdict 和事件输出是否连通。

### 20. package allow action POC

问题：0.2 app-first policy 不只有 block，也需要 allow。当前 JSON helper 能否支持 `action=allow`，并映射到 VPP 放行路径？

最小改动：

- `poc-rules-to-vppctl.py` 支持 `action=allow|block`。
- `action=allow` 映射为 `nfqueue-poc ... mode accept-all`。
- 仍要求规则里存在 `uid` 或 `dst` selector，避免误生成全局 allow。
- `android-package-rules-json.sh` 的 rule id 从固定 `block-...` 改为 `${ACTION}-...`。

本地输出：

```text
allow-com-sakamoto-snort-vpnlite allow
nfqueue-poc enable queue 42 family ip4 mode accept-all event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-package-allow-vpnlite.ndjson
```

Android 实跑：

```sh
ACTION=allow make android-package-rules-json PACKAGE=com.sakamoto.snort.vpnlite
vppctl <generated allow CLI>
iptables -w -I OUTPUT 1 -o lo -p icmp -d 127.0.0.1 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
su 12540 -c /system/bin/ping -c 3 -W 1 127.0.0.1
```

结果：

```text
ping: 3 transmitted, 3 received
ping_rc=0
seen=3 accept=3 drop=0
event_count=3
uid_count=3
allow_count=3
block_count=0
```

事件样例：

```json
{"type":"packet","mode":"nfq","queue":42,"packetId":1,"family":"ipv4","proto":1,"payloadLen":84,"uidKnown":true,"uid":12540,"dstIp":"127.0.0.1","verdict":"allow","reason":"mode_accept_all","ruleId":null}
```

清理验证：

```text
no vpp process
no temporary --uid-owner 12540 iptables rule
empty /proc/net/netfilter/nfnetlink_queue
```

结论：allow 的最小行为可以用 owner rule + VPP `accept-all` 完成，包能通过并产生活动事件。限制是当前 allow event 没有 rule attribution（`ruleId=null`），后续如果 Activity/Cockpit 要解释“被哪条 allow 规则放行”，需要在插件里新增显式 allow rule mode 或 event rule id 注入。

### 21. Docker VPP TUN reflect smoke

问题：VPN/TUN 方向先不碰 Android app，先确认现有 Docker/Linux `tun_poc` 基础是否仍可运行：VPP 能否接收 TUN fd 上的 IPv4 ICMP，并反射 echo reply？

第一次运行：

```sh
./scripts/run-container.sh make vpp-tun-poc-smoke
```

失败：

```text
FileNotFoundError: [Errno 2] No such file or directory: '/dev/net/tun'
VPP exited before CLI socket appeared
```

原因：`run-container.sh` 默认不把宿主 `/dev/net/tun` 传进容器。

宿主确认：

```text
/dev/net/tun exists, character special file, mode 0666
```

重跑：

```sh
DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-poc-smoke
```

结果：

```text
enable command: tun-poc enable fd 3 mode reflect-icmp
ping -I tun-poc0 -c 5 -W 1 198.18.0.2
5 packets transmitted, 5 received, 0% packet loss
rx 7 bytes 516
tx 5 bytes 420
parse-errors 0
read-errors 0
write-errors 0
ping_rc=0
```

结论：Docker/Linux 侧 VPP TUN fd 基础可用。后续 TUN/VPN POC 运行时必须显式传 `DOCKER_TUN_DEVICE=1`；Android VpnService/TUN 方向可以复用 `tun_poc` 的 fd 接入思路，但还没有验证 Android app 提供 TUN fd。

### 22. Docker VPP TUN forward-fd smoke

问题：比 reflect 更接近 VPN/app side 的模式是：VPP 从 TUN fd 收包后，把 packet 转发到另一个 userspace shim fd，再由 shim 回包。现有 `tun_poc forward-fd` 是否仍可用？

命令：

```sh
DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-forward-fd-smoke
```

结果：

```text
tun ifname=tun-poc-forward tun-fd=53 shim-fd=54
mode forward-fd
shim observed 198.19.0.1 -> 198.19.0.2 icmp_type=8 len=84
ping: 1 transmitted, 1 received, 0% packet loss
after ping:
rx 2 bytes 132
tx 1 bytes 84
shim-rx 1 bytes 84
shim-tx 2 bytes 132
parse-errors 0
read-errors 0
write-errors 0
shim-read-errors 0
shim-write-errors 0
```

观察：

- 启用后先出现一个 `shim observed non-icmp packet len=48`，和 before-ping counters 的初始 packet 对应；后续真正 ICMP echo 正常。
- 这一步只验证 Linux userspace fd bridge，不代表 Android VpnService fd 生命周期已解决。

结论：VPP `tun_poc` 的 TUN fd -> shim fd -> TUN reply 路径可用。VPN mode POC 可以优先沿这个 fd bridge 思路继续推进，下一步才需要把 Android VpnService 交出的 TUN fd 接入同样模型。

### 23. Docker VPP TUN -> HEV SOCKS smoke

问题：现有 `vpp-tun-hev-smoke` 是否还能把 TUN 流量经 VPP `forward-fd` 接到 HEV，再到本地 SOCKS5 server，完成一次 HTTP probe？

命令：

```sh
DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-hev-smoke
```

结果：

```text
SOCKS5 server port=38567
HEV pid=16 vpp-shim-fd=54
before curl:
  mode forward-fd
  rx 1 bytes 48
  shim-tx 1 bytes 48
curl output:
  OK
SOCKS event: greeting
SOCKS event: connect 93.184.216.34:80
SOCKS event: payload GET /probe HTTP/1.0
after curl:
  rx 7 bytes 390
  tx 6 bytes 284
  shim-rx 6 bytes 284
  shim-tx 7 bytes 390
  parse-errors 0
  read-errors 0
  write-errors 0
  shim-read-errors 0
  shim-write-errors 0
```

重要风险：

```text
HEV stderr/stdout:
free(): invalid size
```

命令整体返回 0，说明 HTTP probe 完成；但 HEV 退出时的 allocator 错误不能忽略，后续如果继续沿 HEV 路线做 Android VPN mode，需要单独最小化/定位这个 teardown 崩溃。

结论：Docker/Linux 侧 TUN -> VPP forward-fd -> HEV -> SOCKS5 的数据面可以跑通一次 HTTP probe。这给 VPN mode 一个可继续探索的方向；当前主要风险是 HEV teardown 内存错误，以及 Android VpnService fd 尚未接入验证。

### 24. HEV socketpair probe teardown comparison

问题：第 23 步的 `free(): invalid size` 是否能在更小的 HEV socketpair-only probe 中复现？如果不能，问题可能和 VPP/TUN/forward-fd 集成 teardown 有关。

第一次运行：

```sh
./scripts/run-container.sh make hev-socketpair-probe
```

数据面通过，但 runner 出现日志权限问题：

```text
tee: .../results/hev-socketpair-probe.log: Permission denied
SOCKS event: greeting
SOCKS event: connect 93.184.216.34:80
SOCKS event: payload GET /probe HTTP/1.0
HEV exitcode: -15
response payload: HTTP/1.0 200 OK ... OK
```

修正：

```text
scripts/run-hev-socketpair-probe.sh: tee 前 rm -f 旧 log，避免 stale log 权限影响重复运行。
```

重跑结果：

```text
packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x12 len=0
packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x10 len=0
packet 93.184.216.34:80 -> 10.0.0.2:42424 flags=0x18 len=40
SOCKS event: greeting
SOCKS event: connect 93.184.216.34:80
SOCKS event: payload GET /probe HTTP/1.0
HEV exitcode: -15
response payload: HTTP/1.0 200 OK ... OK
```

观察：

- socketpair-only HEV probe 没有出现 `free(): invalid size`。
- HEV 是被 SIGTERM 结束，exitcode `-15` 属于当前 probe 的预期清理方式。

结论：HEV 本身在更小 socketpair probe 中可完成 HTTP payload 往返；第 23 步 allocator 错误更可能和 TUN/VPP forward-fd 集成或 teardown 顺序相关，需要后续单独最小化。

### 25. Android VpnService native TUN fd probe

问题：实验 APK `com.sakamoto.snort.vpnlite` 能否在 Pixel 6a 上通过 `VpnService.Builder.establish()` 拿到 Android VPN TUN fd，并让 native probe 读取 L3 packet header？

前置：

```text
installed package: com.sakamoto.snort.vpnlite
versionName=0.1-debug
versionCode=1
lastUpdateTime=2026-06-23 06:40:50
android.permission.INTERNET: granted=true
```

本轮未重装 APK，避免打断已有 VPN 授权状态。

命令要点：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode native
su 12540 -c /system/bin/ping -c 1 -W 1 1.1.1.1
cat /data/user/0/com.sakamoto.snort.vpnlite/files/logs/vpn-fd-probe.log
```

结果：

```text
nativeStartProbe fd=110 rc=0
probe start fd=110 max_packets=32
packet=1 len=76 ipv6 next=0 fe80::... -> ff02::16
packet=2 len=48 ipv6 next=58 fe80::... -> ff02::2
packet=4 len=60 ipv4 proto=6 10.111.0.2 -> 142.250.107.188
packet=9 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
```

触发 ping：

```text
1 packets transmitted, 0 received
ping_rc=1
```

这是预期内的：native mode 只读 header，不回包/转发，所以 full-route VPN 会黑洞该 ping。

清理验证：

```text
force-stop com.sakamoto.snort.vpnlite
no com.sakamoto.snort.vpnlite pid
dumpsys connectivity did not show active package VPN entry
```

结论：Android app/VpnService 路径可以拿到 TUN fd，native 层能读到真实 VPN packet header。这是 VPN mode 的关键可行性信号；下一步可以尝试 `mode=vpp`，把同一个 detached fd 交给 Android 打包的 VPP `tun_poc`。

### 26. Android VpnService fd -> packaged VPP tun_poc count-only

问题：`vpn-lite` app 能否把 VpnService detached TUN fd 交给 APK 内打包的 VPP，并让 VPP `tun_poc` 从 fd 3 读取 VPN packet？

命令要点：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp
su 12540 -c /system/bin/ping -c 1 -W 1 1.1.1.1
cat /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-cli.log
```

结果：

```text
SnortVpnLiteNative: started VPP pid=6186 fd=112 mode=0
nativeStartVppProbe fd=112 vppMode=0 rc=0
vpp monitor start pid=6186 cli=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/runtime/cli.sock
```

VPP `show tun-poc` 观察：

```text
first sample:
enabled 0 fd -1 shim-fd -1 mode count-only
rx 0 bytes 0

later samples:
enabled 1 fd 3 shim-fd -1 mode count-only
rx 8 bytes 532
rx 9 bytes 580
rx 10 bytes 664
rx 11 bytes 724
tx 0 bytes 0
parse-errors 0
read-errors 0
write-errors 0
```

触发 ping：

```text
1 packets transmitted, 0 received
ping_rc=1
```

这是预期内的：`mode=vpp` 当前是 VPP `count-only`，只读不回包/转发。

清理验证：

```text
force-stop com.sakamoto.snort.vpnlite
no com.sakamoto.snort.vpnlite pid
no vpp pid
dumpsys connectivity did not show active package VPN entry
```

结论：Android VPN mode 的核心 fd handoff 已经跑通：VpnService fd -> native helper -> fork/exec packaged VPP -> `tun_poc enable fd 3` -> VPP 读到真实 VPN packet。下一步可以试 `mode=vpp-forward`，让 app 内 shim fd 反射 ICMP，验证 VPN 模式下最小回包。

### 27. Android VpnService fd -> packaged VPP forward-fd -> shim ICMP reflect

问题：Android VPN mode 下，VPP 不只读包，还能不能通过 `forward-fd` 把 packet 交给 app 内 native shim，由 shim 写回 ICMP echo reply，让发起方看到 ping 成功？

命令要点：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-forward
su 12540 -c /system/bin/ping -c 3 -W 1 1.1.1.1
cat /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-cli.log
cat /data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-shim.log
```

结果：

```text
nativeStartVppProbe fd=112 vppMode=1 rc=0
started VPP pid=6308 fd=112 mode=1
vpp shim driver start fd=109

ping:
3 packets transmitted, 3 received, 0% packet loss
ping_rc=0
```

VPP counters:

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 13 bytes 892
tx 3 bytes 252
shim-rx 3 bytes 252
shim-tx 13 bytes 892
parse-errors 0
read-errors 0
write-errors 0
shim-read-errors 0
shim-write-errors 0
```

Shim log:

```text
packet=10 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
shim reflected icmp len=84 written=84
packet=11 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
shim reflected icmp len=84 written=84
packet=13 len=84 ipv4 proto=1 10.111.0.2 -> 1.1.1.1
shim reflected icmp len=84 written=84
```

清理验证：

```text
force-stop com.sakamoto.snort.vpnlite
no com.sakamoto.snort.vpnlite pid
no vpp pid
dumpsys connectivity did not show active package VPN entry
```

结论：Android VPN mode 的最小回包闭环可行：VpnService TUN fd -> app-packaged VPP `tun_poc forward-fd` -> app native shim -> TUN reply。这个 POC 不是真实转发/NAT/HEV，但证明 VPP 可以在 APK 内接 VPN fd 并参与 packet round-trip。

### 28. Android VpnService fd -> packaged VPP -> HEV -> SOCKS5 HTTP

问题：Android `mode=vpp-hev` 能否完成更接近 VPN 数据面的链路：VpnService TUN fd -> packaged VPP `forward-fd` -> HEV -> 127.0.0.1:41080 SOCKS5 server -> HTTP response？

前置：

- APK 已包含 `libhev-socks5-tunnel.so`。
- 设备有 `/system/bin/nc`。
- `scripts/android-socks5-smoke-server.c` 可编译为 arm64 server，监听 `127.0.0.1:41080`。

小故障：

```text
1. adb push 到 /data/local/tmp/vpp-nfq-poc 失败：
   remote couldn't create file: Permission denied
   处理：root chmod 777 临时目录后再 push。

2. 第一轮 server bind 失败：
   bind: Address already in use
   同时 HTTP nc 得到 Connection reset by peer。
   处理：确认 41080 无监听后重跑。

3. 清理命令 pkill -f android-socks5-smoke-server 会匹配当前 adb shell 命令行并把自己杀掉，导致脚本 exit 137。
   处理：只用 pid 文件清理本轮 server，避免 pkill -f。
```

成功命令要点：

```sh
make android-socks5-smoke-server-build
adb push build/android-socks5-smoke-server /data/local/tmp/vpp-nfq-poc/android-socks5-smoke-server
adb_su "nohup /data/local/tmp/vpp-nfq-poc/android-socks5-smoke-server >... & echo $! >...pid"
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-hev
su 12540 -c "/system/bin/nc -4 -w 5 -W 5 93.184.216.34 80" < http-request.txt
```

HTTP 结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
http_rc=0
```

SOCKS5 server 观察：

```text
android socks5 smoke server ready 127.0.0.1:41080
accepted
greeting ok
connect 93.184.216.34:80
payload-len 43
GET /probe HTTP/1.0
Host: example.test
```

VPP counters：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 21 bytes 1662
tx 10 bytes 520
shim-rx 10 bytes 520
shim-tx 21 bytes 1662
parse-errors 0
read-errors 0
write-errors 0
shim-read-errors 0
shim-write-errors 0
```

HEV log：

```text
started VPP HEV pid=6999
socks5 client tcp -> [93.184.216.34]:80
```

额外观察：

- HEV 也转发了系统/Google 连接，如 `74.125.199.188:5228`，说明 full-route VPN 会带入背景流量。
- 本轮没有在截取日志中看到 Docker 第 23 步那种 `free(): invalid size`，但 stop 后也没有专门检查 HEV 完整退出日志；后续仍需 teardown 专项。

清理验证：

```text
force-stop com.sakamoto.snort.vpnlite
no com.sakamoto.snort.vpnlite pid
no vpp pid
no 41080 listener
no socks5 server process
```

结论：Android VPN mode 的 VPP+HEV 数据面可以完成一次真实 TCP/HTTP 往返。至此两条路线都有关键 POC：root/NFQUEUE app UID block/allow 可行，VPN/VPP/HEV fd bridge 也可行。下一步应围绕规则语义、事件归因、真实 app traffic、teardown 稳定性继续小步验证。

### 29. Android VPP+HEV explicit stop teardown probe

问题：第 23 步 Docker HEV 路径出现过 `free(): invalid size`。Android `mode=vpp-hev` 在完成 HTTP 后，如果显式走 app stop intent，是否会复现 allocator/Fatal signal 问题？

命令要点：

```sh
start local 127.0.0.1:41080 socks5 smoke server
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez start true --es mode vpp-hev
su 12540 -c "nc -4 -w 5 -W 5 93.184.216.34 80" < http-request-teardown.txt
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity --ez stop true
```

结果：

```text
HTTP/1.0 200 OK
Content-Length: 2

OK
http_rc=0
```

SOCKS5 server：

```text
connect 93.184.216.34:80
payload-len 46
GET /teardown HTTP/1.0
Host: example.test
```

HEV/VPP stop log：

```text
started VPP HEV pid=7196
started VPP pid=7195 fd=112 mode=2
vpp monitor stop
stopped HEV pid=7196 log=/data/user/0/com.sakamoto.snort.vpnlite/files/vpp/logs/vpp-hev.log
VPN stopped
```

未观察到：

```text
free(): invalid size
Fatal signal
SIGABRT
```

脚本小故障：

- stop intent 后 app Activity 进程仍可短暂存在，SOCKS server 也仍在等待 trap cleanup。
- 本轮脚本把这两个“即将被 cleanup 清掉的进程”当成失败，exit 9。
- trap 后再次检查：无 app pid、无 vpp pid、无 41080 listener、无 socks5 server process。

结论：Android `vpp-hev` 显式 stop 路径本轮未复现 Docker 中的 `free(): invalid size`。这不是稳定性结论，只说明 Android app stop intent 可以触发 `stopped HEV` 并完成一次干净清理；后续还需要多次循环和异常路径测试。

### 30. Android root/NFQUEUE real egress synthetic UID probe

问题：root 模式下不用 VPN，直接用 iptables owner match 把已安装 app UID 的真实公网 TCP 出口包送入 NFQUEUE/VPP，能否做 allow/block 规则验证？

配置：

```text
package: com.sakamoto.snort.vpnlite
uid: 12540
dst: 93.184.216.34:80
queue: 42
iptables: -p tcp -d 93.184.216.34 --dport 80 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
generator: su 12540 -c "/system/bin/nc -4 -w 5 -W 5 93.184.216.34 80"
```

结果：

```text
baseline_rc=1
allow_rc=1
block_rc=1
```

VPP `accept-all` 仍然看到了包：

```text
seen 3 accept 3 drop 0 missing-id 0
```

VPP `block-uid` 也能按 UID 丢包，并输出事件：

```text
seen 2 accept 0 drop 2 missing-id 0
uid=12540 dstIp=93.184.216.34 verdict=block reason=uid_block
```

额外排查：

```text
su 12540 nc -z 74.125.199.188:5228 -> timeout
su 12540 nc -z 142.250.107.188:443 -> timeout
su 12540 nc -z 1.1.1.1:443 -> timeout
su 12540 nc -z 8.8.8.8:53 -> timeout
su 12540 nc -z 93.184.216.34:80 -> timeout
shell ping 1.1.1.1 -> 0% packet loss
su 12540 ping 1.1.1.1 -> ping: sendmsg: Operation not permitted
```

清理验证：

```text
no vpp pid
no queue 42 iptables rule
empty nfnetlink_queue
```

结论：

```text
1. 当前 Pixel 6a 上，用 `su <app_uid>` 伪造真实公网 app 流量不是可靠 generator。
2. 这个 synthetic UID 进程可以产生被 owner match 归到 UID 12540 的 TCP SYN，VPP/NFQUEUE 能看到并按 UID block。
3. 但 baseline/allow 都无法完成公网 TCP 连接，且 `su 12540 ping` 直接缺少权限，所以不能用它判断真实 app egress 的可达性。
4. 下一步必须让实际 app 进程自己发 HTTP/TCP，再分别验证 root/NFQUEUE 和 VPN/VPP/HEV 路径。
```

### 31. Android app-process HTTP probe entry

问题：为了替代不可靠的 `su <app_uid>` synthetic generator，需要让实验 app 自己在进程内发起 TCP/HTTP，并把结果写入 app 私有日志。

实现：

```text
SnortVpnService.ACTION_HTTP_PROBE
extras: host, port, path
log: /data/user/0/com.sakamoto.snort.vpnlite/files/logs/app-http-probe.log
adb入口: MainActivity --ez appHttpProbe true --es host <ip-or-host> --ei port <port> --es path <path>
```

构建验证：

```sh
experiments/vpp-nfq-poc/android/vpn-lite/scripts/build-debug-apk.sh
```

结果：

```text
compiling Java sources
dexing
linking APK
signing
ok: experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk
```

结论：现在有了一个真实 app 进程 HTTP generator，可以继续验证 baseline、root/NFQUEUE、VPN/VPP/HEV 三条路径，不再依赖 `su UID`。

### 32. Android root/NFQUEUE app-process HTTP allow/block

问题：第 30 步证明 `su <app_uid>` 不是可靠公网流量源。实际 app 进程自己发 TCP/HTTP 时，root-mode iptables owner + NFQUEUE + VPP 是否能完成 allow/block？

稳定目标选择：

```text
baseline app HTTP probe:
connectivitycheck.gstatic.com:80/generate_204 -> HTTP/1.0 204 No Content
142.251.13.94:80/generate_204 -> HTTP/1.0 204 No Content
93.184.216.34:80 -> connect 后 read timeout
neverssl.com:80 -> read timeout
```

本轮使用固定 IPv4：

```text
package: com.sakamoto.snort.vpnlite
uid: 12540
dst: 142.251.13.94:80
iptables: -p tcp -d 142.251.13.94 --dport 80 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
```

`accept-all` 结果：

```text
app log:
start host=142.251.13.94 port=80 path=/nfq-accept
ok bytes=256 elapsedMs=695 first=HTTP/1.0 404 Not Found ...

show nfqueue-poc:
enabled 1 queue 42 family ip4 mode accept-all drop-ratio 50 block-uid 0 fd 12
seen 6 accept 6 drop 0 missing-id 0
payload-missing 0 parse-errors 0 rule-match 0 rule-miss 0

event sample:
uidKnown=true uid=12540 dstIp=142.251.13.94 verdict=allow reason=mode_accept_all ruleId=null
```

`block-uid 12540` 结果：

```text
app log:
start host=142.251.13.94 port=80 path=/nfq-block
fail elapsedMs=5012 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /192.168.4.151 ... after 5000ms

show nfqueue-poc:
enabled 1 queue 42 family ip4 mode block-uid drop-ratio 50 block-uid 12540 fd 12
seen 3 accept 0 drop 3 missing-id 0
payload-missing 0 parse-errors 0 rule-match 3 rule-miss 0

event sample:
uidKnown=true uid=12540 dstIp=142.251.13.94 verdict=block reason=uid_block ruleId=block-uid
```

清理验证：

```text
no vpp pid
no queue 42 iptables rule
empty nfnetlink_queue
```

结论：

```text
1. root-mode “package UID -> iptables owner -> NFQUEUE -> VPP verdict” 对真实 app 进程公网 TCP 生效。
2. allow path 会放行完整 TCP/HTTP 往返；block path 会丢 SYN，app 侧表现为 connect timeout。
3. 事件元数据能拿到 uid=12540 和 dstIp，满足第一版静态规则/用户应用归因的最小需求。
4. allow 仍然没有 ruleId，当前只是 mode_accept_all；如果产品侧要解释“哪条 allow 规则命中”，需要新增显式 allow rule mode。
```

### 33. Android VPN/VPP/HEV app-process HTTP path

问题：真实 app 进程自己发 HTTP 时，会不会进入它自己启动的 `VpnService -> packaged VPP -> HEV -> SOCKS5` 管道？还是被系统排除在 VPN 外直接走公网？

配置：

```text
mode: vpp-hev
SOCKS5 smoke server: 127.0.0.1:41080
app HTTP probe: 142.251.13.94:80 /vpn-app
```

结果：

```text
app-http-probe.log:
start host=142.251.13.94 port=80 path=/vpn-app
ok bytes=40 elapsedMs=7 first=HTTP/1.0 200 OK  Content-Length: 2    OK
```

SOCKS5 server 看到两条连接：

```text
connect 74.125.199.188:5228
connect 142.251.13.94:80
payload-len 65
GET /vpn-app HTTP/1.0
Host: 142.251.13.94
Connection: close
```

VPP counters：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 20 bytes 1644 tx 10 bytes 520
shim-rx 10 bytes 520 shim-tx 20 bytes 1644
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

HEV log：

```text
socks5 client tcp -> [74.125.199.188]:5228
socks5 client tcp -> [142.251.13.94]:80
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. 实验 app 自己发出的 HTTP 会进入自己建立的 VpnService/VPP/HEV 路径。
2. 这条 VPN 路径不是只对 `su UID` synthetic generator 成立；真实 app process 也成立。
3. full-route VPN 会携带背景 Google 长连接，如 74.125.199.188:5228；后续 POC 里需要把目标流量和背景流量区分记录。
```

### 34. VPP NFQUEUE explicit allow-uid event attribution

问题：第 32 步 root/NFQUEUE allow path 用 `accept-all` 可以放行，但 event 里 `ruleId=null`。如果第一版 UI/日志需要解释“哪条 allow 规则放行”，需要最小 rule attribution。

实现：

```text
新增 nfqueue_poc mode allow-uid <uid>
UID 命中时:
  verdict=allow
  reason=uid_allow
  ruleId=allow-uid
  rule-match++
UID 未命中时:
  verdict=allow
  reason=default_allow_uid_miss/default_allow_uid_unknown
  rule-miss++
```

Docker/netns 验证：

```sh
./scripts/run-container.sh \
  env EXPECT_EVENTS=1 EVENT_LOG=results/vpp-nfqueue-allow-uid-root.ndjson \
  ./scripts/run-vpp-nfqueue-smoke.sh allow-uid=0
```

结果：

```text
20 packets transmitted, 20 received, 0% packet loss
enabled 1 queue 42 family ip4 mode allow-uid drop-ratio 50 block-uid 0 fd 12
seen 20 accept 20 drop 0 missing-id 0
payload-missing 0 parse-errors 0 rule-match 20 rule-miss 0
event_count=20
```

事件样例：

```json
{"uidKnown":true,"uid":0,"dstIp":"10.200.42.2","verdict":"allow","reason":"uid_allow","ruleId":"allow-uid"}
```

结论：VPP 插件现在可以给 allow verdict 输出明确 rule attribution。下一步需要把 Android/root-mode 使用的 staged plugin 更新后，用真实 app HTTP 再跑一遍 `allow-uid 12540`。

### 35. Android root/NFQUEUE app-process allow-uid attribution

问题：第 34 步只在 Docker/netns 上证明了 `allow-uid`。Android root-mode、真实 app 进程、真实公网 TCP 下，更新后的 staged plugin 是否同样能输出 allow rule attribution？

构建/推送：

```sh
BUILD_DIR=work/vpp-android-release-no-multiarch-no-ipsec-idle \
  TARGET=nfqueue_poc_plugin \
  scripts/android-build-vpp-probe.sh

BUILD_DIR=work/vpp-android-release-no-multiarch-no-ipsec-idle \
  STAGE_DIR=work/android-vpp-release-no-multiarch-no-ipsec-idle-stage \
  scripts/android-stage-vpp-core.sh

BUILD_DIR=work/vpp-android-release-no-multiarch-no-ipsec-idle \
  STAGE_DIR=work/android-vpp-release-no-multiarch-no-ipsec-idle-stage \
  scripts/android-push-vpp-core.sh
```

验证配置：

```text
package: com.sakamoto.snort.vpnlite
uid: 12540
dst: 142.251.13.94:80
iptables: -p tcp -d 142.251.13.94 --dport 80 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
VPP: nfqueue-poc enable queue 42 family ip4 mode allow-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-app-http-allow-uid.ndjson
```

结果：

```text
app log:
start host=142.251.13.94 port=80 path=/allow-uid
ok bytes=256 elapsedMs=631 first=HTTP/1.0 404 Not Found ...

show nfqueue-poc:
enabled 1 queue 42 family ip4 mode allow-uid drop-ratio 50 block-uid 12540 fd 12
seen 6 accept 6 drop 0 missing-id 0
payload-missing 0 parse-errors 0 rule-match 6 rule-miss 0
event-write-errors 0
```

事件样例：

```json
{"uidKnown":true,"uid":12540,"dstIp":"142.251.13.94","verdict":"allow","reason":"uid_allow","ruleId":"allow-uid"}
```

清理验证：

```text
no app pid
no vpp pid
no queue 42 iptables rule
empty nfnetlink_queue
```

结论：Android root-mode 现在同时具备真实 app process block attribution 和 allow attribution。第一版静态规则 POC 可以表达 package UID 的 allow/block 两种事件，不再只能用 `accept-all` 做匿名放行。

### 36. Android root/NFQUEUE app-process IPv6 static dst block

问题：真实 app 进程 + IPv6 + 静态 dst 规则是否可行？公网 IPv6 不稳定，本轮先用可控 loopback `::1` 和本地 IPv6 HTTP smoke server 验证数据面与事件归因。

baseline：

```text
server: /system/bin/nc -6 -l -s ::1 -p 18080
app HTTP probe: ::1:18080 /ipv6-baseline

app log:
ok bytes=40 elapsedMs=7 first=HTTP/1.0 200 OK  Content-Length: 2    OK

server log:
GET /ipv6-baseline HTTP/1.0
Host: ::1
```

NFQUEUE 规则：

```text
ip6tables -w -I OUTPUT 1 -p tcp -d ::1 --dport 18080 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
```

`accept-all` 结果：

```text
app log:
start host=::1 port=18080 path=/ip6-accept
ok bytes=40 elapsedMs=7 first=HTTP/1.0 200 OK  Content-Length: 2    OK

server log:
GET /ip6-accept HTTP/1.0
Host: ::1

show nfqueue-poc:
enabled 1 queue 42 family ip6 mode accept-all drop-ratio 50 block-uid 0 fd 12
seen 5 accept 5 drop 0 missing-id 0
event: uid=12540 dstIp=::1 verdict=allow reason=mode_accept_all
```

`block-ip6-dst ::1` 结果：

```text
app log:
start host=::1 port=18080 path=/ip6-block
fail elapsedMs=5013 error=SocketTimeoutException: failed to connect to /::1 (port 18080) from /::1 ... after 5000ms

server log:
empty

show nfqueue-poc:
enabled 1 queue 42 family ip6 mode block-ip6-dst drop-ratio 50 block-uid 0 fd 12
seen 3 accept 0 drop 3 missing-id 0
payload-missing 0 parse-errors 0 rule-match 3 rule-miss 0
```

事件样例：

```json
{"uidKnown":true,"uid":12540,"dstIp":"::1","verdict":"block","reason":"exact_ip6_dst","ruleId":"block-ip6-dst"}
```

清理验证：

```text
no app pid
no vpp pid
no nc6 server process
no queue 42 ip6tables rule
empty nfnetlink_queue
```

结论：IPv6 静态 dst block 在 Android root-mode 下对真实 app process 生效。第一版静态规则可以覆盖 IPv4 package UID allow/block 和 IPv6 exact-dst block；公网 IPv6 连通性另行验证，不阻塞规则语义 POC。

### 37. Android VPN/VPP/HEV app-process HTTP 3-cycle loop

问题：单次 `vpp-hev` stop 没有复现 Docker 里的 `free(): invalid size`，但还需要小循环验证启动、真实 app HTTP、stop、清理是否能连续跑。

新增：

```text
scripts/android-run-vpp-hev-app-http-loop.sh
默认 CYCLES=3
每轮:
  1. force-stop app
  2. start mode=vpp-hev
  3. app process HTTP probe -> 142.251.13.94:80 /loop-N
  4. 检查 app 收到 SOCKS smoke server 的 HTTP/1.0 200 OK
  5. stop intent
  6. 检查 HEV log 无 free()/Fatal signal/SIGABRT
  7. force-stop 后检查无 vpp 残留
```

同时把 `android-socks5-smoke-server` 的 accept 上限从 8 提到 32，避免循环中背景 Google 连接提前耗尽 server quota。

命令：

```sh
scripts/android-run-vpp-hev-app-http-loop.sh
```

结果：

```text
cycle 1:
  app HTTP -> HTTP/1.0 200 OK, elapsedMs=10
  socks_connect_count=1
  vpp monitor stop
  HEV: socks5 client tcp -> [142.251.13.94]:80
  cycle 1 ok

cycle 2:
  app HTTP -> HTTP/1.0 200 OK, elapsedMs=10
  socks_connect_count=2
  vpp monitor stop
  HEV: socks5 client tcp -> [142.251.13.94]:80
  cycle 2 ok

cycle 3:
  app HTTP -> HTTP/1.0 200 OK, elapsedMs=10
  socks_connect_count=3
  vpp monitor stop
  HEV: socks5 client tcp -> [142.251.13.94]:80
  cycle 3 ok
```

SOCKS server 最终日志包含：

```text
GET /loop-1 HTTP/1.0
GET /loop-2 HTTP/1.0
GET /loop-3 HTTP/1.0
```

未观察到：

```text
free(): invalid size
Fatal signal
SIGABRT
vpp process leak
socks5 server process leak
41080 listener leak
```

结论：Android `VpnService -> packaged VPP -> HEV -> SOCKS5` 对真实 app process 的 3 轮启动/HTTP/stop 循环通过。本轮仍不是压力测试结论，但足够支持下一步继续围绕规则语义和 root/VPN 模式差异做 POC。

### 38. package allow JSON helper -> allow-uid attribution

问题：第 20 步时 `action=allow` 只能映射到 `accept-all`，导致 allow event 没有 `ruleId`。第 34/35 步已经新增并验证 `allow-uid`，现在需要让 package rule helper 也走这条路径。

改动：

```text
poc-rules-to-vppctl.py:
  action=allow + uid -> mode allow-uid <uid>
  allow 缺 uid 或混入 dst -> 报错
```

规则生成：

```sh
ACTION=allow FAMILY=ip4 scripts/android-package-rules-json.sh com.sakamoto.snort.vpnlite /tmp/sakamoto-vpnlite-allow-rules.json
scripts/poc-rules-to-vppctl.py /tmp/sakamoto-vpnlite-allow-rules.json --event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-helper-allow-uid.ndjson
```

生成 CLI：

```text
nfqueue-poc enable queue 42 family ip4 mode allow-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-helper-allow-uid.ndjson
```

真实 app HTTP 验证：

```text
app log:
start host=142.251.13.94 port=80 path=/helper-allow
ok bytes=256 elapsedMs=659 first=HTTP/1.0 404 Not Found ...

show nfqueue-poc:
enabled 1 queue 42 family ip4 mode allow-uid drop-ratio 50 block-uid 12540 fd 12
seen 6 accept 6 drop 0 missing-id 0
payload-missing 0 parse-errors 0 rule-match 6 rule-miss 0
```

事件样例：

```json
{"uidKnown":true,"uid":12540,"dstIp":"142.251.13.94","verdict":"allow","reason":"uid_allow","ruleId":"allow-uid"}
```

清理验证：

```text
no app pid
no vpp pid
no queue 42 iptables rule
empty nfnetlink_queue
```

结论：package name -> UID -> JSON rule -> VPP CLI -> Android app-process HTTP allow attribution 这条链路闭环。后续 app/UI 可以先基于 package UID 静态 allow/block 做第一版解释，不需要完整规则引擎。

### 39. package block JSON helper -> real app-process block

问题：第 38 步闭合了 package allow helper。为了对称验证第一版 package 静态规则，block 也需要走 package JSON helper，而不是手写 CLI。

规则生成：

```sh
ACTION=block FAMILY=ip4 scripts/android-package-rules-json.sh com.sakamoto.snort.vpnlite /tmp/sakamoto-vpnlite-block-rules.json
scripts/poc-rules-to-vppctl.py /tmp/sakamoto-vpnlite-block-rules.json --event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-helper-block-uid.ndjson
```

生成 CLI：

```text
nfqueue-poc enable queue 42 family ip4 mode block-uid 12540 event-log /data/local/tmp/vpp-nfq-poc/logs/nfq-helper-block-uid.ndjson
```

真实 app HTTP 验证：

```text
app log:
start host=142.251.13.94 port=80 path=/helper-block
fail elapsedMs=5013 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /192.168.4.151 ... after 5000ms

show nfqueue-poc:
enabled 1 queue 42 family ip4 mode block-uid drop-ratio 50 block-uid 12540 fd 12
seen 3 accept 0 drop 3 missing-id 0
payload-missing 0 parse-errors 0 rule-match 3 rule-miss 0
```

事件样例：

```json
{"uidKnown":true,"uid":12540,"dstIp":"142.251.13.94","verdict":"block","reason":"uid_block","ruleId":"block-uid"}
```

清理验证：

```text
no app pid
no vpp pid
no queue 42 iptables rule
empty nfnetlink_queue
```

结论：package name -> UID -> JSON rule -> VPP CLI -> Android app-process HTTP block attribution 也闭环。package allow/block 两条最小规则链路都能用同一 helper 生成。

### 40. Android VPN mode per-app include/exclude POC

问题：root/NFQUEUE 模式可以从 NFQUEUE metadata 得到 UID；VPN/TUN 模式下 VPP 只看到 raw IP packet，没有 UID。第一版如果要在 VPN 模式做 app 粗粒度策略，需要验证 `VpnService.Builder.addAllowedApplication/addDisallowedApplication` 是否能作为 per-app 入口控制。

新增 adb-only POC extras：

```text
--es allowedPackage <package>
--es disallowedPackage <package>
```

Service 启动 VPN 时把这些 extras 传给：

```text
builder.addAllowedApplication(package)
builder.addDisallowedApplication(package)
```

#### disallowedPackage=self

命令要点：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity \
  --ez start true --es mode vpp-hev \
  --es disallowedPackage com.sakamoto.snort.vpnlite

adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity \
  --ez appHttpProbe true --es host 142.251.13.94 --ei port 80 --es path /vpn-disallowed
```

结果：

```text
app log:
ok bytes=256 elapsedMs=620 first=HTTP/1.0 404 Not Found ...

SOCKS log:
no connect 142.251.13.94:80
```

观察：SOCKS 仍看到一个 `74.125.142.188:5228` 背景连接，说明 full-route VPN 还在处理其它系统/Google app 的流量；被排除的是本实验 app 自己。

#### allowedPackage=self

命令要点：

```sh
adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity \
  --ez start true --es mode vpp-hev \
  --es allowedPackage com.sakamoto.snort.vpnlite

adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity \
  --ez appHttpProbe true --es host 142.251.13.94 --ei port 80 --es path /vpn-allowed
```

结果：

```text
app log:
ok bytes=40 elapsedMs=13 first=HTTP/1.0 200 OK  Content-Length: 2    OK

SOCKS log:
connect 142.251.13.94:80
GET /vpn-allowed HTTP/1.0
```

HEV log：

```text
socks5 client tcp -> [142.251.13.94]:80
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. VPN mode 可以用 VpnService Builder 的 allowed/disallowed app list 做 per-app 粗粒度 include/exclude。
2. 这不是 VPP 内部的 UID 识别；进入 TUN/VPP 后仍只有 IP packet。
3. 因此第一版如果要“按应用”选择 VPN 代理范围，可以先用 Builder app list；如果要在 VPN 内按应用解释每个 packet 的 allow/block，仍缺 per-packet UID 来源。
4. root/NFQUEUE 模式才是目前已验证的 UID attribution 路径。
```

### 41. Android VPN/VPP/HEV static IPv4 dst block inside tun_poc

问题：第 40 步证明 VPN mode 可以用 `VpnService.Builder` 做 per-app include/exclude，但进入 TUN/VPP 后没有 UID metadata。第一版 VPN mode 仍需要至少验证“VPP 内按静态 IP 规则拦截”是否可行。

实现：

```text
tun-poc enable ... block-ip4-dst <addr>
```

只在 TUN -> shim/HEV 的 `forward-fd` 出口方向检查 IPv4 dst：

```text
命中 dst -> drop packet, blocked_packets++, blocked_bytes++
未命中 -> 原样写入 shim fd 给 HEV
HEV -> TUN 回包方向不做过滤
```

app 启动参数：

```text
--es blockIp4Dst 142.251.13.94
```

native 写出的 VPP startup.exec：

```text
tun-poc enable fd 3 mode forward-fd shim-fd 4 block-ip4-dst 142.251.13.94
show tun-poc
```

验证配置：

```text
mode: vpp-hev
allowedPackage: com.sakamoto.snort.vpnlite
blockIp4Dst: 142.251.13.94
app HTTP probe: 142.251.13.94:80 /vpn-block
SOCKS5 smoke server: 127.0.0.1:41080
```

结果：

```text
app log:
start host=142.251.13.94 port=80 path=/vpn-block
fail elapsedMs=5010 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /10.111.0.2 ... after 5000ms

SOCKS log:
ready only; no connect 142.251.13.94:80

HEV log:
set limit nofile
no socks5 client tcp -> [142.251.13.94]:80
```

VPP counters：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 9 bytes 580 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 400
blocked 3 bytes 180 block-ip4-dst 142.251.13.94
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. VPN/VPP/HEV 路径里，VPP 可以在交给 HEV 前按静态 IPv4 dst drop。
2. app 侧表现为从 VPN 地址 10.111.0.2 发起连接后超时；SOCKS/HEV 都看不到目标连接。
3. 这补上了 VPN mode 的“静态 IP 规则拦截”最小 POC。
4. 这仍不解决 VPN mode 的 per-packet UID attribution；按应用选择 VPN 范围靠 Builder app list，按 IP/包内容拦截靠 VPP TUN path。
```

### 42. Android VPN/VPP/HEV no-block regression after tun_poc block rule

问题：第 41 步给 `tun_poc` 加了 `block-ip4-dst`。需要确认默认不传 `blockIp4Dst` 时，原有 VPN/VPP/HEV 转发不退化。

命令：

```sh
CYCLES=1 scripts/android-run-vpp-hev-app-http-loop.sh
```

结果：

```text
app log:
start host=142.251.13.94 port=80 path=/loop-1
ok bytes=40 elapsedMs=6 first=HTTP/1.0 200 OK  Content-Length: 2    OK

SOCKS log:
connect 142.251.13.94:80
GET /loop-1 HTTP/1.0

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 20 bytes 1643 tx 10 bytes 520
shim-rx 10 bytes 520 shim-tx 20 bytes 1643
blocked 0 bytes 0 block-ip4-dst -
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：`block-ip4-dst` 是 opt-in；默认 vpp-hev 转发路径保持可用。

### 43. Android root/NFQUEUE app-process public IPv6 static dst block

问题：第 36 步的 IPv6 静态 dst block 用的是 loopback `::1`。设备实际有 IPv6 路由后，需要验证公网 IPv6 目标也能被 root/NFQUEUE/VPP exact dst rule 拦截。

preflight：

```text
ip -6 route:
default via fe80::249b:8bff:fefd:87c5 dev wlan0 table 1047

ping6 2606:4700:4700::1111:
1 transmitted, 1 received, 0% packet loss

app HTTP baseline:
2606:4700:4700::1111:80 /ipv6-public -> HTTP/1.1 400 Bad Request, elapsedMs=306
```

NFQUEUE 规则：

```text
ip6tables -w -I OUTPUT 1 -p tcp -d 2606:4700:4700::1111 --dport 80 -m owner --uid-owner 12540 -j NFQUEUE --queue-num 42 --queue-bypass
```

`accept-all` 结果：

```text
app log:
start host=2606:4700:4700::1111 port=80 path=/ip6-public-accept
ok bytes=256 elapsedMs=396 first=HTTP/1.1 400 Bad Request ...

show nfqueue-poc:
enabled 1 queue 42 family ip6 mode accept-all drop-ratio 50 block-uid 0 fd 12
seen 5 accept 5 drop 0 missing-id 0
event: uid=12540 dstIp=2606:4700:4700::1111 verdict=allow reason=mode_accept_all
```

`block-ip6-dst 2606:4700:4700::1111` 结果：

```text
app log:
start host=2606:4700:4700::1111 port=80 path=/ip6-public-block
fail elapsedMs=5012 error=SocketTimeoutException: failed to connect to /2606:4700:4700::1111 (port 80) from /fd76:d462:c4e3:0:871a:d43:6032:9047 ... after 5000ms

show nfqueue-poc:
enabled 1 queue 42 family ip6 mode block-ip6-dst drop-ratio 50 block-uid 0 fd 12
seen 3 accept 0 drop 3 missing-id 0
payload-missing 0 parse-errors 0 rule-match 3 rule-miss 0
```

事件样例：

```json
{"uidKnown":true,"uid":12540,"dstIp":"2606:4700:4700::1111","verdict":"block","reason":"exact_ip6_dst","ruleId":"block-ip6-dst"}
```

清理验证：

```text
no app pid
no vpp pid
no queue 42 ip6tables rule
empty nfnetlink_queue
```

结论：root-mode IPv6 static dst block 不仅在 loopback 生效，也能拦截真实 app process 的公网 IPv6 TCP。第一版 IPv6 静态规则 POC 可以从 loopback 升级为实际网络结论。

### 44. Android VPN mode current IPv6 gap with IPv4-only VpnService

问题：root-mode 公网 IPv6 已验证。当前 VPN app 只配置：

```text
addAddress(10.111.0.2/32)
addRoute(0.0.0.0/0)
```

需要确认 VPN mode 下真实 app 公网 IPv6 是绕过 VPN、进入 VPN，还是直接不可达。

对照 baseline：

```text
无 VPN 时 app HTTP:
2606:4700:4700::1111:80 /ipv6-public -> HTTP/1.1 400 Bad Request, elapsedMs=306
```

VPN 配置：

```text
mode: vpp-hev
allowedPackage: com.sakamoto.snort.vpnlite
no IPv6 VPN address
no ::/0 route
app HTTP probe: 2606:4700:4700::1111:80 /vpn-ip6-current
```

结果：

```text
app log:
start host=2606:4700:4700::1111 port=80 path=/vpn-ip6-current
fail elapsedMs=6 error=NoRouteToHostException: Host unreachable

SOCKS log:
ready only; no connect 2606:4700:4700::1111:80

show tun-poc:
rx 6 bytes 400
shim-tx 6 bytes 400
blocked 0 bytes 0 block-ip4-dst -
```

HEV log：

```text
set limit nofile
no socks5 client tcp -> [2606:4700:4700::1111]:80
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. 设备本身有公网 IPv6 可达性，但当前 IPv4-only VPN 配置下，allowed app 的 IPv6 连接变成 NoRouteToHost。
2. 该 IPv6 流量没有绕过 VPN 成功直连，也没有进入 HEV/SOCKS。
3. VPN mode 要支持 IPv6，必须单独 POC addAddress(IPv6) + addRoute(::/0) + tun/HEV IPv6 forwarding。
```

### 45. Android VPN/VPP/HEV public IPv6 forwarding

问题：第 44 步确认 IPv4-only VPN 下 allowed app 的公网 IPv6 会 `NoRouteToHost`。现在验证显式加入 IPv6 VPN address/route 后，真实 app IPv6 是否能进入 VPP/HEV/SOCKS。

新增 adb-only extra：

```text
--ez enableIpv6 true
```

Service 配置：

```text
builder.addAddress("fd00:111:111::2", 128)
builder.addRoute("::", 0)
```

验证配置：

```text
mode: vpp-hev
allowedPackage: com.sakamoto.snort.vpnlite
enableIpv6: true
app HTTP probe: 2606:4700:4700::1111:80 /vpn-ip6-enabled
SOCKS5 smoke server: 127.0.0.1:41080
```

结果：

```text
app log:
start host=2606:4700:4700::1111 port=80 path=/vpn-ip6-enabled
ok bytes=40 elapsedMs=10 first=HTTP/1.0 200 OK  Content-Length: 2    OK

SOCKS log:
connect 2606:4700:4700::1111:80
GET /vpn-ip6-enabled HTTP/1.0
Host: 2606:4700:4700::1111

HEV log:
socks5 client tcp -> [2606:4700:4700::1111]:80
```

VPP counters：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 10 bytes 800 tx 4 bytes 284
shim-rx 4 bytes 284 shim-tx 10 bytes 800
blocked 0 bytes 0 block-ip4-dst -
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. VPN/VPP/HEV 可以转发真实 app process 的公网 IPv6 TCP。
2. 第 44 步的 NoRouteToHost 是 IPv4-only VPN 配置缺口，不是 HEV/VPP 不能处理 IPv6。
3. VPN mode 现在有 IPv4/IPv6 forwarding POC；下一步若需要规则，应给 tun_poc 增加 IPv6 static dst block。
```

### 46. Android VPN/VPP/HEV static IPv6 dst block inside tun_poc

问题：第 45 步证明 VPN/VPP/HEV 能转发公网 IPv6。现在补齐 VPN mode 的 IPv6 静态 dst block。

实现：

```text
tun-poc enable ... block-ip6-dst <addr>
```

和 IPv4 block 一样，只在 TUN -> shim/HEV 的 `forward-fd` 出口方向检查 dst，命中则 drop 并累加 `blocked` 计数。

app 启动参数：

```text
--ez enableIpv6 true
--es blockIp6Dst 2606:4700:4700::1111
```

native 写出的 VPP startup.exec：

```text
tun-poc enable fd 3 mode forward-fd shim-fd 4 block-ip6-dst 2606:4700:4700::1111
show tun-poc
```

验证配置：

```text
mode: vpp-hev
allowedPackage: com.sakamoto.snort.vpnlite
enableIpv6: true
blockIp6Dst: 2606:4700:4700::1111
app HTTP probe: 2606:4700:4700::1111:80 /vpn-ip6-block
SOCKS5 smoke server: 127.0.0.1:41080
```

结果：

```text
app log:
start host=2606:4700:4700::1111 port=80 path=/vpn-ip6-block
fail elapsedMs=5014 error=SocketTimeoutException: failed to connect to /2606:4700:4700::1111 (port 80) from /fd00:111:111::2 ... after 5000ms

SOCKS log:
ready only; no connect 2606:4700:4700::1111:80

HEV log:
set limit nofile
no socks5 client tcp -> [2606:4700:4700::1111]:80
```

VPP counters：

```text
enabled 1 fd 3 shim-fd 4 mode forward-fd
rx 9 bytes 700 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 460
blocked 3 bytes 240 block-ip4-dst -
block-ip6-dst 2606:4700:4700::1111
parse-errors 0 read-errors 0 write-errors 0 shim-read-errors 0 shim-write-errors 0
```

清理验证：

```text
no app pid
no vpp pid
no socks5 server process
no 41080 listener
```

结论：

```text
1. VPN/VPP/HEV 路径里，VPP 可以在交给 HEV 前按静态 IPv6 dst drop。
2. VPN mode 现在具备 IPv4 和 IPv6 static dst block POC。
3. 这仍然是 IP 规则，不是 per-packet app UID 规则；app 维度仍靠 VpnService Builder include/exclude。
```

## 2026-06-21

### 01. 创建实验分支和任务文档

分支：

```text
research/vpp-nfq-poc
```

起点提交：

```text
792ab80 docs: capture runtime and VPP datapath research
```

新增任务文档：

```text
docs/reviews/VPP_NFQUEUE_POC_EXPERIMENT_TASKS.md
```

提交：

```text
c434b47 docs: define VPP NFQUEUE POC tasks
```

结论：第一阶段只验证 Linux/Docker NFQUEUE verdict 和 idle CPU，不直接进入 Android/VPN/HEV/UID。

### 02. 创建纯 C NFQUEUE smoke harness

新增目录：

```text
experiments/vpp-nfq-poc/
```

主要入口：

```text
make docker-shell
make build-smoke
make smoke-accept
make smoke-drop
make smoke-ratio
make idle-cpu
```

提交：

```text
05f67d5 experiments: add NFQUEUE smoke POC harness
```

### 03. 宿主机直接编译 smoke 失败

命令：

```sh
make -C experiments/vpp-nfq-poc build-smoke
```

结果：

```text
libnetfilter_queue development package not found. Run: make docker-shell
```

处理：不污染宿主机安装依赖，改走 Docker lane。

### 04. Docker smoke 权限问题

最初只给：

```text
--cap-add NET_ADMIN
--cap-add NET_RAW
```

执行：

```sh
make smoke-accept
```

失败：

```text
mount --make-shared /run/netns failed: Operation not permitted
```

原因：Docker 内 `ip netns add` 需要 mount namespace 相关能力。

处理：smoke 容器加入：

```text
--cap-drop ALL
--cap-add NET_ADMIN
--cap-add NET_RAW
--cap-add SYS_ADMIN
--security-opt apparmor=unconfined
--security-opt seccomp=unconfined
--tmpfs /run
```

### 05. 纯 C NFQUEUE verdict smoke 通过

命令：

```sh
make smoke-accept
make smoke-drop
make smoke-ratio
make idle-cpu
```

结果：

```text
accept-all:     ping 20/20, seen=20 accept=20 drop=0
drop-all:       ping 0/20,  seen=20 accept=0  drop=20
drop-ratio=50:  ping 10/20, seen=20 accept=10 drop=10
idle-cpu:       nfq-smoke sampled at 0.0% CPU before and after traffic
```

踩坑：最初 `drop-ratio=50` 算法按 100 包窗口前半段 drop，20 个 ping 全落在 drop 区间，表现成 100% loss。已改为小样本也均匀交错的 deterministic ratio。

当前 metadata 观察：

```text
packet_id: present
hook: present, OUTPUT = 3
payload_len: present
outdev: present, 数字随容器网络模式变化
uid/gid: present, 当前为 root -> 0
timestamp: current config 下未出现
```

结论：Linux/Docker NFQUEUE harness 可用，足够进入 VPP adapter POC。

### 06. 引入 VPP fetch/build 脚本

新增脚本：

```text
scripts/fetch-vpp.sh
scripts/build-vpp.sh
```

默认 VPP 目录：

```text
experiments/vpp-nfq-poc/work/vpp
```

`work/` 已加入 `.gitignore`，VPP 源码和 build output 不进仓库。

### 07. VPP clone 第一次失败：work 目录权限

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh make fetch-vpp
```

失败：

```text
fatal: could not create work tree dir '.../experiments/vpp-nfq-poc/work/vpp': Permission denied
```

原因：host 创建的 bind mount 目录对容器 root 不可写。

处理：`run-container.sh` 创建 `VPP_WORK_ROOT` 后执行：

```sh
chmod 0777 "$VPP_WORK_ROOT"
```

### 08. VPP v26.02 clone 成功

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh make fetch-vpp
```

结果：

```text
VPP_DIR=.../experiments/vpp-nfq-poc/work/vpp
9258530
HEAD is now at 9258530 misc: VPP 26.02 Release Notes
```

宿主侧注意事项：因为 clone 是容器 root 做的，宿主直接跑 `git -C work/vpp status` 会触发 Git dubious ownership 保护。这不影响容器内 build。需要宿主侧 git 操作时使用 safe.directory 或修正 ownership。

### 09. VPP install-dep 第一次失败：cap-drop 下 sudo 不可用

命令：

```sh
DOCKER_NETWORK=bridge ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
sudo: PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted
sudo: no valid sudoers sources found, quitting
```

原因：smoke lane 默认 `--cap-drop ALL`，VPP upstream `make install-dep` 硬编码 `sudo -E apt-get`。

处理：增加 `DOCKER_CAP_PROFILE=default`。smoke lane 继续用收紧 caps；VPP build lane 使用 Docker 默认 capabilities。

### 10. VPP install-dep 第二次失败：apt 交互确认

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
Do you want to continue? [Y/n] Abort.
```

原因：VPP Makefile 的 `install-dep` 需要 `UNATTENDED=y` 才会传 `-y`。

处理：`build-vpp.sh` 对 install-dep 使用：

```sh
DEBIAN_FRONTEND=noninteractive make -C "$VPP_DIR" UNATTENDED=y install-dep
```

### 11. 当前进行中：VPP install-dep / build-release

当前命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

状态：

```text
VPP install-dep 已开始安装依赖。
计划安装 229 个包，下载约 251 MB，解包约 1335 MB。
```

等待结果：依赖安装完成后脚本会继续执行 upstream `make build-release -j 4`。

### 12. VPP install-dep 已通过，build-release 进入 external deps

状态更新：

```text
install-dep 已完成。
build-release 已进入 build-root/build-vpp-native/external 阶段。
```

观察到的非致命输出：

```text
fatal: ambiguous argument 'v26.02-rc0..': unknown revision or path not in the working tree.
```

推测原因：当前 VPP 是 `git clone --depth 1 --branch v26.02`，浅 clone 里没有 `v26.02-rc0` tag/history。VPP external build 里的版本/变更检测命令引用了 `v26.02-rc0..`。目前该输出没有立即终止 build，但后续如果造成失败，需要改 `fetch-vpp.sh` 从 shallow clone 改为 fetch 足够 tags/history。

当前 external deps 进度：

```text
DAQ 3.0.21 下载、checksum、extract、patch、configure 已通过。
正在下载/构建 intel-ipsec-mb v2.0。
```

### 13. external deps 继续推进

状态更新：

```text
DPDK 25.11 下载、checksum、extract、patch 已通过。
RDMA core 60.0 configure/build/install 已通过。
ipsec-mb 2.0 正在 build。
```

观察到 warning：

```text
Minimum required NASM version for SM3/SM4/SHA512-NI: 2.16.02
SM3/SM4/SHA512-NI code not compiled - update NASM.
```

当前容器 Debian bookworm 提供 NASM `2.16.01`。目前这只是禁用部分 crypto optimized code，build 仍继续；若后续 POC 不需要这类路径，可先接受。

### 14. external deps 进入 DPDK configure

状态更新：

```text
ipsec-mb 2.0 install 已通过。
DPDK 25.11 进入 meson configure。
```

观察到 warning：

```text
WARNING: Location '/root/Downloads' is ignored
```

这是 VPP external build 下载 Python wheel 时检查本地 fallback 目录，目录不存在；随后已从网络下载 `meson==0.57.2`、`pyelftools==0.33`、`wheel`、`setuptools` 等，当前不构成失败。

### 15. DPDK external build 继续推进中

状态更新：

```text
DPDK 25.11 meson configure 已通过，进入 ninja build。
当前观察到的最高进度约为 [1496/2170]。
```

当前没有新的 fatal error。前面出现的 `v26.02-rc0..` shallow clone 输出、NASM 版本 warning、`/root/Downloads` warning 仍按非阻塞问题处理，等待 build 的最终结果确认。

### 16. DPDK external build/install 已通过，进入 xdp-tools

状态更新：

```text
DPDK 25.11 ninja build 已跑完 [2170/2170]，headers/libs/pkgconfig/bin tools 已 install 到 build-root/install-vpp-native/external。
quicly 0.1.5-vpp install 已通过。
xdp-tools 1.5.5 下载、checksum、extract、patch、configure 已通过，正在 build。
```

观察到的非致命输出：

```text
Warning: Got more output options than URLs
```

该 warning 出现在下载 xdp-tools 后，但 checksum 通过，后续 patch/config/build 已继续推进；当前不视为阻塞。

### 17. external deps 完成，VPP 本体 configure/build 开始

状态更新：

```text
xdp-tools 1.5.5 install 已通过。
libcbor 0.13.0 install 已通过。
VPP configure 成功，进入 VPP 本体 ninja build。
当前观察到的 VPP 本体 build 进度约为 [776/3040]。
```

configure 关键信息：

```text
VPP version: 26.02-release
Build type: release
C compiler: Clang 14.0.6
Host/Target processor: x86_64
Plugins: snort 插件存在；未看到 upstream nfqueue 插件。
```

实验含义：当前原版 VPP 能在容器内完成配置并进入本体编译；NFQUEUE 接入大概率仍需要我们按 POC 目标新增/魔改 VPP 插件或 input node。

### 18. VPP core binaries 已开始产出，进入插件编译阶段

状态更新：

```text
VPP 本体 build 已越过基础库和一批 core tool。
已观察到 vppctl、vpp_get_stats、vpp_get_metrics、vat2、vpp_api_test 等目标完成链接。
当前进入 vpp_plugins 编译阶段，进度约为 [1741/3040]。
```

当前正在编译的相关插件包括：

```text
af_packet_plugin
af_xdp_plugin
```

实验含义：原版 VPP 的 Linux 包输入相关插件可以正常参与 build。后续 NFQUEUE POC 可以参考这些插件的 input/device/CLI 组织方式，但 NFQUEUE verdict 语义仍需要单独验证。

### 19. `bin/vpp` 已链接成功，插件编译继续

状态更新：

```text
VPP 主可执行文件 bin/vpp 已在 [1869/3040] 链接成功。
libvnet.so 已完成。
dpdk_plugin.so、af_packet_plugin.so、af_xdp_plugin.so 等已完成链接。
当前插件编译继续推进，进度约为 [2033/3040]。
```

实验含义：即使后续某个非关键插件失败，当前已经可以进一步确认最小 VPP binary 的启动/参数/idle 行为。不过本轮仍等待 upstream `make build-release` 完整结束后再做结论。

### 20. 构建进入 `snort_plugin`

状态更新：

```text
插件编译继续推进，已越过 sflow、sfdp_services 等插件。
当前进入 snort_plugin 编译，观察到 cli.c、format.c、interface.c、socket.c、snort_api.c、main.c 正在构建。
当前进度约为 [2720/3040]。
```

实验含义：VPP 26.02 的 `snort_plugin` 可以在本容器配置下参与 build，前面的 `libdaq.a` 依赖也已被 configure 找到。这个事实只说明 VPP 内置 Snort/DAQ 插件路径能编译，不代表 NFQUEUE 收包/verdict adapter 已存在。

### 21. VPP build-release 完整成功

最终结果：

```text
[3040/3040] Linking C shared library lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
@@@@ Installing vpp @@@@
...
Successfully installed vpp_papi-2.3.2
VPP build completed
```

命令退出码：

```text
0
```

观察到的非阻塞 warning：

```text
WARNING: Running pip as the 'root' user can result in broken permissions and conflicting behaviour with the system package manager.
```

这是 install 阶段构建/安装 `vpp_papi` wheel 时的 pip root warning。当前 Docker build lane 是一次性实验容器，暂不作为阻塞问题处理。

阶段结论：在 Docker/amd64/Linux 下，VPP v26.02 原版源码可以完成 `make build-release`，并成功构建 `snort_plugin.so`、`af_packet_plugin.so`、`af_xdp_plugin.so`、`tap_plugin.so`、`dpdk_plugin.so` 等关键插件。下一步需要确认产物路径、最小启动参数和 idle CPU 行为，然后再进入 NFQUEUE adapter POC。

### 22. 确认 VPP 产物路径和版本命令

踩坑：

```text
rtk find ... 不是 GNU find，会走 rtk 自己的 find 子命令。
后续要查本地文件树时使用 rtk /usr/bin/find ...
```

确认到的 VPP binary：

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp
experiments/vpp-nfq-poc/work/vpp/build-root/build-vpp-native/vpp/bin/vpp
```

确认到的 `snort_plugin.so`：

```text
experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
experiments/vpp-nfq-poc/work/vpp/build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/snort_plugin.so
```

版本命令：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/work/vpp/build-root/install-vpp-native/vpp/bin/vpp -v
```

输出：

```text
vpp v26.02-release built by root on f2a0f575d39a at 2026-06-21T14:45:41
```

结论：host 侧直接执行 `vpp -v` 可以返回版本。下一步可以基于 install tree 尝试最小 `unix { nodaemon }` 启动和 idle CPU 采样。

### 23. 同步 README / NOTES 的当前状态

更新内容：

```text
README.md: 增加 VPP Build Result，记录 v26.02 build 成功、产物路径、版本输出。
NOTES.md: 将 Next Checkpoint 从“先 clone/build VPP”改为“最小启动、idle CPU、nfqueue_poc 插件”。
```

构建命令示例统一为：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

### 24. 最小 VPP 启动第一次试跑

新增文件：

```text
experiments/vpp-nfq-poc/configs/minimal-startup.conf
experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

启动命令：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

结果：

```text
exit code 124
```

解释：`timeout` 到 5 秒后发送 SIGTERM，VPP 收到 SIGTERM 后退出；这说明最小配置下 VPP 可以常驻运行，不是立即启动失败。

观察到的非阻塞输出：

```text
pre-allocating 19 additional 2048K hugepages on numa node 0
falling back to non-hugepage backed buffer pool
vat_plugin_register: ... plugin not loaded
received SIGTERM ... exiting
```

当前判断：

```text
hugepage fallback 不阻塞最小启动，但后续可以尝试用 buffers page-size default 收掉噪声。
vat plugin 提示来自 plugin default disable 后 vat/vat2 侧仍扫描注册，不阻塞最小启动。
```

### 25. 最小启动配置收掉 hugepage fallback

配置调整：

```text
minimal-startup.conf 增加 buffers { page-size default }
```

再次执行：

```sh
/usr/bin/timeout 5s experiments/vpp-nfq-poc/scripts/run-vpp-minimal.sh
```

结果：

```text
exit code 124
```

观察：

```text
hugepage prealloc/fallback 输出消失。
仍有 vat_plugin_register: ... plugin not loaded 提示。
VPP 收到 timeout SIGTERM 后正常退出。
```

当前判断：最小 VPP 启动已经可重复；后续 idle CPU 采样可以用这个 config 作为基线。

### 26. 最小 VPP idle CPU 采样

新增脚本和 target：

```text
scripts/run-vpp-idle-cpu.sh
make vpp-idle-cpu
```

第一次采样方法：

```text
ps -L -p <pid> -o pid,tid,psr,pcpu,comm
```

结果约为：

```text
23.5%, 16.0%, 12.9%, 10.6%, 9.5%
```

问题：`ps %CPU` 是进程生命周期平均值，会被 VPP 启动阶段拉高，不能代表 idle 稳态。

脚本调整：改用 `/proc/<pid>/task/<tid>/stat` 的 `utime+stime` tick delta 计算瞬时 CPU，并增加 `WARMUP=3`。

在没有 `poll-sleep-usec` 时，瞬时 idle 约为：

```text
2.956%, 2.978%, 3.973%, 2.978%, 2.979%
```

配置调整：

```text
unix { poll-sleep-usec 1000 }
```

再次采样结果：

```text
0.992%, 0.992%, 1.985%, 0.993%, 0.993%
```

当前判断：最小 VPP 在没有收发流量时不是单核 100% busy loop；通过 `poll-sleep-usec 1000` 可以把当前宿主上的 idle CPU 降到约 1% 单线程。后续 NFQUEUE adapter 仍要验证启用 fd/input node 后 idle 是否保持这个量级。

### 27. 同步最小启动和 idle CPU 文档

更新内容：

```text
README.md: 增加 make vpp-idle-cpu 入口和最小 VPP idle 结果。
NOTES.md: 将 Next steps 更新为 nfqueue_poc 插件、VPP verdict smoke、NFQUEUE fd/input idle 复测。
```

当前明确结论：

```text
VPP v26.02 build 成功。
最小 VPP 可以启动。
最小 VPP 在 poll-sleep-usec 1000 下 idle 约 1% CPU，不是单核 100% busy loop。
尚未验证 VPP NFQUEUE adapter 的收包/verdict/idle。
```

### 28. 开始 `nfqueue_poc` overlay，宿主写入 VPP tree 权限失败

新增 overlay：

```text
experiments/vpp-nfq-poc/overlay/src/plugins/nfqueue_poc/
experiments/vpp-nfq-poc/scripts/apply-vpp-overlay.sh
make apply-vpp-overlay
```

首次在宿主执行：

```sh
make -C experiments/vpp-nfq-poc apply-vpp-overlay
```

失败：

```text
cp: cannot create directory '.../work/vpp/src/./plugins/nfqueue_poc': Permission denied
cp: preserving times for '.../work/vpp/src/./plugins': Operation not permitted
```

原因：`work/vpp` 是之前 Docker 容器 root clone/build 出来的，宿主用户没有写权限。

处理策略：不修改整个 VPP tree owner；后续用同一个 Docker lane 里的 root 执行 overlay apply/build：

```sh
DOCKER_CAP_PROFILE=default ./scripts/run-container.sh make apply-vpp-overlay
```

### 29. 容器 apply overlay 第二次失败：`cp -a` preserve ownership

容器内执行：

```sh
./scripts/run-container.sh make apply-vpp-overlay
```

失败：

```text
cp: failed to preserve ownership for '.../nfqueue_poc/*.c': Operation not permitted
```

原因：`cp -a` 会保留 owner/timestamp，当前 bind mount 不允许容器对这些目标执行 chown/utime。

处理：`apply-vpp-overlay.sh` 改为：

```sh
cp -R --no-preserve=ownership,timestamps "$OVERLAY_DIR/src/." "$VPP_DIR/src/"
```

### 30. overlay apply 成功

命令：

```sh
./scripts/run-container.sh make apply-vpp-overlay
```

结果：

```text
Applied overlay to .../experiments/vpp-nfq-poc/work/vpp
```

下一步：运行 VPP 增量 build，验证 `nfqueue_poc` CMake 和 C 代码是否能编译。

### 31. overlay 后第一次增量 build 失败：容器没有持久化 VPP build deps

命令：

```sh
./scripts/run-container.sh env JOBS=4 make build-vpp
```

失败：

```text
/usr/bin/bash: line 1: cmake: command not found
make[2]: *** [Makefile:644: vpp-configure] Error 127
```

原因：前一次 `VPP_INSTALL_DEPS=1` 是在一次性 Docker container 内安装 apt 包，容器退出后依赖没有固化到 `sakamoto-vpp-nfq-poc:dev` image。VPP build output 留在 bind mount，但重新 configure/build 仍需要 cmake/ninja/clang 等工具。

处理策略：本轮先重跑带网络的 build lane：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

后续可选优化：把 VPP build deps 烘进专用 Docker image，避免每次增量 build 都重新 apt install。

### 32. 子代理源码调查结论：原版无 NFQUEUE 插件，POC 先 CLI-only

Pauli 调查结论：

```text
原版 VPP tree 里没有现成 libnetfilter_queue / nfq_* 插件。
add_vpp_plugin() 支持 LINK_LIBRARIES。
最小 CLI-only 插件不需要 .api、API_FILES、node、multiarch。
```

建议参考路径：

```text
src/plugins/snort/      外部队列/fd/回注关系最接近
src/plugins/netmap/     简单 fd -> input node 参考
src/plugins/af_packet/  新式 interface/rx queue/fd-ready 参考
src/plugins/af_xdp/     新式 interface/rx queue/fd-ready 参考
src/plugins/tap/        fd-ready/rx queue 参考
src/plugins/memif/      fd-ready/connection lifecycle 参考
```

当前本轮 POC 选择：

```text
第一刀只做 CLI-only nfqueue_poc。
VPP clib_file read callback 直接 drain NFQUEUE fd，并在 libnetfilter_queue callback 中直接 NF_ACCEPT/NF_DROP。
暂不创建 VPP interface，不分配 vlib_buffer，不接 graph node。
```

原因：这个切片最小化变量，先验证 VPP 进程是否能持有 NFQUEUE fd 并给出 verdict。若通过，再进入 fd-ready -> input node -> buffer/graph 的第二刀。

### 33. 重跑 build 命令位置错误：Docker env 传进了容器内

错误命令：

```sh
./scripts/run-container.sh env DOCKER_NETWORK=bridge VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

失败：

```text
sudo: PERM_SUDOERS: setresuid(-1, 1, -1): Operation not permitted
```

原因：`DOCKER_NETWORK=bridge` 和 `DOCKER_CAP_PROFILE=default` 必须作为 `run-container.sh` 的宿主环境变量传入；放在 `env ... make build-vpp` 后面只会进入容器内部，不会影响 Docker run 参数。于是容器仍用了默认 `DOCKER_CAP_PROFILE=smoke`，cap-drop 下 sudo 失败。

正确命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

### 34. 正确 build lane 已启动

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

当前状态：

```text
install-dep 重新开始。
计划安装 229 个包，下载约 251 MB，解包约 1335 MB。
```

等待结果：依赖安装后会重新 configure/build VPP，并验证 `nfqueue_poc` overlay 是否被 CMake 发现和编译。

### 35. overlay 插件随 VPP build 成功安装

命令：

```sh
DOCKER_NETWORK=bridge DOCKER_CAP_PROFILE=default ./scripts/run-container.sh env VPP_INSTALL_DEPS=1 JOBS=4 make build-vpp
```

结果：

```text
VPP build completed
```

安装产物确认：

```text
work/vpp/build-root/install-vpp-native/vpp/include/vpp_plugins/nfqueue_poc/nfqueue_poc.h
work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/nfqueue_poc_plugin.so
```

结论：第一版 CLI-only `nfqueue_poc` overlay 已被 VPP CMake 发现，并完成编译、链接、安装。

下一步：做更小的启动验证，确认 VPP 能加载 `nfqueue_poc_plugin.so`，并且 CLI 命令可见；之后再进入真正 NFQUEUE verdict smoke。

### 36. 插件 CLI 检查前的运行时依赖检查

目的：在真正跑 NFQUEUE 前，先验证 VPP 能加载 `nfqueue_poc_plugin.so`，并且 `show nfqueue-poc` CLI 可见。

先检查主机依赖：

```sh
ldd work/vpp/build-root/install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins/nfqueue_poc_plugin.so
```

结果：

```text
libnetfilter_queue.so.1 => not found
```

结论：主机不能直接加载这个插件，CLI/queue 验证应在实验 Docker image 中跑，因为 image 内已安装 `libnetfilter-queue-dev`。

随后检查容器内 VPP 运行时依赖：

```sh
./scripts/run-container.sh ldd .../bin/vpp
```

结果：

```text
libunwind.so.8 => not found
```

处理：把 `libunwind8` 加入 `experiments/vpp-nfq-poc/Dockerfile`。这属于运行时依赖，不应该只依赖一次性 build container 里的 `make install-dep`。

额外坑：`run-container.sh` 使用固定容器名 `sakamoto-vpp-nfq-poc`，并发执行两个 `run-container.sh` 会冲突：

```text
Conflict. The container name "/sakamoto-vpp-nfq-poc" is already in use
```

当前处理：后续容器实验串行执行。

### 37. 增加插件 CLI 启动检查入口

新增：

```text
configs/nfqueue-poc-startup.conf
scripts/run-vpp-nfqueue-cli-check.sh
make vpp-nfqueue-cli-check
```

检查范围：

```text
1. 用只启用 nfqueue_poc_plugin.so 的 startup config 启动 VPP。
2. 等待 /tmp/sakamoto-vpp-nfq-poc/cli.sock 出现。
3. 用 vppctl 执行 show plugins。
4. 用 vppctl 执行 show nfqueue-poc。
```

当前状态：正在重建 Docker image，并运行：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

### 38. 插件 CLI 检查第一次运行失败：results 目录权限

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

失败点：

```text
./scripts/run-vpp-nfqueue-cli-check.sh: line 39:
/work/sakamoto-snort/experiments/vpp-nfq-poc/results/vpp-nfqueue-cli-check.log:
Permission denied
```

原因：`results/` 在宿主侧是 `0755 js:js`。当前 Docker 环境下容器 root 不能直接写这个 bind mount 目录。之前部分结果文件已有 `root:root`，说明这条路径容易产生权限不一致。

处理：`run-container.sh` 在宿主侧启动容器前执行：

```sh
mkdir -p "$POC_DIR/results"
chmod 0777 "$POC_DIR/results"
```

这样后续实验脚本可以稳定写入 `results/`。

### 39. 插件 CLI 检查通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-cli-check
```

结果：

```text
1. nfqueue_poc_plugin.so  26.02-release  NFQUEUE verdict POC
enabled 0 queue 0 mode accept-all drop-ratio 0 fd -1
seen 0 accept 0 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

结论：

```text
VPP 可以加载 nfqueue_poc_plugin.so。
CLI 注册成功：show nfqueue-poc 可用。
当前还没有验证 nfqueue-poc enable、NFQUEUE fd、verdict、真实包通过/丢弃。
```

下一步：把已有 plain C NFQUEUE smoke 的 netns/iptables 拓扑复用起来，改为由 VPP 插件持有 queue 42 并给出 accept/drop/drop-ratio verdict。

### 40. VPP NFQUEUE smoke 入口新增

新增：

```text
scripts/run-vpp-nfqueue-smoke.sh
make vpp-nfqueue-accept
make vpp-nfqueue-drop
make vpp-nfqueue-ratio
```

设计：

```text
1. 复用 setup-netns.sh 创建 nfq-host <-> nfq-peer，并插入 OUTPUT NFQUEUE 规则。
2. 启动只加载 nfqueue_poc_plugin.so 的 VPP。
3. vppctl: nfqueue-poc enable queue 42 mode <mode>。
4. ping -I nfq-host -c 20 10.200.42.2。
5. vppctl: show nfqueue-poc，读取 seen/accept/drop。
6. 根据 mode 检查 ping 返回码和 VPP verdict 计数。
```

### 41. VPP NFQUEUE accept-all 第一次运行：功能通过，脚本断言失败

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-accept
```

实际包处理结果：

```text
20 packets transmitted, 20 received, 0% packet loss
seen 20 accept 20 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
```

结论：VPP 插件已经能持有 NFQUEUE queue 42，并返回 `NF_ACCEPT` verdict。

脚本失败点：

```text
./scripts/run-vpp-nfqueue-smoke.sh: line 114: ping_rc: unbound variable
```

原因：脚本主体包在 `{ ... } | tee "$LOG"` 管道里执行，`ping_rc` 在 subshell 中赋值，管道结束后外层 shell 读不到。

处理：改为：

```sh
exec > >(tee "$LOG") 2>&1
```

主体流程不再放入管道，变量作用域保持在当前 shell。

### 42. VPP NFQUEUE accept-all 重跑通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-accept
```

结果：

```text
20 packets transmitted, 20 received, 0% packet loss
seen 20 accept 20 drop 0 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=0
```

结论：`accept-all` 路径完整通过。VPP 插件能接收 queue 42 上的 ICMP OUTPUT 包，并给出 `NF_ACCEPT` verdict。

### 43. VPP NFQUEUE drop-all 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-drop
```

结果：

```text
20 packets transmitted, 0 received, 100% packet loss
seen 20 accept 0 drop 20 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=1
```

结论：`drop-all` 路径完整通过。VPP 插件给出的 `NF_DROP` verdict 会让对应 NFQUEUE 包被内核丢弃。

### 44. VPP NFQUEUE drop-ratio=50 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-ratio
```

结果：

```text
20 packets transmitted, 10 received, 50% packet loss
seen 20 accept 10 drop 10 missing-id 0
handle-errors 0 recv-errors 0 enobufs 0
ping_rc=0
```

结论：混合 verdict 路径通过。VPP 插件可以对同一个 NFQUEUE queue 中的包逐包选择 `NF_ACCEPT` 或 `NF_DROP`。

当前 POC 已证明：

```text
1. 原版 VPP 加 overlay 后可以加载 Linux-only nfqueue_poc 插件。
2. VPP 进程可以持有 NFQUEUE fd。
3. VPP clib_file read callback 可以接收 queued packet。
4. VPP 插件 callback 可以对 packet id 调用 nfq_set_verdict。
5. accept/drop/ratio 三个行为都能反馈到内核转发结果。
```

下一步：在 `nfqueue-poc enable` 且无流量时重新测 VPP idle CPU，确认 fd-ready 路径没有退化成单核忙轮询。

### 45. VPP NFQUEUE enabled idle CPU 通过

命令：

```sh
./scripts/run-container.sh make vpp-nfqueue-idle-cpu
```

配置：

```text
nfqueue-poc enable queue 42 mode accept-all
SAMPLES=5 DELAY=1 WARMUP=3
```

无流量采样：

```text
vpp_main CPU%: 0.996, 1.993, 0.997, 0.997, 1.993
```

插入 5 个 ping 包：

```text
5 packets transmitted, 5 received, 0% packet loss
seen 5 accept 5 drop 0 missing-id 0
```

流量后再次空闲采样：

```text
vpp_main CPU%: 1.993, 0.996, 1.993, 0.000, 1.993
```

结论：在当前 `clib_file` fd-ready 直 verdict POC 中，`nfqueue-poc enable` 后 VPP 空闲 CPU 没有出现单核 100% 忙轮询，观测值和 minimal VPP 大致同量级。

这不等于最终性能结论；后续进入 vlib_buffer/graph/worker 版本后仍需重测。

### 47. Android VPN native packet tuple -> owner UID lookup

问题：VPN mode 下，`VpnService` 收到的 TCP/UDP packet 只有 L3/L4 tuple，没有 UID metadata。Android 官方提供
`ConnectivityManager.getConnectionOwnerUid()`；这里先不接规则引擎，只验证 active VPN 进程里能不能用 packet tuple 查回 app UID。

最小实现：

```text
SnortVpnService native mode:
  TUN packet -> native parser -> Java helper -> ConnectivityManager.getConnectionOwnerUid()

native parser:
  IPv4 TCP/UDP: src/dst address + src/dst port
  IPv6 TCP/UDP: no-extension-header baseline only

Java helper:
  queryConnectionOwnerUidForPacket(protocol, localAddress, localPort, remoteAddress, remotePort)
```

新增脚本：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-uid-poc
```

第一次运行问题：

```text
1. script 在 `cmd package list packages -U | awk ... exit` 上因为 pipefail/SIGPIPE 返回 141。
   修复为先收完整 package list 再 awk。

2. TCP 返回目标 APK UID，UDP 初次返回 -1。
   原因是 UDP DatagramSocket 发送后立刻关闭，owner 查询时连接记录已经不可见。
   修复为 connected UDP socket 发送后保持 3 秒再关闭。
```

通过结果：

```text
package_uid=12540

packet=8 len=60 ipv4 proto=6 10.111.0.2:41576 -> 142.251.13.94:80 ownerUid=12540
packet=9 len=52 ipv4 proto=17 10.111.0.2:52674 -> 8.8.8.8:53 ownerUid=12540

app HTTP probe:
  expected timeout, because native VPN probe does not forward packets.

app UDP probe:
  ok bytes=24 elapsedMs=3006
```

结论：

```text
VPN mode per-packet app attribution 的 0->1 能力成立：
  active VpnService process 可以从 TCP/UDP packet tuple 反查 UID。

当前只证明 native VPN probe 可以查 UID；还没有证明 VPP/HEV path 内联 UID block。
下一步若要把它用于 VPN mode 拦截，需要做一个更小的 gate POC：
  TUN read -> owner UID lookup -> drop/forward
然后再决定这个 gate 放在 VPP 前、VPP 父进程 bridge、还是 VPP 插件外部旁路。
```

### 48. Android VPN owner UID gate before VPP/HEV

问题：第 47 步只证明 `VpnService` native probe 能从 TCP/UDP tuple 查 UID。这里继续验证查到 UID 后能否在真实
`VPP -> HEV -> SOCKS5` 转发链路前阻断。

最小实现：

```text
新增 mode:
  vpp-hev-owner-gate

fd 拓扑：
  real Android TUN fd
    -> parent native gate thread
    -> SOCK_SEQPACKET fd used as VPP fd 3
    -> tun_poc forward-fd
    -> HEV shim fd 4
    -> SOCKS5 smoke server

gate 行为：
  TUN -> parse TCP/UDP tuple -> getConnectionOwnerUid()
  ownerUid == blockOwnerUid: drop
  otherwise: write packet to VPP fd
  VPP return packets: write back to real TUN fd
```

新增脚本：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-poc
```

通过结果：

```text
package_uid=12540
miss_uid=112540
```

allow-miss：

```text
block_uid=112540
app HTTP:
  HTTP/1.0 200 OK

gate:
  gate forward ... 10.111.0.2:59832 -> 142.251.13.94:80 ownerUid=12540

SOCKS:
  connect 142.251.13.94:80
```

block-hit：

```text
block_uid=12540
app HTTP:
  SocketTimeoutException from /10.111.0.2:53680 after 5000ms

gate:
  gate drop packet=7 len=60 proto=6 10.111.0.2:53680 -> 142.251.13.94:80 ownerUid=12540
  gate drop packet=8 len=60 proto=6 10.111.0.2:53680 -> 142.251.13.94:80 ownerUid=12540
  gate drop packet=9 len=60 proto=6 10.111.0.2:53680 -> 142.251.13.94:80 ownerUid=12540

SOCKS:
  connect count did not increase
```

结论：

```text
VPN mode 下按 package UID block 的 0->1 能力成立：
  active VpnService process 可以先查 UID，再在 VPP/HEV 前阻断命中 UID 的 TCP packet。

这不是最终架构结论：
  当前 gate 位于 parent native process，不在 VPP plugin 内。
  但它已经回答“VPN 模式能不能按 app UID 阻断”的基础问题：可以。
```

### 49. Android VPN native IPv6 packet tuple -> owner UID lookup

问题：第 47 步验证了 IPv4 TCP/UDP owner UID 查询。这里补 IPv6 TCP/UDP，避免后续误以为
`getConnectionOwnerUid()` 只覆盖 IPv4。

脚本改动：

```text
scripts/android-run-vpn-owner-uid-poc.sh
  IP_FAMILY=inet4: default, keeps previous IPv4 behavior
  IP_FAMILY=inet6: enables VpnService IPv6 address/route and probes IPv6 TCP/UDP

Makefile:
  android-vpn-owner-uid-poc
  android-vpn-owner-uid-ipv6-poc
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-uid-ipv6-poc
make -C experiments/vpp-nfq-poc android-vpn-owner-uid-poc
```

IPv6 结果：

```text
package_uid=12540

packet=8 len=80 ipv6 proto=6 fd00:111:111::2:58766 -> 2606:4700:4700::1111:80 ownerUid=12540
packet=9 len=72 ipv6 proto=17 fd00:111:111::2:40353 -> 2606:4700:4700::1111:53 ownerUid=12540

app HTTP probe:
  expected timeout, because native VPN probe does not forward packets.

app UDP probe:
  ok bytes=24 elapsedMs=3009
```

回归：

```text
默认 IPv4 owner UID POC 重跑通过：
  ipv4 proto=6 ownerUid=12540
  ipv4 proto=17 ownerUid=12540
```

结论：

```text
VPN mode owner UID lookup 现在覆盖 IPv4/IPv6 + TCP/UDP 的最小常规包头。
当前 IPv6 parser 仍是 no-extension-header baseline；真实产品前如果要处理 IPv6 extension headers，需要单独补 walker。
```

### 50. Android VPN IPv6 owner UID gate before VPP/HEV

问题：第 48 步证明 IPv4 owner UID gate 可以在 VPP/HEV 前阻断。这里补 IPv6 forwarding path 上的 owner UID gate。

脚本改动：

```text
scripts/android-run-vpn-owner-gate-poc.sh
  IP_FAMILY=inet4: default IPv4 gate
  IP_FAMILY=inet6: enables VpnService IPv6 address/route and probes public IPv6

Makefile:
  android-vpn-owner-gate-poc
  android-vpn-owner-gate-ipv6-poc
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-ipv6-poc
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-poc
```

IPv6 allow-miss：

```text
block_uid=112540
app HTTP:
  HTTP/1.0 200 OK

gate:
  gate forward packet=7 len=80 proto=6 fd00:111:111::2:46714 -> 2606:4700:4700::1111:80 ownerUid=12540

HEV:
  socks5 client tcp -> [2606:4700:4700::1111]:80

SOCKS:
  connect 2606:4700:4700::1111:80
```

IPv6 block-hit：

```text
block_uid=12540
app HTTP:
  SocketTimeoutException from /fd00:111:111::2:47934 after 5000ms

gate:
  gate drop packet=7 len=80 proto=6 fd00:111:111::2:47934 -> 2606:4700:4700::1111:80 ownerUid=12540
  gate drop packet=8 len=80 proto=6 fd00:111:111::2:47934 -> 2606:4700:4700::1111:80 ownerUid=12540
  gate drop packet=9 len=80 proto=6 fd00:111:111::2:47934 -> 2606:4700:4700::1111:80 ownerUid=12540

SOCKS:
  connect count did not increase
```

回归：

```text
默认 IPv4 owner gate POC 重跑通过：
  allow-miss: HTTP/1.0 200 OK
  block-hit: gate drop ownerUid=12540, SOCKS connect count unchanged
```

观察：

```text
IPv6 allow-miss 中连接后段 packet 偶尔返回 ownerUid=-1。
这说明 getConnectionOwnerUid 的可见窗口仍然重要；真实实现需要在首包/SYN 阶段建 flow owner cache。
当前 block-hit 在 SYN/retry 阶段已经稳定拿到 ownerUid=12540 并 drop。
```

结论：

```text
VPN owner UID gate 现在覆盖 IPv4/IPv6 TCP 转发路径。
加上第 49 步的 UDP owner lookup，VPN mode 的 package UID static block 0->1 风险基本解除。
```

### 51. Android VPN UDP owner UID gate before VPP/HEV

问题：第 48/50 步验证了 TCP gate，UDP 只在第 47/49 步验证了 owner lookup。这里补 UDP gate 的 hit/miss 判定。

范围：

```text
验证 gate decision：
  UDP ownerUid miss -> forward to VPP fd
  UDP ownerUid hit  -> drop before VPP

不验证 SOCKS UDP 端到端响应：
  当前 smoke server 不是完整 UDP ASSOCIATE server。
```

新增脚本：

```text
scripts/android-run-vpn-owner-gate-udp-poc.sh

Makefile:
  android-vpn-owner-gate-udp-poc
  android-vpn-owner-gate-udp-ipv6-poc
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-udp-poc
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-udp-ipv6-poc
```

IPv4 结果：

```text
allow-miss:
  gate forward packet=7 len=52 proto=17 10.111.0.2:59604 -> 8.8.8.8:53 ownerUid=12540

block-hit:
  gate drop packet=7 len=52 proto=17 10.111.0.2:41175 -> 8.8.8.8:53 ownerUid=12540
```

IPv6 结果：

```text
allow-miss:
  gate forward packet=7 len=72 proto=17 fd00:111:111::2:43417 -> 2606:4700:4700::1111:53 ownerUid=12540

block-hit:
  gate drop packet=7 len=72 proto=17 fd00:111:111::2:58032 -> 2606:4700:4700::1111:53 ownerUid=12540
```

结论：

```text
VPN owner UID gate 已覆盖：
  IPv4 TCP block/allow
  IPv6 TCP block/allow
  IPv4 UDP gate forward/drop
  IPv6 UDP gate forward/drop

对 0->1 来说，VPN mode 按 package UID 做静态拦截已经成立。
后续工程设计需要补 flow owner cache、规则更新接口、以及是否把 gate 固化在 VPP 前还是重新设计 VPP/plugin 边界。
```

### 52. Android VPN owner gate flow-owner cache fallback

问题：第 50 步观察到同一个 TCP flow 后段 packet 可能返回 `ownerUid=-1`。这不是首包 block 的阻塞问题，但会影响后续
allow/telemetry/规则变更语义。这里做最小 flow owner cache POC。

最小实现：

```text
owner gate thread local cache:
  key: protocol + local addr/port + remote addr/port
  value: uid
  size: 64 fixed slots, round-robin replacement

gate behavior:
  getConnectionOwnerUid() >= 0:
    store tuple -> uid
  getConnectionOwnerUid() < 0:
    if tuple cache hit, use cached uid and log cached=1
```

命令：

```sh
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-poc
make -C experiments/vpp-nfq-poc android-vpn-owner-gate-ipv6-poc
```

结果：

```text
IPv4 gate regression:
  allow/block POC passed.
  This run did not need fallback; all logged TCP packets returned uid directly.

IPv6 gate:
  gate forward packet=7  ... ownerUid=12540 cached=0
  gate forward packet=8  ... ownerUid=12540 cached=0
  gate forward packet=9  ... ownerUid=12540 cached=0
  gate forward packet=10 ... ownerUid=12540 cached=0
  gate forward packet=11 ... ownerUid=12540 cached=1
```

结论：

```text
getConnectionOwnerUid 的可见窗口问题有最小可行缓解：
  首次查询成功后，同 flow 后续 packet 可以从本地 tuple cache 恢复 owner UID。

这仍不是产品设计：
  cache size、eviction、TCP close、UDP timeout、policy epoch 都还需要后续接口/规则设计时决定。
```

### 53. Scope correction: owner gate is not VPP-internal filtering

问题：第 48/50/51/52 步把“VPN mode 能不能按 owner UID 阻断”验证成了 parent native gate：

```text
real TUN fd -> parent native gate -> VPP fd -> tun_poc -> HEV
```

这不满足当前 POC 目标。目标必须是：

```text
real TUN fd -> VPP plugin/node -> VPP decides drop/forward -> HEV
```

重新分类：

```text
Experiment 47/49:
  保留为 Android API 可用性 POC。
  只证明 active VpnService 进程可以 tuple -> UID。

Experiment 48/50/51:
  降级为 mis-scoped。
  它们证明 parent native gate 可阻断，但没有证明 VPP 内部过滤。

Experiment 52:
  降级为 mis-scoped。
  它证明 parent native cache 可恢复 owner UID，但没有证明 VPP 内部 owner cache。
```

修正后的下一步：

```text
1. 先验证当前 tun_poc 在 VPP 多线程启动时实际在哪个 VPP thread 处理 fd-read packet。
2. 验证 VPP worker/handoff/redirect 能否把一个软件读取的 packet 交给指定 worker。
3. 再做 VPP 内部 tuple -> UID resolver POC：
   VPP parses packet tuple -> asks Java/NDK resolver -> VPP receives uid -> VPP plugin decides drop/forward.
```

结论：

```text
VPN mode VPP-internal UID filtering remains unverified.
The packet decision must move back into VPP.
```

### 54. VPP workers do not automatically receive `tun_poc` fd callbacks

问题：当前 `tun_poc` 使用 `clib_file` fd-ready 回调从 TUN fd / shim fd 读包。VPP 多 worker 启动时，这些 packet 是否会被自动分流到 worker？

最小实现：

```text
tun_poc:
  record vlib_get_thread_index() on main fd callback
  record vlib_get_thread_index() on shim fd callback
  show tun-poc prints:
    thread-hits main last ...
    thread-hits shim last ...

startup config:
  cpu { workers 2 }
```

新增：

```text
configs/tun-poc-workers-startup.conf
scripts/run-vpp-tun-worker-thread-smoke.sh
make vpp-tun-worker-thread-smoke
```

命令：

```sh
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-worker-thread-smoke
```

结果：

```text
show threads:
0      vpp_main
1      vpp_wk_0
2      vpp_wk_1

after ping:
thread-hits main last 0 t0 2 t1 0 t2 0 t3 0 overflow 0
thread-hits shim last 0 t0 1 t1 0 t2 0 t3 0

ping:
  1 transmitted, 1 received
```

结论：

```text
当前 tun_poc adapter 形状不会自动分流到 VPP worker。
TUN fd read、shim fd read 都发生在 VPP thread 0，即 vpp_main。

如果要让 VPP 内部多线程处理 VPN/TUN packet，必须显式做软件 steering/handoff。
下一步应验证：从 thread 0 软件读入 packet 后，能否通过 VPP handoff/redirect 机制交给指定 worker node 处理。
```

### 55. VPP frame-queue handoff can move TUN packets to a worker

问题：如果 TUN fd 事件只在 thread 0 触发，VPP 内部能不能把软件读入的 packet 转成 VPP buffer，再通过 VPP frame queue 交给 worker node？

最小实现：

```text
tun_poc handoff-probe mode:
  clib_file fd-ready callback:
    only records thread hit and calls vlib_node_set_interrupt_pending()

  tun-poc-rx-handoff input node:
    runs on VPP thread 0
    reads TUN fd
    allocates one VPP buffer
    copies packet bytes into the buffer
    calls vlib_buffer_enqueue_to_thread(... target-thread 1 ...)

  tun-poc-worker-probe internal node:
    receives the frame queue packet on worker thread
    records thread hit
    counts bytes
    frees the buffer
```

新增：

```text
scripts/run-vpp-tun-handoff-probe-smoke.py
make vpp-tun-handoff-probe-smoke
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-probe-smoke
```

结果：

```text
show threads:
0      vpp_main
1      vpp_wk_0
2      vpp_wk_1

after ping:
handoff target-thread 1 fq 34 enqueued 2 bytes 132 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 132
thread-hits main last 0 t0 2 t1 0 t2 0 t3 0 overflow 0
thread-hits rx-node last 0 t0 2 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0
```

结论：

```text
VPP 内部 handoff 方向成立：
  fd-ready callback / TUN rx input node 仍在 thread 0
  packet 进入 VPP buffer 后，可以用 vlib_buffer_enqueue_to_thread()
  交给指定 worker thread 的 internal node 处理

这回答了“发现包不该当前线程处理时，能不能用 VPP 内部机制重定向”的 0->1：
  可以，但需要 packet 已经是 VPP buffer，并且 enqueue 调用发生在 VLIB node 上下文里。

边界：
  当前 worker-probe node 只计数并 free buffer，没有把 packet 再送回 forward-fd/HEV 路径。
  下一步要验证 worker 上做静态规则 verdict 后，是否能 drop 或继续转发到 shim/HEV。
```

### 56. VPP worker can forward handoff TUN packets to shim fd

问题：第 55 步只证明 packet 可以被 handoff 到 worker 并计数/free。还需要验证 worker 上处理完 packet 后，能不能继续走当前 `forward-fd`/HEV 形态，把包写到 shim fd。

最小实现：

```text
新增 tun_poc mode:
  handoff-forward-fd

path:
  TUN fd ready on thread 0
  -> tun-poc-rx-handoff input node reads packet on thread 0
  -> vlib_buffer_enqueue_to_thread(target-thread 1)
  -> tun-poc-worker-probe runs on worker thread 1
  -> worker node writes packet bytes to shim fd
  -> shim fd callback reads reply on thread 0 and writes back to TUN
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-forward-fd-smoke
```

结果：

```text
show threads:
0      vpp_main
1      vpp_wk_0
2      vpp_wk_1

after ping:
enabled 1 fd 53 shim-fd 54 mode handoff-forward-fd
rx 2 bytes 132 tx 1 bytes 84
shim-rx 1 bytes 84 shim-tx 2 bytes 132
handoff target-thread 1 fq 34 enqueued 2 bytes 132 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 132
thread-hits rx-node last 0 t0 2 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

ping:
  1 transmitted, 1 received, 0% packet loss
```

结论：

```text
VPP 内部 worker verdict/forward 的基本路径成立：
  packet 可以从 thread 0 TUN input handoff 到 worker
  worker 可以做处理后把 packet 写到 shim fd
  现有 shim read-back 路径可以完成 ping 闭环

这仍是 POC：
  worker node 直接写 shim fd，不是完整 VPP interface/graph 设计。
  下一步要在 worker 上验证 static rule drop/allow，尤其 IPv4/IPv6 dst block。
```

### 57. VPP worker can drop handoff TUN packets by IPv4 static dst rule

问题：第 56 步证明 worker 可以 forward 到 shim。现在验证 worker 上执行静态规则 verdict 是否能真的 drop packet。

最小实现：

```text
mode:
  handoff-forward-fd

rule:
  block-ip4-dst 198.19.0.2

expected:
  TUN packet handoff 到 worker thread 1
  worker 匹配 IPv4 dst 后计入 blocked
  worker 不写 shim fd
  ping 超时失败
```

命令：

```sh
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-forward-fd-ipv4-drop
```

结果：

```text
after ping:
enabled 1 fd 53 shim-fd 54 mode handoff-forward-fd
rx 2 bytes 132 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 1 bytes 48
blocked 1 bytes 84 block-ip4-dst 198.19.0.2
handoff target-thread 1 fq 34 enqueued 2 bytes 132 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 132
thread-hits rx-node last 0 t0 2 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

ping:
  1 transmitted, 0 received, 100% packet loss
```

结论：

```text
VPP worker-side IPv4 static dst drop 成立。
packet verdict 在 VPP worker node 内完成，不是在 parent native gate。

边界：
  这里只验证 IPv4 dst exact match。
  下一步需要验证 worker-side IPv4 miss/allow 和 IPv6 dst drop。
```

### 58. VPP worker IPv4 static dst miss still forwards

问题：第 57 步证明 worker 上 IPv4 dst match 可以 drop。这里验证 miss/allow：配置一个不匹配目标地址的 IPv4 block rule，目标 packet 应继续转发。

命令：

```sh
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-forward-fd-ipv4-miss
```

结果：

```text
rule:
  block-ip4-dst 198.19.0.99

actual ping dst:
  198.19.0.2

after ping:
rx 2 bytes 132 tx 1 bytes 84
shim-rx 1 bytes 84 shim-tx 2 bytes 132
blocked 0 bytes 0 block-ip4-dst 198.19.0.99
handoff target-thread 1 fq 34 enqueued 2 bytes 132 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 132
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

ping:
  1 transmitted, 1 received, 0% packet loss
```

结论：

```text
VPP worker-side IPv4 static dst rule does not overmatch:
  exact dst miss forwards to shim
  ping succeeds

IPv4 worker-side static rule 0->1 now has both match/drop and miss/allow coverage.
```

### 59. VPP worker can drop handoff TUN packets by IPv6 static dst rule

问题：验证 worker-side static rule 在 IPv6 下也能 drop，并且 verdict 仍发生在 VPP worker node 内。

命令：

```sh
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-forward-fd-ipv6-drop
```

配置：

```text
mode:
  handoff-forward-fd

TUN:
  fd00:42::1/64 -> fd00:42::2

rule:
  block-ip6-dst fd00:42::2
```

结果：

```text
shim observed:
  fe80::... -> ff02::2 icmp_type=133 len=48
  no fd00:42::1 -> fd00:42::2 echo request reached shim

after ping:
rx 2 bytes 152 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 1 bytes 48
blocked 1 bytes 104 block-ip6-dst fd00:42::2
handoff target-thread 1 fq 34 enqueued 2 bytes 152 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 152
thread-hits rx-node last 0 t0 2 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

ping:
  1 transmitted, 0 received, 100% packet loss
```

结论：

```text
VPP worker-side IPv6 exact dst drop 成立。
和 IPv4 一样，packet 已 handoff 到 worker thread 后才做 verdict。

当前 worker-side static rule 覆盖：
  IPv4 match/drop
  IPv4 miss/allow
  IPv6 match/drop
```

### 60. VPP worker parses IPv4 TCP/UDP tuples after TUN handoff

问题：后续 VPN UID resolver 需要 VPP 内部先解析 packet tuple。这里先验证 handoff 到 worker 后，VPP worker node 能解析 IPv4 TCP/UDP 的 src/dst/port。

最小实现：

```text
tun_poc worker node:
  parse IPv4 IHL / total length / protocol
  if protocol is TCP or UDP:
    record src addr, dst addr, src port, dst port
  show tun-poc:
    tuple parsed ...
    last-tuple ip4 proto ...
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-tuple-smoke
```

结果：

```text
after udp:
tuple parsed 1 errors 0 non-tcp-udp 1 last-valid 1
last-tuple ip4 proto 17 198.19.20.1:43001 -> 198.19.20.2:53001
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

after tcp:
tuple parsed 2 errors 0 non-tcp-udp 1 last-valid 1
last-tuple ip4 proto 6 198.19.20.1:43002 -> 198.19.20.2:53002
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
```

结论：

```text
VPP worker-side IPv4 TCP/UDP tuple parsing 成立。
这仍没有接 Android ConnectivityManager UID resolver；它只验证 VPP 内部能提供 resolver 所需 tuple。

下一步：
  验证 IPv6 TCP/UDP tuple parsing。
  然后再接 mock resolver / Android resolver。
```

### 61. VPP worker parses IPv6 TCP/UDP tuples after TUN handoff

问题：补齐 IPv6 TCP/UDP tuple parse。当前只验证普通 IPv6 base header，不覆盖 extension headers。

变更：

```text
show tun-poc:
  IPv6 last-tuple uses [addr]:port format to avoid colon ambiguity

tuple smoke:
  supports --ip-family inet6
  sends UDP and TCP through an IPv6 TUN route
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-tuple-ipv6-smoke
```

结果：

```text
after udp:
tuple parsed 1 errors 0 non-tcp-udp 1 last-valid 1
last-tuple ip6 proto 17 [fd00:43::1]:43001 -> [fd00:43::2]:53001
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

after tcp:
tuple parsed 2 errors 0 non-tcp-udp 1 last-valid 1
last-tuple ip6 proto 6 [fd00:43::1]:43002 -> [fd00:43::2]:53002
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
```

结论：

```text
VPP worker-side IPv6 TCP/UDP tuple parsing 成立。
VPP 内部现在能为 IPv4/IPv6 + TCP/UDP 提供 tuple。

边界：
  IPv6 extension headers 尚未处理。
  tuple->UID resolver 仍未接到 VPP worker path。
```

### 62. VPP worker can query a mock tuple owner resolver

问题：第 60/61 步只证明 VPP worker 能解析 tuple。这里验证 VPP worker 能把 tuple 发给外部 resolver fd，收到 UID，并把 UID 留在 VPP 内部状态。这个 resolver 先用 Python socketpair mock，后续可替换为 Android Java/NDK bridge。

最小实现：

```text
tun_poc CLI:
  resolver-fd <n>

worker behavior:
  parse TCP/UDP tuple
  write text query to resolver fd:
    resolve ip4 proto 17 198.19.30.1 43101 198.19.30.2 53101
  poll/read response:
    uid 4242
  record resolver queries/hits/errors/last-uid
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-resolver-smoke
```

结果：

```text
resolver query: resolve ip4 proto 17 198.19.30.1 43101 198.19.30.2 53101
after udp:
resolver enabled 1 fd 55 queries 1 hits 1 errors 0 last-uid 4242
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0

resolver query: resolve ip4 proto 6 198.19.30.1 43102 198.19.30.2 53102
after tcp:
resolver enabled 1 fd 55 queries 2 hits 2 errors 0 last-uid 4242
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
```

结论：

```text
VPP worker -> external tuple owner resolver -> UID response 的同步 POC 成立。
packet verdict 仍在 VPP worker path 内；resolver 只提供 UID。

边界：
  resolver 是 Docker/Python mock，不是 Android ConnectivityManager。
  当前只记录 UID，不基于 UID drop/allow。
  同步 poll/read 会阻塞 worker，产品化时需要异步、cache、timeout 策略。
```

### 63. VPP worker can drop by mock resolver UID

问题：第 62 步只证明 VPP worker 能拿到 mock UID。这里验证 packet verdict 也能留在 VPP worker：resolver 返回 UID 后，worker 根据 UID drop，不写 shim。

最小实现：

```text
tun_poc CLI:
  block-owner-uid 4242

worker behavior:
  parse tuple
  query resolver
  if last_owner_uid == block_owner_uid:
    increment uid-block and blocked counters
    free VPP buffer
    do not write shim fd
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-resolver-uid-drop
```

结果：

```text
resolver query: resolve ip4 proto 17 198.19.30.1 43101 198.19.30.2 53101
after udp:
resolver enabled 1 fd 55 queries 1 hits 1 errors 0 last-uid 4242
uid-block enabled 1 uid 4242 packets 1 bytes 37
shim-rx 0 bytes 0 shim-tx 1 bytes 48

resolver query: resolve ip4 proto 6 198.19.30.1 43102 198.19.30.2 53102
after tcp:
resolver enabled 1 fd 55 queries 2 hits 2 errors 0 last-uid 4242
uid-block enabled 1 uid 4242 packets 2 bytes 97
blocked 2 bytes 97
shim-rx 0 bytes 0 shim-tx 1 bytes 48
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
```

结论：

```text
VPP-internal UID verdict POC 成立：
  resolver 只提供 UID
  drop verdict 在 VPP worker node 内执行
  UDP/TCP packet 都没有继续写到 shim

边界：
  resolver 仍是 mock，不是 Android ConnectivityManager。
  当前是同步阻塞查询，没有 owner cache。
```

### 64. VPP worker can redirect a handed-off packet to another worker

问题：前面的 handoff 只证明 main/input node 可以把 TUN 包送到 worker 1。这里验证如果
worker 1 发现包应该由别的 worker 处理，是否还能使用 VPP 内部机制把同一个 VPP buffer
再送到 worker 2。

最小实现：

```text
tun_poc CLI:
  redirect-thread <n>

worker behavior:
  tun-poc-rx-handoff reads TUN fd on thread 0
  frame queue sends VPP buffer to tun-poc-worker-probe on thread 1
  worker-probe re-enqueues that buffer to tun-poc-worker-redirect on thread 2
  worker-redirect performs the normal handoff-forward-fd write to shim
```

命令：

```sh
./scripts/run-container.sh make vpp-tun-poc-build
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-forward-fd-redirect-smoke
```

结果：

```text
show threads:
0 vpp_main
1 vpp_wk_0
2 vpp_wk_1

after ping:
handoff target-thread 1 fq 34 enqueued 2 bytes 132 congestion-drops 0 alloc-errors 0 worker-packets 2 bytes 132
redirect enabled 1 target-thread 2 fq 35 enqueued 2 bytes 132 congestion-drops 0 worker-packets 2 bytes 132
thread-hits main last 0 t0 2 t1 0 t2 0 t3 0
thread-hits rx-node last 0 t0 2 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 2 t3 0
ping: 1 transmitted, 1 received, 0% packet loss
```

结论：

```text
VPP 内部 worker->worker redirect POC 成立。
这个路径没有绕过 VPP：包已经是 VPP buffer，worker 1 通过 frame queue 转给 worker 2，
worker 2 再执行后续转发。

边界：
  这里只验证短路径 ICMP forward。
  还没验证生产级 sharding 策略、顺序语义、resolver/cache 在 re-handoff 下的行为或性能。
```

### 65. Redirected VPP worker can query mock resolver and drop by UID

问题：第 64 步只证明 worker->worker redirect 后还能 forward ICMP。这里验证真正的
TCP/UDP tuple -> resolver -> UID verdict 能否放在第二个 worker 上执行。

最小实现：

```text
tun_poc CLI:
  target-thread 1
  redirect-thread 2
  resolver-fd 55
  block-owner-uid 4242

worker behavior:
  worker 1 receives the VPP buffer and re-enqueues it
  worker 2 parses IPv4 UDP/TCP tuple
  worker 2 queries mock resolver
  worker 2 drops packets whose returned UID is 4242
```

命令：

```sh
DOCKER_CAP_PROFILE=smoke DOCKER_TUN_DEVICE=1 ./scripts/run-container.sh make vpp-tun-handoff-resolver-redirect-uid-drop
```

结果：

```text
after udp:
redirect enabled 1 target-thread 2 fq 35 enqueued 2 bytes 85 congestion-drops 0 worker-packets 2 bytes 85
last-tuple ip4 proto 17 198.19.30.1:43101 -> 198.19.30.2:53101
resolver enabled 1 fd 55 queries 1 hits 1 errors 0 last-uid 4242
uid-block enabled 1 uid 4242 packets 1 bytes 37
thread-hits worker-probe last 1 t0 0 t1 2 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 2 t3 0

after tcp:
redirect enabled 1 target-thread 2 fq 35 enqueued 3 bytes 145 congestion-drops 0 worker-packets 3 bytes 145
last-tuple ip4 proto 6 198.19.30.1:43102 -> 198.19.30.2:53102
resolver enabled 1 fd 55 queries 2 hits 2 errors 0 last-uid 4242
uid-block enabled 1 uid 4242 packets 2 bytes 97
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 3 t3 0
```

结论：

```text
worker-to-worker redirect 后继续做 VPP-internal UID verdict 成立。
resolver 仍只提供 UID；drop verdict 在第二个 VPP worker node 内执行。

边界：
  resolver 仍是 Docker/Python mock，不是 Android ConnectivityManager。
  没有验证 sharding 策略、顺序语义、负载、异步查询或 owner cache。
```

### 66. Android VPP/HEV can use VPP worker handoff

问题：Docker 已验证 `handoff-forward-fd`，但 Android packaged VPP 仍可能因为线程、fd、
stage 版本或 HEV socketpair 差异失败。这里验证真实 Pixel 6a 上，app HTTP 能进入
`VpnService -> packaged VPP worker -> HEV -> SOCKS5`。

最小实现：

```text
Android mode:
  vpp-hev-handoff

native startup:
  cpu { workers 2 }
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1

test:
  allowedPackage = com.sakamoto.snort.vpnlite
  app HTTP probe -> 142.251.13.94:80
  local Android SOCKS5 smoke server on 127.0.0.1:41080
```

命令：

```sh
make android-vpp-build-release-no-multiarch-no-ipsec-idle android-vpp-stage-release-no-multiarch-no-ipsec-idle
make android-vpp-hev-handoff-poc
```

结果：

```text
app-http-probe.log:
ok bytes=40 elapsedMs=7 first=HTTP/1.0 200 OK  Content-Length: 2    OK

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 11 bytes 693 tx 4 bytes 204
shim-rx 4 bytes 204 shim-tx 11 bytes 693
handoff target-thread 1 fq 21 enqueued 11 bytes 693 congestion-drops 0 alloc-errors 0 worker-packets 11 bytes 693
last-tuple ip4 proto 6 10.111.0.2:49354 -> 142.251.13.94:80
thread-hits main last 0 t0 7 t1 0 t2 0 t3 0
thread-hits rx-node last 0 t0 7 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 7 t2 0 t3 0

HEV:
socks5 client tcp -> [142.251.13.94]:80
socks_count_after=1
```

结论：

```text
Android packaged VPP 的 worker handoff path 成立：
  fd callback/input node 仍在 main thread
  VPP buffer 被 handoff 到 worker thread 1
  worker thread 1 写 shim fd 给 HEV
  app HTTP 完成真实 SOCKS5 往返

边界：
  这里只验证 IPv4 TCP/HTTP allow path。
  Android worker-side static drop、Android resolver bridge、真实 UID drop 仍需单独验证。
```

### 67. Android VPP worker handoff can drop static IPv4 dst before HEV

问题：第 66 步只验证 Android worker handoff allow path。这里验证静态 IPv4 dst drop
也发生在 VPP worker 内，而不是 Android parent native gate。

最小实现：

```text
Android mode:
  vpp-hev-handoff

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 block-ip4-dst 142.251.13.94

test:
  app HTTP probe -> 142.251.13.94:80
  expect app timeout
  expect SOCKS connect count unchanged
  expect VPP blocked counter increases on worker path
```

命令：

```sh
make android-vpp-hev-handoff-ipv4-drop-poc
```

结果：

```text
app-http-probe.log:
fail elapsedMs=5013 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /10.111.0.2 ...

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
blocked 3 bytes 180 block-ip4-dst 142.251.13.94
handoff target-thread 1 fq 21 enqueued 9 bytes 580 congestion-drops 0 alloc-errors 0 worker-packets 9 bytes 580
tuple parsed 3 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 6 10.111.0.2:34514 -> 142.251.13.94:80
thread-hits main last 0 t0 5 t1 0 t2 0 t3 0
thread-hits rx-node last 0 t0 5 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 5 t2 0 t3 0

HEV:
no socks5 client tcp -> [142.251.13.94]:80
socks_count_after=0
```

结论：

```text
Android VPP worker-side static IPv4 dst drop 成立。
包进入 VPP worker thread 1 后被 `tun_poc` drop，没有交给 HEV/SOCKS。

边界：
  这里只验证 IPv4 TCP dst exact drop。
  IPv6 worker drop、Android resolver bridge、真实 UID verdict 仍需单独验证。
```

### 68. Android VPP worker can query ConnectivityManager owner resolver

问题：Docker mock resolver 已验证 VPP worker 能通过 fd 查询 UID。这里验证 Android
真实 `ConnectivityManager.getConnectionOwnerUid` 能否接到 VPP worker path：native/Java
只提供 tuple->UID，packet forwarding/verdict 仍在 VPP worker 内。

最小实现：

```text
Android mode:
  vpp-hev-owner-resolver

native startup:
  socketpair fd 5 is passed to VPP as resolver-fd
  native resolver thread reads:
    resolve ip4 proto 6 10.111.0.2 42790 142.251.13.94 80
  native calls Java queryConnectionOwnerUidForPacket(...)
  native writes:
    uid 12540

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5
```

命令：

```sh
make android-vpp-owner-resolver-poc
```

结果：

```text
app-http-probe.log:
ok bytes=40 elapsedMs=587 first=HTTP/1.0 200 OK  Content-Length: 2    OK

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
handoff target-thread 1 fq 21 enqueued 11 bytes 696 congestion-drops 0 alloc-errors 0 worker-packets 11 bytes 696
tuple parsed 5 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 6 10.111.0.2:42790 -> 142.251.13.94:80
resolver enabled 1 fd 5 queries 5 hits 5 errors 0 last-uid -1
uid-block enabled 0 uid -1 packets 0 bytes 0
thread-hits worker-probe last 1 t0 0 t1 7 t2 0 t3 0

resolver log:
resolver query=1 proto=6 10.111.0.2:42790 -> 142.251.13.94:80 uid=12540
resolver query=2 proto=6 10.111.0.2:42790 -> 142.251.13.94:80 uid=12540
resolver query=3 proto=6 10.111.0.2:42790 -> 142.251.13.94:80 uid=12540
resolver query=4 proto=6 10.111.0.2:42790 -> 142.251.13.94:80 uid=-1
resolver query=5 proto=6 10.111.0.2:42790 -> 142.251.13.94:80 uid=-1

HEV:
socks5 client tcp -> [142.251.13.94]:80
socks_count_after=1
```

结论：

```text
Android VPP worker -> native resolver fd -> Java ConnectivityManager -> UID response 成立。
这次没有 parent native gate；resolver thread 只返回 UID，VPP worker 仍负责 packet path。

重要边界：
  同一 TCP tuple 早期查询能返回 package UID 12540，后续查询可能返回 -1。
  因此产品化不能只看 last-uid；需要 VPP/bridge owner cache 策略。
  本步只验证 allow/query path，尚未验证 VPP worker 的真实 UID drop。
```

### 69. Android VPP worker can drop by real app owner UID

问题：第 68 步只验证 Android resolver bridge 能把真实 package UID 返回给 VPP worker。
这里验证 verdict 是否也能留在 VPP worker：`block-owner-uid=<package_uid>` 后，真实 app
TCP SYN 是否被 VPP drop，HEV/SOCKS 是否看不到目标连接。

最小实现：

```text
Android mode:
  vpp-hev-owner-resolver

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540

test:
  app HTTP probe -> 142.251.13.94:80
  package_uid=12540
  expect app timeout
  expect SOCKS connect count unchanged
  expect resolver uid=12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-uid-drop-poc
```

结果：

```text
app-http-probe.log:
fail elapsedMs=5011 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /10.111.0.2 ...

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
blocked 3 bytes 180 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 9 bytes 580 congestion-drops 0 alloc-errors 0 worker-packets 9 bytes 580
tuple parsed 3 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 6 10.111.0.2:52600 -> 142.251.13.94:80
resolver enabled 1 fd 5 queries 3 hits 3 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 3 bytes 180
thread-hits worker-probe last 1 t0 0 t1 5 t2 0 t3 0

resolver log:
resolver query=1 proto=6 10.111.0.2:52600 -> 142.251.13.94:80 uid=12540
resolver query=2 proto=6 10.111.0.2:52600 -> 142.251.13.94:80 uid=12540
resolver query=3 proto=6 10.111.0.2:52600 -> 142.251.13.94:80 uid=12540

HEV:
no socks5 client tcp -> [142.251.13.94]:80
socks_count_after=0
```

结论：

```text
Android VPN VPP-internal real UID drop 成立：
  VPP worker parses tuple
  VPP worker queries Android resolver fd
  native/Java returns package UID
  VPP worker applies block-owner-uid and drops before HEV/SOCKS

这一步纠正了 parent native gate 的偏差：packet verdict 不在 parent gate，留在 VPP worker。

边界：
  这里只验证 IPv4 TCP。
  没有 owner cache；第 68 步已经观察到 allow path 后续 packet 可能返回 -1。
  IPv6/UDP Android resolver drop、cache 策略、异步查询和性能仍需单独验证。
```

### 70. Android VPP worker can drop UDP by real app owner UID

问题：第 69 步只验证了 Android 上的 IPv4 TCP UID drop。这里验证 UDP send packet
是否同样能走 `VpnService -> VPP worker -> resolver fd -> Java owner UID -> VPP verdict`，
并且 verdict 不落到 parent native gate。

最小实现：

```text
Android mode:
  vpp-hev-owner-resolver

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540

test:
  app UDP probe -> 8.8.8.8:53
  package_uid=12540
  expect UDP send succeeds at app API level
  expect VPP worker parses proto 17 tuple
  expect resolver returns package UID
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-udp-drop-poc
```

结果：

```text
app-udp-probe.log:
ok bytes=24 elapsedMs=3009

show tun-poc:
last-tuple ip4 proto 17 10.111.0.2:58817 -> 8.8.8.8:53
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 1 bytes 52
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0

resolver log:
resolver query=1 proto=17 10.111.0.2:58817 -> 8.8.8.8:53 uid=12540
```

结论：

```text
Android VPN VPP-internal UDP UID drop 成立：
  VPP worker parses UDP tuple
  VPP worker queries Android resolver fd
  native/Java returns package UID
  VPP worker applies block-owner-uid and drops before HEV/SOCKS path

边界：
  这里只验证 UDP send packet 的 owner lookup + VPP verdict。
  当前 smoke server 不是完整 UDP ASSOCIATE 服务器，所以这里不声明 UDP proxy
  end-to-end 成立。
  IPv6 UDP、redirect 后 Android resolver、cache、异步查询和性能仍需单独验证。
```

### 71. Android VPP worker-to-worker redirect can forward app HTTP

问题：Docker 已经验证 worker 1 可以把 VPP buffer re-enqueue 到 worker 2。这里验证同样
机制在 Pixel 6a 的真实 `VpnService -> packaged VPP -> HEV -> SOCKS5` 路径里是否成立，
避免只拿 Docker 结论回答 Android 多线程分流问题。

最小实现：

```text
Android extra:
  redirectThread=2

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 redirect-thread 2

test:
  app HTTP probe -> 142.251.13.94:80
  expect app HTTP 200
  expect SOCKS connect count increases
  expect worker-probe last/t1 shows first worker
  expect worker-redirect last/t2 shows second worker
```

命令：

```sh
make android-vpp-hev-handoff-redirect-poc
```

结果：

```text
app-http-probe.log:
ok bytes=40 elapsedMs=9 first=HTTP/1.0 200 OK  Content-Length: 2    OK

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 11 bytes 693 tx 4 bytes 204
shim-rx 4 bytes 204 shim-tx 11 bytes 693
handoff target-thread 1 fq 21 enqueued 11 bytes 693 congestion-drops 0 alloc-errors 0 worker-packets 11 bytes 693
redirect enabled 1 target-thread 2 fq 22 enqueued 11 bytes 693 congestion-drops 0 worker-packets 11 bytes 693
last-tuple ip4 proto 6 10.111.0.2:41292 -> 142.251.13.94:80
thread-hits main last 0 t0 7 t1 0 t2 0 t3 0 overflow 0
thread-hits rx-node last 0 t0 7 t1 0 t2 0 t3 0
thread-hits worker-probe last 1 t0 0 t1 7 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 7 t3 0

HEV:
socks5 client tcp -> [142.251.13.94]:80
socks_count_after=1
```

结论：

```text
Android VPP worker-to-worker redirect 成立：
  fd/input 仍在 thread 0
  software handoff 把 TUN packet 转成 VPP buffer 后进入 worker 1
  worker 1 可以用 VPP frame queue re-enqueue 到 worker 2
  worker 2 继续处理并 forward 到 shim/HEV

边界：
  这里只验证 redirect 后 allow/forward。
  redirect 后 Android resolver + UID verdict 还没验证。
  这不是生产 sharding policy，也没有回答 packet ordering 或性能。
```

### 72. Android redirected VPP worker can drop by real app owner UID

问题：第 71 步只验证 Android redirect 后 allow/forward。这里验证 packet 从 worker 1
redirect 到 worker 2 之后，worker 2 是否还能执行 tuple parse、Android owner resolver query、
以及 UID drop verdict。

最小实现：

```text
Android extra:
  redirectThread=2
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540 redirect-thread 2

test:
  app HTTP probe -> 142.251.13.94:80
  expect app timeout
  expect SOCKS connect count unchanged
  expect worker-probe thread 1 hit
  expect worker-redirect thread 2 hit
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-redirect-uid-drop-poc
```

结果：

```text
app-http-probe.log:
fail elapsedMs=5009 error=SocketTimeoutException: failed to connect to /142.251.13.94 (port 80) from /10.111.0.2 ...

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 9 bytes 580 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 400
blocked 3 bytes 180 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 9 bytes 580 congestion-drops 0 alloc-errors 0 worker-packets 9 bytes 580
redirect enabled 1 target-thread 2 fq 22 enqueued 9 bytes 580 congestion-drops 0 worker-packets 9 bytes 580
tuple parsed 3 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 6 10.111.0.2:56728 -> 142.251.13.94:80
resolver enabled 1 fd 5 queries 3 hits 3 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 3 bytes 180
thread-hits worker-probe last 1 t0 0 t1 5 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 5 t3 0

resolver log:
resolver query=1 proto=6 10.111.0.2:56728 -> 142.251.13.94:80 uid=12540
resolver query=2 proto=6 10.111.0.2:56728 -> 142.251.13.94:80 uid=12540
resolver query=3 proto=6 10.111.0.2:56728 -> 142.251.13.94:80 uid=12540

HEV:
no socks5 client tcp -> [142.251.13.94]:80
socks_count_after=0
```

结论：

```text
Android redirect 后 VPP-internal real UID drop 成立：
  thread 0 fd/input -> worker 1 handoff -> worker 2 redirect
  worker 2 parses TCP tuple
  worker 2 queries Android resolver fd
  worker 2 applies block-owner-uid
  HEV/SOCKS does not see the target TCP connect

边界：
  这里只验证 TCP UID drop。
  UDP redirect、IPv6 redirect、packet ordering、异步 resolver 和性能仍需单独验证。
```

### 73. Android VPP worker can drop IPv6 TCP by real app owner UID

问题：Android VPP owner resolver/drop 已验证 IPv4 TCP 和 IPv4 UDP send packet。这里补
IPv6 TCP：`enableIpv6=true` 后，VPP worker 是否能解析 IPv6 TCP tuple、通过 Android
resolver 拿到真实 UID，并在 VPP worker 内 drop。

最小实现：

```text
Android extra:
  enableIpv6=true
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540

test:
  app HTTP probe -> [2606:4700:4700::1111]:80
  expect app timeout from fd00:111:111::2
  expect VPP last-tuple ip6 proto 6
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
  expect SOCKS connect count unchanged
```

命令：

```sh
make android-vpp-owner-resolver-ipv6-uid-drop-poc
```

结果：

```text
app-http-probe.log:
fail elapsedMs=5013 error=SocketTimeoutException: failed to connect to /2606:4700:4700::1111 (port 80) from /fd00:111:111::2 ...

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 9 bytes 700 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 460
blocked 3 bytes 240 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 9 bytes 700 congestion-drops 0 alloc-errors 0 worker-packets 9 bytes 700
tuple parsed 3 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip6 proto 6 [fd00:111:111::2]:55018 -> [2606:4700:4700::1111]:80
resolver enabled 1 fd 5 queries 3 hits 3 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 3 bytes 240
thread-hits worker-probe last 1 t0 0 t1 5 t2 0 t3 0

resolver log:
resolver query=1 proto=6 fd00:111:111::2:55018 -> 2606:4700:4700::1111:80 uid=12540
resolver query=2 proto=6 fd00:111:111::2:55018 -> 2606:4700:4700::1111:80 uid=12540
resolver query=3 proto=6 fd00:111:111::2:55018 -> 2606:4700:4700::1111:80 uid=12540

HEV:
no socks5 client tcp -> [2606:4700:4700::1111]:80
socks_count_after=0
```

结论：

```text
Android VPN VPP-internal IPv6 TCP UID drop 成立：
  VpnService IPv6 route sends app IPv6 packets into packaged VPP
  VPP worker parses IPv6 TCP tuple
  VPP worker queries Android resolver fd
  native/Java returns package UID
  VPP worker applies block-owner-uid before HEV/SOCKS

边界：
  只覆盖普通 IPv6 base header，不覆盖 extension headers。
  IPv6 UDP owner drop、redirect 后 IPv6 verdict、cache、异步查询和性能仍需单独验证。
```

### 74. Android VPP worker can drop IPv6 UDP by real app owner UID

问题：第 73 步补齐了 IPv6 TCP。这里补 IPv6 UDP send packet：VPP worker 是否能解析
IPv6 UDP tuple、通过 Android resolver 拿到真实 UID，并在 VPP worker 内 drop。

最小实现：

```text
Android extra:
  enableIpv6=true
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540

test:
  app UDP probe -> [2606:4700:4700::1111]:53
  expect UDP send succeeds at app API level
  expect VPP last-tuple ip6 proto 17
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-ipv6-udp-drop-poc
```

结果：

```text
app-udp-probe.log:
ok bytes=24 elapsedMs=3006

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 7 bytes 532 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 460
blocked 1 bytes 72 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 7 bytes 532 congestion-drops 0 alloc-errors 0 worker-packets 7 bytes 532
tuple parsed 1 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip6 proto 17 [fd00:111:111::2]:33570 -> [2606:4700:4700::1111]:53
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 1 bytes 72
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0

resolver log:
resolver query=1 proto=17 fd00:111:111::2:33570 -> 2606:4700:4700::1111:53 uid=12540
```

结论：

```text
Android VPN VPP-internal IPv6 UDP UID drop 成立：
  VpnService IPv6 route sends app IPv6 UDP packet into packaged VPP
  VPP worker parses IPv6 UDP tuple
  VPP worker queries Android resolver fd
  native/Java returns package UID
  VPP worker applies block-owner-uid

边界：
  这里只验证 UDP send packet 的 owner lookup + VPP verdict。
  当前 smoke server 不是完整 UDP ASSOCIATE 服务器，所以这里不声明 IPv6 UDP proxy
  end-to-end 成立。
  IPv6 extension headers、redirect 后 IPv6 verdict、cache、异步查询和性能仍需单独验证。
```

### 75. Android redirected VPP worker can drop IPv6 TCP by real app owner UID

问题：第 72 步验证 redirect 后 IPv4 TCP UID drop，第 73 步验证不 redirect 的 IPv6 TCP
UID drop。这里验证 IPv6 TCP packet 被 worker 1 redirect 到 worker 2 后，worker 2 是否仍能
完成 Android resolver query 和 UID drop verdict。

最小实现：

```text
Android extra:
  enableIpv6=true
  redirectThread=2
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540 redirect-thread 2

test:
  app HTTP probe -> [2606:4700:4700::1111]:80
  expect app timeout
  expect worker-probe thread 1 hit
  expect worker-redirect thread 2 hit
  expect VPP last-tuple ip6 proto 6
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-ipv6-redirect-uid-drop-poc
```

结果：

```text
app-http-probe.log:
fail elapsedMs=5014 error=SocketTimeoutException: failed to connect to /2606:4700:4700::1111 (port 80) from /fd00:111:111::2 ...

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 9 bytes 700 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 460
blocked 3 bytes 240 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 9 bytes 700 congestion-drops 0 alloc-errors 0 worker-packets 9 bytes 700
redirect enabled 1 target-thread 2 fq 22 enqueued 9 bytes 700 congestion-drops 0 worker-packets 9 bytes 700
tuple parsed 3 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip6 proto 6 [fd00:111:111::2]:40896 -> [2606:4700:4700::1111]:80
resolver enabled 1 fd 5 queries 3 hits 3 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 3 bytes 240
thread-hits worker-probe last 1 t0 0 t1 5 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 5 t3 0

resolver log:
resolver query=1 proto=6 fd00:111:111::2:40896 -> 2606:4700:4700::1111:80 uid=12540
resolver query=2 proto=6 fd00:111:111::2:40896 -> 2606:4700:4700::1111:80 uid=12540
resolver query=3 proto=6 fd00:111:111::2:40896 -> 2606:4700:4700::1111:80 uid=12540

HEV:
no socks5 client tcp -> [2606:4700:4700::1111]:80
socks_count_after=0
```

结论：

```text
Android redirect 后 IPv6 TCP VPP-internal real UID drop 成立：
  thread 0 fd/input -> worker 1 handoff -> worker 2 redirect
  worker 2 parses IPv6 TCP tuple
  worker 2 queries Android resolver fd
  worker 2 applies block-owner-uid
  HEV/SOCKS does not see the target TCP connect

边界：
  这里只验证 IPv6 TCP，不验证 IPv6 extension headers。
  UDP redirect、packet ordering、cache、异步 resolver 和性能仍需单独验证。
```

### 76. Android redirected VPP worker can drop IPv4 UDP by real app owner UID

问题：第 72/75 步验证了 redirect 后 TCP UID drop。这里验证 IPv4 UDP packet 被 worker 1
redirect 到 worker 2 后，worker 2 是否还能解析 UDP tuple、查询 Android owner UID，并执行
UID drop verdict。

最小实现：

```text
Android extra:
  redirectThread=2
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540 redirect-thread 2

test:
  app UDP probe -> 8.8.8.8:53
  expect UDP send succeeds at app API level
  expect worker-probe thread 1 hit
  expect worker-redirect thread 2 hit
  expect VPP last-tuple ip4 proto 17
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-udp-redirect-drop-poc
```

结果：

```text
app-udp-probe.log:
ok bytes=24 elapsedMs=3008

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 7 bytes 452 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 400
blocked 1 bytes 52 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 7 bytes 452 congestion-drops 0 alloc-errors 0 worker-packets 7 bytes 452
redirect enabled 1 target-thread 2 fq 22 enqueued 7 bytes 452 congestion-drops 0 worker-packets 7 bytes 452
tuple parsed 1 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 17 10.111.0.2:53587 -> 8.8.8.8:53
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 1 bytes 52
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 3 t3 0

resolver log:
resolver query=1 proto=17 10.111.0.2:53587 -> 8.8.8.8:53 uid=12540
```

结论：

```text
Android redirect 后 IPv4 UDP VPP-internal real UID drop 成立：
  thread 0 fd/input -> worker 1 handoff -> worker 2 redirect
  worker 2 parses IPv4 UDP tuple
  worker 2 queries Android resolver fd
  worker 2 applies block-owner-uid

边界：
  这里只验证 UDP send packet 的 owner lookup + VPP verdict。
  当前 smoke server 不是完整 UDP ASSOCIATE 服务器，所以这里不声明 UDP proxy
  end-to-end 成立。
  IPv6 UDP redirect、packet ordering、cache、异步 resolver 和性能仍需单独验证。
```

### 77. Android redirected VPP worker can drop IPv6 UDP by real app owner UID

问题：第 76 步验证了 redirect 后 IPv4 UDP UID drop。这里补 IPv6 UDP：worker 1
redirect 到 worker 2 后，worker 2 是否还能解析 IPv6 UDP tuple、查询 Android owner UID，并执行
UID drop verdict。

最小实现：

```text
Android extra:
  enableIpv6=true
  redirectThread=2
  blockOwnerUid=<package_uid>

VPP startup:
  tun-poc enable fd 3 mode handoff-forward-fd shim-fd 4 target-thread 1 resolver-fd 5 block-owner-uid 12540 redirect-thread 2

test:
  app UDP probe -> [2606:4700:4700::1111]:53
  expect UDP send succeeds at app API level
  expect worker-probe thread 1 hit
  expect worker-redirect thread 2 hit
  expect VPP last-tuple ip6 proto 17
  expect resolver UID 12540
  expect uid-block counter increases inside VPP
```

命令：

```sh
make android-vpp-owner-resolver-ipv6-udp-redirect-drop-poc
```

结果：

```text
app-udp-probe.log:
ok bytes=24 elapsedMs=3007

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 7 bytes 532 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 460
blocked 1 bytes 72 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 7 bytes 532 congestion-drops 0 alloc-errors 0 worker-packets 7 bytes 532
redirect enabled 1 target-thread 2 fq 22 enqueued 7 bytes 532 congestion-drops 0 worker-packets 7 bytes 532
tuple parsed 1 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip6 proto 17 [fd00:111:111::2]:54463 -> [2606:4700:4700::1111]:53
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
uid-block enabled 1 uid 12540 packets 1 bytes 72
thread-hits worker-probe last 1 t0 0 t1 3 t2 0 t3 0
thread-hits worker-redirect last 2 t0 0 t1 0 t2 3 t3 0

resolver log:
resolver query=1 proto=17 fd00:111:111::2:54463 -> 2606:4700:4700::1111:53 uid=12540
```

结论：

```text
Android redirect 后 IPv6 UDP VPP-internal real UID drop 成立：
  thread 0 fd/input -> worker 1 handoff -> worker 2 redirect
  worker 2 parses IPv6 UDP tuple
  worker 2 queries Android resolver fd
  worker 2 applies block-owner-uid

边界：
  这里只验证 UDP send packet 的 owner lookup + VPP verdict。
  当前 smoke server 不是完整 UDP ASSOCIATE 服务器，所以这里不声明 IPv6 UDP proxy
  end-to-end 成立。
  IPv6 extension headers、packet ordering、cache、异步 resolver 和性能仍需单独验证。
```

### 78. Android VPP worker can cache owner UID for a TCP tuple

问题：第 68 步观察到同一 TCP tuple 前几包能返回 package UID，后续查询可能返回 `-1`。
如果每包都同步查 `ConnectivityManager.getConnectionOwnerUid`，allow path 的 `last-uid` 会被
后续 `-1` 覆盖。这里验证一个最小 VPP-side owner cache：VPP worker 在 resolver 返回非负
UID 后缓存当前 tuple，后续同 tuple packet 直接用 VPP cache，不再查 resolver。

最小实现：

```text
VPP CLI:
  owner-cache

Android extra:
  ownerCache=true

test:
  app HTTP probe -> 142.251.13.94:80
  expect app HTTP 200
  expect SOCKS connect count increases
  expect resolver query count is lower than tuple packet count
  expect owner-cache stores and hits increase inside VPP
  expect last-uid remains package UID 12540
```

命令：

```sh
make android-vpp-build-release-no-multiarch-no-ipsec-idle android-vpp-stage-release-no-multiarch-no-ipsec-idle
make android-vpp-owner-resolver-cache-poc
```

结果：

```text
app-http-probe.log:
ok bytes=40 elapsedMs=14 first=HTTP/1.0 200 OK  Content-Length: 2    OK

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 11 bytes 696 tx 4 bytes 204
shim-rx 4 bytes 204 shim-tx 11 bytes 696
handoff target-thread 1 fq 21 enqueued 11 bytes 696 congestion-drops 0 alloc-errors 0 worker-packets 11 bytes 696
tuple parsed 5 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 6 10.111.0.2:59744 -> 142.251.13.94:80
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
owner-cache enabled 1 valid 1 hits 4 misses 1 stores 1 uid 12540
uid-block enabled 0 uid -1 packets 0 bytes 0
thread-hits worker-probe last 1 t0 0 t1 7 t2 0 t3 0

resolver log:
resolver query=1 proto=6 10.111.0.2:59744 -> 142.251.13.94:80 uid=12540

HEV:
socks5 client tcp -> [142.251.13.94]:80
socks_count_after=1
```

结论：

```text
VPP-internal owner cache POC 成立：
  cache lives in tun_poc/VPP, not parent native gate
  resolver returned UID once
  VPP stored tuple -> UID
  later same-tuple packets hit VPP cache
  allow path stayed functional and last-uid remained package UID

边界：
  这是 single-entry tuple cache POC。
  没有 TTL/expiry、LRU、reverse-flow mapping、multi-worker ownership model、
  connection close cleanup, or collision policy。
  resolver 仍是同步 query；async resolver 和性能仍需单独验证。
```

### 79. Android VPP owner-cache can handle a short UDP burst

问题：第 78 步证明同一 TCP tuple 可以 cache UID。这里用更直接的短 burst 验证：app 在同一个
UDP socket 上发 20 个 packet，VPP worker 是否能全部解析/drop，同时 owner-cache 是否把
resolver query 降到 1 次。

最小实现：

```text
Android UDP probe:
  count=20

VPP CLI:
  owner-cache
  block-owner-uid=<package_uid>

test:
  app UDP probe -> 8.8.8.8:53 count=20
  expect app send reports packets=20
  expect VPP tuple parsed 20
  expect resolver queries 1
  expect owner-cache hits 19
  expect uid-block packets 20
```

命令：

```sh
make android-vpp-owner-resolver-udp-cache-burst-poc
```

结果：

```text
app-udp-probe.log:
start host=8.8.8.8 port=53 count=20
ok bytes=480 packets=20 elapsedMs=3010

show tun-poc:
enabled 1 fd 3 shim-fd 4 mode handoff-forward-fd
rx 26 bytes 1440 tx 0 bytes 0
shim-rx 0 bytes 0 shim-tx 6 bytes 400
blocked 20 bytes 1040 block-ip4-dst -
handoff target-thread 1 fq 21 enqueued 26 bytes 1440 congestion-drops 0 alloc-errors 0 worker-packets 26 bytes 1440
tuple parsed 20 errors 0 non-tcp-udp 6 last-valid 1
last-tuple ip4 proto 17 10.111.0.2:54785 -> 8.8.8.8:53
resolver enabled 1 fd 5 queries 1 hits 1 errors 0 last-uid 12540
owner-cache enabled 1 valid 1 hits 19 misses 1 stores 1 uid 12540
uid-block enabled 1 uid 12540 packets 20 bytes 1040
thread-hits worker-probe last 1 t0 0 t1 4 t2 0 t3 0

resolver log:
resolver query=1 proto=17 10.111.0.2:54785 -> 8.8.8.8:53 uid=12540
```

结论：

```text
短 burst 下 VPP owner-cache POC 成立：
  app 连续发 20 个 UDP packet
  VPP worker 解析 20 个 UDP tuple
  resolver 只查 1 次
  VPP cache 命中 19 次
  VPP UID verdict drop 20 个 packet

边界：
  这不是正式性能基准，只是小批量可行性验证。
  没有吞吐曲线、延迟分布、CPU/battery、长时间运行、并发 app、多 tuple、多 worker cache
  一致性或 backpressure 结论。
```

### 80. `tun_poc` exposes a minimal VPP binary API status call

问题：上一轮 Tauri/VPP 控制面讨论决定产品控制面不应依赖 VPP CLI 字符串或解析 CLI 输出。
这里验证当前 `tun_poc` POC 能否先暴露一个最小 typed VPP binary API 面，让外部控制端通过
PAPI/VAPI 查询插件状态。

原始依据：

```text
VPP plugin API convention:
  src/plugins/arping/arping.api
  src/plugins/arping/arping_api.c
  src/plugins/af_packet/af_packet.api
  src/plugins/af_packet/af_packet_api.c

Observed pattern:
  add_vpp_plugin(... API_FILES <plugin>.api ...)
  include <plugin>/<plugin>.api_enum.h
  include <plugin>/<plugin>.api_types.h
  include <plugin>/<plugin>.api.c
  setup_message_id_table()
  VLIB_API_INIT_FUNCTION(...)

Python PAPI socket path:
  src/vpp-api/python/vpp_papi/vpp_papi.py
  src/vpp-api/python/vpp_papi/vpp_transport_socket.py
  VPP startup socksvr { socket-name <path> }
```

最小实现：

```text
overlay/src/plugins/tun_poc/tun_poc.api:
  define tun_poc_status
  define tun_poc_status_reply

overlay/src/plugins/tun_poc/tun_poc_api.c:
  vl_api_tun_poc_status_t_handler reads tun_poc_main counters/status
  replies with typed fields

Makefile:
  vpp-tun-poc-api-status-smoke

scripts/run-vpp-tun-poc-api-status-smoke.py:
  start local VPP with tun_poc_plugin and socksvr API socket
  load installed core API JSON plus generated tun_poc.api.json
  call client.api.tun_poc_status()
```

命令：

```sh
CCACHE_DIR=/tmp/ccache make vpp-tun-poc-build
make vpp-tun-poc-api-status-smoke
```

本地构建注意：

```text
The existing native VPP CMake cache had a stale /usr/lib/x86_64-linux-gnu/libiberty.a path.
The local ignored build tree was reconfigured with:
  cmake -S work/vpp/src -B work/vpp/build-root/build-vpp-native/vpp \
    -DLIBIBERTY_INCLUDE_DIR=LIBIBERTY_INCLUDE_DIR-NOTFOUND \
    -DLIBIBERTY_LIB=LIBIBERTY_LIB-NOTFOUND

CCACHE_DIR=/tmp/ccache was used to keep ccache writes out of a restricted home cache path.
```

结果：

```text
make vpp-tun-poc-build:
  generated CMakeFiles/plugins/tun_poc/tun_poc.api.json
  generated CMakeFiles/plugins/tun_poc/tun_poc.api.h
  generated CMakeFiles/vpp-api/vapi/tun_poc.api.vapi.h
  generated CMakeFiles/vpp-api/vapi/tun_poc.api.vapi.hpp
  linked tun_poc_plugin.so
  installed tun_poc_plugin.so to install-vpp-native/vpp/lib/x86_64-linux-gnu/vpp_plugins

make vpp-tun-poc-api-status-smoke:
  tun_poc_status reply:
    retval=0
    enabled=0 mode=0
    counters rx=0 tx=0 shim_tx=0 blocked=0
    owner queries=0 hits=0 cache_hits=0 uid_blocks=0 last_uid=-1
```

结论：

```text
最小 VPP binary API status POC 成立：
  tun_poc.api can be generated by VPP's API tooling
  VAPI C/C++ headers are generated for the message
  tun_poc registers its message table at VPP startup
  Python PAPI can call tun_poc_status over socksvr
  reply carries typed status/counter fields without CLI output parsing

这支持 Tauri/Rust 方向：
  product control plane can target VPP binary API/VAPI
  CLI can stay as dev/debug only
```

边界：

```text
This only proves read-only status.
It does not pass Android fds through VPP API.
It does not implement policy replace/commit/rollback.
It does not prove Rust VAPI binding or thin C ABI shim yet.
It does not test Android packaged VPP or root mode.
The generated tun_poc.api.json currently lives in the build tree for this POC;
API installation/packaging policy is still separate.
```

### 81. `tun_poc` owner policy can be mutated through VPP binary API

问题：第 80 步只证明 binary API 可以读 status。这里验证 product control plane 需要的最小
write/mutation 形态：不用 CLI，直接通过 VPP binary API 设置 `owner-cache` 和
`block-owner-uid` 这两个现有 POC policy knobs。

最小实现：

```text
tun_poc.api:
  autoreply define tun_poc_owner_policy_set {
    bool owner_cache_enabled;
    bool block_owner_uid_set;
    i32 block_owner_uid;
  }

tun_poc_api.c:
  vl_api_tun_poc_owner_policy_set_t_handler mutates tun_poc_main:
    owner_cache_enabled
    owner_cache_valid reset when cache is disabled
    block_owner_uid_set
    block_owner_uid

status reply now also exposes:
  owner_cache_enabled
  block_owner_uid_set
  block_owner_uid
```

命令：

```sh
CCACHE_DIR=/tmp/ccache make vpp-tun-poc-build
make vpp-tun-poc-api-status-smoke
make vpp-tun-poc-api-policy-smoke
```

结果：

```text
make vpp-tun-poc-api-status-smoke:
  tun_poc_status reply:
    retval=0
    enabled=0 mode=0
    counters rx=0 tx=0 shim_tx=0 blocked=0
    owner queries=0 hits=0 cache_enabled=0 cache_hits=0 block_uid_set=0
      block_uid=-1 uid_blocks=0 last_uid=-1

make vpp-tun-poc-api-policy-smoke:
  tun_poc_owner_policy_set reply:
    retval=0
  tun_poc_status after mutation:
    owner_cache_enabled=1 block_owner_uid_set=1 block_owner_uid=4242
```

结论：

```text
最小 VPP binary API mutation POC 成立：
  product control can set POC policy knobs through typed binary API
  the mutation is visible through typed status
  no VPP CLI command or CLI output parsing is needed for this control path
```

边界：

```text
This is not a production policy API.
It directly mutates POC global state, not an epoch/snapshot model.
It does not compile a policy blob.
It does not implement replace/commit/rollback.
It does not validate datapath behavior after mutation because no TUN fd is enabled in this smoke.
It does not cover concurrency, worker cache ownership, or Android packaged VPP.
```

### 82. Generated VAPI C client can call `tun_poc_status`

问题：第 80/81 步用 Python PAPI 验证了 binary API read/write。Tauri/Rust 推荐路径仍需要一个薄 C
ABI shim 或生成客户端层。这里验证生成的 VAPI C header 能否直接被小型 C client 使用，通过
`socksvr` 调用 `tun_poc_status`。

最小实现：

```text
clients/tun_poc_vapi_status.c:
  include <vapi/memclnt.api.vapi.h>
  include <vapi/vlib.api.vapi.h>
  include <tun_poc.api.vapi.h>
  DEFINE_VAPI_MSG_IDS_MEMCLNT_API_JSON
  DEFINE_VAPI_MSG_IDS_VLIB_API_JSON
  DEFINE_VAPI_MSG_IDS_TUN_POC_API_JSON
  vapi_connect_ex(..., use_uds=true)
  vapi_alloc_tun_poc_status()
  vapi_tun_poc_status(...)

scripts/run-vpp-tun-poc-vapi-c-status-smoke.py:
  compile C client against install-vpp-native headers/libs and generated tun_poc VAPI header
  start local VPP with tun_poc_plugin and socksvr API socket
  run the C client against the socket
```

命令：

```sh
make vpp-tun-poc-vapi-c-status-smoke
```

结果：

```text
tun_poc_status via VAPI C:
  enabled=0 mode=0 retval=0
  counters rx=0 tx=0 shim_tx=0 blocked=0
  owner cache_enabled=0 block_uid_set=0 block_uid=-1 last_uid=-1
vapi c client: /tmp/sakamoto-vpp-tun-poc-vapi-c-status/tun_poc_vapi_status
vpp stdout log: /tmp/sakamoto-vpp-tun-poc-vapi-c-status/vpp-stdout.log
```

构建注意：

```text
The smoke compiles with:
  -D_DEFAULT_SOURCE
  -Wno-unused-parameter
  -Wno-sign-compare

Reason:
  Generated VPP VAPI headers use htobe*/be*toh feature macros and emit benign
  warnings in unused generated inline functions. The POC keeps local client
  warnings enabled but does not treat generated-header warnings as fatal.

The VPP runtime root is under /tmp to keep socksvr/statseg Unix socket paths
below path length limits.
```

结论：

```text
VAPI C client POC 成立：
  generated tun_poc.api.vapi.h can be consumed by a small C client
  the client can connect to VPP socksvr over UDS
  the client can call vapi_tun_poc_status and receive typed fields

This is the lower layer needed for a future thin C ABI shim callable from Rust/Tauri.
```

边界：

```text
This only calls status.
It is a smoke client, not a stable shim ABI.
It does not expose Rust FFI yet.
It does not package generated VAPI headers outside the build tree.
It does not test Android packaged VPP.
```
