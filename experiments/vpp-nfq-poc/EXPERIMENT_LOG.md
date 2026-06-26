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
