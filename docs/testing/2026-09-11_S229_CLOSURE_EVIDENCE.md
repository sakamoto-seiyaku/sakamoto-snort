# S229 改造前复验证据与已撤回的例外提议

日期：2026-09-11。关联 Plane **SAKAMOTO-229**
（`979d06d5-26fa-4007-9837-dd1df48bbdb8`）。本记录是证据索引；任务状态和验收以 Plane 为准。
改造前取证阶段为 **HOLD**，没有将当时未命中的 prepared-sendout rejection 改成 PASS。
后续独立重组的源码、构建和新复验见
[独立重组实现记录](2026-09-11_S229_INDEPENDENT_REASSEMBLY.md)，不能混用两轮证据。

**后续决定（2026-09-11）：** 下文仅记录改造前 build-d 的取证过程与结果；prepared-sendout
不可达豁免提议已经撤回，不是待批准方案。产品改用独立有界重组和明确的重组 worker →
FlowOwner 交接，必须重新取得跨 owner 投递拒收及逐 original settlement 证据。下文源码
hash、PASS 和“未修改产品源码”只描述当时取证阶段，不描述后续工作树草稿，也不能证明
新设计已实现或验证。当前设计以实施规格 §1 和 owner/metadata 决策为准。

## 现场与同源身份

HEAD 保持 `46235ce95765d4b2c1e5fd0bd60e894ed9a522c4`，保留接手时全部 dirty/untracked 内容。
本轮修改测试、验证器和说明，未修改 Product C/Rust/Java 源码，未重建 Product。
各 verifier 重算 Product source closure，均匹配现有 build-d：

```text
39b5ab3433080407daa7b5235fe6f35bcb927edaa323aec2b27d150f94593d41
```

- Linux witness：`build-output/s229-errors/linux-build-d/build.json`。
- Linux artifact：`build-output/product-vpp-host-s229-d`，真实 Product graph。
- Pixel witness：`build-output/s229-errors/pixel-build-d/build.json`。
- Pixel APK：该目录下 `apk/sakamoto-runtime-debug.apk`；每次部署核对 APK 与全部 native libraries。
- 新证据根：`build-output/s229-20260911/`。原失败目录、原 verification 均保留。
- Linux 使用独立 rootless user/network namespace；Pixel 仅操作 `28201JEGR0XPAJ`。

## 本轮已验证结果

下面目录均相对新证据根。PASS 只支持列出的范围。

| 目录 | 结果 | 证据范围 |
| --- | --- | --- |
| `s229-0911-nfq4-d` | PASS，65 originals | 真实 IPv4 NFQ OUTPUT，L4 DROP、resource bypass、普通 TCP/UDP、恢复、stop |
| `s229-0911-nfq6-b` | PASS，130 originals | 真实 IPv6 NFQ INPUT/OUTPUT，同上；generations 22810/22811 |
| `s229-0911-l-basic` | PASS，26 originals | Linux 双栈 timeout/malformed/conflict/duplicate/context-capacity/DROP/held-stop |
| `p-basic-b` | PASS，26 originals，generation 962 | Pixel 同一 basic 矩阵；GRAPH_INJECTED |
| `s229-0911-l-in` | PASS，18 originals | Linux 双栈真实 native ingress ring-full rejection；GRAPH_INJECTED |
| `p-in-c` | PASS，18 originals，generation 966 | Pixel 同一 ingress 拒收与逐 original settlement |
| `s229-0911-l-policy` | PASS，24 originals | Linux 双栈 retained DROP completion |
| `p-policy-a` | PASS，24 originals，generation 964 | Pixel 双栈 retained DROP completion |
| `l-out-repro-a` | HOLD，24 originals 已结清 | 双栈 prepare/success；未发生 prepared-sendout rejection |
| `p-out-a` | HOLD，24 originals 已结清，generation 967 | Pixel 得到相同结果 |
| `p-tun-capacity-a` | PASS，40 originals、28 fragment originals、8 datagrams | 真实双栈 TUN capacity 与随后图/completion 恢复；generations 968/969 |

TUN recovery 的正常包 transport 仍为 unavailable/unsupported，不声称 HEV/lwIP 网络送达。
正常 stop 的资源账与进程退出分别核对；缺资源账不能以 process_absent 替代。

## rc=12 与 NFQUEUE verifier 修正

本轮原样执行现存 `linux-build-d/control/s229-nfq-policy`，IPv4/IPv6 的 DROP apply 均返回 rc=0。
从当前 helper 源码和当前 header 重新编译，ELF 与原现场二进制逐字节同 hash：

```text
helper: a39f3ab15f6c73a4f6c3eeb84d408e3ab118a05899b7d49c66c20b90649eaab4
core:   ad3e54e3ccaee66fa0f4c16ab5a503ee1abfaf119166460b49a5df29db72fe18
```

编译 witness 为 `control/helper-build.json`，包含编译命令、compiler、header/source 副本与 hash、
源 Product witness hash 和加载依赖。`build_s229_control.py` 只构建独立测试 helper。
collector 现在记录实际 policy argv、LD_LIBRARY_PATH、返回内容、helper 与所解析 core library hash。

旧 `nfq4-d2/nfq6-d2` 没有 policy ELF hash，不能证明它们运行的是当前二进制；旧 rc=12
未定因，不能宣称已找出并修复历史 ABI 错误。当前合法 bundle 已通过真实 apply 和图中规则命中。

复验发现的确定问题在 verifier：它沿用 Gate DROP reason=7，实际 helper 安装 L4 规则，
native policy 命中 rule=22915，completion reason=8。新参数 `--policy-drop-reason 8` 在采集前
固定期望，verifier 校验该期望及 helper/library 身份；原有 Gate 场景默认 7 保留。
两个新原始复现目录 `nfq4-repro-b`、`nfq6-repro-a` 保留其原 HOLD，未覆盖成 PASS。

## collector 的时序修正

- `p-basic-a` 中 duplicate 没形成预期三-original bundle：两片先完成，另一片 timeout。
  CLI 返回 accepted 仅证明投递；增加首片 native context 就绪检查后，Linux/Pixel 均通过原断言。
- `p-in-a` 的 IPv6 第二批片到达时 hold 已结束；`p-in-b` 也因观察 hold 太迟而停止。
  用一条读取 native log inode 的设备流代替压力窗口内的反复 ADB 查询，按原 300/500ms
  hold、原两槽 native ring 重跑后，`p-in-c` 双栈真实拒收通过。没有修改 native enqueue 返回值。
  日志流随 runtime socket 消失结束；host reader 有有界 join/cleanup。
- `nfq4-repro-a` 是 sandbox 禁止 netlink 的环境失败；随后在沙箱外隔离 namespace 执行。
  `nfq4-c` 是 CLI connection refused 的启动失败；保留目录，后续使用唯一 runtime 名称成功。

## prepared-sendout：已撤回的例外提议（仅保留历史理由）

1. **条目**：[实施附录 §3.3](2026-09-09_IMPLEMENTATION_SPEC.md#33-sendout-handoff-场景约束)
   要求双栈 `reason=8 prepared=1` 真实 native rejection；现有 verifier 继续严格要求该事实。
2. **源码和日志证据**：pinned revision 为 `9258530f3804a152578ce11cc7c8a1e9eab88ed0`。
   在 Linux stage 的 `src/vnet/ip/reass/ip4_full_reass.c`：
   `find_or_create` 在当前 thread 不等于 memory owner 时返回 NULL（约 655–658 行）；
   offset-zero 首片只有在 `reass != NULL` 时才设置 `sendout_thread_index = vm->thread_index`
   （约 1406–1412 行）；finalize 的 handoff 条件要求 memory owner 与 sendout 不同
   （约 1285–1291 行）。因此正常完整 datagram 在 finalize 时两者相同。
   IPv6 的对应位置约为 676–679、1429–1435、1198–1205，逻辑相同。
   pinned clean 源码也有同一赋值关系；本轮两平台每族四个 datagram 均记录 prepare→success，
   总计每平台 24 originals 结清，均未发生 prepared rejection。这不是 timeout 掩盖 prepare。
3. **原最小替代方案（已撤回，不可执行）**：将此单项记录为“当前 pin 正常路径不可达”，保留源码证明和
   严格拒绝该 run 为 PASS 的 verifier；以已通过的双栈 ingress retained rejection 验实际 native
   ring-full，以 policy-return 验 DROP carrier 保留，以真实 NFQ/TUN 验可交还/不可交还。
   不为命中一个验收分支新增 sendout placement 机制，不修改 native context 的跨线程所有权。
4. **受影响测试**：仅 sendout-handoff 的双栈 prepared-rejection 覆盖及其专属反例；S229 总体
   暂不关闭。Product 中 finalized-handoff 错误处理分支仍没有动态验收证据，不能写成已覆盖。

Linux stage 两个已检查源码 SHA-256：

```text
ip4_full_reass.c 990848ce43e18d525916f193f516095164f87197451536289967e92b337a2743
ip6_full_reass.c cb2858376309d16f887dae952c2b9b9533d77a03e67dbe3076d8742baf23dd4e
```

## verifier 与测试 seam 审视

`verify-s229-reassembly.py` 增加必需 status/四 lane 存在性、generation、case 非空、helper hash、
original allocation interval 和 prepared rejection 真实远程满 ring 条件。三个 reassembly verifier
使用独立输出或独占创建 verification，拒绝覆盖既有记录。

- `verifier-negatives-c/results.json`：1 正例 + 12 反例通过，覆盖缺 status/completion、重复 free、
  错误 generation/helper/source/build/adapter、DROP 改 bypass、stop 仍有资源债。
- `nfq4-negatives/results.json`、`nfq6-negatives/results.json`：各 1 正例 + 8 反例通过，覆盖缺
  completion/lane、错误 helper/core/source/build 和预声明 policy expectation。
- 这些反例是独立证据副本的破坏测试，不声称在线故障注入。

现有 `is_mp_safe` 注入入口核对结果：main-thread 检查限制 CLI；case bitmap、generation、
network snapshot 的控制修改在 main；当前私有 buffer 在 transfer 前初始化，admission 账使用
atomic，enqueue rejection 由仍持有 buffer 的 main 清理。正常成功 transfer 后不再访问 buffer。
reassembly capacity/status CLI 保留普通 worker barrier；capacity 只允许空 graph/context/ring。
改变 ring 的 `nelts` 使用原已分配存储，正常 enqueue/free 不被替换。native_error 的 queue
occupancy 只在 trace 标记下读取，属于时点诊断；真实拒收还必须由 retained API 分支确认。
新增 fragment trace header 避免 native 早期错误留下空 trace header。trace 均受现有有界诊断入口约束。

2026-09-11 读取的 Plane S229 正文明确确认 processing fail-open，要求移除旧的所有 capacity
一律 DROP 描述；本轮据此同步 `CONTEXT.md` 与 ADR-0001 的相关分片错误段落。
