# 2026-09-07/08 夜间执行汇总

任务范围：按已约定顺序推进 S247 → S200 → S203 → S244 → S216 → S204 → S205；
截止 9 月 8 日 07:00（台北），周额度剩余 70% 为底线，73% 为提前停止线。
本轮不使用子代理。S245/S246 的前置实验已在夜间额度采样前完成。

执行时段：9 月 7 日约 23:25 至 9 月 8 日 02:48（台北），约 **3 小时 23 分**。
七项约定任务全部完成，提前结束本轮。周额度从 **93% → 87%**，约消耗 **6 个百分点**；
剩余额度高于 70% 底线 17 个百分点。额度来自间隔采样，整数显示不是精确计费统计。

| 任务 | 主要增量 | 验收与报告 |
| --- | --- | --- |
| S247 | 多包重叠下验证 HEV/lwIP 与 VPP 的独立存储所有权、资源上限和停止结清 | Done；[实验结果](../../experiments/vpp-nfq-poc/s247/RESULTS.md)。发现并修复停止后队列继续转发的问题，保留原 HOLD 证据。仅为实验输入。 |
| S200 | 将 handcrafted Direct bridge 从产品路径移出，撤回未经证明的 VPN readiness | Done；[隔离报告](SAKAMOTO_200_POC_ISOLATION.md)。新 APK 真机验证 VPN 明确未就绪、Root 可启动并清理。 |
| S203 | 真实 Root NFQUEUE owner-local packet 进入 VLIB admit、policy、terminal | Done；[真实图报告](SAKAMOTO_203_ROOT_GRAPH.md)。不再由外部 submit helper 同步冒充图执行。 |
| S244 | 建立源码、APK/native、安装结果、运行代次、节点及 packet nonce 的证据链 | Done；[证据链报告](SAKAMOTO_244_EVIDENCE_CHAIN.md)。七类过期/伪造/越界证据反例被拒绝。 |
| S216 | typed PacketFacts / Platform Facts / OwnerAssignment / AdapterObligation；完整 96-byte inline 布局 | Done；[metadata 报告](SAKAMOTO_216_TYPED_METADATA.md)。3 个真实 UDP + 12 个明确标注的真机 graph injection；不再把 admitted 恢复为 L4 COMPLETE。 |
| S204 | terminal 发布 Completion Frame，由 origin lane consumer 发送 verdict 并归还 buffer | Done；[Completion Frame 报告](SAKAMOTO_204_COMPLETION_FRAME.md)。非最后一个 duplicate、64-bit stale generation 均被拒绝；重启与零残留通过。 |
| S205 | 唯一一次真实 Primary Handoff 到 remote owner，再以同一 Completion Frame 返回 origin | Done（功能验收）；[Primary Handoff 报告](SAKAMOTO_205_PRIMARY_HANDOFF.md)。已验证真实 worker 分工、错误投递直接 DROP、无 Owner Guard/Corrective Handoff。 |

## 当前实际能力和边界

最终产品路径针对一个 app UID 的 IPv4 UDP OUTPUT NFQUEUE lane：worker 0 接收，
共享 parser/selector 只计算一次，owner-local 直接进入 policy，remote-owner 一次投递到
worker 1，terminal 只发布 Completion Frame，worker 0 独占 NFQUEUE verdict。
包始终由原生 VPP buffer 持有。未引入已删除 C++ 主线、逐包 Rust 桥或产品 VPN fallback。

各里程碑都保留各自的新源码/制品/真机证据。旧请求在后续源码改变后应拒绝 current-source
校验；它们是当时里程碑的证据，不伪称与最终 HEAD 相同。最终状态以 S205 的构建和运行见证为准。
验收时的代码和测试先以工作区快照保留；现已按任务补齐 Git 提交，见
[提交索引](TASK_COMMITS_2026_09_08.md)。详细二进制/设备证据仍位于各报告列出的 `build-output/` 目录。

## 仍需后续处理

- **跨 worker 延迟约 3.1 秒。** Native 时标显示约 1.13 秒 Primary Handoff 和约 2 秒返回。
  这与已接受的 Android idle profile（最大 epoll 等待 1000 ms）及现有调度顺序吻合。
  1.5 秒等待的初次运行保留为 HOLD；后续按明确的 8 秒功能等待验收。未采用被否决的
  worker wake 方案，未宣称延迟或功耗达标。
- **运行中 L4 调试修改入口报 `product_core_owner_live`。** S204 探索时发现，原因及基线尚未
  建立，未将其作为已修复问题。本轮 completion/handoff 验收不依赖此入口。
- VPN transport/readiness、INPUT、TCP/IPv6 wire、重组、FlowEntry/tracker production mutation、
  queue-full/credit exhaustion、压力/功耗/发布验收仍不在本轮 PASS 内。

## Tracker 同步记录

Plane 的任务状态已逐项同步。早期报告同步完成后，自动审批拒绝了含设备标识和制品明细的
详细正文上传；当时采用本地完整报告加 Plane 状态更新。

9 月 8 日 08:38，用户明确授权把设备与制品明细记录到私有部署的 Plane。随后已补录
S203、S244、S216、S204、S205 的完整验收报告并逐项读回核对，原任务状态、标题、
父项、标签和优先级保持一致。详细记录包含各里程碑制品哈希、运行代次、证据路径及验收边界。

最终安装制品为 S205 `build-c`，真机验收 generations 657/658。设备已停止产品 runtime，
最后两次 stop 的 buffer/frame/obligation、hook 和进程残留检查均通过。

## 9 月 8 日继续执行

用户于 08:35 后授权沿依赖链继续执行，并取消时间截止。新的额度控制为剩余约 60%，
62% 为提前收尾线；08:39 采样仍剩余 87%。下一项 S206 已进入 In Progress。
上方七项及其时段是前一阶段的历史记录。

9 月 8 日 09:03：**S206 完成**。双栈每 family Q2 固定到 W2，四轮独立 lane 关闭，
包括 pending=1 时先归还后关闭；123 次真实捕获完成原 lane verdict，停止清零。
[完整报告](SAKAMOTO_206_ROOT_LANES.md) 已同步私有 Plane。最终见证为
`s206-lanes/build-b`、`request-d.json` 与 `pixel-d`（661–664）；旧七项继续保留历史口径。
08:54 额度采样剩余 86%。随后进入 S230，已确认本机独立 Linux namespace 的真实 NFQUEUE API 可用。

## 09:08 continued execution — S206 closed, S230 active

S206 dual-stack Root Q2/W2 functional acceptance passed on Pixel generations 661–664; full source/artifact/device evidence is in [SAKAMOTO_206_ROOT_LANES.md](SAKAMOTO_206_ROOT_LANES.md) and synchronized to private Plane. S230 is In Progress: actual Linux NFQUEUE in a disposable network namespace, followed by the same-source Pixel baseline. Remaining quota at 09:06 is 85%; time remains unrestricted.

## 09:26 continued execution — S230 closed, S207 active

S230 real Linux NFQUEUE dual-stack TCP/UDP functional acceptance passed: final run 472 packets, 32 fresh processes, all 32 protocol/family/lane/owner/verdict combinations. Same-source Pixel baseline passed generations 666–669, 115 captures; Wi-Fi restored. Full evidence: [SAKAMOTO_230_LINUX_NFQUEUE.md](SAKAMOTO_230_LINUX_NFQUEUE.md), synchronized to private Plane with Done state verified. S207 is next. Usage window reset around 09:23 to 100% remaining; the requested 60% remaining floor and 62% soft stop remain in effect, without a time limit.

## Continued execution — S207 closed, S208 active

S207 unique typed OwnerAssignment and flow_domain removal passed on final same-source artifacts: Linux 581 NFQUEUE packets across 48 processes, Pixel 236 across 24 generations (734–757), plus 14 separately identified native diagnostic carriers per platform. All ledgers zero; Pixel Wi-Fi restored. Full report [SAKAMOTO_207_OWNER_ASSIGNMENT.md](SAKAMOTO_207_OWNER_ASSIGNMENT.md) is synchronized to private Plane; S207 Done was verified. S208 now implements owner-local FlowEntry mutation from that assignment. Latest quota sample at 10:13 is 98% remaining; continue with the same 60% floor.

## 13:18 continued execution — S208 closed, S209 active

S208 bounded owner-local FlowEntry passes on final same-source artifacts:
Linux 936 actual NFQUEUE packets / 56 processes and Pixel 937 / 55 traffic
generations (795–849). Both platforms cover the full dual-stack TCP/UDP,
midstream and lane/owner matrix; supplementary cases prove identical tuples,
wrong-worker rejection and INPUT-first unknown attribution. All obligations,
pools, socket inodes and hook/process residue close cleanly. Pixel generation
850 additionally passes 2,000 worker-barrier queries. Five semantic evidence
corruptions are rejected. Full report [SAKAMOTO_208_FLOW_ENTRY.md](SAKAMOTO_208_FLOW_ENTRY.md)
is synchronized to private Plane and Done is read-back verified. S209 is now
In Progress. Latest quota at 13:13 remains 91%; continue under the same 60% floor.

## 14:43 continued execution — S209 closed, S210 active

S209's final same-source artifacts pass 3,579 actual NFQUEUE packets: Linux
1,861 / four processes and Pixel 1,718 / generations 863–866. All 49 flow
identities and 221 native publications pass independent Gate/L4/cache identity,
reader lifetime, actual worker, packet conservation and cleanup checks. Held
old packets and concurrent new-bank readers are directly observed on both
platforms. FlowEntry counters are owner-private; packet writer-lock acquisitions
and final readers/debt are zero. Five Host checks, Clang ASan/UBSan and seven
semantic evidence negatives pass. Full report
[SAKAMOTO_209_POLICY_SNAPSHOT.md](SAKAMOTO_209_POLICY_SNAPSHOT.md) is synchronized
to private Plane; Done was read-back verified. S210 is In Progress. Quota sampled
at 14:42 remains 87%; continue with the same 60% floor and no time limit.

## 15:30 continued execution — S210 complete, S231 next

S210 passes 932 real NFQUEUE packets on the same source: Linux 460/four
processes and Pixel 472/generations 871–874. All 444 pre-policy capacity
bypasses complete at origin with one NF_ACCEPT attempt; 256 policy DROPs
remain DROP, including 228 actual retained completion returns. Both families
and both target workers pass recovery and native stop/FD/queue/debt checks.
Six Host checks and seven semantic negative cases pass. Full report
[SAKAMOTO_210_CAPACITY_BYPASS.md](SAKAMOTO_210_CAPACITY_BYPASS.md) is recorded
and read-back verified in private Plane. Latest quota at 15:23 is 85% remaining.
S211 is Cancelled, not implementation work; S212 requires S231, so execution
continues with the real NFQUEUE fragment-visibility matrix in S231.

## 16:52 continued execution — S231 complete, S212 active

S231's same-source Product artifacts pass 261 real NFQUEUE packets: Linux
120/four processes and Pixel 141/generations 882–885. Independent PCAP and
NFQ bytes establish all four hook/family rows separately. Pixel sees kernel
reassembly before all tested hooks; the isolated Linux namespace exposes raw
IPv4 OUTPUT and IPv6 INPUT/OUTPUT fragments. Ordinary UDP socket OUTPUT is
pre-fragmentation on both platforms. All 48 ordinary probes, native completion
ledgers, stop, FD inodes and temporary network cleanup pass. Full report
[SAKAMOTO_231_FRAGMENT_VISIBILITY.md](SAKAMOTO_231_FRAGMENT_VISIBILITY.md) and
S212/S228 entry selections are recorded and read-back verified in private Plane.
The latest quota sample at 16:31 is 80% remaining. S212 now starts from its
accepted native reassembly contract and the measured Pixel graph-injection /
Linux real-NFQUEUE entry split.

## 19:00 continued execution — S212 complete, S217 next

S212 passes 48 Pixel native graph originals and 65 real Linux NFQUEUE
original fragments, including one-byte final range, six-original bundle,
duplicate/conflict, resource capacity, timeout and native Stop. The ordinary
same-artifact regressions pass another 476 Linux and 149 Pixel NFQUEUE packets.
Every applicable original completion and physical return is exactly once;
all native/reference/buffer/frame/obligation and network cleanup checks pass.
Six semantic evidence mutations are rejected. Full report
[SAKAMOTO_212_NATIVE_REASSEMBLY.md](SAKAMOTO_212_NATIVE_REASSEMBLY.md) is recorded
and read-back verified in Plane; S212 is Done. The latest quota sample is 66%
remaining. Continue with dependency-ready S217's Root per-packet facts: current
source still synthesizes missing OUTPUT UID evidence from the configured
owner, which the S217 contract explicitly forbids. S228 remains the subsequent
IPv6 reassembly step.

## 19:25 continued execution — S217 complete, S228 active

S217 now requests and preserves real NFQUEUE UID/GID attributes, removes
configured-UID inference/filtering, and normalizes hook-specific Linux ifindex
with explicit unknown facts. The final source passes 64 Linux + 68 Pixel real
NFQUEUE packets / 98 endpoint cases, independent raw-netlink decoding, actual
matcher and completion/cleanup checks, five negative evidence mutations, plus
65 Linux real-fragment and 31 Pixel graph-fragment regressions. Full report
[SAKAMOTO_217_ROOT_PLATFORM_FACTS.md](SAKAMOTO_217_ROOT_PLATFORM_FACTS.md) is
recorded and read-back verified in Plane; S217 is Done. Pixel is stopped901
with Wi-Fi restored. Continue with S228's IPv6 native full-reassembly contract.

## 19:45 quota soft stop — S228 implementation checkpoint

Remaining quota reached 62%; execution is paused at the agreed soft-stop
boundary to preserve 60%. Sixteen tasks are complete, latest S212 and S217.
S228's IPv6 core hooks/shared graph integration and Android compilation are
prepared but have no runtime acceptance. The incomplete Host build candidate
is retained for resumption. See
[SAKAMOTO_228_NATIVE_IPV6_REASSEMBLY.md](SAKAMOTO_228_NATIVE_IPV6_REASSEMBLY.md).
Pixel is stopped901 with Wi-Fi restored; no S228 APK was installed.

## 用户继续执行与 Git 提交整理

用户随后撤销了当前额度下限，继续 S228；以后长时间运行时再另设限制。
按用户要求，已把完成的工作拆成 18 个实际 Git 提交，另提交本汇总及
[任务提交索引](TASK_COMMITS_2026_09_08.md)。产品各里程碑按验收源码快照
逐文件校验，工作区原有内容保持不变，历史制品哈希不作改写。
S228 尚未验收，相关代码、第五补丁与测试仍单独保留在工作区。

## S228 complete after resumed execution

Current-source acceptance passes 130 real Linux IPv6 originals plus 49 Pixel
graph originals, 96 IPv4 reassembly originals and 133 ordinary dual-stack
NFQUEUE packets. Native ownership, policy, original verdict/free and cleanup
checks pass. See [S228 report](SAKAMOTO_228_NATIVE_IPV6_REASSEMBLY.md).
S228 is committed separately after verification; Pixel is stopped906.
