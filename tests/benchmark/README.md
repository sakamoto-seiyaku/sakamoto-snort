# Pixel 6a quick baseline

This is test traffic tooling, not a Product packet-domain implementation.
All main scores come from the actual Pixel 6a, serial `28201JEGR0XPAJ`.
The LAN peer's Linux numbers are only delivery and generator-headroom witnesses.

Each daily run has a **120-second global deadline**, including identity reads,
runtime starts, warmup, diagnostics, mode switches, normal teardown and JSON output.
The fixed measurement window is **5 seconds × 8 cells = 40 seconds**. No repeats,
rate sweeps, TLS, SNI or QUIC are included. Profiling is concurrent with the same
cells; pulling and rendering raw perf is a separate offline operation.

## One-time preparation

Use a unique output directory. Preparation builds C host/NDK helpers and uploads
only the test helper; it preserves the installed APK and rule source. It requires
an initially stopped runtime, existing KernelSU app authorization, existing
ordinary VPN consent, and a phone-reachable IPv4 LAN peer.

```sh
rtk proxy python3 tests/benchmark/pixel_quick.py prepare \
  --peer 192.168.4.5 --port 41020 \
  --output /tmp/pixel-baseline-prepared
rtk proxy /tmp/pixel-baseline-prepared/socket-load-host server 192.168.4.5 41020
```

Keep that peer running in its own terminal. TCP uses the selected port; UDP uses
that port through port+63. The phone helper sends actual sockets through Root
with the recorded app UID (KernelSU `su <uid>`, since `run-as` cannot execute
`/data/local/tmp` binaries), and through ordinary Product VPN with shell UID 2000.
The warmup requires a matching UID-attributed VPP FlowEntry at the real peer.
No controlled/validation VPN extras, worker resizing, flow-capacity changes or
rule writes are used. Android operations always use repo-local `./dev/adb`.

The manifest freezes APK/rule/helper identity, concurrency (4 I/O threads,
16 fixed TCP/UDP sockets or TCP-new window slots per thread), peer and profiling.
`--no-profile` is a distinct collection configuration; do not compare it with
profiled B0 as if the collection cost were identical. `--cell-ms 10000` is available
for an independently frozen configuration, but it must also pass the whole-run
deadline before becoming a baseline.

## Daily entry

```sh
rtk proxy python3 tests/benchmark/pixel_quick.py run \
  --manifest /tmp/pixel-baseline-prepared/manifest.json \
  --output build-output/pixel-quick-B0
```

It runs Root, then ordinary VPN. Each mode uses this fixed order:

1. Start normally; warm the actual LAN/trace path; TCP fixed multi-flow download.
2. UDP fixed multi-flow, 1200-byte datagrams sent as fast as possible.
3. TCP new: bounded concurrency, connect → 24-byte echo → close.
4. Stop normally and start a fresh lifetime; UDP new: new source-port/destination-
   port combinations, four 1200-byte datagrams per tuple, then close.

The two churn cases never share a full Flow table. The first lifetime contains
both fixed groups before TCP churn; initial occupancy is recorded and must stay
below 10% of capacity before each measured group. This avoids eight costly
whole-runtime restarts. After normal native teardown and VPP process exit, the
test app is force-stopped before the next lifetime, preventing delayed Android
Service callbacks from racing with the next start. Natural background VPN traffic remains part of the actual
device environment and is visible in the counters; initial occupancy is not
claimed to be literally zero. Each Root stop checks native zero debts and the
product's hook/queue residue audit. Any deadline, transport, identity or lifecycle
failure produces `INCOMPLETE`; cells are never shortened or omitted for a PASS.

Each cell retains client/peer JSON, sampled per-thread VPP CPU/RSS, actual runtime
generation/PID, before/after CLI counters and sampler logs. UDP loss uses received
unique packets rather than send success; duplicates are separate. UDP input tuple
counts differ from peer underlay tuples, especially through VPN. TCP completed CPS
differs from VPP Flow creates. Flow creates and capacity misses are counter deltas,
including any simultaneous background traffic. Endpoint delivery is not asserted
to be fully admitted policy-path goodput; Root unadmitted accepts, queue/lane facts,
Flow-capacity bypass and TUN counters must accompany interpretation.

Busy Root windows must show capture-counter progress in the same generation;
new-connection windows must show actual VPP Flow creation. Endpoint success with
no native progress is `INCOMPLETE`. The comparison also revalidates older raw
CLI records, so a historical `COMPLETE` label alone cannot qualify such a run.
These checks establish some native progress, not full policy-path coverage.

Fixed TCP latency uses separate persistent echo probes. UDP latency uses separate
echo probes; TCP-new latency includes connect through the matching response.
Histogram upper bounds have 100 µs resolution up to one second; p99 is `null` if
the selected percentile overflows. Timeouts, errors and deadline cancellations
remain separate from successful latency samples. The fast run describes trends,
not thermal steady state, formal p99 qualification or electrical energy.

## Offline graphs and comparisons

```sh
rtk proxy python3 tests/benchmark/report.py collect \
  --run build-output/pixel-quick-B0/result.json \
  --output build-output/pixel-quick-B0-graphs \
  --symfs /path/to/matching-binary-cache
rtk proxy python3 tests/benchmark/report.py compare \
  --runs build-output/pixel-quick-B0/result.json build-output/pixel-quick-B1/result.json \
  --output build-output/pixel-quick-comparison
```

Collection uses the SDK's offline Inferno renderer (`--skip_collection`) and the
phone helper's actual monotonic start/end to exclude setup/teardown samples. It
checks Pixel metadata and reports unknown symbols. Use a cache with matching ELF
build IDs; a cache from another APK is not a symbol identity proof. The comparison
rejects incomplete or over-budget runs and changed benchmark parameters. APK
identity may differ across optimizations; device, rules, helper, load and collection
parameters must stay fixed. It produces standalone HTML and machine-readable JSON.

## Tool correctness

```sh
rtk proxy python3 tests/benchmark/check_socket_load.py
rtk proxy python3 tests/benchmark/check_capture.py
rtk proxy python3 tests/benchmark/check_root_batch.py
rtk proxy python3 tests/benchmark/check_udp_burst.py
rtk proxy python3 tests/host/product_nfqueue_verdict_batch_test.py
rtk proxy python3 tests/host/product_root_pending_test.py
```

These local loopback checks verify socket workloads, connection/tuple ledgers,
duplicate accounting and peer reset between repeated runs. Their rates are never
used as Android performance results. Peer sequence/tuple sets are bounded and
report overflow explicitly. Failed calibration artifacts should be retained in
their own directories, not relabeled or overwritten as B0.

For a separately frozen mechanism experiment, the helper accepts optional
`UDP_FIXED_SOURCE_PORT_BASE [UDP_FIXED_SOURCE_PORT_STRIDE]` after the existing
`udp-fixed` client arguments. It binds all data sockets and four thread probes
before connecting; an occupied port fails explicitly. Without these arguments,
the four original workloads retain their existing socket behavior. The stride
defaults to 1; stride 2 avoids synchronized source/destination port low bits
putting this controlled cohort on one canonical owner. Freeze the new helper
hash and actual owner distribution before comparison; these runs are distinct
from historical B0. See the [withdrawn admit/owner experiment](../../docs/testing/2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_BATCH.md)
for the qualified fixed-tuple setup and failed effectiveness gate.

The socket helper accepts client windows up to 60 seconds and monitor windows
up to 61 seconds. Its bounded duplicate bitmap covers 2^27 sequence values and
still reports overflow explicitly. These limits support separately frozen longer
experiments; the daily quick runner retains its existing window choices and
120-second deadline. See the [30-second repeated comparison](../../docs/testing/2026-10-11_PIXEL6A_VPP_ADMIT_OWNER_LONG.md).

## Frozen Root whole-path cells

`root_batch.py` collects one ordinary Root cell with nonempty applicable rules.
It requires the prepared Pixel manifest plus `rules_count`, `rules_revision`,
`applicable_rule_versions`, and optional frozen `resource_identity`. Both compared
artifacts must enable qualification instrumentation; only the candidate enables
`SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT`. The collector verifies installed APK,
helper, rules, generation, effective policy, app UID/peer/protocol progress, matched
ALLOW success and independent native-zero/capture-residue cleanup. It does not
install artifacts or mutate rules.

```sh
rtk proxy python3 tests/benchmark/root_batch.py \
  --manifest /path/to/frozen-manifest.json \
  --output build-output/root-batch-cell \
  --expect-batch on --case udp-fixed
```

Freeze duration, warmup, rate, flows and ports in the manifest before sampling.
The optional helper argument after source-port base/stride is a global offered
rate: payload packets/s for `udp-fixed`, connection attempts/s for `tcp-new`.
Other paced cases fail explicitly. Workers finish socket initialization before
the shared start; scheduled/offered/missed and capacity misses remain visible.
Separate UDP latency probes are outside that payload rate and also contribute
to policy traffic. Legacy calls without the rate retain their original behavior.

An optional `UDP_BURST_SIZE` after the offered rate groups global payload tickets
at one deadline. For example,4000pps with burst32 emits32 packets every8ms;
the total scheduled work and deadline stay fixed. Bursts require paced
`udp-fixed` and are bounded by16 messages per sender thread. The default burst1
retains the prior uniform schedule. `check_udp_burst.py` observes timing and
identities at independent receivers, including a partial final train.
In a Root manifest, set `udp_burst_size` together with `offered_rate`.

The primary VPP process CPU and Policy-Qualified SUCCEEDED deltas share before/
after batch CLI boundaries; delivery and p99 use the actual client boundaries.
TCP churn additionally requires real Flow create/end progress. Collector
`COMPLETE` does not imply the separately frozen coverage, capacity, delivery and
paired-p99 guards passed. Retain failed windows and do not retry until favorable.
See the [whole-path experiment record](../../docs/testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md)
for the completed 18-window protocol, raw identities, all failures and offline
paired statistics. Its manifests are historical after the original rules were
restored; prepare a new frozen manifest for a new campaign.

For batch/prefetch experiments, verify actual density across admit, per-target
primary publication, policy protection windows, completion publication and
origin frames before comparing CPU. A configured window size is not evidence
that the runtime filled it. Full-speed input can establish mechanism coverage
while saturating receive/pending capacity; retain these failures separately.
Pair exact-APK flamegraphs with the batch counters: a flamegraph locates CPU
costs, while counters show where work became singleton. Current profiles and
symbols verified against the stripped APK payload are linked from the record.

Root 独立 verdict 的发送实验使用 `SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_EXPERIMENT`，
默认 OFF，并要求现有 `SAKAMOTO_PRODUCT_ROOT_BATCH_EXPERIMENT=ON`。对照双方都打开
图内批处理；`SAKAMOTO_PRODUCT_ROOT_VERDICT_BATCH_MODE=scalar|sendmmsg|packed`
在同一 origin window 内选择逐包 sendto、多数据报 sendmmsg 或单数据报的多个独立
verdict。窗口最多 16 条现成 completion，不增加等待或 packet-ID 范围判决。
`show product root lanes` 的 `root.verdict_io` 行分别记录 graph sendto calls、sendmmsg
calls/requested/sent/partial、windows/messages 和 packed calls/messages/bytes/mixed/max；
ingress bypass 和配置发送不进入这些 graph syscall 计数。syscall、datagram 和独立消息
是三个计量单位；`root.control` 单独记录错误回包，不建立 ACK 等待或确认每条 callback。
这些计数须与成功 verdict、有效策略 Q、实际 graph density 和旁路一起读取，不能把
requested messages 当作已发送成功。部分发送的未知边界不重发，未尝试尾部各发送一次。
packed 的异常短返回按整组 unknown，不使用 sendmmsg 的 positive-count prefix 规则。
Root 测量前使用 `product packet-trace limit 0`，要求收到明确的
`packet.trace_limit=0`；0 在 CLI barrier 下关闭未来包的 trace，保留 ordinal 和既有包的
trace flag，正数 cap 仍只允许在首包后增大。healthy 边界的 kernel packet-ID invariant
须经过零 pending/queue 和稳定 native 计数核查，未评估的边界不能算旁路为零；它不覆盖
ID 分配之前的 queue-full FAIL_OPEN。
`root.receive` 另记录 `pending_collisions/full/duplicate_ids` 和
`ingress_normal/envelope/completion/graph`，区分物理槽冲突、真实满池与直接旁路原因。
completion ledger 保持 64 个记录；home 冲突时使用空闲物理槽，按原 ID/token/generation
完成查找和结算。碰撞计数本身不是 bypass；须同时读取拒绝原因和资源守恒。
2026-10-13 的独立计时 helper 与 off-CPU 诊断保留在实验记录的各自证据目录；CPU 分析
明确选择 on-cpu 模式。新增计时和 profiling 不与历史 helper 的 CPU 值直接配对。
精确 unstripped companion 可通过 `SAKAMOTO_ANDROID_PRODUCT_SYMBOLS_DIR` 保存；重新
strip 后必须匹配 APK payload 才用于离线火焰图。实现、原始身份和当前结论继续记录在
[整链实验](../../docs/testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md)。


Root 通用 I/O 诊断入口为 `product root io-tuning <lane> <read-budget 1..64>
<RCVBUF-request-bytes>`。命令在标准 worker barrier 内要求活动 lane 和空的全局
packet graph，设置只属于当前 generation；正常重启恢复 budget64 和默认 socket
容量。request0保留当前容量，正值只使用普通 SO_RCVBUF（最多1 MiB）；每次读取
实际 getsockopt 值。set 后 get 失败时 requested 已更新、effective=0、budget 不提交，
调用方必须将其视作失败。Linux 返回容量与请求值不可混用，且容量上限不是实际 RSS。

`show product root receive` 追加 `root.io`：read_budget、rcvbuf_requested/effective、
callbacks、empty_callbacks、budget_exits、callback_datagrams/max、recv_calls 和
recv_eagain/eintr/enobufs。callback_max 是本代最大值，不能用两次最大值相减；其余
累计计数取同代差值。读取预算统计实际 callback 内 recv 次数（控制数据报也占预算），
不会增加 receive buffers、completion slots、credits 或等待未来包。普通 socket
buffer 控制不修改 maxlen、flags、sysctl、SO_RCVBUFFORCE 或 GSO。

```sh
rtk proxy python3 tests/host/product_root_io_test.py
```

该 Host fixture运行实际接收 callback、receive pool、reserve 和 deactivate，覆盖
预算64/32/1、部分 batch flush、错误路径与 socket capping/读回失败可见性。
2026-10-13 的通用 I/O 真机比较执行7个流量窗口后因 owner-live 启动护栏中止；
全部窗口均未通过交付资格，剩余轻载/空闲/压力探针未执行，不能声称缓冲扩容收益。
原 APK/规则和 Stopped 已恢复，详情与 exact-APK 火焰图见
[本轮记录](../../docs/testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#通用-io-配置与预算对照--2026-10-13)。

Root容量诊断另有 `product root capacity-tuning <lane> <normal slots64|128>`
和 `product root maxlen-tuning <lane> <1..65536>`，要求空packet graph，后者还要求
空socket并验证匹配的Netlink ACK，不消费意外packet消息。正常重启回到normal/pending64、
maxlen1024；128槽接收池和身份账本配套调整，reserve仍8。原64记录说明适用于默认档。
`root.capacity`记录实际normal/pending容量及generation内loan/pending高水位（含预热），
不能对最大值取差值。`tests/host/product_root_capacity_test.py`覆盖实际128个碰撞身份、
重复/历史排除、逆序UNKNOWN drain、事务式扩容和ACK异常的不消费行为。

2026-10-13独立容量对照保留37个固定窗口与全部精确符号CPU-only火焰图：一个组合16k UDP
窗口完整通过，但未证明整体CPU效率收益；32k/64k及TCP不合格，TCP名义双lane实际只一lane。
扩容档不作为原固定预算batch规格的默认采用验收。原APK/配置/Stopped已恢复，
见[全部结果与界限](../../docs/testing/2026-10-13_ROOT_NFQUEUE_CAPACITY_TUNING.md)。
