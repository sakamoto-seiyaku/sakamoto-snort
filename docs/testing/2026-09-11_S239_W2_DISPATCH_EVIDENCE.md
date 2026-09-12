# S239 W2 dispatch evidence — 2026-09-11

Implementation and diagnosis evidence, **not W2 acceptance**. Authoritative
task: SAKAMOTO-239; finding recorded in Plane comment
`2751c460-48ea-47f2-8928-d8b277e6c5f7`.

## Artifact and bounded implementation

- Source closure: `5943108c6f48245160f514899334aae12705394a83e5264887823743ce7c6e30`.
- APK: `b950dc155aaf1a84ff5e20ceb1f3e5923bf0e31a70733d8e4dfbd0b392d82ffa`.
- Manifest: `build-output/s239-20260911/pixel-build-b/build.json`.
- Pixel: `28201JEGR0XPAJ`; real underlay UDP endpoint `192.168.4.5`.
- Native VPP stage remains `/tmp/s237-final-vpp-stage`; no packet-wake patch
  was added or altered during this investigation.

The native driver now constructs two separate owner contexts and subscribes
each HEV reactor, timer and broker channel on its actual VPP worker. Android
authorizes sockets over two independently registered owner-scoped channels;
neither broker executes transport callbacks.

Each return producer has a fixed 128-credit allowance, charged before buffer
allocation and returned after pre-accept failure/free or terminal native free.
The allowance is admission accounting, not a private replacement VPP buffer
pool: native allocation can still fail explicitly. The scalar credit is atomic
across producer and TUN consumer; HEV/PCB/session state is not shared.

Return buffers no longer enter the TUN-capture pending table. Their existing
inline VPN obligation carries the generating credit-owner identity in the
VPN-private `packet_id`; origin worker/lane still identifies the single TUN
writer. Disjoint token ranges avoid a global token allocator. Graph submission
validates the remote return producer, and existing native completion transport
moves its buffer index to the TUN lane. No extra payload copy, packet map,
return queue, shared socket write lock or delivery acknowledgement was added.

The native completion backlog compile-time bound now includes 128 captured
originals, both 128-credit return populations and the existing bounded
injection/probe populations. Fragment completion retains return provenance.

## Executed tests

- Existing real HEV host suite: **10/10 passed**.
- `tests/host/product_vpn_return_credit_test.c`: plain C11/pthreads and
  ASan/UBSan builds passed. Covers both directions of allowance exhaustion,
  independent capacity, stale generations, refusing reinitialization over live
  debt, and concurrent producer/free accounting. This is a scalar-accounting
  test, not proof of native graph lifetime or end-to-end isolation.
- Fresh native and Java/APK build passed. The first build attempt found a Java
  local-name collision, corrected before this artifact was produced.

| Device case | Generation | Result |
| --- | --- | --- |
| `b-owner1-udp4` | 1102 | Two application timeouts, then a late previous reply |
| `b-owner1-udp4-repeat` | 1103 | Same failure reproduced |
| `b-owner0-udp4-control` | 1104 | Three exact echoes, same APK and test; selected owner changed |

Case directories are under `build-output/s239-20260911/`. Each preserves the
manifest identity, installed hashes, app result, real endpoint log, native
trace and stop residue. Both failed cases reached the real endpoint for all
three requests. Their late replies reached TUN and returned their buffer
credits. All three cases stopped both shards with balanced session/socket
counts, no pbuf/input/buffer/obligation/frame debt and no native process left.
The device was left stopped after generation 1104.

## Reproduced dispatch delay

Ranked hypotheses were (1) native cross-worker frame dispatch/idle integration,
(2) owner-local HEV scheduling, and (3) broker/underlay latency. Existing
monotonic graph timestamps localize long delays to native worker transfer,
including the return path after transport processing has already finished.
No extra diagnostic packet logging or timeout relaxation was required.

Selected generation-1103 intervals:

| Packet token | Stage interval | Milliseconds |
| --- | --- | ---: |
| `6` | TUN admit → remote policy | 1815.786 |
| `13835058055282163713` | Return admit → same-owner policy | 1.170 |
| `13835058055282163713` | Return terminal → TUN completion | 1174.977 |
| `13835058055282163715` | Return admit → same-owner policy | 0.812 |
| `13835058055282163715` | Return terminal → TUN completion | 1959.937 |

Pinned-source inspection matches this evidence:

- `vlib_buffer_enqueue_to_thread_inline` publishes `hf->valid` and sets the
  destination `check_frame_queues`, but performs no destination wake.
- The accepted Android idle patch allows worker `epoll_wait` up to 1000 ms and
  ignores worker polling-node counts. The pre-sleep path checks node
  interrupts, but not `check_frame_queues`.
- Thus frame availability alone does not keep the destination from sleeping
  or wake it from sleep. Successive graph-loop sleeps can add more than one
  idle interval; a round trip crosses workers in both directions.
- The existing initial/normal worker-barrier wake correction is separate and
  does not publish ordinary packet wakes.

This is not evidence of copy cost, TUN write contention, PCB sharing or a need
for a third packet copy. A wake mechanism change has not yet been A/B verified.

## Decision boundary and non-claims

[ADR-0006](../adr/0006-vpp-native-packet-io-adapters.md) and
[per-worker ownership](../decisions/PER_WORKER_FLOW_OWNERSHIP.md) explicitly keep
the prior conditional packet-wake proposal on HOLD and require reviewed fresh
evidence before adoption. Implementation paused at that boundary; the new
ownership/copy baseline in ADR-0007 is not reopened by this finding.

The proposed next decision is whether to authorize a narrowly scoped native
frame/idle correctness repair with its own lost-wake and idle-cost regression
evidence. Neither permanent polling, lowering the global sleep interval,
adding packet copies nor restoring the previous rejected wake patch has been
implemented as a workaround.

Concurrent IPv4/IPv6 on both owners, native return-credit exhaustion in both
directions while the other owner continues, controlled-flow isolation,
completion congestion and the complete new-generation failure matrix have not
passed on this artifact. S239 remains In Progress; TCP and release performance
are not claimed.
