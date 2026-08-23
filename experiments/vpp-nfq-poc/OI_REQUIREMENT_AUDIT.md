# Owner-inline OI-3/OI-4/OI-5 requirement audit

Date: 2026-08-23

This audit answers the narrow question “what does the evidence support?”
`GO` means that the named, bounded cell is supported by raw evidence.  It does
not mean production readiness, capacity, soak, external-route safety, or
release sign-off.  Raw VPP/owner output is authoritative for packet-path
claims; an Android sidecar is only a route/lifetime witness and never a second
TUN reader.  Model output supports the cases it explicitly enumerates and is
not substituted for a real transport run.

## OI-3 — single-owner Direct Egress

| Requirement | Evidence that supports it | Exact boundary |
| --- | --- | --- |
| IPv4/IPv6 UDP and TCP success, plus refusal/timeout/policy-drop classification | Host synthetic matrix stdout `/tmp/s128-oi3-matrix-stdout-final-v2.txt` (SHA-256 `da751a9faa95a401d1727a62cc31448c27c4b00f084e37851c9f1404f883a729`) and VPP console `/tmp/sakamoto-vpp-nfq-poc/s128-oi3-matrix-console.log` (SHA-256 `fc6853842a7a3ffe77092ea87837ec363a253d4095829fea85c8197a812876dc`). UDP4/UDP6 and TCP4/TCP6 have direct output; refused is `ECONNREFUSED` with no Direct socket; no-reply is an expected UDP timeout; policy-drop has no broker/socket path. | Host synthetic controlled underlay; not throughput, capacity, or release evidence. |
| Real TUN ingress → canonical FlowOwner → protected Direct → same-TUN output | Host raw console `/tmp/sakamoto-vpp-nfq-poc/s128-oi3-tun-host-console.log` (SHA-256 `8831fb0e949204431bdefd00ce76e2edd95e17140f860b9389fabc07da1df2a5`) plus probe stdout `/tmp/s128-oi3-tun-host-stdout-final-v2.txt` (SHA-256 `432b063329844918f6f32f60a2411eac7e14725004beeed1fa5ec7bed5cb1464`). It records original-destination retention, broker completion, owner-thread socket/connect/send, raw output rewrite, and `buffers=203/203 residue=0`. | Host socketpair TUN and local UDP underlay only; no external/default-route claim. |
| Real Android app → `VpnService` TUN → owner → bind/protect broker → Direct → owner output | Final Pixel 6a controlled matrix uses APK `cb5e6ffd80a66934206c9d62205c3a65f5db37c3f397bbd10997fb47c24545a9`, plugin `7a92ed0c3c9d9e9ad77f972219b48ce143f109fcae1b6b1c538493d4b2efd9eb`, Java `102f67cc35347d3434d7c6e486bf46132e8ca9e359658332d5a3dc8cead91457`, and native probe `f18cf84ac39356063fcf9e990faa806ea9d1eeb79566a37e1fc44cf476ef9579`. The seven authoritative VPP ledgers are listed below. | Pixel routes only `10.200.0.0/24` or `fd00:200::/64`; no default route; underlay is loopback. This is controlled local reachability, not arbitrary device traffic. |
| Raw provenance and exactly-once cleanup | Pixel transport cells contain raw `tun-ingress-raw`/`tun-output-raw` (where applicable), owner pthread, broker completion, and matching Android `java-result=1`/`duplicate close`; every row has `residue=0`. Sidecars report `observer-read=0`. | VPP stdout, not the diagnostic sidecar, is the packet ledger. |
| Failure classes remain distinct | Refused is a bounded closed-loopback fixture: shell namespace supplies RST and the plugin records `transport-refusal ... errno=111`, `transport-failures=1`; it is not policy drop. No-reply is UDP with endpoint `1/0`, no output/direct receive, and app `TIMEOUT`. Policy-drop stops before broker/socket (`broker=0/0`). | The Android refusal fixture is an explicit bounded classification seam, not a claim about arbitrary kernel `SO_ERROR` behavior or external RST handling. |
| Owner-inline path has no paired-thread/second datapath | Host and Pixel raw paths report `owner-submit → shared-graph=flow-stack-owner → owner-output`, owner-local Direct activity, and no SOCKS/packet-port path. The corrected connector initialization, destination normalization, endpoint-ready latch, and TUN lifecycle are implementation-seam fixes. | Supports the bounded architecture seam; does not prove production memory/performance behavior. |

### Pixel final controlled matrix

Each cell used a fresh `am start -S` launch and has separate VPP, broker,
sidecar, and app logs at `/tmp/s128-oi3-android-final-<cell>-v3-*.log`.

| Cell | VPP raw SHA-256 | What the raw ledger supports |
| --- | --- | --- |
| UDP4 | `686f7e5b3d410e92f32c8a17dda566310496b42d184ae7f2c2ff735d0eceb8f0` | IPv4/UDP ingress, broker completion, Direct send, TUN output, app `OK`, `buffers=3/3 residue=0`. |
| TCP4 | `7538ccdb68cd2f4707b81b9449e7cb8c7e3437cbd75ec346f0bff972bad22f02` | SYN/ACK, ACK+payload, accepted endpoint, Direct send/receive, FIN, app `OK`, `buffers=520/520 residue=0`. |
| UDP6 | `c956557203c0bf0b8a527da9a358f6de0c3cbfb118d7e830bea916f0f348b3f9` | IPv6/UDP ingress, IPv6 loopback underlay, Direct send/output, app `OK`, `buffers=3/3 residue=0`. |
| TCP6 | `9ac7e2693b0c0f5744814ed767f4b3e0d47832ce964a27f657d4eba77a8c9e15` | IPv6 SYN/ACK, accepted endpoint, Direct send/receive, FIN, app `OK`, `buffers=520/520 residue=0`. |
| refused | `baed8d4ea1cf5f937b01f99739c096c3c097dbfb8b4043ac6ab4c4608e4c9df6` | Expected transport refusal, no endpoint/direct reply, `transport-failures=1`, `buffers=6/6 residue=0`. |
| no-reply | `b07ac871503e9a0afd02a9d85d99c56d62795720c0f3f6d69f980f5756c77e84` | Expected UDP timeout, endpoint `1/0`, output/direct `0`, `buffers=514/514 residue=0`. |
| policy-drop | `de96f668c9bf9c2916cab44bd20ad86b51530eab5e34cd3985a212046e66f01f` | Expected policy drop before broker/socket, output/direct `0`, `buffers=1/1 residue=0`. |

OI-3 bounded decision: **`SCOPED_DIRECT_EGRESS_GO`**.  This now supports the
bounded host and controlled Pixel IPv4/IPv6 UDP/TCP and failure cells.  It does
not support external/default-route reachability, arbitrary device traffic,
capacity, soak, or production safety.

## OI-4 — per-worker FlowStackShard isolation

| Requirement | Evidence that supports it | Exact boundary |
| --- | --- | --- |
| Stable owner-local tuple routing for IPv4/IPv6 TCP/UDP | Deterministic model schema `owner-inline-oi4-shards/v2`, model output `/tmp/s129-oi4-model-current.json`, SHA-256 `3eb313d0c5b6fe2374d5f7226c577b97407c4052b38a62cbdba5ef0a07c47cd6`; its live-shard cell routes 10 flows to A and 6 to B and all accepted fixture flows succeed with residue 0. | Deterministic model for the full tuple matrix. |
| Real independent owners with local Direct transport, delay, and bounded stop | UDP runner raw `/tmp/s129-oi4-hev-direct.raw`, SHA-256 `550a016162c1778bae2a50eb10e6a1bec54408d76e28431fba804811c3a8e1d9`; distinct owner pthreads, owner-local sockets, underlay receives, owner output, owner0 bounded stop, and owner1 continuation with `accessed-owner0=0 migrated=0 spilled=0`. | Real two-pthread host UDP seam; the separate TCP addendum below is required for real TCP. |
| Real two-owner TCP handshake/data/FIN and Direct sockets | TCP source `experiments/vpp-nfq-poc/prototypes/owner_inline_oi4/oi4_hev_tcp_shard_probe.c`, SHA-256 `3c881a9a2dd005d06e71fc7043e56c1103040119dea4019ef502f6980a9663f1`; binary `/tmp/oi4-hev-tcp-shard-probe`, SHA-256 `1edb2f0fe41fc5c8a277785e0aafea8e4eb7f26dff70e39b98f4f821174090ed`; raw `/tmp/s129-oi4-hev-tcp.raw`, SHA-256 `4fb780b8d52acbca2e48236e6b07ef3c17fe11e056ae3ef380bf79ea508eb58a`. Both owners report handshake, payload, FIN, Direct send/receive, owner output, and `packet=4/4 pbuf=4/4 ... residue=0`. | Real two-pthread host TCP seam; not four-worker Android or capacity. |
| Wrong-owner events cannot mutate another shard; no migration/spill/global mutable core | Model and both raw harness tripwires reject submit/output/completion/callback with `rejected=1 callback-mutated=0`; raw summaries report `migration=0 spill=0 global-mutable=0 core-lock=0`. | Bounded harness guards, not a production pressure campaign. |
| Exact packet/pbuf/session/timer/socket cleanup | Model ledgers allocate/release equally; real UDP/TCP owner shutdown reports packet/pbuf/session/timer/socket equality and `residue=0`, including one post-stop drain step. | Bounded fixture resource ledger. |

OI-4 bounded decision: **`SCOPED_SHARD_ISOLATION_GO`**.  This supports the
two-owner host shard/transport seam, including real TCP, and supports the
owner-local isolation claim for the enumerated cells.  It does not support
four-worker Android, migration under load, capacity, pressure, soak, or
release readiness.

## OI-5 — generation, underlay epoch, fault, and teardown

| Requirement | Evidence that supports it | Exact boundary |
| --- | --- | --- |
| Late wake/fd/timer/stale/broker/output/TUN events are rejected during stop | Model schema `owner-inline-oi5-generation-epoch/v2`, source SHA-256 `c082a28287a5f70747922f4ada75fc251ffeedc745c2a80fb1c77bef230d37d2`, output `/tmp/s130-oi5-model-current.json`, SHA-256 `69ff1dd1a85cf33bffbc6204a1c7ac82ea3e73ad0c2dbbafbdbe31466fe81839`; its stop matrix rejects all eight named event kinds and settles TCP/UDP resources to zero. | Deterministic model for the complete late-event matrix. |
| Generation and underlay epoch invalidate old TCP/UDP state; fresh flow snapshots the new epoch | Model `restart_generation` and `underlay_epoch_invalidation` prove `g1/e1 → g2/e2`, old TCP `TERMINATED`, old UDP `MAPPING_INVALIDATED`, old reconnect/reuse `0`, and fresh flow at `e2`. Host and controlled Pixel stdout also log `old-generation/old-epoch -> new-generation/new-epoch` with `old-tcp-reconnect=0 old-udp-reuse=0` for four transitions. | Pixel evidence is controlled local reachability (`10.200.0.0/24`, loopback underlay), not arbitrary/default-route traffic. |
| Forced Flow Stack fault → one bounded restart → fresh flow success | Host runner `experiments/vpp-nfq-poc/prototypes/owner_inline_oi5/oi5_host_fault_restart.py`, SHA-256 `6c1d7315cd5d53f9824025f6a52469c8acb09fe45eeda1f759d2d9415703ab93`, current stdout `/tmp/s130-oi5-fault-host-stdout-current.txt` SHA-256 `5500a53750f1bdf81133763c0231a2cfa64cfa6775d3b7c32b5d3eff01979694`, and console SHA-256 `59d74ebda2114a9b372dfe156b04a80a10c52f64f8bbe4d4a956b1e722a47ae9`; it records fault-injected generation 1 and fresh generation-2 TCP4 with `buffers=184/184 residue=0`. Controlled Pixel raw stdout `/tmp/s130-oi5-android-stdout-current.log`, SHA-256 `33e75c8dfec800a6d5b26d0c32a67fcd30970e79f80ffa282e5d90d2b0143214`, records `fault-injected=1` generation 2 followed by generation-3 TCP4 `PASS` and `buffers=179/179 residue=0`. | One bounded injected fault and restart on host plus one controlled Pixel sequence; no production or arbitrary-route claim. |
| Pixel normal stop, fault stop, restart, and underlay invalidation raw ledger | Pixel 6a serial `28201JEGR0XPAJ`; runner/CLI `/tmp/s130-oi5-android-cli-current.log` SHA-256 `b7309d17dc06dd23a9a14928309ff80fa2150e843f9633509cc2d683bc15144f`; broker `/tmp/s130-oi5-android-broker-current.log` SHA-256 `ea2dcadded8da29069d09b03f658234a76f7a665b3ade38c3e68c02db310abd9`; VPP stdout above. The five raw cleanup ledgers are g1/e1 normal stop `PASS` `122/122`, g2/e2 fault `PASS` `124/124`, g3/e3 TCP4 `PASS` `179/179`, g4/e4 UDP4 `PASS` `188/188`, and g5/e5 TCP4 `PASS` `431/431`, all residue zero. | Controlled mode only: route `10.200.0.0/24`, no default route, loopback underlay, app-owned in-process CLI monitor. |
| Same-process normal restart and TCP FIN | Host stdout `/tmp/s130-oi5-host-stdout-current.txt`, SHA-256 `7ab6d2c735fdb7b2fdd41dfb06956a94e354e7b39f0b39100547d05c93595f2b`; console `/tmp/sakamoto-vpp-nfq-poc/s130-oi5-host-console.log`, SHA-256 `c043b281f594ec64d46bff9d7446ab28e1af2572e3987aa4260c046ee28ce475`; generation 1 UDP4 (`buffers=144/144`) and generation 2 TCP4 (`buffers=307/307`) both cleanup PASS with zero residue. Controlled Pixel raw adds generations 4 and 5 around the underlay invalidation transition. | Host loopback and controlled Pixel loopback underlay; bounded multi-generation runs. |
| Quiesce/drain/close/settle and exactly-once resource ledger | Model history and resource ledger, host cleanup lines, Pixel VPP stdout, and Pixel broker ledger show equal allocation/release for packet/pbuf/VPP buffers/socket/session/timer; every Pixel cell has residue `0`, one broker request/duplicate-fd close per generation, and no completion `EPIPE`. | Does not establish unbounded soak, capacity, pressure, or release readiness. |

OI-5 bounded decision: **`SCOPED_GENERATION_TEARDOWN_GO`**.  This supports
the bounded host and controlled Pixel generation/epoch/fault/restart direction
and the full late-event model.  It does not support arbitrary/default-route
Android traffic, multi-worker Android, capacity, soak, production, or release
sign-off.

## Final bounded decision and execution contract

The five sequential gates all reached their registered bounded outcome:

| Gate | Scoped result | Evidence record |
| --- | --- | --- |
| OI-1 scheduler/wakeup/fairness | `SCOPED_SCHEDULER_WAKE_GO` | `S126_OI1_EXECUTION_JOURNAL.md` — Host + Pixel arm64, timer/FD/packet/mixed/fairness/stale-wake cells, owner-thread callbacks, zero residue. |
| OI-2 async Android broker | `SCOPED_ASYNC_BROKER_GO` | `S127_OI2_EXECUTION_JOURNAL.md` — Host + Pixel IPv4/IPv6, failure/queue/tripwire/delayed-stop cells, exactly-once duplicate close. |
| OI-3 single-owner Direct Egress | `SCOPED_DIRECT_EGRESS_GO` | `S128_OI3_EXECUTION_JOURNAL.md` — Host TUN/direct path and controlled Pixel IPv4/IPv6 TCP/UDP/failure matrix. |
| OI-4 shard isolation | `SCOPED_SHARD_ISOLATION_GO` | `S129_OI4_EXECUTION_JOURNAL.md` — deterministic tuple/fault/tripwire model and real two-owner UDP/TCP host runners. |
| OI-5 generation/epoch teardown | `SCOPED_GENERATION_TEARDOWN_GO` | `S130_OI5_EXECUTION_JOURNAL.md` — host restart/fault ledgers and Pixel normal/fault/restart/underlay raw ledgers. |

Therefore the single parent-level bounded decision is:

**`OWNER_INLINE_ACCEPTED` — scoped to the bounded POC contract below.**

This is an architecture-direction acceptance for the tested seams.  It is not
production thread-topology acceptance, capacity approval, external/default-
route safety approval, or release closure.  No gate produced a major finding
that overturned the owner-inline assumption; the observed defects were
directional-channel, callback initialization, endpoint readiness, stop-race,
and descriptor-lifetime seam corrections.

The accepted execution contract is:

1. **Flow Stack Module interface.**  The public seam remains opaque to HEV/lwIP
   internals: `submit(shard, PacketLease)`,
   `drive(shard, wake_cause, quantum_budget, wall_deadline) → DriveResult`,
   and `quiesce(shard, generation) → DrainResult`.  `DriveResult` carries only
   `RUNNABLE`/`WAITING`/`STOPPED`/`FAULT`, bounded quanta, work-remaining,
   next-deadline, wake-generation, output count, and stable fault reason.
   PCB/pbuf/raw-fd/TLS/task objects stay behind the module boundary.
2. **Wake topology.**  The canonical FlowOwner worker is the only executor of
   HEV/lwIP mutable callbacks.  A wait-only helper may observe fd/timer
   readiness and publish an opaque `{shard,generation,wake-sequence,cause}`;
   it never drives HEV/lwIP or owns packet/socket state.  `WAITING` does not
   self-requeue or busy-poll; only matching packet/fd/timer/control wakes
   re-arm the owner, with quantum and wall deadlines enforced.
3. **Socket broker ownership.**  The owner creates the nonblocking socket and
   submits a bounded token plus one descriptor duplicate.  The Android broker
   alone performs underlay bind and `VpnService.protect()`, closes its
   duplicate once, and returns a directional completion.  The original owner
   consumes success/failure/stale completion; it alone may connect/send or
   destroy transport state.  Broker failure is an infrastructure/transport
   fact, never Policy DROP or SOCKS fallback.
4. **Per-worker shard mapping.**  A canonical tuple/provenance key selects a
   fixed FlowOwner shard.  HEV task system, lwIP mutable state, PCB/session,
   timer, credit, socket, and output ownership remain local to that shard;
   there is no live migration, alternate-owner spill, process-global mutable
   transport authority, or global lwIP core lock.
5. **Generation/teardown contract.**  Stop quiesces admission, preserves the
   wake/completion/return path for bounded drain, closes/aborts transport
   sessions and protected sockets, reclaims every lease/pbuf/credit/VPP buffer,
   then closes Flow Stack resources and the adapter generation.  Every packet,
   wake, timer, broker, socket, output, and ownership token carries generation
   (and underlay epoch where applicable); mismatches are rejected and counted.
   A new epoch terminates old TCP without automatic reconnect and never
   silently reuses an old UDP mapping; a bounded restart starts fresh shard,
   generation, endpoint, and completion-watcher state.

## Overall interpretation

Across OI-3, OI-4, and OI-5, the evidence supports continuing the owner-inline
architecture through the bounded POC chain.  The findings were implementation
seam corrections—connector callback initialization, original-destination
normalization, endpoint-ready synchronization, bounded timeout/refusal
classification, TCP TUN lifecycle draining, and the shared-TUN no-reader rule.
They did not require a paired-thread HEV/lwIP datapath, migration/spill, or a
global mutable flow lock, and no new major discovery overturned the original
design assumptions.

The evidence supports scoped continuation, not a production conclusion.  Any
broader claim needs a separately authorized campaign for external/default-route
safety, multi-worker Android, capacity, pressure, soak, and release lifecycle.
