# S158 D1-D3 final-topology owner/overload design hotspot

Date: 2026-08-24
Status: `SUPERSEDED_BY_S159` (historical design audit retained)
Scope: Pixel D1, D2, D3; E1/E2 dependency chain

## Historical decision point

Stop the remaining D/E execution chain. This is a design-level blocker, not
an ADB, permission, LAN fixture, or endpoint-readiness problem.

The final OI3 artifact that produced the S157 C2 evidence was a valid
single-owner, re-armed-TUN path. At that snapshot it was not a final-topology
multi-owner implementation, so the original S158 instruction correctly paused
D1-D3 rather than misreporting one-owner limits as shard evidence.

The route decision was subsequently implemented in the working tree: the
Android artifact now starts two independent owner contexts with a canonical
tuple hash, shared TUN/completion seam, and explicit admission ledgers. D1 and
D2 have since produced bounded Pixel evidence. The remaining overload seam is
recorded separately in
[`S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md`](S159_D3_HEV_SUBMIT_BACKPRESSURE_HOTSPOT.md).

## Current disposition (superseding S158)

| POC | Current disposition | Evidence |
| --- | --- | --- |
| D1 | `PASS_FOR_TESTED_ENVELOPE` | Two owners, IPv4/IPv6 UDP/TCP, owner-local context identity, peer fault isolation; recorded in the S159 execution journal. |
| D2 | `PASS_FOR_TESTED_ENVELOPE` | Concurrent owner-busy admission is explicit and bounded; existing owner settles with zero residue. |
| D3 | `PAUSED_BY_RUNTIME_HOTSPOT` | HEV `submit()` returns `-5` after the bounded credit is occupied; S159 records exact settlement but no reply/recovery. |
| E1/E2 | `PAUSED_BY_D3` | Do not interpret lifecycle/performance pressure until the D3 submit/backpressure contract is corrected. |

## Historical static audit evidence (S157 artifact)

The canonical and generated OI3 sources are source-identical. Both contain:

- one process-global `static oi3_main_t oi3_main` (`overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c:436`);
- one `FlowStackOwnerContext`, `target_thread`, `frame_queue`, detached `tun_fd`, completion path, connector wake path, and per-flow queue in that state object;
- one `oi3_tun_command_fn`/`oi3_run_command_fn` command path that configures that global state, rather than an owner registry or tuple-to-shard dispatcher;
- a fixed per-context pending queue (`OI3_TUN_PENDING_CAPACITY=16`) and HEV limits (`packet_credit_limit=8`, `inflight_pbuf_credit_limit=8`, `max_session_count=4`, `protected_socket_credit_limit=4`). These are single-context limits, not a multi-owner admission contract.

The Android OI3 startup path also fixes the topology to one worker and one
target:

```text
sakamoto-oi3 tun fd <n> target-thread 1 ...
cpu { main-core 0 workers 1 }
```

The controlled `run` helper likewise emits `target-thread 1`. No final OI3
source or Android startup path currently provides a canonical tuple hash,
owner/shard map, independent owner contexts, per-owner resource ledgers, or a
second owner instance.

The relevant source audit was performed against the S157-built plugin/APK
(plugin SHA-256
`c7d0b00627202d0a3a1e39a4cf6603f7daa8cd3a91daeb6720b18bf06ab31ed1`, APK
SHA-256
`c5001cfabbb9011df111780d87e1bab41f04aa04f733406a552e498ed8fda71f`).

## Why existing evidence could not close D at S158

`S129_OI4_EXECUTION_JOURNAL.md` contains useful Host/model and two-pthread
HEV/lwIP evidence, including IPv4/IPv6 UDP/TCP and wrong-owner tripwires. It
explicitly does not claim Pixel final-topology coverage, four-worker Android
coverage, capacity, pressure, or soak. The campaign's own substitution rule
therefore rejects it as evidence for Pixel EG-12--EG-15.

S157's same-session IPv4→IPv6 and active-fault evidence closes the historical
one-flow-per-VPN-session lifecycle defect for the registered single-owner
re-arm contract. It does not add a second owner or a shard admission path.

## Impact on the registered POCs

| POC / gap | Current disposition | Reason |
| --- | --- | --- |
| D1 / EG-12, EG-13 | `BLOCKED_BY_DESIGN` | The required two-owner Pixel topology and tuple distribution seam do not exist in the selected artifact. |
| D2 / EG-14, EG-15 | `BLOCKED_BY_D1` | The observed queue/credit/session constants are per one context; no final per-owner admission or resource-exhaustion contract can be exercised. |
| D3 / EG-14, EG-15 | `BLOCKED_BY_D1` | No final multi-owner queue/credit/buffer ownership path exists, so pressure outcomes cannot be attributed to an owner or shard. |
| E1 / EG-16 | `PAUSED` | Repetition before D2/D3 would measure the wrong engineering envelope. |
| E2 / EG-17, EG-18 | `PAUSED` | Performance/device-state results would describe single-owner topology, not the registered final topology. |

The one-owner C2 result remains valid and closed for its stated contract;
this finding does not invalidate S157 or reopen B/C.

## Required route decision before resuming (historical S158)

One of these choices must be made explicitly:

1. **Implement the final multi-owner route.** Add an owner registry/shard
   dispatcher with a canonical tuple hash, independent owner contexts and
   queues, per-owner broker/timer/credit/buffer ledgers, bounded admission and
   overload outcomes, plus an Android startup/configuration that actually
   instantiates at least two owners. Then rebuild and rerun D1, D2, D3 before
   E1/E2.
2. **Narrow the campaign to single-owner feasibility.** Rewrite D/E claims,
   dependencies, Evidence Gap Map, and Plane scope so that multi-owner,
   distribution, and per-owner capacity are explicitly out of scope. This is a
   campaign/spec change, not a POC pass.

That decision is now recorded by the multi-owner implementation and the
exercised artifact matches the owner topology for D1/D2.  D3 remains paused
for the independent S159 HEV backpressure hotspot; no D3/E cell should be
reported as `PASS` until that submit contract is corrected.

## Time estimate

There is no honest remaining-time estimate for the current chain because the
next step is an architecture/spec decision. Under option 1, expect at least a
new design/build/device-validation cycle before D1 can start, followed by the
three D cells and only then E1/E2; this is multi-session engineering work,
not a remaining test-run delay. Under option 2, the work is documentation and
scope reconciliation, after which only a narrowed campaign could continue.
