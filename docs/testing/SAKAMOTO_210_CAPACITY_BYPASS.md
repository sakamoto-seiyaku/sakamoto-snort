# SAKAMOTO-210 — Root Primary Handoff capacity bypass

PASS, 2026-09-08. The same product source passes real Linux NFQUEUE and Pixel
Root tests: **932 packets**, including **444 pre-policy capacity bypasses** and
**256 Policy DROP packets**. Every carrier retains its original buffer,
generation, packet ID and origin lane through one completion, one native verdict
attempt and one buffer free. All eight generations stop without outstanding
queues, credits, completion frames, buffers, obligations, FlowEntries or sockets.

## Product change

The ordinary native Primary Handoff rejection path previously selected
`DROP_RUNTIME / PRIMARY_HANDOFF_CONGESTION`. Root pre-policy rejection now uses
`PROCESSING_CAPACITY_BYPASS` (terminal intent 3), with a separate typed reason:

| Reason | Value | Failure path |
| --- | --- | --- |
| `PRIMARY_CREDIT_EXHAUSTED` | 1 | The actual reservation reads no available credit |
| `PRIMARY_ENQUEUE_REJECTED` | 2 | The native retained enqueue returns the original rejected index |

The guarded transition accepts only an undecided, valid, remote Root lease. It
does not set `policy_owner_ready`, generate a Policy Verdict, allocate/update a
FlowEntry, change ExecutionOwner, spill, or retry Primary Handoff. The caller
keeps the rejected buffer and sends it directly to terminal and origin
completion. Only the origin NFQUEUE lane translates that disposition to its
single `NF_ACCEPT` operation. `runtime_drop_reason` remains `NONE`; the separate
bypass reason survives into the unchanged 32-byte Completion Frame.

An existing Policy DROP cannot enter that transition. Its original intent and
reason remain in the native completion carrier. The existing worker-private
512-index return backlog retains a rejected completion and retries through the
native nonblocking return queue, with at most 64 successful returns per poll.
The compile-time bound exceeds the entire admitted population of four 64-credit
Root lanes plus 32 diagnostic injection buffers. No replacement packet buffer,
packet copy, shared verdict writer, Rust packet path or new VPP core patch was
introduced.

Main implementation:

- [packet disposition and guard](../../src/product/vpp/product_packet.c)
- [native handoff, terminal routing and retained return](../../src/product/vpp/product_packet_graph.c)
- [origin NFQUEUE completion](../../src/product/vpp/product_root_nfqueue_adapter.c)
- [bounded Completion Frame](../../src/product/vpp/product_packet_completion.h)

## Actual failure injection

`product capacity credits N primary-slots N completion-slots N` is a diagnostic
CLI protected by the normal worker barrier. It requires an active empty graph,
zero carrier/return debt and empty native rings. It changes only the available
credit and usable depth of the already allocated native queues. The release
defaults remain 32 credits, 64 Primary slots and 128 return slots; `off` restores
them, and every Root start resets them. All final runs verify those defaults
before traffic after restart and after each fault phase.

The credit phase sets actual available credits to zero. It does not replace the
reservation function's result. The enqueue phase uses a two-slot native ring
and a bounded 500 ms hold of a real owner packet; the ring-full check in the
pinned retained backend rejects subsequent real NFQUEUE buffers. All 380
enqueue-rejected packets complete at origin before the held packet releases.

The DROP phase publishes an actual Gate DROP through Rust Product Core and
generated VAPI, then sends 32 real UDP datagrams through a two-slot completion
return ring. **228 already-decided DROP carriers encounter actual native return
rejection**, remain retained, and subsequently complete as `NF_DROP`. All 256
DROP packets are absent from the echo endpoint. Restoring normal capacity and
policy makes subsequent packets traverse policy and reach the endpoint.

The final bursts fit the existing ingress budget. Final captured, graph-admitted,
verdict and buffer-return totals agree; no Adapter ingress fail-open or kernel
queue loss is included in these PASS claims.

## Final wire evidence

All rows use UDP and real NFQUEUE OUTPUT capture, the native default product
graph, four actual dual-stack queue lanes and two VPP workers. Actual warm
packets identify a remote flow for each selected owner; the test never changes
the assignment or kernel queue placement. The Python oracle independently
reconstructs the complete typed canonical key, hash and owner from wire facts.

| Platform / generation | Family | Target worker | Packets | Credit bypass | Enqueue bypass | Policy DROP | Retained DROP returns |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Linux 21010 | IPv4 | 0 | 115 | 8 | 47 | 32 | 30 |
| Linux 21011 | IPv4 | 1 | 114 | 8 | 47 | 32 | 30 |
| Linux 21012 | IPv6 | 0 | 116 | 8 | 47 | 32 | 14 |
| Linux 21013 | IPv6 | 1 | 115 | 8 | 47 | 32 | 30 |
| Pixel 871 | IPv4 | 0 | 118 | 8 | 48 | 32 | 31 |
| Pixel 872 | IPv4 | 1 | 114 | 8 | 48 | 32 | 31 |
| Pixel 873 | IPv6 | 0 | 115 | 8 | 48 | 32 | 31 |
| Pixel 874 | IPv6 | 1 | 125 | 8 | 48 | 32 | 31 |
| **Total** | | | **932** | **64** | **380** | **256** | **228** |

The remaining 232 packets pass normal policy. All 676 accepted nonces appear
exactly once at both the independent echo endpoint and client; no DROP nonce
does. Native per-thread admit, policy, terminal and origin-completion vector
counts independently agree with the packet ledger. Bypass tokens have no policy
acquisition, Policy Verdict, FlowEntry event, successful handoff or remote
completion return.

Maximum observed bypass admission-to-origin-consumption time is 25.56 ms on
Linux and 57.44 ms on Pixel. Maximum retained-DROP settlement is 23.51 ms on
Linux and 3.277 s on Pixel. The bounded held-packet case reaches 4.080 s on Pixel.
All satisfy the existing 8-second functional collection bound; these are
observations, not latency SLOs, a power qualification, or a change to the
previously accepted Android scheduling scope.

For every generation, native `product root stop` is followed by zero completion
and handoff debt, zero FlowEntries, four closed lane FDs and disappearance of
each recorded NFQUEUE socket inode while the VPP process still exists. Linux
then successfully rebinds every kernel queue and terminates the isolated
namespace process. Pixel then stops RuntimeService, has no VPP process, no
kernel NFQUEUE entries or Product hooks, and restores Wi-Fi to its original
state. The final device generation is 874, stopped; diagnostic endpoint processes
also exit.

## Source and artifact binding

The working tree is intentionally uncommitted. Both builds snapshot every product
source file and the complete dirty diff against commit
`9c67175713baceb46cef015f3464893fa3d69950`; no later product edit is included.

| Identity | SHA-256 |
| --- | --- |
| Product source manifest | `d133ed7a94bd0ae0875c81d14644c5f980b815661f846c55d28e4796719c5f51` |
| Linux native plugin | `e4b75a22e75c411c80add6aa1d52063eda2235dc4f1c6b8d534bd97e789bbec5` |
| Linux VPP executable | `3f68cfab85ae1b49f1f016b6ab13ddb69dc8208dd9fb2d8a4098731bbe264485` |
| Pixel APK | `24043deacf40e4a3e5a8c3a7256a4609d5a0fefa0f763cb3b5d340b0bb096cb7` |
| Pixel native plugin | `d817f06beba742053b145070825e7602071ad330b2369b85b54c637c3e431b1d` |
| Pixel VPP runtime | `52f690bb5fda680ebafcd84061e2d93eb3b4c63ce41917483c642609872e97b7` |

The Pixel collector compares the installed APK and every installed native library
with the actual build. Device/kernel and native thread identities are retained
in each run. The diagnostic UDP endpoint drops its real UID/EUID to 12632 before
creating its socket; UID, kernel capture and wire bytes are observed, not
fabricated. It is a test endpoint, not a claim that these packets originated in
the application's Java UI. The policy helper invokes the same installed Rust
Product Core library through its control ABI. Helper sources, hashes and compiler
arguments are recorded separately from the product build.

Final evidence paths:

- `build-output/s210-capacity/linux-build-a/build.json`
- `build-output/s210-capacity/pixel-build-a/build.json`
- `build-output/s210-capacity/linux-d/verification.json`
- `build-output/s210-capacity/pixel-b/verification.json`
- `build-output/s210-capacity/helpers-build.json`
- `build-output/s210-capacity/host-checks/`
- `build-output/s210-capacity/negative-verification.json`

The S210-only delta against the sealed S209 source is
`build-output/s210-capacity/s210-increment.patch` (five product files).
`evidence-tools/manifest.json` seals the collector, oracle, helper and Host-test
sources with SHA-256
`fe546e40a04409035590173a96ab312aa290f17bcb5af6a79559c996f2aacdd4`.
`records.json` binds the final build and verification records with SHA-256
`bfed6ced38ab771467d94d62b97ad9e56aac60e933438c977b3e9a41ad2777c5`.
Current-source verification intentionally rejects these records after later
product changes; historical reproduction uses the sealed source and tool copies.

## Verification and limits

Six selected CTest checks pass: L4 and FlowEntry C units, the S209 immutable
snapshot source contract, S210's guarded-transition C unit and native source
audit, and S174/S175 C packet contracts. They are auxiliary Host checks; the
native PASS above comes from the current wire artifacts. Seven semantic evidence
corruptions correctly fail: changed generation, missing free, duplicate verdict,
missing bypass reason, DROP changed to ACCEPT, fabricated policy on a bypass,
and a transferred supposedly rejected carrier.

The final independent verifier binds source, artifact, packet identities,
typed facts, native vectors, phases, endpoint delivery and native cleanup:

```sh
rtk proxy python3 tests/device/verify-s210-capacity.py build-output/s210-capacity/linux-d --build build-output/s210-capacity/linux-build-a/build.json --platform linux
rtk proxy python3 tests/device/verify-s210-capacity.py build-output/s210-capacity/pixel-b --build build-output/s210-capacity/pixel-build-a/build.json --platform pixel
rtk proxy python3 tests/evidence/test_s210_capacity_negatives.py build-output/s210-capacity/linux-d --output /tmp/s210-negatives.json
```

Earlier `linux-b` used a 128-packet DROP burst and mixed in Adapter ingress
capacity failures; it is not accepted as isolated S210 evidence. `linux-c` and
`pixel-a` passed functional checks but were superseded to record restart defaults
and the full native-stop FD ledger. The initial `linux-a` collector failed before
creating a runtime. These directories remain separate; only `linux-d` and
`pixel-b` support the final PASS.

This increment does not qualify production capacity, TCP pressure, malformed or
reassembly-content fault handling, VPN transport bypass, soak, or release
readiness. VPN still requires its normal ADR-0007 transport path. The removed C++
implementation and C/VPP POCs were not imported or used as product source.
