# SAKAMOTO-139 / A2 UID policy execution journal

Date: 2026-08-23 (Asia/Taipei)  
Plane: SAKAMOTO-139  
Campaign parent: SAKAMOTO-137  
Evidence level: Pixel 6a / arm64; narrow TUN/VPP policy-boundary evidence  
Overall result: `INSUFFICIENT`; `architecture_interruption=false`

## Registered question and baseline

Can a bounded asynchronous UID fact provider attribute real Android IPv4 and
IPv6 TCP/UDP tuples for controlled App UIDs without blocking FlowOwner,
mutating the direction-independent canonical key, cross-App cache
contamination, stale identity revival, or Android broker/socket/transport work
for a dropped UID?

The A1 baseline remains in force: FlowOwner is selected from the canonical
tuple first; UID is a scoped asynchronous policy fact. Owner execution remains
nonblocking, and UID is not part of the canonical FlowOwner key. A valid
finding that requires changing that baseline would interrupt the campaign.
Ordinary APK, plugin, allow-list, sentinel, and packet-capture fixture defects
are POC corrections and do not satisfy the interruption condition.

This journal does not claim B1 complete VPP plus lwIP external forwarding. A
TCP connect or VPP shim counter is recorded only at the observed boundary.

## Artifact and provenance

- A2 artifact: [uid-attribution-contract-android-a2.json](prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-android-a2.json)
- A1 schema/model baseline: `prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-host-model.json`
- A1 execution journal: `S135_A1_UID_ATTRIBUTION_EXECUTION_JOURNAL.md`
- Evidence schema: `uid-attribution-contract-evidence/v1`
- Device serial: `28201JEGR0XPAJ` (Pixel 6a, Android API 36, SELinux Enforcing)
- Device operations: repository `./dev/adb`; no Windows `adb.exe` was used
- Underlay: Wi-Fi network 113 / `Openwrt_5G`, local address `192.168.4.151`,
  IPv6 ULA prefix `fd76:d462:c4e3::/48`
- VPN addresses: `tun0` `10.111.0.2/32`; IPv6 run `fd00:111:111::2/128`
- Controlled package UIDs: Chrome `com.android.chrome=10180`, Maps
  `com.google.android.apps.maps=10176`, VpnLite
  `com.sakamoto.snort.vpnlite=12628`, androidruntime
  `com.sakamoto.snort.androidruntime=12620`
- Compatibility stage: `experiments/vpp-nfq-poc/work/android-nfqb-stage/`
- Loaded native plugin: `tun_poc_plugin.so`, verified by VPP `show plugins`
- Documentation Git head: `4f01c62f416859dcb904e8452aeb32f381766f6c`

The artifact records the raw path inventory, package provenance, command
families, correction history, claims, non-claims, and the evidence-integrity
caveat that the historical VpnLite IPv4 UDP raw file was later reused by an
IPv6 run.

## Execution and cleanup

Representative commands used in the captured cells were:

```sh
./dev/adb shell am start -n com.sakamoto.snort.vpnlite/.MainActivity \
  --ez start true --es mode vpp-hev-owner-resolver \
  --es allowedPackage com.android.chrome --ei blockOwnerUid 99999 \
  --ez ownerCache true
./dev/adb shell am start -a android.intent.action.VIEW \
  -d http://1.1.1.1:80/
./dev/adb shell dumpsys connectivity
./dev/adb shell su 0 cat /proc/net/tcp
./dev/adb shell su 0 cat /proc/net/tcp6
```

The scripted contract, IPv6, and two-ordinary-App runs were
`android-run-s139-a2-contract-controls.sh`,
`android-run-s139-a2-chrome-ipv6.sh`, and
`android-run-s139-a2-two-ordinary-apps.sh`. The latter was also run with
`CONCURRENT=1` to launch Chrome and Maps without the inter-app delay. The runner
traps stopped VpnLite and
force-stopped the probe app. Chrome HTTP cleanup recorded no remaining VPP
process and no `tun0`; second-UID and dual-allow runners recorded
`pending=0`, `cache=0`, and zero high-water residue after runtime stop. The
rebuilt contract-controls runner now captures a separate final JSONL after its
cleanup trap, including `pending=0;cache=0;flow-ids=0`; the pre-cleanup raw
capture remains clearly separated. A forced Chrome IPv6 HTTP/80 retry also
cleaned up with no remaining VPP process or `tun0`.

`tcpdump` and `toybox tcpdump` were unavailable. The boundary fallback used
`/proc/net/tcp*`, VPP `show tun-poc`, resolver output, and cleanup process/link
checks. The ULA IPv6, gateway reverse-attempt, current-UID drop, and
near-simultaneous dual-App runs all cleaned up with no remaining VPP process or
`tun0`.

## Cell evidence

| Cell | Result | Evidence and exact boundary |
| --- | --- | --- |
| Chrome UID 10180 IPv4 TCP | `PASS_NARROW` | Real `tun0` tuple to `1.1.1.1:80`; `/proc/net/tcp` local hex `02006F0A` decodes to `10.111.0.2`, UID is 10180. VPP observed `tuple parsed=94`, resolver `85/85`, owner-cache UID 10180, `uid-block 99999 packets=0`, and `shim-tx=102`. |
| Chrome UID 10180 IPv4 UDP | `PASS_NARROW` | Real IPv4 UDP tuples reached resolver/cache and post-policy shim. Contract raw records miss, coalescing, completion UID 10180, and cache hit; no cross-App hit was accepted. |
| Chrome UID 10180 + Maps UID 10176 IPv4 TCP/UDP | `PASS_NARROW` | Both ordinary packages were added separately to one allow-list. The final APK regression recorded Chrome UDP UID 10180, Maps UDP UID 10176, Maps TCP UID 10176, `/proc/net/tcp` sockets for both UIDs, final `tuple parsed=119`, `resolver 108/108`, `shim-tx=126`, and sentinel `uid-block 99999 packets=0`. A near-simultaneous Chrome/Maps retry retained both UIDs in `/proc/net/tcp`, Chrome UDP and Maps TCP completions, final `tuple parsed=110`, `resolver=106/106`, `shim-tx=117`, and sentinel `uid-block=0`. This is still a two-App IPv4 boundary observation, not the full matrix. |
| VpnLite UID 12628 IPv4 UDP | `PASS_NARROW_WITH_PROVENANCE_CAVEAT` | Earlier handoff recorded tuple `198.51.100.58:5354`, miss to completion UID 12628, cache/store, and shim output. The original bytes at `android-vpp-owner-resolver-udp-poc.log` were overwritten by a later IPv6 run, so this is not a freshly replayable immutable cell. |
| Chrome UID 10180 IPv6 target | `INSUFFICIENT` | The historical `[2606:4700:4700::1111]:443` run recorded one late resolver completion `uid=10180` for the exact IPv6 tuple (`fd00:111:111::2:42590 -> 2606:4700:4700::1111:443`) while `/proc/net/tcp6` showed UID 10180 in `SYN_SENT`; later retries returned `uid=-1`. The final APK forced HTTP/80 retry likewise kept `uid=-1` for every target query while VPP parsed the IPv6 tuple (`tuple parsed=35`, `shim-tx=42`). A final ULA retry to `[fd76:d462:c4e3::1]:80` added `/proc/net/tcp6` UID 10180 and VPP `tuple parsed=51`, but all exact-target resolver queries were `uid=-1`; an extended final HTTPS/443 retry reached VPP `tuple parsed=77`/`shim-tx=85` with `/proc/net/tcp6` UID 10180 but still had `uid=-1` for every exact target query. The one historical completion is intermittent and not a repeatable current target-UID cell. |
| Contract refresh/unavailable/replay | `PASS_NARROW` | Final JSONL used a package-scoped allow UID 10180 and exercised refresh, unavailable, miss→completion→hit, coalescing, bounds, and live Java pending/cache replay assertions for wrong-owner, wrong-UID, wrong-generation, wrong-scope, duplicate, stale, cross-App cache-hit, and UID-free-key cases. It does not prove native VPP owner/cache invariance. |
| Androidruntime UID 12620 IPv4 TCP | `INSUFFICIENT` / decisive fixture failure | Plain DebugControlActivity socket connected to `1.1.1.1:443`, but `/proc/net/tcp6` decoded local address `192.168.4.151`, not `10.111.0.2`; VPP had `tuple parsed=0`, resolver `q=0`, cache `0`. RuntimeService was absent before/after VPN and activity start. |
| UID drop / no broker work | `INSUFFICIENT` | IPv6 UDP drop raw recorded UID 12628, `blocked=2`, and `uid-block packets=2`; the dedicated Chrome UID 10180 IPv4 drop recorded `uid-block uid=10180 packets=12 bytes=14106` and `blocked=12`, while the allow sentinel remained zero. Independent broker/socket/transport-zero counters were not captured, so the acceptance cell remains open. |

The Androidruntime result is a fixture/binding failure, not evidence that
owner-inline execution must block or that FlowOwner must include UID. The dual
allow-list experiment established that Android accepted both packages, but it
did not make the plain androidruntime socket use the VPN.

## Contract controls and falsifier replay

The rebuilt contract-controls JSONL used schema `uid-attribution-contract/v1`,
pending capacity 4, cache capacity 4, and a package-scoped allow UID of
10180. High-water values were `max_pending=4`, `max_cache=4`, and
`max_flow_ids=8`; final contract state was
`pending=0;cache=0;flow-ids=0` after cleanup. The exact outcome counts from
`results/s139-a2-contract-controls-live-replay-final2/uid-attribution-contract-final.jsonl`
are:

```text
ALLOWED_UID_SCOPE 1
CACHE_EVICTED 32
CACHE_HIT 4
COMPLETION_ACCEPTED 47
COMPLETION_WRONG_UID 1
COMPLETION_DUPLICATE 1
COMPLETION_STALE 1
COMPLETION_WRONG_GENERATION 1
COMPLETION_WRONG_OWNER 1
COMPLETION_WRONG_SCOPE 1
CONTRACT_START 1
CROSS_APP_CACHE_HIT_REJECTED 1
FLOW_OWNER_KEY_MUTATION_REJECTED 1
LOOKUP_PROVIDER_AVAILABLE 1
LOOKUP_UNAVAILABLE 20
LOOKUP_QUEUE_FULL 1
MISS_COALESCED 2
MISS_SUBMITTED 50
REPLAY_ASSERTION 7
RUNTIME_REFRESH 1
SCOPE_REFRESH 6
CLEANUP 3
```

The final replay control created bounded synthetic pending requests and called
the live Java completion path. Wrong-owner, wrong-UID, wrong-generation,
wrong-scope, duplicate, stale-after-refresh, cross-App cache-hit, and
UID-free-key assertions were recorded with pending/cache before-after state;
rejected identity cases left live state unchanged, while wrong-UID rejection
intentionally settled its request. This is decisive for the Android Java
contract state, not for native VPP owner/cache state. A1 Host/model remains
the decisive cross-implementation baseline. Generations 1--4, network epochs
1--3, and app epochs 1--3 were present. The captured contract records
explicit unavailable and invalid-UID outcomes instead of waiting on owner
execution.

## POC corrections

| Correction | Before | After and verification | Architecture impact |
| --- | --- | --- | --- |
| Owner-resolver plugin selection | Startup selected the HEV external-driver plugin; `tun-poc` commands were unknown. | `vpn_fd_probe.c` prefers `tun_poc_plugin.so` with linker-prefixed fallback; VPP `show plugins` and `show tun-poc` work. | None |
| Dual allowed package fixture | Comma-separated `allowedPackage` was treated as one package. | `SnortVpnService` splits and calls `addAllowedApplication` for each package; connectivity showed UIDs 12620/12628 and their isolated IDs. | None |
| Explicit drop sentinel | Blank `BLOCK_OWNER_UID` defaulted to the package UID and self-dropped an intended allow run. | Runners pass sentinel `99999` and log effective block UID; allow runs show zero sentinel blocks. | None |
| Route instrumentation attempt | Temporary route logging was considered for the androidruntime fixture. | Build stopped on retained VPP source mutation; instrumentation was reverted and its failed build was not used as evidence. | None |
| Packet boundary tool | `tcpdump` and `toybox tcpdump` were unavailable. | `/proc/net/tcp*` plus VPP counters were retained as a lower-level fallback. | None |
| Package-scoped UID acceptance | The Android bridge accepted any nonnegative `getConnectionOwnerUid` result when an allow-list was active. | APK package visibility queries resolve the active allow-list to UID 10180/10176; a completion outside that scope emits `COMPLETION_WRONG_UID` and is not cached. | None |
| Android replay control | `replayFaultMatrix` emitted marker-only events. | The control now injects bounded synthetic pending requests into the live Java state and records wrong-owner/UID/generation/scope, duplicate, stale, cross-App-cache, and UID-free-key assertions with before/after counts. | None |

No correction changed owner-inline/nonblocking execution, the canonical
FlowOwner key, or the policy/transport safety boundary.

## Raw evidence inventory

The artifact contains this complete inventory of the raw directories/files
used or inspected for A2:

- `results/s139-a2-chrome-http80/` (cell summary, connectivity, `/proc`, VPP,
  resolver, shim, cleanup)
- `results/s139-a2-two-ordinary-apps/` (Chrome/Maps package UIDs, dual
  allow-list connectivity, VPP/resolver/shim, `/proc` sockets, cleanup)
- `results/s139-a2-two-ordinary-apps-long/` (25-second Chrome/Maps retry;
  both UIDs in `/proc` sockets, Chrome/Maps UDP and Maps TCP resolver
  completions, VPP/resolver/shim, cleanup)
- `results/s139-a2-two-ordinary-apps-long-final/` (final APK regression after
  package-scoped UID guard; both UIDs in `/proc`, Chrome/Maps UDP and Maps TCP
  completions, VPP tuple parsed=119, resolver=108/108, shim-tx=126, cleanup)
- `results/s139-a2-contract-controls/` (JSONL contract, cell log, VPP,
  resolver)
- `results/s139-a2-contract-controls-final/` (rebuilt APK contract JSONL,
  final cleanup event, flow-id high-water, VPP/resolver)
- `results/s139-a2-contract-controls-live-replay-final2/` (rebuilt APK with
  package-scoped UID allow, live replay assertions, and final cleanup JSONL)
- `results/s139-a2-chrome-ipv6/` (IPv6 connectivity, TCP6, VPP, resolver,
  cell log)
- `results/s139-a2-chrome-ipv6-http80/` (forced Chrome IPv6 HTTP/80 retry;
  `/proc/net/tcp6` UID 10180, VPP IPv6 target tuple, resolver `uid=-1` for
  target, and cleanup)
- `results/s139-a2-chrome-ipv6-http80-final/` (final APK IPv6 HTTP/80 retry;
  `/proc/net/tcp6` UID 10180, IPv6 target resolver `uid=-1`, VPP/resolver,
  and cleanup)
- `results/s139-a2-chrome-ipv6-ula-final/` (final APK ULA IPv6 target;
  `/proc/net/tcp6` UID 10180, VPP IPv6 tuple, exact-target resolver `uid=-1`,
  and cleanup)
- `results/s139-a2-chrome-ipv6-443-long-final/` (final APK extended IPv6
  HTTPS/443 retry; `/proc/net/tcp6` retained UID 10180 for the Cloudflare
  target, all exact-target resolver queries stayed `uid=-1`, VPP parsed
  tuples/shim output, and cleanup)
- `results/s139-a2-chrome-ipv4-gateway-reverse-final/` (reachable Wi-Fi
  gateway TCP reverse attempt; target tuple/resolver observed, `shim-rx=0`,
  and cleanup)
- `results/s139-a2-chrome-ipv4-drop-final/` (final APK Chrome UID 10180
  current-UID drop; `uid-block packets=12`, `blocked=12`, and cleanup)
- `results/s139-a2-two-ordinary-apps-concurrent-final/` (near-simultaneous
  Chrome/Maps IPv4 TCP/UDP cell; both UIDs in `/proc`, resolver completions,
  VPP counters, and cleanup)
- `results/s139-a2-tcp4-second-uid/`
- `results/s139-a2-tcp4-diag-repro-delay6/`
- `results/s139-a2-tcp4-diag-repro-delay12/`
- `results/s139-a2-tcp4-dual-allow-delay12/`
- `results/s139-a2-runtime-service-diag-dual-delay12/`
- `results/s139-a2-tun0-boundary-no-tcpdump/`
- `results/s139-a2-proc-tcp-testnet-45623/`
- `results/s139-a2-vpnlite-ipv6-tcp.log`
- `results/s139-a2-vpnlite-ipv6-udp-drop.log`
- `results/s139-a2-vpnlite-ipv6-udp-allow.log` (newly preserved IPv6 allow
  raw: plugin `tun_poc_plugin.so`, `uid-block 99999 packets=0`, no parsed tuple)
- `results/android-vpp-owner-resolver-udp-poc.log` (historical IPv4 UDP path,
  later overwritten by IPv6 UDP)
- `results/android-vpn-owner-gate-udp-inet4-poc.log` (legacy UID 12540 path;
  not used as current UID 12628 proof)

## Finding Ledger update

The A2 artifact carries the machine-readable Finding Ledger. The relevant
entries are:

- `VPN-F026`: `OPEN_RISK`. A2 supports narrow Chrome UID 10180 IPv4 TCP/UDP
  attribution, a two-ordinary-App IPv4 TCP/UDP observation (Chrome 10180 plus
  Maps 10176), and the live Java contract falsifier matrix, but does not close the
  complete IPv4/IPv6 TCP/UDP matrix or lifecycle acceptance.
- `VPN-F026-A2-FIXTURE-01`: `OPEN_RISK`. Androidruntime UID 12620 bypassed
  tun0 on a Wi-Fi local address while its RuntimeService was inactive; this is
  an evidence fixture gap.
- `POC-CORRECTIONS-A2`: `CLOSED_FOR_POC`. Plugin selection, dual allow-list,
  explicit sentinel, and packet-boundary corrections were retained with raw
  verification.

The existing campaign-level `ANDROID_VPN_EVIDENCE_GAP_MAP.md` and
`POC_FINDING_LEDGER.md` remain authoritative for the wider campaign. This
journal does not mark SAKAMOTO-139 or any Plane item Done.

## Supported claims

- Chrome UID 10180 produced real IPv4 TCP and UDP tuples entering tun0/VPP
  owner resolution and reaching the observed post-policy shim boundary.
- Chrome produced real IPv6 TCP tuples for the Cloudflare target and a local
  ULA target. The historical Cloudflare run included one exact-target
  `uid=10180` resolver completion; final HTTP/80 and ULA retries prove the
  tuple and `/proc/net/tcp6` UID 10180 but show intermittent `uid=-1` target
  completion, so this remains a narrow observation rather than a closed
  per-UID IPv6 cell.
- A two-ordinary-App allow-list cell (Chrome UID 10180 and Maps UID 10176)
  produced real IPv4 TCP/UDP tuples on the same tun0/VPP path; the long-window
  raw retained both UIDs in `/proc` sockets, Chrome/Maps UDP completions, and a
  Maps TCP completion, while the wrong-UID sentinel saw no policy drops. A
  near-simultaneous retry also retained both UIDs and distinct resolver
  completions in one window.
- The bounded Android contract emitted miss, coalescing, completion, cache
  hit/eviction, refresh, unavailable, package-scoped wrong-UID rejection, and
  live replay outcomes within declared pending/cache bounds. Replay assertions
  include pending/cache before-after state and final zero residue.
- A1 Host/model and the rebuilt Android Java control reject wrong-owner,
  wrong-generation, duplicate, stale, wrong-scope, wrong-UID, cross-App
  cache-hit, and FlowOwner-key mutation replays. The Android control does not
  prove native VPP owner/cache invariance.
- Plugin selection, dual allow-list handling, and the explicit drop sentinel
  were ordinary POC corrections and did not require an architecture change.
- A historical narrow UID 12628 IPv4 UDP observation exists, with the stated
  raw-overwrite provenance caveat.

## Non-claims and remaining acceptance gaps

This A2 package does not claim:

- complete acceptance across two normal controlled App UIDs for every required
  IPv4/IPv6 TCP/UDP, reverse, concurrent, refresh, and drop cell (the two-App
  IPv4 TCP/UDP and concurrent observations remain narrow PASS only);
- repeatable IPv6 target UID completion at the VPP post-policy boundary;
- a dedicated current-UID IPv4 drop proof with independent zero
  broker/socket/transport counters;
- reverse-traffic acceptance; the concurrent-distinct-tuple observation is
  narrow and does not prove the full matrix;
- Android/OEM-general VPN routing behavior, production capacity, or release
  readiness;
- external SOCKS/HTTP forwarding, reverse forwarding, lwIP external transport,
  or B1 full VPP forwarding.

Remaining acceptance work is therefore a replayable immutable IPv4/IPv6
TCP/UDP matrix for both ordinary UIDs, explicit reverse/concurrent tuples, a
dedicated allow/drop broker and socket-work ledger, and final zero-residue
contract capture. The
androidruntime Wi-Fi bypass must be corrected as a fixture before any of those
cells can be interpreted as architecture evidence.

## Decision

`A2_PIXEL_UID_POLICY_INSUFFICIENT`; `architecture_interruption=false`.

The raw evidence supports retaining the owner-inline/nonblocking/FlowOwner
baseline. No evidence crossed the registered architecture-interruption
condition. Plane was not updated and the ticket was not marked Done.
