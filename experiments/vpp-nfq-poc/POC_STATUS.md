# VPP/NFQUEUE POC Status

This is a throwaway checkpoint for the current fast POC lane. Detailed raw notes
remain in `EXPERIMENT_LOG.md`.

## Verified

| Area | Status | Evidence |
| --- | --- | --- |
| Android app traffic generator | App process can issue HTTP probes and log results. | Experiment 31 |
| Root mode package UID metadata | iptables owner + NFQUEUE + VPP sees real app UID 12540. | Experiments 32, 35, 39 |
| Root mode block by package UID | Real app TCP SYNs are dropped; app connect times out. | Experiments 32, 39 |
| Root mode allow by package UID | Real app HTTP succeeds and events carry `ruleId=allow-uid`. | Experiments 35, 38 |
| Package JSON helper | package name -> UID -> JSON -> VPP CLI works for allow/block. | Experiments 38, 39 |
| Root mode IPv6 static dst block | Real app IPv6 loopback and public IPv6 HTTP are blocked by exact dst rules. | Experiments 36, 43 |
| VPN data path | App traffic enters `VpnService -> packaged VPP -> HEV -> SOCKS5`. | Experiment 33 |
| VPN per-app include/exclude | `allowedPackage` / `disallowedPackage` controls app membership in VPN. | Experiment 40 |
| VPN packet owner UID lookup | Active `VpnService` native probe can parse IPv4/IPv6 TCP/UDP packet tuples and resolve them to the APK UID with `ConnectivityManager.getConnectionOwnerUid`. | Experiments 47, 49 |
| VPN static IPv4 dst block | `tun-poc block-ip4-dst` drops app traffic before HEV. | Experiment 41 |
| VPN IPv6 forwarding | `enableIpv6` adds IPv6 address/route and HEV forwards public IPv6. | Experiment 45 |
| VPN static IPv6 dst block | `tun-poc block-ip6-dst` drops app IPv6 traffic before HEV. | Experiment 46 |
| VPN no-block regression | Default `vpp-hev` forwarding still works after adding static block. | Experiment 42 |
| VPN teardown loop | 3 start/HTTP/stop cycles completed without HEV fatal pattern or VPP leak. | Experiment 37 |
| VPP TUN fd callback thread ownership | With `workers 2`, current `tun_poc` `clib_file` fd callbacks still run on VPP thread 0, not workers. | Experiment 54 |
| VPP TUN software handoff to worker | A `tun-poc-rx-handoff` input node can allocate a VPP buffer and enqueue it to `tun-poc-worker-probe` on worker thread 1. | Experiment 55 |
| VPP worker forward to shim fd | In `handoff-forward-fd` mode, worker thread 1 forwards handoff TUN packets to the shim fd and ping succeeds. | Experiment 56 |
| VPP worker IPv4 static dst drop | In `handoff-forward-fd` mode, worker thread 1 blocks IPv4 ICMP to `198.19.0.2` before shim and ping fails. | Experiment 57 |
| VPP worker IPv4 static dst miss | In `handoff-forward-fd` mode, an unmatched IPv4 dst rule does not overmatch and ping succeeds. | Experiment 58 |
| VPP worker IPv6 static dst drop | In `handoff-forward-fd` mode, worker thread 1 blocks IPv6 ICMP to `fd00:42::2` before shim and ping fails. | Experiment 59 |
| VPP worker IPv4 TCP/UDP tuple parse | Worker thread 1 parses IPv4 UDP and TCP src/dst addresses and ports after TUN handoff. | Experiment 60 |
| VPP worker IPv6 TCP/UDP tuple parse | Worker thread 1 parses IPv6 UDP and TCP src/dst addresses and ports after TUN handoff. | Experiment 61 |
| VPP worker mock tuple owner resolver | Worker thread 1 sends IPv4 UDP/TCP tuples to a resolver fd and records mock UID 4242. | Experiment 62 |
| VPP worker mock UID verdict | Worker thread 1 drops IPv4 UDP/TCP packets when the mock resolver returns blocked UID 4242. | Experiment 63 |
| VPP worker-to-worker redirect | Worker thread 1 can re-enqueue a VPP buffer to worker thread 2 through another frame queue; worker thread 2 forwards to shim and ping succeeds. | Experiment 64 |
| VPP redirected worker mock UID verdict | Worker thread 1 can re-enqueue IPv4 UDP/TCP packets to worker thread 2; worker thread 2 queries the mock resolver and drops by UID. | Experiment 65 |
| Android VPN VPP worker handoff | On Pixel 6a, app HTTP enters `VpnService -> packaged VPP handoff-forward-fd worker -> HEV -> SOCKS5`; VPP worker thread 1 handles the packet path. | Experiment 66 |
| Android VPN VPP worker-to-worker redirect | On Pixel 6a, VPP worker thread 1 re-enqueues app HTTP packets to worker thread 2, and worker thread 2 forwards through HEV/SOCKS. | Experiment 71 |
| Android VPN VPP worker IPv4 static drop | On Pixel 6a, `vpp-hev-handoff` drops app TCP SYNs to a blocked IPv4 dst inside VPP worker thread 1 before HEV/SOCKS. | Experiment 67 |
| Android VPN VPP owner resolver bridge | VPP worker queries a native Android resolver fd; native calls `ConnectivityManager.getConnectionOwnerUid` and returns the real package UID while HTTP still succeeds. | Experiment 68 |
| Android VPN VPP owner cache | VPP worker can cache a tuple owner UID, avoid repeated Android resolver queries on the same TCP tuple, and keep `last-uid` at the package UID on the allow path. | Experiment 78 |
| Android VPN VPP owner UID drop | VPP worker queries Android owner UID and drops real app TCP SYNs by package UID before HEV/SOCKS. | Experiment 69 |
| Android VPN VPP IPv6 owner UID drop | VPP worker parses IPv6 TCP, queries Android owner UID, and drops real app packets by package UID before HEV/SOCKS. | Experiment 73 |
| Android VPN VPP UDP owner UID drop | VPP worker queries Android owner UID for a UDP packet and drops by package UID. | Experiment 70 |
| Android VPN VPP IPv6 UDP owner UID drop | VPP worker queries Android owner UID for an IPv6 UDP packet and drops by package UID. | Experiment 74 |
| Android VPN redirected worker owner UID drop | On Pixel 6a, worker thread 1 re-enqueues app TCP packets to worker thread 2; worker thread 2 queries Android owner UID and drops by package UID. | Experiment 72 |
| Android VPN redirected worker IPv6 owner UID drop | On Pixel 6a, worker thread 2 drops redirected IPv6 TCP packets after querying Android owner UID. | Experiment 75 |
| Android VPN redirected worker UDP owner UID drop | On Pixel 6a, worker thread 2 drops redirected IPv4 UDP packets after querying Android owner UID. | Experiment 76 |
| Android VPN redirected worker IPv6 UDP owner UID drop | On Pixel 6a, worker thread 2 drops redirected IPv6 UDP packets after querying Android owner UID. | Experiment 77 |

## Demoted / Mis-scoped

These are useful Android-side facts, but they do not prove VPP-internal filtering:

| Area | Actual status | Evidence |
| --- | --- | --- |
| VPN owner UID gate before VPP/HEV | Mis-scoped: parent native code drops before VPP, so VPP is bypassed for the decision. | Experiments 48, 50, 51 |
| VPN owner flow cache fallback | Mis-scoped: cache lives in parent native gate, not VPP. | Experiment 52 |

## Current Design Implications

- Root mode is the verified low-friction path for package UID attribution.
- VPN mode can choose app membership with `VpnService.Builder`.
- VPN mode can recover IPv4/IPv6 TCP/UDP owners in the active `VpnService`
  process from packet tuples.
- VPN mode can still do static IP packet rules inside VPP.
- VPN mode VPP-internal UID filtering is proven on Android for IPv4/IPv6 and
  TCP/UDP send packets: Java/NDK only resolves tuple -> UID, while VPP keeps
  packet forwarding/verdict ownership.
- Current `tun_poc` fd adapter does not get worker distribution automatically;
  software steering/handoff must be explicit if we want worker processing.
- VPP frame-queue handoff is viable once the packet is represented as a VPP
  buffer and the enqueue happens from a VLIB node context.
- A worker node can re-enqueue an already handed-off VPP buffer to a different
  worker through another frame queue; this answers the "can VPP internally
  redirect after software steering" question for this POC shape.
- Tuple owner lookup and UID verdicts still work after a worker-to-worker
  redirect in both Docker mock resolver and Android real resolver paths.
- Android VPN mode can run the same `handoff-forward-fd` VPP worker path before
  HEV; this removes the Docker-only caveat for the basic worker handoff.
- Android VPP worker-to-worker redirect is verified on Pixel 6a for the HTTP
  allow path: thread 1 receives the handoff, thread 2 receives the redirected
  frame, and HEV/SOCKS still gets the TCP connection.
- Android worker handoff can enforce a static IPv4 dst drop before HEV; this
  keeps the verdict inside VPP instead of the parent native process.
- Android tuple->UID bridging works with VPP as the packet owner: Java/NDK only
  resolves UID over `resolver-fd`; VPP worker keeps packet forwarding/verdict.
- Android owner lookup can return the package UID for early TCP packets and `-1`
  for later packets on the same tuple. A minimal VPP-side tuple cache is now
  proven for one active tuple; production still needs real cache sizing,
  expiry, reverse-flow semantics, and concurrency rules.
- Android VPP-internal UID drop is now verified for IPv4 TCP: resolver provides
  UID, VPP worker applies `block-owner-uid`, and HEV/SOCKS sees no target
  connection.
- Android VPP-internal UID drop is also verified for IPv4 UDP send packets.
- Worker-side processing can forward back into the current shim/HEV style path,
  so worker verdicts can be tested without designing the final interface shape.
- The first useful product slice can be package UID allow/block in root mode,
  plus VPN app include/exclude, static IP block, and Android VPP owner UID
  filtering for IPv4/IPv6 TCP/UDP.

## Known Gaps

- The older VPN owner gate experiments remain mis-scoped. Experiments 48/50/51
  gate in the parent native process before `tun_poc`; use Experiments 68-70 for
  VPP-internal Android UID filtering evidence.
- The older owner cache experiment is mis-scoped. Experiment 52 caches in the
  parent native process; use Experiment 78 for VPP-internal cache evidence.
- VPP handoff worker-side static rules are verified for IPv4 drop, IPv4
  miss/allow, and IPv6 drop. IPv6 miss/allow can be added if needed, but the
  main IPv6 verdict path is no longer unknown.
- VPP worker-side IPv4/IPv6 TCP/UDP tuple parsing is verified for packets
  without IPv6 extension headers. Mock tuple->UID resolver integration is
  verified, and Android resolver bridging is verified for IPv4/IPv6 TCP/UDP.
  IPv6 extension headers remain separate.
- VPP worker can synchronously query a tuple owner resolver over an fd, cache a
  same-tuple owner UID, and enforce a UID drop verdict. Production cache design,
  async lookup, and performance remain separate POCs.
- Worker-to-worker re-handoff is verified for a short ICMP forward path, IPv4
  UDP/TCP mock UID drop, Android HTTP allow path through HEV, Android IPv4/IPv6
  TCP real UID drop after redirect, and Android IPv4 UDP real UID drop after
  redirect, and Android IPv6 UDP real UID drop after redirect. It does not yet
  prove a production sharding policy, packet ordering behavior, or performance.
- Android worker handoff is verified for IPv4 TCP/HTTP allow, static IPv4 dst
  drop, worker-to-worker redirect allow, Android resolver UID query, Android TCP
  UID drop, Android redirected IPv4/IPv6 TCP UID drop, Android redirected
  IPv4/IPv6 UDP UID drop, Android IPv6 TCP UID drop, Android UDP UID drop, and
  Android IPv6 UDP UID drop through HEV. A single-entry owner cache POC is
  verified; production cache policy remains separate.
- Domain/DNS rules are not validated; current rules use package UID or exact IP.
- Root mode dual IPv4+IPv6 still relies on the earlier workaround, not a clean
  multi-queue plugin design.
- No sustained performance or battery test has been run beyond idle/short loops.
- The Android app is still a POC shell, not a product UI or policy manager.
