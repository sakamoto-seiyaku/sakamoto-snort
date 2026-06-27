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

## Demoted / Mis-scoped

These are useful Android-side facts, but they do not prove VPP-internal filtering:

| Area | Actual status | Evidence |
| --- | --- | --- |
| VPN owner UID gate before VPP/HEV | Mis-scoped: parent native code drops before VPP, so VPP is bypassed for the decision. | Experiments 48, 50, 51 |
| VPN owner flow cache fallback | Mis-scoped: cache lives in parent native gate, not VPP. | Experiment 52 |

## Current Design Implications

- Root mode is the verified path for per-packet UID attribution.
- VPN mode can choose app membership with `VpnService.Builder`.
- VPN mode can recover IPv4/IPv6 TCP/UDP owners in the active `VpnService`
  process from packet tuples.
- VPN mode can still do static IP packet rules inside VPP.
- VPN mode VPP-internal UID filtering is not proven. The next valid POC must keep
  packet verdicts inside a VPP plugin/node; Java/NDK may only resolve tuple -> UID.
- Current `tun_poc` fd adapter does not get worker distribution automatically;
  software steering/handoff must be explicit if we want worker processing.
- The first useful product slice can be package UID allow/block in root mode, plus
  VPN app include/exclude and static IP block POCs. VPN UID filtering is not in
  the verified slice until VPP-internal enforcement passes.

## Known Gaps

- VPN VPP-internal UID enforcement is not verified. Experiments 48/50/51 gate in
  the parent native process before `tun_poc`, not inside VPP.
- VPN VPP-internal owner cache is not verified. Experiment 52 caches in the
  parent native process.
- VPP software steering, handoff, and redirect behavior are not verified for the
  VPN/TUN plugin shape. Experiment 54 only proves current fd callbacks stay on
  thread 0.
- Domain/DNS rules are not validated; current rules use package UID or exact IP.
- Root mode dual IPv4+IPv6 still relies on the earlier workaround, not a clean
  multi-queue plugin design.
- No sustained performance or battery test has been run beyond idle/short loops.
- The Android app is still a POC shell, not a product UI or policy manager.
