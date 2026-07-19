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
| VPN app UID / no-su matrix | On Pixel 6a, APK, VPP, and HEV run as UID 12540 in `untrusted_app`; an ADB-shell-only harness passes IPv4/IPv6 TCP/UDP allow/drop without invoking `su`. | SAKAMOTO-2 |
| VPN upstream socket protect | HEV hands each SOCKS upstream fd to the app parent before connect; real `VpnService.protect(fd)` succeeds for 3 IPv4 and 3 IPv6 external-destination requests, while forced failure aborts before SOCKS accept. | SAKAMOTO-3 |
| VPN VPP/HEV 50-cycle lifecycle | Fixed APK/config on Pixel 6a completes 50 app-UID start/HTTP/protect/stop cycles with stable active fd counts, no RSS growth trend, and no stopped process, `tun0`, or route-rule residue. | SAKAMOTO-4 |
| VPN network failure/recovery | On Pixel 6a, proxy refusal, a paused SOCKS listener, and Wi-Fi off each fail without killing app/VPP; restarting proxy or Wi-Fi restores IPv4/IPv6 probes without reinstall or manual cleanup. | SAKAMOTO-5 |
| VPN screen-off idle/wake | With simulated battery unplug and a 600-second Doze window, app/VPP/HEV stay alive for 20/20 samples, CPU/RSS stay flat, and IPv4/IPv6 probes both recover after wake. | SAKAMOTO-6 |
| VPN sustained TCP/UDP risk baseline | Three 300-second TCP and three 300-second UDP rounds with simulated battery unplug and screen-off Doze keep app/VPP/HEV alive for 96/96 samples with zero app errors; TCP p95/p99 remains about 4.05/4.06 seconds, so resource stability is GO but background TCP release is HOLD. | SAKAMOTO-7 |
| Android packaged VAPI C ABI typed control | Ordinary app UID APK packages generated VAPI client libs plus the public C shim, connects to app-private VPP `socksvr`, reads typed status, sets/clears owner policy, and confirms each mutation in 5/5 rounds without `su`. | SAKAMOTO-8 |
| Android packaged Rust FFI typed control | Ordinary app UID APK packages a Rust staticlib behind JNI; Rust calls only the stable C ABI shim, performs typed status/set/clear against app-private VPP `socksvr`, and passes 5/5 rounds without `su`. | SAKAMOTO-9 |
| Android VPP abnormal child exit and stop/restart | App UID `SIGTERM` is issued without `su`; the long-lived monitor reaps the VPP child, removes stale runtime sockets, and the explicit stop/restart path starts a new VPP PID whose Rust typed control passes. | SAKAMOTO-10 |
| Android Rust persistent client reconnect | One Rust opaque client passes initial status, fails with `rc=-5` after VPP stop, tolerates disconnect `close_rc=-7`, and a fresh client passes status after VPP restart. | SAKAMOTO-11 |
| Android APK-native daemon packaging and RuntimeService HELLO gate | APK packages the staged `libsucre_snortd.so`; after an explicit KernelSU app grant, an ordinary APK Service launches it through root, validates `HELLO` ABI/build/capabilities, and stops with no root daemon residue. | SAKAMOTO-12 |
| Android RuntimeService process-death boundary | `am force-stop` removes the APK process but leaves the root daemon orphaned under PID 1; explicit root cleanup and a fresh RuntimeService launch recover. Automatic recovery/cleanup is HOLD. | SAKAMOTO-13 |
| Android daemon orphan containment after APK process death | On Pixel 6a, `am force-stop` reparenting is detected by the daemon's `getppid()` monitor; the daemon and abstract control socket exit without manual root cleanup, and a fresh RuntimeService recovers. NFQUEUE/iptables chains remain, so network-hook cleanup is HOLD. | SAKAMOTO-14 |
| Android NFQUEUE hook cleanup on daemon shutdown | On Pixel 6a, both normal RuntimeService stop and APK `am force-stop` detach/flush/delete the IPv4/IPv6 NFQUEUE hooks; no daemon, control socket, or `sucre-snort_*` chain remains, and a fresh RuntimeService recovers. | SAKAMOTO-15 |
| Android RuntimeService repeated lifecycle residue baseline | On Pixel 6a, five bounded normal start/stop cycles plus an APK force-stop/recovery pass keep exactly four dual-stack top-level jumps while running and leave no daemon, control socket, NFQUEUE rule, or private chain after each stop; pre-existing chains do not duplicate jumps. | SAKAMOTO-16 |
| Android daemon signal cleanup boundary | SIGTERM exits through the daemon destructor and removes the daemon, control socket, and NFQUEUE hooks; SIGKILL removes only the daemon/socket and leaves NFQUEUE hooks until explicit root cleanup. Fresh recovery passes after both boundaries. | SAKAMOTO-17 |
| Android RuntimeService foreground/background lifecycle smoke | On Pixel 6a, RuntimeService, control socket, and dual-stack NFQUEUE hooks survive a background transition and 5-second lock-screen interval; a local adb-reverse HTTP probe passes and controlled stop cleans all residue. No foreground-service state, notification, or `startForeground` call is present, so release foreground lifecycle remains HOLD. | SAKAMOTO-18 |
| Android RuntimeService short Doze differential | With simulated USB unplug and screen off, forced deep Doze is entered for 10 seconds; daemon, control socket, and dual-stack NFQUEUE hooks remain present, and pre/post-Doze local HTTP probes pass after wake. Controlled stop cleans all residue. | SAKAMOTO-19 |
| Android APK upgrade/rollback hook residue boundary | On Pixel 6a, upgrading from versionCode 1 to 2 and rolling back from 2 to 1 while RuntimeService is active both remove the old daemon, control socket, and NFQUEUE hooks automatically; each version starts with exactly four top-level jumps and stops cleanly. | SAKAMOTO-20 |
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
| VPP binary API status surface | `tun_poc` exposes a generated `tun_poc_status` binary API; Python PAPI calls it over `socksvr` and receives typed status/counters without parsing CLI output. | Experiment 80 |
| VPP binary API owner policy mutation | Python PAPI sets `owner_cache_enabled` and `block_owner_uid=4242` through `tun_poc_owner_policy_set`; typed status confirms the mutation. | Experiment 81 |
| VPP binary API owner policy transaction | Python PAPI stages owner-policy knobs, confirms active status is unchanged, rolls back, stages again, commits, and confirms active status changes only after commit. | Experiment 89 |
| VAPI C client status call | A small C client consumes generated `tun_poc.api.vapi.h`, connects to VPP `socksvr`, and calls `vapi_tun_poc_status`. | Experiment 82 |
| Rust FFI C-shim status call | Rust calls a thin C ABI shim with `repr(C)` status output; the shim hides generated VAPI types and calls `tun_poc_status` through VPP `socksvr`. | Experiment 83 |
| Rust FFI C-shim owner policy mutation | Rust calls the same C ABI shim to set `owner_cache_enabled` and `block_owner_uid=4242`; a follow-up status read confirms the mutation. | Experiment 84 |
| Rust shim staged SDK smoke | A local SDK staging directory can hold the public shim header, static shim lib, and VPP client runtime libs; Rust links/runs from it when the launcher sets `LD_LIBRARY_PATH` to the staged lib dir. | Experiment 85 |
| Rust FFI persistent C-shim client | Rust opens one opaque C-shim client handle and reuses one VAPI connection for status, owner-policy set, status, owner-policy clear, and status. | Experiment 86 |
| Rust FFI C-shim reconnect boundary | After VPP stops, a stale persistent handle returns an error instead of false success; after VPP restarts, a fresh handle can open and read status on the same `socksvr` path. | Experiment 87 |
| Rust FFI serialized threaded access | Four Rust threads share one persistent C-shim client behind a `Mutex` and complete 20 serialized status calls against VPP `socksvr`. | Experiment 88 |
| Android VPN VPP owner cache | VPP worker can cache a tuple owner UID, avoid repeated Android resolver queries on the same TCP tuple, and keep `last-uid` at the package UID on the allow path. | Experiment 78 |
| Android VPN VPP owner-cache UDP burst | App can send a 20-packet UDP burst through VPP; VPP owner-cache reduces resolver queries to one and drops all 20 packets by UID. | Experiment 79 |
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
- The Android root handoff now has a proven process-containment and hook-cleanup
  POC: after APK death, the daemon detects reparenting to PID 1, exits, and its
  shutdown destructor removes the dual-stack NFQUEUE/iptables hooks before a
  fresh RuntimeService recovery.
- The same handoff is repeatable for five short normal lifecycle cycles: an
  already-present dual-stack chain/jump state is normalized to exactly one
  INPUT and one OUTPUT jump per family, and each stop returns the device to the
  no-daemon/no-hook baseline.
- Graceful daemon termination is cleanup-safe, but SIGKILL cannot run the
  destructor: NFQUEUE hooks remain after the process and control socket exit.
  A release handoff therefore needs an explicit supervisor or root cleanup
  boundary rather than relying on daemon destruction alone.
- The current RuntimeService survives a short HOME plus lock-screen interval
  with daemon/socket/hooks intact and passes a local data-plane probe, but its
  service dump reports `startForegroundCount:0` and no app notification is
  observed. It is therefore a lifecycle smoke baseline, not a release-safe
  background service.
- A forced 10-second deep Doze window on the same Pixel 6a preserves the
  RuntimeService daemon, control socket, and dual-stack hooks; local HTTP
  probes pass both before Doze and after wake. This is a short retention
  result, not a battery or long-suspension guarantee.
- APK package replacement is currently clean across a short upgrade and
  rollback: the active old/new RuntimeService process is removed, its daemon
  exits, and the dual-stack hooks/socket disappear before the replacement
  version starts. Both version transitions normalize to four top-level jumps.
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
- The first non-CLI VPP control surface is proven at status-read scope:
  `tun_poc_status` is generated through VPP API tooling and callable through
  Python PAPI over `socksvr`. This supports keeping CLI as dev/debug only while
  future Tauri/Rust control targets VPP binary API/VAPI.
- The same binary API path can mutate POC owner policy knobs:
  `tun_poc_owner_policy_set` sets owner-cache and block-owner-UID state, and
  `tun_poc_status` confirms the update without CLI output parsing.
- Android can now package that typed VAPI path inside the ordinary app UID:
  JNI calls the stable-shaped C shim, the shim calls generated VAPI, and VPP
  remains the policy owner behind an app-private `socksvr` socket. SAKAMOTO-9
  also proves an Android Rust staticlib can call the same shim without exposing
  generated VAPI types to Rust; the APK still has no real Tauri command surface.
- Android VPP child lifecycle now has a tested abnormal-exit boundary: the
  app-UID monitor reaps a killed VPP child, removes `api.sock`, `cli.sock`, and
  `statseg.sock`, and leaves explicit stop/restart to the service lifecycle.
  A fresh VPP PID and fresh Rust typed control session pass after restart.
- Android Rust control now has a persistent-handle reconnect boundary: a stale
  client returns an error after VPP stop, its close may also report the expected
  disconnect error, and a fresh opaque client can status successfully after a
  new VPP PID is ready.
- The VPP binary API can also stage, rollback, and commit owner-policy knobs:
  staged policy does not affect active status, rollback discards it, and commit
  is the step that changes active state.
- Generated VAPI C headers are usable from a small external C client for the
  status path. This is the immediate substrate for a thin C ABI shim callable
  from Rust/Tauri.
- Rust can call that thin C ABI shape and receive typed status without exposing
  generated VAPI types to the Rust side. The recommended product path remains
  `Tauri/Rust -> C ABI shim -> VAPI -> VPP binary API`.
- The same Rust-facing C ABI shape can also mutate POC owner policy and verify
  it through typed status, so the minimal control-plane read/write loop is
  proven without CLI parsing.
- The Rust shim can be staged into a local Linux SDK with public header,
  static shim lib, and VPP client runtime libs. On this host, copied VPP libs
  retain build-tree RUNPATH, so the smoke uses launcher-managed
  `LD_LIBRARY_PATH=<sdk>/lib`; final packaging needs rpath rewrite or an
  equivalent loader plan.
- The Rust-facing C ABI can expose an opaque persistent client handle, and Rust
  can reuse one VAPI connection across multiple status/mutation calls. This
  supports a stateful Tauri control layer without forcing per-command reconnects.
- A stale persistent handle returns an error after VPP stops, and a fresh handle
  can open/status after VPP restarts on the same `socksvr` path. Reconnect can
  live above the shim handle boundary, but stale-handle errors must be treated
  as connection-loss signals.
- Multiple Rust threads can share one persistent C-shim client behind a mutex
  and serialize calls. This gives Tauri a conservative state-object model
  without claiming VAPI context calls are safe concurrently.
- Android owner lookup can return the package UID for early TCP packets and `-1`
  for later packets on the same tuple. A minimal VPP-side tuple cache is now
  proven for one active tuple; production still needs real cache sizing,
  expiry, reverse-flow semantics, and concurrency rules.
- HEV upstream protection is viable across the current fork boundary. The child
  retains the original socket, sends a duplicate through `SCM_RIGHTS`, and waits
  for the app parent to call Java `VpnService.protect` before bind/connect.
- Recreating the app, VPP, and HEV processes on each stop/start is stable over a
  50-cycle short-flow run. Active fd counts remain exactly 120/24/121 for the
  app/VPP/HEV processes, and stopped route rules return to the baseline each time.
- A short 20-packet UDP owner-cache burst works on Pixel 6a: VPP parses and
  drops all 20 packets while resolver queries stay at one. This is not a
  sustained throughput or battery result.
- SAKAMOTO-7 establishes a 30-minute-class sustained-load baseline with
  simulated battery unplug. App/VPP/HEV stayed alive and RSS/temperature were
  stable, but screen-off Doze TCP latency was consistently about four seconds.
  Treat this as a release blocker until a screen-on versus background-service
  comparison separates Android scheduling from the VPP/HEV path.
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
- SAKAMOTO-7 is a controlled path-risk baseline, not a product throughput or
  battery certification: the TCP endpoint is a device-local mock SOCKS server
  that returns fixed HTTP 200, and UDP has no end-to-end UDP ASSOCIATE relay.
  Public relay throughput, packet drops at the network boundary, and power
  attribution to the individual app/VPP/HEV processes remain open.
- The app UID / no-su matrix ran on a Pixel 6a whose bootloader is unlocked and
  whose verified boot state is orange. It proves runtime identity, not the
  separate release check on a never-rooted, bootloader-locked device.
- The protect POC uses a synchronous one-request-at-a-time fd broker, discovers a
  fixed `wlan0` IPv4 address for its device-local SOCKS endpoint, and uses a mock
  SOCKS server that returns HTTP 200 instead of relaying payloads to the public
  destination. It proves the protect boundary and non-recursion, not production
  broker concurrency or full public SOCKS relay behavior.
- The 50-cycle lifecycle POC uses one short IPv4 HTTP probe per cycle. It does
  not cover long-lived flows, parallel traffic, network handover, process death,
  device sleep, or teardown after sustained operation. Its first formal attempt
  also exposed a harness-only 32-accept SOCKS server limit; the valid 50-cycle
  result was rerun from scratch after removing that limit.
- The network recovery POC proves proxy refusal, a short listener blackhole, and
  the controlled Wi-Fi off/on transition on one Pixel 6a. The device did not
  expose a second independently controllable upstream network, so cellular,
  USB-tether, and cross-network handover remain unverified.
- The idle/wake POC uses `dumpsys battery unplug` because USB charging otherwise
  contaminates Doze observations. It proves one 600-second Pixel 6a window and
  wake recovery, with device-level batterystats as an equivalent wakeup signal;
  it is not a long-term battery certification or physical cable-removal result.
- The Android app is still a POC shell, not a product UI or policy manager.
- The binary API POC covers status, direct owner-policy mutation, a minimal
  owner-policy transaction, and Android packaging of the C ABI path. It does
  not yet cover fd handoff, compiled policy blobs, snapshot epoch/generation,
  or a Tauri command surface.
- The VAPI C client POC is a smoke client only. It does not define the stable C
  ABI that Rust should call, and it still consumes generated headers from the
  local VPP build tree.
- The Rust FFI status/mutation POCs now include Android packaging through SAKAMOTO-9.
  They still do not define async/reconnect behavior or a real Tauri command surface.
- The Rust FFI owner-policy mutation POC still mutates direct POC knobs only. It
  does not define the final compiled policy schema, epoch model, transaction
  semantics, or connection lifetime strategy.
- The reusable staged SDK layout is still local Linux only. Android SAKAMOTO-8
  and SAKAMOTO-9 prove packaged C and Rust smoke paths, but do not produce a
  versioned SDK, patch VPP shared-library RUNPATH to `$ORIGIN`, or prove Tauri
  bundling.
- The persistent shim client POC is single-threaded. It does not define Rust
  `Send`/`Sync`, reconnect after VPP restart, cancellation, async command
  queues, or concurrent access rules.
- The reconnect boundary POC does not implement automatic reconnect, backoff,
  health polling, in-flight command recovery, or command replay semantics.
- The serialized threaded access POC does not prove concurrent calls on one
  VAPI context, mutation interleaving, async scheduling, cancellation, or
  poisoning recovery.
- APK-native daemon packaging and the minimal RuntimeService root handoff are
  proven on one Pixel 6a: `nativeLibraryDir` contains the staged ELF, and the
  service gates startup on `HELLO` metadata before reporting success. The app
  requires an explicit KernelSU Superuser grant; its mount namespace cannot use
  `/system/bin/su` before that grant.
- RuntimeService stop tracks the daemon PID and terminates it through a root
  shell. Killing only the Java `Process` wrapper is insufficient after `su`
  executes the daemon. Automatic service/process restart, foreground-service
  policy, release signing, upgrade/rollback, and tombstone collection remain
  unverified.
- SAKAMOTO-13 established the original APK process-death failure: `am force-stop`
  left `libsucre_snortd.so` alive as a root child of PID 1.
- SAKAMOTO-14 proves daemon/socket containment with a `getppid()` monitor after
  the Android `PR_SET_PDEATHSIG` path failed to fire reliably in this launch
  chain. SAKAMOTO-15 adds idempotent dual-stack hook detach/flush/delete during
  daemon shutdown and verifies it after both normal stop and APK force-stop on
  one Pixel 6a; the formal snapshots are the authority when an individual
  iptables command reports an already-missing object.
- SAKAMOTO-15 does not cover partial hook installation, permission denial,
  duplicate rules beyond the tested idempotent path, foreground-service policy,
  release signing, upgrade/rollback, or tombstone collection.
- SAKAMOTO-16 does not cover long-run endurance, foreground-service behavior,
  Doze latency, APK upgrade/rollback, or SIGKILL cleanup; the force-stop path
  still uses the previously proven parent monitor.
- SAKAMOTO-17 covers one Pixel 6a and confirms the SIGTERM/SIGKILL boundary,
  but does not provide an automatic supervisor, crash backoff, concurrent kill
  handling, or permission-denial matrix. The SIGKILL cleanup path remains HOLD.
- SAKAMOTO-18 covers only a short background and 5-second lock-screen window;
  it does not validate Doze policy, long suspension, reboot, OEM process
  eviction, notification-channel behavior after upgrade, or a real foreground
  service implementation. The current foreground-service requirement remains
  HOLD.
- SAKAMOTO-19 covers one forced 10-second deep Doze interval on one Pixel 6a;
  it does not cover natural Doze entry, maintenance windows, long idle,
  network handover, reboot, OEM eviction, or battery attribution. Foreground
  service policy remains the SAKAMOTO-18 HOLD.
- SAKAMOTO-20 covers only debug APKs signed by the same local key, versionCode
  1/2, one Pixel 6a, and one active-process upgrade plus rollback pair. It does
  not cover release signing/key rotation, schema-incompatible daemon changes,
  interrupted installs, staged rollout, data migration, or crash/tombstone
  collection.
- SAKAMOTO-10 validates one app-UID `SIGTERM` child-death path and explicit
  stop/restart on one Pixel 6a. It does not yet cover process crash signals,
  Android service/process death, automatic VPP restart policy, or concurrent
  stop versus child-exit races.
- SAKAMOTO-11 validates one persistent Rust handle and one fresh-handle
  reconnect on one Pixel 6a. It does not define automatic backoff, health
  polling, in-flight command recovery, command replay, or concurrent reconnect
  ownership.
