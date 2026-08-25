# S163 E1/E2 execution journal (2026-08-24)

Status: E1 supported for the registered bounded envelope; E2 remains
`INCONCLUSIVE` for the ADR-0007 comparison.  The S164 external-ingress gateway
design hotspot was corrected and regressed by S165; the HEV/LAN arm was
reopened for the remaining matched matrix, then paused after the fourth valid
S168 VPN-F042 owner-context teardown recurrence.  S169/S170 later closed that
pause for the bounded four-owner UDP envelope and post-F046 repeat/stop
resource window.  The two repeated loader failures in this run were artifact
provenance defects and were corrected before interpreting datapath results.

## Run identity and validity

- Device: Pixel 6a, Android 16, serial `28201JEGR0XPAJ`.
- Wi-Fi address: `192.168.4.151/24`; selected physical underlay handle was
  `510211837965` in the final smoke.
- VPN UID: `12628`; AppA UID: `12630`.
- Android 16 LAN preflight was already completed by S161: the stale
  `RESTRICT_LOCAL_NETWORK` override was disabled, `NEARBY_WIFI_DEVICES` was
  granted, and the device was rebooted.  A same-UID no-VPN control to the
  temporary WSL2 server `192.168.4.5:42083` returned in 24 ms.
- The temporary WSL2 HTTP server was stopped after the run.  Final device
  state has no `vpp`/HEV process and no `tun0` interface.

## Artifact provenance boundary

The canonical product VPP stage is clean source revision
`9258530f3804a152578ce11cc7c8a1e9eab88ed0`; its `vpp` SHA-256 is
`3235eb48ec4240cba9fd3100ec7d86c90481511518438c77c16723529b9907f5`.

The compatible OI3 plugin was rebuilt from that same clean source snapshot:

| Member | SHA-256 |
| --- | --- |
| `hev_external_driver_poc_plugin.so` | `1780433671e5acfa1217e9301b432ec7d56b5d9dabfe327816be89348de0f5d0` |
| owner-context `libhev-socks5-tunnel.so` | `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04` |
| temporary A2 `tun_poc_plugin.so` (paired regression only) | `fd3ceb866678f8eddd3517563ca921142d4caf45658d40d047cecd8de3539ad4` |

Two invalid combinations were observed and stopped at the loader boundary:

1. An OI3 plugin built from the dirty conditional-wake worktree required the
   absent symbol `vlib_frame_queue_wakeup_mode` when loaded by the clean product
   core.
2. The default HEV stage lacked `hev_socks5_owner_config_default`; the paired
   owner-context HEV stage above fixed that `dlsym` failure.

These are build/stage provenance failures, not datapath failures and not a new
architecture hotspot.  The corrected pair loaded, passed IPv4 DNS, and passed
the Direct HTTP smoke.  The final canonical APK was rebuilt without the
temporary `tun_poc` plugin:

- host APK SHA-256: `b90a86873e3e80f2c1bff705da0ff873cf6ebfab8321d7bd1dbc0a7599043724`;
- installed `base.apk` SHA-256: the same value;
- packaged members include the compatible OI3 plugin and owner-context HEV,
  and do not include `tun_poc`.

## E1 -- lifecycle/resource trend

The final clean unique-port window completed `40/40` samples with
`COUNT=40 BAD=0`; IPv4/IPv6 UDP/TCP public DNS responses were valid and source
ports were unique.  The bounded fault-injection cell returned
`PASS_EXPECTED_FAULT` with exact buffers and zero residue.  Wi-Fi epoch loss and
owner apply published the invalid epoch and both owners applied it.  Explicit
stop/start and fresh post-restart traffic passed; no `vpp` child or `tun0`
remained after cleanup.

Representative process snapshots during the final active session were:

| Process | RSS | Threads | Voluntary/nonvoluntary context switches |
| --- | ---: | ---: | ---: |
| VPP (`vpp_main`) | 132584 kB | 4 | 1440 / 7709 |
| VpnLite | 174048 kB | 34 | 283 / 180 |

The durable E1 evidence is in [`evidence/s163-e1-e2/`](evidence/s163-e1-e2/),
including `clean-results.tsv`, fault/restart/epoch results and the final
canonical VPP stdout/CLI logs.

## E2 -- performance and device state

### Corrected Direct path, controlled WSL2 endpoint

Three independent VPN start/probe/stop samples against
`192.168.4.5:42083/` returned HTTP 200 with 256 bytes:

| Sample | Latency |
| --- | ---: |
| 1 | 364 ms |
| 2 | 386 ms |
| 3 | 585 ms |

The bounded sample quantiles are `p50=386 ms`, `p95=585 ms`, `p99=585 ms`.
The canonical APK smoke then returned HTTP 404 for `/canonical` in 237 ms (the
server was intentionally a simple directory server; this still proves TCP,
HTTP response and TUN return).  Its native cleanup was `PASS`,
`handshake=1 direct=3 rewritten=3 buffers=480/480 residue=0`.

### Endpoint and HEV baseline boundaries

The public endpoint used by the existing HEV loop returned Direct samples of
865 ms and 845 ms, followed by one read timeout.  A 10-second repeated-HTTP
probe produced two `tcp-tail` admissions and no response samples.  Native
cleanup still reported `PASS` with zero transport/infrastructure failures, so
these values are not accepted as a Direct performance verdict; the endpoint
and repeated-flow shape are observation contamination, not a reproduced code
hotspot.

The existing HEV public baseline remains three successful cycles at 8/6/9 ms
with SOCKS connect counts 1/2/3.  Two attempts to use the controlled LAN
endpoint through HEV timed out at 5010 ms, while the same-UID no-VPN control
returned in 24 ms.  This establishes a HEV/LAN fixture compatibility boundary,
not a valid matched Direct-vs-HEV comparison.  The bounded S164 resumption then
proved that this is a design boundary in the owner-context external ingress:
the fd is read and the TCP SYN checksum passes, but the transparent gateway's
port-0 listener never matches the incoming destination port.  Three valid
post-fix attempts (external nonlocal acceptance, ANY-aware type matching, and a
bounded TCP-input trace) timed out without a TCP accept or HEV session.  The
attempts met the campaign stop rule and are recorded in
[`S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md`](S164_HEV_EXTERNAL_INGRESS_GATEWAY_WILDCARD_PORT_HOTSPOT.md);
no further retries were made within that failure series.

### S165 correction regression

S165 moved the wildcard behavior into an explicit external-ingress owner mode,
marked the UDP gateway listener by identity, and preserved the original UDP
destination metadata.  The first valid post-correction Pixel/WSL2 cycle then
returned HTTP 200:

```text
app-http-probe: ok bytes=40 elapsedMs=8 first=HTTP/1.0 200 OK
socks_connect_count=1
socks5 client tcp -> [192.168.4.5]:42083
cycle 1 ok
```

The compact evidence is in
[`S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md`](S165_HEV_EXTERNAL_INGRESS_CORRECTION_EXECUTION.md)
and `evidence/s165-hev-external-ingress/`.  This closes the S164 design
hotspot for controlled IPv4/TCP correctness; it does not close E2's matched
performance or IPv6/UDP/multi-owner gates.  The follow-up 50-cycle
owner-resolver run completed `50/50 PASS` with constant App/VPP/HEV fd counts
(`119/24/117`) and HEV RSS `62104..62324 KiB`; its raw CSV and resource summary
are under `evidence/s165-hev-external-ingress/`.

### Device state

- Screen-off Direct HTTP: success, 234 ms; display state was `Dozing`.
- Forced Doze Direct HTTP: success, 1352 ms; `deviceidle` reported `IDLE`.
- `cmd deviceidle unforce` restored `ACTIVE`; the display was restored before
  the final canonical smoke.

### A2 owner-resolver runner boundary (S166)

On 2026-08-24 the legacy owner-resolver UDP runner was exercised with its
former one-shot default.  The packet and exact VPP tuple were valid, but the
only resolver observation was the expected asynchronous `uid=-1` pending
miss; the runner incorrectly required a same-run non-negative completion and
therefore exited non-zero.  This is recorded as a fixture/verdict boundary,
not a UID or datapath failure.  The runner now defaults to two sends on the
same connected UDP socket, while `UDP_COUNT=1` remains an explicit raw-miss
mode.  See [S166_A2_OWNER_RESOLVER_ONE_SHOT_FIX.md](S166_A2_OWNER_RESOLVER_ONE_SHOT_FIX.md).

The corrected two-packet device cell then passed on the same WSL2 ADB path with
`PROBE_WAIT=12`: `ok bytes=48 packets=2 received=0`, resolver `queries=3
hits=3 errors=0 last-uid=12628`, two UID-block packets, and a zero-exit runner.
The wait increase is a runner fixture correction because each intentionally
dropped UDP packet can wait five seconds for an echo.  Raw evidence is in
[`evidence/s166-a2-4-two-packet-uid-20260824/`](evidence/s166-a2-4-two-packet-uid-20260824/).

### Canonical OI3 single-owner TCP-tail correction (S166)

The first formal isolated OI3 HTTP cell returned HTTP 200 and a successful
generation-1 cleanup, but a same-tuple FIN/ACK tail entered the re-armed
single-owner TUN as generation 2 and emitted `oi3_cleanup result=FAIL` with
zero residue.  Static inspection matched the symptom: the multi-owner
dispatcher had a TCP tombstone, while the single-owner reader did not retain
the active tuple or reject non-SYN tail packets.  This is recorded as VPN-F041,
a POC re-arm admission gap, not an ADB or endpoint failure.

The owner-local correction records the canonical TCP hash on the first packet,
rejects non-SYN packets while waiting for the next SYN, and clears the
tombstone only on that SYN.  The runner now checks cleanup after stop and does
not depend on field ordering.  The rebuilt ARM64 canonical plugin is
`8e127fbb28fe9612e08d966cc19ba95eff273db030546bc4cb20e46dcff561a9` and the
APK has no `tun_poc` member.

The bounded regression against WSL2 `192.168.4.5:42084` with
`allowedPackage=com.sakamoto.snort.vpnlite` returned HTTP 200 (135 bytes,
1410 ms), logged `single-admission ... reason=tcp-tail`, then one
`oi3_cleanup result=PASS` (`direct=3`, `broker=1/1`, `residue=0`) and no
cleanup `FAIL`; the runner exited zero.  Raw evidence is in
[`evidence/s166-oi3-tail-fix-20260824/`](evidence/s166-oi3-tail-fix-20260824/).

### IPv6 UDP UID allow/drop extension (S167)

The diagnostic owner-resolver path was extended to the real IPv6 UDP tuple
`[fd00:111:111::2]:<ephemeral> -> [2606:4700:4700::1111]:53`.  Both policy
directions passed with the corrected two-packet wait window: allow resolved the
package UID `12628` with `queries=3 hits=3 errors=0` and zero UID-block
packets; drop resolved the same UID and counted two blocked packets.  Both
cells preserved the exact IPv6 destination and left no VPP/TUN residue.  Raw
logs are in
[`evidence/s167-ipv6-udp-uid-20260824/`](evidence/s167-ipv6-udp-uid-20260824/).

Correctness and bounded resource checks pass for these cells.  E2's
comparative decision gate remains open because a matched HEV endpoint/traffic
arm, throughput, full IPv6 TCP/UDP, multi-owner load and repeated OS trend
sampling are not all present.  No architecture-level cliff can be claimed
either way.

### Multi-owner teardown heap-corruption correction (S168)

The first final-topology UDP pressure seam exposed a real non-HEV-worker stop
ordering defect.  The 4-flow cell and the minimized 2-flow cell both reached
the same Scudo `invalid chunk state`/`corrupted chunk header` SIGABRT while
one owner was still draining a HEV session.  Static inspection showed that
`flow_stack_owner_stop()` invalidated the lwIP owner pools immediately after
signalling `hev_socks5_tunnel_owner_stop()`, while OI3's later scheduler drain
could still run queued HEV work on the VPP worker thread.  This is recorded as
VPN-F042.

The first correction added a bounded, thread-local
`hev_task_system_driver_step()` drain on the non-HEV VPP worker path before
`lwip_owner_context_stop()`.  The follow-up correction expanded that drain to
64 calls of 1024 quanta, made OI3 propagate/retry `NOT_READY`, and guarded HEV
destroy against freeing a not-ready context.  The new HEV stage and OI3 plugin
were rebuilt and packaged as APK `0aa8c066…15afb1`.  The post-fix 2-flow
regression against WSL2 `192.168.4.5:42085`
completed with `fatalFlows=0`; both owners emitted two generations of
`oi3_cleanup result=PASS` with `broker=1/1`, `direct=1`, `buffers=10/10`,
`residue=0`, and zero transport/infrastructure failures.  That narrow cell
had no Scudo/SIGABRT and left no VPP/HEV process or `tun0`.

The next registered 4-flow final-topology cell, using the follow-up lifecycle
correction, still reached VPP pid `10355` and logged
`Scudo ERROR: invalid chunk state` at `0x200006d9ad4e340`, matching the
owner-1 lwIP context, followed by SIGABRT.  This is the fourth valid recurrence
of the same owner-context heap-lifetime boundary.  Per the campaign rule, the
pressure branch is paused and no further blind retry is allowed.  Evidence:
[`post-fix-summary.txt`](evidence/s168-multi-owner-udp-teardown-20260824/post-fix-summary.txt),
[`third-failure-summary.txt`](evidence/s168-multi-owner-udp-teardown-20260824/third-failure-summary.txt),
and [`fourth-failure-summary.txt`](evidence/s168-multi-owner-udp-teardown-20260824/fourth-failure-summary.txt).

VPN-F042 was `OPEN_RISK` at the end of S163/S168.  S169 later closed the UDP
lifecycle and four-owner capacity blockers for the registered four-flow UDP
closed-echo envelope, and S170 reran the bounded post-F046 repeat/stop resource
window with five clean four-owner cycles.  The original S163 2-flow PASS remains
a narrow historical regression observation; use S169/S170 for the current
four-owner artifact.

## Remaining work

1. Run the matched Direct/HEV bounded samples using the corrected S169/S170
   artifact;
   do not mix the diagnostic `tun_poc` member into the canonical result.
2. Complete the registered E2 measurements: throughput, CPU/work/wakes,
   context switches, FD/thread/RSS trend, thermal state, IPv4/IPv6 TCP/UDP/DNS,
   and the final-topology multi-owner load.
3. Add the strict-owner negative and UDP destination-preservation cells, then
   update the campaign/gap/ledger records and run the final evidence audit.

The artifact mismatch and public/LAN endpoint boundaries are recorded for
future preflight.  Under the campaign stop rule they do not justify another
blind retry; stop and escalate only if the same valid runtime/design failure is
reproduced three times.
