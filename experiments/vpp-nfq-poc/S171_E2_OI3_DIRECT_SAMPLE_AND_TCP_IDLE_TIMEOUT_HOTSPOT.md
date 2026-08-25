# S171 E2 OI3 Direct Sample and TCP Idle-timeout Hotspot

Date: 2026-08-25
Environment: Pixel 6a Android 16 + WSL2 LAN fixture `192.168.4.5`, app
`com.sakamoto.snort.vpnlite`

## Question

Can the corrected four-owner OI3 final topology carry the same bounded app-side
L4 stress cells as the VPN-stopped Direct control against the same WSL2 LAN
fixture, without owner-busy rejects, cleanup failures, stale process/TUN
residue, or TCP tail loss?

S171 is a bounded E2 sample. It is not the full E2 comparative performance and
device-state verdict: matched HEV SOCKS baseline, broader IPv4/IPv6 TCP/UDP/DNS,
screen-off/Doze, thermal and copy-investment conclusions remain separate gates.

## Artifact pitfall closed before the valid runs

Two invalid diagnostic runs were caused by stale build inputs, not datapath
behavior:

- `evidence/s171-e2-oi3-direct-sample-20260825-postfix-min/` packaged a stale
  plugin that did not understand `target-thread-c/d`; OI3 startup rejected the
  generated four-owner command with `unknown OI4 multi input`.
- `evidence/s171-e2-oi3-direct-sample-20260825-postfix-artifact/` used the
  corrected plugin but stale HEV stage; UDP then failed because the APK did not
  carry the UDP persistent connector fix.

The valid runs below use a single rebuilt closure:

- APK `3ba6f24260e2e2dc417e3f150f04ad7a67e6458c26e630e369e623e0dc8f14e4`
- OI3 plugin `6a0fdd9f915be2127ef5cd5423514db836def0ffebd51239178644c8d6a4f643`
- HEV owner-context library
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

## Hotspot reproduction

The first corrected-artifact full sample
`evidence/s171-e2-oi3-direct-sample-20260825-postfix-hev/` passed Direct UDP,
OI3 UDP and Direct TCP, but failed OI3 TCP 1400B:

- OI3 TCP run `34068893509792`
- app `sent=186 received=185 errors=1 fatalFlows=1`
- failure `SocketTimeoutException:Read_timed_out`
- cleanup `5/0`, `ownerBusy=0`, `multiRejectNonTail=0`, `tcpTailReject=7`

The failure was then minimized:

- `evidence/s171-e2-oi3-direct-sample-20260825-tcp-diff/` showed
  `tcp:1:64 steady=3` and `tcp:1:1400 steady=3` both passing in OI3. This ruled
  out an unconditional 1400B payload failure.
- `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-repeat/` reproduced
  the failure at `tcp:1:1400 steady=6`: Direct passed 3/3; OI3 failed 3/3 with
  `sent=N received=N-1`, cleanup `5/0`, `ownerBusy=0`, and only `tcp-tail`
  rejects.
- `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-timeout15s/` kept
  the same failure with `tcpReadTimeoutMs=15000`, so the root cause was not a
  too-short app read timeout.

## Root cause

`OI3_TUN_FLOW_TIMEOUT_NS` was implemented as an absolute five-second lifetime
for multi-owner TCP generations. Active TCP ingress/output did not refresh
`tun_flow_deadline_ns`. Therefore a steady TCP connection crossing the five
second mark could be cleaned up and re-armed while the Java socket still held
the same tuple. The re-arm installed the completed tuple tombstone, and
subsequent same-tuple non-SYN packets were rejected as `reason=tcp-tail`.

This explains the observed boundary:

- `steady=3` passes because it finishes before the five-second generation cap.
- `steady=6` fails consistently because the active TCP stream crosses the cap.
- Increasing Java `tcpReadTimeoutMs` to 15 seconds does not help because native
  cleanup/tombstone already happened.

## Correction

`owner_inline_oi3.c` now treats the TUN flow timeout as an idle timeout for
multi-owner TCP:

- new `oi3_refresh_tun_flow_deadline()` helper;
- TCP and UDP TUN submits refresh the deadline;
- TCP SYN-ACK/data output refreshes the deadline;
- FIN or RST marks the TCP generation terminal.

Static coverage is in
`scripts/tests/test_verify_s171_e2_oi3_direct_sample.py`:

- `test_oi3_multi_tcp_deadline_is_refreshed_by_activity`
- plus runner coverage for explicit OI3 cleanup and tcp-tail accounting.

## Post-correction evidence

Targeted regression:

- `evidence/s171-e2-oi3-direct-sample-20260825-tcp-steady6-after-fix/`
- cells `tcp:1:1400:1:closed`, `steadySeconds=6`, `repeats=3`
- Direct passed 3/3
- OI3 passed 3/3:
  - run `70923827954308`: `sent=357 received=357`, `tcpTailReject=0`
  - run `84436075470179`: `sent=370 received=370`, `tcpTailReject=0`
  - run `80734001190065`: `sent=371 received=371`, `tcpTailReject=0`
- manifest `run-20260825-122412-384385-manifest.json`, `failureCount=0`

Full S171 bounded sample:

- `evidence/s171-e2-oi3-direct-sample-20260825-after-fix-full/`
- cells `udp:1:64:1:closed udp:4:1400:1:closed tcp:1:1400:1:closed`
- `steadySeconds=10`, `tcpReadTimeoutMs=5000`
- Direct and OI3 all passed, `failureCount=0`
- OI3 TCP run `52350053089758`: `sent=612 received=612`,
  `ownerBusy=0`, `tcpTailReject=0`, `multiRejectNonTail=0`
- fixture counters were symmetric: UDP `15471/15471`, TCP `2144/2144`

## Result and non-claims

S171 closes the bounded direct-vs-final-topology sample for the tested cells and
closes the TCP idle-timeout/tombstone hotspot as VPN-F047. The final Android VPN
Engineering Feasibility claim remains open for matched HEV baseline comparison,
broader protocol/address-family coverage, screen-off/Doze, thermal/device-state
and final audit evidence.
