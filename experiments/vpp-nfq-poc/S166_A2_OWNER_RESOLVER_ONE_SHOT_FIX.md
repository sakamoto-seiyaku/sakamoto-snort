# S166 A2 owner-resolver one-shot fixture correction

Date: 2026-08-24 (Asia/Taipei)
Device: Pixel 6a / Android 16 / `28201JEGR0XPAJ`

## Observation

The legacy `android-run-vpp-owner-resolver-udp-poc.sh` was run with its old
default `UDP_COUNT=1`.  The real UDP packet reached VPP and the exact tuple
was parsed:

```text
last-tuple ip4 proto 17 10.111.0.2:42664 -> 8.8.8.8:53
resolver query=1 proto=17 10.111.0.2:42664 -> 8.8.8.8:53 uid=-1
ledger event=POLICY_PENDING ... uid=-1 decision=PENDING resolver=uid
```

The VPP resolver and packet paths had zero parse/read/write/shim errors.  The
runner nevertheless exited non-zero because it required a non-negative UID
completion from the only packet.  This is the normal asynchronous first miss,
not evidence of a wrong UID or a new datapath failure.

## Correction

The runner default is now `UDP_COUNT=2`.  Both sends use the same connected
`DatagramSocket`, so the second packet can observe the asynchronous resolver
completion.  `UDP_COUNT=1` remains available when a raw pending/miss cell is
being tested intentionally.  Shell syntax and `git diff --check` pass.

The one-shot run is retained as raw pending evidence only; it is not a UID
PASS/FAIL verdict.  The corrected two-packet cell was then executed on the
same Pixel/WSL2 path with `PROBE_WAIT=12`.  The larger wait is required because
the app probe waits up to five seconds for each intentionally dropped echo;
the previous five-second runner default was a fixture timing defect, not a
VPP failure.

Evidence:
[`evidence/s166-a2-4-two-packet-uid-20260824/runner.log`](evidence/s166-a2-4-two-packet-uid-20260824/runner.log)

```text
ok bytes=48 packets=2 received=0 elapsedMs=10012
last-tuple ip4 proto 17 10.111.0.2:34492 -> 8.8.8.8:53
resolver enabled 1 fd 5 queries 3 hits 3 errors 0 last-uid 12628
resolver query=1 ... uid=-1
resolver query=2 ... uid=12628 ... decision=DROP
uid-block enabled 1 uid 12628 packets 2 bytes 100
ok: Android VPP owner resolver handled UDP UID verdict
```

This closes the bounded A2-4 registered UID resolver/drop cell.  It is not a
three-attempt hotspot: the only failed invocation was the now-corrected
runner wait window, and the valid rerun passed with resolver hits and two UID
block packets.

The HTTP loop runner also accepts `MODE=vpp-oi3`.  This keeps the canonical
S165 APK on its OI3/external-driver path; the legacy default `vpp-hev` still
requires the temporary `tun_poc` plugin and must not be used as a canonical
packaging check.

## Stop-rule decision

This was one fixture/verdict-boundary observation.  It is distinct from the
S164 external-ingress design hotspot, which already met the three-attempt stop
rule and was corrected by S165.  No new repeated runtime/design hotspot is
declared; do not blind-retry the one-shot form.

## Canonical OI3 single-owner TCP-tail correction

The first formal canonical OI3 HTTP run used the isolated package context and
returned HTTP 200, but its post-response log exposed a second, same-tuple
FIN/ACK tail after the successful generation had re-armed the TUN:

```text
oi3_cleanup result=PASS ... generation=1 ... direct=3 ... residue=0
oi3_cleanup result=FAIL ... generation=2 ... direct=0 ... residue=0
```

This was a real POC design gap in the single-owner re-arm boundary.  The
multi-owner dispatcher already held a TCP tombstone, while the single-owner
reader did not record the active tuple or reject non-SYN tail packets before a
new SYN.  The tail was therefore mistaken for a new application generation.

The correction is deliberately owner-local: record the canonical TCP tuple on
the first single-owner packet, retain it as a re-arm tombstone, reject
non-SYN packets while waiting for the next SYN, and clear the tombstone only
on that SYN.  The multi-owner path is unchanged.  The runner cleanup check was
also moved after the bounded stop wait and made field-order independent.

The ARM64 plugin was rebuilt from the clean VPP source/core pair:

```text
plugin_sha256=8e127fbb28fe9612e08d966cc19ba95eff273db030546bc4cb20e46dcff561a9
apk_contains_tun_poc=false
```

The same isolated Pixel/WSL2 cell then returned HTTP 200 with 135 bytes in
1410 ms.  Its native evidence contains
`oi3 single-admission result=REJECT reason=tcp-tail` followed by one
`oi3_cleanup result=PASS` (`generation=1`, `direct=3`, `broker=1/1`,
`residue=0`) and no `oi3_cleanup result=FAIL`.  The runner exited zero and
left no VPP/TUN residue.  Raw evidence is under
[`evidence/s166-oi3-tail-fix-20260824/`](evidence/s166-oi3-tail-fix-20260824/).

This records VPN-F041 as a corrected single-owner re-arm admission finding,
not a new three-attempt hotspot.  Ambient-flow isolation remains mandatory;
the matched E2 matrix is still open.
