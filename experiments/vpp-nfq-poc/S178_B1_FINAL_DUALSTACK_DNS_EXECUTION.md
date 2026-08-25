# S178 B1 final-artifact dual-stack DNS execution and cleanup-marker hotspot

Date: 2026-08-25
Status: `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS`

## Scope

S178 reran the B1 whole-device DNS matrix on the current S176/S177 final
artifact.  The purpose was to confirm that the selected owner-inline
full-device VPN path still carries IPv4/IPv6 UDP/TCP DNS after the later E2/E1
corrections, and to separate dataplane proof from lifecycle cleanup-marker
timing.

Artifact under test:

- VPN APK:
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
- AppA traffic-adapter APK:
  `c6d0e744c4c506b26dfd635f2798a11382aff2969bce9fc5d2f6a137f9154731`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s178-b1-final-dualstack-dns.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s178_b1_final_dualstack_dns.py
```

## Hotspot and POC design adjustment

The repeated hotspot was in the B1 runner/verdict design, not in the observed
VPN dataplane.  Three concrete harness issues had to be separated before the
POC result was meaningful:

1. `tun0` residue detection initially trusted the `su ip link show tun0` exit
   code.  On this device that command can return `0` with empty output, so the
   runner falsely marked residue.  The runner now records the command output
   and only treats text containing `tun0:` as a residual interface.
2. The runner force-stopped the app/VPN too soon after the AppA DNS response,
   which could miss late `oi3_cleanup result=` markers even when native
   direct/broker/TUN-return evidence and post-run residue checks were clean.
   The runner now allows a bounded native settle window and tails regular log
   files for cleanup markers.
3. Repeated TCP reruns reused fixed source ports and hit local
   `Address not available` failures from source tuple reuse/TIME_WAIT.  The
   default source-port base is now dynamic while remaining overrideable.

The final design splits the verdicts:

- `PASS` requires AppA DNS success, native direct/broker/TUN-output markers,
  zero post-run residue, and a cleanup marker.
- `PASS_DATAPLANE_CLEANUP_MARKER_MISSING` requires AppA DNS success, native
  direct/broker/TUN-output markers, and zero post-run residue, but reports that
  the lifecycle cleanup marker was not observed.
- A run with no failed cells and only cleanup-marker gaps is reported as
  `PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS`.

This prevents the POC from treating a missing lifecycle marker as proof that
the IPv4/IPv6 DNS dataplane failed.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s178-b1-final-dualstack-dns-20260825/
```

Run ID: `20260825-170934-541913`
Source port base: `60740`

Manifest summary:

```text
status=PASS_DATAPLANE_WITH_CLEANUP_MARKER_GAPS
cellsRecorded=6
passCount=3
cleanupMarkerGapCount=3
failureCount=0
appValidCount=6
nativeValidCount=6
```

Cell summary:

| Cell | Family | Protocol/write | Source port | Destination | Response | Cleanup P/F | Residue | Verdict |
| --- | --- | --- | ---: | --- | --- | ---: | --- | --- |
| ip4-udp-dns | IPv4 | UDP | 60741 | `1.1.1.1:53` | 61-byte DNS | 2/0 | no VPP, no `tun0` | `PASS` |
| ip4-tcp-dns-separate | IPv4 | TCP separate | 60742 | `1.1.1.1:53` | 61-byte DNS | 0/0 | no VPP, no `tun0` | `PASS_DATAPLANE_CLEANUP_MARKER_MISSING` |
| ip4-tcp-dns-coalesced | IPv4 | TCP coalesced | 60743 | `1.1.1.1:53` | 61-byte DNS | 0/0 | no VPP, no `tun0` | `PASS_DATAPLANE_CLEANUP_MARKER_MISSING` |
| ip6-udp-dns | IPv6 | UDP | 60744 | `[2606:4700:4700::1111]:53` | 61-byte DNS | 2/0 | no VPP, no `tun0` | `PASS` |
| ip6-tcp-dns-separate | IPv6 | TCP separate | 60745 | `[2606:4700:4700::1111]:53` | 61-byte DNS | 0/0 | no VPP, no `tun0` | `PASS_DATAPLANE_CLEANUP_MARKER_MISSING` |
| ip6-tcp-dns-coalesced | IPv6 | TCP coalesced | 60746 | `[2606:4700:4700::1111]:53` | 61-byte DNS | 1/0 | no VPP, no `tun0` | `PASS` |

All six cells recorded:

- AppA bind/send/return success and valid DNS response.
- Native direct-send/direct-recv, broker completion, selected underlay,
  rewritten/TUN-output markers.
- `rulesMatch=1`, `appValid=1`, `nativeValid=1`, and `valid=1`.
- Empty post-run `pidof vpp` and no root-visible `tun0`.

Direct preflight is explicitly not claimed for this current AppA B1 helper:
the helper requires an active VPN Network, so `vpn_unavailable` outside an
active VPN session is not endpoint evidence.

## Interpretation

S178 supports the current final artifact for B1 dual-stack DNS dataplane:
IPv4/IPv6 UDP DNS, IPv4/IPv6 TCP DNS, and separate/coalesced TCP application
writes all completed with valid DNS responses through the full-device
owner-inline route.

S178 does not close lifecycle cleanup timing for the three TCP rows whose
dataplane evidence is valid but whose cleanup marker was not observed.  It also
does not claim large DNS response fallback, arbitrary external traffic,
throughput, CPU/thermal/power, Doze, long soak, or the final E2/E1 campaign
verdict.
