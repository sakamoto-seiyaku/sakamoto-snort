# S183 B2 real per-App UID-drop execution

Date: 2026-08-25
Status: `PASS`

## Scope

S183 is a bounded B2 per-App UID-drop slice on the full-device
AppA -> VpnService -> native TUN gate -> OI3 multi-owner route.  It proves that
a real AppA UDP packet can be attributed to AppA UID and dropped before OI3
multi creates broker/socket transport.

This is a POC seam proof, not a production policy architecture claim.  The
drop is enforced at the native TUN gate before OI3 multi broker/socket
admission; it is not VPP-internal UID policy and it does not close production
capacity, lifecycle convergence, IPv6, public Internet, performance, Doze, or
long-soak claims.

Artifact under test in the accepted run:

- VPN APK:
  `a222fd3a82993903aa67f1f377b0787891556ee72036c682719597663c2fd12c`
- AppA APK:
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`
- OI3 plugin APK member:
  `b62d8a5fc3cda96dfe6bdd902ad9cb9ce1e5f86a646dbed4feed302fc194d933`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s183-b2-real-uid-drop.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s183_b2_real_uid_drop.py
```

The wrapper reuses the S181 full-device harness but sets:

```text
INCLUDE_UID_DROP=true
INCLUDE_POLICY_DROP=false
INCLUDE_NO_REPLY=false
INCLUDE_TCP_TIMEOUT=false
STAGE_PREFIX=S183
```

## Hotspot and correction

The first valid S183 run (`20260825-191707-411618`) failed in the target way:
the native gate was wired into `vpp-oi3-multi`, but the AppA UDP packet was
forwarded with `ownerUid=-1 cached=0`.  The fixture then received the packet on
the UID-drop observer port.

Root cause: `UidAttributionContract.lookup()` is sentinel-first.  The first
call submits bounded async Android owner lookup work and returns
`INVALID_UID`; the later completion becomes a scoped cache hit.  The old native
gate treated that first sentinel as terminal.

Correction:

- `vpp-oi3-multi + blockOwnerUid>=0` now uses the native TUN gate.
- Legacy HEV/shim startup remains limited to the old `vpp-hev-owner-gate`
  mode.
- The gate now calls `query_owner_uid_with_bounded_wait()` before applying UID
  policy, so the same canonical key can observe
  `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT`.
- The runner captures `uid-attribution-contract.jsonl` as first-class evidence.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s183-b2-real-uid-drop-20260825/
```

Run ID: `20260825-192207-202830`
Device: `28201JEGR0XPAJ`
Fixture host: `192.168.4.5`
AppA UID: `12630`

Run-validity summary:

```text
status=PASS
scope=bounded_full_device_b2_real_uid_drop
claim_boundary=WSL2-LAN-fixture-real-AppA-UID-drop-at-native-TUN-gate-before-OI3-multi-broker-socket
cells_recorded=2
pass_count=2
design_gap_count=0
failure_count=0
non_claim=not VPP-internal UID policy, not lifecycle/cache convergence closure, not IPv6, not public internet, not long soak/performance
```

Cell summary:

| Cell | App proof | Fixture proof | Native proof | Residue | Verdict |
| --- | --- | --- | --- | --- | --- |
| `positive-udp-dns` | `udp_datagram_sent/dns_response_received` | UDP query and response on `53541` | broker/TUN/direct markers, `EXPECTED_DIRECT_REPLY` | no VPP, no `tun0` | PASS |
| `uid-drop-udp-dns` | `udp_datagram_sent/dns_response_timeout`, AppA UID `12630` | observer ready on `53545`, no `uid_drop_udp_query` | UID contract completion/cache hit for UID `12630`; owner gate `DROP` with `lookup-attempts=2`; `gateDrop=2`, `gateForward=0`, broker/direct/tun output zero | no VPP, no `tun0` | PASS |

Key UID ledger:

```text
MISS_SUBMITTED key=ip4/UDP/10.111.0.2:58275-192.168.4.5:53545 uid=-1
COMPLETION_ACCEPTED key=ip4/UDP/10.111.0.2:58275-192.168.4.5:53545 uid=12630
CACHE_HIT key=ip4/UDP/10.111.0.2:58275-192.168.4.5:53545 uid=12630
```

Key native gate line:

```text
gate drop packet=7 len=57 proto=17 10.111.0.2:58275 -> 192.168.4.5:53545 ownerUid=12630 cached=0 lookup-attempts=2
```

## Invalid intermediate runs

- `20260825-191707-411618`: target hotspot reproduction.  The native gate was
  present but forwarded on `ownerUid=-1`; fixture received the UID-drop query.
- `20260825-192114-742258`: WSL/ADB vsock transient
  (`UtilAcceptVsock accept4 failed 110`); not target evidence.

## Interpretation

S183 closes the representative AppA UID-drop POC slice for the selected
full-device OI3 multi path.  It also records the design lesson: UID policy
must not treat the first Android owner-lookup sentinel as terminal; a policy
gate that consumes the current async contract needs a bounded completion/cache
barrier or a production replacement seam.
