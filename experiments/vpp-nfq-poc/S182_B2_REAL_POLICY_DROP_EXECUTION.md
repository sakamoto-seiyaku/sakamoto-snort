# S182 B2 real policy-drop execution

Date: 2026-08-25
Status: `PASS`

## Scope

S182 is a bounded B2 representative policy-drop slice on the full-device
AppA -> VpnService -> OI3 multi-owner route.  It proves that a selected target
IPv4 policy drop can stop a real AppA packet before owner admission,
FlowStackOwner creation, Android bind/protect brokerage, protected socket
transport, and fixture delivery.

It is not a per-App UID drop proof.  Android `addDisallowedApplication()` is
not used as evidence because that would route AppA outside the VPN rather than
exercise OI3 policy.

Artifact under test in the accepted run:

- VPN APK:
  `804a69734de9ceb2bc6f91c15fb8b09d3df8517b3bc7562c63a8379967b87a96`
- AppA APK:
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`
- OI3 plugin APK member:
  `b62d8a5fc3cda96dfe6bdd902ad9cb9ce1e5f86a646dbed4feed302fc194d933`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s182-b2-real-policy-drop.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s182_b2_real_policy_drop.py
```

The wrapper reuses the S181 full-device harness but sets:

```text
INCLUDE_POLICY_DROP=true
INCLUDE_NO_REPLY=false
INCLUDE_TCP_TIMEOUT=false
```

This keeps S182 scoped to one positive control plus the policy-drop cell and
prevents unrelated S181 timeout cleanup-marker behavior from deciding the S182
policy result.

## POC correction

The selected seam is pre-owner dispatcher policy:

- Java/VpnLite already accepts `blockIp4Dst`;
- native `vpn_fd_probe.c` passes that value into the VPP child as
  `SAKAMOTO_OI3_POLICY_DROP_IP4` only for `vpp-oi3-multi`;
- OI3 multi checks the raw IPv4 destination in `oi3_multi_tun_read_ready()`
  before tuple hashing, route lookup, owner admission or TUN queueing;
- a match logs
  `oi4 multi-policy-drop result=DROP stage=pre-owner ... no-transport=1
  broker=0 socket=0` and deliberately creates no owner cleanup generation.

The verifier therefore treats the session-level pre-owner DROP marker as the
native terminal evidence.  Requiring `oi3_cleanup` here would be the wrong
proof shape because no owner context should exist for a dropped packet.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s182-b2-real-policy-drop-20260825/
```

Run ID: `20260825-190147-303631`
Fixture host: `192.168.4.5`

Fixture ports:

- positive UDP DNS: `53541`
- policy-drop UDP observer: `53544`

Run-validity summary:

```text
status=PASS
scope=bounded_full_device_b2_transport_failure_exploration
claim_boundary=WSL2 LAN fixture real no-reply, TCP timeout and policy-drop exploration
cells_recorded=2
pass_count=2
design_gap_count=0
failure_count=0
non_claim=not per-App UID drop, not IPv6, not public internet, not long soak/performance
```

Cell summary:

| Cell | App proof | Fixture proof | Native proof | Residue | Verdict |
| --- | --- | --- | --- | --- | --- |
| `positive-udp-dns` | `udp_datagram_sent/dns_response_received` | UDP query and response on `53541` | broker/TUN/direct markers, `EXPECTED_DIRECT_REPLY` | no VPP, no `tun0` | PASS |
| `policy-drop-udp-dns` | `udp_datagram_sent/dns_response_timeout` | observer ready on `53544`, no `policy_drop_udp_query` | `stage=pre-owner`, `no-transport=1`, `broker=0`, `socket=0`, `policyDrop=1`, `brokerSuccess=0`, `tunOutput=0`, `directSend=0` | no VPP, no `tun0` | PASS |

The policy-drop CSV row recorded `appValid=1`, `fixtureValid=1`,
`nativeObserved=1`, `nativeExpected=1`, `transportFailures=0`,
`infrastructureFailures=0`, `residualVpp=` and `tun0After=0`.

## Invalid intermediate runs

Two invalid/failed intermediate runs are retained in the same evidence
directory for traceability:

- `20260825-184442-304529`: file changed while the runner was executing due to
  concurrent agent work; not target evidence.
- `20260825-185117-053427`: `am start` hit a WSL/ADB vsock transient
  (`UtilAcceptVsock accept4 failed 110`), so VPP never started in the first
  cell.
- `20260825-185642-439694`: policy-drop itself passed, but the wrapper still
  reran the unrelated S181 `closed-tcp-timeout` cell and failed on a missing
  native cleanup marker.  The wrapper was narrowed to positive + policy-drop
  only before the accepted run.

## Interpretation

S182 supports representative target-IP policy/drop separation on the selected
full-device OI3 multi path: the packet enters the VPN, is dropped before owner
transport, does not reach the WSL2 fixture, and leaves no process or TUN
residue.

S182 does not prove per-App UID policy drop, UID lifecycle/cache convergence,
deterministic RST/`ECONNREFUSED`, bind/protect failure, infrastructure failure,
IPv6, public Internet behavior, production policy authoring, performance,
Doze, or long soak.
