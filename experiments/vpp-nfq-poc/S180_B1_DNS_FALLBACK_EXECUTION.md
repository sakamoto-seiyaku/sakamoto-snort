# S180 B1 DNS UDP-to-TCP fallback execution

Date: 2026-08-25
Status: `PASS`

## Scope

S180 closes the B1 forced DNS fallback design gap for one bounded IPv4 fixture
cell.  The cell uses a WSL2/LAN DNS fixture that returns a truncated UDP DNS
response (`TC=1`) and then returns a valid full DNS response over TCP for the
same query ID.  AppA must perform the TCP retry inside one B1 operation; two
independent UDP/TCP requests are not accepted as fallback evidence.

Artifact under test:

- VPN APK:
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
- AppA fallback APK:
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`
- OI3 plugin:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s180-b1-dns-fallback.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s180_b1_dns_fallback.py
```

## POC design correction

The pre-S180 AppA B1 helper could send either UDP DNS or TCP DNS, but it had no
resolver fallback state machine.  That meant independent S178-style UDP and TCP
cells could prove both protocols, but could not prove forced UDP-to-TCP
fallback.

S180 adds an explicit POC-only seam:

- `b1FallbackTcpOnTruncated=true`
- `b1FallbackTcpSourcePort=<port>`

When enabled for a UDP DNS probe, AppA accepts a valid DNS response with `TC=1`
as the trigger and immediately retries the same DNS payload over TCP.  The
single JSONL record retains both phases:

- `fallback_attempted=true`
- `fallback_reason=udp_tc`
- `udp_truncated=true`
- `return_outcome=dns_tcp_fallback_response_received`
- `fallback_return_outcome=dns_response_received`
- `tcp_response_valid=true`

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s180-b1-dns-fallback-20260825/
```

Run ID: `20260825-173925-730529`
Fixture: `192.168.4.5:53535`

Manifest summary:

```text
status=PASS
scope=bounded_b1_dns_udp_to_tcp_fallback
claim_boundary=WSL2 LAN fixture forced TC fallback; not public resolver coverage
cellsRecorded=1
passCount=1
cleanupMarkerGapCount=0
failureCount=0
```

Cell summary:

| Cell | App fallback | Fixture proof | Native proof | Residue | Verdict |
| --- | --- | --- | --- | --- | --- |
| `ip4-udp-tcp-dns-fallback` | `fallback=True/udp_tc`, `dns_tcp_fallback_response_received`, TCP `dns_response_received` | UDP query `1234`, UDP TC response `1234`, TCP query `1234`, TCP full response `1234` | `brokerSuccess=2`, `tunOutput=4`, `directSend=2`, cleanup `1/0` | no VPP, no `tun0` | PASS |

The AppA record used source `10.111.0.2:49651` for UDP and fallback TCP source
port `49652`, destination `192.168.4.5:53535`, payload length `29`, TCP
response length `45`, and `response_valid=true`.

Independent post-run checks also found no `vpp` process and no root-visible
`tun0`.

## Interpretation

S180 supports the B1 DNS fallback behavior for one current-artifact IPv4
full-device route using a deterministic WSL2/LAN fixture.  It proves that a
truncated UDP DNS response can trigger an in-app TCP retry through the same
owner-inline VPN dataplane, with app, fixture, native and residue evidence
joined by one run.

S180 does not claim public resolver fallback behavior, IPv6 fallback, arbitrary
large DNS responses, throughput, CPU/thermal/power, Doze, or long soak.
