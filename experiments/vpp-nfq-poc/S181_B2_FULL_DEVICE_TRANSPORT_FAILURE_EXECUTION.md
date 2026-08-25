# S181 B2 full-device transport fixture execution

Date: 2026-08-25
Status: `PASS`

## Scope

S181 is a bounded B2 real-transport fixture slice on the full-device
AppA -> VpnService -> OI3 multi-owner route.  It uses a WSL2/LAN fixture on the
same LAN as the Pixel device.  It is not the S146/S179 controlled negative
contract and it is not a policy-drop, public-Internet, performance, Doze, or
long-soak claim.

Artifact under test in the accepted run:

- VPN APK:
  `70f14dc28ec102175bb6eddd31f83b2aec6efd27942c18a72450b36e8c66ce31`
- AppA APK:
  `24eb2af558fdb44a300e86a08643125b048c3d31b14ca9272cebc0674a2d3a88`
- OI3 plugin APK member:
  `60a9c3924c39409d1bfe931d4a19b90647f850c07852a96c3df0cc25565d799b`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s181-b2-full-device-transport-explore.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s181_b2_full_device_transport.py
```

## Hotspot and POC design correction

The original third S181 cell treated an unbound WSL2/LAN TCP port as a real
transport-refusal fixture and passed `oi3ExpectedFailure=real-refused`.  That
was not a valid claim for the observed topology.

The key pre-correction evidence was run `20260825-182316-640498` in
`experiments/vpp-nfq-poc/evidence/s181-b2-full-device-transport-explore-20260825/`:

- the service log proved `oi3ExpectedFailure=real-refused` reached VpnLite;
- OI3 startup proved `expected-failure=real-refused` reached the multi-owner
  native path;
- AppA saw `tcp_connect_succeeded/dns_response_timeout`;
- native cleanup saw broker/protect success, TUN output, handshake and return
  rewrite, but zero transport-failure events and no endpoint refusal report;
- cleanup therefore failed as `EXPECTED_REAL_TRANSPORT_REFUSAL`.

The root cause was POC design, not ADB, UID lookup, startup, or missing native
parameter propagation.  Android VPN/OI3 can complete the app-facing TCP
handshake before the protected underlay produces a result.  In this WSL2/LAN
environment, an unbound TCP port did not reliably produce an observable native
RST/`ECONNREFUSED` signal at the OI3 cleanup boundary.  The valid bounded claim
is therefore closed-port TCP timeout after local proxy handshake.

S181 now uses three cells:

- `positive-udp-dns`: positive UDP DNS response;
- `no-reply-udp-dns`: real UDP no-reply with explicit
  `oi3ExpectedFailure=real-no-reply`;
- `closed-tcp-timeout`: unbound TCP port classified as post-allow timeout,
  with no `real-refused` claim.

The third cell now requires AppA `tcp_connect_succeeded/dns_response_timeout`
and native `PASS_EXPECTED_AMBIENT_TIMEOUT` / `EXPECTED_TIMEOUT`.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s181-b2-full-device-transport-explore-20260825/
```

Run ID: `20260825-183033-563849`
Fixture host: `192.168.4.5`

Fixture ports:

- positive UDP DNS: `53541`
- no-reply UDP DNS: `53542`
- closed TCP timeout: `53543`

Run-validity summary:

```text
status=PASS
scope=bounded_full_device_b2_transport_failure_exploration
claim_boundary=WSL2 LAN fixture real no-reply and TCP timeout exploration; not policy-drop closure
cells_recorded=3
pass_count=3
design_gap_count=0
failure_count=0
non_claim=not policy drop, not IPv6, not public internet, not long soak/performance
```

Cell summary:

| Cell | App proof | Fixture proof | Native proof | Residue | Verdict |
| --- | --- | --- | --- | --- | --- |
| `positive-udp-dns` | `udp_datagram_sent/dns_response_received` | UDP query and response on `53541` | broker/TUN/direct markers, `EXPECTED_DIRECT_REPLY` | no VPP, no `tun0` | PASS |
| `no-reply-udp-dns` | `udp_datagram_sent/dns_response_timeout` | UDP query on `53542`, no response | `PASS_EXPECTED_REAL_NO_REPLY` / `EXPECTED_REAL_NO_REPLY` | no VPP, no `tun0` | PASS |
| `closed-tcp-timeout` | `tcp_connect_succeeded/dns_response_timeout` | port `53543` confirmed unbound | `PASS_EXPECTED_AMBIENT_TIMEOUT` / `EXPECTED_TIMEOUT` | no VPP, no `tun0` | PASS |

The accepted CSV records `appValid=1`, `fixtureValid=1`, `nativeObserved=1`,
and `nativeExpected=1` for all three cells.  The third cell recorded
`outputCleanup=1`, `handshakeCleanup=1`, `rewrittenCleanup=1`,
`directCleanup=0`, `ambientTimeout=1`, `transportFailures=0`, and
`infrastructureFailures=0`.

## Additional corrections made during S181

- The VPN service/AppA start path now carries `oi3ExpectedFailure` from the
  Activity intent to native process environment.
- The OI3 native path now reads that expected-failure parameter in the
  multi-owner `sakamoto-oi3 multi tun` command path, not only in the older
  single-owner command path.
- S181 runner verification now rejects the old `real-refused` claim unless a
  future deterministic reset/refusal fixture is added.

## Interpretation

S181 supports a bounded real full-device B2 transport slice for the current
artifact: positive UDP DNS, real UDP no-reply, and closed TCP timeout are
separated from policy-drop and infrastructure failure and complete with zero
post-run residue.

S181 does not prove real external RST/`ECONNREFUSED`, real policy drop,
bind/protect failure, infrastructure failure, IPv6, public Internet behavior,
production timeout constants, throughput, CPU/thermal/power, Doze, or long
soak.  A future real-refusal claim must use a deterministic refusal/reset
fixture and require an observed native refusal signal.
