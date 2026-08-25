# S185 B2 bind/protect/broker infrastructure failure separation

Execution and retry are governed by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md),
especially the rule that timeout, policy drop, transport failure, and
infrastructure failure require distinct observed events.

Date: 2026-08-25
Status: `PASS`

## Decision

S185 isolates the remaining B2 infrastructure-failure branch on the selected
full-device AppA -> VpnService -> OI3 multi path.  It reuses the S181 runner
only as shared fixture/device scaffolding, disables policy-drop, UID-drop,
no-reply, and TCP-timeout cells, then runs one positive UDP DNS control plus
three pre-connector infrastructure-failure cells:

- `bind-failure-udp-dns`
- `protect-failure-udp-dns`
- `broker-unavailable-udp-dns`

The key hotspot was the oracle, not ADB reachability.  A shared
“broker-failed” assertion is invalid because the three failures happen at
different Android broker phases:

| Cell | Expected broker result | Expected bind/protect calls |
| --- | --- | --- |
| bind failure | `BIND_FAILURE` | `1/0` |
| protect failure | `PROTECT_FAILURE` | `1/1` |
| broker unavailable | `BROKER_UNAVAILABLE` | `0/0` |

The corrected POC therefore injects the exact broker-request flag for the
registered cell, requires the exact completion enum, and requires exact phase
accounting.  All three failures must stop before TUN output, Direct send,
fixture query, transport failure, policy drop, or downstream return.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s185-b2-infrastructure-failures-20260825-run1/
```

Run ID: `20260825-213903-524622`

Device: `28201JEGR0XPAJ` (Pixel 6a)

Fixture host: `192.168.4.5`

Ports:

| Purpose | Port |
| --- | --- |
| positive UDP DNS | `53541` |
| forced bind failure observer | `53547` |
| forced protect failure observer | `53548` |
| broker-unavailable observer | `53549` |

Runner and static guard:

```text
experiments/vpp-nfq-poc/scripts/android-run-s185-b2-infrastructure-failures.sh
experiments/vpp-nfq-poc/scripts/tests/test_verify_s185_b2_infra_failure.py
```

Artifact SHA-256 values:

```text
VPN APK  5ab5ef07e178ee4e0f613c7d7b231b355088953a1e517fc075ffb1a72baaaf8a
AppA     05a6081804235ba8618cd1d27f329c9e7080161661f8144fd6034388acc9b24c
OI3      2ad3068daa32aa788933bb947f0f09cfed52b283e9bae72fd222772022d6fe89
HEV      420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466
```

## Result

The accepted run passed all four cells with zero design gaps, zero failures,
and zero post-run `vpp`/`tun0` residue:

```text
status=PASS
cells_recorded=4
pass_count=4
design_gap_count=0
failure_count=0
```

Cell outcomes:

| Cell | Verdict | App result | Infrastructure result | Native counters |
| --- | --- | --- | --- | --- |
| positive UDP DNS | `PASS` | `dns_response_received` | none | `brokerInfra=0/0/0`, bind/protect success `1/1` |
| bind failure | `PASS` | `dns_response_timeout` | `EXPECTED_BIND_FAILURE` | `brokerInfra=1/0/0`, bind/protect success `0/0` |
| protect failure | `PASS` | `dns_response_timeout` | `EXPECTED_PROTECT_FAILURE` | `brokerInfra=0/1/0`, bind/protect success `1/0` |
| broker unavailable | `PASS` | `dns_response_timeout` | `EXPECTED_BROKER_UNAVAILABLE` | `brokerInfra=0/0/1`, bind/protect success `0/0` |

The machine CSV records the failure-specific native oracles:

```text
bind-failure-udp-dns:
  brokerInfra=1/0/0 bindProtect=0/0 infrastructureFailures=1
protect-failure-udp-dns:
  brokerInfra=0/1/0 bindProtect=1/0 infrastructureFailures=1
broker-unavailable-udp-dns:
  brokerInfra=0/0/1 bindProtect=0/0 infrastructureFailures=1
```

No failure cell reached the fixture query observer, emitted TUN output, sent
Direct data, or recorded a transport failure.  This is the required
infrastructure branch: the app sees timeout only as the external surface, while
native evidence proves the distinct pre-transport cause.

## Correction details

The bounded correction added three pieces:

- `oi3_request_flags_for_expected_failure()` maps the registered
  `oi3ExpectedFailure` value to the exact OI2 broker request flag.
- OI3 completion accounting now counts bind/protect phases according to the
  actual broker completion result, not a shared “request attempted” shortcut.
- The infrastructure classifier requires exact enum, exact phase counters,
  zero output/direct/fixture/transport side effects, one infrastructure
  failure, and no duplicate-close residue.

The wrapper `android-run-s185-b2-infrastructure-failures.sh` is intentionally
narrow.  It only enables the S185 infrastructure cells and records the claim
boundary:

```text
WSL2-LAN-fixture-real-AppA-positive-control-plus-bind-protect-broker-failure-before-OI3-connector-transport
```

## Regression checks

Static and syntax checks executed before accepting the device result:

```text
rtk python3 -m unittest \
  experiments/vpp-nfq-poc/scripts/tests/test_verify_s181_b2_full_device_transport.py \
  experiments/vpp-nfq-poc/scripts/tests/test_verify_s182_b2_real_policy_drop.py \
  experiments/vpp-nfq-poc/scripts/tests/test_verify_s183_b2_real_uid_drop.py \
  experiments/vpp-nfq-poc/scripts/tests/test_verify_s184_b2_real_rst.py \
  experiments/vpp-nfq-poc/scripts/tests/test_verify_s185_b2_infra_failure.py

rtk bash -n \
  experiments/vpp-nfq-poc/scripts/android-run-s181-b2-full-device-transport-explore.sh \
  experiments/vpp-nfq-poc/scripts/android-run-s185-b2-infrastructure-failures.sh

rtk git diff --check
```

The native plugin and VPN APK were rebuilt before the accepted device run, and
the installed APK/native-member hashes above prove the packaged artifact
contains the S185 classifier.

## Boundary

S185 supports only bounded full-device infrastructure-failure separation for
the selected Pixel, current artifact, AppA, OI3 multi path, and WSL2/LAN
fixture.

It does not claim policy-drop behavior, post-connect transport failure,
pre-connect `ECONNREFUSED`, public-Internet behavior, production timeout or
capacity constants, Doze behavior, long soak, or the full distinct-App matrix.
