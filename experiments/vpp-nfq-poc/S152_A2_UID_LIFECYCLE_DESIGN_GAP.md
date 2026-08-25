# S152 A2 UID lifecycle matrix design gap

Execution and retry are governed by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).

Date: 2026-08-25
Status: `INCONCLUSIVE_DESIGN_GAP`

## Decision

S152 cannot continue as currently designed.  The attempted A2-1 residual
two-App UID matrix produced useful partial evidence, but it does not close
EG-08/EG-09 because the runner uses public endpoints as the tuple-driving
oracle and does not pass the per-cell UID contract stage into the native/Java
resolver logs.

This is not a product seam hotspot.  It is a POC design gap with a companion
harness defect:

- TCP tuples can fail in the App socket layer before the packet reaches the
  VPN/TUN resolver seam.
- Resolver and UID contract logs are labelled `A2-4/startup`, so cell/stage
  joins are not authoritative for A2-1.

Per the hotspot rule, do not keep retrying S152 until the POC design is
revised.

## Evidence

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s152-a2-1-two-app-20260825-dualplugin-rerun1/
```

Result:

```text
status=INCONCLUSIVE
registeredTuples=8
passedTuples=5
```

The run had valid setup and cleanup:

- device `28201JEGR0XPAJ`;
- VpnLite UID `12628`, AppA UID `12630`, AppB UID `12631`;
- VPN APK `31bfab0c094d160820a9875bba858ef4fe3dc9fb0167ce0434fef45766a9cfc7`;
- AppA `05a6081804235ba8618cd1d27f329c9e7080161661f8144fd6034388acc9b24c`;
- AppB `1f3ce74382da23ab698ec671beff572eee27428444adb3930bd3df8053a47bb2`;
- TUN POC plugin `4edd62ac3bf39067fc704ed46450ee57c60bf38a5686deb47f299e0c1fadc925`;
- native start, dual allowed-UID scope, package UID snapshot, and cleanup all
  passed;
- no post-run `vpp` process or `tun0` residue remained.

The decisive gap is tuple join:

| Tuple | App result | Resolver result |
| --- | --- | --- |
| AppA IPv4/TCP `45641 -> 1.1.1.1:443` | `tcp_connect_failed`, `Address not available` | missing |
| AppA IPv6/TCP `45643 -> 2606:4700:4700::1111:443` | `tcp_connect_failed`, `Address not available` | missing |
| AppB IPv4/TCP `45651 -> 1.1.1.1:443` | `tcp_connect_failed`, `ECONNREFUSED` | missing |

The four UDP tuples and AppB IPv6/TCP `45653` produced resolver records, but
that is not enough to close the registered eight-tuple matrix.

## Root cause

The manifest uses public endpoints:

```text
1.1.1.1:443
1.1.1.1:53
2606:4700:4700::1111:443
2606:4700:4700::1111:53
```

Those endpoints are invalid as a UID resolver oracle for this claim.  S152 is
not trying to prove public Internet reachability or external TCP behavior; it
is trying to prove that registered AppA/AppB tuples are observed and joined at
the native owner-resolver seam.  A public TCP connect failure can occur before
that seam and therefore cannot distinguish target behavior from endpoint,
route, address binding, or timing.

The resolver logs also prove the stage join is not reliable:

```text
resolver query=1 ... uid=-1 cell=A2-4 stage=startup
ledger event=POLICY_PENDING stage-id=startup ...
```

For A2-1, native/Java contract rows must carry the A2-1 cell and the exact
stage ID.  Otherwise the verifier can only infer by tuple and cannot prove the
intended cell generated the resolver event.

The temporary ADB failure observed before the final rerun was an environment
noise event.  ADB recovered and the only authorized rerun reproduced the
design gap, so ADB is not the primary blocker.

## Required redesign before rerun

Do not run S152 again until the following are in place:

1. Replace public endpoints with controlled WSL2/LAN fixtures for the
   registered IPv4/IPv6 TCP/UDP tuples, including readiness proof and explicit
   no-public-Internet non-claim.
2. Pass a `uidContractStage` or equivalent cell/stage identifier from the
   runner into VpnLite/native resolver and Java UID contract logs.
3. Update the verifier so A2-1 rejects resolver rows labelled as another cell
   or `startup`; tuple-only matching is insufficient.
4. Keep the first rerun bounded to the smallest A2-1 slice: two apps, exact
   registered IPv4/IPv6 TCP/UDP tuples, and resolver join.  Do not add
   lifecycle recovery, reverse attribution, or UID-drop variants until this
   base join is decisive.

## Boundary

S152 remains open.  The current evidence does not close the complete
multi-App UID lifecycle matrix, reverse attribution, refresh/unavailable/
recovery, stale rejection, UID-drop zero-broker/socket behavior, production
cache sizing, public Internet behavior, or arbitrary OEM behavior.

