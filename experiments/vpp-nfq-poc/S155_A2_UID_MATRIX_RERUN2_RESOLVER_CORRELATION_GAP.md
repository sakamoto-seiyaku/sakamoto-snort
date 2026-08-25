# S155 A2 UID matrix rerun2 resolver/correlation gap

Execution and retry are governed by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).

Date: 2026-08-25
Status: `INCONCLUSIVE_SUCCESSOR_GAP`
Plane: `SAKAMOTO-152` parent; `SAKAMOTO-155` repaired fixture/stage oracle.
Successor finding: `VPN-F061`.

## Decision

Do not keep rerunning A2-1 as currently specified. S155 fixed the S152 POC
design defect: the rerun used a controlled WSL2/LAN IPv4+IPv6 TCP/UDP fixture,
retained fixture readiness, installed the local VpnLite/AppA/AppB APKs, passed
an exact A2-1 `uidContractStage`, and required exact cell/stage verifier joins.
The previous S152 `A2-4/startup` and public-endpoint oracle problems did not
recur.

The corrected run is still `INCONCLUSIVE`: only 3/8 registered tuples produced
decisive native resolver + UID contract joins. This is a new resolver/correlation
gap, not the old harness stage-arm problem.

## Evidence

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s155-a2-1-fixture-stage-20260825-run2/
```

Result:

```text
status=INCONCLUSIVE
registeredTuples=8
passedTuples=3
```

Valid gates:

- controlled WSL2/LAN fixture registration and readiness passed for IPv4/IPv6
  TCP/UDP;
- two App packages had distinct UIDs: AppA `12630`, AppB `12631`;
- VpnLite and both traffic APK hashes matched local builds;
- source provenance, VPN session receipt, native VPP start, allowed UID scope,
  A2-1 stage registration, runtime records, VPN handle, and cleanup passed;
- all eight `STAGE_BEGIN` records were present with `cell_id=A2-1` and exact
  tuple stage IDs;
- no wrong-UID decisive record was observed.

Tuple disposition:

| Tuple | Result | Evidence boundary |
| --- | --- | --- |
| AppA IPv4/TCP `45641` | `INCONCLUSIVE` | runtime passed, but no decisive native resolver/contract join |
| AppA IPv4/UDP `45642` | `PASS` | `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT`, uid `12630` |
| AppA IPv6/TCP `45643` | `INCONCLUSIVE` | repeated Android owner lookups returned `uid=-1` / `android-api-invalid-uid` |
| AppA IPv6/UDP `45644` | `PASS` | `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT`, uid `12630` |
| AppB IPv4/TCP `45651` | `INCONCLUSIVE` | runtime passed, but no decisive native resolver/contract join |
| AppB IPv4/UDP `45652` | `PASS` | `MISS_SUBMITTED -> COMPLETION_ACCEPTED -> CACHE_HIT`, uid `12631` |
| AppB IPv6/TCP `45653` | `INCONCLUSIVE` | Android owner lookup returned `uid=-1` |
| AppB IPv6/UDP `45654` | `INCONCLUSIVE` | Java contract accepted uid `12631`, but native resolver log never produced a decisive uid hit for that tuple |

## Root cause candidates

The evidence identifies two separate seams that must be designed or instrumented
before another A2-1 rerun is useful:

1. **TCP/IPv6 owner lookup seam.** `UidAttributionContract` calls
   `ConnectivityManager.getConnectionOwnerUid(protocol, local, remote)`. In the
   corrected run, IPv6 TCP tuples repeatedly completed as
   `LOOKUP_UNAVAILABLE` with reason `android-api-invalid-uid`, even though the
   App runtime and VPP tuple evidence existed. This may be an Android API
   tuple-direction/state/timing constraint, a request-shape issue, or a
   production seam limitation; rerunning the same matrix will not distinguish
   those.
2. **Global stage marker used as per-flow evidence.** The native resolver log
   copies the current global stage when a resolver line is processed. A delayed
   query can therefore be logged under the next tuple's stage; rerun2 contains
   an AppA IPv6 TCP query logged under `A2-1-appa-ip6-udp`. A2-1 needs
   per-request/per-flow stage correlation, not a process-global current-stage
   marker, before asynchronous resolver events can prove an exact tuple.

## Required redesign before continuing A2-1

1. Decide the production-valid UID resolver contract for TCP, especially IPv6
   TCP, on the target Android version: either prove the current Android owner
   API can return the correct App UID with adjusted tuple direction/timing, or
   define a replacement seam that preserves nonblocking FlowOwner execution and
   does not put UID in the canonical owner key.
2. Replace process-global native stage attribution with per-flow/per-request
   correlation. The stage attached to a resolver query must be fixed from the
   packet/request identity, not sampled at completion time from the current
   control-plane stage.
3. Update the verifier so A2-1 distinguishes:
   - no resolver query;
   - resolver query with terminal `uid=-1`;
   - contract accepted but native decisive hit missing;
   - wrong UID;
   - delayed query logged under another stage.
4. Rerun only the smallest repaired A2-1 slice after the above seam is
   implemented. Do not proceed to A2-2/A2-4/A2-5 dependent cells while A2-1
   cannot decisively join the base two-App matrix.

## Boundary

S155 does not contradict the owner-inline baseline and does not prove that UID
must block FlowOwner execution, enter the canonical owner key, or use an
alternate/unprotected path. It proves that the old S152 POC oracle was fixed
and that the remaining A2-1 closure depends on a deeper UID resolver/correlation
design seam.
