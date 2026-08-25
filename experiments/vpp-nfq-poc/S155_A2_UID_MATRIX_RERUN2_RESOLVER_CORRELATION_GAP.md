# S155 A2 UID matrix rerun2 resolver/correlation gap

Execution and retry are governed by
[`ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md`](ANDROID_VPN_POC_EXECUTION_GUARDRAILS.md).

Date: 2026-08-25
Status: `RESOLVED_BY_S156`
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

## Resolution addendum: S156 run5

`VPN-F061` is closed for the A2-1 base matrix by:

```text
experiments/vpp-nfq-poc/evidence/s156-a2-1-correlation-20260825-run5/
status=PASS
registeredTuples=8
passedTuples=8
```

The repaired run used clean source provenance:

```text
gitHead=a3e66a6c3fb34967ca98a39ed5a47c28b8f342be
gitDirty=false
vpnApkSha256=ea213596ba618786d2a0185e8a8a424b1a2b8f98da96a7d51bba56f1855f81ce
appAApkSha256=2318eff70a633d6c5f0428f49d501d2932a800d68a70fb81d760514cac9f86dd
appBApkSha256=fa539d2b416b3575b4e51a8c8c7dd37f10caa7f7d3a18c404066df41d806cb74
tunPocPluginSha256=1df3694f14fe9e1bc5d2c9926caab3f91d0ba3456d77212c4a83e3c89696c0a9
resolverCorrelationSchema=a2-1-resolver-cell-stage-request/v1
tcpRepeat=4
udpRepeat=2
```

Three POC fixes were required:

1. Rebuild and gate the VpnLite APK so both `libvpnfdprobe.so` and
   `libtun_poc_plugin.so` carry immutable `cell/stage/request` resolver
   metadata.  The runner now rejects stale APKs before install.
2. Replace process-global native stage sampling with per-request resolver
   correlation.  Delayed resolver work no longer proves a tuple unless the
   request itself carries the exact A2-1 cell/stage/request metadata.
3. Stop reusing fixed TCP source ports for the A2-1 TCP matrix.  TCP commands
   request `sourcePort=0`; the Android app records the actual VPN-local source
   port; the runner writes that actual port into the manifest and selects a TCP
   repeat with a decisive positive resolver UID.  TCP repeat is now `4`, UDP
   remains `2`.

Run5 selected these TCP ports in the manifest:

| Tuple | Manifest source port | Requested source port | Repeat |
| --- | ---: | ---: | ---: |
| AppA IPv4/TCP | `34459` | `0` | `4` |
| AppA IPv6/TCP | `44015` | `0` | `4` |
| AppB IPv4/TCP | `42037` | `0` | `4` |
| AppB IPv6/TCP | `45917` | `0` | `4` |

All eight tuple checks passed with runtime, resolver, and UID-contract verdicts
equal to `PASS`.  This closes the S155 successor hotspot for the registered
A2-1 two-App IPv4/IPv6 TCP/UDP base matrix.

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

These items were completed by the S156/run5 repair:

1. The production-valid TCP contract for this POC is: TCP may use an Android
   assigned VPN-local ephemeral source port; the durable runtime record supplies
   the actual port used for the resolver/contract join.
2. Native resolver attribution now carries per-request cell/stage/request
   metadata.  The verifier rejects old artifact schemas.
3. The verifier distinguishes:
   - no resolver query;
   - resolver query with terminal `uid=-1`;
   - contract accepted but native decisive hit missing;
   - wrong UID;
   - delayed query logged under another stage.
4. The smallest repaired A2-1 slice was rerun as S156 run5 and passed.

A2-2/A2-4/A2-5 may continue from this checkpoint.  They must inherit the
request-correlation and TCP dynamic-port guardrails; they must not revert to
fixed TCP source-port reuse or tuple-only resolver joins.

## Boundary

S155 does not contradict the owner-inline baseline and does not prove that UID
must block FlowOwner execution, enter the canonical owner key, or use an
alternate/unprotected path. It proves that the old S152 POC oracle was fixed
and that A2-1 required an explicit resolver-correlation and TCP source-port
design.  S156 run5 proves that corrected design for the registered base matrix;
it does not prove lifecycle recovery, reverse attribution, cache bounds, or
production capacity.
