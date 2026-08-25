# Android VPN POC execution guardrails

Date: 2026-08-25
Status: active execution runbook

Plane is the source of truth for open work. This document defines evidence,
classification, and stop rules; it is not a backlog.

## Product and environment boundary

These POCs validate a user-controlled privacy firewall on the user's own
Android device. The app uses Android `VpnService`, per-application UID
attribution, local policy, protected Direct sockets, and controlled fixtures on
the user's WSL2/LAN host. The purpose is to let the device owner observe and
control local traffic. It does not add an externally reachable service, scan
third-party systems, evade another party's controls, or provide an implicit
public-network fallback.

Use repo-local `./dev/adb` for every device or app operation. Prefer controlled
WSL2/LAN fixtures. Public Internet behavior is evidence only when a registered
claim explicitly requires it; it must never be introduced as an unrecorded
substitute for a local oracle.

## Why this runbook exists

S140--S185 plus S152 showed that a target failure, a POC-design defect, an invalid run,
and an architecture hotspot can look identical at the App timeout surface.
Small execution agents repeatedly lost time by acting on the last visible
symptom instead of joining App, TUN, policy, owner, broker, connector, fixture,
return, cleanup, and artifact provenance evidence.

Every new slice must therefore answer exactly one registered question and must
classify the run before changing code.

## Mandatory evidence chain

A real-device cell is valid only when all applicable rows are joined by a
run ID, cell ID, generation, canonical tuple, or broker token.

| Layer | Required evidence |
| --- | --- |
| Artifact | Git revision; APK hash; packaged plugin and HEV hashes; source/stage provenance; installed package/version |
| Device | selected serial; Android build; package UIDs; VPN consent/state; required permissions; physical network snapshot |
| Harness | repo-local ADB wrapper; bounded command timeouts/retries; unique ports; fixture process and readiness proof |
| App | exact operation, source/destination tuple, result, timeout/error, and whether the tuple was attempted |
| TUN/policy | ingress tuple; UID lookup state; policy winner/verdict/reason; whether admission stopped before owner/broker |
| Owner | canonical owner; generation/epoch; queue/admission result; owner-thread execution; stale/duplicate rejection |
| Broker | request/completion token; exact result enum; selected non-VPN Network handle; bind/protect ordering |
| Connector | fd creation; connect/send/read event; `poll`/`SO_ERROR`/EOF/error when relevant; no alternate socket |
| Fixture | independent readiness; exact packet/connection received or explicitly absent; response/reset action |
| Return | HEV output; provenance rewrite; VPP TUN output; App receipt |
| Settlement | terminal outcome; buffers/credits/fds/tasks settled once; no unexpected VPP or `tun0` residue |

App success alone is not a pass. App timeout alone is not a target failure.
`bindSocket()` and `protect()` returning success do not prove a physical
underlay was selected. A fixture claiming it sent a reset does not prove the
owner observed a reset.

## Classification before correction

Classify every non-pass into exactly one primary category before editing code.

| Category | Meaning | Required action |
| --- | --- | --- |
| `INVALID_ENVIRONMENT` | Device, ADB/WSL transport, permission, package, network, or fixture precondition failed | Correct the precondition and rerun; do not count it as product evidence |
| `HARNESS_DEFECT` | Runner blocked, reused a tuple, read logs incorrectly, mixed artifacts, or used a false oracle | Correct and statically regress the harness; rerun the same unchanged claim |
| `POC_DESIGN_GAP` | The selected injection point, outcome, or oracle cannot prove the registered claim | Revise the POC contract and dependent DAG before more execution |
| `IMPLEMENTATION_DEFECT` | Valid evidence reaches the intended production-shaped seam and violates its local contract | Make one bounded seam correction, rebuild, and rerun the smallest reproducer plus regressions |
| `ARCHITECTURE_HOTSPOT` | Valid higher-fidelity evidence contradicts owner locality, no-fallback, boundedness, generation safety, or the registered performance envelope | Stop the affected route and request an explicit architecture decision |

Do not make a failing run green by weakening an assertion, expanding a skip,
renaming timeout as refusal, or moving the injection to a shallower substitute.

## Recurring hotspot catalogue

| Trap | Historical evidence | Guardrail |
| --- | --- | --- |
| APK/plugin/source mismatch | VPN-F027, VPN-F039, VPN-F048 | Hash the installed APK and every packaged native member. A source edit is irrelevant until the rebuilt member hash changes and is recorded. |
| Android permission or WSL/ADB transport failure | VPN-F028, VPN-F043, VPN-F052 | Run permission, LAN, fixture, and ADB preflights first. Bounded retry is allowed only for transport setup, never for hiding a valid target failure. |
| VPN selected as its own underlay | VPN-F029 | Enumerate candidates, reject every VPN transport, record the selected physical handle, then bind and protect. Fail closed when no physical Network exists. |
| Public or unbound endpoint used as an oracle | S140, VPN-F055, VPN-F058, S152 / VPN-F060 | Use a controlled LAN listener and prove readiness, reachability, and the exact action. An unbound TCP port commonly yields post-handshake timeout through this stack; public TCP endpoints can fail before the VPN/TUN resolver seam and cannot prove UID attribution. |
| Cell/stage provenance inferred from tuple only | S152 / VPN-F060 | Pass the registered cell/stage through App, Java UID contract, native resolver, verifier, and manifest. A resolver row labelled as another cell or `startup` cannot satisfy an A2 matrix cell even when the tuple matches. |
| Process-global stage marker used as per-flow proof | S155 / VPN-F061 | Do not treat a current global stage as the identity of delayed async resolver work. Carry the registered stage on the resolver request/flow identity, and require resolver `cell/stage/request` artifact gates before install. |
| Fixed TCP source-port reuse used as UID oracle | S156 / VPN-F061 | For Android VPN TCP probes, request `sourcePort=0`, durably record the actual VPN-local source port, and join resolver/contract evidence on that actual tuple. Use bounded TCP repeat plus decisive-repeat selection; do not reuse fixed TCP ports to force determinism. |
| Timeout conflated with reset, refusal, policy drop, or infrastructure failure | VPN-F032, VPN-F053, VPN-F055, VPN-F058 | Each outcome needs a distinct observed event. Timeout proves only deadline expiry. Reset/refusal requires owner-observed socket evidence; policy drop requires zero broker/socket; infrastructure failure requires an exact broker result. |
| Bind/protect/broker failure phases share one oracle | S185 / VPN-F059 | Keep pre-connector infrastructure failures on the broker branch, but assert their phase-specific contract exactly: bind failure is broker result `BIND_FAILURE` with bind/protect `1/0`; protect failure is `PROTECT_FAILURE` with `1/1`; broker unavailable is `BROKER_UNAVAILABLE` with `0/0`. Do not reuse success-path bind/protect counters or treat App timeout as the proof. |
| Async UID sentinel treated as a terminal result | VPN-F026, VPN-F057 | Treat `uid=-1` as `MISS_SUBMITTED`, not Unknown/terminal. Join completion and scoped cache hit with a bounded barrier or use a production replacement seam. |
| App exclusion used as policy-drop evidence | VPN-F056 | Inject/observe policy at the registered TUN/VPP pre-owner seam. Prove the dropped tuple entered TUN and created no owner, broker, or connector work. |
| Positive cleanup rules reused for negative or stop cells | VPN-F032, VPN-F034, VPN-F053 | Define cell-aware terminal outcomes. Keep Policy Verdict, Transport Outcome, Infrastructure Fault, explicit stop, and cleanup-marker timing separate. |
| TUN or tuple lifecycle ends too early | VPN-F035, VPN-F041 | Separate VPN-session lifetime from per-flow owner generation. Preserve TUN/watchers across eligible re-arm and reject stale TCP tail before admitting a successor SYN. |
| Mutable Flow Stack work leaks to helper/broker threads | owner-inline OI1--OI5 contract | Helpers publish opaque generation-tagged readiness only. The canonical owner alone reads connector outcome state and executes HEV/lwIP callbacks. |
| One-owner evidence substituted for multi-owner claims | VPN-F036 | Confirm the artifact exposes the registered owner count, independent contexts, canonical dispatch, and per-owner ledgers before D/E pressure or performance work. |
| Capacity mismatch disguised as packet loss | VPN-F037, VPN-F046, VPN-F050, VPN-F051 | Precompute tuple-to-owner mapping and registered concurrency. Distinguish admission, packet credit, inflight pbuf, socket/session, and owner-busy limits. Never silently lower the offered load. |
| Teardown destroys shared state before task drain | VPN-F042 | Quiesce admission, reclaim owner tokens, drain queued tasks, then destroy contexts/pools. A repeated heap abort is a hotspot, not a flaky test. |
| Ambient Android traffic contaminates a registered cell | VPN-F038, VPN-F044 | Use exact registered tuples and unique dynamic source ports. Classify ambient tuples separately; do not let them satisfy or fail the target oracle. |
| Fixed source-port/TIME_WAIT reuse | VPN-F044, S178 | Allocate a fresh bounded port range per run and record it. Never rerun TCP cells on a stale fixed tuple unless reuse itself is the claim. |
| Blocking or late log collection changes the verdict | VPN-F052, VPN-F053 | Read regular files with bounded tail/poll; allow an explicit settlement window. Separate missing telemetry from observed dataplane failure. |
| Combined and source logs are counted as independent events | S184 / VPN-F058 | Declare log provenance before aggregating. If a combined log embeds a source log, deduplicate presence markers or use authoritative monotonic owner counters for exact-once claims; never spend a device rerun on a proven parser-only duplicate. |
| Throughput/latency comparison includes unequal startup work | S171--S175 | Use the same endpoint, payload, concurrency, warm-up, live-session interval, and measurement boundary. Report validity and correctness before applying ADR performance ratios. |

## Required execution protocol for delegated agents

An execution task handed to a smaller model must contain this protocol in its
description or link here and state that it is mandatory.

1. Read the campaign claim, Finding Ledger entries, latest accepted evidence,
   and source implementing the exact seam.
2. Restate one question, one target failure, one positive control, the expected
   outcome enum, non-claims, and stop condition before editing or running.
3. Check that no stale runner, fixture, VPP process, VPN session, or `tun0`
   residue can contaminate the run.
4. Record artifact and installed-device provenance before interpreting traffic.
5. Prove fixture and path readiness independently of the target cell.
6. Run the smallest positive control first, then exactly one negative/pressure
   variable. Do not start a broad matrix to diagnose an unresolved seam.
7. Join the mandatory evidence chain and classify the result before editing.
8. For an implementation defect, add a failing static/model/integration guard,
   make one bounded correction at the registered seam, and run focused
   regressions.
9. Rebuild every affected native layer and APK, prove the packaged hashes
   changed as expected, reinstall, and rerun the exact reproducer.
10. Update evidence documents and Plane in the same execution slice. Record
    invalid attempts separately; never promote them to accepted evidence.

## Prohibited shortcuts

- Do not call Windows `adb.exe` or bypass `./dev/adb`.
- Do not use a public endpoint because the controlled fixture is inconvenient.
- Do not interpret silence, deadline expiry, or missing telemetry as refusal,
  reset, policy drop, or bind/protect failure.
- Do not create an unprotected retry, Direct/SOCKS fallback, second packet path,
  live owner migration, or alternate hash to make connectivity pass.
- Do not modify both the target and positive control in the same diagnostic
  step.
- Do not lower concurrency, request count, or capacity pressure without
  explicitly narrowing the registered claim in Plane first.
- Do not accept source-level tests as proof that the installed APK contains the
  fix.
- Do not force-stop immediately after App output when cleanup/settlement is an
  assertion; use a bounded settlement window.
- Do not continue dependent POCs while their prerequisite seam is classified
  `POC_DESIGN_GAP` or `ARCHITECTURE_HOTSPOT`.

## Hotspot and retry rule

A valid first failure starts diagnosis; it is not permission for unbounded
trial-and-error.

- `INVALID_ENVIRONMENT` and `HARNESS_DEFECT`: correct only the invalid layer and
  rerun the same claim.
- `POC_DESIGN_GAP`: stop dependent cells, revise the claim/oracle/outcome seam,
  and update Plane before running again.
- `IMPLEMENTATION_DEFECT`: one bounded correction and one exact device rerun
  are allowed when the task authorizes implementation.
- If the same invariant fails again after that correction, or if the same
  crash/corruption reproduces twice in valid runs, stop and report it as a
  hotspot. Do not rotate through speculative fixes.
- Any need for unprotected fallback, second datapath, global mutable authority,
  live owner migration/spill, weakened ownership settlement, or a valid ADR
  performance cliff is an immediate architecture stop.

An unrelated independent branch may proceed only when its evidence and
artifact do not depend on the paused seam. For B2, post-SYN RST/reset outcome
work and pre-connect bind/protect/broker failures are separate branches.

## Task acceptance template

Every Plane execution item should specify:

- registered claim and evidence-gap/finding IDs;
- exact seam and code/artifact under test;
- positive control and single target variable;
- validity preflights and evidence join keys;
- expected Policy Verdict, Runtime Disposition, Transport Outcome,
  Infrastructure Fault, App result, and cleanup result;
- immutable assertions and prohibited fallbacks;
- bounded command/runtime budget and retry rule;
- accepted evidence directory and machine-readable summary shape;
- regressions required after a correction;
- non-claims and hotspot stop condition;
- documentation and Plane updates required before completion.
