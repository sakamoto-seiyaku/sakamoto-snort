# S237--S244 post-F074 count64 tail-fix validation

Date: 2026-08-26
Status: `COUNT64_TAIL_FIX_SUPPORTED_WITH_REPEAT_START_RISK_RECORDED`

## Question

After the F074 Android VPP worker-idle correction, is the remaining count64
OI3 p99 tail caused by a local owner-inline re-arm seam, and does the candidate
fix pass the same count64 foreground Direct/OI3 shape without reintroducing CPU
runaway or cleanup residue?

## Scope

- Runner: `scripts/android-run-s172-e2-http-baseline-sample.sh`.
- Device: Pixel 6a / Android 16 / arm64-v8a.
- Fixture: WSL2/LAN HTTP fixture at `192.168.4.5:42187`.
- Primary traffic shape: `MAX_REQUESTS=64`, `REQUEST_INTERVAL_MS=0`,
  `DURATION_SECONDS=10`, foreground, Direct/OI3.
- OI3 plugin source: `experiments/vpp-nfq-poc/overlay/src/plugins/hev_external_driver_poc/owner_inline_oi3.c`.
- Correct post-F074 runtime package:
  - APK SHA-256 `7a636861584aba9bd8d4e05832b1576c3823f8560c8f65fe8f3935cd085d82a2`.
  - VPP runtime core SHA-256
    `87cba5b2133f3ec1db0df2440a09ced921f78665b93e33bf1a2fbcc6837aa6e2`.
  - OI3 plugin SHA-256
    `1c629adc13301d3a2dd98f86f8a39acc2533e24ec62f90433b10770a15f16338`.
  - HEV owner-context SHA-256
    `420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466`.

Excluded: HEV/tun-poc broad comparison.  VPN-F073 already records that HEV is
not a valid broad matched baseline around the 64-request envelope.

## POC correction

S237 found that a same-owner deferred successor SYN could be re-armed through
the frame-queue path even though execution was already on that owner.  In that
case OI3 depended on another scheduling turn to drive pending TUN work and
finish the owner lifecycle, which produced an isolated high p99 tail without
cleanup failure or CPU runaway.

The correction keeps canonical owner selection and the deferred-SYN contract.
It only changes the same-owner re-arm path:

- `oi3_send_request()` now logs `broker-request wall-ms=...` so broker timing
  can be joined against app latency.
- `oi3_admit_deferred_tun_flow()` detects `current_thread == target_thread`.
  Instead of self-enqueuing a frame-queue token, it logs
  `oi3 deferred-owner-drive ... reason=same-owner-rearm`, applies pending
  underlay state, runs the owner for the current bounded quantum, and finishes
  if ready.

This is a local POC seam correction.  It does not reopen ADR-0007's
owner-inline topology decision.

## Packaging/provenance pitfall

Two invalid packaging paths appeared while validating this correction:

- A plugin built from the generated `work/vpp` tree (`6063ee407c75...`) was
  injected into the product runtime stage.  The APK started but OI3 CLI/plugin
  evidence was missing, so S238 was invalid.
- The historical OI3 runtime stage loaded the corrected plugin and produced
  good latency, but its VPP core hash
  `6e7c692929da876b651df06fad8a7344598da5dae40100389425e4b7b4ac8ef8`
  did not contain the F074 idle-profile fix.  S239 therefore showed
  `cpuTicksDelta` around `3300` and is not valid post-F074 evidence.

The valid post-F074 package builds the OI3 plugin from the same product/F074
VPP source used by `build-output/android-vpp-runtime/stage`.  This is another
instance of VPN-F039: VPP core, external plugin, HEV member, APK and installed
runtime must share explicit provenance before any POC result is interpreted.

## Evidence

### Pre-fix S237 tail

S237
`evidence/s237-e2-count64-post-f074-p99-repeat-20260826/`
(`runId=20260826-093500-130681`) produced eight valid rows before the run was
stopped.  The decisive valid OI3 row was repeat 4:

| Cell | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| OI3 r1 | `64/64` | `16 / 27 / 76` | `195` | `140` | `68/0` | `1` |
| OI3 r2 | `64/64` | `19 / 60 / 62` | `201` | `142` | `68/0` | `1` |
| OI3 r3 | `64/64` | `17 / 26 / 29` | `208` | `150` | `68/0` | `1` |
| OI3 r4 | `64/64` | `19 / 32 / 879` | `214` | `153` | `68/0` | `1` |

The tail was not a startup failure, correctness failure, cleanup failure, or
F074 CPU recurrence.  It was a valid latency tail in the same count64 shape.

### Candidate S241 validation and repeat-start abort

S241
`evidence/s241-e2-count64-tail-fix-f074-product-20260826/`
(`runId=20260826-102409-220536`) used the corrected product/F074 package.  The
first four OI3 repeats were valid and no longer reproduced the S237 p99 tail:

| Cell | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| OI3 r1 | `64/64` | `19 / 27 / 67` | `208` | `147` | `68/0` | `1` |
| OI3 r2 | `64/64` | `20 / 29 / 74` | `217` | `153` | `68/0` | `1` |
| OI3 r3 | `64/64` | `18 / 26 / 68` | `205` | `146` | `68/0` | `1` |
| OI3 r4 | `64/64` | `18 / 63 / 65` | `205` | `146` | `68/0` | `1` |

S241 was still invalid as a full repeat because `oi3-r5` aborted during VPP
startup before OI3 ran:

```text
vlib_worker_thread_initial_barrier_sync_and_release: worker thread deadlock
libvpppoc.so: received signal SIGABRT
```

The failure happened in VPP's initial worker barrier before the OI3 plugin path,
so it is not evidence against the same-owner tail fix.  It is recorded as the
separate repeat-start lifecycle risk VPN-F076.

### Repeat-start controls S242/S243/S244

S242 one-cell smoke immediately after the S241 abort passed OI3 `4/4`, proving
the device/runtime was not permanently corrupted.

S243
`evidence/s243-f074-product-oi3-repeat-start-20260826/`
(`runId=20260826-103856-338554`) ran OI3-only repeat-start with 8 repeats and
4 requests per repeat.  All eight cells passed; p99 was
`22/23/78/74/75/75/79/69ms`, total CPU ticks stayed `123--130`, and cleanup was
`8/0`.

S244
`evidence/s244-e2-count64-tail-fix-f074-product-repeat-20260826/`
(`runId=20260826-104636-405379`) reran the full S241 count64 Direct/OI3 shape.
All ten cells passed with `failureCount=0`.  OI3 results:

| Cell | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | --- | --- |
| OI3 r1 | `64/64` | `17 / 33 / 65` | `200` | `144` | `68/0` | `1` |
| OI3 r2 | `64/64` | `19 / 26 / 76` | `214` | `150` | `68/0` | `1` |
| OI3 r3 | `64/64` | `20 / 27 / 70` | `206` | `144` | `68/0` | `1` |
| OI3 r4 | `64/64` | `16 / 21 / 77` | `194` | `139` | `68/0` | `1` |
| OI3 r5 | `64/64` | `17 / 63 / 82` | `201` | `143` | `68/0` | `1` |

S244 logs also contain `oi3 deferred-owner-drive ... reason=same-owner-rearm`,
showing that the new same-owner path was exercised in the valid run.

### F076 clean repeat-start follow-up

F076 clean-single follow-up
`evidence/f076-oi3-repeat-start-20260826-clean-single/`
(`runId=20260826-142410-470543`) reran the OI3-only repeat-start shape with 8
repeats and 4 requests per repeat after clearing all host runners, fixture
ports, the Android VPN service, and device-side VPP residue.  All eight cells
passed with `failures=0`:

| Cell | Requests | p50 / p95 / p99 ms | total CPU ticks | Cleanup | Valid |
| --- | ---: | ---: | ---: | --- | --- |
| OI3 r1 | `4/4` | `14 / 74 / 74` | `93` | `8/0` | `1` |
| OI3 r2 | `4/4` | `17 / 60 / 60` | `91` | `8/0` | `1` |
| OI3 r3 | `4/4` | `15 / 21 / 21` | `88` | `8/0` | `1` |
| OI3 r4 | `4/4` | `11 / 27 / 27` | `90` | `8/0` | `1` |
| OI3 r5 | `4/4` | `12 / 26 / 26` | `89` | `8/0` | `1` |
| OI3 r6 | `4/4` | `21 / 69 / 69` | `89` | `8/0` | `1` |
| OI3 r7 | `4/4` | `15 / 71 / 71` | `89` | `8/0` | `1` |
| OI3 r8 | `4/4` | `17 / 69 / 69` | `89` | `8/0` | `1` |

Two earlier same-hour attempts are invalid and must not be promoted to F076
evidence:

- `evidence/s172-f076-repeat-20260826-rerun/`
  (`runId=20260826-141352-810266`) was launched by a delegated agent and was
  still running after the agent was interrupted.
- `evidence/f076-oi3-repeat-start-20260826-mainline/`
  (`runId=20260826-141519-908345`) was launched while the first runner still
  owned the same Android package/VPN/log state.

The two concurrent runners shared `com.sakamoto.snort.vpnlite`, the same remote
`app-http-probe.log`, VPN service, and fixture space.  Their alternating
`startupValid=0` / missing `app-http-probe.log` rows are classified as
`HARNESS_DEFECT` caused by concurrent runner contamination, not as VPP
initial-barrier evidence and not as OI3 dataplane failure.

## Interpretation

The S237 count64 p99 tail is closed for the tested post-F074 foreground
Direct/OI3 count64 shape.  The same-owner deferred re-arm correction removes
the observed `879ms` OI3 p99 tail while preserving cleanup, correctness, and
post-F074 CPU behavior.

The S241 VPP initial-barrier abort remains a recorded low-frequency lifecycle
risk, but S242/S243/S244 and the F076 clean-single follow-up did not reproduce
it.  It is not currently the active blocker for this tail-fix candidate; it
should remain a repeat-start regression condition for future runtime/lifecycle
work.

This still does not close EG-17 release evidence or ADR-0007 release
performance.  Main-stack seam work is no longer blocked on broader historical
POC performance tuning: the 2026-08-26 disposition narrows HEV/tun-poc to
small-control and historical reference evidence, treats p99/tail as a POC
Performance Guardrail rather than a release SLO, and defers broader
throughput/capacity, thermal, power, and soak until the real product Direct
Egress seam and driver exist.

## Next step

Use S244 as the current count64 tail-fix regression evidence for Direct/OI3.
Do not import the throwaway POC runner or APK as product code.  If main-stack
work begins, import the behavior at the owner-inline Flow Stack shard seam:
same-owner re-arm must be driven locally and bounded; frame-queue handoff is
only for cross-owner scheduling.
