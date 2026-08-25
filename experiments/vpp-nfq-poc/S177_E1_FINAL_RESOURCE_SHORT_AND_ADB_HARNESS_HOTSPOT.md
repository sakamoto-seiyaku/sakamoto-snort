# S177 E1 final resource short run and ADB harness hotspot

Date: 2026-08-25
Status: `PASS_FOR_BOUNDED_FINAL_RESOURCE_SHORT_SLICE`

## Scope

S177 resumed E1/E2 device-state work after the S176 UDP route-pinning closure.
The target was a short final-artifact resource trend slice, not a full soak,
Doze, thermal, or ADR-0007 performance verdict.

Artifact under test:

- APK:
  `f4e350c6478ce9f495afa9b1b97f174c79915592a461aeb25d7e8cdd803e1541`
- OI3 plugin:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

## Harness hotspot

The first S177 attempts did not enter a valid resource cell:

- `s177-e1-e2-final-short-resource-20260825` stopped during APK install after
  a WSL `UtilAcceptVsock: accept4 failed 110` transport error.
- `s177-e1-final-resource-short-20260825` was interrupted before the runner
  could write a manifest.
- `s177-e1-final-resource-short2-20260825` stopped after `package_uid` with the
  same WSL/ADB transport symptom.

This was a harness/environment hotspot, not an OI3 dataplane failure.  The
runner was corrected in three bounded ways:

1. S170 provenance now records current artifact hashes by default instead of
   hard-coding the older S169 APK/plugin expected hashes.
2. `wait_vpp_ready` no longer directly greps possibly blocking VPP log paths;
   it only reads regular files through bounded `tail`.
3. `adb_read` now has a bounded retry loop for transient WSL/ADB transport
   failures while preserving the caller's `errexit` state.

Static guard:

```text
rtk bash -n experiments/vpp-nfq-poc/scripts/android-run-s170-e1-resource-trend.sh
rtk python3 -m unittest \
  experiments.vpp-nfq-poc.scripts.tests.test_verify_s170_e1_resource_trend \
  experiments.vpp-nfq-poc.scripts.tests.test_verify_s171_e2_oi3_direct_sample
```

The final static run passed 10 tests.

## Accepted run

Evidence directory:

```text
experiments/vpp-nfq-poc/evidence/s177-e1-final-resource-short3-20260825/
```

Command shape:

```text
RESULT_DIR=experiments/vpp-nfq-poc/evidence/s177-e1-final-resource-short3-20260825
APK=experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/snort-vpn-lite-debug.apk
CYCLES=2
STEADY_SECONDS=3
DRAIN_SECONDS=1
WARMUP_SECONDS=1
PORT=42190
SOURCE_PORT_BASE=45240
./experiments/vpp-nfq-poc/scripts/android-run-s170-e1-resource-trend.sh
```

Run ID: `20260825-163352-816347`

Result:

| Cycle | runId | sent | received | errors | app RSS KiB | VPP RSS KiB | app fd | VPP fd | app threads | VPP threads | cleanup P/F | fixture RX/TX |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 64757893398202 | 763 | 763 | 0 | 159668 | 136252 | 120 | 41 | 34 | 6 | 4/0 | 994/994 |
| 2 | 44230085700333 | 784 | 784 | 0 | 158256 | 135776 | 120 | 41 | 33 | 6 | 4/0 | 2008/2008 |

Manifest:

```text
cyclesRequested=2
cyclesRecorded=2
fixtureRx=2008
fixtureTx=2008
failureCount=0
```

Thermal/device-state snapshots in both cycles recorded `Thermal Status: 0`,
`mScreenOn=true`, `mScreenLocked=true`, and
`mState=ACTIVE mLightState=ACTIVE`.

Post-run residual checks found no `vpp` process and no root-visible `tun0`.

## Interpretation

S177 supports the final S176 artifact for a bounded foreground two-cycle
four-owner UDP resource slice.  It also closes the immediate S170/S177 harness
hotspot that was preventing valid resource evidence from being collected.

It does not close EG-17/EG-18.  Remaining work still includes broader
IPv4/IPv6 TCP/UDP/DNS coverage, matched throughput/latency/CPU comparisons,
screen-off/Doze, longer resource trend/soak, and final audit.

## 2026-08-26 recurrence: cleanup control without explicit OI3 stop

S153 later reused the S170 runner for a one-cycle E1 residual preflight.  That
run proved the same-package app-to-fixture path but failed the cleanup oracle:

```text
evidence/s153-e1-residual-20260826-preflight-positive2/
cycle=1 sent=255 received=255 errors=0 cleanup_pass=0 cleanup_fail=0
fixtureRx=501 fixtureTx=501 residual_vpp= tun0_after=0 rules_match=1
```

Root cause: the runner had a `wait_stop_cleanup_marker` helper, but it never
first drove the OI3 test-only cleanup control.  Ordinary product stop may
terminate or supervise the native child without emitting the test-only
`oi3_cleanup result=PASS` ledger.  Waiting for that marker after product stop is
therefore an invalid oracle.

The corrected runner now follows the same pattern as the later S171/S172 E2
runners:

1. send `oi3Control=multi-stop`;
2. capture `cleanup-pre-stop.log`;
3. then request ordinary product stop;
4. merge pre-stop and post-stop cleanup logs;
5. keep process/TUN/ip-rule residue checks separate from the marker count.

Post-fix smoke:

```text
evidence/s153-e1-residual-20260826-cleanup-fix-smoke/
runId=20260826-024859-356974
cycle=1 sent=258 received=258 errors=0 cleanup_pass=8 cleanup_fail=0
fixtureRx=506 fixtureTx=506 residual_vpp= tun0_after=0 rules_match=1
failureCount=0
```

Avoidance rule for future POC agents: if a cell requires native bounded cleanup
proof, product stop alone is not sufficient evidence.  Drive the explicit OI3
cleanup control first, record its durable ledger, and only then use product stop
as the Android lifecycle/residue settlement step.
