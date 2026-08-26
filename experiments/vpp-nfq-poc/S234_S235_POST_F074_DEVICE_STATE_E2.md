# S234--S235 post-F074 E2 device-state count128 rerun

Date: 2026-08-26
Status: `PARTIAL_DEVICE_STATE_COUNT128_REPAIRED_FOR_DIRECT_OI3`

## Question

After the F074 Android VPP barrier-holdoff fix, do the same Direct/OI3
count128 HTTP cells still pass under screen-off and forced-Doze without
reintroducing the OI3 CPU/sched runaway?

## Scope

- Runner: `scripts/android-run-s172-e2-http-baseline-sample.sh`.
- Device: Pixel 6a / Android 16 / arm64-v8a.
- Fixture: WSL2/LAN HTTP fixture at `192.168.4.5:42187`.
- Arms: Direct and OI3 only.
- Excluded: HEV/tun-poc, because F073 already shows the HEV arm is not a
  valid broad comparator around the 64-request envelope.
- Count shape: `MAX_REQUESTS=128`, `REQUEST_INTERVAL_MS=0`, `REPEATS=1`.
- Artifact provenance recorded by the runners:
  - APK SHA-256 `f8bd89d310b1748244a105d66cfa2b353d4a4e9060158f8bd47d5070393f6300`.
  - OI3 plugin SHA-256
    `ab5f1ab11b020f5e49e74ed95c97ec52cf795ed99ee545f2afb950d9f8e1ce15`.
  - HEV SHA-256 `420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466`.
  - Tun POC plugin SHA-256
    `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.

## Evidence

| Run | State | Arm | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | total sched runtime ns | VPP sched runtime ns | Cleanup | Valid |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| S234 `20260826-090709-371689` | screen-off | Direct | `128/128` | `6 / 10 / 16` | `152` | `0` | `1375235762` | `0` | `0/0` | `1` |
| S234 `20260826-090709-371689` | screen-off | OI3 | `128/128` | `19 / 28 / 71` | `336` | `229` | `2870746951` | `2149352292` | `132/0` | `1` |
| S235 `20260826-090906-200063` | forced-Doze | Direct | `128/128` | `6 / 8 / 11` | `158` | `0` | `1428650529` | `0` | `0/0` | `1` |
| S235 `20260826-090906-200063` | forced-Doze | OI3 | `128/128` | `18 / 26 / 30` | `343` | `238` | `2940605200` | `2224723879` | `132/0` | `1` |

Validity checks:

- Both manifests report `failureCount=0`.
- All rows report `stateValid=1`, `startupValid=1`, `errors=0`,
  `rulesMatch=1`, and `valid=1`.
- S234 screen-off state captured `mScreenOn=false`.
- S235 forced-Doze state captured `mState=IDLE`.

## Interpretation

The post-F074 Direct/OI3 count128 device-state cells do not reproduce the
historical seconds-level device-state cliff or the later OI3 CPU runaway.  The
bounded screen-off OI3 cell has p95/p99 `28/71ms`; the bounded forced-Doze OI3
cell has p95/p99 `26/30ms`.  CPU remains in the same low-hundreds envelope as
the S231--S233 foreground reruns.

This narrows the remaining E2 gap.  Screen-off/forced-Doze Direct/OI3 count128
coverage is no longer an active blocker for the tested shape.  This still does
not close ADR-0007 release performance or EG-17 release evidence, but under the
2026-08-26 disposition it satisfies the POC Performance Guardrail for continuing
main-stack seam work.

## Next step

Use S234--S235 as post-F074 device-state regression evidence for the Direct/OI3
count128 shape.  S236 extends the foreground shape to count512.  The
2026-08-26 disposition narrows the remaining work:

1. HEV/tun-poc is small-control and historical reference evidence only, not a
   broad matched baseline blocker.
2. p99/tail is a POC Performance Guardrail, not a release SLO; repeat severe
   tails, CPU runaway, startup invalidity, or cleanup failure reopen diagnosis.
3. broader throughput/capacity CPU plus thermal/power/soak evidence is deferred
   until the real product Direct Egress seam and driver exist.
