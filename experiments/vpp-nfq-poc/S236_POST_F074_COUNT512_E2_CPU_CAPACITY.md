# S236 post-F074 E2 foreground count512 CPU/capacity rerun

Date: 2026-08-26
Status: `PARTIAL_COUNT512_CPU_CAPACITY_REPAIRED_FOR_DIRECT_OI3`

## Question

After the F074 Android VPP barrier-holdoff fix, does a broader foreground
Direct/OI3 count512 HTTP shape still pass without reintroducing OI3 worker
CPU/sched runaway or cleanup failure?

## Scope

- Runner: `scripts/android-run-s172-e2-http-baseline-sample.sh`.
- Device: Pixel 6a / Android 16 / arm64-v8a.
- Fixture: WSL2/LAN HTTP fixture at `192.168.4.5:42187`.
- Arms: Direct and OI3 only.
- Excluded: HEV/tun-poc, because F073 already shows the HEV arm is not a
  valid broad comparator around the 64-request envelope.
- Count shape: `MAX_REQUESTS=512`, `REQUEST_INTERVAL_MS=0`, `REPEATS=3`,
  `DURATION_SECONDS=30`, foreground.
- Valid run: `20260826-091906-854703`.
- Ignored pre-run: `20260826-091845-628184` failed before test execution
  because sandboxed ADB was unavailable; it is not evidence for the POC.
- Artifact provenance recorded by the runner:
  - APK SHA-256 `f8bd89d310b1748244a105d66cfa2b353d4a4e9060158f8bd47d5070393f6300`.
  - OI3 plugin SHA-256
    `ab5f1ab11b020f5e49e74ed95c97ec52cf795ed99ee545f2afb950d9f8e1ce15`.
  - HEV SHA-256 `420e67e71029888c3d6423b24a513bf6ed760fd159762903f22ee4235d016466`.
  - Tun POC plugin SHA-256
    `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`.

## Evidence

Manifest: `failureCount=0`, fixture HTTP GET `3072`.

| Cell | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | total sched runtime ns | VPP sched runtime ns | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- | --- |
| Direct r1 | `512/512` | `7 / 13 / 16` | `275` | `0` | `1486159690` | `0` | `0/0` | `1` |
| OI3 r1 | `512/512` | `20 / 28 / 72` | `1015` | `648` | `8315614058` | `5996366238` | `516/0` | `1` |
| Direct r2 | `512/512` | `8 / 11 / 14` | `276` | `0` | `1413916331` | `0` | `0/0` | `1` |
| OI3 r2 | `512/512` | `20 / 28 / 106` | `1060` | `677` | `8662396779` | `6236450702` | `516/0` | `1` |
| Direct r3 | `512/512` | `7 / 9 / 14` | `291` | `0` | `1594191154` | `0` | `0/0` | `1` |
| OI3 r3 | `512/512` | `20 / 27 / 71` | `1028` | `660` | `8290621322` | `6001958110` | `516/0` | `1` |

Validity checks:

- All six rows report `stateValid=1`, `startupValid=1`, `errors=0`,
  `rulesMatch=1`, and `valid=1`.
- OI3 cleanup is `516/0` in all three repeats.
- The runner recorded local WSL2/LAN endpoint `192.168.4.5:42187`; no public
  internet target was used by this cell.

## Interpretation

S236 extends the post-F074 Direct/OI3 HTTP evidence from count128 to count512.
The selected shape remains correct and cleanup-stable.  OI3 CPU cost grows with
the larger request count but stays in a bounded envelope around `1015--1060`
total CPU ticks and `8.3--8.7s` aggregate sched runtime across three repeats,
not the pre-F074 idle-worker runaway around `32s`.

The p99 tail remains a formal tolerance question.  OI3 p99 was
`72/106/71ms`, materially higher than Direct p99 `16/14/14ms`, but not a
correctness failure, timeout, cleanup failure, or CPU-runaway recurrence.

This still does not close ADR-0007 or EG-17.  HEV baseline validity, formal
p99/tail tolerance, broader throughput/capacity beyond this bounded count512
shape, thermal, power, and long soak remain open.

## Next step

Use S236 as post-F074 foreground count512 regression evidence for Direct/OI3.
Continue E2 with:

1. a pre-registered p99/tail tolerance decision over S231--S236;
2. a HEV-baseline disposition or narrowing decision for F073;
3. broader throughput/capacity plus thermal/power/soak evidence if the
   tolerance decision still permits main-stack import.
