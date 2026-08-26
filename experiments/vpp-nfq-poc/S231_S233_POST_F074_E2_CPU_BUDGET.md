# S231--S233 post-F074 E2 CPU-budget rerun

Date: 2026-08-26
Status: `PARTIAL_CPU_BUDGET_REPAIRED_FOR_FOREGROUND_COUNT64_128_REPEAT`

## Question

After the F074 Android VPP barrier-holdoff fix, does the same foreground
count-bounded HTTP shape that exposed OI3 worker CPU burn in S227/S228 still
show a VPP CPU/sched runaway?

## Scope

- Runner: `scripts/android-run-s172-e2-http-baseline-sample.sh`.
- Device: Pixel 6a / Android 16 / arm64-v8a.
- Fixture: WSL2/LAN HTTP fixture at `192.168.4.5:42187`.
- Arms: Direct and OI3 only.
- Excluded: HEV/tun-poc, because F073 already shows the HEV arm is not a
  valid broad comparator around the 64-request envelope.
- Artifact provenance recorded by the runners:
  - `git_revision=74217353e33dc8c8fd7d76da24d79f7217c22626`.
  - APK SHA-256 `f8bd89d310b1748244a105d66cfa2b353d4a4e9060158f8bd47d5070393f6300`.
  - OI3 plugin SHA-256
    `ab5f1ab11b020f5e49e74ed95c97ec52cf795ed99ee545f2afb950d9f8e1ce15`.

## Evidence

| Run | Arm | Requests | p50 / p95 / p99 ms | total CPU ticks | VPP CPU ticks | total sched runtime ns | VPP sched runtime ns | Cleanup |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| S231 `20260826-084531-509342` | Direct | `64/64` | `7 / 9 / 16` | `143` | `0` | `1351051814` | `0` | `0/0` |
| S231 `20260826-084531-509342` | OI3 | `64/64` | `17 / 32 / 486` | `198` | `141` | `1773100641` | `1351639464` | `68/0` |
| S232 `20260826-084721-668441` | Direct | `128/128` | `6 / 9 / 13` | `158` | `0` | `1415846457` | `0` | `0/0` |
| S232 `20260826-084721-668441` | OI3 | `128/128` | `20 / 28 / 253` | `302` | `204` | `2644077026` | `1967370453` | `132/0` |
| S233 `20260826-085408-873886` | Direct r1/r2/r3 | all `128/128` | p99 `11 / 13 / 15` | `151 / 156 / 160` | `0` | `1360768251 / 1400645943 / 1451036855` | `0` | `0/0` |
| S233 `20260826-085408-873886` | OI3 r1/r2/r3 | all `128/128` | p99 `33 / 71 / 68` | `286 / 292 / 302` | `190 / 195 / 204` | `2445945530 / 2499276322 / 2588360709` | `1791094734 / 1835900713 / 1925968239` | `132/0` |

Historical comparison:

- S228 OI3 count64 before the F074 fix passed `64/64` but recorded
  `cpuTicksDelta=3295` and `schedRuntimeNsDelta=32799922706`.
- S227 OI3 count128 before the F074 fix passed `128/128` but recorded
  `cpuTicksDelta=3326` and `schedRuntimeNsDelta=32507058071`.

## Interpretation

The F074 correction also removes the active foreground HTTP CPU/sched runaway
for the tested Direct/OI3 count64 and count128 shapes.  The old signal was a
VPP worker scheduling pathology; after `0324f92`, the same OI3 count64/count128
request envelopes stay in the low hundreds of total CPU ticks and around
`1.8--2.6s` aggregate sched runtime instead of about `32s`.

This does not close ADR-0007 or EG-17.  The OI3 p95 values are still higher
than Direct.  S231 and S232 saw one or more p99 tail spikes (`486ms` and `253ms`),
but S233's three count128 repeats did not reproduce that level of tail
(`33ms`, `71ms`, `68ms`).  The remaining tail question is therefore a
latency/tolerance and repeatability decision, not the resolved idle-worker CPU
burn.  S234--S235 cover the matching post-F074 Direct/OI3 count128
screen-off/forced-Doze cells, and S236 extends the foreground shape to
count512.  HEV baseline validity, broader throughput/capacity CPU budgets,
formal p99/tail tolerance, thermal, power, and soak remain open.

## Next step

Use S231--S233 as post-F074 regression evidence for the foreground
count-bounded CPU budget.  Continue E2 with one of these explicitly narrower
questions:

1. register and apply the S231--S236 absolute p99/tail tolerance decision;
2. decide whether HEV remains a broad matched baseline or is narrowed to small
   control cells until F073 is fixed;
3. gather broader throughput/capacity CPU plus thermal/power/soak evidence.
