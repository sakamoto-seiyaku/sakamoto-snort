# S192 E2 matched HTTP device-state execution

Date: 2026-08-26
Status: `PASS_CORRECTNESS_WITH_E2_PERFORMANCE_GAP`

## Question

After A2, B2, D, and S153/E1 closure, can the current final OI3 artifact carry
a matched Direct / HEV / OI3 HTTP shape while the device is screen-off and in
forced-Doze, with valid app responses, explicit OI3 cleanup, resource snapshots,
and device-state proof?

This is a bounded E2 device-state comparison slice.  It is not production
performance certification, arbitrary browser traffic, a long soak, or a final
ADR-0007 pass by itself.

## Runner corrections before accepted evidence

S172 was extended to support `DEVICE_STATE=foreground|screen-off|forced-doze`.
Each cell now records `dumpsys power`, `dumpsys deviceidle`, thermal and battery
state, and `stateValid` is part of the CSV validity gate.  The runner applies
screen-off or forced-Doze after the app HTTP probe starts, recovers/wakes the
device after each cell, and records wake state.

The first screen-off attempt
`evidence/s192-e2-http-device-state-screenoff-20260826/`,
`runId=20260826-040401-071118`, stopped after APK install because the runner
sent a `dumpsys connectivity | grep -E ...` pipeline through the Windows ADB
wrapper.  That is a harness defect: `cmd.exe` split the regex pipe and reported
`'TRANSPORT_VPN' is not recognized`.  S171/S172 validity dumps now pull raw
device output and filter on the WSL host.

## Artifact

The accepted S192 comparison APK is a test comparison artifact, not the
canonical production APK.  It carries the current OI3 plugin and owner-context
HEV library plus `tun_poc_plugin.so` for the HEV baseline arm.

- APK:
  `c943d32e3eec0d0281d60dae2acd9af6455eecadbaab81657ce056049c5b8678`
- OI3 plugin:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context library:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`
- `tun_poc_plugin.so`:
  `d919117842eb41b6924693f7b79a2d20ee6ce22f8ab371b7995039c38b46d9bc`
- Device: Pixel 6a `28201JEGR0XPAJ`, Android 16
- Fixture: WSL2 LAN HTTP fixture on `192.168.4.5`

Both accepted runs record installed APK/native-library hash joins in their
`run-validity-*.txt` files.

## Accepted evidence

### Screen-off

Evidence:

```text
evidence/s192-e2-http-device-state-screenoff-20260826/
```

Run ID: `20260826-040544-466075`

Parameters: `ARMS="direct hev oi3"`, `MAX_REQUESTS=8`,
`REQUEST_INTERVAL_MS=1500`, `DURATION_SECONDS=24`,
`DEVICE_STATE=screen-off`.

| Arm | Requests | Successes | Errors | stateValid | p50 ms | p95 ms | p99 ms | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `direct` | 8 | 8 | 0 | 1 | 73 | 77 | 77 | 0/0 | 1 |
| `hev` | 8 | 8 | 0 | 1 | 17 | 23 | 23 | 0/0 | 1 |
| `oi3` | 8 | 8 | 0 | 1 | 1281 | 2604 | 2604 | 12/0 | 1 |

The manifest records `fixtureHttpGet=16` and `failureCount=0`.  Every cell's
screen-off state file records `mScreenOn=false` and a dozing/asleep wakefulness
state, and every wake file records return to `Awake`.

### Forced-Doze

Evidence:

```text
evidence/s192-e2-http-device-state-forced-doze-20260826/
```

Run ID: `20260826-040857-293622`

Parameters: `ARMS="direct hev oi3"`, `MAX_REQUESTS=8`,
`REQUEST_INTERVAL_MS=1500`, `DURATION_SECONDS=24`,
`DEVICE_STATE=forced-doze`.

| Arm | Requests | Successes | Errors | stateValid | p50 ms | p95 ms | p99 ms | Cleanup | Valid |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- | ---: |
| `direct` | 8 | 8 | 0 | 1 | 72 | 81 | 81 | 0/0 | 1 |
| `hev` | 8 | 8 | 0 | 1 | 17 | 20 | 20 | 0/0 | 1 |
| `oi3` | 8 | 8 | 0 | 1 | 729 | 2618 | 2618 | 11/0 | 1 |

The manifest records `fixtureHttpGet=16` and `failureCount=0`.  Every
forced-Doze state file records `mState=IDLE` and `mScreenOn=false`; wake files
record return to `Awake`.

## Interpretation

S192 closes the missing E2 device-state correctness slice for this matched HTTP
shape: Direct, HEV, and OI3 all completed the registered requests under
screen-off and forced-Doze, and OI3 settled with exact cleanup and no process,
TUN, or rule residue.

S192 does not close ADR-0007 E2 performance feasibility.  The same accepted
cells preserve the existing performance boundary: OI3 p95/p99 latency is about
2.6 seconds while Direct and HEV stay in the tens of milliseconds.  This is not
a transport correctness, cleanup, UID, policy, or device-state failure, but it
does fail the registered comparative E2 performance gate.

## Result

The E2 evidence now supports correctness and bounded device-state operation for
the tested final OI3 route, but the campaign cannot state
`SUPPORTS_BASELINE`.  The final audit must be `ADJUSTMENT_REQUIRED` until the
OI3 latency/cost gap is explained and corrected, or the architecture route is
explicitly revised.
