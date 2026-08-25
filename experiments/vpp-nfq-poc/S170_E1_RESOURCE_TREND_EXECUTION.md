# S170 E1 four-owner resource trend execution

Date: 2026-08-25

Status: `PASS_FOR_BOUNDED_POST_F046_E1_WINDOW`

Scope: Pixel `vpp-oi3-multi` on the corrected four-owner artifact, same-package
WSL2 LAN UDP echo fixture `192.168.4.5:42185`, five repeated 4-flow UDP
closed-echo generations, per-cycle stop cleanup, and app/VPP resource snapshots.

This is an E1/EG-16 resource-trend regression after VPN-F046. It is not an E2
performance result, not a soak, and not a production capacity claim.

## Run validity

- Device: Pixel 6a `28201JEGR0XPAJ`, Android 16.
- Package: `com.sakamoto.snort.vpnlite`, UID `12628`.
- APK SHA-256:
  `96726fa8e56d74e731105c71568735af338f74fcb06cc067eff00b7525b07179`.
- OI3 plugin SHA-256:
  `b97c57a853a31e0bd7451dd4216519553091954ba45412b3b3def0825dda5951`.
- HEV owner-context SHA-256:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`.
- Physical underlay: Wi-Fi handle `437197393933`, NOT_VPN, device address
  `192.168.4.151/24`.
- Same-package VPN-stopped UDP preflight passed against the exact endpoint:
  `packets=3 received=3`.
- The runner-owned host fixture was bound at `0.0.0.0:42185` and recorded
  `fixtureRx=12762 fixtureTx=12762`.
- Post-run cleanup checks: `pidof vpp` empty and host UDP `42185` had no
  listener.

The first attempted S170 run was rejected as runner-invalid before being used
as evidence: a stale external fixture was still listening on `192.168.4.5:42185`
and the runner's `pm path` provenance sed pattern let shell `$#` expansion
corrupt device member paths. The runner now owns its fixture and escapes the
device-side sed end anchor.

## Accepted evidence

Evidence directory:
[`evidence/s170-e1-resource-trend-20260825-valid/`](evidence/s170-e1-resource-trend-20260825-valid/)

Runner:
[`scripts/android-run-s170-e1-resource-trend.sh`](scripts/android-run-s170-e1-resource-trend.sh)

Run ID: `20260825-112255-922529`

Cell parameters:

- `cycles=5`
- `flows=4`
- `sourcePortBase=43000`
- `payloadBytes=64`
- `warmupSeconds=1`
- `steadySeconds=6`
- `drainSeconds=2`
- `udpClosedTimeoutMs=1000`

Per-cycle app and cleanup results:

| Cycle | Run ID | Sent | Received | Errors | Cleanup PASS | Cleanup FAIL | Fixture RX/TX |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | `13049571877470` | 2168 | 2168 | 0 | 4 | 0 | 2532 / 2532 |
| 2 | `24661175557201` | 2214 | 2214 | 0 | 4 | 0 | 5106 / 5106 |
| 3 | `108084543328518` | 2198 | 2198 | 0 | 4 | 0 | 7669 / 7669 |
| 4 | `121942597308558` | 2192 | 2192 | 0 | 4 | 0 | 10216 / 10216 |
| 5 | `134103890013440` | 2191 | 2191 | 0 | 4 | 0 | 12762 / 12762 |

Every accepted cycle had `residual_vpp` empty, `tun0_after=0`, and
`rules_match=1` after stop cleanup.

Resource range across the five pre-probe snapshots:

| Metric | Min | Max | Delta |
| --- | ---: | ---: | ---: |
| App RSS KiB | 157320 | 157968 | 648 |
| VPP RSS KiB | 596040 | 596520 | 480 |
| HEV child RSS KiB | 0 | 0 | 0 |
| App FD count | 120 | 120 | 0 |
| VPP FD count | 41 | 41 | 0 |
| HEV child FD count | 0 | 0 | 0 |
| App threads | 33 | 35 | 2 |
| VPP threads | 6 | 6 | 0 |
| HEV child threads | 0 | 0 | 0 |

VPP evidence across the accepted cycles:

- `vpp-oi3-multi` started with four owners.
- Each cycle emitted four `oi3_cleanup result=PASS` records.
- There were no cleanup `FAIL` records.
- There were no F046 `owner-busy`/multi-admission rejects in the accepted
  cycle stdout logs.

## Disposition

S170 supports EG-16 for this bounded post-F046 four-owner UDP repeat window:
five repeated final-topology 4-flow generations completed with exact app echo,
owned fixture RX/TX, stable FD/thread counts, bounded RSS variation, and clean
per-cycle teardown.

The result intentionally remains narrower than the full E batch. It does not
close matched Direct-vs-HEV E2 performance, IPv4/IPv6 TCP/UDP/DNS coverage,
screen-off/Doze behavior, thermal envelope, production capacity constants,
long soak, or the final feasibility audit.

## 2026-08-26 cleanup-control runner recurrence

S153 reused the S170 runner for a one-cycle residual preflight and reproduced a
runner-level cleanup-control gap. The data path was healthy, but the cycle
failed with `cleanup_pass=0` because the runner only requested ordinary product
stop and then waited for `oi3_cleanup` markers that product stop is not
required to emit.

Rejected pre-fix smoke:

```text
evidence/s153-e1-residual-20260826-preflight-positive2/
cycle=1 sent=255 received=255 errors=0 cleanup_pass=0 cleanup_fail=0
fixtureRx=501 fixtureTx=501 residual_vpp= tun0_after=0 rules_match=1
```

Correction:

- preserve the WSL2 remote-shell quoting fix for `dumpsys connectivity`;
- drive the test-only OI3 `multi-stop` control before ordinary product stop;
- record `cleanup-pre-stop.log` and merge it into the final per-cycle
  `cleanup.log`;
- keep the final product stop and residue gates (`pidof vpp`, `tun0_after`,
  `ip rule`) as separate settlement checks.

Post-fix smoke:

```text
evidence/s153-e1-residual-20260826-cleanup-fix-smoke/
runId=20260826-024859-356974
cycle=1 sent=258 received=258 errors=0 cleanup_pass=8 cleanup_fail=0
fixtureRx=506 fixtureTx=506 residual_vpp= tun0_after=0 rules_match=1
failureCount=0
```

This closes the S170/S153 runner hotspot only. It is not the full S153 E1
residual verdict; the larger dual-stack, stop/start, epoch, fault/restart, and
screen-off/Doze sequence still has to run against the corrected runner.
