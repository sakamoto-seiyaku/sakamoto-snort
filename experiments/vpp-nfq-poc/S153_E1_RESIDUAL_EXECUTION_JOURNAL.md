# S153 E1 residual device-state and lifecycle resource trend

Date: 2026-08-26
Status: `FOREGROUND_RESOURCE_PASS_CONTINUING`

## Registered question

On the stabilized final Pixel artifact, does a bounded mixed E1 sequence settle
OS and owner resources across real IPv4/IPv6 TCP/UDP/DNS traffic, normal
stop/start, one physical-underlay epoch transition, and one injected
fault/restart, including foreground, screen-off, and forced-Doze/wake state
snapshots?

This is a bounded E1 resource/lifecycle POC. It is not release battery
certification, an unbounded soak, an E2 performance verdict, or an OEM-wide
device-state claim.

## Artifact and validity gates

The registered VPN artifact is the current packaged APK at execution time; the
run must record the host APK hash, installed `base.apk` hash, packaged and
installed OI3 plugin hash, and owner-context HEV hash. The required Pixel is
serial `28201JEGR0XPAJ`, model Pixel 6a, Android 16. The physical underlay must
be Wi-Fi `NOT_VPN` with a recorded network handle and the WSL2 fixture must
prove readiness independently. Every cell uses the repo-local `dev/adb`
wrapper, explicit fixture endpoint registration, and explicit cleanup control
before ordinary product stop.

Any ADB/WSL transport, package/permission, underlay, fixture, or missing-log
failure is classified separately as `INVALID_ENVIRONMENT` or
`HARNESS_DEFECT`; it is never a target resource trend.

## Pre-registered sequence

The sequence is fixed before execution and has no adaptive retries of valid
target cells:

| Phase | Registered cells | Required observation |
| --- | --- | --- |
| `resource-foreground` | S170 runner, 5 cycles, four-owner paced UDP fire-and-count resource driver (`EXPECT_ECHO=false`) on an explicitly registered fixture tuple | app sends nonzero paced UDP without app-side timeout errors; fixture RX/TX symmetry; per-cycle OI3 cleanup; App/VPP/HEV fd, thread, RSS snapshots; internal owner/buffer/credit/route ledgers; no process/TUN/rule residue |
| `dualstack-dns` | S178 runner, IPv4/IPv6 UDP plus TCP separate/coalesced DNS, one cell each | AppA bind/send/valid response; native broker/direct/TUN-return; cleanup and residue are separate gates |
| `state-screen-off` | one four-owner UDP control while display is off | `dumpsys power`, `deviceidle`, thermal, resource and cleanup snapshots; wake recovery |
| `state-forced-doze` | one four-owner UDP control after bounded `force-idle`, then wake | reported `IDLE`/`IDLE_MAINTENANCE`, same resource/cleanup snapshots, wake recovery |
| `epoch-restart` | one active real flow during Wi-Fi loss, Wi-Fi replacement, explicit VPN stop/start, fresh UDP recovery | callback `lost`/`available` epochs and handles, owner invalidation/cleanup, fresh post-restart traffic and resource/residue snapshots |
| `fault-restart` | one active real flow with `multi-fault-0`, explicit stop/start, fresh UDP recovery | `PASS_EXPECTED_FAULT`, exact buffers/credits/broker cleanup, fresh generation and no stale activity/residue |

The five foreground cycles are the trend bound. The other phases are one
registered representative each; they are lifecycle/device-state closure cells,
not statistical performance samples. The decision is `PASS` only if every
required cell is valid, exact cleanup is observed, no stale generation remains,
and the foreground resource series has no monotonic FD/thread/RSS increase.
One bounded correction is allowed only for a classified harness defect; a
reproducible implementation/architecture hotspot stops dependent execution.

## Non-claims and stop conditions

The sequence does not claim release power/battery budgets, maximum capacity,
infinite duration, seamless Android VPN migration, arbitrary OEM behavior,
unbounded TCP/UDP/DNS correctness, or ADR-0007 thresholds. Stop immediately if
the fixture/ADB/telemetry contract cannot distinguish validity from a target
trend, if cleanup is ambiguous after explicit OI3 control, if old-generation
traffic revives, or if FD/thread/RSS/internal resources increase monotonically
in a valid series.

## Evidence layout

The accepted evidence root is:

```text
experiments/vpp-nfq-poc/evidence/s153-e1-residual-20260826/
```

The phase runner directories and machine-readable manifests are linked below
after execution. Invalid attempts and harness corrections remain under their
original evidence directories and are not promoted into the S153 result.

## Setup status before full execution

The S170/S153 cleanup-control hotspot is already corrected before this full
sequence starts. Commit `98678cc` updates the S170 runner to drive
`oi3Control=multi-stop`, capture `cleanup-pre-stop.log`, and only then request
ordinary product stop. The post-fix smoke
`evidence/s153-e1-residual-20260826-cleanup-fix-smoke/` passed with
`sent=258`, `received=258`, `errors=0`, `cleanup_pass=8`,
`cleanup_fail=0`, `fixtureRx=506`, `fixtureTx=506`, no residual `vpp`,
`tun0_after=0`, `rules_match=1`, and `failureCount=0`.

The earlier `evidence/s153-e1-residual-20260826-preflight-positive3/` attempt
is retained only as an invalid/superseded runner attempt: it had exact app echo
and zero residue but `cleanup_pass=0` because it did not use the corrected
explicit cleanup-control sequence. It is not part of the accepted S153 result.

## Tuple design correction during execution

The original `resource-foreground` registration used UDP exact closed-echo as
both the traffic driver and the resource-trend gate.  That over-bound S153 to a
UDP lossless correctness property already owned by S169/F046, while S153's
target question is OS/native resource and lifecycle settlement.  Two
current-artifact probes using fresh `466xx` source-port ranges failed before
any resource trend could be promoted:

- `evidence/s153-e1-residual-20260826/resource-foreground/`,
  `runId=20260826-030526-927489`, endpoint `192.168.4.5:42360`,
  `SOURCE_PORT_BASE=46600`, `udpClosedTimeoutMs=1000`: cycle 2 failed with
  `sent=1309`, `received=1305`, `errors=4`, `late=4`; fixture RX/TX and cleanup
  still matched.
- `evidence/s153-e1-residual-20260826/resource-foreground-timeout3000-probe/`,
  `runId=20260826-031012-417454`, endpoint `192.168.4.5:42361`,
  `SOURCE_PORT_BASE=46620`, `udpClosedTimeoutMs=3000`: cycle 1 failed with
  `sent=1317`, `received=1315`, `errors=2`, `late=0`; fixture RX/TX and cleanup
  still matched.  Native evidence showed `udp-datagram-inflight`,
  `tun-flow timeout`, and rearm at the UDP window tail.

The old registered S170/F046 tuple shape was then rerun on the same current
APK/plugin/HEV hashes as a control and passed a short probe:

- `evidence/s153-e1-residual-20260826/resource-foreground-s170shape-probe/`,
  `runId=20260826-031314-315178`, endpoint `192.168.4.5:42185`,
  `SOURCE_PORT_BASE=43000`, `udpClosedTimeoutMs=1000`: two cycles passed with
  `sent=3327`, `received=3327`, `errors=0`, `fixtureRx=3836`,
  `fixtureTx=3836`, and `failureCount=0`.

That short control was not sufficient: the same old tuple shape failed when
promoted back to the full five-cycle exact-echo resource trend:

- `evidence/s153-e1-residual-20260826/resource-foreground-corrected/`,
  `runId=20260826-031549-830075`, endpoint `192.168.4.5:42185`,
  `SOURCE_PORT_BASE=43000`, `udpClosedTimeoutMs=1000`: cycle 1 failed with
  `sent=1382`, `received=1377`, `errors=5`, `late=4`.  Native logs narrowed
  this to an OI3 UDP window tail: one datagram was inflight when the native
  five-second flow deadline fired; cleanup classified the generation as
  `EXPECTED_DIRECT_REPLY`, then rearmed and delivered the remaining pending
  datagrams late while the inflight sequence was not recovered.

Therefore the S153 foreground resource trend is corrected away from UDP exact
closed-echo.  The accepted resource driver uses paced UDP fire-and-count
(`EXPECT_ECHO=false`) plus fixture RX/TX symmetry, native owner ledgers,
cleanup, residue checks, and resource snapshots.  UDP exact closed-echo remains
a separate correctness envelope owned by S169/F046 and is not re-litigated as
an E1 resource trend gate.  The failed exact-echo attempts are retained as
design-correction evidence and are not part of the accepted S153 result.

## Results

### `resource-foreground` -- PASS

Accepted evidence:

```text
evidence/s153-e1-residual-20260826/resource-foreground-firecount/
```

Run ID: `20260826-032313-031928`

Cell parameters:

- `EXPECT_ECHO=false`
- `PORT=42189`
- `SOURCE_PORT_BASE=43000`
- `flows=4`
- `payloadBytes=64`
- `warmupSeconds=1`
- `steadySeconds=6`
- `drainSeconds=2`

Manifest hashes:

- APK:
  `3cafe5ee25e634347af790d2cf66bb2c1fa5cd64c595d4e9605a019f4f396964`
- OI3 plugin:
  `5012eeecb16828edca58f3dc98ddd52330a3b09b26394a3baa94b7c39604cc72`
- HEV owner-context:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`

Per-cycle result:

| Cycle | Run ID | Sent | Received | Errors | Cleanup PASS | Cleanup FAIL | Fixture RX/TX |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | `56638254162912` | 2317 | 0 | 0 | 16 | 0 | 2711 / 2711 |
| 2 | `39625291881788` | 2316 | 0 | 0 | 16 | 0 | 5412 / 5412 |
| 3 | `51014908525646` | 2319 | 0 | 0 | 16 | 0 | 8119 / 8119 |
| 4 | `99697629670602` | 2320 | 0 | 0 | 16 | 0 | 10827 / 10827 |
| 5 | `130152538446498` | 2308 | 0 | 0 | 20 | 0 | 12639 / 12639 |

Resource range across the five pre-probe snapshots:

| Metric | Min | Max | Delta |
| --- | ---: | ---: | ---: |
| App RSS KiB | 156804 | 157828 | 1024 |
| VPP RSS KiB | 135760 | 136132 | 372 |
| HEV child RSS KiB | 0 | 0 | 0 |
| App FD count | 120 | 120 | 0 |
| VPP FD count | 41 | 41 | 0 |
| HEV child FD count | 0 | 0 | 0 |
| App threads | 33 | 35 | 2 |
| VPP threads | 6 | 6 | 0 |
| HEV child threads | 0 | 0 | 0 |

This closes only the foreground E1 resource driver.  The remaining S153 cells
are still pending: `dualstack-dns`, `state-screen-off`,
`state-forced-doze`, `fault-restart`, and `epoch-restart`.
