# S153 E1 residual device-state and lifecycle resource trend

Date: 2026-08-26
Status: `PRE_REGISTERED_NOT_EXECUTED`

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
wrapper, fresh ports, and explicit cleanup control before ordinary product
stop.

Any ADB/WSL transport, package/permission, underlay, fixture, or missing-log
failure is classified separately as `INVALID_ENVIRONMENT` or
`HARNESS_DEFECT`; it is never a target resource trend.

## Pre-registered sequence

The sequence is fixed before execution and has no adaptive retries of valid
target cells:

| Phase | Registered cells | Required observation |
| --- | --- | --- |
| `resource-foreground` | S170 runner, 5 cycles, four-owner UDP closed echo, fresh source-port range | exact echo; per-cycle OI3 cleanup; App/VPP/HEV fd, thread, RSS snapshots; internal owner/buffer/credit/route ledgers; no process/TUN/rule residue |
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

## Results

Execution results, hashes, trend calculations, state snapshots, and any
finding-ledger entries are appended after the registered sequence completes.
