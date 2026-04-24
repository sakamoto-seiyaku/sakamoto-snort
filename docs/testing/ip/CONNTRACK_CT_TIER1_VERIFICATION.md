# Conntrack `ct.*` Tier‑1 Verification (device‑module)

This document records how to verify `IPRULES` `ct.state/ct.direction` on a real device using the Tier‑1 controlled topology (`netns+veth`) and how to capture comparable perf baselines.

## Preconditions

- Rooted Android device (Tier‑1 prereqs): `su`, `ip`, `ip netns`, `veth`, `ping`, `nc`
- `sucre-snort` deployed and reachable via control socket (via `dev/dev-deploy.sh` + adb forward)

## Functional (Tier‑1)

Runs the conntrack functional smoke that asserts:
- outbound `ct.state=new ct.direction=orig` rule hits
- inbound `ct.state=established ct.direction=reply` rule hits
- `ct.state=new ct.direction=orig` BLOCK actually drops traffic and increments `METRICS.REASONS.IP_RULE_BLOCK`

Command:

```bash
bash tests/device/ip/run.sh --profile matrix --case conntrack_ct
```

Key knobs (optional):
- `IPTEST_UID` (default `2000`)
- `IPTEST_CT_PORT` (default `18081`)

## Perf compare (Tier‑1)

Runs `60_perf.sh` twice:
- Scenario A: `ct=off` (no ct consumers ⇒ conntrack update skipped)
- Scenario B: `ct=on` (adds a low‑priority `ct.state=invalid` rule ⇒ conntrack update on hot path)

Command:

```bash
IPTEST_PERF_CT_COMPARE=1 bash tests/device/ip/run.sh --profile perf --case perf_ct_compare
```

Notes:
- Each run prints a single `PERF_RESULT_JSON ...` line. Capture those lines for the table below.
- The embedded `preflight.summary` includes `ctRulesTotal/ctUidsTotal` so you can confirm whether ct gating is active.

## Results (fill after running)

### Device / build

| Field | Value |
|---|---|
| Date (UTC) | `2026-03-30T15:05:00Z` |
| Device model | `Pixel 6a` |
| Android build fingerprint | `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys` |
| `sucre-snort` build id | `ea9db2674ca12d05cf6d9a4009831617` |
| Notes | Tier-1 controlled topology (`netns+veth`), deployed via `dev/dev-deploy.sh`; conntrack policy path uses accept-only miss commit, and conntrack epoch TLS slot rebinding was re-verified after the reset lifetime fix. |

### Functional

| Case | Result | Notes |
|---|---:|---|
| `22_conntrack_ct.sh` | PASS | `ct.state=new ct.direction=orig` allow hit=`1`; `ct.state=established ct.direction=reply` allow hit=`20`; block phase observed `IP_RULE_BLOCK packets=3`, rule `hitPackets=3`, TCP read `count=0`. |

### Perf (`PERF_RESULT_JSON`)

| Scenario | `ctRulesTotal` | `ctUidsTotal` | samples | avg(us) | p95(us) | p99(us) | max(us) | bytes | connections | Notes |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| A (`ct=off`) | 0 | 0 | 1084 | 235 | 831 | 1535 | 2639 | 20000000 | 0 | No ct consumers; gating confirmed off by preflight. |
| B (`ct=on`) | 1 | 1 | 1162 | 241 | 895 | 1919 | 5873 | 20000000 | 0 | One low-priority ct consumer rule installed; preflight confirms conntrack gating engaged for one UID. |

Interpretation:
- This single-run compare primarily verifies functional gating (`ctRulesTotal/ctUidsTotal`) and that the perf path remains healthy on device.
- The observed latency delta remains small for this run (`avg +6us`, `p95 +64us`, `p99 +384us`), so it should not be treated as a stable perf claim.
