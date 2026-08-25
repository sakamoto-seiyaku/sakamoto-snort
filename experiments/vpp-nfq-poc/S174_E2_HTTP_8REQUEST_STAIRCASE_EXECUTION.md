# S174 E2 HTTP 8-request staircase execution

Date: 2026-08-25

Status: `PASS_FOR_BOUNDED_8REQUEST_HTTP_STAIRCASE_SLICE`

Scope: Pixel `vpp-oi3-multi` and matched Direct/HEV/OI3 foreground HTTP
staircase against the WSL2 LAN fixture `192.168.4.5`, using the final S173 APK
and OI3 deferred-successor plugin.

S174 extends the S173 four-request closure to a bounded eight-request
foreground HTTP staircase. It is not a throughput, concurrency, CPU/thermal,
Doze, long-soak, or final EG-17 performance verdict.

## Run validity

- Device: Pixel 6a `28201JEGR0XPAJ`, Android 16.
- Package: `com.sakamoto.snort.vpnlite`, UID `12628`.
- APK SHA-256:
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`.
- OI3 plugin SHA-256:
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`.
- HEV owner-context library SHA-256:
  `37481673d6547c5f2a178de04bf4c4b5f60ba6ce1bed7c7cba1cd22b606ac96d`.
- `tun_poc` plugin SHA-256:
  `4f5608a631215a622b60bb72026edb6a8743011ed2c7d5ede9e1243a3844b0cd`.
- Physical underlay: Wi-Fi handle `437197393933`, NOT_VPN, device address
  `192.168.4.151/24`.
- HTTP fixture was runner-owned and bound on `0.0.0.0`; run manifests recorded
  the exact fixture port and GET count.

## Accepted evidence

OI3-only evidence directory:
[`evidence/s174-e2-http-8request-oi3-20260825/`](evidence/s174-e2-http-8request-oi3-20260825/)

- Run ID: `20260825-144710-417439`
- Parameters: `arms=oi3`, `repeats=3`, `durationSeconds=45`,
  `maxRequests=8`, `requestIntervalMs=0`
- CSV:
  [`cells-20260825-144710-417439.csv`](evidence/s174-e2-http-8request-oi3-20260825/cells-20260825-144710-417439.csv)
- Manifest:
  [`run-20260825-144710-417439-manifest.json`](evidence/s174-e2-http-8request-oi3-20260825/run-20260825-144710-417439-manifest.json)

| Cell | Requests | Successes | Errors | Content-Length completions | p50 ms | p95 ms | Cleanup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `oi3-r1` | 8 | 8 | 0 | 8 | 233 | 1630 | 12/0 |
| `oi3-r2` | 8 | 8 | 0 | 8 | 237 | 1314 | 12/0 |
| `oi3-r3` | 8 | 8 | 0 | 8 | 237 | 2594 | 12/0 |

The OI3-only manifest records `fixtureHttpGet=24` and `failureCount=0`.

Matched Direct/HEV/OI3 evidence directory:
[`evidence/s174-e2-http-8request-matched-20260825/`](evidence/s174-e2-http-8request-matched-20260825/)

- Run ID: `20260825-145127-375231`
- Parameters: `arms=direct hev oi3`, `repeats=1`, `durationSeconds=45`,
  `maxRequests=8`, `requestIntervalMs=0`
- CSV:
  [`cells-20260825-145127-375231.csv`](evidence/s174-e2-http-8request-matched-20260825/cells-20260825-145127-375231.csv)
- Manifest:
  [`run-20260825-145127-375231-manifest.json`](evidence/s174-e2-http-8request-matched-20260825/run-20260825-145127-375231-manifest.json)

| Cell | Requests | Successes | Errors | Content-Length completions | p50 ms | p95 ms | Extra |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `direct-r1` | 8 | 8 | 0 | 8 | 7 | 63 | no VPN cleanup |
| `hev-r1` | 8 | 8 | 0 | 8 | 5 | 7 | `socksConnect=8` |
| `oi3-r1` | 8 | 8 | 0 | 8 | 230 | 1603 | cleanup `12/0` |

The matched manifest records `fixtureHttpGet=16` and `failureCount=0`.

## Interpretation

S174 supports a stronger bounded HTTP construction claim than S173: with the
S173 deferred-successor design, OI3 can complete an unpaced eight-request
foreground HTTP staircase across repeated OI3-only cells and a matched
Direct/HEV/OI3 comparison cell.

The result does not reopen `VPN-F050`; deferred owner-local successor admission
is still the active correction. The remaining E2 gap is performance and
engineering envelope breadth. OI3 latency remains materially higher than the
Direct and HEV controls in this slice, with OI3 p95 around 1.3--2.6 seconds
versus Direct/HEV single- or double-digit millisecond p95 values. That is a
recorded performance boundary, not a new correctness hotspot.

## Non-claims

S174 does not prove arbitrary TCP concurrency, representative browser traffic,
IPv4/IPv6 DNS fallback, UDP behavior, CPU/thermal/power budgets, Doze or
screen-off behavior, long-soak stability, production capacity constants, or the
final ADR-0007/EG-17 performance verdict.
