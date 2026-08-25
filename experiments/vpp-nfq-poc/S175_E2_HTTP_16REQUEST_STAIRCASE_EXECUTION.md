# S175 E2 HTTP 16-request staircase execution

Date: 2026-08-25

Status: `PASS_FOR_BOUNDED_16REQUEST_HTTP_STAIRCASE_SLICE`

Scope: Pixel `vpp-oi3-multi` and matched Direct/HEV/OI3 foreground HTTP
staircase against the WSL2 LAN fixture `192.168.4.5`, using the final
S173/S174 artifact.

S175 extends S174 from eight to sixteen unpaced foreground HTTP requests. It is
still a bounded construction and correctness slice, not a final E2 performance,
capacity, CPU/thermal, Doze, long-soak, or ADR-0007 verdict.

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
- Fixture bind: `0.0.0.0`; endpoint `192.168.4.5:42187`.
- Request shape: `maxRequests=16`, `requestIntervalMs=0`.

## Accepted evidence

OI3-only evidence directory:
[`evidence/s175-e2-http-16request-oi3-20260825/`](evidence/s175-e2-http-16request-oi3-20260825/)

- Run ID: `20260825-150115-968569`
- Parameters: `arms=oi3`, `repeats=3`, `durationSeconds=30`
- CSV:
  [`cells-20260825-150115-968569.csv`](evidence/s175-e2-http-16request-oi3-20260825/cells-20260825-150115-968569.csv)
- Manifest:
  [`run-20260825-150115-968569-manifest.json`](evidence/s175-e2-http-16request-oi3-20260825/run-20260825-150115-968569-manifest.json)

| Cell | Requests | Successes | Errors | Content-Length completions | p50 ms | p95 ms | Cleanup |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `oi3-r1` | 16 | 16 | 0 | 16 | 237 | 2598 | 20/0 |
| `oi3-r2` | 16 | 16 | 0 | 16 | 236 | 1378 | 20/0 |
| `oi3-r3` | 16 | 16 | 0 | 16 | 234 | 2521 | 20/0 |

The OI3-only manifest records `fixtureHttpGet=48` and `failureCount=0`.

Matched Direct/HEV/OI3 evidence directory:
[`evidence/s175-e2-http-16request-matched-20260825/`](evidence/s175-e2-http-16request-matched-20260825/)

- Run ID: `20260825-150431-029771`
- Parameters: `arms=direct hev oi3`, `repeats=3`, `durationSeconds=30`
- CSV:
  [`cells-20260825-150431-029771.csv`](evidence/s175-e2-http-16request-matched-20260825/cells-20260825-150431-029771.csv)
- Manifest:
  [`run-20260825-150431-029771-manifest.json`](evidence/s175-e2-http-16request-matched-20260825/run-20260825-150431-029771-manifest.json)

| Cell | Requests | Successes | Errors | Content-Length completions | p50 ms | p95 ms | Extra |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `direct-r1` | 16 | 16 | 0 | 16 | 7 | 18 | no VPN cleanup |
| `hev-r1` | 16 | 16 | 0 | 16 | 4 | 8 | `socksConnect=16` |
| `oi3-r1` | 16 | 16 | 0 | 16 | 239 | 1648 | cleanup `20/0` |
| `direct-r2` | 16 | 16 | 0 | 16 | 7 | 18 | no VPN cleanup |
| `hev-r2` | 16 | 16 | 0 | 16 | 4 | 12 | `socksConnect=32` |
| `oi3-r2` | 16 | 16 | 0 | 16 | 238 | 1833 | cleanup `20/0` |
| `direct-r3` | 16 | 16 | 0 | 16 | 7 | 63 | no VPN cleanup |
| `hev-r3` | 16 | 16 | 0 | 16 | 6 | 10 | `socksConnect=48` |
| `oi3-r3` | 16 | 16 | 0 | 16 | 235 | 1656 | cleanup `20/0` |

The matched manifest records `fixtureHttpGet=96` and `failureCount=0`.

## Verification

- S170/S171/S172 static verifier set: `19 passed`.
- Runner shell syntax and S175 manifest/CSV static checks passed.
- No `valid=0`, `errors>0`, cleanup `FAIL`, `SocketTimeoutException`, or
  manifest `failureCount>0` marker was present in the accepted S175 summaries.
- The run was stopped after the 16-request matched slice. Further request-count
  pressure would be a new capacity/performance exploration, not required to
  close this bounded slice.

## Interpretation

S175 further strengthens the bounded HTTP staircase construction: OI3 completed
sixteen unpaced foreground HTTP requests in three OI3-only repeats and in three
matched Direct/HEV/OI3 repeats. This does not reopen `VPN-F050`; the
deferred-successor owner-local admission design remains valid for this bounded
request-count ladder.

The same performance boundary remains visible. Direct and HEV p95 values stayed
below 100 ms in these cells, while OI3 p95 stayed around 1.3--2.6 seconds. That
is not a correctness hotspot, but it remains material evidence for the still
open EG-17 performance/resource envelope.

## Non-claims

S175 does not prove arbitrary TCP concurrency, production throughput/capacity,
representative browser/multi-app traffic, IPv4/IPv6 DNS fallback, UDP behavior,
CPU/thermal/power budgets, Doze or screen-off behavior, long-soak stability, or
the final ADR-0007/EG-17 performance verdict.
