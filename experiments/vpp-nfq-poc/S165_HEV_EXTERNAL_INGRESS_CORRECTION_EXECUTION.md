# S165 HEV external-ingress correction execution (2026-08-24)

Status: the S164 design hotspot is closed for the controlled IPv4/TCP
correctness arm.  E2 is reopened, but remains `INCONCLUSIVE` until the
matched performance/resource and protocol matrix is complete.

## Correction

The durable correction is
[`patches/hev-owner-context-external-ingress.patch`](patches/hev-owner-context-external-ingress.patch).
It is applied by `scripts/android-build-hev-poc7.sh`, whose marker checks are
idempotent on an already patched fixture.

- External gateway initialization enables `accept_nonlocal` and
  `external_ingress` before listener creation.
- TCP owner demux allows the port-zero listener to match only in that external
  mode; a newly accepted PCB receives the actual incoming destination port.
- UDP demux matches the explicitly marked external listener, because
  `udp_bind(port=0)` allocates a real ephemeral PCB port.  The callback-scoped
  original destination address/port is copied into the SOCKS5 UDP frame.
- Context reset and gateway teardown clear the mode, listener marker, and
  current UDP destination state.
- Ordinary owner contexts retain exact address/port matching.  The strict-owner
  negative behavior is covered by the conditional source path and static patch
  audit; a separate IPv4/IPv6 UDP negative device cell remains outstanding.

Build checks passed:

```text
rtk bash -n experiments/vpp-nfq-poc/scripts/android-build-hev-poc7.sh
rtk git diff --check
owner-context HEV: 645c97b465f3fd1f1d8f3d37c751f13f4a8edd07406f4f7b856e9c6bf8943e2e
```

The patch applied cleanly to a clean owner fixture and a repeated build on an
already patched fixture was idempotent.  The resulting diagnostic APK was
`0294916277a0108c6fcc83358a3ae9bc0c5c3706d36cbc200250c2540924b218`.

## Fresh device regression

- Device: Pixel 6a, Android 16, serial `28201JEGR0XPAJ`.
- Endpoint: WSL2 HTTP server `192.168.4.5:42083`.
- Run: one cycle through the patched HEV path; temporary server stopped after
  the cycle.

Observed result:

```text
app-http-probe: ok bytes=40 elapsedMs=8 first=HTTP/1.0 200 OK
socks_connect_count=1
socks5 client tcp -> [192.168.4.5]:42083
GET /loop-1 HTTP/1.0
cycle 1 ok
```

VPP stop counters included:

```text
rx 33 bytes 5167 tx 8 bytes 452
shim-rx 8 bytes 452 shim-tx 33 bytes 5167
parse-errors 0 read-errors 0 write-errors 0
shim-read-errors 0 shim-write-errors 0
```

The compact, binary-safe summary is
[`evidence/s165-hev-external-ingress/s165-http-loop-summary.txt`](evidence/s165-hev-external-ingress/s165-http-loop-summary.txt).
The loop stopped the app/VPP processes cleanly.  Ambient Android TCP/5228
sessions also produced expected read timeouts; they are unrelated to the
controlled LAN flow, which returned HTTP 200.

The follow-up 50-cycle owner-resolver lifecycle run completed `50/50 PASS`
against the same target shape.  The measured bounded resource envelope was:

| Process | RSS min/avg/max (KiB) | fd min/avg/max |
| --- | ---: | ---: |
| App | 174672 / 177581.7 / 178920 | 119 / 119 / 119 |
| VPP | 127696 / 127959.6 / 128284 | 24 / 24 / 24 |
| HEV | 62104 / 62223.1 / 62324 | 117 / 117 / 117 |

All 50 rounds passed HTTP/protect/cleanup checks; `failures=0`, and the
post-stop process/TUN/routing residue checks remained clean.  Raw artifacts are
[`s165-50-cycle-cycles.csv`](evidence/s165-hev-external-ingress/s165-50-cycle-cycles.csv),
[`s165-50-cycle-resource-summary.txt`](evidence/s165-hev-external-ingress/s165-50-cycle-resource-summary.txt),
and [`s165-50-cycle-run.log`](evidence/s165-hev-external-ingress/s165-50-cycle-run.log).

## Canonical packaging boundary

After the diagnostic run, the canonical APK was rebuilt and installed with no
`tun_poc` plugin.  It contains the patched HEV library and compatible OI3
plugin; its SHA-256 is
`902fcb5b618db30412855ac4b73c60c49014ad20417a6804c2bd91dee8534ad2`.
Running the generic HEV loop once against this package timed out at 5008 ms,
and VPP logged `unknown input 'tun-poc enable...'` plus `unknown input
'tun-poc'`.  That script hard-codes the temporary diagnostic plugin command,
so the attempt is a harness/fixture compatibility boundary, not a new
external-ingress failure.  The canonical package is left installed and no
VPP process remains.  A canonical-compatible E2 entry point is still required
before treating a no-tun package as a matched HEV performance sample; see
[`s165-canonical-packaging-boundary.txt`](evidence/s165-hev-external-ingress/s165-canonical-packaging-boundary.txt).

## Remaining E2 work

1. Run the matched Direct/HEV bounded samples using this corrected artifact.
2. Add IPv6 TCP/UDP and UDP destination-preservation cells, including the
   strict-owner negative cell.
3. Measure throughput, CPU/work/wakes, context switches, RSS/FD/thread trend,
   thermal/device-state behavior, and final-topology multi-owner load.
4. Update the campaign/gap/ledger records and perform the final evidence audit.
