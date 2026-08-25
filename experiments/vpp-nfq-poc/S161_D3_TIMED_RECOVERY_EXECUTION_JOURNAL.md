# S161 D3 timed overload/recovery closure

Date: 2026-08-24
Status: `CLOSED_FOR_TESTED_UDP_ENVELOPE`
Scope: Pixel `vpp-oi3-multi`, final two-owner OI3 artifact, HEV submit
backpressure, owner-local overload, post-pressure recovery

## Decision

The D3 gate is closed for the registered bounded IPv4/UDP pressure envelope.
The earlier S160 recovery attempt was not a code failure: its recovery probe
was issued while the four `repeat=16` Android pressure commands were still
emitting packets.  S161 adds the missing completion barrier and reruns the
same artifact with the recovery probe only after all 64 offered packets have
been emitted.

No new hotspot was reproduced in the corrected sequence.  E1/E2 may proceed;
they remain subject to their own resource/performance gates.

## Matched artifact

- Device: `28201JEGR0XPAJ` (Pixel 6a, Android 16)
- VPP core: `b7917ff34897ca731ba2a800b7c04762ec27feb3a0f9bf6688572a1a53acc132`
- OI3 plugin: `282ec14d1d6628a42c1141ce393742222e8a5aa780edc999a8ee4a5dbbcbdaf5`
- APK: `292e6a0a9ffe7d2122c6c06da3adf10b6aa6fdf8746a57ac45973d90d1993d91`
- HEV arm64 library: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`
- Underlay handle: `432902426637`
- Controlled recovery endpoint: WSL2 `192.168.4.5:5353` (`example.com` DNS fixture)

## Pressure and recovery result

Four concurrent AppA `EMIT` intents used the same IPv4/UDP tuple
`10.111.0.2:47004 -> 1.1.1.1:53`, each with `repeat=16`.  The app evidence
contains exactly 64 records for each stage (`D3-S161-timed-burst-1..4`).
The runner waited for the complete 16-second repeat window before starting the
recovery probe.

| VPP generation | Result | HEV submit rejects | Buffers | Residue | Re-armed |
| ---: | --- | ---: | ---: | ---: | --- |
| 1 | `PASS` (ambient TCP direct reply) | 0 | 22/22 | 0 | yes |
| 2 | `PASS_EXPECTED_OVERLOAD` | 2 | 37/37 | 0 | yes |
| 3 | `PASS_EXPECTED_OVERLOAD` | 10 | 62/62 | 0 | yes |
| 4 | `PASS_EXPECTED_OVERLOAD` | 8 | 89/89 | 0 | yes |
| 5 | `PASS_EXPECTED_OVERLOAD` | 1 | 109/109 | 0 | yes |
| 6 | `PASS` (controlled recovery) | 0 | 113/113 | 0 | yes |

Every overload generation had `broker=1/1`, no transport or infrastructure
failure, and an exact credit-ledger settlement.  The recovery B1 probe used
source port `47005` and received a valid 45-byte DNS response:

```text
return_outcome=dns_response_received
return_received=true
response_valid=true
```

The matching VPP cleanup is `generation=6 ... output=1 direct=1 rewritten=1
... buffers=113/113 residue=0`.

## Ambient-flow and Android 16 boundaries

The source now classifies the unrelated full-route TCP/5228 no-reply outcome
as `PASS_EXPECTED_AMBIENT_TIMEOUT` when it has the expected handshake/output
shape; it no longer stops the shared owner.  S161 also verified the Android 16
LAN return preflight: after disabling `RESTRICT_LOCAL_NETWORK`, granting
`NEARBY_WIFI_DEVICES`, and rebooting, a same-UID WSL2 UDP echo and the baseline
WSL2 DNS B1 both returned successfully.  These are run-validity conditions,
not product policy claims.

## Evidence

- VPP stdout: [`evidence/s161-d3-timed-recovery/vpp-stdout.log`](evidence/s161-d3-timed-recovery/vpp-stdout.log)
  SHA-256 `9c7eb8aa924816e0302a19acb0d156792de65d1c527d4ea2850d3dde7848816e`
- AppA pressure JSONL: [`evidence/s161-d3-timed-recovery/appa-a2-runtime.jsonl`](evidence/s161-d3-timed-recovery/appa-a2-runtime.jsonl)
  SHA-256 `e14c53e3c386cb54070dc8fed275fb08f9e287b94bc1771fbf7fed96b2c79e80`
- Recovery B1 JSONL: [`evidence/s161-d3-timed-recovery/appa-b1-runtime.jsonl`](evidence/s161-d3-timed-recovery/appa-b1-runtime.jsonl)
  SHA-256 `6dce4e149cb1eb8262c791fa0fa8c7fbdc14c0527eb45de80a2c64f6656d2fe2`

## Non-claims

This closes only the registered bounded UDP overload/recovery cell.  It does
not establish production capacity, infinite soak, four-worker Android
scaling, arbitrary public endpoint availability, or the E1/E2 engineering
envelope.
