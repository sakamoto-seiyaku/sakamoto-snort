# S147 B2 Failure-Semantics Execution Journal

Date: 2026-08-24
Device: Pixel 6a (`28201JEGR0XPAJ`), Android 16
VpnLite APK: `cb921108bf88b8a9ae77818378547bd11b3fa77fb7e0680191465e501820963e`
OI3 plugin: `b1a2f018180fb5b79d322c02b32340aa7e6bc924e038b345363ef1660cea8a6c`
HEV arm64: `88cc920e6aca9bf1b999372d40fc895077208ea545d918ac2b22471eeabffc04`

## Build and deployment gates

- Added cell-aware native cleanup classification and TUN-deadline timeout
  handling in `owner_inline_oi3.c`.
- App probe now records explicit expected transport/timeout/drop outcomes.
- Added `verify-s146-b2.py` and four host regression tests; all passed.
- Reapplied the overlay to the actual VPP build source before the final build.
- Android VPP plugin arm64 build passed with `CCACHE_DISABLE=1`.
- APK build and streamed install passed.

## Final Pixel matrix

Each row was run in a fresh VpnLite session.  App and native records are
durable files under `run-as com.sakamoto.snort.vpnlite`; all rows ended with
zero VPP buffer residue.

| Cell | App result | Native terminal evidence | Verdict |
| --- | --- | --- | --- |
| `refused` | `EXPECTED_TRANSPORT_FAILURE`, sent 22, received 0 | `PASS_EXPECTED_FAILURE`, `EXPECTED_TRANSPORT_REFUSAL`, `output=1`, `handshake=1`, `direct=0`, `rewritten=1`, `endpoint=0/0`, `broker=1/1`, `transport-failures=1`, `buffers=5/5`, `residue=0` | PASS |
| `no-reply` | `EXPECTED_NO_REPLY_TIMEOUT`, sent 22, received 0 | `PASS_EXPECTED_FAILURE`, `EXPECTED_TIMEOUT`, `output=0`, `direct=0`, `rewritten=0`, `endpoint=1/0`, `broker=1/1`, `transport-failures=0`, `buffers=5/5`, `residue=0` | PASS |
| `policy-drop` | `EXPECTED_POLICY_DROP_NO_TRANSPORT`, sent 22, received 0 | `PASS_EXPECTED_FAILURE`, `EXPECTED_POLICY_DROP`, `output=0`, `direct=0`, `rewritten=0`, `endpoint=0/0`, `broker=0/0`, `transport-failures=0`, `infrastructure-failures=0`, `buffers=1/1`, `residue=0` | PASS |
| `tcp4` control | `OK`, sent 22, received 22 | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=3`, `handshake=1`, `direct=3`, `rewritten=3`, `endpoint=1/1`, `broker=1/1`, `buffers=827/827`, `residue=0` | PASS |
| `udp6` control | `OK`, sent 22, received 22 | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=1`, `direct=1`, `rewritten=1`, `endpoint=1/1`, `broker=1/1`, `buffers=4/4`, `residue=0` | PASS |
| `tcp6` control | `OK`, sent 22, received 22 | `PASS`, `EXPECTED_DIRECT_REPLY`, `output=3`, `handshake=1`, `direct=3`, `rewritten=3`, `endpoint=1/1`, `broker=1/1`, `buffers=291/291`, `residue=0` | PASS |

## Closure boundary

S146 is closed for the POC.  This closes the negative-result contract for the
controlled full-TUN seam; it does not claim production timeout constants,
whole-device external failure coverage, or completion of C/D/E.
