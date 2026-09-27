# T24 pre-Flow blocked observation acceptance

[SAKAMOTO-276](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/74a66a66-7be5-425f-8761-5ab18928d4ae)
extends the VPP-native C producer, existing bounded transport, Rust consumer
and SQLite windows with a separate Blocked Observation for actual PRE policy
DROP. The [Interface contract](../interfaces/T24_BLOCKED_OBSERVATION.md) fixes
its identity, wire, errors and lifecycle. This is T24's functional and scoped
cost evidence. Retention, complete stress coverage and combined calibration
remain their separate Plane tasks T27, T29 and T30.

## Source and artifact identity

Base commit: `4f54165c659f5458d4c737c1f54c35bd127c74f8` (T23).
Final Host and Android Product source SHA-256:
`5c79abe77dffa4dd6aa9d5eadfc4f61660399a0c618356bb3fbda21ee8a39d3d`.
The final Host artifact is `build-output/product-vpp-host-t24-c`, witnessed by
`build-output/t24-20260927/linux-build-c/build.json`. The APK is witnessed by
`pixel-build-b/build.json`, with APK SHA-256
`a5a864c1c3fb7fe6df5376c6c88b03f7642f0a4af26872e99817881d7639b2ac`.
Both builds use the pinned VPP stage. The final V4 observation mapping remains
922,368 bytes per generation: the formerly unused odd owner channels carry
Blocked records without expanding the T23 ring mapping. The blocked table is
separate preallocated owner-local memory capped at 1,024 slots per owner.

All raw and failed attempts remain under `build-output/t24-20260927/`. The
`evidence-index.json` seals the final proofs, build manifests and retained
attempts. The 34 unrelated dirty files entering this ticket are checked
against T23's `preservation.json` and excluded from the T24 commit.

## Real packet and history result

| Final evidence | Result |
|---|---|
| `linux-verification-h.json` | VALID; four allowed requests and replies, 3,041 actual PRE drops; 3,049 native packet paths accounted for |
| `pixel-root-verification-b.json` | VALID; four allowed requests/replies, nine actual PRE drops and nine Blocked contributions; no capacity miss |
| `pixel-vpn-verification-b.json` | VALID; same scoped counts in VPN, including protected return packets and zero capacity miss |
| `linux-real-h-mutation.json`, `pixel-root-b-mutation.json`, `pixel-vpn-b-mutation.json` | Six Linux and four mutations per Android profile rejected by semantic checks after bypassing file seals |
| `native-final/result.json` | Six real C→Rust tests, C transport/handshake, ASan/UBSan and ARM64 builds pass |
| `arm-final/result.json` | Actual ARM64 C transport/handshake tests pass on the stopped Pixel; scratch removed |
| `device-final-c.json` | PASS; generation 1650 stopped, both empty policies restored, 1,222 original historical rows retained, original JSON hash unchanged, no VPP or owned NFQUEUE hooks |
| `full-suite.json` | 51/51 CTest, 45/45 ordinary Rust tests, bounded Blocked C ASan/UBSan pass; raw log hashes retained |

The Linux policy uses a device OUTPUT predicate (`0603`), which compiles PRE.
The T23 Flow-direction predicate (`0e01`) compiles POST and was deliberately
excluded from the final PRE claim. Independent packet-oracle checks join the
saved/applied rule version, native admission bytes and terminal action,
absence of any Flow observe for a blocked token, endpoint and pcap delivery,
basic counters, Blocked records and maintained windows. A persistent Flow
keeps the same owner/slot/incarnation and counters during each block phase;
allow phases advance that Flow. The Blocked incarnation persists across
block→allow→block while its winner version changes. The Flow and Blocked slots
can have the same numeric index without merging their history. Linux also
proves a 31-second idle END with reason 2, then a new incarnation for the same
tuple, and verifies 32-packet growth and one-second pending flush at the C
boundary.

At 3,000 distinct short blocked tuples, all 3,000 packets reached actual
NFQUEUE verdicts and basic policy-DROP accounting. Rust retained 2,115
pressure contributions and exposed exactly 885 blocked capacity misses; the
gap is explicit rather than attributed to a different rule. Across the full
Linux scenario, 3,041 basic policy drops equal 2,156 retained Blocked packets
plus 885 misses. No controlled blocked payload reached the endpoint. The
capacity is per owner, and idle retirement during the 30.7-second sender run
reused some slots, so total retained instances can exceed 2,048 even though
simultaneously active slots cannot.

The final Android Root/VPN runs each preserve the earlier committed history
and add nine Blocked packets with no loss. Their 17 scoped native packet paths
are four requests and four replies that were allowed plus nine dropped
requests. Each run stops and restarts the Service, reads the same persisted
views, restores the original empty policy through the public API, then stops.
The final direct readback finds 1,273 non-metadata SQLite rows and 36 cumulative
Blocked packets, including the retained diagnostic A and final B runs. The
legacy JSON hash remains
`75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4`.

## Bounded cost and limits

The isolated final Linux pressure phase sent 3,000 unique tuples over
30.694 seconds. Process samples across send, observation drain, durability and
the normal query work show 4.91 seconds VPP CPU, 10.90 seconds Rust CPU,
66,859,008 Rust process write bytes, 45 SQLite commits/checkpoints, 4,163
Blocked export attempts, 4,161 notifications, 358,328 KiB VPP high-water RSS
and 96,668 KiB Rust high-water RSS. The exporter had zero full-channel writes;
the 885 losses were bounded-table admission misses. The current one-second
flush and 30-second idle END both contribute records during short-tuple churn.

These are descriptive Host costs for this one paced pressure run, not isolated
per-packet engine cost, device energy, a release performance threshold or a
comparison against the E01 workload. The final Android Root/VPN tests cover
representative short tuples but do not saturate the 1,024-slot table on the
phone. Earlier diagnostic Linux G overlapped an Android build and recorded
higher CPU; H is the isolated final cost observation. E01's early persistence
estimate is therefore supplemented by actual blocked lifecycle and pressure
measurements, without treating unlike workloads as an A/B comparison. T27
owns longer retention and storage budget, T29 broader stress, and T30 combined
calibration.

Earlier retained attempts exposed a POST-only test predicate, a reused client
socket in the burst sender, its file-descriptor limit, and a collector timeout
while SQLite drained thousands of records. The final collector sends paced
short tuples one socket at a time, waits for durable drain, and independently
verifies packet identity and loss arithmetic. No Product behavior is inferred
from those failed attempts.
