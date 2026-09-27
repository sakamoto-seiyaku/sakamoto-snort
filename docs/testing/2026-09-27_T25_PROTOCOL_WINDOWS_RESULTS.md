# T25 L4 and multi-label L7 window acceptance

[SAKAMOTO-277](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e7b5168c-cfa3-4b84-9db1-9ee1a8891bc5)
extends the existing VPP-native C Flow observation record and Rust SQLite
consumer. The [interface contract](../interfaces/T25_PROTOCOL_WINDOWS.md)
records V5 identity, availability, error and lifecycle rules. This report is
T25's functional and scoped cost evidence; T27 owns complete retention and
space policy, T29 broader combined stress, and T30 combined calibration.

## Bound source and artifacts

Base: T24 commit `4b83101f3e08e28a9d469f13640880b149a1beb6`.
Final Product source SHA-256 on both Host and Android:
`3b87ea4f37129a23e63b9d944c31d5d8a9f6697fb562940a0b59f36cbb28b027`.
Host Product artifact: `build-output/product-vpp-host-t25-final`, witnessed by
`build-output/t25-20260927/linux-build-final/build.json`. Android APK witness:
`build-output/t25-20260927/pixel-build-final/build.json`, APK SHA-256
`b22663f52f5223a226f6c44323e0abc2b035f52edfb922eaeed7844b5d8c6d77`.
Both use the pinned VPP stage, not POC source. V5 Flow/Blocked records are
456/480 bytes, with a stable-catalog mask and availability in each directional
segment. Four queues retain 256 entries in each of their 464/480-byte rings;
the generation mapping is 987,904 bytes, 65,536 bytes above T24 V4.

All raw runs, failed attempts, source snapshots, build witnesses and independent
verifier results remain under `build-output/t25-20260927/`. The entering 34
unrelated dirty paths were byte-verified against T24's preservation proof and
recorded in `entry-baseline.json`. No prior Product history was reset.
The final `evidence-index.json` hashes 9,171 retained files; its SHA-256 is
`37d16a44ed17b97ba527e8fe9a3549315f3b6e5c666fbdda6d1bd0d66becf72f`.

## Functional result

The C owner reads the actual published LPI set after recognition, including
the supplemental stable catalog bits. A change in either direction exports
that direction's old cumulative boundary before counting the next packet.
Rust credits each distinct label once for that packet contribution while
overall, application and rule rows each advance once in one SQLite transaction.
An available empty result, unavailable recognition, missing attribution and
pre-Flow Blocked observations remain distinct. Query shares use the matching
application minute, UID, actual action and direction; overlapping L7 shares
can total above 100%. Historical T24 rows keep unavailable protocol coverage
instead of acquiring current labels.

| Product path | Independent result | Packet paths / actual policy drops | Published-set changes |
| --- | --- | ---: | ---: |
| Isolated Linux T12/R1 HTTP→TLS and mDNS→QUIC | `linux-verification-final.json` VALID; six summary mutations rejected | 176 / 5 | 4 |
| Isolated Linux R2 SMTP/FTP/FTPS | `linux-r2-verification-final.json` VALID | 458 / 21 | 7 |
| Isolated Linux R3 OpenVPN/WireGuard/SOCKS/RDP | `linux-r3-verification-final.json` VALID | 429 / 19 | 7 |
| Isolated Linux R4 STUN/RTP/RTCP/SIP/DTLS | `linux-r4-verification-final.json` VALID | 557 / 21 | 13 |
| Physical Pixel Root | `pixel-verification-final.json` VALID | 154 / 8 | 4 |
| Physical Pixel controlled VPN | same verifier VALID | 157 / 7 | 4 |

The Linux oracle reconstructs each selected packet's direction, size, UID,
actual result and published set from real wire bytes, endpoint dialogue,
complete-winner reference evaluation and packet trace. It compares every
queried minute/window contribution with the C→Rust record and independently
checks each protocol row's denominator and share. HTTP and mDNS rows precede
TLS and QUIC; the newer labels cover only traffic after publication, and the
R1 workload has app slices whose L7 percentages exceed 100%. R2–R4 use the
same arithmetic oracle with each suite's independent protocol dialogue and
endpoint check. All 15 supplemental stable IDs, 1006–1020, reached maintained
windows through the normal producer/record/consumer path. They were not
derived from provider-private enums or a five-label table.

The phone oracle binds installed APK/native hashes, saved/applied policy,
endpoint handshakes, native packet decisions, catalog facts, Flow
owner/slot/incarnation and queried V5 directional masks. Root and VPN both
show HTTP mask `2→6` and mDNS mask `32→40`; TLS and QUIC windows are empty at
the first boundary and positive after publication, with no earlier packet
credited to the new tag. Both returned fresh, scoped query shares. Six phone
mutations of masks, tags, legacy history and shares were rejected. The two
profiles restored empty configurations through the public API and stopped.

The stopped-device readback in `device-final/summary.json` is PASS. It found
all 1,348 pre-run nonmetadata SQLite rows byte-for-byte intact, 1,422 current
rows including 69 protocol rows, and SQLite integrity `ok`. The 1,348 prior
rows already included all 1,273 byte-verified T24 rows. The previous
`[8160,8107]` directional packets remain explicitly
`legacy_protocol_unavailable`. The original JSON SHA-256 remains
`75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4`.
The KernelSU grant, installed APK hash, stopped state, restored configurations,
absence of VPP and absence of owned NFQUEUE hooks were read back directly.

## Verification and scoped cost

The final standalone C suite passed 51/51 tests. Ordinary Rust passed 49/49;
seven actual Product C transport→Rust tests passed, including a deliberately
skipped protocol boundary whose two unprovable packets stayed unknown. C
transport and Blocked tests passed ASan/UBSan; transport and handshake ARM64
cross-builds passed, and both ARM64 boundary binaries passed on the stopped Pixel.
The SQLite migration test removed the new rows/metadata and baseline fields
from a committed predecessor-shaped database, then proved the old totals stayed
unclassified and only new traffic gained labels.
The catalog-tombstone regression also reopened persisted L7 history under a
reserved ID and an old baseline mask; newly received records still reject
noncurrent mask bits.

The source-bound Linux R1 run's controlled workload made 39 Flow
export attempts for 176 real packet paths, with 39 publications, 27
notifications, zero full or oversize queue writes, 15 final protocol rows and
14 SQLite commits. Across its 12.11-second sample the two-worker VPP process
used 22.08 CPU seconds; the Rust observer used 0.05 CPU seconds and wrote
598,016 bytes. High-water RSS was 358,268 KiB VPP and 10,340 KiB Rust.
These are observed costs of this trace-enabled Host run, with coarse CPU-tick
resolution and no matched pre-T25 run. They are not phone energy, a release
threshold or isolated per-packet engine cost. The phone evidence exercises
representative Root/VPN publication, not sustained ring saturation.

Retained failed probes include a first Pixel harness argument-shadowing error
before traffic and an R3 Linux fixture dependency error before its corrected
run. Two final R3/R4 harness invocations also passed a fixture directory where
the runner required its JSON file; corrected runs used `fixtures.json` and
passed. The old T12/R2/R3/R4 verifier's exact cache-storage byte assertion no longer
matches the current Product; T25's independent verifiers rerun its packet,
endpoint, complete-winner and catalog checks before assessing the maintained
windows. No unresolved Product behavior arose from those harness attempts.
