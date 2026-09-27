# T23 directional attribution acceptance

SAKAMOTO-275 implements independent directional attribution and application/rule
minute effects on the existing VPP owner → C transport → Rust → SQLite path.
The [contract](../interfaces/T23_DIRECTIONAL_ATTRIBUTION.md) defines version,
ownership, loss handling, atomicity, bounded state and query freshness. This is
T23's bounded acceptance, not T27 retention, T29 full capability/stress coverage
or T30 final combined calibration.

## Identity and evidence

Base commit: `118612b50e5a6fe85d4a8fadc0cee444aef46c2a` (E02).
Final Product source: `2a1ffa3f64e8b7c7a5c0c0ec773513edf6b2e49fddb5c99cebb507e29b768d0b`.
Raw evidence is under `build-output/t23-20260927/`; `evidence-index.json`
seals retained runs, failed attempts, builds, source snapshots and verifier
outputs. Final APK SHA-256: `2f5efa2a9460a7a1bc17c252ea093b327cb5dae3a44fe77aebf1fa1209385e7f`.
Final Host and APK manifests are `linux-build-c/build.json` and
`pixel-build-c/build.json`. Earlier A/B artifacts remain historical diagnostics;
they are not evidence that final C source ran. E02 source comparator is
`5f0e31d428b24f10e788a08979003ed5348b91a75795bd6016c4f4f88ed57722`.
The entering 34 unrelated dirty paths are checked against `entry-baseline.json`.

## Semantics and failures

The real Linux collector keeps a Flow while request/reply winners, full policy
versions, UID and observe/enforce settings change. It fills the paused owner
queue through 140 changes, resumes, and accounts recovered unprovable growth as
unknown. It closes a Flow with an unexported tail, terminates the Rust consumer
while packet processing continues, and restarts against the retained SQLite
store with a new generation. The independent verifier reconstructs packet
lengths, direction, identities, final logical winners and attribution segment
boundaries from native admission evidence and public configuration responses.
It compares all maintained API views, their minute conservation and persistence.
Resealed semantic mutations must fail; file-hash rejection alone is insufficient.

Physical Android Root and VPN runs keep one application socket through NoMatch,
request/reply DROP, observe DROP with actual ALLOW, six alternating changes,
combined END and Service process replacement. API history survives restart.
Root may also admit independently captured background SSDP: such packets remain
explicit unknown-UID NoMatch contributions, separate from endpoint test delivery.
The raw transport/debug evidence is the packet-boundary oracle; screenshots and
shell success are not packet accounting proof.

`store-faults-final/result.json` binds unchanged observation/store source to real
SQLite kind-4 and kind-5 write aborts. All views and the baseline roll back
together, pending live state remains visible, retry and duplicate END do not
recount, and abrupt process exit loses only the accepted uncommitted tail.
`query-refined/result.json` exercises five real C→Rust tests, including idle
commit without queries, paused and concurrent fresh queries, restart, unseen
queued shutdown gap, and one-shot three-second WAL synchronization delay.
The delayed owner returns a coherent qualified stale view after its two-second
wait and a fresh durable view after recovery. The shim is test-only; VPP does
not wait for SQLite. The deadline is owner-response waiting, not total RPC cost.
C transport/handshake, ASan/UBSan and actual ARM boundary checks are retained.

| Final evidence | Result |
|---|---|
| `query-full-suite.json` | 50/50 CTest and 42 ordinary Rust tests pass |
| `query-refined/result.json` | Five native C→Rust tests, C transport/handshake, ASan/UBSan pass |
| `linux-semantic-c-verification.json` | VALID; all 15 semantic mutations rejected; unknown growth [11,11], END sequence 619→620 |
| `linux-benchmark-0-c-verification.json` | VALID; 1,916/1,916 packets; all 12 mutations rejected |
| `linux-benchmark-10000-c-verification.json` | VALID; 1,916/1,916 packets; all 12 mutations rejected |
| `pixel-benchmark-c-verification.json` | VALID for actual 1,916/1,913 admission; all 12 mutations rejected |
| `pixel-root-semantic-d-verification.json` | VALID; 25/23 packets, four actual policy drops; all 13 mutations rejected |
| `pixel-vpn-semantic-d-verification.json` | VALID; 25/23 packets, four actual policy drops; all 13 mutations rejected |
| `arm-final/result.json` | Actual Android root-context C transport/handshake pass |
| `device-restoration/result.json` | PASS; original empty policy restored through public API, 1,222 prior rows retained |



## Representative cost and the corrected regression

The representative workload keeps the E01 classes: low rate, 256-packet burst,
1,000 sustained packets, 128 active sockets carrying 512 packets, and 128 short
Flows (1,916 requests total). Attribution changes at phase boundaries and
request/reply rules differ. Host runs use zero and 10,000 seeded baselines.
The same Java probe is used across the E02, T23-B and final C phone comparison.
Its per-byte `String.format` encoding slows pacing compared with the original
E01 probe (about 4.7 versus 2.6 seconds burst; 23 versus 9.6 seconds sustained).
Thus workload classes and counts match, but timing is not a replay of E01 and
these measurements cannot isolate wire-layout cost or establish an energy SLO.

The initial same-probe phone consumer measurement regressed from E02 2.68 s to
T23-A 5.11 s and T23-B 5.69 s. Release Host profiling against copied real phone
history measured 1,000 incremental consumes at 5,984,088 ns and repeated full
query projection at 61,761,573 ns, identifying unnecessary per-drain JSON work.
T23 now maintains the aggregate and persistence in the background but constructs
presentation only on an API request. This uses the existing consumer wake and
control channel, with no second aggregate or new framework. New requests during
projection retain their own completion sequence; rendering and response copying
run outside the control mutex. The old regression evidence remains retained.

| Run | Consumer CPU ms | Process CPU ms | Process write bytes | Export attempts / full | Commits | Process HWM KiB |
|---|---:|---:|---:|---:|---:|---:|
| Host0 E02 | 30 | 120 | 1294336 | 593 / 0 | 15 | 9728 |
| Host0 T23-C | 100 | 210 | 4481024 | 733 / 0 | 15 | 18132 |
| Host10k E02 | 50 | 100 | 1687552 | 593 / 0 | 15 | 18952 |
| Host10k T23-C | 90 | 200 | 4980736 | 733 / 0 | 16 | 30748 |
| Pixel E02 | 2680 | 3700 | 5029888 | 979 / 0 | 53 | 165140 |
| Pixel T23-B before fix | 5690 | 6550 | 11612160 | 990 / 0 | 50 | 167052 |
| Pixel T23-C | 1180 | 2090 | 12455936 | 990 / 0 | 52 | 168196 |

Final C Pixel sent 1,916 requests and received 1,913 replies. Three replies
(one each in burst, sustained and short-flow phases) are captured at host egress
but absent at device ingress and native observation. Maintained growth is exactly
[1,916, 1,913] packets, with zero full/oversize/notify-error exports. Its 1.18 s consumer CPU is 79.3% below pre-fix T23-B's 5.69 s and
56.0% below the same-probe E02's 2.68 s in these runs. The final 12,455,936 process
write bytes remain 2.48× E02's 5,029,888, while commits/checkpoints are 52 versus
53. The V3 mapping grows from 332,544 to 922,368 bytes per generation (+589,824),
with each Flow record growing to 424/448 bytes. The added directional attribution records and application/rule indexes
therefore still have a real storage cost; removing redundant JSON does not
remove that cost. The final phone SQLite file is 3,837,952 bytes versus E02
176,128 bytes and T23-B 2,576,384 bytes, with accumulated history explicitly
unequal. VPP CPU was 25.49 s versus B 24.52 s and E02 26.68 s; these single runs
are descriptive, not a precise datapath CPU improvement claim. Host consumer
cost remains around 90–100 ms; the small Host runs do not show the large phone
projection benefit. The extension was re-reviewed after this measured regression
and correction; no unmeasured zero-cost claim remains.


## Retained failures and limits

The initial native red tests precede implementation. The first ctypes reference
run used the old struct layout; fixing the test-only layout restored 55,470
complete-winner comparisons. The first store-fault fixture used an invalid
zero revision, and the first profiling compile missed the release panic strategy;
both failures and corrected runs remain. Root semantic B's history assertion
mistakenly prohibited appending an existing minute bucket; it was corrected to
preserve identity and require monotonically retained counts, then rerun.

E02's phone comparator lost two replies between host egress and device ingress;
native observations agree with captured device admission. T23-A lost one reply
in the same underlay interval. Neither is labeled observer loss or silently
removed. The paired T23-B run received all 1,916 replies. Final C retained three similarly
localized underlay losses, as reported above; an initial summary incorrectly
assumed full delivery and was corrected against independent review and raw
phase counts before acceptance. Queue loss is exercised
separately and explicitly represented as attribution gaps.

Process CPU has 10 ms granularity. Process write bytes are not NAND writes or
energy. Query and final persistence costs are included in normal measured phases;
configuration apply precedes the phase samples. Phone history grows between runs,
so database size and memory are not randomized equivalent-history A/B results.
Minute placement uses coalesced directional activity, not per-packet timestamps.
The complete 48-hour/30-day/180-day retention and 256 MiB budget remain T27;
combined Root/VPN stress and final cost calibration remain T29/T30.


## Final device state

The final C APK remains installed, with KernelSU app grant confirmed. Root and
VPN were started serially for restoration, then stopped; final generation is
1642. The original empty configuration from the pre-T23 E02 comparator was
restored through the public configuration API. Queries before/after deleting
active rules preserve historical full identities/names and their accumulated
counts. All 1,222 pre-restoration SQLite rows remain (metadata may evolve and
count-bearing minute rows may append legitimate background traffic).
The runtime and VPP processes, owned test probes/captures, packet hooks and VPN
interface are absent after cleanup. The original legacy JSON remains byte-for-byte
SHA-256 `75a715a4ce1fd64679631baca1c0d398de3186bf95dad5cdcfa6beabbb9091c4`.
The evidence includes the restoration runner, every API response, final SQLite
copy/integrity check, process/hook/interface listings, APK hash and root grant.
