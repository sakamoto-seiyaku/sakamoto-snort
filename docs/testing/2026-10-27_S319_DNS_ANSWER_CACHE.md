# S319: valid DNS answer data cache — scoped qualification record

The shared VPP-native DNS proxy now reuses valid answer data within the same
owner and resolution view. Every request still executes the current query and
response policy with its actual caller facts. Cached data carries no permission,
caller, rule winner or transport obligation from the original request.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md),
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) and
[SAKAMOTO-319](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e7346057-33a3-4445-b1d3-3ee5628d1b44).
ADRs 0006/0007/0008 retain the existing VPP-native C product boundary.

## Runtime behavior

Each existing FlowOwner owns at most **512 cache entries and 2 MiB** including
the fixed cache metadata and live owned query/answer allocations. Least recently
used data is retired before replacement allocation, so transient insertion does
not exceed the byte bound. Cache data is released on normal Stop/destruction.

The complete query bytes except the transaction ID form the data key. This
includes original Question case, QTYPE/QCLASS, flags and supported empty EDNS0
metadata, including DO. Network and resolver/configuration route revisions fence
the view. A view change prunes old entries; the existing transaction identity
rejects old-view or old-generation late writes. Unknown EDNS options and names
whose cache semantics cannot be proved still forward transparently and skip cache.

A hit restores the requesting ID and exact Question, ages every ordinary RR TTL
from the original resolution time and re-runs current response policy. The
shortest actual reusable TTL bounds the whole answer. NXDOMAIN/NODATA requires
one relevant SOA and uses min(SOA TTL, MINIMUM). TTL0 and the reserved high TTL
bit provide no cache lifetime. OPT metadata is preserved. Expired data cannot
rescue a transport failure; policy errors and transport failures are not stored.

Compression targets must point backward to an already visited DNS name boundary.
TTL, header, label-interior and opaque bytes cannot become anchors. Supported
RDATA name fields are walked conservatively. Ordinary textual names retain
negative-cache ancestor checks; binary, escaped and ambiguous labels remain
transparent on the wire and are excluded from this data cache. Invalid retained
data is dropped and the same request immediately uses the ordinary upstream path.

Normal observations use the existing 704-byte DNS record, adding an explicit
cache source bit/result without a new storage channel. A hit has no invented
upstream socket. Existing upstream provenance, current rule identities, actual
Unknown callers and return provenance remain distinct.

If allocating the final output fails after a cached answer has been parsed,
the local SERVFAIL retains its real cache provenance in both error and delivery
history. The consumer accepts that precise CAPACITY outcome only with complete
correlation and response facts; other error results and mixed source flags remain
invalid.

## Artifacts and cached builds

Fixed review base: `e99719b235aea69604cf26ad874fcc021a7f8f50`.
R5 cache qualification APK: `63007f0e32663916360275bc4b094876e6ffe913e15d7d921e46ce750cd04461`.
R5 plugin: `3d80728092f5c4e9d0c2dd5b8539e30c16a391b87a5331012de53480c9e90bca`.
R6 N1 lifecycle APK: `52c32d4af35e5d2b6fe72d38beee6d28288d570a21c38168248d39ffd3835d4b`.
R6 N1 lifecycle Rust core: `24e9f640d387c450aa190f55437901d371ba3bac050879867377889380ef85ae`.
The R6 plugin and JNI bytes are identical to R5. Its sole production source
change preserves a finite prefix of already published normal observations during
consumer close. Exact compiler outputs for all three payloads remain retained.
The R6b Rust core is `21032d37ffbadb7036cd510faa8f7c20473525dcc0851eaa3359b5c97584423b`;
its APK is `260ade80702dd4e42bc40a41e1b30b8bfc2ef332dba57ac4fbf08f57874798f5`.
R6b adds the producer-disconnect entry into the same finite-prefix close. Its
C/VPP plugin, JNI and Java/DEX bytes remain identical to R5/R6.

The R5 native, Host and Java/DEX repeat builds used the existing persistent Product
caches and compiled zero inputs, with 777 / 3539 / 182 compiled metadata entries
unchanged. All 266 R5 runtime inputs match their sealed build and actual earlier device
source closures. R6 changes only the shared Rust observation consumer in that
runtime closure; original cache qualifications retain their R5 artifact scope. Three separately retained raw compiler outputs match selected
payload sections and program headers. Later fixture and evidence-reader changes
do not relabel earlier device source ZIPs or require rebuilding unchanged runtime.

R7 adds only the strict cached-output CAPACITY decoding above to the R6b runtime.
Its Rust core is `b0dc4bd0f7e99e2303ae0496aff5e172a352031ae973cddd55d2e8f4fb987ab6`
and selected APK is `cab06b8f7532c9ab14c3312c4c5029be72737c1d803d9c2bdc8ad775bd117ce3`.
Plugin, JNI and Java/DEX bytes remain unchanged. The native, Host and Java/DEX
repeat builds compile zero inputs and preserve all 777 / 3630 / 182 compiled
metadata entries, respectively; all native payloads are identical across each
pair. Three separately frozen raw compiler outputs match the selected payloads.
The exact R7 Host artifact passes the real VPP unified-rule runtime contract.
Its first socket-restricted attempt remains HOLD; the same artifact passes with
actual local sockets enabled. The Rust default core-profile contract also passes
using its existing separate fixture-ABI cache. Earlier socket-denial and an
incorrect actual-VAPI/fixture-ABI environment remain separate failed attempts.

## Qualified behavior and honest composition

The evidence composes26 separately scoped components: **393 case groups** and
25 transport-precondition groups. The final immutable-MAIN join contains
**5643 unique complete records**:5562 case records and81 preflight records,
comprising5459 proxy and184 passive records. Every selected whole record occurs
exactly once in each cited MAIN; store keys, raw values and received clocks remain
identical wherever a record survives across multiple MAINs.

The normal history remains bounded at4096 rows. Earlier evidence is sealed before
later oldest-row eviction. This is a union of original artifact scopes, not one
all-history final database or one complete matrix invocation. Whole-run HOLDs
remain unchanged when a separately qualified data slice supplies evidence.

| Scope | Groups | Qualified artifact and behavior |
| --- | ---: | --- |
| Basic reuse and representative owners |45| R3 Root/VPN N1/N3 ordinary UDP/TCP, IPv4/IPv6 and actual owner coverage |
| TTL, negative answers, EDNS and RR semantics |80| R3 Root/VPN N1: TTL0, positive/SOA-negative data, empty/unknown EDNS, TXT/MX/SRV/HTTPS/opaque wire |
| Root name boundaries |40| R4 captured groups, separately requalified with exact complete proxy identity and native-clock TTL ages; original whole HOLD retained |
| Compression eligibility |128| R5 Root/VPN N1/N3, both transports and families, composed from six source-frozen cohorts |
| Current response policy |8| R5 Root/VPN: installing an alias rule refuses existing cached data; removing it allows the same data without another peer request; policy connections prove reliable App facts |
| Current resolution view |4| R5 Root/VPN: configured IPv4-to-IPv6 upstream change obtains its separately registered answer before the next hit |
| Entry/byte bounds and LRU |52| R5 Root/VPN N1,26 groups and557 ordinary App queries each;1671 complete selected records per profile |
| Complete Stop/restart/old late answer |20| R6 N1 and R6b N3 Root/VPN, five groups/23 selected whole records per cohort |
| VPN name boundary replay |8| R6b legitimate SOA-parent data caches and literal-dot label ambiguity does not; both transports/families,48 case+12 preflight whole records |
| Minimal final R7 artifact entrance |8| Root/VPN N1 ordinary App UDP/TCP and both families:28 Root and24 VPN selected whole records in separately closed normal MAINs |

The compression union has768 complete proxy records,64 separately preserved
passive case records and55 preflight records. VPN N3 IPv4 contributes a16-group
data slice with an unretained historical Stop-counter log and old collector
terminal-clock limits. Later IPv6 has full normal Stop and stamped terminal
capture; it cannot backfill that earlier gap.

Both capacity cohorts actually fill512 entries, touch LRU and replace the correct
oldest entry. Forty large same-resolver UDP-TC→TCP fills and one later large
query exercise the byte bound. Both finish at34 entries/2072804 live bytes,
peak2097084 <2097152 and520 evictions. Root history accepts1697 and removes
exactly the oldest1697, preserving2399 old raw records and clocks. VPN accepts
1731 and removes the oldest1731, preserving2365 old records and clocks. Each
final MAIN retains4096 with zero new rejection; neither clears nor raises history.
Each cohort proves106 actual network windows.

The first natural retention boundary is R5 VPN N3 IPv6:4002 prior rows plus144
new rows yields4096, retiring the exact oldest50 and preserving3952 old raw values
and receipt clocks. Subsequent complete lifecycle/name MAINs retain the same
strict oldest-order, raw-value and clock checks.

## Red/green and retained failed attempts

Real public-seam and Adapter failures are retained with their exact source and
artifact identities. The allocation RED proved a transient live-byte overrun;
retiring entries before allocation fixed the same bound, with measured Host peak
2071116 bytes. High-bit TTL RED and positive/negative controls preserve the same
assertion. Binary-label SOA ancestor confusion and compression into TTL bytes
were reproduced through public submit/answer and real Root/VPN entrances before
conservative cache qualification fixed them. First-wire transparency remains a
separate core assertion from cache reuse.

The original complete Host evidence is composed: 111/113 passed in the original 30-second
wrapper, and the same two unchanged tests passed with a 300-second wrapper.
This is 113 qualified tests across invocations, not a single all-green run.
The final dispatch-reader test adds eight methods / 47 scenarios across the three
S319 direct entrances and both delegated Root/VPN paired exchanges;
the existing Host cache reconfigured with zero compilation and the new CTest
entry was independently listed without repeating already passed assertions.
Directed 50 and separate ASAN9/UBSAN9 checks remain scoped to their frozen inputs.
Affected UI/network/lifecycle/route/retention checks qualify only the actual
changed methods and their dependency closures.

Earlier unexplained sender-to-peer losses remain failures with full wire/time
facts. A same-name interface is not sufficient network identity; actual C-bound
ifindex and complete physical/Android view snapshots are checked. A real
LinkProperties change is not relabeled a caller or cache bug. UI dump timeouts,
Dozing/focus failures, an exhausted finite test relay and evidence-reader schema
mistakes retain their original HOLDs. No request or Stop is replayed for a receipt
label. The finite relay now reserves a separate bounded cleanup budget; collector
terminals carry actual monotonic times after socket close. Those changes cannot
backfill missing historical observations.

The first Root capacity attempt completed 128 queries and received exact replies
for the next 32, then failed an exact-one-datagram assertion. One question
actually used the existing allowed UDP retry: distinct full physical packets
were separated by 1.504296062 seconds; the native request completed in
1.581588 seconds. The shared S319 count reader now distinguishes logical
dispatches from that one bounded retry using complete bytes, tuple, peer,
physical and native-clock proof. More than two datagrams, changed identity,
missing evidence or an ambiguous native identity still fail. Cache hits still
require zero new dispatch. This qualifies the failed batch only; the later two complete capacity cohorts
provide their separate acceptance. Packet-loss location remains unestablished. The raw HOLD remains.
A subsequent VPN attempt retained exact App replies for its eighth batch but
failed an observer-gap assertion at 1.499995891 seconds. The unchanged native
request completed in 1.526805 seconds. Native admission anchors retry and total
deadline; physical and peer receive observations can be compressed or delayed.
The shared reader now applies timer bounds only in the native clock, with one
complete query/response/delivery identity and real upstream session; observation
gaps retain only their actual order. It uses no arbitrary tolerance. Exact send
times and packet-loss location remain unestablished. Both original HOLDs are
retained; the common Root/VPN read-only classifier verifies each failed batch
32 logical requests / 33 actual datagrams / 96 exact normal MAIN records.

The full finite capacity witness explicitly uses 8192 packets; legacy default
1024, compile maximum16384 and 16 MiB byte bound remain separate. Normal/invalid
compile controls are retained. No Product deadline or socket option changed.

The first stopped-pending Root case has normal QUERY/STOPPED evidence and an
actual old reply after restart. Its original wrapper exhausted the physical
observer window while fetching unrelated loopback coverage; the original release
clock was not persisted. That slice proves old Stop and actual late arrival only,
with no two-second or fresh-query claim. The common observer now prepares complete
network/all-interface coverage before release, persists release intent/completion
and actual arrival clocks, observes physical arrival within the original two
seconds, then requires complete return/fence coverage after that scope. Both
actual Root/VPN TCP callers use this path. Controlled tests retain missing, late
and failed full-coverage rejection. A historical RED test hash/log is retained;
its separate original file bytes were not captured and cannot be reconstructed.

The later Root pending Stop at generation2854 retained its native cancellation
and zero-resource log, but its hash-stable closed normal MAIN contained only the
pending QUERY. All4096 normal rows obeyed exact oldest retention; the missing
STOPPED row was not removed by normal eviction. Its precise historical native
publication/loss point was not observed. A deterministic Host reproduction then
showed that closing a paused consumer abandoned already published Root UDP,
Root TCP and VPN TCP records before normal SQLite close. The fixed shared
consumer captures each C channel's real queue occupancy once and consumes only
that finite prefix in bounded batches. It keeps incomplete coverage because a
producer may still publish later. It adds no wait-for-empty loop or fabricated
quiescence claim.

Actual source-linked Root/VPN UDP/TCP IPv4/IPv6 Adapter Stop emits16 QUERY/STOPPED
records; the new paused consumer test preserves all16 complete identities in
reopened normal SQLite. Multiowner batches exceed128 records. Another control
captures260 records, then publishes129 more while the consumer is held at its
capture boundary: actual C channel status proves389 published,260 consumed and
129 still queued when the consumer joins while the producer remains alive.
The existing coverage-gap and normal capacity lifecycle controls also pass.
Exact RED and final GREEN source ZIPs, the initial synthetic-header fixture
failure and all original device HOLDs remain available.

The durable regression entry is `tests/evidence/s319_shutdown_prefix.py` with
explicit Host artifact, VPP include and persistent Cargo target parameters.
It generates actual Adapter Stop records, compiles only the small C producer,
runs five native shutdown methods plus the existing channel-capacity lifecycle,
and reopens normal SQLite through the existing Store. Host temporary database
files are removed after the test; their reopened projections are retained.
Device normal MAINs remain separately sealed for independent SQLite reads. Its invocation and sealed run are in
the evidence index; ordinary unqualified `cargo test` does not execute ignored
native integration methods.

A second deterministic close test holds only the observation consumer's actual
libc `poll`, after the C queue-empty check. The real Adapter's16 stopped records
are published, actual C status proves16 queued/zero consumed, and the owned
producer closes before the poll gate releases. Actual poll reports socket
revents17 with the data notification also ready. The old consumer's immediate
wait-error exit stores0 DNS rows; the same operation now stores all16 and keeps
the coverage gap. This test is an intervention at a controlled boundary; it does
not identify the precise historical loss point in generation2854. Both ordinary
consumer disconnect and producer/wait termination now use the same one-time
per-channel published occupancy capture. Corrupt-channel, invalid-occupancy and
store-close error paths retain their separate failure handling and are outside
the successful-prefix claim.

R6 actual Root N1 and VPN N1 each pass five complete Stop/restart groups and23
selected whole records across two sealed normal MAINs. Pending queries end as
STOPPED8 in0.765441 and2.312708 seconds respectively. The actual old replies reach
the physical witness within0.070011 and0.091615 seconds of persisted release.
The same old Question then proves fresh upstream followed by a current cache hit,
with actual owner0 on both sides; the whole requery completes within20.821135 and
32.712341 seconds of release, both below the old answer's60-second lifetime.
Complete return fences, native/cache/TUN/resource closure and current routing
checks pass. N3 and name coverage use their separately selected R6b artifact
scope. Neither accepted N1 run is replayed for a new receipt label.

The Root N3 R6b lifecycle also passes five groups/23 selected whole records at
generations2859/2860. Actual pending STOPPED8 takes0.815576 seconds, the old reply
arrives within0.079595 seconds, and the same Question proves cold then cached on
the same actual owner2 within20.848507 seconds of release, below its60-second TTL.
All three owners reach native/cache zero and current rules are restored.

The later VPN N3 attempt retains a payload-free RST|ACK from the exact old App
socket after its pending Stop. Its tuple, TCP sequence/acknowledgement, complete
old TUN query and handshake, native original-resolver FD absence, no App reply,
normal QUERY/STOPPED8 and zero-resource Stop satisfy the existing narrow stopped
control qualifier. The earlier warm connection's deliberately global resolver
fence lacked that shared Stop interval and rejected the same packet. The fixed
fixture shares only one proved Stop interval among unclosed fences with the same
generation, complete collector identity and original resolver. The global
resolver predicate remains unchanged. Earlier explicit end intervals, mismatched
scope, missing lifecycle facts, ambiguous boundaries, data, SYN/FIN, other tuples,
wrong sequence/acknowledgement, duplicate controls and incoming packets reject.
The same actual-packet Host operation fails before the fix and passes afterward;
seven new methods/21 scenarios plus eight existing methods pass. The original
whole device HOLD remains unchanged; no late two-second/fresh/cold completion is
inferred from its failure cleanup.

The complete VPN N3 R6b cohort subsequently passes five groups/23 selected
whole records at generations2863/2864. Pending STOPPED8 takes2.251199 seconds;
the old reply arrives within0.203443 seconds; the same Question is fresh then
cached on actual owner0 within33.108186 seconds of release, below60 seconds.
All four complete lifecycle cohorts therefore prove the same-owner cold-query
precondition; no different-owner miss is used as a no-late-cache-write proof.

All eight VPN name groups complete at generation2865 with48 case and12 preflight
whole records in final MAIN4096, SHA256
`1abef846671c11295a45da4406f3dbaa9232b51aad6db38d8305d2c4ae9dc835`.
The original whole result remains HOLD solely because the Windows physical-peer
readback exceeded its lifecycle budget after normal Product Stop. Its peer log
reports28 received/exchanged, zero pending/connections/queued bytes and two actual
UDP receive errors. A later read-only check proves exact peer PID32116 and its
owned53053 endpoints absent; foreign UDP53 PID5740 remains untouched. No query,
peer or Product Stop is replayed for this cleanup label.

The final R7 artifact passes four ordinary-App fresh/cache groups per profile at
generations2866 (Root) and2867 (VPN). Root has24 proxy and4 separate passive
records in MAIN94; VPN has24 proxy records in MAIN145. All selected records occur
exactly once, all94 earlier raw records and clocks survive the VPN run, and new
history rejection remains zero. Both normal Stops prove native/cache/owned
resource absence and complete current IPv6 rule equality. These eight groups
qualify the new decoder's ordinary device chain; actual allocator faults remain
the separately qualified Host operation. They add52 whole records to the earlier
385-group/5591-record composition without changing its original artifact scopes.

## Restoration and limits

The first complete restoration actually installed the original APK
`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and restored all 4861 original private-data members, including their metadata.
Only the two generation fields changed from the original 2809 to the freshly
read maximum 2865. Root authorization, permissions, SELinux labels, CPU frequency,
stay-awake setting, original Wi-Fi SSID and native-resource absence passed.
The complete 6547-node final R6b test graph was preserved separately before that
restoration. After the later minimal R7 verification, its complete4889-node graph
was separately preserved. A second restoration with a unique controller/output
actually restored the same original APK and all4861 original members again,
with only the two freshly read maximum generation fields set to2867. All original
metadata, permissions, labels, root grant and settings checks passed again;
native/hooks/queues/owned route table remain absent. The first restoration's
receipt and all raw evidence remain unchanged.

After restoration, all11 exact owned remote archive pairs were either already
absent or matched their retained local archive and metadata hashes before
removal. This retired2528661385 logical bytes (2531205120 allocated bytes).
Every local raw archive remains retained; all4861 restored members and both
generation ledgers are unchanged after cleanup. No Product Stop or signal was
replayed for archive retirement.

An automatic approval review initially rejected the remaining two-cohort launcher
before process creation, citing missing explicit authorization for physical VPN
device-state changes. The user then explicitly authorized that reviewed device
operation. The same unchanged command and escalation path were approved; the
cohorts above supply its actual data. The original denial and subsequent approval
remain separately retained, without any workaround or relabelled Product failure.

Qualification is controlled Pixel hardware and ordinary socket upstreams. It
does not implement encrypted upstreams/HTTP Age, association consumption,
postponed cross-App/profile visibility policy, UID-resolver redesign, system hooks,
release coverage or performance claims. Different callers share reusable data
only; every actual request retains its own current policy and original identity.

## Reproduction and retained evidence

The native regression uses the existing Host dependency caches. The retained
invocation compiles the current Rust consumer into its test executable and links
the unchanged pinned C transport libraries from this Host artifact:

```sh
rtk proxy python3 tests/evidence/s319_shutdown_prefix.py \
  --host-artifact build-output/s319-dns-cache-20261026/product-vpp-host-s319-final-r6-repeat \
  --vpp-include build-output/product-vpp-host-stage-s296/source/build-root/install-vpp-native/vpp/include \
  --cargo-target-dir build-output/product-build-cache/host/da624b6452801ed58299c9baaed3c61772c20f1fc88b2084c9f1e5cc0dc7b0e3/cargo-target \
  --output build-output/s319-shutdown-prefix-recheck
```

Choose a new output directory for each invocation. Existing Product libraries and
Cargo dependencies are reused; no device operation is part of this command.
`rtk proxy python3 tests/host/product_device_vpn_tcp_stop_wire_test.py` runs the
registered shared Stop-wire positive and negative controls.

The allocation-history regression uses the same dependency arguments with
`tests/evidence/s319_cache_resource.py` and a new output directory. It links real
`malloc` fault injection into the source-linked Adapter, then runs the normal
Rust test profile and reopens the existing normal SQLite Store. All eight
Root/VPN, UDP/TCP and IPv4/IPv6 scopes exercise upstream data, cached data, cache
scratch failure, cached output failure and upstream output failure: 24 one-shot
allocation failures produce 120 complete records. The old decoder persists 104;
the corrected decoder persists all 120 with exact whole-record identity, ten
invalid-cache controls rejected and conflicting replay unable to replace history.
The two C record streams differ only in their actual wall-clock activity fields.
An earlier release-profile invocation exposed a Cargo abort/unwind output-file
collision before the test ran; its build HOLD remains separate from the real
RED/GREEN. The ordinary test profile avoids that conflicting graph without
changing the Product's release panic strategy.

| Evidence | Retained record |
| --- | --- |
| Public/Adapter cache behavior, names, compression and allocation | [R5 canonical public GREEN](../../build-output/s319-dns-cache-20261026/coordination/canonical-public-green-r5.json) |
| R5 compression128 composition and original data-only limits | [Independent composition](../../build-output/s314-vpn-tcp-20261023/coordination/root-s319-r5m-compression128-composition-independent-audit.json) |
| Root/VPN capacity and exact natural4096 retention | [Root](../../build-output/s314-vpn-tcp-20261023/coordination/root-s319-g2847-root-capacity-independent-audit.json), [VPN](../../build-output/s314-vpn-tcp-20261023/coordination/root-s319-g2850-vpn-capacity-independent-audit.json) |
| Final R6b Android/Host cached pairs and selected raw symbols | [Android](../../build-output/s319-dns-cache-20261026/coordination/native-current-r6b-result.json), [Host](../../build-output/s319-dns-cache-20261026/coordination/host-final-artifact-and-rule-r6b-result.json), [raw symbols](../../build-output/s319-dns-cache-20261026/coordination/frozen-native-r6b/manifest.json) |
| R7 strict resource-history decoder, cached build pairs, matching symbols and affected contracts | [Scoped build/gate composition](../../build-output/s319-dns-cache-20261026/coordination/r7-build-and-affected-gates-composition.json) |
| Explicit consumer-close prefix RED/GREEN and exact Adapter STOPPED16 | [Sealed index](../../build-output/s319-dns-cache-20261026/coordination/shutdown-prefix-sealed-index-r6.json) |
| Actual C poll/producer-disconnect RED/GREEN, durable five-method entry and limits | [Sealed index](../../build-output/s319-dns-cache-20261026/coordination/shutdown-wait-prefix-sealed-index-r6b.json) |
| Real allocator cached-output history failure, exact same-operation104→120 normal SQLite RED/GREEN | [Sealed pair](../../build-output/s319-dns-cache-20261026/coordination/cache-resource-red-green-r7a-sealed.json) |
| Unified lookup/first allocation/output/upstream/refusal/truncation/cancel/view/Stop exit inventory and exact tested limits | [Terminal-exit inventory](../../build-output/s319-dns-cache-20261026/coordination/terminal-exit-inventory-r7.json) |
| First executed original APK/all4861 restoration with fresh BOTH2865 | [Receipt](../../build-output/s319-dns-cache-20261026/coordination/device-restoration/original-restoration-r5-receipt.json) |
| Complete final R7 test graph and second executed original APK/all4861 restoration at fresh BOTH2867 | [Preservation](../../build-output/s319-dns-cache-20261026/coordination/device-restoration/posttest-final-complete-r7-receipt.json), [restoration](../../build-output/s319-dns-cache-20261026/coordination/device-restoration/original-restoration-r7-receipt.json) |
| Exact owned remote archive retirement, retained local evidence and unchanged4861-member original graph | [Receipt](../../build-output/s319-dns-cache-20261026/coordination/device-restoration/final-owned-remote-archive-retirement-r7/result.json) |
| Complete N1 and Root N3 lifecycle records | [Root N1](../../build-output/s319-dns-cache-20261026/coordination/lifecycle2855-2856-root-n1-r6-sealed.json), [VPN N1](../../build-output/s319-dns-cache-20261026/coordination/lifecycle2857-2858-vpn-n1-r6-sealed.json), [Root N3](../../build-output/s319-dns-cache-20261026/coordination/lifecycle2859-2860-root-n3-r6b-sealed.json) |
| Original VPN N3 overlapping global-fence failure and exact stopped control | [Read-only classification](../../build-output/s319-dns-cache-20261026/coordination/lifecycle2861-overlapping-warm-fence-classification.json), [same-operation Host GREEN](../../build-output/s319-dns-cache-20261026/coordination/shared-stop-scope-green-r6c/result.json) |
| Earlier failed-cohort closed MAIN/current-resource/owned-wire settlement | [Receipt](../../build-output/s319-dns-cache-20261026/coordination/device-restoration/lifecycle2862-closed-main-wire-r1-receipt.json) |
| Original pre-process rejection and later explicit authorization | [Rejection](../../build-output/s319-dns-cache-20261026/coordination/automatic-approval-rejection-r6c.json), [same-command authorization](../../build-output/s319-dns-cache-20261026/coordination/automatic-approval-authorization-retry-r6c.json) |
| Final393-group/5643-whole component union | [Catalog](../../build-output/s319-dns-cache-20261026/coordination/accepted-components-final-r7.json), [exact whole-record join](../../build-output/s319-dns-cache-20261026/coordination/accepted-whole-record-union-final-r7/result.json) |
| Final R7 ordinary-App entrances with separate complete MAINs | [Root2866](../../build-output/s319-dns-cache-20261026/coordination/smoke2866-root-r7-sealed.json), [VPN2867](../../build-output/s319-dns-cache-20261026/coordination/smoke2867-vpn-r7-sealed.json) |
| Complete VPN N3 and final names8 with independent peer absence | [VPN N3](../../build-output/s319-dns-cache-20261026/coordination/lifecycle2863-2864-vpn-n3-r6c-sealed.json), [names8](../../build-output/s319-dns-cache-20261026/coordination/names2865-vpn8-scoped-qualification-r6c.json), [peer absence](../../build-output/s319-dns-cache-20261026/coordination/peer2865-physical-readback/result.json) |

The raw evidence remains local. Missing local artifacts are not a passing or
skipped branch. Closed device SQLite reads use `mode=ro&immutable=1`; earlier
required records are sealed before later natural history eviction. The tracker
owns work state; this report records only the listed source/artifact scopes.
