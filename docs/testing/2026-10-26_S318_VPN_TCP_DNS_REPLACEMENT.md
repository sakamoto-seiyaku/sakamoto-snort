# S318: optional VPN TCP DNS replacement

Configured VPN client TCP53 now selects bounded local HEV/lwIP handling before
an original-destination Direct socket is created. Complete framed messages use
the shared DNS proxy and current QName/CNAME policy, with independent request
identity, legal local TCP replies and normal SQLite observations. Root/VPN,
IPv4/IPv6 and ordinary UDP/TCP replacement entrances have composed acceptance.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md),
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) and
[SAKAMOTO-318](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/2b15f3ae-6823-4e27-a219-68dcc1cec180).
The VPP-native C boundary in ADRs [0006](../adr/0006-vpp-native-packet-io-adapters.md),
[0007](../adr/0007-owner-local-lwip-direct-egress.md) and
[0008](../adr/0008-remove-snort-cpp-mainline.md) remains unchanged.

The independent [final union](../../build-output/s314-vpn-tcp-20261023/coordination/root-s318-r5d-78groups583whole-final1656-union-audit.json)
qualifies **78 composed groups and 583 unique required whole records** in one
closed normal SQLite MAIN containing **1,656 DNS records**. It combines R4
48 groups/440 required records and R5 30 groups/143 records; it is not one
78-group invocation or a claim that every R4 case ran on R5. Of the 583 required
records, 571 have a reliable caller and 12 retain actual cold Unknown callers.
Original whole-run HOLDs remain HOLD.

## Runtime and observation behavior

One owner retains at most **8 local TCP clients, 128 pending/output slots and
2 MiB owned TCP bytes**. The shared proxy retains its **64-transaction** limit.
Two-byte framing accepts split headers, split messages, pipelines and bounded
out-of-order replies. A refused message does not close an allowed neighbor.
Complete frames before FIN survive a partial final frame; RST cancels promptly.
Owned copies and existing owner-local callbacks carry asynchronous work; borrowed
VPP, NFQ or HEV memory does not escape its established lifetime.

Generation, Flow incarnation, transport session and per-message token remain
separate. Qualified per-message caller facts do not rewrite an earlier Unknown
record or invent a caller from a return packet. TUN return provenance and any
Unknown return UID remain explicit. The public DNS record stays **704 bytes**;
opaque/completion layouts and the existing submission/readback path are reused.

A live local session stays local across configuration OFF. An OFF follow-up
receives a legal SERVFAIL with an actual zero upstream endpoint and no selected
upstream dispatch. Its normal record now survives public decode, normal store
consumption and SQLite reopen. After ON, a later message on that same socket
uses the current route/network view; original SYN bindings and old in-flight
identities remain unchanged. A newly admitted OFF connection uses the original
route. Its observed original SYN qualifies routing, not public resolver success.

Canonical proxy record keys distinguish transport/profile/family/session/view
scopes while retaining old keys, raw payloads and received clocks. A true
same-identity body conflict still rejects. Historical rejected records are not
synthesized or repaired in place.

## Artifacts and persistent build reuse

Fixed review base: `9be0a8743aa722a282ad4517f4d5bcf949e16fb2`.
The [R5 prebuild source](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/prebuild-source-r5.json)
pins 359 inputs. The complete [370-input device source](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/remaining-device-r5d-batch-source-index.json)
adds the actual harness/fixture/runner changes. At that R5 capture, all **266 runtime inputs** matched
the selected R5 artifact; later wire and deadline fixes affect its acceptance
harness. No C++ compatibility implementation or POC source was imported.

| Identity | SHA256 |
| --- | --- |
| R4 selected APK | `917a234e15d772399d2d88bce9e5c22f681e06c0ef0a4f6d3a62ed13a5e1e868` |
| [R5 selected APK](../../build-output/s318-vpn-tcp-dns-20261025/android-apk-high-default-r5/repeat/sakamoto-runtime-debug.apk) | `a048ee0c95c7d715ce408b2ffcccfec940bcb4dcb50535c8dbb814808c6e694e` |
| R5 plugin payload | `8c02f36326c27c630a6ca4d877864066cf7747585030d701da6760ba28a2e665` |
| R5 Rust core payload | `8314f06a4810a2d1ad0799138a330fa32ee8d830673a38679ffc89691b22449e` |
| R5 classes.dex | `8bca32c11fc24bd98112dc7ade2ad0ec9b849a62be2fa9d30f1b4c9b7f9e871a` |
| R5 closed test MAIN | `311e2773b8016688f287059d5c910e8041860420523751e89213546defcc2bc2` |
| R5 complete test-data tar | `7ce364b260871bdb1ffc585687a55b76cc7cbc7247785d2bacd06a18198cc40b` |
| Restored original APK | `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110` |

The [native pair](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/native-current-r5-result.json)
used the existing Android cache: first Rust1/Ninja3, repeat0/0, all **777** compiled
metadata entries exact and native payloads identical. Three independent
[raw compiler outputs](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/frozen-native-r5/manifest.json)
strip exactly to selected payloads. The [APK pair](../../build-output/s318-vpn-tcp-dns-20261025/android-apk-high-default-r5/result.json)
compiled Java/D8 once, then zero times; all **182** class/DEX metadata entries
remain exact and all 12 native/APK joins match.

The Linux Host pair used its separate persistent cache: first Rust1/Ninja2,
repeat0/0 with **3,520** metadata entries and all 36 payload paths exact. Its
initial socket-restricted RuleRuntime HOLD remains raw; the unchanged exact
artifact subsequently passed both normal Stop/residue checks with socket access.
No dependency build was created under an evidence directory.

## Composed actual App, wire and normal SQLite acceptance

| Artifact and measured groups | Groups | Required whole records |
| --- | ---: | ---: |
| R4 VPN N1/N3 dual-stack core: full RR/TCP continuation, same-ID out-of-order, independent query/alias denial, half FIN and partial FIN | 24 | 132 |
| R4 dual-stack RR/EDNS, upstream RCODE, FORMERR/NOTIMP, observe and current-policy hot refusal | 14 | 88 |
| R4 deadline, late/fresh recovery and prompt FIN/RST cancellation | 8 | 22 |
| R4 65th-request capacity failure and fresh recovery | 2 | 198 |
| R5 dual-stack OFF/ON same old socket plus independent fresh success | 4 | 24 |
| R5 actual pending Stop, old-generation late answer and fresh restarted socket | 2 | 5 |
| R5 VPN App UDP TC, then separately launched App TCP with the same ID/Question | 4 | 18 |
| R5 VPN N3 UDP regression | 2 | 12 |
| R5 Root N3 dual-stack TCP core | 12 | 66 |
| R5 Root App UDP TC, then separately launched App TCP with the same ID/Question | 4 | 12 |
| R5 Root ordinary UDP and same-candidate TC/TCP continuation | 2 | 6 |
| **Composed union** | **78** | **583** |

The [six final R5 cohorts](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/remaining-device-r5d-batch.json)
ran strictly sequentially and all launcher/driver processes actually exited zero
and were reaped. They add to the separately sealed R5 toggle cohort. VPN retry
records include 12 reliable rows plus 6 real cold Unknown warm-up rows; the N3
UDP regression likewise includes 6 reliable plus 6 real Unknown rows. The
controller launches the TCP retry after the App's actual UDP TC receipt; this
is not a claim that the debug App automatically falls back to TCP.

The capacity case independently requires **195** records for 65 complete query
identities, then 3 for fresh recovery. Its early observation arrays do not stand
in for that closed-MAIN assertion. The original 3-second Product deadline stays
unchanged. The final pending Stop retains one active transaction and cancels it
once, with QUERY→STOPPED(ERROR8) in **2,674,048 microseconds** in the native DNS
clock. It is not the earlier observer-induced timeout case.

The old TUN collector finishes before VPN removal. The new TUN binds its own
old-source negative fence through actual late underlay arrival, fresh success
and final Stop; no old identity reappears in the new generation's normal MAIN.
The final accepted Stop/late run has **zero original-resolver TCP53 packets** on
the full underlay interval. A controlled replay separately verifies strict
qualification of an exact payload-free old-App terminal control after an explicit
lifecycle boundary; it does not upgrade the earlier unclassified RST HOLD.
Ordinary active replacement still requires zero original-resolver TCP on every
outer source port.

All 1,648 prior raw keys, payload values and present received clocks survive
unchanged into final MAIN1,656. Earlier checkpoints conserve their entire prior
histories too, including all 1,179 records before R5. The metadata retains
`dns_rejected=2` and `dns_evicted=0`; new rejection/eviction deltas are zero. The
three malformed OFF records lost in the original 2791 run are not backfilled.

## Host checks, red/green evidence and retained failures

[Host qualification](../../build-output/s314-vpn-tcp-20261023/coordination/root-s318-r5-host-build-rule-dns35-full104-qualified-audit.json)
retains the real full-suite result: **104/105 passed**, with the preexisting
`docs/current/README.md` 101-line navigation failure. It also verifies DNS35,
exact-artifact RuleRuntime and scoped Rust **30 passed/13 ignored plus DNS9
passed/1 ignored**. The final navigation entry is checked separately after its
documentation update. This is composed evidence, not an invented single all-green
106-test invocation. R4/R5 reused their frozen HEV normal8,
ASAN8 and UBSAN8 results; the changed R6 HEV inputs have separate checks below.

| Retained failure / correction | Qualified evidence |
| --- | --- |
| Local TCP initially required an original Direct socket; partial final FIN discarded earlier complete work | Original controlled Host REDs and corrected eight-case transport acceptance remain sealed |
| Real same-number DNS records collided in SQLite across proxy scopes | Original missing QUERY/rejected2 kept; same normal decode/store identity seam RED→GREEN and legacy replay, followed by actual N1/N3 readback |
| Selected local TCP with no upstream endpoint was filtered | Real C32×704-byte input → public decode → normal store close/reopen: accepted12 RED → accepted32 GREEN; nine invalid scopes and a true body conflict still reject |
| Same old socket did not dispatch a later ON/current-view request | Same Host test/libraries RED SIGABRT → GREEN44 records, then actual dual-stack three-message same-session App/TUN/SQLite acceptance |
| 68ms remaining could spawn a remote operation; expired case clocks blocked local reap/cleanup | Real subprocess RED→GREEN55 across Trace, inherited Device and Peer; minimum start budget, separate finite reap and reserved cleanup; actual lost-ACK counter executes once and independent witness prevents replay |
| Stop/late whole fence encountered an unclassified old-flow RST | Original 2793/2794 whole HOLD kept; full wire identity and lifecycle replay has strict counterexamples, and new actual Stop/late validates native socket ownership plus both TUN generations |
| New observer incorrectly used the normal projection's unavailable PID | Original 2795 precondition HOLD kept; native actor is selected by executable/UID/owned startup and rechecked by PID/start/UID |
| Observer work used 3.959s before Stop, so Product legitimately timed out at 3.000113s | Original 2796 HOLD and SERVFAIL delivery kept; measured critical path was expanded once, fd reads batched and only proved terminal file retirement deferred until after Stop; subsequent real pending Stop passed |
| Sandbox socket restrictions, an already-retired helper path, earlier framing/observer and mixed fixture-ABI failures | Raw setup/HOLD records remain separate from Product results; only affected entrances rerun after concrete correction |

The current wire/lifecycle helper has a sealed **8-method** standalone pass;
the earlier registered CTest pass is separately retained at its earlier source
scope. The 55 transport/cleanup tests include real short-budget zero-spawn,
bootstrap exhaustion, witness-read exhaustion, cancellation, partial output and
local reaping. Already completed remote operations are not automatically replayed.
Stable problem-family clocks and the complete ownership/cost inventory remain in
[coordination](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/).

## R5 device restoration retained as evidence

Before restoration, all **5,332** final private-data members were actually
[measured and archived](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-test2803-before-original-r5-receipt.json)
with a complete 307,590,144-byte tar, exact before/after graphs and no socket
members. The [executed original restoration](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/original-restoration-receipt.json)
reinstalled the original APK and restored all **4,861** original members. Exactly
two content fields changed: the state and ledger `generation` moved from 2778
to the freshly measured maximum **2803**. No earlier backup or generation rollback
was used. KSU app root grant, Android permissions, SELinux labels/state, CPU
frequency settings, Wi-Fi preference and stay-on setting match the original.
That restoration finished stopped in the original VPN profile, with no package/native owner.

Seven exact owned remote archive pairs were retired or already absent after
local tar and original producer-witness hashes were verified. All raw host
evidence remains. A final [post-cleanup full graph](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-owned-remote-archive-retirement-r5/result.json)
still matches all 4,861 restored members and BOTH2803. No foreign process was
signalled, no unrelated resolver was unbound and no Product Stop was replayed.

## R6 progress correction and final restoration

Final Standards review found that occupied local pending/output slots imposed a
10ms timer even while waiting for upstream or ACK progress. The retained actual
RED measured **131 timer wakes in 1.317181916 host seconds**, above the unchanged
51-wake bound. A separate public HEV owner-step RED showed that a bounded large
write failed to advertise immediately writable remaining work.

R6 removes the occupancy clamp and reports local runnable work only after actual
successful write progress with remaining send capacity, or closing work. A full
send buffer, failed allocation and fully written ACK wait use their actual event
or protocol/local deadline. Existing new-reply and ACK schedules remain in use.
The same physical gate assertion then measured **5 timer wakes in 1.292232602
host seconds**, below its original formula's 50-wake bound, with no ready wake.
Peer release reached the App before any later CLI or observation command.
These are native cumulative counters over host sample-return boundaries, not an
absolute clock conversion, exact transmit-time measurement or CPU claim.

The [R6 composed readback](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/r6-composed-19groups92-whole301.json)
qualifies **19 groups and 92 unique complete records**, each exactly once in
closed MAIN**301**: 86 reliable caller records and 6 actual cold Unknown records.
It preserves all 8 pre-R6 RED-baseline records and does not backfill old R5 data.
The earlier 78 groups/583 records in R5 MAIN1656 remain separate evidence.

| R6 measured scope | Groups | Required whole records |
| --- | ---: | ---: |
| Quiet upstream wait/release and dual-stack greater-than-60KB actual App replies | 3 | 9 |
| Corrected strict pending Stop, actual late arrival and fresh restarted App | 2 | 5 |
| N3 IPv4/IPv6 TCP core, with actual owners 0/1/2 in each family | 12 | 66 |
| N3 UDP regression, including 6 real cold Unknown records | 2 | 12 |
| **R6 composed union** | **19** | **92** |

The first three cases are qualified inside a retained whole-run Stop HOLD; they
are not a green whole invocation. That observer chain let the real 3-second
Product deadline expire at **3.012877 seconds**, producing TIMEOUT3 instead of
the required STOPPED8. Shared log preparation now opens the same owned reader
before the App query, reuses it for normal or failure cleanup, and removes an
unused second CLI query. Actual pending/local counters, exact socket identity,
terminal/drop-free TUN capture, whole underlay fences and the original ERROR8
assertion stay intact. The [new strict Stop/late run](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-vpn-n1-stop-prepared-r6c/result.json)
cancelled at **2,342,744 native microseconds**, then passed both TUN generations,
late-answer exclusion, fresh App success and final resource-zero Stop.

The [shared Host invocation](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/timer-shared-host-r6/result.json)
passed **56/56** HEV/Direct/UDP/broker/Flow-stack tests. Its progress fixture is
the earlier c7d863 source; separate ASAN10/UBSAN10 checks use that same source.
The expanded [public owner checks](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/timer-memory-deadline-r6/result.json)
retain those progress assertions and add a real four-pbuf allocation failure,
non-runnable wait and actual unchanged 10-second local expiry: normal2,
ASAN/LeakSanitizer2 and UBSAN2 pass. Both new public CTest entries are registered
and passed separately. Lifecycle35 and wire8 passed through the corrected runner.
The first LSan ptrace-environment failure remains raw; its stale RUNNING JSON
is qualified by the actual terminal1/reaped controller receipt, not treated as live.

One evidence-wrapper bookkeeping failure occurred after spawn but before its
first PID receipt. Its original PID/start/exit/reap remain **unobserved HOLD**;
a later exact host inventory proves no current survivor, not a historical wait.
The final [owned-command checks](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/rtk-owned-tree-finally-final-r6/result.json)
use actual RTK-prefixed descendants and receipt exceptions. They verify natural
completion and bounded per-PID/start/session cleanup, adopted-child wait/reap,
restoration of the prior local subreaper value, and an untouched outside-session
sentinel. No process-name kill or killpg is used. Public route receipt and native
clock-tick failures likewise report only after child settlement. The same helper
covers the three R6 builder wrappers and restoration runner; their bookkeeping
correction does not rebuild or relabel the already sealed Product artifacts.

The selected [R6 APK](../../build-output/s318-vpn-tcp-dns-20261025/android-apk-high-default-r6/repeat/sakamoto-runtime-debug.apk)
is `e6a642f86a44751669ac98d46e14f941322dc3481d9653b7b7c171a2af191056`.
Its plugin payload is `e1215e2d5dde07265a3b72b24be96da93709401a4265de66d7b2079e48a15e46`;
Rust, JNI and DEX match the R5 rows above. Native first/repeat compiled Rust0/
Ninja4 then0/0 with 777 exact metadata entries. APK Java/D8 compiled0/0 with
182 exact entries and all 12 native joins. Host first/repeat compiled0/4 then0/0
with 3,539 exact entries and 36 exact payload paths; its exact-artifact rule
contract passed. Independent [raw R6 compiler outputs](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/frozen-native-r6/manifest.json)
match the selected stripped payloads. All 266 runtime inputs match the sealed R6
prebuild; later closure changes are tests, harnesses, bookkeeping and this report.

Final closed MAIN301 is `3fd1b9f1e4dc062a3f4ed7d99651e655c6d6440415bb21bf1ccd63ff3bb15ded`.
All **4,956** final private-data members were actually
[preserved](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-test2809-before-original-r6-receipt.json)
in a complete **103,528,960-byte** tar with SHA256
`9c3471210709b4fe13b7959a2227a0a0c449e4e4de3a77f130795f2dcdaf005c`; its MAIN bytes match that closed readback.
The [executed R6 original restoration](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/original-restoration-r6-receipt.json)
restored original APK `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and all **4,861** original members. Only the two generation contents change from
2778 to the freshly measured **2809**. Root grant, Android permissions, labels,
SELinux, CPU frequency settings, Wi-Fi and stay-on remain verified.

The [final exact remote retirement](../../build-output/s318-vpn-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-owned-remote-archive-retirement-r6/result.json)
qualified ten owned archive pairs as retired or already absent after local tar
and producer-witness hashes were checked. It released 114,472,675 logical bytes
and 114,601,984 allocated bytes while retaining all raw host evidence. Its final
full graph still matches all 4,861 original members and BOTH2809, stopped in the
original VPN profile with no package/native owner. No Product Stop was replayed
and no foreign process was signalled.

Qualification remains controlled Pixel hardware, ordinary socket upstreams and
the stated Host seams. This ticket does not implement the following cache or
encrypted-upstream tickets, association consumption, deferred cross-App/profile
visibility policy, a UID-resolver redesign, release/device coverage or a
performance claim. Earlier failed whole runs and their clock/transport limits
remain evidence, not retroactively green results.
