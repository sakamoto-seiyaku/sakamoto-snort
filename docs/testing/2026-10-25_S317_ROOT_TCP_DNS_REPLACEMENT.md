# S317: optional Root TCP DNS replacement

Root now automatically redirects selected client TCP53 connections into bounded
VPP-owned DNS socket I/O. Framed messages reuse the shared DNS proxy, current
QName/CNAME policy and existing ordinary upstream transport. A denied message
returns REFUSED without closing unrelated messages on the same connection.
The original SYN caller, original destination, Flow incarnation, generation and
per-message token remain distinct from later capture facts and socket returns.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md),
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) and
[SAKAMOTO-317](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/6d16bf8e-56bd-4493-9ad2-57f4334d7a94).
This record qualifies **70 composed groups on one R3 APK**, across 16 actual
cohorts. It is not one all-green invocation. The original APK and all **4,861**
private-data members were actually restored, with both fresh generation fields
at **2778**. Failed runs remain raw HOLD.

## Artifacts and build reuse

Fixed review base: `912e835c00dec28c504927de6eeb56f62b8d7fd0`.
The [R3 prebuild source](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/prebuild-source-r3.json)
pins 304 inputs. Subsequent Host/Device fixture changes do not change the
237 Product C/Rust/JNI/Java runtime inputs used by the accepted Android artifact.
The final source identity and review receipts are retained in coordination.

| Selected artifact | SHA256 |
| --- | --- |
| [R3 repeat APK](../../build-output/s317-root-tcp-dns-20261025/android-apk-high-default-r3/repeat/sakamoto-runtime-debug.apk) | `dc96d935672571790a69b02fe1b7e97dc1b7eba9d53606869373d4f7b04b9270` |
| `libproduct_core_plugin.so` payload | `2efd1e4995b7943c7417e45f96b0c463d506043607fae797fa8f56cbdfd65b69` |
| APK `classes.dex` | `639c6381b51e432b7a308c86be21a3ed4d626297ecb2656505e9d106766a8bfc` |
| Final accepted SQLite MAIN | `13cf1e054b5e7e5d178bebe35b541030d007b4c89a752d3aa0e7c2e878609db0` |

The [native pair](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/native-current-r3-result.json)
used the persistent Product cache: first 0 Rust compilations/4 Ninja actions,
repeat 0/0, all 777 compiled-file metadata entries exact and all 12 payloads
identical. Three raw compiler outputs were copied to independent files before
cache reuse; stripping independently reproduces the packaged payloads, with
all allocated ELF sections and program headers checked. No build-ID claim is made.
The APK first build compiled Java/DEX once; its repeat compiled neither. All
182 class/DEX metadata entries and all 24 native/APK joins were verified.

The final current-source Linux Host pair uses its existing separate persistent
cache and verified S296 stage: first Rust1/Ninja26, repeat0/0, all **3346**
compiled-file metadata entries exact and all 36 listed payload paths identical.
[Host build receipt](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/host-final-artifact-and-rule-r2-result.json)
retains a sandbox RuleRuntime HOLD after the successful pair; the unchanged
[exact-artifact RuleRuntime](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/host-unified-rule-runtime-final-r3-result.json)
subsequently passed outside the socket-restricted sandbox, with both normal
Stop/residue-clean witnesses. The original sandbox owner exited; its three
stale marker/config files were copied and removed by exact identity, without
signals, and separately verified residue-clean.

## Transparent ingress, identity and bounded lifecycle

IPv4 uses ordinary NAT REDIRECT. This Pixel kernel has no IPv6 NAT table;
IPv6 uses native transparent listeners, scoped packet/conntrack routing tags,
a dedicated local route and lo TPROXY. The tag is routing state only. It never
supplies caller, policy or session authority. Listener marks prevent reply
route inheritance; nonzero-only tag restore preserves unrelated existing marks.
Admission, current-view and old-flow ownership qualify route-or-drop behavior
across disabled/closing, primary rejection, parse and reassembly exits.

One owner keeps at most **8 clients, 128 output/pending slots and 2 MiB owned
output bytes**; the shared proxy keeps its existing **64 active transactions**.
Complete requests use a persistent socket sequence with an independent high-bit
message token. Multiple same-ID requests can complete out of order. Complete
frames before FIN remain valid; an incomplete final frame does not cancel prior
complete frames. Later reset cancels promptly, including after FIN.

Original SYN caller availability/UID is frozen. A later Known capture cannot
upgrade an originally Unknown or unreliable caller. Captured input facts remain
separate from that authorization. TCP socket returns use their actual socket
provenance and 65,535-byte capacity; they do not claim a VPP packet return.
The public 704-byte DNS record remains normally committed and read independently.
Opaque40 and completion32 layouts retain their existing sizes.

NFQUEUE scalar, sendmmsg and packed paths preserve ordinary **32-byte** verdicts
and serialize tagged verdicts as **40 bytes**, including mixed batches. Original
non-mask mark bits remain exact; invalid origin/owner/collision cases drop.
A statistics flag is not authority: its absence remains a legal tagged positive
with the statistics counter zero. These are controlled Host sender assertions,
not observations of every Android verdict mode.

## Composed App, wire and normal SQLite acceptance

The [independent final union](../../build-output/s314-vpn-tcp-20261023/coordination/root-s317-r3-70canonical-662whole-final-device-union-audit.json)
checks **654 distinct required complete public records**, plus **8** independently
derived replacement-OFF original-path records, in one final **1,593-row MAIN**.
Every selected earlier MAIN payload and received clock remains exact; all 591
underlying audit pins were rechecked. Recent API page limits were not changed.

| Actual cohort | Generation / configured owners | Groups | Required whole records |
| --- | --- | ---: | ---: |
| [device-n1-smoke-r3-observer-r2](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-smoke-r3-observer-r2/result.json) | 2758 / N1 | 2 | 6 |
| [device-n1-pipeline-r3-observer-r2](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-pipeline-r3-observer-r2/result.json) | 2760 / N1 | 10 | 60 |
| [device-n3-core-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-core-r3/result.json) | 2761 / N3 | 12 | 66 |
| [device-n1-lifecycle-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-lifecycle-r3/result.json) | 2762 / N1 | 8 | 22 |
| [device-n3-lifecycle-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-lifecycle-r3/result.json) | 2763 / N3 | 8 | 22 |
| [device-n1-capacity-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-capacity-r3/result.json) | 2764 / N1 | 2 | 198 |
| [device-n3-capacity-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-capacity-r3/result.json) | 2765 / N3 | 2 | 198 |
| [device-n1-toggle-r3-reconciled-r2](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-toggle-r3-reconciled-r2/result.json) | 2767 / N1 | 4 | 12 |
| [device-n3-toggle-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-toggle-r3/result.json) | 2768 / N3 | 4 | 12 |
| [device-n1-stop-late-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-stop-late-r3/result.json) | 2769, 2770 / N1 | 2 | 5 |
| [device-n3-stop-late-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-stop-late-r3/result.json) | 2771, 2772 / N3 | 2 | 5 |
| [device-n1-udp-regression-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-udp-regression-r3/result.json) | 2773 / N1 | 2 | 6 |
| [device-n3-udp-regression-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-udp-regression-r3/result.json) | 2774 / N3 | 2 | 6 |
| [device-shared-vpn-minimal-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-shared-vpn-minimal-r3/result.json) | 2775, 2776 / N1/N3 | 2 | 12 |
| [device-n1-client-retry-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n1-client-retry-r3/result.json) | 2777 / N1 | 4 | 12 |
| [device-n3-client-retry-r3](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-n3-client-retry-r3/result.json) | 2778 / N3 | 4 | 12 |
| Total | 16 cohorts / 19 generations | **70** | **654** |

Dual-stack Root core groups check split/coalesced framing, full answers,
same-ID reverse-order completion, QName and connected CNAME REFUSED with an
allowed collateral message, half-close and partial final frames. N3 core uses
all three actual owners. Complete TCP stream bytes and original endpoints are
checked alongside whole query/result/delivery records and actual App UID12632.

Both lifecycle cohorts cover the actual three-second deadline and FIN followed
by SO_LINGER reset before that deadline. Old upstream replies arrive on Device
wire within a strict two-second observation budget; the no-return interval
continues through fresh success and final normal Stop. Both pending-Stop runs
hold **one** request, observe terminal result enum8 (STOPPED), restart with a
fresh generation, witness the old reply, and complete a new request. Enum8 is
not a claim of eight pending requests.

Each capacity cohort sends 65 distinct frames on one real connection: 64
transactions each issue two planned-silent UDP attempts, the 65th has no upstream
request, and all 65 legal SERVFAIL frames plus all 195 complete terminal records
are checked independently. A fresh positive adds three records. Actual stressed
owner is N1 owner0 and N3 owner1; this is not simultaneous stress of all N3 owners.
Resource snapshots are bounded, with no pending output after completion.

Ordinary UI off/on returns one old-view SERVFAIL, witnesses the old reply and
then allows a fresh proxied connection. OFF actual App responses are full
original-resolver NXDOMAIN/SOA messages with full Question and matching wire;
these are stronger independently derived facts than the fixture's conservative
`resolver_success_asserted=false`. OFF has zero proxy clients; retained blocked
old output while reopening listeners is qualified by real POSIX mode6 and the
source-linked Host check, not claimed as a Device blocked-output case.

The client-retry cohorts additionally establish the distinct causal chain:
ordinary client UDP receives **44-byte TC** at capacity512, then that client
uses TCP with the same ID, complete Question and original resolver to receive
**682-byte full DNS / 684-byte framed output**. Both transactions independently
use upstream UDP-TC to same-candidate TCP. Earlier direct-TCP smokes receive
676/678 bytes and are not relabeled as client retry.

Directed shared regressions cover Root UDP small/full-to-client-truncation
behavior and actual VPN IPv4 UDP on the same live Java DatagramSocket, with
cold Unknown then reliable Known caller. VPN is not TCP replacement. The
existing VPN wrapper overwrites its first run's final wire/identity filenames;
N1 per-case TUN/WLAN/MAIN and normal Stop remain valid, but exact final witness
identity/drop-zero is attributed only to N3. No N3 terminal witness is borrowed
for N1. The selected peer uses only port53053; independent Windows UDP53 PID5740
was never stopped or rebound.

## Failures retained and scoped verification

Original R3 gen2757 mixed retained generations in its observer; gen2759 applied
an empty local-error shape assertion to a valid full upstream answer. Their
whole raw runs remain HOLD. Corrected selectors require the actual generation,
and complete upstream bytes/Question/RCODE remain strict. Gen2766 failed before
the UI toggle with uiautomator/reader255; normal Stop was not issued. A fresh
owned transport proved the healthy running owner, then actually stopped it,
read committed MAIN and verified native-zero/route cleanup before continuing.
Original cleanup errors are preserved; later reconciliation does not rewrite them.

The shared TCP family exceeded its expansion threshold and was handled as one
ledger across I/O, identity, lifecycle, ingress, mark serialization and related
entries. Both real R2 regressions are retained: off→on with a retained client,
and FIN→RST unregistration. R3 reopens listeners on retained I/O and keeps error
watching after EOF. Real POSIX regression modes cover both fixes.

Final Host initial invocation is **88 passed / 15 failed of103**, retained
unchanged. Fourteen relevant failed contracts subsequently pass through scoped
corrections and the exact-artifact runtime entry. Fixtures now share the real
mark helper/offset8 and complete public dependencies, reserve a common TCP/UDP
port correctly, reset inherited mark preconditions and retain legitimate
replacement-disabled TCP53 paths. The verdict fixture preserves its original
instrumented failure and tests true invalid owner authority instead of a
statistics-only bit. The 15th failure is the pre-existing README
101-line length against an existing `<100` assertion. Final S317 navigation
content differs from the base while retaining101 lines. One post-docs run
passes all three link/registration/archive checks and fails only that same
line-count assertion; the earlier byte-identity comparison applies before
the navigation update. [Final navigation qualification](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/final-docs-navigation-qualification.json) retains both stages.
This is a **102-case qualified Host union**, not a single103 all-green result.

[Host failure inventory](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/host-final-failure-inventory.json),
[baseline qualification](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/baseline-navigation-101-lines-qualification.json)
and original logs retain those distinctions. Rust native-VAPI workspace checks
pass **92 ordinary tests / 15 explicitly ignored**. A separately selected
ignored integration passes one real source-linked 24-record C producer through
the normal Rust socket, SQLite commit and reopen. Zero-test selection and stale
producer failures remain separate. ASan/UBSan/leak checking passes all **8 real
POSIX TCP-I/O modes**; Android/VPP is not claimed sanitizer-instrumented.

## Executed preservation and restoration

The [complete final test archive](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-test2778-before-original-r3-receipt.json)
retains **5,164 measured nodes / 209,831,424 bytes**, SHA256
`e1fa349ffabcdfda6bef3259a24c2b706d85ffb88c63cd88db889b2241d387b4`,
with exact before/after graphs, tar fields/content, producer0 and complete EOF.
The sandbox relay EPERM and an earlier mistyped APK filename are retained setup
HOLDs; no Product operation was retried to weaken a business assertion.

[Executed original restoration](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/original-restoration-receipt.json)
restores original APK
`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and every original member. Only the two generation values change from2755 to
the fresh maximum2778, read before and after installation. Final state is
STOPPED/native0; KernelSU grant, Android permissions, SELinux, CPU frequency,
Wi-Fi and stay-on settings match the original baseline. All exact owned remote
restore inputs and test archives were removed after local verification; the
[final archive cleanup](../../build-output/s317-root-tcp-dns-20261025/coordination-sol-high-default-r1/device-restoration/earlier-preservation-cleanup-receipt.json)
again proves the original4861 nodes and fresh state unchanged. Independent
[full preservation](../../build-output/s314-vpn-tcp-20261023/coordination/root-s317-final2778-complete-preservation-audit.json) and
[executed restoration](../../build-output/s314-vpn-tcp-20261023/coordination/root-s317-executed-original-restoration2778-audit.json)
audits recheck all raw archive/member identities and the two intentional fields.

This controlled Pixel qualification does not establish VPN client-TCP replacement
(S318), cache, encrypted upstreams, association consumption, UID-resolver redesign,
bound SO_BINDTODEVICE/link-local or extension-header Device coverage, real cellular
handover, broad device support, release readiness or throughput improvement.
