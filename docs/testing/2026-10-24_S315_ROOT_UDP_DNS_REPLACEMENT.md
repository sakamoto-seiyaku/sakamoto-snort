# S315: explicitly configured Root UDP DNS replacement

S315 adds optional ordinary UDP53 replacement to the existing VPP-native C
runtime. Normal Root startup connects the configured single ordinary IP
upstream; disabling replacement preserves the original resolver path. The
shared DNS core applies current query and response policy, and the Root Adapter
preserves original App/resolver facts and provides bounded asynchronous sockets
and legal generated returns. There is no additional runtime or DNS thread.

The authority is the [approved DNS specification](../product/APPLICATION_DNS_SPEC.md)
and [SAKAMOTO-315](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/8fb5dc78-af44-4630-9e55-f1103c19ed41).
This record qualifies **35 composed groups**, rather than one successful full
invocation. Original failed attempts remain failed. The original APK and all
4,861 private-data members were restored after qualification, preserving both
fresh generation fields at **2727**.

## Source, artifacts and cache reuse

Review base: `9fd8451c1db839f19c8313614371f92a8f2bd4ab`.
The [250-file Product source identity](../../build-output/s315-root-dns-20261023/artifact-source-identity-r17.json)
pins the selected native, Java and build inputs. The final Device source is
frozen in each raw run; the coverage receipt verifies its current-source join.

| Selected artifact | SHA256 |
| --- | --- |
| [APK11 repeat](../../build-output/s315-root-dns-20261023/android-apk-cache-r11/repeat/sakamoto-runtime-debug.apk) | `3d6313242c79e8b14dc08cdcb6bac46d7a8e2e19d43852e68944da08775625b5` |
| Native17 `libproduct_core_plugin.so` | `0395bb2833c9721c00d64039d895b8218182a58c96f67a5120ee90a59934dbaa` |
| Native17 `libsakamoto_product_core.so` | `6149d82271c3c01952368e84780ba4b62e6af571b9e0704cc9303fae2c622d9d` |
| Native17 `libsakamoto_runtime_control.so` | `2a17aaeee114e4b37bfd3d4c15e22f0a2596bb0cd5c2b6188e817e60f0162ddd` |

Each current Device run independently hashes the installed APK and all 12
native payloads against Native17. Stage properties alone are not the payload
identity. [Android native](../../build-output/s315-root-dns-20261023/android-native-cache-r17/result.json),
[Host13/14](../../build-output/s315-root-dns-20261023/native-host-final-r4.json)
and [APK](../../build-output/s315-root-dns-20261023/android-apk-cache-r11/result.json)
publications reuse the Product caches. Native repeats compile zero Ninja/Rust
inputs, with 974 Android and 3,281 Host compiled-file states unchanged. Both
APK11 publications reuse all 182 Java/DEX outputs. The
[frozen symbol companions](../../build-output/s315-root-dns-20261023/symbols-r17/receipt.json)
reproduce the staged libraries with the official NDK strip tool. Plugin/JNI
companions have debug information and build IDs; the Rust companion has a
symbol table, without line debug information or a GNU build ID.

## Processing, identity and bounds

The complete-message core reuses the existing policy and c-ares wire boundary.
Accepted upstream answers retain their bytes except the request DNS ID. A
denied query is not dispatched; denied queries or answers produce REFUSED.
Transport/deadline and capacity failures remain distinct from policy, while
safe malformed requests and unsupported opcodes produce FORMERR and NOTIMP.
Real upstream NOERROR, NXDOMAIN, REFUSED and SERVFAIL retain their source.

UDP TC continues over nonblocking TCP to the same resolver under the original
three-second deadline. UDP retries occur once at 1.5 seconds. Local replies
preserve Question, RD/CD and applicable OPT/DO, with a 512-byte ordinary or
at-most-1,232-byte EDNS capacity and legal TC envelope when needed. A causal
[host RED/GREEN receipt](../../build-output/s315-root-dns-20261023/coordination/edns-local-causal-receipt.json)
records the invalid OPT constructor class corrected to `ARES_CLASS_IN`:
seven query types, deadline SERVFAIL, local TC and capacity replies pass. The
same final regression fails at the reply callback with the old class. Earlier
test-observer correction and the unavailable original red-executable hash are
explicitly qualified. Actual App EDNS SERVFAIL and TC are separately proved by
[the current supplemental run](../../build-output/s315-root-dns-20261023/device-edns-r1/result.json).

Transactions retain generation, owner-local request/attempt, Flow incarnation,
network and route identity. Completion retires an obligation before cancellation
callbacks; stale keys and late answers cannot complete it again. Response
policy is acquired again before delivery. Actual gated tests require a native
pending transaction after canonical UI publication; the Product deadline is
unchanged. Route changes and normal stop cancel old obligations. Late old
answers are observed on Device underlay without becoming generated App returns.

Per owner, normal CLI output exposes limits of 64 transactions, 128 reply/waiter
slots, eight total sockets and an 8 MiB shared work budget. Current N1 overload
uses two ordinary Java App socket batches, 32 plus 33 queries: 64 reach upstream
(128 datagrams including retries), the extra request gets resource SERVFAIL,
and all 65 App replies are independently checked. Observed high-water values
are 64 transactions, 583,588 proxy-owned bytes and 70,048 socket bytes, within
the published bounds. This is a controlled capacity result, without a general
throughput claim.

Generated Root returns use the normal return/completion seam, original resolver
source and App destination, hop limit one and validated IP/UDP checksums.
Successful return observations retain original App identity while recording
the actual generated packet UID and return provenance. A separate privileged
raw IPv6 negative probe qualifies obsolete-address confinement to loopback;
it is not an ordinary App or Product semantic test.

Valid 2,048-byte EDNS padding exceeds the actual Root receive envelope. With
replacement active, its incomplete captured obligation terminates locally as
resource/coverage failure, without invented policy/RCODE, upstream dispatch or
unsafe reply. With replacement disabled, the same ordinary App datagram takes
the original route and receives the exact controlled answer. The 65,535-byte
codec bound and larger codec-workspace exhaustion are Host qualifications;
they are not a maximum-size Device datagram claim.

## Composed actual Device coverage and normal SQLite

The [final coverage receipt](../../build-output/s315-root-dns-20261023/coverage-final-r2.json)
pins 8,152 raw inputs, the exact source reuse and these canonical groups:

| Actual run | Generation / owners | Canonical groups | Scope |
| --- | --- | ---: | --- |
| [Full R15 qualified prefix](../../build-output/s315-root-dns-20261023/device-full-r15/result.json) | 2725 / N1 | 21 | Dual-stack ordinary/off paths, RR/EDNS, local errors, query/CNAME/Observe policy, current-policy update, TC/TCP, RCODE, client capacity, upstream port53/deadline/view change, padded admission and actual system resolver IPC |
| [Current completion run](../../build-output/s315-root-dns-20261023/device-completion-r1/result.json) | 2726 / N1 | 2 | Capacity and active-stop cancellation; two repeated hot-control cases remain supplemental |
| [Complete N3 run](../../build-output/s315-root-dns-20261023/device-n3-final-r1/result.json) | 2727 / N3 | 12 | All N3 planned ordinary/off, padded, policy, current-policy, TC/TCP and active-stop cases |
| Total | Same APK11 / Native17 | **35** | 37 actual passing cases including two supplemental controls |

R15 remains HOLD: its client-capacity loop variable shadowed the later capacity
function. The [exact three-line rename](../../build-output/s315-root-dns-20261023/coordination/full15-current-matrix-name-only.diff)
preserves every completed prefix assertion. A causal actual-matrix caller
regression reproduces that TypeError, then reaches the capacity call after
both client sizes at N1 and completes N3 dispatch. Native/APK inputs did not
change. The existing timing path then exercised the actual remaining N1
capacity/stop helpers before the full N3 run.

The ordinary App uses real `DatagramSocket` calls. The system case uses actual
Android `DnsResolver.rawQuery` IPC; native DNS caller remains Unknown and does
not inherit the App's domain denial. Wire capture and independent peer receipt
verify selected destinations and original-path preservation. Capture is bounded
to 1,024 selected packets, 16 MiB payload and 1,200 seconds per helper, with
recorded zero socket drops in these runs. IPv4 fragmented coverage distinguishes
the first fragment; it is not a complete arbitrary-extension/fragment recorder.

After ordinary stop, the independently exported
[SQLite file](../../build-output/s315-root-dns-20261023/device-n3-final-r1/n3-overall.sqlite3)
has SHA256 `b552ba9ce481a018282c3023faad5a2ee87f36d5ea45c50366aec084e40c2e27`
and passes integrity checking. It retains all three generations: 234, 271 and
35 DNS rows respectively. There are 245 exact canonical case-record
comparisons plus seven supplemental comparisons, and all 65 capacity requests
have query/resource/result stages checked with exact App UID and source port.
These counts describe comparisons, not distinct record counts. Metadata reports
`dns_accepted=2464`, `open_session=false`; the N3 pre-stop commit target is 2463.

Stop history is bounded and loss-tolerant: current N1 generation2726 persists
its query and STOPPED terminal, while generation2727 persists the query without
the STOPPED terminal. The normal consumer records its stop gap. This is not
lossless terminal-history acceptance. Native cancellation, App timeout, actual
late underlay and absent generated return are separate evidence. Stop logs
prove zero transactions/upstream/raw sockets/replies across all owners; raw
opens/closes balance 8/8, 4/4 and 7/7 + 8/8 + 7/7. Root native-zero, process,
hook, queue, wire, peer, trace and route cleanup are independently retained.

## Checks, retained failures and restoration

The [final check closure](../../build-output/s315-root-dns-20261023/coordination/host-final-check-closure-r3.json)
maps 21 current checks to the changed codec/current Host14 and documentation,
and reuses 63 source-qualified unchanged checks, plus 47 harness regressions. It
retains the original 77/84 and corrected7/7 history; this is not one 84/84 run.
The final documentation navigation/reference checks are among those 21 checks.

All [full attempts](../../build-output/s315-root-dns-20261023/coordination/full-attempt-index-final.json)
remain retained, including missing-result/unqualified attempts. Earlier native
ingress/IPv6, control deadline and trace ownership failures have their own
source-linked evidence and qualified review history. The visible diagnostic
window now stays awake; an identical controlled 32-second UI operation had
Dozing RED then Awake GREEN without changing device power settings. R13's
hot-policy failure preceded policy publication; the corrected harness proves
actual pending business state instead of weakening REFUSED or timing assertions.
Only Windows UDP receive-side `ConnectionReset` is counted and continued by the
controlled peer; no datagram is admitted or send replayed, and other errors fail.

R14's valid selected-upstream RR wire had no independent peer receipt. Its
cause remains **unproven**. An exact minimized original prefix and the current
R15 RR case pass; that recovery is not attributed to the separate OPT local
reply fix. Historical stop gaps and absent red-binary identity remain qualified.

[Executed original restoration](../../build-output/s315-root-dns-20261023/restoration-final-r4/receipt.json)
passes. R3 first stopped before install/swap because its complete 243 MiB
posttest archive exceeded a 128 MiB guard. The exact completed archive was then
boundedly transferred, device/local hashed, fully parsed and frozen with all
5,090 fingerprints; its SQLite equals the accepted export. Only after preservation
was that exact remote archive removed. R4 adopts the pinned immutable snapshot,
freshly verifies BOTH and five critical live hashes, and retains the original
staging/restore checks. It does not truncate evidence or raise a generic limit.

The posttest archive SHA256 is
`d19f53d9a6b28e7eda362acfe67eca6ca08d18b5a1c93ff0b733297dc39736e0`.
Original APK `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and all 4,861 original members match before swap and after cleanup; only the two
generation fields advance from 2697 to the fresh maximum 2727. Rules, original
SQLite, preferences, granted Android permissions, root grant, frequency,
Wi-Fi and stay-on setting match their baseline. SELinux verification covers the
recorded rules/preferences/observation trees. Final state is stopped VPN,
`mayBeActive=false`, with no native runtime, owned hooks or queues. All 31 exact
trace directories are absent; the remaining directory was archived before
removal. Kernel FIN_WAIT entries from closed App probes are not an owned-process
leak or an all-kernel-sockets-absent claim.

This scope does not establish VPN or Root TCP-client replacement, encrypted
upstreams, answer caching, association consumption, KSU/libnetd integration,
cellular handover, general public-resolver compatibility, supported-device
coverage or performance/power budgets. Existing original-path Root/VPN TCP
qualification remains separately scoped.
