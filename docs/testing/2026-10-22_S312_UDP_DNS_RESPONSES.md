# S312: original UDP DNS replies and connected CNAME policy

S312 adds owner-local UDP request/reply correlation and connected CNAME answer
policy to the existing Root/NFQUEUE and VPN TUN/HEV paths. Allowed answers retain
the original UDP payload and resolver; rejection drops the original answer.
This implements the UDP response slice of the
[application DNS specification](../product/APPLICATION_DNS_SPEC.md).
TCP DNS, proxy/replacement, cache, IP association consumption and the deferred
cross-App/profile association decision are outside this slice.

The [independent composite](../../build-output/s312-dns-response-20261022/qualification.json)
is **PASS_WITH_EXPLICIT_LIMITS**: 62 groups/186 ordinary App messages cover 60
distinct required profile/owner/case combinations. Nine historical Root groups
use the earlier decoder; 53 groups/159 messages use the final APK. The original
failed/HOLD collectors remain unchanged and their scopes are explicit below.

## Source and artifacts

Review base: `55820abe26c3c09efb77ee658e1bc3505b203a45`.
Product implementation: `004d111c44be914d014ce2826ffdf53bd0b780a1`.
The [227-file Product/build identity](../../build-output/s312-dns-response-20261022/reviewed-source-identity.json)
includes the existing Product/Java/build closure and every HEV Product integration
file. Later Host evidence, verifier and documentation changes do not alter it.
The [HEV source-to-binary receipt](../../build-output/s312-dns-response-20261022/hev-source-binary-receipt.json)
checks all seven integration files against each active staged manifest, owner
object identity/header dependencies and final plugin archive link rule.

| Final artifact | SHA256 |
| --- | --- |
| [Android APK](../../build-output/s312-apk-cache-r2-20261022/repeat/sakamoto-runtime-debug.apk) | `dc35700724a27e49b5001a3ed1c6e3d086f8897f8116acde132fc7a027e4cca7` |
| Android `libproduct_core_plugin.so` | `1dda577fc35850b3d28f8823beb4d5c709154bc8747500fd5dd54ea4d0e16391` |
| Android `libsakamoto_product_core.so` | `825ebbe68f19dfb6ffa75a7929efe803f1ff0b305a3965296935bc7311f5b1a2` |
| [Host plugin](../../build-output/product-vpp-host-s312-r2-repeat/lib/vpp_plugins/product_core_plugin.so) | `b35a82f273fffb5a5c2a5f3fe7b082f8817fecab913b6ce1090a6e1034bfc4f7` |

Every actual device run checks the installed APK and all twelve native library
hashes. [Host](../../build-output/s312-host-cache-r2-20261022/result.json),
[Android native](../../build-output/s312-native-cache-r2-20261022/result.json) and
[APK](../../build-output/s312-apk-cache-r2-20261022/result.json) cache receipts
prove unchanged second builds: zero Ninja/Rust/Java/DEX compilations, stable
compiled-file identities and byte-identical native payloads. The persistent
caches retain 1,830 Host and 905 Android compiled files; no per-run dependency
build was created. APK ZIP metadata differs between publications; DEX is reused.

## Correlation, policy and observation

The bounded request record retains the original tuple, DNS ID and complete
Question, direction, resolver/network/interface context, runtime generation,
FlowEntry incarnation and original caller availability. VPN adds the actual HEV
transport session and bound underlay epoch/context through the existing input,
return stamp and TUN path. No ID-only or current-UID guess supplies a caller.
Retransmissions with different wire, caller or historical policy become
ambiguous; completed IDs remain finite tombstones. A later binding or UID lookup
cannot upgrade a completed cold query's Unknown caller.

The response uses one current policy snapshot. Its complete connected QName and
Answer-section CNAME chain and all memberships are prepared before evaluation.
Each name receives the complete rule expression; the winning candidate uses
normal Rank, including alias ALLOW and DROP. Memberships from different names
never form an AND. Unknown/incomplete facts cannot manufacture a NOT hit; a
generic independent rule remains applicable. DNS facts never become SNI, and
transport predicates retain the actual reply direction, addresses and ports.
Additional CNAMEs, MX/SRV targets and HTTPS address hints do not extend the chain.

Normal DNS observation ABI v6 is 576 bytes. Rust retains v5/480-byte query
decoding and existing stored query keys; separate response/name keys preserve
QName and alias records. Each answer records current response policy separately
from its original query token, incarnation, policy identity and winner. Actual
packet UID availability is separate from the original DNS caller. `delivery=0`
describes a policy observation; App/peer/underlay witnesses establish wire delivery.
Short-header and copy-gap errors retain missing header facts without fabricated
QR bits or a claimed Question/correlation.

## Actual Android evidence

The device is Pixel 6a `28201JEGR0XPAJ`, normal RuntimeService protection, ordinary
App UDP sockets, Root and VPN at N1/N3. The independent Windows UDP53 peer emits
explicit complete CNAME/ordinary/unknown-RR fixtures without the Product codec.
A bounded, endpoint-restricted, read-only `wlan0` witness records original query
and answer bytes. Root OUTPUT capture is the existing debug-App UID scope; this
does not qualify netd IPC, all-system capture or a general device release.

| Evidence | Proved scope |
| --- | --- |
| [Root N1 final](../../build-output/s312-root-n1-final-attempt3-20261022/result.json), generation2598 | Four groups/twelve messages: IPv4/IPv6 actual CNAME DROP, old-query/current-response hot policy and three-byte malformed answer through normal SQLite; native zero and clean stop |
| [Root N3 final](../../build-output/s312-root-n3-final-20261022/result.json), generation2599 | Nineteen groups/fifty-seven messages: ordinary RR and unknown EDNS wire, 32 aliases, 33-alias capacity, loop, unrelated additional/MX/SRV/HTTPS data, TC/malformed/short/NXDOMAIN, public IPv4/IPv6 destination wire and all-owner stop |
| [VPN N1 partial](../../build-output/s312-vpn-final-20261022/result.json), generation2600 | Nine groups/twenty-seven messages: IPv4/IPv6 CNAME DROP, alias ALLOW, QName Rank, AND/OR, SNI/business-port guards and Observe; HOLD arose from a read-only WSL UI-XML transport timeout before the next case |
| [VPN hot raw](../../build-output/s312-vpn-n1-hot-final-20261022/result.json), generation2601, and [independent derived check](../../build-output/s312-dns-response-20261022/vpn-hot-derived-receipt.json) | Historical query revision1164/caller App, response revision1165/DROP, original query token/session/epoch, client timeout and exact independent wire; later control returns Unknown after the existing 2s UDP UID cache expires during the 3s denied-answer deadline |
| [VPN N1 short final](../../build-output/s312-vpn-n1-short-final-20261022/result.json), generation2602 | Three ordinary App messages, actual three-byte answer unchanged, unmatched/malformed record retained in normal SQLite, original cold caller preserved and clean normal stop |
| [VPN N3 final](../../build-output/s312-vpn-n3-final-20261022/result.json), generation2603 | Nineteen groups/fifty-seven messages: dual-stack CNAME, ordinary/unknown RR/EDNS, complete/capacity/loop/unrelated/TC/malformed/short/NXDOMAIN answers, public-destination wire, per-owner identity and native-zero normal stop |

Nine earlier [Root N1 rule groups](../../build-output/s312-root-n1-wire-attempt2-20261022/result.json)
use the preceding decoder APK `2bdef593…`. Both final Host/Android packet plugins
are byte-identical to that version. The final APK supplements specifically prove
the corrected missing-header decoder and normal hot/stop paths; the earlier
groups are not relabelled as executions of the final APK.

The Root hot answer was held for 0.675 seconds, after receipt of its original
query and before the normal UI replacement became active. Its query history
retains the old snapshot while the answer is denied under the new snapshot.
The [stopped-runtime UI contract](../../build-output/s312-dns-response-20261022/hot-ui-contract/result.json)
proves the pending draft survives HOME/background, a separate headless probe
task and return to the interactive Activity. Earlier stale-coordinate, invalid
8.5s probe timeout and singleTop task-reuse attempts remain HOLD. These are
harness failures, not Product policy failures. An initial third control packet
had no independent peer receipt and remains unqualified.
The earlier failed Root hot collector closed/reaped its owned peer with one held
fixture answer still queued. That fixture was cancelled, not reported as zero
pending Product work. All PASS peers acknowledge zero pending fixture answers.

Public checks qualify original destination and observed answer bytes. The network
may intercept DNS; no public resolver provider identity is authenticated.
System DNS delegation, TCP and cross-profile association are not inferred.

## Bounds, regression and review

Each owner has 1,024 finite request slots, a ten-second request window, at most
32 aliases/33 candidates, a 65,535-byte message ceiling and a 512KiB synchronous
codec ceiling. Retained state plus wire/observation work fits an explicit 8MiB
owner bound. Request-table exhaustion makes correlation unavailable rather than
guessing from partial state. Normal status exposes request high-water, capacity,
ambiguity, expiry, coverage and codec resources. DNS adds no socket, retained
datagram borrow, timer service or asynchronous DNS job. Stop clears request state
and reports zero codec bytes/operations for every owner.

Focused evidence under [tdd/](../../build-output/s312-dns-response-20261022/tdd/)
covers full context/session/epoch negatives, retransmission/ID reuse ambiguity,
current policy, original Unknown caller, 1,024-slot capacity/expiry/stop/old
generation, CNAME order/duplicates/cycles/class/limits, ordinary and unknown wire,
3,000 malformed mutations, actual Root/VPN graph seams and TCP/non-DNS return
regressions. The explicit response NOT regression checks coherent per-name Rank
and malformed/overflow/Unknown availability with an independent generic fallback.
These request-capacity/late-generation checks are Host shared-seam evidence;
actual adapters exercise chain capacity, wire, identity and normal cleanup.

The initial normal C-producer/Rust/SQLite test accepted five rows and rejected
the two missing-header errors. Its narrow validator correction accepts all seven
records and preserves them after SQLite reopen; complete/correlated records still
require their own response facts and legacy query decode stays valid. Initial
full-suite failures were stale extracted-C DNS stub signatures/stop fields and
the navigation line budget; original verdict/early-stop assertions are retained.

[Final Product Standards review](../../build-output/s312-dns-response-20261022/reviews/standards-review-final-product.md)
and [Spec review](../../build-output/s312-dns-response-20261022/reviews/spec-review-final-product.md)
report zero remaining findings at the pinned Product commit. The original
missing-header finding and follow-up reports are retained alongside them.
The final [packaging Standards](../../build-output/s312-dns-response-20261022/reviews/standards-review-final-packaging.md)
and [packaging Spec](../../build-output/s312-dns-response-20261022/reviews/spec-review-final-packaging.md)
audits also report zero findings after independently checking source/HEV inputs,
all 998 qualification input hashes, every case/stop, forged-winner rejection and
the full restoration fingerprints.

The [final full suite](../../build-output/s312-dns-response-20261022/final-r2-qualified-ctest.log)
passes **73/73** against the exact Host artifact, including the existing Rust
profile gate. Its [receipt](../../build-output/s312-dns-response-20261022/full-suite-r2-receipt.json)
records reuse of the existing standalone Host tree and root fixture Cargo target;
the Product VAPI cache was not switched to a fixture backend.

The offline verifier independently compares actual App, peer, underlay and
normal SQLite records against the configured rule versions. It reconstructs
only the proved VPN hot case from its immutable HOLD inputs. It also rejects a
forged rule winner changed in both the case and its persisted observation.
Every owner stop must prove DNS zero, Root's full native-zero tuple or VPN's
zero sessions/input pbufs/buffers/frames/obligations, closed sockets and negative
timer/broker/TUN fds, followed by native process absence.

```sh
rtk proxy python3 tests/evidence/verify_s312_dns_response.py \
  --runs build-output/s312-root-n1-final-attempt3-20261022 \
    build-output/s312-root-n3-final-20261022 build-output/s312-vpn-final-20261022 \
    build-output/s312-vpn-n1-short-final-20261022 build-output/s312-vpn-n3-final-20261022 \
  --historical build-output/s312-root-n1-wire-attempt2-20261022 \
  --hot-supplement build-output/s312-vpn-n1-hot-final-20261022 \
  --restoration build-output/s312-dns-response-20261022/restoration/receipt.json \
  --output build-output/host-tests/s312-recheck.json
```

## Original device restoration

The [sealed fresh pretest](../../build-output/s312-dns-response-20261022/pretest/manifest.json)
captured the original stopped VPN at generation2593. The
[restoration receipt](../../build-output/s312-dns-response-20261022/restoration/receipt.json)
verifies all 4,858 staged content/type/mode/ownership fingerprints before swap,
then critical rules, SQLite history, preferences and SELinux labels afterward.
Original APK `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`,
settings and CPU frequencies are restored; Wi-Fi remains Openwrt_5G. The original
VPN profile is stopped with `mayBeActive=false`; both runtime snapshot and core
ledger preserve maximum generation **2603**, the only two intentional backup
content changes. The sealed original archive remains unchanged.

Restoration uses a verified regular-file push, device SHA, private-stage full
comparison and data swap. The first local driver typo failed before any device
operation and remains logged. No stdin tar listing was used. Post-restore
process evidence contains no Product native runtime, owned Wi-Fi witness or
stdin tar reader; owned files/stages, hooks and queues are removed. The
[host endpoint audit](../../build-output/s312-dns-response-20261022/posttest-host-peer-receipt.json)
also finds no UDP53 listener on either owned resolver address after peer exit.
