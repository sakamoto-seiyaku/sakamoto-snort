# S322 — authenticated DoT and original-network address discovery

This record separates each artifact's actual qualification. Task authority is
[SAKAMOTO-322](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/50c8d194-55b4-422c-a20f-de275e001970),
under the [application DNS specification](../product/APPLICATION_DNS_SPEC.md).
The evidence root is [the S322 coordination directory](../../build-output/s322-dot-bootstrap-20261029/coordination/).

## Implemented contract

The existing DNS Core selects explicit `dot` candidates through its ordered
routes, cache and current-policy checks. The same Root/VPN socket Adapter runs
nonblocking TLS through its existing owner file readiness, timer and VPN socket
broker. Android publishes the selected non-VPN underlay's advertised DNS addresses
with the same revision as its network facts. A domain endpoint without a configured
connection IP resolves only that service name through those original-network DNS
sockets; application queries acquire no bootstrap exemption. Root marks and binds
bootstrap sockets; VPN protects and binds each socket before native connect.
The original DNS fd closes before the TLS fd is opened. Addresses, TLS identity
and the application's original resolver remain separate facts.

Normal upstream syntax includes `upstream 0 dot dot.test 192.0.2.53 853` for a
separate connection IP, `upstream 0 dot 192.0.2.53 - 853` for an IP identity, and
`upstream 0 dot dot.test - 853` for original-network discovery. Existing `route`
and `exception` records retain their bounds and semantics. UDP/TCP ordinary
candidates remain explicit choices. Exhausted encrypted candidates return legal
SERVFAIL; no implicit plaintext, system or public application-DNS candidate is added.

The pinned [Mbed TLS profile](../../third_party/mbedtls/README.md) authenticates
TLS 1.2 certificate chain, validity and DNS/IP SAN identity with nonblocking
`getrandom`. System trust is read-only. The controlled offline CA is an explicit
debug-only Start dependency, never an application-query trust selection or a
modification of Android's global CA store. Application DNS is offered only after
authentication. Discovery handles A/AAAA, connected CNAME and same-resolver TC/TCP,
with at most four selected addresses. It shares the existing three-second attempt
and ten-second request deadlines; address/transport progress does not reset them.

All TLS heap shares a one-MiB owner cap, with 256-KiB connection sublimits,
256 CA certificates, 512-KiB trust input and 16-KiB streamed certificate bounds.
At most five TCP/TLS slots share six upstream sockets; Root's two raw return
sockets remain within the existing eight-socket bound. The DNS owner budget stays
eight MiB. Live allocation accounting is distinct from process RSS.

Product C/Rust ABI is **5** because the platform snapshot grew from 280 to
368 bytes. API version remains 1 with generated CRC `48091080`. Normal DoT
observation v10 is 1032 bytes and preserves service identity, attempted address,
original-network bootstrap resolver/interface, TLS/authorization/trust state and
raw transport/TLS error. Ordinary v8/704-byte and routing v9/720-byte output stays
unchanged; old SQLite JSON omits the new zero-valued fields and retains its raw
bytes and received clocks. Cached answer data has its own state and creates no
new socket/authentication claim.

## Recorded entry and failure evidence

The initial explicit-IP artifact passed ordinary Root generation2927 and VPN
generation2926. Native R3/APK R4 then passed complete hostname bootstrap chains on
Root generation2931 and VPN generation2932: advertised original-network IPv6 DNS
resolved fixed `localhost`, an independent finite Android TLS peer authenticated
that identity, and an ordinary App received the exact original-resolver reply.
Physical/loopback/TUN captures, normal SQLite close/reopen and independent whole
history reads, native-zero Stop and all owned peer/collector cleanup are retained
in [Root bootstrap R3](../../build-output/s322-dot-bootstrap-20261029/coordination/device-root-n1-bootstrap-r3/result.json)
and [VPN bootstrap R1](../../build-output/s322-dot-bootstrap-20261029/coordination/device-vpn-n1-bootstrap-r1/result.json).
These records qualify their exact earlier artifacts, not later source changes.

Original RED/HOLD results are retained in the coordination directory. They include
unsupported DoT dispatch, peer-certificate retention, aggregate TLS reservation,
fixture trust lifetime, c-ares success convention, first-address-only discovery,
test listener collision and incomplete capture/peer VM termination. Each later
pass uses the same relevant business assertion. ABI4 builder/preflight holds are
kept separately from DNS behavior; a preflight rejection sent no application DNS.

## Final artifact qualification (2026-10-31)

Verification on the first complete host run found a heap corruption in the TLS
owner: RSA/ECP state that Mbed TLS caches lazily inside the shared trust anchors
during verification was allocated under a per-connection budget, but freed with
the anchors after that connection and its budget were gone. The release path
then wrote into freed memory (`sakamoto_mbedtls_free` budget chain), which glibc
detected as a corrupted free list after about nine owner replacements. An ASan
build with the TLS, Mbed TLS and owner sources instrumented reported the
use-after-free and, after the change below, none.

Connection budgets are now fixed slots inside the owner, so a recorded budget
outlives every anchor-held allocation. Bytes cached in the anchors stay charged
to their slot until the owner closes; that is retained memory, not a leak.
Sources: [`product_dns_tls.c`](../../src/product/vpp/product_dns_tls.c).

Host: `ctest -R 'dns|tls|root|vapi|plugin'` passes 61/61 on the rebuilt libraries,
and the TLS-view replacement case passes repeatedly. The Android native stage
(`android-native-r6`) and APK (`android-apk-r8`, SHA-256 `21e79527…`) rebuilt
with an unchanged repeat of zero compilations and byte-identical payloads.

Pixel 6a, ordinary App entry, normal SQLite, clean stops, on those artifacts:

| Run | Scope | Result |
| --- | --- | --- |
| `device-root-n1-bootstrap-r4` | Root N1, original-network address discovery | PASS |
| `device-vpn-n1-bootstrap-r2` | VPN N1, original-network address discovery | PASS |
| `device-root-n1-full-r4` | Root N1: IPv4/IPv6 × UDP/TCP client, explicit and discovered identity, IP identity, identity failover, all-encrypted-failed SERVFAIL, normal cache and cache hit, handshake Stop | PASS, 17 cases, 76 whole case records |
| `device-root-n1-handshake-stop-r3` | Stop during a gated TLS handshake | PASS |

Device driver corrections found on the way, none changing Product source: the
cache-hit case now passes the origin-relative cache age to the reply check, a
`--budget-seconds` option replaces the fixed 900 s capture budget, and after a
Product Stop the debug App is brought to the foreground before its probe result
is read, because Android's cached-app freezer otherwise freezes the probe thread
until the next UI action. The original APK and all 4861 private-data members were
restored at generation 2947 in both fields (`original-restoration-r2`). Root N3 and
VPN N3 full matrices are not re-run on this artifact; the earlier N3 cells keep
their own earlier-artifact scope.

## Qualification boundaries

The independent Host TLS peer tests exercise the public shared IO boundary;
controlled platform dependencies are identified as such. A debug CA does not
qualify an arbitrary public service or Android's full system trust collection.
The self-hosted bootstrap peer qualifies the real original-network DNS request
and protected local TLS path; the external dual-stack peer supplies separate
physical-network TLS evidence. Missing platform DNS facts fail explicitly; the
Linux network-classification producer does not synthesize a resolver from a
hidden default. Physical cellular handover is not claimed by a logical snapshot
revision test. DoH, TLS1.3, external encrypted-DNS blocking, netd hooks, UID resolver
restructuring and cross-App/profile association enforcement are outside this ticket.
