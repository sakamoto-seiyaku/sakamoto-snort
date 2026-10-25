# S316: optional VPN UDP DNS replacement

VPN now selects a local DNS session before creating a Direct upstream. Normal
START uses the existing protection and underlay broker; disabling replacement
preserves Direct, including transitions on the same App socket. Complete
messages reuse the shared VPP-native C DNS core, current query/response policy,
bounded I/O and the existing TUN return/completion path. Native buffer release
precedes the original owner's observation export. No additional runtime,
packet thread, C++ fallback or UID-resolver redesign is introduced.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md)
and [SAKAMOTO-316](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/a9689ce5-35c7-4b61-9431-8b78516e545b).
This record qualifies **52 composed VPN groups**, plus a current Root idle
health check. It is not one successful full invocation. Original failed runs
remain HOLD. The original APK and all 4,861 private-data members were actually
restored, with both fresh generation fields at **2755**.

## Artifacts and unchanged-build evidence

Review base: `94b67ed34f98e148d6e19680e42eca7e703c8afb`.
The [actual 294-file R4 prebuild identity](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/current-prebuild-source-identity-r4-startup.json)
pins compiled inputs. Later [296-file fixture qualification](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/current-postbuild-source-identity-r4-observer-bounded.json)
records exactly seven Host/device fixture changes; every Product runtime input
remains equal to R4. Those test changes do not require a new native build.

| Current artifact | SHA256 |
| --- | --- |
| [R4 repeat APK](../../build-output/s316-vpn-dns-20261025/android-apk-high-default-r4/repeat/sakamoto-runtime-debug.apk) | `458624c2bb5715b84c6cc298234d0f2734e2035782ce75fc2de2ddb7da6b199f` |
| `libproduct_core_plugin.so` payload | `7e05cfc9e9175d787c4d03ad4647a516dc85d0b86527b4f75fd9b42f3075d1b8` |
| `libsakamoto_product_core.so` payload | `433894d6d9f5423a09e4592f0ddbc39890e8c508c6c1216e6558d6eefa5500bb` |
| `libsakamoto_runtime_control.so` payload | `f45d18a57dca4731040fd4fe071eadaf1b4c6deb8afbd45b5713774e5d8c7de1` |

The [native pair](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/native-current-r4-result.json) reused the persistent
Product cache: first build 0 Rust compilations/2 Ninja actions; unchanged repeat
0/0, all 776 compiled-file hashes and timestamps unchanged, and all 12 native
payloads identical. Both APK publications reused Java/DEX outputs. The
[identity join](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/current-r4-native-apk-symbol-identity.json) checks all 24
native/APK pairs and three exact frozen raw compiler outputs; no GNU build-ID
qualification is claimed. Each real cohort independently checks its installed
APK and payload identities.

## Processing and identity

Allowed answers, NXDOMAIN/REFUSED/SERVFAIL, malformed/unsupported inputs,
QName/CNAME policy, Observe, EDNS capacities, legal truncation and same-resolver
TC-to-TCP are covered at their scoped entries. The existing three-second
request deadline and 1.5-second retry remain unchanged. Generation, owner,
request/attempt, Flow incarnation, route/network revision and broker context
fence stale authorization and replies. Actual query caller facts remain
separate from the transport socket UID and generated return identity.

The cold datagram remains Unknown; a later message on that same live socket can
use the normal lookup result. UI transitions also preserve actual expired UID
qualification rather than backfilling from the socket. Capacity messages had
observed Unknown/Known mixes: N1 **11/54**, N3 **6/59**;
the App client UID was 12632. These are not 65-Known-caller claims.

## Composed real App, wire and SQLite coverage

The [coverage receipt](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/coverage-final-r4.json) independently opens committed
SQLite files read-only and matches **685 distinct complete public records in
one final MAIN**. All seven prior cohort DNS payloads and receipt clocks remain
exact in its 1,346 retained DNS rows. Public recent-page limits are unchanged.

| Actual cohort | Artifact | Generation / owners | Groups | Whole public records |
| --- | --- | --- | ---: | ---: |
| [device-core-current-r1](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-core-current-r1/result.json) | R1 | 2738 / N1 | 26 | 145 |
| [device-n3-core-r2](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n3-core-r2/result.json) | R2 | 2739 / N3 | 14 | 80 |
| [device-n1-lifecycle-r4](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n1-lifecycle-r4/result.json) | R4 qualified prefix; raw HOLD retained | 2746 / N1 | 3 | 29 |
| [device-n1-lifecycle-remaining-observer-r4](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n1-lifecycle-remaining-observer-r4/result.json) | R4 | 2750, 2751 / N1 | 2 | 6 |
| [device-n1-capacity-r4](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n1-capacity-r4/result.json) | R4 | 2752 / N1 | 1 | 195 |
| [device-n3-lifecycle-r4](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n3-lifecycle-r4/result.json) | R4 | 2753, 2754 / N3 | 5 | 35 |
| [device-n3-capacity-r4](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-n3-capacity-r4/result.json) | R4 | 2755 / N3 | 1 | 195 |
| Total | Qualified composition | 32 N1 + 20 N3 | **52** | **685** |

Core groups cover client/upstream IPv4/IPv6 combinations, disabled Direct,
reply/error classes, policy and transport/size boundaries. The first 40 groups
remain actual R1/R2 executions, with [source qualification](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/source-qualified-core-reuse-r4.json).
N1 lifecycle is explicitly three passing groups from a retained HOLD plus two
current successful cases. Each lifecycle tests both same-socket toggle
families, hot current-policy REFUSED, actual pending cancellation, an old answer
on Device WLAN after restart, no matching fresh TUN return, and a successful
fresh-generation App request.

Both capacity cases send 65 real App queries to one actual owner (N1 owner 0,
N3 owner 2): 64 reach upstream, 128 datagrams include retries, the overflow has
no upstream request, and all 65 legal SERVFAIL replies and all 195
query/error/delivery records are checked. Transaction high-water is 64;
published byte/socket/work limits hold. This is a controlled capacity result,
not a throughput claim.

All successful cohorts use normal Stop and independent SQLite reading, with
native owner/session/socket/buffer/obligation counts zero and owned peer,
reader, capture and trace resources settled. Pending-stop terminal history
remains bounded and is **not claimed lossless**.

## Shared readiness, retention and causal regressions

UDP state distinguishes authorizing, authorized, clean idle and failed.
`socket_ready` reflects an actually authorized fd. Route readiness can remain
healthy after legal 30-second idle reclamation; the first input reopens and
obtains fresh authorization before wire send. Never-confirmed expiry, denial,
stale callbacks and stopping cannot inherit clean-idle readiness. Global health
and each CLI row share exact current generation/route/network qualification.
Android's initial current network revision 0 is legal before platform capture;
a stale revision is rejected after publication.

[Current Root2745](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-root-idle-r4/result.json) observed 30 real samples
and **66.50249 seconds after actual idle**, with Runtime health/protection and
independent public Native availability/protection healthy. Its first own App
request reopened on the same route/network, passed peer/WLAN/loopback and three
whole SQL records, and stopped cleanly. Root caller UID12632 and actual raw
return UID0/provenance5 remain distinct. Earlier
[VPN2742](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-idle-diagnosis-r2/result.json) separately proved real idle
and first-input recovery on its earlier artifact; it is not relabeled R4.

The original2737 missing24 whole records were causally tied to false multi-day
age during wall-clock reconciliation; that does not explain every historical
83 evictions. Shared DNS/Flow/Blocked first receipts now carry optional boot
identity plus native `CLOCK_BOOTTIME`. Same-boot elapsed age is precise;
legacy/different-boot/unknown fallback is guarded and reported. Real 60-second
Host reconciliation, controlled multi-day/backward/reopen/expiry cases, and an
actual Device gap of about 1.06 hours qualify this change. No real three-day or
24-hour Device wait is claimed. Duplicate END at count capacity no longer
evicts/recreates existing detail, and valid Flow owners 2 through 61 share the
existing DNS owner bound. Controlled owner62/u16-max negatives remain rejected.

The recent-cap duplicate regression uses a supported compact legacy 32,768-row
database below the byte bound. The modern bulk setup that hit dirty/database
limits remains a separate SETUP_HOLD; it is not capacity PASS.

Late-response fixtures retain default30-second gates; only Stop/restart uses a
bounded120-second entry, within the overall deadline. Both fixture backends
check expiry before sending, including already-released gates and partial TCP
writes. Real POSIX I/O tests use controlled monotonic/FS boundaries; those are
not real 31/121-second waits. Root route/stop and VPN late cases share a strict
two-second observation-only arrival budget. Complete captured bytes/endpoints
must match. Owned witness identity and final requested/drop-zero capture
validate the entire no-return interval through the fresh positive and final
TUN closure before Stop. No extra Product send or relaxed business assertion
is used.

## Retained failures and checks

- Original2735 projected-denominator panic and its earlier causal fix/audit stay
  separate. Earlier selected-peer losses remain unexplained by current success.
- Original2737 full-run connection-cap HOLD and 24-record SQLite gap remain raw
  HOLD. The cap stays4096; corrected bounded cohorts supply the coverage union.
- Original2740 prequery socket requirement, background-traffic idle setup2741,
  Root startup2743/2744, peer gate expiry2746/2747 and one-shot capture2748/2749
  remain failed attempts. The last capture's final log contains both old
  answers; the first read was only5.46ms after peer write. The successful
  corrected entry is2750/2751, not an offline whole-run PASS.
- Missing-library/empty-regex fixture setup, invalid initial Blocked fixture,
  sandbox socket/UDS permissions and inherited missing Host artifact environment
  remain explicitly qualified. Their corrected checks preserve the assertions.
- The new standalone Windows gate unit was rejected for an unsigned UNC script.
  It remains ENVHOLD. Read-only PowerShell AST parsing passed; it is not Windows
  runtime gate PASS. No execution-policy change was made for that probe.

Qualified regression union: **93 Host cases**, **92 Rust passed/3 ignored**,
affected current readiness/fixture checks, and `git diff --check`. The Host and
Rust unions compose retained passing evidence with scoped corrections; they
are not single all-green invocations. Rust and native inputs unchanged since
their accepted checks were reused. Baseline/current voluntary formatting has
the same pre-existing failures; no mass formatting was performed. Paired
source reviews and raw evidence remain under [coordination reviews](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/reviews/).

## Executed restoration

Before overwrite, [the complete final test-state archive](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-posttest-preservation-r4-receipt.json)
retained all **5,121 measured nodes**, **238,776,832 bytes**, SHA256
`638918b8648cba07b161bb42503a656590b2f9e00ca3a726ca630c356f379e58`, with exact
before/after graphs, every tar field/content, producer0 and complete EOF.
[Executed restoration](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-restoration/original-restoration-receipt.json)
restored original APK `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and every original private-data member. Only the two generation fields are
intentionally derived at fresh maximum2755. Final state is STOPPED/native0;
KSU grant, permissions, SELinux, CPU frequency and Wi-Fi/stay-on preferences
match the baseline. No Product Stop was replayed. Exact owned remote archives
and metadata were removed after local hash verification; restored data was
[rechecked unchanged](../../build-output/s316-vpn-dns-20261025/coordination-sol-high-default-r1/device-restoration/final-owned-archive-cleanup-receipt.json).

Client-TCP replacement, encrypted upstreams, cache, association consumption,
UID-resolver extension, real cellular handover, broader device support and
release/performance qualification remain outside this record.
