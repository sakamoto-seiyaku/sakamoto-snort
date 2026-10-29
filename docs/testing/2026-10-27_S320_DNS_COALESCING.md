# S320: simultaneous DNS data sharing and independent delivery

The existing VPP-native DNS Core can share one pending upstream exchange between
safely equivalent, concurrently outstanding questions. Each waiter retains its
own caller evidence, request ID, Question, channel/session, token and deadline,
and independently executes query policy before joining and current response
policy before delivery. Shared data never becomes shared permission.

Authority: [application DNS specification](../product/APPLICATION_DNS_SPEC.md),
[ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md) and
[SAKAMOTO-320](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/e82bc4ed-d207-4086-b7d9-bb4a73f23081).
ADRs 0006/0007/0008 retain the VPP-native C and existing FlowOwner boundaries.
This is offline qualification of the user privacy application, not a release or
supported-device claim. On 2026-10-29, independent Standards and Spec reviews
reported zero findings, and a separate acceptance agent qualified the actual
source, ordinary entries, raw behavior, normal SQLite and restored-device evidence.
The final source and delivery identities are linked below; original failures and
artifact-specific limits remain preserved.

## Runtime behavior and bounds

Each existing owner keeps at most 64 upstream exchanges and 128 waiters. Both use
the existing 8 MiB DNS work budget; answer data retains its separate 512 entry / 2 MiB
cache bound. No global mutable container, new DNS runtime or worker-blocking wait
is introduced. Existing Root sockets and VPN HEV/lwIP sessions remain responsible
for transport and return/completion.

Only a complete reusable Question/flags/EDNS message and an equivalent resolver,
network, route/configuration, profile, family and available network-context view
may join. All query bytes except the DNS ID remain significant. Unknown EDNS
options and other unsafe reuse cases continue independently without discarding
opaque data to widen equivalence. Query policy refusal precedes joining and cache.

A later waiter joins only the remaining original 3 second candidate lifetime.
Neither joining, the single permitted UDP retransmission nor same-resolver TCP
continuation extends that candidate. Each waiter keeps its own identity and
request deadline. One cancellation retires only that waiter; the final waiter
releases the exchange and socket obligation. Old generation, incarnation, token,
attempt and view events cannot revive work or write a cache entry without a
still-owned legitimate exchange. Data ownership and reply ownership are separate.

Root and VPN local TCP inputs retain a complete extra frame in bounded input
storage when all 128 transport obligations are owned. Released slots resume work;
multiple ready sessions make bounded progress. FIN/RST and Stop still settle
accepted work exactly once. A full pending table does not implicitly close a
healthy stream and cancel unrelated accepted requests.

The TCP 2 MiB budgets include a fixed 512 byte per-obligation reserve for small local
errors. A large output allocation/budget failure retains only that token for one
SERVFAIL fallback. Stale/closed channels stay distinct from capacity. If encoding
or transport cannot accept a reply, only that still-pending obligation is
abandoned. A failure after actual answer parsing retains its cache/upstream
source, actual current policy and response facts. Encoding failure reports zero
output bytes; rejected transmission retains the actual encoded length and failed
delivery. None is reported as a policy refusal.

## Current artifact identity

Review base is`1dca2114e2d9631f9e5eff59b1aa0d5e9579895b`.
Selected R4 APK:
`62725d16d77b86c12fe1f0a2bfb2dfbe1360686335abf838c6d0a99a2e7e1ce3`.
R4 plugin payload:
`7caa2bc4e0d3b0477d4d4e9e428de894a7a7fd1cd7cf5afd819a1f163a2367f6`.
Rust core and JNI payloads remain respectively
`b0dc4bd0f7e99e2303ae0496aff5e172a352031ae973cddd55d2e8f4fb987ab6`
and`f45d18a57dca4731040fd4fe071eadaf1b4c6deb8afbd45b5713774e5d8c7de1`.

The 294 native and 295 APK build inputs are sealed with exact raw compiler outputs
and independently stripped copies. All 12 staged native payloads match the APK.
Native and Host builds reuse the persistent Product caches; their unchanged
second builds compile zero Rust/Ninja inputs and retain all 777/3630 compiled
metadata entries. Java/DEX reuse retains all 182 entries with zero bytecode
compilation. Matching Product raw ELF files, tested Host executables and exact
normal consumer binary identity remain retained separately from mutable caches.
R4 retains the existing Root packed verdict and VPN MTU10000/sndbuf65528
profiles and enables policy qualification counters; it makes no performance claim.

The evidence root is
[`build-output/s320-dns-coalescing-20261027`](../../build-output/s320-dns-coalescing-20261027/).
Its final source/artifact/evidence map is in the
[final source seal](../../build-output/s320-dns-coalescing-20261027/coordination/s320-max-fast-20261029/implement-owner-r1/final-source-seal-v3/manifest.json).
The reviewed safety-v2 package remains immutable. Earlier
R1/R2a/R3 results keep their original artifacts and source ZIPs; they are not
relabeled as executions of R4.

## Qualified behavior and composition

| Scope | Actual evidence |
| --- | --- |
| Shared public Core | Equivalent pending questions send one logical exchange and independently reply; current query/response policy, reliable distinct caller contexts, Unknown, strict candidate deadline, complete equivalence, limits and exactly-once event races |
| Real POSIX transport and controlled Adapter | Actual socket contexts and source-linked Root/VPN Adapter cover both client transports/families;72 coalescing groups produce 392 normal records, including 8 independently reliable caller/channel groups |
| Output resources | Real Root/VPN allocator failures produce 120 normal records across both families/transports; current policy/source, encoding failure, transport rejection, single-token abandon and stale classification remain distinct |
| TCP capacity and lifecycle | Current Root POSIX and real HEV/lwIP checks cover 129 frames, multiple sessions, FIN/RST/Stop,2MiB ceilings and actual malloc failures |
| Current ordinary App capacity | Root g2893 finite slice and full VPN g2894 each receive 65 independent SERVFAIL replies and 129 successful shared-question replies; 128 are upstream data and one is current-view cache data |
| Current ordinary App entries | R4 Root/VPN N1 g2895/g2896 and N3 g2897/g2898:40 groups/256 whole target records across UDP/TCP and both families, every configured owner observed |
| Current pending Stop/late/restart | R4 Root g2899–2901 and VPN g2902–2904:8 groups/28 whole target records, actual pending quiesce getters, old-channel fencing and new-generation uncached positive controls |
| Earlier scoped current-policy semantics | R3 Root/VPN actual pending rule publication, query refusal before joining, single/all cancellation, deadline races and route-view changes retain their separate source/artifact/generation scopes |

The current R4 union contains52 device case groups and1448 distinct whole target
records (1432 proxy and16 passive), plus two separately preserved no-identity
resource gaps and394 other normal records. All1844 rows remain in the final
immutable MAIN, SHA-256
`d3134e9f648561f16539dc6968bd6736e968515250585abac09c296e1c8225d7`.
Each prior whole row, raw store value and received clock survives the12 MAIN
checkpoints from g2893 through g2904 unchanged. This current union does not
merge older artifact scopes or convert a whole HOLD to a whole PASS.

The device peer is an explicitly selected local Linux 53054 UDP fixture. Ordinary
App TCP and UDP entries are independently exercised; this fixture does not claim
a device TCP upstream. The separately sealed real POSIX transport qualification
retains its own TCP-upstream scope. Original Windows 53053 peer status remains
unknown; no unowned process or global networking was changed.

Different reliable App/channel decisions are source-linked controlled Adapter
and public Core evidence. Ordinary Android records retain each actual reliable
or Unknown caller as observed. Unknown is never promoted to a claimed original
App, and this does not qualify a new cross-App/profile association policy.

Normal observations keep the 704 byte ABI and existing SQLite path, 128 public query
limit and 4096 row retention bound. Stage3 failure observations use direction3;
response/delivery stages2/4 use direction1. Actual response policy facts remain
separate from that record-stage direction. The current 392/120 Adapter records
pass real Rust unified commit, close and reopen; independent immutable SQLite
reads verify all whole rows and the available 128 recent rows without raising
limits. Device replies, native identities, actual wire, normal histories and
before-free resource getters are joined with exact artifact/generation scope.

## Original failures and limits

- The original public callback-cache reentry ASan use-after-free remains RED with
  its matching source ZIP and binary. A saved original attempt key prevents a
  completed cached callback from continuing through a newly reused request slot.
  The same operation and adjacent cancellation/stop/reentry cases pass current
  ASan/UBSan. This is a public synchronous callback fixture, not a claim that the
  Android transport adapter itself exhibited that same reentry.
- Original Root g2892 received zero replies/EOF after 129 writes and canceled 128
  accepted requests. Its raw App, normal MAIN and whole HOLD remain unchanged.
  R4 fixes bounded TCP admission/output behavior; current Root and VPN each
  actually receive all 129 replies.
- Original R4 Root g2893 whole HOLD remains unchanged: its helper assumed an
  uncached TTL 60 for the retained 129th frame, whose real cache reply correctly
  carries 59. The same saved App/wire/closed MAIN separately qualifies 195 distinct
  and 387 shared target records, plus two preserved pre-admission resource gaps
  with no safe DNS identity. No test or Stop was replayed. Exact same-view native
  source ages are 9779 us in Root and 6199 us in VPN; TTL/data bytes are checked fully.
- Earlier counter, output/input policy, concurrency, view-action timing,
  prepared-reader Stop, AF_PACKET-view/datagram and Windows interop HOLDs remain
  separate from finite qualified data slices. A bounded UDP retry is one logical
  exchange, not an invented second resolution. Raw observations are retained.
- Socket-restricted sandbox attempts, a missing generated-header include and
  unsupported LeakSanitizer-under-ptrace remain environment/harness HOLDs.
  ASan/UBSan checks explicitly disable unavailable leak checking. The ASan-built
  archive static state audit sees sanitizer shadow metadata; its 65 behavioral
  checks pass and the exact unsanitized Product archive separately passes the
  static mutable-state audit. The full current Host suite passes 121/121.

No encrypted upstream, resolver-hook integration, deferred UID-resolver rewrite,
association enforcement, performance benefit or general release claim is added.

## Reproduction and restoration

Use the current Product builders and persistent compilation caches. The public
Host checks and evidence regressions are:

```sh
rtk proxy cmake --build build-output/host-tests -j8
rtk proxy ctest --test-dir build-output/host-tests --output-on-failure
rtk proxy python3 -m unittest discover -s tests/evidence -p 'test_s320*.py'
```

The source-linked Adapter runner is
[`product_root_dns_adapter_test.py`](../../tests/host/product_root_dns_adapter_test.py),
with `--case coalescing` or `--case cache-resource`, explicit persistent Host libraries
and a fresh records/evidence output. The ignored Rust methods in
[`dns_observation.rs`](../../crates/product-core/tests/dns_observation.rs) require
those actual binary records and the verified current Product VAPI environment;
ordinary unqualified Cargo execution does not run these integrations.

[`s320-dns-coalescing.py`](../../tests/device/s320-dns-coalescing.py) uses the normal
configuration/start/stop/App probe paths, repo `./dev/adb`, an explicit complete
stopped-device backup and task-owned collectors. It must not overwrite a device
without a fresh complete baseline. Closed MAIN validation matches reply IDs
rather than assuming pipeline reply order and derives cache TTL from the actual
same-view source record; additional no-identity resource observations are retained.

Before installing R4, a fresh stopped-device backup preserved the original APK
`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`
and all 4861 private graph members at generation 2892. The current matrix ends
stopped at generation 2904.

The main controller then returned a model-turn “possible cybersecurity risk”
interruption, identifying no specific tool action; the two review agents had not
started. Under the existing device-recovery authorization, the owner preserved
all 5035 current test nodes in a complete 139324928-byte TAR and retained the
matching R4 test APK before restoring the original APK and all 4861 original
nodes. Only the two generation fields advance to the actual fresh maximum 2904;
all other original node types, modes, uid/gid, links and contents match. The TAR
also contains the exact final 1844-row MAIN hash cited above.

The complete test TAR SHA-256 is
`7a5c8efde31749dced97164594852570f71ef0ac6c792d5eae9f2fa31c43e330`.
Independent post-restore reads verify stopped state, both generation fields 2904,
original APK, KSU grant, permissions, SELinux and controlled settings, with no
native/App processes, product hooks/queues or task-owned routes. All 138 safety
operations are terminal and reaped without signals; the three IPv6 NAT-table
absence results exactly match the original baseline. All five task-local routes
have zero remaining sockets, threads and errors.

Only the exact completed-producer remote test TAR and its metadata were retired
after confirming the complete local copy and rechecking both hashes in the
delete command. Local evidence is retained. The recovery result is
[`independent-final-safety-audit.json`](../../build-output/s320-dns-coalescing-20261027/coordination/device-restoration/sol-continuation-r1/independent-final-safety-audit.json).
No Product Stop, historical generation, unowned process signal or global network
reset was replayed. The interrupted checkpoint remains preserved.

## Independent review and delivery record, 2026-10-29

The actual parallel [Standards review](../../build-output/s320-dns-coalescing-20261027/coordination/s320-max-fast-20261029/standards/standards-review.md)
and [Spec review](../../build-output/s320-dns-coalescing-20261027/coordination/s320-max-fast-20261029/spec/report.md)
found no changes required. A separate acceptance agent independently checked
actual wire/App/UI inputs, every normal Store row, the complete restoration TARs
and the R3/R4 composition described in its
[behavior and recovery report](../../build-output/s320-dns-coalescing-20261027/coordination/s320-max-fast-20261029/acceptance/behavior-and-recovery.md).
Its delivery gate binds the reviewed source freeze and both real review reports.
The continuation reused matching Host/build/device evidence. After review, only
these dated documentation facts and one trailing blank line in a Host test
changed; runtime and test behavior remain unchanged. The final seal maps that
exact whitespace delta to the tested source.

The exact scoped commit, S320-only tracker write and protected readback, and
actual OS-temp handoff with its identical durable copy are recorded in the
[delivery receipt](../../build-output/s320-dns-coalescing-20261027/coordination/s320-max-fast-20261029/implement-owner-r1/delivery-final-receipt.json).
This record qualifies S320's stated scope; it does not complete the remaining DNS
tickets or broaden the limits above.
