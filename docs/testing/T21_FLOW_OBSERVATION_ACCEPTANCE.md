# T21 Flow observation acceptance — 2026-09-26

Task: SAKAMOTO-272 / T21, under SAKAMOTO-251. The selected T20 transport is
the pinned VPP `svm_msg_q`. This report concerns the current Flow overview,
not persistent history, attribution segments, a release capacity budget,
or performance superiority over Aeron.

## Implementation and identity

The Product VPP-native C owner exports creation, cumulative growth, low-frequency
pending updates and END into independent normal/debug queues. Rust owns one
ingestion thread per runtime and exposes its bounded overview with the typed
VAPI channel health through the ordinary Product API. END applies unseen tail
growth; old UPDATEs cannot revive an ended incarnation. Basic IP accounting
occurs once at terminal, independent of Flow allocation and export success.
Timer flush uses the existing owner deadline and does not refresh CT activity.

The Android application creates the sealed-size memfd and eventfds and offers
them through SCM_RIGHTS. VPP adopts the mapping under its worker barrier before
acknowledging the consumer. This preserves the Android application memory label
without modifying SELinux. The generation permits one successful consumer
claim. Silent pending proposals expire after two seconds. RuntimeService starts
ingestion after policy readiness/reconciliation; ordinary status queries do
not claim it. See [the interface contract](../interfaces/T21_FLOW_OBSERVATION.md).

Final Product source closure:
`861e3ba14230f1505518ef9d6e080089746b8e98e0a0e68ec60a6d0f3eb5a1a9`.
Generated API identity: `product_core.api/1.0.0@c9a3f640`.
Pinned VPP revision: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`.
The working tree began at `9fa98afc6e9d9a0ae34070595f9f1bdf64c80dbe`;
the build manifests retain the complete source snapshots and dirty diff.

| Evidence | Retained location under `build-output/t21-20260926/` |
|---|---|
| Final Host build | `linux-build-e/build.json`; artifact `build-output/product-vpp-host-t21-e` |
| Final Android build | `pixel-build-f/build.json` |
| Installed APK SHA-256 | `b1a96905dce24542981b8a3823cfa17466470dfaedef5c03ef76de43da00c97d` |
| Linux actual run | `linux-c/` |
| Android representative run | `pixel-h/` |
| Independent verification | `linux-verification.json`, `pixel-verification.json` |
| Final native/ARM64/sanitizer results | `final-native/` |
| Complete Host regression | `ctest-final.log`: 50/50 PASS |
| Final device state/cleanup | `device-final-*` |

`tests/evidence/verify_t21.py` independently verifies current source equality,
retained source snapshots, build order, binaries and installed native hashes,
runtime generations, packet identities, endpoint/capture evidence, cumulative
records, quiet timers, END, reuse, queue progress and resource release. Its eleven
semantic mutations are rehashed before verification, so a file-seal mismatch
alone cannot explain their rejection: wrong generation, directional total,
zero IPv4 address, missing END, missing tail bytes, owner count, notification
failure, debug interference, missing delivery, substituted terminal identity
and substituted endpoint payload. The last two were first accepted by the old
count-only verifier; `identity-mutations-red.json` preserves that RED evidence.
The final verifier compares native cross-stage identity maps and the actual
admitted/endpoint/captured payload maps. Both final verification results bind
the same final verifier hash.

## Results by platform

**Linux:** actual UID-separated UDP sockets in an isolated network namespace
traversed NFQUEUE → current VPP → C shared-memory queue → Rust → Product API.
Generation 27201 used two owner workers. The first quiet flow reported 1/1
packets and 60/60 IP bytes; its CT timer was unchanged after the pending flush.
Three subsequent packets per side were included in one END update, producing
4/4 packets and 264/264 bytes. The same tuple acquired a new incarnation.

With Rust paused, 2400 distinct echo transactions completed while both normal
queues reached 512 occupied slots. Their full-rejection counts were 1676 and
1675; reserved debug queues remained unused. Both Flow pools reached their
1024-entry capacity and recorded allocation misses, while independent basic
accounting still reached exactly 4810 packets / 288648 IP bytes. Resuming drained
the queues and exposed incomplete coverage. Killing the consumer did not stop
the next echo pair. A separate zero-credit primary-handoff arm delivered 32
further echo pairs and increased actual primary rejection counters; final
basic totals were exactly 4876 packets / 292608 bytes, confirmed by the endpoint.
A silent authenticated peer received EOF after 2.00013 seconds; a health query
still observed no consumer, and the later real consumer claimed successfully.

**Android representative acceptance:** the same Product source was installed
and verified by APK and individual native-library hashes. Root generation 1594
and VPN generation 1595 each completed 106 real echo transactions, including
quiet flush, END, tuple reuse and a bounded 100-echo pause/resume arm. Root
traces prove NFQ_CAPTURED; VPN traces prove TUN_CAPTURED and FLOW_STACK_RETURN.
For each profile the independent verifier matches 212 Product admit, policy
and terminal packets, exact IP lengths, unique obligation identities, endpoint
payloads, and host/device capture payloads. The 100-echo arm does **not** claim
Android queue saturation or unseen END-only tail: its pending values had already
been exported. Linux and the real cross-process native/Rust test cover those
separate conditions. Both VPP processes disappeared after normal stop and the
application's observation mappings were released. Final device checks found no
VPP/capture processes, queue sockets, Product hooks or T21 scratch directories.

**Native boundaries:** the actual pinned-VPP C producer and Rust ingestion
thread passed capacity isolation, notification waiting without periodic wakeups,
END tail, duplicate/old-update rejection and producer exit across processes.
IPv4/IPv6 record classes are exercised at this seam. Direct Product transport
tests passed on Host and ARM64 for capacity, independent debug space, oversize,
malformed/truncated/zero-length descriptor offers, no descriptor leak, bounded
empty receive and independent outcome accounting. Product transport plus its
boundary test passed ASan/UBSan with leak detection; the pinned shared libraries
were not rebuilt with sanitizers. A sandbox run first failed because
LeakSanitizer cannot operate under ptrace; the unsandboxed run and both logs are
retained. The complete standalone C/Android-contract/Rust Host suite passed
50/50 after the three API-shaped harnesses were extended for the new query.

## Preserved failures and claim boundaries

- Early `linux-a`/`linux-b` candidates had incorrect IPv4 record addresses.
  `wire-address-red.json` records the failing assertion. Canonical IPv4 lives
  in the final four key bytes; the final producer and independent verifier
  check the actual socket addresses. Those earlier candidates are not final PASS.
- Android generations 1587/1588 exposed Root-created mapping rejection by
  SELinux and a Bionic control-message iteration hang after failed receive.
  The ARM regression changed from timeout exit 137 to a bounded 2.011-second
  error. App-created descriptors and the final ARM/native/installed pipeline
  passed; no SELinux setting was relaxed.
- `pixel-c` exposed a test timing assumption: Android CLI latency can outlast
  the one-second flush, so an END need not be the first record carrying growth.
  It is retained and is not labeled a Product error.
- Long Android UDP stress remains **HOLD**. `pixel-d`, generation 1591,
  stopped at 1669 sent / 1667 received; `pixel-e`, generation 1592, stopped
  at 1390 / 1389. Neither has complete two-end boundary capture, so those
  earlier failures remain unclassified.
- `pixel-g`, final source, generation 1593, stopped at 776 / 775. Its host
  capture contains all 776 requests and 776 replies; its device capture has
  776 requests and 775 replies. Sequence 775's reply is absent at device
  ingress, with zero kernel capture drops on both sides. This bounds that
  single failure between host egress and device ingress; it does not identify
  AP, radio, driver or WSL as the cause, or retroactively explain prior runs.
  `pixel-f` was an instrumentation setup failure because unprivileged dumpcap
  lacked capture capability; no Product run was started. The later capture
  used a temporary host-network container and removed it afterward.

The longer Android pressure and cross-capability conditions belong to
[T29 / SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64).
This report does not assert Doze/background power behavior, release capacity,
persistent history, rule attribution, reconnect within one generation, or
representative IPv6/TCP device traffic. Later attribution/history work remains
the next scoped slice, T22; no T22 implementation was started here.

## Reproduction

Use the source-bound build helpers and retained stage paths from their manifests:

```sh
rtk proxy python3 tests/evidence/verify_t21.py build-output/t21-20260926/linux-c
rtk proxy python3 tests/evidence/verify_t21.py build-output/t21-20260926/pixel-h --mutations
rtk proxy ctest --test-dir build-output/t21-20260926/host-tests --output-on-failure
```

The device collector uses only `./dev/adb`, serial selection from an existing
evidence file, fresh nonces, serialized profile operations, and normal runtime
stop. KernelSU Superuser access is checked immediately after installation.
The 34 pre-existing dirty files are protected by
`build-output/t21-20260926/preserved-baseline.json`; they are not part of T21.
