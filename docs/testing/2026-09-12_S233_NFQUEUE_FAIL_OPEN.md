# S233: NFQUEUE fail-open and bounded receive resources

2026-09-12. Acceptance for SAKAMOTO-233 on the current VPP-native C Product
artifact B. This is pre-admission resource behavior, not S210 graph handoff
congestion or the full S242 lifecycle qualification. No readiness is expanded.

## Artifact identity

Both platforms were built from the same Product source snapshot, including
the supervisor rule installer. Helpers are independently built kernel UDP
endpoints and Rust/VAPI policy clients, not replacement packet-domain code.

| Identity | SHA-256 / revision |
| --- | --- |
| Git commit | `0f5957290fded7884f7b5a795a97f9145c58f182` |
| Product source | `d3627915051372239ce2c171def92d0d4a8a86a3ddb28a0121ea6665751687f6` |
| Captured dirty diff | `e1bf966667385d6cd0738aad98435d927bb61a566bb408bbb731e95020369a4d` |
| Linux build witness | `08e8100a704acfd1b92b4912f56fd37b87ea1267234d8f81f5e63c2713b07b1f` |
| Pixel build witness | `4b70f4c800bf8e5041b058c5e43394c3c2461d093daf45eec451233114da2168` |
| Installed APK | `406166d0bb3bbc34dd92940a81e6871c58859637ee46a1dd0116bfce6bebcf2a` |
| Android Product plugin | `3002f9407bfc8deaa859bcb612d1554506eed4cc0c1e7a61015083774e4e648f` |
| Android Product Core | `a42526bd795e73c513ce59be1f534a8dec5a6de340a36468ae8b1659d5190414` |
| Android VPP executable | `62d2c7339c9d17089f7198d4d74cc3d79f44321cd841e734e38004c607dff5bb` |
| Linux Product plugin | `eb6206ab5f5a3e6507ab3711f4acb2e96fe83abbefdc9b418e0cef633135f0c6` |
| Linux VPP executable | `f0153172eda7ae31f01d8ef2c4f81b52c8a82bf10cee542e99fc5b691f6a17bb` |

Full source copies, dirty diff, generated API, native library hashes and build
inputs are in `build-output/s233-20260912/{linux,pixel}-build-b/build.json`.
The independent verifiers compare these witnesses with current Product source,
actual artifact files, and the installed APK/native-library hashes.

Linux uses `6.6.114.1-microsoft-standard-WSL2` in a disposable rootless user and
network namespace. Endpoint/rule UID is namespace UID 0; actual `NFQA_UID` is
initial-namespace UID 1000. Policy targets the observed 1000 and the verifier
checks that packet facts were not rewritten. Pixel `28201JEGR0XPAJ` uses
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, with app UID 12632.

The Linux stage was rebuilt with all five current core patches; its manifest
hash is `96cf8310ec2e7e69ff0b584c770aab2448433b8816a61ebccc59e9674c2e4c1f`.
The generic package preflight listed absent formatting tools and optional
libiberty. Only that generated preflight stamp was supplied locally; no host
package was installed and actual compiler/link checks remained enabled.
Upstream also warned about installed external-dependency package version
24.06-10 versus requested 26.02-1. The build succeeded and the artifact
allowlists only Product; this does not qualify unrelated VPP drivers/plugins.
Android reuses the already qualified S241/S243 VPP stage, whose manifest hash
is `02b29be6c7fd3922bfa050e43d87397c3a4beb698780ce3f3d62147b6bcf6ff8`.

## Implementation boundary

Each of four NFQUEUE lanes owns 64 normal and 8 reserve **existing VPP buffer
indices**, allocated before any listener opens. There is no receive-path pool
growth, cross-lane borrowing or shared reserve lock. The original receive
materializes packet bytes directly in its borrowed VPP buffer. A valid graph
completion returns that exact index to its origin lane; it is not separately
freed back to VPP while the lane still owns the partition.

Normal exhaustion takes a reserve buffer and attempts a counted `NF_ACCEPT`
on the origin worker without graph admission. Truncated/unadmitted envelopes
use only a complete native identity already present in the same buffer; no
temporary packet copy is introduced. If neither partition has storage,
zero-length `recv(MSG_TRUNC)` consumes the datagram without copying packet
bytes: the mandatory identity is unavailable, an explicit loss is recorded,
and no verdict is fabricated. The kernel obligation is left for queue teardown.
The missing-identity diagnostic likewise drops identity only after a real recv.

Queue configuration now requests `UID_GID | FAIL_OPEN` (`flags=9`) and waits
for the actual kernel ACK. The default maximum queue length is 1024; the
startup-only bounded override accepts 1..65536. Production rules retain
`--queue-bypass`, and the installer verifies the exact rule including that flag.

The first unoptimized Linux build exposed a 43 KiB forced-inline VPP allocator
stack frame in the default 32 KiB adapter-start process. The existing startup
process now uses a fixed 256 KiB control stack, matching VPP's own CLI process;
this is neither packet storage nor a hot-path allocation. The no-hooks
regression failed with SIGSEGV before the fix and passed startup/stop with
queue limits 1024 and 1 afterward (`startup-a-red`, `startup-b-green`).

## Real fault matrix

The main collector uses exact private UDP loopback hooks, an independently
bound endpoint for each selected address, unique payload nonces and fresh
source ports. IPv4 queues are 176–177 and IPv6 queues 178–179. Family lane 0/1
maps to logical worker 0/1, VPP thread 1/2. Source/owner/lane and the original
queue packet ID are retained in the raw traces; no graph-injected packets
participate in this matrix.

| Case, all four lanes on both platforms | Independent result |
| --- | --- |
| Baseline ALLOW / Gate DROP | Matching kernel endpoint echoes / physical `NF_DROP`, respectively |
| Hold all 64 normal slots | Eight reserve-origin ACCEPT attempts total, successful request/reply echoes, no additional graph admissions |
| Clear normal exhaustion | New flows encounter the still-installed DROP policy again |
| Hold all 72 slots | One consumed datagram/lane, explicit reserve loss, zero verdict attempts and no endpoint receipt |
| Clear total exhaustion | New flows again get policy DROP; all partition indices recover |
| Remove mandatory identity after real recv | One explicit identity loss/lane, zero verdict attempts, no receipt |
| Clear identity fault | New flows again get policy DROP; subsequent ALLOW echoes succeed |
| Bound listeners, queue maximum 1, consumers paused | First packet/lane remains queued; later fresh flows echo via kernel fail-open with no adapter recv/verdict delta |
| Resume consumers | The four previously queued packets receive actual policy DROP; fresh flows also encounter policy |
| Pause/fill again, close listeners | Already queued nonces never reach the endpoint; fresh flows echo via no-listener bypass with zero adapter delta |
| New process/generation | Q2 per family, fresh ALLOW/DROP/ALLOW behavior and fully allocated empty partitions |
| Stop | Zero graph debt, zero lane loans/allocated slots, queues unbound, original socket inodes absent, exact private hooks removed |

Pressure proof includes `/proc/net/netlink`: each bound queue socket contains
one small message (896 bytes on Linux) and zero socket drops; its occupancy
does not change while subsequent probes bypass. Pixel additionally reports
actual NFQUEUE depth 1 for all four queues. Linux denies its NFQUEUE proc table
in the rootless namespace, so its evidence instead combines successful config
ACKs, the one-message occupancy, actual bind-ownership probes and endpoint
behavior. This distinction is recorded, not represented as a proc-table read.

These are three distinct origins: no-listener kernel bypass, queue-full kernel
fail-open, and pre-admission adapter reserve verdict. None is a policy ACCEPT.
In particular, a packet that has already received policy DROP stays DROP.

## Results and negative checks

- `linux-b-3`: **94 endpoint cases**, generations 23310–23312, independent PASS.
- `pixel-b-2`: **76 endpoint cases**, generations 23310–23312, independent PASS.
- Each platform rejects **14 altered evidence sets**, covering flags, queue
  size, reserve/identity loss, pool ownership, fake adapter origin, policy
  DROP-to-ACCEPT, old-queued-packet delivery, socket overflow and queue cleanup.
- `linux-fragment-b2`: **120 native NFQUEUE packets**, all four family/hook
  combinations, independent PCAP/endpoint and original-buffer conservation PASS.
  Original fragment groups actually traverse Product reassembly on Linux.
- `pixel-fragment-b`: **114 native NFQUEUE packets**, Root app generations
  1316–1319, all four family/hook combinations PASS. This kernel presents the
  tested fragment datagrams already reassembled to NFQUEUE; no Pixel Product
  fragment-path coverage is inferred from that result.
- Five additional mutations of Linux fragment evidence reject missing original
  release/completion, nonexclusive references, wrong bundle size and wrong survivor.
- All four Pixel app starts expose **16 production NFQUEUE rules** with the
  correct family spans, protocol/UID scope and `--queue-bypass`.
- Fixed-pool C test: 4 lanes × 1000 full normal/reserve exhaustion/return cycles,
  wrong/stale/duplicate return rejection and lane isolation; ASAN+UBSAN with
  leak detection PASS. This is a pool unit check, not a sanitized VPP claim.
- Full Android runtime contract suite and `git diff --check` PASS.

The fragment oracle has an explicit `--product-reassembly` mode. It checks one
logical policy evaluation per complete bundle and one native completion per
original buffer, including `refs=1`. Its default historical S231 rejection
model remains unchanged. It never executes Product reassembly itself.

Final Pixel state is generation 1319, `stopped`, `mayBeActive=false`, PID -1,
empty error fields. Wi-Fi is restored to its original enabled state. Test
processes, veth links, destination rules, private hooks and queues are absent.

## Recheck stored evidence

```sh
rtk proxy python3 tests/device/verify-s233-fail-open.py build-output/s233-20260912/linux-b-3
rtk proxy python3 tests/device/verify-s233-fail-open.py build-output/s233-20260912/pixel-b-2
rtk proxy python3 tests/host/s233_verifier_negative_test.py build-output/s233-20260912/linux-b-3 --output build-output/s233-20260912/linux-b-3/negative-verification.json
rtk proxy python3 tests/host/s233_verifier_negative_test.py build-output/s233-20260912/pixel-b-2 --output build-output/s233-20260912/pixel-b-2/negative-verification.json
rtk proxy python3 tests/device/verify-s231-fragments.py build-output/s233-20260912/linux-fragment-b2 --build build-output/s233-20260912/linux-build-b/build.json --platform linux --product-reassembly
rtk proxy python3 tests/device/verify-s231-fragments.py build-output/s233-20260912/pixel-fragment-b --build build-output/s233-20260912/pixel-build-b/build.json --platform pixel --product-reassembly
```

Collectors and separate helper builders are in `tests/device/s233-fail-open.py`
and `tests/evidence/build_s233_helpers.py`. Linux collection requires an isolated
`unshare -Urn`; Pixel collection requires the app stopped and uses `./dev/adb`.
Use a new output directory per run. Failed preliminary runs remain HOLD;
their CLI handshake and exact-address endpoint issues were fixed in the runner,
not hidden by changing Product verdicts or weakening the final gate.

## Kernel semantics and limits

The queue-full flag is checked before the netlink unicast. The same flag also
covers a later unicast failure, but does not cover every earlier allocation
failure. Queue destruction flushes already queued packets as DROP, rather than
turning them into no-listener bypass traffic. See the primary
[Linux 6.1 NFQUEUE implementation](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nfnetlink_queue.c)
and [Linux 6.6 NFQUEUE implementation](https://github.com/torvalds/linux/blob/v6.6/net/netfilter/nfnetlink_queue.c).
The no-listener branch is separately conditional on `-ESRCH` and the bypass
verdict flag in [Linux nf_queue](https://github.com/torvalds/linux/blob/v6.1/net/netfilter/nf_queue.c).

No zero-loss guarantee is made under memory pressure, missing identity or a
failed physical verdict. A successful verdict syscall is not itself delivery
proof; positive delivery claims above require the independent endpoint echo.
No public-network, mobile-network, arbitrary kernel-OOM or full S242 lifecycle
claim is inferred from this bounded acceptance.
