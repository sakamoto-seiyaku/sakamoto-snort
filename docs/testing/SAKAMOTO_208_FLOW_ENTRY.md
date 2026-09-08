# SAKAMOTO-208 — owner-local FlowEntry and first-packet direction

Acceptance: **PASS — 2026-09-08** for the S208 bounded owner-local FlowEntry
increment. Final same-source artifacts pass **1,873 actual NFQUEUE packets**:
Linux 936 packets / 56 processes and Pixel 937 packets / 55 traffic generations.
All 111 persistent identities retain the required ownership and direction
semantics; cleanup and obligation conservation pass. Pixel also passes 2,000
additional no-traffic worker-barrier queries in generation 850.

This is a functional milestone. Production table unification, protocol trackers,
VPN transport, concurrent immutable-snapshot lifetime, and performance release
gates retain their separate scope.

## Implemented contract

The actual policy node obtains its pool from the current VPP worker. It consumes
S207's existing typed assignment, canonical hash and source-side projection.
There is no downstream canonicalization, second hash/selector, arbitrary owner
pool lookup, Owner Guard node or Corrective Handoff in the default product.

The first PASS_NEXT packet that allocates an entry defines its ORIG side and
flowOriginDeviceDirection. Reverse packets are REPLY. Identical endpoints always
remain ORIG, including when Device Packet Direction changes between OUTPUT and
INPUT. No TCP SYN or port-size inference assigns a client/server role.

The bounded table retains 64 entries per worker. Hash is a filter; identity is a
comparison of the complete typed key. Early Gate/L4 DROP precedes lookup and
allocation. Policy epoch changes invalidate only the cached decision when the
owner next observes a passing packet; entry identity, first attribution,
first-seen time and cumulative packet/byte counts survive. Equal revision with
a different snapshot hash is also an epoch change. Bootstrap PASS before the
first policy snapshot may create an entry with no cached decision.

Wrong-worker delivery is a deterministic runtime DROP without another handoff
or FlowEntry mutation. Capacity exhaustion also runtime-drops rather than
replacing a live entry. Native Root stop first quiesces lanes and checks owned
work, then closes sockets and flushes pools under the VPP barrier.

The table/pool unification (S221), protocol trackers, timers, FlowEnd and VPN
transport are not claimed. S209 still owns packet snapshot lifetime, removal of
publisher-side pool revision updates, and concurrent revision stress. S208's
current publication/inspection uses the existing control worker barrier.

## Acceptance blockers fixed during validation

- L4 authoring already allowed an omitted network context, but typed bundle
  hashing dereferenced null and crashed the runtime. Validation, encoding and
  hashing now map omitted L4 context to the native ANY value. The focused Java
  regression and real Pixel L4 DROP/ALLOW path exercise this behavior.
- A real Pixel run aborted in `vlib_worker_thread_barrier_sync_int`. The Android
  idle profile can sleep for the same one second as the barrier timeout; its
  conditional wake can miss a worker entering sleep. Android profile patch 18
  queues the barrier wake unconditionally in eventfd, retaining it across sleep
  entry. It preserves the accepted idle interval and ordinary packet wakeup.
  The original no-traffic 2,000-barrier stress did not reproduce the failure;
  the recorded real-traffic abort remains the failing witness. Final device
  revision checks pass across all 49 main-matrix generations; the final barrier
  result is recorded below.

## Final-source Linux proof

`build-output/s208-flow/linux-f`: 52 fresh processes, generations 20810–20861,
914 actual NFQUEUE packets and 52 persistent transport identities. The full 24
family/protocol/mode/lane/owner combinations are present: IPv4/IPv6, UDP and TCP,
TCP established before hooks, both family lanes and owner 0/1. Every connection
spans two policy epochs and matching endpoint nonces are recovered from raw
captured bytes. Blocked first probes leave zero entries/allocations.

`build-output/s208-flow/linux-extras-e`: four additional generations 20890–20893,
22 actual packets. Each family covers self-addressed UDP with identical ports
and a deliberately misdelivered remote packet followed by recovery of that
same tuple. Misdelivery skips policy evaluation, never enters the FlowEntry
mutation seam, returns the original obligation once and leaves both pools
unchanged. Recovery uses the correct owner pool.

The independent verifier checks raw packet parsing, full assignment, actual
worker/CPU/pool, ordered lifecycle events, entry contents and counters, native
VLIB vectors, fd inode disappearance, queue rebind and final zero residue.
Five separately cloned corruptions are rejected: stored origin, foreign pool,
early-DROP mutation, reset counters and changed full key.

Host support: typed full-key collision and foreign-pointer rejection, bounded
capacity, initial INPUT/unknown facts, bootstrap epoch, reverse/degenerate
identity, lazy revision/hash invalidation, and flush are covered by the C
properties. The FlowEntry binary also passes ASan/UBSan outside the sandbox;
the sandbox ASan signal-handler failure is not counted as a product defect.
Historical Host-evidence graph fixtures are not the real-wire acceptance path.

## Source and artifacts

- Commit: `9c67175713baceb46cef015f3464893fa3d69950` with the recorded dirty source snapshot.
- Source SHA-256: `7f055a15f96918c70966c7cdef48ed56307a0758cdd18810bb239af903897235`.
- Android dirty diff SHA-256: `191ed13584db252d47d6aa8050b872e9c97fd17df029f01d4b9b0f7953529afc`.
- APK SHA-256: `07e63c05aa9ac1a5ad42d9ac09c4206ddce7c15965a426f2a506c3e2493c5c23`.
- Linux dirty diff SHA-256: `191ed13584db252d47d6aa8050b872e9c97fd17df029f01d4b9b0f7953529afc`.
- Android stage: `/tmp/sakamoto-s208-vpp-stage`; 18 Android profile patches, series SHA-256 `2f2b87b011cc131cada294ae31e6ebfb618ccdf3f303b303ff4b7f00b562af74`.
- VPP revision: `9258530f3804a152578ce11cc7c8a1e9eab88ed0`; API identity `product_core.api/1.0.0@76115fdc`.

| Android native entry | SHA-256 |
| --- | --- |
| `libproduct_core_plugin.so` | `369417c82b1b70c5862ac98dfcaabb415951d9d55595922dc1775ef4c427f498` |
| `libsakamoto_product_core.so` | `3daa281f6952eb5438fa89f5caaf57b4120d077177b0b91852a4ad7c7a7d4336` |
| `libsakamoto_runtime_control.so` | `00ac497525f4949c2393bd13107ac5d0953dd51fbe16aee903a40b08363b16cc` |
| `libsvm.so` | `b091cff3dbb233d4b0973e899d7e8077dbcc530b1aecddea6186a7ad7aa7aa53` |
| `libvapiclient.so` | `d9ee9f04c97110c0f5d2470062e65c9360ad6e6575e7055db99351b0f5403ac9` |
| `libvlib.so` | `1224a8c38e8f396b753c162a39282cca0b963d0b29c095d9e5fcf3c130eeaf5e` |
| `libvlibapi.so` | `b650b403ce3c4d4c8616c117611e8410eb9b1361e627772634a24b0f4845e615` |
| `libvlibmemory.so` | `8170514a36baa3d78f0ac3037fbe935b742a61f3483c02d3e87f0bd602672e82` |
| `libvlibmemoryclient.so` | `f3464e9f97c03e2bb97bcff19eeea30b87f94f15a6ba787e98f43181003e9c97` |
| `libvnet.so` | `098428abd79a3ee88d2f2c122488546f0b7f4de4731b2c74ea6da3f289f58af0` |
| `libvpp_runtime.so` | `52f690bb5fda680ebafcd84061e2d93eb3b4c63ce41917483c642609872e97b7` |
| `libvppinfra.so` | `691d7a5273c7316ecc7456e3c04748facfcc8e1bd06add451d5206dfe6efe063` |

Build manifests: `build-output/s208-flow/pixel-build-e/build.json` and `linux-build-e/build.json`. They include immutable source copies and all artifact hashes.

## Final-source Pixel matrix

`pixel-f` passes 49 fresh generations, 801–849: **897 actual NFQUEUE packets**,
49 persistent flows and all 24 required family/protocol/mode/lane/owner
combinations. Each persistent connection spans two policy epochs; raw captured
bytes and endpoint output prove both nonce exchanges. Early L4 DROP leaves
zero entries and allocations. Later publication preserves identity, direction,
first attribution and cumulative counters while the owner invalidates the
cached decision on the next passing packet.

| Family / transport | Mode | Generations | Packets |
| --- | --- | --- | --- |
| IPv4 UDP | Normal | 801–811 (11) | 77 |
| IPv4 TCP | Normal | 812–815 (4) | 110 |
| IPv4 TCP | Established before hooks | 816–819 (4) | 70 |
| IPv6 UDP | Normal | 820–825 (6) | 42 |
| IPv6 TCP | Normal | 826–845 (20) | 528 |
| IPv6 TCP | Established before hooks | 846–849 (4) | 70 |

Every row contains both family lanes crossed with both owners. Additional
connections reflect actual kernel socket placement; assignment and pool are
never rewritten to fill coverage. The final verifier passes all per-packet
lifecycle, native vector, actual pool, full-key and counter checks. All 49 stops
flush pools, close the recorded NFQUEUE socket inodes, remove kernel queues and
product hooks, and leave no runtime process. Wi-Fi returns to 1.

## Final-source Pixel supplementary proof

`pixel-incoming-e` passes both families in generations 795–796: 22 actual
NFQUEUE packets, two entries. The app's existing debug TCP listener accepts a
shell connection before hooks are installed. The first captured packet is
INPUT with unknown UID (4294967295); it establishes ORIG and immutable origin
direction 1. The app's outbound echo is REPLY. Captured TCP contains no SYN,
and both endpoint records plus raw nonce bytes prove the established exchange.

`pixel-extras-b` passes generations 797–800: 18 actual packets and four entries.
Both families cover identical endpoint tuples and deliberately wrong-worker
remote delivery followed by correct-owner recovery. Stop closes recorded socket
inodes, clears both pools and all completion debt, removes product hook residue,
and restores Wi-Fi to its original value 1.

These use Pixel 6a (`bluejay`) serial `28201JEGR0XPAJ`, application UID 12632,
Root profile, kernel `6.1.134-android14-11-g66e758f7d0c0-ab13748739` (aarch64),
and the APK/native hashes above. Linux uses
`6.6.114.1-microsoft-standard-WSL2` (x86_64) with isolated network namespaces.
The main matrix above supplies the full local/remote and owner coverage.

For example, incoming IPv4 generation 795 retains worker 1 / slot 0 with
key `127.0.0.1:33818 <-> 127.0.0.1:40609`, protocol 6, canonical hash
12114355387247031989, `origin_is_a=1`, `flow_origin_dir=1`, and unknown first
UID/context. The final entry contains 12 packets / 732 bytes; its original
attribution survives alternating captured INPUT/OUTPUT traffic. The immutable
trace and full key are in `pixel-incoming-e/g0-flow-final.txt`.

## Fixture corrections and rejected preliminary runs

- `pixel-e` was interrupted and remains HOLD. TCP FIN/ACK traffic arrived after
  an initial zero-debt sample, so the earlier log and later runtime counters
  described different moments. No trace was truncated or salvaged. Final
  collectors flush only the existing product capture chains, retain their
  empty jumps for normal stop cleanup, and require unchanged captured counters
  plus zero pending/frames/buffers/obligations for at least 2.2 seconds before
  collecting all final views. This exceeds the one-second maximum idle sleep.
- Repeated legacy debug empty-policy publications advanced the derived native
  revision without advancing Java authoring transactions. The collector now
  begins each case with a typed publication, then uses one legacy successor.
  At stopped generation 772, the old derived `files/product-policy` directory
  was archived on host and renamed on device so fresh derived intent could be
  rebuilt. Authoring ProductState and transactions were preserved. The exact
  operation and backup hash are in `runtime-intent-reset.json`, with archive
  `runtime-intent-before-reset.tar`. This is test setup, not a product migration.
- Preliminary incoming cases overlapped listener initialization's idle
  RuntimeService query with Root start. Collectors now wait for the prior idle
  service record to retire before issuing start. Final incoming generations
  complete correctly with that ordering. This does not claim a product
  lifecycle race fix; readiness checks were not relaxed.
- Earlier sources and failed or incomplete runs remain separate witnesses and
  do not contribute to final-source acceptance totals. Ordinary packet wakeup
  performance is unchanged and no new latency/performance claim is made.

## Linux executable identity

| Artifact entry | SHA-256 |
| --- | --- |
| `bin/vpp` | `3f68cfab85ae1b49f1f016b6ab13ddb69dc8208dd9fb2d8a4098731bbe264485` |
| `lib/vpp_plugins/product_core_plugin.so` | `540e193a4378bf35ea90a87307f5d06d040bbc126221192838f2d4037be78a21` |
| `bin/sakamoto-product-core-host` | `aa8274431cbf601e987e2144089a5d894b264f2599a459c46dfedb67a2345fbe` |
| `control/libsakamoto_product_core.so` | `22de04ccd8acdf3ce5f19cb0c9ec990502638677453307c2ce65b4c7d39456a5` |
| `control/s230-policy` | `7f1b1a2b8e7e5bcd2b1eb339bbf03a46412de0a3381d77ce47a7c59638705d86` |

## Reproduction

Run commands from the repository root. Device collectors use `./dev/adb` and
operate the existing Debug Control Activity. Build the Android stage with all
18 patches before creating the APK, and set
`SAKAMOTO_VPP_STAGE_DIR=/tmp/sakamoto-s208-vpp-stage` for that build; an older
cached stage is not an equivalent artifact. Build manifests retain the exact
source snapshot, stage manifest and build logs.

```sh
python3 tests/device/verify-s208-flow.py build-output/s208-flow/linux-f --build build-output/s208-flow/linux-build-e/build.json --platform linux
python3 tests/device/verify-s208-extras.py build-output/s208-flow/linux-extras-e --build build-output/s208-flow/linux-build-e/build.json --platform linux
python3 tests/device/verify-s208-incoming.py build-output/s208-flow/pixel-incoming-e --build build-output/s208-flow/pixel-build-e/build.json --platform pixel
python3 tests/device/verify-s208-extras.py build-output/s208-flow/pixel-extras-b --build build-output/s208-flow/pixel-build-e/build.json --platform pixel
python3 tests/device/verify-s208-flow.py build-output/s208-flow/pixel-f --build build-output/s208-flow/pixel-build-e/build.json --platform pixel
python3 tests/evidence/test_s208_flow_negatives.py build-output/s208-flow/linux-f --build build-output/s208-flow/linux-build-e/build.json --output /tmp/s208-negative-fresh
```

The negative output path must be new. Current-source verification intentionally
rejects evidence after later product edits; use the preserved source snapshot
for historical reproduction. Linux namespace and Android Root collection need
the corresponding kernel privileges. Unit properties alone do not replace
these real-wire runs.

## Barrier regression and final evidence seal

`barrier-after-f`, generation 850, passes 40 batches of 50 `show product flows`
queries: all 2,000 queries return both worker pools. The largest batch took
0.232 seconds; aggregate command duration was 8.184 seconds. These durations
are diagnostic observations, not a packet-latency claim. The final runtime
stops with no product residue. `barrier-after-e` was blocked before device
access by the WSL sandbox channel and remains separate from the successful run.
The older no-traffic baseline also passed; the recorded real-traffic barrier
abort is the failing witness for the wake fix.

`evidence-tools-e/` preserves 17 collector, verifier, oracle and supporting test
files at acceptance time. Its manifest records their SHA-256 values and hashes
of all five positive verification results, negative cases, barrier result and
both build manifests. No preliminary run contributes to the final totals.

Evidence manifest SHA-256: `c5da0998456afb61defda5b2b44b037a923f09347d36a023f5442311e1f09918`.

| Verification record | SHA-256 |
| --- | --- |
| `linux-verification-f.json` | `44ec154986fadecca58d81f49d0764029fb56893c7454c43d838ed03d7eb20cd` |
| `linux-extras-verification-e.json` | `66ed4e40b9fa9e38bdabfd87cde7acafc00a9c4dc392fa23d84fca4ed1d6f32d` |
| `pixel-verification-f.json` | `1cf310674de419aaebc8fba243ffcfc414eefdbdba4b405627a95018b1afed29` |
| `pixel-extras-verification-b.json` | `fbaa0a1374763b40bfbc624a2e287985fa9c086ff443f83c2ea8fe39afc23b5b` |
| `pixel-incoming-verification-e.json` | `8454862bbf544eb907f51f06969bd38c1054da0e08b16534cdac214b9f6f0d83` |
| `barrier-after-f/result.json` | `8f8b44217cf9b5ece267ce1d96d6b2711dfde45ad0b8a64631b96cffdcb1ff7d` |
| `negative-evidence-f/results.json` | `f5e9e03f513ff449b057b42aa3db4debf0e33fd88812de4e2481d0b29977b436` |
| `pixel-build-e/build.json` | `8b8fe537503c225582fa690ad5c5d8932ac2ac089de92d26fd49fb79afb565dc` |
| `linux-build-e/build.json` | `198bca415ee71c8e2ca33e174de4dd337849fcd34a1caa77411dd1444bf3eb9c` |

| Acceptance tool | SHA-256 |
| --- | --- |
| `tests/device/s208-flow-verify.py` | `9322ba395d3a3675641aa4be2ded1c7e6dfdb74bc3b15d5dfa31b8d2cc442e09` |
| `tests/device/s208-pixel-barrier.py` | `e405aaa1e2d587eca6af9181455823bcd1c5226a1db67b74207573e811b77b8a` |
| `tests/device/verify-s208-extras.py` | `ae7e67e36bd79a8626282c6a1a7c2b4ba43bc88709f86f0563a6e67b7a7ba0a9` |
| `tests/device/verify-s208-flow.py` | `99b275266b4d9275457af9fbad0881dc99d668c5dc636acbf50be30bde890476` |
| `tests/device/verify-s208-incoming.py` | `7ce3854109851f2b890c5b265a91768a82f062461c12728a986316b1062e7931` |
