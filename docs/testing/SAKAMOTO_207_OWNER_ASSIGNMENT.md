# SAKAMOTO-207 — one typed Canonical OwnerAssignment

Acceptance: **functional PASS**, 2026-09-08. Linux and Pixel execute the same
source through the real default Product graph. The unique assignment is
constructed from shared PacketFacts and remains unchanged through policy and
terminal processing.

## Implemented contract

`product_owner_assign(layout, facts, assignment)` is the single assignment
Interface. Its arguments cannot carry packet bytes, UID, interface, queue,
Runtime Profile, provenance, Device Packet Direction, arrival worker or CPU.
The result contains a typed key, 64-bit canonical hash, logical ExecutionOwner,
validity and a non-semantic source-side projection.

| Key kind | Included identity beyond kind/family/terminal protocol/address pair |
| --- | --- |
| L3 | None; unavailable ports are omitted |
| L4_PORTS | Canonical typed TCP/UDP ports, including legitimate zero values |
| ICMP_QUERY | Normalized Echo class and identifier; no sequence or fake ports |

Address-and-port endpoints are sorted for L4_PORTS; L3 and ICMP_QUERY sort only
addresses. Echo request/reply normalize to query class ECHO. All started W2
workers participate equally in hash modulo worker count; Worker Placement is
not a key input. No weighted mapping or live reshard was introduced.

Invalid L3 has no valid assignment: kind NONE, hash zero, owner UNKNOWN. It
runtime-drops on the current execution context and completes the original
obligation. A parser-success L3 packet with unavailable transport facts gets an
explicit L3 assignment; unavailable policy predicates continue to no-match.

The 56-byte serialized opaque2 layout is preserved. The previously duplicated
obligation token slot now stores canonical hash; the one authoritative token
remains in opaque's AdapterObligation and is projected into a stack temporary.
Key kind, query class, validity and source-side projection fit existing padding
and state fields. Downstream restores addresses from the retained immutable
native span using that saved projection, without comparing endpoints, parsing
headers again, hashing or selecting another owner. No exdata, side table, extra
packet allocation, packet copy or expanded VPP buffer was added.

The old Guard helper is compiled only in the historical Host evidence build;
it and the Guard node are absent from the default Product binary. The default
binary contains one `product_owner_assign` implementation and no old
`product_packet_owner_from_facts` symbol. The existing unactivated FlowEntry
API/storage rewrite remains S208; this task does not create FlowEntry or an
ICMP tracker.

`flow_domain` was removed from Product structures, hashing, API/status, Rust,
JNI, Java and test inputs. Generated API CRC is now **76115fdc**. The JNI status
prefix has 135 values after the removal, with all later field offsets and
contract tests updated. The typed policy bundle itself retains its existing
schema. Android Root now installs TCP/UDP and Echo request/reply hooks on each
family's shared Q2 range; readiness is
`root-nfqueue-tcp-udp-echo-dualstack-q2w2`.

## Actual Linux NFQUEUE proof

Final artifact/run: `build-output/product-vpp-host-s207-c`,
`build-output/s207-owner/owner-run-d`. Kernel is
`6.6.114.1-microsoft-standard-WSL2`, x86_64, in a disposable rootless user/network
namespace. The namespace is test isolation only.

**48 fresh processes**, generations **20710–20757**, carry **581 real NFQUEUE
packets**. All 48 family/protocol/lane/owner/verdict combinations are observed:
IPv4/IPv6, TCP/UDP/Echo, both family queues, both owners, ALLOW/DROP. There are
48 blocked and 48 allowed endpoint probes. Each allowed Echo probe sends two
sequences with one identifier and receives actual kernel Echo replies.

The Linux namespace forbids ICMP datagram sockets by its ping-group policy;
standard raw ICMP sockets perform the Echo test instead. IPv4 request checksum
is computed by the test endpoint, IPv6 checksum is supplied by the kernel, and
real kernel replies traverse the NFQUEUE hooks. This is not graph injection.

The independent verifier decodes captured L3 bytes, constructs the typed key
and hash independently, and compares the actual admit/policy/terminal assignment.
Forward/reverse TCP/UDP packets and Echo request/reply keep the same identity.
Different Echo sequence values retain key/hash/owner. Actual callback TLS,
polling thread, policy node and completion thread match their respective lane,
canonical owner and original Adapter worker. Actual syscall CPU matches each
run's selected VPP lcore; CPU IDs are not assumed to equal logical worker IDs.

Every admitted wire packet has one parse and assignment, one original live
buffer, one original-lane verdict and one return. Remote packets have one
Primary Handoff and one completion return; there is no corrective hop. Native
VLIB vector counters conserve all captures. Linux DROP uses the ordinary Gate
rule 230 through the existing Product Core/VAPI client; TCP drop occurs at SYN,
while UDP/Echo blocked nonces do not receive a reply.

Every stop removes both-family hooks, closes the four original queue socket
inodes, permits fresh binds to queues 176–179, and exits the process. Pending,
frame, buffer, obligation, handoff and actual flow-entry counts are zero; both
handoff credits return to 32. The rootless environment still cannot read the
kernel queue table, so queue bind ACKs plus fd/ledger/process evidence are used,
as documented in S230.

## Actual Pixel Root proof

Pixel 6a `28201JEGR0XPAJ`, final `pixel-b`, generations **734–757**:
**24 fresh runtime generations**, **236 real NFQUEUE packets**, all 24
family/protocol/lane/owner combinations. Eight UDP and eight TCP nonce echoes
match an independent native socket endpoint. Eight app-UID native ping commands
send two Echo sequences each and receive both real kernel replies.

The same independent raw-byte key/hash and native node/worker/buffer/completion
checks pass. Both-family hooks use the same Q2 ranges for INPUT/OUTPUT; four
independent lanes close and stop cleanly after every case. Flow entries,
handoff credits, buffers and obligations have no residue. Wi-Fi is temporarily
disabled for bounded loopback evidence and restored to its original enabled
state. This is functional ownership acceptance, not latency/power qualification.

The first source-A Pixel run completed 64 exploratory wire cases, generations
670–733. Final source-C tests use those address/port observations only to choose
an efficient starting order, then independently verify every current capture.
No queue is forced and no prior observation substitutes for a final PASS.

## Supplemental native failure and invariance proof

Each platform additionally executes **14 GRAPH_INJECTED carriers**, separately
recorded from NFQUEUE traffic. Seven byte-identical pairs run on arrival worker
0 and worker 1 while UID, Linux ifindex, context, availability and device
direction vary. Cases cover typed zero UDP ports, unavailable UDP/TCP transport,
other valid L3, ICMP error L3 fallback, and invalid version/truncated IPv4.

Ten valid cases preserve the same assignment across the changed platform/arrival
facts. Four invalid L3 cases have no selected owner and skip policy; each drops
on its current worker. All fourteen return their buffer exactly once through
that injected origin context, with no invented NFQUEUE verdict. Exact native
counter deltas and zero final frame/buffer/obligation/handoff/flow debts are
verified. These records do not claim that injected platform values were obtained
from Linux or Android.

## Validation and boundaries

- Linux and Pixel source/build/install/run witnesses and independent verifiers:
  PASS. Every native APK library is hashed below and checked on the device.
- Typed-key property tests: reverse symmetry, Echo identifier zero and sequence
  independence, explicit unavailable ports, platform/arrival invariance, invalid
  owner absence, and exact W2 equal participation in a 4096-port set: PASS.
- ASan/UBSan, Host kernel vectors, actual default/Host plugin compilation,
  generated VAPI callback and initialization contracts, Android runtime/status
  field-order contract, S187 placement contract, S192 policy bundle contract,
  Rust Product Core tests (25 across two suites), syntax and diff checks: PASS.
  LeakSanitizer required execution outside the ptrace-restricted sandbox.
- Default Product binary audit confirms the old Guard/selector symbols are
  absent. Source audit confirms one assignment Interface and no re-canonicalize
  or rehash in metadata restoration.
- Corrupted evidence clones changing an Echo hash, inventing an owner for
  invalid L3, or changing typed key kind are rejected.
- Linux run a remains HOLD at the unsupported ICMP datagram socket. Later raw
  ICMP runs close normally. Source-A/B campaigns are preliminary; final claims
  above use source C, including explicit flow readback and Guard exclusion.
- Parser extension/fragment matrices remain S218/S219. This task proves
  assignment for the shared parser's current facts, not expanded capture or
  parser support for every wire envelope. ICMP session creation/tracking,
  unified production flow storage, expiry and FlowEnd remain later tasks.

## Artifact identities and reproduction

- Source commit: `9c67175713baceb46cef015f3464893fa3d69950` plus saved dirty source.
- Shared source SHA-256: `74cab6c69bec95f3708fde2e0976ac31fe5402f51db955df57a3d77856275301`.
- Artifact identity: `sakamoto-product-vpp-s207-v1`.
- API identity: `product_core.api/1.0.0@76115fdc`.
- Linux plugin SHA-256: `1bf63694a78f164d7eedf38fa0a694eeb1fb530642cc45eca01852ba2696be8b`.
- Linux VPP SHA-256: `3f68cfab85ae1b49f1f016b6ab13ddb69dc8208dd9fb2d8a4098731bbe264485`.
- APK SHA-256: `e77d6c2487f576d0f277691f9f9b3ddc73bde24b7483d35652ef970bb34544c9`.
- Linux build witness: `build-output/s207-owner/linux-build-c/build.json`.
- Pixel build witness: `build-output/s207-owner/pixel-build-c/build.json`.
- Final verifiers: `linux-verification-d.json`, `pixel-verification-b.json` in
  `build-output/s207-owner`; corruption results: `negative-d/verification.json`.

### Installed Pixel native closure

| Library | SHA-256 |
| --- | --- |
| libproduct_core_plugin.so | `c351df3e0e6029a1f853b0313b6a47a60f0b65d507bf41e29f99be464774ac5c` |
| libsakamoto_product_core.so | `3daa281f6952eb5438fa89f5caaf57b4120d077177b0b91852a4ad7c7a7d4336` |
| libsakamoto_runtime_control.so | `00ac497525f4949c2393bd13107ac5d0953dd51fbe16aee903a40b08363b16cc` |
| libsvm.so | `f9310112579b666a219aa8c059fc979790153712624e543a5baaf2e25ca95242` |
| libvapiclient.so | `8baeabcfdf33e2a511fada2e4932696508e7e02983dfa2d52e3a48fc0552a4b4` |
| libvlib.so | `5cdb7ec5d4bf32a1e7b32903ab196403d1fe3ede9ff3533cf8f1c471b4f0c62a` |
| libvlibapi.so | `c54e393ac7092c2823f356e29195cccd279c52faabfabc04910d961097934741` |
| libvlibmemory.so | `973231e8e7a44494521cbd4f54f0a7357ad1f4fc2a136b671b74e2a5a9b92bab` |
| libvlibmemoryclient.so | `88178938a57935b1113c3f0de286d6feb1ebf9b5f2d8b44bb29d29161cf6de8e` |
| libvnet.so | `d43c44ae7d6f744a499462865a1c2f40c59a1b252219cc55c9406e83d6f982f6` |
| libvpp_runtime.so | `c196564c9ee80833134a742802155d90fcaeafe321237496fb816c56c2bf961c` |
| libvppinfra.so | `306ddfca3cb9be02564f6e4a53f853ea673dec4d370c501d1a6e5c61690d7c51` |

```sh
python tests/evidence/build_s230_linux.py \
  --output build-output/s207-owner/linux-build-new \
  --artifact build-output/product-vpp-host-s207-new \
  --stage /tmp/sakamoto-s193-host-stage-current
unshare --user --map-root-user --net \
  python tests/device/s207-linux-owner.py \
  --output build-output/s207-owner/owner-run-new \
  --artifact build-output/product-vpp-host-s207-new \
  --policy-client build-output/s207-owner/linux-build-new/control/s230-policy \
  --vppctl /tmp/sakamoto-s193-host-stage-current/source/build-root/install-vpp-native/vpp/bin/vppctl
python tests/device/verify-s207-linux-owner.py \
  build-output/s207-owner/owner-run-new \
  --build build-output/s207-owner/linux-build-new/build.json
python tests/evidence/product_chain.py build build-output/s207-owner/pixel-build-new
python tests/device/s207-pixel-owner.py \
  --apk build-output/s207-owner/pixel-build-new/apk/sakamoto-runtime-debug.apk \
  --output build-output/s207-owner/pixel-new
python tests/device/verify-s207-pixel-owner.py \
  build-output/s207-owner/pixel-new \
  --build build-output/s207-owner/pixel-build-new/build.json
```

Use fresh evidence/runtime directories. The optional Pixel `--reference-run`
only prioritizes already-observed endpoint addresses; coverage and identity are
always established from the new run. Android operations use repo-local `dev/adb`.
