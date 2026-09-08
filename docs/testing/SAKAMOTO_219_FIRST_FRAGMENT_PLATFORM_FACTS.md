# SAKAMOTO-219 — Offset-zero platform facts across native reassembly

PASS, 2026-09-09.

The existing native full-reassembly path preserves Platform Packet Facts in
its 56-byte inline fragment envelope before handing VNET opaque to the engine.
On native success it restores the offset-zero survivor's facts by value.
This task verifies that rule field by field, adds bounded controlled facts to
the existing graph injector and exposes the missing ifindex/context trace
fields. It adds no metadata merger, fragment table or new ownership overlay.

Inspection also found that the envelope validator still allowed only Root
and diagnostic obligations. It now accepts the real VPN TUN obligation kind,
so valid kernel-fragmented TUN traffic can use the same native reassembly and
original completion path. The omission was found in code; no deliberate
pre-fix device crash is claimed. The post-fix real TUN acceptance is below.

## Accepted source and artifacts

Both builds use source SHA-256 `a4e0da7a0e2e1b998928924b8ac5b6d59247f21419d8db275fc52165643797fc`.
Build base: `c4c1c3b4958159c67c8074a3f908ba7d25a41d41`; dirty-diff SHA-256:
`cd0f7a471e11c8eb3770d005f90252b54f73aeb30586529a720093f19dfaa7a0`. Complete per-file source snapshots and pinned
artifact hashes are retained in the manifests. The later task commit does
not rewrite these historical build identities.

- Android: `build-output/s219-first-facts/pixel-build-a/build.json`.
- Linux: `build-output/s219-first-facts/linux-build-a/build.json`, artifact
  `build-output/product-vpp-host-s219-a`.
- Product identity: `sakamoto-product-vpp-s219-v1`.
- Generated API remains `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256: `5f9ee0dca886febf3ed97c670b63da674f1e29748caecb3dbb3e5cecab91829e`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `0bc86c6526bfc7e1b2d6ecfeab2410b44a3fe941565333bc2290f2c0eb91a05a` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

The installed APK/native files match the actual package. Both Product plugins
were compiled from this source with Host fixtures disabled. The pinned VPP
five-patch profile is unchanged. The removed C++ mainline and historical C/VPP
POC implementations were not imported.

## Controlled first-facts matrix

Pixel `28201JEGR0XPAJ`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`, runs `pixel-a` / generation 941.
Linux x86-64 `6.6.114.1-microsoft-standard-WSL2` runs `linux-b` / generation
21910 in an isolated user/net namespace. Each platform processes **30
GRAPH_INJECTED originals**, producing **14 successful native datagrams** and
two missing-first timeouts. The injector remains bounded to 32 cases and
256-byte original spans; this task does not widen its resource envelope.

Each family exercises these seven successful scenarios plus missing first:

| Scenario | Offset-zero facts | Other fragment facts | Result |
| --- | --- | --- | --- |
| First arrives first / first arrives late | A known | Unknown | Restore A; actual policy DROP |
| First arrives first / first arrives late | Unknown | A known | Preserve unknown; category-dependent policy no-match |
| Differing fields, first arrives first | A known | B known | Restore A; actual policy DROP |
| Differing fields, first arrives late | B known | A known | Restore B; rule for A does not match |
| Snapshot changes while first is retained | A known | B known after publication | Restore A; actual policy DROP |
| No offset-zero fragment | Absent | One noninitial fragment | No success/parser/policy; Runtime DROP timeout |

A is UID 21900, interface 31, context Wi-Fi, availability 7, OUTPUT and
TUN_ORIGIN provenance. B is UID 21901, interface 32, context Mobile,
availability 7, INPUT and FLOW_STACK_RETURN provenance. Unknown is zero
availability and unavailable identity/direction/provenance. These are explicit
controlled field values on GRAPH_INJECTED carriers, not actual Android UID,
network acquisition, TUN capture or Flow Stack return evidence.

The verifier derives the expected facts from the original at offset zero,
not the first arrival or a reported expected-result field. It checks all six
fields at native ingress, native success, shared parser, actual matcher and
terminal. An unknown first is never filled from another original. A later
field disagreement does not become malformed and does not overwrite first
facts. Payload reconstruction, IPv4/IPv6 lengths, UDP checksums and canonical
owner are independently verified. Both final owners are exercised; this
controlled matrix's native memory owner is W0, so it does not claim all four
memory-owner/final-owner pairs.

Pixel changes the real Android publisher revision through its controlled
missing/restored event seam while the first original is already retained.
Linux publishes a clearly labelled controlled snapshot through the actual
Product Core/VAPI interface. Native records prove the revision changed between
the two fragment admissions. Restoration never substitutes the current
snapshot for the stored first facts. This is not Linux platform event
collection acceptance, which remains S235.

Every diagnostic original retains its own case identity, generation, arrival
worker and original buffer. Native lifetime pins are released once. Each
successful datagram receives one shared parser/selector/policy path after
native reassembly, and its policy disposition settles both original
obligations. No-first cases never create a successful output. Diagnostic
carriers produce no NFQUEUE verdicts.

## Real TUN fragment acceptance

`tun-a` / generations **942 and 943** uses an independent kernel UDP endpoint
under the test application's UID 12632. It sends 1800-byte payloads with kernel
fragmentation enabled through the actual VPN route. The helper neither writes
a TUN fd nor injects a graph packet.

Across two families, Gate/L4 policies and canonical owners 0/1, each generation
sends eight UDP datagrams. Total: **16 datagrams, 32 real TUN fragment
originals**, plus 14 separately accounted kernel control packets, for **46
real TUN originals**. This proves the newly allowed TUN envelope kind through
actual native IPv4 and IPv6 reassembly.

The verifier groups actual captures by wire fragment identity, checks complete
nonoverlapping coverage, reconstructs the UDP payload and checksum, binds the
nonce/ports to the kernel endpoint receipt and compares native reassembled
bytes. First facts remain UID 12632 with explicit controlled-provider identity,
unknown packet Linux ifindex, event-derived VPN context, OUTPUT and
TUN_ORIGIN. Every target datagram has an actual Gate or L4 DROP on its canonical
worker. Every original gets its own typed Completion Frame, TUN obligation
settlement and physical free on origin W0. No TUN write or transport admission
is performed.

Normal Service Stop closes the network subscription before TUN drain. Both
generations settle all 23 originals with zero buffers/frames/obligations,
close TUN and leave no process/interface. Native fragment contexts and retained
references are zero.

## Real NFQUEUE originals and ordinary regressions

The same Linux artifact additionally proves actual NFQUEUE original verdicts:

| Run | Actual visible fragment entry | Originals |
| --- | --- | ---: |
| `nfq4`, generation 21210 | IPv4 OUTPUT | 65 |
| `nfq6/g0`, generation 22810 | IPv6 INPUT | 64 |
| `nfq6/g1`, generation 22811 | IPv6 OUTPUT | 66 |

These **195 real NFQUEUE originals** retain independent packet IDs,
queue/generation/lane identities and exactly-once verdict/free through success,
errors and cleanup. They are additional original-ownership evidence; the
controlled cross-fragment field-variation matrix remains labelled graph
injection. Pixel's previously established NFQUEUE pre-reassembly visibility
limit is not bypassed or relabelled.

Same-source ordinary regressions pass **70 Pixel Root originals /
50 endpoint cases** at generation 946, **64
Linux Root originals / 48 cases**, and **38 Pixel TUN originals /
24 target facts cases** at generations 944/945. The TUN facts run includes
missing/restored snapshots and real Wi-Fi loss/reconnect. All isolated Linux
resources are released; Pixel is stopped946 with Wi-Fi restored.

## Verification and evidence

Twelve controlled first-facts mutations and six real-TUN mutations are
rejected: first-arrival substitution, unknown merging, later-field overwrite,
lost ifindex/provenance, unchanged snapshot revision, wrong original identity,
missing success/completion/free, false source and wrong TUN obligation kind.
Native asynchronous ownership and exceptional packet contracts pass;
`git diff --check` passes.

The first Linux launcher attempt used a runtime basename outside the launcher's
allowed pattern. It failed before starting VPP and is retained as `linux-a`;
`linux-b` uses the accepted namespace-owned runtime name. No packet failure is
claimed for that tooling checkpoint. The initial verifier omitted the IPv6
L4 helper's rule-ID increment; the helper and actual verdict were correct, and
the verifier now checks the actual declared dual-family rule IDs.

`build-output/s219-first-facts/records.json` binds all eight accepted runs,
current-source manifests, exact evidence tools, test helper binaries and the
retained launcher checkpoint. SHA-256: `ed930802db2b0b4151a746acbf223fccad0f5755cb665ed14689b98e2393696a`.

This is first-facts and original-ownership acceptance. It does not implement a
new reassembly engine, general UID collection, Linux network event collection,
real Flow Stack return, VPN forwarding, performance or release readiness.
TUN zero endpoint-operation fields remain structural invariants backed by the
accepted source and actual path, not syscall tracing.
