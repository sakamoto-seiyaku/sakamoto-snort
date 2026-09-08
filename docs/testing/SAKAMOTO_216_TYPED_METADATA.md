# SAKAMOTO-216 — typed ordinary-graph metadata

Acceptance: **PASS**, 2026-09-08, final artifact run generation 645. Scope: Android Pixel Root,
IPv4 UDP, one NFQUEUE lane, ExecutionOwner equal to arrival worker. TCP/ICMP,
IPv6 and unavailable-L4 coverage below uses explicitly labeled `GRAPH_INJECTED`
packets on the same native VPP worker. It is not NFQUEUE wire or VPN evidence.

## Semantic inventory

`product_packet.h` separates `product_packet_facts_t`,
`product_platform_packet_facts_t` and `product_adapter_obligation_t`.
`product_owner_assignment_t` in the graph owns the 64-bit generation,
ExecutionOwner and bounded primary/corrective handoff counts. Packet lifecycle
bits and runtime drop reason are outside OwnerAssignment. The ordinary lease
is a by-value semantic projection; these types do not allocate dynamic objects.

| Facts / identity | Representation and availability | Consumer |
| --- | --- | --- |
| L3 status, L4 status, IP family, terminal protocol | Independent compact enums; admitted never reconstructs L4 COMPLETE | Parser, policy, terminal |
| IPv4 / IPv6 source and destination | Validated immutable buffer span; IPv4 offsets 12/16, IPv6 offsets 8/24; normalized 16-byte addresses reconstructed by fixed-width copies | Canonical key projection, policy |
| TCP/UDP ports | Two uint16 values, available only for COMPLETE TCP/UDP | Owner key, port predicates |
| L3 and L4 header lengths | Two uint8 values; current IPv4 header <=60, basic IPv6 header 40, TCP <=60 | Validated addressing, tracker seam |
| Packet length | uint32 validated L3 packet length, independent of retained span length | Policy / terminal facts |
| Transport offset, transport length, payload offset/length | Derived from validated L3 length, packet length and L4 length; unavailable L4 cannot yield a complete payload view | Future tracker seam |
| TCP sequence, acknowledgment, window, flags | uint32/uint32/uint16/uint8, available only with COMPLETE TCP | Future tracker; no tracker implemented here |
| TCP window scale | Option list validated once; effective scale capped at 14, 255 compact sentinel for option unavailable; semantic projection has explicit `tcp_window_scale_known` | Future tracker, not a negotiated connection value |
| ICMP type/code | Header length 8 and ICMP/ICMPv6 protocol establish header availability | Non-flow terminal identity |
| ICMP Echo identifier/sequence | uint16 pair plus explicit known bit; only valid echo request/reply with code 0 | Future ICMP identity consumers |
| UID / Linux ifindex / NetworkContextId | Three uint32 values and independent availability bits; zero remains representable as known | Policy |
| Device Packet Direction / provenance | Separate typed compact enums; UNKNOWN is explicit | Policy / adapter provenance |
| Owner key and ordering | Canonical endpoint ordering bit plus facts; reconstruct key without another parse, comparison or hash. Existing owner-selection algorithm is unchanged | Assigned owner; S207 owns later key work |
| Adapter obligation | Opaque token, 64-bit queue generation, packet ID, origin lane, completion kind | Adapter completion only |

IPv6 extension traversal, fragments/reassembly, FlowEntry production admission,
TCP state tracking and VPN return transport are not implemented by this task.
S219 owns fragment save/restore. Unknown or invalid L4 remains separately
representable while valid L3/address facts survive.

## Physical layout and lifetime audit

No `vlib_buffer_t` expansion, opaque3, exdata, per-packet heap or general side
table was added. Pinned native capacities are **opaque 40 + opaque2 56 = 96 bytes**.
This replaces the earlier `unused[6]` restriction. Accessors use `memcpy`, so
8-byte C type alignment is not imposed on a potentially less aligned member.

| Region | Offset | Bytes | Contents |
| --- | ---: | ---: | --- |
| opaque | 0 | 24 | AdapterObligation: token at 0, queue generation at 8, packet ID at 16, origin lane at 20, kind at 22, reserved at 23 |
| opaque | 24 | 16 | Platform facts: UID/ifindex/context at relative 0/4/8; availability/direction/provenance/reserved at 12/13/14/15 |
| opaque2 | 0 | 16 | OwnerAssignment: generation at 0, owner at 8, primary/corrective count at 10/11, four alignment bytes |
| opaque2 | 16 | 8 | Opaque obligation token copied through lease transitions; never part of a matcher or owner key |
| opaque2 | 24 | 12 | TCP or ICMP tagged transport detail; protocol selects interpretation |
| opaque2 | 36 | 4 | Validated packet length |
| opaque2 | 40 | 4 | Source/destination ports |
| opaque2 | 44 | 4 | Retained current_length / current_data |
| opaque2 | 48 | 6 | L3 length, L4 length, family, protocol, independent L3 and L4 statuses |
| opaque2 | 54 | 2 | Packet lifecycle bits and drop reason |

Compile-time guards cover capacities, sizes, alignment and significant field
offsets. `product metadata check` on Pixel reports the compiled layout, checks
semantic roundtrip, rejects changed current_data/current_length, and rejects a
platform generation differing only above bit 32. Its temporary native buffer is
returned before the command completes.

The ownership interval starts after the Root adapter has selected the NFQA
payload span and initialized both overlays. It ends at native terminal completion
and buffer free. Product admit, policy and terminal use only these accessors;
VLIB frame scheduling carries buffer indices. The retained enqueue core patch
copies indices into frame queues and does not access packet overlays. Fixed
address copies occur only after equality with the saved span and bounds checks;
no downstream code traverses headers, compares endpoints again or hashes again.
No pointer escapes the retained buffer lifetime.

`vnet_buffer_opaque_t` IP/reassembly, feature, routing, adjacency and other VNET
overlays conflict with this ownership. They are not wired into the current
ordinary product path. The historical Host-only fragment route remains outside
this claim; its reassembly overlay cannot carry these facts without S219's
explicit transition. The real Root path keeps fragments/unsupported protocols
closed. The test-only injection FQM targets admit, adds a bounded obligation,
and never sends an NFQUEUE verdict.

## Platform normalization

LOCAL_OUT uses only NFQA_IFINDEX_OUTDEV; LOCAL_IN uses only NFQA_IFINDEX_INDEV.
Attribute absence keeps availability clear. UID evidence is NFQA_UID or the
existing exact OUTPUT uid-owner hook constraint. Queue/lane never becomes Linux
ifindex. No reliable per-interface network snapshot currently exists in this
adapter, so NetworkContext remains unknown instead of hardcoded Wi-Fi.

The Pixel loopback wire case has UID known and Linux ifindex 1 known, with
NetworkContext unknown. Installing a Wi-Fi-only Gate rule does not drop that
packet. Other evaluable policy stages continue. Injected cases alternate all
three availability bits while preserving numeric UID/ifindex/context zero.

## Acceptance matrix and evidence

The runner `tests/device/s216-metadata.py` installs and hashes the APK and every
native library, sends three actual app UDP requests to the controlled loopback
shell-UID echo endpoint, runs the compiled metadata guards, injects twelve
explicit fixture packets, and stops/collects residue. The independent Python
wire oracle is `tests/device/verify-s216-metadata.py`.

Injected cases: IPv4/IPv6 TCP with window-scale option; IPv4/IPv6 ICMP Echo;
IPv4/IPv6 truncated TCP; invalid UDP length; IPv6 No Next Header; IPv4 options
plus TCP; malformed TCP option; ICMPv4 error; unavailable ICMPv6 header.
Each case has an actual parser/selector assignment to owner 0 and runs native
admit -> policy -> terminal on VPP thread 1. The injection seam does not bypass
metadata serialization or restore and does not claim wire capture.

The checker requires fifteen calls/vectors in each real node on thread 1,
per-field agreement with raw packet bytes at all three stages, one buffer return
per obligation, exactly three real NFQUEUE verdicts, endpoint nonce delivery,
full source/APK/native closure and final zero graph debt. Only the real UDP
packets count toward NFQUEUE acceptance. Completion Frame is still S204 work.

Earlier evidence retained: `pixel-b` failed startup before acceptance traffic;
`pixel-c` completed two real UDP cases but the harness's CLI newline quoting
failed; both cleaned up. A diagnostic format bug was fixed before the C build.
`pixel-c2` passed the full matrix on generation 644. Final acceptance uses a
fresh run after the final layout and source snapshot; see the final identity
record below.

## Final identity record

- Build/source witness: `build-output/s216-metadata/build-e/build.json`; source
  snapshot and dirty diff are retained beside it.
- Request: `build-output/s216-metadata/request-e.json`, created after the build
  and before all accepted packet nonces.
- Accepted run: `build-output/s216-metadata/pixel-e`; verifier report
  `verification.json` is PASS with no errors, generation 645.
- Commit: `9c67175713baceb46cef015f3464893fa3d69950` plus recorded dirty source.
- Source closure SHA-256: `28f80eed7a705780934d8ca5da45e261e6594042a687bd3f19774e3ea74228ec`.
- APK SHA-256: `f2be514fe242e098b835910dfc8d962d0115d3d6dacc8720d4587c4abd8a87ee`.
- Product plugin SHA-256: `de1a965adb13da8053ec89bfd4eae91b368f32363a55cf31a02bd8c7fbd15694`.
- All twelve native library hashes and installed base.apk hash are checked;
  device/kernel, node/thread and cleanup records remain in the accepted run.
- Semantic evidence mutations in `build-output/s216-metadata/negative-e` reject
  L4 promotion, lost availability, and injection relabeled as NFQ wire.
- Supporting checks: S174/S175 pure C semantic tests, S192 graph source contract,
  native Android/APK build, and Host-evidence plugin compilation all passed.
  S192 Host runtime execution was not run; the Pixel matrix supplies this task's
  runtime acceptance. Native builds have no new C warnings.

The complete acceptance report is also recorded in the private Plane instance.
