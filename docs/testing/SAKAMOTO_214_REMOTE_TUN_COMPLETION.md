# SAKAMOTO-214 — Real TUN remote-owner DROP and origin completion

PASS, 2026-09-09.

The real TUN path now uses immutable AdapterObligation kind dispatch at the
shared origin-completion node. Root and TUN expose their native settlement
entry points; there is no mutable process-global external completion callback
or opaque callback owner. The obsolete synchronous external-result structure
and argument are removed. Ingress reports only native frame acceptance.

The implementation reuses S205's existing retained Primary Handoff and S204's
32-byte Completion Frame. It adds no owner algorithm, packet-byte copy,
transport queue, Owner Guard or corrective handoff. Root checks its native
obligation kind as well as generation, lane, token, packet and original buffer
before attempting its one verdict. TUN performs its existing immutable
identity checks before consuming its pending obligation.

## Accepted source and artifacts

Both final builds use source SHA-256 `ac949cbdeaf825ae184908b5f9c02f62c78f78a7051eb282f44944d67d9046fa`.
Build base: `1da916ba8bb2fec4b592ef1dbe8e9c6e61ae1a19`; dirty-diff SHA-256:
`4b94adf2bbc770bd65c6daac55a0567ad38c153965c501feae78f2525f49eba5`.
The manifests retain complete per-file source snapshots and pinned dependency
hashes. The later task commit preserves rather than rewrites build identities.

- Android: `build-output/s214-remote/pixel-build-a/build.json`.
- Linux: `build-output/s214-remote/linux-build-a/build.json`, artifact
  `build-output/product-vpp-host-s214-a`.
- Product identity: `sakamoto-product-vpp-s214-v1`.
- Generated API: unchanged `product_core.api/1.0.0@2e53fed5`.
- APK SHA-256: `51ac5a4b6f4c0d54b28bdd0f719010caaf59424916b2fed7de8003f80adf446c`.

| Android native file | SHA-256 |
| --- | --- |
| `libvpp_runtime.so` | `d201d23fdfe48068562b8d514c661870fe747913d0af130fa6d7e3f4226edc08` |
| `libproduct_core_plugin.so` | `76ea83ee8a239c99f95fcbf10c5c069c17ae1b8288f52645fa51f3a840aee00c` |
| `libsakamoto_product_core.so` | `51eae3f6ba2716b022d5b1833eec425ece2f062d285d7471c4d23e9878365bbd` |
| `libsakamoto_runtime_control.so` | `3c93ee6c3e6b3322f636b388a0ee93747b289cf1d91ac7fe05864512dca28d49` |

Installed APK/native bytes match the actual package. Product source was
compiled for Android and Linux with Host fixtures disabled. The old
Host-only Owner Guard is excluded from the Product graph; it was not copied
into the native path. No removed C++ or POC packet implementation was imported.

## Actual Pixel remote path

Pixel `28201JEGR0XPAJ`, application UID `12632`, kernel
`6.1.134-android14-11-g66e758f7d0c0-ab13748739` runs VPP as the app UID.
Accepted `pixel-a` generations **936 and 937** each contain 16 target real app
IPv4 UDP packets, eight Gate DROP and eight L4 DROP. There are **32 targets**
and **48 real TUN originals** including 16 separately accounted kernel IPv6
control packets.

The test oracle selects real socket source ports whose canonical owner is W1;
it does not inject a desired owner into Product. Raw TUN payload nonces bind
each app receipt to a single original packet. For every target the independent
verifier establishes this path:

| Stage | Native thread / worker | Evidence |
| --- | --- | --- |
| TUN materialization, parser, selector | thread 1 / W0 | Original byte equality, parse=1, assignment=1, independent canonical owner W1 |
| Primary publish and acceptance | thread 1 / W0 → thread 2 / W1 | One retained original buffer index; primary=1, corrective=0 |
| Primary dequeue, Gate/L4 policy, terminal | thread 2 / W1 | One dequeue, policy and terminal; actual DROP rule 21801 or 21802 |
| Completion Frame publish and return | thread 2 / W1 → thread 1 / W0 | One 32-byte frame, same obligation and buffer, one return acceptance |
| Adapter settlement and physical free | thread 1 / W0 | Original token/generation/lane consumed once, original buffer freed once |

Each target retains S218's actual event-derived VPN context, OUTPUT direction,
TUN_ORIGIN provenance and unknown packet Linux ifindex across the handoff.
UID is still explicitly CONTROLLED_TEST_PROVIDER for the scoped test app;
this is not general platform UID collection. Snapshot/provenance do not enter
the key or owner calculation. There is no second parser, selector or owner
assignment at policy or completion.

Both pre-stop settled snapshots show credit0=credit1=32, no handoff debt,
rejections, owner delivery failures, deferred returns, retries or pending
returns. The actual trace has no target Owner Guard or corrective path.
Target Policy DROP has NOT_ATTEMPTED transport outcome; native TUN writes,
NFQUEUE verdicts and Flow Stack admissions are absent on that path.

## Normal stop and regressions

The Android network subscription closes and publishes unknown before native
TUN drain. Both generations close the callback thread and settle all 24
originals with zero buffers/frames/obligations and tun_fd=-1 before process
cleanup. Original TUN interfaces and VPP processes are absent afterward.

Generation 936 captured one final kernel control packet after the pre-stop
status snapshot: that snapshot has 23 completed originals and the actual stop
record has 24. The verifier therefore checks the exact final conservation
against the native stop record, while treating the pre-stop status as a
bounded earlier observation. It still checks every original's completion and
free. This correction is also applied to the shared S218 verification tool;
no raw record or historical S218 source identity is changed.

Same-source regressions pass:

| Run | Platform / scope | Real originals | Target or endpoint cases |
| --- | --- | ---: | ---: |
| `local-network`, generations 938/939 | Pixel local TUN facts, missing/restored snapshot, Wi-Fi events | 38 | 24 |
| `root-pixel`, generation 940 | Pixel ordinary Root dual-stack TCP/UDP | 69 | 50 |
| `s214-l1`, generation 21710 | Linux ordinary Root dual-stack TCP/UDP | 64 | 48 |

Root regressions independently verify raw NFQUEUE attributes, canonical owner,
actual policy, original-lane verdict/free and cleanup through the new typed
dispatch. Linux's isolated namespace is released; Pixel Wi-Fi is restored.

The asynchronous external ownership contract replaces the stale synchronous
POC-oriented check. It validates acceptance-before-later-completion, fixed
native endpoint dispatch and physical free after adapter settlement. S210
retained-capacity source and packet-semantics contracts and S175 exceptional packet
semantics pass. Fifteen evidence mutations are rejected, including duplicate
Primary Handoff, missing dequeue, wrong return worker, lost credit, wrong
owner, missing physical free, wrong adapter identity and snapshot evidence.
`git diff --check` passes.

## Evidence and limits

`build-output/s214-remote/records.json` binds accepted raw records, build
manifests, exact collectors/verifiers and reused policy helper binaries.
SHA-256: `0d1c018dab4935ca5fc2a3c99cb7c13f42148e146ebab4297c9416d16a2d4ca4`.

Zero endpoint-operation fields are structural invariants backed by accepted
source and actual graph path, not syscall tracing. No HEV/lwIP, protected
Direct socket, POC sink, real Flow Stack return or TUN write is enabled.
Ordinary VPN START/Resume remain unavailable. This is remote DROP ownership
acceptance, not transport, startup robustness, performance or release readiness.
