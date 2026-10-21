# SAKAMOTO-301: bounded startup and TUN queue faults

2026-10-22. This record covers [SAKAMOTO-301](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/83dd995e-06f2-41a2-8f6e-7b8266f28168) under [ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md). It is Product functional and fault evidence, not a release or performance adoption result.

## Artifacts and test scope

| Artifact | SHA-256 |
| --- | --- |
| Final Android APK `build-output/s301-apk-final4/sakamoto-runtime-debug.apk` | `bb0e4fc41c53149a7ee62cf9f2259cd72175275c25192123dd8aaa4d63711159` |
| Android Product plugin in `build-output/android-product-stage-s301-final4/` | `76ea30156d220b7062e30fa08c49d3390ecf3ed87b388a4f13d9e33579b2479a` |
| Host Product plugin in `build-output/product-vpp-host-s301-final4/` | `20275211e8e855be1f26cbd2e6ad4e2d87c72bb1d0948d10da6e8aca22fe32aa` |
| Android raw TUN injector `build-output/s301-tun-packets` | `9f6247d11772f85ce17dabbf67e31fa17501565cea1ee4db6cd278af96b72b26` |

`build-output/s301-final4-host-identity.json` binds the Host VPP/Core/plugin bytes and Product source digest `d611568e0736a6daead22600d422e441acce7c6b2433751b2f80f43b97b79dd3`. The two final Pixel results bind the installed APK and all installed native library bytes to the APK. The Product CLI trace is deliberately disabled for ordinary VPN mode; the validation mode supplies exact packet index witnesses using the same native TUN reader, graph, handoff and completion implementation.

## Configuration and partial startup

The actual Host VPP startup matrix in `/tmp/s301-startup-faults-final4/result.json` covers Root and VPN offline/absent CPUs, inherited affinity exclusion, ordered binding count mismatch, pinned VPP thread limit, and checked `owner_count × flow_capacity` overflow. VPN additionally rejects TUN I/O CPU collision with a FlowOwner. For both profiles, a controlled failure after allocation of owner 1 leaves all owner flow pools null, capture unopened and graph debts zero. The matrix uses the gated `SAKAMOTO_PRODUCT_HOST_STARTUP_FAULTS=1` fault only for the partial allocation rollback case. Host VPN `N=1/2/3/4` topology, duplicate owner CPU placement and explicit I/O worker startup pass in `/tmp/s301-vpn-topology-final4/`.

The exact Host artifact also passed isolated real NFQUEUE Root `N=1` and `N=3` packet regressions in `build-output/s301-final4-root-n1/` and `build-output/s301-final4-root-n3/`. The N=3 run observed all three canonical owners, 87 exact packet tokens, policy allow/drop/recover, IPv6 bidirectional ownership and clean process exit.

## Real Pixel TUN fault and settlement

The ordinary Product VPN run `build-output/s301-pixel-product-mode-final4/` used generation 2302 with `protectionRunning=true` and an installed APK/native hash match. A one-shot `capture-alloc` fault occurred **before** a TUN `read`, paused and resumed the fd subscription once, and subsequently settled an invalid IPv4 packet as an origin-lane runtime fault. Setting primary handoff credits to zero rejected the selected owner without a reroute; restoring credits resumed remote owner progress. With two completion ring slots, a 64-packet real TUN burst produced 17 bounded completion deferrals and 18 retry attempts. Two real IPv4 fragments were reassembled and their origin obligations settled. The final status has zero pending frames, native buffers, obligations, handoff debt and return debt. The independent verifier reports `PASS` from status and installed artifact evidence.

The controlled graph validation run `build-output/s301-pixel-validation-final4/` used the **same APK** in generation 2303. Its [independent verifier](../../tests/evidence/verify_s301_tun_faults.py) matched 69 scoped capture tokens to exactly one completion and native free each, preserving the original buffer index and generation. The injected allocation failure produced one pause/resume without a scratch read; the malformed packet stayed on the I/O worker without owner policy. A valid packet rejected at primary handoff retained its selected owner and original index. After recovery the original index reached that owner. Two-slot completion congestion produced 13 index-only deferrals and 26 retries with no residual debt. The two fragments had offsets 0/MF and 16/final, one reassembled survivor, final canonical owner and two distinct original index returns. This controlled mode proves packet identity; ordinary Product mode independently proves the same fault classes run through the active VPN supervision path.

Both Pixel runs stopped cleanly, removed the VPP process and restored the pretest S300 APK hash `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`, saved Wi-Fi SSID and route. Earlier failed attempts and narrower interim runs are retained under `build-output/s301-pixel-tun-faults-*/` and `build-output/s301-pixel-product-mode-*/`; they do not replace the two final runs.

## Build and test checks

`build-output/s301-final4-cache-reuse.json` records zero Rust/C compilation and Ninja compile actions on unchanged second Host and Android stage builds, unchanged compiled object hashes/timestamps, and byte-identical native plugins. Android runtime contract tests pass. Full Host CTest is 63/67 in `build-output/s301-final4-ctest.log`: three pre-existing source-token contract tests (#28, #31, #51) still expect removed inlined code, and #64 cannot open its required Unix socket inside the sandbox. #64 passes 1/1 with socket access in `build-output/s301-core-profile-escalated.log`. These are the same four limits recorded for S300; no S301 behavior test failed.

The one-shot pre-read allocation fault exercises the same failure branch as real `vlib_buffer_alloc` exhaustion, without reserving the whole VPP pool or creating scratch packet storage. It does not measure the maximum sustained pressure at which the physical pool empties. Short TUN writes and `EAGAIN` remain immediate failed attempts under the existing write contract; this campaign does not claim a new device-level short-write or `EAGAIN` occurrence.
