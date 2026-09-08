# S203 real Root owner-local graph acceptance

2026-09-08, real Pixel 6a `28201JEGR0XPAJ`: **PASS**, five real NFQUEUE-captured IPv4 UDP datagrams across generations 636 and 637. Evidence: `build-output/s203-graph/pixel-matrix-d/verification.json` and its raw per-case records.

## Product change

NFQUEUE owns one lane/queue 176 on actual VPP worker 0 (thread index 1). Its nonblocking receive callback has a 64-message budget and hands its existing native buffer to `vlib_put_frame_to_node`; acceptance now transfers ownership for later processing. The ordinary VLIB admit node runs the existing shared parser/canonical selector once, then owner-local Gate/L4 policy and terminal nodes. Terminal performs the existing local Adapter callback and native free. No synchronous graph helper, fake arrival, Owner Guard or corrective handoff executes in this path.

The production startup scope is explicitly `root-nfqueue-udp4-owner-local`, with only this debug APK UID's IPv4 UDP OUTPUT traffic captured. Remote-owner and unsupported packets terminate as runtime drops; remote handoff and full Root forwarding are not advertised. The preliminary FlowEntry observation path is disabled for product traffic pending its own implementation slice. Completion Frames, typed metadata expansion, typed-key consolidation and remote closure remain separate tasks.

The VPP worker's epoll setup completes after its initial worker barrier. Registering its NFQUEUE listener too early attached the fd to an inherited main-thread epoll instance. The new bounded main-process startup waits for worker-init readiness flags, then registers the listener under the normal VPP worker barrier. The worker-init callback publishes readiness only and never waits for NFQUEUE configuration or socket I/O. This was confirmed by a rejected diagnostic trace (`polling_thread=1`, actual thread/TLS=0) and then actual thread/TLS=1 with the full node path.

## Device matrix

A separate, bounded shell-UID UDP endpoint binds `127.0.0.1:40403` on the Pixel. The Product app sends real UDP through Linux OUTPUT/NFQUEUE. This is actual platform I/O with a controlled loopback endpoint, not graph injection or a claim about LAN/underlay forwarding. A Host helper selects source ports for the existing canonical hash; actual device admit independently confirms the selected owner.

| Case | Source port / owner | Real VLIB path | Outcome |
| --- | --- | --- | --- |
| Allow, generation 636 | 30001 / 0 | admit → policy → terminal | exact endpoint echo, NF_ACCEPT |
| Explicit Gate DROP | 30001 / 0 | admit → policy → terminal | Gate stage DROP with nonzero rule; NF_DROP, no endpoint receipt |
| Gate reopened | 30001 / 0 | admit → policy → terminal | exact echo, NF_ACCEPT |
| Remote not open | 30000 / 1 | admit → terminal on origin worker | runtime rejection, NF_DROP; no handoff/policy on remote owner |
| Restart, generation 637 | 30001 / 0 | admit → policy → terminal | exact echo, fresh generation |

Each packet has one capture, native frame acceptance, parse/assignment, terminal intent, origin-lane verdict and native free, with unchanged buffer/obligation identity. Local policy runs on thread 1. Actual VPP `show runtime` counters contain admit/policy/terminal on `vpp_wk_0`, and no Owner Guard node activity; `show threads` records actual LWPs/core placement. Each free reports buffer/obligation debt zero. First-generation totals are 4 verdicts/settlements/returns, restart totals 1/1/1; fail-open, duplicate, stale, remote completion and verdict-failure counters are zero. Both stops have clean hook/queue and process residue.

## Artifact and reproducibility

Final Product APK SHA256 `73091c6d43d7f16e5be79b35a1b2182bf4d870ef2b8afba68d0fcdb56d1ee1c9`, plugin SHA256 `115b70395a8b59a324673b866fabccceb27fed695ed3ca16663b2eb8134231f9`. All 12 installed native files match the APK. Artifact ID `sakamoto-product-vpp-s203-v1`, pinned VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, API `product_core.api/1.0.0@aa3af3cd`. Product stage is `build-output/android-product-stage-s203-d`, APK `build-output/s203-graph/apk-d/sakamoto-runtime-debug.apk`. Clean manifest-validated VPP base DSOs are reused; the Product plugin/core/APK were freshly built.

Source commit, dirty diff, complete product-source snapshot and file hashes: `build-output/s203-graph/source-d/`. Source-tree SHA256 `be54f68f03721ce8670185b1470352bbf2b8305e522e7f77f4142aa6055388c1`. The current product sources were cross-checked against that snapshot after the successful matrix. Run `tests/device/s203-root-graph.py --apk APK --output NEW_DIRECTORY`, then `tests/device/verify-s203-root-graph.py DIRECTORY`. The helper endpoint is `tests/device/helpers/product-udp-echo.c`; the Host port-selection helper is auxiliary only.

Fresh native/APK builds, the Android runtime contract suite and S174/S175 pure C semantic tests passed. Old Host guard fixtures retain their historical contract and are not product W2 evidence.

## Retained failures / limitations

Earlier directories are preserved: bootstrap listener ordering failure; an accidental VPN-bind setting in the Root probe; echo success through the legacy submit-fail-open path (not a graph PASS); CLI telnet-byte decoding failure followed by explicit safe stop; and stale diagnostic policy-stage/status polling. The runner now uses ordinary persisted Gate open/block/open transitions and fresh generated-VAPI queries, and always attempts bounded cleanup after collection errors. Only `pixel-matrix-d` is the full accepted matrix.

No VPN, TCP, IPv6, fragmentation/reassembly, production FlowEntry, Completion Frame, remote-owner forwarding, capacity, performance or release closure is claimed. S200's POC separation remains in force.
