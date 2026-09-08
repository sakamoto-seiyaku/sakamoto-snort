# Product evidence chain (S244)

This validator accepts only the implemented Root / IPv4 UDP / single-lane owner-local scope. It distinguishes real `NFQ_CAPTURED` from `GRAPH_INJECTED` and Host evidence; neither of the latter can satisfy the wire claim. It does not certify VPN or HEV/lwIP.

The builder records the current product source set (including untracked source and deleted-file markers), commit, dirty diff, an immutable source snapshot, before/after source equality, clean VPP stage identity, build logs and APK/native hashes. A request created after the build fixes the expected run, device, origin and scope. Verification compares the installed APK and all native entries, running artifact/revision, fresh per-case nonces, generation/packet IDs, exact actual VLIB node counters and order, policy/verdict/endpoint outcomes, native buffer conservation and clean stop/restart. Missing or contradictory facts are HOLD.

```sh
rtk proxy python tests/evidence/product_chain.py build build-output/NEW/build
rtk proxy python tests/evidence/product_chain.py request --build build-output/NEW/build/build.json --run-dir build-output/NEW/pixel --output build-output/NEW/request.json
rtk proxy python tests/device/s203-root-graph.py --apk build-output/NEW/build/apk/sakamoto-runtime-debug.apk --output build-output/NEW/pixel
rtk proxy python tests/evidence/product_chain.py verify build-output/NEW/request.json --output build-output/NEW/verification.json
```

The current builder uses the manifest-validated clean product VPP stage and pinned source paths recorded in `product_chain.py`. It never selects an experiment stage. Build outputs/run directories must be new. Device operations use repo `./dev/adb` and the fixed Pixel serial.

`test_product_chain_negatives.py REQUEST --output NEW_DIRECTORY` preserves the positive run and makes separately labelled local corruptions. Its old-run case uses a preceding same-APK run named `pixel` next to the accepted `pixel-b`; the other cases clone the accepted run. It asserts the expected semantic rejection, not merely a nonzero exit.

A PASS is source-scoped. After product source changes, the old request must fail the current-source check; build a new witness and run. Historical acceptance is preserved in its report/snapshot, not promoted automatically to a new head. Future protocol, metadata-injection, completion or HEV/lwIP slices must extend the relevant semantic verifier and explicitly label their own input source. The existing checker must not be loosened to accept a broader claim.
