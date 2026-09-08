# S200 Product / POC identity isolation

2026-09-08, Pixel 6a `28201JEGR0XPAJ`, Android 16 / kernel 6.1.134: **PASS for S200 isolation and Root start/stop**. This is not VPN transport or Root packet-graph acceptance.

The handcrafted bridge source/header is preserved under `experiments/handcrafted-direct-bridge/source`, with original hashes and explicit `poc-handcrafted-direct-bridge` identity. It is absent from product CMake and Product Core startup/status calls. The retained ABI counters are zero; no facade, HEV child or fd fallback was introduced. Historical S180–S185 test entry points reject product execution and retain their original recipes in the isolated POC directory. The S195 dossier/release gate and related Plane cards now declare the narrow historical scope, including S192 VPN cells.

Ordinary Android VPN startup checks its unavailable Adapter contract before establishing TUN, protected sockets or a VPP child. It publishes `vpn_flow_stack_not_ready` against the requested VPN profile. Automatic service teardown preserves the failure projection; an explicit stop can clear it. Root remains on the existing NFQUEUE Adapter.

## Device evidence

`build-output/s200-isolation/pixel-20260908-0004/` contains the successful run:

- Installed APK SHA256 `036fb9f05afd32c735e32662872b6e8c2d1718427e9bd2663f9aa325bace11a8`.
- Product plugin SHA256 `bde34249ab406e4b117229c60276eec227c6f859f3da16bda2e663a12ffa3b8c`; pinned VPP executable SHA256 `c196564c9ee80833134a742802155d90fcaeafe321237496fb816c56c2bf961c`.
- All 12 installed native files match the actual APK entries. Product artifact ID `sakamoto-product-vpp-s200-v1`; VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0`; generated API identity unchanged (`product_core.api/1.0.0@aa3af3cd`). The fresh plugin has no bridge control commands, implementation symbol or false HEV/lwIP readiness string.
- VPN: profile=vpn, error=`vpn_flow_stack_not_ready`, adapterReadiness=unavailable, protectionRunning=false, mayBeActive=false, pid=-1; no VPP process in the device process listing.
- Root: generation 627, `root-nfqueue`, health=ok, protectionRunning=true; existing two lanes/queues 176–177 ready. This idle lifecycle baseline has zero packet verdicts/settlements/buffer returns and does not claim node execution or packet delivery. S203 provides the actual graph packet proof.
- Stop: state=stopped, mayBeActive=false, empty error; `productRootNfqueueResidueClean=true`; no VPP process. KernelSU grant remained valid.

Source commit/dirty diff and exact product-source snapshot: `build-output/s200-isolation/source/`; source-tree SHA256 `4a5fc8087bd18ace9b8433dd456515934d1190426971f7c271ed21b3427daf12`. Fresh plugin/core stage: `build-output/android-product-stage-s200`; corrected APK: `build-output/s200-isolation/apk-corrected`. The pinned runtime DSOs/executable are the manifest-validated clean product VPP stage, not experiment binaries.

## Retained failed attempts and verification

The initial APK rejected VPN but incorrectly attributed the error to the previous Root profile, then erased the error during automatic teardown. `pixel-20260908-0000` remains HOLD. The corrected APK uses the requested profile and preserves errors through automatic cleanup. `pixel-20260908-0003` remains a harness HOLD: Android dumpsys had no nativeLibraryDir field; the runner now derives the verified arm64 native path from codePath. The successful repeat used the same corrected APK.

`tests/device/s200-vpn-poc-isolation.py` provides bounded startup/stop and installed-payload verification. The current Android runtime contract suite passed after the correction. Native Product Core and APK builds passed; product source has no reference to the removed bridge. Source/byte scans only corroborate the real device result and do not substitute for it.
