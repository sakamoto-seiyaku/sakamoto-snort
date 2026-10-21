# SAKAMOTO-300: VPN arbitrary owners and shared owner CPU

2026-10-22. This is functional Product evidence for [SAKAMOTO-300](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/f6b4ddc0-adff-4da6-a0a8-7ba0e374c6c5) under [ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md). It does not establish a VPN performance adoption decision or general release readiness.

## Artifact and source identity

| Artifact | SHA-256 |
| --- | --- |
| `build-output/s300-apk-g/sakamoto-runtime-debug.apk` (final build) | `cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110` |
| `build-output/s300-apk-e/sakamoto-runtime-debug.apk` (all-owner status matrix) | `e20b6e70678aa75ab13ee0675aa1da78597ca8e09a03d2a1f0430e3b4f45df5e` |
| `build-output/s300-apk-b/sakamoto-runtime-debug.apk` (earlier packet matrix) | `24a70e6f35563984552793735de6694adf422c3013b831f5853c404f30856d99` |
| `build-output/android-product-stage-s300-c/lib/arm64-v8a/libproduct_core_plugin.so` | `acb4fe225bbfa7398906694619c06dc4ed5e583f0f53b0dcd2023546f6eb8267` |
| `build-output/android-product-stage-s300-c/lib/arm64-v8a/libsakamoto_runtime_control.so` | `9fbf6389b9f9da8646f694a7ff16c406e92f9aff871c856d8d07834be0b28c9c` |
| `build-output/product-vpp-host-s300-a/lib/vpp_plugins/product_core_plugin.so` | `4ba1522cd9ef8b3d5aff6acd1a510b3b134c71ec5313b17c68afc990478b24d4` |

The final Product source digest from `tests/evidence/product_chain.py` is `197b428c2e78724a9f489721d2448cb82ba451845073e2a84ad8efa76458c988`. Every listed Android APK has the same native Product packet plugin bytes; APK `b` predates the all-owner Android status bridge, and `e` predates the zero-owner failure-status parser correction. `build-output/s300-host-artifact-identity.json` records the exact Host VPP, Product Core and plugin bytes. Each Pixel run retains installed APK/native hashes, its test/verifier source hashes, `/proc` affinity, packet traces or ordinary status, and stop state.

## Product runtime evidence

`/tmp/s300-vpn-topology-n4/` contains Host Product VPP startups for VPN `N=1`, `N=2`, `N=3` and `N=4`. N=3 uses ordered owner CPUs `1,2,1`; N=4 uses `1,2,1,2`, both with a distinct I/O CPU. The N=3 case reports four separate VPP worker threads plus main, correct roles and actual affinity, and a successful TUN stop. Missing I/O CPU is rejected before capture.

| Pixel run | Generation | Verified path |
| --- | ---: | --- |
| `build-output/s300-pixel-n3-final-apk/` | 2290 | Exact final APK: controlled owner-2 UDP original/return chain, full S187 owner status, FlowEnd and clean stop. |
| `build-output/s300-pixel-n3-status-green/` | 2285 | APK `e`: controlled owner-2 UDP return plus S187 VPN status with owner thread indexes `1,2,3`, actual cores `1,2,1`, matching configuration and clean stop. |
| `build-output/s300-pixel-n1-status-green/` and `s300-pixel-n2-status-green/` | 2286, 2287 | APK `e`: exact VPN original/return path, full owner status, FlowEnd and clean stop for N=1/N=2. |
| `build-output/s300-pixel-n3-ordinary-status/` | 2288 | APK `e`: ordinary Product owner-1 echo, full owner status, natural expiry/FlowEnd and clean stop. |
| `build-output/s300-pixel-n3-owner2-final/` | 2276 | Controlled Product: three UDP echoes on owner 2, 1,500 invalid TUN ingress packets overlapping successful return writes, explicit FlowEnd, zero native stop debt. |
| `build-output/s300-pixel-n3-owner0/` | 2277 | Controlled Product: three UDP echoes on owner 0, explicit FlowEnd, zero native stop debt. |
| `build-output/s300-pixel-n3-owner1-controlled/` | 2279 | Controlled Product: three UDP echoes on owner 1, explicit FlowEnd, zero native stop debt. |
| `build-output/s300-pixel-n3-owner1-ordinary/` | 2278 | Ordinary Product: three UDP echoes, natural expiry and FlowEnd, clean stop. |
| `build-output/s300-pixel-n3-owner2-expiry/` | 2282 | Ordinary Product: three UDP echoes, natural expiry and FlowEnd, clean stop. |
| `build-output/s300-pixel-n3-owner0-expiry/` | 2283 | Ordinary Product: three UDP echoes, natural expiry and FlowEnd, clean stop. |
| `build-output/s300-pixel-n1-regression/` and `s300-pixel-n2-regression/` | 2280, 2281 | Same new APK: exact original/return buffer index and bytes, explicit FlowEnd and clean stop. |

The independent `tests/evidence/verify_s298_vpn_return.py` passes every listed run. In each controlled N=3 case it checks the canonical owner, one original-index handoff from the I/O worker, per-owner policy and Flow Stack, full return token owner identity, the original live return buffer index, byte-equal echo, a single TUN write attempt, credit release and zero debt. Kernel `/proc` affinity records main/owner0/owner1/owner2/I/O on CPUs `0/1/2/1/3`. `show product observation` exposes channels `0..5` and `show product tun` reports all three return-credit owners. Final APK runs additionally assert the Android S187 status file belongs to the current VPN generation and lists every owner core/thread. Ordinary runs verify external echo, per-owner FlowEntry query and natural FlowEnd release, completion counters and stopped state. Four independent corruptions of the owner-2 controlled witness were rejected by `tests/evidence/test_s298_vpn_return_negatives.py`.

The same Host artifact produced `RAW_COMPLETE` in `build-output/s300-root-n1/`, `s300-root-n2/` and `s300-root-n3/` using the isolated real NFQUEUE runner. Root N=3 retains repeated owner CPU binding and independent lane count.

## Build and test checks

`build-output/s300-host-repeat.log` and `s300-stage-status-repeat.log` show unchanged second builds with no Ninja compile action; the repeated Host plugin and all 12 final Android native libraries match byte for byte. `build-output/s300-apk-final-repeat.log` reports Java/DEX reuse; the two final APKs have different version codes, while all 13 DEX and arm64 native members compared are byte-identical. `tests/android/android-runtime-contract-test.sh`, the S187 contract, the Host topology unit test and the VPN return verifier pass. The Android contract also covers the full 148-field zero-owner failure status so it retains its error and generation. Full Host CTest in `build-output/s300-ctest-final.log` passed 63/67. Three failures are the same stale source-token contracts recorded in S299; the fourth is Unix socket access denied by the sandbox and passes 1/1 with access in `build-output/s300-core-profile-escalated.log`. An initial 62/67 run in `s300-ctest.log` exposed an S300 external-batch test fixture missing the new runtime owner-count field; that fixture was corrected and the test passes.

## Retained failed attempts and scope

`build-output/s300-pixel-n3-owner2/` records the first failed N=3 Android startup: the socket broker still had a fixed-two owner guard, corrected in this ticket. `s300-pixel-n3-owner2-b/` records a genuine L4 DROP from the preexisting saved Product rule for source port 42006; the rule was preserved and later tests used an unblocked test port. `s300-pixel-n3-owner2-c/` records a route failure when the Pixel was temporarily on `192.168.1.0/24` and the Host endpoint was on `192.168.4.0/24`. `s300-pixel-n3-owner2-local-a/` records an on-device echo that bypassed TUN and is explicitly excluded from Product acceptance. `s300-pixel-n3-status-final/` records an S187 status check that found a stale Root generation: the VPN startup path skipped the status writer, corrected before the final APK. `s300-pixel-n3-committed-final/` records a transient WSL ADB vsock timeout in the diagnostic flood helper, not a Product fault; the exact final APK then passed the independent packet verifier in `s300-pixel-n3-final-apk/`. The Pixel was switched to its saved `Openwrt_5G` test LAN for the qualifying remote endpoint runs, then restored to its original `CU_7WFb_5G` network.

The broader parent PRD fault matrix (short writes, `EAGAIN`, handoff/completion congestion, buffer exhaustion and fragments) is outside this ticket's evidence and remains for later qualification. No throughput, latency, CPU or power adoption threshold is inferred.
