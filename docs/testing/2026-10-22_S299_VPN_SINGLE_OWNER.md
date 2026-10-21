# SAKAMOTO-299: Product VPN with one FlowOwner

2026-10-22. This is functional evidence for the VPN `N=1` slice of
accepted ADR-0012 and the [SAKAMOTO-293 PRD](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/727dbca5-9a92-46c1-89b5-a068eb51022d).
The APK was built from this worktree with the Product Android builder. It is
not a performance or general VPN release qualification.

## Artifacts and runs

| Artifact | SHA-256 |
| --- | --- |
| `build-output/s299-apk-c/sakamoto-runtime-debug.apk` | `8efbadbf407d9a37b7d8fab9ca39c8ae8dbf9825bbc4d859efa8ff47025c0273` |
| `build-output/android-product-stage-s299-b/lib/arm64-v8a/libproduct_core_plugin.so` | `97e4f4ed8f4f1975d25f8e0fc40797f9903ce7d495b4987de9f77b61fb0c0bd3` |
| `build-output/product-vpp-host-s299-a/lib/vpp_plugins/product_core_plugin.so` | `e237679e300ee1f0243ff00319363951f072f5b46c32b49c044247269f745330` |

The Pixel run directories each retain `result.json`, installed native hashes,
the test source and verifier hashes, VPP status, packet or app results, and
stop evidence. The independent verifier is
[`verify_s298_vpn_return.py`](../../tests/evidence/verify_s298_vpn_return.py),
extended to accept one or two owners and read kernel affinity for `N=1`.

| Pixel run | Generation | Observation |
| --- | ---: | --- |
| `build-output/s299-pixel-n1-final/` | 2265 | Controlled Product trace: three byte-equal UDP echoes on owner 0; TUN ingress directly in the I/O worker, one original buffer-index handoff, original index returned to I/O, and each return's same live buffer index sent to I/O for one write and one free. During 1,500 invalid ingress packets, valid return writes progressed. Explicit FlowEnd released its FlowEntry. |
| `build-output/s299-pixel-n1-ordinary-sealed/` | 2267 | Ordinary Product mode: three byte-equal UDP echoes, natural UDP FlowEntry expiry after the 30-second bidirectional timeout, FlowEnd release, and clean stop. `observation-extra.txt` records two channels for owner 0, with 63 published and consumed events on channel 0, no additional owner channels. |
| `build-output/s299-pixel-n1-write-fault/` | 2270 | Real TUN write syscall returned `EINVAL` on one deliberately invalid request; one failed attempt was classified and settled, then later echo succeeded. |
| `build-output/s299-pixel-n2-owner1/` | 2268 | New APK, two owners: owner 1 retained original/return index and byte equality during sustained ingress. |
| `build-output/s299-pixel-n2-ordinary/` | 2269 | New APK, ordinary Product two-owner echo and clean stop. |

For `N=1`, `show product topology` reports main thread 0, owner 0 thread 1,
and dedicated I/O thread 2. The run's `affinity-main.txt`,
`affinity-wk_0.txt`, and `affinity-wk_1.txt` read the live kernel
`Cpus_allowed_list` as CPU 0, 1, and 2 respectively. `show product tun` reports
only `tun.return owner=0`, capacity 128, in-use 0 after traffic. The Flow Stack
reports only owner 0. Its stop record has zero sessions, input packets, pbufs,
buffers, obligations and frames; the TUN stop record has zero pending, buffers,
frames and obligations. Each restart above used a new generation, with no
carry-over token or native debt. The verifier rejects deliberately corrupted
return buffer index, payload, missing write and missing concurrent ingress
evidence (`tests/evidence/test_s298_vpn_return_negatives.py`).

## Host and build checks

`/tmp/s299-vpn-startup/` contains actual Product VPP startup for missing I/O
CPU, VPN `N=2`, and VPN `N=1`; the valid cases report distinct main, owner and
I/O thread cores and a clean TUN stop. `build-output/s299-root-n1/`,
`s299-root-n2/`, and `s299-root-n3/` each report `RAW_COMPLETE` for Root NFQUEUE
allow/drop/recover and IPv6 bidirectional packet chains with no remaining
process. The Android placement contract, Host topology test and return-credit
test pass.

The full Host CTest log is `build-output/s299-ctest.log`: 63/67 pass. The three
source-token contract failures match `build-output/s298-ctest.log`; the fourth
requires a Unix socket disallowed by the sandbox and passed 1/1 with access
(`build-output/s299-core-profile-escalated.log`). Android stage repeat
`build-output/s299-stage-b.log` reports no Ninja work; all 12 native libraries
in stages `s299-a` and `s299-b` are byte-identical. Host repeat
`build-output/s299-host-repeat.log` also reports no Ninja work and an identical
plugin. APK repeat `build-output/s299-apk-b.log` reused Java/DEX bytecode.

The functional slice supports VPN `N=1` and preserves `N=2`. Arbitrary VPN
`N>2` and shared owner CPU placement remain the separate SAKAMOTO-300 slice of
ADR-0012. This N=1 record does not cover short TUN writes, `EAGAIN`, handoff
or completion congestion, buffer exhaustion, fragments, or IPv6; those remain
part of the parent PRD qualification matrix. No throughput or latency adoption
threshold is claimed here.
