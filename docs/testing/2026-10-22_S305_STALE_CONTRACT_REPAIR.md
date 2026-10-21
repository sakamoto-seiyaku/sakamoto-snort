# SAKAMOTO-305: current Product test contracts

Date: 2026-10-22. Source baseline: `91646a8bea7cc2c7c003d709fa39d85a6b14acb8`.
This change edits tests, suite registration and dated documentation only. It does
not change Product packet source or decide the ADR-0012 VPN layout trade-off.

## Failure baseline and disposition

The S303/S304 broad Host baseline was 62/67. Its raw logs remain at
`build-output/s303-host-ctest.log` and `build-output/s303-host-socket-escalated.log`;
the broad Android baseline stopped on missing `crates/product-core/src/policy.rs`
in `build-output/s303-android-runtime-contract.log`. The S305 targeted baseline
is retained in `build-output/s305-stale-tests-20261022/baseline-targeted-ctest.log`
and `baseline-android-aggregate.log`. These reports are historical observations,
not rewritten by the later passing run.

| Baseline failure | Current source contract and repair |
| --- | --- |
| Host #28 S210 capacity | Completion identity, capacity bypass and single verdict attempt now span `product_root_nfqueue_prepare_completion`, `product_root_nfqueue_complete_from_graph` and `product_root_nfqueue_finish_completion`. The source guard checks call order and the receive return; the existing executable bypass test still checks retained identity, terminal intent and single settlement. Default credits are selected by Adapter kind. |
| Host #31 external graph ownership | The default Root batch path schedules through `product_packet_graph_submit_external_batch_internal` and completes through `product_origin_reclaim_flush` and `product_root_nfqueue_complete_batch_from_graph`; scalar paths remain checked too. The guard checks accepted identity before lifecycle accounting, one completion endpoint, native return ordering and absence of policy in submit. |
| Host #51 platform boundary | Root completion validation moved into `product_root_nfqueue_prepare_completion`, native result accounting into `finish_completion`, and Root packet-fact projection into `product_root_nfqueue_read_dispatch`. The source guard now follows those actual functions and retains its negative mutation witnesses. |
| Host #44 S192 fixture | `SAKAMOTO_PRODUCT_HOST_EVIDENCE=ON` is rejected by both the current builder and CMake on the pinned VPP; with the exact current artifact and local socket access, the old CLI reports `unknown input` and the script fails at `graph.configure=ok` (`baseline-s192-stdout.log`, `baseline-s192-runtime/vpp.trace`). ADR-0009 supersedes the separate Gate/L4 bundle and Rust writer. The script is archived under `docs/archived/tests/`; CTest #44 now runs the installed Product RuleConfig source contract. CTest's RuleConfig, policy cache, CT policy, policy batch and VAPI tests cover current publication and packet decisions. |
| Android S192 bundle | The Rust `policy.rs` file and its durable writer were retired. The old script and its Java fixture are archived. The aggregate now runs `t01-rule-configuration-test.sh`, which checks current Java RuleConfiguration wire inputs, saved/active status and rejection of invalid inputs; `android-runtime-contract-test.sh` and the existing Host VAPI contract still cover Android supervision and native transport. |
| Host #64 UDS | Sandbox Unix-socket denial only. The unmodified Rust test passed in the full Host suite with local socket permission. |

The new installed Host RuleConfig test starts VPP twice with an isolated VPP-owned
source file and an explicitly selected artifact. It verifies empty initial state,
saved DROP rule, stale saved-revision rejection, byte-identical source after
restart, and clean stop. Bare Host VPP has no Root/VPN Adapter, so it reports
publish result `6`, saves the new revision and keeps active revision `0`. The test
asserts that distinction; it does not claim a live packet-policy publication.
The separate policy executable tests and S303 device witnesses cover the active
packet path. Host CTest does not make a fresh live Adapter packet claim; the
S303 device runners remain the current executable integration gate. See
[archived test mapping](../archived/tests/README.md).

## Commands and results

The exact installed Host artifact was `build-output/product-vpp-host/`: VPP SHA-256
`b170536c0198a8084a57136ef9da6cd9c57df7ae6e0e76d2f384e1fedcae9a69`,
Product plugin `33208e20c72912327bc38b151852283020953b1e97999695f1e2154cad48c91e`,
Rust Host core `b0f7dfdfd4fe0d6ddad1c30569aee1d8b40f20546e177c9a79caf75d9a4e24ee`,
artifact manifest `91734a009eb7f63ab031f3fc10a1c89766d3eec06ded61752f6cf7709a5eb4b3`.
Its manifest sets `product.host.evidence=OFF`. The S303 APK verified below is
`build-output/s303-apk-a/sakamoto-runtime-debug.apk`, SHA-256
`6a424ab27181b40772a4298e46d6bf5bf4c19329618e78a3ea35d2139bf32ce1`.

| Command from repo root | Result / raw record |
| --- | --- |
| `ctest --test-dir build-output/host-tests --output-on-failure -R 's210-capacity-bypass\|external-graph-ownership\|platform-boundary\|s192-product-packet-graph-policy'` before edit | 0/4; `baseline-targeted-ctest.log`. This sandbox run also denied #44's socket. |
| `PRODUCT_ARTIFACT_DIR="$PWD/build-output/product-vpp-host" SAKAMOTO_S192_REQUIRE_RUNTIME=1 SAKAMOTO_S192_EVIDENCE_DIR="$PWD/build-output/s305-stale-tests-20261022/baseline-s192-runtime" bash tests/host/s192-product-packet-graph-policy-contract.sh` before edit, with local socket access | Exit 1, missing `graph.configure=ok`; `baseline-s192-stdout.log` and `baseline-s192-runtime/vpp.trace`. |
| `bash tests/android/runtime-contract-test.sh` before edit | Exit 2 on missing `policy.rs`; `baseline-android-aggregate.log`. |
| `cmake -S . -B build-output/host-tests -G Ninja` then `cmake --build build-output/host-tests` twice | Configure succeeded; both unchanged builds reported `ninja: no work to do.` No new native Product artifact was built. |
| `bash tests/android/runtime-contract-test.sh` after edit | PASS; `after-android-aggregate.log` and `after-android-status`. |
| `PRODUCT_ARTIFACT_DIR="$PWD/build-output/product-vpp-host" SAKAMOTO_RULE_RUNTIME_EVIDENCE_DIR="$PWD/build-output/s305-stale-tests-20261022/unified-rule-runtime-ctest" ctest --test-dir build-output/host-tests --output-on-failure -R sakamoto-product-unified-rule-runtime-contract` with local socket access | 1/1; `target-unified-rule-ctest.log` and full API/source/stop traces in `unified-rule-runtime-ctest/`. Earlier failed attempts and their raw output remain under `unified-rule-runtime-{first,second,third}/`; they found and corrected test harness assumptions about runtime paths and pre-Adapter publication. |
| The same targeted CTest twice with `SAKAMOTO_RULE_RUNTIME_EVIDENCE_DIR="$PWD/build-output/s305-stale-tests-20261022/unified-rule-runtime-repeat"` | Both 1/1 PASS; `target-unified-rule-repeat{1,2}.log`. Each invocation created a distinct `sakamoto-rule-runtime.*` child, preserving the prior trace and source. |
| `PRODUCT_ARTIFACT_DIR="$PWD/build-output/product-vpp-host" SAKAMOTO_RULE_RUNTIME_EVIDENCE_DIR="$PWD/build-output/s305-stale-tests-20261022/unified-rule-runtime-full" ctest --test-dir build-output/host-tests --output-on-failure` with local socket access | **67/67 PASS**, 153.28 seconds, including the new #44 and unmodified Rust UDS #64; `final-host-ctest.log`, `final-host-status`, and `unified-rule-runtime-full/`. |
| The same full CTest after the evidence-directory repair, using the same artifact and `unified-rule-runtime-full` evidence parent | **67/67 PASS**, 152.40 seconds; `final-host-repeat-ctest.log`, `final-host-repeat-status`, and a new child under `unified-rule-runtime-full/`. The prior full-run traces remain intact. |

The original S303 Root and VPN N=1/N=3 APK and source-bound raw runs were
rechecked with the current independent verifiers, without replacing those raw
observations or claiming a new Pixel run. Eleven verifier logs under
`build-output/s305-stale-tests-20261022/verify-*.log` passed: Root topology and
IPv4/IPv6 fragment N=1/N=3; VPN owner 0 at N=1 and owners 0/1/2 at N=3;
N=1 FlowEnd and N=3 expiry under ingress stress; and N=1/N=3 TUN faults with
69 exact original indexes each. Commands were `python3
tests/evidence/verify_s303_root_topology.py <run> --apk <S303 APK>`,
`verify_s303_root_fragments.py <run> --apk <S303 APK>`,
`verify_s298_vpn_return.py <run> --apk <S303 APK>`, and
`verify_s301_tun_faults.py <run>`, with the run paths recorded in the S303
qualification report. The Product and APK bytes are unchanged by this ticket;
these are rechecks of frozen Product runtime evidence, not new device traffic.

The [portable S305 raw archive](evidence/s305-test-contract-20261022.zip)
contains 155 baseline, passing and failed-attempt files (81,563 bytes,
SHA-256 `d84b3ccc5bfc1aa5ed0059652ee288d98917a838b37ba3007a01c94faad9b513`).
Its [index](evidence/s305-test-contract-20261022-index.json) records each member's
relative path, byte count and SHA-256. The zip members and index were verified
against each other after creation. It contains no compiler cache or APK copy;
the artifact hashes above bind the tested inputs.
