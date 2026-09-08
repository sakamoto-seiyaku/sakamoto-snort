# SAKAMOTO-230 — real Linux NFQUEUE acceptance entry

Acceptance: **functional PASS**, 2026-09-08. The actual default Product graph runs
on Linux and passes the same-source Pixel Root baseline. No Host evidence graph,
POC datapath, platform UI, daemon or numeric namespace discriminator was added.

## Product increment

The existing verified Host artifact builder now accepts
`SAKAMOTO_PRODUCT_HOST_EVIDENCE=OFF`; its historical auxiliary default remains ON.
The artifact records the selected mode. S230 builds explicitly use OFF and the
real `product_packet_graph.c`. Existing launch/hash verification is reused.

Root UID parsing accepts the real Linux UID 0 and rejects the unknown sentinel
UINT32_MAX. Ordinary complete IPv4/IPv6 TCP joins UDP in the shared graph envelope;
the existing typed parser, owner selection, policy and original-lane completion
path handle both. Android hook/readiness scope remains the S206 UDP baseline.

The reusable Linux collector runs only in a rootless user/network namespace.
Its isolated Linux sockets generate real INPUT/OUTPUT NFQUEUE traffic. An
acceptance control client calls the existing Rust Product Core and generated VAPI
to install an ordinary Gate drop rule for UID 0, then an empty allow policy.
The immutable control cdylib/client hashes are included in the build witness.
Network namespace identity is recorded as environment evidence only.

## Actual Linux result

- Kernel: `6.6.114.1-microsoft-standard-WSL2`, x86_64, hostname `Main`.
- Final run: `build-output/s230-linux/run-f`; **32 fresh processes**, generations
  23010–23041, **472 captured packets**, 32 blocked probes and 32 matched echoes.
- All **32** family/protocol/lane/owner/verdict combinations are observed:
  IPv4/IPv6 × TCP/UDP × two family lanes × owner 0/1 × DROP/ALLOW.
- IPv4 queues 176/177 and IPv6 queues 178/179 each have an independent socket.
  Global lanes 0/2 belong to logical worker 0, lanes 1/3 to worker 1. Actual
  callback TLS, polling thread and policy worker are independently checked.
  Linux VPP selects available CPU cores at startup; observed syscall CPU matches
  each run's actual `show threads` lcore, rather than assuming Pixel CPU IDs.
- Every admitted packet has one parser/assignment, immutable typed facts,
  canonical owner verified from raw bytes, the original native buffer, one
  original-lane verdict and one return. Native node vectors conserve all packets.
  Remote packets use one Primary Handoff and one Completion Frame return to the
  origin worker. Owner Guard and corrective dispatch remain absent.
- DROP uses the actual policy rule 230 and NF_DROP. UDP nonces are absent at the
  endpoint; TCP attempts stop at a captured SYN, before application payload.
  After policy replacement, both protocols produce an exact nonce echo.
- Every process stops with zero pending, frame, buffer, obligation and handoff
  debts. Both-family hooks are removed, all four queue sockets disappear from
  `/proc/<pid>/fd`, their kernel queue IDs accept a fresh binding, and the process
  exits. Cleanup also runs on failure.

The rootless environment denies reading `/proc/net/netfilter/nfnetlink_queue`.
Live queues reject another socket's bind with EPERM, while all four binds return
ACK=0 after Product lane close. This is paired with actual fd and zero-ledger
checks; a readable kernel queue table is not claimed.

## Same-source Pixel result

Pixel 6a `28201JEGR0XPAJ`, generations **666–669**, passes the full S206 baseline:
38 successful dual-stack UDP echo probes, **115 captures**, all eight lane/owner
combinations, one in-flight draining closure and survivor traffic after closing
each of the four lanes. All final ledgers and kernel queue/hook/process residues
are zero. This task's Pixel baseline does not qualify Android TCP readiness.

The first Pixel run (generation 665, `pixel`) remains HOLD. Background QUIC
replies exhausted the bounded trace (341 captures); the collector stopped and
cleaned successfully. The accepted `pixel-b` run temporarily disabled Wi-Fi for
loopback isolation and restored its original enabled state afterwards. No trace
bound was enlarged and no product hook was narrowed for acceptance. Existing
Android idle-profile remote-path latency remains outside functional acceptance.

## Evidence and validation

- Linux source/build/control witness: `build-output/s230-linux/linux-build/build.json`.
- Linux artifact: `build-output/product-vpp-host-s230-evidence`.
- Linux verifier: `tests/device/verify-s230-linux-nfqueue.py`;
  `build-output/s230-linux/linux-verification-f.json`: PASS.
- Pixel build: `build-output/s230-linux/pixel-build/build.json`;
  request/run: `pixel-request-b.json`, `pixel-b` under the same evidence root;
  `pixel-verification.json`: PASS using the S206 independent verifier.
- Same source SHA-256:
  `2c891384192ae8a84c21745ac1194b717e6142065a3a7b6feb14a338227d098d`.
- Source commit: `9c67175713baceb46cef015f3464893fa3d69950` plus saved dirty source.
- Linux plugin SHA-256:
  `ce92c40d98f635553058a71b9c0489f8f463fbd4a4339c439ad66df8450623a1`.
- Linux VPP SHA-256:
  `3f68cfab85ae1b49f1f016b6ab13ddb69dc8208dd9fb2d8a4098731bbe264485`.
- APK SHA-256:
  `63c26e8d5a1c3d2d64efb2092ccc9d0171b8678e60be34562d3666061cc1df9b`.
- Android plugin SHA-256:
  `d56dacc6ea74f3d68f2feefa6f62f3a44fdca340d21fef11a7071d5704caafb0`.
- Artifact identity: `sakamoto-product-vpp-s230-v1`.
- Wrong-return-worker, wrong-verdict and missing-queue-release evidence clones
  are rejected; these are verifier negatives, not claimed wire fault injection.
- Host generated-VAPI build contract, C control-client compilation with warnings
  as errors, Python syntax and diff checks pass.

Early Linux runs a–c remain HOLD: collector expectations for the occupied queue
ACK, Gate authoring fields, and the supported generation range were corrected.
Run d established wire closure, run e added complete source/control binding,
and final run f also exercises the final namespace guard and cleanup structure.
None of these collector corrections changed the Product policy schema or widened
its generation contract. This task does not qualify pressure, fragmentation,
ICMP ownership, latency, power or online worker placement.

## Reproduction

```sh
python tests/evidence/build_s230_linux.py \
  --output build-output/s230-linux/linux-build-new \
  --artifact build-output/product-vpp-host-s230-new \
  --stage /tmp/sakamoto-s193-host-stage-current
unshare --user --map-root-user --net \
  python tests/device/s230-linux-nfqueue.py \
  --output build-output/s230-linux/run-new \
  --artifact build-output/product-vpp-host-s230-new \
  --policy-client build-output/s230-linux/linux-build-new/control/s230-policy \
  --vppctl /tmp/sakamoto-s193-host-stage-current/source/build-root/install-vpp-native/vpp/bin/vppctl
python tests/device/verify-s230-linux-nfqueue.py \
  build-output/s230-linux/run-new \
  --build build-output/s230-linux/linux-build-new/build.json
```

The evidence directories must be fresh. The VPP stage must match the pinned
revision and verified core patch/runtime closure. Rebuild the Pixel APK from the
same source and run the S206 collector/verifier for the required Android baseline.
