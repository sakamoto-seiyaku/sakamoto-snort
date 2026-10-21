# Host tests

Root [CMakeLists.txt](../../CMakeLists.txt) is the executable registration authority.
The [tooling guide](../../docs/tooling/README.md) gives configure/build/CTest commands.

- C tests exercise the real standalone policy, flow/protocol/expiry, receive-pool,
  network and diagnostic seams. The packet-free ABI fixture is Host-only.
- Shell/Python contracts check wiring, generated-VAPI boundaries, source ownership
  and build safety. Source-shape checks do not prove real packet delivery.
- Android-specific Host checks live in [tests/android](../android/); Rust tests in
  [crates/product-core](../../crates/product-core/). Unix-socket tests require a
  host environment that permits socket creation.
- The full Product acceptance gate lives in [tests/evidence](../evidence/) and is
  described in the [testing map](../../docs/testing/README.md).

Keep dated failures intact when updating an obsolete contract. New results must
state the current test set and must not relabel the foundation report's 35/40
Host observation as a pass.


`product_l4_match_evidence_test.py` compiles the actual C match-evidence projection,
hashing, recording and association functions against an independent byte oracle.
It checks key compatibility, sticky Match/NoMatch behavior, final publication
order and duplicate-work bounds under ASan/UBSan. Run it directly with
`rtk proxy python3 tests/host/product_l4_match_evidence_test.py` or use the registered
CTest `sakamoto-product-l4-match-evidence-test`. Host timing and Android native
compilation have their own scoped [evidence](../../docs/testing/2026-10-11_ROOT_WHOLE_PATH_BATCH_EXPERIMENT.md#匹配证据计算复用--2026-10-13);
they do not establish whole-device CPU savings.

`product_root_defaults_test.py` exercises actual Root adapter and shared graph
startup: 128+8 preallocated receive buffers, 16-read callbacks, socket request and
capped readback, failures before listener registration, profile-specific
Root 48 / VPN 32 credits and restart reset of diagnostics. Run the registered CTest
`sakamoto-product-root-defaults-test`; related pending/capacity checks retain
ASan/UBSan with no-PIE Host fixtures. The corresponding
[default adoption record](../../docs/testing/2026-10-13_ROOT_COMPOSITE_DEFAULTS.md)
separates startup correctness from complete policy throughput.
