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
