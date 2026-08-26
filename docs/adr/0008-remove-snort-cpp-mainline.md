---
status: accepted
date: 2026-08-26
---

# Remove the Snort C++ mainline

The active and archived Snort C++ daemon, host model, tests, Android NDK artifact, and C++ Flow Stack facade are removed. They had become a competing packet implementation that could not satisfy the accepted VPP-native C ownership, execution, and buffer contracts. The product remains intentionally unavailable until a new VPP-native C mainline is designed from ADR-0006, ADR-0007, and the OI1--OI5 evidence; POC sources themselves are not imported.

## Consequences

- No C++ Snort source, host test, NDK build target, APK daemon artifact, deploy/debug helper, or archive remains an implementation reference.
- The former S55--S71 C++ daemon/device results remain historical evidence only and cannot be rerun or claimed for current head.
- Android RuntimeService rejects launch with `c_vpp_mainline_required` until a real C/VPP runtime contract and artifact exist.
- The next implementation work begins with a formal VPP-native C Flow Stack Module specification and tickets, not a C++ port or a direct OI3 import.
