# Host test survey

Status: **retired for the Snort C++ host model; a scoped Product Core Host
control fixture exists** (2026-08-28, ADR-0008/SAKAMOTO-171).

The former gtest/CTest lanes were removed because they modeled the retired C++
packet-domain implementation. SAKAMOTO-171 adds the explicitly named
`sakamoto-product-host-fixture-abi-test` CTest target plus a Rust Unix-socket
semantic fixture. This is a pre-adapter control-spine test and does not prove
the ADR-0007 Flow Stack, packet graph, VPP runtime, or device behavior. Do not
recreate the old tests as a compatibility layer or use old coverage/sanitizer
results as C/VPP evidence.

The production VAPI bridge is selected only by the pinned official VPP build;
its compile/runtime evidence is separate from this fixture and is recorded as
`NOT RUN` when no clean checkout/install of the pinned revision is available.

The future C/VPP mainline needs its own test charter, with boundaries derived
from ADR-0006, ADR-0007, and the OI1–OI5 POC findings.
