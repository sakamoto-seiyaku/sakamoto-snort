# Host test survey

Status: **retired with the Snort C++ host model** (2026-08-26, ADR-0008).

`tests/host/` and its gtest/CTest lanes were removed because they modeled the
retired C++ packet-domain implementation. There is currently no host product
test target. Do not recreate these tests as a compatibility layer or use old
coverage/sanitizer results as C/VPP evidence.

The future C/VPP mainline needs its own test charter, with boundaries derived
from ADR-0006, ADR-0007, and the OI1–OI5 POC findings.
