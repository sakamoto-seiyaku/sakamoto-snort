# Retired source-shape contracts

SAKAMOTO-249, 2026-09-13. These four scripts remain byte-for-byte historical
records, with executable bits removed. Their original paths were `tests/android/`.
They are not registered in current CTest and are not commands to run.
The short-name S191 alias is retained here too; it only delegated to the retired check.

| Retired check | Invalid implementation assumption | Current coverage |
| --- | --- | --- |
| S176 Root OUTPUT | Old adapter name, OUTPUT-only single lane and old lifecycle source shape | Executed Android Runtime contract; current Root lane/completion boundary check; source-bound Root device evidence |
| S189 Root network gate | Hard-coded Wi-Fi hints, fixed old ABI counts and scalar gate-only path | Current platform snapshot boundary; policy bundle Android contract; Linux network C test; source-bound S232/S235 evidence |
| S190 VPN network gate | Removed `product_vpn_udp4_adapter.c`, policy-derived TUN identity | Executed adapter readiness contract; controlled VPN TUN handoff boundary; source-bound TUN/HEV joint evidence |
| S191 Root TCP4 L4 | Removed scalar matcher/no-match function and IPv4/TCP-only shape | Real shared L4 C semantic test; current S192 policy bundle/graph and S209 snapshot contracts |

The VPP artifact contract remains active and now accepts the existing configurable
Host-evidence build option. This is a replacement test set, not “the same four
tests now pass”. The dated foundation report's 35/40 remains unchanged.
See [test navigation](../../README.md) and [current evidence](../../../docs/testing/README.md).
