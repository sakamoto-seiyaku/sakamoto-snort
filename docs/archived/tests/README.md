# Retired S192 policy contract scripts

These source snapshots are historical records, not runnable acceptance tests.
ADR-0009 replaced S192's separate Gate/L4 policy bundle and Rust-owned durable
writer with one VPP-owned RuleConfig. The current VPP pin also excludes the
Host-only `product packet-graph configure` fixture at build time.

| Retired assertion | Current verification |
| --- | --- |
| Host fixture policy decisions, owner delivery and complete settlement | Host CTest `sakamoto-product-policy-cache-test`, `sakamoto-product-ct-policy-test`, `sakamoto-product-policy-batch-test`, and Product Root/VPN device verifiers in the S303 record |
| Durable source, saved versus active status, revision conflict and restart | Host CTest `sakamoto-product-unified-rule-runtime-contract` against an exact installed VPP artifact, and `sakamoto-product-rule-config-test` for publication success/failure and recovery |
| S192 ABI/VAPI policy bundle serialization | Host CTest `sakamoto-product-vapi-callback-contract` and `sakamoto-product-l4-policy-contract`; current rule request and saved/active status use `sakamoto-product-rule-config-test` |
| Java authoring bundle and Rust `policy.rs` durability | Host CTest `sakamoto-rule-config-android-contract`, and Android aggregate `t01-rule-configuration-test.sh` plus `android-runtime-contract-test.sh` |

The archived scripts retain their original assumptions for interpretation of
dated evidence. Their old paths must not be added back to CMake or the Android
aggregate. The current acceptance and exact baseline are in
[`2026-10-22_S305_STALE_CONTRACT_REPAIR.md`](../../testing/2026-10-22_S305_STALE_CONTRACT_REPAIR.md).
