# Handcrafted Direct bridge POC (S200)

This is the former S180–S185 minimal C packet-to-socket bridge. It does **not** run HEV/lwIP and cannot satisfy ADR-0007 or product VPN readiness. Its only identity is `poc-handcrafted-direct-bridge`.

`source/` preserves the implementation formerly compiled from `src/product/vpp/product_vpn_udp4_adapter.*`; `source-lineage.json` records its original hashes. Product CMake no longer compiles it, the product plugin no longer starts or queries it, and ordinary Android VPN startup reports `vpn_flow_stack_not_ready` before creating TUN, sockets or a VPP child. Existing API fields remain zero for ABI stability. Root retains its actual NFQUEUE adapter.

`tests/` retains the historical recipes verbatim, including their former names and erroneous readiness assertions, solely for interpreting the old logs. They are not current runnable product gates, and their paths assume the former checkout layout. The original test entry points now fail explicitly rather than generating a product PASS. There is no enabled runtime entry or build target for this POC in the current product. Any future independent replay needs a separately identified experiment artifact and entry point; do not point these historical recipes at an ordinary product APK.

Historical build-output evidence is retained unchanged: S180 UDP4, S181 TCP4, S182 UDP6, S183 TCP6, S184 epoch and S185 fault/recovery demonstrated this narrow handcrafted bridge. S192's VPN cells (and related S186–S196 VPN closure cells) have the same limitation. Root and shared-policy evidence retain their original scope; none of the VPN cells establish owner-inline HEV/lwIP implementation or release closure. See `docs/testing/SAKAMOTO_195_RECOVERY_ACCEPTANCE_DOSSIER.md` for the corrected rollup.
