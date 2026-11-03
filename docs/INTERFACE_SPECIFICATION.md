# Current interface map

The accepted [unified rule specification](product/UNIFIED_RULE_ENGINE_SPEC.md)
and [ADR-0009](adr/0009-unified-rules-and-vpp-owned-configuration.md) define
rule-management, compilation and observation semantics. The
[DNS specification](product/APPLICATION_DNS_SPEC.md) adds query/proxy/domain contracts.
Implementation and qualification are mapped by the [current mainline](current/README.md);
the typed sources below own the actual fields and versions.

The former v3.10 vNext/netstring daemon interface is
[archived intact](archived/pre-vpp/INTERFACE_SPECIFICATION.md). It is not the
current Product API and must not be restored as a C++ compatibility surface.

Current contracts are typed at their owning boundary:

| Boundary | Authoritative source |
| --- | --- |
| VPP generated API | [`product_core.api`](../src/product/vpp/product_core.api) |
| Native Product ABI and status | [`sakamoto_product_abi.h`](../src/product/include/sakamoto_product_abi.h) |
| Rust/native control calls | [`sakamoto_product_core_ffi.h`](../src/product/include/sakamoto_product_core_ffi.h), [Rust Product Core](../crates/product-core/src/lib.rs) |
| Online rules and DNS configuration | [`sakamoto_product_rule_config.h`](../src/product/include/sakamoto_product_rule_config.h), [`product_dns_proxy.h`](../src/product/vpp/product_dns_proxy.h) |
| DNS messages, upstreams and association qualification | [`product_dns.h`](../src/product/vpp/product_dns.h), [`product_dns_proxy.h`](../src/product/vpp/product_dns_proxy.h), [`product_dns_assoc.h`](../src/product/vpp/product_dns_assoc.h); association enforcement remains disabled |
| Flow/DNS observation records and versions | [`sakamoto_product_observation.h`](../src/product/include/sakamoto_product_observation.h), [Rust decoding](../crates/product-core/src/dns_observation.rs) |
| Current-flow and observation queries | [`sakamoto_product_flow_query.h`](../src/product/include/sakamoto_product_flow_query.h), [`sakamoto_product_core_ffi.h`](../src/product/include/sakamoto_product_core_ffi.h) |
| Platform network facts | [`sakamoto_product_network.h`](../src/product/include/sakamoto_product_network.h) |
| Android request protocol | [`RuntimeControlProtocol.java`](../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java) |
| Android adapter readiness | [`ProductPacketAdapterContract.java`](../app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPacketAdapterContract.java) |

This is navigation, not a duplicated wire schema. Check the owning source and its
tests before changing a field. For lifecycle, ownership and acceptance limits,
read [current mainline](current/README.md) and [testing](testing/README.md).
Product intent remains in [product docs](product/README.md).
