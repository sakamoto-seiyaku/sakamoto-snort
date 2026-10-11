# Decision map

Read the relevant current decisions before architectural work. This directory
contains both accepted constraints and older design lineage; location alone does
not make every historical execution claim current.

## Current architecture constraints

- [Accepted ADRs](../adr/), especially [0006](../adr/0006-vpp-native-packet-io-adapters.md),
  [0007](../adr/0007-owner-local-lwip-direct-egress.md) and
  [0008](../adr/0008-remove-snort-cpp-mainline.md).
- [Unified rule semantics and VPP-owned configuration](../adr/0009-unified-rules-and-vpp-owned-configuration.md):
  accepted September redesign, with the [behavior specification](../product/UNIFIED_RULE_ENGINE_SPEC.md);
  supersedes conflicting policy/observation design lineage, not evidence of implemented capability.
- [Application DNS filtering across Root and VPN](../adr/0011-application-dns-filtering-root-and-vpn.md):
  accepted query-stage and subsequent-connection control under the same application
  policy; preserves attribution/cache limits and shared DNS implementation.
  The first version targets Root/NFQ and VPN; KSU's system-resolver integration
  is a future extension. A design decision, not runtime evidence.
- [Per-worker flow ownership](PER_WORKER_FLOW_OWNERSHIP.md).
- [VPP packet metadata ownership](VPP_PACKET_METADATA_OWNERSHIP.md).
- [L4 conntrack working decisions](L4_CONNTRACK_WORKING_DECISIONS.md).

## Mixed constraints and historical execution

These remain in place because they contain domain principles as well as old
implementation detail. Read the relevant section with its date and supersession
notes; do not treat old C++ layouts, commands or PASS records as current evidence.

- [Android functional closure](ANDROID_FUNCTIONAL_CLOSURE_CONTRACT.md): accepted
  invariants; its former C++ execution contract is retired.
- [NFQUEUE module boundaries](NFQUEUE_DATAPATH_MODULE_BOUNDARIES.md): older module
  and authoring rationale, with later ownership supersession notes.
- [Dual-stack rule model](IPRULES_DUAL_STACK_WORKING_DECISIONS.md): domain lineage;
  current typed fields are linked by the [interface map](../INTERFACE_SPECIFICATION.md).
- [Flow telemetry](FLOW_TELEMETRY_WORKING_DECISIONS.md): earlier export design;
  not evidence that the former shared-memory ABI ships in today's Product.

## Superseded records

The [pre-VPP archive](../archived/pre-vpp/README.md) holds the former reconstruction,
RESETALL and domain-policy observability records. Stable redirects remain at their
old paths. The [current mainline](../current/README.md) routes actual implementation
and dated acceptance evidence; Plane owns open work.
