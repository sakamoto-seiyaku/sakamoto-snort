# Review Artifacts

This directory contains point-in-time audits, verification notes, and review prompts.

Reviews are evidence, not standing authority. Accepted findings must be promoted into `docs/decisions/`, active runbooks, or Plane project `SNORT` before future agents treat them as current work.

Use reviews to recover reasoning, reproduce a past audit, or inspect risk categories. Do not use review TODOs as an issue tracker.

- [2026-10-08 CCP / Coralflow rule-matching source research](2026-10-08_CCP_CORALFLOW_RULE_MATCHING_SOURCE_RESEARCH.md): pinned remote tengine/cross/classifier/RUPS source, current C-mainline comparison, bounded local probes and adoption limits.
- [2026-10-08 rule compiler, SIMD and VPP batch research](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md): pinned VPP/DPDK execution and compilation mechanisms, current ARM64 code-generation evidence and semantic adaptation boundaries.
- [2026-10-08 VPP best practices and existing flamegraph audit](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md): evidence-based investment ranking, singleton ingress frames, empty-policy cache cost, diagnostic overhead and matched-ELF analysis.
- [2026-10-11 current VPP batch, pipeline and parallelism audit](2026-10-11_VPP_BEST_PRACTICES_AUDIT.md): four parallel source audits of ingress frames, node preparation, lookup locality, retained publication and owner drain; distinguishes existing mechanisms from structural gaps.
- [2026-10-11 Root batch design discussion](2026-10-11_VPP_BATCH_DESIGN_DISCUSSION.md): confirmed whole-path scope, fixed resource budget, qualified CPU metric and flexible snapshot granularity; synthesized into Plane SAKAMOTO-291 and the linked product spec.
- [2026-10-11 Root batch design walkthrough](2026-10-11_VPP_ROOT_BATCH_DESIGN_MAP.md): current-to-proposed Module map, four-packet example and outstanding Interface/layout/settlement choices; records the user's clarification that concrete design understanding must precede ticketing.
- [2026-10-11 VPP batch and prefetch code gap map](2026-10-11_VPP_BATCH_CODE_GAP_MAP.md): four new parallel audits compare current functions and layouts with the actual Stellar fork and pinned official VPP; includes caller/build evidence, concrete Interface changes, hot-index dependencies and producer/return lifecycle.
- [2026-10-12 Root NFQUEUE parallelism source audit](2026-10-12_ROOT_NFQUEUE_PARALLELISM_SOURCE_AUDIT.md): matched Android queue hashing, RCU dispatch, per-queue lock scope and measured lane concentration; separates placement imbalance from CPU saturation.
- [2026-10-12 Root Netlink verdict datagram research](2026-10-12_ROOT_NETLINK_VERDICT_DATAGRAM_RESEARCH.md): independent verdicts in one bounded datagram, allocation and parsing scope, native-return/error semantics and a concrete candidate; durable conclusions are summarized in the [Root verdict memo](../memos/ROOT_NFQUEUE_VERDICT_OPTIMIZATION_MEMO.md).
- [2026-10-13 portable NFQUEUE configuration and remaining hotspots](2026-10-13_ROOT_NFQUEUE_CONFIGURATION_HOTSPOT_OPTIONS.md): exact-kernel queue distribution, GSO, pressure and copy controls, own VPP wakeups and stable single-function candidates; excludes vendor-specific tuning and keeps CPU and absolute latency together.
