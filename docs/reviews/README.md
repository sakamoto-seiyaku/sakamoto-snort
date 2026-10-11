# Review Artifacts

This directory contains point-in-time audits, verification notes, and review prompts.

Reviews are evidence, not standing authority. Accepted findings must be promoted into `docs/decisions/`, active runbooks, or Plane project `SNORT` before future agents treat them as current work.

Use reviews to recover reasoning, reproduce a past audit, or inspect risk categories. Do not use review TODOs as an issue tracker.

- [2026-10-08 CCP / Coralflow rule-matching source research](2026-10-08_CCP_CORALFLOW_RULE_MATCHING_SOURCE_RESEARCH.md): pinned remote tengine/cross/classifier/RUPS source, current C-mainline comparison, bounded local probes and adoption limits.
- [2026-10-08 rule compiler, SIMD and VPP batch research](2026-10-08_RULE_COMPILER_SIMD_AND_VPP_BATCH_RESEARCH.md): pinned VPP/DPDK execution and compilation mechanisms, current ARM64 code-generation evidence and semantic adaptation boundaries.
- [2026-10-08 VPP best practices and existing flamegraph audit](2026-10-08_VPP_BEST_PRACTICES_AND_FLAMEGRAPH_AUDIT.md): evidence-based investment ranking, singleton ingress frames, empty-policy cache cost, diagnostic overhead and matched-ELF analysis.
