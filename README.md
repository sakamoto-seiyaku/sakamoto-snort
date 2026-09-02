# Sakamoto Snort

This repository is being reconstructed as a VPP-native C Android privacy
firewall. ADR-0008 removed the former Snort C++ daemon, tests, NDK artifact,
and archive because they formed a competing packet architecture.

The active engineering inputs are the accepted VPP-native C decisions
(ADR-0006 and ADR-0007), the S170 baseline, and scoped C/VPP POC evidence.
POC source is not product source. S171-S196 now provide the current VPP-native
Product Core, Rust control plane, Java RuntimeService, APK packaging, and
current-head acceptance evidence; the recovery dossier records the exact
claims and remaining release boundaries.

Read `CONTEXT.md`, `docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md`, and
`docs/adr/0008-remove-snort-cpp-mainline.md` before implementation work.
