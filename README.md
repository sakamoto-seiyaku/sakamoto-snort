# Sakamoto Snort

This repository is being reconstructed as a VPP-native C Android privacy
firewall. ADR-0008 removed the former Snort C++ daemon, tests, NDK artifact,
and archive because they formed a competing packet architecture.

The active engineering inputs are the accepted VPP-native C decisions
(ADR-0006 and ADR-0007) and scoped C/VPP POC evidence. POC source is not
product source. A packet runtime is intentionally unavailable until the new C
packet mainline is specified and implemented. SAKAMOTO-171 supplies only a
Host pre-adapter control spine; its fixture/Host evidence does not test the
ADR-0007 Flow Stack or claim a runnable VPP packet runtime.

Read `CONTEXT.md`, `docs/ANDROID_VPP_CURRENT_STATE_HANDOFF.md`, and
`docs/adr/0008-remove-snort-cpp-mainline.md` before implementation work.
