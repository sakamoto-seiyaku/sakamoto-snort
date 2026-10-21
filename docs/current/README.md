# Current mainline

Baseline: 2026-09-13. This is the short implementation entry, not a backlog or a
release announcement. Current task state belongs to Plane.

Accepted design update, 2026-09-24: [ADR-0009](../adr/0009-unified-rules-and-vpp-owned-configuration.md)
and the [unified rule specification](../product/UNIFIED_RULE_ENGINE_SPEC.md)
define the next policy/configuration/normal-observation behavior. They do not
extend the implementation or acceptance claims listed below.

Accepted design extension, 2026-10-07: [ADR-0011](../adr/0011-application-dns-filtering-root-and-vpn.md)
aligns application DNS filtering across Root and VPN through query-stage and
subsequent-connection control. The first-version scope is Root/NFQ and VPN using
the same DNS core; KSU/libnetd integration is deferred to a future extension.
This is not evidence that DNS ingress, filtering or association consumption has
been implemented.

## What exists

The product packet domain is VPP-native C. Root uses native NFQUEUE lanes; the
controlled Android VPN validation path uses TUN and the owner-local HEV/lwIP
transport stack. Shared parsing, canonical worker ownership, L4 policy,
FlowRuntime/protocol trackers, bounded reassembly, expiry and network facts have
separately scoped evidence. Rust owns control-plane sessions; Java RuntimeService
owns Android supervision. POC source and the removed C++ implementation are not
product code or compatibility fallbacks.

Root defaults selected on 2026-10-13 now use 128 ordinary receive/pending slots,
48 primary credits, a 16-datagram callback budget, a 1 MiB socket buffer request
(Pixel 2 MiB effective) and NFQUEUE maxlen 4096. Build entrypoints default to the
existing batch+packed implementation; production connection-stable queue placement
is retained. The installed Pixel artifact passed mixed ALLOW/DROP and the 8kpps
startup check; 16kpps still had four primary rejections. This is a user-selected
capacity change, with no whole-path CPU benefit claim. See the scoped
[implementation and regression record](../testing/2026-10-13_ROOT_COMPOSITE_DEFAULTS.md).

The [foundation joint report](../testing/2026-09-13_FOUNDATION_JOINT_ACCEPTANCE.md)
records `PASS_WITH_EXPLICIT_LIMITS` across Linux Root and 64 distinct Pixel
generations, with independent verifiers and retained failed attempts. Its Product
source closure is `ab278ba6c69555a0772277f17d9350bc73ced8312d061a663d52fe3b06b05b96`.
That identity describes the frozen Product sources, not every later docs/test commit.

## What that does not establish

- Ordinary-user VPN product launch remains gated. Controlled debug validation
  reports `protectionRunning=false`; successful packet tests are not a protection
  or release promise.
- The real 24-hour TCP ESTABLISHED expiry/reuse test is user-deferred and unverified.
- Pixel cellular handover and real Linux physical Wi-Fi/Wired/Mobile coverage are
  not proved by the available hardware or controlled projections.
- Signed release, supported-device coverage, complete UI scenarios and performance,
  power and thermal budgets remain separate release requirements.

## Source and reading map

| Area | Source / entry |
| --- | --- |
| Packet graph, policy, flows, adapters | [`src/product/vpp/`](../../src/product/vpp/) |
| C ABI, VAPI and native platform bridge | [`src/product/include/`](../../src/product/include/), [`src/product/native/`](../../src/product/native/) |
| Control-plane sessions | [`crates/product-core/`](../../crates/product-core/) |
| Android supervision, platform facts, validation UI | [`app/android-runtime/`](../../app/android-runtime/) |
| Owner-local transport dependency | [`third_party/hev/`](../../third_party/hev/) |
| Artifact build and launch | [`tools/product/`](../../tools/product/), [tooling guide](../tooling/README.md) |
| Architecture constraints | [Decision map](../decisions/README.md), ADRs [0006](../adr/0006-vpp-native-packet-io-adapters.md), [0007](../adr/0007-owner-local-lwip-direct-egress.md), [0008](../adr/0008-remove-snort-cpp-mainline.md) |
| Verification | [Testing map](../testing/README.md), [test layout](../../tests/README.md) |
| Intended product | [Product docs](../product/README.md) |

For older reasoning or measurements, use the [documentation map](../README.md)
to select a focused record. Large source modules are still present intentionally;
this repository organization does not change their behavior or split their ownership.

For the subsequent private-module refactor and its separate fresh regression,
see [KISS code organization](../maintenance/2026-09-13_KISS_CODE_ORGANIZATION.md).
