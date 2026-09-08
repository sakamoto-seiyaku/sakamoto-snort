# SAKAMOTO-195 Recovery Acceptance Dossier

> **S200 correction, 2026-09-07:** This is a historical dossier, not current product closure. S180–S185 and the VPN portions of S192/S196 ran a handcrafted packet-to-socket bridge with no HEV/lwIP. Their recorded PASS values prove only those narrow POC cases; the `vpn-tun-hev-lwip` identity was incorrect. VPN Foundation and the seven-card/product-release closure are **NOT PROVEN** by these results. Root/shared-policy evidence keeps its documented scope. The implementation and historical test recipes are isolated under `experiments/handcrafted-direct-bridge/`; ordinary product VPN is unavailable until the actual ADR-0007 Flow Stack is implemented and accepted. Raw logs and their hashes remain unchanged. All “current-head” and “Done” statements below describe their original date and are superseded by this correction for product claims.

Date: 2026-09-01
Scope: provenance, seven-card recovery audit, and the current-head Android
lifecycle recovery. The stale-service teardown fix is recorded here together
with its static contract and delegated device evidence.

## Verdict

The original SAKAMOTO-195 **PASS is insufficient for product closure**. The dated audit claimed all seven Recovery Acceptance Cards had
claim-matched current-head evidence. The current4 APK, Host artifact, pinned VPP
revision, API identity, and the final Root -> VPN -> Root closure are recorded
below. The old APK runs remain explicitly historical and are not used to upgrade
the current result.

Under `CONTEXT.md`'s Current-head Product Evidence rule, a card is accepted only
when every required evidence cell is a claim-matched current-head PASS. This
dossier marks a card PASS only when that rule is satisfied.

## Current-head Addendum (2026-09-02)

The dated current4 index below remains retained as historical provenance.  The
following evidence supersedes the child-card cells that changed after that
index and is the basis for the final S195 closure:

| Child card | Current evidence | Result |
| --- | --- | --- |
| S192 | `build-output/s192-root-vpn-l4-matrix/20260902-005715/summary.properties` (SHA-256 `168194f2f5c2e9b860bd692618167c2061ccd632c04654cb0f6e5835cbc7e1a7`), APK SHA-256 `923860e89cb08e20004a1c5a266ca8c383d9332f4ccb9f19e1fbb6ad48161d64`; Root/VPN IPv4/IPv6 TCP/UDP match/no-match, restart, parity, provenance and residue | PASS; S192 Done |
| S193 | Host artifact `build-output/product-vpp-host-s193-current-head` (manifest SHA-256 `4b034479503c1d65e49a9399ed308fc073c6d9ce48bcf7d2b6ca7c4500b9e877`), live evidence `/tmp/sakamoto-s193-final-1006765`; FlowEntry/Gate/L4 lifecycle and clear-counter fixes; CTest 27/27 | PASS; S193 Done |
| S194 | APK `/tmp/s194-apk-output-current-fixed/sakamoto-runtime-debug.apk` (SHA-256 `413191fc0739338487dc59d51b254ed4f4911a11bf4162eb833cad350bd3e843`), stage manifest SHA-256 `b9e3f2b9b0017419c838aad464c0838ab72c6cd8d673b2b223adb36cf4a27380`, API `product_core.api/1.0.0@aa3af3cd`, VPP revision `9258530f3804a152578ce11cc7c8a1e9e9ab88ed0`; callback omission summary `build-output/s194-product-mutation/physical-20260902-0400-callback-installed/summary.properties` SHA-256 `e63b4690f629708534134ff0cfbfba601f8168ebcfb9d77e832c9be8baad5b1a`; pre-submit summary `build-output/s194-product-mutation/physical-20260902-0500-pre-submit-fixed/summary.properties` SHA-256 `7a8ad88e94bc600d674c9bcecae88dd111495609ab222a6b8d08830a506e1818`; both controlled Pixel 6a runs PASS with final residue/lock clean | PASS; S194 Done |
| S196 | Current-head run `build-output/s196-acceptance/physical-20260902-current-head/summary.properties` SHA-256 `2fe1ed2de052fdcc40bd1400d860387e3b0b76a58310e4114545a26d70aaeebd`; evidence index `build-output/s196-acceptance/physical-20260902-current-head/s196-current-head-evidence.properties` SHA-256 `464c586fe4ecc9b25f80c63856a10af493d3cc1bfd58e6b6a34954e55c9277ec`; APK SHA-256 `413191fc0739338487dc59d51b254ed4f4911a11bf4162eb833cad350bd3e843`, APK provenance SHA-256 `bb4a3541226143b803ce77c9b823cde8081299ef08277d25500530b7c0aab996`, product-stage manifest SHA-256 `b9e3f2b9b0017419c838aad464c0838ab72c6cd8d673b2b223adb36cf4a27380`, full VPP stage manifest `/tmp/sakamoto-s181-clean-vpp-stage.current/android-vpp-stage.properties` SHA-256 `f6c7c346a96342d06ba24650b549e2e452b31a49982931d50d267fec8404bfd5` with `stagePayloadBytes=20951768`, `runtimePayloadBytes=9848016` and matching closure, API `product_core.api/1.0.0@aa3af3cd`; Root/VPN idle/active CPU, IPv4/IPv6 TCP/UDP, UID, short switch, current generation stop and residue all PASS; static S196 contracts PASS | PASS; S196 Done |

S194 callback omission specifically records code 14 `product_policy_outcome_unknown`,
durable fence/candidate retention, same-generation code 15 fencing with no
second VAPI submission, and fresh-generation readback-only/no-replay flags.  The
pre-submit mode records code 13 `product_policy_apply_failed`, zero VAPI
submission, no fence/candidate, and a successful explicit retry.  The two
runner/runtime projection defects found during verification (nested `sh -c`
existence checks and loss of the fresh reconcile marker after empty-policy
initialisation) were fixed and revalidated; they do not change the VPP-native
product contract or introduce a legacy C++ path.

Current child-card status is therefore S192 Done, S193 Done, S194 Done, and
S196 Done on the current head.  The
remaining S195 claims are closure/audit claims only; no new product feature is
being added here.  Deferred public IPv6, formal UI, LPI/CT/DNS, release/OEM,
power/thermal and soak claims remain explicitly outside this recovery closure.

## Source and Artifact Provenance

Observed repository revision:

```text
HEAD=482f028304fbf319237288a796574abd7f82bcbb
branch=docs/s103-vpn-flow-stack-fixed-spec
worktree=dirty (pre-existing product and test changes)
```

The following auditor fingerprint covers the current sorted files under `CMakeLists.txt`,
`app/android-runtime` (excluding build/.gradle/.cxx), `crates/product-core`
(excluding target), `src/product/include`, `src/product/native`,
`src/product/vpp`, `tests/host`, and `tests/android`. It includes tracked and
untracked files and excludes this dossier, `docs/`, `build-output/`, and
`target/`:

The APK was built before the final S188 runner-only precondition patch. The
product implementation fingerprint at APK build time was:

```text
43d46bafd0a19cf815b446d64569d2b0265d419915235d5d41841bfa50c87c08
```

The final worktree fingerprint after that runner-only patch is:

```text
b1570e2f114c3d9af28a3bb077bf5019471df98bc0259ecd63fd427e412a2352
```

The current-head fingerprint after the S192-S194 fixes and evidence updates is
`19d4f965a8e6fe64f41683a3184202da552ae59c56b2c6ec9ce9fc72e491376f`.

The two fingerprints immediately above the current-head value belong to the
historical current4 index. The historical S188 patch changed only acceptance
setup/assertions and did not change that APK's product source; the current-head
fingerprint supersedes those historical values for this closure.

Reproduction command:

```bash
find CMakeLists.txt app/android-runtime crates/product-core \
  src/product/include src/product/native src/product/vpp tests/host tests/android \
  -type f -not -path '*/build/*' -not -path '*/.gradle/*' \
  -not -path '*/.cxx/*' -not -path '*/target/*' -print |
  LC_ALL=C sort |
  while IFS= read -r f; do sha256sum "$f"; done | sha256sum
```

Current source/API and Host artifact facts:

| Item | Value |
| --- | --- |
| Product API source SHA | `c749425c01cf9507d24dd40353a47bc2962367aef67fe85a8145ca3e00e2087d` |
| Product source manifest SHA | `dd3330d28831e91ffc736f17f829beb9fc3d3b988f4a7f25c48bafe7b2a5b686` |
| Generated API JSON SHA | `1e1115c70bf9b3f7a1a3873d02a3793827c8a92c455a13a6c5de639ed7d71c31` |
| API identity | `product_core.api/1.0.0@aa3af3cd` |
| Pinned VPP revision | `9258530f3804a152578ce11cc7c8a1e9eab88ed0` |
| Host artifact | `build-output/product-vpp-host-s196-current4` |
| Host artifact manifest SHA | `a8562cd503143fbab6ca9c48b54f5d7230b13c9afa77f2562fb939e618469f4e` |
| Host VPP binary SHA | `f5018d3bfe9365253e8a6c17f383f0e0d860e8033bb17cd2b2290edb3e420f25` |
| Host product plugin SHA | `2cd9e8cc7bc811193343898fc7022607cc9259023332458e1c5ebd7f32d72ba2` |
| Host Rust core SHA | `dbe62ff0921e94f014f950dfb3b08f442564036cfa6cae7030d3882588d49d17` |

Current Android stage/APK facts:

| Item | Value |
| --- | --- |
| Stage | `/tmp/s196-product-stage-current3` |
| Stage manifest SHA | `cab6fa1262d98aeec19fc9458e582b258893d74c9eb5e0670678f428728ea3de` |
| Current APK | `/tmp/s196-apk-output-current4/sakamoto-runtime-debug.apk` |
| Current APK SHA | `b8d0b2e393296f2f763d984602522b9b398bd4200ab7dbcbcb0edb1160530174` |
| APK product plugin SHA | `951ddcb057a4181c492cf1c2c56a4f2e03c1dcc5161c5a61423797adaa58b9b7` |
| APK Product Core SHA | `1c22aecb7e93278689f8c5b3980e91d23408930069ce0e380ca805ec1d8d838e` |
| APK Runtime Control SHA | `74a3335ca0231af848b22476f71c02b0bea773ba34be20b169e51a09af4c5738` |
| APK VPP runtime SHA | `ab718c3105b84d5e585994bfab85f37b791a182700f247884a05b047a8ff8d07` |

The artifact and stage manifests bind pinned VPP/API identities and library
hashes, but neither embeds the product repository `HEAD` or the dirty product
source tree fingerprint. The auditor fingerprint therefore records observed
inputs; it does not cryptographically prove that an APK was built from those
inputs.

## Device Evidence Binding

All current4 device runs below carry the same APK SHA:

```text
b8d0b2e393296f2f763d984602522b9b398bd4200ab7dbcbcb0edb1160530174
```

The strict current4 evidence is:

| Slice | Evidence | Result | Summary SHA |
| --- | --- | --- | --- |
| S176 Root OUTPUT | `build-output/s176-root-nfqueue-output/physical-20260901-0110-s196-current4-port18080-listener/` | PASS | runner log |
| S177 Root multi-lane | `build-output/s177-root-nfqueue-multilane/physical-20260901-0100-s196-current4-port18080/` | PASS | runner log |
| S178 Root dual-stack | `build-output/s178-root-nfqueue-dual-stack-matrix/physical-20260901-0135-s196-current4/` | PASS | runner log |
| S179 Root fault/recovery | `build-output/s179-root-fault-recovery/physical-20260901-0200-s196-current4/` | PASS | runner log |
| S180 VPN UDP4 | `build-output/s180-vpn-udp4-direct-egress/physical-20260901-0230-s196-current4/summary.properties` | PASS | `device summary` |
| S181 VPN TCP4 | `build-output/s181-vpn-tcp4-direct-egress/physical-20260901-0240-s196-current4/summary.properties` | PASS | `device summary` |
| S182 VPN UDP6 | `build-output/s182-vpn-udp6-direct-egress/physical-20260901-0250-s196-current4-explicit-host6/summary.properties` | PASS | `device summary` |
| S183 VPN TCP6 | `build-output/s183-vpn-tcp6-direct-egress/physical-20260901-0300-s196-current4-explicit-host6/summary.properties` | PASS | `device summary` |
| S184 VPN epoch | `build-output/s184-vpn-network-epoch/physical-20260901-0315-s196-current4-explicit-host6/summary.properties` | PASS | `device summary` |
| S185 VPN fault/recovery | `build-output/s185-vpn-fault-recovery/physical-20260901-0500-s196-current4-vpn-wait/summary.properties` | PASS | `device summary` |
| S186 profile barrier | `build-output/s186-profile-switch-barrier/physical-20260901-0550-s196-current4-cold/summary.properties` | PASS | `device summary` |
| S187 worker/core guardrails | `build-output/s187-worker-core-guardrails/physical-20260901-0610-s196-current4/summary.properties` | PASS | `device summary` |
| S188 empty snapshot | `build-output/s188-empty-policy-snapshot/physical-20260901-2318-s196-current4-preconditioned/summary.properties` | PASS | `f040af40484d13321366e6572b236ef6674523019c39295cdc107f8da5399292` |
| S189 Root Network Gate | `build-output/s189-root-network-gate/physical-20260901-2345-s196-current4/summary.properties` | PASS | `d232b0579e47d3508ad58790823217ee650246f9ecb60401dce18b44ced1f226` |
| S190 VPN Network Gate | `build-output/s190-vpn-network-gate/physical-20260901-2355-s196-current4/summary.properties` | PASS | `9e3b28d77763a754c8bf2533a7024fb1054c369c049d2ae2894368832c661712` |
| S191 Root TCP4 L4 | `build-output/s191-root-tcp4-l4/physical-20260901-0015-s196-current4/summary.properties` | PASS | `7bebb833f3938ccdbbc954558ea8471cd86483c6e2709a3805145a6e31a13d33` |
| S192 Root/VPN L4 matrix | `build-output/s192-root-vpn-l4-matrix/physical-20260901-2325-s196-current4-full/summary.properties` | PASS | `99b15cf91fa820cbc39f07a4264cbf5df5eb30e16f83aa24cee3c9c1ff9f8d03` |
| Final S186 closure | `build-output/s186-profile-switch-barrier/physical-20260901-2335-s196-current4-final-closure/summary.properties` | PASS | `844d7598cbaea97d117c0aa9094d9ade6bc44a98e43f42a0a09cfe962414e422` |

S192 reports Root/VPN x IPv4/IPv6 x TCP/UDP match/no-match, restart parity,
`root_vpn_bundle_byte_equal=true`, same UID/revision/hash/rule identity, and
`final_residue_clean=true`. The final closure reports generations
`598 -> 599 -> 600`, stale VPN events ignored, cleanup barrier recovery, and no
Product Core PID, TUN/VPN agent, profile directory, or device lock residue.

Two runner-only corrections are part of the evidence history: S185 added a
bounded VPN readiness wait/retry, S186 added a cold-start barrier, and S188
clears and asserts all persisted policy-authority files before its empty-snapshot
start. The retained S188 `0630` failure was caused by a durable L4 bundle left
from S191; the current4 preconditioned run proves the corrected setup. None of
these changes recreate C++ or alter the VPP-native product path.

## Seven Recovery Acceptance Cards

The cards and claims follow `docs/reviews/SAKAMOTO_170_TICKETING_KISS_AUDIT.md`.
`INVALID` means evidence exists but its identity or claim boundary cannot meet
the current-head rule. `NOT RUN` means the required current-head evidence is
absent; supporting static/unit results do not change that status.

| Card | Current supporting evidence | Strict status | Blocking cell |
| --- | --- | --- | --- |
| A. Product Spine | Current4 installed APK lifecycle, S186 final closure, Host/VAPI identity and artifact checks | PASS | None |
| B. Shared VPP Packet Kernel | Current4 Host artifact plus S174/S175 graph, fragment, congestion, lifecycle and S192 graph runtime evidence | PASS | None |
| C. Root Foundation | Current4 S176-S179 plus S192 Root matrix/restart/residue cells | PASS | None |
| D. VPN Foundation | Historical S180–S185 and S192 handcrafted bridge POC only | NOT PROVEN for ADR-0007 | Real HEV/lwIP product acceptance |
| E. VPP Foundation Closure | Current4 S186/S187 and final Root -> VPN -> Root closure | PASS | None |
| F. Shared Policy/Control Foundation | Current4 S188-S192, Host/Rust/Android contracts, and Root/VPN parity | PASS | None |
| G. Mainline Recovery Closure | Current4 final closure, provenance, and residue record | PASS | None |

Historical PASS paths retained as input, not current acceptance:

```text
S176  build-output/s176-root-nfqueue-output/20260831-232636/runner.log
S177  build-output/s177-root-nfqueue-multilane/20260831-232612/runner.log
S178  build-output/s178-root-nfqueue-dual-stack-matrix/20260901-005300/runner.log
S178  build-output/s178-root-nfqueue-matrix/20260831-231557/runner.log
S179  build-output/s179-root-fault-recovery/20260901-004907/runner.log
S180  build-output/s180-vpn-udp4-direct-egress/20260901-040413/summary.properties
S181  build-output/s181-vpn-tcp4-direct-egress/20260901-040431/summary.properties
S182  build-output/s182-vpn-udp6-direct-egress/20260901-040521/summary.properties
S183  build-output/s183-vpn-tcp6-direct-egress/20260901-040538/summary.properties
S184  build-output/s184-vpn-network-epoch/20260901-040304/summary.properties
S185  build-output/s185-vpn-fault-recovery/s185-isolated-20260901-continue7/summary.properties
S186  build-output/s186-profile-switch-barrier/s186-trace/summary.properties
S187  build-output/s187-worker-core-guardrails/20260901-065359/summary.properties
S188  build-output/s188-empty-policy-snapshot/20260901-073553/summary.properties
S189  build-output/s189-root-network-gate/20260901-082038/summary.properties
S190  build-output/s190-vpn-network-gate/20260901-084031/summary.properties
S191  build-output/s191-root-tcp4-l4/20260901-102815/summary.properties
```

## Current Verification

The following checks were run against the current shared worktree; device
operations were delegated to the single device owner and are listed above:

| Command | Result |
| --- | --- |
| `rtk ctest --test-dir build-output/cmake-host --output-on-failure` | 27/27 PASS |
| `rtk cargo test -p sakamoto-product-core` | 24 tests PASS |
| `rtk bash tests/host/product_vpp_contract.sh` | PASS |
| `rtk bash tests/host/product_vapi_callback_contract.sh` | PASS |
| `rtk bash tests/host/product_plugin_init_contract.sh` | PASS |
| `rtk bash tests/host/s192-policy-bundle-contract.sh` | PASS |
| `rtk bash tests/host/s192-product-packet-graph-policy-contract.sh` | PASS with current4 Host artifact; evidence `/tmp/sakamoto-s192-product-packet-graph-553326` |
| `rtk bash tests/host/product_flow_entry_contract.sh` | S193 semantic and contract PASS |
| `rtk bash tests/host/s194-product-mutation-contract.sh` | VAPI callback and S194 contract PASS |
| `rtk bash tests/android/s192-policy-bundle-contract-test.sh` | Java policy bundle PASS |
| `rtk bash tests/android/s192-root-vpn-l4-matrix-contract-test.sh` | PASS |
| `rtk bash tests/android/s194-product-mutation-contract-test.sh` | PASS |
| `rtk bash tests/android/s196-runtime-instance-teardown-contract-test.sh` | PASS |
| `rtk env ... build-debug-apk.sh --apk-only` | current4 APK build PASS; SHA `b8d0b2e3...` |
| `rtk env ... build-host-artifact.sh` | current4 Host artifact build PASS; manifest SHA `a8562cd5...` |
| `rtk cmake --build build-output/cmake-host --parallel 2` | PASS |
| `rtk bash -n ...` (S185/S186/S188/S192/S193/S194 scripts) | PASS |
| `rtk git diff --check` | PASS |

At S195 closure, `tests/android/runtime-contract-test.sh` still contained
archival greps for the removed C++ paths and was not a product gate; targeted
VPP-native contracts above were the authoritative checks. S197 subsequently
removed those active legacy assertions and made the aggregate VPP-native-only.
No C++ source, NDK artifact, or compatibility fallback was restored.

Post-closure source review also found and fixed an ambiguity in the synchronous
external graph API: its boolean return had represented completion while callers
treated it as buffer ownership, allowing a defensive internal-failure path to
free the same VPP buffer twice. The API now returns zero only before ownership
transfer and has a dedicated Host ownership contract. The same review records a
separate evidence limit: current device runs do not prove that Adapter packets
traverse the real VLIB worker-node graph or an origin-lane completion frame.
That limit narrows the architecture claim without rewriting the retained device
observations above.

## Current-head Host Graph Evidence

The current4 Host artifact was rebuilt after the latest VPP graph changes and
exercised with clean, product-owned runtime directories. These are live VPP CLI
fixtures, not substitute model implementations:

| Claim | Result | Evidence |
| --- | --- | --- |
| S174 parser/owner/ledger and unchanged buffer identity | PASS | `build-output/s195-s174-s175-current4/s174-r1/` |
| S175 IPv4/IPv6 full reassembly, duplicate/conflict/timeout/capacity | PASS | `build-output/s195-s174-s175-current4/s175-fragment-r2/` |
| S175 nonblocking primary/corrective congestion rejection | PASS | `build-output/s195-s174-s175-current4/s175-congestion-r2/` |
| S175 bounded drain, generation fencing, repeated enable/disable, residue | PASS | `build-output/s195-s174-s175-current4/s175-lifecycle-r2/` |
| S192 typed policy graph runtime | PASS | `/tmp/sakamoto-s192-product-packet-graph-553326` |

Current4 fixture trace SHA-256 values:

```text
S174 cycle-1-fixture.trace       13765940a9515d9a086177fa61231fd4e62be06e58fa0b2190e52addb971f9fa
S174 cycle-2-fixture.trace       9b9f7ed35ce2d7f78c8763c72ef519b64d49f368919c28c9b52c574f66bd7fe5
S175 fragment-fixture.trace      05a6d0cc9d7b0fa1c9ab216103f448253cc5c5e4da48a13bd43e352803863a78
S175 congestion-fixture.trace    84f9b45cc21fcbcc0b3365389a4a3afb2b4f993a9f75959c84b20f1858bf2abd
S175 lifecycle-fixture.trace     be429000da3345c4400478586c69cab86ace0ff1f50779d59a98c0770407eb23
```

The evidence directories were run with
`PRODUCT_ARTIFACT_DIR=build-output/product-vpp-host-s196-current4`; the artifact
manifest SHA is `a8562cd503143fbab6ca9c48b54f5d7230b13c9afa77f2562fb939e618469f4e`,
the product source fingerprint at APK build time is
`43d46bafd0a19cf815b446d64569d2b0265d419915235d5d41841bfa50c87c08`, the API
identity is `product_core.api/1.0.0@aa3af3cd`, and the pinned VPP revision is
`9258530f3804a152578ce11cc7c8a1e9eab88ed0`. Each run ended with zero
fragment, handoff-credit, obligation, buffer, duplicate-settlement, and lost-
buffer debt.

The current4 Host artifact also passed the S192 graph runtime contract with a
clean runtime directory. A sandbox-only attempt failed before VPP CLI startup
because hugepage/socket privileges were unavailable; the same fixture was
rerun with the required local Host permissions and passed.
Two failed long-path attempts left inert runtime directories containing only
their generation/owner metadata and startup configuration:
`build-output/product-vpp-runtime-s195-s174-current4` and
`build-output/product-vpp-runtime-s195-s175-congestion-current4`. They contain
no sockets or running process and are retained as failed-attempt traces, not
accepted runtime residue.

## Closure

All required current4 APK Root/VPN policy, transport, profile-switch,
worker/core, fault, restart, and residue cells are PASS. The final controlled-LAN
Root -> VPN -> Root run is PASS and is recorded as Card G. The product manifests
still do not embed the source tree, so the reproducible fingerprint and exact
artifact hashes above remain part of the acceptance record.

No retired C++/NDK route or POC result is credited anywhere in this audit.
