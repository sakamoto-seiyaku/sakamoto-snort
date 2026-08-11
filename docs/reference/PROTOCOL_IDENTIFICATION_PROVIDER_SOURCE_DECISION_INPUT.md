# Protocol Identification Provider Source Decision Input

Date: 2026-08-12

Status: concise decision input for SAKAMOTO-61 provider source and runtime
wiring. This document does not choose a provider source strategy, does not
approve vendoring or distribution, does not provide legal advice, and does not
start ProtocolRule enforcement.

Primary reference inputs:

- `docs/reference/PROTOCOL_IDENTIFICATION_VPP_REFERENCE_INVENTORY.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_REFERENCE_AUDIT.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_STELLAR_LPI_WRAPPER_INVENTORY.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_LIBPROTOIDENT_NDK_PROBE.md`
- `docs/reference/PROTOCOL_IDENTIFICATION_VPP_LPI_CORPUS_MANIFEST.md`

Contract guardrails:

- does not choose a provider source strategy.
- does not provide legal advice.
- does not start ProtocolRule enforcement.
- No provider source has been copied into this repository.
- do not introduce a second flow/session table.

## Current Proven Evidence

- The backup reference tree is
  `/home/js/backup/backup/Git/vpp`, observed on branch
  `dev-26.03...origin/dev-26.03`. It is a deeply modified VPP gateway tree,
  not plain upstream VPP.
- The relevant recognizer lineage is `src/plugins/stellar_lpi/`, with
  `stellar_lpi_core.{c,h}`, `stellar_lpi_extend.{c,h}`, and vendored
  `libprotoident/`.
- The wrapper exposes a small C boundary:
  `lpi_detector_new`, `lpi_detector_free`, `lpi_detect_context_new`,
  `lpi_detect_context_free`, `lpi_detect_context_update`, `lpi_detect`, and
  `lpi_appid2name`.
- The observed call shape matches Sakamoto's high-level provider seam:
  detector lifecycle, per-flow context, per-payload
  `lpi_detect_context_update -> lpi_detect`, and a `stop_detect` signal.
- The backup wrapper plus vendored `libprotoident` has passed local
  compile/link probes:
  - Android base `libprotoident` NDK probe: `probe.result=PASS`.
  - Android wrapper candidate probe for
    `stellar_lpi_core.c + stellar_lpi_extend.c`: `probe.result=PASS`.
  - Host synthetic payload probe through
    `LpiRecognitionPipeline -> LpiRecognitionAdapter -> BoundedFlowTable`:
    `probe.result=PASS`.
  - Host selected-reference-PCAP probe for HTTP, DNS, QUIC, UNKNOWN/no-result,
    and SOCKS-then-HTTP compound behavior: `selectedExpectedJsonValidation=PASS`
    and `probe.result=PASS`.
- The repo-local Sakamoto seam already exists:
  `LpiRecognitionProvider` submits bounded payload-bearing packets before
  adapter completion; `LpiRecognitionAdapter` maps provider aliases through the
  project-owned Application Protocol Catalog; recognition state is recorded on
  the worker-owned `BoundedFlowTable` / `FlowEntry`. Per-flow real-provider
  recognizer context is owned by `FlowEntry` as opaque provider state. When a
  payload-bearing eligible packet reaches the pipeline but the worker-owned flow
  table cannot supply the existing recognition slot, the pipeline increments
  `flowSlotUnavailablePackets` and does not create a provider-side flow map or
  parallel table. A wired provider that cannot create its opaque context increments
  `providerContextUnavailablePackets` without submitting the packet to the
  provider.
- The build contract now pins real-provider compilation behind
  `SAKAMOTO_ENABLE_LPI_PROVIDER`, which defaults `OFF` and fails configure if
  enabled before an explicit source/provenance decision selects provider source.
- The runtime contract now has host coverage for both Root/NFQUEUE and VPN/TUN:
  after payload-bearing eligible traffic with no injected provider,
  `lpiProvider.available=false`, `lpiProvider.name=disabled`,
  `providerUnavailablePackets` increments, and
  `packetsSubmittedToProvider` remains `0`; control-plane JSON contract tests
  pin the same disabled `lpiProvider` status shape for `NFQUEUE.STATUS` and
  `VPN_TUN.STATUS`.
- The host seam parity contract
  `tests/host/lpi_provider_seam_parity_tests.cpp` proves Root/NFQUEUE and
  VPN/TUN can inject the same provider-neutral `LpiRecognitionProvider`
  implementation, submit equivalent payload-bearing TCP facts through that
  interface, and project the same catalog-mapped result into allowed-flow
  Activity without wiring a real provider. The same parity contract also covers
  no-result and unmapped-alias provider outcomes so both profiles consume
  payload budget without inventing temporary Sakamoto catalog IDs.
- The provider-neutral status shape exposes terminal recognition counters:
  `detectorDonePackets` and `budgetExhaustedPackets`. These are driven by
  FlowEntry terminal state transitions and do not require a real provider to be
  enabled by default.
- No real provider is wired by default. No provider source has been copied into
  this repository. No PCAP corpus or expected JSON has been imported. No Android
  Root/VPN device evidence proves a real provider. No ProtocolRule enforcement
  has started.

## Source Shape Options

These are decision options only; this document does not prefer one.

### Option A: Backup VPP wrapper plus vendored libprotoident

Use the observed extractable candidate:
`stellar_lpi_core.c + stellar_lpi_extend.c + libprotoident`.

Known shape:

- recognizer source: `3` top-level `.cc`, `284` `tcp/*.cc`, and `244`
  `udp/*.cc` files from vendored `libprotoident`;
- wrapper source: observed wrapper inventory reports `4` `.c` files and `8`
  `.h` files;
- build style: static C++11 PIC recognizer, Sakamoto-owned build wrapper would
  be needed;
- compatibility work: replace or wrap modified-VPP dependencies such as
  `ALLOC` / `FREE`, `uthash`, and VPP utility headers;
- mapping work: translate app names to `lpi:<name>` provider aliases and then
  to Sakamoto catalog IDs. Fork-local numeric AppIDs must not cross the
  Sakamoto provider seam.

Decision and risk inputs:

- source provenance and license posture for Android distribution;
- whether `stellar_lpi_extend` should be included, trimmed, or replaced;
- warning policy for legacy third-party C/C++ source;
- runtime evidence on Root and VPN profiles.

### Option B: Reference-only lineage

Keep the backup tree and probes as reference evidence only, and implement or
select a different provider source.

Known shape:

- no backup source, PCAP, or expected JSON is copied into this repository;
- existing reference docs, inventory scripts, and probes remain as comparison
  inputs;
- Sakamoto still uses `lpi:<name>` aliases and the project-owned Application
  Protocol Catalog.

Decision and risk inputs:

- a replacement provider must independently prove equivalent source,
  licensing, build, corpus, and runtime behavior;
- existing selected PCAP/probe evidence remains lineage evidence, not product
  evidence for the replacement.

### Option C: External or curated provider package

Use an external upstream, curated, or separately packaged recognizer source
instead of the backup VPP vendored copy.

Known shape:

- package source, version, checksum, license files, notice files, and Android
  build behavior must be pinned before runtime wiring;
- Sakamoto should still adapt through `LpiRecognitionProvider` and provider
  aliases, not provider-native numeric IDs;
- package updates would need their own reproducible probe and corpus baseline.

Decision and risk inputs:

- API and recognition behavior may differ from the backup wrapper;
- expected alias coverage and selected PCAP behavior must be re-established;
- supply-chain, redistribution, and release packaging obligations remain
  unresolved until reviewed.

## License / Provenance Facts and Gaps

Facts observed locally:

- vendored `libprotoident/libprotoident.h` states University of Waikato WAND
  research group copyright, 2011-2016;
- vendored `libprotoident/libprotoident.h` states GNU Lesser General Public
  License, version 3 or later;
- the local vendored `libprotoident` directory does not provide an adjacent
  `COPYING`, `LICENSE`, or `NOTICE` file;
- plugin wrapper files include placeholder Apache-2.0 text such as
  `<current-year> <your-organization>`;
- the reference corpus tree does not include corpus-local README, NOTICE,
  source-attribution, or privacy documentation;
- reference captures and expected JSON contain real-looking public/private IPs,
  service names, and application names.

Gaps before distribution or import:

- whether LGPL-3.0-or-later is acceptable for the Android artifact and release
  model;
- whether static or dynamic linking will be used, and what source/relink/notice
  posture that implies;
- whether the placeholder wrapper headers can be relied on, need replacement,
  or require upstream attribution clarification;
- whether any backup source, expected JSON, or PCAP subset may be copied into
  this repository;
- whether captures must be minimized, synthetic, anonymized, or replaced before
  becoming repo-local fixtures.

This section is a fact inventory, not legal advice.

## Runtime Seam / Wiring Path

The intended runtime seam is already present and should stay provider-neutral:

```text
Root/NFQUEUE or VPN/TUN Adapter
  -> shared VPP parser / PacketFacts
  -> per-worker FlowEntry / BoundedFlowTable
  -> LpiRecognitionPipeline
  -> LpiRecognitionProvider implementation
  -> LpiRecognitionAdapter
  -> Application Protocol Catalog via provider alias
  -> FlowEntry LpiRecognitionState / Activity projection
```

Wiring constraints:

- Root and VPN must share the same recognition seam; VPN must not add a parallel
  recognition path.
- Recognition state belongs on the existing worker-owned `FlowEntry`; do not
  introduce a second flow/session table.
- Any real-provider per-flow recognizer context must also be owned by the
  existing `FlowEntry` as an opaque provider context; a provider-side flow map is
  not allowed as the default integration shape.
- Packet submission stays bounded and payload-bearing only.
- Provider aliases are the boundary currency, for example `lpi:http` and
  `lpi:dns`; fork-local Qosmos/qDPI-style AppIDs remain provider-local evidence.
- Current packet use is valid only for facts produced before adapter
  completion. Later/asynchronous facts can affect future packets only.
- ProtocolRule work waits until a real pinned provider and licensed/minimized
  corpus evidence exist.

## Safe Work Before the Source Decision

These items can proceed while provider source remains undecided, as long as they
keep the provider disabled by default:

- keep `DisabledLpiRecognitionProvider` as the default runtime provider;
- add build flags or CMake plumbing that makes real-provider compilation
  explicit and off by default, for example a disabled
  `SAKAMOTO_ENABLE_LPI_PROVIDER`-style gate;
- add provider-neutral host tests for unavailable/no-result/mapped/unmapped
  behavior through `LpiRecognitionPipeline`;
- add adapter-neutral contract tests that assert Root and VPN both pass through
  the same `LpiRecognitionProvider` seam;
- extend status/counter tests for payload eligibility, provider unavailable,
  provider no-result, provider fact, detector done, and budget exhausted;
- keep reference probes read-only and writing only under `build-output`;
- prepare source-package evidence requirements for license files, checksums,
  NOTICE/source/relink posture, warning policy, and Android ABI settings; see
  `docs/reference/PROTOCOL_IDENTIFICATION_PROVIDER_SOURCE_PACKAGE_CHECKLIST.md`
  as a pre-decision evidence catalog only. It is not the source of truth for
  open work.

## Work That Must Wait

These items must wait for an explicit provider-source and license/provenance
decision:

- copying backup VPP source, vendored `libprotoident`, expected JSON, or PCAP
  files into this repository;
- enabling any real provider by default in host, Android, Root, or VPN runtime;
- shipping Android artifacts that link the chosen provider;
- importing corpus fixtures as redistributable repo assets;
- treating selected reference PCAP smoke as full corpus accuracy;
- mapping or persisting fork-local numeric AppIDs as Sakamoto catalog IDs;
- starting ProtocolRule enforcement or product UI commitments based on provider
  results.

## Exact Decision Questions

1. Which provider source is authoritative for S61: backup VPP wrapper plus
   vendored `libprotoident`, reference-only lineage with a new provider source,
   or an external/curated package?
2. If the backup wrapper is used, is `stellar_lpi_extend` included as-is,
   trimmed, or replaced by Sakamoto-owned normalization?
3. Is LGPL-3.0-or-later acceptable for the Android distribution model, and if
   yes, what exact source/relink/notice/release obligations must the build and
   release process satisfy?
4. Is the provider linked statically, dynamically, or kept as a separately
   packaged component?
5. What exact source pin is required: repository URL/path, revision/checksum,
   source archive checksum, and expected local file manifest?
6. Which license, NOTICE, provenance, and privacy files must exist in the repo
   before source or fixture import?
7. May any reference PCAP or expected JSON be copied, or must initial fixtures
   be reduced/synthetic/anonymized?
8. What is the minimum corpus baseline for first real-provider acceptance:
   DNS, HTTP, TLS/SSL, QUIC, SSH, unmapped, no-result, and compound behavior?
9. What Android ABIs and API levels must the provider build support before
   runtime wiring?
10. What warning policy applies to third-party provider source in host and NDK
    builds?
11. What provider build flag name and default-off behavior should be locked by
    tests?
12. What Root/VPN device evidence is required before the provider can be
    enabled outside host tests?
13. What evidence is required before any ProtocolRule enforcement work begins?
