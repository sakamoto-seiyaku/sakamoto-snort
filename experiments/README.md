# Experiment and POC map

Organized 2026-09-13, SAKAMOTO-250. Product implementation is under
[`src/product/`](../src/product/) and [current mainline](../docs/current/README.md).
No directory here is a Product implementation template, compatibility fallback
or default acceptance target. Task state belongs to Plane.

| Material | Classification / use |
| --- | --- |
| [VPP/NFQUEUE campaign](vpp-nfq-poc/README.md) | Historical C/VPP, TUN, Android and owner-inline experiments; source and evidence retained in place |
| [S245/S246 copy experiment](vpp-nfq-poc/s245-s246/README.md) | Frozen single-owner UDP4 registration, artifacts and bounded observations; not Product or general zero-copy evidence |
| [S247 resource experiment](vpp-nfq-poc/s247/README.md) | Frozen pbuf/buffer/credit characterization; controlled cells remain labelled separately |
| [Handcrafted Direct bridge](handcrafted-direct-bridge/README.md) | Already isolated by S200; no HEV/lwIP Product readiness and no enabled Product entry |
| [Protocol identification tools](../tools/protocol_identification/README.md) | External inventories/third-party probes versus retired C++-dependent entrypoints |
| [T20 observation IPC comparison](t20-observation-ipc/README.md) | Pinned C/Rust Host and Android transport measurements; selection gate in Plane, not Product integration |

## Complete directory inventory

[`catalog.json`](catalog.json) classifies every tracked file under `experiments/`
and `tools/protocol_identification/`. It covers the intake's 528 experiment files
and 12 reference tools, plus this organization metadata. The Host catalog check
rejects a new unclassified path and verifies known retained references and retired
entrypoints. Classification is not a claim that every historical command was rerun.

The campaign map below that root separates source/overlays, patch lineage, clients,
Android shells, model/litmus prototypes, scripts/tests, registrations and raw records.
Those paths are retained because historical manifests and recipes may bind them.
Explicitly requesting a replay still requires checking its exact artifact, tool,
device and source prerequisites. Do not restore the removed C++ daemon/model.

## Local generated material

Ignored `build/`, `work/`, Android APK output, `runtime/`, `results/`, `evidence/`
and Python caches are not one disposable bucket. Some hold frozen source, installed
artifact identities, raw successful/failed runs or source checkouts. They remain
untouched. A cleanup that deletes them needs a separate, exact retention decision.
Directory classification here does not claim disk-cache purging.

All Android operations use [`dev/adb`](../dev/adb). Current Product tests start at
the [testing map](../docs/testing/README.md); no device operation or experiment
replay is part of this organization pass.
