# SAKAMOTO-138 / A1 UID attribution contract execution journal

Date: 2026-08-23 (Asia/Taipei)  
Plane: SAKAMOTO-138  
Campaign parent: SAKAMOTO-137  
Evidence level: deterministic Host/model; no Android or Pixel execution

## Registered question and baseline

Can a UID fact provider represent miss, completion, cache hit, refresh/expiry,
reverse lookup, and failure without waiting on the canonical FlowOwner or
changing the direction-independent canonical flow owner?

Working assumption: FlowOwner selection happens first from the canonical
five-tuple. UID is an asynchronous policy/provenance fact. Requests and cache
entries carry owner, flow, generation, network epoch, and app epoch; invalid
or late completions are rejected without changing live flow ownership.

The interruption condition is a valid finding that the required identity can
only be obtained by blocking owner execution or changing an existing flow's
owner. Ordinary model or harness defects are corrected and rerun.

## Artifact and provenance

- Prototype source: `prototypes/uid_attribution_contract/model.py`
- Runner: `prototypes/uid_attribution_contract/runner.py`
- One-command entry point: `make uid-attribution-contract-poc`
- Raw artifact: `prototypes/uid_attribution_contract/artifacts/uid-attribution-contract-host-model.json`
- Schema: `uid-attribution-contract-evidence/v1`
- Artifact records Git/source/runner SHA-256, Python/platform provenance,
  per-cell raw histories, live-resource accounting, claims, non-claims, and
  corrections.

## Execution

Command:

```sh
rtk make -C experiments/vpp-nfq-poc uid-attribution-contract-poc
```

Result:

```text
UID attribution contract PROTOTYPE: PASS pass=6 fail=0 invalid=0
PASS A1-miss-completion-hit-reverse
PASS A1-concurrent-misses
PASS A1-refresh-expiry
PASS A1-completion-identity-faults
PASS A1-unavailable-queue-full
PASS A1-bounds-zero-residue-teardown
```

The independent audit reran the same target and additionally checked that
wrong-owner, wrong-generation, wrong-flow/key, wrong-network/app-scope,
duplicate, and stale completions leave live flow identity, UID, owner,
pending requests, and cache state unchanged.

## Cell evidence

| Cell | Result | Evidence meaning |
| --- | --- | --- |
| `A1-miss-completion-hit-reverse` | PASS | Miss submits without owner wait; completion becomes a hit; reverse packet reuses the flow and owner. |
| `A1-concurrent-misses` | PASS | Distinct pending requests remain isolated; same-flow lookup coalesces; owner sentinel continues. |
| `A1-refresh-expiry` | PASS | TTL expiry and app/network/generation scope changes reject old identity and require a fresh request. |
| `A1-completion-identity-faults` | PASS | Wrong owner/generation/flow scope, duplicate, and stale completions are rejected without live-state mutation. |
| `A1-unavailable-queue-full` | PASS | Provider unavailability and bounded queue-full are explicit nonblocking outcomes; retry works after capacity returns. |
| `A1-bounds-zero-residue-teardown` | PASS | Pending/cache high-water stays within configured bounds; eviction and teardown settle to residue zero; late completion is stale. |

## Corrections

Two ordinary harness corrections were recorded and rerun in the raw artifact:

1. A duplicate `_record` keyword made the initial runner invalid; the owner
   turn fact was renamed and all cells reran.
2. Initial identity cells did not assert rejection invariance and the model
   accepted forged flow/scope fields. The runner now snapshots live identity
   around rejected completions, and the model validates flow/key plus
   network/app scope before acceptance. Generation-restart assertions were
   added. Architecture impact: none.

## Supported claim

The deterministic Host/model contract supports a bounded asynchronous UID fact
provider: owner turns continue during misses; reverse traffic preserves the
canonical owner; scoped refresh/expiry prevents stale identity; invalid
completions cannot mutate a live flow; and live flows, pending requests, and
cache entries settle to zero at teardown.

## Non-claims and finding linkage

This does not prove Android `ConnectivityManager` timing or real App UID
correctness, Pixel/arm64 behavior, VpnService/TUN/VPP integration, full policy
path behavior, production queue/cache capacities, or OEM compatibility. It
does not close A2 or later campaign batches.

The evidence updates the follow-up record for `VPN-F026` and supports the
Host/model portions of EG-08/EG-09. `VPN-F026` remains Pixel `OPEN_RISK`, and
EG-09 remains `INSUFFICIENT_EVIDENCE` until the later Pixel work proves the
Android side of the contract.

## Decision

`A1_HOST_MODEL_CONTRACT_GO`; `architecture_interruption=false`.

The native blocker frontier can expose SAKAMOTO-139 only after the Plane
acceptance evidence and tracker state are updated. No production code or
Android/Pixel conclusion is inferred from this journal.
