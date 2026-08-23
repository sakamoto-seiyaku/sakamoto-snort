# PROTOTYPE — A1 nonblocking UID attribution contract

This is throwaway Host/model evidence for **SAKAMOTO-138**. It does not call
Android, VPP, a socket, or Plane, and it is not production implementation.

## Question and baseline

Can an asynchronous UID fact provider represent `miss → completion → hit`,
refresh/expiry, reverse lookup, and failure without waiting on the canonical
FlowOwner or changing the direction-independent five-tuple owner? The model
keeps UID outside `CanonicalFlowKey`, scopes every request/cache entry by
generation + network epoch + app epoch, and gives every completion an owner
identity.

The registered interruption condition is reached only if a required identity
cannot be obtained without blocking owner execution or changing existing-flow
ownership. Ordinary model/harness defects are corrected and rerun; they do not
reopen the owner-inline baseline.

## Run

From `experiments/vpp-nfq-poc`:

```sh
make uid-attribution-contract-poc
```

Equivalent direct command:

```sh
python3 prototypes/uid_attribution_contract/runner.py
```

The optional hand-driven state view is:

```sh
python3 prototypes/uid_attribution_contract/runner.py --interactive
```

The interactive shell clears and renders the complete relevant state after
each action. Commands include `open`, `lookup`, `complete`, `tick`,
`refresh-app`, `refresh-network`, `restart`, `stop`, and `quit`.

## Registered cells

| Cell | Evidence exercised |
| --- | --- |
| `A1-miss-completion-hit-reverse` | miss/completion/hit, reverse-direction reuse, UID-independent owner |
| `A1-concurrent-misses` | distinct concurrent misses, same-flow coalescing, sentinel progress, no cross-cache hit |
| `A1-refresh-expiry` | TTL expiry, app refresh, network refresh, stale old completion |
| `A1-completion-identity-faults` | duplicate, stale, wrong-owner, wrong-generation completion rejection |
| `A1-unavailable-queue-full` | provider unavailable and bounded pending queue-full outcomes |
| `A1-bounds-zero-residue-teardown` | bounded pending/cache high water, cache eviction, late completion, zero-residue teardown |

## Raw artifact and provenance

The checked-in raw ledger is:

`artifacts/uid-attribution-contract-host-model.json`

It records schema version, source/runner SHA-256, Git head, Python/platform
provenance, every cell result, every model action history, final state, live
request/cache bounds, cleanup state, and the registered falsifiers. The model's
`request_archive` is audit history; `live_resources` is the runtime resource
accounting used for the bounded-queue and zero-residue claims.

The current run result is `PASS` for all six cells. Two bounded POC
Corrections are recorded in the artifact and were rerun: the initial runner
instrumentation collision (`_record` received a duplicate keyword), and a
completion-scope/rejection-invariance correction. The latter made the harness
  snapshot live flow/UID/owner/pending/cache state around rejected
  wrong-owner, wrong-generation, duplicate, stale, and wrong-network/app-scope
completions, and made the model validate flow/key plus network/app scope before
accepting a pending result. Neither correction changes the owner-inline
architecture baseline.

The artifact links this evidence to Plane `SAKAMOTO-138`, campaign gaps
`EG-08`/`EG-09`, and `VPN-F026`. `VPN-F026` remains an open Pixel finding;
this Host/model POC does not close Android UID correctness or timing.

## Supported claim

Within this deterministic in-memory contract, UID attribution can be an
asynchronous, bounded fact provider: owner turns continue during misses,
reverse packets reuse the same canonical owner, scoped refresh/expiry prevents
stale identity, invalid completions cannot mutate a live flow, and teardown
settles live flows, pending requests, and cache entries to zero.

## Non-claims

- No real Android `ConnectivityManager` timing or App UID correctness.
- No Pixel/arm64, `VpnService`/TUN, VPP, transport, or full policy-path result.
- No production queue/cache capacity, TTL, persistence, multi-user, or OEM claim.
- No assertion that this Python class or its field names are the production ABI.

The model therefore supports A1's Host/model contract question only. It does
not close A2 or any later Pixel/network POC.
