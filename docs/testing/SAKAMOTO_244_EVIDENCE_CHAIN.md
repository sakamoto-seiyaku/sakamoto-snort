# S244 evidence-chain acceptance

2026-09-08: **PASS**. No product dataplane change. A fresh Product build and a new actual Pixel NFQUEUE matrix supplied the positive control; seven independently corrupted local evidence sets were rejected.

## Positive evidence

- Request: `build-output/s244-chain/request-b.json`; result: `positive-b.json`; raw device run: `pixel-b/`.
- Real Pixel 6a `28201JEGR0XPAJ`, Android 16/kernel 6.1.134; Root single NFQUEUE lane/queue 176, actual VPP worker 0/thread 1, IPv4 UDP with controlled shell-UID loopback endpoint.
- Generations 640/641: allow, explicit Gate DROP, reopen/recovery, deliberately unsupported remote rejection, restart allow. Exact native node/counter, packet/generation, verdict/free and endpoint correlation; both stops clean.
- Fresh APK SHA256 `b51064493b8a298ad2d4fdeef52f51a0855f2a652accdb1d53ae22988a471cc5`; all installed native files match its entries. The installed APK itself was additionally hashed after clean stop at the unchanged package path (explicit timing in `installed-apk-capture.json`); future runner executions capture this before startup.
- Build witness `build-output/s244-chain/build/build.json`; source SHA256 `defa03e7c7a0c75450d4148a49870a642b4409ef31f5f150e78550fdc0ffbf2e`; commit/dirty diff, exact source snapshot, stage/build logs and actual binary hashes retained beside it. The validator compares every source file against both snapshot and current source, and rejects source drift.

The first `pixel/` attempt remains HOLD because its allow-case status file was stale even though final totals were correct. The collector now waits for each case's generated-VAPI verdict count/generation before capturing it. Acceptance was not weakened.

## Required and additional negative controls

`build-output/s244-chain/negatives/results.json` records all seven as REJECTED with the expected reason:

| Corruption | Required rejection |
| --- | --- |
| Old/wrong APK hash | Artifact differs from fresh build witness |
| Old run with the same APK | Nonces predate this request; stale per-case evidence |
| Missing real admit node | Native node/settlement sequence incomplete |
| POC readiness | Does not match the implemented Product Adapter scope |
| GRAPH_INJECTED relabelled as wire evidence | Capture source mismatch |
| Old node generation mixed into a new run | Trace not bound to runtime/NFQUEUE generation |
| Broader owner declaration | Claim exceeds the accepted owner-local scope |

Checks compare actual VLIB calls/vectors on the recorded worker, not just token/file presence. The matcher also requires unchanged buffer/obligation identity, exact origin-lane verdict/return counts, no fail-open/duplicate/stale/remote completion, per-case endpoint results and zero stop residue. Host and graph injection cannot replace NFQUEUE capture.

Implementation/replay: `tests/evidence/product_chain.py`, `tests/evidence/test_product_chain_negatives.py`, `tests/evidence/README.md`, and the bounded device collector/packet verifier under `tests/device/`. Final verifier hashes are in `positive-b.json`.

This establishes an executable evidence chain for the implemented UDP4 Root slice. It is not cryptographic remote attestation, nor evidence of TCP/IPv6, product VPN, lwIP, reassembly, FlowEntry, cross-worker completion, capacity or release readiness. Later source changes require new build/run witnesses and appropriate slice-specific facts.
