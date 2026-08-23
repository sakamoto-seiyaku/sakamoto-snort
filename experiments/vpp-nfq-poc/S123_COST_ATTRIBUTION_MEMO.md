# S123 cost-attribution memo

## What this memo records

This is the review memo for POC-5. It is not a command transcript; raw facts
and individual samples remain in `S123_EXECUTION_JOURNAL.md` and
`results/s123/`.

## Current status

The real-device pilot and formal matrix are complete. The formal run contains
288 measurement files (96 cells: four arms × two protocols × three payloads ×
two bursts × two loads × three repeats); all 288 ended `result=PASS` on the
Pixel 6a.

## What the pilot already establishes

- The four test arms can be compared on the same arm64 device and the same
  VPP worker. `full` and `prebuilt` exercise the HEV/lwIP boundary; `builder`
  and `memcpy` are control arms.
- The complete UDP path reports two byte-for-byte copy counters, and the TCP
  path reports the extra handshake and `tcp_write(...COPY)` work. Those are
  measurement seams, not a claim that either copy is the dominant bottleneck.
- The first TCP prebuilt checksum defect was exposed by a real-device failure
  and fixed before collecting the passing rerun. This is a correctness risk to
  keep covered in the formal matrix.
- For the p33/burst32 low-load cells, median instrumented HEV copy components
  were approximately 2.70 ms of 62.9 ms for full UDP (4.3%) and 7.75 ms of
  42.6 ms for full TCP (18.2%). At high load the corresponding shares were
  approximately 1.9% and 9.7%. These are HEV component timings, not a complete
  VPP/TUN/kernel copy budget.

## Decision boundary

Do not change lwIP ownership or add zero-copy from this data alone. The formal
matrix makes the copy share measurable, but a production decision still needs
simpleperf/resource samples and the real-TUN concurrency data in S124. Compare
copy share against builder, allocator, protocol-stack, and queue/wakeup shares;
if copy remains a small on-device share, deprioritize zero-copy work.

## Review points

- Preserve the same Pixel/build/plugin/HEV hashes and CPU affinity for every
  arm and protocol.
- Keep instrumentation overhead visible; use batch-boundary timing and
  simpleperf samples to cross-check it.
- Treat TCP handshake bytes and setup time separately from steady-state data.
- POC-6 is a separate correctness/scale test: real TUN ingress/egress,
  single-owner baseline, then flow-hash assignment to independent worker-local
  owners. It must not silently reuse the synthetic S122 trigger as evidence.
