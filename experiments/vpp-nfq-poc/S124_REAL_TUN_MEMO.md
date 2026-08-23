# S124 real-TUN memo

## Bottom line

The real Android VPN path is viable as a test-only VPP plugin: `VpnService`
TUN fd → VPP main read callback → worker-local queue → worker-local HEV/lwIP
owner → the same TUN fd completed UDP and TCP echo on the Pixel 6a. Two workers
also kept flow ownership local and split the final 32-flow UDP/TCP runs across
both owners without mismatch, submit errors, output errors, or controlled-run
congestion drops.

This is a correctness and ownership result, not yet a production performance
claim. The app flow probe opens/tears down flows sequentially, so its elapsed
time includes Android socket setup and timeout behavior.

## What the data says

- Single-worker UDP and TCP are byte-correct with zero submit/output errors.
- With two workers, UDP 32 flows completed `32/32`; the final owner split was
  17/15. TCP 8 and 32 flows completed `8/8` and `32/32`; the 32-flow owner
  packet split was 169/230, with TCP write calls 17/23.
- The original 32-flow UDP failure (`7/32`) and four-flow TCP ceiling were
  reproducible temporary HEV owner-context limits: eight flow slots and two
  TCP PCBs per owner. Expanding the test-only pools removed both ceilings. This
  is a discovery about the current owner-context implementation and its
  resource configuration, not evidence that VPP needs a different worker
  model.
- A background-traffic run produced 37 queue congestion drops. The controlled
  app-only runs produced zero; queue capacity/back-pressure remains a design
  item for a later stress POC.
- The final S124 HEV build is deliberately different from the S123 formal
  cost run because it contains the owner-context capacity expansion. S123's
  copy percentages remain the packet-path baseline; S124 is the real-TUN
  correctness/ownership baseline.

## Relation to the copy question

S124 still performs the expected boundary copies: VPP buffer into an HEV/lwIP
submit pbuf, and HEV/lwIP output into an output buffer before writing TUN. The
owner perf counters report those copy bytes and nanoseconds, but S124 was not
designed to isolate all Android TUN/kernel copies. Therefore it does not justify
zero-copy work by itself.

The paired S123 formal matrix is the cost evidence: all 288 measurement files
passed. On p33/burst32, the median measured HEV copy components were about
2.70 ms of 62.9 ms for full UDP (4.3%), and 7.75 ms of 42.6 ms for full TCP
(18.2%) at low load; high-load shares were lower (about 1.9% UDP and 9.7% TCP).
Those numbers cover instrumented HEV copy components, not every VPP/TUN copy.

## Decision and next POC

Do not change production lwIP ownership, introduce zero-copy, or freeze a
multi-worker API from S123/S124 alone. The next bounded POC should hold the
successful S124 owner/worker seam fixed and measure the real VPN path under
concurrent (not sequential) flow generation: UDP/TCP 1/8/32 flows, payloads
33/512/1400, burst 1/32, with per-worker queue depth, drops, CPU/RSS/thermal,
and simpleperf samples. Keep the expanded HEV pools as explicit test
parameters, and add close/reuse coverage so session lifetime is measured rather
than hidden by process restarts.
