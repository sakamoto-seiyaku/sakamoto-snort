# SAKAMOTO-122 Packet-Path Performance Memo

## Decision status

The real-device evidence is complete; the Plane item remains `In Progress`
until the design decision is accepted. This POC does not authorize production
zero-copy, lwIP, or multi-worker changes.

This run covers the deterministic single-worker echo baseline. It does not yet
cover three repeats, a separate warm-up per matrix cell, multi-connection TCP,
or a real VPN/TUN endpoint; those are follow-up measurements if the baseline is
accepted for deeper optimization work.

## Conclusion

On the Pixel 6a, the two-boundary-copy UDP/TCP path is stable and measurable,
but the data does not show that the copies are the only, or even the dominant,
cost in this fixture. The right next move is whole-path instrumentation and
optimization, not freezing a zero-copy design from this result alone.

## Evidence

- 32 final matrix cases passed on the real device: 16 UDP + 16 TCP. No packet
  loss, counter mismatch, or queue error was observed.
- For UDP, copy A and B exactly matched the packet length per packet. At
  payload 1400 this was 1428 bytes × 100,000 packets = 142,800,000 bytes in
  each direction.
- For TCP, the data path copies matched the full packet length; the fixed SYN,
  SYN/ACK, and ACK handshake accounts for the small A/B difference. The test
  SYN advertises MSS 1460 so the 1400-byte fixture remains one lwIP segment.
- All final callbacks ran on the same VPP worker thread for setup, receive, and
  output. The recorded process had two threads, with main/core 0 and worker/core
  1.
- In the p1400, 100k comparison, burst 1 → burst 32 reduced elapsed time from
  2.978 s to 1.703 s for UDP and from 4.135 s to 1.732 s for TCP, while the
  boundary-copy byte counts stayed the same. This is a batching/scheduler
  signal, not a copy reduction.
- RSS stayed around 157.9 MiB with HWM around 159.6 MiB in the corrected TCP
  resource run; Android reported thermal status 0 during the sample window.

## Profile reading

- UDP simpleperf: 54,485 samples, 0 lost. Self time included the plugin worker
  node (55.58%), libc `memmove` (8.95%), and `clock_gettime` (3.84%).
- TCP simpleperf: 60,027 samples, 0 lost. Self time included libc `memmove`
  (10.44%), but the synthetic `s122_build_tcp_packet` fixture alone was
  49.06%.
- Therefore the profiles demonstrate that copying is visible, while also
  demonstrating that packet construction, checksum/stack work, batching, and
  the POC's per-stage timing contribute materially. The TCP flamegraph must not
  be read as a production lwIP/VPP cost breakdown because its packet builder is
  test-only.

## What the copy counters do and do not mean

The ledger counts only the two explicit ownership-boundary copies:

1. VPP ingress buffer into the lwIP-facing `pbuf` input.
2. lwIP/netif output into a VPP-owned output buffer.

It does not claim that lwIP internals, checksums, allocator bookkeeping, or
other stack operations perform no additional memory movement. Conversely, the
counter equality proves that the intended boundary copies happened for every
packet in the final runs; it is not a proof that those copies are the global
performance bottleneck.

## Design decision for the next step

Keep the current two-copy architecture as the measurement baseline. Before
touching production lwIP/VPP ownership rules, run a follow-up measurement that:

1. separates synthetic packet construction/checksum time from submit/receive/
   output timing (prebuilt packets or an explicit `build-ns` counter);
2. measures allocation/free and pbuf-chain behavior separately from the two
   boundary copies; and
3. compares burst/queue sizes under the same payload and protocol mix.

Only after that comparison should we decide whether a copy-specific optimization
or a deeper ownership redesign pays for its complexity. The current TCP API and
the foreign-thread HEV safety change are test-only POC support, not production
interfaces.

## Review points

- The foreign VPP worker must not call HEV task-system TLS helpers from the
  synchronous netif-output boundary; the Android crash established this as a
  safety constraint for the POC integration.
- The TCP fixture uses `TCP_WRITE_FLAG_COPY` and a single-segment MSS setup;
  this validates the selected path, not general zero-copy or arbitrary chained
  `pbuf` behavior.
- Raw chronological evidence is in `S122_EXECUTION_JOURNAL.md` and the result
  directories under `results/s122/`.
