# S123 execution journal

> This file is a chronological raw ledger. Interpretation belongs in
> `S123_COST_ATTRIBUTION_MEMO.md`.

## 2026-08-21

- Target: Pixel 6a, serial `28201JEGR0XPAJ`, product `bluejay`, Android
  `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`.
- VPP startup: PID `15426`; `vpp_main` on core 0 and `vpp_wk_0` on core 1;
  `/proc/15426/status` reported two threads.
- HEV library on device:
  `/data/local/tmp/s122-vpp/lib/libhev-socks5-tunnel.so`;
  SHA-256 `7629f5c3c157510d2c8e3b446aadde5f3b106d3dcec833e3f657cf6cb5ce554b`.
- VPP plugin on device:
  `/data/local/tmp/s122-vpp/plugins/hev_external_driver_poc_plugin.so`;
  SHA-256 `56b4ef8ce2a4528c01e16601dba2560d6b13b3c19f3bb20f8b1f139874c6b430`.
- The HEV test-only symbol `flow_stack_owner_perf_metrics` was present in
  the staged arm64 library.
- A first TCP `prebuilt` trial failed after the first packet because the
  incremental checksum replacement used an integer-promotion-sensitive
  expression. The run was stopped, the expression was corrected, the
  arm64 plugin was rebuilt and redeployed, and the same TCP trial was rerun.
- Pilot command shape: `s122-packet-path-perf run arm <arm> protocol <udp|tcp>
  target-thread 1 payload 33 count 1000 burst 32`.
- Pilot result directory:
  `results/s123/20260821-pixel6a-smoke/`.
- Pilot cells present: UDP/TCP × `full`, `prebuilt`, `builder`, `memcpy`;
  each low-load cell had one 1000-packet measurement and independent warmup
  runs. All eight measurement cells ended with `result=PASS`.
- Final pilot raw files:
  - `full-udp-p33-low-r1.raw`: 1000/1000 UDP echo, copies `61000/61000`,
    elapsed sample `6376791 ns`.
  - `prebuilt-udp-p33-low-r1.raw`: 1000/1000 UDP echo, copies `61000/61000`,
    elapsed sample `3566569 ns`.
  - `builder-udp-p33-low-r1.raw`: builder-only 1000/1000, `build-ns=409931`.
  - `memcpy-udp-p33-low-r1.raw`: copy-only 61000 bytes, `memcpy-ns=76464`.
  - `full-tcp-p33-low-r1.raw`: handshake 2, data 1000, echo 1000,
    copies `73084/73044`, elapsed sample `5838501 ns`.
  - `prebuilt-tcp-p33-low-r1.raw`: handshake 2, data 1000, echo 1000,
    copies `73084/73044`, elapsed sample `4892863 ns`.
  - `builder-tcp-p33-low-r1.raw`: builder-only 1000/1000,
    `build-ns=338055`.
  - `memcpy-tcp-p33-low-r1.raw`: copy-only 73000 bytes,
    `memcpy-ns=8138`.
- The runner wrote raw `show s122-packet-path-perf` output and VPP stdout tails
  into every file; no raw file is treated as a memo.

## Formal matrix completion

- Formal result directory:
  `results/s123/20260821-pixel6a-formal/`.
- Matrix shape: four arms × two protocols × three payloads × two bursts × two
  loads × three repeats = 288 measurement raw files (96 cells).
- Every measurement file ended `result=PASS`; no measurement cell reported a
  submit, echo, output, or queue error.
- The formal run used low count 10,000, high count 1,000,000, ten-second
  warmup, payloads 33/512/1400, bursts 1/32, and the Pixel/thread metadata in
  `device-metadata.raw`. Detailed interpretation is in
  `S123_COST_ATTRIBUTION_MEMO.md`.
