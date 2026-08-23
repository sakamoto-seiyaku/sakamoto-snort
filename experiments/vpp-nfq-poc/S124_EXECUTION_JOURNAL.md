# S124 execution journal

> Chronological raw ledger for the real `VpnService` TUN path. Reviewable
> conclusions are in `S124_REAL_TUN_MEMO.md`; this file keeps observations and
> command-shaped facts only.

## 2026-08-21

- Target device: serial `28201JEGR0XPAJ`, product `bluejay`, model `Pixel 6a`,
  build `google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`.
- Test-only APK modes were added for `vpp-hev-tun-single` (one worker) and
  `vpp-hev-tun-multi` (two workers). The APK calls `VpnService.prepare()` and
  `VpnService.establish()`; the TUN fd is passed to the VPP plugin as fd 3.
- First controlled single-worker run: UDP, 20 packets, 33-byte payload;
  application log reported `sent=20 received=20 elapsedMs=20305`.
  `show s124-vpn-tun` ended with ingress `29/1764`, worker `20/1220`, submit
  `20/1220`, output `20/1220`, errors `0`, output-errors `0`, parse-errors `9`,
  congestion-drops `0`.
- Single-worker UDP owner 0 reported 20 packets/1220 bytes;
  `submit-copy-bytes=1220`, `udp-copy-bytes=660`.
- Single-worker TCP run: five 33-byte echo writes; application log reported
  `sent=5 received=5 elapsedMs=11412`. The owner reported
  `tcp-write-calls=5`, `tcp-write-bytes=165`, with no submit or output errors.
- A run without the app-only package filter observed `congestion-drops=37`.
  The same path with `allowedPackage=com.sakamoto.snort.vpnlite` was used for
  the controlled measurements below.
- Initial two-worker startup showed `vpp_main` on core 0, `vpp_wk_0` on core 1,
  and `vpp_wk_1` on core 2. Owner 0 and owner 1 were created lazily on their
  respective worker callbacks.

## 2026-08-21/22: UDP flow spread

- With two workers and the original temporary HEV owner-context session array
  (`FLOW_STACK_OWNER_MAX_SESSIONS=8`), UDP flow probe results were:
  - 1 flow: `20/20` echo packets;
  - 8 flows: `8/8` echo packets;
  - 32 flows: `7/32` echo packets, `errors=25`.
- The 32-flow failure was followed to the temporary HEV owner-context bound,
  not to the VPP worker hash: the flow owner had eight session slots per
  owner. The test-only bound was raised to 64 and rebuilt.
- Rebuilt HEV hash for the expanded flow-session bound:
  `bf1a95ea2d3048962e1061c55658b495253a8e85b33c447d0ed026b3c9e987ee`.
- On the same Pixel and two-worker path, UDP 32 flows then reported
  `sent=32 received=32 errors=0 elapsedMs=53916`. Counters ended at ingress
  `42/2544`, worker `32/1952`, submit `32/1952`, output `32/1952`, errors `0`,
  output-errors `0`, parse-errors `10`, congestion-drops `0`.
- The two owners handled 17 and 15 packets respectively (1037 and 915 bytes);
  no owner mismatch or owner-start error was reported.

## 2026-08-21/22: TCP flow spread and temporary pool expansion

- Before expanding the owner-context TCP pools, two workers accepted only four
  TCP data flows. The application reported `flows=8 sent=4 received=4 errors=4`;
  the owner-context source showed `OWNER_TCP_PCB_POOL_COUNT=2U` per owner.
- For this POC only, the HEV owner-context pools were expanded to
  `TCP_PCB=64`, `TCP_SEG=128`, `PBUF=64`, and `PBUF_PAYLOAD=64`; the flow owner
  session bound remained 64. The reproducible diff is
  `patches/hev-poc6-owner-context-capacity.patch`.
- Final APK hash:
  `189e4c9c6ffce0e71fb56b0826ce6e479780e523138b243551deeed6784d0ddf`.
  Final POC-6 plugin hash:
  `8b8e76a69e07f9727618c08339bc9c09f25cfc9ff687cb69e9c8d7da6fabac56`.
  Final HEV hash:
  `fb9ce1c888ce52fd5f984396770514a133843f3f80062777995cfd0b819e6235`.
- Final two-worker TCP 8-flow probe, 33-byte payload:
  `flows=8 sent=8 received=8 errors=0 elapsedMs=31784`.
  Counters: ingress `82/4056`, worker `72/3464`, submit `72/3464`, output
  `16/936`, errors `0`, output-errors `0`, parse-errors `10`,
  congestion-drops `0`. TCP write calls were 3 on owner 0 and 5 on owner 1.
- Final two-worker TCP 32-flow probe, 33-byte payload:
  `flows=32 sent=32 received=32 errors=0 elapsedMs=126871`.
  Counters: ingress `410/19500`, worker `398/18820`, submit `398/18860`,
  output `80/4680`, errors `0`, output-errors `0`, parse-errors `11`,
  congestion-drops `0`, owner-mismatch `0`. TCP write calls were 17 on owner
  0 and 23 on owner 1; owner packet totals were 169 and 230.

## POC-5 formal run cross-reference

- The separate POC-5 formal directory is
  `results/s123/20260821-pixel6a-formal/`.
- It contains 288 measurement raw files (96 cells × 3 repeats); all 288 cells
  ended `result=PASS`. The formal run used the POC-5 HEV/plugin hashes recorded
  in `results/s123/20260821-pixel6a-formal/device-metadata.raw` and is not
  silently mixed with the later POC-6 owner-pool rebuild.
