# SAKAMOTO-130 OI-5 execution journal

Date: 2026-08-23 (host Linux, x86_64; Pixel 6a controlled OI-5 rerun)

OI-5 asks whether stop/restart identity is generation/epoch safe: runnable and
waiting owners, established/FIN TCP, active UDP timers, broker/output/TUN late
events, and one bounded restart must release every socket/PCB/timer/buffer while
preventing old TCP reconnect or old UDP reuse.

## Deterministic generation/epoch model

```text
model source  c082a28287a5f70747922f4ada75fc251ffeedc745c2a80fb1c77bef230d37d2
model output  /tmp/s130-oi5-model-current.json
model JSON SHA-256 69ff1dd1a85cf33bffbc6204a1c7ac82ea3e73ad0c2dbbafbdbe31466fe81839
```

The model passed five cells:

| Cell | Evidence |
| --- | --- |
| `stop_matrix` | generation/epoch `1/1 -> 2/2`; RUNNABLE/WAITING late wake, timer, fd wake, stale, broker, duplicate broker, output, and TUN events rejected (`8`); established TCP, FIN_WAIT TCP, and active UDP all have socket/PCB/timer/buffer/lease `0`; old TCP/UDP reconnect/reuse `0` (one attempted each); residue `0`. |
| `restart_generation` | old generation `1/1` is dead; stale broker rejected; fresh session runs at `2/2`; bounded second stop ends `3/3`; old TCP reconnect `0` (one attempted); residue `0`. History records `open -> stop -> generation advance -> restart -> stop`. |
| `underlay_epoch_invalidation` | old TCP becomes `TERMINATED`, old UDP mapping becomes `MAPPING_INVALIDATED` at `e1 -> e2`; fresh flow snapshots `e2`; stale duplicate-broker rejected; old UDP reuse `0`; final stop settles all resources. |
| `fault_restart` | forced Flow Stack fault, one bounded stop/restart, fresh generation-2 flow succeeds, second stop ends `3/3`; exact resource ledgers settle. |
| `two_shard_teardown` | both owners independently advance `1/1 -> 2/2`, reject all eight late-event kinds, and release TCP/UDP ledgers with residue `0`. |

The model's evidence includes the stop/restart history, explicit
quiesce→drain→close→settle phases with bounded deadlines, session
socket/PCB/timer/PacketLease/pbuf/VPP-buffer/socket-request/output state,
late-event counters, underlay epoch snapshots, and attempted-versus-actual old
reuse counters.  Every resource is reported allocated/released exactly once.
It intentionally does not model unbounded soak or release capacity.

## Real same-process bounded restart

`/tmp/s130_oi5_host_restart.py` ran one two-worker VPP process, first UDP4 and
then TCP4, letting the first generation finish before queueing the second.  Raw
stdout is `/tmp/s130-oi5-host-stdout-current.txt` (SHA-256
`7ab6d2c735fdb7b2fdd41dfb06956a94e354e7b39f0b39100547d05c93595f2b`); the
owner-thread console is `/tmp/sakamoto-vpp-nfq-poc/s130-oi5-host-console.log`
(SHA-256 `c043b281f594ec64d46bff9d7446ab28e1af2572e3987aa4260c046ee28ce475`).

```text
generation=1 UDP4: state=DONE steps=143 packets=1 output=1 direct=1 rewritten=1
endpoint=1/1 broker bind/protect=1/1 duplicate-close=1 buffers=144/144 residue=0

generation=2 TCP4: state=DONE steps=162 packets=4 output=2 handshake=1 direct=2 rewritten=2
endpoint=1/1 accepted=1 broker bind/protect=1/1 duplicate-close=1 buffers=307/307 residue=0
```

The raw owner trace shows generation-1 cleanup PASS, then a new generation-2
owner request and cleanup PASS in the same VPP process.  Both direct flows were
on the owner pthread; the second exercised nonblocking TCP connect, direct
send/receive, handshake, payload, and FIN.  Neither generation left VPP buffer
residue.

The current `show sakamoto-oi3` counters are UDP4
`steps=143 ... buffers=144/144 residue=0` and TCP4
`steps=162 ... buffers=307/307 residue=0`; the raw console records the same
generation-1 and generation-2 cleanup PASS lines.  The final `stop` command
reports “OI3 is not active” because both bounded cells had already settled.

## Real host fault → epoch → restart addendum

The plugin now exposes one explicitly bounded `sakamoto-oi3 fault` CLI seam;
it stops the active owner on its owner thread, marks the termination as an
injected fault, and leaves the normal generation gate in place for the next
run.  `oi5_host_fault_restart.py` exercised it with a generation-1 UDP
no-reply cell followed by a fresh generation-2 TCP4 cell:

```text
runner source  oi5_host_fault_restart.py
               SHA-256 6c1d7315cd5d53f9824025f6a52469c8acb09fe45eeda1f759d2d9415703ab93
runner stdout  /tmp/s130-oi5-fault-host-stdout-current.txt
               SHA-256 5500a53750f1bdf81133763c0231a2cfa64cfa6775d3b7c32b5d3eff01979694
owner console   /tmp/sakamoto-vpp-nfq-poc/s130-oi5-fault-console.log
               SHA-256 59d74ebda2114a9b372dfe156b04a80a10c52f64f8bbe4d4a956b1e722a47ae9
```

The raw owner ledger contains:

```text
fault-injected generation=1 epoch=1 action=bounded-stop-restart
cleanup PASS generation=1 epoch=1 fault-injected=1 buffers=2/2 residue=0
epoch-invalidated old-generation=1 old-epoch=1 new-generation=2 new-epoch=2
old-tcp-reconnect=0 old-udp-reuse=0
cleanup PASS generation=2 epoch=2 output=2 handshake=1 direct=2
endpoint=1/1 accepted=1 broker=1/1 duplicate-close=1 buffers=184/184 residue=0
```

The first cell is intentionally interrupted before a normal no-reply packet
completion; `fault-injected=1` makes that bounded termination expected rather
than an ordinary cell failure.  The second cell proves fresh TCP handshake,
payload, direct receive, and FIN cleanup after the epoch advance.  This is a
real host fault/restart and epoch ledger, not a Pixel claim; the model remains
the source for the complete late-event matrix and exact stale-token counters.

## Real Pixel 6a controlled stop/fault/restart/underlay sequence

The Android acceptance gap was closed with the same OI-2 POC VPP runtime and
the OI-3 plugin built from the source above.  The mode is deliberately
controlled: only `10.200.0.0/24` is routed, no default route is installed, the
underlay is loopback, and the app-owned monitor drives the VPP CLI in-process.
It does not read the TUN or redirect unrelated device traffic.

```text
device       Google Pixel 6a (serial 28201JEGR0XPAJ)
APK          experiments/vpp-nfq-poc/android/vpn-lite/build/outputs/
             snort-vpn-lite-debug.apk
APK SHA-256  956fcd3829fcffb747425079bc9bc5e983bdb3978c8a5cfd7caba9d7f68f6591
core         libvpppoc.so  fb2a39de91c84cf913c14417bdc5c8c2e48f95d1d88af7d3d61d17e1e32bfa08
plugin       hev_external_driver_poc_plugin.so
             2a4fa8ff8133032982b0d48f74ac816d2def349303451dba2d6fe83c4404535c
native probe vpn_fd_probe.c  fd4b0dab8a0cc7ed0fec525d975f0c90d815083cbf5e80d207fa198765e1e5d8
probe .so     libvpnfdprobe.so  c79182dfafd7532827bfef2dec3486a38ed1c668a8767097810f5345e9d84a28
HEV library   libhev-socks5-tunnel.so  fb9ce1c888ce52fd5f984396770514a133843f3f80062777995cfd0b819e6235
Java         SnortVpnService.java  9e2a213922bb133cbf475df1c1376f2d9e6ae21d4a71973f0d758f5dbf23f5d4
OI-3 source  overlay/work owner_inline_oi3.c
             de2d9f9904a4356e8a15b90e2119c6bf39fbe118638a89ae4bea8ab65c74151d
```

Raw files captured from the app-owned files directory are independently
hashable:

| Raw ledger | Path | SHA-256 |
| --- | --- | --- |
| Android runner + CLI snapshots | `/tmp/s130-oi5-android-cli-current.log` | `b7309d17dc06dd23a9a14928309ff80fa2150e843f9633509cc2d683bc15144f` |
| VPP owner stdout | `/tmp/s130-oi5-android-stdout-current.log` | `33e75c8dfec800a6d5b26d0c32a67fcd30970e79f80ffa282e5d90d2b0143214` |
| external broker requests/completions | `/tmp/s130-oi5-android-broker-current.log` | `ea2dcadded8da29069d09b03f658234a76f7a665b3ade38c3e68c02db310abd9` |
| VPP CLI command log | `/tmp/s130-oi5-android-vppcli-current.log` | `d912eee1ac8d0375ea3402101eb8a68534e6c17479930e5ea04890c1d9f007e3` |
| VPP runtime log | `/tmp/s130-oi5-android-vpp-current.log` | `53935c0059ea572ed6bc67e13d1e428de93ef9ae6d65bf65109177bb547c1cf9` |

The authoritative VPP cleanup lines are:

```text
normal stop       g1/e1 PASS EXPECTED_TIMEOUT endpoint=1/0 broker=1/1 buffers=122/122 residue=0
fault stop        g2/e2 PASS EXPECTED_TIMEOUT fault-injected=1 endpoint=0/0 broker=0/0 buffers=124/124 residue=0
restart TCP4      g3/e3 PASS EXPECTED_DIRECT_REPLY output=2 handshake=1 direct=2 rewritten=2 endpoint=1/1 broker=1/1 stale=1 buffers=179/179 residue=0
underlay old UDP  g4/e4 PASS EXPECTED_DIRECT_REPLY output=1 direct=1 rewritten=1 endpoint=1/1 broker=1/1 buffers=188/188 residue=0
underlay new TCP  g5/e5 PASS EXPECTED_DIRECT_REPLY output=2 handshake=1 direct=2 rewritten=2 endpoint=1/1 broker=1/1 buffers=431/431 residue=0
```

The stdout ledger records each transition as
`old-generation/old-epoch -> new-generation/new-epoch` with
`old-tcp-reconnect=0 old-udp-reuse=0` for `1→2`, `2→3`, `3→4`, and `4→5`.
The broker ledger records one request and one duplicate-fd close for each of
generations 1 through 5, with no completion `EPIPE` and no broker stop during
the sequence.  The runner snapshots show `state=DONE`, `active=0`, and
`residue=0` for all four acceptance cells; `show plugins` also records the
expected OI-3 plugin row before any cell is admitted.
Each generation re-created its endpoint and completion watcher; the inherited
broker infrastructure fds remained stable by design, while the per-generation
request token reset to `1` and was completed/closed exactly once.

This is the required Pixel raw evidence for normal stop, fault stop, restart,
and underlay invalidation.  It supports the same bounded lifecycle seam on the
controlled Android route; it does not support arbitrary device/default-route
traffic, pressure, capacity, soak, production, or release readiness.

## Boundary and conclusion

**SCOPED_GENERATION_TEARDOWN_GO.** The host same-process UDP4→TCP4 restart,
the real host fault→epoch→TCP restart addendum, the controlled Pixel 6a
normal/fault/restart/underlay sequence, the expanded generation/epoch/underlay/
fault model, and exact teardown history support the bounded owner-inline
lifecycle direction; no major design reversal was found.  The Pixel result is
strictly controlled local reachability: default-route/external traffic would
violate the safety boundary.  No soak, capacity, production, or release
sign-off is asserted.
