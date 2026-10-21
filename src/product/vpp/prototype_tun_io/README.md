# THROWAWAY — pinned VPP TUN I/O worker prototype

Question: can the pinned VPP run `N` owner workers plus one I/O-only worker,
read a packet directly into one VPP buffer on that worker, pass only its buffer
index through an owner and back, then write the unchanged bytes and free the
same buffer? Can separate owner workers run on the same CPU while the I/O worker
keeps its own CPU?

Run from the repository root (local Host VPP stage required):

```sh
rtk proxy python3 src/product/vpp/prototype_tun_io/run.py
```

Press `0`–`2` to send a synthetic packet to a selected owner; `s` refreshes
state and `q` quits. For a noninteractive demonstration, add `--demo`.
`--owners 1` exercises the single-owner case. The plugin is compiled once into
the persistent Product prototype cache; raw VPP logs, CLI outputs, identities
and outcomes are retained under `build-output/prototype-tun-io-20261021/`.

To check actual startup with repeated owner CPUs, run:

```sh
rtk proxy python3 src/product/vpp/prototype_tun_io/run.py --demo --duplicate-startup
```

That command first records the original VPP rejection, then compiles only a
modified `threads.c` and relinks `libvlib` from the existing pinned Host build
objects into the persistent prototype cache. The original VPP source, objects,
libraries and Product plugin are not modified. The modified library changes
the ordered-worker launcher to iterate the list, including duplicate CPU IDs.

This uses a local Unix datagram socketpair in place of Android TUN and a first
byte in place of the Product canonical selector. It tests VPP thread, native
buffer and frame-queue mechanics, not real VPN policy, performance, Android
CPU placement or the Product Adapter. Without `--duplicate-startup`, current
pinned VPP rejects duplicate `ordered-workers` CPU IDs; the runner starts on
distinct CPUs, then binds the last owner to the first owner's CPU. With the
flag, the duplicate startup uses only the temporary relinked `libvlib`. Neither
path proves an Android release build or real VPN performance.

Delete this source after its answer has been captured in the implementation
issue. Keep the throwaway branch and its exact run evidence as the source.
