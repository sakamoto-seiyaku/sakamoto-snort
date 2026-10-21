# VPN dedicated I/O worker — pinned-VPP throwaway prototype

2026-10-21. This is a bounded feasibility result for
[ADR-0012](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md),
not a Product implementation or a VPN performance result. The question was
whether pinned VPP can run `N` owner workers plus an I/O-only worker, read
directly into a VPP buffer on that I/O worker, transfer only its index to one
owner and back, write identical bytes, and start multiple owner threads on the
same CPU while keeping the I/O worker on another CPU.

The runnable throwaway source is retained in local commit `cac80417` on
`prototype/vpn-tun-io-worker-20261021`, outside the Product branch. Its
isolated checkout is `/tmp/sakamoto-prototype-tun-io-worktree`; inspect the
committed source with `git show cac80417:src/product/vpp/prototype_tun_io/README.md`.
The branch was pushed to `origin/prototype/vpn-tun-io-worker-20261021`
after explicit authorization; its remote-tracking commit is `cac80417`.
It uses a local Unix datagram socketpair as the TUN stand-in and the first
payload byte as a synthetic `hash % N` selector. Its input callback calls
`read` with `vlib_buffer_get_current(buffer)` as the destination. Native VPP
frame queues move the original buffer index to the selected owner node and
back to the I/O node, which calls `write` on those buffer bytes and frees the
same native buffer. The source adds no payload staging buffer or packet-byte
copy between those steps. The 32-byte response is compared byte-for-byte by
the sending CLI command. This proves that limited VPP mechanism, not the
Product parser or Flow Stack.

| Run | VPP layout and actual CPU affinity | Observed result |
| --- | --- | --- |
| `run-20261021T145340Z-3111780` | main 0, W0 1, I/O 2; original pinned `libvlib` | 1/1 reads, owner receives, returns and writes; 0 failures; thread `2→1→2`, buffer `524242→524242→524242`, 32 equal bytes. |
| `run-20261021T145332Z-3111700` | main 0, W0 1, W1 2, W2 1, I/O 4; prototype-only relinked `libvlib` | 3/3 reads, owner receives, returns and writes; 0 failures; owner threads `1/2/3`, I/O thread `4`, identical buffer index and bytes at every stage. |

The original pinned library rejects `ordered-workers 1,2,1,4` at startup with
`ordered-workers: duplicate CPU 1`; the second run retains that exact failure
in `original-startup.log`. A prototype-only variant of `threads.c` removes the
duplicate parser rejection **and** changes worker launch from iterating unique
CPU bitmap bits to iterating the ordered list. Merely deleting the rejection
would allocate four VPP worker contexts but launch only three threads. The
modified file and relinked library live only in the persistent prototype cache;
the pinned source, its compiled objects, libraries and Product plugin were not
modified. The successful run proves the proposed startup change on this Host
VPP artifact, not on Android.

Exact final run records are retained at:

- `build-output/prototype-tun-io-20261021/run-20261021T145340Z-3111780/`
- `build-output/prototype-tun-io-20261021/run-20261021T145332Z-3111700/`

Each has `startup.conf`, `cli.jsonl`, `vpp.log` and `result.json`; the duplicate
run also has the original rejection config/log. The final runner source hash is
`ac20a9b8c2ca0242c854555932d141e64a0b0426d67b12a77a36d1a3514b3799`,
prototype plugin source hash
`f3ada9b1e1568e936bdb6d6a8d803fce065b6a243721e51afb70c61c617726f9`,
and relink helper hash
`cc2bafdfb1e8995c57529220fe36c893c30a1d38e2f168a62ec2667bbff65acc`.
The VPP binary SHA-256 is
`bebea5ec6918d38d2eeb53640d48544bfb205c22bbf3f978afae8b442c1a28f3`;
the original and prototype `libvlib.so.26.02` hashes are respectively
`7d819b42698edcbd88ee11c94e205e2181da6dcbc4f3e5af66bc770bc5bc30d7`
and `247cc5c92e2e607a73e7662e1e0a056ae7b2183ad32e6574ef37ada85d9bdfcc`.
The plugin hash is
`76fbe79a0210461838e68a8eec6cd21e159804f1ea437350983b499693e0ed90`.
Both final runs report `compiled=false`; the duplicate run also reports
`patched_vlib_compiled=false`, with unchanged plugin/library mtimes. Compilation
reused the existing pinned Host object build and persistent prototype cache,
not a new per-evidence dependency tree.

The first manual packet probe timed out because its CLI command was not marked
MP-safe: VPP's CLI worker barrier paused the workers that the command awaited.
After the throwaway command was marked MP-safe, the same mechanism completed
through every owner. This is a prototype harness correction; the bounded
final runs above are the result to use.

The prototype did not use a real Android TUN fd, Product canonical parsing,
fragment handling, HEV/lwIP, policy, production completion ledgers, queue-full
faults, shutdown drain, or benchmark traffic. It establishes no throughput or
release claim. The Product source still has fixed-two assumptions and keeps
TUN I/O on worker0; implementing ADR-0012 remains separate work.
