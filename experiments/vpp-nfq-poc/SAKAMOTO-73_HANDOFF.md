# SAKAMOTO-73 handoff: VPP-native NFQUEUE live-buffer probe

This is a throwaway, source-owned probe. It is not the product NFQUEUE path and
does not claim completion of S74--S81. The plugin receives one NFQUEUE netlink
datagram directly into a VPP buffer's current data span, keeps the packet
obligation in the fixed `vlib_buffer_t.opaque` area, hands the buffer index to
worker 1, and sends one verdict plus one native `vlib_buffer_free_one()` return
on the origin lane.

## Reproduce

Build a clean pinned VPP tree and install only this plugin:

```sh
cd experiments/vpp-nfq-poc
PYTHONPATH=/tmp/s73-venv/lib/python3.13/site-packages JOBS=12 \
  ./scripts/build-nfqueue-live-poc.sh
```

The build is pinned to VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0` and
records the source, patch hashes, buffer header hash, plugin hash, and install
paths in `work/vpp-s73-install-*/s73-provenance.properties`. The auditable
9000-byte buffer patch hash is
`439ac1c67a76d5bac61aa964f114505884a3eee3254691675362a2601e0a0bc9`; the
separate opt-in regular-memfd portability patch hash is
`1ddd591c271860887c8d7576dec1a2d6d1b649dbe1038172fffcf7b76f432afe`.

On a rootless host, run the real-kernel OUTPUT probe inside a disposable user
and network namespace. `S73_LOCAL_DUMMY=1` only replaces the veth/netns setup
that cannot mount `/run/netns`; the packet still traverses the kernel
OUTPUT/NFQUEUE rule. `SAKAMOTO_S73_REGULAR_MEMFD=1` is a throwaway portability
opt-in for hosts without a hugepage pool. It changes only backing allocation
and the corresponding page-lock requirement; VPP buffer index, opaque state,
handoff, verdict, and free ownership remain unchanged. It is not a product
Linux/Android memory policy.

IPv4 with stale/duplicate completion probes:

```sh
rtk unshare -Urn env S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 \
  INJECT_STALE=1 INJECT_DUPLICATE=1 \
  S73_EVIDENCE_DIR=/tmp/sakamoto-s73-evidence-ipv4 \
  ./scripts/run-nfqueue-live-poc.sh
```

IPv6:

```sh
rtk unshare -Urn env S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 \
  IP_FAMILY=inet6 S73_EVIDENCE_DIR=/tmp/sakamoto-s73-evidence-ipv6 \
  ./scripts/run-nfqueue-live-poc.sh
```

Both commands finish with `S73 runtime acceptance: PASS`. The raw logs and
before/after-disable CLI snapshots are in the two evidence directories above.

## Acceptance evidence

| S73 requirement | Evidence |
| --- | --- |
| Clean pinned source build and auditable 9000-byte data span | `s73-provenance.properties`: pinned revision, `bufferDataSize=9000`, both patch hashes, and plugin hash. |
| One command starts VPP and injects a real packet | The run commands set up a kernel OUTPUT NFQUEUE rule, start the dedicated VPP install, and invoke `ping`; no plugin packet shortcut is used. |
| IPv4 direct live-buffer parse | IPv4 `show-before-disable.txt`: `buffer-data-size 9000`, `datagrams 1`, `callbacks 1`, `last-buffer-index 2391916`, `last-buffer-base 0x10091fdc00`, `datagram-length 144`, `nfqa-payload-offset 60`, `nfqa-payload-length 84`, `original-length 84`, `captured-length 84`, `hook 3`, `ip-version 4`, `uid-known 1 uid 1000`. |
| IPv6 direct live-buffer parse | IPv6 snapshot: `datagrams 1`, `buffer-data-size 9000`, `datagram-length 164`, payload offset 60/length 104, original/captured 104, `hook 3`, `ip-version 6`, `uid-known 1 uid 1000`. |
| No scratch/side copy path | Both snapshots report `packet-copies 0`, `scratch-rx-buffers 0`, `full-packet-memcpy 0`, `per-packet-heap-objects 0`, and `payload-span-failures 0`. The static seam script rejects scratch allocation/copy/logging patterns. |
| One verdict, unknown kernel outcome, native return | IPv4 snapshot reports `verdict-attempts 1`, `send-success 1`, `send-failures 0`, `outcome-unknown 1`, `native-buffer-returns 1`, `outstanding-obligations 0`; IPv6 reports the same one-for-one result. |
| Origin/owner and stale/duplicate guards | IPv4 fault run reports `handoffs 1`, `owner-mismatches 1`, `completion-frames 3`, `stale 1`, `duplicate 1`, `ring-overflow 0`; only the origin lane attempts the verdict. These are probe guards, not claims about later ticket scope. |
| Missing identity guard | The callback rejects a missing `nfq_get_msg_packet_hdr()` identity before creating a live obligation (`missing_ingress_identity` branch); the outer receive loop frees the VPP buffer without a worker handoff. The static script covers this boundary; normal kernel NFQUEUE packets in the live runs carry the requested UID/GID metadata. |
| Teardown and residue | Each command disables the queue only after `outstanding-obligations 0`; `show-after-disable.txt` reports `enabled 0` with no outstanding obligation, ring overflow, verdict failure, or span failure. |

Run the source-only seam check with:

```sh
./scripts/test-nfqueue-live-poc-static.sh
```

It prints `S73 static ownership seam: PASS` and verifies inline metadata,
thread handoff, verdict, native return, and forbidden scratch/copy/heap/logging
operations.
