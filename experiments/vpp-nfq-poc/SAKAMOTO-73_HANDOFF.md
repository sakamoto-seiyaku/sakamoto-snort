# SAKAMOTO-73 handoff: VPP-native NFQUEUE live-buffer probe

This is a throwaway, source-owned probe. It is not the product NFQUEUE path and
does not claim completion of S74--S81 (in particular, it is not evidence for
S74--S77). The plugin receives one NFQUEUE netlink datagram directly into a VPP
buffer's current data span, keeps the packet obligation in the fixed
`vlib_buffer_t.opaque` area, hands the buffer index to worker 1, and sends one
verdict plus one native `vlib_buffer_free_one()` return on the origin lane in
the proven path. A bounded transport-fault fail-open may settle directly on
the producer when publishing a completion is impossible.
The inline identity is `(generation, original NFQUEUE packet_id,
obligation_nonce)`; completion rings transport that identity and inline
reference tokens only. They are fixed transport rings, not a side lease table.

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

IPv4 with stale/duplicate completion probes (the acceptance run):

```sh
rtk unshare -Urn env S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 \
  INJECT_STALE=1 INJECT_DUPLICATE=1 \
  S73_EVIDENCE_DIR=/tmp/sakamoto-s73-evidence-ipv4-final3 \
  ./scripts/run-nfqueue-live-poc.sh
```

Optional IPv6 smoke (same S73 probe, not a later-ticket claim):

```sh
rtk unshare -Urn env S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 \
  IP_FAMILY=inet6 S73_EVIDENCE_DIR=/tmp/sakamoto-s73-evidence-ipv6-final \
  ./scripts/run-nfqueue-live-poc.sh
```

Both commands finish with `S73 runtime acceptance: PASS`. The raw logs and
before/after-disable CLI snapshots are in the two evidence directories above.

## Acceptance evidence

| S73 requirement | Evidence |
| --- | --- |
| Clean pinned source build and auditable 9000-byte data span | `s73-provenance.properties`: pinned revision, `bufferDataSize=9000`, both patch hashes, and final plugin hash `7fcbaa8565f10575b1df23aff29215085bfc0beaed41838132b2cc0a3add3bbe`. |
| One command starts VPP and injects a real packet | The run commands set up a kernel OUTPUT NFQUEUE rule, start the dedicated VPP install, and invoke `ping`; no plugin packet shortcut is used. |
| IPv4 direct live-buffer parse | `/tmp/sakamoto-s73-evidence-ipv4-final3/show-before-disable.txt`: `buffer-data-size 9000`, `datagrams 1`, `callbacks 1`, `live-buffer-receives 1`, `inline-metadata-writes 1`, `payload-pointer-projections 1`, `last-buffer-index 2391916`, `last-buffer-base 0x10091fdc00`, `datagram-length 144`, `nfqa-payload-offset 60`, `nfqa-payload-length 84`, `original-length 84`, `captured-length 84`, `hook 3`, `ip-version 4`, `uid-known 1 uid 1000`. |
| IPv6 smoke | `/tmp/sakamoto-s73-evidence-ipv6-final/show-before-disable.txt`: datagram 164, payload offset 60/length 104, original/captured 104, `hook 3`, `ip-version 6`, `uid-known 1 uid 1000`; this is additional smoke evidence only, not a later-ticket claim. |
| No scratch/side copy path | IPv4 snapshot reports `packet-copies 0`, `scratch-rx-buffers 0`, `full-packet-memcpy 0`, `per-packet-heap-objects 0`, and `payload-span-failures 0`. Positive counters prove the live receive, inline metadata write, and payload pointer projection; compile-time zero-path assertions and the static seam reject scratch allocation/copy/logging patterns. |
| Original length source | `original-length` is populated by the vendored `nfq_get_cap_len()` NFQA_CAP_LEN adapter. When this local kernel omits NFQA_CAP_LEN, the bounded probe fallback uses libnetfilter_queue's captured payload length (`cap-len-missing 1`); it never parses an L3 header to invent the value. |
| One verdict, unknown kernel outcome, native return | IPv4 snapshot reports `verdict-attempts 1`, `send-success 1`, `send-failures 0`, `outcome-unknown 1`, `native-buffer-returns 1`, `outstanding-obligations 0`. |
| Origin/owner and stale/duplicate guards | IPv4 fault run reports `handoffs 1`, `owner-mismatches 1`, `completion-frames 3`, `stale 1`, `duplicate 1`, `ring-overflow 0`; full completion identity is checked before verdict. Completion refs stay inline until every published completion token is consumed. |
| Missing identity / malformed / truncation guards | Missing packet header, payload failure, span failure, parser failure, and MSG_TRUNC/oversize branches always free the allocated VPP buffer; when the packet id is recoverable from NFQA_PACKET_HDR they issue one bounded direct ACCEPT first. The static seam covers these candidate=0 branches. |
| Teardown and residue | Disable sets quiescing, removes the netlink read channel, drains ingress and completion transports for a bounded interval while the completion channel remains live, and refuses close on residual obligations. The final snapshot reports `enabled 0`, `outstanding-obligations 0`, no ring overflow, verdict failure, or span failure; cleanup records and propagates disable/netns teardown failures. |

Run the source-only seam check with:

```sh
./scripts/test-nfqueue-live-poc-static.sh
```

It prints `S73 static ownership seam: PASS` and verifies inline metadata,
thread handoff, verdict, native return, and forbidden scratch/copy/heap/logging
operations.
