# SAKAMOTO-75 handoff: dual-stack NFQUEUE ingress metadata conformance

This is a throwaway, source-owned probe. It is not the product NFQUEUE path.
The S75 command starts one VPP process with four independent native NFQUEUE
lanes and drives IPv4 and IPv6 packets through both INPUT and OUTPUT hooks at
the same time. It does not restart the process per family. The direct receive
path materializes each accepted single-message envelope in a VPP buffer,
writes the packet metadata inline in `vlib_buffer_t.opaque`, hands the buffer
to worker 1, and returns the verdict and native buffer on the packet's origin
lane.

The existing S74 rule remains in force: a datagram containing more than one
NFQUEUE message is rejected before admission (one bounded direct verdict per
recoverable packet id, one native buffer return, no copy). S75 adds the lane
identity and platform-hint checks around that path; it does not claim
independent multi-message obligations in one VPP buffer.

## Reproduce

Build a clean pinned VPP tree and install only this plugin:

```sh
cd experiments/vpp-nfq-poc
PYTHONPATH="$PWD/work/s73-python-venv/lib/python3.13/site-packages" JOBS=12 \
  ./scripts/build-nfqueue-live-poc.sh
```

The build checks out VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, applies
the checked-in 9,000-byte buffer patch and the opt-in regular-memfd fallback,
then overlays this plugin. The final clean build used:

```text
bufferDataSize=9000
pluginSha256=45cc18149918cd2d86aa8977529db4ad3efe2b2e1a77b72176922d51371bf6d6
```

The complete provenance is in
`work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.

Run the normal dual-stack topology smoke in a disposable user and network
namespace. `S75_REGULAR_MEMFD=1` is only a portability fallback for hosts
without the hugepage pool; it does not alter packet ownership or verdict/free
placement.

```sh
rtk unshare -Urn env S75_REGULAR_MEMFD=1 \
  S75_EVIDENCE_DIR=/tmp/sakamoto-s75-evidence-normal-final \
  ./scripts/run-nfqueue-live-poc-s75.sh
```

The command creates a veth pair and a child network namespace, installs these
kernel rules, and starts concurrent peer pings:

```text
ip4 OUTPUT queue 42   ip4 INPUT queue 43
ip6 OUTPUT queue 44   ip6 INPUT queue 45
host 10.201.75.1 / fd00:201:75::1
peer 10.201.75.2 / fd00:201:75::2
```

The child emits IPv4 and IPv6 pings concurrently; the host-side OUTPUT and
INPUT rules exercise all four lanes in this one VPP process. Raw evidence is:

```text
/tmp/sakamoto-s75-evidence-normal-final/run.log
/tmp/sakamoto-s75-evidence-normal-final/show-before-disable.txt
/tmp/sakamoto-s75-evidence-normal-final/show-after-disable.txt
```

Run the identity and UID fault case with the same topology:

```sh
rtk unshare -Urn env S75_REGULAR_MEMFD=1 \
  INJECT_UID_UNKNOWN=1 \
  INJECT_MISSING_PACKET_ID=1 \
  INJECT_MISSING_GENERATION=1 \
  S75_EVIDENCE_DIR=/tmp/sakamoto-s75-evidence-fault-final \
  ./scripts/run-nfqueue-live-poc-s75.sh
```

Its raw evidence is:

```text
/tmp/sakamoto-s75-evidence-fault-final/run.log
/tmp/sakamoto-s75-evidence-fault-final/show-before-disable.txt
/tmp/sakamoto-s75-evidence-fault-final/show-after-disable.txt
```

## Inline metadata and ownership contract

Every admitted packet carries the following fields in the fixed opaque area;
the lane is explicit metadata and is never packed into the raw hook value.

| Field | Source/meaning |
| --- | --- |
| `original_length` | `nfq_get_cap_len()` / `NFQA_CAP_LEN`; if this optional attribute is absent, the bounded probe records the captured payload length as the fallback and increments `cap-len-missing`. |
| `captured_length` | Bytes returned by the NFQUEUE payload projection. |
| `payload_offset`, `payload_length` | In-place offset and length inside the VPP buffer's current data span. |
| `hook` | Raw `NFQA_PACKET_HDR` hook hint. It is not inferred from packet bytes. |
| `device-packet-direction` | Hook-derived normalization: `NF_INET_LOCAL_IN` → `INPUT`, `NF_INET_LOCAL_OUT` → `OUTPUT` (the helper also normalizes PRE/POST_ROUTING). |
| `ip_version` | Family hint from the owning lane (`ip4` or `ip6`); the adapter does not parse an L3 header. |
| `uid-known`, `uid` | Optional `nfq_get_uid()` platform hint and value. `uidKnown=false` is a valid fast path. |
| `packet_id` | Original NFQUEUE packet id from `NFQA_PACKET_HDR`. |
| `queue_generation` | Generation assigned when that native queue lane is opened. |
| `origin_lane` | Explicit lane index `0..3`; it selects the only queue allowed to issue the verdict and the only origin path allowed to free the buffer. |

The completion identity is `(queue_generation, packet_id,
obligation_nonce, origin_lane)`. The callback is the only producer of a live
obligation; worker completion transports carry indices and this identity only.
The worker never calls `nfq_set_verdict()` or frees a buffer. The origin lane
validates identity, attempts at most one verdict, and performs the native
`vlib_buffer_free_one()` return. No lease map, scratch packet, or per-packet
heap object exists.

When packet id or queue generation is absent, the callback records
`INGRESS_IDENTITY_MISSING`, does not write live metadata, does not admit a
`PacketLease` or worker handoff, and does not fabricate a Policy Verdict or
Adapter completion. The allocated VPP buffer is returned through the bounded
unowned path. UID absence is different: it is an explicit `uidKnown=false`
hint and the valid packet continues without waiting, caching, or replay.

## Acceptance evidence

The normal final snapshot reports:

```text
datagrams 17 callbacks 17 live-buffer-receives 17
inline-metadata-writes 17 payload-pointer-projections 17
uid-known-packets 0 uid-unknown-fast-path 17 uid-waits 0 uid-cache-reads 0 uid-replays 0
packet-id 5 queue-generation 1 origin-lane 2 hook 3 device-packet-direction OUTPUT
nfqa-payload-offset 44 nfqa-payload-length 104 original-length 104 captured-length 104
handoffs 17 completion-frames 17 stale 0 duplicate 0 ring-overflow 0 origin-return-overflow 0
verdict-attempts 17 send-success 17 send-failures 0 native-buffer-returns 17
outstanding-obligations 0 residue-obligations 0 packet-copies 0 scratch-rx-buffers 0
full-packet-memcpy 0 per-packet-heap-objects 0 policy-verdicts 0 adapter-policy-parser-attempts 0
lane 0 ... datagrams 4 callbacks 4 obligations 4 verdict-attempts 4 native-returns 4
lane 1 ... datagrams 4 callbacks 4 obligations 4 verdict-attempts 4 native-returns 4
lane 2 ... datagrams 5 callbacks 5 obligations 5 verdict-attempts 5 native-returns 5
lane 3 ... datagrams 4 callbacks 4 obligations 4 verdict-attempts 4 native-returns 4
```

Both ping processes returned zero. The local kernel omitted both optional UID
and cap-length attributes in this run, so the explicit unknown-UID and
captured-length fallback counters are expected; no identity wait/cache/replay
was used.

The fault snapshot reports the same 17 datagrams and 17 callbacks, with 15
valid admissions and two bounded identity failures:

```text
ingress-identity-missing 2 missing-packet-id 1 missing-queue-generation 1
inline-metadata-writes 15 payload-pointer-projections 15
handoffs 15 ledger-message-obligations 15 packet-leases 15
verdict-attempts 15 send-success 15 native-buffer-returns 17
policy-verdicts 0 adapter-policy-parser-attempts 0
uid-known-packets 0 uid-unknown-fast-path 15 uid-waits 0 uid-cache-reads 0 uid-replays 0
outstanding-obligations 0 residue-obligations 0 packet-copies 0
```

The two missing-identity callbacks do not enter the worker graph or produce
completion tokens. Their buffers are returned directly; the additional two
native returns explain `native-buffer-returns 17` versus 15 admitted
obligations.

Run the source-only ownership seam, deterministic envelope harness, and
multi-message settlement harness:

```sh
./scripts/test-nfqueue-live-poc-static.sh
./scripts/test-nfqueue-live-poc-envelope.sh
./scripts/test-nfqueue-live-poc-multimessage.sh
bash -n ./scripts/run-nfqueue-live-poc-s75.sh ./scripts/setup-netns-s75.sh
```

They report `S73 static ownership seam: PASS`, `S74 netlink envelope parser:
PASS`, and `S73 multi-message settlement harness: PASS`. The static seam also
checks the four-lane topology, explicit captured length/origin lane metadata,
hook-derived direction, and the missing-identity no-recovery guard.

## Boundaries

This is evidence for the S75 prototype only. The standard `nfqueue-live-poc
enable` command remains the single-lane S73 path; `enable-dual` is the S75
four-lane command. The accepted envelope is bounded by the patched 9,000-byte
VPP data span, and the fixed opaque metadata uses 16-bit datagram/offset/
payload/captured fields within that bound while retaining a full 32-bit
original length. Product integration, policy parsing, and later-ticket
claims remain out of scope.
