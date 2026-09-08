# SAKAMOTO-206 — dual-stack Root Q2/W2

Acceptance: **functional PASS**, 2026-09-08, Pixel 6a `28201JEGR0XPAJ`,
generations **661–664**. Scope is ordinary IPv4/IPv6 UDP: app-UID OUTPUT and
UDP INPUT share each family's queue range. TCP, VPN, pressure, latency and power
qualification remain separate work. Q2/W2 is this stage's configuration, not a
permanent owner-selector or capacity constant.

## Implemented ownership

| Family | Global origin lane | Family lane | Queue / independent fd at start | Actual worker / thread / CPU |
| --- | --- | --- | --- | --- |
| IPv4 | 0 | 0 | 176 / 14 | 0 / 1 / 1 |
| IPv4 | 1 | 1 | 177 / 15 | 1 / 2 / 2 |
| IPv6 | 2 | 0 | 178 / 16 | 0 / 1 / 1 |
| IPv6 | 3 | 1 | 179 / 17 | 1 / 2 / 2 |

Each listener, pending ledger, generation and token sequence belongs to its
lane. The 24-byte AdapterObligation now names the frozen origin worker separately
from its global lane identity, using the previous reserved byte. Canonical owner
selection remains independent of queue, lane, fd, UID and CPU. The existing
32-byte Completion Frame returns to that worker, where the matching lane alone
attempts the original generation/packet-ID verdict. No shared TX lock, foreign
fd write, main-thread fan-in, Owner Guard or corrective dispatch was added.

Shared totals use atomic increments. Last-packet details are lane-private;
control/API and default CLI reads use VPP's existing worker barrier. The errno
used by netlink operations is thread-local. Bounded tracing records actual
callback/TLS thread and CPU; CPU does not enter the owner key.

The retained completion-return backlog is now 512 indices per worker. Its static
bound covers all four 64-obligation lanes plus 32 diagnostic carriers (288 total),
without another packet copy or packet allocation. This is a conservation bound,
not a throughput or queue-pressure result. Primary rejection behavior remains
owned by S210 and is not qualified by this task.

## Real packet and closure evidence

The collector used real app UDP sends and an independent native echo endpoint.
Temporary IPv6 loopback addresses only supplied different kernel-balanced flows;
they were removed afterwards. No graph injection or forced queue rule replaced
ordinary NFQUEUE capture. Both `iptables` and `ip6tables` snapshots show INPUT and
OUTPUT using respectively `176:177` and `178:179`.

All eight family/lane/owner combinations are observed. There are **38 successful
nonce echo probes** (114 real captures: one OUTPUT and two INPUT per loopback
exchange), one additional admitted in-flight close probe, and eight incidental
UDP captures. The independent verifier accounts for **all 123 captures**, actual
native vectors, one parser/selector, correct worker policy, immutable metadata,
original buffer identity, one verdict and one return per admitted obligation.

| Generation | Closed lane | Verdicts | Local / remote completions | Final pending / frame / buffer / obligation debt |
| --- | --- | --- | --- | --- |
| 661 | 0 | 69 | 31 / 38 | 0 / 0 / 0 / 0 |
| 662 | 1 | 18 | 9 / 9 | 0 / 0 / 0 / 0 |
| 663 | 2 | 18 | 9 / 9 | 0 / 0 / 0 / 0 |
| 664 | 3 | 18 | 9 / 9 | 0 / 0 / 0 / 0 |

Each cycle closes one lane and exercises both owners on all three survivors.
The first closure deliberately occurs with **pending=1**. It quiesces new reads,
keeps the original fd for completion, reaches zero admitted debt, then closes.
The CLI returns `draining` instead of waiting under the worker barrier; a later
retry closes the fd. Kernel queue snapshots verify only that queue disappeared.
Partial readiness is reported by the ready mask while other listeners continue.

That closing probe's already-admitted OUTPUT packet is accepted and returned
once. Its later INPUT packet cannot finish an echo through the quiesced lane,
so the app timeout is recorded separately, not counted as a successful echo.
This does not promise that kernel balance avoids a closed listener (S233).

After every full stop, kernel queues 176–179, both-family hooks and the runtime
process are absent. The fd snapshot uses the actual main-thread LWP from
`show threads`; the supervisor's diagnostic PID may legitimately be `-1`.

## Validation and limitations

- Fresh Product build, install, all twelve native hashes and source/run witness:
  PASS with `tests/device/verify-s206-root-lanes.py --request ...`.
- Android runtime contract suite, Host-evidence plugin compilation, S192 source
  contract, Python syntax and diff checks: PASS. S192 runtime is explicitly
  SKIPPED by that source-contract invocation; real Product execution is above.
- Corrupted evidence clones reject a wrong completion-return target, duplicate
  verdict and rewritten owner. These are verifier negatives, not wire packets.
- Earlier `pixel-b` and `pixel-c` attempts remain HOLD: the collector first used
  the wrong OUTPUT enum, then used diagnostic PID `-1` for `/proc` capture.
  Product cleanup succeeded; neither attempt is presented as final acceptance.
- Existing Android idle-profile delays remain. Ordinary remote packets commonly
  spend about 3 seconds in the graph/return route; an echo traverses several
  captured packets. The collector explicitly allows 20 seconds for functional
  echo closure. No latency/power acceptance or worker-wake change is claimed.

## Artifact and reproduction

- Source commit: `9c67175713baceb46cef015f3464893fa3d69950` plus preserved dirty source.
- Source SHA-256: `2e63d9dc86875d91eb2afeffb7de73becb1a307b7436fee3550edd3c1ae2ad4c`.
- APK SHA-256: `3dd5aa91d71191f9b620b911b5e7176386e7d9fd6709cabc7f1cae4b3fa8a03d`.
- Plugin SHA-256: `c1ec51dfbef316557d295822e91709b3843efeab7bfd2e10112d0fc448fb68e2`.
- Artifact: `sakamoto-product-vpp-s206-v1`.
- Build: `build-output/s206-lanes/build-b/build.json`.
- Accepted request/run: `build-output/s206-lanes/request-d.json`,
  `build-output/s206-lanes/pixel-d`.
- Negatives: `build-output/s206-lanes/negative-d`.
- Collector: `tests/device/s206-root-lanes.py`; endpoint source:
  `tests/device/helpers/s206-udp-echo.c`.

The full report is recorded in the private Plane task. Later source changes make
this a historical milestone; they require a fresh current-source witness.
