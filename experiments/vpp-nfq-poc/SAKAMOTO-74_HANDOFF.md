# SAKAMOTO-74 handoff: measured NFQUEUE netlink envelope

This experiment measures the bytes that arrive in one VPP buffer before the
shared NFQUEUE parser is called. It does not copy a datagram into an adapter
scratch buffer. A complete datagram with exactly one valid NFQUEUE message is
projected in place; every multi-message, oversize, or malformed result is
rejected before `nfq_handle_packet()` and each recoverable packet id receives
an explicit direct `ACCEPT`. The one VPP buffer is then returned once, with no
independent packet obligations admitted for that datagram.

Conclusion: single-message direct materialization is **PASS**. Multi-message
independent one-buffer obligations are **NOT SUPPORTED**; safe pre-admission
rejection with one verdict attempt per recoverable id is **PASS**. Therefore
the ticket's overall one-buffer-per-obligation result is **PARTIAL**. This is
an explicit safe rejection allowed by the accepted contiguous-envelope design,
not a silent partial parse or a full-copy fallback.

## Reproduce

Build the clean pinned VPP tree and overlay the plugin:

```sh
PYTHONPATH="$PWD/experiments/vpp-nfq-poc/work/s73-python-venv/lib/python3.13/site-packages" \
  JOBS=12 ./experiments/vpp-nfq-poc/scripts/build-nfqueue-live-poc.sh
```

The final build used VPP revision `9258530f3804a152578ce11cc7c8a1e9eab88ed0`,
`bufferDataSize=9000`, and installed plugin SHA256
`63e7d41b0f8f6b5f8caff7bd930727928ca6221806a1a08f94992120d395fd8c` (recorded
in `work/vpp-s73-install-*/s73-provenance.properties`).

Run the real kernel OUTPUT → NFQUEUE → VPP ingress → origin verdict/native
return path in a disposable rootless user/network namespace:

```sh
rtk unshare -Urn env \
  PYTHONPATH="$PWD/experiments/vpp-nfq-poc/work/s73-python-venv/lib/python3.13/site-packages" \
  S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 INJECT_STALE=1 INJECT_DUPLICATE=1 \
  S73_EVIDENCE_DIR=/tmp/sakamoto-s74-evidence-ipv4-mixed-final \
  ./experiments/vpp-nfq-poc/scripts/run-nfqueue-live-poc-s74.sh
```

The command prints `S74 runtime acceptance: PASS`. Raw snapshots are:

```text
/tmp/sakamoto-s74-evidence-ipv4-mixed-final/run.log
/tmp/sakamoto-s74-evidence-ipv4-mixed-final/show-before-disable.txt
/tmp/sakamoto-s74-evidence-ipv4-mixed-final/show-after-disable.txt
```

Run the deterministic real-netlink envelope harness (not shell arithmetic):

```sh
./experiments/vpp-nfq-poc/scripts/test-nfqueue-live-poc-envelope.sh
```

It compiles the checked-in C test against the vendored NFQUEUE headers and
executes the same bounded packet-id visitor used by the plugin's rejection
path. The output is:

```text
multi ledger: messages=2 recoverable=2 rejection-attempts=2 native-returns=1 obligations=0 copies=0 residue=0 ids=11,12
exact boundary: datagram=9000 capacity=9000 status=COMPLETE parsed=9000 payload=8940
oversize boundary: datagram=9001 capacity=9000 status=OVERSIZE parsed=9000 rejection-attempts=1 native-returns=1 obligations=0 copies=0 residue=0
declared-oversize truncation: declared=9001 captured=9000 status=OVERSIZE recoverable=1 recovery-attempts=1 recoveries=1 rejection-attempts=1 native-returns=1 obligations=0 copies=0 residue=0 id=51
mixed complete+truncated: messages=2 recoverable=2 rejection-attempts=2 native-returns=1 obligations=0 copies=0 residue=0 ids=11,51
empty payload: status=MALFORMED projectable=0
S74 netlink envelope parser: PASS
```

## Acceptance evidence

| Obligation | Evidence |
| --- | --- |
| Real netlink envelope fields | Live snapshot reports `datagrams 1`, `envelope-messages 1`, `valid-messages 1`, `recoverable-messages 1`, `envelope-netlink-header-bytes 16`, `attribute-bytes 123`, `attribute-aligned-bytes 124`, `envelope-payload-offset 60`, `usable-l3-envelope 84`, and `parsed-bytes 144`. |
| One-buffer single-message path | The live snapshot reports `buffer-data-size 9000`, `callbacks 1`, `live-buffer-receives 1`, `payload-pointer-projections 1`, `ledger-message-obligations 1`, `verdict-attempts 1`, `native-buffer-returns 1`, and `outstanding-obligations 0`. |
| Exact 9000-byte boundary | The C harness constructs a 9,000-byte NLMSG/NLA envelope (`payload=8940`) and reports `status=COMPLETE parsed=9000`; no byte beyond the VPP data span is read. |
| Oversize boundary and MSG_TRUNC identity recovery | The harness covers both a complete 9,000-byte prefix with `datagram=9001` and a declared-oversize header (`nlmsg_len=9001`) whose captured prefix is 9,000 bytes. The latter reports `recoverable=1`, direct rejection attempt `1`, one native return, zero obligations/copies/residue; the bounded walk never projects payload bytes. |
| Multi-message behavior | The harness constructs two complete messages (`ids=11,12`), measures `messages=2 recoverable=2`, attempts two direct verdicts, admits zero independent obligations, returns one VPP buffer, performs zero copies, and leaves zero residue. A mixed `[complete ID11][declared-oversize ID51]` datagram exercises the same full-prefix walk and reports two recovered identities and two attempts. |
| No silent partial parse/full copy | The live preflight rejects every status other than `COMPLETE` before `nfq_handle_packet()`. Compile-time `NFQUEUE_LIVE_PACKET_COPY_PATHS` and runtime `copy-count`, `packet-copies`, `full-packet-memcpy`, and `per-packet-heap-objects` are all zero. |
| Explicit oversize recovery ledger | The plugin records `envelope-recovery-attempts` and `recoveries` separately from normal message rejection. The normal live run reports both zero; the declared-oversize harness reports one recovered identity and one direct verdict attempt without admitting an obligation. |
| Teardown | The live before/after-disable snapshots report `outstanding-obligations 0` and `residue-obligations 0`. |

## Primary source behavior

The vendored `nfq_handle_packet()` is a direct wrapper over
`nfnl_handle_packet()` (`third_party/netfilter/libnetfilter_queue/src/libnetfilter_queue.c:609-612`).
The primary parser loops over a received buffer while at least one netlink
message remains, validates `nlmsg_len`, advances by `NLMSG_ALIGN(nlmsg_len)`,
and invokes the callback for each message
(`third_party/netfilter/libnfnetlink/src/libnfnetlink.c:1266-1287`). This is why
the S74 preflight must make the one-buffer/multi-message decision before
calling the library: the library can produce more than one callback, but one
VPP buffer cannot safely expose two independent packet spans without copying.
