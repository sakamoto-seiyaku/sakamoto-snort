# SAKAMOTO-76 handoff: two-worker canonical live-buffer round trip

This is a throwaway VPP-native NFQUEUE probe. It extends the accepted S73-S75
path with two real VPP worker contexts and a reproducible owner-local/owner-
remote route. A worker transports a VPP buffer index and fixed inline identity;
it never copies packet bytes, issues a verdict, or frees the native buffer.
The origin NFQUEUE lane validates the bounded Completion Frame and performs the
single verdict plus the native return.

## Reproduce

Build the clean pinned VPP source and overlay:

```sh
cd experiments/vpp-nfq-poc
JOBS=12 ./scripts/build-nfqueue-live-poc.sh
```

The build exports the fallback venv's `site-packages` to `vppapigen`, so a
fresh checkout does not depend on the invoking shell's Python path. The final
build used VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`, 9,000-byte patched
buffers, and produced:

```text
bufferDataSize=9000
pluginSha256=9a63b69bdb447a8ac974769a33788be4bc4d505e1deaba29c4fe60e1991aaa00
```

The complete provenance is in
`work/vpp-s73-install-9258530f3804a152578ce11cc7c8a1e9eab88ed0/s73-provenance.properties`.

The runtime needs a disposable user/network namespace. `S76_REGULAR_MEMFD=1`
is only a portability fallback for hosts without the 2 MiB hugepage pool; it
does not change ownership, transport, verdict, or free placement.

```sh
rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=mixed \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence \
  ./scripts/run-nfqueue-live-poc-s76.sh
```

The runner starts two workers (`corelist-workers 1-2`), one process, and four
native lanes:

```text
ip4 OUTPUT queue 42   ip4 INPUT queue 43
ip6 OUTPUT queue 44   ip6 INPUT queue 45
host 10.201.76.1 / fd00:201:76::1
peer 10.201.76.2 / fd00:201:76::2
```

The owner route can be reproduced independently:

```sh
rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=local \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-local \
  ./scripts/run-nfqueue-live-poc-s76.sh
rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=remote \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-remote \
  ./scripts/run-nfqueue-live-poc-s76.sh
```

Bounded fault paths:

```sh
rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=remote \
  INJECT_OWNER_QUEUE_FULL=1 \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-queue-full \
  ./scripts/run-nfqueue-live-poc-s76.sh
rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=mixed \
  INJECT_COMPLETION_CREDIT_EXHAUSTION=1 \
  S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-credit \
  ./scripts/run-nfqueue-live-poc-s76.sh
```

Each run records `run.log`, `show-before-disable.txt`, and
`show-after-disable.txt` under its evidence directory.

The deterministic model has no namespace requirement:

```sh
./scripts/test-nfqueue-live-poc-s76-static.sh
```

It exercises mixed local/remote routing, queue-full terminal closure, credit
exhaustion, and stale/duplicate exactly-once settlement.

## Inline identity and transport contract

`nfqueue_live_meta_t` remains exactly the VPP `vlib_buffer_t.opaque` size. It
contains the queue generation, packet id, obligation nonce, origin lane,
payload offset/length, captured/original lengths, initial worker, canonical
worker, and handoff stage. The completion-credit held marker is packed into
the high bit of the origin-lane byte; all lane comparisons mask that bit.

The ingress process routes each admitted index to its deterministic initial
worker. The owner node computes the canonical worker from owner mode and inline
identity only. Local ownership completes on the initial worker. Remote
ownership calls `vlib_buffer_enqueue_to_thread()` with the index and target
thread, then the destination validates the complete live identity (buffer
index/base, packet id, payload offset/length, generation, and origin lane).
No packet bytes are passed through the handoff.

Normal completion and terminal completion are bounded by separate fixed rings.
The origin validates generation, packet id, nonce, and lane before attempting
one verdict. A stale token has no reference; an exact duplicate drops one
inline completion reference; only the origin can perform the final native
`vlib_buffer_free_one()` return. Completion credits and live obligations are
tracked independently and both must reach zero at teardown.

## Runtime evidence

The mixed run (`/tmp/sakamoto-s76-evidence`) reports:

```text
workers 2 worker-ids 1,2 owner-mode mixed
owner-local-obligations 17 owner-remote-obligations 17 owner-remote-handoffs 17 owner-queue-full 0
completion-credit-acquired 34 completion-credit-released 34 completion-credits-held 0 residue-completion-credits 0
identity-proof-checks 17 identity-proof-matches 17 identity-proof-failures 0
handoff-before buffer-index 2391771 buffer-base 0x10091fb7c0 packet-id 8 generation 1 origin-lane 1 payload-offset 88 payload-length 84
handoff-after buffer-index 2391771 buffer-base 0x10091fb7c0 packet-id 8 generation 1 origin-lane 1 payload-offset 88 payload-length 84
verdict-attempts 34 send-success 34 send-failures 0
native-buffer-returns 34 outstanding-obligations 0 residue-obligations 0 packet-copies 0
```

The local-only run reports `owner-local-obligations 34`, no remote handoffs,
and zero proof failures. The remote-only run reports
`owner-remote-obligations 34`, `owner-remote-handoffs 34`, and
`identity-proof-checks 34 identity-proof-matches 34 identity-proof-failures 0`.

The owner queue-full fault reports:

```text
owner-remote-obligations 34 owner-remote-handoffs 33 owner-queue-full 1 owner-terminal-intents 1
completion-credit-acquired 34 completion-credit-released 34 completion-credits-held 0 residue-completion-credits 0
identity-proof-checks 33 identity-proof-matches 33 identity-proof-failures 0
verdict-attempts 34 native-buffer-returns 34 outstanding-obligations 0 residue-obligations 0
```

The completion-credit fault reports one bounded admission rejection while all
admitted obligations close:

```text
owner-local-obligations 17 owner-remote-obligations 16 owner-remote-handoffs 16
completion-credit-acquired 33 completion-credit-released 33 completion-credit-exhausted 1 completion-credits-held 0 residue-completion-credits 0
identity-proof-checks 16 identity-proof-matches 16 identity-proof-failures 0
verdict-attempts 34 native-buffer-returns 34 outstanding-obligations 0 residue-obligations 0
```

All five runtime modes returned zero for IPv4 and IPv6 peer pings, native
buffer residue, completion-credit residue, origin-ring overflow, packet-copy
paths, scratch buffers, full-packet memcpy, and per-packet heap objects.

## Deterministic evidence

`test-nfqueue-live-poc-s76-ledger.sh` compiles and runs
`tests/nfqueue_live_s76_ledger_test.c`, which prints:

```text
normal mixed: local=4 remote=4 handoffs=4 proof=4/4 verdicts=8 native-returns=8 credits=8/8 residue=0
queue-full fault: queue-full=1 terminal-intents=1 verdicts=1 native-returns=1 residue=0
credit exhaustion fault: exhausted=1 acquired=1 released=1 residue=0
stale+duplicate fault: stale=1 duplicate=1 verdicts=1 native-returns=1 residue=0
S76 deterministic ledger: PASS
```

## Scope boundary

This handoff covers only the S76 two-worker live-buffer round trip and its
bounded evidence. Product NFQUEUE integration, policy parsing, and later
architecture work remain outside this throwaway probe.
