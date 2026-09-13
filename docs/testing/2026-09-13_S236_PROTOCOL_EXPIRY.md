# SAKAMOTO-236 — unified TCP/ICMP expiry evidence

## User-approved scope adjustment — 2026-09-13

The user explicitly deferred real 86400-second ESTABLISHED idle expiry and
post-expiry held-socket reuse, declining day-long interactive waiting. This
decision is recorded in the S236 Plane description. It does not change Product
defaults or turn incomplete evidence into PASS. S220/S235 are not blocked by it.
The original full acceptance remains available; current scoped acceptance is
named `PASS_WITH_DEFERRED_LONG`, with `full_original_acceptance=false`.

The final scoped verifier passed both platforms' twelve short/mixed cases and
both cancelled-run cleanup checks, retaining all 206 semantic-negative results.
`acceptance.json` SHA-256 is
`8c5607be4724920b9965a371d0251374ea11ac0409bfe1ba25ab5803d7781469`;
the gate source is
`a9ba39d3c133a3ca89a28969cb13be7c80634549a687abc147322d37de249e77`.
The full protocol authority still rejects the cancelled `HOLD` result, and a
wrong-platform cancellation check is also rejected. No verifier clock was changed.

Both original long collectors were interrupted through SIGINT and their existing
finally cleanup. Linux stopped at 09:06:59 +08:00 and Pixel at 09:07:23 +08:00.
Original raw results remain `HOLD`, with no cleanup error; runtime/client and
endpoint processes were closed, private hooks removed, and Pixel's UID-owned
control directory removed. Four CLOSING entries per platform had already expired
after real 900-second deadlines; the four still-established entries were released
administratively at stop, not claimed as automatic 24-hour expiry.

## Preregistered scope (before first collection)

Parent S199; prerequisites S227/S222/S224. Product changes only extend the existing
default-on owner-local deadline driver to TCP/ICMP and map all eleven classes from
OVS `3c2bea086ef8912d57331173af266f21d36740a0`. No tracker, clock, configured timeout,
per-protocol pool, heap, timer thread, END path, or user setting is added/changed.
The retained explicitly enabled S226 A/B initializer remains UDP-only.

Linux uses real sockets/NFQUEUE in a disposable rootless network namespace. Pixel
uses the newly built APK's native runtime, actual root NFQUEUE, private loopback
tuples and the app UID while RuntimeService is stopped. No Wi-Fi/underlay changes.
No graph-injected packets or fake time qualify as device completion.

| Case | Real captured state and default deadline |
| --- | --- |
| TCP FIRST | Capture original SYN only; 30 s. Kernel handshake/nonce echo still completes outside the capture window. |
| TCP OPENING | Capture SYN in both directions; 30 s. Final ACK/data remain outside this explicit capture window. |
| TCP FIN_WAIT | Full established handshake/echo; then capture FIN-bearing packets only during real orderly socket close, omitting final ACK from Product; 45 s. |
| TCP CLOSED | Full capture, real reset close; established 86400 s shortens to 30 s. |
| TCP INVALID | FIRST capture; later checksum-valid SYN+FIN reaches Product, then an exact private INPUT filter suppresses kernel reaction. INVALID must not renew the original 30 s. |
| ICMP FIRST/REPLY | Real IPv4/IPv6 Echo with request-only/both-direction capture; 60/30 s. |
| ICMP renew | Repeat request at +20 s; survive original +60 s, expire at renewed +80 s. |
| ICMP shorten | FIRST then bidirectional Echo before the original has aged 30 s; new 30 s deadline is earlier than original 60 s. |
| TCP long | Four real established sockets (two families × two owners) remain quiet for 86400 s, plus four real half-closed sockets for CLOSING 900 s. Keepalive explicitly off on both endpoints. |
| Mixed/batch/lookup | W2 TCP/UDP/ICMP share the same heap and capacity. Real default deadlines, packet-triggered refresh, bounded batches and expired lookup require separate raw evidence; host vectors alone do not close this gate. |

Every short class covers IPv4/IPv6 and owner 0/1; controlled initial lane placement
exercises local and remote execution without changing owner selection. Trace binds
raw packet, parser facts, tracker result, timer deadline, owner thread, instance,
END, consumer, final buffer free and underlying NFQUEUE completion. Endpoint nonces
and TCP/ICMP checksums are independent packet evidence, not assertions synthesized
from Product state. A capture window is not a claim that the physical TCP socket
remained in that state; the long ESTABLISHED/CLOSING cases have no such exclusion.

Each normal expiry must occur with no new captured packet after its accepted
refresh, not via administrative stop. Runtime restart/stop must leave entries,
heap memberships, control/END buffers, queues, hooks and timer FDs at zero. The
existing per-owner 100 END / 100 ms bound remains. INVALID must preserve the
accepted tracker state and deadline even if generic observation counters advance.

Long cases run separately; the 24-hour result cannot be inferred from shorter
waits, a shortened configuration, CPU time, a wall-clock jump or host vectors.
After real expiry, an echo on the still-open socket may create a new midstream
instance, which is then explicitly counted as administrative stop cleanup.

Source/build/installed-native/helper hashes and frozen collector/plan inputs are
required. Partial runs must remain partial. Completion status lives in Plane;
this document is the evidence plan/report, not a parallel open-work ledger.

The INVALID injector waits 1 s after preparation, then leaves the original
deadlines untouched and waits 35 s. The initial +15 s preparation-relative
attempt was too late for several Pixel originals because real shell/CLI setup
already consumed part of their 30 s lifetime. Such expired-miss packets do not
qualify as INVALID-on-live-entry evidence; an explicit corrected run is required.

Likewise, the initial Pixel shortening attempt's preparation-relative +20 s
made some originals older than 30 s. The packet-derived deadline was correct,
but not earlier than the original deadline. Corrected shortening adds only 1 s
after preparation and asserts all four deadlines actually moved earlier. The
original run remains rejected for this gate; seven other short cases verify.

## Mixed preregistration (before collection)

The mixed endpoint combines existing independent test socket helpers, without
Product code. `mixed-batch` interleaves 16 reset-closed TCP connections, 16 UDP
Echo tuples and 16 ICMP queries; all retain their actual 30-second defaults.
`mixed-renew` refreshes four established TCP, four bidirectional UDP and four
ICMP entries after a real 10-second wait. TCP retains its 86400-second class;
those four live entries are explicitly counted in administrative stop cleanup.

`mixed-lookup` primes 1792 real bidirectional UDP entries (896 per owner), then
four TCP FIRST and four ICMP REPLY entries, and refreshes one existing UDP tuple
per family/owner. After 30.001 real seconds, the held TCP sockets send data and
the same ICMP/UDP tuples exchange Echo packets. The bounded 100/100ms physical
backlog must leave all twelve expired originals available to logical lookup;
the verifier rejects a run without actual logical replacement on both owners.
TCP initially captures SYN only, then retains full capture before that lookup;
the new midstream entries keep their unmodified 86400-second class.

The global packet trace limit remains the existing 4096, with 1024 per lane.
Actual lane counts must fit; no omitted packet is silently treated as traced.
END graph tracing is independently capped at 256 per owner: the small mixed
case proves complete cross-protocol END paths, while the large case must bind
every release callback and batch/lookup event plus explicitly bounded graph
samples. One shared capacity/heap per owner and zero stop residue remain gates.

Initial Linux mixed lookup with 48 outstanding endpoint requests hit real
fail-open under full packet tracing: 3604 captured but only 3088 submitted,
with 1458/1800 entries. It is HOLD, not a scheduler failure or accepted coverage;
cleanup completed. The corrected helper limits initial UDP echo requests to
eight outstanding, preserving all actual default durations and batch budgets.

The 1792-flow/full-trace attempt also did not reliably create the lookup
precondition: Linux's initial population took ~14 s, and actual scheduled
cleanup won before lookup. Pixel produced 11/12 logical replacements in one
run and 0/12 in the eight-request run. None closes the twelve-cell lookup gate.

The revised large lookup returns to S227's proven 8192 UDP priming population
and 256-packet native diagnostic sample, with 4160 shared slots per owner for
the eight added TCP/ICMP entries. The 100 END/100ms default remains unchanged.
An independent AF_PACKET socket, restricted to the exact test loopback address
pairs and twelve target tuples, now records the actual target packets after
NFQUEUE acceptance. It records the full-capture-window transition using its
own monotonic clock. Native raw samples and all lane/completion counters bind
the bulk path; target wire bytes/nonces and full entry/timer snapshots bind
the untraced target instances; every expiry/lookup/release is still traced.
This is explicitly sampled native packet evidence, not a claim of a complete
8192-flow native packet trace. The small mixed cases retain full native traces.

The first 8192-flow attempt exposed an endpoint-ordering error: sending the
entire low-port half before the high half concentrated a 48-request window on
two lanes, unlike S227's alternating low/high order. Linux recorded adapter
fail-open; Pixel recorded 29 primary-handoff rejections and nine missing flows.
Both attempts were rejected and stopped cleanly. The corrected tuple order is
the same independently assigned, alternating low/high order used by S227.

For the small same-batch case, TCP connection establishment is moved before the
deadline cluster. One real reset per owner starts the ordinary pacing interval;
20 ms later the remaining real resets and concurrent kernel Echo requests run.
This controls only endpoint timing, not Product time or scheduler invocation.
The verifier still requires an observed three-protocol batch on both owners.

## Verified short and mixed results (source B)

Product source closure is
`552df94d507ed6cc081b78d53e0e41696227b996f60e743c7d4c24b6e65c8e98`.
Linux uses `linux-build-b`; Pixel uses the installed APK from `pixel-build-b`.
The original ICMP enum-ceiling crash was reproduced by a typed-packet → tracker
→ actual heap API host regression before correcting the stale upper bound.
All subsequent qualifying runs use source B; artifact A is not accepted.

Under `build-output/s236-20260913/`, `linux-short-c` independently verifies all
nine short cases. Pixel combines the seven explicitly selected good cases in
`pixel-short-b`, `pixel-invalid-c` and `pixel-shorten-c`. The two excluded cases
in the original Pixel run are never counted as passing.

Both `linux-mixed-d` and `pixel-mixed-d` independently verify the full mixed
matrix. Each has 48 same-batch expirations, eight renewed UDP/ICMP expirations,
and 8208 large-lookup releases. Both owners have an actual three-protocol batch;
all twelve protocol × family × owner lookup cells replace an expired original.
The large case captures 16432 actual packets in total, with 256 native raw
samples, 256 completion samples, 512 END graph samples, 56 independently
captured target packets and all 8208 release callbacks. The 24 TCP handshake/
payload packets outside the initial explicit SYN-only window are not claimed
as Product input. The independent capture verifies checksums on actual captured
window traffic; it does not mislabel offloaded, excluded kernel packets as bad.

Mixed small-case maximum deadline-to-release latencies are 92.512/99.165 ms
(Linux batch/renew) and 88.282/91.819 ms (Pixel). Large backlog maxima are
3858.118 ms (Linux) and 3666.680 ms (Pixel), with the existing 100 END/100ms
per-owner work bound. Ordinary deadlines retain the inherited p99 ≤1100 ms,
max ≤1500 ms acceptance bound; the 4100-entry-per-owner due backlog has a
5600 ms bound, including the same 1500 ms callback allowance.

## Long-run clock evidence

Linux `linux-long-a` entered its quiet interval at 2026-09-13 04:37:30 +08:00;
Pixel `pixel-long-a` at 05:23:56 +08:00. Each has already observed four real
CLOSING expirations after the actual 900-second default while retaining four
ESTABLISHED entries. The final 86400-second result is not yet claimed.
The verifier binds native last-refresh → deadline → callback times and the
still-open endpoints' own CLOCK_MONOTONIC gap between nonce receipts. CLI and
FD observations are packet-quiet time too; summing only sleep-loop durations
would incorrectly omit that observation time. No fake clock, default override,
periodic keepalive or packet exclusion is used for the long case.

## Broader regression context

All eight focused flow/timeout/diagnostic C tests pass, including the new W2,
dual-stack mixed shared-heap boundary vector. The broader CTest suite is
34/39 after allowing local Unix sockets. Its five remaining static-contract
failures are unchanged from committed pre-S236 HEAD
`82547e84a4d36eefe46b855d213bf9f4eb418dd8`: the VPP contract expects hardcoded
Host evidence ON; S176 expects the old adapter string; S189 expects the old
hardcoded Wi-Fi hint; S190 points at the removed UDP4 adapter file; S191 expects
the old no-match function. Each failing script and first failing input matches
that HEAD byte-for-byte. These are not reported as a green whole-repo suite or
as S236 regressions. The initial sandbox-only Rust UDS failure passes when local
socket creation is allowed. XML and exact first-failure traces are retained in
`host-tests/` under the evidence directory.

## Verification entry points

`tests/evidence/test_s236_expiry_negatives.py` rejects 206 rehashed semantic
corruptions with the current verifier closure: Linux short 50, Pixel selected
short 48, and mixed 54 on each platform. Deadline/class drift, INVALID renewal,
wire checksum/identity/window corruption, incorrect owner/heap/batch/lookup,
duplicate or missing END/free, false native completion and nonzero stop residue
are rejected semantically, not merely because an input hash changed.

The explicit acceptance recipe is
`build-output/s236-20260913/acceptance-input.json`. It combines only the selected
qualifying Pixel short cases with their corrected runs, plus both complete mixed
runs and both separate long runs. Verification can be repeated with:

```sh
rtk proxy python tests/evidence/verify_s236_acceptance.py \
  --input build-output/s236-20260913/acceptance-input.json \
  --output build-output/s236-20260913/acceptance.json
```

This gate requires every short/long/mixed case exactly once per platform, one
Product source closure, fresh independent verification, matching semantic-
negative verifier hashes, the focused host regressions and explicitly recorded
unchanged whole-repo baseline failures. Individual run verifiers return only
`VALID_PARTIAL`; neither those reports nor a missing long-run result can become
full original S236 PASS. Without a scope override, the gate still reports HOLD
for the interrupted long runs. The approved scoped gate adds
`--allow-deferred-long` to the command above and requires the explicit user
decision in the input manifest. It freshly verifies all twelve short/mixed cases
per platform and the cancelled runs' cleanup, but emits only
`PASS_WITH_DEFERRED_LONG`; both long cases are `DEFERRED_UNVERIFIED`, excluded
from verified coverage. No VPN expiry or general readiness is implied.
