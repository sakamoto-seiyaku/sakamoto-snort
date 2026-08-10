# SAKAMOTO-81 handoff: ownership closure audit and return handoff

Status: SAKAMOTO-81 audit complete for the throwaway NFQUEUE live-buffer
prototype campaign SAKAMOTO-73 through SAKAMOTO-80. This is evidence for
SAKAMOTO-72's POC question only. It is not a claim that SAKAMOTO-68 Gate/L4
product slice, release packaging, Debug Activity, VPN parity, policy engine, or
production Android capacity gates are complete.

Plane:

- SAKAMOTO-72 — parent: POC: VPP-native NFQUEUE live-buffer ownership closure.
- SAKAMOTO-81 — this audit: POC: ownership closure audit 与 return handoff.
- Inputs: SAKAMOTO-73 through SAKAMOTO-79 handoffs plus SAKAMOTO-80 result
  directories, provenance, and LLDB repair evidence.

Evidence-retention note: Plane remains the tracker source of truth. This file
is a point-in-time evidence handoff, not a tracker. Some early host raw
directories were intentionally written under `/tmp`; S81 therefore
distinguishes repo-retained handoff/counter evidence, current raw paths still
present on this filesystem, and historical raw paths that are cited by earlier
handoffs but are no longer retained locally.

Current audit revision:

- Repo/branch at audit time: `poc/p6-conditional-wake-redesign`.
- Audit source HEAD: `4f58d8cc050271bb5c3556ed890953c519b8f3f3`.
- Throwaway prototype fixed point before S80: `db7547c012626a82896f33e08f8f40f9b5262a86`.
- Final S80 Android evidence provenance still records the runtime artifact source
  revision as `18dac1cbe3a97358749bdc8d66daba72ae876f4b`; later commits
  `713bff5` and `4f58d8c` refactor/fix S80 script/control seams and are covered
  by this S81 source audit.

## Executive result

| Obligation | Result | Judgment |
| --- | --- | --- |
| Direct materialization | PASS | Host and Android receive NFQUEUE datagrams directly into VPP-owned buffer storage; L3 payload is projected in place. |
| One-buffer-per-obligation | PARTIAL | Single-message datagrams are one live VPP buffer per admitted obligation. Multi-message datagrams are explicitly rejected before admission with bounded direct verdicts; independent multi-message obligations in one buffer are not supported. |
| Worker handoff | PASS | Owner-local and owner-remote paths were proven on host; Android proves real remote mismatch handoff with stable buffer identity. |
| Origin completion | PASS | Origin lane performs the only verdict attempt with original generation/packet id; duplicate/stale tokens do not create a second physical attempt. |
| Native return | PASS | Buffers remain live until completion classification and are returned through VPP native buffer lifecycle; final residue is zero for clean paths. Process death is classified as an explicit live-obligation failure before fresh restart. |

The only non-PASS closure item is the accepted multi-message limitation. This is
not hidden under an aggregate pass: S74 proves safe pre-admission rejection, not
independent no-copy materialization of multiple NFQUEUE messages from one
netlink datagram.

## Static ownership audit

Audited proven path: `experiments/vpp-nfq-poc/overlay/src/plugins/nfqueue_live_poc/nfqueue_live_poc.c`.

Command:

```sh
rtk bash experiments/vpp-nfq-poc/scripts/test-nfqueue-live-poc-s80-static.sh
```

Result: `S80 static seam: PASS`.

Static findings:

- No scratch rx buffer path: compile-time proof macro
  `NFQUEUE_LIVE_SCRATCH_BUFFER_PATHS == 0`, runtime CLI reports
  `scratch-rx-buffers 0`.
- No packet `std::vector`: plugin is C, and source search found no `std::vector`
  or `vector<` in the audited plugin path.
- No full-packet memcpy path: compile-time proof macro
  `NFQUEUE_LIVE_FULL_PACKET_MEMCPY_PATHS == 0`, runtime CLI reports
  `full-packet-memcpy 0`.
- No side lease registry: the obligation identity is carried in
  `vlib_buffer_t.opaque` plus fixed transport frames. S76's identity-evidence
  pool is test evidence, not an ownership table used to carry packet
  obligations.
- No second packet buffer in the admitted proven path: one `vlib_buffer_alloc`
  is used for each receive; reserve buffers are capacity/fail-open resources,
  not a duplicate packet representation for normal admitted obligations.
- No per-packet heap object: compile-time proof macro
  `NFQUEUE_LIVE_HEAP_OBLIGATION_PATHS == 0`, runtime CLI reports
  `per-packet-heap-objects 0`; source search found no `malloc`, `calloc`,
  C++ `new`, or per-packet allocation carrier in the plugin.
- No per-packet synchronous logs in the hot path: runtime evidence is bounded
  counters/CLI snapshots, not packet-by-packet synchronous logging.

Important code seams:

- NFQUEUE receive projects the kernel datagram directly into
  `vlib_buffer_get_current(buffer)` using `recv(..., base, capacity,
  MSG_DONTWAIT | MSG_TRUNC)`.
- All non-complete, oversize, or multi-message envelopes are rejected before
  `nfq_handle_packet`; the comment explicitly states one received VPP buffer
  cannot carry independent payload obligations without copying bytes.
- `nfqueue_live_owner_node` and `nfqueue_live_ingress_process_node` contain no
  `nfq_set_verdict`, `vlib_buffer_free_one`, or direct accept/free path; the
  S80 static seam checks this.

Exception: fail-open reserve/loss paths may allocate bounded reserve VPP
buffers for capacity fault handling. They are not a second packet buffer for an
already admitted obligation and report separate reserve counters.

## Measured evidence summary

### Buffer size and netlink/L3 envelope

- Host S73/S74/S79 clean pinned VPP path used the 9000-byte data patch. S74
  measured `bufferDataSize=9000`, exact boundary `datagram=9000`, usable payload
  `8940`, and oversize rejection at `datagram=9001`.
- Android S80 final path used `buffer-data-size 2048`. Observed ICMP netlink
  datagrams fit: `parsed-bytes` was `164` or `192`, and
  `usable-l3-envelope` was `104`.
- This means Android parity proves the live-buffer ownership path for the
  measured ICMP envelopes, not a 9000-byte Android capacity result. Production
  buffer sizing remains a release/capacity decision.

### Multi-message behavior

S74 deterministic envelope harness:

```text
multi ledger: messages=2 recoverable=2 rejection-attempts=2 native-returns=1 obligations=0 copies=0 residue=0 ids=11,12
mixed complete+truncated: messages=2 recoverable=2 rejection-attempts=2 native-returns=1 obligations=0 copies=0 residue=0 ids=11,51
S74 netlink envelope parser: PASS
```

Judgment: safe rejection PASS; independent one-buffer-per-message obligations
from a multi-message datagram remain unsupported/PARTIAL.

### Copy count and forbidden paths

Android S80 final evidence repeatedly reports:

- `payload-span-failures 0 packet-copies 0`
- `scratch-rx-buffers 0 full-packet-memcpy 0 per-packet-heap-objects 0`
- `copy-count 0 residue-obligations 0`

S76/S77/S78/S79 host evidence reports the same zero-copy/no-residue counters
across local, remote, stress, fault, reserve, and teardown cases.

### Local and remote handoff

- S76 host mixed run: `owner-local-obligations 16`,
  `owner-remote-obligations 17`, `owner-remote-handoffs 17`, and zero residue.
- S76 host local-only run: `owner-local-obligations 33`, no remote handoffs, no
  proof failures.
- S76 host remote-only/stress: remote obligations/handoffs reached `33/33` and
  stress reached `257/257`, with credits released and zero residue.
- S80 Android final remote runs: `owner-local-obligations 0`,
  `owner-remote-obligations 13..15`, `owner-remote-handoffs 13..15`,
  `identity-proof-matches 13..15`, `identity-proof-failures 0`.

Judgment: owner-local and owner-remote closure proven for the prototype; Android
specifically proves the remote mismatch path.

### Completion outcomes

- Normal Android S80 cases report `physical-verdict-attempts 13..15`,
  `completion-outcome-succeeded 13..15`,
  `completion-outcome-failed-definite 0`,
  `completion-outcome-unknown 0`, `send-failures 0`, `retry-attempts 0`.
- Duplicate/stale Android case reports `duplicate-attempts 1` and
  `stale-generation-completions 1` while keeping physical attempts equal to live
  obligations and final debt/residue at zero.
- S77 host fault matrix separately proves the injected outcome partitions:
  normal `33/0/0`, failed-definite `33/1/0`, explicit ambiguity `33/0/1`.

Judgment: NFQUEUE nonnegative verdict return is Adapter Completion `SUCCEEDED`
for the terminal operation only. It does not claim downstream network delivery.

### Peak/outstanding buffers and teardown residue

- Android normal: `normal-peak-occupancy 1`, outstanding obligations/debt/credits
  zero after disable.
- Android clean-drain: `normal-peak-occupancy 2`,
  `teardown-drain-accepts 1`, no deadline, no resource residue.
- Android process-death pre-cleanup ledger: explicitly records
  `PROCESS_TERMINATED_WITH_LIVE_CURRENT_GENERATION_OBLIGATION`,
  `held-obligation 1`, `completion-debt 1`, `completion-credits-held 1`, open
  queue/socket resources, and `residue-obligations 1` before process kill.
- Android fresh restart in the same case then returns to clean closure:
  `completion-debt 0`, credits held/residue zero,
  `native-buffer-returns 15`, `outstanding-obligations 0`,
  `residue-obligations 0`.
- Per-case residue captures show empty `/proc/net/netfilter/nfnetlink_queue`,
  empty VPP PID output, no S80 NFQUEUE hooks, and the remote runtime directory
  reduced to `startup.conf` and `source-provenance.properties`.

Judgment: clean teardown and fresh restart close with zero residue; process
death is not rewritten as clean and remains explicit fault evidence.

### Android parity measurements

Final Android matrix:

```text
normal-dual-owner-remote        PASS
duplicate-stale-completion      PASS
queue-clean-drain               PASS
process-death-fresh-restart     PASS
```

Linux-vs-Android comparison:

```text
IPv4 NFQUEUE live-buffer obligation             PASS/PASS/PASS
IPv6 NFQUEUE live-buffer obligation             PASS/PASS/PASS
metadata/copy-count/inline lease                PASS/PASS/PASS
owner mismatch/origin verdict/native return     PASS/PASS/PASS
duplicate/stale completion                      PASS/PASS/PASS
queue/process teardown                          PASS/PASS/PASS
fresh restart and zero residue                  PASS/PASS/PASS
```

Environment: Pixel 6a `28201JEGR0XPAJ`, Android 16 / SDK 36, arm64-v8a,
kernel `6.1.134-android14-11-g66e758f7d0c0-ab13748739`, root context
`u:r:ksu:s0`, SELinux Permissive, repo-local `./dev/adb`.

## Per-result audit ledger

| Result | Source revision | Artifact identity | Environment | One command | Raw evidence | Validity | Residue check |
| --- | --- | --- | --- | --- | --- | --- | --- |
| S73 initial live-buffer probe | VPP `9258530f3804a152578ce11cc7c8a1e9eab88ed0`; repo handoff records plugin hash `8a2dc0...` | `nfqueue_live_poc_plugin.so`, 9000-byte patch `439ac1...`; regular-memfd fallback `1ddd59...` | Host disposable user/netns | `rtk unshare -Urn env S73_LOCAL_DUMMY=1 S73_REGULAR_MEMFD=1 INJECT_STALE=1 INJECT_DUPLICATE=1 S73_EVIDENCE_DIR=/tmp/sakamoto-s73-evidence-ipv4-third ./scripts/run-nfqueue-live-poc.sh` | Repo-retained: `experiments/vpp-nfq-poc/SAKAMOTO-73_HANDOFF.md`. Current raw: `/tmp/sakamoto-s73-evidence-s77-align-default/` has `run.log`, `show-before-disable.txt`, `show-after-disable.txt` for a later aligned S73 path. Historical raw cited by S73 but currently missing: `/tmp/sakamoto-s73-evidence-ipv4-third/`, `/tmp/sakamoto-s73-evidence-overflow/`, and optional IPv6 smoke `/tmp/sakamoto-s73-evidence-ipv6-third/` (S73 explicitly says this smoke is additional evidence only, not a later-ticket claim). | Technical claim remains supported by repo-retained S73 counters and current aligned raw for the normal path; evidence retention is PARTIAL for the original IPv4/overflow raw directories. Optional IPv6 smoke raw is not retained and is not used as a later-ticket proof. | Repo handoff records zero outstanding/native-return closure; current aligned raw also reports `outstanding-obligations 0`, `residue-obligations 0`. Original overflow residue is repo-retained only. |
| S74 envelope/multi-message | VPP `9258530...`; plugin hash `63e7d41...` | Envelope harness plus live plugin | Host user/netns and deterministic C harness | `rtk bash experiments/vpp-nfq-poc/scripts/test-nfqueue-live-poc-envelope.sh` | Repo-retained: `experiments/vpp-nfq-poc/SAKAMOTO-74_HANDOFF.md` and `experiments/vpp-nfq-poc/tests/nfqueue_live_envelope_test.c`. Current raw: `/tmp/sakamoto-s74-envelope-test/` and `/tmp/sakamoto-s74-s78reg/`. Historical raw currently missing: `/tmp/sakamoto-s74-evidence-ipv4-mixed-final/`. | Envelope/multi-message rejection is currently reproducible via the deterministic harness; live mixed-final raw retention is PARTIAL. One-buffer-per-obligation remains PARTIAL by design. | Current harness reports `native-returns=1 obligations=0 copies=0 residue=0` for multi-message rejection; `/tmp/sakamoto-s74-s78reg/show-before-disable.txt` reports zero outstanding/residue for a later live single-message path. |
| S75 dual-stack ingress metadata | VPP `9258530...`; plugin hash `45cc181...` | Four NFQUEUE lanes ip4/ip6 INPUT/OUTPUT | Host user/netns, concurrent IPv4/IPv6 pings | `rtk unshare -Urn env S75_REGULAR_MEMFD=1 S75_EVIDENCE_DIR=/tmp/sakamoto-s75-evidence-normal-final ./scripts/run-nfqueue-live-poc-s75.sh` | Repo-retained: `experiments/vpp-nfq-poc/SAKAMOTO-75_HANDOFF.md`. Current raw: `/tmp/sakamoto-s75-s78reg/` has a later dual-stack live path. Historical raw currently missing: `/tmp/sakamoto-s75-evidence-normal-final/`, `/tmp/sakamoto-s75-evidence-fault-final/`. | Dual-stack metadata claim remains supported by repo-retained S75 counters and current later dual-stack raw; original normal/fault raw retention is PARTIAL, especially for missing-identity fault raw. | Repo handoff records after-disable zero outstanding/residue; current `/tmp/sakamoto-s75-s78reg/show-before-disable.txt` reports `native-buffer-returns 17`, `outstanding-obligations 0`, `residue-obligations 0`. |
| S76 worker ownership | VPP `9258530...` | Host live plugin plus deterministic ledger | Host user/netns with local/remote/stress/fault modes | `rtk unshare -Urn env S76_REGULAR_MEMFD=1 S76_OWNER_MODE=remote S76_STRESS=1 S76_EVIDENCE_DIR=/tmp/sakamoto-s76-evidence-stress ./scripts/run-nfqueue-live-poc-s76.sh` | Repo-retained: `experiments/vpp-nfq-poc/SAKAMOTO-76_HANDOFF.md`. Current raw: `/tmp/sakamoto-s76-evidence-s77-resume-stress/`, `/tmp/sakamoto-s76-s78reg/`. Historical raw currently missing: `/tmp/sakamoto-s76-evidence/`, `/tmp/sakamoto-s76-evidence-local/`, `/tmp/sakamoto-s76-evidence-remote/`, `/tmp/sakamoto-s76-evidence-stress/`, `/tmp/sakamoto-s76-evidence-queue-full/`, `/tmp/sakamoto-s76-evidence-credit/`. | Remote stress is currently raw-retained via the S77 resume stress rerun. Local/mixed/queue-full/credit-exhaustion original raw retention is PARTIAL and relies on repo-retained S76 handoff plus deterministic source seams. | Current S77 resume stress raw reports `257` obligations/verdicts/native returns, `completion-credit-acquired 257`, released `257`, and `residue-obligations 0`; other S76 fault residues are repo-retained only. |
| S77 completion outcomes | VPP `9258530...` | Completion outcome matrix | Host user/netns | `rtk unshare -Urn env S77_FAULT=normal S77_OWNER_MODE=remote S77_REGULAR_MEMFD=1 S77_EVIDENCE_DIR=/tmp/sakamoto-s77-evidence-matrix-normal-resume ./scripts/run-nfqueue-live-poc-s77.sh` | `/tmp/sakamoto-s77-evidence-matrix-*`, S77 handoff | Valid for normal, failed-definite, explicit unknown outcome classification | All rows report zero retry/re-entry/debt/outstanding |
| S78 reserve/capacity | VPP `9258530...` | Lane-local reserve matrix | Host user/netns and deterministic reserve ledger | `rtk unshare -Urn env S78_MATRIX_DIR=/tmp/sakamoto-s78-matrix-faultfix2 ./scripts/run-nfqueue-live-poc-s78-matrix.sh` | `/tmp/sakamoto-s78-*`, S78 handoff | Valid for reserve, loss, degradation and no dynamic growth/cross-lane borrowing | Matrix reports zero outstanding/residue after disable |
| S79 teardown/process lifecycle | VPP `9258530...`; plugin hash `0cf3bd...` | Teardown runner/matrix | Host user/netns | `rtk unshare -Urn env S79_MATRIX_DIR=/tmp/sakamoto-s79-final-matrix3 S79_ROUNDS=3 ./scripts/run-nfqueue-live-poc-s79-matrix.sh` | `/tmp/sakamoto-s79-final-matrix3/`, S79 handoff | Valid for queue-disable, clean stop, drain deadline, process termination, fresh restart, multiple generations | Clean rounds report zero obligations/ring/debt/credit/resource residue; process death explicitly classified |
| S80 Android parity | Evidence runtime revision `18dac1c`; audit HEAD `4f58d8c` | Android stage `android-s80-live-stage`; VPP SHA `0366e79...`; vppctl SHA `7200fb...`; plugin SHA `f5bbf23...` in final evidence | Pixel 6a `28201JEGR0XPAJ`, Android 16 SDK 36, arm64-v8a, repo `./dev/adb` | `rtk timeout 1200 env S80_STAGE=0 experiments/vpp-nfq-poc/scripts/android-run-nfqueue-live-s80.sh` | `experiments/vpp-nfq-poc/results/sakamoto-80-android-live-20260810-220318/`; LLDB repair evidence under `experiments/vpp-nfq-poc/results/sakamoto-80-lldb-20260810-214559/` | Valid for Android IPv4/IPv6 ICMP NFQUEUE live-buffer parity and four-case lifecycle matrix; not a product APK or Gate/L4 claim | Per-case residue files show no VPP PIDs, empty nfnetlink queue, no S80 hooks, only provenance/startup runtime files |

## Accepted design statements

Confirmed:

- Root/NFQUEUE packet I/O can execute inside a VPP-native C adapter without
  Rust owning packet bytes or live VPP buffers.
- Queue/lane identity is only initial placement; canonical owner mismatch must
  use software handoff and return terminal intent to origin.
- Handoff transports VPP buffer index plus inline identity/metadata, not packet
  bytes.
- Origin lane confines verdict operation to original queue generation and packet
  ID.
- Nonnegative `nfq_set_verdict` result is Adapter Completion `SUCCEEDED` for the
  NFQUEUE terminal operation, not downstream delivery proof.
- Duplicate/stale completion frames are ledger events and do not create a second
  physical verdict attempt.
- Teardown must quiesce, drain with completion channel live, close channels, and
  report residue/faults explicitly.
- Android can run the prototype through real IPv4/IPv6 NFQUEUE obligations after
  the S80 frame-queue readiness fix.

Contradicted or revised:

- "9000-byte data size is present on Android" is contradicted by S80 final
  Android evidence: `buffer-data-size 2048`. Host S73/S74 proves the 9000-byte
  patch path; Android S80 proves the measured 164/192-byte ICMP envelopes fit
  2048. Needed decision: production Android buffer sizing/capacity must be
  settled by HITL/ADR or a release capacity ticket before broad payload claims.
- "One netlink datagram with multiple NFQUEUE messages can be admitted as
  independent no-copy obligations" is contradicted by S74 design/evidence. The
  accepted safe behavior is bounded pre-admission rejection with direct verdicts
  and no admitted obligations. Needed decision: accept this as product behavior
  or design a VPP chain/multi-buffer strategy; do not silently copy.
- "Process death can be reported as clean zero residue" is contradicted by
  S79/S80 ledgers. The valid result is explicit
  `PROCESS_TERMINATED_WITH_LIVE_CURRENT_GENERATION_OBLIGATION` followed by
  external cleanup/fresh generation. Needed decision: product supervisor policy
  for automatic restart/backoff remains outside this POC.

Still unproven:

- Formal SAKAMOTO-68 Android Gate/L4 product slice, including policy parser,
  Network Gate/L4 matching, Debug Control Activity, Product UI, Activity Store,
  and release APK behavior.
- VPN/TUN parity for the final product closure matrix.
- Production capacity constants for queue count, worker count, buffer size,
  credit depth, reserve depth, throughput/latency/power/thermal/soak.
- Android payload families beyond the measured ICMP NFQUEUE parity envelopes.
- Real verdict-send native failure on a device, as opposed to injected
  failed-definite/unknown outcome seams.

## Return handoff

Return SAKAMOTO-72 to the main design flow with this conclusion:

The throwaway VPP-native NFQUEUE live-buffer prototype has enough evidence to
confirm the ownership architecture for a single-message NFQUEUE obligation:
direct receive into VPP buffer storage, inline fixed metadata, canonical worker
handoff by buffer index, origin-only verdict, honest completion outcome
classification, and native buffer return all close on both host and Android.

The return must carry three explicit limits:

1. Multi-message netlink datagrams are safely rejected, not independently
   materialized without copy. This leaves one-buffer-per-obligation PARTIAL.
2. Android final evidence used 2048-byte VPP buffers and only measured small ICMP
   envelopes; the 9000-byte envelope proof is host/pinned-VPP evidence.
3. Process death is explicit fault evidence plus fresh restart, not clean
   in-process teardown.

Return-design inputs for Plane SAKAMOTO-72 / SAKAMOTO-81:

- Multi-message behavior: S74's safe rejection is a confirmed POC boundary.
  Carry it back as design evidence when Plane-owned product work decides whether
  production Root behavior accepts rejection or adds a no-copy chain/multi-buffer
  admission design.
- Capacity: S80's Android proof is bounded to 2048-byte VPP buffers and the
  measured ICMP envelopes. Capacity constants and broader payload coverage must
  be chosen in Plane-owned release/capacity work, not inferred from this doc.
- Product promotion: the ownership seam is reusable evidence, but this
  throwaway plugin shape is not itself the SAKAMOTO-68 Gate/L4 implementation.
- Lifecycle: S79/S80 process-death evidence is a fault classification plus
  fresh-generation recovery input. Product supervisor restart/backoff behavior
  remains a Plane-owned design concern outside this handoff.
