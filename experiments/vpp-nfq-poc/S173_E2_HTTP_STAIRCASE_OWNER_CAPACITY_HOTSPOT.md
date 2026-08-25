# S173 E2 HTTP staircase owner-capacity hotspot (2026-08-25)

## Status

`CLOSED_FOR_BOUNDED_HTTP_STAIRCASE_SLICE`.

S172 remains accepted as the count-bounded one-GET Direct/HEV/OI3 matched HTTP
baseline construction slice. S173 extends that only to a bounded 4-request
foreground HTTP staircase. It does not prove arbitrary TCP concurrency,
throughput capacity, thermal/power behavior, or the final EG-17 performance
verdict.

The hotspot is recorded as `VPN-F050`.

## Initial evidence

Before the hash-quality correction:

- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-132622-224298.csv`
  showed that a 2-request staircase could pass: Direct `2/2`, HEV `2/2`, and
  OI3 `2/2`.
- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-132911-843206.csv`
  showed that a 4-request staircase failed only in OI3: Direct `4/4`, HEV
  `4/4`, OI3 `requests=4 successes=3 errors=1`, OI3 cleanup `7/0`.
- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-134129-897385.csv`
  showed the old 6s-paced OI3-only run still failed `3/4`; its VPP evidence
  showed all accepted/rejected request hashes landing on owner 0.

Harness and hash-quality corrections:

- `scripts/android-run-s172-e2-http-baseline-sample.sh` writes raw cell
  evidence under `evidence/.../cells/<run-id>/<cell>/`, preventing later runs
  from overwriting earlier per-cell logs.
- `SnortVpnService` and `MainActivity` accept and forward
  `requestIntervalMs`, so staircase pacing is explicit in the app log and run
  manifest.
- `owner_inline_oi3.c` applies a MurmurHash3-style final avalanche after
  FNV-1a and before owner modulo selection. The intermediate rebuilt Android
  OI3 plugin was
  `2ed7dc0183ce209a0a9ace497ad33c89af5084f407a4f814f50bd7ab3d7f64a9`.

After the hash-quality correction alone:

- Unpaced OI3-only run
  `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-135431-402507.csv`
  still failed `requests=4 successes=3 errors=1`, OI3 cleanup `7/0`.
  `vpp-stdout.log` confirmed `hash=fnv1a+mix`, improved owner distribution,
  and a rejected new SYN on an owner whose previous generation was still
  active: `reason=owner-busy`.
- 6s-paced OI3-only run
  `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-135602-091258.csv`
  also failed `requests=4 successes=3 errors=1`, OI3 cleanup `7/0`. The app
  log recorded `requestIntervalMs=6000`; the fixture received only three GETs.

## Root cause

High confidence:

1. Raw FNV owner collapse was a real sub-problem and is corrected by
   `fnv1a+mix`.
2. The remaining failure was not an APK, ADB, fixture, or HTTP-parser issue.
   Direct and HEV passed the same request shape, fixture logs received only
   three OI3 GETs, and OI3 cleanup was otherwise clean.
3. OI3 multi-owner selection is deterministic `hash % owner_count`. It is not
   an idle-owner allocator, and each owner had one active TCP generation. A new
   sequential HTTP TCP connection could therefore hash to an owner whose
   previous generation had not finished teardown/re-arm.

## POC design correction

The selected fix preserves the per-worker ownership decision in
`docs/decisions/PER_WORKER_FLOW_OWNERSHIP.md`: a flow is not moved to another
idle owner. Instead, a successor TCP SYN remains bound to its canonical owner
and is queued owner-locally until that owner can re-arm.

Implemented in `owner_inline_oi3.c`:

- `OI3_TUN_DEFERRED_KIND` carries successor SYN packets to the canonical owner
  without submitting them into the current HEV context.
- `multi_deferred[]` is a bounded owner-local deferred queue keyed by flow
  hash; SYN retransmits are deduplicated by hash.
- `owner-busy-deferred` records a busy canonical-owner SYN that is queued
  instead of dropped.
- When the current TCP generation has already produced a direct rewritten
  response, the deferred successor SYN forces the completed active owner toward
  bounded stop/re-arm.
- `oi3_admit_deferred_tun_flow()` promotes exactly one deferred SYN after
  `oi3_rearm_tun_flow()` publishes the completed generation's tombstone/wait
  state.
- Normal admission now rolls back `active_flow_hash/active_flow_valid` if the
  VPP handoff enqueue fails (`reason=admission-rollback`).
- Late non-SYN packets from a previous generation are classified as
  `tcp-non-syn-busy`, not as the original successor-SYN capacity failure.
- A second defect found during repeat testing is also fixed: TCP pending tail
  already queued on an owner is cleared at re-arm (`tcp-rearm-stale-tail`) so
  stale packets cannot be submitted into the next deferred successor context.
  UDP pending preservation remains unchanged.

The behavior is locked by
`experiments/vpp-nfq-poc/scripts/tests/test_verify_s158_multi_owner.py`.

## Closure evidence

Intermediate regression after the first deferred-SYN fix:

- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-142114-146880.csv`
  ran OI3 repeat=5. Four cells passed, but `oi3-r3` failed `3/4` with cleanup
  `6/1`.
- `oi3-r3/vpp-stdout.log` showed two successful `owner-busy-deferred`
  promotions, then `pending=2` at the next re-arm and
  `oi3_cleanup result=FAIL ... output=1 direct=0`. That proved stale TCP
  pending tail could be mixed into a deferred successor generation.

Final OI3 stress closure:

- Final OI3 plugin:
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`.
- Final comparison APK:
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4`.
- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-142858-176008.csv`
  ran OI3 repeat=5 with `MAX_REQUESTS=4`, `REQUEST_INTERVAL_MS=0`. All five
  cells passed `requests=4 successes=4 errors=0`, `contentLengthCompletions=4`,
  cleanup `8/0`, `valid=1`, `failures=0`.
- The same run's VPP logs show `owner-busy-deferred`,
  `multi-deferred successor SYN forces completed active owner toward rearm`,
  and `multi-deferred admit` in every repeat. Late old-generation packets are
  classified as `tcp-non-syn-busy`; no cleanup failures are present.

Matched Direct/HEV/OI3 staircase closure:

- `evidence/s172-e2-http-baseline-sample-20260825/cells-20260825-143509-282679.csv`
  ran the original matched 4-request shape with Direct, HEV, and OI3:
  Direct `4/4`, HEV `4/4`, OI3 `4/4`, all `valid=1`, `failures=0`.
- The run validity file records APK
  `441b0279e2685d0d89b6092ce00f64e49742a1fcfaaf691611c826a20fca97c4` and
  device OI3 plugin
  `9282f8c82c5223e2c7b144f85a2533100df646ec821ff0ef91737b9ef8a85186`.
- OI3 in this matched run hit `owner-busy-deferred` twice and still completed
  `4/4` with cleanup `8/0`.

## Remaining non-claims

- This is not a general TCP connection-pool proof.
- This is not SYN-time idle-owner selection or a flow-table pinning design.
- This is not a throughput/soak/thermal/power closure.
- `tcp-non-syn-busy` rejects are late stale non-SYN packets from previous
  TCP generations; they are classified separately from the fixed successor-SYN
  owner-capacity cliff.

## Next execution rule

- S172 one-GET matched HTTP baseline: accepted.
- S173 four-request foreground HTTP staircase: accepted for the bounded
  Direct/HEV/OI3 comparison shape above.
- Continue remaining E2 work. If a new repeatable architecture cliff appears,
  record it separately instead of reopening F050.
