# T22 two-axis review — 2026-09-26

Fixed point: `379b61e7431db63018db9bf708e4246394f4b8d6`.
Review scope is only the T22 implementation/tests/contracts; 34 pre-existing dirty
files were excluded and preserved. Independent reviewers read the scoped working
diff against that fixed point and new files. Spec sources were live SAKAMOTO-273,
parent SAKAMOTO-251 and the authoritative unified-rule specification/ADR-0009.

## Standards

The independent reviewer identified one P2: newly created observation directories
were not durably published in their containing directory. A first revision synced
only newly created paths; re-review correctly identified that a failed/interrupted
attempt could leave a visible directory and let a retry skip that sync.

The final implementation creates only the immediate observation directory under
an established storage root and syncs its containing directory on every open,
including retries. The filesystem-boundary regression retains the failed parent
fsync and requires a successful parent fsync before the retry can be accepted.
The reviewer rechecked this implementation and GREEN evidence and closed P2.

No other concrete documented-standard violations or actionable P1/P2 baseline
smells were reported. Duplicated numeric wire layout details were noted as an ABI
maintenance consideration, covered here by assertions and native transport tests.

Final Standards verdict: **PASS; no remaining P1/P2 findings.** The reviewer
confirmed the current directory retry result, source/verifier identity consistency,
eight semantic negatives on each platform, confined test-only fault injection,
and accurate limits/failure reporting in the acceptance document.

## Spec

The independent reviewer identified one P2: stopping an empty/all-ended consumer
before draining could discard an entirely unseen queued lifecycle while clearing
the durable open-session marker without a coverage gap.

The final consumer marks every termination as incomplete unless quiescence/drain
can be proven; this implementation does not claim such proof. It preserves
committed baselines and never fabricates END. The actual C transport regression
pauses an empty consumer, enqueues an END, stops, reopens, and checks zero invented
traffic plus incomplete coverage. The reviewer checked the retained RED and GREEN
results and closed P2; no scope creep or additional issue was reported in that fix.

The initial review explicitly did not treat unfinished Linux/Android verification
as acceptance. Final pipeline evidence and boundaries are in the
[acceptance report](../testing/T22_PERSISTENT_MINUTE_ACCEPTANCE.md).

Final Spec verdict: **PASS for T22's stated scope; no outstanding P1/P2 or
blocking acceptance omission.** The reviewer checked the Linux 960-byte incomplete
pending snapshot and committed/restored/new-generation totals, inspected its
verifier and retained PASS evidence, and independently reran Android verification
with all eight semantic negatives. The reviewer explicitly did not rerun Linux's
protected-file verification. E01 remains the mandatory experiment/user-result
gate; this acceptance does not approve a release storage engine or later views.
