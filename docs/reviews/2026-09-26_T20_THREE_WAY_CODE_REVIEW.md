# T20 three-way independent review

Fixed point: `558b03a3192565f457c68fca545ef9f388ab1845`.
Initial extension reviewed: `51cb732729b336fcc522c4750df731c08bcd7035`.
The two independent reviewers separately inspected the subsequent corrections
and final retained evidence. Final native source closure:
`11f82153497bc90af1bc2d21bb1b6dbea9ce62225787ac11cb8a6b69c11075cb`.

Scope is the user's explicit three-candidate extension to SAKAMOTO-271, the
dated plan extension, parent specification §10 and ADR-0009. User selection remains
pending; the earlier condition on starting a third candidate was explicitly
overridden by the user. Product integration and T21 remain outside this delivery.

## Standards

No hard documented breach or actionable smell finding remains. The experiment
stays within the C/Rust boundary, preserves the earlier data and user gate, and
does not introduce a Product backend or import removed C++/packet POC source.

An optional wording finding noted that 1927 records of 136 aligned bytes leave
72 bytes, so `full_immutable` proves insufficient space for the next 128-byte
payload rather than exact byte occupancy. The final report distinguishes this
case, and the borrowed-reclamation test now directly asserts occupancy equals
the full byte capacity and rejects even a one-byte payload. The reviewer confirmed
resolution and found no new Standards issue in the wait-epoch correction.

Read-only final checks confirm current source matches both retained C snapshots,
both report build-manifest hashes match, Host/Pixel each have 135 final PASS runs
and 11 rejected mutations, and primitive evidence has nine groups. The report
retains the earlier VPP admission miss and qualifies the Aeron burst outlier
without claiming a fix or universal performance superiority.

## Spec

One original **P2 test-witness defect**, resolved: reading `wait_phase` only after
publication could count an old publication in a later consumer pre-poll phase.
Positive counts therefore did not prove the originally claimed race coverage.

The corrected witness brackets the queue call with reads of a monotonic 64-bit
epoch. Only the same odd epoch counts; odd begins after the empty check and ends
just before poll. Producer never waits for it. Regression cases reject entry
into a later window, exit from the current window and an odd-to-different-odd
transition. Shared-header magic v2 distinguishes the changed layout. This fixes
the witness; it is not a claim that a queue-ordering bug was found or repaired.

All three candidates were rebuilt and remeasured because the common producer
instrumentation changed. Read-only independent final verification checked all
270 corrected run records with strict per-run checks, both primitive results,
complete candidate/repetition matrices, unique generations, source/artifact
hashes, current source equality, all 12 Android installed-file hashes and cleanup.
The corrected witness counts are 9156–9583 on ARM64 and 9802–9839 on Host. Both
final verifications report PASS with 11 rejected mutations. **P2 is closed at
source and evidence levels.**

No remaining Spec findings. Earlier `pixel-matrix-b/2-boundary-vpp` admission
loss and final `pixel-matrix-c/2-burst-aeron` latency/admission outlier remain
explicit limitations, not hidden failures or claimed fixes. The recommendation
is accurately framed as a maintenance preference. User review and explicit
selection are still the required gate before T20 Done/T21.

Final counts: Standards 0 hard findings (1 optional precision issue resolved);
Spec 1 original P2, resolved; 0 outstanding findings in either axis.
