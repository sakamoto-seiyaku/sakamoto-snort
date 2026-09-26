# T20 independent code review

Fixed point: `6bfe983fc963a46da14a708bffc8d66315c224ef`.
Reviewed commit: `e8a4dfdff16a418eee76a1807d6fc85d85700630`.
Command: `git diff 6bfe983fc963a46da14a708bffc8d66315c224ef...HEAD`.
Two separate agents reviewed Standards and Spec in parallel, read-only, under
the code-review skill. Existing unrelated dirty files were excluded.

Scope is [SAKAMOTO-271](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/7d77e5d6-cf66-49f2-ae7b-bec9a12b85ff),
the [preregistered experiment](../../experiments/t20-observation-ipc/PLAN.md),
parent specification §10 and ADR-0009. The user result-review/selection gate is
deliberately pending; it is not a missing implementation claim.

## Standards

One low-severity documented-evidence finding: the report originally said C/Rust
builds use warnings as errors, but the retained commands set C `-Werror` without
Rust `-D warnings`. The report now limits that statement to C and describes Rust
using its actual retained commands. The independent reviewer re-read the changed
paragraph and confirmed resolution; no native source or measurement changed.

No other concrete documented-standard breach was found. Changes remain isolated
experimental C/Rust transport code, preserve the ADR-0006/0007/0008 Product
boundary, use `dev/adb`, and leave selection explicitly pending. The report
distinguishes synthetic transport measurements from Product integration,
notification-policy differences, storage costs and Android qualification.

Read-only checks confirmed both retained verifications report PASS / 78 runs,
report build-manifest hashes match, and frozen source hashes match their
manifests. The reviewer did not rerun device workloads or Product tests.

No actionable optional smell finding. The duplicated workload expectations in
runner/verifier support independent envelope checking; consolidating them would
weaken that independence.

## Spec

No blocking Spec findings. User review and selection remain pending, correctly
reflected by T20 remaining In Progress. No premature completion or Product
backend selection appears.

No scope creep was found. The report distinguishes synthetic record transport
from Product accounting/storage and E01 qualification. Fresh-generation
replacement is described accurately; it does not claim in-place recovery,
replay, or Product FD/lifecycle qualification.

No wrong implementation was found against T20's transport scope. Specification
§10 requires bounded, nonblocking export and independent bounded channel
capacity/loss accounting. Implementation and retained evidence cover separate
channels, full/absent/paused/crashed consumers, independent counter queries,
generation rejection, and real C/Rust processes. Notification-inclusive timing
supports the comparison, which explicitly disclaims universal CPU superiority.

Read-only independent validation passed all 156 final run ledgers and both
run-to-build manifest bindings. No device operations or evidence edits were
performed. The same compiler-wording nit was reported and has been corrected.

Final counts: Standards 1 original low-severity finding, resolved, 0 outstanding;
Spec 0 blocking findings. User selection remains the required external gate.
