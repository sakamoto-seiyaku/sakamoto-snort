# T27 independent review

Two independent agents reviewed the T27 scoped implementation against the
Plane acceptance criteria and repository standards. Both review axes reached
zero remaining material product findings before final-source builds. Their
later evidence review found and closed verifier/report gaps before completion.

The Standards review identified an initially unbounded SQLite FULL recovery
path: 512 retries could each do eight pressure calls, and each pressure call
repeated up to 256 ordinary retention steps. It also noted that an ordinary
age expiry staged just before a pressure check could evict unexpired detail
before committing and remeasuring the age result. The final implementation
advances ordinary expiry once, commits and checkpoints it before elective
pressure removal, and bounds FULL recovery to 32 × 8 one-unit pressure steps.
If an age write itself fails FULL, bounded pressure work is allowed in that
same pending transaction so the age work can make progress. A smaller flush
threshold for a scaled tiny database prevents a large live tail from using
the capacity needed for a single write.

The Spec review identified maintenance errors that bypassed save-error and
coverage-gap accounting, and a possible deadlock when FULL occurred during
a large partial tier transition. The final error path records both the error
and gap. Pressure can retire END detail and unused rule-name links while a
partial tier transition remains the sole active tier change. A regression
proves that this does not duplicate totals or cancel the transition; the
forced SQLite FULL regression checks that a terminal capacity failure exposes
an error and incomplete coverage. The Spec reviewer found no remaining
concrete defect after those changes.

In the final evidence audit, Standards found that the independent verifier
compared declared source hashes without independently closing the hash over
the 1,326-file manifest, and did not inspect the stopped-device raw readback.
It now recomputes both Host and Android source digests, checks every frozen
source copy and dirty diff, hashes build artifacts, and reads the copied
ordinary SQLite, APK attestation, process table, hooks and device summary.
Standards also identified an unfrozen CLI helper used by the Pixel harness;
both profiles were rerun with that helper copied and indexed inside each raw
run bundle. The Spec evidence audit found that the first cost probe changed
only caller chunk sizes. A replacement compares durable flush every 64,
flush every 256 and automatic internal flush, plus idle-tick and receipt-path
rollup scheduling on the same 1,000-row fixture. All arrangements finish with
the same totals and SQLite integrity. The fixed 256-row maintenance page size
was not varied, and the report states that limit.
The report explicitly discloses conservative coverage gaps at each deliberate
process stop and distinguishes scaled Pixel ages from default 180-day Host
clock-boundary verification.

The final verifier is
[`verification-verified.json`](../../build-output/t27-20260927/verification-verified.json)
(`VALID`). The corresponding raw runs, failed attempts, controlled reproducer
and source-bound build witnesses remain under `build-output/t27-20260927/`.
