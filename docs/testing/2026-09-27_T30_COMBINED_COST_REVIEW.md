# T30 independent review

Fixed point: T29 commit `04f5852b52cb7247470d60dbbeb3aac6dee46331`.
The two axes independently reviewed only T30's scoped diff, current
[SAKAMOTO-282](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/0787fc9d-808b-48f5-bb2c-b7cacab78a5c)
acceptance and retained raw evidence. The 34 pre-existing unrelated dirty files
were excluded and later rechecked byte/status identical.

## Standards

The first pass found no substantive repository-standard violation or material
Fowler smell in the Product-neutral cost work. A supplemental review found that
the ARM64 compiler helper could leave its `/data/local/tmp` directory if push,
permission or hash verification failed before entering cleanup, and that added
Linux endpoints lacked a kill fallback after a termination timeout. Both paths
now use guarded cleanup. The helper also verifies that each saved configuration's
parent Product build has the exact same native C/header/rax source hashes as its
Host or ARM64 binary. The reported matcher timings are explicitly loop-inclusive
of assertions and signature accumulation. The independent final recheck reports
**zero hard findings and zero material smells**.

No POC or removed C++ source was imported. The original T29 default packet
oracles still return `VALID` after the optional T30 workload flags and verifier
parameter were added. Scoped `git diff --check` and Python syntax pass.

## Spec

The first pass found two partial requirements: extra rules/names originally
increased scale but did not keep R2/R3 detector work active with R4/QUIC, and
the original evidence timed full apply without isolating native configuration
activation and query work. The source-bound
[Host](../../build-output/t30-20260927/compile-host-run-d/result.json) and
[physical ARM64](../../build-output/t30-20260927/compile-arm-run-d/result.json)
helpers now time the same Product C saved-source activation, including a test
publish callback, and exact-domain/RTP matcher loops on all three current
source shapes. Their report states the excluded save/IPC/VPP-barrier work.

The [four-flow Linux Product run](../../build-output/t30-20260927/linux-supplement-f-verification.json)
adds simultaneous R2 SMTP, R3 OpenVPN, R4 RTP/STUN and QUIC/SNI/domain across
three publications. It joins endpoint bytes, native admissions, winners,
observation windows, LPI/SNI work, caches, owner allocation and normal stop;
both its own oracle and the inherited T29 oracle report `VALID`. Root and
controlled VPN retain their separate verified two-flow phone cost runs. The
independent Spec recheck finds **zero remaining missing, incorrect or scope
creep findings** within this representative ticket. Broader detector pairs,
full Android VPN release protection, full-capacity device load and long-term
power/retention qualification remain explicit limits in the
[results](2026-09-27_T30_COMBINED_COST_RESULTS.md).

Summary: Standards 0 findings; Spec 0 findings. CTest 51/51, Rust 73 passed /
three ignored, Android runtime contract PASS, five-case cost oracle `VALID`,
native packet timing `VALID`, and final stopped Pixel readback `PASS`.
