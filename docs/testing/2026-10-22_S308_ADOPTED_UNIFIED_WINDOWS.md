# S308 adopted packet path and unified windows

2026-10-22. Implementation of the user's accepted
[ADR-0012 packet-path and window decisions](../adr/0012-configurable-flow-owners-and-dedicated-vpn-tun-io.md).
This qualification is separate from the earlier
[S308 CPU attribution](2026-10-22_S308_VPN_IO_CPU_ATTRIBUTION.md).
Those historical controls, measurements and artifact identities retain their
original meaning. This package has no new comparative CPU result. Parent
acceptance and current work state are tracked in
[SAKAMOTO-293](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/727dbca5-9a92-46c1-89b5-a068eb51022d).

## Implemented rules

| Item | Current rule |
| --- | --- |
| Packet-path topology | Read validated generation-local graph owner count and Adapter kind; no per-packet environment parsing |
| Primary packet credits | 48 per canonical target owner, Root and VPN; explicit diagnostic overrides remain |
| TUN collection and callback budget | 64, independent of TCP experiments; submit every valid partial batch before callback exit |
| Primary publication | Up to 64 across owners, reserving each packet's own owner credit |
| Completion publication and existing retry | 64 |
| Origin/I/O consume and native reclamation | 64 plus final partial window, including received native frames larger than 64 |
| Owner-local return graph frame | Native VPP capacity 256; submit available work without waiting to fill it |
| TUN output | One nonblocking write per packet, individual immediate result and settlement/free |

The shared `PRODUCT_HANDOFF_COMPLETION_WINDOW` drives collection, publication,
retry and reclamation. Policy snapshot cadence16, prepare/unroll4, Root platform
receive budget and native queue element capacities are separate units and retain
their previous settings.

Primary credits return at owner processing entry, or on publisher settlement of
an enqueue failure. They do not remain occupied until TUN completion. Mixed-owner
publication can reach64; a single owner's48 credits are not a global batch cap.
Credit exhaustion first flushes collected work, then follows the existing bounded
admission path. With no consumer progress, packet49 for one owner can fail after
the first48 publish; this does not spill into another owner or wait for credits.

HEV/lwIP spans still describe one packet. Each return uses its independently
owned VPP buffer and existing copy. The output callback schedules native graph
work and returns before that work runs. Completion does not turn a batch into a
delivery acknowledgement or retry unit. Native free precedes release of that
packet's return stamp and credit. No persistent queue, fill timer, payload copy,
owner rerouting or new retry policy was added.

## Frozen artifact and cache evidence

Qualification APK:
`build-output/s308-final-unified64-20261022/apk-cache-proof/first/sakamoto-runtime-debug.apk`.

| Artifact | SHA-256 |
| --- | --- |
| APK | `fbb5cd3bf98ad2df0304572bbdcf564b485336f3f4e8cfb6b8f76a348169c1a2` |
| Stripped Product plugin | `798c1f42a5768a1c21db4e7c02bad466bb1b272aced4b71d042bfc75ea8e075d` |
| Matching frozen unstripped plugin | `cb946bfb1085a08d498e164101ef14dc310eefa8cb7298d5d8c73b444bf35e46` |

The frozen unstripped plugin is in the same evidence directory's `symbols/`.
Stripping that copy reproduces the staged plugin exactly. `source-hashes.json`,
`source-snapshot/`, native ZIP hashes and `symbol-verification.json` retain the
source-to-artifact chain. Additional source and seam hashes are in
`build-output/s308-final-unified64-summary-20261022/source-and-seam-hashes.json`.

Both builders reused persistent Product caches. Android first/repeat used
0/0 Rust compilations and10/0 Ninja actions; the unchanged repeat retained all758
compiled-file hashes, sizes and timestamps and byte-identical native payload.
Host retained756 compiled files with zero repeat compilation. APK publication
reused Java/DEX compilation in both passes; DEX stayed identical. Its signed APK
hash changes between publications because packaging/version allocation still
runs; the first APK above is the sole device qualification target.

Raw cache proofs and commands:

- `build-output/s308-final-unified64-20261022/result.json`
- `build-output/s308-final-unified64-host-20261022/result.json`

## Host and Android gates

Full Host CTest passed **69/69**, using the exact fresh Host Product artifact via
`PRODUCT_ARTIFACT_DIR`; the builder-only VPP stage environment was unset for
tests. Both Android contract scripts passed. Logs and environment identities are
retained under the Host evidence directory above.

Eight focused current-source checks passed in
`build-output/s308-unified64-verification-20261022/targeted-checks.json`.
The shared helper matrix covers15/16/17,47/48/49,63/64/65 and255/256/257;
single/mixed owners, partial and nonprefix rejection, held completions/retry,
original buffer identities, Root receive-pool returns and VPN native free.
It proves mixed-owner64 publication and single-owner48 capacity separately,
and proves larger origin frames are actually fetched/consumed/freed in64 windows.

The actual Root verdict helpers additionally pass scalar, sendmmsg, packed and
default-mode tests at the upper64 indexes: successful prefixes, unknown/short
results, reordered identities, mixed lanes and nonprefix invalid identities.
The original16 implementation failed the new17-packet boundary as expected
(`root-verdict-before.log`); `root-verdict-after.log` passes. Both shared helper
and verdict matrices use nonrecovering UBSan.

The return adapter seam executes TCP OFF/ON and N1/N3 owners. It verifies native
next selection, NULL-source fallback, mixed packet write results and free-before-
credit release. Successful writes use a real nonblocking pipe; short/EAGAIN in
that callback test use the existing validation-result seam. Existing independent
TUN-write tests cover the actual short/EAGAIN syscall behavior. The pinned-VPP
enqueue test executes its real inline append implementation at255/256/257 and
existing partial-frame boundaries, with controlled get/put frame primitives;
it does not claim to simulate the complete VPP scheduler. A portable environment
without the pinned source reports that native portion as SKIP explicitly.

## Pixel functional qualification

Pixel6a `28201JEGR0XPAJ`, only repository `./dev/adb`, saved controlled
`Openwrt_5G`. No profiler or comparative performance campaign was run.

Ordinary N1/N3 TCP functional windows both passed. Their manifests omit primary
credit and capture overrides; before/after CLI confirms native defaults48 and64,
read budget64 and publication window64. Every owner reports return admission
vectors exceeding frames, proving actual multi-vector scheduling. Both native
stops settle all debts, and the original APK is restored after each case.
The phase-owned Host endpoint was command-checked and terminated, with gone
proof retained. Raw campaign:
`build-output/s308-final-unified64-tcp-functional-20261022/campaign.json`.

The following completed device cases retain the same exact APK/native identity:

| Case | Result and independent check |
| --- | --- |
| N1 short write with stress ingress and flow close | PASS, S298 exact buffer/token/credit verifier |
| N3 EAGAIN with stress ingress and flow expiry | PASS, S298 verifier |
| N1/N3 held completions at native capture default64 | PASS, S301 held-original verifier |
| N3 pre-stop draining then next-generation stale return | PASS, S302 generation adjacency and cutoff verifier |
| Held return stop: N3 short, N1 EAGAIN, N3 success | PASS, S302 individual post-cutoff write/result/settlement verifier |
| N3 stop during congestion | PASS, pending-at-cutoff and exact completion/free identities |
| Root N1/N3 ALLOW/DROP, zero credits, recovery and restart | PASS, S303 independent verifier |

Raw campaigns:

- `build-output/s308-final-unified64-fault-functional-20261022/campaign.json`
- `build-output/s308-final-unified64-stop-root-functional-20261022/campaign.json`

The first campaign deliberately remains INCOMPLETE: its subsequent N1 physical
ring-pressure attempt failed to trigger the required cause. With explicit scalar
capture1, credits48 and completion slots2, six64-packet bursts settled with
`deferred=0`, `retries=0` and zero pending/handoff debt. The collector correctly
retained HOLD rather than a false ring-full PASS. Unlike the prior16-window runs, this64-window fixture did not fill the native
ring. Reduced fragmentation is a plausible explanation; this arm did not isolate
it from scheduling/drain differences. This is untriggered fault evidence, not a
demonstrated settlement failure.
The completed held-original cases are separate causes and do not replace a
native ring-full test. The external consumer-pause qualification below subsequently established the
required native ring-full cause without changing Product capacity or semantics.

### Actual native ring occupancy and recovery

An external helper opened Product memory read only, verified the current
PID/TID/generation/topology and empty diagnostic ring, then used
`PTRACE_SEIZE`/`PTRACE_INTERRUPT` on the I/O TID alone. Its maximum pause is1.9s
with a2s alarm and checked detach. No worker-barrier CLI ran while I/O was paused.
The helper observed actual queue `head`, `tail`, `valid`, vector count and Product
deferred/pending counters through addresses derived from matching Android
ELF/DWARF and runtime maps. Native slots2 allow one occupied element.

| Qualification | Observed full state | Pause through successful detach |
| --- | --- | --- |
| N1, generation2537 | head1, tail2, slots2, valid1, deferred1, pending1 | 12.086ms |
| N3, generation2540 | head1, tail2, slots2, valid1, deferred1, pending1 | 12.539ms |

Both returned to an empty ring, retried retained work and independently verified
all65 return buffer/token identities through copy, individual successful TUN
write, completion, native free and after-free credit release, followed by zero-
debt native stop. TracerPid was0 before and after the bounded fault. N1's initial
Java probe independently proves65 native writes; it does not prove65 application
receipts. N3's held-open same-UID receiver additionally proves unique receipts0–64.
N3 sent the65 responses at a fixed5ms interval; the helper detached immediately
on full+defer rather than waiting for all responses.

The unpaced N3 attempts remain HOLD: host sent65, but only33 reached return
copy/completion. The same33 limit with a held-open receiver falsified the early-
Java-close hypothesis. One fixed instrumented unpaced diagnostic found the
protected UDP socket's `rx_queue=0`, `drops=0` before/after/final and no increase
in `Udp.RcvbufErrors` or `Udp.InErrors`; it did not observe a readable32-packet
backlog. This neither establishes kernel receive-buffer overflow nor proves all
possible readiness defects absent. The precise loss cause before protected UDP
reception is unresolved. The paced PASS proves its ring/retry/settlement cause;
it does not explain or relabel those burst failures as successful.

Raw attempts, corrected hypotheses and independent verifier:

- `build-output/s308-native-ring-diagnosis-20261022/summary.json`
- `build-output/s308-native-ring-diagnosis-20261022/independent-verifier-final.log`
- `tests/evidence/verify_s308_native_ring.py`

### Intermediate restoration

After Root tests, exact original app-owned rules were atomically restored and
SHA-256 checked in `s308-final-unified64-summary-20261022/rule-restoration/`.
After the complete functional phase, the original APK
`cc329acc906ba6ce8dd6e626c2849de1e9f335a96e2548a7ea3ab2becf9a1110`, rules
`2b24ea2630d231e9f52f014aa8a64ae1ba593d1f1371389f05c92b97517a450f`, saved
`CU_7WFb_5G`, stopped runtime and no VPP/NFQUEUE/profiler/test helper state were
verified. Evidence:
`build-output/s308-final-unified64-summary-20261022/functional-restoration/result.json`.
The user subsequently authorized a separate fixed TCP download/CPU qualification;
its protocol and results are recorded separately, with another final restoration.

## Review and retention

Independent explicit GPT-6.1 Spec and Standards code reviews found no Product
correctness or documented-standard violation. The UBSan recovery recommendation
was applied and rechecked; both reviewers verified all eight current-source
evidence hashes. The additional tools passed Standards rechecks, including historical CPU-schema
compatibility and independently scoped receiver receipts. The final combined
report and performance/restoration review were completed during S308 closeout.
The [TCP download and CPU record](2026-10-22_S308_TCP_DOWNLOAD_CPU.md) and
`build-output/s308-final-closeout-summary-20261022/summary.json` retain the final
results and review receipts.

Raw evidence, APKs and symbols are local gitignored artifacts, not a portable
archive. The committed report and tests retain their named evidence paths and
identities; reproducing device acceptance requires those raw files or a new
qualified run.
