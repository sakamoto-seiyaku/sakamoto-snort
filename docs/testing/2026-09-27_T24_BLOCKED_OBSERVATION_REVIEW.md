# T24 independent Standards and Spec review

Fixed point: T23 commit `4f54165c659f5458d4c737c1f54c35bd127c74f8`.
The two read-only review axes inspected the T24-owned working-tree diff and
untracked additions. The 34 entering unrelated dirty paths were excluded.
The [T24 ticket](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/74a66a66-7be5-425f-8761-5ab18928d4ae),
[accepted Plane parent specification](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/28bb5f21-f21c-4018-a3c6-60a5dbfdb82e),
accepted ADR-0009 in the entering working tree,
[ADR-0010](../adr/0010-sqlite-observation-storage.md), and
[T24 Interface](../interfaces/T24_BLOCKED_OBSERVATION.md) were the Spec sources.
The repository's AGENTS/domain routing and the code-review smell baseline were
the Standards sources. Final Product source SHA-256:
`5c79abe77dffa4dd6aa9d5eadfc4f61660399a0c618356bb3fbda21ee8a39d3d`.

## Standards

The first independent pass found two P2 problems: Rust admitted blocked slots
up to the Flow capacity and allocated a Flow-sized blocked overview even
though the producer caps blocked slots at 1,024. It also found a P3 malformed
record path that counted a blocked record with valid actual-ALLOW attribution.
The fix makes direct transport health report `min(flow_capacity, 1024)`, gives
the Rust overview its own blocked bound, rejects odd-channel slots outside
that bound, and validates blocked actual-DROP/winner provenance at decode,
overview and store admission. The Standards reviewer re-read the patched diff
and reported **zero remaining findings**. No product or tracker edits were made
by that reviewer.

## Spec

The independent Spec pass confirmed those consumer-shape gaps and also found
that an idle blocked END had no explicit expired reason. The producer now emits
reason `2`; the consumer accepts blocked live records only with reason `0` and
blocked END only with reason `2`, while still allowing unavailable attribution
to remain unknown. A focused C test covers pending flush, threshold growth,
combined tail/END, capacity, rule changes, opposite direction and tuple reuse.
Rust tests reject malformed blocked action, winner, slot and END shape.

The Spec reviewer re-read the final source and replayed the sealed independent
Linux, Pixel Root and Pixel VPN packet oracle and adversarial mutations. It
reported **zero remaining findings**. The final evidence links and measured
limits are in the [results](2026-09-27_T24_BLOCKED_OBSERVATION_RESULTS.md).

The initial findings and failed exploratory collector runs remain in the
evidence index. Source-bound real packet reruns followed the substantive fixes;
the final Linux/Android artifacts share the SHA-256 above. Ordinary Rust tests
pass 45/45, CTest 51/51, native C→Rust six/six, actual ARM boundary and the
blocked C ASan/UBSan test pass. Optional `cargo fmt --check` reports formatting
differences in the inherited T23 service code and compact T24 test literals;
this repository has no formatter gate, and neither review axis found a
documented Standards violation.
