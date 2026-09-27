# T29 independent review

Fixed point: T28 commit `19c00f6a9438db6bd35f2f5980ffed748c9a93ed`.
The two axes independently reviewed the T29-scoped diff and evidence against
the repository rules and [SAKAMOTO-281](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/faaa95d4-dfb4-4a8e-9605-9fa22c207c64).
All 34 pre-existing unrelated dirty paths were excluded.

## Standards

The first review found that the new T29 docs cited an untracked ADR-0009
workspace file, and that the Pixel combined and stress verifiers could accept
`RAW_COMPLETE` even if final cleanup recorded an error. The docs now refer to
the existing Product interfaces without depending on that uncommitted file.
The verifiers reject `cleanup_error`; the combined verifier also rejects
`cleanup_config_error`. The negative suite validates every clean copied run
before corrupting it and rejects both cleanup-error mutations. The interface
now defines `transportTimeouts` as unresolved payloads, including multiple
pending payloads in one timed-out batch. The independent recheck found no
remaining hard standards issue. Repeated adb/state/UI/setup code in the
separate retained Pixel collectors is a nonblocking maintenance judgment.

## Spec

The first review found that the original Pixel QUIC probe finished before RTP
rule publications and that the combined verifiers checked winner/action but
not the full explanation. The bounded diagnostic driver now permits two
concurrent probes and reports a nonce-scoped capacity error for a third.
The final [Pixel combined verifier](../../build-output/t29-20260927/pixel-combined-k-verification.json)
checks the same QUIC Flow across a later revision while RTP remains active in
both Root and controlled VPN, and compares five rule explanations per profile:
winner, revision, effective mode, declared and actual action, source
availability and stable logical identity. The [Linux combined recheck](../../build-output/t29-20260927/linux-combined-b-recheck.json)
compares six analogous explanations. Both are `VALID`. The independent Spec
recheck found both findings closed, with no remaining finding in those areas.

The [results report](2026-09-27_T29_COMBINED_RESULTS.md) records final source,
device, stress, failure and cleanup limits. The [final negative suite](../../build-output/t29-20260927/negative-verification-final-e.json)
rejects ten mutations against clean baseline copies.
