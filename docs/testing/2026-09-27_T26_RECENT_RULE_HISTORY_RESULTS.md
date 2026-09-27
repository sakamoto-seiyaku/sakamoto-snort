# T26 recent rule history acceptance

[SAKAMOTO-278](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/218d7e47-73cf-49b5-ba12-3666432acd6d)
adds historical rule interpretation to the existing VPP-native C observation
record and Rust SQLite consumer. The [interface contract](../interfaces/T26_RECENT_RULE_HISTORY.md)
defines what a recent rule window and END can say after an edit or deletion.
The full old rule definition is unavailable unless the saved, active VPP source
still matches its snapshot revision, content hash and complete rule version.

## Source and evidence

Base commit: `5889585755a774b77b99199fc1f2d43fd923c85b` (T25).
Final Product source SHA-256, independently witnessed by both Host
`build-output/t26-20260927/linux-build-f/build.json` and Android
`build-output/t26-20260927/pixel-build-d/build.json`:
`edb29608d687e9b2c05fb2da7ce7655d4c91b03387dd32494426395cc9b72c1d`.
The installed APK SHA-256 was
`3589b5bbd570d2f45c48e45e0d9fd8edd05a86e3211b1b9f9d1b749ddc5900e2`.
All runs, build witnesses, raw logs, source snapshots and failed attempts are
retained under `build-output/t26-20260927/`. The final evidence index hashes
15,666 retained files with zero readback mismatches:
`build-output/t26-20260927/evidence-index.json`, SHA-256
`811ddbf4ea83f3b2f4ac305171c7a44ac0e7e8c5910a451d5ac784b7567b41d4`.
The 34 unrelated dirty paths present at entry remained byte-for-byte equal to
`/tmp/sakamoto-t26-entry-dirty.json` throughout T26.

## Result

| Product path | Independent verification | Real packet paths / policy drops | Historical checks |
| --- | --- | ---: | --- |
| Isolated Linux Root NFQUEUE | `linux-history-source-f-verification.json` VALID | 12 / 2 | Six semantic mutations rejected; reopen after deletion |
| Physical Pixel Root | `pixel-root-source-d-verification.json` VALID | 12 / 2 | Six mutations rejected; UI Query, END and restart |
| Physical Pixel controlled VPN | `pixel-vpn-source-d-verification.json` VALID | 12 / 2 | Six mutations rejected; UI Query, END and restart |

The real packet oracles checked endpoint echoes, wire capture, native packet
decisions and the corresponding queried rule windows. A same logical rule was
renamed, revised with a different condition and action, then deleted. Each
historic window kept its complete 64-bit winner version, contemporaneous name,
actual action and directional counts; the two ended flows retained their last
segment interpretations. The current source supplied complete conditions only
while its saved and active identity matched. After deletion, the query kept the
old effects but reported the old conditions unavailable. The saved SQLite rows
reopened unchanged after a new consumer/service generation. The Pixel debug
Query button displayed those old names and unavailable condition state in
UIAutomator XML and a screenshot; the UI-owned temporary response file was
removed after reading. A separate raw Query readback corroborated the UI text.

The stopped-device [readback](../../build-output/t26-20260927/device-final-b/summary.json)
is PASS at generation 1665. It found SQLite integrity `ok`, all 1,422 T25
nonmetadata rows byte-for-byte intact and 1,575 current nonmetadata rows.
The original JSON SHA-256 remained unchanged. The installed APK hash and
KernelSU grant remained valid; both saved configurations were empty after the
runs, and VPP processes and owned NFQUEUE hooks were absent. The failed first
readback directory `device-final/` is retained: its shell command lacked the
quote required by Android `sh -c`; corrected `device-final-b/` passed without
changing device state.

Rust tests passed 59/59, including seven new history tests for name linking,
conflict, capacity, migration and reopen. The full Host CTest suite passed
51/51. Python syntax and `git diff --check` passed. Both independent review
axes closed with zero material findings; see the [review](2026-09-27_T26_RECENT_RULE_HISTORY_REVIEW.md).

The Root verifier initially used an exact global packet delta and failed when
the physical device completed an unrelated UID `4294967295` flow in the prior
minute, adding 25 origin packets during the first phase. The corrected
independent verifier accepts unrelated global packets while still requiring
the exact selected rule-window counts, native decisions, endpoint/pcap paths
and UI interpretation. Its six semantic mutations still fail. The retained
failed verifier output and unaltered raw run show that distinction.

The VPN run used the debug HEV validation path. Its runtime state reported
`protectionRunning=false` and `adapter=unavailable`; it proves the controlled
VPN Product packet path, not full authorized VPN protection. No battery or
sustained-load claim follows from these short runs. The 65,536-entry optional
version/name association skips new links at capacity, reports misses and keeps
packet accounting; T27 owns its retirement and complete retention policy.
