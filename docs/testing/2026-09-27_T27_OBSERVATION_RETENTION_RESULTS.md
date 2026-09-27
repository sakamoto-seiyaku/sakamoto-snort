# T27 observation retention acceptance

[SAKAMOTO-279](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/59efd142-a964-44e9-861c-e7291ff3d8e9)
implements the [retention interface](../interfaces/T27_OBSERVATION_RETENTION.md)
on the existing VPP-native C record and Rust SQLite consumer. A proven
directional increment is assigned to its last-activity UTC minute. Minute,
hour and day views retain one logical copy of each contribution. Active
cumulative baselines survive rollup; ended context can become a compact
duplicate-rejecting marker. Queries distinguish lifetime totals from retained
coverage and durable evictions.

## Source and evidence

Base commit: `7f8abcb68096c989f966938b9f0c2b53658aa07d` (T26). Final
Product source SHA-256 is
`1a2111f9b2325a9ee441fe9023ef373f3fecc6fe2ca60f5fdb8718a69695df8a`,
identical in the Host `build-output/t27-20260927/linux-build-final/build.json`
and Android `pixel-build-final/build.json` witnesses. The installed APK is
SHA-256 `c2154826e94dfbf3af919d0b0551a52163a6daf1ae130e26d4c6854dfb52f7a6`.
The [independent final verifier](../../build-output/t27-20260927/verification-verified.json)
is `VALID`. Raw runs, copied controlled-test code, build inputs and earlier
failed attempts remain under `build-output/t27-20260927/`.
The [evidence index](../../build-output/t27-20260927/evidence-index.json)
rehashes 9,763 retained files with zero mismatches; its SHA-256 is
`2512de0adee199df924121ba563a841db3b145dd353c9ddb2f2d0868be7a75ed`.
All 34 unrelated dirty paths present at entry still match
`/tmp/sakamoto-t26-entry-dirty.json` byte-for-byte.

## Result

| Path | Actual input and result | Storage and restart |
| --- | --- | --- |
| Linux Root NFQUEUE | Final-source real traffic oracle `VALID`: 12 packet paths, two policy drops, six rejected semantic mutations; saved history reopened after process replacement. | A copy of its real 7/5-packet SQLite store was driven across exact default 48-hour, 30-day and 180-day boundaries. Its minute became one hour, then one day, then `coverage.evicted=[7,5]`, while lifetime packets and bytes stayed `[7,5]` and `[644,460]`. Both staged databases passed SQLite integrity and FULL auto-vacuum checks. |
| Physical Pixel 6a Root | Two allowed exchanges reached the endpoint; two dropped exchanges did not. Host capture and the selected rule window independently showed the two allowed and two dropped decisions. | The isolated debug store passed a five-generation pressure/hour/day/expiry/restart sequence. After expiry, lifetime totals remained `[4,2]` and `coverage.evicted=[4,2]`. |
| Physical Pixel 6a controlled VPN | Same two allowed/two dropped exchanges and exact selected rule count. | The isolated store passed the same five-generation sequence with durable totals and eviction; debug HEV validation reported `protectionRunning=false` and `adapter=unavailable`. This is controlled Product-path evidence, not full authorized VPN protection. |

The Linux controlled run used the actual final-source packet producer's
SQLite database, copied before time or quota injection. The separate quota
copy started with one recent END and one minute bucket. A 96 KiB total
budget, including the database, SQLite SHM/WAL and test configuration, removed
the ended detail (`recent_count` 1→0) while keeping the minute bucket and
`[7,5]` lifetime packets; no aggregate count was evicted. The database and
indexes shrank from 32 KiB to 24 KiB, and the actual owned files totaled
57,551 bytes after reclamation. The controlled reproducer and its two
database copies are under `linux-controlled-final-source-b/` and
`reproducer/`. This checks the order of age and space changes on real
observations, while the Rust regressions cover late duplicate END, active
increments, rollback, clock changes, a partial transition, SQLite FULL and
restart.

Both Pixel profiles used an isolated `files/observation/t27-test/overall`
store selected only by a debuggable runtime marker. Their raw query and copied
SQLite snapshots show one minute bucket, a pressure-promoted hour, a day, and
then no retained bucket with `[4,2]` evicted packets. The pressure test used
an 86,016-byte budget; actual owned files were 45,252 bytes after pressure.
The stopped database and indexes shrank from 28 KiB to 12 KiB; the WAL was
zero bytes at every stop, and each copied database passed integrity and FULL
auto-vacuum checks. The highest observed owned-file total during either
profile was 61,637 bytes. Over a five-second idle interval each consumer
recorded one wait; sampled VPP process CPU increased one 100-Hz tick in each
profile and Android runtime CPU increased one tick in Root or zero in VPN.
Those process samples include observation and query work; they are not a
battery or sustained-load measurement.

The live Pixel traffic snapshots had zero reported coverage gaps. The
consumer conservatively adds one gap at each deliberate process stop because
it cannot prove that no producer record remained queued. The four restart
boundaries therefore leave `coverage.gaps=4` and `incomplete=true` in the final
Pixel stores, even though the selected observed flows retained exact totals.
The Linux source store similarly reports two gaps across its two process
lifetimes. Expiration also removes the retained bucket range; no missing
period between sparse buckets is claimed to be observed traffic loss.

The [stopped-device readback](../../build-output/t27-20260927/device-readback-verified/summary.json)
is `PASS` at generation 1689: no runtime/VPP process or owned NFQUEUE hook,
KernelSU grant intact, debug selector removed, installed APK attested, and
ordinary SQLite integrity `ok`. The ordinary SQLite and predecessor JSON
SHA-256 values match both before/after snapshots and the T26 handoff exactly;
the 1,575 pre-existing nonmetadata SQLite rows remain untouched. Each final
restart's saved rule configuration was empty.

## Bounded work and cost

Rust tests passed 72 with three ignored probes; the explicit 5,000-row
partial-transition query probe passed separately at 65 ms and 640,349 response
bytes. The final-source, 1,000-observation Host comparison changed the
durable schedule: flush after each 64-record caller batch, flush after each
256-record batch, or allow the consumer's own dirty-row threshold to flush a
1,000-record call. Each case completed the same paged minute→hour rollup with
seven maintenance flushes and no pending transition.

| Write schedule | Ingestion | Complete rollup | Commits / checkpoints | Query median / p90 | Actual files | WAL peak |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Flush every 64 | 184 ms | 148 ms | 26 / 25 | 35.1 / 38.9 ms | 5,570,560 B | 477,952 B |
| Flush every 256 | 125 ms | 144 ms | 14 / 13 | 34.9 / 36.9 ms | 5,574,656 B | 1,545,032 B |
| Automatic, 1,000 input | 125 ms | 146 ms | 13 / 12 | 35.9 / 38.8 ms | 5,586,944 B | 2,414,352 B |

Eager 64-record writes took longer and produced a smaller WAL peak; the
bounded 256-record schedule and automatic consumer schedule were similar for
this workload. A separate maintenance comparison held the 1,000-row input
and automatic write schedule fixed, then advanced the age boundary through
an idle `tick` or a receipt-path empty `consume` call. The idle path staged
1,536 dirty keys with no trigger-time commit and needed eight subsequent
flushes; the receipt path committed once during the trigger and needed seven
subsequent flushes. Both finished at 13 commits/12 checkpoints, 2,418,472 B
peak WAL, 5,582,848 B actual owned files, intact `[1000,0]` totals, and
186–187 ms full rollup time. Thus the experiment covers two real maintenance
arrangements, while the implementation's 256-row per-pass bound stays fixed;
it does not compare a second rollup page-size parameter. The cost fixture has
1,000 distinct application rows in one minute; query time
includes live projection and JSON serialization on this Host. SQLite
integrity was `ok` for each schedule store. The default 256 MiB owned-file
budget reserves 48 MiB for maintenance and caps the database plus indexes at
64 MiB. The product limits are 48 hours of minute rows, 30 days of hour rows,
180 days of day rows and 24 hours of END context. The Pixel exercise used
one-minute/two-hour/two-day/one-minute **scaled** lifetimes and explicit
clock offsets; its minutes of elapsed testing do not demonstrate 180 days of
physical-device retention. No per-packet timing is inferred from a coalesced
last-activity timestamp.

The independent verifier recomputed source/asset hashes, packet capture
payloads, rule counts, tier totals, all owned file accounting, SQLite page
sizes and integrity, restart generations, stopped processes and the preserved
ordinary history. Python syntax and `git diff --check` passed. See the
[review](2026-09-27_T27_OBSERVATION_RETENTION_REVIEW.md) for the two independent
code-review axes and closed quota findings. The earlier `pixel-root-a` harness
assertion and `pixel-root-b` over-reclamation failure are retained; the former
misread a genuine DROP rule count, and the latter drove the final pressure
recheck fix. A final-source T23 Linux smoke was also retained, but the T26
real-packet oracle and T27 controlled run are the acceptance evidence.
