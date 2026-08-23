# SAKAMOTO-126 OI-1 execution journal

Date: 2026-08-22 (host Linux, x86_64)

This is a test-only host proof of the owner-inline scheduler/wakeup seam. It
does not claim Android arm64 closure, Direct Egress, broker, multi-worker
isolation, or production readiness.

## Hypothesis

One pinned VPP worker can drive an opaque HEV/lwIP owner in bounded quanta,
return `RUNNABLE`/`WAITING`/`STOPPED` without unconditional self-requeue,
receive timer/FD wake tokens from a wait-only helper, reject stale/duplicate
wakes, keep callbacks on the owner thread, and remain fair to a VPP graph
sentinel even when the HEV side is always runnable.

## Build and identity

The HEV source was copied to `/tmp/oi1-hev`, the repository patch
`patches/hev-owner-inline-oi1.patch` was applied, and the library was built
with `make -C /tmp/oi1-hev -j4 shared`. The VPP overlay was applied to the
existing S119 build tree and the plugin was built with the repository PLY
fallback and a writable `/tmp` ccache directory.

```text
hev lib       bdebc1f33833d151df1ea719d52faa5d4d67881bb11208f874f61df5415d6685
vpp plugin    f713e309958ce76e1a8438fcbecdd009a1bf1154e719f35c2f6a99fc5881bfbc
vpp binary    5c4d1f707d2e7072a2da5974b76e3f7c43b13ecd823f2d76fbb91d5aa644908d
oi1 patch     12d2aaf28dcf6fa39ae435323770c5e553adf61412b9fcad7b67f58cc41fce37
oi1 plugin    97ea4f73e68e72d3e8ea31ed1d0abcf4d139a708be207509cad816cfa966bcd1
state model   8a9b870130e31a6e57ee75d3efa8117727f3f46ecb62296d586703e1f384c80d
```

VPP ran with two workers and `target-thread 1`. The HEV third-party library
path was supplied through `LD_LIBRARY_PATH`; the dynamic adapter itself was
loaded through `OI1_HEV_LIB`.

## Deterministic cells

All completed cells ended with `status=STOPPED` and `tasks=0`. The final
instrumented mixed and fairness cells additionally reported
`timer-residue=0`, `credit-residue=0`, `fd-residue=0`,
`foreign-callbacks=0`, and VPP buffer residue zero.

| Cell | Key result |
| --- | --- |
| Idle | Reached `WAITING` with `tasks=3`, `running=0`, no ingress; stop completed with `task-residue=0`. |
| Timer-only | `wakes=1`, `wait-publishes=1`, `timer=3`, `input=0`, `output=0`; timer progress came from a deadline wake, not TUN ingress. |
| FD-only | `wakes=1`, `wait-publishes=1`, `input=1`, `output=1`; the delayed source was consumed after an FD wake. |
| Packet-only | `input=1`, `output=1`, no wait helper required. |
| Mixed | `wakes=2`, `wait-publishes=2`, `input=1`, `output=1`, `timer=4`; timer and FD causes were both accepted in order. |
| Always-runnable fairness | `sentinel=64/64`, `first-owner-turn=2`, `last-owner-turn=2`; HEV did not starve the VPP sentinel. Final VPP accounting was `allocated=72 freed=72 residue=0`. |

The mixed cell initially exposed a real helper bug: the cancel byte remained
in the shared wait pipe, so a re-armed helper exited immediately and missed the
FD. Draining the cancel pipe before re-arm fixed the cell; the final mixed
trace contains both:

```text
oi1_wake stage=accept ... cause=4   # timer
oi1_wake stage=accept ... cause=3   # FD
```

## Wake and thread tripwires

In the second idle generation, the raw ledger showed
`wakes=1 stale=1 duplicate=1`: a previous-generation token was rejected, one
current token was accepted, and the same sequence was rejected as duplicate.
Every cell ran the foreign-thread probe and ended with
`foreign-attempts=1 foreign-rejections=1` while
`foreign-callbacks=0`; HEV/lwIP callbacks were observed on the bound owner
pthread only.

Representative bounded-turn trace:

```text
oi1_drive ... status=WAITING quanta=1 work=0 tasks=3 running=0
oi1_wait  ... generation=1 sequence=1
oi1_wake  ... cause=4
oi1_drive ... status=WAITING quanta=1 work=0 tasks=3 running=0
oi1_wake  ... cause=3
oi1_drive ... status=RUNNABLE quanta=1 work=1
oi1_drive ... status=STOPPED quanta=1 work=0 tasks=0
oi1_cleanup ... result=PASS ... timer-residue=0 credit-residue=0
oi1_cleanup stage=vpp-buffer allocated=11 freed=11 residue=0
```

## Conclusion / gate

**Host OI-1 hypothesis: GO for this bounded test seam.** The evidence
supports owner-thread-only HEV/lwIP callbacks, wait-only wake publication,
timer/FD progress without TUN ingress, stale/duplicate rejection, graph
fairness, and zero observed cleanup residue.

## Android arm64 / Pixel 6a gate

The gate ran on serial `28201JEGR0XPA` (Pixel 6a, Android 16,
`google/bluejay/bluejay:16/BP3A.250905.014/13873947:user/release-keys`) using
the repo-local `./dev/adb` wrapper.  The direct test runtime was pushed to
`/data/local/tmp/s126-oi1`; it used one VPP worker (`corelist-workers 1`) and
explicitly enabled `hev_external_driver_poc_plugin.so`.  `show threads`
reported `vpp_main` plus `vpp_wk_0`, and `show plugins` reported the OI-1
plugin loaded.

Artifact identity:

```text
VPP binary       269470772e6eacf432c82778045b7a513ec196f96412af0659a2be518dfc9572
VPPCTL           295804a96ebbae4cb57128c12b0f296b71459254718f63d89c8721e58e1ccb2c
OI1 plugin       244eeffd004a7d224223f2fd04664e087aae4b87f583f6c5a582fa140eeb5e42
HEV arm64        8b5b429f66dbb4e91129f347554c06d857d19aaf4a609886435d250ead89b989
startup.conf     7e5fd85bf6f8ea4dac6508c01102b0527f39b8600a99b1db5b343e1dbd324366
APK              9e1cde5087fb1ae7aa8cf84bad2cce727b841f2d4d55163cbaa67701127d470b
```

The APK was built with the same plugin and HEV members; the bounded gate used
the direct staged runtime so the test-only OI-1 CLI and worker target were
unambiguous.  The first launch exposed a staging-only path mismatch (a copied
startup file still pointed at the old `/data/local/tmp/vpp-nfq-poc` root and
loaded no plugin).  The stage was corrected, pushed afresh, and the gate was
rerun; no OI-1 code change was inferred from that setup issue.

Final CLI results (each cell was stopped and queried after completion):

| Cell | Result |
| --- | --- |
| Idle | `STOPPED`, tasks=0, input/output=0, VPP buffers 9/9, residue=0. |
| Timer-only | wakes=1, wait-publishes=1, timer=3, input/output=0, buffers 9/9. |
| FD-only | wakes=1, wait-publishes=1, input=1, output=1, buffers 9/9. |
| Packet-only | input=1, output=1, wait-publishes=0, buffers 8/8. |
| Mixed | wakes=2, wait-publishes=2, timer=3, input=1, output=1, buffers 10/10. |
| Always-runnable fairness | sentinel=64/64, first-owner-turn=2, last-owner-turn=2, buffers 72/72. |
| Stale/duplicate wake | wakes=1, stale=1, duplicate=1, then `STOPPED`, tasks=0, buffers 9/9. |

Across the cells, `foreign-callbacks=0`, `foreign-attempts=1`,
`foreign-rejections=1`, and final task/fd residue were zero.  The VPP stderr
cleanup ledger also reported `timer-residue=0`, `credit-residue=0`, and zero
VPP buffer residue for every completed cell.  The temporary VPP process was
stopped after collection and no VPP process remained.

**Host OI-1 hypothesis: GO; Pixel 6a arm64 gate: scoped GO.** This supports
the bounded owner-inline scheduler/wakeup seam on both host and the selected
Android device.  It does not authorize OI-2 (async broker), Direct Egress,
worker isolation, teardown generations, or a production topology decision;
pause for owner review before advancing.
