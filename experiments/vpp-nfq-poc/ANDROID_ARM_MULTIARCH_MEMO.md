# Android ARM Multiarch Memo

Date: 2026-06-23

## Summary

Current Android VPP POC disables VPP's AArch64 multiarch variants to reduce runtime size, but it does not disable the baseline ARM optimization path.

The current runtime still uses:

```text
-march=armv8-a+crc
```

That keeps AArch64 baseline codegen, NEON helpers, and ARM CRC32 intrinsic support. The disabled part is the repeated compilation and runtime dispatch for server-style ARM variants such as Octeon TX2, ThunderX2, Cortex-A72, and Neoverse.

## Important Distinction

VPP multiarch is not per-thread or per-core dispatch.

It is effectively process/function-level selection:

```text
process startup
  -> register compiled variants
  -> compute clib_cpu_march_priority_<variant>()
  -> select a function/node variant
  -> workers use the selected function path
```

It does not do this:

```text
worker on Cortex-A55 -> A55-specific function
worker on Cortex-A76 -> A76-specific function
worker on Cortex-X1  -> X1-specific function
```

That matters for Android big.LITTLE SoCs because worker placement and code variant selection are different mechanisms.

## Pixel 6a CPU Shape

Observed device CPU parts:

```text
CPU 0-3: implementer 0x41, part 0xd05, Cortex-A55
CPU 4-5: implementer 0x41, part 0xd0b, Cortex-A76
CPU 6-7: implementer 0x41, part 0xd44, Cortex-X1
```

VPP's current ARM multiarch table covers:

```text
octeontx2
thunderx2t99
qdf24xx
cortexa72
neoversen1
neoversen2
neoversev2
```

It does not include Cortex-A55, Cortex-A76, or Cortex-X1.

## Current Judgment

Disabling ARM multiarch for this Android POC mostly removes server/infrastructure ARM variants. It does not remove a known Android phone SoC-specific A55/A76/X1 fast path, because upstream VPP does not currently provide that path here.

The remaining risk is performance uncertainty:

```text
functional risk: low, already covered by Android datapath regression
size benefit: high, release stage 29M -> no-multiarch stage 11M
performance risk: needs throughput and latency measurement
```

## Next Experiment

Keep the current no-multiarch baseline for functional and idle-power POC work.

For performance:

```text
1. Pin VPP main/worker placement explicitly.
2. Measure throughput and latency on:
     low:        main=0 workers=1-2
     single-mid: main=0 worker=4
     big:        main=4 workers=6-7
3. If CPU-bound, evaluate whether an Android-specific variant is worth adding.
```

If optimization is needed, likely candidates are not the existing server variants. More relevant options would be:

```text
Cortex-A76-oriented build flags
Cortex-X1-oriented build flags
explicit per-worker/per-core-class dispatch
```

The third option is architecturally larger because VPP's current multiarch machinery does not select different node functions per worker based on the core where that worker is pinned.
