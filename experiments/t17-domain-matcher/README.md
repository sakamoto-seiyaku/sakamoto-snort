# T17 domain membership experiment

This is reproducible experimental evidence for [SAKAMOTO-268](http://192.168.4.22:2080/work/projects/f55a54bf-1693-42a3-9e38-50128f4b3a7e/issues/063537dd-410c-44e9-9ec1-dcfdbf5b26eb),
not Product source. Do not import these adapters into T18 or build a Product
backend selector. The pre-run [plan](PLAN.md) fixes semantics and envelope.

Use Python 3.12+, GCC, the repo's NDK r29/API31 and the verified Host/Android
VPP stages at `build-output/s220-20260913/{host-stage-b,android-stage-b}`. All
shell commands go through `rtk`; use a new output directory for every run.

```sh
rtk proxy python3 experiments/t17-domain-matcher/fetch.py build-output/t17-replay/upstream
rtk proxy python3 experiments/t17-domain-matcher/generate.py build-output/t17-replay/workloads
rtk proxy python3 experiments/t17-domain-matcher/test_oracle.py
rtk proxy python3 experiments/t17-domain-matcher/build.py build-output/t17-replay/host --upstream build-output/t17-replay/upstream
rtk proxy python3 experiments/t17-domain-matcher/build.py build-output/t17-replay/android --upstream build-output/t17-replay/upstream --android
rtk proxy python3 experiments/t17-domain-matcher/run.py build-output/t17-replay/host build-output/t17-replay/workloads build-output/t17-replay/host-runs
rtk proxy python3 experiments/t17-domain-matcher/run.py build-output/t17-replay/android build-output/t17-replay/workloads build-output/t17-replay/android-runs --android
rtk proxy python3 experiments/t17-domain-matcher/verify.py build-output/t17-replay/host-runs build-output/t17-replay/host build-output/t17-replay/workloads
rtk proxy python3 experiments/t17-domain-matcher/verify.py build-output/t17-replay/android-runs build-output/t17-replay/android build-output/t17-replay/workloads
```

Android runner obtains the private device selector from the T16 local accepted
result. It uses only `./dev/adb` with the existing server/client configuration.
It deploys a nonce-owned native process and library; it does not install an APK,
start VPN/Root capture, or change KernelSU grants. Device operations are serial.
Android shell `timeout` caps the native process; a transport timeout stops the
series for inspection instead of continuing with uncertain remote state.

`build.json` records compiler commands, time, binary sizes/hashes, and the
consumed-source closure. `provenance.py` compares actual extracted libdatrie
sources and copied rax files with retained archive members and binds VPP headers,
library and stage manifest. `index.json` retains raw output, errors, timings and
identities per run. `verify.py` checks completeness, identities, dimensions and
independent expected checksums. `failures.py` intentionally corrupts native
expectations and evidence. A failed run remains a failed run, never a zero-cost
sample.

The native query counter wraps libc allocation calls in the executable and
statically compiled candidate files. It does **not** intercept internal VPP
shared-library/private-heap allocation. VPP allocation freedom is separately
established by the pinned source audit below, not by claiming the wrapped
counter covers all allocators. Sanitizers instrument the adapters and static
candidate files, not the prebuilt VPP shared library.

## Query allocation source audit

- libdatrie `trie.c:736,798,833,920`: copy overwrites an existing cursor; walk,
  terminal test and data read call the existing double-array/tail accessors.
  `darray.c:429` and `tail.c:556` only inspect state/bytes. Root/cursor creation
  occurs during build. No per-query root/clone/iterator allocation.
- Valkey `rax.c:911`: `raxFind` calls `raxLowWalk` with a NULL stack, then reads
  terminal data. Its stack-growth branch requires a non-NULL stack. Debug output
  is disabled. The public exact API is called at reversed label boundaries;
  no iterator or private ancestor walker was added.
- VPP `hash.c:414` calls `lookup(..., GET, ...)` at line327. Allocating insertion
  helpers are guarded by SET at358/368; deletion branches require UNSET.
  GET uses `get_indirect` at178, key comparisons and string-key sum/equality
  at726/733 (strlen/hash_memory/strcmp), with no allocation or table mutation.
  `hash_memory` consumes bytes through integer arithmetic. Stack normalization
  and suffix-pointer queries in `bench.c` add no heap use.

These are source-derived properties of the bound versions and adapters, not a
promise for future upstream changes or arbitrary APIs from those libraries.
