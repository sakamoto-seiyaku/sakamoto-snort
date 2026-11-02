# Test source map

| Directory | Purpose |
| --- | --- |
| [host](host/README.md) | C semantic/ABI tests and source/build contract checks registered by root CMake |
| [android](android/) | Host-side Java/native Android contract checks; not device acceptance by themselves |
| [device](device/) | Current scoped device collectors and reusable helpers; select a runner through its dated evidence record |
| [evidence](evidence/) | Independent raw-evidence/source-identity verifiers and negative witnesses |
| [integration](integration/README.md) | Retained migration harnesses and archive routing, not the current acceptance entry |
| [archive](archive/README.md) | Historical non-runnable test/tool records |

Start at the [testing evidence map](../docs/testing/README.md), not the highest
ticket number or newest filename. Numbered runners can still be dependencies of
current verification; preserve their names and bytes unless changing that contract.

The removed C++ daemon/model is not a fixture or implementation reference.
Device operations must use [`dev/adb`](../dev/adb) and an explicitly scoped device.
Host PASS is not Product/device/release PASS.

The [S319 observation shutdown regression](evidence/s319_shutdown_prefix.py)
generates actual Adapter QUERY/STOPPED records and exercises the real C transport,
consumer close and SQLite reopen with explicit existing Host dependencies and a
persistent Product Cargo cache. Its five native shutdown methods are ignored by
ordinary `cargo test`; use the dependency-qualified invocation in the
[S319 evidence record](../docs/testing/2026-10-27_S319_DNS_ANSWER_CACHE.md#reproduction-and-retained-evidence).

The [S319 allocation-history regression](evidence/s319_cache_resource.py) uses
the same explicit Host dependency arguments. It injects actual Adapter `malloc`
failures across Root/VPN, UDP/TCP and both address families, then validates all
120 decoded records through normal SQLite close/reopen. Its integration method
is also ignored by ordinary `cargo test`; use the documented runner.

The [S320 coalescing record](../docs/testing/2026-10-27_S320_DNS_COALESCING.md)
qualifies the public Core, real transport and controlled Adapter seams separately
from ordinary App device evidence. Its [capacity reply regression](evidence/test_s320_capacity_reply.py)
checks actual reply IDs, exact same-view cache ages and negative data/source
mutations; the device runner retains complete normal histories and original
failed attempts.

POC source, historical recipes and reference-tool retirement are classified in
the [experiment catalog](../experiments/README.md). Its checks inspect paths and
guards only; they do not run historical experiments.

The [S332 shared-query acceptance](device/s332-debug-query.py) exercises the normal
Root/VPN validation UI, independent Flow/Blocked/DNS facts, saved history and Host
shared reads. Its [dated report](../docs/testing/2026-11-02_S332_DEBUG_QUERY.md)
records prerequisites and the reuse of prior qualifications. Producerless Java
Activity checks are [preserved as historical records](archive/activity-channel-20261102/README.md);
the old command paths return77 (retired), not Product PASS. Lifecycle, online rules
and desensitized diagnostics retain their current Java/native checks.
