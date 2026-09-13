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
