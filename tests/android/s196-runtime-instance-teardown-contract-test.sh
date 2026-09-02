#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

test -f "$service"
grep -Fq 'private static volatile RuntimeService activeServiceInstance' "$service"
grep -Fq 'private static final Object SERVICE_INSTANCE_LOCK' "$service"
grep -Fq 'private volatile boolean serviceInstanceSuperseded' "$service"
grep -Fq 'runtime_service_instance=superseded' "$service"
grep -Fq 'lifecycle_teardown=skipped_superseded_service' "$service"
grep -Fq 'product_core_cleanup=skipped_superseded_service' "$service"
grep -Fq 'product_core_global_cleanup=skipped_superseded_service' "$service"

python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


def body(signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError("unclosed method: " + signature)


create = body("public void onCreate()")
stop = body("private boolean stopRuntime(boolean stopService)")
residue = body("private boolean stopProductCoreResidue(boolean stopService)")
global_stop = body("private boolean terminateGlobalProductCoreProcessesForStop()")
destroy = body("public void onDestroy()")

for token in (
        "previousInstance = activeServiceInstance",
        "activeServiceInstance = this",
        "previousInstance.serviceInstanceSuperseded = true",
        "previousInstance.stopRequested = true"):
    if token not in create:
        raise AssertionError("service replacement does not fence the old instance: " + token)

if stop.index("isSupersededServiceInstance()") > stop.index("stopProductCoreResidue("):
    raise AssertionError("superseded teardown guard must precede Product Core cleanup")
if residue.index("isSupersededServiceInstance()") > residue.index("initializeProfilePaths"):
    raise AssertionError("superseded residue cleanup guard must precede profile access")
if residue.index("isSupersededServiceInstance()") > residue.index(
        "terminateGlobalProductCoreProcessesForStop"):
    raise AssertionError("superseded residue cleanup guard must precede global termination")
if global_stop.index("isSupersededServiceInstance()") > global_stop.index("cleanupFaultInjected"):
    raise AssertionError("global termination must recheck the current service instance")

if "final boolean ownsServiceInstance = isCurrentServiceInstance()" not in destroy:
    raise AssertionError("onDestroy must capture instance ownership before queuing teardown")
if destroy.index("ownsServiceInstance && isCurrentServiceInstance()") > destroy.index(
        "publish(RuntimeSnapshot.stopping(snapshot))"):
    raise AssertionError("stale onDestroy must not publish an obsolete stopping projection")
if "if (ownsServiceInstance && isCurrentServiceInstance())" not in destroy:
    raise AssertionError("onDestroy teardown must require current instance ownership")
if "if (activeServiceInstance == this)" not in destroy:
    raise AssertionError("onDestroy must not clear a replacement service's authority")
if destroy.index("lifecycle.shutdown()") < destroy.index("activeServiceInstance == this"):
    raise AssertionError("service authority must be cleared before lifecycle shutdown")

print("sakamoto-196 runtime-instance teardown contract: PASS")
PY
