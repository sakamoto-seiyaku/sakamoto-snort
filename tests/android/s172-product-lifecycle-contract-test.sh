#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
snapshot="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSnapshot.java"

test -f "$service"
grep -Fq 'product-stage.properties' "$service"
grep -Fq 'product_core_plugin.so' "$service"
grep -Fq 'SAKAMOTO_PRODUCT_GENERATION' "$service"
grep -Fq 'SAKAMOTO_VPP_SVM_DIR' "$service"
grep -Fq 'RuntimeControlNative.Session' "$service"
grep -Fq 'ProductCoreLifecycle.isReady' "$service"
grep -Fq 'RuntimeControlNative.Status status = session.query()' "$service"
grep -Fq 'closeProductCoreSession();' "$service"
grep -Fq 'socket.exists()' "$service"
grep -Fq 'ProductCoreLifecycle.canRetryConnection' "$service"
grep -Fq 'ProductCoreLifecycle.UNKNOWN_PID' "$service"
grep -Fq 'ProductCoreLifecycle.preflightStart' "$service"
grep -Fq 'ProductCoreLifecycle.preflightStop' "$service"
grep -Fq 'probeProductCoreProfile' "$service"
grep -Fq 'ADAPTER_UNAVAILABLE' "$snapshot"
grep -Fq 'Protection: not running' "$snapshot"

# Android's java.lang.Process has no pid() API on the supported device. The
# Product Core path keeps the Process handle for isAlive()/waitFor(), while
# its durable projection intentionally carries an unknown PID.
if grep -Fq 'process.pid()' "$service"; then
  echo "RuntimeService still calls the unavailable Android Process.pid API" >&2
  exit 1
fi
if grep -Fq 'writePid(pidFile' "$service"; then
  echo "Product Core lifecycle writes a vpp.pid without a supported PID" >&2
  exit 1
fi

# Reconciliation and lifecycle cleanup for the app-UID mainline must use the
# bounded app-owned socket/profile path, never the retired Root ownership/PID
# path. Parse complete method bodies so this gate checks call placement rather
# than merely finding helper names somewhere in the file.
grep -Fq 'reconcileProductCoreRuntime' "$service"

python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()


def method_body(signature):
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


start = method_body("private void startProductCoreRuntime(")
stop = method_body("private boolean stopProductCoreRuntime(")
reconcile = method_body("private void reconcileProductCoreRuntime(")
probe = method_body("private ProductCoreLifecycle.ProbeResult probeProductCoreProfile(")
profiles = method_body("private ProductCoreLifecycle.ProbeResult probeProductCoreProfiles(")
clear_profiles = method_body("private boolean clearProductCoreProfiles(")
stop_dispatch = method_body("private boolean stopRuntime(boolean stopService)")
pause = method_body("private void pauseProtection(")

retired = (
    "terminateAndClean", "validatePid", "auditOwnedProcess",
    "rootCommandAvailable", "runRootCommandStatus",
)
for name, body in (("startProductCoreRuntime", start),
                   ("stopProductCoreRuntime", stop),
                   ("reconcileProductCoreRuntime", reconcile),
                   ("probeProductCoreProfile", probe)):
    for helper in retired:
        if helper in body:
            raise AssertionError(f"{name} routes through retired helper {helper}")

if "RuntimeControlNative.connect" not in probe:
    raise AssertionError("Product Core probe must use the app-owned API socket")
if "ProductCoreLifecycle.isReady" not in probe or "probe.close()" not in probe:
    raise AssertionError("Product Core probe must validate and close its temporary session")
if start.index("ProductCoreLifecycle.preflightStart") > start.index("generation++"):
    raise AssertionError("START must preflight before assigning a new generation")
if start.index("ProductCoreLifecycle.preflightStart") > start.index("new ProcessBuilder"):
    raise AssertionError("START must probe/clear before launching VPP")
if stop.index("ProductCoreLifecycle.preflightStop") > stop.rindex("stopProductCoreServiceIfNeeded"):
    raise AssertionError("STOP must finish the lost-handle preflight before service teardown")
if "return stopProductCoreRuntime(stopService);" not in stop_dispatch:
    raise AssertionError("Product Core STOP must dispatch to its core-only cleanup path")
if stop_dispatch.index("return stopProductCoreRuntime(stopService);") > stop_dispatch.index(
        "terminateAndClean"):
    raise AssertionError("Product Core STOP dispatch must precede the legacy path")
if "if (!stopped" not in pause or "productCoreMainline()" not in pause \
        or "return;" not in pause:
    raise AssertionError("PAUSE must fail closed when Product Core stop cannot prove cleanup")
if "probeProductCoreProfiles()" not in reconcile:
    raise AssertionError("reconciliation must probe recreated Product Core owners")
if "for (RuntimeProfile profile : RuntimeProfile.values())" not in profiles:
    raise AssertionError("START must inspect both mutually exclusive profiles")
if "deleteTree(root)" not in clear_profiles:
    raise AssertionError("global Product Core cleanup must remain app-owned")
if "clearProductCoreProfiles" not in start or "clearProductCoreProfiles" not in stop:
    raise AssertionError("START/STOP must clear only after the global app-owned probe")
PY

# The Product Core path is app-UID and executable/session owned. It must not
# enter the retired packet adapters or legacy daemon.
grep -Fq 'new ProcessBuilder(vpp.getPath()' "$service"
if grep -n 'startProductCoreRuntime' "$service" | grep -Fq 'libsucre_snortd.so'; then
  echo "Product Core lifecycle references the retired daemon" >&2
  exit 1
fi

echo "sakamoto-172 Product Core lifecycle contract: PASS"
