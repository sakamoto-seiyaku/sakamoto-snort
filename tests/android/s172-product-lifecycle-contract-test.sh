#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
snapshot="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSnapshot.java"

test -f "$service"
grep -Fq 'product-stage.properties' "$service"
grep -Fq 'libproduct_core_plugin.so' "$service"
grep -Fq 'nativeLibraryDir' "$service"
grep -Fq 'SAKAMOTO_PRODUCT_GENERATION' "$service"
grep -Fq 'SAKAMOTO_VPP_SVM_DIR' "$service"
grep -Fq 'RuntimeControlNative.Session' "$service"
grep -Fq 'ProductCoreLifecycle.isReady' "$service"
grep -Fq 'RuntimeControlNative.Status status = session.query()' "$service"
grep -Fq 'closeProductCoreSession();' "$service"
grep -Fq 'socket.exists()' "$service"
grep -Fq 'ProductCoreLifecycle.canRetryConnection' "$service"
grep -Fq 'ProductCoreLifecycle.UNKNOWN_PID' "$service"
grep -Fq 'ProductCoreLifecycle.shouldClearStaleProfile' "$service"
grep -Fq 'builder.redirectErrorStream(true)' "$service"
grep -Fq 'builder.redirectOutput(' "$service"
grep -Fq 'process.getOutputStream().close();' "$service"
grep -Fq 'process.destroy();' "$service"
grep -Fq 'process.waitFor(STOP_TERM_MILLIS, TimeUnit.MILLISECONDS)' "$service"
grep -Fq 'process.destroyForcibly();' "$service"
grep -Fq 'process.waitFor(STOP_KILL_MILLIS, TimeUnit.MILLISECONDS)' "$service"
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
if grep -Fq 'PRODUCT_PLUGIN_ASSET' "$service" || \
    grep -Fq 'copyAsset(' "$service"; then
  echo "Product Core lifecycle still copies the plugin from APK assets" >&2
  exit 1
fi

# Reconciliation for the app-UID mainline must not route a tokenless stale
# profile through the retired Root ownership/su audit. Visible START owns the
# bounded app-owned deleteTree preflight.
grep -Fq 'reconcileProductCoreRuntime' "$service"
grep -Fq 'Product Core path defers stale-profile cleanup to visible START' "$service"

# The Product Core path is app-UID and executable/session owned. It must not
# enter the retired packet adapters or legacy daemon.
grep -Fq 'new ProcessBuilder(vpp.getPath()' "$service"
if grep -n 'startProductCoreRuntime' "$service" | grep -Fq 'libsucre_snortd.so'; then
  echo "Product Core lifecycle references the retired daemon" >&2
  exit 1
fi

python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


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
prepare = method_body("private void prepareProductCoreProfile(")
stop = method_body("private boolean stopRuntime(boolean stopService)")
terminate = method_body("private boolean terminateProductCoreProcess(")
for forbidden in (
        "/system/bin/sh", "SU_PATH", "new ProcessBuilder(\"/system/bin/su\"",
        "echo $$", "vpp.pid",
        "process.pid()", "ProcessHandle", "toHandle()"):
    if forbidden in start:
        raise AssertionError("Product Core start uses forbidden process API: " + forbidden)

start_index = start.index("new ProcessBuilder(vpp.getPath()")
if "nativeLibraryDir" not in start or "PRODUCT_PLUGIN_BINARY" not in start \
        or "libproduct_core_plugin.so" not in source:
    raise AssertionError("Product Core must resolve the plugin from nativeLibraryDir")
for required in (
        "plugin.isFile()", "plugin.canRead()", "nativeDir.equals(plugin.getParentFile())"):
    if required not in start:
        raise AssertionError("Product Core must validate the native plugin boundary: " + required)
if "plugin_path" not in start:
    raise AssertionError("Product Core must pass an explicit native plugin path")
if "plugins {" not in prepare or "plugin default { disable }" not in prepare \
        or "PRODUCT_PLUGIN_BINARY" not in prepare:
    raise AssertionError("Product Core startup config must allowlist the native plugin")
if "setExecutable" in start or "chmod" in start or "filesDir" in start:
    raise AssertionError("Product Core must not chmod/copy plugin into a writable profile")
stdin_index = start.index("process.getOutputStream().close()")
stdout_index = start.index("builder.redirectOutput(")
launch_index = start.index("Process process = builder.start()")
if not start_index < launch_index < stdin_index:
    raise AssertionError("Product Core must close stdin immediately after direct launch")
if not stdout_index < launch_index:
    raise AssertionError("Product Core must configure output redirection before launch")

close_index = stop.index("closeProductCoreSession()")
terminate_index = stop.index("terminateProductCoreProcess()")
cleanup_index = stop.index("deleteTree(profileRoot)")
if not close_index < terminate_index < cleanup_index:
    raise AssertionError("STOP must close session and terminate before profile cleanup")
destroy_index = terminate.index("process.destroy();")
term_wait_index = terminate.index("process.waitFor(STOP_TERM_MILLIS")
force_index = terminate.index("process.destroyForcibly();")
kill_wait_index = terminate.index("process.waitFor(STOP_KILL_MILLIS")
if not destroy_index < term_wait_index < force_index < kill_wait_index:
    raise AssertionError("Product Core stop must remain bounded TERM/destroy/wait then KILL/wait")
if "&& !process.isAlive()" not in terminate:
    raise AssertionError("Product Core stop must confirm the process ended before cleanup")
PY

echo "sakamoto-172 Product Core lifecycle contract: PASS"
