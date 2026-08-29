#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
snapshot="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeSnapshot.java"
pinned_vpp_source="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
pinned_revision="$(tr -d '[:space:]' < "$repo_root/src/product/vpp/pinned-vpp-revision.txt")"
pinned_main="$pinned_vpp_source/src/vpp/vnet/main.c"
pinned_plugin="$pinned_vpp_source/src/vlib/unix/plugin.c"

test -f "$service"
test -f "$pinned_main"
test -f "$pinned_plugin"
test "$(git -C "$pinned_vpp_source" rev-parse HEAD)" = "$pinned_revision"
test -z "$(git -C "$pinned_vpp_source" status --porcelain)"
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
prepare = method_body("private void prepareProductCoreProfile(File profile, File nativeDir)")
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
builder_end = start.index(");", start_index) + 2
builder = start[start_index:builder_end]
if builder.count('"-c"') != 1 or "new File(profileRoot, \"startup.conf\").getPath()" not in builder:
    raise AssertionError("Product Core must launch VPP with only -c startup.conf")
if "plugin_path" in builder or "nativeDir.getPath()" in builder:
    raise AssertionError("Product Core must not pass the retired plugin_path argv")
if "plugins {" not in prepare or "path " not in prepare \
        or "plugin default { disable }" not in prepare \
        or "PRODUCT_PLUGIN_BINARY" not in prepare:
    raise AssertionError("Product Core startup config must allowlist the native plugin")
path_index = prepare.index('"plugins {\\n  path "')
default_index = prepare.index('plugin default { disable }')
enable_index = prepare.index('PRODUCT_PLUGIN_BINARY + " { enable }')
if not path_index < default_index < enable_index:
    raise AssertionError("Product Core plugins config order is not path/default/exact enable")
if "safeVppConfigPath(nativeDir)" not in prepare:
    raise AssertionError("Product Core plugins path bypasses the native-library path guard")
safe_path = method_body("private static String safeVppConfigPath(File path)")
if "Character.isISOControl(character)" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must reject control characters")
if "nativeLibraryDir is not absolute" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must remain absolute")
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

# The pinned VPP mainline treats -c as an exclusive startup-config source:
# when config_file is set, it reads that file and never appends positional
# argv config. The plugin loader then consumes plugins { path ... } from that
# same file before loading plugins. Keep this source contract beside the
# RuntimeService launch contract so a future VPP pin cannot silently revive
# the discarded plugin_path argv.
python3 - "$pinned_main" "$pinned_plugin" <<'PY'
import pathlib
import sys

main = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
plugin = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")

config_start = main.index("if (config_file)")
argv_start = main.index("/* construct config out of argvs */", config_start)
config_end = argv_start
config_branch = main[config_start:config_end]
if "open (config_file" not in config_branch:
    raise AssertionError("pinned VPP -c branch does not read config_file")
if "for (i = config_arg_index; i < argc; i++)" in config_branch:
    raise AssertionError("pinned VPP -c branch still appends positional argv config")

argv_end = main.index("unformat_init_string", argv_start)
argv_branch = main[argv_start:argv_end]
if "for (i = config_arg_index; i < argc; i++)" not in argv_branch:
    raise AssertionError("pinned VPP positional-config fallback changed unexpectedly")

path_index = plugin.index('unformat (input, "path %s", &s)')
default_index = plugin.index('unformat (input, "plugin default %U"')
plugin_path_index = plugin.index("pm->plugin_path = s", path_index)
if not path_index < plugin_path_index < default_index:
    raise AssertionError("pinned VPP plugin config no longer consumes path before loading")
if 'unformat (input, "plugin %s %U"' not in plugin:
    raise AssertionError("pinned VPP plugin config no longer accepts named plugins")
PY

echo "sakamoto-172 Product Core lifecycle contract: PASS"
