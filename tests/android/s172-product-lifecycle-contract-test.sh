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
grep -Fq 'ProductCoreLifecycle.validate' "$service"
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

# Reconciliation for the app-UID mainline must not route a stale profile
# through the retired Root ownership/su audit. Visible START owns the
# bounded durable Product Core owner audit and exact cleanup preflight.
grep -Fq 'reconcileProductCoreRuntime' "$service"
grep -Fq 'auditProductCoreOwner' "$service"
grep -Fq 'owner audit below' "$service"

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
launch = method_body("private ProcessBuilder buildProductCoreProcessBuilder(")
prepare = method_body("private void prepareProductCoreProfile(")
stop = method_body("private boolean stopRuntime(boolean stopService)")
terminate = method_body("private boolean terminateProductCoreProcess(")
product_builder = method_body("private ProcessBuilder buildProductCoreProcessBuilder(")
monitor_product_exit = method_body("private void monitorProductCoreExit(")
query_product = method_body("private void queryProductCoreRuntime(")
for forbidden in (
        "/system/bin/sh", "SU_PATH", "new ProcessBuilder(\"/system/bin/su\"",
        "echo $$", "vpp.pid",
        "process.pid()", "ProcessHandle", "toHandle()"):
    if forbidden in start:
        raise AssertionError("Product Core start uses forbidden process API: " + forbidden)

if "SAKAMOTO_VPP_SVM_DIR" not in start:
    raise AssertionError("Product Core start does not pass the VPP Android SVM directory")
if "SAKAMOTO_ANDROID_SHM_DIR=" in start:
    raise AssertionError("Product Core start still uses the retired Android SHM environment name")

if "nativeLibraryDir" not in start or "PRODUCT_PLUGIN_BINARY" not in start \
        or "libproduct_core_plugin.so" not in source:
    raise AssertionError("Product Core must resolve the plugin from nativeLibraryDir")
for required in (
        "plugin.isFile()", "plugin.canRead()", "nativeDir.equals(plugin.getParentFile())"):
    if required not in start:
        raise AssertionError("Product Core must validate the native plugin boundary: " + required)
start_index = product_builder.index("new ProcessBuilder(vpp.getPath()")
builder_end = product_builder.index(");", start_index) + 2
builder = product_builder[start_index:builder_end]
if builder.count('"-c"') != 1 or "startup.getPath()" not in builder:
    raise AssertionError("Product Core must launch VPP with only -c startup.conf")
if "plugin_path" in builder or "nativeDir.getPath()" in builder:
    raise AssertionError("Product Core must not pass the retired plugin_path argv")
if '"plugin_path " + nativeLibraryPath' not in prepare:
    raise AssertionError("Product Core startup config must publish the early VPP plugin path")
if "plugins {" not in prepare or "path " not in prepare \
        or "plugin default { disable }" not in prepare \
        or "PRODUCT_PLUGIN_BINARY" not in prepare:
    raise AssertionError("Product Core startup config must allowlist the native plugin")
early_path_index = prepare.index('"plugin_path " + nativeLibraryPath')
path_index = prepare.index('"plugins {\\n  path "')
default_index = prepare.index('plugin default { disable }')
enable_index = prepare.index('PRODUCT_PLUGIN_BINARY + " { enable }')
if not early_path_index < path_index:
    raise AssertionError("Product Core startup config must set plugin_path before the plugins allowlist")
if not path_index < default_index < enable_index:
    raise AssertionError("Product Core plugins config order is not path/default/exact enable")
if "safeVppConfigPath(nativeDir)" not in prepare:
    raise AssertionError("Product Core plugins path bypasses the native-library path guard")
safe_path = method_body("private static String safeVppConfigPath(File path)")
if "Character.isISOControl(character)" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must reject control characters")
if "nativeLibraryDir is not absolute" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must remain absolute")
if "Character.isISOControl(character) || character == '#' || character == ':'" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must reject VPP path-list separators")
if safe_path.count("character == ':'") != 1:
    raise AssertionError("nativeLibraryDir config path must reject exactly the colon separator")
if "if (character == '\\\\' || character == '{' || character == '}')" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must retain backslash/brace escaping")
if "return escaped.append('}').toString();" not in safe_path:
    raise AssertionError("nativeLibraryDir config path must render one brace-delimited token")
# A normal Android native-library path contains only safe token characters and
# must remain the exact value inside the braces written to the VPP config.
android_native_dir = "/data/app/~~abc/com.sakamoto.snort-xyz/lib/arm64-v8a"
if any(character in android_native_dir for character in "\x00\n\r#:"):
    raise AssertionError("normal Android nativeLibraryDir fixture is unexpectedly unsafe")
if 'plugins {\\n  path " + nativeLibraryPath' not in prepare:
    raise AssertionError("VPP config must use the guarded native-library path value")
if 'escaped.append(character);' not in safe_path:
    raise AssertionError("normal Android nativeLibraryDir must remain unchanged in the token")
if "setExecutable" in start or "filesDir" in start:
    raise AssertionError("Product Core must not chmod/copy plugin into a writable profile")
stdin_index = start.index("process.getOutputStream().close()")
stdout_index = start.index("builder.redirectOutput(")
launch_index = start.index("Process process = builder.start()")
if not launch_index < stdin_index:
    raise AssertionError("Product Core must close stdin immediately after direct launch")
if not stdout_index < launch_index:
    raise AssertionError("Product Core must configure output redirection before launch")

close_index = stop.index("closeProductCoreSession()")
terminate_index = stop.index("terminateProductCoreProcess()")
cleanup_index = stop.index("cleanProductCoreResidue(postKill)")
if not close_index < terminate_index < cleanup_index:
    raise AssertionError("STOP must close session and terminate before profile cleanup")
post_kill_index = stop.index("ProductCoreOwner.GlobalDecision postKill")
if not terminate_index < post_kill_index < cleanup_index:
    raise AssertionError("STOP must globally audit after killing the in-memory owner")
product_success_index = stop.index("productCoreSession = null;")
product_process_clear_index = stop.index("vppProcess = null;", product_success_index)
product_stopped_publish_index = stop.index("RuntimeSnapshot.stopped(", product_process_clear_index)
product_stop_clear_index = stop.index("stopRequested = false;", product_stopped_publish_index)
if not product_process_clear_index < product_stopped_publish_index < product_stop_clear_index:
    raise AssertionError("Product Core STOP must clear the process and publish stopped before clearing stopRequested")
if "RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)" not in monitor_product_exit:
    raise AssertionError("Product Core exit monitor must ignore the expected STOPPING exit")
dead_process_start = query_product.index("if (process == null || !process.isAlive())")
dead_process_failure = query_product.index('failProductCoreGeneration("unexpected_exit"', dead_process_start)
dead_process_guard = query_product[dead_process_start:dead_process_failure]
for required in (
        "stopRequested",
        "RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)",
        "RuntimeSnapshot.STATE_STOPPED.equals(snapshot.state)"):
    if required not in dead_process_guard:
        raise AssertionError("Product Core QUERY must not turn expected STOP/STOPPED into unexpected_exit: " + required)
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
# argv config. Product Core therefore publishes the early plugin directory as a
# top-level startup-config `plugin_path`, not as ignored positional argv, then
# keeps `plugins { path ...; default disable; exact enable }` as the allowlist.
# Keep this source contract beside RuntimeService so a future VPP pin cannot
# silently break Product Core plugin discovery on Android.
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

top_level_path_index = main.index('unformat (&input, "plugin_path %s", &vlib_plugin_path)')
default_path_index = main.index("if (!vlib_plugin_path)")
unix_main_index = main.index("return vlib_unix_main", default_path_index)
if not top_level_path_index < default_path_index < unix_main_index:
    raise AssertionError("pinned VPP no longer consumes top-level plugin_path before plugin init")

path_index = plugin.index('unformat (input, "path %s", &s)')
default_index = plugin.index('unformat (input, "plugin default %U"')
plugin_path_index = plugin.index("pm->plugin_path = s", path_index)
if not path_index < plugin_path_index < default_index:
    raise AssertionError("pinned VPP plugin config no longer consumes path before loading")
if 'unformat (input, "plugin %s %U"' not in plugin:
    raise AssertionError("pinned VPP plugin config no longer accepts named plugins")
PY

echo "sakamoto-172 Product Core lifecycle contract: PASS"
