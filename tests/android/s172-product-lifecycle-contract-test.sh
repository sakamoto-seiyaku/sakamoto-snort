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
grep -Fq 'ProductCoreLifecycle.shouldClearStaleProfile' "$service"
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

echo "sakamoto-172 Product Core lifecycle contract: PASS"
