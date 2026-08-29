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
grep -Fq 'RuntimeSnapshot.ADAPTER_UNAVAILABLE' "$service"
grep -Fq 'Protection: not running' "$snapshot"

# The Product Core path is app-UID and executable/session owned. It must not
# enter the retired packet adapters or legacy daemon.
grep -Fq 'new ProcessBuilder(vpp.getPath()' "$service"
if grep -n 'startProductCoreRuntime' "$service" | grep -Fq 'libsucre_snortd.so'; then
  echo "Product Core lifecycle references the retired daemon" >&2
  exit 1
fi

echo "sakamoto-172 Product Core lifecycle contract: PASS"
