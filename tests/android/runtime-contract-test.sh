#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
out_dir="$(mktemp -d)"
trap 'rm -rf "$out_dir"' EXIT

javac -d "$out_dir" \
  "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/RuntimeSnapshot.java" \
  "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/RuntimeStateStore.java" \
  "$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/VppHealthHandshake.java" \
  "$repo_root/tests/android/RuntimeContractTest.java"
java -cp "$out_dir" RuntimeContractTest

# SAKAMOTO-67 production-incubator seam. The experiment remains covered below
# as migration evidence, while this gate proves the forward app contract.
bash "$repo_root/tests/android/android-runtime-contract-test.sh"
# Build/artifact seam: the core runtime is packaged without experiment packet
# adapter artifacts and carries a generated-VAPI identity.
bash "$repo_root/tests/android/android-runtime-artifact-contract-test.sh"
bash "$repo_root/tests/android/android-runtime-hardening-contract-test.sh"
production_service_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
production_ownership_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeOwnershipReconciliation.java"
production_activity_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
grep -q 'ACTION_START' "$production_service_source"
grep -q 'RuntimeControlOrdering' "$production_service_source"
grep -q 'ignored stale ' "$production_service_source"
grep -q 'RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION' "$production_service_source"
grep -q 'RuntimeControlNative' "$production_service_source"
grep -q 'apiIdentity' "$production_service_source"
grep -q 'kill -TERM' "$production_service_source"
grep -q 'kill -KILL' "$production_service_source"
grep -q 'root_authorization_required' "$production_service_source"
grep -q 'SAKAMOTO_VPP_RUNTIME_DIR' "$production_service_source"
if grep -q 'vppctl.*quit' "$production_service_source"; then
  echo "product stop must not use vppctl quit" >&2
  exit 1
fi
grep -q 'ADAPTER_UNAVAILABLE' "$production_service_source"
grep -q 'PidIdentity' "$production_service_source"
grep -q 'health_query=vapi_start' "$production_service_source"
grep -q 'health_query=vapi_result' "$production_service_source"
grep -q 'android.os.Process.myUid' "$production_service_source"
grep -q 'VPP_OWNER_PID=' "$production_ownership_source"
grep -q 'sha256sum' "$production_ownership_source"
grep -q 'onDestroy' "$production_activity_source"
grep -q 'RuntimeControlBackend' "$production_activity_source"
grep -q 'backend.query' "$production_activity_source"
grep -q 'current.profile == RuntimeProfile.VPN' "$production_activity_source"
grep -q 'requestedProfile' "$production_activity_source"
if grep -q 'LocalProductBackend' "$production_activity_source"; then
  echo "Activity control adapter retained the misleading LocalProductBackend name" >&2
  exit 1
fi

service_source="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortRuntimeService.java"
grep -q 'SAKAMOTO_VPP_OWNER_TOKEN' "$service_source"
grep -q 'startup.conf' "$service_source"
if grep -q 'cleanup.get' "$service_source" || grep -q 'shutdownNow' "$service_source"; then
  echo "runtime service cleanup must not block or cancel from onDestroy" >&2
  exit 1
fi
echo "runtime service lifecycle contract: PASS"
