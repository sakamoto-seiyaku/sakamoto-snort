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
production_control_protocol_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java"
production_control_request_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlRequest.java"
production_control_backend_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlBackend.java"
product_catalog_device_evidence="$repo_root/tests/device/product-catalog-device-evidence.sh"
grep -q 'ACTION_START' "$production_service_source"
grep -q 'RuntimeControlOrdering' "$production_service_source"
grep -q 'ignored stale ' "$production_service_source"
grep -q 'RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION' "$production_service_source"
grep -q 'ACTION_PRODUCT_PROFILE_SELECT' "$production_service_source"
grep -q 'ACTION_PRODUCT_BIND_APP' "$production_service_source"
grep -q 'ACTION_PRODUCT_UNBIND_APP' "$production_service_source"
grep -q 'productBackend.selectRuntimeProfile(profile)' "$production_service_source"
grep -q 'productBackend.bindApplication(subjectId)' "$production_service_source"
grep -q 'productBackend.unbindApplication(subjectId)' "$production_service_source"
grep -q 'ACTION_PRODUCT_PROFILE_SELECT' "$production_control_protocol_source"
grep -q 'EXTRA_APPLICATION_SUBJECT' "$production_control_protocol_source"
grep -q 'PRODUCT_PROFILE_SELECT' "$production_control_request_source"
grep -q 'bindProductApplication' "$production_control_request_source"
grep -q 'unbindProductApplication' "$production_control_request_source"
grep -q 'RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION' "$production_control_backend_source"
grep -q 'RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT' "$production_control_backend_source"
grep -q './dev/adb' "$product_catalog_device_evidence"
grep -q 'pm list users' "$product_catalog_device_evidence"
grep -q 'cmd package list packages --user "$user_id" -U' "$product_catalog_device_evidence"
grep -q 'multi_user_identity' "$product_catalog_device_evidence"
grep -q 'cannot_prove_same_package_multi_user_uid_differentiation' "$product_catalog_device_evidence"
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
grep -q 'ProductCatalogFormatter' "$production_activity_source"
grep -q 'ProductCatalogProjectionStore.read' "$production_activity_source"
grep -q 'backend.queryService' "$production_activity_source"
grep -q 'backend.selectProductProfile' "$production_activity_source"
grep -q 'backend.bindProductApplication' "$production_activity_source"
grep -q 'backend.unbindProductApplication' "$production_activity_source"
grep -q 'appSpinner' "$production_activity_source"
grep -q 'selectedApplicationSubjectId' "$production_activity_source"
grep -q 'selectedApplicationRow' "$production_activity_source"
grep -q 'LauncherApps' "$production_activity_source"
grep -q 'getBadgedIcon' "$production_activity_source"
grep -q 'getApplicationIcon' "$production_activity_source"
grep -q 'setImageDrawable' "$production_activity_source"
grep -q 'EXTRA_DEBUG_APPLY_GATE_AND_PROBE' "$production_activity_source"
grep -q 'EXTRA_DEBUG_TRAFFIC_HOST' "$production_activity_source"
grep -q 'EXTRA_DEBUG_TRAFFIC_PORT' "$production_activity_source"
grep -q 'EXTRA_DEBUG_LISTEN' "$production_activity_source"
grep -q 'EXTRA_DEBUG_LISTEN_PORT' "$production_activity_source"
grep -q 'ServerSocket' "$production_activity_source"
grep -q 'LocalSocketAddress.Namespace.ABSTRACT' "$production_activity_source"
grep -q 'POLICY.APPLY' "$production_activity_source"
grep -q 'POLICY.EVALUATE' "$production_activity_source"
grep -q 'NFQUEUE.STATUS' "$production_activity_source"
grep -q 'targetUid=' "$production_activity_source"
grep -q 'packetDelta=' "$production_activity_source"
grep -q 'acceptDelta=' "$production_activity_source"
grep -q 'dropDelta=' "$production_activity_source"
grep -q 'lastObservedResult' "$production_activity_source"
grep -q 'runDebugApplyGateAndProbe' "$production_activity_source"
grep -q 'runDebugTrafficListener' "$production_activity_source"
grep -q 'runDebugTrafficProbeBlocking' "$production_activity_source"
python3 - "$production_activity_source" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()
connect = source.index("socket.connect(new LocalSocketAddress(")
timeout = source.index("socket.setSoTimeout(CONTROL_SOCKET_TIMEOUT_MILLIS);")
if timeout < connect:
    raise SystemExit("Control socket timeout must be set after connect")
PY
if grep -q 'LocalProductBackend' "$production_activity_source"; then
  echo "Activity must not instantiate the service-side Local Product Backend writer" >&2
  exit 1
fi
if grep -q 'PackageManagerApplicationCatalogProvider' "$production_activity_source"; then
  echo "Activity must not own the PackageManager-backed product catalog provider" >&2
  exit 1
fi
if grep -q 'ProductStateStore' "$production_activity_source"; then
  echo "Activity must not read ProductStateStore for the product catalog projection" >&2
  exit 1
fi
if grep -q 'ProductStore' "$production_activity_source"; then
  echo "Activity must not mutate ProductStore directly" >&2
  exit 1
fi
if grep -q 'bindApplication(subjectId)' "$production_activity_source" \
  || grep -q 'unbindApplication(subjectId)' "$production_activity_source" \
  || grep -q 'selectRuntimeProfile(profile)' "$production_activity_source"; then
  echo "Activity product mutations must be versioned RuntimeService requests" >&2
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
