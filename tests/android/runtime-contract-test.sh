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
rtk bash "$repo_root/tests/android/android-runtime-contract-test.sh"
production_service_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
production_activity_source="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
grep -q 'ACTION_START' "$production_service_source"
grep -q 'RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION' "$production_service_source"
grep -q 'adapterArtifact' "$production_service_source"
grep -q 'shellQuote(command)' "$production_service_source"
grep -q 'new ProcessBuilder(vppctl.getPath(), "-s", socket.getPath(), command)' \
  "$production_service_source"
grep -q 'manifestAdapterArtifact' "$production_service_source"
grep -q 'PidIdentity' "$production_service_source"
grep -q 'onDestroy' "$production_activity_source"

service_source="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortRuntimeService.java"
grep -q 'SAKAMOTO_VPP_OWNER_TOKEN' "$service_source"
grep -q 'startup.conf' "$service_source"
if grep -q 'cleanup.get' "$service_source" || grep -q 'shutdownNow' "$service_source"; then
  echo "runtime service cleanup must not block or cancel from onDestroy" >&2
  exit 1
fi
echo "runtime service lifecycle contract: PASS"
