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

service_source="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/src/main/java/com/sakamoto/snort/vpnlite/SnortRuntimeService.java"
grep -q 'SAKAMOTO_VPP_OWNER_TOKEN' "$service_source"
grep -q 'startup.conf' "$service_source"
if grep -q 'cleanup.get' "$service_source" || grep -q 'shutdownNow' "$service_source"; then
  echo "runtime service cleanup must not block or cancel from onDestroy" >&2
  exit 1
fi
echo "runtime service lifecycle contract: PASS"
