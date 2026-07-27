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
