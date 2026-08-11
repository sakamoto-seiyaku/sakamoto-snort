#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
probe="$repo_root/tests/device/s59-release-budget-probe.sh"
release_gate="$repo_root/docs/product/ANDROID_L4_RELEASE_GATE.md"

[[ -f "$probe" ]]
grep -q 'SAKAMOTO-59-release-budget-probe' "$probe"
grep -q 'debug_apk_budget_probe_only' "$probe"
grep -q 'runtimeProfile' "$probe"
grep -q 'root vpn' "$probe"
grep -q 'workflowLatency' "$probe"
grep -q 'nominalThroughput' "$probe"
grep -q 'cpuRss' "$probe"
grep -q 'thermal' "$probe"
grep -q 'shutdownDrain' "$probe"
grep -q 'capacityHighWatermark' "$probe"
grep -q 'correctiveHandoff' "$probe"
grep -q 'NFQUEUE.STATUS' "$probe"
grep -q 'VPN_TUN.STATUS' "$probe"
grep -q 'policyDropActivity' "$probe"
grep -q 'allowedFlowActivity' "$probe"
grep -q 'dumpsys thermalservice' "$probe"
grep -q 'files/debug/traffic-probe.properties' "$probe"
grep -q 'speed.cloudflare.com/__down' "$probe"
grep -q 'runtimeStop true' "$probe"
grep -q 'repo_root}/dev/adb' "$probe"

grep -q 'tests/device/s59-release-budget-probe.sh' "$release_gate"

echo "s59 release budget probe static contract: PASS"
