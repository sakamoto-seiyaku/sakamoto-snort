#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

flow_header="$repo_root/src/core/flow/FlowSteering.hpp"
flow_impl="$repo_root/src/core/flow/FlowSteering.cpp"
graph_injection="$repo_root/src/core/flow/FlowGraphInjection.cpp"
runtime_control="$repo_root/src/main/RuntimeControl.hpp"
control_server="$repo_root/src/control/vnext/ControlServer.cpp"
vpn_tun_adapter="$repo_root/src/datapath/tun/VpnTunFlowAdapter.cpp"
vpn_tun_runtime="$repo_root/src/datapath/tun/VpnTunFdRuntime.hpp"
debug_activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
flow_tests="$repo_root/tests/host/flow_steering_tests.cpp"
graph_tests="$repo_root/tests/host/vpp_graph_injection_tests.cpp"
control_tests="$repo_root/tests/host/control_server_contract_tests.cpp"

grep -q 'FlowAttributionObservation' "$flow_header"
grep -q 'applyResolvedAttribution' "$flow_header"
grep -q 'factsWithResolvedAttribution' "$flow_header"
grep -q 'attributionMisses' "$flow_header"
grep -q 'attributionResolutions' "$flow_header"
grep -q 'found == entries_.end()' "$flow_impl"
grep -q '++counters_.attributionMisses' "$flow_impl"
grep -q '++counters_.attributionResolutions' "$flow_impl"
grep -q 'runtime_.flowTable().factsWithResolvedAttribution' "$graph_injection"
grep -q 'vpnTunAttributionControlReady' "$runtime_control"
grep -q 'applyResolvedVpnTunAttribution' "$runtime_control"
grep -q 'vpn-tun-attribution-control' "$control_server"
grep -q 'VPN_TUN.ATTRIBUTION.APPLY' "$control_server"
grep -q 'applyResolvedAttribution' "$vpn_tun_adapter"
grep -q 'flowAdapter_.applyResolvedAttribution' "$vpn_tun_runtime"
grep -q 'debugTrafficSourcePort' "$debug_activity"
grep -q 'socket.setReuseAddress(true)' "$debug_activity"
grep -q 'socket.bind(new InetSocketAddress(sourcePort))' "$debug_activity"
grep -q 'LateAttributionOnlyUpdatesExistingFlowEntry' "$flow_tests"
grep -q 'LateResolvedAttributionReevaluatesSubsequentUnknownPacket' "$graph_tests"
grep -q 'RealVpnTunRuntimeLateAttributionReevaluatesNextUnknownPacket' "$control_tests"

if grep -R -n 'pendingAttribution\|pendingUid\|attributionReplay\|replayAttribution' \
  "$repo_root/src/core/flow" "$repo_root/src/datapath/tun" >/dev/null; then
  echo "S56 attribution miss path must not introduce pending packet attribution or replay state" >&2
  exit 1
fi

echo "s56 vpn attribution runtime static contract: PASS"
