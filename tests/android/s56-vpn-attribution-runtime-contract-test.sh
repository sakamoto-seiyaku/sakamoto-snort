#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

flow_header="$repo_root/src/core/flow/FlowSteering.hpp"
flow_impl="$repo_root/src/core/flow/FlowSteering.cpp"
graph_injection="$repo_root/src/core/flow/FlowGraphInjection.cpp"
flow_tests="$repo_root/tests/host/flow_steering_tests.cpp"
graph_tests="$repo_root/tests/host/vpp_graph_injection_tests.cpp"

grep -q 'FlowAttributionObservation' "$flow_header"
grep -q 'applyResolvedAttribution' "$flow_header"
grep -q 'factsWithResolvedAttribution' "$flow_header"
grep -q 'attributionMisses' "$flow_header"
grep -q 'attributionResolutions' "$flow_header"
grep -q 'found == entries_.end()' "$flow_impl"
grep -q '++counters_.attributionMisses' "$flow_impl"
grep -q '++counters_.attributionResolutions' "$flow_impl"
grep -q 'runtime_.flowTable().factsWithResolvedAttribution' "$graph_injection"
grep -q 'LateAttributionOnlyUpdatesExistingFlowEntry' "$flow_tests"
grep -q 'LateResolvedAttributionReevaluatesSubsequentUnknownPacket' "$graph_tests"

if grep -R -n 'pendingAttribution\|pendingUid\|attributionReplay\|replayAttribution' \
  "$repo_root/src/core/flow" "$repo_root/src/datapath/tun" >/dev/null; then
  echo "S56 attribution miss path must not introduce pending packet attribution or replay state" >&2
  exit 1
fi

echo "s56 vpn attribution runtime static contract: PASS"
