#!/usr/bin/env bash
set -euo pipefail

# Source contract for the SAKAMOTO-192 device runner.  This test is static:
# it must not contact a device or treat an older transport runner as the
# Product L4 acceptance oracle.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
device_runner="$repo_root/tests/device/s192-root-vpn-l4-matrix-product.sh"
graph_source="$repo_root/src/product/vpp/product_packet_graph.c"
host_graph_source="$repo_root/src/product/vpp/product_packet_graph_host_evidence.c"
abi_header="$repo_root/src/product/include/sakamoto_product_abi.h"
api_source="$repo_root/src/product/vpp/product_core.api"
plugin_source="$repo_root/src/product/vpp/product_core_plugin.c"
vapi_source="$repo_root/src/product/native/sakamoto_product_vapi.c"
rust_source="$repo_root/crates/product-core/src/lib.rs"
jni_source="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
java_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
java_service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

test -f "$device_runner"
test -x "$device_runner"
test -f "$graph_source"
test -f "$host_graph_source"
for source in "$abi_header" "$api_source" "$plugin_source" "$vapi_source" \
  "$rust_source" "$jni_source" "$java_status" "$java_service"; do
  test -f "$source"
done
bash -n "$device_runner"

# Native evidence must correlate a completed typed match with the current
# probe tuple.  A same-probe retransmit remains effective, a wrong destination
# port remains visible as NO_MATCH, and unrelated background traffic cannot
# erase the status consumed by this runner.
for symbol in \
  'l4_typed_match_policy_key' 'l4_typed_match_probe_key' \
  'l4_typed_match_subject_key' \
  'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_PROBE' \
  'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_SAME_SUBJECT' \
  'PRODUCT_PACKET_GRAPH_L4_MATCH_ASSOCIATION_UNRELATED' \
  'product_packet_graph_policy_association_fixture_cli'; do
  grep -Fq "$symbol" "$graph_source" ||
    { echo "S192 graph evidence seam missing: $symbol" >&2; exit 1; }
done
grep -Fq 'run-policy-association-fixture' "$host_graph_source"
for field in \
  'policy_l4_typed_match_policy_key' 'policy_l4_typed_match_probe_key' \
  'policy_l4_last_evaluation_probe_key'; do
  for source in "$abi_header" "$api_source" "$plugin_source" "$vapi_source" \
    "$rust_source" "$jni_source"; do
    grep -Fq "$field" "$source" ||
      { echo "S192 status key is not wired: $field ($source)" >&2; exit 1; }
  done
done
for field in policyL4TypedMatchPolicyKey policyL4TypedMatchProbeKey \
  policyL4LastEvaluationProbeKey; do
  grep -Fq "$field" "$java_status" ||
    { echo "S192 Java status key missing: $field" >&2; exit 1; }
done
grep -Fq 'STATUS_ASSOCIATION_VALUE_COUNT = 3' "$jni_source"
grep -Fq 'status.policyL4TypedMatchProbeKey == 0L' "$java_service"
grep -Fq 'status.policyL4LastEvaluationProbeKey == 0L' "$java_service"
grep -Fq 's192ProbePortsMatch' "$java_service"
grep -Fq 'counters.probeEpochFallbackCandidate' "$java_service"

# --help is the only executable smoke path in this contract; it exits before
# device preflight and therefore cannot accidentally become physical execution.
help_output="$(bash "$device_runner" --help)"
grep -Fq 'Physical execution is intentionally opt-in' <<<"$help_output"
grep -Fq '192.168.4.5' <<<"$help_output"
grep -Fq 'runtime-discovered' <<<"$help_output"

# The runner owns the ADB boundary and must use the repository wrapper only.
grep -Fq 'export ADB="${repo_root}/dev/adb"' "$device_runner"
grep -Fq 'adb_raw' "$device_runner"
grep -Fq 'adb_target' "$device_runner"
grep -Fq 'timeout "$ADB_TIMEOUT_SECONDS" "$ADB"' "$device_runner"
for forbidden in 'adb.exe' 'source "$repo_root/tests/device/' 'SNORT_CTL' \
  'sucre-snort-control' 'snort-control' 'am startservice' 'ANDROID_HOME'; do
  if grep -Fq "$forbidden" "$device_runner"; then
    echo "S192 device runner uses forbidden dependency: $forbidden" >&2
    exit 1
  fi
done

# Controlled topology and runtime IPv6 discovery are explicit, not guessed.
grep -Fq 'S192_SERIAL="28201JEGR0XPAJ"' "$device_runner"
grep -Fq 'controlled_host4="192.168.4.5"' "$device_runner"
grep -Fq 'controlled host4 must be exactly 192.168.4.5' "$device_runner"
grep -Fq 'discover_host6()' "$device_runner"
grep -Fq 'ip -6 -o addr show' "$device_runner"
grep -Fq 'ip -6 route get' "$device_runner"
grep -Fq 'validate_and_discover_host6' "$device_runner"
grep -Fq 'S192_CONTROLLED_LAN_HOST6' "$device_runner"

# The actual acceptance matrix is table-driven and covers both profile rows,
# both IP families, and both supported L4 protocols.
grep -Fq 'MATRIX_CASES=(ipv4-tcp ipv4-udp ipv6-tcp ipv6-udp)' "$device_runner"
grep -Fq 'MATRIX_PROFILES=(root vpn)' "$device_runner"
grep -Fq 'run_profile_matrix root false' "$device_runner"
grep -Fq 'run_profile_matrix vpn true' "$device_runner"
for cell in ipv4-tcp ipv4-udp ipv6-tcp ipv6-udp; do
  grep -Fq "$cell" "$device_runner"
done
grep -Fq 'CASE_PROTOCOL=6' "$device_runner"
grep -Fq 'CASE_PROTOCOL=17' "$device_runner"
grep -Fq 'CASE_FAMILY=4' "$device_runner"
grep -Fq 'CASE_FAMILY=6' "$device_runner"
grep -Fq 'debugSetL4RuleFamily' "$device_runner"
grep -Fq 'debugSetL4RuleIpProtocol' "$device_runner"
grep -Fq 'debugSetL4RuleDirection' "$device_runner"
grep -Fq 'Device Packet Direction is an independent matcher fact' "$device_runner"
grep -Fq 'VPN TUN adapter profile_id=1 is' "$device_runner"
grep -Fq 'need("policy_direction", "3")' "$device_runner"
grep -Fq 'debugSetL4RuleNetworkContext' "$device_runner"
grep -Fq 'debugSetL4RuleSourceCidr' "$device_runner"
grep -Fq 'debugSetL4RuleDestinationCidr' "$device_runner"
grep -Fq 'debugSetL4RuleSourcePortFirst' "$device_runner"
grep -Fq 'debugSetL4RuleSourcePortLast' "$device_runner"
grep -Fq 'debugSetL4RuleDestinationPortFirst' "$device_runner"
grep -Fq 'debugSetL4RuleDestinationPortLast' "$device_runner"
grep -Fq 'debugSetL4RuleAction' "$device_runner"
grep -Fq 'debugSetL4RulePriority 10' "$device_runner"
grep -Fq 'debugSetL4RuleOrder' "$device_runner"

# Host nonce echo is the authoritative traffic oracle.  Existing direct
# transport runners may be used as setup elsewhere but cannot be acceptance.
grep -Fq 'host_tcp_echo_once' "$device_runner"
grep -Fq 'host_udp_echo_once' "$device_runner"
grep -Fq 'socket.AF_INET6' "$device_runner"
grep -Fq 'tcp_echo_matched' "$device_runner"
grep -Fq 'udp_echo_matched' "$device_runner"
grep -Fq 'validate_host_result' "$device_runner"
grep -Fq 'debugTrafficNonce' "$device_runner"
grep -Fq 'debugUdpNonce' "$device_runner"
grep -Fq 'debugTrafficBindToVpn "$bind_to_vpn"' "$device_runner"
grep -Fq 'run_profile_case' "$device_runner"
grep -Fq 'no_match' "$device_runner"
grep -Fq 'policy_no_match_reason' "$device_runner"
grep -Fq 'pass_next' "$device_runner"

# The status file is the explicit Product matcher contract.  It carries the
# complete input identity, winner/rank, action/verdict, and bounded probes.
grep -Fq 'MATRIX_STATUS_PATH="files/product-state/s192-root-vpn-l4-matrix.properties"' \
  "$device_runner"
for key in \
  'policy_uid' 'policy_uid_complete' 'policy_revision' \
  'policy_snapshot_hash' 'policy_snapshot_identity' 'policy_network_context' \
  'policy_ifindex' 'policy_direction' 'policy_ports_available' \
  'policy_rule_id' 'policy_reason_id' 'policy_winner_rank' \
  'policy_candidate_count' 'policy_probe_count' 'policy_probe_limit' \
  'policy_subject_probe_count' 'policy_evaluation' 'policy_action' \
  'policy_verdict' 'residue_clean=true'; do
  grep -Fq "$key" "$device_runner"
done
grep -Fq 'probe_limit > 128' "$device_runner"
grep -Fq 'probe_count > probe_limit' "$device_runner"
grep -Fq 'subject_probe_count > 16' "$device_runner"
grep -Fq 'policy_winner_rank' "$device_runner"
if grep -Fq 'specificity' "$device_runner"; then
  echo "S192 runner must not introduce a specificity hidden rank" >&2
  exit 1
fi

# Bundle identity is read from the shared Product store and compared after
# Root/VPN and each profile restart.  Four L4 entries cover the eight profile
# cells; rule/reason IDs remain stable in every readback.
grep -Fq 'POLICY_BUNDLE_PATH="files/product-policy/policy-bundle.properties"' \
  "$device_runner"
grep -Fq 'read_app_file "$POLICY_BUNDLE_PATH" > "$bundle"' "$device_runner"
if grep -Fq 'read_app_file "$L4_STORE_PATH"' "$device_runner"; then
  echo "S192 runner must not use legacy l4-intent.properties as an authoring gate" >&2
  exit 1
fi
grep -Fq 'l4RuleCount", "4"' "$device_runner"
grep -Fq 'rule_id_' "$device_runner"
grep -Fq 'reason_id_' "$device_runner"
grep -Fq 'root.policy-bundle.properties' "$device_runner"
grep -Fq 'vpn.policy-bundle.properties' "$device_runner"
grep -Fq 'cmp -s "$RESULT_DIR/root.policy-bundle.properties"' "$device_runner"
grep -Fq 'same_uid_revision_hash_rule_reason=true' "$device_runner"
grep -Fq 'compare_profile_statuses' "$device_runner"
grep -Fq 'root_vpn_same_uid true' "$device_runner"
grep -Fq 'root_vpn_same_revision true' "$device_runner"
grep -Fq 'root_vpn_same_snapshot_hash true' "$device_runner"
grep -Fq 'root_vpn_same_rule_reason true' "$device_runner"

# Profile/restart/residue evidence must be explicit and must not be inferred
# from a transport helper's counters.
grep -Fq 'runtimeStart true' "$device_runner"
grep -Fq 'runtimeStop true' "$device_runner"
grep -Fq 'cold_start_control_activity' "$device_runner"
grep -Fq 'preflight_cold_start_settled true' "$device_runner"
grep -Fq 'am force-stop "$PACKAGE"' "$device_runner"
grep -Fq 'wait_for_profile_ready root root-nfqueue' "$device_runner"
grep -Fq 'wait_for_profile_ready vpn vpn-tun-hev-lwip' "$device_runner"
grep -Fq 'root_restart_same_revision true' "$device_runner"
grep -Fq 'root_restart_same_snapshot_hash true' "$device_runner"
grep -Fq 'vpn_restart_same_revision true' "$device_runner"
grep -Fq 'vpn_restart_same_snapshot_hash true' "$device_runner"
grep -Fq 'mayBeActive=false' "$device_runner"
grep -Fq 'final_residue_clean true' "$device_runner"
grep -Fq 'SAKAMOTO-192 Root/VPN L4 matrix: PASS' "$device_runner"

echo "sakamoto-192 Root/VPN L4 matrix device contract: PASS"
