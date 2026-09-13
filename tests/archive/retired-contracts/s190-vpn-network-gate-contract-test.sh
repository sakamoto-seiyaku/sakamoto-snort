#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
fd_client="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlFdClient.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"
device_runner="$repo_root/tests/device/s190-vpn-network-gate-product.sh"

for file in "$service" "$fd_client" "$activity" "$graph" "$vpn_adapter" \
  "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'product-state/s190-vpn-network-gate.properties' "$service"
grep -Fq 'String gateStage = preservedNetworkGateEvidenceStage(status)' "$service"
grep -Fq 'rememberNetworkGateEvidenceStage(status, gateStage)' "$service"
grep -Fq 'lastNetworkGateEvidenceGeneration' "$service"
grep -Fq 'lastNetworkGateEvidenceRevision' "$service"
grep -Fq 'lastNetworkGateEvidenceProfile' "$service"
grep -Fq 'writeS190VpnNetworkGateStatus(status, gateStage, "", "")' "$service"
grep -Fq 'policyStoreEvidencePath(status,' "$service"
grep -Fq 'String gateStage = blocked ? "gate_blocked" : "gate_open"' "$service"
grep -Fq 'RuntimeProfile.VPN' "$service"
grep -Fq 'currentVpnPolicyHints()' "$service"
grep -Fq 'AuthoringPolicyBundle.NetworkContextId.VPN' "$service"
grep -Fq 'RuntimeControlFdClient.attachVpnTun(rawFd, session.ipv6Enabled,' "$service"
grep -Fq 'policyHints.subjectUid, policyHints.networkContext)' "$service"
grep -Fq 'schema=s190-vpn-network-gate/v1' "$service"
grep -Fq 'profile=vpn' "$service"
grep -Fq 'gate_network_context=' "$service"
grep -Fq 'vpn_policy_hint_subject_uid=' "$service"
grep -Fq 'vpn_policy_hint_network_context=' "$service"
grep -Fq 'policy_last_drop_packet_origin=' "$service"
grep -Fq 'expected_policy_last_drop_packet_origin=1' "$service"
grep -Fq 'vpn_adapter_policy_drop_completion=' "$service"
grep -Fq 'adapter_completion_separate=vpn_tun_and_flow_stack_counters' "$service"
grep -Fq 'transport_outcome_separate=direct_socket_counters' "$service"
grep -Fq 'physical_nfqueue_completion=false' "$service"
grep -Fq 'root_vpn_shared_product_store=true' "$service"
grep -Fq 'rust_product_store_single_writer=true' "$service"
grep -Fq 'ui_policy_authority=false' "$service"
grep -Fq 'vpp_policy_authority=false' "$service"

grep -Fq 'vpn-policy-hints-v1' "$fd_client"
grep -Fq 'VPN_POLICY_HINTS_UNAVAILABLE' "$fd_client"
grep -Fq 'public static AttachResult attachVpnTun(' "$fd_client"
grep -Fq 'policySubjectUid' "$fd_client"
grep -Fq 'networkContext' "$fd_client"
grep -Fq 'callWithFd(1, VPN_TUN_ATTACH, args, rawFd)' "$fd_client"

grep -Fq 'EXTRA_DEBUG_TRAFFIC_BIND_TO_VPN' "$activity"
grep -Fq 'requestDebugNetworkGate' "$activity"
grep -Fq 'AuthoringPolicyBundle.NetworkContextId.parse(contextName)' "$activity"

grep -Fq 'u32 policy_subject_uid;' "$vpn_adapter"
grep -Fq 'u64 policy_network_context_id;' "$vpn_adapter"
grep -Fq 'product_vpn_payload_u32' "$vpn_adapter"
grep -Fq 'vpn-policy-hints-v1' "$vpn_adapter"
grep -Fq 'policySubjectUid' "$vpn_adapter"
grep -Fq 'policyNetworkContext' "$vpn_adapter"
grep -Fq 'product_vpn_attach_tun_fd (nm, passed_fd, ipv6, policy_subject_uid,' "$vpn_adapter"
grep -Fq 'hints.uid = nm->policy_subject_uid;' "$vpn_adapter"
grep -Fq 'hints.network_context_id = nm->policy_network_context_id;' "$vpn_adapter"
# TUN remains the interface provenance; the inner packet is Device OUTPUT for
# the policy matcher.
grep -Fq 'hints.interface_id = PRODUCT_VPN_PACKET_ORIGIN_TUN;' "$vpn_adapter"
grep -Fq 'hints.profile_id = PRODUCT_L4_POLICY_DIRECTION_OUTPUT;' "$vpn_adapter"
grep -Fq 'product_packet_graph_submit_external' "$vpn_adapter"

# The GateTable matcher compares packet facts to the selected typed entry;
# scalar S191 fields are no longer the product path for S192/S190.
grep -Fq 'packet->uid != rule->uid' "$graph"
grep -Fq 'packet->network_context_id != rule->network_context_id' "$graph"
grep -Fq 'product_packet_graph_gate_table_t' "$graph"
grep -Fq 'product_packet_graph_record_policy_drop' "$graph"
grep -Fq 'PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE' "$graph"

grep -Fq 'SAKAMOTO-190-vpn-network-gate' "$device_runner"
grep -Fq 'debugSetNetworkGateContext vpn' "$device_runner"
grep -Fq 'debugTrafficBindToVpn true' "$device_runner"
grep -Fq 'capture_s190_status gate_drop - "$app_uid" 3 true' "$device_runner"
grep -Fq 'vpn_adapter_policy_drop_completion' "$device_runner"
grep -Fq 'compare_policy_fields root_seed.vpn_start "$ROOT_SEED_STATUS" "$VPN_START_STATUS"' "$device_runner"
grep -Fq 'compare_policy_fields final_root_vpn "$ROOT_FINAL_STATUS" "$VPN_OPEN_STATUS"' "$device_runner"
grep -Fq 'kv final_residue_clean true' "$device_runner"

python3 - "$service" "$fd_client" "$vpn_adapter" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
fd_client = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
vpn_adapter = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")


def body(source, signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError("unclosed body for " + signature)


writer = body(service, "private void writeS190VpnNetworkGateStatus(")
for token in (
    "profile != RuntimeProfile.VPN",
    "VPN_TUN.STATUS",
    "AuthoringPolicyBundle.NetworkContextId.VPN.wireId",
    "status.policyLastDropRevision == status.policyActiveRevision",
    "status.policyLastDropRuleId == status.policyGateRuleId",
    "status.policyLastDropNetworkContext == status.policyGateNetworkContext",
    "status.policyLastDropVerdict == PRODUCT_POLICY_VERDICT_DROP",
    "status.policyLastDropWinner == PRODUCT_NETWORK_GATE_WINNER_NETWORK_GATE",
    "vpnPolicyDropPacketOriginCode(status, result)",
    "packetOriginCode == 1",
    "vpnTunIngressPackets",
    "vpnFlowStackAdmissions",
    "vpnDirectTcp4ConnectAttempts",
    "vpnDirectTcp4ConnectSucceeded",
):
    if token not in writer:
        raise AssertionError("S190 evidence missing " + token)

preserved = body(service, "private String preservedNetworkGateEvidenceStage(")
for token in (
    "lastNetworkGateEvidenceProfile != activeProfile",
    "lastNetworkGateEvidenceGeneration != generation",
    "status.policyGeneration != lastNetworkGateEvidenceGeneration",
    "status.policyRequestedRevision != lastNetworkGateEvidenceRevision",
    "status.policyActiveRevision != lastNetworkGateEvidenceRevision",
    "clearNetworkGateEvidenceStage()",
    'return "running"',
):
    if token not in preserved:
        raise AssertionError("S190 stage preservation missing " + token)

origin = body(service, "private static int vpnPolicyDropPacketOriginCode(")
for token in (
    "status.policyLastDropDeviceDirection != PRODUCT_DEVICE_DIRECTION_OUTPUT",
    'vpnTunTcp4TunOriginPackets',
    "return 1",
):
    if token not in origin:
        raise AssertionError("S190 origin projection missing " + token)

hints = body(service, "private VpnPolicyHints currentVpnPolicyHints()")
for token in (
    "productBackend.productState()",
    "state.authoringPolicyBundle.gateMatrix",
    "AuthoringPolicyBundle.NetworkContextId.VPN",
    "rule.subjectId.uid",
    "rule.networkContext.wireId",
    "VpnPolicyHints.none()",
):
    if token not in hints:
        raise AssertionError("VPN policy hints path missing " + token)

attach = body(fd_client, "public static AttachResult attachVpnTun(\n            int rawFd")
for token in (
    'args.put("enableIpv6", enableIpv6)',
    'args.put("policySubjectUid", policySubjectUid)',
    'args.put("networkContext", networkContext)',
    "callWithFd(1, VPN_TUN_ATTACH, args, rawFd)",
):
    if token not in attach:
        raise AssertionError("VPN attach args missing " + token)

native_attach = body(vpn_adapter, "product_vpn_attach_tun_fd")
for token in (
    "nm->policy_subject_uid = policy_subject_uid",
    "nm->policy_network_context_id = policy_network_context_id",
    "nm->vpn_tun_fd_attached++",
):
    if token not in native_attach:
        raise AssertionError("native VPN attach missing " + token)
PY

echo "sakamoto-190 VPN Network Gate contract: PASS"
