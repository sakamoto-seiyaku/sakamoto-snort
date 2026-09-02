#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
adapter_contract="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPacketAdapterContract.java"
runtime_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
rust="$repo_root/crates/product-core/src/lib.rs"
api="$repo_root/src/product/vpp/product_core.api"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"
vpn_adapter_header="$repo_root/src/product/vpp/product_vpn_udp4_adapter.h"
cmake="$repo_root/src/product/vpp/CMakeLists.txt"
device_runner="$repo_root/tests/device/s180-vpn-udp4-direct-egress-product.sh"

for file in \
  "$service" "$activity" "$adapter_contract" "$runtime_status" "$jni" "$abi" \
  "$vapi" "$rust" "$api" "$plugin" "$graph" "$vpn_adapter" \
  "$vpn_adapter_header" "$cmake"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'ADAPTER_VPN_TUN_HEV_LWIP' "$adapter_contract"
grep -Fq 'adapterReadyAfterHandoff' "$adapter_contract"
grep -Fq 'VpnDirectUdp4TransportSession.start' "$service"
grep -Fq 'attachVpnTunSessionForProductCore' "$service"
grep -Fq 'waitForVpnAdapterReadyAfterHandoff' "$service"
grep -Fq 'writeS180VpnUdp4DirectEgressStatus' "$service"
grep -Fq 'product-state/s180-vpn-udp4-direct-egress.properties' "$service"
grep -Fq 'setUnderlyingNetworks(new Network[]{underlay.network})' "$service"
grep -Fq 'VpnService.prepare(this)' "$activity"

for field in \
  vpn_tun_fd_attached \
  vpn_direct_udp4_socket_attached \
  vpn_direct_udp4_protect_succeeded \
  vpn_direct_udp4_bind_succeeded \
  vpn_tun_ingress_packets \
  vpn_tun_udp4_tun_origin_packets \
  vpn_flow_stack_admissions \
  vpn_direct_udp4_send_succeeded \
  vpn_direct_udp4_transport_failed \
  vpn_flow_stack_return_packets \
  vpn_flow_stack_return_provenance_packets \
  vpn_tun_write_completions \
  vpn_infrastructure_faults \
  vpn_duplicate_or_stale_drops; do
  grep -Fq "$field" "$api"
  grep -Fq "$field" "$abi"
  grep -Fq "$field" "$vapi"
  grep -Fq "$field" "$plugin"
  grep -Fq "$field" "$rust"
  grep -Fq "$field" "$jni"
done

for field in \
  vpnTunFdAttached \
  vpnDirectUdp4SocketAttached \
  vpnDirectUdp4ProtectSucceeded \
  vpnDirectUdp4BindSucceeded \
  vpnTunIngressPackets \
  vpnTunUdp4TunOriginPackets \
  vpnFlowStackAdmissions \
  vpnDirectUdp4SendSucceeded \
  vpnDirectUdp4TransportFailed \
  vpnFlowStackReturnPackets \
  vpnFlowStackReturnProvenancePackets \
  vpnTunWriteCompletions \
  vpnInfrastructureFaults \
  vpnDuplicateOrStaleDrops; do
  grep -Fq "$field" "$runtime_status"
done

grep -Fq 'STATUS_VALUE_COUNT = 136' "$runtime_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'product_vpn_udp4_adapter_start' "$plugin"
grep -Fq 'product_vpn_udp4_adapter_available' "$plugin"
grep -Fq 'product_vpn_udp4_adapter_protection_running' "$plugin"
grep -Fq 'product_vpn_udp4_adapter.c' "$cmake"

python3 - "$service" "$vpn_adapter" "$graph" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
adapter = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
graph = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")


def function_body(source, signature):
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
    raise AssertionError("unclosed function: " + signature)


start_core = function_body(service, "private void startProductCoreRuntime(")
for required in (
        "establishPacketAdapterSession(adapter)",
        "attachVpnTunSessionForProductCore(",
        "VpnDirectUdp4TransportSession.start(",
        "waitForVpnAdapterReadyAfterHandoff(",
        "closeVpnTunSessionAfterNativeHandoff()"):
    if required not in start_core:
        raise AssertionError("ProductCore VPN start path missing " + required)

direct_start = function_body(
    service,
    "static StartResult start(RuntimeService service, UnderlayNetwork underlay)")
for required in (
        "new DatagramSocket(null)",
        "ParcelFileDescriptor.fromDatagramSocket(socket).dup()",
        "service.protect(socket)",
        "underlay.network.bindSocket(socket)",
        "setUnderlyingNetworks(new Network[]{underlay.network})",
        "RuntimeControlFdClient.attachVpnTransport(rawFd)"):
    if required not in direct_start:
        raise AssertionError("Direct UDP4 setup missing " + required)
if direct_start.index("service.protect(socket)") > direct_start.index(
        "RuntimeControlFdClient.attachVpnTransport(rawFd)"):
    raise AssertionError("Direct UDP4 fd can be handed off before protect")
if direct_start.index("service.protect(socket)") > direct_start.index(
        "underlay.network.bindSocket(socket)"):
    raise AssertionError("Direct UDP4 socket can enter Network.bindSocket before protect")
if direct_start.index("underlay.network.bindSocket(socket)") > direct_start.index(
        "RuntimeControlFdClient.attachVpnTransport(rawFd)"):
    raise AssertionError("Direct UDP4 fd can be handed off before Network.bindSocket")

for required in (
        "CONTROL_SOCKET_NAME",
        "VPN_TUN.ATTACH",
        "VPN_TUN.STATUS",
        "VPN_TRANSPORT.ATTACH",
        "SCM_RIGHTS",
        "product_packet_graph_submit_external",
        "product_vpn_udp4_parse_tun_origin",
        "product_vpn_udp4_remember_flow",
        "product_vpn_udp4_find_flow",
        "product_vpn_udp4_send_direct",
        "product_vpn_udp4_build_return_packet",
        "PRODUCT_VPN_MAX_UDP4_FLOWS",
        "product_vpn_udp4_find_flow",
        "sockaddr_storage",
        "IN6_IS_ADDR_V4MAPPED",
        "product_vpn_send_status_response",
        "policyDropActivity",
        "allowedFlowActivity",
        "PRODUCT_VPN_PACKET_ORIGIN_TUN",
        "PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK",
        "vpn_flow_stack_return_provenance_packets++",
        "sendto (",
        "recvfrom (",
        "write (nm->tun_fd",
        "MSG_DONTWAIT"):
    if required not in adapter:
        raise AssertionError("VPN adapter missing " + required)

if "tun-poc" in adapter or "vpnlite" in adapter or "socks5" in adapter.lower():
    raise AssertionError("S180 VPN adapter must not be a POC/vpnlite/SOCKS pass")

tun_read = function_body(adapter, "product_vpn_tun_read_ready (")
parse_start = tun_read.index("if (!product_vpn_udp4_parse_tun_origin")
parse_end = tun_read.index("vpn_tun_udp4_tun_origin_packets++", parse_start)
if "vpn_infrastructure_faults++" in tun_read[parse_start:parse_end]:
    raise AssertionError("Unsupported TUN traffic must not be counted as S180 infrastructure failure")

submit_external = function_body(graph, "product_packet_graph_submit_external (")
if "PRODUCT_PACKET_INTENT_PASS_ADAPTER" not in submit_external:
    raise AssertionError("S180 still needs the shared Product graph terminal PASS path")
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-180-vpn-udp4-direct-egress' \
  'shell_external_udp_source true' \
  'uid=2000' \
  'toybox nc -4 -u' \
  'wait_for_host_ready' \
  '.udp4.ready' \
  '.udp4.server.log' \
  'files/product-state/s180-vpn-udp4-direct-egress.properties' \
  'adapterReadiness=vpn-tun-hev-lwip' \
  'vpn_tun_udp4_tun_origin_packets' \
  'vpn_direct_udp4_protect_succeeded' \
  'vpn_direct_udp4_bind_succeeded' \
  'vpn_flow_stack_return_provenance_packets' \
  'vpn_tun_write_completions' \
  'final_residue_clean true'; do
  grep -Fq "$token" "$device_runner"
done

if grep -Eq 'src/datapath/tun|libsucre_snortd|VPN_TUN.STATUS|sakamoto-app|adb[.]exe|tun-poc|vpnlite' "$device_runner"; then
  echo "S180 runner uses a retired or non-repo device path" >&2
  exit 1
fi

python3 - "$device_runner" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
readiness = runner.index('wait_app_property "$STATE_PATH" adapterReadiness')
server = runner.index('start_udp4_echo_server "0.0.0.0"')
if server < readiness:
    raise AssertionError("S180 UDP echo server must start after VPN adapter readiness")
if 'server_pid="$(start_udp4_echo_server' in runner:
    raise AssertionError("S180 UDP echo server must not be spawned from command substitution")
start_fn = runner[runner.index("start_udp4_echo_server()"):runner.index("kv acceptance")]
if ">/dev/null 2>&1 &" not in start_fn:
    raise AssertionError("S180 UDP echo server must not keep command-substitution stdout open")
if "tr -d '\\r'" not in runner:
    raise AssertionError("S180 runner must normalize adb CRLF properties before numeric checks")
PY

echo "sakamoto-180 VPN UDP4 Direct Egress contract: PASS"
