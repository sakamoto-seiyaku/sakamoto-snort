#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
fd_client="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlFdClient.java"
runtime_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust="$repo_root/crates/product-core/src/lib.rs"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"
device_runner="$repo_root/tests/device/s182-vpn-udp6-direct-egress-product.sh"

for file in "$service" "$activity" "$fd_client" "$runtime_status" "$jni" "$abi" "$rust" \
  "$vpn_adapter"; do
  test -f "$file"
done
test -x "$device_runner"

# S182 deliberately keeps the fixed Product Core VAPI/JNI/Rust ABI stable.
grep -Fq 'STATUS_VALUE_COUNT = 136' "$runtime_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'VPN_UDP6_TRANSPORT.ATTACH' "$fd_client"
grep -Fq 'attachVpnUdp6Transport' "$fd_client"
grep -Fq 'VpnDirectUdp6TransportSession.start' "$service"
grep -Fq 'writeS182VpnUdp6DirectEgressStatus' "$service"
grep -Fq 'product-state/s182-vpn-udp6-direct-egress.properties' "$service"
grep -Fq 'VPN_TUN.STATUS' "$service"
grep -Fq 'address.getAddress().length == 16' "$activity"
grep -Fq 'InetAddress.getByName("::")' "$activity"
grep -Fq 'bindDebugDatagramSocketToVpn(socket)' "$activity"

python3 - "$service" "$vpn_adapter" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
adapter = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")


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


udp6_class = service[
    service.index("private static final class VpnDirectUdp6TransportSession"):
    service.index("private static final class VpnDirectTcp4TransportSession")
]
for token in (
        "new DatagramSocket(null)",
        "service.protect(socket)",
        "underlay.network.bindSocket(socket)",
        'InetAddress.getByName("::")',
        "socket.bind(new InetSocketAddress",
        "ParcelFileDescriptor.fromDatagramSocket(socket).dup()",
        "RuntimeControlFdClient.attachVpnUdp6Transport(rawFd)",
        "setUnderlyingNetworks(new Network[]{underlay.network})"):
    if token not in udp6_class:
        raise AssertionError("Direct UDP6 Android handoff missing " + token)
if udp6_class.index("service.protect(socket)") > udp6_class.index(
        "underlay.network.bindSocket(socket)"):
    raise AssertionError("UDP6 socket can be bound to Network before protect")
if udp6_class.index("underlay.network.bindSocket(socket)") > udp6_class.index(
        'InetAddress.getByName("::")'):
    raise AssertionError("UDP6 local IPv6 bind must happen after Network.bindSocket")
if udp6_class.index('InetAddress.getByName("::")') > udp6_class.index(
        "RuntimeControlFdClient.attachVpnUdp6Transport(rawFd)"):
    raise AssertionError("UDP6 fd can be handed off before local IPv6 bind")

status_body = body(service, "private void writeS182VpnUdp6DirectEgressStatus(")
for token in (
        "RuntimeControlFdClient.callJson(",
        '"VPN_TUN.STATUS"',
        "vpn_direct_udp6_socket_attached",
        "vpn_direct_udp6_protect_succeeded",
        "vpn_direct_udp6_bind_succeeded",
        "vpn_tun_udp6_tun_origin_packets",
        "vpn_direct_udp6_send_succeeded",
        "vpn_direct_udp6_return_packets",
        "vpn_direct_udp6_tun_write_completions",
        "vpn_direct_udp6_transport_failed",
        "controlled_lan_response"):
    if token not in status_body:
        raise AssertionError("S182 evidence writer missing " + token)

for token in (
        "VPN_UDP6_TRANSPORT.ATTACH",
        "vpn-direct-udp6-protected-socket-handoff",
        "PRODUCT_VPN_MAX_UDP6_FLOWS",
        "product_vpn_ipv6_transport_offset",
        "product_vpn_udp6_parse_tun_origin",
        "product_vpn_udp6_remember_flow",
        "product_vpn_udp6_find_flow",
        "product_vpn_udp6_send_direct",
        "product_vpn_udp6_build_return_packet",
        "product_vpn_udp6_checksum",
        "product_vpn_udp6_read_ready",
        "AF_INET6",
        "sockaddr_in6",
        "IPPROTO_UDP",
        "product_packet_graph_submit_external",
        "PRODUCT_VPN_PACKET_ORIGIN_TUN",
        "PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK",
        "vpnTunUdp6TunOriginPackets",
        "vpnDirectUdp6SendSucceeded",
        "vpnDirectUdp6ReturnPackets",
        "vpnDirectUdp6TunWriteCompletions",
        "sendto (",
        "recvfrom (",
        "write (nm->tun_fd",
        "MSG_DONTWAIT"):
    if token not in adapter:
        raise AssertionError("VPN adapter missing UDP6 requirement " + token)

if "libsucre_snortd" in adapter or "tun-poc" in adapter or "vpnlite" in adapter:
    raise AssertionError("S182 VPN UDP6 path must stay in Product VPP adapter")
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-182-vpn-udp6-direct-egress' \
  'installed_app_udp_source true' \
  'uid_not_shell true' \
  '--ez debugUdpTraffic true' \
  '--es debugUdpHost "$controlled_host"' \
  '--ei debugUdpPort "$port"' \
  '--es debugUdpNonce "$nonce"' \
  '--ez debugUdpExpectReply true' \
  '--ez debugTrafficBindToVpn true' \
  'wait_for_host_ready' \
  '.udp6.ready' \
  '.udp6.server.log' \
  'files/product-state/s182-vpn-udp6-direct-egress.properties' \
  'adapterReadiness=vpn-tun-hev-lwip' \
  'vpn_tun_udp6_tun_origin_packets' \
  'vpn_direct_udp6_socket_attached' \
  'vpn_direct_udp6_protect_succeeded' \
  'vpn_direct_udp6_bind_succeeded' \
  'vpn_direct_udp6_send_succeeded' \
  'vpn_direct_udp6_return_packets' \
  'vpn_direct_udp6_tun_write_completions' \
  'vpn_direct_udp6_transport_failed' \
  'final_residue_clean true'; do
  grep -Fq -- "$token" "$device_runner"
done

if grep -Eq 'src/datapath/tun|sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|2001:4860|2606:4700|dns.google|cloudflare' "$device_runner"; then
  echo "S182 runner uses a retired or non-repo device path" >&2
  exit 1
fi

python3 - "$device_runner" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
readiness = runner.index('wait_app_property "$STATE_PATH" adapterReadiness')
server = runner.index('start_udp6_echo_server "$controlled_host"')
if server < readiness:
    raise AssertionError("S182 UDP6 echo server must start after VPN adapter readiness")
if 'start_udp6_echo_server "::"' in runner:
    raise AssertionError("S182 UDP6 echo server must bind the controlled IPv6 endpoint")
if 'server_pid="$(start_udp6_echo_server' in runner:
    raise AssertionError("S182 UDP6 echo server must not be spawned from command substitution")
start_fn = runner[runner.index("start_udp6_echo_server()"):runner.index("kv acceptance")]
if ">/dev/null 2>&1 &" not in start_fn:
    raise AssertionError("S182 UDP6 echo server must not keep command-substitution stdout open")
if "tr -d '\\r'" not in runner:
    raise AssertionError("S182 runner must normalize adb CRLF properties")
PY

echo "sakamoto-182 VPN UDP6 Direct Egress contract: PASS"
