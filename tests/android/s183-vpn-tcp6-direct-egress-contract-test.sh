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
device_runner="$repo_root/tests/device/s183-vpn-tcp6-direct-egress-product.sh"

for file in "$service" "$activity" "$fd_client" "$runtime_status" "$jni" "$abi" "$rust" \
  "$vpn_adapter"; do
  test -f "$file"
done
test -x "$device_runner"

# S183 deliberately keeps the fixed Product Core VAPI/JNI/Rust ABI stable.
grep -Fq 'STATUS_VALUE_COUNT = 136' "$runtime_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'VPN_TCP6_TRANSPORT.ATTACH' "$fd_client"
grep -Fq 'attachVpnTcp6Transport' "$fd_client"
grep -Fq 'vpn-direct-tcp6-protected-socket-handoff' "$fd_client"
grep -Fq 'VpnDirectTcp6TransportSession.start' "$service"
grep -Fq 'writeS183VpnTcp6DirectEgressStatus' "$service"
grep -Fq 'product-state/s183-vpn-tcp6-direct-egress.properties' "$service"
grep -Fq 'VPN_TUN.STATUS' "$service"
grep -Fq 'bindDebugTrafficSocketToVpn(socket)' "$activity"
grep -Fq 'debugTrafficBindToVpn' "$activity"
grep -Fq 'debugTrafficProbeResultCode' "$activity"
grep -Fq 'tcp_echo_matched' "$activity"

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


tcp6_class = service[
    service.index("private static final class VpnDirectTcp6TransportSession"):
    service.index("private static final class UnderlayNetwork")
]
for token in (
        "SOCKET_POOL_SIZE = 16",
        "new Socket()",
        "service.protect(socket)",
        "underlay.network.bindSocket(socket)",
        'InetAddress.getByName("::")',
        "socket.bind(new InetSocketAddress",
        "ParcelFileDescriptor.fromSocket(socket).dup()",
        "RuntimeControlFdClient.attachVpnTcp6Transport(rawFd)",
        "setUnderlyingNetworks(new Network[]{underlay.network})"):
    if token not in tcp6_class:
        raise AssertionError("Direct TCP6 Android handoff missing " + token)
if tcp6_class.index("service.protect(socket)") > tcp6_class.index(
        "underlay.network.bindSocket(socket)"):
    raise AssertionError("TCP6 socket can be bound to Network before protect")
if tcp6_class.index("underlay.network.bindSocket(socket)") > tcp6_class.index(
        'InetAddress.getByName("::")'):
    raise AssertionError("TCP6 local IPv6 bind must happen after Network.bindSocket")
if tcp6_class.index('InetAddress.getByName("::")') > tcp6_class.index(
        "RuntimeControlFdClient.attachVpnTcp6Transport(rawFd)"):
    raise AssertionError("TCP6 fd can be handed off before local IPv6 bind")

status_body = body(service, "private void writeS183VpnTcp6DirectEgressStatus(")
for token in (
        "RuntimeControlFdClient.callJson(",
        '"VPN_TUN.STATUS"',
        "vpn_direct_tcp6_socket_attached",
        "vpn_direct_tcp6_protect_succeeded",
        "vpn_direct_tcp6_bind_succeeded",
        "vpn_tun_tcp6_tun_origin_packets",
        "vpn_direct_tcp6_connect_succeeded",
        "vpn_direct_tcp6_payload_bytes_from_tun",
        "vpn_direct_tcp6_socket_write_completions",
        "vpn_direct_tcp6_socket_read_packets",
        "vpn_direct_tcp6_return_packets",
        "vpn_direct_tcp6_tun_write_completions",
        "vpn_direct_tcp6_transport_failed",
        "controlled_lan_response"):
    if token not in status_body:
        raise AssertionError("S183 evidence writer missing " + token)

for token in (
        "VPN_TCP6_TRANSPORT.ATTACH",
        "vpn-direct-tcp6-protected-socket-handoff",
        "PRODUCT_VPN_MAX_TCP6_FLOWS",
        "product_vpn_ipv6_transport_offset",
        "product_vpn_tcp6_parse_tun_origin",
        "product_vpn_tcp6_consume_from_tun",
        "product_vpn_tcp6_submit_return",
        "product_vpn_tcp6_socket_read_ready",
        "product_vpn_tcp6_socket_write_ready",
        "product_vpn_tcp6_checksum",
        "AF_INET6",
        "sockaddr_in6",
        "IPPROTO_TCP",
        "connect (",
        "getsockopt",
        "SO_ERROR",
        "UNIX_FILE_DATA_AVAILABLE_TO_WRITE",
        "MSG_DONTWAIT | MSG_NOSIGNAL",
        "recv (",
        "send (",
        "shutdown (",
        "product_packet_graph_submit_external",
        "PRODUCT_VPN_PACKET_ORIGIN_TUN",
        "PRODUCT_VPN_PACKET_ORIGIN_FLOW_STACK",
        "vpnTunTcp6TunOriginPackets",
        "vpnDirectTcp6SocketReadPackets",
        "vpnDirectTcp6TunWriteCompletions"):
    if token not in adapter:
        raise AssertionError("VPN adapter missing TCP6 requirement " + token)

if "libsucre_snortd" in adapter or "tun-poc" in adapter or "vpnlite" in adapter:
    raise AssertionError("S183 VPN TCP6 path must stay in Product VPP adapter")
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-183-vpn-tcp6-direct-egress' \
  'installed_app_tcp_source true' \
  'uid_not_shell true' \
  '--ez debugTraffic true' \
  '--es debugTrafficHost "$controlled_host"' \
  '--ei debugTrafficPort "$port"' \
  '--es debugTrafficNonce "$nonce"' \
  '--ez debugTrafficBindToVpn true' \
  'wait_for_host_ready' \
  '.tcp6.ready' \
  '.tcp6.server.log' \
  'files/product-state/s183-vpn-tcp6-direct-egress.properties' \
  'adapterReadiness=vpn-tun-hev-lwip' \
  'vpn_tun_tcp6_tun_origin_packets' \
  'vpn_direct_tcp6_socket_attached' \
  'vpn_direct_tcp6_protect_succeeded' \
  'vpn_direct_tcp6_bind_succeeded' \
  'vpn_direct_tcp6_connect_succeeded' \
  'vpn_direct_tcp6_payload_bytes_from_tun' \
  'vpn_direct_tcp6_socket_write_completions' \
  'vpn_direct_tcp6_socket_read_packets' \
  'vpn_direct_tcp6_return_packets' \
  'vpn_direct_tcp6_tun_write_completions' \
  'vpn_direct_tcp6_transport_failed' \
  'final_residue_clean true'; do
  grep -Fq -- "$token" "$device_runner"
done

if grep -Eq 'src/datapath/tun|sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|2001:4860|2606:4700|dns.google|cloudflare' "$device_runner"; then
  echo "S183 runner uses a retired, shell-TCP, or public-network path" >&2
  exit 1
fi

python3 - "$device_runner" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
readiness = runner.index('wait_app_property "$STATE_PATH" adapterReadiness')
server = runner.index('start_tcp6_echo_server "::"')
if server < readiness:
    raise AssertionError("S183 TCP6 echo server must start after VPN adapter readiness")
if 'server_pid="$(start_tcp6_echo_server' in runner:
    raise AssertionError("S183 TCP6 echo server must not be spawned from command substitution")
start_fn = runner[runner.index("start_tcp6_echo_server()"):runner.index("kv acceptance")]
if ">/dev/null 2>&1 &" not in start_fn:
    raise AssertionError("S183 TCP6 echo server must not keep command-substitution stdout open")
if "tr -d '\\r'" not in runner:
    raise AssertionError("S183 runner must normalize adb CRLF properties")
PY

echo "sakamoto-183 VPN TCP6 Direct Egress contract: PASS"
