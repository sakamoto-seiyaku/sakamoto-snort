#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
fd_client="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlFdClient.java"
runtime_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
rust="$repo_root/crates/product-core/src/lib.rs"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"
device_runner="$repo_root/tests/device/s181-vpn-tcp4-direct-egress-product.sh"

for file in "$service" "$fd_client" "$runtime_status" "$jni" "$abi" "$rust" \
  "$vpn_adapter"; do
  test -f "$file"
done
test -x "$device_runner"

# S181 deliberately keeps the fixed Product Core VAPI/JNI/Rust ABI stable.
grep -Fq 'STATUS_VALUE_COUNT = 136' "$runtime_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'VPN_TCP_TRANSPORT.ATTACH' "$fd_client"
grep -Fq 'attachVpnTcpTransport' "$fd_client"
grep -Fq 'VpnDirectTcp4TransportSession.start' "$service"
grep -Fq 'writeS181VpnTcp4DirectEgressStatus' "$service"
grep -Fq 'product-state/s181-vpn-tcp4-direct-egress.properties' "$service"
grep -Fq 'VPN_TUN.STATUS' "$service"

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


tcp_class = service[
    service.index("private static final class VpnDirectTcp4TransportSession"):
    service.index("private static final class UnderlayNetwork")
]
for token in (
        "SOCKET_POOL_SIZE = 16",
        "new Socket()",
        "service.protect(socket)",
        "underlay.network.bindSocket(socket)",
        'InetAddress.getByName("0.0.0.0")',
        "ParcelFileDescriptor.fromSocket(socket).dup()",
        "RuntimeControlFdClient.attachVpnTcpTransport(rawFd)",
        "setUnderlyingNetworks(new Network[]{underlay.network})"):
    if token not in tcp_class:
        raise AssertionError("Direct TCP4 Android handoff missing " + token)
if tcp_class.index("service.protect(socket)") > tcp_class.index(
        "underlay.network.bindSocket(socket)"):
    raise AssertionError("TCP4 socket can be bound to Network before protect")
if tcp_class.index("underlay.network.bindSocket(socket)") > tcp_class.index(
        "RuntimeControlFdClient.attachVpnTcpTransport(rawFd)"):
    raise AssertionError("TCP4 fd can be handed off before Network.bindSocket")
if tcp_class.index('InetAddress.getByName("0.0.0.0")') > tcp_class.index(
        "RuntimeControlFdClient.attachVpnTcpTransport(rawFd)"):
    raise AssertionError("TCP4 fd can be handed off before local bind")

status_body = body(service, "private void writeS181VpnTcp4DirectEgressStatus(")
for token in (
        "RuntimeControlFdClient.callJson(",
        '"VPN_TUN.STATUS"',
        "vpn_direct_tcp4_socket_attached",
        "vpn_direct_tcp4_connect_succeeded",
        "vpn_direct_tcp4_payload_bytes_from_tun",
        "vpn_direct_tcp4_socket_write_completions",
        "vpn_direct_tcp4_socket_read_packets",
        "vpn_direct_tcp4_return_packets",
        "vpn_direct_tcp4_tun_write_completions",
        "vpn_direct_tcp4_transport_failed",
        "controlled_lan_response"):
    if token not in status_body:
        raise AssertionError("S181 evidence writer missing " + token)

for token in (
        "VPN_TCP_TRANSPORT.ATTACH",
        "vpn-direct-tcp4-protected-socket-handoff",
        "PRODUCT_VPN_MAX_TCP4_FLOWS",
        "PRODUCT_VPN_TCP4_PENDING_BYTES",
        "product_vpn_tcp4_parse_tun_origin",
        "product_vpn_tcp4_consume_from_tun",
        "product_vpn_tcp4_submit_return",
        "product_vpn_tcp4_socket_read_ready",
        "product_vpn_tcp4_socket_write_ready",
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
        "vpnTunTcp4TunOriginPackets",
        "vpnDirectTcp4SocketReadPackets",
        "vpnDirectTcp4TunWriteCompletions"):
    if token not in adapter:
        raise AssertionError("VPN adapter missing TCP4 requirement " + token)

if "libsucre_snortd" in adapter or "tun-poc" in adapter or "vpnlite" in adapter:
    raise AssertionError("S181 VPN TCP4 path must stay in Product VPP adapter")
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-181-vpn-tcp4-direct-egress' \
  'shell_external_tcp_source true' \
  'uid=2000' \
  'toybox nc -4' \
  'wait_for_host_ready' \
  '.tcp4.ready' \
  '.tcp4.server.log' \
  'files/product-state/s181-vpn-tcp4-direct-egress.properties' \
  'adapterReadiness=vpn-tun-hev-lwip' \
  'vpn_tun_tcp4_tun_origin_packets' \
  'vpn_direct_tcp4_connect_succeeded' \
  'vpn_direct_tcp4_socket_write_completions' \
  'vpn_direct_tcp4_socket_read_packets' \
  'vpn_direct_tcp4_tun_write_completions' \
  'vpn_direct_tcp4_transport_failed' \
  'final_residue_clean true'; do
  grep -Fq "$token" "$device_runner"
done

if grep -Eq 'src/datapath/tun|sakamoto-app|adb[.]exe|tun-poc|vpnlite' "$device_runner"; then
  echo "S181 runner uses a retired or non-repo device path" >&2
  exit 1
fi

python3 - "$device_runner" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
readiness = runner.index('wait_app_property "$STATE_PATH" adapterReadiness')
server = runner.index('start_tcp4_echo_server "0.0.0.0"')
if server < readiness:
    raise AssertionError("S181 TCP echo server must start after VPN adapter readiness")
if 'server_pid="$(start_tcp4_echo_server' in runner:
    raise AssertionError("S181 TCP echo server must not be spawned from command substitution")
start_fn = runner[runner.index("start_tcp4_echo_server()"):runner.index("kv acceptance")]
if ">/dev/null 2>&1 &" not in start_fn:
    raise AssertionError("S181 TCP echo server must not keep command-substitution stdout open")
if "tr -d '\\r'" not in runner:
    raise AssertionError("S181 runner must normalize adb CRLF properties")
PY

echo "sakamoto-181 VPN TCP4 Direct Egress contract: PASS"
