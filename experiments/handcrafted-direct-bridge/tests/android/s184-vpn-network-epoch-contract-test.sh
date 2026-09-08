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
device_runner="$repo_root/tests/device/s184-vpn-network-epoch-product.sh"

for file in "$service" "$activity" "$fd_client" "$runtime_status" "$jni" "$abi" "$rust" \
  "$vpn_adapter"; do
  test -f "$file"
done
test -x "$device_runner"

# S184 adds a RuntimeService projection/runner only; the fixed Product Core ABI stays stable.
grep -Fq 'STATUS_VALUE_COUNT = 136' "$runtime_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'VPN_TCP6_TRANSPORT.ATTACH' "$fd_client"
grep -Fq 'vpn-direct-tcp6-protected-socket-handoff' "$fd_client"
grep -Fq 'writeS184VpnNetworkEpochStatus' "$service"
grep -Fq 'product-state/s184-vpn-network-epoch.properties' "$service"
grep -Fq 'vpnDirectUnderlayEpoch' "$service"
grep -Fq 'vpnDirectUnderlayTransport' "$service"
grep -Fq 'vpnDirectUnderlayNetworkHandle' "$service"
grep -Fq 'vpnDirectUdp4NetworkHandle' "$service"
grep -Fq 'vpnDirectUdp6NetworkHandle' "$service"
grep -Fq 'vpnDirectTcp4NetworkHandle' "$service"
grep -Fq 'vpnDirectTcp6NetworkHandle' "$service"
grep -Fq 'network.getNetworkHandle()' "$service"
grep -Fq 'transportRank(NetworkCapabilities capabilities)' "$service"
grep -Fq 'transportName(NetworkCapabilities capabilities)' "$service"
grep -Fq 'NetworkCapabilities.TRANSPORT_WIFI' "$service"
grep -Fq 'setUnderlyingNetworks(new Network[]{underlay.network})' "$service"
grep -Fq 'bindDebugTrafficSocketToVpn(socket)' "$activity"
grep -Fq 'bindDebugDatagramSocketToVpn(socket)' "$activity"
grep -Fq 'uid=' "$activity"
grep -Fq 'tcp_echo_matched' "$activity"
grep -Fq 'udp_echo_matched' "$activity"

python3 - "$service" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


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


writer = body(service, "private void writeS184VpnNetworkEpochStatus(")
for token in (
        "network_context_snapshot=explicit_underlay_at_socket_creation",
        "set_underlying_networks=explicit_bound_underlay",
        "vpn_direct_underlay_epoch",
        "vpn_direct_underlay_transport",
        "vpn_direct_underlay_network_handle",
        "vpn_direct_udp4_network_handle",
        "vpn_direct_udp6_network_handle",
        "vpn_direct_tcp4_network_handle",
        "vpn_direct_tcp6_network_handle",
        "vpn_direct_underlay_handles_consistent",
        "vpn_direct_udp4_socket_attached",
        "vpn_direct_udp6_socket_attached",
        "vpn_direct_tcp4_socket_attached",
        "vpn_direct_tcp6_socket_attached",
        "vpn_tun_udp4_tun_origin_packets",
        "vpn_tun_udp6_tun_origin_packets",
        "vpn_tun_tcp4_tun_origin_packets",
        "vpn_tun_tcp6_tun_origin_packets",
        "vpn_direct_udp4_send_succeeded",
        "vpn_direct_udp4_transport_failed",
        "vpn_direct_udp6_send_succeeded",
        "vpn_direct_udp6_transport_failed",
        "vpn_direct_tcp4_connect_succeeded",
        "vpn_direct_tcp4_transport_failed",
        "vpn_direct_tcp6_connect_succeeded",
        "vpn_direct_tcp6_transport_failed"):
    if token not in writer:
        raise AssertionError("S184 writer missing " + token)

start = body(service, "private void startProductCoreRuntime(")
for token in (
        "resetVpnDirectUnderlaySnapshot()",
        "UnderlayNetwork directUnderlay = UnderlayNetwork.select(this)",
        "vpnDirectUnderlayEpoch = directUnderlay.networkHandle",
        "vpnDirectUnderlayTransport = directUnderlay.transport",
        "vpnDirectUnderlayNetworkHandle = directUnderlay.networkHandle",
        "vpnDirectUdp4NetworkHandle = direct.networkHandle",
        "vpnDirectUdp6NetworkHandle = udp6Direct.networkHandle",
        "vpnDirectTcp4NetworkHandle = tcp4Direct.networkHandle",
        "vpnDirectTcp6NetworkHandle = tcp6Direct.networkHandle"):
    if token not in start:
        raise AssertionError("S184 start path missing " + token)
if "vpnDirectUnderlayEpoch = generation" in start:
    raise AssertionError("S184 underlay epoch must not be Product Core generation")
for token in (
        "VpnDirectUdp4TransportSession.start(this, directUnderlay)",
        "VpnDirectUdp6TransportSession.start(this, directUnderlay)",
        "VpnDirectTcp4TransportSession.start(this, directUnderlay)",
        "VpnDirectTcp6TransportSession.start(this, directUnderlay)"):
    if token not in start:
        raise AssertionError("S184 start path does not share underlay snapshot: " + token)
if start.index("VpnDirectUdp4TransportSession.start") > start.index(
        "VpnDirectTcp4TransportSession.start"):
    raise AssertionError("S184 startup should preserve UDP4 before TCP4 ordering")
if start.index("VpnDirectUdp6TransportSession.start") > start.index(
        "VpnDirectTcp6TransportSession.start"):
    raise AssertionError("S184 startup should preserve UDP6 before TCP6 ordering")
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-184-vpn-network-epoch' \
  'installed_app_udp4_source true' \
  'installed_app_tcp4_source true' \
  'installed_app_udp6_source true' \
  'installed_app_tcp6_source true' \
  'uid_not_shell true' \
  '--ez debugUdpTraffic true' \
  '--ez debugTraffic true' \
  '--ez debugTrafficBindToVpn true' \
  'wifi.disable' \
  'wifi.enable' \
  'cmd wifi set-wifi-enabled disabled' \
  'cmd wifi set-wifi-enabled enabled' \
  'cmd wifi status' \
  'dumpsys connectivity' \
  'Wifi is disabled' \
  'Wifi is connected' \
  'old_tcp6_active_flow_observed true' \
  'old_tcp6_not_migrated true' \
  'fresh_epoch_after_wifi_restore true' \
  'new_flow_after_wifi_restore true' \
  'files/product-state/s184-vpn-network-epoch.properties' \
  'vpn_direct_underlay_epoch' \
  'vpn_direct_underlay_transport=wifi' \
  'vpn_direct_underlay_network_handle' \
  'vpn_direct_underlay_handles_consistent' \
  'underlay_handle_changed true' \
  'vpn_direct_tcp6_transport_failed' \
  'final_residue_clean true'; do
  grep -Fq -- "$token" "$device_runner"
done

if grep -Eq 'sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|2001:4860|2606:4700|dns.google|cloudflare' "$device_runner"; then
  echo "S184 runner uses a retired, shell-network, or public-network path" >&2
  exit 1
fi

python3 - "$device_runner" <<'PY'
import pathlib
import sys

runner = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
for needle in (
        "trap restore_wifi EXIT",
        "run_udp4_probe",
        "run_tcp4_probe",
        "run_udp6_probe",
        "run_tcp6_probe",
        "start_delayed_tcp6_echo_server",
        "wait_probe_nonce \"$TCP_PROBE_PATH\" \"$old_tcp6_nonce\"",
        "capture_connectivity initial",
        "capture_connectivity wifi_off",
        "capture_connectivity restored",
        "wifi_handle_from_connectivity",
        "compare_epoch"):
    if needle not in runner:
        raise AssertionError("S184 runner missing " + needle)
compare_start = runner.index("compare_epoch()")
compare_end = runner.index("\n}\n", compare_start)
compare_body = runner[compare_start:compare_end]
if "property_value generation" in compare_body:
    raise AssertionError("S184 runner must compare vpn_direct_underlay_epoch, not generation")
disable = runner.rindex('\ndisable_wifi\n')
enable = runner.rindex('\nenable_wifi\n')
if enable < disable:
    raise AssertionError("S184 runner can enable Wi-Fi before disable")
PY

echo "sakamoto-184 VPN network epoch contract: PASS"
