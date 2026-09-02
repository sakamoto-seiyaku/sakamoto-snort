#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
debug_activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
api="$repo_root/src/product/vpp/product_core.api"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
device_runner="$repo_root/tests/device/s178-root-nfqueue-matrix-product.sh"

test -f "$service"
test -f "$debug_activity"
test -f "$native_status"
test -f "$jni"
test -f "$abi"
test -f "$api"
test -f "$plugin"
test -f "$root_adapter"
test -x "$device_runner"

grep -Fq 'S178_ROOT_NFQUEUE_MATRIX_STATUS' "$service"
grep -Fq 'product-state/s178-root-nfqueue-matrix.properties' "$service"
grep -Fq 'hooks=INPUT,OUTPUT' "$service"
grep -Fq 'families=IPv4,IPv6' "$service"
grep -Fq 'input_packets=' "$service"
grep -Fq 'output_packets=' "$service"
grep -Fq 'ipv4_packets=' "$service"
grep -Fq 'ipv6_packets=' "$service"
grep -Fq 'tcp_packets=' "$service"
grep -Fq 'udp_packets=' "$service"
grep -Fq 'uid_known_packets=' "$service"
grep -Fq 'uid_unknown_packets=' "$service"
grep -Fq 'last_hook=' "$service"
grep -Fq 'last_uid_known=' "$service"
grep -Fq 'Root NFQUEUE INPUT/OUTPUT hooks could not be installed' "$service"
grep -Fq 'PRODUCT_ROOT_NFQUEUE_INPUT_CHAIN' "$service"
grep -Fq 'iptables -w -t mangle -I INPUT -j ' "$service"
grep -Fq 'iptables -w -t mangle -I OUTPUT -j ' "$service"
grep -Fq 'ip6tables -w -t mangle -I INPUT -j ' "$service"
grep -Fq 'ip6tables -w -t mangle -I OUTPUT -j ' "$service"
grep -Fq ' -m owner --uid-owner ' "$service"
grep -Fq ' -j NFQUEUE --queue-balance " + queue + ":" + queueLast' "$service"

grep -Fq 'NFQNL_CFG_CMD_PF_BIND, 0,' "$root_adapter"
grep -Fq 'AF_INET)' "$root_adapter"
grep -Fq 'AF_INET6)' "$root_adapter"
grep -Fq 'packet->hook == NF_INET_LOCAL_OUT' "$root_adapter"
grep -Fq 'packet->hook == NF_INET_LOCAL_IN' "$root_adapter"
grep -Fq 'packet->ip_family = 4' "$root_adapter"
grep -Fq 'packet->ip_family = 6' "$root_adapter"
grep -Fq 'packet.protocol == IPPROTO_TCP' "$root_adapter"
grep -Fq 'packet.protocol == IPPROTO_UDP' "$root_adapter"
grep -Fq 'nm->input_packets++' "$root_adapter"
grep -Fq 'nm->output_packets++' "$root_adapter"
grep -Fq 'nm->uid_known_packets++' "$root_adapter"
grep -Fq 'nm->uid_unknown_packets++' "$root_adapter"
grep -Fq "OUTPUT reaches this queue only through the supervisor's uid-owner rule" "$root_adapter"
grep -Fq 'packet.uid = nm->uid_owner' "$root_adapter"
grep -Fq 'hints.uid = packet.uid_present ? packet.uid : UINT32_MAX' "$root_adapter"

for field in \
  root_nfqueue_input_packets \
  root_nfqueue_output_packets \
  root_nfqueue_ipv4_packets \
  root_nfqueue_ipv6_packets \
  root_nfqueue_tcp_packets \
  root_nfqueue_udp_packets \
  root_nfqueue_uid_known_packets \
  root_nfqueue_uid_unknown_packets \
  root_nfqueue_last_ip_family \
  root_nfqueue_last_protocol \
  root_nfqueue_last_hook \
  root_nfqueue_last_uid_known \
  root_nfqueue_last_uid \
  root_nfqueue_last_queue_id \
  root_nfqueue_last_packet_id; do
  grep -Fq "$field" "$api"
  grep -Fq "$field" "$abi"
  grep -Fq "$field" "$plugin"
  grep -Fq "$field" "$jni"
done
grep -Fq 'STATUS_VALUE_COUNT = 136' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 136' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"

grep -Fq 'EXTRA_DEBUG_TRAFFIC_NONCE' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_UDP_TRAFFIC_NONCE' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_UDP_TRAFFIC_EXPECT_REPLY' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_LISTEN_NONCE' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_LISTEN_HOST = "debugListenHost"' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_UDP_LISTEN' "$debug_activity"
grep -Fq 'EXTRA_DEBUG_UDP_LISTEN_HOST = "debugUdpListenHost"' "$debug_activity"
grep -Fq 'DEBUG_TCP_LISTENER_RESULT_PATH' "$debug_activity"
grep -Fq 'DEBUG_UDP_LISTENER_RESULT_PATH' "$debug_activity"
grep -Fq 'tcp_echo_matched' "$debug_activity"
grep -Fq 'udp_echo_matched' "$debug_activity"
grep -Fq 'requestBytes=' "$debug_activity"
grep -Fq 'responseBytes=' "$debug_activity"
grep -Fq 'backend.queryService(this)' "$debug_activity"

for case_name in \
  ipv4_tcp_output \
  ipv4_udp_output \
  ipv6_tcp_output \
  ipv6_udp_output \
  ipv4_tcp_input \
  ipv4_udp_input \
  ipv6_tcp_input \
  ipv6_udp_input; do
  grep -Fq "$case_name" "$device_runner"
done
grep -Fq 'SAKAMOTO-178-root-nfqueue-matrix=PASS' "$device_runner"
grep -Fq 'tcp_echo_matched' "$device_runner"
grep -Fq 'udp_echo_matched' "$device_runner"
grep -Fq 'debugListenHost "$listen_host"' "$device_runner"
grep -Fq 'debugUdpListenHost "$listen_host"' "$device_runner"
grep -Fq 'output_packets' "$device_runner"
grep -Fq 'input_packets' "$device_runner"
grep -Fq 'uid_known_packets' "$device_runner"
grep -Fq 'product-status.fresh-restart.properties' "$device_runner"
grep -Fq './dev/adb' "$device_runner"

echo "sakamoto-178 Root NFQUEUE dual-stack matrix contract: PASS"
