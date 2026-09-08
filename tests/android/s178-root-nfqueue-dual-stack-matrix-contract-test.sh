#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
api="$repo_root/src/product/vpp/product_core.api"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
root_adapter_header="$repo_root/src/product/vpp/product_root_nfqueue_adapter.h"
device_runner="$repo_root/tests/device/s178-root-nfqueue-dual-stack-matrix-product.sh"

test -f "$service"
test -f "$activity"
test -f "$native_status"
test -f "$jni"
test -f "$abi"
test -f "$api"
test -f "$plugin"
test -f "$root_adapter"
test -f "$root_adapter_header"
test -x "$device_runner"

grep -Fq 'PRODUCT_ROOT_NFQUEUE_INPUT_CHAIN = "SAKAMOTO_PRODUCT_S178_INPUT"' "$service"
grep -Fq 'S178_ROOT_NFQUEUE_MATRIX_STATUS' "$service"
grep -Fq 'writeBestEffortEvidenceFile(S178_ROOT_NFQUEUE_MATRIX_STATUS, text)' "$service"
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
grep -Fq 'rootNfqueueHookName(status.rootNfqueueLastHook)' "$service"

python3 - "$service" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


def method_body(source, signature):
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
    raise AssertionError("unclosed method: " + signature)


install = method_body(service, "private boolean installProductRootNfqueueHook(")
cleanup = method_body(service, "private boolean productRootNfqueueResidueClean(RuntimeProfile profile)")
status = method_body(service, "private void writeRootNfqueueStatus(")

for expected in (
        "iptables -w -t mangle -N \" + outputChain",
        "iptables -w -t mangle -N \" + inputChain",
        "ip6tables -w -t mangle -N \" + outputChain",
        "ip6tables -w -t mangle -N \" + inputChain",
        "iptables -w -t mangle -I OUTPUT -j \" + outputChain",
        "iptables -w -t mangle -I INPUT -j \" + inputChain",
        "ip6tables -w -t mangle -I OUTPUT -j \" + outputChain",
        "ip6tables -w -t mangle -I INPUT -j \" + inputChain",
        "--queue-balance \" + queue + \":\" + queueLast",
        "--queue-bypass"):
    if expected not in install:
        raise AssertionError("Root S178 hook install missing: " + expected)

if install.count(" -m owner --uid-owner ") != 2:
    raise AssertionError("Root S178 OUTPUT owner filter should appear once per family")
if "iptables -w -t mangle -A \" + inputChain\n                + \" -j NFQUEUE" not in install:
    raise AssertionError("IPv4 INPUT hook must not fake an owner match")
if "ip6tables -w -t mangle -A \" + inputChain\n                + \" -j NFQUEUE" not in install:
    raise AssertionError("IPv6 INPUT hook must not fake an owner match")

for expected in (
        "iptables -w -t mangle -D INPUT -j \" + inputChain",
        "iptables -w -t mangle -D OUTPUT -j \" + outputChain",
        "ip6tables -w -t mangle -D INPUT -j \" + inputChain",
        "ip6tables -w -t mangle -D OUTPUT -j \" + outputChain",
        "iptables -w -t mangle -S INPUT",
        "iptables -w -t mangle -S OUTPUT",
        "ip6tables -w -t mangle -S INPUT",
        "ip6tables -w -t mangle -S OUTPUT"):
    if expected not in cleanup:
        raise AssertionError("Root S178 cleanup missing: " + expected)

for expected in (
        "input_packets=",
        "output_packets=",
        "ipv4_packets=",
        "ipv6_packets=",
        "tcp_packets=",
        "udp_packets=",
        "uid_known_packets=",
        "uid_unknown_packets=",
        "last_hook_code=",
        "last_uid_known=",
        "last_uid="):
    if expected not in status:
        raise AssertionError("S178 status missing: " + expected)
PY

grep -Fq 'Root dual-stack INPUT/OUTPUT adapter' "$root_adapter"
grep -Fq 'NFQNL_CFG_CMD_PF_BIND, 0,' "$root_adapter"
grep -Fq 'AF_INET6' "$root_adapter"
grep -Fq 'packet->hook == NF_INET_LOCAL_OUT' "$root_adapter"
grep -Fq 'packet->hook == NF_INET_LOCAL_IN' "$root_adapter"
grep -Fq 'version == 4' "$root_adapter"
grep -Fq 'version == 6' "$root_adapter"
grep -Fq 'packet->payload[9]' "$root_adapter"
grep -Fq 'packet->payload[6]' "$root_adapter"
grep -Fq 'packet.hook == NF_INET_LOCAL_OUT && packet.uid_present' "$root_adapter"
grep -Fq 'hints.uid = packet.uid_present ? packet.uid : UINT32_MAX' "$root_adapter"
grep -Fq 'nm->input_packets++' "$root_adapter"
grep -Fq 'nm->output_packets++' "$root_adapter"
grep -Fq 'nm->ipv4_packets++' "$root_adapter"
grep -Fq 'nm->ipv6_packets++' "$root_adapter"
grep -Fq 'nm->tcp_packets++' "$root_adapter"
grep -Fq 'nm->udp_packets++' "$root_adapter"
grep -Fq 'nm->uid_known_packets++' "$root_adapter"
grep -Fq 'nm->uid_unknown_packets++' "$root_adapter"
grep -Fq 'nm->last_uid = packet.uid_present ? packet.uid : UINT32_MAX' "$root_adapter"

for symbol in \
  input_packets output_packets ipv4_packets ipv6_packets tcp_packets \
  udp_packets uid_known_packets uid_unknown_packets last_ip_family \
  last_protocol last_hook last_uid_known last_uid last_queue_id last_packet_id
do
  grep -Fq "root_nfqueue_${symbol}" "$api"
  grep -Fq "root_nfqueue_${symbol}" "$abi"
  grep -Fq "root_nfqueue_${symbol}" "$plugin"
  grep -Fq "root_nfqueue_${symbol}" "$jni"
done

grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'STATUS_VALUE_COUNT = 135' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 135' "$jni"
grep -Fq 'Long.parseLong(value)' "$native_status"
grep -Fq 'parsed > 0xffffffffL' "$native_status"

grep -Fq 'EXTRA_DEBUG_REFRESH = "debugRefresh"' "$activity"
grep -Fq 'refreshProductCatalog();' "$activity"
grep -Fq 'DEBUG_UDP_TRAFFIC_PROBE_RESULT_PATH' "$activity"
grep -Fq 'writeDebugUdpTrafficProbeResult' "$activity"
grep -Fq 'EXTRA_DEBUG_TRAFFIC_BIND_TO_VPN' "$activity"
grep -Fq 'EXTRA_DEBUG_LISTEN' "$activity"
grep -Fq 'EXTRA_DEBUG_LISTEN_HOST = "debugListenHost"' "$activity"
grep -Fq 'EXTRA_DEBUG_UDP_LISTEN' "$activity"
grep -Fq 'EXTRA_DEBUG_UDP_LISTEN_HOST = "debugUdpListenHost"' "$activity"
grep -Fq 'tcp_echo_matched' "$activity"
grep -Fq 'udp_echo_matched' "$activity"
grep -Fq 'uid=" + android.os.Process.myUid()' "$activity"

grep -Fq './dev/adb' "$device_runner"
grep -Fq '28201JEGR0XPAJ' "$device_runner"
grep -Fq 'SAKAMOTO-178-root-nfqueue-dual-stack-matrix' "$device_runner"
grep -Fq 'S178_CONTROLLED_LAN_HOST4' "$device_runner"
grep -Fq 'S178_CONTROLLED_LAN_HOST6' "$device_runner"
grep -Fq 'debugTrafficNonce' "$device_runner"
grep -Fq 'debugUdpNonce' "$device_runner"
grep -Fq 'debugTrafficBindToVpn false' "$device_runner"
grep -Fq 'debugListen true' "$device_runner"
grep -Fq 'debugListenHost "$listen_host"' "$device_runner"
grep -Fq 'debugUdpListen true' "$device_runner"
grep -Fq 'debugUdpListenHost "$listen_host"' "$device_runner"
grep -Fq 'files/product-state/s178-root-nfqueue-matrix.properties' "$device_runner"
grep -Fq 'files/debug/udp-traffic-probe.properties' "$device_runner"
grep -Fq 'files/debug/tcp-listener.properties' "$device_runner"
grep -Fq 'files/debug/udp-listener.properties' "$device_runner"
grep -Fq 'input_packets' "$device_runner"
grep -Fq 'output_packets' "$device_runner"
grep -Fq 'ipv4_packets' "$device_runner"
grep -Fq 'ipv6_packets' "$device_runner"
grep -Fq 'tcp_packets' "$device_runner"
grep -Fq 'udp_packets' "$device_runner"
grep -Fq 'uid_known_packets' "$device_runner"
grep -Fq 'uid_unknown_packets' "$device_runner"
grep -Fq 'restart_no_residue=true' "$device_runner"

echo "sakamoto-178 Root NFQUEUE dual-stack matrix contract: PASS"
