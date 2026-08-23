#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: real VPN-bound second-UID refresh/unavailable boundary.
# This is a narrow Android contract cell.  It does not claim external egress,
# reverse traffic, or complete lifecycle correctness.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
ALLOWED_PACKAGE="${ALLOWED_PACKAGE:-com.sakamoto.snort.androidruntime}"
TRIGGER_ACTIVITY="${TRIGGER_ACTIVITY:-com.sakamoto.snort.androidruntime/.DebugControlActivity}"
HOST="${HOST:-1.1.1.1}"
PORT="${PORT:-53}"
FIRST_SOURCE_PORT="${FIRST_SOURCE_PORT:-45625}"
UNAVAILABLE_SOURCE_PORT="${UNAVAILABLE_SOURCE_PORT:-45626}"
RECOVERED_SOURCE_PORT="${RECOVERED_SOURCE_PORT:-45627}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-99999}"
BIND_TO_VPN="${BIND_TO_VPN:-true}"
EXPECTED_ALLOWED_UID="${EXPECTED_ALLOWED_UID:-}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-second-uid-lifecycle-unavailable}"

VPP_CLI_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-cli.log"
RESOLVER_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-owner-resolver.log"
HEV_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-hev.log"
SHIM_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-shim.log"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
RUNTIME_PROBE_PATH="/data/user/0/$ALLOWED_PACKAGE/files/debug/udp-traffic-probe.properties"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

cleanup() {
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2 second UID lifecycle/unavailable"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE allowed_package=$ALLOWED_PACKAGE"
echo "target=$HOST:$PORT source_ports=$FIRST_SOURCE_PORT,$UNAVAILABLE_SOURCE_PORT,$RECOVERED_SOURCE_PORT"
echo "bind_to_vpn=$BIND_TO_VPN wrong_uid_drop_target=$BLOCK_OWNER_UID"
echo "external-forwarding=NON-CLAIM; this cell observes only the VPN/VPP contract boundary"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$ALLOWED_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
if [[ -z "$EXPECTED_ALLOWED_UID" ]]; then
  EXPECTED_ALLOWED_UID="$allowed_uid"
fi
echo "vpn_uid=$vpn_uid allowed_uid=$allowed_uid expected_allowed_uid=$EXPECTED_ALLOWED_UID"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null || true
adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$HEV_PATH' '$SHIM_PATH' '$CONTRACT_PATH' '$RUNTIME_PROBE_PATH'"

echo
echo "## start owner resolver with IPv6 disabled"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$ALLOWED_PACKAGE" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --ez ownerCache true \
  --ez enableIpv6 false
sleep "$START_WAIT"

capture_runtime() {
  local label="$1"
  adb_su "cat '$RUNTIME_PROBE_PATH' 2>/dev/null || true" \
    | tr -d '\r' | tee "$RESULT_DIR/runtime-$label.properties" >/dev/null
}

trigger_udp() {
  local source_port="$1"
  local label="$2"
  adb_cmd shell am start -n "$TRIGGER_ACTIVITY" \
    --ez debugUdpTraffic true \
    --es debugUdpHost "$HOST" \
    --ei debugUdpPort "$PORT" \
    --ei debugUdpSourcePort "$source_port" \
    --ei debugUdpTimeoutMillis 1200 \
    --ez debugTrafficBindToVpn "$BIND_TO_VPN"
  sleep "$PROBE_WAIT"
  echo "trigger=$label source_port=$source_port"
  capture_runtime "$label"
}

echo
echo "## baseline real second-UID UDP"
trigger_udp "$FIRST_SOURCE_PORT" baseline

echo
echo "## registered app/network scope refresh"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez uidContractRefreshApp true --ez uidContractRefreshNetwork true >/dev/null
sleep 1
trigger_udp "$FIRST_SOURCE_PORT" after-refresh

echo
echo "## provider unavailable with a new real tuple"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez uidContractUnavailable true >/dev/null
sleep 1
trigger_udp "$UNAVAILABLE_SOURCE_PORT" unavailable

echo
echo "## provider restore with a new real tuple"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez uidContractUnavailable false >/dev/null
sleep 1
trigger_udp "$RECOVERED_SOURCE_PORT" recovered

capture() {
  local name="$1"
  local path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/$name"
}

echo
echo "## VPP and contract raw evidence"
capture vpp-cli.log "$VPP_CLI_PATH"
capture vpp-owner-resolver.log "$RESOLVER_PATH"
capture uid-attribution-contract.jsonl "$CONTRACT_PATH"
capture vpp-hev.log "$HEV_PATH"
capture vpp-shim.log "$SHIM_PATH"
echo
echo "## service log (allowed-package provenance)"
adb_cmd shell logcat -d -t 500 -s SnortVpnLite:I SnortVpnService:I '*:S' 2>/dev/null \
  | tr -d '\r' | tee "$RESULT_DIR/snort-vpn-service.log" || true

vpp_cli="$(<"$RESULT_DIR/vpp-cli.log")"
resolver_log="$(<"$RESULT_DIR/vpp-owner-resolver.log")"
contract_log="$(<"$RESULT_DIR/uid-attribution-contract.jsonl")"
pass=1
check() {
  local label="$1"
  local pattern="$2"
  local text="$3"
  if grep -Eq "$pattern" <<<"$text"; then
    echo "PASS $label"
  else
    echo "INSUFFICIENT $label"
    pass=0
  fi
}

for label in baseline after-refresh recovered; do
  runtime_probe="$(<"$RESULT_DIR/runtime-$label.properties")"
  check "runtime-$label-uid" "^uid=$EXPECTED_ALLOWED_UID$" "$runtime_probe"
  check "runtime-$label-vpn-bind" '^bindResult=bound$' "$runtime_probe"
  check "runtime-$label-network-handle" '^bindNetworkHandle=[1-9][0-9]*$' "$runtime_probe"
  check "runtime-$label-udp-sent" '^result=udp_datagram_sent$' "$runtime_probe"
done
runtime_probe="$(<"$RESULT_DIR/runtime-unavailable.properties")"
check "runtime-unavailable-uid" "^uid=$EXPECTED_ALLOWED_UID$" "$runtime_probe"
check "runtime-unavailable-vpn-bind" '^bindResult=bound$' "$runtime_probe"
check "runtime-unavailable-udp-sent" '^result=udp_datagram_sent$' "$runtime_probe"

check "contract-app-refresh" '"outcome":"SCOPE_REFRESH".*app-refresh=intent' "$contract_log"
check "contract-network-refresh" '"outcome":"SCOPE_REFRESH".*network-refresh=intent' "$contract_log"
check "contract-unavailable" '"outcome":"LOOKUP_UNAVAILABLE"' "$contract_log"
check "contract-provider-restored" '"outcome":"LOOKUP_PROVIDER_AVAILABLE"' "$contract_log"
miss_count="$(grep -Ec '"outcome":"MISS_SUBMITTED"' <<<"$contract_log" || true)"
completion_count="$(grep -Ec '"outcome":"COMPLETION_ACCEPTED"' <<<"$contract_log" || true)"
hit_count="$(grep -Ec '"outcome":"CACHE_HIT"' <<<"$contract_log" || true)"
if (( miss_count >= 2 )); then echo "PASS contract-miss-count=$miss_count"; else echo "INSUFFICIENT contract-miss-count=$miss_count"; pass=0; fi
if (( completion_count >= 2 )); then echo "PASS contract-completion-count=$completion_count"; else echo "INSUFFICIENT contract-completion-count=$completion_count"; pass=0; fi
if (( hit_count >= 2 )); then echo "PASS contract-cache-hit-count=$hit_count"; else echo "INSUFFICIENT contract-cache-hit-count=$hit_count"; pass=0; fi

host_pattern="${HOST//./\.}"
check "resolver-baseline-miss" "resolver query=[0-9]+ proto=17 .*:${FIRST_SOURCE_PORT} -> ${host_pattern}:${PORT} uid=-1" "$resolver_log"
check "resolver-baseline-completion" "resolver query=[0-9]+ proto=17 .*:${FIRST_SOURCE_PORT} -> ${host_pattern}:${PORT} uid=${EXPECTED_ALLOWED_UID}" "$resolver_log"
check "resolver-unavailable-sentinel" "resolver query=[0-9]+ proto=17 .*:${UNAVAILABLE_SOURCE_PORT} -> ${host_pattern}:${PORT} uid=-1" "$resolver_log"
check "resolver-recovered-completion" "resolver query=[0-9]+ proto=17 .*:${RECOVERED_SOURCE_PORT} -> ${host_pattern}:${PORT} uid=${EXPECTED_ALLOWED_UID}" "$resolver_log"
check "owner-cache-final-uid" "owner-cache enabled 1 valid 1 .*uid ${EXPECTED_ALLOWED_UID}" "$vpp_cli"
check "post-policy-shim-tx" 'shim-tx [1-9]' "$vpp_cli"
check "allow-sentinel-drop-zero" "uid-block enabled 1 uid $BLOCK_OWNER_UID packets 0" "$vpp_cli"
check "allowed-package-provenance" "VPN allowed package=$ALLOWED_PACKAGE" \
  "$(<"$RESULT_DIR/snort-vpn-service.log")"

echo
echo "## cleanup"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null || true
sleep 2
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -z "$leftovers" ]]; then echo "PASS cleanup-no-vpp"; else echo "INSUFFICIENT cleanup-no-vpp"; printf '%s\n' "$leftovers"; pass=0; fi
tun0_leftover="$(adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r')"
if [[ -z "$tun0_leftover" ]]; then echo "PASS cleanup-no-tun0"; else echo "INSUFFICIENT cleanup-no-tun0"; printf '%s\n' "$tun0_leftover"; pass=0; fi

if (( pass == 1 )); then
  echo "RESULT PASS_NARROW second-uid-lifecycle-unavailable; external-forwarding=NON-CLAIM"
else
  echo "RESULT INSUFFICIENT second-uid-lifecycle-unavailable; external-forwarding=NON-CLAIM"
fi
exit 0
