#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: one controlled second-App UID IPv4 UDP cell.
# This runner proves only the VPN/VPP UID boundary.  A successful UDP send is
# a datagram submission observation; no external UDP reply or proxy egress is
# claimed.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
ALLOWED_PACKAGE="${ALLOWED_PACKAGE:-com.sakamoto.snort.androidruntime}"
TRIGGER_ACTIVITY="${TRIGGER_ACTIVITY:-com.sakamoto.snort.androidruntime/.DebugControlActivity}"
HOST="${HOST:-1.1.1.1}"
PORT="${PORT:-53}"
SOURCE_PORT="${SOURCE_PORT:-45624}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-99999}"
BIND_TO_VPN="${BIND_TO_VPN:-true}"
ENABLE_IPV6=false
EXPECTED_ALLOWED_UID="${EXPECTED_ALLOWED_UID:-}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-udp4-second-uid}"

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

echo "# SAKAMOTO-139 A2 udp4 second UID"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE"
echo "allowed_package=$ALLOWED_PACKAGE"
echo "trigger_activity=$TRIGGER_ACTIVITY"
echo "target=$HOST:$PORT source_port=$SOURCE_PORT"
echo "wrong_uid_drop_target=$BLOCK_OWNER_UID"
echo "bind_to_vpn=$BIND_TO_VPN enable_ipv6=$ENABLE_IPV6"
echo "expected_allowed_uid=$EXPECTED_ALLOWED_UID"
echo "correction=single-package allowedPackage; no comma/double-allow change required"
echo "udp-egress=NON-CLAIM; successful result means datagram sent only"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$ALLOWED_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
if [[ -z "$EXPECTED_ALLOWED_UID" ]]; then
  EXPECTED_ALLOWED_UID="$allowed_uid"
fi
echo "vpn_uid=$vpn_uid"
echo "allowed_uid=$allowed_uid"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null || true
adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$HEV_PATH' '$SHIM_PATH' '$CONTRACT_PATH' '$RUNTIME_PROBE_PATH'"

echo
echo "## start owner resolver with allowedPackage=$ALLOWED_PACKAGE and IPv6 disabled"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$ALLOWED_PACKAGE" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --ez ownerCache true \
  --ez enableIpv6 false
sleep "$START_WAIT"

echo
echo "## trigger androidruntime DebugControlActivity IPv4 UDP (twice for miss/completion/hit)"
for attempt in 1 2; do
  adb_cmd shell am start -n "$TRIGGER_ACTIVITY" \
    --ez debugUdpTraffic true \
    --es debugUdpHost "$HOST" \
    --ei debugUdpPort "$PORT" \
    --ei debugUdpSourcePort "$SOURCE_PORT" \
    --ei debugUdpTimeoutMillis 1200 \
    --ez debugTrafficBindToVpn "$BIND_TO_VPN"
  sleep "$PROBE_WAIT"
  echo "trigger_attempt=$attempt"
done

capture() {
  local name="$1"
  local path="$2"
  adb_su "cat '$path' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/$name"
}

echo
echo "## runtime UDP probe"
capture runtime-udp-traffic-probe.properties "$RUNTIME_PROBE_PATH"
echo
echo "## VPP CLI"
capture vpp-cli.log "$VPP_CLI_PATH"
echo
echo "## resolver"
capture vpp-owner-resolver.log "$RESOLVER_PATH"
echo
echo "## contract"
capture uid-attribution-contract.jsonl "$CONTRACT_PATH"
echo
echo "## HEV / shim"
capture vpp-hev.log "$HEV_PATH"
capture vpp-shim.log "$SHIM_PATH"
echo
echo "## service log (allowed-package provenance)"
adb_cmd shell logcat -d -t 400 -s SnortVpnLite:I SnortVpnService:I '*:S' 2>/dev/null \
  | tr -d '\r' | tee "$RESULT_DIR/snort-vpn-service.log" || true

vpp_cli="$(<"$RESULT_DIR/vpp-cli.log")"
resolver_log="$(<"$RESULT_DIR/vpp-owner-resolver.log")"
runtime_probe="$(<"$RESULT_DIR/runtime-udp-traffic-probe.properties")"
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

check "allowed-uid-12629" "^allowed_uid=$EXPECTED_ALLOWED_UID$" \
  "allowed_uid=$allowed_uid"
check "runtime-real-uid" "^uid=$EXPECTED_ALLOWED_UID$" "$runtime_probe"
check "runtime-vpn-bind-requested" '^bindToVpn=true$' "$runtime_probe"
check "runtime-vpn-bind-succeeded" '^bindResult=bound$' "$runtime_probe"
check "runtime-vpn-bind-network-handle" '^bindNetworkHandle=[1-9][0-9]*$' "$runtime_probe"
check "runtime-vpn-bind-error-empty" '^bindError=$' "$runtime_probe"
check "runtime-udp-datagram-sent" '^result=udp_datagram_sent$' "$runtime_probe"
check "runtime-udp-no-reply-claim" '^message=.*No external reply is claimed\.$' "$runtime_probe"
check "allowed-package-provenance" "VPN allowed package=$ALLOWED_PACKAGE" \
  "$(<"$RESULT_DIR/snort-vpn-service.log")"

host_pattern="${HOST//./\\.}"
check "ipv4-udp-tuple" \
  "last-tuple ip4 proto 17 [^ ]+:$SOURCE_PORT -> $host_pattern:$PORT" \
  "$vpp_cli"

resolver_miss_pattern="resolver query=[0-9]+ proto=17 .*:${SOURCE_PORT} -> ${host_pattern}:${PORT} uid=-1"
resolver_hit_pattern="resolver query=[0-9]+ proto=17 .*:${SOURCE_PORT} -> ${host_pattern}:${PORT} uid=${EXPECTED_ALLOWED_UID}"
check "resolver-ipv4-miss-uid" "$resolver_miss_pattern" "$resolver_log"
check "resolver-ipv4-completion-uid" "$resolver_hit_pattern" "$resolver_log"
miss_line="$(grep -nE "$resolver_miss_pattern" <<<"$resolver_log" \
  | head -n 1 | cut -d: -f1 || true)"
hit_line="$(grep -nE "$resolver_hit_pattern" <<<"$resolver_log" \
  | head -n 1 | cut -d: -f1 || true)"
if [[ -n "$miss_line" && -n "$hit_line" && "$miss_line" -lt "$hit_line" ]]; then
  echo "PASS resolver-ipv4-miss-before-completion"
else
  echo "INSUFFICIENT resolver-ipv4-miss-before-completion"
  pass=0
fi
check "resolver-last-uid" \
  "resolver enabled 1 fd 5 queries [1-9].*last-uid $EXPECTED_ALLOWED_UID" "$vpp_cli"
check "owner-cache-uid" \
  "owner-cache enabled 1 valid 1 .*hits [1-9].*stores [1-9].*uid $EXPECTED_ALLOWED_UID" \
  "$vpp_cli"
check "wrong-uid-drop-zero" \
  "uid-block enabled 1 uid $BLOCK_OWNER_UID packets 0" "$vpp_cli"
check "post-policy-shim-tx" "shim-tx [1-9]" "$vpp_cli"
check "contract-miss-retained" '"outcome":"MISS_SUBMITTED"' "$contract_log"
check "contract-completion-retained" '"outcome":"COMPLETION_ACCEPTED"' "$contract_log"
check "contract-cache-hit-retained" '"outcome":"CACHE_HIT"' "$contract_log"

echo
echo "## cleanup"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null || true
sleep 2
adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null || true
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -z "$leftovers" ]]; then
  echo "PASS cleanup-no-vpp"
else
  echo "INSUFFICIENT cleanup-no-vpp"
  printf '%s\n' "$leftovers"
  pass=0
fi
tun0_leftover="$(adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r')"
if [[ -z "$tun0_leftover" ]]; then
  echo "PASS cleanup-no-tun0"
else
  echo "INSUFFICIENT cleanup-no-tun0"
  printf '%s\n' "$tun0_leftover"
  pass=0
fi

if (( pass == 1 )); then
  echo "RESULT PASS_NARROW second-uid-udp4; external-forwarding=NON-CLAIM"
else
  echo "RESULT INSUFFICIENT second-uid-udp4; external-forwarding=NON-CLAIM"
fi
exit 0
