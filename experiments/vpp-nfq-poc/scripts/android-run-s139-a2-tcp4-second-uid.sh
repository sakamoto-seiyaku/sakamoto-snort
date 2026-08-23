#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: one controlled second-App UID IPv4 TCP cell.
# This is a throwaway evidence runner. It deliberately does not assert
# external SOCKS/HTTP forwarding; shim-tx is the VPP post-policy boundary.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"

VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
ALLOWED_PACKAGE="${ALLOWED_PACKAGE:-com.sakamoto.snort.androidruntime}"
TRIGGER_ACTIVITY="${TRIGGER_ACTIVITY:-com.sakamoto.snort.androidruntime/.DebugControlActivity}"
HOST="${HOST:-1.1.1.1}"
PORT="${PORT:-443}"
SOURCE_PORT="${SOURCE_PORT:-45621}"
BLOCK_OWNER_UID="${BLOCK_OWNER_UID:-99999}"
BIND_TO_VPN="${BIND_TO_VPN:-true}"
START_WAIT="${START_WAIT:-6}"
PROBE_WAIT="${PROBE_WAIT:-5}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-tcp4-second-uid}"

VPP_CLI_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-cli.log"
RESOLVER_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-owner-resolver.log"
HEV_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-hev.log"
SHIM_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-shim.log"
CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
RUNTIME_PROBE_PATH="/data/user/0/$ALLOWED_PACKAGE/files/debug/traffic-probe.properties"

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

echo "# SAKAMOTO-139 A2 tcp4 second UID"
echo "adb_serial=$(adb_target_desc)"
echo "vpn_package=$VPN_PACKAGE"
echo "allowed_package=$ALLOWED_PACKAGE"
echo "trigger_activity=$TRIGGER_ACTIVITY"
echo "target=$HOST:$PORT source_port=$SOURCE_PORT"
echo "wrong_uid_drop_target=$BLOCK_OWNER_UID"
echo "bind_to_vpn=$BIND_TO_VPN"
echo "correction=single-package allowedPackage; no comma/double-allow change required"

packages="$(adb_cmd shell cmd package list packages -U | tr -d '\r')"
vpn_uid="$(awk -F'uid:' -v pkg="package:$VPN_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
allowed_uid="$(awk -F'uid:' -v pkg="package:$ALLOWED_PACKAGE" 'index($0, pkg) == 1 { print $2; exit }' <<<"$packages")"
echo "vpn_uid=$vpn_uid"
echo "allowed_uid=$allowed_uid"

adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null || true
adb_cmd shell am force-stop "$ALLOWED_PACKAGE" >/dev/null || true
adb_su "rm -f '$VPP_CLI_PATH' '$RESOLVER_PATH' '$HEV_PATH' '$SHIM_PATH' '$CONTRACT_PATH' '$RUNTIME_PROBE_PATH'"

echo
echo "## start owner resolver with allowedPackage=$ALLOWED_PACKAGE"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$ALLOWED_PACKAGE" \
  --ei blockOwnerUid "$BLOCK_OWNER_UID" \
  --ez ownerCache true
sleep "$START_WAIT"

echo
echo "## trigger androidruntime DebugControlActivity TCP (twice for completion/cache)"
for attempt in 1 2; do
  adb_cmd shell am start -n "$TRIGGER_ACTIVITY" \
    --ez debugTraffic true \
    --es debugTrafficHost "$HOST" \
    --ei debugTrafficPort "$PORT" \
    --ei debugTrafficSourcePort "$SOURCE_PORT" \
    --ei debugTrafficTimeoutMillis 1200 \
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
echo "## runtime probe"
capture runtime-traffic-probe.properties "$RUNTIME_PROBE_PATH"
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
# RuntimeService emits under the SnortVpnLite tag. Keep the legacy tag as a
# compatibility capture so older builds remain diagnosable, but do not filter
# out the current service tag.
adb_cmd shell logcat -d -t 400 -s SnortVpnLite:I SnortVpnService:I '*:S' 2>/dev/null \
  | tr -d '\r' | tee "$RESULT_DIR/snort-vpn-service.log" || true

vpp_cli="$(<"$RESULT_DIR/vpp-cli.log")"
resolver_log="$(<"$RESULT_DIR/vpp-owner-resolver.log")"
runtime_probe="$(<"$RESULT_DIR/runtime-traffic-probe.properties")"
pass=1
check() {
  local label="$1"
  local pattern="$2"
  local text="$3"
  if grep -Eq "$pattern" <<<"$text"; then
    echo "PASS $label"
  else
    echo "FAIL $label"
    pass=0
  fi
}

check "runtime-real-uid" "^uid=$allowed_uid$" "$runtime_probe"
if [[ "$BIND_TO_VPN" == true ]]; then
  check "runtime-vpn-bind-requested" '^bindToVpn=true$' "$runtime_probe"
  check "runtime-vpn-bind-succeeded" '^bindResult=bound$' "$runtime_probe"
  check "runtime-vpn-bind-network-handle" '^bindNetworkHandle=[1-9][0-9]*$' "$runtime_probe"
  check "runtime-vpn-bind-error-empty" '^bindError=$' "$runtime_probe"
fi
check "allowed-package-provenance" "VPN allowed package=$ALLOWED_PACKAGE" "$(<"$RESULT_DIR/snort-vpn-service.log")"
check "ipv4-tcp-tuple" "last-tuple ip4 proto 6 .* -> $HOST:$PORT" "$vpp_cli"
check "resolver-uid" "resolver query=.* proto=6 .* -> $HOST:$PORT uid=$allowed_uid" "$resolver_log"
check "resolver-last-uid" "resolver enabled 1 fd 5 queries [1-9].*last-uid $allowed_uid" "$vpp_cli"
check "owner-cache-uid" "owner-cache enabled 1 valid 1 .*hits [1-9].*stores [1-9].*uid $allowed_uid" "$vpp_cli"
check "wrong-uid-drop-zero" "uid-block enabled 1 uid $BLOCK_OWNER_UID packets 0" "$vpp_cli"
check "post-policy-shim-tx" "shim-tx [1-9]" "$vpp_cli"

echo
echo "## cleanup"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null || true
sleep 2
adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null || true
leftovers="$(adb_su "ps -A 2>/dev/null | grep '[v]pp' || true" | tr -d '\r')"
if [[ -z "$leftovers" ]]; then
  echo "PASS cleanup-no-vpp"
else
  echo "FAIL cleanup-no-vpp"
  printf '%s\n' "$leftovers"
  pass=0
fi
tun0_leftover="$(adb_su "ip link show tun0 2>/dev/null || true" | tr -d '\r')"
if [[ -z "$tun0_leftover" ]]; then
  echo "PASS cleanup-no-tun0"
else
  echo "FAIL cleanup-no-tun0"
  printf '%s\n' "$tun0_leftover"
  pass=0
fi

if (( pass == 1 )); then
  echo "RESULT PASS narrow-second-uid-tcp4; external-forwarding=NON-CLAIM"
else
  echo "RESULT INSUFFICIENT or FAIL; see raw files under $RESULT_DIR"
fi
exit 0
