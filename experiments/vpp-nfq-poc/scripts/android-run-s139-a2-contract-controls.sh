#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-139 A2: registered refresh/unavailable/replay controls on Pixel.
# This is UID-contract evidence only; it never claims external forwarding.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
VPN_PACKAGE="${VPN_PACKAGE:-com.sakamoto.snort.vpnlite}"
APP_PACKAGE="${APP_PACKAGE:-com.android.chrome}"
RESULT_DIR="${RESULT_DIR:-$POC_DIR/results/s139-a2-contract-controls}"

CONTRACT_PATH="/data/user/0/$VPN_PACKAGE/files/logs/uid-attribution-contract.jsonl"
VPP_CLI_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-cli.log"
RESOLVER_PATH="/data/user/0/$VPN_PACKAGE/files/vpp/logs/vpp-owner-resolver.log"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RESULT_DIR/cell.log") 2>&1

cleanup() {
  adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez stop true >/dev/null 2>&1 || true
  sleep 1
  adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
  adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
  adb_su "cat '$CONTRACT_PATH' 2>/dev/null || true" | tr -d '\r' \
    >"$RESULT_DIR/uid-attribution-contract-final.jsonl" || true
}
trap cleanup EXIT

echo "# SAKAMOTO-139 A2 contract controls"
echo "adb_serial=$(adb_target_desc) vpn=$VPN_PACKAGE app=$APP_PACKAGE"
adb_cmd shell am force-stop "$VPN_PACKAGE" >/dev/null 2>&1 || true
adb_cmd shell am force-stop "$APP_PACKAGE" >/dev/null 2>&1 || true
adb_su "rm -f '$CONTRACT_PATH' '$VPP_CLI_PATH' '$RESOLVER_PATH'"

echo "## start owner resolver"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" \
  --ez start true \
  --es mode vpp-hev-owner-resolver \
  --es allowedPackage "$APP_PACKAGE" \
  --ei blockOwnerUid 99999 \
  --ez ownerCache true
sleep 6

echo "## baseline Chrome traffic"
adb_cmd shell am start -a android.intent.action.VIEW -p "$APP_PACKAGE" \
  -d "http://1.1.1.1/" >/dev/null
sleep 5

echo "## registered scope refreshes"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez uidContractRefreshApp true >/dev/null
sleep 1
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez uidContractRefreshNetwork true >/dev/null
sleep 1

echo "## provider unavailable then traffic"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez uidContractUnavailable true >/dev/null
sleep 1
adb_cmd shell am start -a android.intent.action.VIEW -p "$APP_PACKAGE" \
  -d "http://1.1.1.1/" >/dev/null
sleep 4

echo "## provider restore and fault replay"
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez uidContractUnavailable false >/dev/null
sleep 1
adb_cmd shell am start -n "$VPN_PACKAGE/.MainActivity" --ez uidContractReplay true >/dev/null
sleep 1

echo "## raw contract"
adb_su "cat '$CONTRACT_PATH' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/uid-attribution-contract.jsonl"
echo "## raw vpp/resolver"
adb_su "cat '$VPP_CLI_PATH' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/vpp-cli.log"
adb_su "cat '$RESOLVER_PATH' 2>/dev/null || true" | tr -d '\r' | tee "$RESULT_DIR/vpp-owner-resolver.log"
echo "RESULT contract-controls-observed"
