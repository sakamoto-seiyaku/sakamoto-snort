#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-192 Root/VPN stateless L4 matrix acceptance.
#
# This runner is independent of the retired Snort control client.  The
# installed debug Activity is the only device-side command surface and the
# host TCP/UDP endpoints are the transport oracle.  A Product status writer
# publishes the small s192 status schema consumed below; transport/helper
# counters are supporting diagnostics only.
# Device Packet Direction is an independent matcher fact: app-origin traffic
# is OUTPUT (3) in both profile phases.  VPN TUN adapter profile_id=1 is
# provenance, not this direction; the status gate deliberately rejects a
# profile-id-to-direction substitution so a graph mapping defect is visible.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export ADB="${repo_root}/dev/adb"

readonly S192_SERIAL="28201JEGR0XPAJ"
readonly PACKAGE="${PACKAGE:-com.sakamoto.snort.androidruntime}"
readonly ACTIVITY="${ACTIVITY:-${PACKAGE}/.DebugControlActivity}"
readonly RESULTS_ROOT="${RESULTS_ROOT:-${repo_root}/build-output/s192-root-vpn-l4-matrix}"
readonly RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)}"
readonly RESULT_DIR="${RESULT_DIR:-${RESULTS_ROOT}/${RUN_ID}}"
readonly RUN_LOCK_DIR="${RESULTS_ROOT}/.s192-device-run.lock"

readonly STATE_PATH="files/runtime-state/snapshot.properties"
readonly MATRIX_STATUS_PATH="files/product-state/s192-root-vpn-l4-matrix.properties"
readonly PRODUCT_STATE_PATH="files/product-state/product.properties"
readonly PRODUCT_TRANSACTIONS_PATH="files/product-transactions/transactions.properties"
readonly POLICY_BUNDLE_PATH="files/product-policy/policy-bundle.properties"
readonly L4_STORE_PATH="files/product-policy/l4-intent.properties"
readonly TCP_PROBE_PATH="files/debug/traffic-probe.properties"
readonly UDP_PROBE_PATH="files/debug/udp-traffic-probe.properties"
readonly WAIT_ATTEMPTS="${S192_WAIT_ATTEMPTS:-120}"
readonly VPN_NETWORK_WAIT_ATTEMPTS="${S192_VPN_NETWORK_WAIT_ATTEMPTS:-45}"
readonly ADB_TIMEOUT_SECONDS="${S192_ADB_COMMAND_TIMEOUT_SECONDS:-20}"
readonly MATRIX_POLICY_CONTEXT="${S192_NETWORK_CONTEXT:-wifi}"

# Stable four-row table: two families x two protocols.  Orders are part of
# the policy identity and make the expected WinnerRank observable.
readonly MATRIX_CASES=(ipv4-tcp ipv4-udp ipv6-tcp ipv6-udp)
readonly MATRIX_PROFILES=(root vpn)

usage() {
  cat <<'EOF'
Usage:
  tests/device/s192-root-vpn-l4-matrix-product.sh --run

Required:
  --run

Optional:
  --serial 28201JEGR0XPAJ
  --host4 192.168.4.5
  --host6 <controlled-lan-ipv6>  (otherwise discovered at runtime)
  --base-port / S192_BASE_PORT       default 19200
  --timeout-ms / S192_TIMEOUT_MILLIS default 3000

The acceptance topology binds the controlled IPv4 endpoint 192.168.4.5 and a
runtime-discovered non-link-local IPv6 address on the same host.  The same
complete policy bundle is retained while Root and VPN are started in turn.
Root/VPN profile selection is a lifecycle concern; the policy network context
is deliberately identical in both phases (S192_NETWORK_CONTEXT, default
wifi) so UID/revision/hash/rule/reason identity can be compared directly.

Each profile runs eight output cells: IPv4/IPv6 x TCP/UDP, followed by one
non-matching-port PASS_NEXT probe per cell.  TCP rows are DROP and UDP rows
are ALLOW.  PASS requires host nonce echo for ALLOW/PASS_NEXT, no host echo
for DROP, complete s192 status evidence, bounded probes, same policy identity
across profiles/restarts, and clean stopped residue.

Physical execution is intentionally opt-in; --help and static contracts do
not contact a device.
EOF
}

serial="$S192_SERIAL"
run=0
controlled_host4="192.168.4.5"
controlled_host6="${S192_CONTROLLED_LAN_HOST6:-}"
base_port="${S192_BASE_PORT:-19200}"
timeout_ms="${S192_TIMEOUT_MILLIS:-3000}"
run_lock_acquired=0
server_pid=""
runtime_started=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --serial)
      serial="${2:-}"
      shift 2
      ;;
    --run)
      run=1
      shift
      ;;
    --host4)
      controlled_host4="${2:-}"
      shift 2
      ;;
    --host6)
      controlled_host6="${2:-}"
      shift 2
      ;;
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --timeout-ms)
      timeout_ms="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$serial" != "$S192_SERIAL" ]]; then
  echo "SAKAMOTO-192 only accepts controlled Pixel 6a serial $S192_SERIAL; got $serial" >&2
  exit 2
fi
if [[ "$run" != 1 ]]; then
  usage >&2
  exit 2
fi
if [[ "$controlled_host4" != "192.168.4.5" ]]; then
  echo "SAKAMOTO-192 controlled host4 must be exactly 192.168.4.5; got $controlled_host4" >&2
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]] \
    || (( base_port < 1024 || base_port > 64000 )); then
  echo "invalid base port: $base_port" >&2
  exit 2
fi
if (( base_port + 107 > 65535 )); then
  echo "base port leaves no room for matrix/no-match probes: $base_port" >&2
  exit 2
fi
if ! [[ "$timeout_ms" =~ ^[0-9]+$ ]] \
    || (( timeout_ms < 500 || timeout_ms > 30000 )); then
  echo "invalid timeout ms: $timeout_ms" >&2
  exit 2
fi
if [[ "$MATRIX_POLICY_CONTEXT" != "wifi" \
      && "$MATRIX_POLICY_CONTEXT" != "mobile" \
      && "$MATRIX_POLICY_CONTEXT" != "vpn" ]]; then
  echo "invalid S192 network context: $MATRIX_POLICY_CONTEXT" >&2
  exit 2
fi

mkdir -p "$RESULT_DIR"
summary="$RESULT_DIR/summary.properties"
: > "$summary"

kv() {
  printf '%s=%s\n' "$1" "$2" | tee -a "$summary"
}

fail_closed() {
  kv result FAIL
  kv failure "$1"
  echo "SAKAMOTO-192 FAIL: $1" >&2
  exit 1
}

adb_raw() {
  local rc=1
  local attempt
  for attempt in 1 2 3; do
    if timeout "$ADB_TIMEOUT_SECONDS" "$ADB" "$@"; then
      return 0
    fi
    rc=$?
    sleep 1
  done
  return "$rc"
}

adb_target() {
  adb_raw -s "$serial" "$@"
}

read_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" cat "$relative" 2>/dev/null \
    | tr -d '\r' || true
}

clear_app_file() {
  local relative="$1"
  adb_target shell run-as "$PACKAGE" rm -f "$relative" >/dev/null 2>&1 || true
}

property_value() {
  local file="$1"
  local key="$2"
  awk -F= -v key="$key" '$1 == key { print substr($0, length(key) + 2); exit }' "$file"
}

start_activity() {
  adb_target shell am start -W -f 0x10008000 -n "$ACTIVITY" "$@" \
    >> "$RESULT_DIR/am-start.log" 2>&1
}

acquire_run_lock() {
  mkdir -p "$RESULTS_ROOT"
  if mkdir "$RUN_LOCK_DIR" 2>/dev/null; then
    run_lock_acquired=1
    printf '%s\n' "$$" > "$RUN_LOCK_DIR/pid"
    kv device_run_lock_acquired true
    return 0
  fi
  fail_closed "another S192 device runner owns $RUN_LOCK_DIR"
}

cleanup() {
  local status=$?
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$runtime_started" == 1 ]]; then
    start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  fi
  if [[ "$run_lock_acquired" == 1 ]]; then
    rm -f "$RUN_LOCK_DIR/pid" >/dev/null 2>&1 || true
    rmdir "$RUN_LOCK_DIR" >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

adb_devices_contains_serial() {
  local output="$RESULT_DIR/adb-devices.txt"
  adb_raw devices > "$output" 2> "$RESULT_DIR/adb-devices.stderr" || true
  tr -d '\r' < "$output" \
    | awk 'NR > 1 && $1 == serial && $2 == "device" { found = 1 }
           END { exit found ? 0 : 1 }' serial="$serial"
}

installed_app_uid() {
  local output="$RESULT_DIR/package-list.txt"
  local dumpsys="$RESULT_DIR/package-dumpsys.txt"
  local uid=""
  adb_target shell cmd package list packages -U "$PACKAGE" > "$output" 2>/dev/null || true
  uid="$(tr -d '\r' < "$output" | awk -v package="package:${PACKAGE}" \
    '$1 == package { for (i = 1; i <= NF; i++) {
       if ($i ~ /^uid:/) { sub(/^uid:/, "", $i); print $i; exit }
     }}')"
  if [[ -z "$uid" ]]; then
    adb_target shell dumpsys package "$PACKAGE" > "$dumpsys" 2>/dev/null || true
    uid="$(tr -d '\r' < "$dumpsys" \
      | awk -F= '/userId=/{ gsub(/[^0-9].*/, "", $2); print $2; exit }')"
  fi
  if ! [[ "$uid" =~ ^[0-9]+$ ]] || (( uid <= 0 || uid >= 4294967295 )); then
    fail_closed "could not discover installed APK complete UID for $PACKAGE"
  fi
  printf '%s\n' "$uid"
}

validate_ipv6_literal() {
  local value="$1"
  python3 - "$value" <<'PY'
import ipaddress
import sys

try:
    address = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("controlled host6 must be an IPv6 literal")
if address.version != 6:
    raise SystemExit("controlled host6 must be an IPv6 literal")
if address.is_loopback or address.is_unspecified or address.is_link_local:
    raise SystemExit("controlled host6 must not be loopback/unspecified/link-local")
if getattr(address, "ipv4_mapped", None) is not None:
    raise SystemExit("controlled host6 must not be IPv4-mapped")
if address.is_global:
    raise SystemExit("controlled host6 must be a controlled LAN address")
PY
}

discover_host6() {
  local iface=""
  local candidates=""
  local candidate=""
  local route=""
  command -v ip >/dev/null 2>&1 \
    || fail_closed "runtime host6 discovery requires the host ip command"
  iface="$(ip -4 route get "$controlled_host4" 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }' \
    || true)"
  if [[ -n "$iface" ]]; then
    candidates="$(ip -6 -o addr show dev "$iface" scope global 2>/dev/null \
      | awk '{ print $4 }' | cut -d/ -f1 || true)"
  else
    candidates="$(ip -6 -o addr show scope global 2>/dev/null \
      | awk '{ print $4 }' | cut -d/ -f1 || true)"
  fi
  while IFS= read -r candidate; do
    [[ -n "$candidate" ]] || continue
    validate_ipv6_literal "$candidate" >/dev/null 2>&1 || continue
    route="$(adb_target shell ip -6 route get "$candidate" 2>/dev/null \
      | tr -d '\r' || true)"
    if [[ -n "$route" ]] \
        && ! grep -Eq '(^|[[:space:]])(unreachable|prohibit|blackhole)([[:space:]]|$)' \
          <<<"$route"; then
      controlled_host6="$candidate"
      kv host6_discovery runtime
      kv host6_interface "${iface:-unknown}"
      return 0
    fi
  done <<<"$candidates"
  fail_closed "could not discover a routed controlled LAN IPv6 host on the runtime host"
}

validate_and_discover_host6() {
  if [[ -n "$controlled_host6" ]]; then
    validate_ipv6_literal "$controlled_host6" \
      || fail_closed "invalid explicit controlled host6: $controlled_host6"
    kv host6_discovery explicit
  else
    discover_host6
  fi
}

wait_for_state() {
  local expected="$1"
  local expected_profile="${2:-}"
  local output="$RESULT_DIR/state-${expected}${expected_profile:+-${expected_profile}}.properties"
  local attempt
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fxq "state=${expected}" "$output" \
        && { [[ -z "$expected_profile" ]] || grep -Fxq "profile=${expected_profile}" "$output"; }; then
      if [[ "$expected" == "stopped" ]]; then
        if grep -Fxq 'mayBeActive=true' "$output" \
            || ! grep -Fxq 'mayBeActive=false' "$output"; then
          sleep 0.5
          continue
        fi
      fi
      return 0
    fi
    sleep 0.5
  done
  return 1
}

wait_for_profile_ready() {
  local profile="$1"
  local adapter="$2"
  local output="$RESULT_DIR/state-${profile}-running.properties"
  local attempt
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    read_app_file "$STATE_PATH" > "$output"
    if grep -Fxq 'state=running' "$output" \
        && grep -Fxq "profile=${profile}" "$output" \
        && grep -Fxq "adapterReadiness=${adapter}" "$output" \
        && grep -Fxq 'coreHealth=ok' "$output" \
        && grep -Fxq 'mayBeActive=true' "$output"; then
      kv "${profile}.runtime.generation" "$(property_value "$output" generation)"
      kv "${profile}.runtime.adapterReadiness" "$adapter"
      return 0
    fi
    if grep -Fxq 'errorCode=root_authorization_required' "$output"; then
      fail_closed "Root start requires KernelSU Superuser grant for $PACKAGE"
    fi
    if grep -Fxq 'errorCode=vpn_authorization_required' "$output"; then
      fail_closed "VPN start requires Android VpnService approval for $PACKAGE"
    fi
    if grep -Fxq 'errorCode=notification_permission_required' "$output"; then
      fail_closed "start requires Android notification permission"
    fi
    sleep 0.5
  done
  fail_closed "$profile Product Core did not reach running/$adapter"
}

capture_vpn_connectivity() {
  local label="$1"
  adb_target shell dumpsys connectivity \
    > "$RESULT_DIR/connectivity.${label}.txt" 2>&1 || true
}

vpn_network_present() {
  local file="$1"
  python3 - "$file" "$PACKAGE" "$app_uid" <<'PY'
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
package = sys.argv[2]
uid = sys.argv[3]
text = path.read_text(encoding="utf-8", errors="replace")

# Keep all checks inside one NetworkAgentInfo block.  Global greps could
# combine this app's VPN package with another network's tun0 or owner UID.
for block in re.split(r"(?=NetworkAgentInfo\{)", text):
    if f"VPN:{package}" not in block:
        continue
    if "InterfaceName: tun0" not in block:
        continue
    transports = re.search(r"Transports:\s*([A-Z0-9_|]+)", block)
    if transports is None or "VPN" not in transports.group(1).split("|"):
        continue
    if re.search(rf"\bOwnerUid:\s*{re.escape(uid)}\b", block) is None:
        continue
    handle = re.search(r"\bhandle\{([0-9]+)\}", block)
    print(f"networkHandle={handle.group(1) if handle else -1}")
    raise SystemExit(0)
raise SystemExit(1)
PY
}

wait_for_vpn_network() {
  local label="$1"
  local output="$RESULT_DIR/connectivity.${label}.txt"
  local attempts_dir="$RESULT_DIR/connectivity.${label}.attempts"
  local attempts_log="$RESULT_DIR/connectivity.${label}.attempts.tsv"
  local attempt
  local match
  mkdir -p "$attempts_dir"
  : > "$attempts_log"
  for ((attempt = 1; attempt <= VPN_NETWORK_WAIT_ATTEMPTS; attempt++)); do
    capture_vpn_connectivity "$label"
    cp "$output" \
      "$attempts_dir/attempt-$(printf '%03d' "$attempt").txt" 2>/dev/null || true
    if match="$(vpn_network_present "$output" 2>/dev/null)"; then
      printf '%s\t%s\tpresent\t%s\n' \
        "$attempt" "$(date +%s)" "$match" >> "$attempts_log"
      kv "${label}.vpn_network_present" true
      kv "${label}.vpn_network_attempt" "$attempt"
      kv "${label}.vpn_network_handle" "${match#networkHandle=}"
      return 0
    fi
    printf '%s\t%s\tabsent\n' "$attempt" "$(date +%s)" >> "$attempts_log"
    sleep 1
  done
  kv "${label}.vpn_network_present" false
  fail_closed "$label did not show app-owned TRANSPORT_VPN/tun0 network for UID $app_uid"
}

stop_profile() {
  local profile="$1"
  local label="$2"
  local snapshot="$RESULT_DIR/${label}.state-stopped.properties"
  local status="$RESULT_DIR/${label}.matrix-status.properties"
  start_activity --ez runtimeStop true >/dev/null 2>&1 || true
  wait_for_state stopped "$profile" \
    || fail_closed "${profile} Product Core did not stop cleanly (${label})"
  read_app_file "$STATE_PATH" > "$snapshot"
  if ! grep -Fxq 'mayBeActive=false' "$snapshot"; then
    fail_closed "${profile} stopped state did not report mayBeActive=false (${label})"
  fi
  for attempt in $(seq 1 "$WAIT_ATTEMPTS"); do
    read_app_file "$MATRIX_STATUS_PATH" > "$status"
    if grep -Fxq "profile=${profile}" "$status" \
        && grep -Fxq 'stage=stopped' "$status" \
        && grep -Fxq 'residue_clean=true' "$status"; then
      runtime_started=0
      kv "${label}_residue_clean" true
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${profile} stopped status did not prove residue_clean (${label})"
}

clear_product_policy_files() {
  clear_app_file "$PRODUCT_STATE_PATH"
  clear_app_file "$PRODUCT_TRANSACTIONS_PATH"
  clear_app_file "$POLICY_BUNDLE_PATH"
  clear_app_file "$L4_STORE_PATH"
  clear_app_file "$MATRIX_STATUS_PATH"
  clear_app_file "$TCP_PROBE_PATH"
  clear_app_file "$UDP_PROBE_PATH"
}

# RuntimeService stop is delivered through a headless Activity.  Force-stop
# and settle the control process before the first profile start so a delayed
# stop intent cannot terminate the new Product Core owner.
cold_start_control_activity() {
  adb_target shell am force-stop "$PACKAGE" >/dev/null 2>&1 || true
  sleep 2
}

case_metadata() {
  local case_id="$1"
  case "$case_id" in
    ipv4-tcp)
      CASE_INDEX=0
      CASE_FAMILY=4
      CASE_FAMILY_NAME=ipv4
      CASE_PROTOCOL=6
      CASE_PROTOCOL_NAME=tcp
      CASE_ACTION=drop
      CASE_DESTINATION_CIDR="${controlled_host4}/32"
      CASE_HOST="$controlled_host4"
      ;;
    ipv4-udp)
      CASE_INDEX=1
      CASE_FAMILY=4
      CASE_FAMILY_NAME=ipv4
      CASE_PROTOCOL=17
      CASE_PROTOCOL_NAME=udp
      CASE_ACTION=allow
      CASE_DESTINATION_CIDR="${controlled_host4}/32"
      CASE_HOST="$controlled_host4"
      ;;
    ipv6-tcp)
      CASE_INDEX=2
      CASE_FAMILY=6
      CASE_FAMILY_NAME=ipv6
      CASE_PROTOCOL=6
      CASE_PROTOCOL_NAME=tcp
      CASE_ACTION=drop
      CASE_DESTINATION_CIDR="${controlled_host6}/128"
      CASE_HOST="$controlled_host6"
      ;;
    ipv6-udp)
      CASE_INDEX=3
      CASE_FAMILY=6
      CASE_FAMILY_NAME=ipv6
      CASE_PROTOCOL=17
      CASE_PROTOCOL_NAME=udp
      CASE_ACTION=allow
      CASE_DESTINATION_CIDR="${controlled_host6}/128"
      CASE_HOST="$controlled_host6"
      ;;
    *)
      fail_closed "unknown S192 matrix case: $case_id"
      ;;
  esac
  CASE_PORT=$((base_port + CASE_INDEX))
  CASE_NO_MATCH_PORT=$((base_port + 100 + CASE_INDEX))
}

wait_for_authoring_count() {
  local expected="$1"
  local bundle="$RESULT_DIR/authoring-bundle.poll"
  local attempt
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    read_app_file "$POLICY_BUNDLE_PATH" > "$bundle"
    if grep -Fxq "l4RuleCount=${expected}" "$bundle" \
        && (grep -Fxq 'defaultPass=1' "$bundle" \
            || grep -Fxq 'defaultPass=true' "$bundle"); then
      return 0
    fi
    sleep 0.5
  done
  fail_closed "authoring policy did not publish L4 count ${expected}"
}

apply_matrix_rules() {
  local subject="$1"
  local index
  local case_id
  local source_cidr
  for index in "${!MATRIX_CASES[@]}"; do
    case_id="${MATRIX_CASES[$index]}"
    case_metadata "$case_id"
    source_cidr='0.0.0.0/0'
    if [[ "$CASE_FAMILY" == 6 ]]; then
      source_cidr='::/0'
    fi
    start_activity \
      --es debugSetL4RuleSubject "$subject" \
      --es debugSetL4RuleFamily "$CASE_FAMILY_NAME" \
      --es debugSetL4RuleSourceCidr "$source_cidr" \
      --es debugSetL4RuleDestinationCidr "$CASE_DESTINATION_CIDR" \
      --ei debugSetL4RuleSourcePortFirst 0 \
      --ei debugSetL4RuleSourcePortLast 65535 \
      --ei debugSetL4RuleDestinationPortFirst "$CASE_PORT" \
      --ei debugSetL4RuleDestinationPortLast "$CASE_PORT" \
      --ei debugSetL4RuleIpProtocol "$CASE_PROTOCOL" \
      --es debugSetL4RuleDirection output \
      --es debugSetL4RuleNetworkContext "$MATRIX_POLICY_CONTEXT" \
      --es debugSetL4RuleAction "$CASE_ACTION" \
      --ei debugSetL4RulePriority 10 \
      --ei debugSetL4RuleOrder "$CASE_INDEX"
    wait_for_authoring_count "$((index + 1))"
    kv "root_policy_rule_${CASE_INDEX}" "$CASE_FAMILY_NAME/$CASE_PROTOCOL_NAME"
  done
}

capture_bundle_identity() {
  local label="$1"
  local output="$RESULT_DIR/${label}.policy-bundle.properties"
  local identity="$RESULT_DIR/${label}.policy-identity.properties"
  read_app_file "$POLICY_BUNDLE_PATH" > "$output"
  python3 - "$output" "$app_uid" "$controlled_host4" "$controlled_host6" \
    "$base_port" "$MATRIX_POLICY_CONTEXT" > "$identity" <<'PY'
import ipaddress
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
uid = sys.argv[2]
host4 = sys.argv[3]
host6 = sys.argv[4]
base_port = int(sys.argv[5])
context = sys.argv[6]
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

def need(key, expected=None):
    actual = props.get(key, "")
    if expected is not None and actual != expected:
        raise SystemExit(f"{key}={actual!r}, expected {expected!r}")
    if expected is None and actual == "":
        raise SystemExit(f"{key} is empty")
    return actual

need("schema", "sakamoto-policy-bundle/v1")
need("abiVersion", "1")
need("structSize", "15496")
revision = int(need("revision"))
if revision <= 0:
    raise SystemExit("bundle revision is not positive")
snapshot_hash = int(need("snapshotHash"))
if snapshot_hash <= 0:
    raise SystemExit("bundle snapshotHash is not positive")
identity = need("snapshotIdentity")
need("gateEntryCount", "0")
need("l4RuleCount", "4")
if props.get("defaultPass") not in ("1", "true"):
    raise SystemExit(f"defaultPass={props.get('defaultPass')!r}, expected 1/true")

expected = (
    (4, 6, 0, "drop", host4, 32),
    (4, 17, 1, "allow", host4, 32),
    (6, 6, 2, "drop", host6, 128),
    (6, 17, 3, "allow", host6, 128),
)
for index, (family, protocol, order, action, host, prefix) in enumerate(expected):
    prefix_name = f"l4.{index}."
    need(prefix_name + "subjectUid", uid)
    need(prefix_name + "networkContext", {"wifi": "1", "mobile": "2", "vpn": "3"}[context])
    need(prefix_name + "ifindex", "4294967295")
    need(prefix_name + "ruleKind", "2")
    need(prefix_name + "ipFamily", str(family))
    need(prefix_name + "ipProtocol", str(protocol))
    need(prefix_name + "direction", "3")
    need(prefix_name + "action", "2" if action == "drop" else "1")
    need(prefix_name + "enabled", "1")
    need(prefix_name + "sourcePrefixLen", "0")
    need(prefix_name + "destinationPrefixLen", str(prefix))
    need(prefix_name + "sourcePortFirst", "0")
    need(prefix_name + "sourcePortLast", "65535")
    need(prefix_name + "destinationPortFirst", str(base_port + index))
    need(prefix_name + "destinationPortLast", str(base_port + index))
    need(prefix_name + "priority", "10")
    need(prefix_name + "order", str(order))
    reason_id = int(need(prefix_name + "reasonId"))
    if reason_id <= 0:
        raise SystemExit(f"{prefix_name}reasonId is not positive")
    rule_id = int(need(prefix_name + "ruleId"))
    if rule_id <= 0:
        raise SystemExit(f"{prefix_name}ruleId is not positive")
    if family == 4:
        source_address = "00" * 16
        destination_address = ipaddress.ip_address(host).packed.hex() + ("00" * 12)
    else:
        source_address = "00" * 16
        destination_address = ipaddress.ip_address(host).packed.hex()
    need(prefix_name + "sourceAddress", source_address)
    need(prefix_name + "destinationAddress", destination_address)
    print(f"rule_id_{index}={rule_id}")
    print(f"reason_id_{index}={reason_id}")

print(f"revision={revision}")
print(f"snapshot_hash={snapshot_hash}")
print(f"snapshot_identity={identity}")
PY
  bundle_revision="$(property_value "$identity" revision)"
  bundle_snapshot_hash="$(property_value "$identity" snapshot_hash)"
  bundle_snapshot_identity="$(property_value "$identity" snapshot_identity)"
  [[ "$bundle_revision" =~ ^[0-9]+$ ]] \
    || fail_closed "bundle revision identity is missing"
  [[ "$bundle_snapshot_hash" =~ ^[0-9]+$ ]] \
    || fail_closed "bundle hash identity is missing"
  [[ -n "$bundle_snapshot_identity" ]] \
    || fail_closed "bundle snapshot identity is missing"
  kv "${label}_policy_revision" "$bundle_revision"
  kv "${label}_policy_snapshot_hash" "$bundle_snapshot_hash"
  kv "${label}_policy_snapshot_identity" "$bundle_snapshot_identity"
}

wait_for_host_ready() {
  local file="$1"
  local attempt
  for ((attempt = 1; attempt <= 50; attempt++)); do
    [[ -f "$file" ]] && return 0
    sleep 0.1
  done
  return 1
}

host_tcp_echo_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local ready_file="$5"
  local result_file="$6"
  python3 - "$family" "$host" "$port" "$nonce" "$ready_file" "$result_file" <<'PY'
import socket
import sys
from pathlib import Path

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
ready_file = Path(sys.argv[5])
result_file = Path(sys.argv[6])
result = "tcp_echo_unseen"
remote = ""
request_bytes = 0
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(1)
        server.settimeout(5.0)
        ready_file.write_text("ready=true\n", encoding="utf-8")
        try:
            conn, address = server.accept()
        except socket.timeout:
            conn = None
            address = ""
        if conn is not None:
            remote = str(address)
            with conn:
                conn.settimeout(2.0)
                data = bytearray()
                while len(data) < len(nonce):
                    try:
                        chunk = conn.recv(len(nonce) - len(data))
                    except socket.timeout:
                        break
                    if not chunk:
                        break
                    data.extend(chunk)
                request_bytes = len(data)
                if data:
                    conn.sendall(data)
                    response_bytes = len(data)
                if bytes(data) == nonce:
                    result = "tcp_echo_matched"
                elif data:
                    result = "tcp_echo_mismatch"
except Exception as error:
    result = "tcp_echo_failed:" + error.__class__.__name__ + ":" + str(error).replace("\n", "_")
result_file.write_text(
    f"host={host}\nport={port}\nnonce={nonce.decode()}\nresult={result}\n"
    f"remote={remote}\nrequestBytes={request_bytes}\nresponseBytes={response_bytes}\n",
    encoding="utf-8")
PY
}

host_udp_echo_once() {
  local family="$1"
  local host="$2"
  local port="$3"
  local nonce="$4"
  local ready_file="$5"
  local result_file="$6"
  python3 - "$family" "$host" "$port" "$nonce" "$ready_file" "$result_file" <<'PY'
import socket
import sys
from pathlib import Path

family = socket.AF_INET6 if sys.argv[1] == "6" else socket.AF_INET
host = sys.argv[2]
port = int(sys.argv[3])
nonce = sys.argv[4].encode()
ready_file = Path(sys.argv[5])
result_file = Path(sys.argv[6])
result = "udp_echo_unseen"
remote = ""
request_bytes = 0
response_bytes = 0
try:
    with socket.socket(family, socket.SOCK_DGRAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.settimeout(5.0)
        ready_file.write_text("ready=true\n", encoding="utf-8")
        try:
            data, address = server.recvfrom(4096)
        except socket.timeout:
            data, address = b"", ""
        remote = str(address)
        request_bytes = len(data)
        if data:
            server.sendto(data, address)
            response_bytes = len(data)
        if data == nonce:
            result = "udp_echo_matched"
        elif data:
            result = "udp_echo_mismatch"
except Exception as error:
    result = "udp_echo_failed:" + error.__class__.__name__ + ":" + str(error).replace("\n", "_")
result_file.write_text(
    f"host={host}\nport={port}\nnonce={nonce.decode()}\nresult={result}\n"
    f"remote={remote}\nrequestBytes={request_bytes}\nresponseBytes={response_bytes}\n",
    encoding="utf-8")
PY
}

wait_for_probe_result() {
  local path="$1"
  local expected_uid="$2"
  local expected_nonce="$3"
  local mode="$4"
  local output="$5"
  local bind_to_vpn="${6:-false}"
  local attempt
  local evidence
  local result
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    evidence="$(read_app_file "$path")"
    printf '%s\n' "$evidence" > "$output"
    if grep -Fxq "nonce=${expected_nonce}" <<<"$evidence" \
        && grep -Fxq "uid=${expected_uid}" <<<"$evidence"; then
      if [[ "$bind_to_vpn" == true ]]; then
        if grep -Fxq 'bindResult=vpn_network_not_found' <<<"$evidence"; then
          return 2
        fi
        if ! grep -Fxq 'bindResult=bound' <<<"$evidence"; then
          sleep 0.5
          continue
        fi
      fi
      result="$(awk -F= '$1 == "result" { print substr($0, 8); exit }' <<<"$evidence")"
      if [[ "$mode" == "allow" && "$path" == "$TCP_PROBE_PATH" \
            && "$result" == "tcp_echo_matched" ]]; then
        return 0
      fi
      if [[ "$mode" == "allow" && "$path" == "$UDP_PROBE_PATH" \
            && "$result" == "udp_echo_matched" ]]; then
        return 0
      fi
      if [[ "$mode" == "drop" && "$path" == "$TCP_PROBE_PATH" \
            && "$result" != "tcp_echo_matched" \
            && "$result" != "tcp_echo_mismatch" \
            && -n "$result" ]]; then
        return 0
      fi
      if [[ "$mode" == "drop" && "$path" == "$UDP_PROBE_PATH" \
            && "$result" != "udp_echo_matched" \
            && "$result" != "udp_echo_mismatch" \
            && -n "$result" ]]; then
        return 0
      fi
    fi
    sleep 0.5
  done
  return 1
}

validate_host_result() {
  local file="$1"
  local protocol="$2"
  local mode="$3"
  [[ -f "$file" ]] || fail_closed "host $protocol echo result is missing: $file"
  if [[ "$mode" == "allow" ]]; then
    grep -Fxq "result=${protocol}_echo_matched" "$file" \
      || fail_closed "host $protocol ALLOW/PASS_NEXT nonce did not echo"
  elif grep -Fxq "result=${protocol}_echo_matched" "$file"; then
    fail_closed "host observed an echo for a DROP policy"
  fi
}

validate_matrix_status() {
  local file="$1"
  local profile="$2"
  local expected_case="$3"
  local expected_evaluation="$4"
  local expected_action="$5"
  local expected_rule_id="$6"
  local expected_reason_id="$7"
  local expected_rank="$8"
  python3 - "$file" "$profile" "$expected_case" "$expected_evaluation" \
    "$expected_action" "$expected_rule_id" "$expected_reason_id" "$expected_rank" \
    "$app_uid" "$bundle_revision" "$bundle_snapshot_hash" \
    "$bundle_snapshot_identity" "$MATRIX_POLICY_CONTEXT" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
profile = sys.argv[2]
expected_case = sys.argv[3]
expected_evaluation = sys.argv[4]
expected_action = sys.argv[5]
expected_rule_id = sys.argv[6]
expected_reason_id = sys.argv[7]
expected_rank = sys.argv[8]
expected_uid = sys.argv[9]
expected_revision = sys.argv[10]
expected_hash = sys.argv[11]
expected_identity = sys.argv[12]
expected_context = {"wifi": "1", "mobile": "2", "vpn": "3"}[sys.argv[13]]
props = {}
for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        props[key] = value

def need(key, expected=None):
    actual = props.get(key, "")
    if expected is not None and actual != expected:
        raise SystemExit(f"{key}={actual!r}, expected {expected!r}")
    if expected is None and actual == "":
        raise SystemExit(f"{key} is empty")
    return actual

need("schema", "s192-root-vpn-l4-matrix/v1")
need("profile", profile)
need("stage", "probe")
need("policy_case", expected_case)
need("policy_uid", expected_uid)
need("policy_uid_complete", "true")
need("policy_revision", expected_revision)
need("policy_snapshot_hash", expected_hash)
need("policy_snapshot_identity", expected_identity)
need("policy_network_context", expected_context)
need("policy_ifindex", "4294967295")
need("policy_direction", "3")
need("policy_ports_available", "true")
need("policy_evaluation", expected_evaluation)
need("policy_action", expected_action)
need("policy_rule_id", expected_rule_id)
need("policy_reason_id", expected_reason_id)
need("policy_winner_rank", expected_rank)
need("policy_candidate_count", "4")
probe_count = int(need("policy_probe_count"))
probe_limit = int(need("policy_probe_limit"))
subject_probe_count = int(need("policy_subject_probe_count"))
if probe_limit <= 0 or probe_limit > 128:
    raise SystemExit(f"policy_probe_limit={probe_limit!r} is outside the bounded limit")
if probe_count < 0 or probe_count > probe_limit:
    raise SystemExit(f"policy_probe_count={probe_count!r} exceeds probe limit")
if subject_probe_count < 0 or subject_probe_count > 16:
    raise SystemExit(f"policy_subject_probe_count={subject_probe_count!r} is unbounded")
if expected_evaluation == "match":
    need("policy_no_match_reason", "none")
    need("policy_verdict", "drop" if expected_action == "drop" else "pass_next")
else:
    need("policy_no_match_reason", "no_rule")
    need("policy_verdict", "pass_next")
    need("policy_winner_rank", "0")
print(f"policy_uid={props['policy_uid']}")
print(f"policy_revision={props['policy_revision']}")
print(f"policy_snapshot_hash={props['policy_snapshot_hash']}")
print(f"policy_snapshot_identity={props['policy_snapshot_identity']}")
print(f"policy_rule_id={props['policy_rule_id']}")
print(f"policy_reason_id={props['policy_reason_id']}")
print(f"policy_winner_rank={props['policy_winner_rank']}")
print(f"policy_probe_count={probe_count}")
print(f"policy_probe_limit={probe_limit}")
PY
}

capture_matrix_status() {
  local label="$1"
  local profile="$2"
  local case_id="$3"
  local evaluation="$4"
  local action="$5"
  local rule_id="$6"
  local reason_id="$7"
  local rank="$8"
  local output="$RESULT_DIR/${label}.matrix-status.properties"
  local values="$RESULT_DIR/${label}.matrix-status.values"
  local attempt
  start_activity --ez debugRefresh true
  for ((attempt = 1; attempt <= WAIT_ATTEMPTS; attempt++)); do
    read_app_file "$MATRIX_STATUS_PATH" > "$output"
    if validate_matrix_status "$output" "$profile" "$case_id" "$evaluation" \
        "$action" "$rule_id" "$reason_id" "$rank" > "$values" 2> \
        "$RESULT_DIR/${label}.matrix-status.validation.stderr"; then
      while IFS= read -r line; do
        kv "${label}.${line%%=*}" "${line#*=}"
      done < "$values"
      return 0
    fi
    sleep 0.5
  done
  fail_closed "${label} did not publish valid s192 matrix status"
}

run_tcp_probe() {
  local profile="$1"
  local bind_to_vpn="$2"
  local case_id="$3"
  local label="$4"
  local port="$5"
  local host="$6"
  local mode="$7"
  local evaluation="$8"
  local rule_id="$9"
  local reason_id="${10}"
  local rank="${11}"
  local nonce="s192-${profile}-${case_id}-${label}-${RUN_ID}"
  local ready_file="$RESULT_DIR/host-${label}.ready"
  local host_file="$RESULT_DIR/host-${label}.properties"
  local probe_file="$RESULT_DIR/${label}.traffic-probe.properties"
  local status_action="$CASE_ACTION"
  local probe_rc=1
  local probe_relaunches=0
  while :; do
    rm -f "$ready_file" "$host_file"
    clear_app_file "$TCP_PROBE_PATH"
    host_tcp_echo_once "$CASE_FAMILY" "$host" "$port" "$nonce" \
      "$ready_file" "$host_file" &
    server_pid=$!
    wait_for_host_ready "$ready_file" \
      || fail_closed "host TCP endpoint did not become ready (${label})"
    start_activity --ez debugTraffic true \
      --es debugTrafficHost "$host" \
      --ei debugTrafficPort "$port" \
      --es debugTrafficNonce "$nonce" \
      --ei debugTrafficTimeoutMillis "$timeout_ms" \
      --ez debugTrafficBindToVpn "$bind_to_vpn"
    if wait_for_probe_result "$TCP_PROBE_PATH" "$app_uid" "$nonce" "$mode" \
        "$probe_file" "$bind_to_vpn"; then
      probe_rc=0
    else
      probe_rc=$?
    fi
    if (( probe_rc == 0 )); then
      wait "$server_pid" || true
      server_pid=""
      break
    fi
    if [[ "$bind_to_vpn" == true && "$probe_rc" == 2 \
        && "$probe_relaunches" == 0 ]]; then
      probe_relaunches=1
      cp "$probe_file" \
        "$RESULT_DIR/${label}.bind-retry-1.traffic-probe.properties" \
        2>/dev/null || true
      cp "$host_file" \
        "$RESULT_DIR/${label}.bind-retry-1.host.properties" \
        2>/dev/null || true
      kill "$server_pid" >/dev/null 2>&1 || true
      wait "$server_pid" >/dev/null 2>&1 || true
      server_pid=""
      wait_for_vpn_network "${label}-bind-retry"
      kv "${label}.vpn_probe_relaunched" true
      continue
    fi
    fail_closed "${label} TCP app probe did not satisfy ${mode}"
  done
  validate_host_result "$host_file" tcp "$mode"
  if [[ "$evaluation" == no_match ]]; then
    status_action=none
  fi
  capture_matrix_status "$label" "$profile" "$case_id" "$evaluation" \
    "$status_action" "$rule_id" "$reason_id" "$rank"
}

run_udp_probe() {
  local profile="$1"
  local bind_to_vpn="$2"
  local case_id="$3"
  local label="$4"
  local port="$5"
  local host="$6"
  local mode="$7"
  local evaluation="$8"
  local rule_id="$9"
  local reason_id="${10}"
  local rank="${11}"
  local nonce="s192-${profile}-${case_id}-${label}-${RUN_ID}"
  local ready_file="$RESULT_DIR/host-${label}.ready"
  local host_file="$RESULT_DIR/host-${label}.properties"
  local probe_file="$RESULT_DIR/${label}.udp-probe.properties"
  local status_action="$CASE_ACTION"
  local probe_rc=1
  local probe_relaunches=0
  while :; do
    rm -f "$ready_file" "$host_file"
    clear_app_file "$UDP_PROBE_PATH"
    host_udp_echo_once "$CASE_FAMILY" "$host" "$port" "$nonce" \
      "$ready_file" "$host_file" &
    server_pid=$!
    wait_for_host_ready "$ready_file" \
      || fail_closed "host UDP endpoint did not become ready (${label})"
    start_activity --ez debugUdpTraffic true \
      --es debugUdpHost "$host" \
      --ei debugUdpPort "$port" \
      --es debugUdpNonce "$nonce" \
      --ez debugUdpExpectReply true \
      --ez debugTrafficBindToVpn "$bind_to_vpn" \
      --ei debugUdpTimeoutMillis "$timeout_ms"
    if wait_for_probe_result "$UDP_PROBE_PATH" "$app_uid" "$nonce" "$mode" \
        "$probe_file" "$bind_to_vpn"; then
      probe_rc=0
    else
      probe_rc=$?
    fi
    if (( probe_rc == 0 )); then
      wait "$server_pid" || true
      server_pid=""
      break
    fi
    if [[ "$bind_to_vpn" == true && "$probe_rc" == 2 \
        && "$probe_relaunches" == 0 ]]; then
      probe_relaunches=1
      cp "$probe_file" \
        "$RESULT_DIR/${label}.bind-retry-1.udp-probe.properties" \
        2>/dev/null || true
      cp "$host_file" \
        "$RESULT_DIR/${label}.bind-retry-1.host.properties" \
        2>/dev/null || true
      kill "$server_pid" >/dev/null 2>&1 || true
      wait "$server_pid" >/dev/null 2>&1 || true
      server_pid=""
      wait_for_vpn_network "${label}-bind-retry"
      kv "${label}.vpn_probe_relaunched" true
      continue
    fi
    fail_closed "${label} UDP app probe did not satisfy ${mode}"
  done
  validate_host_result "$host_file" udp "$mode"
  if [[ "$evaluation" == no_match ]]; then
    status_action=none
  fi
  capture_matrix_status "$label" "$profile" "$case_id" "$evaluation" \
    "$status_action" "$rule_id" "$reason_id" "$rank"
}

run_profile_case() {
  local profile="$1"
  local bind_to_vpn="$2"
  local index="$3"
  local suffix="${4:-}"
  local case_id="${MATRIX_CASES[$index]}"
  local rule_id=""
  local reason_id=""
  local label="${profile}-${case_id}${suffix}"
  case_metadata "$case_id"
  rule_id="$(property_value "$RESULT_DIR/root.policy-identity.properties" "rule_id_${CASE_INDEX}")"
  reason_id="$(property_value "$RESULT_DIR/root.policy-identity.properties" "reason_id_${CASE_INDEX}")"
  [[ "$rule_id" =~ ^[0-9]+$ && "$rule_id" != 0 ]] \
    || fail_closed "missing stable rule id for ${case_id}"
  [[ "$reason_id" =~ ^[0-9]+$ && "$reason_id" != 0 ]] \
    || fail_closed "missing stable reason id for ${case_id}"
  if [[ "$CASE_PROTOCOL_NAME" == tcp ]]; then
    run_tcp_probe "$profile" "$bind_to_vpn" "$case_id" "$label" \
      "$CASE_PORT" "$CASE_HOST" "$CASE_ACTION" match "$rule_id" \
      "$reason_id" "$((CASE_INDEX + 1))"
  else
    run_udp_probe "$profile" "$bind_to_vpn" "$case_id" "$label" \
      "$CASE_PORT" "$CASE_HOST" "$CASE_ACTION" match "$rule_id" \
      "$reason_id" "$((CASE_INDEX + 1))"
  fi

  local no_match_label="${label}-no-match"
  if [[ "$CASE_PROTOCOL_NAME" == tcp ]]; then
    run_tcp_probe "$profile" "$bind_to_vpn" "$case_id" "$no_match_label" \
      "$CASE_NO_MATCH_PORT" "$CASE_HOST" allow no_match 0 0 0
  else
    run_udp_probe "$profile" "$bind_to_vpn" "$case_id" "$no_match_label" \
      "$CASE_NO_MATCH_PORT" "$CASE_HOST" allow no_match 0 0 0
  fi
}

run_profile_matrix() {
  local profile="$1"
  local bind_to_vpn="$2"
  local index
  for index in "${!MATRIX_CASES[@]}"; do
    run_profile_case "$profile" "$bind_to_vpn" "$index"
  done
}

compare_status_identity() {
  local label="$1"
  local left="$2"
  local right="$3"
  python3 - "$left" "$right" "$label" <<'PY'
import pathlib
import sys

left_path, right_path, label = sys.argv[1:]

def read(path):
    result = {}
    for line in pathlib.Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result

left = read(left_path)
right = read(right_path)
for key in (
    "policy_uid", "policy_uid_complete", "policy_revision",
    "policy_snapshot_hash", "policy_snapshot_identity", "policy_rule_id",
    "policy_reason_id", "policy_winner_rank", "policy_evaluation",
    "policy_action", "policy_verdict",
):
    if left.get(key, "") != right.get(key, ""):
        raise SystemExit(
            f"{label}: {key} differs: {left.get(key)!r} != {right.get(key)!r}")
print("same_uid_revision_hash_rule_reason=true")
PY
}

compare_profile_statuses() {
  local case_id
  local left
  local right
  for case_id in "${MATRIX_CASES[@]}"; do
    left="$RESULT_DIR/root-${case_id}.matrix-status.properties"
    right="$RESULT_DIR/vpn-${case_id}.matrix-status.properties"
    compare_status_identity "root-vpn-${case_id}" "$left" "$right" \
      || fail_closed "Root/VPN policy identity differs for ${case_id}"
    left="$RESULT_DIR/root-${case_id}-no-match.matrix-status.properties"
    right="$RESULT_DIR/vpn-${case_id}-no-match.matrix-status.properties"
    compare_status_identity "root-vpn-${case_id}-no-match" "$left" "$right" \
      || fail_closed "Root/VPN no-match identity differs for ${case_id}"
  done
  kv root_vpn_same_uid true
  kv root_vpn_same_revision true
  kv root_vpn_same_snapshot_hash true
  kv root_vpn_same_rule_reason true
}

kv test_id SAKAMOTO-192-root-vpn-l4-matrix
kv serial "$serial"
kv package "$PACKAGE"
kv activity "$ACTIVITY"
kv controlled_lan_host4 "$controlled_host4"
kv base_port "$base_port"
kv timeout_ms "$timeout_ms"
kv matrix_policy_context "$MATRIX_POLICY_CONTEXT"
kv matrix_profiles 'root,vpn'
kv matrix_dimensions 'root,vpn x ipv4,ipv6 x tcp,udp'
kv matrix_cases 'ipv4-tcp,ipv4-udp,ipv6-tcp,ipv6-udp'

acquire_run_lock
adb_devices_contains_serial \
  || fail_closed "adb devices does not show $serial as device through ./dev/adb"
kv adb_devices_contains_serial true
adb_target get-state > "$RESULT_DIR/adb-get-state.txt"
kv adb_get_state "$(tr -d '\r\n' < "$RESULT_DIR/adb-get-state.txt")"
adb_target shell pm path "$PACKAGE" >/dev/null 2>&1 \
  || fail_closed "installed debug APK is missing: $PACKAGE"
adb_target shell pm grant "$PACKAGE" android.permission.POST_NOTIFICATIONS \
  >/dev/null 2>&1 || true
validate_and_discover_host6
kv controlled_lan_host6 "$controlled_host6"

app_uid="$(installed_app_uid)"
subject="android.uid:${app_uid}"
kv installed_app_uid "$app_uid"
kv installed_app_uid_complete true
kv policy_uid "$app_uid"

start_activity --ez runtimeStop true >/dev/null 2>&1 || true
wait_for_state stopped || true
cold_start_control_activity
kv preflight_cold_start_settled true
clear_product_policy_files

start_activity --ez runtimeStart true --es runtimeProfile root
runtime_started=1
wait_for_profile_ready root root-nfqueue
start_activity --ez debugApplyEmptyPolicy true
apply_matrix_rules "$subject"
capture_bundle_identity root
bundle_revision="$(property_value "$RESULT_DIR/root.policy-identity.properties" revision)"
bundle_snapshot_hash="$(property_value "$RESULT_DIR/root.policy-identity.properties" snapshot_hash)"
bundle_snapshot_identity="$(property_value "$RESULT_DIR/root.policy-identity.properties" snapshot_identity)"
run_profile_matrix root false

stop_profile root root_after_matrix
start_activity --ez runtimeStart true --es runtimeProfile root
runtime_started=1
wait_for_profile_ready root root-nfqueue
run_profile_case root false 0 -restart
compare_status_identity root_restart_same_identity \
  "$RESULT_DIR/root-ipv4-tcp.matrix-status.properties" \
  "$RESULT_DIR/root-ipv4-tcp-restart.matrix-status.properties" \
  || fail_closed "Root restart changed policy identity"
kv root_restart_same_revision true
kv root_restart_same_snapshot_hash true
stop_profile root root_after_restart

start_activity --ez runtimeStart true --es runtimeProfile vpn
runtime_started=1
wait_for_profile_ready vpn vpn-tun-hev-lwip
wait_for_vpn_network vpn-start
capture_bundle_identity vpn
cmp -s "$RESULT_DIR/root.policy-bundle.properties" \
  "$RESULT_DIR/vpn.policy-bundle.properties" \
  || fail_closed "VPN policy-bundle store differs from Root policy-bundle store"
kv root_vpn_bundle_byte_equal true
run_profile_matrix vpn true
compare_profile_statuses

stop_profile vpn vpn_after_matrix
start_activity --ez runtimeStart true --es runtimeProfile vpn
runtime_started=1
wait_for_profile_ready vpn vpn-tun-hev-lwip
wait_for_vpn_network vpn-restart
run_profile_case vpn true 0 -restart
compare_status_identity vpn_restart_same_identity \
  "$RESULT_DIR/vpn-ipv4-tcp.matrix-status.properties" \
  "$RESULT_DIR/vpn-ipv4-tcp-restart.matrix-status.properties" \
  || fail_closed "VPN restart changed policy identity"
kv vpn_restart_same_revision true
kv vpn_restart_same_snapshot_hash true
stop_profile vpn vpn_after_restart

kv final_residue_clean true
kv result PASS
echo "SAKAMOTO-192 Root/VPN L4 matrix: PASS"
