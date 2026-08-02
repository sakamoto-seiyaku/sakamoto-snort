#!/usr/bin/env bash
set -euo pipefail

# SAKAMOTO-42 preflight: observe whether Android root NFQUEUE can receive
# post-fragment IPv4 packet IDs at all. This intentionally uses the existing
# async-lease implementation; the result decides whether a fragment lease
# implementation can be exercised on this device.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$POC_DIR/../.." && pwd)"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"
BUILD_DIR="${BUILD_DIR:-$VPP_WORK_ROOT/vpp-android-configure-probe}"
STAGE_DIR="${STAGE_DIR:-$VPP_WORK_ROOT/android-nfq-async-stage}"
REMOTE_ROOT="${REMOTE_ROOT:-/data/local/tmp/vpp-nfq-poc-42-fragment-observe}"
RUN_ID="$(date +%Y%m%d-%H%M%S)"
RESULT_DIR="$POC_DIR/results/sakamoto-42-nfqueue-fragment-observe-$RUN_ID"
RUN_LOG="$RESULT_DIR/run.log"
TARGET="${TARGET:-192.168.4.1}"
QUEUE="${QUEUE:-60}"
PING_SIZE="${PING_SIZE:-4000}"
PING_COUNT="${PING_COUNT:-4}"
SENDER_SRC="$POC_DIR/clients/android_fragment_sender.c"
SENDER_BIN="$POC_DIR/build/android-fragment-sender"

source "$REPO_ROOT/dev/dev-android-device-lib.sh"
mkdir -p "$RESULT_DIR"
exec > >(tee "$RUN_LOG") 2>&1

vppctl_cmd() {
  adb_su "LD_LIBRARY_PATH='$REMOTE_ROOT/lib' '$REMOTE_ROOT/bin/vppctl' -s '$REMOTE_ROOT/runtime/cli.sock' $1"
}

remove_rule() {
  while adb_su "/system/bin/iptables -w -t mangle -D POSTROUTING -p icmp -d '$TARGET' -j NFQUEUE --queue-num $QUEUE --queue-bypass 2>/dev/null" >/dev/null 2>&1; do :; done
}

stop_vpp() {
  vppctl_cmd 'nfqueue-poc disable' >/dev/null 2>&1 || true
  adb_su "if [ -f '$REMOTE_ROOT/runtime/vpp.pid' ]; then kill -TERM \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; sleep 1; kill -KILL \$(cat '$REMOTE_ROOT/runtime/vpp.pid') 2>/dev/null || true; fi; for p in \$(pidof vpp 2>/dev/null || true); do kill -TERM \$p 2>/dev/null || true; done; sleep 1"
}

cleanup() {
  local rc=$?
  remove_rule || true
  stop_vpp || true
  local pids queues hooks
  pids="$(adb_su 'pidof vpp 2>/dev/null || true' | tr -d '\r\n')"
  queues="$(adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' | sed '/^[[:space:]]*$/d' | wc -l)"
  hooks="$(adb_su '/system/bin/iptables -S 2>/dev/null || true; /system/bin/iptables -t mangle -S 2>/dev/null || true' | tr -d '\r' | grep -Ec 'NFQUEUE|nfqueue_poc' || true)"
  echo "final residue: vpp_pids=${pids:-none} queue_lines=$queues nfqueue_hooks=$hooks"
  [[ -z "$pids" && "$queues" == 0 && "$hooks" == 0 ]] || rc=1
  return "$rc"
}
trap cleanup EXIT

echo '# SAKAMOTO-42 NFQUEUE post-fragment observation POC'
echo "run_id=$RUN_ID"
echo "adb_serial=$(resolve_adb_serial)"
echo "target=$TARGET queue=$QUEUE ping_size=$PING_SIZE ping_count=$PING_COUNT"

device_preflight
remove_rule
mkdir -p "$POC_DIR/build"
"${ANDROID_CLANG:-/home/js/.local/share/android-sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang}" \
  -O2 -Wall -Wextra -Werror -o "$SENDER_BIN" "$SENDER_SRC"
BUILD_DIR="$BUILD_DIR" STAGE_DIR="$STAGE_DIR" REMOTE_ROOT="$REMOTE_ROOT" \
  "$POC_DIR/scripts/android-push-vpp-core.sh"
stop_vpp
adb_su "rm -rf '$REMOTE_ROOT/runtime/cli.sock' '$REMOTE_ROOT/runtime/statseg.sock' '$REMOTE_ROOT/logs/vpp-stdout.log'; mkdir -p '$REMOTE_ROOT/runtime' '$REMOTE_ROOT/logs'; cd '$REMOTE_ROOT' && export LD_LIBRARY_PATH='$REMOTE_ROOT/lib'; nohup '$REMOTE_ROOT/bin/vpp' plugin_path '$REMOTE_ROOT/plugins' -c '$REMOTE_ROOT/runtime/startup.conf' >'$REMOTE_ROOT/logs/vpp-stdout.log' 2>&1 < /dev/null & echo \$! > '$REMOTE_ROOT/runtime/vpp.pid'"
sleep 3
vppctl_cmd 'show version' >/dev/null
vppctl_cmd "nfqueue-poc enable queue $QUEUE family ip4 mode async-lease event-log '$REMOTE_ROOT/logs/fragment.ndjson'" >"$RESULT_DIR/enable.txt"
adb_su "/system/bin/iptables -w -t mangle -I POSTROUTING 1 -p icmp -d '$TARGET' -j NFQUEUE --queue-num $QUEUE --queue-bypass"
# The staged VPP root is deliberately root-owned after the core push.  ADB's
# transport user cannot create a file there, so land the sender in the normal
# shell-writable temp directory and move it into place with root.
SENDER_REMOTE_TMP="/data/local/tmp/vpp-nfq-poc-42-fragment-sender"
adb_cmd push "$SENDER_BIN" "$SENDER_REMOTE_TMP" >/dev/null
adb_su "mv '$SENDER_REMOTE_TMP' '$REMOTE_ROOT/android-fragment-sender'; chmod 755 '$REMOTE_ROOT/android-fragment-sender'"
set +e
adb_su "'$REMOTE_ROOT/android-fragment-sender' '$TARGET' '$PING_COUNT' '$PING_SIZE'" >"$RESULT_DIR/ping.txt" 2>&1
ping_rc=$?
set -e
sleep 1
show="$(vppctl_cmd 'show nfqueue-poc' | tr -d '\r')"
printf '%s\n' "$show" >"$RESULT_DIR/show.txt"
adb_su "cat '$REMOTE_ROOT/logs/fragment.ndjson' 2>/dev/null || true" | tr -d '\r' >"$RESULT_DIR/events.ndjson"
adb_su 'cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true' | tr -d '\r' >"$RESULT_DIR/nfnetlink_queue.txt"
echo "ping_rc=$ping_rc"
printf '%s\n' "$show"
echo "post_fragment_rule=iptables -t mangle POSTROUTING"
echo "fragment_observation_policy=multiple_packet_ids_required"
if grep -Eq 'async ingress [2-9][0-9]*' "$RESULT_DIR/show.txt"; then
  echo 'fragment_observation=userspace_received_multiple_packets'
else
  echo 'fragment_observation=not-reproduced'
fi
