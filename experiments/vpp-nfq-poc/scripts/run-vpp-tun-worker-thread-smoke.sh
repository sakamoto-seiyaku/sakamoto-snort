#!/usr/bin/env bash
set -euo pipefail

# PROTOTYPE: verify which VPP thread handles tun_poc clib_file callbacks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VPP_BIN="${VPP_BIN:-$POC_DIR/work/vpp/build-root/install-vpp-native/vpp/bin/vpp}"
VPPCTL_BIN="${VPPCTL_BIN:-$POC_DIR/work/vpp/build-root/install-vpp-native/vpp/bin/vppctl}"
VPP_CONFIG="${VPP_CONFIG:-$POC_DIR/configs/tun-poc-workers-startup.conf}"
LOG_DIR="$POC_DIR/results"
LOG="$LOG_DIR/vpp-tun-worker-thread-smoke-check.log"
SMOKE_LOG="$LOG_DIR/vpp-tun-forward-fd-smoke.log"

mkdir -p "$LOG_DIR"
exec > >(tee "$LOG") 2>&1

echo "# VPP tun_poc worker thread smoke"
echo "vpp_bin=$VPP_BIN"
echo "vpp_config=$VPP_CONFIG"

"$SCRIPT_DIR/run-vpp-tun-forward-fd-smoke.py" \
  --vpp-bin "$VPP_BIN" \
  --vppctl-bin "$VPPCTL_BIN" \
  --vpp-config "$VPP_CONFIG" \
  --log-dir "$LOG_DIR"

echo
echo "## show threads excerpt"
grep -E 'vpp_main|vpp_wk_' "$SMOKE_LOG" || true

main_line="$(grep '^thread-hits main' "$SMOKE_LOG" | tail -n 1)"
shim_line="$(grep '^thread-hits shim' "$SMOKE_LOG" | tail -n 1)"
echo
echo "main_line=$main_line"
echo "shim_line=$shim_line"

if [[ -z "$main_line" || -z "$shim_line" ]]; then
  echo "missing thread-hits lines from show tun-poc" >&2
  exit 1
fi

if ! grep -q 'vpp_wk_0' "$SMOKE_LOG"; then
  echo "expected VPP worker thread vpp_wk_0 in show threads" >&2
  exit 1
fi

main_t0="$(awk '{ print $6 }' <<<"$main_line")"
main_t1="$(awk '{ print $8 }' <<<"$main_line")"
main_t2="$(awk '{ print $10 }' <<<"$main_line")"
shim_t0="$(awk '{ print $6 }' <<<"$shim_line")"
shim_t1="$(awk '{ print $8 }' <<<"$shim_line")"
shim_t2="$(awk '{ print $10 }' <<<"$shim_line")"

echo "main_t0=$main_t0 main_t1=$main_t1 main_t2=$main_t2"
echo "shim_t0=$shim_t0 shim_t1=$shim_t1 shim_t2=$shim_t2"

if [[ "$main_t0" -le 0 || "$shim_t0" -le 0 ]]; then
  echo "expected main and shim fd callbacks to hit thread 0 at least once" >&2
  exit 1
fi
if [[ "$main_t1" -ne 0 || "$main_t2" -ne 0 || "$shim_t1" -ne 0 || "$shim_t2" -ne 0 ]]; then
  echo "expected clib_file callbacks to stay on thread 0 for this POC shape" >&2
  exit 1
fi

echo
echo "ok: tun_poc clib_file callbacks stayed on VPP thread 0 while workers were present"
