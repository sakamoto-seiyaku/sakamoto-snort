#!/usr/bin/env bash
set -euo pipefail

# Build the exact owner-context HEV fixture used by S125.  The generic HEV
# build script intentionally remains separate because its default checkout is
# the ordinary tunnel tree and does not contain the S118 owner seam.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
HEV_DIR="${HEV_DIR:-/tmp/hev-3911f79}"
NDK_ROOT="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
NDK_BUILD="${NDK_BUILD:-$NDK_ROOT/ndk-build}"
BUILD_DIR="${BUILD_DIR:-$POC_DIR/work/hev-poc7-android-build}"
STAGE_DIR="${STAGE_DIR:-$POC_DIR/work/android-hev-poc7-stage}"
APP_ABI="${APP_ABI:-arm64-v8a}"
APP_PLATFORM="${APP_PLATFORM:-android-31}"
PATCH_FILE="$POC_DIR/patches/hev-poc7-tcp-copy-timing.patch"
ACK_PATCH_FILE="$POC_DIR/patches/hev-owner-context-empty-ack.patch"
EXTERNAL_INGRESS_PATCH_FILE="$POC_DIR/patches/hev-owner-context-external-ingress.patch"
DEFERRED_STOP_PATCH_FILE="$POC_DIR/patches/hev-owner-context-deferred-stop.patch"
DESTROY_GUARD_PATCH_FILE="$POC_DIR/patches/hev-owner-context-destroy-guard.patch"
UDP_CONNECTOR_PATCH_FILE="$POC_DIR/patches/hev-owner-context-udp-connector-persistent.patch"
TRANSPORT_EVENT_PATCH_FILE="$POC_DIR/patches/hev-owner-context-transport-event.patch"
DOWNSTREAM_RESET_PATCH_FILE="$POC_DIR/patches/hev-owner-context-downstream-reset.patch"

for path in "$HEV_DIR/Android.mk" "$HEV_DIR/src/include/lwip/owner_context.h" \
            "$HEV_DIR/src/hev-flow-stack-owner-context.c" "$PATCH_FILE" \
            "$ACK_PATCH_FILE" "$EXTERNAL_INGRESS_PATCH_FILE" \
            "$DEFERRED_STOP_PATCH_FILE" "$DESTROY_GUARD_PATCH_FILE" \
            "$UDP_CONNECTOR_PATCH_FILE" "$TRANSPORT_EVENT_PATCH_FILE" \
            "$DOWNSTREAM_RESET_PATCH_FILE"; do
  [[ -f "$path" ]] || { echo "missing POC-7 HEV input: $path" >&2; exit 1; }
done
[[ -x "$NDK_BUILD" ]] || { echo "ndk-build not found: $NDK_BUILD" >&2; exit 1; }

if ! grep -q 'flow_stack_owner_tcp_copy_metrics' \
    "$HEV_DIR/src/hev-flow-stack-owner-context.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$PATCH_FILE"
fi
grep -q 'flow_stack_owner_tcp_copy_metrics' \
  "$HEV_DIR/src/hev-flow-stack-owner-context.c" || {
  echo "POC-7 TCP copy seam was not applied" >&2
  exit 1
}

if ! grep -q 'tcp_send_empty_ack_ctx' \
    "$HEV_DIR/third-part/lwip/src/core/tcp_in.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$ACK_PATCH_FILE"
fi
grep -q 'tcp_send_empty_ack_ctx' \
    "$HEV_DIR/third-part/lwip/src/core/tcp_in.c" || {
  echo "owner-context empty ACK seam was not applied" >&2
  exit 1
}

if ! grep -q 'lwip_owner_context_set_external_ingress' \
    "$HEV_DIR/src/include/lwip/owner_context.h"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$EXTERNAL_INGRESS_PATCH_FILE"
fi
grep -q 'lwip_owner_context_set_external_ingress' \
    "$HEV_DIR/src/include/lwip/owner_context.h" || {
  echo "external-ingress owner seam was not applied" >&2
  exit 1
}
grep -q 'lwip_owner_context_current_udp_dest_port' \
    "$HEV_DIR/src/include/lwip/owner_context.h" || {
  echo "external-ingress UDP destination seam was not applied" >&2
  exit 1
}
grep -q 'lwip_owner_context_external_udp_listener' \
    "$HEV_DIR/src/include/lwip/owner_context.h" || {
  echo "external-ingress UDP wildcard seam was not applied" >&2
  exit 1
}
grep -q 'lwip_owner_context_external_ingress(context)' \
    "$HEV_DIR/third-part/lwip/src/core/tcp_in.c" || {
  echo "external-ingress TCP wildcard seam was not applied" >&2
  exit 1
}
grep -q 'lwip_owner_context_external_ingress(context)' \
    "$HEV_DIR/third-part/lwip/src/core/udp.c" || {
  echo "external-ingress UDP wildcard seam was not applied" >&2
  exit 1
}
grep -q 'lwip_owner_context_external_udp_listener(context)' \
    "$HEV_DIR/third-part/lwip/src/core/udp.c" || {
  echo "external-ingress UDP listener identity seam was not applied" >&2
  exit 1
}

if ! grep -q 'flow_stack_owner_drain_external_tasks' \
    "$HEV_DIR/src/hev-flow-stack-owner-context.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$DEFERRED_STOP_PATCH_FILE"
fi
grep -q 'flow_stack_owner_drain_external_tasks' \
  "$HEV_DIR/src/hev-flow-stack-owner-context.c" || {
  echo "deferred owner-context stop seam was not applied" >&2
  exit 1
}

if ! grep -q 'flow_stack_owner_stop(context) != FLOW_STACK_OWNER_OK' \
    "$HEV_DIR/src/hev-flow-stack-owner-context.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$DESTROY_GUARD_PATCH_FILE"
fi
grep -q 'flow_stack_owner_stop(context) != FLOW_STACK_OWNER_OK' \
  "$HEV_DIR/src/hev-flow-stack-owner-context.c" || {
  echo "owner-context destroy guard was not applied" >&2
  exit 1
}

if ! grep -q 'External-driver UDP direct egress is a flow/window' \
    "$HEV_DIR/src/hev-socks5-session-udp.c"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$UDP_CONNECTOR_PATCH_FILE"
fi
grep -q 'External-driver UDP direct egress is a flow/window' \
  "$HEV_DIR/src/hev-socks5-session-udp.c" || {
  echo "UDP connector persistent-session seam was not applied" >&2
  exit 1
}
grep -q 'One protected UDP response completes one datagram' \
  "$HEV_DIR/src/hev-socks5-session-udp.c" || {
  echo "UDP connector response drain seam was not applied" >&2
  exit 1
}

if ! grep -q 'HEV_SOCKS5_TCP_TRANSPORT_READ_ERROR' \
    "$HEV_DIR/src/hev-socks5-tunnel-owner.h"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$TRANSPORT_EVENT_PATCH_FILE"
fi
grep -q 'HEV_SOCKS5_TCP_TRANSPORT_READ_ERROR' \
  "$HEV_DIR/src/hev-socks5-tunnel-owner.h" || {
  echo "owner-context TCP transport event seam was not applied" >&2
  exit 1
}
grep -q 'tcp_transport_event' \
  "$HEV_DIR/src/hev-socks5-session-tcp.c" || {
  echo "owner-context TCP transport event publisher was not applied" >&2
  exit 1
}

if ! grep -q 'tcp_send_reset_ctx' \
    "$HEV_DIR/src/include/lwip/owner_context.h"; then
  patch -p1 --forward --batch -d "$HEV_DIR" <"$DOWNSTREAM_RESET_PATCH_FILE"
fi
grep -q 'tcp_send_reset_ctx' \
  "$HEV_DIR/third-part/lwip/src/core/tcp_in.c" || {
  echo "owner-context downstream TCP reset primitive was not applied" >&2
  exit 1
}
grep -q 'pcb_reset_attempted' \
  "$HEV_DIR/src/hev-socks5-session-tcp.c" || {
  echo "HEV upstream-reset to downstream-reset mapping was not applied" >&2
  exit 1
}

rm -rf "$BUILD_DIR" "$STAGE_DIR"
mkdir -p "$BUILD_DIR" "$STAGE_DIR/lib/$APP_ABI"
"$NDK_BUILD" \
  NDK_PROJECT_PATH="$HEV_DIR" \
  APP_BUILD_SCRIPT="$HEV_DIR/Android.mk" \
  NDK_OUT="$BUILD_DIR/obj" \
  NDK_LIBS_OUT="$BUILD_DIR/libs" \
  APP_ABI="$APP_ABI" \
  APP_PLATFORM="$APP_PLATFORM" \
  -j"$(nproc)"

cp "$BUILD_DIR/libs/$APP_ABI/libhev-socks5-tunnel.so" \
  "$STAGE_DIR/lib/$APP_ABI/"
sha256sum "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so" \
  >"$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so.sha256"
echo "hev_dir=$HEV_DIR"
echo "stage_dir=$STAGE_DIR"
echo "tcp_copy_symbol=$(nm -D "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so" \
  | awk '$3 == "flow_stack_owner_tcp_copy_metrics" { print "present"; found=1 } END { if (!found) print "missing" }')"
ls -lh "$STAGE_DIR/lib/$APP_ABI/libhev-socks5-tunnel.so"
