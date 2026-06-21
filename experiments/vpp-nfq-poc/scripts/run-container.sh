#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
IMAGE="${IMAGE:-sakamoto-vpp-nfq-poc:dev}"
DOCKER_NETWORK="${DOCKER_NETWORK:-none}"
DOCKER_CAP_PROFILE="${DOCKER_CAP_PROFILE:-smoke}"
VPP_WORK_ROOT="${VPP_WORK_ROOT:-$POC_DIR/work}"

docker build -t "$IMAGE" "$POC_DIR"

if [ "$#" -eq 0 ]; then
  set -- bash
fi

mkdir -p "$VPP_WORK_ROOT"
chmod 0777 "$VPP_WORK_ROOT"

tty_args=()
if [ -t 0 ] && [ -t 1 ]; then
  tty_args=(-it)
fi

cap_args=()
case "$DOCKER_CAP_PROFILE" in
  smoke)
    cap_args=(
      --cap-drop ALL
      --cap-add NET_ADMIN
      --cap-add NET_RAW
      --cap-add SYS_ADMIN
      --security-opt apparmor=unconfined
      --security-opt seccomp=unconfined
    )
    ;;
  default)
    cap_args=()
    ;;
  *)
    echo "unknown DOCKER_CAP_PROFILE=$DOCKER_CAP_PROFILE" >&2
    exit 2
    ;;
esac

exec docker run --rm "${tty_args[@]}" \
  --name sakamoto-vpp-nfq-poc \
  --network "$DOCKER_NETWORK" \
  "${cap_args[@]}" \
  --tmpfs /run \
  -e VPP_WORK_ROOT="$VPP_WORK_ROOT" \
  -v "$REPO_ROOT:/work/sakamoto-snort" \
  -v "$VPP_WORK_ROOT:$VPP_WORK_ROOT" \
  -w /work/sakamoto-snort/experiments/vpp-nfq-poc \
  "$IMAGE" \
  "$@"
