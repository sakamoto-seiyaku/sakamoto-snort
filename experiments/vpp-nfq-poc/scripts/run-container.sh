#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$POC_DIR/../.." && pwd)"
IMAGE="${IMAGE:-sakamoto-vpp-nfq-poc:dev}"
DOCKER_NETWORK="${DOCKER_NETWORK:-none}"

docker build -t "$IMAGE" "$POC_DIR"

if [ "$#" -eq 0 ]; then
  set -- bash
fi

tty_args=()
if [ -t 0 ] && [ -t 1 ]; then
  tty_args=(-it)
fi

exec docker run --rm "${tty_args[@]}" \
  --name sakamoto-vpp-nfq-poc \
  --network "$DOCKER_NETWORK" \
  --cap-drop ALL \
  --cap-add NET_ADMIN \
  --cap-add NET_RAW \
  --cap-add SYS_ADMIN \
  --security-opt apparmor=unconfined \
  --security-opt seccomp=unconfined \
  --tmpfs /run \
  -v "$REPO_ROOT:/work/sakamoto-snort" \
  -w /work/sakamoto-snort/experiments/vpp-nfq-poc \
  "$IMAGE" \
  "$@"
