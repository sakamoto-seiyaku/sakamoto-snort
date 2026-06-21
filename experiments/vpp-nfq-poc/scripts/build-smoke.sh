#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
SRC="$POC_DIR/src/nfq-smoke.c"
OUT_DIR="$POC_DIR/build"
OUT="$OUT_DIR/nfq-smoke"

mkdir -p "$OUT_DIR"

if ! command -v pkg-config >/dev/null 2>&1; then
  echo "pkg-config not found. Run inside the POC Docker image." >&2
  exit 1
fi

if ! pkg-config --exists libnetfilter_queue; then
  echo "libnetfilter_queue development package not found. Run: make docker-shell" >&2
  exit 1
fi

CC="${CC:-cc}"
CFLAGS="${CFLAGS:--std=c11 -O2 -g -Wall -Wextra}"

"$CC" $CFLAGS \
  $(pkg-config --cflags libnetfilter_queue) \
  "$SRC" \
  -o "$OUT" \
  $(pkg-config --libs libnetfilter_queue)

echo "$OUT"
