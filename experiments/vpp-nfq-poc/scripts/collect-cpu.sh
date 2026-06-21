#!/usr/bin/env bash
set -euo pipefail

NAME_PATTERN="${NAME_PATTERN:-nfq-smoke}"
SAMPLES="${SAMPLES:-10}"
DELAY="${DELAY:-1}"

pid="$(pgrep -f "$NAME_PATTERN" | head -n 1 || true)"
if [ -z "$pid" ]; then
  echo "No process matched NAME_PATTERN=$NAME_PATTERN" >&2
  exit 1
fi

echo "pid=$pid pattern=$NAME_PATTERN"
echo "Sampling thread CPU with ps for $SAMPLES seconds"

for _ in $(seq 1 "$SAMPLES"); do
  ps -L -p "$pid" -o pid,tid,psr,pcpu,comm
  sleep "$DELAY"
done
