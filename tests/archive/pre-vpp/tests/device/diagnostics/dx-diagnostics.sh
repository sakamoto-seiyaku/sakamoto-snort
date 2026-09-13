#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# DX diagnostics 总入口（当前只聚合 perf-network-load；后续可扩展）。
bash "$SCRIPT_DIR/dx-diagnostics-perf-network-load.sh" "$@"

