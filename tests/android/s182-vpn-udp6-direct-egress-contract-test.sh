#!/usr/bin/env bash
set -euo pipefail
# S200: the original recipe is retained as handcrafted bridge POC evidence.
echo "S182: historical handcrafted Direct bridge POC only; this is not a Product HEV/lwIP gate." >&2
echo "See experiments/handcrafted-direct-bridge/README.md and tests/android/s182-vpn-udp6-direct-egress-contract-test.sh there." >&2
exit 2
