#!/usr/bin/env bash
set -euo pipefail

# Keep this historical entry name fail-closed; do not restore its C++ model.
echo "RETIRED: this S61 gate depends on the C++ Product recognition seam removed by ADR-0008." >&2
echo "See tools/protocol_identification/README.md for reference-only inventories and historical evidence." >&2
exit 2
