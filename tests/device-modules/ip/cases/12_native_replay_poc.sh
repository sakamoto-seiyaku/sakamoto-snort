#!/bin/bash

set -euo pipefail

CASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IPMOD_DIR="$(cd "$CASE_DIR/.." && pwd)"
source "$IPMOD_DIR/lib.sh"

log_section "native replay poc"

bash "$IPMOD_DIR/native_replay_poc.sh" --skip-deploy

exit 0
