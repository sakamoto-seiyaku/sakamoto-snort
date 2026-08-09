#!/usr/bin/env bash
set -euo pipefail

# S77 uses the proven S76 four-lane topology with isolated interface/rule and
# state names.  The wrapper keeps the network ownership contract identical
# while preventing an unfinished S76 run from sharing resources.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export S76_HOST_IF="${S77_HOST_IF:-nfq77-host}"
export S76_PEER_IF="${S77_PEER_IF:-nfq77-peer}"
export S76_HOST4="${S77_HOST4:-10.201.77.1}"
export S76_PEER4="${S77_PEER4:-10.201.77.2}"
export S76_HOST6="${S77_HOST6:-fd00:201:77::1}"
export S76_PEER6="${S77_PEER6:-fd00:201:77::2}"
export S76_NETNS_STATE="${S77_NETNS_STATE:-/tmp/sakamoto-nfqueue-s77-state}"
exec "$SCRIPT_DIR/setup-netns-s76.sh" "$@"
