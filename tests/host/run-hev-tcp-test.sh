#!/bin/sh
set -eu
# Isolate kernel TCP endpoints from host routing/firewall/port-forward services.
# Only this temporary user-owned network namespace is configured.
exec unshare --user --map-root-user --net sh -ec '
  ip link set lo up
  exec "$@"
' sh "$@"
