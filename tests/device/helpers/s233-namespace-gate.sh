#!/bin/sh
# Adapt the older six-argument fragment runner to the current, unmodified
# kernel UID facts. The real policy application remains Rust -> native VAPI.
set -eu
test "$#" -eq 5
read -r namespace_uid kernel_uid mapped_count < /proc/self/uid_map
test "$namespace_uid" = 0
test "$kernel_uid" != 0
test "$mapped_count" = 1
test -n "${SAKAMOTO_TEST_POLICY_CLIENT:-}"
exec "$SAKAMOTO_TEST_POLICY_CLIENT" "$1" "$2" "$3" "$4" "$5" "$kernel_uid" 0
