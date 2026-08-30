#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
fixture_root="$(mktemp -d /tmp/sakamoto-product-host-vapi-build.XXXXXX)"
cleanup() {
  rm -rf -- "$fixture_root"
}
trap cleanup EXIT

mkdir -p "$fixture_root/include" "$fixture_root/generated/vapi"

# Exercise the Cargo build-script seam without needing an external VPP tree.
# The compiler wrapper accepts only the narrow compatibility flags required by
# pinned generated VAPI headers, then materializes the requested object.
cc_wrapper="$fixture_root/cc"
cat >"$cc_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
for required in -Werror -D_DEFAULT_SOURCE=1 \
  -Wno-unused-parameter -Wno-sign-compare; do
  if [[ "$args" != *" $required "* ]]; then
    echo "missing Host generated-VAPI compiler flag: $required" >&2
    exit 1
  fi
done
output=""
while [[ "$#" -gt 0 ]]; do
  if [[ "$1" == -o && "$#" -ge 2 ]]; then
    output="$2"
    break
  fi
  shift
done
[[ -n "$output" ]] || exit 1
: >"$output"
EOF
chmod +x "$cc_wrapper"

ar_wrapper="$fixture_root/ar"
cat >"$ar_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -ge 2 ]] || exit 1
: >"$2"
EOF
chmod +x "$ar_wrapper"

CARGO_TARGET_DIR="$fixture_root/target" \
CC="$cc_wrapper" \
AR="$ar_wrapper" \
SAKAMOTO_PRODUCT_VAPI_INCLUDE_DIR="$fixture_root/include" \
SAKAMOTO_PRODUCT_VAPI_GENERATED_DIR="$fixture_root/generated/vapi" \
SAKAMOTO_PRODUCT_VAPI_LIBRARY_DIR="$fixture_root/lib" \
SAKAMOTO_PRODUCT_VAPI_REQUIRED=1 \
  cargo check --quiet --manifest-path "$repo_root/Cargo.toml" \
    -p sakamoto-product-core --lib

# Suppressing the two confirmed generated-header diagnostics must not weaken
# -Werror for project-owned C. An unrelated implicit declaration stays fatal.
cat >"$fixture_root/owned-warning.c" <<'EOF'
int sakamoto_owned_warning(void) { return undeclared_function(); }
EOF
if cc -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE=1 \
    -Wno-unused-parameter -Wno-sign-compare \
    -c "$fixture_root/owned-warning.c" -o "$fixture_root/owned-warning.o" \
    >/dev/null 2>&1; then
  echo "Host generated-VAPI flags weakened -Werror for project-owned C" >&2
  exit 1
fi

echo "sakamoto Product Host generated-VAPI build contract: PASS"
