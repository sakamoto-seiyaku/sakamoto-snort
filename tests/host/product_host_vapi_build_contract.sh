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
# The compiler wrapper requires Host endian compatibility but rejects warning
# suppressions applied to the whole project-owned translation unit.
cc_wrapper="$fixture_root/cc"
cat >"$cc_wrapper" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
args=" $* "
required_flags=(-Werror)
# The observation transport deliberately uses GNU C11; generated VAPI is
# strict C11 and needs the explicit glibc endian feature switch.
if [[ "$args" != *"product_observation_transport.c "* ]]; then
  required_flags+=(-D_DEFAULT_SOURCE=1)
fi
for required in "${required_flags[@]}"; do
  if [[ "$args" != *" $required "* ]]; then
    echo "missing Host generated-VAPI compiler flag: $required" >&2
    exit 1
  fi
done
for forbidden in -Wno-unused-parameter -Wno-sign-compare; do
  if [[ "$args" == *" $forbidden "* ]]; then
    echo "translation-unit-wide generated-VAPI suppression: $forbidden" >&2
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

# Project-owned C must retain -Werror for the same two warning classes emitted
# by generated headers, as well as unrelated compiler diagnostics.
cat >"$fixture_root/owned-unused.c" <<'EOF'
int sakamoto_owned_unused(int value) { return 0; }
EOF
cat >"$fixture_root/owned-sign.c" <<'EOF'
int sakamoto_owned_sign(unsigned left, int right) { return left < right; }
EOF
cat >"$fixture_root/owned-implicit.c" <<'EOF'
int sakamoto_owned_implicit(void) { return undeclared_function(); }
EOF
for warning_source in owned-unused owned-sign owned-implicit; do
  if cc -std=c11 -Wall -Wextra -Werror -D_DEFAULT_SOURCE=1 \
      -c "$fixture_root/$warning_source.c" \
      -o "$fixture_root/$warning_source.o" >/dev/null 2>&1; then
    echo "Host VAPI build weakened -Werror for $warning_source" >&2
    exit 1
  fi
done

echo "sakamoto Product Host generated-VAPI build contract: PASS"
