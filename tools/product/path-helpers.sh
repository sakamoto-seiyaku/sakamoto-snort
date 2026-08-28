#!/usr/bin/env bash

# Shared path policy for product-owned build and runtime state.  Callers must
# set repo_root to this checkout before sourcing the file.  The helpers return
# canonical paths and fail closed before a caller creates or removes anything.

if [[ -z "${repo_root:-}" ]]; then
  echo "path-helpers.sh requires repo_root" >&2
  return 2 2>/dev/null || exit 2
fi

product_path_error() {
  echo "$*" >&2
  return 2
}

product_require_absolute() {
  local raw="$1"
  if [[ "$raw" != /* ]]; then
    product_path_error "path must be absolute: $raw"
    return 2
  fi
}

product_canonical_existing() {
  local raw="$1"
  product_require_absolute "$raw" || return
  if ! realpath -e -- "$raw"; then
    product_path_error "path does not exist: $raw"
    return 2
  fi
}

product_canonical_for_write() {
  local raw="$1"
  product_require_absolute "$raw" || return
  if ! realpath -m -- "$raw"; then
    product_path_error "cannot canonicalize path: $raw"
    return 2
  fi
}

product_require_config_safe_path() {
  local path="$1"
  # VPP config values are tokenized paths.  Keep generated paths to the
  # portable absolute subset and reject whitespace/control/config metacharacters.
  if [[ ! "$path" =~ ^/[A-Za-z0-9._/-]+$ ]]; then
    product_path_error "unsafe VPP runtime/config path: $path"
    return 2
  fi
}

product_prepare_build_output() {
  local raw="$repo_root/build-output"
  local repo_canonical expected canonical
  if [[ -L "$raw" || ( -e "$raw" && ! -d "$raw" ) ]]; then
    product_path_error "product build-output must be a real directory: $raw"
    return 2
  fi
  if ! mkdir -p -- "$raw"; then
    product_path_error "cannot create product build-output directory: $raw"
    return 2
  fi
  repo_canonical="$(realpath -e -- "$repo_root")" || return 2
  expected="$repo_canonical/build-output"
  canonical="$(realpath -e -- "$raw")" || return 2
  if [[ "$canonical" != "$expected" || -L "$raw" ]]; then
    product_path_error "product build-output resolves outside this checkout: $raw"
    return 2
  fi
  product_require_config_safe_path "$canonical" || return
}

product_validate_product_root() {
  local raw="$1"
  local kind="$2"
  local build_output canonical base name
  if [[ ! -d "$repo_root/build-output" || -L "$repo_root/build-output" ]]; then
    product_path_error "product build-output directory is missing or unsafe"
    return 2
  fi
  if ! base="$(realpath -e -- "$repo_root")"; then
    product_path_error "repository root cannot be canonicalized"
    return 2
  fi
  build_output="$base/build-output"
  if ! base="$(realpath -e -- "$repo_root/build-output")" ||
     [[ "$base" != "$build_output" ]]; then
    product_path_error "product build-output resolves outside this checkout"
    return 2
  fi
  canonical="$(product_canonical_for_write "$raw")" || return
  if [[ "$canonical" == "$build_output" || "$canonical" != "$build_output/"* ]]; then
    product_path_error "product $kind must stay below $build_output: $raw"
    return 2
  fi
  if [[ -L "$raw" ]]; then
    product_path_error "product $kind path must not be a symlink: $raw"
    return 2
  fi
  name="$(basename -- "$canonical")"
  case "$kind:$name" in
    artifact:product-vpp-host|artifact:product-vpp-host-*) ;;
    runtime:product-vpp-runtime|runtime:product-vpp-runtime-*) ;;
    *)
      product_path_error "unexpected product $kind directory name: $raw"
      return 2
      ;;
  esac
  product_require_config_safe_path "$canonical" || return
  printf '%s\n' "$canonical"
}

product_validate_artifact_root() {
  product_validate_product_root "$1" artifact
}

product_validate_runtime_root() {
  product_validate_product_root "$1" runtime
}

product_validate_owned_child() {
  local root="$1"
  local name="$2"
  local candidate
  if [[ -z "$name" || "$name" == */* || "$name" == .* ]]; then
    product_path_error "invalid product-owned child name: $name"
    return 2
  fi
  candidate="$(realpath -m -- "$root/$name")" || return
  if [[ "$candidate" != "$root/$name" ]]; then
    product_path_error "product-owned child escapes runtime root: $name"
    return 2
  fi
  if [[ -L "$root/$name" ]]; then
    product_path_error "product-owned child must not be a symlink: $root/$name"
    return 2
  fi
  product_require_config_safe_path "$candidate" || return
  printf '%s\n' "$candidate"
}

product_require_within() {
  local base="$1"
  local candidate="$2"
  if [[ "$candidate" != "$base" && "$candidate" != "$base/"* ]]; then
    product_path_error "path is outside the validated root: $candidate"
    return 2
  fi
}
