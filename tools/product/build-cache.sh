#!/usr/bin/env bash
# Shared cache ownership/key boundary. Keep the lock in the calling shell until
# compilation and distribution assembly finish; never invoke via command substitution.
product_build_cache_helper_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

product_open_build_cache() {
  local namespace="$1" destination="$2"
  shift 2
  command -v flock >/dev/null 2>&1 || {
    echo "Product build cache: flock is required" >&2
    return 2
  }
  product_build_cache_dir="$(python3 "$product_build_cache_helper_dir/build-cache.py" \
    --repo-root "$repo_root" --namespace "$namespace" --destination "$destination" "$@")" || return
  exec {product_build_cache_lock_fd}>"$product_build_cache_dir/.build.lock" || return
  flock -x "$product_build_cache_lock_fd" || return
  printf 'buildCache=%s\nbuildCacheKey=%s\n' \
    "$product_build_cache_dir" "${product_build_cache_dir##*/}"
}

product_configure_cached() {
  local build="$1" arguments cache_hash state
  local cmake_program="${product_build_cache_cmake:-cmake}"
  shift
  arguments="$(printf '%s\0' "$cmake_program" "$@" | sha256sum | awk '{print $1}')"
  state="$build/.product-configure-identity"
  if [[ -f "$build/CMakeCache.txt" ]]; then
    cache_hash="$(sha256sum "$build/CMakeCache.txt" | awk '{print $1}')"
    if [[ -f "$state" && "$(cat "$state")" == "$arguments $cache_hash" ]]; then
      # Ninja still performs CMake's own dependency/glob checks. CLI options
      # and a manually altered CMakeCache must go through configure again.
      printf 'buildConfigure=reuse %s\n' "$build"
      return 0
    fi
  fi
  "$cmake_program" "$@" || return
  cache_hash="$(sha256sum "$build/CMakeCache.txt" | awk '{print $1}')"
  printf '%s %s\n' "$arguments" "$cache_hash" >"$state"
}
