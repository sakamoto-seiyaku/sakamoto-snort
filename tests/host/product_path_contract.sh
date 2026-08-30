#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
helpers="$repo_root/tools/product/path-helpers.sh"
source "$helpers"
product_prepare_build_output
suffix="$$"
runtime_root="$repo_root/build-output/product-vpp-runtime-path-contract-$suffix"
runtime_link="$repo_root/build-output/product-vpp-runtime-path-link-$suffix"
vpp_source_fixture="$(mktemp -d /tmp/sakamoto-product-vpp-source.XXXXXX)"
multiarch_prefix="$vpp_source_fixture/build-root/install-vpp-native/vpp"
outside_library_dir="$(mktemp -d /tmp/sakamoto-product-vpp-external-lib.XXXXXX)"
foreign_source="$(mktemp -d /tmp/sakamoto-product-vpp-foreign-source.XXXXXX)"
escape_source="$(mktemp -d /tmp/sakamoto-product-vpp-escape-source.XXXXXX)"
cleanup() {
  rm -rf -- "$runtime_root" "$runtime_link"
  rm -rf -- "$vpp_source_fixture" "$outside_library_dir" \
    "$foreign_source" "$escape_source"
}
trap cleanup EXIT
mkdir -p "$runtime_root"

set +e
product_validate_runtime_root "$repo_root/../unsafe-runtime" >/dev/null 2>&1
unsafe_status=$?
product_validate_runtime_root "$repo_root/build-output/product-vpp-runtime unsafe-$suffix" \
  >/dev/null 2>&1
space_status=$?
product_validate_owned_child "$runtime_root" ../escape >/dev/null 2>&1
escape_status=$?
set -e
if [[ "$unsafe_status" -ne 2 || "$space_status" -ne 2 || "$escape_status" -ne 2 ]]; then
  echo "unsafe product path was accepted" >&2
  exit 1
fi

ln -s "$runtime_root" "$runtime_link"
set +e
product_validate_runtime_root "$runtime_link" >/dev/null 2>&1
link_status=$?
set -e
if [[ "$link_status" -ne 2 ]]; then
  echo "symlinked product runtime path was accepted" >&2
  exit 1
fi

# Official GNUInstallDirs installs may place VPP libraries under a target
# multiarch directory. Resolve only a directory identified by the installed
# VPP CMake package and libvapiclient, never an arbitrary external override.
multiarch_lib="$multiarch_prefix/lib/x86_64-linux-gnu"
mkdir -p "$multiarch_prefix/lib" "$multiarch_prefix/bin" \
  "$multiarch_prefix/include" "$multiarch_lib/cmake/vpp"
touch "$multiarch_lib/cmake/vpp/VPPConfig.cmake" \
  "$multiarch_lib/libvapiclient.so.26.02"
ln -s libvapiclient.so.26.02 "$multiarch_lib/libvapiclient.so"

validated_prefix="$(product_validate_host_vpp_install_prefix \
  "$vpp_source_fixture" "$multiarch_prefix")"
if [[ "$validated_prefix" != "$multiarch_prefix" ]]; then
  echo "source-owned official Host VPP prefix was not validated" >&2
  exit 1
fi

mkdir -p "$foreign_source/build-root/install-vpp-native/vpp"
set +e
product_validate_host_vpp_install_prefix \
  "$foreign_source" "$multiarch_prefix" >/dev/null 2>&1
foreign_source_status=$?
product_validate_host_vpp_install_prefix \
  "$vpp_source_fixture" "$outside_library_dir" >/dev/null 2>&1
external_prefix_status=$?
mkdir -p "$escape_source/build-root/install-vpp-native"
ln -s "$outside_library_dir" \
  "$escape_source/build-root/install-vpp-native/vpp"
product_validate_host_vpp_install_prefix \
  "$escape_source" "$outside_library_dir" >/dev/null 2>&1
escape_prefix_status=$?
set -e
if [[ "$foreign_source_status" -ne 2 || "$external_prefix_status" -ne 2 ||
      "$escape_prefix_status" -ne 2 ]]; then
  echo "unproven or escaping Host VPP install prefix was accepted" >&2
  exit 1
fi

resolved_lib="$(product_resolve_vpp_library_dir "$multiarch_prefix" "")"
if [[ "$resolved_lib" != "$multiarch_lib" ]]; then
  echo "official multiarch VPP library directory was not resolved" >&2
  exit 1
fi
if [[ "$(product_resolve_vpp_library_dir \
    "$multiarch_prefix" "$multiarch_lib")" != "$multiarch_lib" ]]; then
  echo "matching explicit multiarch VPP library directory was rejected" >&2
  exit 1
fi

touch "$outside_library_dir/libvapiclient.so"
set +e
product_resolve_vpp_library_dir \
  "$multiarch_prefix" "$outside_library_dir" >/dev/null 2>&1
external_library_status=$?
set -e
if [[ "$external_library_status" -ne 2 ]]; then
  echo "external VPP library override was accepted" >&2
  exit 1
fi

ambiguous_lib="$multiarch_prefix/lib/aarch-linux-gnu"
mkdir -p "$ambiguous_lib/cmake/vpp"
touch "$ambiguous_lib/cmake/vpp/VPPConfig.cmake" \
  "$ambiguous_lib/libvapiclient.so"
set +e
product_resolve_vpp_library_dir "$multiarch_prefix" "" >/dev/null 2>&1
ambiguous_library_status=$?
set -e
if [[ "$ambiguous_library_status" -ne 2 ]]; then
  echo "ambiguous VPP library directories were accepted" >&2
  exit 1
fi

echo "sakamoto product path contract: PASS"
