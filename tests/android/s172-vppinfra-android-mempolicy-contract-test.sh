#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
profile_module="$repo_root/src/product/vpp/android/apply-profile.sh"
pinned_revision="$(tr -d '[:space:]' < "$pin_file")"
expected_patch_series_count=15
expected_patch_series_sha256=96417ad8655f0c8d39a256aaaaf40d3661c9f8599ae1418450f80b25fd9b91bf
source_dir="${SAKAMOTO_S172_VPP_SOURCE_DIR:-/tmp/sakamoto-172-vpp-official.6CoCcd/source-git}"
stage_dir="${SAKAMOTO_S172_VPP_STAGE_DIR:-/tmp/sakamoto-172-clean-vpp-stage}"
ndk_root="${SAKAMOTO_S172_ANDROID_NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
llvm_readelf="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"
llvm_objdump="$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objdump"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-mempolicy-contract.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT

fail() {
  echo "s172 vppinfra Android mempolicy contract: $*" >&2
  exit 1
}

[[ -f "$pin_file" ]] || fail "pinned revision file is missing"
[[ "$pinned_revision" =~ ^[[:xdigit:]]{40}$ ]] || \
  fail "pinned VPP revision is not a 40-character commit"
[[ -x "$profile_module" ]] || fail "Android VPP profile module is missing"
[[ -x "$llvm_readelf" ]] || fail "NDK llvm-readelf is missing"
[[ -x "$llvm_objdump" ]] || fail "NDK llvm-objdump is missing"

canonical_source_dir="$(realpath -e "$source_dir" 2>/dev/null)" || \
  fail "official VPP source cannot be canonicalized"
source_dir="$canonical_source_dir"
case "${source_dir,,}" in
  *experiments*|*poc*) fail "POC/experiment source is not permitted" ;;
esac
[[ -d "$source_dir/.git" || -f "$source_dir/.git" ]] || \
  fail "official VPP source checkout is missing"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pinned_revision" ]] || \
  fail "official VPP source is not at the exact product pin"
[[ -z "$(git -C "$source_dir" status --porcelain)" ]] || \
  fail "official VPP source must remain clean"

artifact="$(realpath -e "$stage_dir/lib/libvppinfra.so" 2>/dev/null)" || \
  fail "staged libvppinfra.so is missing"
case "${artifact,,}" in
  *experiments*|*poc*) fail "POC/experiment artifact is not permitted" ;;
esac
file -Lb "$artifact" | grep -Fq 'ARM aarch64' || \
  fail "staged libvppinfra.so is not a real AArch64 ELF"

symbol_range() {
  local symbol="$1"
  "$llvm_readelf" -Ws "$artifact" |
    awk -v symbol="$symbol" '$8 == symbol { print $2, $3; exit }'
}

disassemble_symbol() {
  local symbol="$1"
  local range start size stop
  range="$(symbol_range "$symbol")"
  [[ -n "$range" ]] || fail "staged libvppinfra.so is missing symbol $symbol"
  read -r start size <<<"$range"
  [[ "$start" =~ ^[[:xdigit:]]+$ && "$size" =~ ^[0-9]+$ ]] || \
    fail "invalid ELF range for $symbol: $range"
  stop="$(printf '0x%x' $((16#$start + size)))"
  "$llvm_objdump" -d --no-show-raw-insn \
    --start-address="0x$start" --stop-address="$stop" "$artifact"
}

forbidden_mempolicy_syscalls() {
  local symbol="$1"
  local disassembly="$2"
  local syscall_number
  for syscall_number in 0xec 0xed 0xef; do
    if grep -Eiq "mov[[:space:]]+w0,[[:space:]]+#${syscall_number}([[:space:]]|$)" \
        <<<"$disassembly"; then
      mempolicy_violations+="$symbol still materializes forbidden Android mempolicy syscall $syscall_number"$'\n'
    fi
  done
}

# This is the real artifact seam: comments or source-only guards cannot make
# this pass when an AArch64 shared object still contains the raw syscall
# numbers in the functions reached by the Android startup/pmalloc paths.
mempolicy_violations=""
main_init_disassembly="$(disassemble_symbol clib_mem_main_init)"
page_stats_disassembly="$(disassemble_symbol clib_mem_get_page_stats)"
numa_disassembly="$(disassemble_symbol clib_mem_set_numa_affinity)"
default_numa_disassembly="$(disassemble_symbol clib_mem_set_default_numa_affinity)"

forbidden_mempolicy_syscalls clib_mem_main_init "$main_init_disassembly"
forbidden_mempolicy_syscalls clib_mem_get_page_stats "$page_stats_disassembly"
forbidden_mempolicy_syscalls clib_mem_set_numa_affinity "$numa_disassembly"
forbidden_mempolicy_syscalls clib_mem_set_default_numa_affinity \
  "$default_numa_disassembly"
if [[ -n "$mempolicy_violations" ]]; then
  printf '%s' "$mempolicy_violations" >&2
  fail "staged libvppinfra.so still materializes Android mempolicy syscalls"
fi

grep -Eiq 'mov[[:space:]]+w0,[[:space:]]+#0x117([[:space:]]|$)' \
  <<<"$main_init_disassembly" || \
  fail "clib_mem_main_init lost the ordinary memfd_create syscall path"
grep -Eiq 'bl[[:space:]]+.*syscall@plt' <<<"$main_init_disassembly" || \
  fail "clib_mem_main_init lost its memfd_create syscall call"
map_disassembly="$(disassemble_symbol clib_mem_vm_map_internal)"
grep -Eiq 'bl[[:space:]]+.*mmap@plt' <<<"$map_disassembly" || \
  fail "clib_mem_vm_map_internal lost ordinary mmap"
create_fd_disassembly="$(disassemble_symbol clib_mem_vm_create_fd)"
grep -Eiq 'mov[[:space:]]+w0,[[:space:]]+#0x117([[:space:]]|$)' \
  <<<"$create_fd_disassembly" || \
  fail "clib_mem_vm_create_fd lost the ordinary memfd_create syscall path"

echo "artifact check: mempolicy syscall materialization is absent from the staged artifact"

# Fast source-patch contract.  The artifact checks above intentionally run
# first so the old stage gives a useful RED even before the source guard is
# present.  This source check remains a quick review aid; it is not a
# replacement for the final ELF inspection.
patched_tree="$work_dir/patched-source"
bash "$profile_module" \
  --profile android-api31-arm64 \
  --source-dir "$source_dir" \
  --work-dir "$patched_tree" >"$work_dir/profile.log"
grep -Fxq "patchSeriesCount=$expected_patch_series_count" "$work_dir/profile.log" || \
  fail "profile did not report the ordered patch count"
grep -Fxq "patchSeriesSha256=$expected_patch_series_sha256" "$work_dir/profile.log" || \
  fail "profile did not report the ordered patch hash"
mem_source="$patched_tree/src/vppinfra/linux/mem.c"
[[ -f "$mem_source" ]] || fail "patched vppinfra linux/mem.c is missing"
grep -Fq 'mm->numa_node_bitmap = 1;' "$mem_source" || \
  fail "Android NUMA node-0 source guard is missing"
grep -Fq 'stats->unknown = n_pages;' "$mem_source" || \
  fail "Android page-stats unknown result is missing"
grep -Fq 'syscall (__NR_memfd_create' "$mem_source" || \
  fail "ordinary memfd_create source path is missing"
grep -Fq 'MAP_PRIVATE | MAP_ANONYMOUS' "$mem_source" || \
  fail "ordinary anonymous mmap source path is missing"

echo "s172 vppinfra Android mempolicy contract: PASS"
