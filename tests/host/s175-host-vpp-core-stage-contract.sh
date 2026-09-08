#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
stage_builder="$repo_root/src/product/vpp/host/build-stage.sh"
artifact_builder="$repo_root/tools/product/build-host-artifact.sh"
pin_file="$repo_root/src/product/vpp/pinned-vpp-revision.txt"
identity_file="$repo_root/src/product/vpp/product-vpp-artifact.properties"

fail() {
  echo "SAKAMOTO-175 Host VPP core stage contract: FAIL: $*" >&2
  exit 1
}

expect_fail_with() {
  local label="$1"
  local expected="$2"
  shift 2
  local output status

  set +e
  output="$("$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -ne 0 ]] || fail "$label was accepted"
  [[ "$output" == *"$expected"* ]] ||
    fail "$label did not report the expected identity failure: $output"
}

property() {
  local manifest="$1"
  local key="$2"
  local value
  value="$(sed -n "s/^${key}=//p" "$manifest")"
  [[ -n "$value" && "$value" != *$'\n'* ]] ||
    fail "$manifest must contain exactly one $key"
  printf '%s\n' "$value"
}

[[ -x "$stage_builder" ]] ||
  fail "missing executable public stage seam: $stage_builder"
[[ -x "$artifact_builder" ]] || fail "missing Host artifact builder"
bash -n "$stage_builder"
bash -n "$artifact_builder"

# The stage owns patch application and the only optional full VPP build.
# Artifact assembly is deliberately unable to build or accept an arbitrary
# source checkout or independently supplied install prefix.
grep -Fq 'apply-core.sh' "$stage_builder" ||
  fail "Host stage does not use the Product core patch seam"
grep -Fq -- '--source-dir' "$stage_builder" ||
  fail "Host stage has no explicit clean-source input"
grep -Fq -- '--stage-dir' "$stage_builder" ||
  fail "Host stage has no explicit owned-stage output"
grep -Fq 'BUILD_VPP_RUNTIME' "$stage_builder" ||
  fail "Host stage has no explicit first-full-build gate"
grep -Fq 'VPP_BUILD_PYTHON_API=OFF' "$stage_builder" ||
  fail "Host stage still depends on the unrelated pip-installed Python API"
grep -Fq '.sakamoto-product-vpp-stage-building' "$stage_builder" ||
  fail "Host stage cannot safely resume its owned incremental candidate"
grep -Fq 'VPP_HOST_STAGE_DIR' "$artifact_builder" ||
  fail "Host artifact builder does not consume the verified stage"
if grep -Eq '\$\{(VPP_SOURCE_DIR|VPP_INSTALL_PREFIX)(:|\})' "$artifact_builder"; then
  fail "Host artifact builder still accepts clean-base source/prefix inputs"
fi
if grep -Fq 'BUILD_VPP_RUNTIME' "$artifact_builder"; then
  fail "Host artifact builder still owns the full VPP build"
fi

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-s175-host-stage-contract.XXXXXX")"
cleanup() {
  rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

pin="$(tr -d '[:space:]' < "$pin_file")"
[[ "$pin" =~ ^[[:xdigit:]]{40}$ ]] || fail "invalid Product VPP pin"

# A clean base and install prefix are not an alternate artifact-builder API.
# The failure text is part of the public command-line contract and ensures the
# check happens before artifact cleanup or compilation.
expect_fail_with "clean-base source/prefix without a stage" \
  "VPP_HOST_STAGE_DIR is required" \
  env VPP_SOURCE_DIR="$tmp_dir/clean-base" \
      VPP_INSTALL_PREFIX="$tmp_dir/clean-prefix" \
      "$artifact_builder"

bad_stage="$tmp_dir/bad-stage"
mkdir -p "$bad_stage"
expect_fail_with "stage without an ownership marker" \
  "Host VPP stage marker is missing or invalid" \
  env VPP_HOST_STAGE_DIR="$bad_stage" "$artifact_builder"

printf '%s\n' 'sakamoto-product-vpp-stage-v1' \
  >"$bad_stage/.sakamoto-product-vpp-stage"
cat >"$bad_stage/host-vpp-stage.properties" <<EOF
schema=sakamoto-product-vpp-stage/v1
vpp.base.revision=0000000000000000000000000000000000000000
vpp.core.patch.count=4
vpp.core.patch.sha256=0d95c4e7e0144d57728bfa29e1f734fa6205dcc73a09929ebd4b57e8995bb72f
vpp.stage.profile=host
vpp.runtime.closure.sha256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
vpp.source.closure.sha256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
expect_fail_with "stage at the wrong base revision" \
  "Host VPP stage base revision mismatch" \
  env VPP_HOST_STAGE_DIR="$bad_stage" "$artifact_builder"

sed -i "s/^vpp.base.revision=.*/vpp.base.revision=$pin/" \
  "$bad_stage/host-vpp-stage.properties"
sed -i 's/^vpp.stage.profile=.*/vpp.stage.profile=android/' \
  "$bad_stage/host-vpp-stage.properties"
expect_fail_with "non-Host stage profile" \
  "Host VPP stage profile mismatch" \
  env VPP_HOST_STAGE_DIR="$bad_stage" "$artifact_builder"

sed -i 's/^vpp.stage.profile=.*/vpp.stage.profile=host/' \
  "$bad_stage/host-vpp-stage.properties"
sed -i \
  's/^vpp.core.patch.sha256=.*/vpp.core.patch.sha256=cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc/' \
  "$bad_stage/host-vpp-stage.properties"
expect_fail_with "stage with the wrong Product core identity" \
  "Host VPP stage core patch identity mismatch" \
  env VPP_HOST_STAGE_DIR="$bad_stage" "$artifact_builder"

expected_core_sha256="$(property "$identity_file" vpp.core.patch.sha256)"
sed -i \
  "s/^vpp.core.patch.sha256=.*/vpp.core.patch.sha256=$expected_core_sha256/" \
  "$bad_stage/host-vpp-stage.properties"
sed -i \
  's/^vpp.runtime.closure.sha256=.*/vpp.runtime.closure.sha256=not-a-digest/' \
  "$bad_stage/host-vpp-stage.properties"
expect_fail_with "stage with an invalid closure identity" \
  "Host VPP stage closure identity is invalid" \
  env VPP_HOST_STAGE_DIR="$bad_stage" "$artifact_builder"

# Dirty and wrong-revision source rejection belongs to the stage seam. It is
# cheap when the pinned official checkout is already available and otherwise
# remains part of formal Host evidence rather than fabricating a VPP tree.
source_dir="${SAKAMOTO_S175_VPP_SOURCE_DIR:-}"
if [[ -z "$source_dir" && -d /tmp/sakamoto-172-vpp-official.6CoCcd/source-git ]]; then
  source_dir=/tmp/sakamoto-172-vpp-official.6CoCcd/source-git
fi
if [[ -n "$source_dir" ]]; then
  source_dir="$(realpath -e -- "$source_dir")"
  [[ "$(git -C "$source_dir" rev-parse HEAD)" == "$pin" ]] ||
    fail "formal VPP source is not at the Product pin"
  [[ -z "$(git -C "$source_dir" status --porcelain=v1 --untracked-files=all)" ]] ||
    fail "formal VPP source must start clean"

  dirty_source="$tmp_dir/dirty-source"
  git clone --shared --no-checkout "$source_dir" "$dirty_source" >/dev/null 2>&1
  git -C "$dirty_source" checkout --detach "$pin" >/dev/null 2>&1
  dirty_path="$(git -C "$dirty_source" ls-files | sed -n '1p')"
  printf '\nSAKAMOTO-175 dirty source fixture\n' >>"$dirty_source/$dirty_path"
  expect_fail_with "dirty arbitrary source" \
    "source checkout must be clean" \
    "$stage_builder" --source-dir "$dirty_source" \
      --stage-dir "$tmp_dir/dirty-stage"

  wrong_source="$tmp_dir/wrong-source"
  git clone --shared --no-checkout "$source_dir" "$wrong_source" >/dev/null 2>&1
  git -C "$wrong_source" checkout --detach "$pin" >/dev/null 2>&1
  git -C "$wrong_source" -c user.name=contract \
    -c user.email=contract.invalid commit --allow-empty -m wrong-pin >/dev/null
  expect_fail_with "wrong-revision arbitrary source" \
    "source checkout is not at the pinned revision" \
    "$stage_builder" --source-dir "$wrong_source" \
      --stage-dir "$tmp_dir/wrong-stage"
fi

# A real first full build is explicit because it is expensive. The second call
# must reuse the same verified identity without another full build. The Host
# artifact then has to carry the stage's core/source/runtime closure identity.
if [[ "${SAKAMOTO_S175_RUN_FULL_STAGE:-0}" == 1 ]]; then
  [[ -n "$source_dir" ]] ||
    fail "SAKAMOTO_S175_RUN_FULL_STAGE=1 requires SAKAMOTO_S175_VPP_SOURCE_DIR"
  stage_dir="$tmp_dir/formal-stage"
  first_log="$tmp_dir/first-stage.log"
  reuse_log="$tmp_dir/reuse-stage.log"

  BUILD_VPP_RUNTIME=1 "$stage_builder" \
    --source-dir "$source_dir" --stage-dir "$stage_dir" >"$first_log"
  grep -Fxq 'stageDisposition=built' "$first_log" ||
    fail "first full stage build did not report built"
  "$stage_builder" \
    --source-dir "$source_dir" --stage-dir "$stage_dir" >"$reuse_log"
  grep -Fxq 'stageDisposition=reused' "$reuse_log" ||
    fail "same-identity stage was not reused incrementally"

  marker="$stage_dir/.sakamoto-product-vpp-stage"
  manifest="$stage_dir/host-vpp-stage.properties"
  [[ "$(tr -d '\r\n' < "$marker")" == sakamoto-product-vpp-stage-v1 ]] ||
    fail "formal stage ownership marker is invalid"
  [[ "$(property "$manifest" schema)" == sakamoto-product-vpp-stage/v1 ]] ||
    fail "formal stage schema is invalid"
  [[ "$(property "$manifest" vpp.base.revision)" == "$pin" ]] ||
    fail "formal stage lost its base revision"
  [[ "$(property "$manifest" vpp.core.patch.count)" == 4 ]] ||
    fail "formal stage lost its core patch count"
  [[ "$(property "$manifest" vpp.stage.profile)" == host ]] ||
    fail "formal stage is not the Host profile"
  for key in \
    vpp.core.patch.sha256 \
    vpp.runtime.closure.sha256 \
    vpp.source.closure.sha256; do
    [[ "$(property "$manifest" "$key")" =~ ^[[:xdigit:]]{64}$ ]] ||
      fail "formal stage $key is not a SHA-256 identity"
  done

  artifact_dir="$repo_root/build-output/product-vpp-host-s175-stage-contract"
  VPP_HOST_STAGE_DIR="$stage_dir" PRODUCT_ARTIFACT_DIR="$artifact_dir" \
    "$artifact_builder" >/dev/null
  installed="$artifact_dir/product-vpp-artifact.properties"
  for key in \
    vpp.core.patch.count \
    vpp.core.patch.sha256 \
    vpp.runtime.closure.sha256 \
    vpp.source.closure.sha256; do
    [[ "$(property "$installed" "$key")" == "$(property "$manifest" "$key")" ]] ||
      fail "installed artifact did not preserve stage identity: $key"
  done
fi

echo "SAKAMOTO-175 Host VPP core stage contract: PASS"
