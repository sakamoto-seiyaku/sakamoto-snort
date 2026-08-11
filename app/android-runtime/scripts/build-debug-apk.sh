#!/usr/bin/env bash
set -euo pipefail

# Production-incubator build. The VPP stage is an explicit artifact input;
# this script never falls back to the reconstructed raw daemon.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"
repo_root="$(cd -- "${app_dir}/../.." && pwd)"
default_stage_dir="${repo_root}/build-output/android-vpp-runtime/stage"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-$default_stage_dir}"
stage_dir_explicit=0
if [[ -n "${VPP_RUNTIME_STAGE_DIR+x}" ]]; then
  stage_dir_explicit=1
fi
default_hev_stage_dir="${repo_root}/experiments/vpp-nfq-poc/work/android-hev-stage"
hev_stage_dir="${HEV_STAGE_DIR:-$default_hev_stage_dir}"
hev_stage_explicit=0
if [[ -n "${HEV_STAGE_DIR+x}" ]]; then
  hev_stage_explicit=1
fi
sdk_prebuilts="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
android_jar="${ANDROID_JAR:-${sdk_prebuilts}/36/public/android.jar}"
aapt2="${AAPT2:-${sdk_prebuilts}/tools/linux/bin/aapt2}"
d8_jar="${D8_JAR:-${sdk_prebuilts}/tools/linux/lib/d8.jar}"
apksigner_jar="${APKSIGNER_JAR:-${sdk_prebuilts}/tools/linux/lib/apksigner.jar}"
zipalign_bin="${ZIPALIGN:-zipalign}"

die() { echo "error: $*" >&2; exit 1; }

required_stage_artifacts=(
  "$stage_dir/bin/vpp"
  "$stage_dir/bin/vppctl"
)
provenance_file="$stage_dir/runtime/source-provenance.properties"
stage_has_required_artifacts() {
  local file
  for file in "${required_stage_artifacts[@]}"; do
    [[ -f "$file" ]] || return 1
  done
}

# The default stage is produced by the repository-local POC staging pipeline.
# Run that boundary on every default build so it can refresh a stage when its
# configured source/build output is newer. An explicitly selected stage is
# never replaced or supplemented implicitly: callers must provide both real
# core artifacts and the stage's explicit build inputs themselves.
if [[ "$stage_dir_explicit" == 0 ]]; then
  stage_script="$repo_root/experiments/vpp-nfq-poc/android/vpn-lite/scripts/stage-vpp-runtime.sh"
  [[ -f "$stage_script" ]] || die "default runtime stage is incomplete and stage builder is absent: $stage_script"
  VPP_RUNTIME_STAGE_DIR="$stage_dir" bash "$stage_script"
fi
stage_has_required_artifacts \
  || die "runtime stage is missing VPP core diagnostics: $stage_dir"
hev_lib="$hev_stage_dir/lib/arm64-v8a/libhev-socks5-tunnel.so"
ndk_daemon="$repo_root/build-output/apk-native/lib/arm64-v8a/libsucre_snortd.so"
if [[ "$hev_stage_explicit" == 0 && ! -f "$hev_lib" ]]; then
  hev_build_script="$repo_root/experiments/vpp-nfq-poc/scripts/android-build-hev.sh"
  [[ -f "$hev_build_script" ]] || die "default HEV stage is incomplete and builder is absent: $hev_build_script"
  STAGE_DIR="$hev_stage_dir" bash "$hev_build_script"
fi
(cd "$repo_root" && cmake --build --preset dev-debug --target snort-build-ndk)

for file in "$android_jar" "$aapt2" "$d8_jar" "$apksigner_jar" \
    "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl" "$hev_lib" "$ndk_daemon"; do
  [[ -f "$file" ]] || die "missing required build input: $file"
done
[[ -f "$provenance_file" ]] || die "runtime stage provenance is missing: $provenance_file"
grep -Fqx 'conditionalWakeSource=absent' "$provenance_file" \
  || die "runtime stage source provenance is not a clean-core proof"
grep -Fqx 'conditionalWakeBinary=absent' "$provenance_file" \
  || die "runtime stage binary provenance is not a clean-core proof"
for artifact in "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl"; do
  if strings "$artifact" | grep -Eq 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
    die "runtime stage contains rejected conditional-wake symbols: $artifact"
  fi
done
command -v javac >/dev/null || die "missing javac"
command -v java >/dev/null || die "missing java"
command -v keytool >/dev/null || die "missing keytool"
command -v zip >/dev/null || die "missing zip"
command -v flock >/dev/null || die "missing flock"
command -v "$zipalign_bin" >/dev/null || die "missing zipalign: $zipalign_bin"

build_dir="$app_dir/build"
lock_dir="$repo_root/build-output/android-runtime-locks"
mkdir -p "$lock_dir"
build_variant="${ANDROID_RUNTIME_BUILD_VARIANT:-debug}"
case "$build_variant" in
  debug|release-candidate)
    ;;
  *)
    die "unsupported Android runtime build variant: $build_variant"
    ;;
esac
exec 9>"$lock_dir/build-${build_variant}-apk.lock"
flock 9
signing_dir="${ANDROID_RUNTIME_SIGNING_DIR:-$repo_root/build-output/android-runtime-signing}"
signing_keystore="${ANDROID_RUNTIME_SIGNING_KEYSTORE:-$signing_dir/debug.keystore}"
signing_alias="${ANDROID_RUNTIME_SIGNING_ALIAS:-androiddebugkey}"
signing_dname="${ANDROID_RUNTIME_SIGNING_DNAME:-CN=Android Debug,O=sakamoto,C=US}"
apk_version_name_default="0.1-runtime-debug"
apk_output_name="sakamoto-runtime-debug.apk"
if [[ "$build_variant" == "release-candidate" ]]; then
  apk_version_name_default="0.1-runtime-release-candidate"
  apk_output_name="sakamoto-runtime-release-candidate.apk"
fi
classes_dir="$build_dir/classes"
dex_dir="$build_dir/dex"
dex_work_dir="$build_dir/dex.$$"
jni_dir="$build_dir/jni/lib/arm64-v8a"
assets_dir="$build_dir/assets"
intermediates="$build_dir/intermediates"
outputs="$build_dir/outputs"
rm -rf "$classes_dir" "$dex_dir" "$dex_work_dir" "$build_dir/jni" "$assets_dir" \
    "$intermediates" "$outputs"
mkdir -p "$classes_dir" "$jni_dir" "$assets_dir" "$intermediates" "$outputs"
mkdir -p "$signing_dir"

cp "$stage_dir/bin/vpp" "$jni_dir/libvpp_runtime.so"
cp "$stage_dir/bin/vppctl" "$jni_dir/libvppctl.so"
chmod 755 "$jni_dir/libvpp_runtime.so" "$jni_dir/libvppctl.so"
if strings "$jni_dir/libvpp_runtime.so" | grep -Eq 'wakeup_epoch|vlib_frame_queue_wakeup_mode|VLIB_WAKE_PHASE'; then
  die "packaged VPP core contains rejected conditional-wake symbols"
fi
for so in "$stage_dir"/lib/*.so; do
  [[ -f "$so" ]] || continue
  cp "$so" "$jni_dir/$(basename "$so")"
  chmod 755 "$jni_dir/$(basename "$so")"
done
cp "$hev_lib" "$jni_dir/libhev-socks5-tunnel.so"
chmod 755 "$jni_dir/libhev-socks5-tunnel.so"
cp "$ndk_daemon" "$jni_dir/libsucre_snortd.so"
chmod 755 "$jni_dir/libsucre_snortd.so"

# Build the committed core control boundary against the generated VPE VAPI.
# The generated headers and libvapiclient are build inputs, never runtime
# packet adapters. They prove the running VPP binary through show_version.
native_dir="$app_dir/src/main/native"
vpp_source="${VPP_SOURCE_TREE:-}"
if [[ -z "$vpp_source" && -f "$provenance_file" ]]; then
  vpp_source="$(awk -F= '$1 == "sourceTree" {print substr($0, index($0, "=") + 1); exit}' \
    "$provenance_file")"
fi
vpp_source="${vpp_source:-$repo_root/experiments/vpp-nfq-poc/work/vpp}"

source_tree_sha256() {
  local tree="$1"
  (
    cd -- "$tree"
    find . -type f -print0 | sort -z | xargs -0 -r sha256sum
  ) | sha256sum | awk '{print $1}'
}

# A pinned revision marker is not sufficient provenance: an extracted source
# archive can be edited while retaining that marker.  Require the source
# origin to contain the pinned commit, verify the marker, and compare the
# complete post-overlay tree digest recorded by the staging boundary.
expected_source_revision="${VPP_RUNTIME_SOURCE_REVISION:-9258530f3804a152578ce11cc7c8a1e9eab88ed0}"
provenance_value() {
  local key="$1"
  awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' \
    "$provenance_file"
}
source_revision="$(provenance_value sourceRevision)"
source_status="$(provenance_value sourceStatus)"
source_tree="$(provenance_value sourceTree)"
source_origin="$(provenance_value sourceOrigin)"
recorded_source_tree_digest="$(provenance_value sourceTreeSha256)"
recorded_base_archive_digest="$(provenance_value baseArchiveSha256)"
recorded_base_tree_digest="$(provenance_value baseTreeSha256)"
recorded_overlay_digest="$(provenance_value overlaySha256)"
overlay_script="$repo_root/experiments/vpp-nfq-poc/scripts/apply-vpp-android-overlay.sh"
[[ -f "$overlay_script" ]] || die "repository VPP overlay script is missing: $overlay_script"
actual_overlay_digest="$(sha256sum "$overlay_script" | awk '{print $1}')"
[[ "$source_revision" == "$expected_source_revision" ]] \
  || die "runtime stage source revision is not the pinned product revision: $source_revision"
[[ "$source_status" == "committed-snapshot" ]] \
  || die "runtime stage source provenance is not a committed snapshot: $source_status"
[[ -d "$source_tree" ]] || die "runtime stage source snapshot is missing: $source_tree"
marker="$source_tree/.sakamoto-source-revision"
[[ -f "$marker" ]] && [[ "$(tr -d '[:space:]' <"$marker")" == "$source_revision" ]] \
  || die "runtime stage source snapshot marker does not match pinned revision"
[[ "$source_origin" == git:*@"$source_revision" ]] \
  || die "runtime stage source origin is not bound to the pinned revision"
source_origin_repo="${source_origin#git:}"
source_origin_repo="${source_origin_repo%@${source_revision}}"
[[ -d "$source_origin_repo" ]] \
  || die "runtime stage source origin repository is missing: $source_origin_repo"
git -C "$source_origin_repo" cat-file -e "$source_revision^{commit}" 2>/dev/null \
  || die "runtime stage source origin cannot prove pinned commit: $source_revision"
[[ "$recorded_base_archive_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "runtime stage base archive digest is missing from provenance"
[[ "$recorded_base_tree_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "runtime stage base tree digest is missing from provenance"
[[ "$recorded_overlay_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "runtime stage overlay digest is missing from provenance"
if [[ "$stage_dir_explicit" == 1 && "$recorded_overlay_digest" != "$actual_overlay_digest" ]]; then
  die "runtime stage overlay digest does not match the repository overlay script"
fi
actual_base_archive_digest="$(git -C "$source_origin_repo" archive --format=tar --prefix=./ \
  "$source_revision" | sha256sum | awk '{print $1}')"
[[ "$actual_base_archive_digest" == "$recorded_base_archive_digest" ]] \
  || die "runtime stage pinned base archive changed after provenance was recorded"
base_probe_dir="$(mktemp -d /tmp/sakamoto-vpp-base-archive.XXXXXX)"
git -C "$source_origin_repo" archive --format=tar --prefix=./ "$source_revision" \
  | tar -x -C "$base_probe_dir"
printf '%s\n' "$source_revision" >"$base_probe_dir/.sakamoto-source-revision"
actual_base_tree_digest="$(source_tree_sha256 "$base_probe_dir")"
rm -rf -- "$base_probe_dir"
[[ "$actual_base_tree_digest" == "$recorded_base_tree_digest" ]] \
  || die "runtime stage extracted base tree changed after provenance was recorded"
[[ "$recorded_source_tree_digest" =~ ^[0-9a-fA-F]{64}$ ]] \
  || die "runtime stage source tree digest is missing from provenance"
actual_source_tree_digest="$(source_tree_sha256 "$source_tree")"
[[ "$actual_source_tree_digest" == "$recorded_source_tree_digest" ]] \
  || die "runtime stage source tree changed after provenance was recorded"

vapi_build_dir="${VPP_RUNTIME_VAPI_BUILD_DIR:-}"
if [[ -z "$vapi_build_dir" && -f "$stage_dir/runtime/vapi-build-dir" ]]; then
  vapi_build_dir="$(tr -d '[:space:]' <"$stage_dir/runtime/vapi-build-dir")"
fi
vapi_build_dir="${vapi_build_dir:-$repo_root/experiments/vpp-nfq-poc/work/vpp-android-configure-probe}"
vapi_header="$vapi_build_dir/CMakeFiles/vpp-api/vapi/vpe.api.vapi.h"
vapi_lib_dir="$vapi_build_dir/lib/aarch64-linux-android"
[[ -f "$native_dir/sakamoto_vpp_control.c" && -f "$native_dir/sakamoto_vpp_control_jni.c" ]] \
  || die "missing committed native core control source"
[[ -f "$native_dir/sakamoto_vpn_transport_jni.c" ]] \
  || die "missing committed native VPN transport source"
[[ -f "$vapi_header" ]] || die "generated VPE VAPI header is missing: $vapi_header"
for vapi_lib in libvapiclient.so libvlibmemoryclient.so; do
  [[ -f "$vapi_lib_dir/$vapi_lib" ]] \
    || die "generated VAPI client library is missing: $vapi_lib_dir/$vapi_lib"
  cp "$vapi_lib_dir/$vapi_lib" "$jni_dir/$vapi_lib"
  chmod 755 "$jni_dir/$vapi_lib"
done
api_identity="$(grep -E 'name_with_crc.*"show_version_[0-9a-fA-F]{8}"' "$vapi_header" \
  | head -n 1 | cut -d'"' -f2)"
[[ "$api_identity" =~ ^show_version_[0-9a-fA-F]{8}$ ]] \
  || die "unable to extract generated show_version API identity"
ndk_root="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
control_clang="${ANDROID_CLANG:-$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang}"
[[ -x "$control_clang" ]] || die "Android clang is missing: $control_clang"
"$control_clang" -shared -fPIC -std=c11 -Wall -Wextra \
  -DSAKAMOTO_VPP_CONTROL_API_IDENTITY=\"$api_identity\" \
  -I"$native_dir" -I"$vpp_source/src" -I"$vpp_source/src/vpp-api" \
  -I"$vapi_build_dir/CMakeFiles/vpp-api" \
  "$native_dir/sakamoto_vpp_control.c" \
  "$native_dir/sakamoto_vpp_control_jni.c" \
  -L"$jni_dir" -Wl,-rpath,'$ORIGIN' -Wl,-soname,libsakamoto_runtime_control.so \
  -lvapiclient -ldl -lm -o "$jni_dir/libsakamoto_runtime_control.so"
chmod 755 "$jni_dir/libsakamoto_runtime_control.so"
"$control_clang" -shared -fPIC -std=c11 -Wall -Wextra -pthread \
  -I"$native_dir" \
  "$native_dir/sakamoto_vpn_transport_jni.c" \
  -llog -ldl -o "$jni_dir/libsakamoto_vpn_transport.so"
chmod 755 "$jni_dir/libsakamoto_vpn_transport.so"

version="${VPP_RUNTIME_VERSION:-$(strings "$stage_dir/bin/vpp" \
    | awk '/vpp v[0-9]/{if (!found) {print $2; found=1}}') }"
version="$(printf '%s' "$version" | tr -d '[:space:]')"
[[ "$version" =~ ^v[0-9]+\.[0-9]+ ]] || die "unable to determine VPP version"
artifact="sha256:$(sha256sum "$jni_dir/libvpp_runtime.so" | awk '{print $1}')"
printf 'version=%s\nabi=arm64-v8a\nprotocol=vpp-runtime-health/v1\nartifact=%s\n' \
  "$version" "$artifact" >"$assets_dir/vpp-runtime.properties"
printf 'apiIdentity=%s\n' "$api_identity" >>"$assets_dir/vpp-runtime.properties"
for key in sourceRevision sourceOrigin sourceTree sourceStatus baseArchiveSha256 \
    baseTreeSha256 overlaySha256 sourceTreeSha256 conditionalWakeSource \
    conditionalWakeBinary vppSha256 vppctlSha256; do
  value="$(awk -F= -v wanted="$key" '$1 == wanted {print substr($0, index($0, "=") + 1); exit}' \
    "$provenance_file")"
  [[ -n "$value" ]] || die "runtime stage provenance is missing key: $key"
  printf '%s=%s\n' "$key" "$value" >>"$assets_dir/vpp-runtime.properties"
done
cp "$provenance_file" "$assets_dir/vpp-runtime-provenance.properties"
printf '%s\n' "${artifact#sha256:}" >"$assets_dir/vpp-runtime.sha256"
sha256sum "$jni_dir/libsucre_snortd.so" | awk '{print $1}' \
  >"$assets_dir/sucre-snortd.sha256"

mapfile -t sources < <(find "$app_dir/src/main/java" -name '*.java' | sort)
javac -Xlint:-options -source 8 -target 8 -classpath "$android_jar" -d "$classes_dir" "${sources[@]}"
mapfile -t class_files < <(find "$classes_dir" -name '*.class' | sort)
mkdir -p "$dex_work_dir"
java -cp "$d8_jar" com.android.tools.r8.D8 --min-api 31 --lib "$android_jar" \
  --output "$dex_work_dir" "${class_files[@]}"
rm -rf "$dex_dir"
mv "$dex_work_dir" "$dex_dir"

base_apk="$intermediates/base.apk"
unsigned_apk="$intermediates/unsigned.apk"
aligned_apk="$intermediates/aligned.apk"
apk="$outputs/$apk_output_name"
manifest_for_build="$intermediates/AndroidManifest.xml"
if [[ "$build_variant" == "release-candidate" ]]; then
  sed 's/android:debuggable="true"/android:debuggable="false"/' \
    "$app_dir/src/main/AndroidManifest.xml" >"$manifest_for_build"
else
  cp "$app_dir/src/main/AndroidManifest.xml" "$manifest_for_build"
fi
aapt_args=(
  link -o "$base_apk" -I "$android_jar"
  --manifest "$manifest_for_build" --min-sdk-version 31
  --target-sdk-version 36 --version-code "${APK_VERSION_CODE:-1}" \
  --version-name "${APK_VERSION_NAME:-$apk_version_name_default}"
)
if [[ "$build_variant" == "debug" ]]; then
  aapt_args+=(--debug-mode)
fi
"$aapt2" "${aapt_args[@]}"
cp "$base_apk" "$unsigned_apk"
(cd "$dex_dir" && zip -q -r "$unsigned_apk" classes.dex)
(cd "$build_dir/jni" && zip -q -r "$unsigned_apk" lib)
(cd "$build_dir" && zip -q -r "$unsigned_apk" assets)
if [[ ! -f "$signing_keystore" ]]; then
  keytool -genkeypair -keystore "$signing_keystore" -storepass android \
    -keypass android -alias "$signing_alias" -keyalg RSA -keysize 2048 \
    -validity 10000 -dname "$signing_dname" >/dev/null
fi
"$zipalign_bin" -f -p 4 "$unsigned_apk" "$aligned_apk"
java -jar "$apksigner_jar" sign --ks "$signing_keystore" \
  --ks-pass pass:android --key-pass pass:android --ks-key-alias "$signing_alias" \
  --out "$apk" "$aligned_apk"
java -jar "$apksigner_jar" verify --print-certs "$apk" >/dev/null
echo "ok: $apk"
