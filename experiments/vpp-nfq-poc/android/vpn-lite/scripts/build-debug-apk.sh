#!/usr/bin/env bash
set -euo pipefail

# Active SAKAMOTO-46 APK build: package one VPP runtime and its dependencies.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="$(cd -- "${script_dir}/.." && pwd)"
poc_dir="$(cd -- "${app_dir}/../.." && pwd)"
repo_root="$(cd -- "${poc_dir}/../.." && pwd)"
sdk_prebuilts="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
android_jar="${ANDROID_JAR:-${sdk_prebuilts}/36/public/android.jar}"
aapt2="${AAPT2:-${sdk_prebuilts}/tools/linux/bin/aapt2}"
d8_jar="${D8_JAR:-${sdk_prebuilts}/tools/linux/lib/d8.jar}"
apksigner_jar="${APKSIGNER_JAR:-${sdk_prebuilts}/tools/linux/lib/apksigner.jar}"
zipalign_bin="${ZIPALIGN:-zipalign}"
stage_dir="${VPP_RUNTIME_STAGE_DIR:-${VPP_STAGE_DIR:-${repo_root}/build-output/android-vpp-runtime/stage}}"
hev_stage_dir="${HEV_STAGE_DIR:-${poc_dir}/work/android-hev-stage}"
tun_poc_plugin="${VPP_TUN_POC_PLUGIN:-}"
if [[ ! -x "$stage_dir/bin/vpp" || ! -x "$stage_dir/bin/vppctl" ]]; then
  VPP_RUNTIME_STAGE_DIR="$stage_dir" \
    bash "$script_dir/stage-vpp-runtime.sh" >/dev/null
fi

die() { echo "error: $*" >&2; exit 1; }
# Test-only owner-resolver plugin injection for A2-0.  Keep this input
# separate from the shared runtime stage: the APK build owns the extracted
# copy, while the existing VPP_POC_PLUGIN path below remains compatible.
if [[ -n "$tun_poc_plugin" ]]; then
  [[ -f "$tun_poc_plugin" ]] || die "missing VPP_TUN_POC_PLUGIN: $tun_poc_plugin"
fi
# Test-only plugin injection for POC-124.  The product runtime stage normally
# contains no experimental plugin; passing this path makes the APK carry the
# explicitly selected probe artifact without changing the product stage
# defaults.
if [[ -n "${VPP_POC_PLUGIN:-}" ]]; then
  [[ -f "$VPP_POC_PLUGIN" ]] || die "missing VPP_POC_PLUGIN: $VPP_POC_PLUGIN"
  mkdir -p "$stage_dir/plugins"
  # VPP startup selects this canonical plugin name.  Preserve the source
  # artifact's hash in the manifest separately; never let a temporary stage
  # filename silently leave the old canonical plugin in the APK.
  cp "$VPP_POC_PLUGIN" "$stage_dir/plugins/hev_external_driver_poc_plugin.so"
fi

for file in "$android_jar" "$aapt2" "$d8_jar" "$apksigner_jar" "$stage_dir/bin/vpp" "$stage_dir/bin/vppctl"; do
  [[ -f "$file" ]] || die "missing file: $file"
done
command -v javac >/dev/null || die "missing javac"
command -v java >/dev/null || die "missing java"
command -v keytool >/dev/null || die "missing keytool"
command -v zip >/dev/null || die "missing zip"
command -v "$zipalign_bin" >/dev/null || die "missing zipalign: $zipalign_bin"

build_dir="$app_dir/build"
classes_dir="$build_dir/classes"
dex_dir="$build_dir/dex"
jni_dir="$build_dir/jni/lib/arm64-v8a"
assets_dir="$build_dir/assets"
intermediates="$build_dir/intermediates"
outputs="$build_dir/outputs"
rm -rf "$classes_dir" "$dex_dir" "$build_dir/jni" "$assets_dir" "$intermediates" "$outputs"
mkdir -p "$classes_dir" "$dex_dir" "$jni_dir" "$assets_dir" "$intermediates" "$outputs"

cp "$stage_dir/bin/vpp" "$jni_dir/libvpp_runtime.so"
cp "$stage_dir/bin/vpp" "$jni_dir/libvpppoc.so"
cp "$stage_dir/bin/vppctl" "$jni_dir/libvppctl.so"
chmod 755 "$jni_dir/libvpp_runtime.so" "$jni_dir/libvpppoc.so" "$jni_dir/libvppctl.so"
for so in "$stage_dir"/lib/*.so "$stage_dir"/plugins/*.so; do
  [[ -f "$so" ]] || continue
  so_name="$(basename "$so")"
  cp "$so" "$jni_dir/$so_name"
  chmod 755 "$jni_dir/$so_name"
  if [[ "$so_name" != lib*.so ]]; then
    cp "$so" "$jni_dir/lib$so_name"
    chmod 755 "$jni_dir/lib$so_name"
  fi
done
if [[ -f "$hev_stage_dir/lib/arm64-v8a/libhev-socks5-tunnel.so" ]]; then
  cp "$hev_stage_dir/lib/arm64-v8a/libhev-socks5-tunnel.so" "$jni_dir/libhev-socks5-tunnel.so"
  chmod 755 "$jni_dir/libhev-socks5-tunnel.so"
fi
if [[ -n "$tun_poc_plugin" ]]; then
  # Android's extraction/linker spelling is the required runtime artifact.
  # Retain the canonical VPP spelling as a sibling without touching the
  # shared stage/plugins directory.
  cp "$tun_poc_plugin" "$jni_dir/libtun_poc_plugin.so"
  cp "$tun_poc_plugin" "$jni_dir/tun_poc_plugin.so"
  chmod 755 "$jni_dir/libtun_poc_plugin.so" "$jni_dir/tun_poc_plugin.so"
  tun_poc_sha256="$(sha256sum "$jni_dir/libtun_poc_plugin.so" | awk '{print $1}')"
  printf '%s\n' "$tun_poc_sha256" >"$assets_dir/vpp-tun-poc-plugin.sha256"
  {
    printf 'schema=vpp-tun-poc-plugin-provenance/v1\n'
    printf 'abi=arm64-v8a\n'
    printf 'sourcePath=%s\n' "$tun_poc_plugin"
    printf 'sourceSha256=%s\n' "$tun_poc_sha256"
    printf 'artifactName=libtun_poc_plugin.so\n'
    printf 'canonicalArtifactName=tun_poc_plugin.so\n'
    printf 'artifactSha256=%s\n' "$tun_poc_sha256"
  } >"$assets_dir/vpp-tun-poc-plugin.properties"
fi

native_dir="$app_dir/native"
ndk_root="${NDK_ROOT:-/home/js/.local/share/android-sdk/ndk/29.0.14206865}"
android_clang="${ANDROID_CLANG:-$ndk_root/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android31-clang}"
[[ -x "$android_clang" ]] || die "Android clang is missing: $android_clang"
[[ -f "$native_dir/vpn_fd_probe.c" ]] || die "missing native VPN/TUN POC JNI source"
"$android_clang" -shared -fPIC -std=c11 -Wall -Wextra -Wno-unused-parameter \
  "$native_dir/vpn_fd_probe.c" \
  -llog -ldl -Wl,-soname,libvpnfdprobe.so \
  -o "$jni_dir/libvpnfdprobe.so"
chmod 755 "$jni_dir/libvpnfdprobe.so"

version="${VPP_RUNTIME_VERSION:-}"
if [[ -z "$version" ]]; then
  strings "$stage_dir/bin/vpp" >"$intermediates/vpp.strings"
  version="$(awk '/vpp v[0-9]/{print $2; exit}' "$intermediates/vpp.strings")"
fi
[[ "$version" =~ ^v[0-9]+\.[0-9]+ ]] || die "unable to determine VPP version"
printf 'version=%s\nabi=arm64-v8a\nprotocol=vpp-runtime-health/v1\n' "$version" >"$assets_dir/vpp-runtime.properties"
sha256sum "$jni_dir/libvpp_runtime.so" | awk '{print $1}' >"$assets_dir/vpp-runtime.sha256"

mapfile -t sources < <(find "$app_dir/src/main/java" -name '*.java' | sort)
javac -Xlint:-options -source 8 -target 8 -classpath "$android_jar" -d "$classes_dir" "${sources[@]}"
mapfile -t class_files < <(find "$classes_dir" -name '*.class' | sort)
java -cp "$d8_jar" com.android.tools.r8.D8 --min-api 31 --lib "$android_jar" --output "$dex_dir" "${class_files[@]}"

base_apk="$intermediates/base.apk"
unsigned_apk="$intermediates/unsigned.apk"
aligned_apk="$intermediates/aligned.apk"
apk="$outputs/sakamoto-runtime-debug.apk"
legacy_apk="$outputs/snort-vpn-lite-debug.apk"
"$aapt2" link -o "$base_apk" -I "$android_jar" --manifest "$app_dir/src/main/AndroidManifest.xml" \
  --min-sdk-version 31 --target-sdk-version 36 --version-code "${APK_VERSION_CODE:-1}" \
  --version-name "${APK_VERSION_NAME:-0.1-runtime-debug}" --debug-mode
cp "$base_apk" "$unsigned_apk"
(cd "$dex_dir" && zip -q -r "$unsigned_apk" classes.dex)
(cd "$build_dir/jni" && zip -q -r "$unsigned_apk" lib)
(cd "$build_dir" && zip -q -r "$unsigned_apk" assets)
if [[ ! -f "$build_dir/debug.keystore" ]]; then
  keytool -genkeypair -keystore "$build_dir/debug.keystore" -storepass android -keypass android \
    -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=Android Debug,O=sakamoto,C=US" >/dev/null
fi
"$zipalign_bin" -f -p 4 "$unsigned_apk" "$aligned_apk"
java -jar "$apksigner_jar" sign --ks "$build_dir/debug.keystore" --ks-pass pass:android \
  --key-pass pass:android --ks-key-alias androiddebugkey --out "$apk" "$aligned_apk"
java -jar "$apksigner_jar" verify --print-certs "$apk" >/dev/null
cp "$apk" "$legacy_apk"
echo "ok: $apk"
echo "ok: $legacy_apk"
