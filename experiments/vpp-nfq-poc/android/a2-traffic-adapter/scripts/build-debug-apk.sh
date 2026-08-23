#!/usr/bin/env bash
set -euo pipefail

# Build the two S139 A2-1 traffic-generator APKs from the same Java source.
# This deliberately stays outside Gradle and the production Android runtime.

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd -- "$APP_DIR/../../../.." && pwd)"

VARIANT="${VARIANT:-debug}"
PACKAGE_A="${PACKAGE_A:-com.sakamoto.snort.poc.appa}"
PACKAGE_B="${PACKAGE_B:-com.sakamoto.snort.poc.appb}"
APPLICATION_ID="${APPLICATION_ID:-}"
OUTPUT_DIR="${OUTPUT_DIR:-$APP_DIR/build/outputs}"
BUILD_ROOT="${BUILD_ROOT:-$APP_DIR/build}"

SDK_PREBUILTS="${ANDROID_LINEAGE_SDK_PREBUILTS:-/home/js/android/lineage/prebuilts/sdk}"
ANDROID_JAR="${ANDROID_JAR:-$SDK_PREBUILTS/36/public/android.jar}"
AAPT2="${AAPT2:-$SDK_PREBUILTS/tools/linux/bin/aapt2}"
D8_JAR="${D8_JAR:-$SDK_PREBUILTS/tools/linux/lib/d8.jar}"
APKSIGNER_JAR="${APKSIGNER_JAR:-$SDK_PREBUILTS/tools/linux/lib/apksigner.jar}"
ZIPALIGN="${ZIPALIGN:-$SDK_PREBUILTS/tools/linux/bin/zipalign}"
SIGNING_DIR="${SIGNING_DIR:-$REPO_ROOT/build-output/a2-1-traffic-adapter-signing}"
SIGNING_KEYSTORE="${SIGNING_KEYSTORE:-$SIGNING_DIR/debug.keystore}"
SIGNING_ALIAS="${SIGNING_ALIAS:-androiddebugkey}"

die() {
  echo "error: $*" >&2
  exit 1
}

valid_package() {
  [[ "$1" =~ ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$ ]]
}

validate_package() {
  local apk="$1"
  local expected="$2"
  local package_line
  package_line="$("$AAPT2" dump badging "$apk" | awk '/^package: name=/{print; exit}')"
  [[ "$package_line" == *"package: name='$expected'"* ]] \
    || die "APK package mismatch: expected $expected in $apk; got $package_line"
}

[[ "$VARIANT" =~ ^[a-z][a-z0-9_-]*$ ]] || die "invalid variant: $VARIANT"
if [[ -n "$APPLICATION_ID" ]]; then
  valid_package "$APPLICATION_ID" || die "invalid application ID: $APPLICATION_ID"
  package_ids=("$APPLICATION_ID")
else
  valid_package "$PACKAGE_A" || die "invalid PACKAGE_A: $PACKAGE_A"
  valid_package "$PACKAGE_B" || die "invalid PACKAGE_B: $PACKAGE_B"
  [[ "$PACKAGE_A" != "$PACKAGE_B" ]] || die "PACKAGE_A and PACKAGE_B must differ"
  package_ids=("$PACKAGE_A" "$PACKAGE_B")
fi

for input in "$ANDROID_JAR" "$AAPT2" "$D8_JAR" "$APKSIGNER_JAR" "$ZIPALIGN"; do
  [[ -f "$input" ]] || die "missing pinned Android build input: $input"
done
command -v javac >/dev/null || die "missing javac"
command -v java >/dev/null || die "missing java"
command -v keytool >/dev/null || die "missing keytool"
command -v zip >/dev/null || die "missing zip"

COMMON_DIR="$BUILD_ROOT/common-$VARIANT"
CLASSES_DIR="$COMMON_DIR/classes"
DEX_DIR="$COMMON_DIR/dex"
SOURCE_DIGEST=""
mkdir -p "$SIGNING_DIR"
rm -rf -- "$COMMON_DIR" "$OUTPUT_DIR"
mkdir -p "$CLASSES_DIR" "$DEX_DIR" "$OUTPUT_DIR"

mapfile -t sources < <(find "$APP_DIR/src/main/java" -name '*.java' -print | sort)
[[ "${#sources[@]}" -gt 0 ]] || die "traffic adapter Java source is missing"
javac -Xlint:-options -source 8 -target 8 -classpath "$ANDROID_JAR" \
  -d "$CLASSES_DIR" "${sources[@]}"
mapfile -t class_files < <(find "$CLASSES_DIR" -name '*.class' -print | sort)
[[ "${#class_files[@]}" -gt 0 ]] || die "Java compilation produced no class files"
java -cp "$D8_JAR" com.android.tools.r8.D8 --min-api 31 --lib "$ANDROID_JAR" \
  --output "$DEX_DIR" "${class_files[@]}"

SOURCE_DIGEST="$(
  cd -- "$APP_DIR"
  find src -type f -print0 | sort -z | xargs -0 sha256sum
)"
SOURCE_DIGEST="$(printf '%s' "$SOURCE_DIGEST" | sha256sum | awk '{print $1}')"

if [[ ! -f "$SIGNING_KEYSTORE" ]]; then
  keytool -genkeypair -noprompt -keystore "$SIGNING_KEYSTORE" \
    -storepass android -keypass android -alias "$SIGNING_ALIAS" \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname 'CN=Android Debug,O=sakamoto,C=US' >/dev/null
fi
keytool -list -keystore "$SIGNING_KEYSTORE" -storepass android \
  -alias "$SIGNING_ALIAS" >/dev/null \
  || die "stable debug signing key is missing alias $SIGNING_ALIAS"

build_one() {
  local package_id="$1"
  local safe_name="${package_id//./-}"
  local variant_dir="$BUILD_ROOT/$safe_name-$VARIANT"
  local assets_dir="$variant_dir/assets"
  local intermediates="$variant_dir/intermediates"
  local manifest_path="$intermediates/AndroidManifest.xml"
  local unsigned_apk="$intermediates/unsigned.apk"
  local aligned_apk="$intermediates/aligned.apk"
  local output_apk="$OUTPUT_DIR/${safe_name}-${VARIANT}.apk"

  rm -rf -- "$variant_dir"
  mkdir -p "$assets_dir" "$intermediates"
  sed "s/__APPLICATION_ID__/$package_id/g" \
    "$APP_DIR/src/main/AndroidManifest.xml.template" >"$manifest_path"
  {
    printf 'schema=s139-a2-1-traffic-adapter-build/v1\n'
    printf 'applicationId=%s\n' "$package_id"
    printf 'variant=%s\n' "$VARIANT"
    printf 'sourceTreeSha256=%s\n' "$SOURCE_DIGEST"
    printf 'activity=com.sakamoto.snort.a2traffic.TrafficAdapterActivity\n'
  } >"$assets_dir/a2-1-traffic-adapter.properties"

  "$AAPT2" link -o "$unsigned_apk" -I "$ANDROID_JAR" \
    --manifest "$manifest_path" --min-sdk-version 31 --target-sdk-version 36 \
    --version-code "${APK_VERSION_CODE:-1}" \
    --version-name "${APK_VERSION_NAME:-0.1-a2-1-$VARIANT}"
  (cd "$DEX_DIR" && zip -q -r "$unsigned_apk" classes.dex)
  (cd "$variant_dir" && zip -q -r "$unsigned_apk" assets)
  "$ZIPALIGN" -f -p 4 "$unsigned_apk" "$aligned_apk"
  java -jar "$APKSIGNER_JAR" sign --ks "$SIGNING_KEYSTORE" \
    --ks-pass pass:android --key-pass pass:android \
    --ks-key-alias "$SIGNING_ALIAS" --out "$output_apk" "$aligned_apk"
  java -jar "$APKSIGNER_JAR" verify --print-certs "$output_apk" >/dev/null
  validate_package "$output_apk" "$package_id"
  echo "ok: $output_apk"
}

for package_id in "${package_ids[@]}"; do
  build_one "$package_id"
done

echo "built ${#package_ids[@]} APK(s) with shared implementation"
