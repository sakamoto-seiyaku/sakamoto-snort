#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
dex_guard="$repo_root/app/android-runtime/scripts/check-android-process-api.py"
android_jar="${SAKAMOTO_S172_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
d8_jar="${SAKAMOTO_S172_D8_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar}"

test -f "$build_script"
test -f "$dex_guard"
test -f "$android_jar"
test -f "$d8_jar"
command -v javac >/dev/null
command -v javap >/dev/null
command -v java >/dev/null
command -v python3 >/dev/null
command -v zip >/dev/null

# The build must bind javac's platform classes to Android and prove that
# java.lang.Process was loaded from that stub, rather than from host JDK17.
grep -Fq -- '-bootclasspath "$javac_bootclasspath"' "$build_script"
grep -Fq 'javac_bootclasspath="$android_jar:$javac_support_jar"' "$build_script"
grep -Fq 'javac_support_jar' "$build_script"
grep -Fq 'LambdaMetafactory.class' "$build_script"
grep -Fq 'javac.verbose.log' "$build_script"
grep -Fq 'java/lang/Process.class' "$build_script"
grep -Fq 'modules/java.base/java/lang/Process.class' "$build_script"
grep -Fq 'check-android-process-api.py' "$build_script"
grep -Fq 'process.getOutputStream().close();' "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-process-api.XXXXXX")"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$work_dir/classes" "$work_dir/dex" "$work_dir/bad-classes" "$work_dir/bad-dex"
java_bin="$(command -v java)"
java_home="$($java_bin -XshowSettings:properties -version 2>&1 \
  | sed -n 's/^[[:space:]]*java.home = //p' | head -n 1)"
mkdir -p "$work_dir/javac-support"
jimage extract --dir="$work_dir/javac-support" \
  --include "glob:**/java/lang/invoke/LambdaMetafactory.class" \
  "$java_home/lib/modules" >/dev/null
jar cf "$work_dir/javac-support.jar" \
  -C "$work_dir/javac-support/java.base" java/lang/invoke/LambdaMetafactory.class
javac_bootclasspath="$android_jar:$work_dir/javac-support.jar"

# Compile the complete Android Java source set using the same bootclasspath
# contract as the APK builder, then inspect both class files and DEX output.
mapfile -t sources < <(find "$repo_root/app/android-runtime/src/main/java" \
  -type f -name '*.java' -print | sort)
((${#sources[@]} > 0))
javac -encoding UTF-8 -Xlint:-options -source 8 -target 8 \
  -bootclasspath "$javac_bootclasspath" -classpath "$android_jar" -verbose \
  -d "$work_dir/classes" "${sources[@]}" >"$work_dir/javac.log" 2>&1
grep -Fq "$android_jar(/java/lang/Process.class)" "$work_dir/javac.log"
if grep -Fq '/modules/java.base/java/lang/Process.class' "$work_dir/javac.log"; then
  echo "complete Android source compile used host java.base" >&2
  exit 1
fi

while IFS= read -r -d '' class_file; do
  class_dump="$(javap -verbose "$class_file")"
  if grep -Fq 'java/lang/Process.pid' <<<"$class_dump" || \
      grep -Fq 'java/lang/Process.toHandle' <<<"$class_dump" || \
      grep -Fq 'java/lang/ProcessHandle' <<<"$class_dump"; then
    echo "complete Android source compile emitted an unsupported Process API" >&2
    exit 1
  fi
done < <(find "$work_dir/classes" -type f -name '*.class' -print0 | sort -z)

java -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/dex" \
  $(find "$work_dir/classes" -type f -name '*.class' -print | sort)
python3 "$dex_guard" "$work_dir/dex/classes.dex"

# Reproduce the old 1787969241 artifact's forbidden method reference through
# the same JDK17 -> D8 path. The DEX gate must reject the APK, not merely the
# source spelling of process.pid().
printf '%s\n' \
  'public final class BadProcessApi {' \
  '  public static long pid(java.lang.Process process) { return process.pid(); }' \
  '}' >"$work_dir/BadProcessApi.java"
javac -source 8 -target 8 -d "$work_dir/bad-classes" "$work_dir/BadProcessApi.java"
java -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$work_dir/bad-dex" \
  "$work_dir/bad-classes/BadProcessApi.class"
mkdir -p "$work_dir/old-1787969241"
cp "$work_dir/bad-dex/classes.dex" "$work_dir/old-1787969241/classes.dex"
(
  cd "$work_dir/old-1787969241"
  zip -q -0 "../sakamoto-runtime-debug-1787969241.apk" classes.dex
)
if python3 "$dex_guard" "$work_dir/sakamoto-runtime-debug-1787969241.apk"; then
  echo "1787969241-style APK passed the Android Process API gate" >&2
  exit 1
fi

echo "sakamoto-172 Android Process API contract: PASS"
