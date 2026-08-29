#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
build_script="$repo_root/app/android-runtime/scripts/build-debug-apk.sh"
android_jar="${SAKAMOTO_S172_ANDROID_JAR:-/home/js/android/lineage/prebuilts/sdk/36/public/android.jar}"
d8_jar="${SAKAMOTO_S172_D8_JAR:-/home/js/android/lineage/prebuilts/sdk/tools/linux/lib/d8.jar}"
runtime_service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"

test -f "$build_script"
test -f "$android_jar"
test -f "$d8_jar"

# The API boundary is enforced by javac's Android boot class path.  There is
# no DEX parser or artifact-text gate in either the builder or this contract.
if rg -n -i 'dexdump|check-android-process-api|javap_bin|class_dump' \
    "$build_script" "$repo_root/app/android-runtime/scripts"; then
  echo "the Android build still contains a removed artifact parser/gate" >&2
  exit 1
fi
test ! -e "$repo_root/app/android-runtime/scripts/check-android-process-api.py"
test ! -e "$repo_root/app/android-runtime/scripts/check-android-process-api.sh"

# Keep the production seam explicit and reviewable: one JDK is selected, its
# java.home supplies every JDK tool, and Android's jar is the only boot-class-
# path input.  The LambdaMetafactory class is a compiler-only signature needed
# to lower Java 8 lambdas; it is not packaged.
grep -Fq 'java_launcher="$(command -v java' "$build_script"
grep -Fq 'java_home="$($java_launcher -XshowSettings:properties -version' "$build_script"
grep -Fq 'java_bin="$java_home/bin/java"' "$build_script"
grep -Fq 'javac_bin="$java_home/bin/javac"' "$build_script"
grep -Fq 'javac_support_jar' "$build_script"
grep -Fq 'javac_classpath="$android_jar:$javac_support_jar"' "$build_script"
grep -Fq -- '-source 8 -target 8' "$build_script"
grep -Fq -- '-bootclasspath "$android_jar"' "$build_script"
grep -Fq -- '-classpath "$javac_classpath"' "$build_script"
grep -Fq -- '-verbose' "$build_script"
grep -Fq 'javac.verbose.log' "$build_script"
grep -Fq 'if ((${#d8_outputs[@]} != 1))' "$build_script"
grep -Fq 'D8 produced unexpected classes*.dex output' "$build_script"

grep -Fq 'new ProcessBuilder(vpp.getPath()' "$runtime_service"
grep -Fq 'process.getOutputStream().close();' "$runtime_service"

base_dir="$(mktemp -d "${TMPDIR:-/tmp}/sakamoto-172-process-api.XXXXXX")"
trap 'rm -rf -- "$base_dir"' EXIT
work_dir="$base_dir/path with spaces"
classes_dir="$work_dir/classes"
dex_dir="$work_dir/dex"
mkdir -p "$classes_dir" "$dex_dir"

# Resolve all JDK tools from one java.home, matching the production builder.
java_launcher="$(realpath -e -- "$(command -v java)")"
java_home="$($java_launcher -XshowSettings:properties -version 2>&1 \
  | sed -n 's/^[[:space:]]*java.home = //p' | head -n 1)"
test -n "$java_home"
java_home="$(realpath -e -- "$java_home")"
java_bin="$java_home/bin/java"
javac_bin="$java_home/bin/javac"
jimage_bin="$java_home/bin/jimage"
jar_bin="$java_home/bin/jar"
for tool_path in "$java_bin" "$javac_bin" "$jimage_bin" "$jar_bin"; do
  test -x "$tool_path"
done
test "$(realpath -e -- "$java_bin")" = "$java_launcher"
test -f "$java_home/lib/modules"

mkdir -p "$work_dir/javac-support"
"$jimage_bin" extract --dir="$work_dir/javac-support" \
  --include "glob:**/java/lang/invoke/LambdaMetafactory.class" \
  "$java_home/lib/modules" >/dev/null
"$jar_bin" cf "$work_dir/javac-support.jar" \
  -C "$work_dir/javac-support/java.base" \
  java/lang/invoke/LambdaMetafactory.class
javac_classpath="$android_jar:$work_dir/javac-support.jar"

# This function is deliberately the same javac seam as the product builder:
# Java 8 syntax/bytecode, Android public stubs as boot classes, and the
# compiler-only LambdaMetafactory support on the ordinary class path.  It makes
# every positive and negative compile below use the same boundary.
compile_android_java() {
  "$javac_bin" -encoding UTF-8 -Xlint:-options -source 8 -target 8 \
    -bootclasspath "$android_jar" -classpath "$javac_classpath" "$@"
}

# The complete Android source tree must compile with the same boundary.  Keep
# verbose output as evidence that Process was loaded from android.jar; this is
# a test observation, not a product-build gate on javac's unstable log text.
mapfile -t sources < <(find "$repo_root/app/android-runtime/src/main/java" \
  -type f -name '*.java' -print | sort)
((${#sources[@]} > 0))
compile_android_java -verbose -d "$classes_dir" "${sources[@]}" \
  >"$work_dir/javac.log" 2>&1
grep -Fq "$android_jar(/java/lang/Process.class)" "$work_dir/javac.log"
if grep -Fq '/modules/java.base/java/lang/Process.class' "$work_dir/javac.log"; then
  echo "complete Android source compile used host java.base for Process" >&2
  exit 1
fi

# Exercise the supported Process surface directly.  These methods are API 1
# or API 26 and therefore compile for the product's API-31 minimum.
printf '%s\n' \
  'import java.util.concurrent.TimeUnit;' \
  '' \
  'final class LegalProcessApi {' \
  '  static boolean alive(Process process) {' \
  '    return process.isAlive();' \
  '  }' \
  '' \
  '  static int waitFor(Process process) throws InterruptedException {' \
  '    return process.waitFor();' \
  '  }' \
  '' \
  '  static boolean waitForBounded(Process process) throws InterruptedException {' \
  '    return process.waitFor(1L, TimeUnit.MILLISECONDS);' \
  '  }' \
  '' \
  '  static void destroy(Process process) {' \
  '    process.destroy();' \
  '  }' \
  '}' >"$work_dir/LegalProcessApi.java"
compile_android_java -d "$classes_dir" "$work_dir/LegalProcessApi.java"

# D8 is still the official Java-to-DEX step.  The product intentionally keeps
# a single-dex output policy, but no DEX bytes are inspected here.
mapfile -t class_files < <(find "$classes_dir" -type f -name '*.class' -print | sort)
((${#class_files[@]} > 0))
"$java_bin" -cp "$d8_jar" com.android.tools.r8.D8 --lib "$android_jar" \
  --min-api 31 --output "$dex_dir" "${class_files[@]}"
mapfile -t dex_outputs < <(find "$dex_dir" -mindepth 1 -maxdepth 1 -print | sort)
test "${#dex_outputs[@]}" -eq 1
test "${dex_outputs[0]}" = "$dex_dir/classes.dex"

compile_rejected_source() {
  local label="$1"
  local expected_symbol="$2"
  local source_file="$3"
  local output_dir="$4"
  local log_file="$5"
  mkdir -p "$output_dir"
  if compile_android_java -d "$output_dir" "$source_file" >"$log_file" 2>&1; then
    echo "$label unexpectedly compiled against Android public stubs" >&2
    exit 1
  fi
  grep -Fq 'cannot find symbol' "$log_file"
  grep -Eq "symbol:[[:space:]]+${expected_symbol}" "$log_file"
}

# Each forbidden source must fail at the source/API boundary itself.  Assert
# the javac diagnostic identifies the missing class or method, so a typo or an
# unrelated syntax error cannot satisfy this contract.
cat >"$work_dir/BadProcessPid.java" <<'EOF'
final class BadProcessPid {
  static long value(Process process) {
    return process.pid();
  }
}
EOF
compile_rejected_source "Process.pid()" 'method pid\(\)' \
  "$work_dir/BadProcessPid.java" "$work_dir/bad-pid" "$work_dir/bad-pid.log"

cat >"$work_dir/BadProcessToHandle.java" <<'EOF'
final class BadProcessToHandle {
  static Object value(Process process) {
    return process.toHandle();
  }
}
EOF
compile_rejected_source "Process.toHandle()" 'method toHandle\(\)' \
  "$work_dir/BadProcessToHandle.java" "$work_dir/bad-to-handle" \
  "$work_dir/bad-to-handle.log"

cat >"$work_dir/BadProcessHandle.java" <<'EOF'
final class BadProcessHandle {
  ProcessHandle value;
}
EOF
compile_rejected_source "ProcessHandle" 'class ProcessHandle' \
  "$work_dir/BadProcessHandle.java" "$work_dir/bad-process-handle" \
  "$work_dir/bad-process-handle.log"

echo "sakamoto-172 Android Process API contract: PASS (Android javac boundary + D8 single-dex)"
