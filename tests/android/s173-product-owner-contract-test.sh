#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
owner="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreOwner.java"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
runtime_contract="$repo_root/tests/android/android-runtime-contract-test.sh"

test -f "$owner"
test -f "$service"
grep -Fq 'public final class ProductCoreOwner' "$owner"
grep -Fq 'public static final String RECORD_FILE = "owner.properties"' "$owner"
grep -Fq 'public static OwnerRecord read(File file)' "$owner"
grep -Fq 'owner record key is duplicate or unknown' "$owner"
grep -Fq 'ProductCoreOwner.OwnerRecord.create' "$service"
grep -Fq 'owner.write(new File(profile, ProductCoreOwner.RECORD_FILE))' "$service"
grep -Fq 'SAKAMOTO_VPP_OWNER_TOKEN", owner.token' "$service"
grep -Fq 'auditProductCoreOwner' "$service"
grep -Fq 'ProductCoreOwner.buildProcessAuditCommand' "$service"
grep -Fq 'ProductCoreOwner.ProcessState.UNKNOWN' "$service"
grep -Fq 'Integer.toString(android.os.Process.myUid())' "$service"
grep -Fq 'ProductCoreOwner.Action.BLOCK_LIVE' "$service"
grep -Fq 'ProductCoreOwner.Action.BLOCK_UNKNOWN' "$service"
grep -Fq 'ProductCoreOwner.Action.CLEAN_THEN_START' "$service"
grep -Fq 'ProductCoreOwner.Decision.unknown' "$service"
grep -Fq 'cleanup_failed' "$service"
grep -Fq 'productCoreSession = null;' "$service"
grep -Fq 'vppProcess = null;' "$service"
grep -Fq 'if (cleanupFaultInjected)' "$service"
if grep -Fq 'process.pid()' "$service" || grep -Fq 'ProcessHandle' "$service"; then
  echo "Product Core owner seam uses an unsupported numeric PID API" >&2
  exit 1
fi

grep -Fq 'ProductCoreOwner.java' "$runtime_contract"

python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")


def method_body(signature):
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError("unclosed method: " + signature)


start = method_body("private void startProductCoreRuntime(")
prepare = method_body("private void prepareProductCoreProfile(")
fail = method_body("private void failProductCoreGeneration(")
stop = method_body("private boolean stopRuntime(boolean stopService)")
residue = method_body("private boolean stopProductCoreResidue(boolean stopService)")

if "return stopProductCoreResidue(stopService)" not in stop:
    raise AssertionError("Product Core STOP can fall through to the legacy cleanup path")
if start.index("auditProductCoreOwner") > start.index("deleteTree(profileRoot)"):
    raise AssertionError("Product Core START deletes residue before owner audit")
if "owner.write" not in prepare:
    raise AssertionError("Product Core START launches before durable owner record")
if start.index("prepareProductCoreProfile(profileRoot, nativeDir, owner)") \
        > start.index("Process process = builder.start()"):
    raise AssertionError("Product Core START launches before durable owner record")
if "builder.environment().put(\"SAKAMOTO_VPP_OWNER_TOKEN\", owner.token)" not in start:
    raise AssertionError("Product Core launch does not pass the durable token")
if fail.index("if (clean)") > fail.index("productCoreSession = null"):
    raise AssertionError("Product Core failure clears handles outside successful cleanup")
if stop.index("if (!clean)") > stop.index("productCoreSession = null"):
    raise AssertionError("Product Core STOP clears handles before checking cleanup")
if "return false;" not in stop[stop.index("if (!clean)"):stop.index("productCoreSession = null")]:
    raise AssertionError("Product Core STOP does not retain owner state on cleanup failure")
if "auditProductCoreOwnerForStop" not in residue or "deleteTree(profileRoot)" not in residue:
    raise AssertionError("Product Core STOP residue path lacks its own owner audit/cleanup")
PY

echo "sakamoto-173 Product Core owner contract: PASS"
