#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
lifecycle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java"
adapter_contract="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPacketAdapterContract.java"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
root_adapter_header="$repo_root/src/product/vpp/product_root_nfqueue_adapter.h"
plugin_cmake="$repo_root/src/product/vpp/CMakeLists.txt"
device_runner="$repo_root/tests/device/s176-root-nfqueue-output-product.sh"

test -f "$service"
test -f "$activity"
test -f "$lifecycle"
test -f "$adapter_contract"
test -f "$plugin"
test -f "$graph"
test -f "$root_adapter"
test -f "$root_adapter_header"
test -x "$device_runner"

grep -Fq 'ROOT_ADAPTER = "root-nfqueue"' "$adapter_contract"
grep -Fq '"Root NFQUEUE lanes"' "$adapter_contract"
grep -Fq '"origin-lane NFQUEUE verdict completion"' "$adapter_contract"

# S176 is the first Product Core path that may publish Root adapter readiness.
# The root profile must require root authorization before launching the same
# product VPP runtime; VPN/core-only paths must not inherit Root NFQUEUE.
grep -Fq 'if (selected == RuntimeProfile.ROOT && !rootCommandAvailable())' "$service"
grep -Fq 'buildProductCoreProcessBuilder(' "$service"
grep -Fq 'SAKAMOTO_RUNTIME_PROFILE", selected.wireName' "$service"
grep -Fq 'SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE", "176"' "$service"
grep -Fq 'SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID' "$service"
grep -Fq 'Integer.toString(getApplicationInfo().uid)' "$service"
grep -Fq 'new ProcessBuilder(SU_PATH, "0", "sh", "-c", command)' "$service"
grep -Fq 'new ProcessBuilder(vpp.getPath(), "-c",' "$service"
grep -Fq 'backend.queryService(this);' "$activity"

python3 - "$service" "$lifecycle" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
lifecycle = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")


def method_body(source, signature):
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


start = method_body(service, "private void startProductCoreRuntime(")
connect = method_body(service, "private RuntimeControlNative.Session connectProductCoreSession(")
publish = method_body(service, "private boolean publishProductCoreRunning(")
builder = method_body(service, "private ProcessBuilder buildProductCoreProcessBuilder(")
stop = method_body(service, "private boolean stopProductCoreResidue(")
stop_runtime = method_body(service, "private boolean stopRuntime(boolean stopService)")
root_cleanup = method_body(service,
                           "private boolean productRootNfqueueResidueClean(RuntimeProfile profile)")
root_install = method_body(service, "private boolean installProductRootNfqueueHook(")
owner_terminate = method_body(service, "private boolean terminateProductCoreOwnerProcess(")
validate = method_body(lifecycle, "public static String validate(")

if start.index("selected == RuntimeProfile.ROOT && !rootCommandAvailable()") \
        > start.index("publish(RuntimeSnapshot.starting("):
    raise AssertionError("Root Product Core start publishes starting before root authorization")
if "nextProductCoreGeneration(ownerDecision)" not in start:
    raise AssertionError("Product Core generation can reuse a retired native generation")
generation_state = method_body(service, "private long nextProductCoreGeneration(")
if "PRODUCT_CORE_GENERATION_STATE" not in generation_state:
    raise AssertionError("Product Core generation is not persisted across service recreation")
if "ownerDecision.highestGeneration()" not in generation_state:
    raise AssertionError("Product Core generation does not account for durable owner residue")
if "ProductPacketAdapterContract.forProfile(selected)" not in start:
    raise AssertionError("Product Core start does not bind readiness to the selected adapter")
if "adapter.requiresRootAuthorization" not in start:
    raise AssertionError("Root adapter authorization is not a first-class adapter contract")
if "status.adapterAvailable == adapter.adapterReadyOnStart" not in start:
    raise AssertionError("Product Core connect validation is not profile-adapter exact")
if "ProductCoreLifecycle.shouldKeepSessionForReadinessRetry" not in connect:
    raise AssertionError("Product Core readiness retry can retire the active generation")
if "RuntimeControlNative.Status status = session.query()" not in connect:
    raise AssertionError("Product Core readiness retry must poll the same live session")
if "RuntimeSnapshot.runningProduct(" not in publish:
    raise AssertionError("Product Core running state does not publish adapter readiness from VAPI")
if "status.adapterAvailable ? adapter.adapterName : RuntimeSnapshot.ADAPTER_UNAVAILABLE" not in publish:
    raise AssertionError("Product Core running state can infer adapter readiness without VAPI")
if 'profile == RuntimeProfile.ROOT' not in builder:
    raise AssertionError("Product Core process builder does not split Root/VPN launch identity")
if 'new ProcessBuilder(SU_PATH, "0", "sh", "-c", command)' not in builder:
    raise AssertionError("Root Product Core launch must use the approved root runner")
if 'new ProcessBuilder(vpp.getPath(), "-c",' not in builder:
    raise AssertionError("Non-root Product Core launch must keep direct app-UID VPP")
if "SAKAMOTO_PRODUCT_ROOT_NFQUEUE_QUEUE" not in builder:
    raise AssertionError("Root NFQUEUE queue identity is not passed to the Product VPP runtime")
if "SAKAMOTO_PRODUCT_ROOT_NFQUEUE_LANES" not in builder:
    raise AssertionError("Root NFQUEUE lane count is not passed to the Product VPP runtime")
if "SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID" not in builder:
    raise AssertionError("Root NFQUEUE must be narrowed to this debug APK UID")
if "installProductRootNfqueueHook()" not in start:
    raise AssertionError("Root Product Core start must install the platform NFQUEUE hook")
if start.index("installProductRootNfqueueHook()") > start.index("builder.start()"):
    raise AssertionError("Root NFQUEUE hook must be installed before Product VPP launch")
if "Android owns the platform hook" not in root_install:
    raise AssertionError("Root NFQUEUE platform ownership is not documented at the Java boundary")
for expected in (
        "iptables -w -t mangle -N ",
        " -m owner --uid-owner ",
        " -j NFQUEUE --queue-balance ",
        " --queue-bypass",
        "iptables -w -t mangle -I OUTPUT -j ",
        "iptables -w -t mangle -S OUTPUT"):
    if expected not in root_install:
        raise AssertionError("Root NFQUEUE hook install is missing: " + expected)
if "productRootNfqueueResidueClean()" not in stop:
    raise AssertionError("Product Core STOP does not verify Root NFQUEUE residue")
if "terminateProductCoreOwnerProcess()" not in stop_runtime:
    raise AssertionError("Product Core STOP does not terminate the audited root VPP owner")
if "auditProductCoreProcessPid" not in owner_terminate or "kill -KILL " not in owner_terminate:
    raise AssertionError("Product Core owner termination must use exact owner PID before KILL")
if "snapshot == null || !snapshot.isActive()" not in stop_runtime:
    raise AssertionError("inactive Product Core teardown must not require Root NFQUEUE cleanup")
if "iptables -w -t mangle -D OUTPUT -j " not in root_cleanup:
    raise AssertionError("Root NFQUEUE cleanup must remove the mangle OUTPUT jump")
if "iptables -w -t mangle -S OUTPUT" not in root_cleanup:
    raise AssertionError("Root NFQUEUE cleanup must verify the mangle OUTPUT table")
if "adapterAvailable != expectedAdapterAvailable" not in validate:
    raise AssertionError("Product Core lifecycle still treats every adapter as core-only")
PY

# The product plugin must derive readiness from the Root adapter state. A hard
# coded adapter_available=false is the S172 pre-adapter shape and is a false
# pass for S176.
grep -Fq '#include "product_root_nfqueue_adapter.h"' "$plugin"
grep -Fq 'product_root_nfqueue_adapter_available' "$plugin"
if grep -Fq 'rmp->adapter_available = 0;' "$plugin"; then
  echo "Product Core status still hard-codes adapter_available=false" >&2
  exit 1
fi

grep -Fq 'product_root_nfqueue_adapter.c' "$plugin_cmake"
grep -Fq 'product_root_nfqueue_adapter.h' "$root_adapter"
grep -Fq '<linux/netfilter/nfnetlink_queue.h>' "$root_adapter"
grep -Fq 'NETLINK_NETFILTER' "$root_adapter"
grep -Fq 'SAKAMOTO_PRODUCT_ROOT_NFQUEUE_UID' "$root_adapter"
grep -Fq 'NFQNL_MSG_VERDICT' "$root_adapter"
grep -Fq 'NFQA_VERDICT_HDR' "$root_adapter"
grep -Fq 'sendto (fd, nlh, nlh->nlmsg_len, 0' "$root_adapter"
grep -Fq 'uid_present' "$root_adapter"
grep -Fq 'packet.hook == NF_INET_LOCAL_OUT && packet.uid_present' "$root_adapter"
grep -Fq 'hints.uid = packet.uid_present ? packet.uid : UINT32_MAX' "$root_adapter"
if grep -Eq '(^|[^_[:alnum:]])send[[:space:]]*\(fd, &request\.nlh' "$root_adapter"; then
  echo "Root NFQUEUE adapter sends nfnetlink messages without a kernel peer" >&2
  exit 1
fi
if grep -Eq '(^|[^_[:alnum:]])system[[:space:]]*\(' "$root_adapter" \
    || grep -Fq 'iptables' "$root_adapter"; then
  echo "Root NFQUEUE adapter must not own Android platform iptables hooks" >&2
  exit 1
fi
grep -Fq 'NF_INET_LOCAL_OUT' "$root_adapter"
grep -Fq 'PRODUCT_PACKET_INTENT_PASS_ADAPTER' "$root_adapter"
grep -Fq 'product_packet_graph_submit_external' "$root_adapter"
grep -Fq 'product_packet_graph_register_external_completion (' "$root_adapter"
grep -Fq 'graph->external_completion (' "$graph"

# Device evidence is still decisive. The runner must drive the installed debug
# APK on an explicitly selected device and record the single-lane OUTPUT proof.
grep -Fq './dev/adb' "$device_runner"
grep -Fq '28201JEGR0XPAJ' "$device_runner"
grep -Fq 'SAKAMOTO-176-root-nfqueue-output' "$device_runner"
grep -Fq 'product.adapter_available=1' "$device_runner"
grep -Fq 'queue_id=176' "$device_runner"
grep -Fq 'PRODUCT_ROOT_NFQUEUE_QUEUE_LAST = "177"' "$service"
grep -Fq 'queue_range=' "$service"
grep -Fq 'lane_count=' "$service"
grep -Fq 'ready_lane_mask=' "$service"
grep -Fq 'hook=OUTPUT' "$device_runner"
grep -Fq 'origin_verdict_attempts>=1' "$device_runner"
grep -Fq 'positive_equal_packet_counters' "$device_runner"
grep -Fq 'internal_settlements=origin_verdict_attempts' "$device_runner"
grep -Fq 'buffer_returns=origin_verdict_attempts' "$device_runner"
grep -Fq 'Controlled LAN' "$device_runner"
grep -Fq 'productRootNfqueueResidueClean' "$device_runner"
grep -Fq 'state=stopped' "$device_runner"
grep -Fq 'mayBeActive=false' "$device_runner"
grep -Fq 'S176_CONTROLLED_LAN_HOST' "$device_runner"
grep -Fq 'debugTrafficHost' "$device_runner"
grep -Fq 'root_authorization_required' "$device_runner"
if grep -Fq 'S176_PROBE_COMMAND is not implemented' "$device_runner"; then
  echo "S176 runner still blocks on a missing external probe command" >&2
  exit 1
fi

echo "sakamoto-176 Root NFQUEUE OUTPUT contract: PASS"
