#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
abi_header="$repo_root/src/product/include/sakamoto_product_abi.h"
rust_core="$repo_root/crates/product-core/src/lib.rs"
device_runner="$repo_root/tests/device/s187-worker-core-guardrails-product.sh"

for file in "$service" "$native_status" "$abi_header" "$rust_core" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'S187_WORKER_CORE_GUARDRAILS_STATUS' "$service"
grep -Fq 'product-state/s187-worker-core-guardrails.properties' "$service"
grep -Fq 'schema=s187-worker-core-guardrails/v1' "$service"
grep -Fq 'PRODUCT_CORE_MAIN_CORE = "0"' "$service"
grep -Fq 'PRODUCT_CORE_WORKER_COUNT = "2"' "$service"
grep -Fq 'WorkerCpuPlacement.DEFAULT' "$service"
grep -Fq 'activeWorkerPlacement.worker0CpuId' "$service"
grep -Fq 'activeWorkerPlacement.worker1CpuId' "$service"
grep -Fq 'writeS187WorkerCoreGuardrailsStatus(status)' "$service"
grep -Fq 'threshold_scope=engineering_guardrail_not_release_slo' "$service"
grep -Fq 'placement_fixed_before_start=true' "$service"
grep -Fq 'dynamic_worker_change=false' "$service"
grep -Fq 'runtime_resize=false' "$service"
grep -Fq 'runtime_reshard=false' "$service"

python3 - "$service" "$native_status" "$abi_header" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
native_status = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
abi_header = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")


def body(source, signature):
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
    raise AssertionError("unclosed body for " + signature)


prepare = body(service, "private void prepareProductCoreProfile(")
for token in (
        'activeWorkerPlacement.startupConfig()',
        '"plugin_path " + nativeLibraryPath',
        '"plugins {\\n  path " + nativeLibraryPath',
        "ProductCoreOwner.writeAtomic(new File(profile, \"startup.conf\")"):
    if token not in prepare:
        raise AssertionError("S187 startup placement/config seam missing " + token)
if prepare.index('"plugin_path " + nativeLibraryPath') > prepare.index('"plugins {\\n  path "'):
    raise AssertionError("startup config must still publish plugin_path before allowlist")
if prepare.index('activeWorkerPlacement.startupConfig()') > prepare.index('"unix {'):
    raise AssertionError("S187 CPU placement must be in startup.conf before unix runtime launch config")

running_publish = body(service, "private boolean publishProductCoreRunning(")
if "writeS187WorkerCoreGuardrailsStatus(status)" not in running_publish:
    raise AssertionError("S187 running evidence must be written from product running publication")

writer = body(service, "private void writeS187WorkerCoreGuardrailsStatus(")
for token in (
        "schema=s187-worker-core-guardrails/v1",
        "profile=",
        "generation=",
        "placement_fixed_before_start=true",
        "main_core=",
        "worker_count=",
        "worker_cores=",
        "vpp_main_core=",
        "vpp_worker_count=",
        "vpp_worker0_thread_index=",
        "vpp_worker0_core=",
        "vpp_worker1_thread_index=",
        "vpp_worker1_core=",
        "worker_core_config_match=",
        "owner_mapping=",
        "owner_mapping_seed=",
        "dynamic_worker_change=false",
        "runtime_resize=false",
        "runtime_reshard=false",
        "product_graph_worker_count=",
        "product_graph_hash_seed=",
        "product_graph_handoff_credits=",
        "product_graph_enabled=",
        "product_graph_accepting=",
        "product_graph_worker_layout_ready=",
        "product_graph_obligation_debt=",
        "product_graph_buffer_debt=",
        "product_graph_handoff_debt=",
        "flow_pool_capacity=0",
        "worker_cache_capacity=0",
        "telemetry=low_cardinality_status_and_runner_samples",
        "threshold_scope=engineering_guardrail_not_release_slo",
        "artifact_id=",
        "api_identity=",
        "vpp_revision="):
    if token not in writer:
        raise AssertionError("S187 evidence writer missing " + token)

publish = body(service, "private boolean publish(")
if "writeS186ProfileSwitchBarrierStatus(next)" not in publish:
    raise AssertionError("S187 must not replace the durable S186 runtime-state projection")
if "writeS187WorkerCoreGuardrailsStatus" in publish:
    raise AssertionError("S187 status must be running-product evidence, not generic snapshot evidence")

if "private static final int STATUS_VALUE_COUNT = 135" not in native_status:
    raise AssertionError("S187 Product Core JNI status vector must include graph guardrail fields")
for token in (
        "public final int productGraphWorkerCount",
        "public final int productGraphVppWorkerCount",
        "public final int productGraphVppMainCore",
        "public final int productGraphVppWorker0Core",
        "public final int productGraphVppWorker1Core",
        "public final int productGraphWorkerLayoutReady",
        "public final long productGraphObligationDebt",
        "public final long productGraphBufferDebt",
        "public final long productGraphHandoffDebt"):
    if token not in native_status:
        raise AssertionError("S187 native status missing " + token)
if "_Static_assert(sizeof(sakamoto_product_status_t) == 1304U" not in abi_header:
    raise AssertionError("S187 Product Core ABI must include graph guardrail fields")
PY

for token in \
  'pub product_graph_worker_count: u32' \
  'pub product_graph_vpp_worker_count: u32' \
  'pub product_graph_vpp_main_core: u32' \
  'pub product_graph_worker_layout_ready: u32' \
  'product_graph_worker_count: value.product_graph_worker_count' \
  'product_graph_vpp_worker_count: value.product_graph_vpp_worker_count' \
  'value.product_graph_worker_count = status.product_graph_worker_count' \
  'value.product_graph_vpp_worker_count = status.product_graph_vpp_worker_count' \
  'assert_eq!(size_of::<ProductStatus>(), 1304)'; do
  grep -Fq -- "$token" "$rust_core"
done

for token in \
  'SAKAMOTO-187-worker-core-guardrails' \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'files/product-state/s187-worker-core-guardrails.properties' \
  '.s187-device-run.lock' \
  'if [[ "$run_lock_acquired" == 1 ]]; then' \
  'device_run_lock_acquired true' \
  'threshold_scope=engineering_guardrail_not_release_slo' \
  'pre_registered_thresholds=true' \
  'am force-stop "$PACKAGE"' \
  'preflight_force_stop_after_install true' \
  'SAKAMOTO_VPP_OWNER_TOKEN' \
  'adb_devices_contains_serial' \
  'adb-devices.${attempt}.stderr' \
  'owner.properties' \
  'startup.conf' \
  'main_core_configured' \
  'worker_count_configured' \
  'worker_cores_configured' \
  '(^|[[:space:]])workers[[:space:]]+[0-9]' \
  'idle.cpuPct' \
  'active.cpuPct' \
  'dual_stack_tcp_udp_load' \
  'assert_placement_static' \
  'capture_proc_metrics' \
  'pidof libvpp_runtime.so vpp' \
  '^[0-9]+([[:space:]][0-9]+)*' \
  'Cpus_allowed_list' \
  'did not show a main thread pinned to core 0' \
  'fd_count' \
  'thread_count' \
  'rss_kb' \
  'vpn_network_not_found' \
  'vpn_network_retry' \
  'start_probe_activity' \
  'runtimeStart true --es runtimeProfile "$profile"' \
  'debugTrafficBindToVpn "$bind_to_vpn"' \
  'final_residue_clean true'; do
  grep -Fq -- "$token" "$device_runner"
done

if grep -Eq 'sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|build-release-candidate|build-final-release|rm -rf' "$device_runner"; then
  echo "S187 runner uses a release/retired/historical path" >&2
  exit 1
fi

echo "sakamoto-187 worker/core guardrails contract: PASS"
