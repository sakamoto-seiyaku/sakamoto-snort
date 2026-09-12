#!/usr/bin/env bash
set -euo pipefail

# Historical S179 source-shape oracle. Its fixed ABI sizes, synchronous
# completion bodies and synthetic unknown-verdict expectations predate the
# current worker-owned implementation. Do not cite it as S242 coverage; use
# the current VAPI lifecycle, receive identity and real device matrices.

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
recovery="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeRecoveryPolicy.java"
native_status="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
api="$repo_root/src/product/vpp/product_core.api"
plugin="$repo_root/src/product/vpp/product_core_plugin.c"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
rust="$repo_root/crates/product-core/src/lib.rs"
graph="$repo_root/src/product/vpp/product_packet_graph.c"
root_adapter="$repo_root/src/product/vpp/product_root_nfqueue_adapter.c"
root_adapter_header="$repo_root/src/product/vpp/product_root_nfqueue_adapter.h"
device_runner="$repo_root/tests/device/s179-root-fault-recovery-product.sh"

for file in \
  "$service" "$activity" "$recovery" "$native_status" "$jni" "$abi" \
  "$api" "$plugin" "$vapi" "$rust" "$graph" "$root_adapter" \
  "$root_adapter_header"; do
  test -f "$file"
done
test -x "$device_runner"
chain_name="$(sed -n 's/^readonly NO_LISTENER_CHAIN="\(.*\)"/\1/p' "$device_runner")"
[[ -n "$chain_name" && "${#chain_name}" -le 28 ]]

grep -Fq 'S179_ROOT_FAULT_RECOVERY_STATUS' "$service"
grep -Fq 'product-state/s179-root-fault-recovery.properties' "$service"
grep -Fq 'writeBestEffortEvidenceFile(S179_ROOT_FAULT_RECOVERY_STATUS, text)' "$service"
grep -Fq 'runtimeCleanupFault' "$activity"
grep -Fq 'backend.setCleanupFault' "$activity"
grep -Fq 'cleanupFaultInjected' "$service"
grep -Fq 'publishError("cleanup_failed"' "$service"
grep -Fq 'mayBeActive' "$service"
grep -Fq 'productRootNfqueueResidueClean()' "$service"
grep -Fq 'reconcileProductCoreRuntime' "$service"
grep -Fq 'runtime_recovered' "$service"
grep -Fq 'kill -TERM ' "$service"
grep -Fq 'kill -KILL ' "$service"
grep -Fq 'MAX_FAILURES = 3' "$recovery"
grep -Fq 'runtime_auto_recovery_pending' "$recovery"
grep -Fq 'runtime_recovery_intervention_required' "$recovery"

for field in \
  root_nfqueue_verdict_succeeded \
  root_nfqueue_verdict_failed_definite \
  root_nfqueue_verdict_outcome_unknown \
  root_nfqueue_ingress_identity_missing \
  root_nfqueue_graph_submit_fail_opens \
  root_nfqueue_non_owner_bypasses \
  root_nfqueue_duplicate_completion_drops \
  root_nfqueue_stale_completion_drops; do
  grep -Fq "$field" "$api"
  grep -Fq "$field" "$abi"
  grep -Fq "$field" "$plugin"
  grep -Fq "$field" "$vapi"
  grep -Fq "$field" "$jni"
  grep -Fq "$field" "$rust"
done

for field in \
  rootNfqueueVerdictSucceeded \
  rootNfqueueVerdictFailedDefinite \
  rootNfqueueVerdictOutcomeUnknown \
  rootNfqueueIngressIdentityMissing \
  rootNfqueueGraphSubmitFailOpens \
  rootNfqueueNonOwnerBypasses \
  rootNfqueueDuplicateCompletionDrops \
  rootNfqueueStaleCompletionDrops; do
  grep -Fq "$field" "$native_status"
done

grep -Fq 'STATUS_VALUE_COUNT = 135' "$native_status"
grep -Fq 'STATUS_VALUE_COUNT = 135' "$jni"
grep -Fq 'sizeof(sakamoto_product_status_t) == 1304U' "$abi"
grep -Fq 'size_of::<ProductStatus>(), 1304' "$rust"

grep -Fq 'nm->ingress_identity_missing++' "$root_adapter"
grep -Fq 'nm->graph_submit_fail_opens++' "$root_adapter"
grep -Fq 'nm->non_owner_bypasses++' "$root_adapter"
grep -Fq 'nm->duplicate_completion_drops++' "$root_adapter"
grep -Fq 'nm->stale_completion_drops++' "$root_adapter"
grep -Fq 'nm->verdict_failed_definite++' "$root_adapter"
grep -Fq 'lane->listener_ready && lane->clib_file_index != ~0' "$root_adapter"
grep -Fq 'product_root_nfqueue_adapter_verdict_succeeded' "$root_adapter_header"
grep -Fq 'product_root_nfqueue_adapter_verdict_failed_definite' "$root_adapter_header"
grep -Fq 'product_root_nfqueue_adapter_ingress_identity_missing' "$root_adapter_header"
grep -Fq 'product_root_nfqueue_adapter_duplicate_completion_drops' "$root_adapter_header"

python3 - "$root_adapter" "$graph" <<'PY'
import pathlib
import sys

adapter = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
graph = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")


def function_body(source, signature):
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
    raise AssertionError("unclosed function: " + signature)


def if_block(source, needle):
    start = source.index(needle)
    brace = source.index("{", start)
    depth = 0
    for index in range(brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    raise AssertionError("unclosed block: " + needle)


read_ready = function_body(adapter, "product_root_nfqueue_read_ready (")
parse_missing = if_block(read_ready, "if (!product_root_nfqueue_parse_packet")
if "nm->ingress_identity_missing++" not in parse_missing:
    raise AssertionError("missing ingress identity is not counted")
if "product_packet_graph_submit_external" in parse_missing:
    raise AssertionError("missing ingress identity still enters the graph")
if "packet.packet_id != 0" not in parse_missing:
    raise AssertionError("parse failure does not distinguish packets with a verdict identity")
if "nm->graph_submit_fail_opens++" not in parse_missing:
    raise AssertionError("parse failure with a verdict identity is not fail-open")
if "product_root_nfqueue_send_counted_verdict" not in parse_missing:
    raise AssertionError("parse failure with a verdict identity cannot release the kernel packet")

submit_fail = if_block(read_ready, "if (!submitted)")
if "nm->graph_submit_fail_opens++" not in submit_fail:
    raise AssertionError("graph submit failure is not counted as fail-open")
if "NF_ACCEPT" not in submit_fail:
    raise AssertionError("graph submit failure does not fail-open")

non_owner = if_block(
    read_ready,
    "if (packet.hook == NF_INET_LOCAL_OUT && packet.uid_present",
)
if "nm->non_owner_bypasses++" not in non_owner or "NF_ACCEPT" not in non_owner:
    raise AssertionError("non-owner OUTPUT bypass is not explicit")

complete = function_body(adapter, "product_root_nfqueue_complete_from_graph (")
send_index = complete.index("product_nfqueue_send_verdict")
if complete.index("nm->stale_completion_drops++") > send_index:
    raise AssertionError("stale completion can reach verdict send")
if complete.index("nm->duplicate_completion_drops++") > send_index:
    raise AssertionError("duplicate completion can reach verdict send")
if "nm->verdict_failed_definite++" not in complete:
    raise AssertionError("deterministic verdict send failure is not classified")

send_verdict = function_body(adapter, "product_nfqueue_send_verdict (")
if "request.nlh.nlmsg_flags = NLM_F_REQUEST;" not in send_verdict:
    raise AssertionError("NFQUEUE verdicts must not request netlink ACKs")
if "NLM_F_ACK" in send_verdict:
    raise AssertionError("NFQUEUE verdict path reintroduced netlink ACKs")

recover_extra = function_body(adapter, "product_root_nfqueue_accept_extra_messages (")
for required in (
        "NLMSG_NEXT",
        "NFQNL_MSG_PACKET",
        "NFQA_PACKET_HDR",
        "primary_packet_id",
        "product_root_nfqueue_packet_id_seen",
        "nm->graph_submit_fail_opens++",
        "product_root_nfqueue_send_counted_verdict"):
    if required not in recover_extra:
        raise AssertionError("multi-message fail-open recovery missing " + required)
if "product_root_nfqueue_accept_extra_messages" not in parse_missing:
    raise AssertionError("parse-failure fail-open does not recover extra packet IDs")
if "product_root_nfqueue_accept_extra_messages" not in submit_fail:
    raise AssertionError("graph-submit fail-open does not recover extra packet IDs")

submit_external = function_body(graph, "product_packet_graph_submit_external (")
for required in (
        "origin_obligation_id == 0",
        "product_handoff_credit_reserve",
        "PRODUCT_PACKET_DROP_PRIMARY_HANDOFF_CONGESTION",
        "PRODUCT_PACKET_INTENT_PASS_ADAPTER",
        "graph->external_completion",
        "vlib_buffer_free"):
    if required not in submit_external:
        raise AssertionError("graph external submit missing " + required)
if submit_external.index("origin_obligation_id == 0") > submit_external.index("vlib_get_buffer"):
    raise AssertionError("missing origin identity is checked after buffer ownership")

for required in (
        "PRODUCT_GRAPH_HANDOFF_CREDITS 32",
        "duplicate_terminals",
        "duplicate_settlements",
        "stale_events_rejected",
        "congestion_rejections",
        "product_packet_graph_run_lifecycle_fixture_cli",
        "fixture.generation.stale_events_rejected",
        "fixture.duplicate_settlements=0",
        "product_packet_graph_disable_cli"):
    if required not in graph:
        raise AssertionError("packet graph fault/recovery fixture missing " + required)
PY

for token in \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-179-root-fault-recovery' \
  'remote_shell_quote' \
  'adb_target shell "su 0 sh -c $quoted"' \
  'try_lan_probe_echo' \
  'wait_for_host_ready' \
  '.properties.ready' \
  '.server.log' \
  '_probe_attempt' \
  'cleanup_product_hooks_best_effort' \
  'assert_product_hooks_absent' \
  'S179 preflight saw Product NFQUEUE hook residue' \
  'no_listener_bypass supported' \
  'no_listener_bypass unsupported' \
  'pixel6a_nfqueue_queue_bypass_did_not_release_without_listener' \
  'no-listener-bypass.${label}.iptables' \
  'runtimeCleanupFault true' \
  'runtimeCleanupFault false' \
  'debugRefresh true' \
  'cleanup_fault_blocks_stop true' \
  'recovery_lan_probe matched' \
  'final_residue_clean true' \
  'files/product-state/s179-root-fault-recovery.properties' \
  'verdict_failed_definite' \
  'graph_submit_fail_opens' \
  'duplicate_completion_drops' \
  'stale_completion_drops'; do
  grep -Fq "$token" "$device_runner"
done

echo "sakamoto-179 Root fault/recovery contract: PASS"
