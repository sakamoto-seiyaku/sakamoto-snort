#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
ffi="$repo_root/src/product/include/sakamoto_product_core_ffi.h"
rust="$repo_root/crates/product-core/src/lib.rs"
jni="$repo_root/app/android-runtime/src/main/native/sakamoto_product_core_jni.c"
bundle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyBundle.java"
compiler="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyCompiler.java"
transactions="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductPolicyTransactions.java"
native_java="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlNative.java"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
api="$repo_root/src/product/vpp/product_core.api"
artifact="$repo_root/src/product/vpp/product-vpp-artifact.properties"

# ABI and bounds are part of the source contract, not an allocation detail.
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_ABI_VERSION UINT32_C(1)' "$abi"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_GATE_ENTRIES UINT32_C(64)' "$abi"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_L4_ENTRIES UINT32_C(64)' "$abi"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_BUNDLE_MAX_RULE_ENTRIES UINT32_C(128)' "$abi"
grep -Fq 'uint32_t ifindex;' "$abi"
grep -Fq 'uint32_t rule_kind;' "$abi"
grep -Fq 'uint32_t ip_family;' "$abi"
grep -Fq 'uint32_t ip_protocol;' "$abi"
grep -Fq 'uint32_t enabled;' "$abi"
grep -Fq 'uint64_t rule_id;' "$abi"
grep -Fq 'uint32_t reason_id;' "$abi"
grep -Fq 'uint8_t source_address[16];' "$abi"
grep -Fq 'uint8_t destination_address[16];' "$abi"
grep -Fq 'sizeof(sakamoto_product_policy_rule_entry_t) == 120' "$abi"
grep -Fq 'sizeof(sakamoto_product_policy_bundle_t) == 15496' "$abi"
grep -Fq 'sakamoto_product_session_apply_policy_bundle' "$abi"
grep -Fq 'sakamoto_product_core_apply_policy_bundle' "$ffi"

# S192 status is an append-only native view extension.  The old 136-value
# prefix remains parseable, while the wire bridge carries seven typed fields.
for field in \
  'uint32_t policy_l4_view_active;' \
  'uint32_t policy_l4_view_rule_count;' \
  'uint32_t policy_l4_view_max_probes;' \
  'uint32_t policy_l4_view_last_match_winner_rank;' \
  'uint32_t policy_l4_view_last_match_probes;' \
  'uint32_t policy_l4_view_last_match_candidate_count;' \
  'uint32_t policy_l4_view_last_no_match_reason;'; do
  grep -Fq "$field" "$abi"
done
for field in \
  'u32 policy_l4_view_active;' \
  'u32 policy_l4_view_rule_count;' \
  'u32 policy_l4_view_max_probes;' \
  'u32 policy_l4_view_last_match_winner_rank;' \
  'u32 policy_l4_view_last_match_probes;' \
  'u32 policy_l4_view_last_match_candidate_count;' \
  'u32 policy_l4_view_last_no_match_reason;'; do
  grep -Fq "$field" "$api"
done

# Rust validates every count/entry before one complete store + native path.
grep -Fq 'pub struct ProductPolicyRuleEntry' "$rust"
grep -Fq 'pub struct ProductPolicyBundle' "$rust"
grep -Fq 'fn validate_policy_bundle' "$rust"
grep -Fq 'POLICY_BUNDLE_MAX_GATE_ENTRIES: usize = 64' "$rust"
grep -Fq 'POLICY_BUNDLE_MAX_L4_ENTRIES: usize = 64' "$rust"
grep -Fq 'fn current_policy_bundle' "$rust"
grep -Fq 'fn stage_policy_bundle' "$rust"
grep -Fq 'fn commit_policy_bundle' "$rust"
grep -Fq 'policy-bundle.properties.tmp' "$rust"
grep -Fq 'sakamoto_product_session_apply_policy_bundle' "$rust"
grep -Fq 'apply_policy_bundle_native' "$rust"

# The new native path cannot hide a count==1 or replay legacy scalar applies.
bundle_fn="$(sed -n '/pub unsafe extern "C" fn sakamoto_product_core_apply_policy_bundle(/,/^}/p' "$rust")"
test -n "$bundle_fn"
! grep -Eq 'l4_rule_count[[:space:]]*==[[:space:]]*1' <<<"$bundle_fn"
! grep -Fq 'sakamoto_product_session_apply_l4_policy' <<<"$bundle_fn"
! grep -Fq 'sakamoto_product_session_apply_network_gate_policy' <<<"$bundle_fn"

# JNI carries one fixed byte payload and calls one typed FFI entry.
grep -Fq 'nativeApplyPolicyBundle' "$native_java"
grep -Fq 'bundlePayload.length == AuthoringPolicyBundle.BUNDLE_BYTES' "$native_java"
grep -Fq 'Java_com_sakamoto_snort_androidruntime_RuntimeControlNative_nativeApplyPolicyBundle' "$jni"
grep -Fq 'GetByteArrayRegion' "$jni"
grep -Fq 'sizeof (sakamoto_product_policy_bundle_t)' "$jni"
grep -Fq 'sakamoto_product_core_apply_policy_bundle' "$jni"

# Java encoder mirrors the fixed C layout and retains legacy constructors.
grep -Fq 'BUNDLE_ABI_VERSION = 1' "$bundle"
grep -Fq 'MAX_GATE_ENTRIES = 64' "$bundle"
grep -Fq 'MAX_L4_RULES = 64' "$bundle"
grep -Fq 'RULE_ENTRY_BYTES = 120' "$bundle"
grep -Fq 'BUNDLE_BYTES' "$bundle"
grep -Fq 'ifIndex' "$bundle"
grep -Fq 'enabled' "$bundle"
grep -Fq 'validateForNativeBundle' "$bundle"
grep -Fq 'toNativeBundlePayload' "$bundle"
grep -Fq 'ByteOrder.LITTLE_ENDIAN' "$bundle"
grep -Fq 'compilePolicyBundle' "$compiler"
grep -Fq 'nativeBundlePayload' "$compiler"
grep -Fq 'bundleSnapshotHash' "$compiler"
grep -Fq 'requiresCompleteNativeBundle' "$compiler"
grep -Fq 'forceNativeBundle' "$compiler"
grep -Fq 'nativeApply\":\"s191-scalar' "$compiler"
grep -Fq 'compilePolicyBundle(committed)' "$transactions"
grep -Fq 'compilePolicyBundle(selected.bundle)' "$transactions"
if grep -Fq 'compilePacketPolicyApply(committed)' "$transactions"; then
  echo "S192 transaction apply must not call the legacy scalar compiler" >&2
  exit 1
fi
grep -Fq 'scalar Product policy apply requires explicit S191 compatibility' "$service"
grep -Fq 'session.applyPolicyBundle' "$service"
grep -Fq 'Base64.getDecoder().decode' "$service"
grep -Fq 'nativeBundleSnapshotHash(bundleWire)' "$service"
grep -Fq 'status.policySnapshotHash != canonicalBundleHash' "$service"
grep -Fq 'Long.parseUnsignedLong(canonicalHashText)' "$service"

# Typed status readback is selected by the durable bundle identity and remains
# profile-neutral; the S191 scalar branch keeps its Root/one-rule boundary.
python3 - "$service" <<'PY'
import pathlib
import sys

source = pathlib.Path(sys.argv[1]).read_text()

def body(signature):
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
    raise AssertionError("unterminated method: " + signature)

runtime = body("private String validateRuntimePolicySnapshot(")
assert runtime.index("AuthoringPolicyBundle.BUNDLE_FORMAT") < runtime.index(
    "validateEmptyPolicySnapshot"), "typed validator must precede legacy validators"
assert "validatePolicyBundleSnapshot(status, -1L)" in runtime

bundle = body("private String validatePolicyBundleSnapshot(")
for token in (
    "AuthoringPolicyBundle.MAX_GATE_ENTRIES",
    "AuthoringPolicyBundle.MAX_L4_RULES",
    "AuthoringPolicyBundle.MAX_RULE_ENTRIES",
    "policyL4ViewActive != 1",
    "policyL4ViewRuleCount > l4Rules",
    "policyMixedRevision",
    "policyArtifactMatch",
):
    assert token in bundle, token

apply = body("private LocalProductBackend.PolicyApplyResult applyCommittedProductPolicy(")
typed_start = apply.index('if (payload.has("bundleAbiVersion")')
scalar_start = apply.index('if (!"s191-scalar".equals', typed_start)
typed = apply[typed_start:scalar_start]
assert "validatePolicyBundleSnapshot(status, compiledRevision)" in typed
assert "nativeBundleSnapshotHash(bundleWire)" in typed
assert "status.policySnapshotHash != canonicalBundleHash" in typed
assert "nativeBundleHeaderMatches(bundleWire, compiledRevision)" in typed
assert "String gateStage = networkGateEvidenceStage(status)" in typed
assert "writeS189RootNetworkGateStatus(status, gateStage, \"\", \"\")" in typed
assert "writeS190VpnNetworkGateStatus(status, gateStage, \"\", \"\")" in typed
assert "rootL4FactsFromPolicyPayload(subjects)" in typed
assert "writeS191RootL4Status(status, facts, \"l4_apply\", \"\", \"\")" in typed
assert "activeProfile != RuntimeProfile.ROOT" not in typed, \
    "typed bundle apply must allow Root and VPN"
scalar = apply[scalar_start:]
assert "activeProfile != RuntimeProfile.ROOT" in scalar
assert "l4Rules.length() != 1" in scalar
assert "session.applyL4PolicyRevision" in scalar

writer = body("private void writeS192L4MatrixStatus(")
for token in (
    "observeS192Counters(status, probe)",
    "s192ProbeMatchesRule",
    "strongExactProbeIdentity",
    "perProbeMatchEvidence",
    "policyEpochMatchEvidence",
    "policyNoMatchRecordsAdvanced",
    "probeEpochFallbackCandidate",
    "policyL4TypedMatchProbeKey",
    "policyL4LastEvaluationProbeKey",
    "policy_l4_match_records=",
    "policy_l4_no_match_records=",
    "policy_drop_records=",
):
    assert token in writer, token
assert "boolean matched = evaluation == PRODUCT_L4_EVALUATION_MATCH" not in writer
assert "boolean strongExactProbeIdentity = probeMatchesLastRule" in writer
assert "boolean policyEpochMatchEvidence" in writer
assert "boolean epochMatchFallback = policyEpochMatchEvidence" in writer
assert "&& counters.probeEpochFallbackCandidate" in writer
assert "boolean noMatchEpochFallback = counters.policyNoMatchRecordsAdvanced" in writer
assert "boolean noMatch = (counters.noMatchRecordsAdvanced || noMatchEpochFallback)" in writer
assert "boolean matched = nativeMatchEvidence && strongExactProbeIdentity" in writer
assert writer.index("policyEpochMatchEvidence") < writer.index(
    "boolean matched = nativeMatchEvidence")

typed_probe = body("private static boolean s192ProbeMatchesRule(")
assert "s192TypedWinnerMatches(status)" in typed_probe
typed_winner = body("private static boolean s192TypedWinnerMatches(")
assert "policyL4ViewLastMatchWinnerRank" in typed_winner
assert "PRODUCT_POLICY_WINNER_L4" in typed_winner
claim_count = body("private static int s192BlockedGateClaimCount(")
assert "rule.enabled && rule.blocked" in claim_count
bundle_status = body("private static boolean s192BundleStatusMatches(")
assert "s192BlockedGateClaimCount(bundle)" in bundle_status
assert "status.policyGateClaimCount != bundle.gateEntryCount" not in bundle_status
PY

# Runtime evidence is sourced from native view status plus durable bundle and
# completed probe facts, and is published for apply/query/stop transitions.
grep -Fq 'S192_ROOT_VPN_L4_MATRIX_STATUS' "$service"
grep -Fq 'writeS192L4MatrixStatus' "$service"
grep -Fq 'readLatestS192Probe' "$service"
for key in \
  'schema=s192-root-vpn-l4-matrix/v1' \
  'policy_case=' \
  'policy_uid_complete=' \
  'policy_revision=' \
  'policy_snapshot_hash=' \
  'policy_snapshot_identity=' \
  'policy_network_context=' \
  'policy_ifindex=' \
  'policy_direction=' \
  'policy_ports_available=' \
  'policy_evaluation=' \
  'policy_action=' \
  'policy_rule_id=' \
  'policy_reason_id=' \
  'policy_winner_rank=' \
  'policy_candidate_count=' \
  'policy_probe_count=' \
  'policy_probe_limit=' \
  'policy_subject_probe_count=' \
  'policy_no_match_reason=' \
  'policy_l4_match_records=' \
  'policy_l4_no_match_records=' \
  'policy_drop_records=' \
  'policy_probe_baseline_known=' \
  'policy_probe_match_delta=' \
  'policy_probe_no_match_delta=' \
  'policy_probe_drop_delta=' \
  'policy_strong_exact_probe_identity=' \
  'policy_probe_match_evidence=' \
  'policy_epoch_match_evidence=' \
  'policy_epoch_match_fallback=' \
  'policy_no_match_epoch_delta=' \
  'policy_epoch_no_match_fallback=' \
  'policy_probe_epoch_fallback_candidate=' \
  'policy_typed_match_probe_key=' \
  'policy_last_evaluation_probe_key=' \
  'policy_same_probe=' \
  'policy_verdict=' \
  'residue_clean='; do
  grep -Fq "$key" "$service"
done
grep -Fq 'policyL4ViewActive' "$native_java"
grep -Fq 'policyL4ViewLastNoMatchReason' "$native_java"
grep -Fq 'policyL4TypedMatchPolicyKey' "$native_java"
grep -Fq 'policyL4TypedMatchProbeKey' "$native_java"
grep -Fq 'policyL4LastEvaluationProbeKey' "$native_java"
grep -Fq 'STATUS_VIEW_VALUE_COUNT = 7' "$native_java"
grep -Fq 'parseIntAt(values, offset + 142' "$native_java"

# The API source and generated-artifact identity are kept in lockstep by the
# pinned VPP generator; generated output is verified by the host build gate.
grep -Fq 'typedef product_policy_rule_entry' "$api"
grep -Fq 'define product_core_policy_bundle_apply' "$api"
grep -Fq 'vl_api_product_policy_rule_entry_t gate_entries[64]' "$api"
grep -Fq 'vl_api_product_policy_rule_entry_t l4_entries[64]' "$api"
grep -Fq 'product_core_policy_bundle_apply_reply' "$api"
grep -Fq 'product_core.api/1.0.0@aa3af3cd' "$artifact"

plugin="$repo_root/src/product/vpp/product_core_plugin.c"
grep -Fq 'vl_api_product_core_policy_bundle_apply_t_handler' "$plugin"
grep -Fq 'product_l4_policy_compile' "$plugin"
grep -Fq 'product_packet_graph_apply_policy_bundle' "$plugin"
grep -Fq 'gate_entries[' "$plugin"
grep -Fq 'l4_entries[' "$plugin"

# S191 scalar ABI and exactly-one compatibility checks remain in place.
grep -Fq 'sizeof(sakamoto_product_policy_snapshot_t) == 264' "$abi"
grep -Fq 'applyL4PolicyRevision' "$native_java"
grep -Fq 'l4Rules.length() != 1' "$service"
grep -Fq 'observeS192Counters' "$service"
grep -Fq 's192ProbeMatchesRule' "$service"
grep -Fq 's192ProbePortsMatch' "$service"
grep -Fq 's192HostMatchesCidr' "$service"
grep -Fq 'policyL4TypedMatchProbeKey' "$service"
grep -Fq 'policyL4LastEvaluationProbeKey' "$service"
if grep -Fq 'boolean matched = evaluation == PRODUCT_L4_EVALUATION_MATCH' "$service"; then
  echo "S192 writer must not trust last_evaluation_result without bounded evidence" >&2
  exit 1
fi

out_dir="$(mktemp -d)"
trap 'rm -rf -- "$out_dir"' EXIT
javac -source 8 -target 8 -d "$out_dir" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ApplicationSubjectId.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyBundle.java" \
  "$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/AuthoringPolicyCompiler.java" \
  "$repo_root/tests/android/S192PolicyBundleContractTest.java"
java -cp "$out_dir" S192PolicyBundleContractTest

echo "s192 policy bundle contract: PASS"
