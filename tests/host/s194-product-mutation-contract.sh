#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/../.." && pwd)"
abi="$repo_root/src/product/include/sakamoto_product_abi.h"
vapi="$repo_root/src/product/native/sakamoto_product_vapi.c"
fixture="$repo_root/src/product/native/sakamoto_product_host_fixture_abi.c"
core="$repo_root/crates/product-core/src/lib.rs"
callback_contract="$repo_root/tests/host/product_vapi_callback_contract.sh"

fail() {
  echo "s194 product mutation contract: $*" >&2
  exit 1
}

grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN UINT32_C(14)' "$abi" \
  || fail "missing append-only OUTCOME_UNKNOWN tag"
grep -Fq '#define SAKAMOTO_PRODUCT_POLICY_MUTATION_FENCED UINT32_C(15)' "$abi" \
  || fail "missing append-only mutation-fenced tag"
grep -Fq 'call->transport_code = SAKAMOTO_PRODUCT_POLICY_OUTCOME_UNKNOWN;' "$vapi" \
  || fail "post-submit callback failure is not classified as unknown"
grep -Fq '"VAPI policy apply callback was not invoked"' "$vapi" \
  || fail "callback omission path disappeared"
grep -Fq 'SAKAMOTO_PRODUCT_POLICY_APPLY_FAILED' "$vapi" \
  || fail "deterministic VPP retval path disappeared"
grep -Fq 'SAKAMOTO_PRODUCT_POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT' "$abi" \
  || fail "pre-submit fault tag is missing"
grep -Fq 'sakamoto_product_session_set_policy_mutation_fault' "$vapi" \
  || fail "VAPI fault arming seam is missing"
grep -Fq 'sakamoto_product_session_set_policy_mutation_fault' "$fixture" \
  || fail "Host fixture does not export the append-only fault ABI"
grep -Fq 'debug policy bundle apply was not submitted' "$vapi" \
  || fail "pre-submit not-sent path is missing"

grep -Fq 'PolicyOutcomeUnknown' "$core" \
  || fail "Rust outcome-unknown projection is missing"
grep -Fq 'PolicyMutationFenced' "$core" \
  || fail "Rust mutation-fenced projection is missing"
grep -Fq 'policy-mutation-fence.properties' "$core" \
  || fail "durable fence file is missing"
grep -Fq 'policy-mutation-candidate.properties' "$core" \
  || fail "durable candidate file is missing"
grep -Fq 'reconcile_unknown_mutation' "$core" \
  || fail "fresh-generation reconcile path is missing"
grep -Fq 'active_policy_matches_fence' "$core" \
  || fail "readback identity tuple is missing"

# The ambiguous native result must retain a candidate before publishing the
# fence; a deterministic native error must only remove the temp file.
grep -Fq 'store.quarantine_policy_bundle(&temporary)' "$core" \
  || fail "unknown result does not retain the staged candidate"
grep -Fq 'store.write_mutation_fence(&fence)' "$core" \
  || fail "unknown result does not persist the fence"
grep -Fq 'store.discard_staged_policy_bundle(&temporary)' "$core" \
  || fail "definite failure does not discard the staged file"

bash "$callback_contract"
echo "s194 product mutation contract: PASS"
