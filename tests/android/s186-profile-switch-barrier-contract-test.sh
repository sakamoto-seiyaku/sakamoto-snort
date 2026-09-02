#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
ordering="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlOrdering.java"
owner="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreOwner.java"
lifecycle="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/ProductCoreLifecycle.java"
debug_activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
device_runner="$repo_root/tests/device/s186-profile-switch-barrier-product.sh"

for file in "$service" "$ordering" "$owner" "$lifecycle" "$debug_activity" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'S186_PROFILE_SWITCH_BARRIER_STATUS' "$service"
grep -Fq 'product-state/s186-profile-switch-barrier.properties' "$service"
grep -Fq 'writeS186ProfileSwitchBarrierStatus(next)' "$service"
grep -Fq 'schema=s186-profile-switch-barrier/v1' "$service"
grep -Fq 'java_supervisor_single_switch_authority=true' "$service"
grep -Fq 'root_vpn_mutual_exclusion=one_profile_per_generation' "$service"
grep -Fq 'replacement_blocked_on_cleanup_failure=true' "$service"
grep -Fq 'isRetryableStartupTransportFailure(validation)' "$service"
grep -Fq 'boolean startupTransportRace = !session.isConnected()' "$service"
grep -Fq 'process.isAlive()' "$service"
grep -Fq 'isRetryableStartupReadinessFailure(validation)' "$service"
grep -Fq 'isRetryableStartupReadinessFailure(String code)' "$lifecycle"
grep -Fq '"product_worker_layout_mismatch".equals(code)' "$lifecycle"
grep -Fq 'isRetryableStartupTransportFailure(String code)' "$lifecycle"
grep -Fq '"product_core_unavailable".equals(code)' "$lifecycle"
grep -Fq '"product_core_unknown_failure".equals(code)' "$lifecycle"
grep -Fq 'applyHeadlessControlIntent(getIntent())' "$debug_activity"
grep -Fq 'applyHeadlessControlIntent(intent)' "$debug_activity"
grep -Fq 'hasInteractiveDebugExtras(intent)' "$debug_activity"
grep -Fq 'finish();' "$debug_activity"

python3 - "$service" "$ordering" "$owner" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
ordering = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
owner = pathlib.Path(sys.argv[3]).read_text(encoding="utf-8")


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


start = body(service, "private void startProductCoreRuntime(")
for token in (
        "boolean productProcessAlive = processAlive(vppProcess)",
        "boolean productSessionLive = productCoreSession != null",
        "if (productProcessAlive && productSessionLive)",
        "RuntimeProfile runningProfile = activeProfile == null",
        "if (selected == runningProfile)",
        "queryProductCoreRuntime()",
        "product_profile_switch_barrier=begin",
        "stopRequested = true",
        "stopRuntime(false)",
        "product_profile_switch_barrier=blocked",
        "cleanProductCoreProfileResidue(runningProfile)",
        "product_profile_switch_barrier=cleanup_failed",
        "product_profile_switch_barrier=old_stopped",
        "productProcessAlive = false",
        "productSessionLive = false",
        "if (productProcessAlive || productSessionLive)",
        "failProductCoreGeneration(\"product_core_session_missing\"",
        "activeProfile = selected",
        "generation = nextProductCoreGeneration(ownerDecision)"):
    if token not in start:
        raise AssertionError("Product Core switch path missing " + token)

if start.index("if (productProcessAlive && productSessionLive)") > start.index(
        "if (productProcessAlive || productSessionLive)"):
    raise AssertionError("different-profile switch must run before inconsistent-handle failure")
switch_block = start[start.index("product_profile_switch_barrier=begin"):
                     start.index("if (productProcessAlive || productSessionLive)")]
if switch_block.count("stopRequested = false;") < 2:
    raise AssertionError("switch barrier must clear stopRequested on failure and success")
if switch_block.index("stopRuntime(false)") > switch_block.index(
        "product_profile_switch_barrier=old_stopped"):
    raise AssertionError("target launch evidence appears before old profile stop barrier")
if switch_block.index("cleanProductCoreProfileResidue(runningProfile)") > switch_block.index(
        "product_profile_switch_barrier=old_stopped"):
    raise AssertionError("old profile residue cleanup must precede replacement evidence")

stop = body(service, "private boolean stopRuntime(boolean stopService)")
for token in (
        "publish(RuntimeSnapshot.stopping(current))",
        "boolean productProfileResidue = profileDirectory(RuntimeProfile.ROOT).exists()",
        "return stopProductCoreResidue(stopService)",
        "cleanupFaultInjected",
        "publishError(\"cleanup_failed\"",
        "return false",
        "closeProductCoreSession()",
        "terminateProductCoreProcess()",
        "terminateProductCoreOwnerProcess()",
        "auditProductCoreOwnerForStop()",
        "cleanProductCoreResidue(postKill)",
        "cleanProductCoreResidue(finalAudit)",
        "publish(RuntimeSnapshot.stopped("):
    if token not in stop:
        raise AssertionError("Product Core stop barrier missing " + token)

query = body(service, "private void queryProductCoreRuntime(")
if "productCoreQueryBlockedByErrorLatch()" not in query:
    raise AssertionError("health query must not clear terminal or cleanup-failed replacement blocks")

reconcile = body(service, "private void reconcileProductCoreRuntime(")
for token in (
        "publishError(\"runtime_recovered\"",
        "stopProductCoreResidue(false)"):
    if token not in reconcile:
        raise AssertionError("Product Core recovery must enter residue barrier before STOPPED")

cleanup = body(service, "private boolean cleanProductCoreResidue(")
if "productRootNfqueueResidueClean(RuntimeProfile.ROOT)" not in cleanup:
    raise AssertionError("explicit ROOT profile cleanup must not depend on activeProfile")

profile_cleanup = body(service, "private boolean cleanProductCoreProfileResidue(")
for token in (
        "RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile",
        "productRootNfqueueResidueClean(RuntimeProfile.ROOT)",
        "cleanProductCoreProfile(profileDirectory(selected))"):
    if token not in profile_cleanup:
        raise AssertionError("explicit old-profile switch cleanup missing " + token)

stop_residue = body(service, "private boolean stopProductCoreResidue(")
for token in (
        "if (ownerDecision.action == ProductCoreOwner.Action.BLOCK_LIVE)",
        "terminateGlobalProductCoreProcessesForStop()",
        "ownerDecision = auditProductCoreOwnerForStop()"):
    if token not in stop_residue:
        raise AssertionError("Product Core residue stop barrier missing " + token)

global_terminate = body(service, "private boolean terminateGlobalProductCoreProcessesForStop(")
for token in (
        "terminateGlobalProductCoreProcess(vpp, RuntimeProfile.ROOT)",
        "terminateGlobalProductCoreProcess(vpp, RuntimeProfile.VPN)"):
    if token not in global_terminate:
        raise AssertionError("Product Core orphan termination must cover both profiles")

single_global_terminate = body(service, "private boolean terminateGlobalProductCoreProcess(")
for token in (
        "auditGlobalProductCoreProcessPid(vpp, profile)",
        "kill -TERM ",
        "waitGlobalProductCoreProcessGone",
        "kill -KILL "):
    if token not in single_global_terminate:
        raise AssertionError("Product Core orphan termination missing " + token)

fault = body(service, "private void handleVpnFaultEvent(")
if "ignored stale VPN fault event=" not in fault:
    raise AssertionError("stale VPN fault event must be ignored after profile switch")
stale_fault = fault[fault.index("if (activeProfile != RuntimeProfile.VPN)"):
                    fault.index('if ("close_tun".equals(normalized))')]
if "publishError(" in stale_fault:
    raise AssertionError("stale VPN fault event must not publish replacement error")

revoke = body(service, "private void handleVpnAuthorizationRevoked(")
for token in (
        "ignored stale vpn_authorization_revoked",
        "snapshot.profile != RuntimeProfile.VPN",
        "!snapshot.isActive()",
        "failProductCoreGeneration(\"vpn_authorization_revoked\""):
    if token not in revoke:
        raise AssertionError("VPN revoke generation fence missing " + token)
if revoke.index("ignored stale vpn_authorization_revoked") > revoke.index(
        "failProductCoreGeneration(\"vpn_authorization_revoked\""):
    raise AssertionError("stale revoke guard must run before active VPN failure handling")

publish = body(service, "private boolean publish(")
if "writeS186ProfileSwitchBarrierStatus(next)" not in publish:
    raise AssertionError("S186 status must be written from the durable publish seam")

query = body(service, "private void queryProductCoreRuntime(")
if "productCoreQueryBlockedByErrorLatch()" not in query:
    raise AssertionError("Product Core query must honor cleanup-failure latch")

running_publish = body(service, "private boolean publishProductCoreRunning(")
for token in (
        "productCoreQueryBlockedByErrorLatch()",
        "product_core_running_publish=blocked_by_error_latch"):
    if token not in running_publish:
        raise AssertionError("Product Core running publish must not overwrite error latch")

error_latch = body(service, "private boolean productCoreQueryBlockedByErrorLatch(")
for token in (
        "RuntimeSnapshot.STATE_ERROR.equals(current.state)",
        "\"cleanup_failed\".equals(current.errorCode)"):
    if token not in error_latch:
        raise AssertionError("Product Core error latch missing " + token)

for token in (
        "latestRequestTimeMillis",
        "Decision.STALE",
        "requestTimeMillis < latestRequestTimeMillis",
        "startId < latestRequestStartId"):
    if token not in ordering:
        raise AssertionError("RuntimeControlOrdering missing " + token)

for token in (
        "Action.BLOCK_LIVE",
        "Action.BLOCK_UNKNOWN",
        "highestGeneration()",
        "decideGlobalForStart",
        "safeRoot.isLive() || safeVpn.isLive()",
        "safeRoot.isUnknown() || safeVpn.isUnknown()",
        "CLEAN_THEN_START"):
    if token not in owner:
        raise AssertionError("ProductCoreOwner global gate missing " + token)
PY

for token in \
  'SAKAMOTO-186-profile-switch-barrier' \
  'dev/adb' \
  '28201JEGR0XPAJ' \
  'files/product-state/s186-profile-switch-barrier.properties' \
  'runtimeStart true --es runtimeProfile "$profile"' \
  'runtimeCleanupFault true' \
  'cleanup_fault_blocks_replacement true' \
  'switch_root_to_vpn true' \
  'switch_vpn_to_root true' \
  'stale_vpn_events_ignored true' \
  'assert_no_mixed_resources' \
  'assert_no_root_hooks' \
  'assert_vpn_present' \
  'assert_no_vpn_residue' \
  'assert_product_process_count_at_most_one' \
  'assert_pid_absent_after_switch' \
  'zero_residue_observed' \
  'wait_for_zero_residue' \
  'did not reach stopped zero-residue' \
  'wait_for_zero_residue preflight' \
  'cold_start_control_activity' \
  'preflight_cold_start_settled true' \
  'wait_for_zero_residue cleanup_fault_cleared' \
  'wait_for_zero_residue final' \
  'final_residue_clean true' \
  'am_start_retry=' \
  'am start failed after 8 retries' \
  'am start -W -f 0x10008000'; do
  grep -Fq -- "$token" "$device_runner"
done

grep -Fq '/^[0-9]+$/ { count++ }' "$device_runner"
grep -Fq "awk '/^[0-9]+$/'" "$device_runner"

if grep -Eq 'sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|s70-profile-lifecycle|build-release-candidate|build-final-release|rm -rf' "$device_runner"; then
  echo "S186 runner uses a retired, runner-side cleanup, or historical path" >&2
  exit 1
fi

echo "sakamoto-186 profile switch barrier contract: PASS"
