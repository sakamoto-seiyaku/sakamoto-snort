#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

protocol="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlProtocol.java"
backend="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlBackend.java"
activity="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/DebugControlActivity.java"
service="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeService.java"
fd_client="$repo_root/app/android-runtime/src/main/java/com/sakamoto/snort/androidruntime/RuntimeControlFdClient.java"
vpn_adapter="$repo_root/src/product/vpp/product_vpn_udp4_adapter.c"
device_runner="$repo_root/tests/device/s185-vpn-fault-recovery-product.sh"

for file in "$protocol" "$backend" "$activity" "$service" "$fd_client" \
  "$vpn_adapter" "$device_runner"; do
  test -f "$file"
done
test -x "$device_runner"

grep -Fq 'EXTRA_VPN_FAULT_MODE' "$protocol"
grep -Fq 'runtimeVpnFaultMode' "$protocol"
grep -Fq 'EXTRA_VPN_FAULT_EVENT' "$protocol"
grep -Fq 'runtimeVpnFaultEvent' "$protocol"
grep -Fq 'setVpnFaultMode' "$backend"
grep -Fq 'sendVpnFaultEvent' "$backend"
grep -Fq 'backend.start(this, profile, rootNfqueueFaultMode, vpnFaultMode)' "$activity"
grep -Fq 'startProfile(requestedRuntimeProfile, requestedRootNfqueueFaultMode,' "$activity"
if grep -Fq 'main.post(() -> startProfile(requestedRuntimeProfile' "$activity"; then
  echo "S185 automation start must execute directly from the delivered Activity intent" >&2
  exit 1
fi
grep -Fq 'runtimeVpnFaultMode' "$activity"
grep -Fq 'runtimeVpnFaultEvent' "$activity"
grep -Fq 'startProfile(requestedRuntimeProfile, requestedRootNfqueueFaultMode,' "$activity"
grep -Fq 'requestedVpnFaultMode, false)' "$activity"
grep -Fq 'boolean requireVpnPrepare' "$activity"
grep -Fq 'requireVpnPrepare && profile == RuntimeProfile.VPN' "$activity"
grep -Fq 'connectivityManager.getAllNetworks()' "$activity"
grep -Fq 'capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)' "$activity"
grep -Fq 'vpn_network_not_found' "$activity"
if grep -Fq 'active_network_not_vpn' "$activity"; then
  echo "S185 VPN-bound debug probes must find the VPN Network, not assume active Network is VPN" >&2
  exit 1
fi

grep -Fq 'S185_VPN_FAULT_RECOVERY_STATUS' "$service"
grep -Fq 'product-state/s185-vpn-fault-recovery.properties' "$service"
grep -Fq 'writeS185VpnFaultRecoveryStatus(status)' "$service"
grep -Fq 'writeS185VpnFaultRecoveryErrorStatus(next)' "$service"
grep -Fq 'handleVpnAuthorizationRevoked("system")' "$service"
grep -Fq 'handleVpnAuthorizationRevoked("debug")' "$service"
grep -Fq 'vpnFaultModeIs("establish_null")' "$service"
grep -Fq 'vpnFaultModeIs("protect_false")' "$service"
grep -Fq 'vpnFaultModeIs("bind_failed")' "$service"
grep -Fq 'VPN_FAULT_CLOSE_TUN' "$service"
grep -Fq 'VPN_FAULT.CLOSE_TUN' "$fd_client"

grep -Fq 'vpn-fault-close-tun-debug' "$vpn_adapter"
grep -Fq 'VPN_FAULT.CLOSE_TUN' "$vpn_adapter"
grep -Fq 'product_vpn_close_tun_for_fault' "$vpn_adapter"
grep -Fq 'tun_abnormal_close' "$vpn_adapter"

python3 - "$service" "$vpn_adapter" <<'PY'
import pathlib
import sys

service = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
adapter = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")


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


on_create = body(service, "public void onCreate()")
if "enqueueLifecycle(this::reconcileDurableRuntime)" in on_create:
    raise AssertionError("service_create must not reconcile before S185 fault-event intents")

publish = body(service, "private boolean publish(")
if "RuntimeSnapshot.STATE_ERROR.equals(next.state)" not in publish:
    raise AssertionError("S185 error projection must be emitted from durable publish")

revoke = body(service, "private void handleVpnAuthorizationRevoked(")
if "failProductCoreGeneration(\"vpn_authorization_revoked\"" not in revoke:
    raise AssertionError("VPN revoke must enter Product Core cleanup")
if "publishError(\"vpn_authorization_revoked\"" not in revoke:
    raise AssertionError("VPN revoke must publish a stable projection without a runtime")

establish = body(service, "private VpnTunPlatformSession establishPacketAdapterSession(")
if establish.index("VpnService.prepare(this)") > establish.index(
        "VpnTunPlatformSession.establish"):
    raise AssertionError("VPN authorization must be checked before TUN establish")
if "vpn_establish_returned_null" not in establish:
    raise AssertionError("S185 must cover establish-null classification")

event = body(service, "private void handleVpnFaultEvent(")
for token in (
        "RuntimeSnapshot.STATE_ERROR.equals(snapshot.state)",
        "!snapshot.mayBeActive",
        "ignored VPN fault event=",
        "VPN_FAULT_CLOSE_TUN",
        "writeS185VpnFaultEventStatus(\"tun_abnormal_close\"",
        "failProductCoreGeneration(\"vpn_tun_abnormal_close\"",
        "failProductCoreGeneration(\"unexpected_exit\"",
        "crashProductCoreOwnerProcess()",
        "process.destroyForcibly()"):
    if token not in event:
        raise AssertionError("VPN fault event missing " + token)

owner_crash = body(service, "private boolean crashProductCoreOwnerProcess(")
for token in (
        "readProductCoreOwner(profile)",
        "auditProductCoreProcessPid(owner, vpp)",
        "kill -KILL ",
        "waitProductCoreOwnerGone(owner, vpp, STOP_KILL_MILLIS)"):
    if token not in owner_crash:
        raise AssertionError("native crash owner fallback missing " + token)

on_start = body(service, "public int onStartCommand(")
event_gate = on_start.index("final boolean hasVpnFaultEvent")
query_skip = on_start.index("if (hasVpnFaultEvent && ACTION_QUERY.equals(action))")
health_query = on_start.index("queueHealthQuery(startId)")
if not event_gate < query_skip < health_query:
    raise AssertionError(
        "S185 fault-event intents must not fall through to public health query")

query = body(service, "private void queryProductCoreRuntime(")
if "productCoreQueryBlockedByErrorLatch()" not in query:
    raise AssertionError("VPN terminal error classification must not be overwritten by health query")
query_latch = body(service, "private boolean productCoreQueryBlockedByErrorLatch(")
for token in (
        "RuntimeSnapshot.STATE_ERROR.equals(current.state)",
        "!current.mayBeActive"):
    if token not in query_latch:
        raise AssertionError("VPN terminal error classification must not be overwritten by health query")

fail_generation = body(service, "private void failProductCoreGeneration(")
for token in (
        '"unexpected_exit".equals(code)',
        "processStopped && ownerStopped",
        "product_core_close=ignored_after_unexpected_exit"):
    if token not in fail_generation:
        raise AssertionError("unexpected Product Core exit cleanup missing " + token)

status = body(service, "private void writeS185VpnFaultRecoveryStatus(")
for token in (
        "schema=s185-vpn-fault-recovery/v1",
        "policy_verdict_separate=policy_default_pass",
        "adapter_completion_separate=vpn_tun_and_flow_stack_counters",
        "transport_outcome_separate=direct_socket_counters",
        "infrastructure_fault_separate=vpn_infrastructure_faults",
        "vpnDirectUdp4TransportFailed",
        "vpnDirectUdp6TransportFailed",
        "vpnDirectTcp4TransportFailed",
        "vpnDirectTcp6TransportFailed",
        "vpnDuplicateOrStaleDrops"):
    if token not in status:
        raise AssertionError("S185 status missing " + token)

for signature in (
        "private static final class VpnDirectUdp4TransportSession",
        "private static final class VpnDirectUdp6TransportSession",
        "private static final class VpnDirectTcp4TransportSession",
        "private static final class VpnDirectTcp6TransportSession"):
    session = body(service, signature)
    if "vpnFaultModeIs(\"protect_false\")" not in session:
        raise AssertionError(signature + " does not prove protect=false fail-closed")
    if "vpnFaultModeIs(\"bind_failed\")" not in session:
        raise AssertionError(signature + " does not prove bind failure fail-closed")
    if "underlay.network.bindSocket(socket)" not in session:
        raise AssertionError(signature + " lost explicit Network.bindSocket")

close = body(adapter, "product_vpn_close_tun_for_fault")
for token in ("clib_file_del_by_index", "close (nm->tun_fd)",
              "nm->tun_ready = 0", "nm->available = 0",
              "nm->vpn_infrastructure_faults++"):
    if token not in close:
        raise AssertionError("native TUN-close fault missing " + token)
PY

for token in \
  'dev/adb' \
  'am start -W -f 0x10008000' \
  '28201JEGR0XPAJ' \
  'SAKAMOTO-185-vpn-fault-recovery' \
  'runtimeVpnFaultMode establish_null' \
  'runtimeVpnFaultMode protect_false' \
  'runtimeVpnFaultMode bind_failed' \
  'runtimeVpnFaultEvent close_tun' \
  'runtimeVpnFaultEvent revoke' \
  'runtimeVpnFaultEvent native_crash' \
  'errorCode=product_core_not_ready' \
  'retry_after_product_core_not_ready' \
  'errorCode=vpn_underlay_unavailable' \
  'retry_after_vpn_underlay_unavailable' \
  'VPN_NETWORK_WAIT_ATTEMPTS' \
  'wait_for_vpn_network' \
  'vpn_network_present' \
  'bindResult=vpn_network_not_found' \
  'preflight_force_stopped true' \
  'wait_for_vpn_inactive "${label}.race-settled"' \
  'revoke_stop_start_race_settled true' \
  'am force-stop "$PACKAGE"' \
  'installed_app_udp4_source true' \
  'installed_app_tcp4_source true' \
  'installed_app_udp6_source true' \
  'installed_app_tcp6_source true' \
  'uid_not_shell true' \
  'flow_stack_admission_observed true' \
  'files/product-state/s185-vpn-fault-recovery.properties' \
  'final_residue_clean true'; do
  grep -Fq -- "$token" "$device_runner"
done

if grep -Fq 'runtimeVpnFaultEvent revoke --ez runtimeStop true' "$device_runner"; then
  echo "S185 runner must send revoke and stop as separate lifecycle requests" >&2
  exit 1
fi
if grep -Eq -- '--activity-new-task' "$device_runner"; then
  echo "S185 runner must not use activity flags unsupported by the controlled Pixel 6a" >&2
  exit 1
fi

if grep -Eq 'sakamoto-app|adb[.]exe|tun-poc|vpnlite|toybox nc|2001:4860|2606:4700|dns.google|cloudflare' "$device_runner"; then
  echo "S185 runner uses a retired, shell-network, or public-network path" >&2
  exit 1
fi

echo "sakamoto-185 VPN fault recovery contract: PASS"
