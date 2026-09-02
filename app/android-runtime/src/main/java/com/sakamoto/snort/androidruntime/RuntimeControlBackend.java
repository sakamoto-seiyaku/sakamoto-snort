package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.SystemClock;

/** Activity-side request adapter; RuntimeService remains the lifecycle owner. */
public final class RuntimeControlBackend {
    public enum StartResult {
        ACCEPTED,
        NOTIFICATION_REQUIRED
    }

    public RuntimeSnapshot query(Context context) {
        return RuntimeStateStore.read(context.getFilesDir());
    }

    public StartResult start(Context context, RuntimeProfile profile) {
        return start(context, profile, null);
    }

    public StartResult start(Context context, RuntimeProfile profile,
                             String rootNfqueueFaultMode) {
        return start(context, profile, rootNfqueueFaultMode, null);
    }

    public StartResult start(Context context, RuntimeProfile profile,
                             String rootNfqueueFaultMode, String vpnFaultMode) {
        if (!RuntimeService.notificationsReady(context)) {
            return StartResult.NOTIFICATION_REQUIRED;
        }
        Intent intent = requestIntent(context, RuntimeControlRequest.start(profile));
        if (rootNfqueueFaultMode != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_ROOT_NFQUEUE_FAULT_MODE,
                    rootNfqueueFaultMode);
        }
        if (vpnFaultMode != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_VPN_FAULT_MODE, vpnFaultMode);
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
        return StartResult.ACCEPTED;
    }

    public void stop(Context context) {
        context.startService(requestIntent(context, RuntimeControlRequest.stop()));
    }

    public void pauseProtection(Context context) {
        context.startService(requestIntent(context, RuntimeControlRequest.pauseProtection()));
    }

    public StartResult resumeProtection(Context context) {
        if (!RuntimeService.notificationsReady(context)) {
            return StartResult.NOTIFICATION_REQUIRED;
        }
        Intent intent = requestIntent(context, RuntimeControlRequest.resumeProtection());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
        return StartResult.ACCEPTED;
    }

    public boolean queryService(Context context) {
        try {
            context.startService(requestIntent(context, RuntimeControlRequest.query()));
            return true;
        } catch (RuntimeException ignored) {
            // Query is a best-effort projection refresh. Android may reject a
            // background service start while the Activity is being resumed from
            // shell/device automation; the durable projection remains readable.
            return false;
        }
    }

    public void selectProductProfile(Context context, RuntimeProfile profile) {
        context.startService(requestIntent(context,
                RuntimeControlRequest.selectProductProfile(profile)));
    }

    public void bindProductApplication(Context context, ApplicationSubjectId subjectId) {
        context.startService(requestIntent(context,
                RuntimeControlRequest.bindProductApplication(subjectId)));
    }

    public void unbindProductApplication(Context context, ApplicationSubjectId subjectId) {
        context.startService(requestIntent(context,
                RuntimeControlRequest.unbindProductApplication(subjectId)));
    }

    public void setNetworkGate(Context context, ApplicationSubjectId subjectId,
                               AuthoringPolicyBundle.NetworkContextId networkContext,
                               boolean blocked) {
        context.startService(requestIntent(context,
                RuntimeControlRequest.setNetworkGate(subjectId, networkContext, blocked)));
    }

    public void setL4Rule(Context context, AuthoringPolicyBundle.L4Rule rule) {
        Intent intent = new Intent(context, RuntimeService.class)
                .setAction(RuntimeControlProtocol.ACTION_PRODUCT_SET_L4_RULE)
                .putExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION,
                        RuntimeControlProtocol.VERSION)
                .putExtra(RuntimeControlProtocol.EXTRA_ACTION,
                        RuntimeControlProtocol.ACTION_PRODUCT_SET_L4_RULE)
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_ID,
                        java.util.UUID.randomUUID().toString())
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS,
                        SystemClock.elapsedRealtime())
                .putExtra(RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT,
                        rule.subjectId.encode())
                .putExtra(RuntimeControlProtocol.EXTRA_L4_FAMILY, rule.family.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_SOURCE_CIDR, rule.sourceCidr)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_DESTINATION_CIDR,
                        rule.destinationCidr)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_IP_PROTOCOL, rule.ipProtocol)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_PACKET_DIRECTION,
                        rule.direction.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_ACTION, rule.action.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_PRIORITY, rule.priority)
                .putExtra(RuntimeControlProtocol.EXTRA_L4_ORDER, rule.order);
        if (rule.networkContext != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT,
                    rule.networkContext.wireName);
        }
        if (rule.sourcePorts != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_FIRST,
                    rule.sourcePorts.first);
            intent.putExtra(RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_LAST,
                    rule.sourcePorts.last);
        }
        if (rule.destinationPorts != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_FIRST,
                    rule.destinationPorts.first);
            intent.putExtra(RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_LAST,
                    rule.destinationPorts.last);
        }
        context.startService(intent);
    }

    public void applyEmptyPolicy(Context context) {
        Intent intent = new Intent(context, RuntimeService.class)
                .setAction(RuntimeControlProtocol.ACTION_PRODUCT_APPLY_EMPTY_POLICY)
                .putExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION,
                        RuntimeControlProtocol.VERSION)
                .putExtra(RuntimeControlProtocol.EXTRA_ACTION,
                        RuntimeControlProtocol.ACTION_PRODUCT_APPLY_EMPTY_POLICY)
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_ID,
                        java.util.UUID.randomUUID().toString())
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS,
                        SystemClock.elapsedRealtime());
        context.startService(intent);
    }

    /** Debug-only seam used to prove replacement remains blocked on cleanup failure. */
    public void setCleanupFault(Context context, boolean enabled) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_CLEANUP_FAULT, enabled);
        context.startService(intent);
    }

    /** Debug-only seam used by S179 Root NFQUEUE fault/recovery acceptance. */
    public void setRootNfqueueFaultMode(Context context, String mode) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_ROOT_NFQUEUE_FAULT_MODE,
                mode == null ? "" : mode);
        context.startService(intent);
    }

    /** Debug-only seam used by S185 VPN fault/recovery acceptance. */
    public void setVpnFaultMode(Context context, String mode) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_VPN_FAULT_MODE,
                mode == null ? "" : mode);
        context.startService(intent);
    }

    /** Debug-only seam used by S185 to enter VPN revoke/TUN-close paths. */
    public void sendVpnFaultEvent(Context context, String event) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_VPN_FAULT_EVENT,
                event == null ? "" : event);
        context.startService(intent);
    }

    /** Debug-only one-shot fault for the typed Product policy mutation reply. */
    public void setPolicyMutationFaultMode(Context context, String mode) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_POLICY_MUTATION_FAULT_MODE,
                mode == null ? "" : mode);
        context.startService(intent);
    }

    private static Intent requestIntent(Context context, RuntimeControlRequest request) {
        Intent intent = new Intent(context, RuntimeService.class)
                .setAction(request.action.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION, request.protocolVersion)
                .putExtra(RuntimeControlProtocol.EXTRA_ACTION, request.action.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_ID, request.requestId)
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS,
                        SystemClock.elapsedRealtime());
        if (request.profile != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_PROFILE, request.profile.wireName);
        }
        if (request.applicationSubjectId != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT,
                    request.applicationSubjectId.encode());
        }
        if (request.networkContext != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT,
                    request.networkContext.wireName);
            intent.putExtra(RuntimeControlProtocol.EXTRA_NETWORK_GATE_BLOCKED,
                    request.networkGateBlocked);
        }
        return intent;
    }
}
