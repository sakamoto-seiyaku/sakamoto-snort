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
        if (!RuntimeService.notificationsReady(context)) {
            return StartResult.NOTIFICATION_REQUIRED;
        }
        Intent intent = requestIntent(context, RuntimeControlRequest.start(profile));
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

    /** Debug-only seam used to prove replacement remains blocked on cleanup failure. */
    public void setCleanupFault(Context context, boolean enabled) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        intent.putExtra(RuntimeControlProtocol.EXTRA_CLEANUP_FAULT, enabled);
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
