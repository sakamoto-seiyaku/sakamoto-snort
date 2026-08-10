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
        queryService(context);
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

    public void queryService(Context context) {
        context.startService(requestIntent(context, RuntimeControlRequest.query()));
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
        return intent;
    }
}
