package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;

import java.util.UUID;

/** Thin product-control adapter; RuntimeService remains the lifecycle owner. */
public final class LocalProductBackend {
    public enum StartResult {
        ACCEPTED,
        NOTIFICATION_REQUIRED,
        VPN_PERMISSION_REQUIRED
    }

    public RuntimeSnapshot query(Context context) {
        return RuntimeStateStore.read(context.getFilesDir());
    }

    public StartResult start(Context context, RuntimeProfile profile) {
        if (!RuntimeService.notificationsReady(context)) {
            return StartResult.NOTIFICATION_REQUIRED;
        }
        if (profile == RuntimeProfile.VPN) {
            Intent prepare = VpnService.prepare(context);
            if (prepare != null) {
                return StartResult.VPN_PERMISSION_REQUIRED;
            }
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
        Intent intent = requestIntent(context, RuntimeControlRequest.stop());
        context.startService(intent);
    }

    public void queryService(Context context) {
        Intent intent = requestIntent(context, RuntimeControlRequest.query());
        context.startService(intent);
    }

    private static Intent requestIntent(Context context, RuntimeControlRequest request) {
        Intent intent = new Intent(context, RuntimeService.class)
                .setAction(request.action == RuntimeControlRequest.Action.START
                        ? RuntimeControlProtocol.ACTION_START
                        : request.action == RuntimeControlRequest.Action.STOP
                        ? RuntimeControlProtocol.ACTION_STOP : RuntimeControlProtocol.ACTION_QUERY)
                .putExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION, request.protocolVersion)
                .putExtra(RuntimeControlProtocol.EXTRA_ACTION, request.action.wireName)
                .putExtra(RuntimeControlProtocol.EXTRA_REQUEST_ID, request.requestId);
        if (request.profile != null) {
            intent.putExtra(RuntimeControlProtocol.EXTRA_PROFILE, request.profile.wireName);
        }
        return intent;
    }
}
