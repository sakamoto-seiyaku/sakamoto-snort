package com.sakamoto.snort.vpnlite;

import android.content.Context;
import android.content.Intent;
import android.os.Build;

/**
 * The Android Product UI adapter.  RuntimeService remains the lifecycle owner;
 * this class only translates product intent into versioned Android service
 * commands and projects the durable runtime summary.
 */
public final class LocalProductBackend {
    public static final int CONTROL_PROTOCOL_VERSION = 1;

    public RuntimeSnapshot getRuntimeSnapshot(Context context) {
        return RuntimeStateStore.read(context.getFilesDir());
    }

    public StartResult startProtection(Context context) {
        if (!SnortRuntimeService.notificationsReady(context)) {
            return StartResult.NOTIFICATION_REQUIRED;
        }
        Intent intent = new Intent(context, SnortRuntimeService.class)
                .setAction(SnortRuntimeService.ACTION_START)
                .putExtra(SnortRuntimeService.EXTRA_CONTROL_PROTOCOL_VERSION,
                        CONTROL_PROTOCOL_VERSION);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
        return StartResult.ACCEPTED;
    }

    public void stopProtection(Context context) {
        Intent intent = new Intent(context, SnortRuntimeService.class)
                .setAction(SnortRuntimeService.ACTION_STOP)
                .putExtra(SnortRuntimeService.EXTRA_CONTROL_PROTOCOL_VERSION,
                        CONTROL_PROTOCOL_VERSION);
        context.startService(intent);
    }

    public enum StartResult {
        ACCEPTED,
        NOTIFICATION_REQUIRED
    }
}
