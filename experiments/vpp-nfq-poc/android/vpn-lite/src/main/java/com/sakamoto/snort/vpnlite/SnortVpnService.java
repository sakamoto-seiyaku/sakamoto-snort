package com.sakamoto.snort.vpnlite;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.File;

public final class SnortVpnService extends VpnService {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.STOP";

    private static final String TAG = "SnortVpnLite";
    private static final String VPN_ADDRESS = "10.111.0.2";
    private static final int MAX_LOGGED_PACKETS = 32;

    static {
        System.loadLibrary("vpnfdprobe");
    }

    private ParcelFileDescriptor vpnFd;

    private static native int nativeStartProbe(int fd, String logPath, int maxPackets);

    private static native void nativeStopProbe();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }

        startVpn();
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn() {
        if (vpnFd != null) {
            Log.i(TAG, "VPN already active");
            return;
        }

        try {
            File logsDir = new File(getFilesDir(), "logs");
            if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
                Log.w(TAG, "failed to create logs dir: " + logsDir);
            }
            File logPath = new File(logsDir, "vpn-fd-probe.log");

            Builder builder = new Builder()
                    .setSession("Snort VPN Lite")
                    .setMtu(1500)
                    .addAddress(VPN_ADDRESS, 32)
                    .addRoute("0.0.0.0", 0);

            vpnFd = builder.establish();
            if (vpnFd == null) {
                Log.e(TAG, "VpnService establish returned null");
                return;
            }

            int rawFd = vpnFd.detachFd();
            vpnFd = null;
            int rc = nativeStartProbe(rawFd, logPath.getAbsolutePath(), MAX_LOGGED_PACKETS);
            Log.i(TAG, "nativeStartProbe fd=" + rawFd + " rc=" + rc + " log=" + logPath);
        } catch (Exception e) {
            Log.e(TAG, "startVpn failed", e);
            stopVpn();
        }
    }

    private synchronized void stopVpn() {
        nativeStopProbe();
        if (vpnFd != null) {
            try {
                vpnFd.close();
            } catch (Exception e) {
                Log.w(TAG, "close vpn fd failed", e);
            }
            vpnFd = null;
        }
        Log.i(TAG, "VPN stopped");
    }
}
