package com.sakamoto.snort.vpnlite;

import android.content.Intent;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public final class SnortVpnService extends VpnService {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.STOP";
    public static final String ACTION_HTTP_PROBE = "com.sakamoto.snort.vpnlite.HTTP_PROBE";
    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";
    public static final String EXTRA_PATH = "path";
    public static final String EXTRA_ALLOWED_PACKAGE = "allowedPackage";
    public static final String EXTRA_DISALLOWED_PACKAGE = "disallowedPackage";
    public static final String EXTRA_BLOCK_IP4_DST = "blockIp4Dst";
    public static final String EXTRA_BLOCK_IP6_DST = "blockIp6Dst";
    public static final String EXTRA_ENABLE_IPV6 = "enableIpv6";
    public static final String MODE_NATIVE = "native";
    public static final String MODE_VPP = "vpp";
    public static final String MODE_VPP_FORWARD = "vpp-forward";
    public static final String MODE_VPP_HEV = "vpp-hev";
    public static final String MODE_HEV = "hev";

    private static final String TAG = "SnortVpnLite";
    private static final String VPN_ADDRESS = "10.111.0.2";
    private static final String VPN_ADDRESS_V6 = "fd00:111:111::2";
    private static final int MAX_LOGGED_PACKETS = 32;

    static {
        System.loadLibrary("vpnfdprobe");
    }

    private ParcelFileDescriptor vpnFd;

    private static native int nativeStartProbe(int fd, String logPath, int maxPackets);

    private static native void nativeStopProbe();

    private static native int nativeStartVppProbe(int fd, String nativeLibraryDir, String filesDir,
                                                  int vppMode, String blockIp4Dst,
                                                  String blockIp6Dst);

    private static native void nativeStopVppProbe();

    private static native int nativeStartHevProbe(String nativeLibraryDir, String filesDir);

    private static native void nativeStopHevProbe();

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_HTTP_PROBE.equals(action)) {
            startHttpProbe(intent);
            return START_NOT_STICKY;
        }

        String mode = intent == null ? MODE_NATIVE : intent.getStringExtra(EXTRA_MODE);
        String allowedPackage = intent == null ? null : intent.getStringExtra(EXTRA_ALLOWED_PACKAGE);
        String disallowedPackage = intent == null ? null
                : intent.getStringExtra(EXTRA_DISALLOWED_PACKAGE);
        String blockIp4Dst = intent == null ? null : intent.getStringExtra(EXTRA_BLOCK_IP4_DST);
        String blockIp6Dst = intent == null ? null : intent.getStringExtra(EXTRA_BLOCK_IP6_DST);
        boolean enableIpv6 = intent != null && intent.getBooleanExtra(EXTRA_ENABLE_IPV6, false);
        startVpn(mode == null ? MODE_NATIVE : mode, allowedPackage, disallowedPackage,
                blockIp4Dst, blockIp6Dst, enableIpv6);
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn(String mode, String allowedPackage,
                                       String disallowedPackage, String blockIp4Dst,
                                       String blockIp6Dst, boolean enableIpv6) {
        if (MODE_HEV.equals(mode)) {
            int rc = nativeStartHevProbe(getApplicationInfo().nativeLibraryDir,
                    getFilesDir().getAbsolutePath());
            Log.i(TAG, "nativeStartHevProbe rc=" + rc);
            return;
        }

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
            if (enableIpv6) {
                builder.addAddress(VPN_ADDRESS_V6, 128)
                        .addRoute("::", 0);
                Log.i(TAG, "VPN IPv6 enabled address=" + VPN_ADDRESS_V6);
            }
            if (allowedPackage != null && !allowedPackage.isEmpty()) {
                builder.addAllowedApplication(allowedPackage);
                Log.i(TAG, "VPN allowed package=" + allowedPackage);
            }
            if (disallowedPackage != null && !disallowedPackage.isEmpty()) {
                builder.addDisallowedApplication(disallowedPackage);
                Log.i(TAG, "VPN disallowed package=" + disallowedPackage);
            }

            vpnFd = builder.establish();
            if (vpnFd == null) {
                Log.e(TAG, "VpnService establish returned null");
                return;
            }

            int rawFd = vpnFd.detachFd();
            vpnFd = null;
            if (MODE_VPP.equals(mode) || MODE_VPP_FORWARD.equals(mode)
                    || MODE_VPP_HEV.equals(mode)) {
                int vppMode = 0;
                if (MODE_VPP_FORWARD.equals(mode)) {
                    vppMode = 1;
                } else if (MODE_VPP_HEV.equals(mode)) {
                    vppMode = 2;
                }
                int rc = nativeStartVppProbe(rawFd, getApplicationInfo().nativeLibraryDir,
                        getFilesDir().getAbsolutePath(), vppMode,
                        blockIp4Dst == null ? "" : blockIp4Dst,
                        blockIp6Dst == null ? "" : blockIp6Dst);
                Log.i(TAG, "nativeStartVppProbe fd=" + rawFd + " vppMode=" + vppMode
                        + " rc=" + rc);
            } else {
                int rc = nativeStartProbe(rawFd, logPath.getAbsolutePath(), MAX_LOGGED_PACKETS);
                Log.i(TAG, "nativeStartProbe fd=" + rawFd + " rc=" + rc + " log=" + logPath);
            }
        } catch (Exception e) {
            Log.e(TAG, "startVpn failed", e);
            stopVpn();
        }
    }

    private void startHttpProbe(Intent intent) {
        String host = intent == null ? null : intent.getStringExtra(EXTRA_HOST);
        if (host == null || host.isEmpty()) {
            host = "93.184.216.34";
        }
        int port = intent == null ? 80 : intent.getIntExtra(EXTRA_PORT, 80);
        String path = intent == null ? null : intent.getStringExtra(EXTRA_PATH);
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        if (!path.startsWith("/")) {
            path = "/" + path;
        }

        final String probeHost = host;
        final int probePort = port;
        final String probePath = path;
        Thread thread = new Thread(() -> runHttpProbe(probeHost, probePort, probePath),
                "snort-app-http-probe");
        thread.start();
    }

    private void runHttpProbe(String host, int port, String path) {
        long started = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-http-probe.log");
        appendHttpProbeLog(logPath, "start host=" + host + " port=" + port + " path=" + path);

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(5000);
            String request = "GET " + path + " HTTP/1.0\r\n"
                    + "Host: " + host + "\r\n"
                    + "Connection: close\r\n"
                    + "\r\n";
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
            byte[] buf = new byte[256];
            int n = in.read(buf);
            String first = n <= 0 ? "" : new String(buf, 0, n, StandardCharsets.ISO_8859_1)
                    .replace('\r', ' ').replace('\n', ' ');
            long elapsed = System.currentTimeMillis() - started;
            appendHttpProbeLog(logPath, "ok bytes=" + n + " elapsedMs=" + elapsed
                    + " first=" + first);
            Log.i(TAG, "app HTTP probe ok host=" + host + " port=" + port + " bytes=" + n);
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - started;
            appendHttpProbeLog(logPath, "fail elapsedMs=" + elapsed + " error="
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.w(TAG, "app HTTP probe failed host=" + host + " port=" + port, e);
        }
    }

    private void appendHttpProbeLog(File logPath, String line) {
        String text = System.currentTimeMillis() + " " + line + "\n";
        try (FileOutputStream out = new FileOutputStream(logPath, true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.w(TAG, "write HTTP probe log failed: " + logPath, e);
        }
    }

    private synchronized void stopVpn() {
        nativeStopProbe();
        nativeStopVppProbe();
        nativeStopHevProbe();
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
