package com.sakamoto.snort.vpnlite;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;

public final class SnortVpnService extends VpnService {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.STOP";
    public static final String ACTION_HTTP_PROBE = "com.sakamoto.snort.vpnlite.HTTP_PROBE";
    public static final String ACTION_UDP_PROBE = "com.sakamoto.snort.vpnlite.UDP_PROBE";
    public static final String ACTION_CONTROL_PROBE = "com.sakamoto.snort.vpnlite.CONTROL_PROBE";
    public static final String ACTION_RUST_CONTROL_PROBE =
            "com.sakamoto.snort.vpnlite.RUST_CONTROL_PROBE";
    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";
    public static final String EXTRA_PATH = "path";
    public static final String EXTRA_COUNT = "count";
    public static final String EXTRA_DURATION_SECONDS = "durationSeconds";
    public static final String EXTRA_ALLOWED_PACKAGE = "allowedPackage";
    public static final String EXTRA_DISALLOWED_PACKAGE = "disallowedPackage";
    public static final String EXTRA_BLOCK_IP4_DST = "blockIp4Dst";
    public static final String EXTRA_BLOCK_IP6_DST = "blockIp6Dst";
    public static final String EXTRA_BLOCK_OWNER_UID = "blockOwnerUid";
    public static final String EXTRA_REDIRECT_THREAD = "redirectThread";
    public static final String EXTRA_OWNER_CACHE = "ownerCache";
    public static final String EXTRA_ENABLE_IPV6 = "enableIpv6";
    public static final String EXTRA_ROUNDS = "rounds";
    public static final String MODE_NATIVE = "native";
    public static final String MODE_VPP = "vpp";
    public static final String MODE_VPP_FORWARD = "vpp-forward";
    public static final String MODE_VPP_HEV = "vpp-hev";
    public static final String MODE_VPP_HEV_HANDOFF = "vpp-hev-handoff";
    public static final String MODE_VPP_HEV_OWNER_GATE = "vpp-hev-owner-gate";
    public static final String MODE_VPP_HEV_OWNER_RESOLVER = "vpp-hev-owner-resolver";
    public static final String MODE_HEV = "hev";

    private static final String TAG = "SnortVpnLite";
    private static final String VPN_ADDRESS = "10.111.0.2";
    private static final String VPN_ADDRESS_V6 = "fd00:111:111::2";
    private static final int MAX_LOGGED_PACKETS = 32;

    static {
        System.loadLibrary("vpnfdprobe");
    }

    private ParcelFileDescriptor vpnFd;

    public boolean protectSocketForNative(int fd) {
        File forceFailure = new File(getFilesDir(), "force-protect-failure");
        if (forceFailure.isFile()) {
            Log.w(TAG, "forced VpnService.protect failure fd=" + fd);
            return false;
        }
        boolean protectedSocket = protect(fd);
        Log.i(TAG, "VpnService.protect fd=" + fd + " result=" + protectedSocket);
        return protectedSocket;
    }

    private static native int nativeStartProbe(int fd, String logPath, int maxPackets,
                                               SnortVpnService ownerLookup);

    private static native void nativeStopProbe();

    private static native int nativeStartVppProbe(int fd, String nativeLibraryDir, String filesDir,
                                                  int vppMode, String blockIp4Dst,
                                                  String blockIp6Dst, int blockOwnerUid,
                                                  int redirectThread,
                                                  boolean ownerCache,
                                                  SnortVpnService ownerLookup);

    private static native void nativeStopVppProbe();

    private static native int nativeStartHevProbe(String nativeLibraryDir, String filesDir);

    private static native void nativeStopHevProbe();

    private static native int nativeRunVppControlProbe(String filesDir, int blockOwnerUid,
                                                       int rounds);

    private static native int nativeRunRustVppControlProbe(String filesDir, int blockOwnerUid,
                                                           int rounds);

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
        if (ACTION_UDP_PROBE.equals(action)) {
            startUdpProbe(intent);
            return START_NOT_STICKY;
        }
        if (ACTION_CONTROL_PROBE.equals(action)) {
            startControlProbe(intent);
            return START_NOT_STICKY;
        }
        if (ACTION_RUST_CONTROL_PROBE.equals(action)) {
            startRustControlProbe(intent);
            return START_NOT_STICKY;
        }

        String mode = intent == null ? MODE_NATIVE : intent.getStringExtra(EXTRA_MODE);
        String allowedPackage = intent == null ? null : intent.getStringExtra(EXTRA_ALLOWED_PACKAGE);
        String disallowedPackage = intent == null ? null
                : intent.getStringExtra(EXTRA_DISALLOWED_PACKAGE);
        String blockIp4Dst = intent == null ? null : intent.getStringExtra(EXTRA_BLOCK_IP4_DST);
        String blockIp6Dst = intent == null ? null : intent.getStringExtra(EXTRA_BLOCK_IP6_DST);
        int blockOwnerUid = intent == null ? -1 : intent.getIntExtra(EXTRA_BLOCK_OWNER_UID, -1);
        int redirectThread = intent == null ? -1 : intent.getIntExtra(EXTRA_REDIRECT_THREAD, -1);
        boolean ownerCache = intent != null && intent.getBooleanExtra(EXTRA_OWNER_CACHE, false);
        boolean enableIpv6 = intent != null && intent.getBooleanExtra(EXTRA_ENABLE_IPV6, false);
        startVpn(mode == null ? MODE_NATIVE : mode, allowedPackage, disallowedPackage,
                blockIp4Dst, blockIp6Dst, blockOwnerUid, redirectThread, ownerCache,
                enableIpv6);
        return START_STICKY;
    }

    private void startControlProbe(Intent intent) {
        final int blockOwnerUid = intent == null
                ? -1 : intent.getIntExtra(EXTRA_BLOCK_OWNER_UID, -1);
        final int rounds = intent == null ? 1 : intent.getIntExtra(EXTRA_ROUNDS, 1);
        Thread thread = new Thread(() -> {
            int rc = nativeRunVppControlProbe(getFilesDir().getAbsolutePath(), blockOwnerUid,
                    rounds);
            Log.i(TAG, "nativeRunVppControlProbe uid=" + Process.myUid()
                    + " blockOwnerUid=" + blockOwnerUid + " rounds=" + rounds + " rc=" + rc);
        }, "snort-vpp-control-probe");
        thread.start();
    }

    private void startRustControlProbe(Intent intent) {
        final int blockOwnerUid = intent == null
                ? -1 : intent.getIntExtra(EXTRA_BLOCK_OWNER_UID, -1);
        final int rounds = intent == null ? 1 : intent.getIntExtra(EXTRA_ROUNDS, 1);
        Thread thread = new Thread(() -> {
            int rc = nativeRunRustVppControlProbe(getFilesDir().getAbsolutePath(), blockOwnerUid,
                    rounds);
            Log.i(TAG, "nativeRunRustVppControlProbe uid=" + Process.myUid()
                    + " blockOwnerUid=" + blockOwnerUid + " rounds=" + rounds + " rc=" + rc);
        }, "snort-rust-vpp-control-probe");
        thread.start();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn(String mode, String allowedPackage,
                                       String disallowedPackage, String blockIp4Dst,
                                       String blockIp6Dst, int blockOwnerUid,
                                       int redirectThread, boolean ownerCache,
                                       boolean enableIpv6) {
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
                    || MODE_VPP_HEV.equals(mode) || MODE_VPP_HEV_HANDOFF.equals(mode)
                    || MODE_VPP_HEV_OWNER_GATE.equals(mode)
                    || MODE_VPP_HEV_OWNER_RESOLVER.equals(mode)) {
                int vppMode = 0;
                if (MODE_VPP_FORWARD.equals(mode)) {
                    vppMode = 1;
                } else if (MODE_VPP_HEV.equals(mode)) {
                    vppMode = 2;
                } else if (MODE_VPP_HEV_OWNER_GATE.equals(mode)) {
                    vppMode = 3;
                } else if (MODE_VPP_HEV_HANDOFF.equals(mode)) {
                    vppMode = 4;
                } else if (MODE_VPP_HEV_OWNER_RESOLVER.equals(mode)) {
                    vppMode = 5;
                }
                int rc = nativeStartVppProbe(rawFd, getApplicationInfo().nativeLibraryDir,
                        getFilesDir().getAbsolutePath(), vppMode,
                        blockIp4Dst == null ? "" : blockIp4Dst,
                        blockIp6Dst == null ? "" : blockIp6Dst,
                        blockOwnerUid, redirectThread, ownerCache, this);
                Log.i(TAG, "nativeStartVppProbe fd=" + rawFd + " vppMode=" + vppMode
                        + " blockOwnerUid=" + blockOwnerUid
                        + " redirectThread=" + redirectThread
                        + " ownerCache=" + ownerCache + " rc=" + rc);
            } else {
                int rc = nativeStartProbe(rawFd, logPath.getAbsolutePath(), MAX_LOGGED_PACKETS,
                        this);
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
        final int durationSeconds = intent == null ? 0
                : Math.max(0, Math.min(3600, intent.getIntExtra(EXTRA_DURATION_SECONDS, 0)));
        Thread thread = new Thread(() -> {
            if (durationSeconds > 0) {
                runHttpStreamProbe(probeHost, probePort, probePath, durationSeconds);
            } else {
                runHttpProbe(probeHost, probePort, probePath);
            }
        },
                "snort-app-http-probe");
        thread.start();
    }

    private void startUdpProbe(Intent intent) {
        String host = intent == null ? null : intent.getStringExtra(EXTRA_HOST);
        if (host == null || host.isEmpty()) {
            host = "8.8.8.8";
        }
        int port = intent == null ? 53 : intent.getIntExtra(EXTRA_PORT, 53);
        int count = intent == null ? 1 : intent.getIntExtra(EXTRA_COUNT, 1);
        count = Math.max(1, Math.min(1000, count));

        final String probeHost = host;
        final int probePort = port;
        final int probeCount = count;
        final int durationSeconds = intent == null ? 0
                : Math.max(0, Math.min(3600, intent.getIntExtra(EXTRA_DURATION_SECONDS, 0)));
        Thread thread = new Thread(() -> {
            if (durationSeconds > 0) {
                runUdpStreamProbe(probeHost, probePort, durationSeconds);
            } else {
                runUdpProbe(probeHost, probePort, probeCount);
            }
        },
                "snort-app-udp-probe");
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

    private void runHttpStreamProbe(String host, int port, String path, int durationSeconds) {
        long started = System.currentTimeMillis();
        long deadline = started + durationSeconds * 1000L;
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-http-probe.log");
        int requests = 0;
        int successes = 0;
        long requestBytes = 0;
        long responseBytes = 0;
        int errors = 0;
        ArrayList<Long> latencies = new ArrayList<>();
        appendHttpProbeLog(logPath, "stream-start host=" + host + " port=" + port
                + " durationSeconds=" + durationSeconds);
        while (System.currentTimeMillis() < deadline) {
            requests++;
            long requestStarted = System.currentTimeMillis();
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 5000);
                socket.setSoTimeout(5000);
                String request = "GET " + path + " HTTP/1.0\r\n"
                        + "Host: " + host + "\r\n"
                        + "Connection: close\r\n\r\n";
                byte[] requestData = request.getBytes(StandardCharsets.US_ASCII);
                OutputStream out = socket.getOutputStream();
                out.write(requestData);
                out.flush();
                requestBytes += requestData.length;
                BufferedInputStream in = new BufferedInputStream(socket.getInputStream());
                byte[] buf = new byte[512];
                int n;
                int total = 0;
                while ((n = in.read(buf)) > 0) {
                    total += n;
                }
                responseBytes += total;
                if (total > 0) {
                    successes++;
                    latencies.add(System.currentTimeMillis() - requestStarted);
                }
            } catch (Exception e) {
                errors++;
            }
        }
        long elapsed = System.currentTimeMillis() - started;
        appendHttpProbeLog(logPath, "stream-done requests=" + requests
                + " successes=" + successes + " errors=" + errors
                + " requestBytes=" + requestBytes + " responseBytes=" + responseBytes
                + " elapsedMs=" + elapsed + " latencyMsP50=" + percentileMillis(latencies, 0.50)
                + " latencyMsP95=" + percentileMillis(latencies, 0.95)
                + " latencyMsP99=" + percentileMillis(latencies, 0.99));
        Log.i(TAG, "app HTTP stream done host=" + host + " requests=" + requests
                + " successes=" + successes + " errors=" + errors
                + " elapsedMs=" + elapsed);
    }

    private long percentileMillis(ArrayList<Long> values, double percentile) {
        if (values.isEmpty()) {
            return -1;
        }
        Collections.sort(values);
        int index = (int) Math.ceil(percentile * values.size()) - 1;
        index = Math.max(0, Math.min(index, values.size() - 1));
        return values.get(index);
    }

    private void runUdpProbe(String host, int port, int count) {
        long started = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-udp-probe.log");
        appendProbeLog(logPath, "start host=" + host + " port=" + port + " count=" + count);

        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress remote = InetAddress.getByName(host);
            socket.connect(remote, port);
            byte[] payload = "snort-vpn-lite-udp-probe".getBytes(StandardCharsets.US_ASCII);
            DatagramPacket packet = new DatagramPacket(payload, payload.length);
            int sent = 0;
            for (int i = 0; i < count; i++) {
                socket.send(packet);
                sent++;
            }
            Thread.sleep(3000);
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "ok bytes=" + (payload.length * sent)
                    + " packets=" + sent + " elapsedMs=" + elapsed);
            Log.i(TAG, "app UDP probe ok host=" + host + " port=" + port
                    + " packets=" + sent + " bytes=" + (payload.length * sent));
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "fail elapsedMs=" + elapsed + " error="
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.w(TAG, "app UDP probe failed host=" + host + " port=" + port, e);
        }
    }

    private void runUdpStreamProbe(String host, int port, int durationSeconds) {
        long started = System.currentTimeMillis();
        long deadline = started + durationSeconds * 1000L;
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-udp-probe.log");
        byte[] payload = "snort-vpn-lite-udp-stream".getBytes(StandardCharsets.US_ASCII);
        long sent = 0;
        int errors = 0;
        appendProbeLog(logPath, "stream-start host=" + host + " port=" + port
                + " durationSeconds=" + durationSeconds + " payloadBytes=" + payload.length);
        try (DatagramSocket socket = new DatagramSocket()) {
            InetAddress remote = InetAddress.getByName(host);
            socket.connect(remote, port);
            DatagramPacket packet = new DatagramPacket(payload, payload.length);
            while (System.currentTimeMillis() < deadline) {
                try {
                    socket.send(packet);
                    sent++;
                } catch (Exception e) {
                    errors++;
                }
                if ((sent & 1023) == 0) {
                    Thread.yield();
                }
            }
        } catch (Exception e) {
            errors++;
        }
        long elapsed = System.currentTimeMillis() - started;
        appendProbeLog(logPath, "stream-done packets=" + sent + " errors=" + errors
                + " bytes=" + (sent * payload.length) + " elapsedMs=" + elapsed);
        Log.i(TAG, "app UDP stream done host=" + host + " packets=" + sent
                + " errors=" + errors + " elapsedMs=" + elapsed);
    }

    private void appendHttpProbeLog(File logPath, String line) {
        appendProbeLog(logPath, line);
    }

    private void appendProbeLog(File logPath, String line) {
        String text = System.currentTimeMillis() + " " + line + "\n";
        try (FileOutputStream out = new FileOutputStream(logPath, true)) {
            out.write(text.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            Log.w(TAG, "write probe log failed: " + logPath, e);
        }
    }

    @SuppressWarnings("unused")
    private int queryConnectionOwnerUidForPacket(int protocol, String localAddress, int localPort,
                                                 String remoteAddress, int remotePort) {
        try {
            ConnectivityManager connectivityManager =
                    (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
            if (connectivityManager == null) {
                return Process.INVALID_UID;
            }
            InetSocketAddress local = new InetSocketAddress(
                    InetAddress.getByName(localAddress), localPort);
            InetSocketAddress remote = new InetSocketAddress(
                    InetAddress.getByName(remoteAddress), remotePort);
            int uid = connectivityManager.getConnectionOwnerUid(protocol, local, remote);
            Log.i(TAG, "owner uid query proto=" + protocol + " "
                    + localAddress + ":" + localPort + " -> "
                    + remoteAddress + ":" + remotePort + " uid=" + uid);
            return uid;
        } catch (Exception e) {
            Log.w(TAG, "owner uid query failed proto=" + protocol + " "
                    + localAddress + ":" + localPort + " -> "
                    + remoteAddress + ":" + remotePort, e);
            return Process.INVALID_UID;
        }
    }

    private synchronized void stopVpn() {
        nativeStopVppProbe();
        nativeStopProbe();
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
