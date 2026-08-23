package com.sakamoto.snort.vpnlite;

import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.util.Log;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.io.EOFException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.LockSupport;

public final class SnortVpnService extends VpnService {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.STOP";
    public static final String ACTION_HTTP_PROBE = "com.sakamoto.snort.vpnlite.HTTP_PROBE";
    public static final String ACTION_UDP_PROBE = "com.sakamoto.snort.vpnlite.UDP_PROBE";
    public static final String ACTION_TCP_PROBE = "com.sakamoto.snort.vpnlite.TCP_PROBE";
    public static final String ACTION_L4_STRESS_PROBE =
            "com.sakamoto.snort.vpnlite.L4_STRESS_PROBE";
    public static final String ACTION_PING_PROBE = "com.sakamoto.snort.vpnlite.PING_PROBE";
    public static final String ACTION_CONTROL_PROBE = "com.sakamoto.snort.vpnlite.CONTROL_PROBE";
    public static final String ACTION_RUST_CONTROL_PROBE =
            "com.sakamoto.snort.vpnlite.RUST_CONTROL_PROBE";
    public static final String ACTION_RUST_RECONNECT_PROBE =
            "com.sakamoto.snort.vpnlite.RUST_RECONNECT_PROBE";
    public static final String EXTRA_MODE = "mode";
    public static final String EXTRA_HOST = "host";
    public static final String EXTRA_PORT = "port";
    public static final String EXTRA_PATH = "path";
    public static final String EXTRA_COUNT = "count";
    public static final String EXTRA_PAYLOAD_BYTES = "payloadBytes";
    public static final String EXTRA_SIZE = "size";
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
    public static final String EXTRA_FLOWS = "flows";
    public static final String EXTRA_PROTOCOL = "protocol";
    public static final String EXTRA_LOAD = "load";
    public static final String EXTRA_BURST = "burst";
    public static final String EXTRA_WARMUP_SECONDS = "warmupSeconds";
    public static final String EXTRA_STEADY_SECONDS = "steadySeconds";
    public static final String EXTRA_DRAIN_SECONDS = "drainSeconds";
    public static final String EXTRA_RECONNECT_EVERY = "reconnectEvery";
    public static final String EXTRA_EXPECT_ECHO = "expectEcho";
    public static final String EXTRA_S124_PATH = "s124Path";
    public static final String EXTRA_S124_OBSERVE = "s124Observe";
    public static final String MODE_NATIVE = "native";
    public static final String MODE_VPP = "vpp";
    public static final String MODE_VPP_FORWARD = "vpp-forward";
    public static final String MODE_VPP_HEV = "vpp-hev";
    public static final String MODE_VPP_HEV_HANDOFF = "vpp-hev-handoff";
    public static final String MODE_VPP_HEV_DIRECT_OWNER = "vpp-hev-direct-owner";
    public static final String MODE_VPP_HEV_DIRECT_OWNER_POLLING =
            "vpp-hev-direct-owner-polling";
    public static final String MODE_VPP_HEV_DIRECT_OWNER_FAULT =
            "vpp-hev-direct-owner-fault";
    public static final String MODE_VPP_HEV_DIRECT_OWNER_RETURN =
            "vpp-hev-direct-owner-return";
    public static final String MODE_VPP_HEV_DIRECT_OWNER_SINGLE_WRITER =
            "vpp-hev-direct-owner-single-writer";
    public static final String MODE_VPP_HEV_FRAGMENT_OWNER = "vpp-hev-fragment-owner";
    public static final String MODE_VPP_FRAGMENT_OWNER = "vpp-fragment-owner";
    public static final String MODE_VPP_HEV_OWNER_GATE = "vpp-hev-owner-gate";
    public static final String MODE_VPP_HEV_OWNER_RESOLVER = "vpp-hev-owner-resolver";
    public static final String MODE_VPP_HEV_TUN_SINGLE = "vpp-hev-tun-single";
    public static final String MODE_VPP_HEV_TUN_MULTI = "vpp-hev-tun-multi";
    public static final String MODE_VPP_OI2 = "vpp-oi2";
    public static final String MODE_VPP_OI3 = "vpp-oi3";
    /**
     * OI-3 test-only mode.  It establishes a VPN with a narrow, non-default
     * route and lets the native probe inject one loopback packet into the
     * detached TUN.  This is deliberately separate from MODE_VPP_OI3 so a
     * normal POC launch can never silently become a traffic-capturing test.
     */
    public static final String MODE_VPP_OI3_CONTROLLED = "vpp-oi3-controlled";
    public static final String MODE_VPP_OI3_CONTROLLED_TCP4 = "vpp-oi3-controlled-tcp4";
    public static final String MODE_VPP_OI3_CONTROLLED_UDP6 = "vpp-oi3-controlled-udp6";
    public static final String MODE_VPP_OI3_CONTROLLED_TCP6 = "vpp-oi3-controlled-tcp6";
    public static final String MODE_VPP_OI3_CONTROLLED_REFUSED = "vpp-oi3-controlled-refused";
    public static final String MODE_VPP_OI3_CONTROLLED_NO_REPLY = "vpp-oi3-controlled-no-reply";
    public static final String MODE_VPP_OI3_CONTROLLED_POLICY_DROP =
            "vpp-oi3-controlled-policy-drop";
    /**
     * OI-5 test-only lifecycle mode.  It installs the same narrow controlled
     * route as OI-3 but lets the native VPP monitor drive the synthetic
     * generation/epoch stop and restart cells inside the app process.  It
     * never installs a default route or starts an app traffic injector.
     */
    public static final String MODE_VPP_OI5_CONTROLLED = "vpp-oi5-controlled";
    public static final String MODE_HEV = "hev";

    private static final String TAG = "SnortVpnLite";
    private static final String VPN_ADDRESS = "10.111.0.2";
    private static final String VPN_ADDRESS_V6 = "fd00:111:111::2";
    private static final int MAX_LOGGED_PACKETS = 32;
    /* Pre-registered POC-7 UDP receive policy.  Closed cells measure
     * correctness/RTT and get a generous tail budget; saturating cells use a
     * shorter window so the offered-load loop does not stall on one packet. */
    private static final int UDP_CLOSED_TIMEOUT_MS = 1000;
    private static final int UDP_SATURATING_TIMEOUT_MS = 200;
    private static final int MAX_TRACKED_UDP_TIMEOUTS = 4096;
    /* Fire-and-count controls must remain a bounded offered-load source. */
    private static final long FIRE_AND_COUNT_PACING_NS_PER_PACKET = 10_000_000L;

    static {
        System.loadLibrary("vpnfdprobe");
    }

    private ParcelFileDescriptor vpnFd;
    private final Object l4StressLock = new Object();
    private volatile boolean l4StressStopRequested;
    private volatile ArrayList<L4StressFlow> activeL4Flows;
    private volatile ExecutorService activeL4Executor;

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

    /**
     * OI-2 broker operation.  The native broker owns only a received
     * SCM_RIGHTS duplicate; this Java method performs the Android-only
     * underlay selection and VPN-loop prevention in the required order.
     *
     * @return 1 on bind+protect success, 2 on bind failure, 3 on protect
     *         failure
     */
    public int bindAndProtectSocketForNative(int fd) {
        Log.i(TAG, "OI2 bindAndProtect entry fd=" + fd);
        File forceBindFailure = new File(getFilesDir(), "force-bind-failure");
        if (forceBindFailure.isFile()) {
            Log.w(TAG, "forced Network.bindSocket failure fd=" + fd);
            return 2;
        }
        ConnectivityManager connectivityManager =
                (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);
        Network network = connectivityManager == null
                ? null : connectivityManager.getActiveNetwork();
        if (network == null) {
            Log.w(TAG, "Network.bindSocket unavailable: no active network fd=" + fd);
            return 2;
        }
        Log.i(TAG, "OI2 active network fd=" + fd
                + " networkHandle=" + network.getNetworkHandle());
        ParcelFileDescriptor duplicate = null;
        try {
            duplicate = ParcelFileDescriptor.fromFd(fd);
            network.bindSocket(duplicate.getFileDescriptor());
            Log.i(TAG, "Network.bindSocket fd=" + fd
                    + " networkHandle=" + network.getNetworkHandle() + " result=true");
        } catch (Exception e) {
            Log.w(TAG, "Network.bindSocket failed fd=" + fd
                    + " networkHandle=" + network.getNetworkHandle(), e);
            return 2;
        } finally {
            if (duplicate != null) {
                try {
                    duplicate.close();
                } catch (Exception e) {
                    Log.w(TAG, "close bind duplicate failed fd=" + fd, e);
                }
            }
        }
        File forceProtectFailure = new File(getFilesDir(), "force-protect-failure");
        if (forceProtectFailure.isFile()) {
            Log.w(TAG, "forced VpnService.protect failure fd=" + fd);
            return 3;
        }
        boolean protectedSocket = protect(fd);
        Log.i(TAG, "VpnService.protect fd=" + fd + " result=" + protectedSocket);
        Log.i(TAG, "OI2 bindAndProtect exit fd=" + fd
                + " result=" + (protectedSocket ? 1 : 3));
        return protectedSocket ? 1 : 3;
    }

    private static native int nativeStartProbe(int fd, String logPath, int maxPackets,
                                               SnortVpnService ownerLookup);

    private static native void nativeStopProbe();

    private static native int nativeStartVppProbe(int fd, String nativeLibraryDir, String filesDir,
                                                  int vppMode, String s124Path,
                                                  String s124Observe, String blockIp4Dst,
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

    private static native int nativeRunRustVppReconnectProbe(String filesDir,
                                                              int timeoutSeconds);

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
        if (ACTION_TCP_PROBE.equals(action)) {
            startTcpProbe(intent);
            return START_NOT_STICKY;
        }
        if (ACTION_L4_STRESS_PROBE.equals(action)) {
            startL4StressProbe(intent);
            return START_NOT_STICKY;
        }
        if (ACTION_PING_PROBE.equals(action)) {
            startPingProbe(intent);
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
        if (ACTION_RUST_RECONNECT_PROBE.equals(action)) {
            startRustReconnectProbe(intent);
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
        String s124Path = intent == null ? null : intent.getStringExtra(EXTRA_S124_PATH);
        String s124Observe = intent == null ? null : intent.getStringExtra(EXTRA_S124_OBSERVE);
        startVpn(mode == null ? MODE_NATIVE : mode, allowedPackage, disallowedPackage,
                blockIp4Dst, blockIp6Dst, blockOwnerUid, redirectThread, ownerCache,
                enableIpv6, s124Path, s124Observe);
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

    private void startRustReconnectProbe(Intent intent) {
        final int timeoutSeconds = intent == null ? 60
                : Math.max(5, Math.min(120, intent.getIntExtra(EXTRA_DURATION_SECONDS, 60)));
        Thread thread = new Thread(() -> {
            int rc = nativeRunRustVppReconnectProbe(getFilesDir().getAbsolutePath(),
                    timeoutSeconds);
            Log.i(TAG, "nativeRunRustVppReconnectProbe uid=" + Process.myUid()
                    + " timeoutSeconds=" + timeoutSeconds + " rc=" + rc);
        }, "snort-rust-vpp-reconnect-probe");
        thread.start();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private static boolean isControlledOi3Mode(String mode) {
        return MODE_VPP_OI3_CONTROLLED.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_TCP4.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_UDP6.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_TCP6.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_REFUSED.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_NO_REPLY.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_POLICY_DROP.equals(mode);
    }

    private static boolean isControlledOi5Mode(String mode) {
        return MODE_VPP_OI5_CONTROLLED.equals(mode);
    }

    private static boolean isControlledOi3Ipv6Mode(String mode) {
        return MODE_VPP_OI3_CONTROLLED_UDP6.equals(mode)
                || MODE_VPP_OI3_CONTROLLED_TCP6.equals(mode);
    }

    private static String controlledOi3Cell(String mode) {
        if (MODE_VPP_OI3_CONTROLLED_TCP4.equals(mode)) return "tcp4";
        if (MODE_VPP_OI3_CONTROLLED_UDP6.equals(mode)) return "udp6";
        if (MODE_VPP_OI3_CONTROLLED_TCP6.equals(mode)) return "tcp6";
        if (MODE_VPP_OI3_CONTROLLED_REFUSED.equals(mode)) return "refused";
        if (MODE_VPP_OI3_CONTROLLED_NO_REPLY.equals(mode)) return "no-reply";
        if (MODE_VPP_OI3_CONTROLLED_POLICY_DROP.equals(mode)) return "policy-drop";
        return "udp4";
    }

    private synchronized void startVpn(String mode, String allowedPackage,
                                       String disallowedPackage, String blockIp4Dst,
                                       String blockIp6Dst, int blockOwnerUid,
                                       int redirectThread, boolean ownerCache,
                                       boolean enableIpv6, String s124Path,
                                       String s124Observe) {
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

            boolean controlledOi3 = isControlledOi3Mode(mode);
            boolean controlledOi5 = isControlledOi5Mode(mode);
            boolean controlledRoute = controlledOi3 || controlledOi5;
            boolean controlledOi3Ipv6 = isControlledOi3Ipv6Mode(mode);
            Builder builder = new Builder()
                    .setSession("Snort VPN Lite")
                    .setMtu(1500)
                    .addAddress(controlledRoute ? "10.200.0.2" : VPN_ADDRESS, 32);
            if (controlledRoute) {
                // Safety boundary: only one narrow test prefix is routed; no
                // default route and no unrelated device traffic are captured.
                if (controlledOi3Ipv6) {
                    builder.addAddress("fd00:200::2", 128)
                            .addRoute("fd00:200::", 64);
                    Log.i(TAG, "OI3 controlled VPN route=fd00:200::/64 "
                            + "default-routes=none");
                } else {
                    builder.addRoute("10.200.0.0", 24);
                    Log.i(TAG, "OI3 controlled VPN route=10.200.0.0/24 "
                            + "default-routes=none");
                }
            } else {
                builder.addRoute("0.0.0.0", 0);
            }
            if (enableIpv6 && !controlledOi3) {
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
                    || MODE_VPP_HEV_DIRECT_OWNER.equals(mode)
                    || MODE_VPP_HEV_DIRECT_OWNER_POLLING.equals(mode)
                    || MODE_VPP_HEV_DIRECT_OWNER_FAULT.equals(mode)
                    || MODE_VPP_HEV_DIRECT_OWNER_RETURN.equals(mode)
                    || MODE_VPP_HEV_DIRECT_OWNER_SINGLE_WRITER.equals(mode)
                    || MODE_VPP_HEV_FRAGMENT_OWNER.equals(mode)
                    || MODE_VPP_FRAGMENT_OWNER.equals(mode)
                    || MODE_VPP_HEV_OWNER_GATE.equals(mode)
                    || MODE_VPP_HEV_OWNER_RESOLVER.equals(mode)
                    || MODE_VPP_HEV_TUN_SINGLE.equals(mode)
                    || MODE_VPP_HEV_TUN_MULTI.equals(mode)
                    || MODE_VPP_OI2.equals(mode)
                    || MODE_VPP_OI3.equals(mode)
                    || controlledOi3
                    || controlledOi5) {
                int vppMode = 0;
                if (MODE_VPP_FORWARD.equals(mode)) {
                    vppMode = 1;
                } else if (MODE_VPP_HEV.equals(mode)) {
                    vppMode = 2;
                } else if (MODE_VPP_HEV_OWNER_GATE.equals(mode)) {
                    vppMode = 3;
                } else if (MODE_VPP_HEV_HANDOFF.equals(mode)) {
                    vppMode = 4;
                } else if (MODE_VPP_HEV_DIRECT_OWNER.equals(mode)) {
                    vppMode = 6;
                } else if (MODE_VPP_HEV_DIRECT_OWNER_POLLING.equals(mode)) {
                    vppMode = 7;
                } else if (MODE_VPP_HEV_DIRECT_OWNER_FAULT.equals(mode)) {
                    vppMode = 8;
                } else if (MODE_VPP_HEV_DIRECT_OWNER_RETURN.equals(mode)) {
                    vppMode = 9;
                } else if (MODE_VPP_HEV_DIRECT_OWNER_SINGLE_WRITER.equals(mode)) {
                    vppMode = 10;
                } else if (MODE_VPP_HEV_FRAGMENT_OWNER.equals(mode)) {
                    vppMode = 11;
                } else if (MODE_VPP_FRAGMENT_OWNER.equals(mode)) {
                    vppMode = 12;
                } else if (MODE_VPP_HEV_OWNER_RESOLVER.equals(mode)) {
                    vppMode = 5;
                } else if (MODE_VPP_HEV_TUN_SINGLE.equals(mode)) {
                    vppMode = 13;
                } else if (MODE_VPP_HEV_TUN_MULTI.equals(mode)) {
                    vppMode = 14;
                } else if (MODE_VPP_OI2.equals(mode)) {
                    vppMode = 15;
                } else if (MODE_VPP_OI3.equals(mode)) {
                    vppMode = 16;
                } else if (MODE_VPP_OI3_CONTROLLED.equals(mode)) {
                    vppMode = 17;
                } else if (MODE_VPP_OI3_CONTROLLED_TCP4.equals(mode)) {
                    vppMode = 18;
                } else if (MODE_VPP_OI3_CONTROLLED_UDP6.equals(mode)) {
                    vppMode = 19;
                } else if (MODE_VPP_OI3_CONTROLLED_TCP6.equals(mode)) {
                    vppMode = 20;
                } else if (MODE_VPP_OI3_CONTROLLED_REFUSED.equals(mode)) {
                    vppMode = 21;
                } else if (MODE_VPP_OI3_CONTROLLED_NO_REPLY.equals(mode)) {
                    vppMode = 22;
                } else if (MODE_VPP_OI3_CONTROLLED_POLICY_DROP.equals(mode)) {
                    vppMode = 23;
                } else if (MODE_VPP_OI5_CONTROLLED.equals(mode)) {
                    vppMode = 24;
                }
                int rc = nativeStartVppProbe(rawFd, getApplicationInfo().nativeLibraryDir,
                        getFilesDir().getAbsolutePath(), vppMode,
                        s124Path == null ? "full" : s124Path,
                        s124Observe == null ? "off" : s124Observe,
                        blockIp4Dst == null ? "" : blockIp4Dst,
                        blockIp6Dst == null ? "" : blockIp6Dst,
                        blockOwnerUid, redirectThread, ownerCache, this);
                Log.i(TAG, "nativeStartVppProbe fd=" + rawFd + " vppMode=" + vppMode
                        + " blockOwnerUid=" + blockOwnerUid
                        + " redirectThread=" + redirectThread
                        + " ownerCache=" + ownerCache + " rc=" + rc);
                if (controlledOi3 && rc == 0) {
                    startControlledOi3AppPacket(controlledOi3Cell(mode));
                }
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

    /**
     * Exercise one real app -> TUN ingress cell on a narrow controlled route.
     * No write() on the detached TUN fd is used: UDP/TCP sockets created here
     * are ordinary app sockets, so Android routes their packets into VpnService.
     */
    private void startControlledOi3AppPacket(String cell) {
        Thread thread = new Thread(() -> {
            try {
                Thread.sleep(1200L);
                byte[] payload = "android-oi3-controlled".getBytes(StandardCharsets.US_ASCII);
                boolean ipv6 = "udp6".equals(cell) || "tcp6".equals(cell);
                boolean tcp = "tcp4".equals(cell) || "tcp6".equals(cell)
                        || "refused".equals(cell);
                boolean policyDrop = "policy-drop".equals(cell);
                String destinationText = ipv6 ? "fd00:200::1" : "10.200.0.1";
                int port = tcp ? 42080 : 42081;
                InetAddress destination = InetAddress.getByName(destinationText);
                StringBuilder payloadHex = new StringBuilder(payload.length * 2);
                for (byte value : payload) {
                    payloadHex.append(String.format("%02x", value & 0xff));
                }
                String result;
                int sent = 0;
                int received = 0;
                if (tcp) {
                    try (Socket socket = new Socket()) {
                        socket.connect(new InetSocketAddress(destination, port), 5000);
                        socket.setSoTimeout(3500);
                        OutputStream out = socket.getOutputStream();
                        out.write(payload);
                        out.flush();
                        sent = payload.length;
                        byte[] reply = new byte[payload.length + 64];
                        try {
                            int n = socket.getInputStream().read(reply);
                            received = Math.max(0, n);
                        } catch (java.net.SocketTimeoutException timeout) {
                            // Expected for the controlled no-reply cell.
                        }
                        result = policyDrop ? "UNEXPECTED_CONNECTED" : "OK";
                    }
                } else {
                    try (DatagramSocket socket = new DatagramSocket()) {
                        socket.setSoTimeout(3500);
                        DatagramPacket packet = new DatagramPacket(payload, payload.length,
                                destination, port);
                        socket.send(packet);
                        sent = payload.length;
                        if (!policyDrop) {
                            byte[] reply = new byte[payload.length + 64];
                            DatagramPacket response = new DatagramPacket(reply, reply.length);
                            try {
                                socket.receive(response);
                                received = response.getLength();
                            } catch (java.net.SocketTimeoutException timeout) {
                                // Expected for no-reply; preserve a raw timeout result.
                            }
                        }
                        result = policyDrop ? "OK_NO_TRANSPORT_EXPECTED"
                                : (received > 0 ? "OK" : "TIMEOUT");
                    }
                }
                appendProbeLog(new File(getFilesDir(),
                                "logs/vpp-oi3-controlled-app.log"),
                        "cell=" + cell + " result=" + result + " sent=" + sent
                                + " received=" + received + " destination="
                                + destinationText + ":" + port + " payload-hex="
                                + payloadHex);
                Log.i(TAG, "OI3 controlled app-inject cell=" + cell + " result=" + result
                        + " sent=" + sent + " received=" + received
                        + " destination=" + destinationText + ":" + port);
            } catch (java.net.ConnectException refused) {
                appendProbeLog(new File(getFilesDir(),
                                "logs/vpp-oi3-controlled-app.log"),
                        "cell=" + cell + " result=REFUSED error=" + refused);
                Log.i(TAG, "OI3 controlled app-inject cell=" + cell + " result=REFUSED");
            } catch (Exception e) {
                appendProbeLog(new File(getFilesDir(),
                                "logs/vpp-oi3-controlled-app.log"),
                        "cell=" + cell + " result=FAIL error=" + e);
                Log.e(TAG, "OI3 controlled app-inject failed cell=" + cell, e);
            }
        }, "snort-oi3-controlled-app-inject-" + cell);
        thread.start();
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
        int payloadBytes = intent == null ? 0 : intent.getIntExtra(EXTRA_PAYLOAD_BYTES, 0);
        payloadBytes = Math.max(0, Math.min(60000, payloadBytes));
        int flows = intent == null ? 1 : intent.getIntExtra(EXTRA_FLOWS, 1);
        flows = Math.max(1, Math.min(32, flows));

        final String probeHost = host;
        final int probePort = port;
        final int probeCount = count;
        final int probePayloadBytes = payloadBytes;
        final int probeFlows = flows;
        final int durationSeconds = intent == null ? 0
                : Math.max(0, Math.min(3600, intent.getIntExtra(EXTRA_DURATION_SECONDS, 0)));
        Thread thread = new Thread(() -> {
            if (probeFlows > 1) {
                runUdpFlowProbe(probeHost, probePort, probeFlows, probePayloadBytes);
            } else if (durationSeconds > 0) {
                runUdpStreamProbe(probeHost, probePort, durationSeconds);
            } else {
                runUdpProbe(probeHost, probePort, probeCount, probePayloadBytes);
            }
        },
                "snort-app-udp-probe");
        thread.start();
    }

    private void startTcpProbe(Intent intent) {
        String host = intent == null ? null : intent.getStringExtra(EXTRA_HOST);
        if (host == null || host.isEmpty()) {
            host = "10.0.0.1";
        }
        int port = intent == null ? 49155 : intent.getIntExtra(EXTRA_PORT, 49155);
        int count = intent == null ? 1 : intent.getIntExtra(EXTRA_COUNT, 1);
        count = Math.max(1, Math.min(1000, count));
        int payloadBytes = intent == null ? 0 : intent.getIntExtra(EXTRA_PAYLOAD_BYTES, 0);
        payloadBytes = Math.max(0, Math.min(1400, payloadBytes));
        int flows = intent == null ? 1 : intent.getIntExtra(EXTRA_FLOWS, 1);
        flows = Math.max(1, Math.min(32, flows));
        final String probeHost = host;
        final int probePort = port;
        final int probeCount = count;
        final int probePayloadBytes = payloadBytes;
        final int probeFlows = flows;
        Thread thread = new Thread(() -> {
            if (probeFlows > 1) {
                runTcpFlowProbe(probeHost, probePort, probeFlows, probePayloadBytes);
            } else {
                runTcpProbe(probeHost, probePort, probeCount, probePayloadBytes);
            }
        }, "snort-app-tcp-probe");
        thread.start();
    }

    private void startL4StressProbe(Intent intent) {
        cancelL4StressProbe();
        String protocol = intent == null ? "udp" : intent.getStringExtra(EXTRA_PROTOCOL);
        protocol = "tcp".equalsIgnoreCase(protocol) ? "tcp" : "udp";
        String host = intent == null ? "10.0.0.1" : intent.getStringExtra(EXTRA_HOST);
        if (host == null || host.isEmpty()) {
            host = "10.0.0.1";
        }
        int port = intent == null ? ("tcp".equals(protocol) ? 49155 : 49154)
                : intent.getIntExtra(EXTRA_PORT, "tcp".equals(protocol) ? 49155 : 49154);
        int flows = intent == null ? 1 : intent.getIntExtra(EXTRA_FLOWS, 1);
        int payloadBytes = intent == null ? 33 : intent.getIntExtra(EXTRA_PAYLOAD_BYTES, 33);
        int burst = intent == null ? 1 : intent.getIntExtra(EXTRA_BURST, 1);
        String load = intent == null ? "closed" : intent.getStringExtra(EXTRA_LOAD);
        int warmupSeconds = intent == null ? 10
                : intent.getIntExtra(EXTRA_WARMUP_SECONDS, 10);
        int steadySeconds = intent == null ? 30
                : intent.getIntExtra(EXTRA_STEADY_SECONDS, 30);
        int drainSeconds = intent == null ? 10
                : intent.getIntExtra(EXTRA_DRAIN_SECONDS, 10);
        int reconnectEvery = intent == null ? 0
                : intent.getIntExtra(EXTRA_RECONNECT_EVERY, 0);
        boolean expectEcho = intent == null || intent.getBooleanExtra(EXTRA_EXPECT_ECHO, true);
        long runId = System.nanoTime() ^ (((long) Process.myPid()) << 32);
        final L4StressConfig config = new L4StressConfig(protocol, host, port,
                Math.max(1, Math.min(32, flows)), Math.max(21, Math.min(1400, payloadBytes)),
                burst == 32 ? 32 : 1,
                "saturating".equalsIgnoreCase(load) ? "saturating" : "closed",
                Math.max(1, Math.min(120, warmupSeconds)),
                Math.max(1, Math.min(600, steadySeconds)),
                Math.max(1, Math.min(120, drainSeconds)),
                Math.max(0, Math.min(600, reconnectEvery)), expectEcho, runId);
        Thread thread = new Thread(() -> runL4StressProbe(config),
                "snort-app-l4-stress-probe");
        thread.start();
    }

    private void cancelL4StressProbe() {
        l4StressStopRequested = true;
        ArrayList<L4StressFlow> flows = activeL4Flows;
        if (flows != null) {
            for (L4StressFlow flow : flows) flow.cancel();
        }
        ExecutorService executor = activeL4Executor;
        if (executor != null) executor.shutdownNow();
    }

    private void startPingProbe(Intent intent) {
        String host = intent == null ? null : intent.getStringExtra(EXTRA_HOST);
        if (host == null || host.isEmpty()) {
            host = "1.1.1.1";
        }
        int size = intent == null ? 4000 : intent.getIntExtra(EXTRA_SIZE, 4000);
        int count = intent == null ? 1 : intent.getIntExtra(EXTRA_COUNT, 1);
        size = Math.max(0, Math.min(60000, size));
        count = Math.max(1, Math.min(10, count));
        final String probeHost = host;
        final int probeSize = size;
        final int probeCount = count;
        Thread thread = new Thread(() -> {
            try {
                java.lang.Process process = new ProcessBuilder("/system/bin/ping", "-c",
                        Integer.toString(probeCount), "-s", Integer.toString(probeSize),
                        "-W", "5", probeHost).redirectErrorStream(true).start();
                ByteArrayOutputStream outputBuffer = new ByteArrayOutputStream();
                byte[] outputChunk = new byte[256];
                int outputRead;
                while ((outputRead = process.getInputStream().read(outputChunk)) > 0) {
                    outputBuffer.write(outputChunk, 0, outputRead);
                }
                byte[] output = outputBuffer.toByteArray();
                int rc = process.waitFor();
                File logPath = new File(getFilesDir(), "logs/app-ping-probe.log");
                appendProbeLog(logPath, "rc=" + rc + " host=" + probeHost + " size="
                        + probeSize + " count=" + probeCount + " output="
                        + new String(output, StandardCharsets.UTF_8).replace('\n', ' '));
            } catch (Exception e) {
                File logPath = new File(getFilesDir(), "logs/app-ping-probe.log");
                appendProbeLog(logPath, "fail host=" + probeHost + " error=" + e);
            }
        }, "snort-app-ping-probe");
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

    private void runUdpProbe(String host, int port, int count, int payloadBytes) {
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
            byte[] payload = payloadBytes > 0 ? new byte[payloadBytes]
                    : "snort-vpn-lite-udp-probe".getBytes(StandardCharsets.US_ASCII);
            if (payloadBytes > 0) {
                byte[] prefix = "snort-vpn-lite-udp-fragment".getBytes(StandardCharsets.US_ASCII);
                System.arraycopy(prefix, 0, payload, 0, Math.min(prefix.length, payload.length));
            }
            DatagramPacket packet = new DatagramPacket(payload, payload.length);
            byte[] responseBytes = new byte[Math.max(2048, payload.length)];
            DatagramPacket response = new DatagramPacket(responseBytes, responseBytes.length);
            socket.setSoTimeout(5000);
            int sent = 0;
            int received = 0;
            for (int i = 0; i < count; i++) {
                socket.send(packet);
                sent++;
                try {
                    response.setLength(responseBytes.length);
                    socket.receive(response);
                    if (response.getLength() == payload.length) {
                        received++;
                    }
                } catch (java.net.SocketTimeoutException timeout) {
                    // Keep the send count and record missing echo responses.
                }
            }
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "ok bytes=" + (payload.length * sent)
                    + " packets=" + sent + " received=" + received + " elapsedMs=" + elapsed);
            Log.i(TAG, "app UDP probe ok host=" + host + " port=" + port
                    + " packets=" + sent + " received=" + received
                    + " bytes=" + (payload.length * sent));
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "fail elapsedMs=" + elapsed + " error="
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.w(TAG, "app UDP probe failed host=" + host + " port=" + port, e);
        }
    }

    private void runUdpFlowProbe(String host, int port, int flows, int payloadBytes) {
        long started = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-udp-probe.log");
        byte[] payload = payloadBytes > 0 ? new byte[payloadBytes]
                : "snort-vpn-lite-udp-flow".getBytes(StandardCharsets.US_ASCII);
        int sent = 0;
        int received = 0;
        int errors = 0;
        appendProbeLog(logPath, "flows-start host=" + host + " port=" + port
                + " flows=" + flows + " payloadBytes=" + payload.length);
        try {
            InetAddress remote = InetAddress.getByName(host);
            for (int flow = 0; flow < flows; flow++) {
                try (DatagramSocket socket = new DatagramSocket()) {
                    socket.connect(remote, port);
                    socket.setSoTimeout(5000);
                    socket.send(new DatagramPacket(payload, payload.length));
                    sent++;
                    byte[] responseBytes = new byte[Math.max(2048, payload.length)];
                    DatagramPacket response = new DatagramPacket(responseBytes,
                            responseBytes.length);
                    socket.receive(response);
                    if (response.getLength() == payload.length) {
                        received++;
                    }
                } catch (Exception e) {
                    errors++;
                }
            }
        } catch (Exception e) {
            errors++;
        }
        long elapsed = System.currentTimeMillis() - started;
        appendProbeLog(logPath, "flows-done flows=" + flows + " sent=" + sent
                + " received=" + received + " errors=" + errors
                + " elapsedMs=" + elapsed);
        Log.i(TAG, "app UDP flows done host=" + host + " flows=" + flows
                + " sent=" + sent + " received=" + received + " errors=" + errors);
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

    private void runTcpProbe(String host, int port, int count, int payloadBytes) {
        long started = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-tcp-probe.log");
        appendProbeLog(logPath, "start host=" + host + " port=" + port + " count=" + count);
        int sent = 0;
        int received = 0;
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), 5000);
            socket.setSoTimeout(5000);
            byte[] payload = payloadBytes > 0 ? new byte[payloadBytes]
                    : "snort-vpn-lite-tcp-probe".getBytes(StandardCharsets.US_ASCII);
            if (payloadBytes > 0) {
                byte[] prefix = "snort-vpn-lite-tcp-data".getBytes(StandardCharsets.US_ASCII);
                System.arraycopy(prefix, 0, payload, 0, Math.min(prefix.length, payload.length));
            }
            OutputStream output = socket.getOutputStream();
            BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
            byte[] response = new byte[payload.length];
            for (int i = 0; i < count; i++) {
                output.write(payload);
                output.flush();
                int offset = 0;
                while (offset < response.length) {
                    int n = input.read(response, offset, response.length - offset);
                    if (n < 0) {
                        throw new java.io.EOFException("TCP echo closed");
                    }
                    offset += n;
                }
                sent++;
                if (java.util.Arrays.equals(payload, response)) {
                    received++;
                }
            }
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "ok sent=" + sent + " received=" + received
                    + " payloadBytes=" + payload.length + " elapsedMs=" + elapsed);
            Log.i(TAG, "app TCP probe ok host=" + host + " port=" + port
                    + " sent=" + sent + " received=" + received);
        } catch (Exception e) {
            long elapsed = System.currentTimeMillis() - started;
            appendProbeLog(logPath, "fail sent=" + sent + " received=" + received
                    + " elapsedMs=" + elapsed + " error="
                    + e.getClass().getSimpleName() + ": " + e.getMessage());
            Log.w(TAG, "app TCP probe failed host=" + host + " port=" + port, e);
        }
    }

    private void runTcpFlowProbe(String host, int port, int flows, int payloadBytes) {
        long started = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-tcp-probe.log");
        byte[] payload = payloadBytes > 0 ? new byte[payloadBytes]
                : "snort-vpn-lite-tcp-flow".getBytes(StandardCharsets.US_ASCII);
        if (payloadBytes > 0) {
            byte[] prefix = "snort-vpn-lite-tcp-data".getBytes(StandardCharsets.US_ASCII);
            System.arraycopy(prefix, 0, payload, 0, Math.min(prefix.length, payload.length));
        }
        int sent = 0;
        int received = 0;
        int errors = 0;
        appendProbeLog(logPath, "flows-start host=" + host + " port=" + port
                + " flows=" + flows + " payloadBytes=" + payload.length);
        try {
            for (int flow = 0; flow < flows; flow++) {
                try (Socket socket = new Socket()) {
                    socket.connect(new InetSocketAddress(host, port), 5000);
                    socket.setSoTimeout(5000);
                    OutputStream output = socket.getOutputStream();
                    BufferedInputStream input = new BufferedInputStream(socket.getInputStream());
                    output.write(payload);
                    output.flush();
                    sent++;
                    byte[] response = new byte[payload.length];
                    int offset = 0;
                    while (offset < response.length) {
                        int n = input.read(response, offset, response.length - offset);
                        if (n < 0) {
                            throw new java.io.EOFException("TCP echo closed");
                        }
                        offset += n;
                    }
                    if (java.util.Arrays.equals(payload, response)) {
                        received++;
                    }
                } catch (Exception e) {
                    errors++;
                }
            }
        } catch (Exception e) {
            errors++;
        }
        long elapsed = System.currentTimeMillis() - started;
        appendProbeLog(logPath, "flows-done flows=" + flows + " sent=" + sent
                + " received=" + received + " errors=" + errors
                + " elapsedMs=" + elapsed);
        Log.i(TAG, "app TCP flows done host=" + host + " flows=" + flows
                + " sent=" + sent + " received=" + received + " errors=" + errors);
    }

    private static final class L4StressConfig {
        final long runId;
        final String protocol;
        final String host;
        final int port;
        final int flows;
        final int payloadBytes;
        final int burst;
        final String load;
        final int warmupSeconds;
        final int steadySeconds;
        final int drainSeconds;
        final int reconnectEvery;
        final boolean expectEcho;

        L4StressConfig(String protocol, String host, int port, int flows, int payloadBytes,
                       int burst, String load, int warmupSeconds, int steadySeconds,
                       int drainSeconds, int reconnectEvery, boolean expectEcho, long runId) {
            this.runId = runId;
            this.protocol = protocol;
            this.host = host;
            this.port = port;
            this.flows = flows;
            this.payloadBytes = payloadBytes;
            this.burst = burst;
            this.load = load;
            this.warmupSeconds = warmupSeconds;
            this.steadySeconds = steadySeconds;
            this.drainSeconds = drainSeconds;
            this.reconnectEvery = reconnectEvery;
            this.expectEcho = expectEcho;
        }
    }

    private static final class L4StressPhase {
        volatile long setupStartNanos;
        volatile long setupEndNanos;
        volatile long warmupStartNanos;
        volatile long steadyStartNanos;
        volatile long steadyEndNanos;
        volatile long drainEndNanos;
        volatile long teardownStartNanos;
        volatile long teardownEndNanos;

        synchronized void markTeardownStart(long value) {
            if (teardownStartNanos == 0 || value < teardownStartNanos) {
                teardownStartNanos = value;
            }
        }

        synchronized void markTeardownEnd(long value) {
            if (value > teardownEndNanos) teardownEndNanos = value;
        }
    }

    private static final class L4FlowStats {
        final int flow;
        int localPort;
        long sent;
        long received;
        long errors;
        long mismatches;
        long unexpected;
        long late;
        long reordered;
        long reconnects;
        long reconnectErrors;
        boolean tcpConnected;
        boolean tcpFirstEcho;
        long tcpConnectNanos;
        long tcpFirstEchoNanos;
        boolean fatal;
        String failure = "";
        final ArrayList<Long> rttNanos = new ArrayList<>();

        L4FlowStats(int flow, int localPort) {
            this.flow = flow;
            this.localPort = localPort;
        }
    }

    private final class L4StressFlow implements Runnable {
        private final L4StressConfig config;
        private final InetAddress remote;
        private final CyclicBarrier barrier;
        private final L4StressPhase phase;
        private final L4FlowStats stats;
        private DatagramSocket udp;
        private Socket tcp;
        private OutputStream tcpOutput;
        private BufferedInputStream tcpInput;
        private long nextSequence;
        private long nextReconnectNanos;
        private volatile boolean stopped;
        private final byte[] sendBuffer;
        private final byte[] receiveBuffer;
        private final byte[] tcpResponseBuffer;
        private final DatagramPacket udpSendPacket;
        private final DatagramPacket udpReceivePacket;
        private final Map<Long, Long> pendingUdp = new HashMap<>();
        private final Set<Long> timedOutUdp = new HashSet<>();
        private final ArrayList<Long> pendingTcp = new ArrayList<>();
        private final Map<Long, Long> sentTcpAt = new HashMap<>();

        L4StressFlow(L4StressConfig config, InetAddress remote, int flow,
                     CyclicBarrier barrier, L4StressPhase phase) throws Exception {
            this.config = config;
            this.remote = remote;
            this.barrier = barrier;
            this.phase = phase;
            int base = "tcp".equals(config.protocol) ? 41000 : 40000;
            this.stats = new L4FlowStats(flow, base + flow);
            this.sendBuffer = new byte[config.payloadBytes];
            this.receiveBuffer = new byte[Math.max(2048, config.payloadBytes)];
            this.tcpResponseBuffer = new byte[config.payloadBytes];
            this.udpSendPacket = new DatagramPacket(sendBuffer, sendBuffer.length);
            this.udpReceivePacket = new DatagramPacket(receiveBuffer, receiveBuffer.length);
            open();
        }

        L4FlowStats stats() {
            return stats;
        }

        private void open() throws Exception {
            closeSocket();
            if ("udp".equals(config.protocol)) {
                udp = new DatagramSocket(null);
                udp.setReuseAddress(true);
                udp.bind(new InetSocketAddress(stats.localPort));
                udp.connect(remote, config.port);
                udp.setSoTimeout("closed".equals(config.load)
                        ? UDP_CLOSED_TIMEOUT_MS : UDP_SATURATING_TIMEOUT_MS);
            } else {
                tcp = new Socket();
                long connectStarted = System.nanoTime();
                tcp.connect(new InetSocketAddress(remote, config.port), 5000);
                // Android may reject a repeatedly reused fixed TCP source port
                // with EHOSTUNREACH while the VPN policy is being recreated.
                // Let the kernel allocate a source port and record the actual
                // value in the flow log; UDP keeps its deterministic bind.
                stats.localPort = tcp.getLocalPort();
                stats.tcpConnected = true;
                stats.tcpConnectNanos = System.nanoTime() - connectStarted;
                tcp.setSoTimeout(1000);
                tcpOutput = tcp.getOutputStream();
                tcpInput = new BufferedInputStream(tcp.getInputStream());
            }
        }

        private void closeSocket() {
            if (udp != null) {
                udp.close();
                udp = null;
            }
            if (tcp != null) {
                try {
                    tcp.close();
                } catch (Exception ignored) {
                    // Raw close is recorded by the next operation if relevant.
                }
                tcp = null;
                tcpOutput = null;
                tcpInput = null;
            }
        }

        void cancel() {
            stopped = true;
            closeSocket();
        }

        private void fillPayload(long sequence, byte[] value) {
            value[0] = 'S';
            if (value.length > 1) value[1] = '1';
            if (value.length > 2) value[2] = '2';
            if (value.length > 3) value[3] = '5';
            if (value.length > 4) value[4] = (byte) (stats.flow & 0xff);
            for (int i = 0; i < 8 && 5 + i < value.length; i++) {
                value[5 + i] = (byte) (config.runId >>> (56 - i * 8));
            }
            for (int i = 0; i < 8 && 13 + i < value.length; i++) {
                value[13 + i] = (byte) (sequence >>> (56 - i * 8));
            }
            for (int i = 21; i < value.length; i++) {
                value[i] = (byte) (i * 31 + stats.flow);
            }
        }

        private long sequence(byte[] value) {
            return sequence(value, 0, value.length);
        }

        private long sequence(byte[] value, int offset, int length) {
            if (length < 21 || value[offset] != 'S' || value[offset + 1] != '1'
                    || value[offset + 2] != '2' || value[offset + 3] != '5'
                    || (value[offset + 4] & 0xff) != (stats.flow & 0xff)) {
                return Long.MIN_VALUE;
            }
            for (int i = 0; i < 8; i++) {
                if ((value[offset + 5 + i] & 0xff)
                        != ((config.runId >>> (56 - i * 8)) & 0xff)) {
                    return Long.MIN_VALUE;
                }
            }
            long sequence = 0;
            for (int i = 0; i < 8; i++) {
                sequence = (sequence << 8) | (value[offset + 13 + i] & 0xffL);
            }
            return sequence;
        }

        private void waitUntil(long deadlineNanos) {
            while (!stopped) {
                long remaining = deadlineNanos - System.nanoTime();
                if (remaining <= 0) return;
                LockSupport.parkNanos(Math.min(remaining, 5_000_000L));
            }
        }

        private void reconnect() {
            try {
                open();
                stats.reconnects++;
            } catch (Exception error) {
                stats.reconnectErrors++;
                stats.errors++;
                stats.fatal = true;
                stopped = true;
            }
        }

        private void runUdpBatch(boolean record) throws Exception {
            int batch = "closed".equals(config.load) ? 1 : Math.max(1, config.burst);
            pendingUdp.clear();
            for (int i = 0; i < batch; i++) {
                long sequence = nextSequence++;
                fillPayload(sequence, sendBuffer);
                long sentAt = System.nanoTime();
                udpSendPacket.setLength(sendBuffer.length);
                udp.send(udpSendPacket);
                pendingUdp.put(sequence, sentAt);
                if (record) stats.sent++;
                if (!config.expectEcho) {
                    // Fire-and-count is a lossless control arm.  Pace every
                    // packet, including the last packet of a batch: for
                    // burst=1 the next batch otherwise starts immediately,
                    // and for burst=32 a batch-sized microburst can overrun
                    // the VPP handoff queue despite a nominal 100 packets/s.
                    LockSupport.parkNanos(FIRE_AND_COUNT_PACING_NS_PER_PACKET);
                }
            }
            if (!config.expectEcho) {
                return;
            }
            while (!pendingUdp.isEmpty()) {
                try {
                    udpReceivePacket.setLength(receiveBuffer.length);
                    udp.receive(udpReceivePacket);
                    long sequence = sequence(udpReceivePacket.getData(),
                            udpReceivePacket.getOffset(), udpReceivePacket.getLength());
                    Long sentAt = pendingUdp.remove(sequence);
                    if (sentAt == null) {
                        if (record) {
                            // A valid packet is late only when this flow
                            // previously timed out that exact sequence.  A
                            // duplicate or an untracked sequence remains an
                            // unexpected payload and invalidates correctness.
                            if (sequence != Long.MIN_VALUE
                                    && timedOutUdp.remove(sequence)) {
                                stats.late++;
                            } else {
                                stats.unexpected++;
                            }
                        }
                        continue;
                    }
                    if (udpReceivePacket.getLength() != config.payloadBytes) {
                        if (record) stats.mismatches++;
                    } else if (record) {
                        stats.received++;
                        stats.rttNanos.add(System.nanoTime() - sentAt);
                    }
                } catch (java.net.SocketTimeoutException timeout) {
                    for (Long sequence : pendingUdp.keySet()) {
                        if (timedOutUdp.size() >= MAX_TRACKED_UDP_TIMEOUTS) {
                            timedOutUdp.clear();
                        }
                        timedOutUdp.add(sequence);
                    }
                    if (record) {
                        stats.errors += pendingUdp.size();
                    }
                    pendingUdp.clear();
                }
            }
        }

        private void drainUdpUntil(long deadlineNanos) {
            if (!config.expectEcho || udp == null) {
                waitUntil(deadlineNanos);
                return;
            }
            try {
                // Drain late echoes explicitly instead of merely sleeping.
                // This separates a true timeout from a packet that arrived
                // after the steady window and makes closed-cell tail behavior
                // visible in the raw app ledger.
                udp.setSoTimeout(20);
                while (!stopped && !l4StressStopRequested
                        && System.nanoTime() < deadlineNanos) {
                    try {
                        udpReceivePacket.setLength(receiveBuffer.length);
                        udp.receive(udpReceivePacket);
                        long sequence = sequence(udpReceivePacket.getData(),
                                udpReceivePacket.getOffset(),
                                udpReceivePacket.getLength());
                        if (sequence != Long.MIN_VALUE
                                && timedOutUdp.remove(sequence)) {
                            stats.late++;
                        } else {
                            stats.unexpected++;
                        }
                    } catch (java.net.SocketTimeoutException timeout) {
                        // Keep polling until the pre-registered drain bound.
                    }
                }
            } catch (Exception error) {
                stats.errors++;
            }
        }

        private void readFully(byte[] value) throws Exception {
            int offset = 0;
            while (offset < value.length) {
                int count = tcpInput.read(value, offset, value.length - offset);
                if (count < 0) throw new EOFException("TCP echo closed");
                offset += count;
            }
        }

        private void runTcpBatch(boolean record) throws Exception {
            int batch = "closed".equals(config.load) ? 1 : Math.max(1, config.burst);
            pendingTcp.clear();
            sentTcpAt.clear();
            for (int i = 0; i < batch; i++) {
                long sequence = nextSequence++;
                fillPayload(sequence, sendBuffer);
                long started = System.nanoTime();
                tcpOutput.write(sendBuffer);
                pendingTcp.add(sequence);
                sentTcpAt.put(sequence, started);
                if (record) stats.sent++;
                if (!config.expectEcho) {
                    // Keep the fire-and-count control lossless at the packet
                    // boundary, including the batch boundary; sleeping only
                    // after the whole burst creates a microburst, while
                    // omitting the final sleep breaks burst=1 pacing.
                    LockSupport.parkNanos(FIRE_AND_COUNT_PACING_NS_PER_PACKET);
                }
            }
            tcpOutput.flush();
            if (!config.expectEcho) {
                return;
            }
            for (long expected : pendingTcp) {
                readFully(tcpResponseBuffer);
                long actual = sequence(tcpResponseBuffer);
                if (actual != expected) {
                    if (record) {
                        stats.reordered++;
                        if (actual == Long.MIN_VALUE) stats.mismatches++;
                    }
                    continue;
                }
                if (!stats.tcpFirstEcho) {
                    stats.tcpFirstEcho = true;
                    stats.tcpFirstEchoNanos = System.nanoTime();
                }
                if (record) {
                    stats.received++;
                    Long started = sentTcpAt.get(expected);
                    if (started != null) stats.rttNanos.add(System.nanoTime() - started);
                }
            }
        }

        private void runBatch(boolean record) throws Exception {
            if (config.reconnectEvery > 0 && System.nanoTime() >= nextReconnectNanos) {
                reconnect();
                nextReconnectNanos = System.nanoTime()
                        + TimeUnit.SECONDS.toNanos(config.reconnectEvery);
                if (stopped) return;
            }
            if ("udp".equals(config.protocol)) runUdpBatch(record);
            else runTcpBatch(record);
        }

        @Override
        public void run() {
            try {
                barrier.await();
                nextReconnectNanos = phase.steadyStartNanos
                        + TimeUnit.SECONDS.toNanos(config.reconnectEvery);
                while (!stopped && !l4StressStopRequested
                        && System.nanoTime() < phase.steadyStartNanos) {
                    runBatch(false);
                }
                while (!stopped && !l4StressStopRequested
                        && System.nanoTime() < phase.steadyEndNanos) {
                    runBatch(true);
                }
                if ("udp".equals(config.protocol)) {
                    drainUdpUntil(phase.drainEndNanos);
                } else {
                    waitUntil(phase.drainEndNanos);
                }
            } catch (Exception error) {
                stats.errors++;
                stats.fatal = true;
                String message = error.getMessage();
                stats.failure = (error.getClass().getSimpleName()
                        + (message == null || message.isEmpty() ? "" : ":" + message))
                        .replace(' ', '_');
            } finally {
                phase.markTeardownStart(System.nanoTime());
                closeSocket();
                phase.markTeardownEnd(System.nanoTime());
            }
        }

    }

    private void runL4StressProbe(L4StressConfig config) {
        long startedMillis = System.currentTimeMillis();
        File logsDir = new File(getFilesDir(), "logs");
        if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
            Log.w(TAG, "failed to create logs dir: " + logsDir);
        }
        File logPath = new File(logsDir, "app-l4-stress-probe.log");
        appendProbeLog(logPath, "start protocol=" + config.protocol + " host=" + config.host
                + " port=" + config.port + " flows=" + config.flows
                + " runId=" + Long.toUnsignedString(config.runId)
                + " payloadBytes=" + config.payloadBytes + " burst=" + config.burst
                + " load=" + config.load + " warmupSeconds=" + config.warmupSeconds
                + " steadySeconds=" + config.steadySeconds + " drainSeconds="
                + config.drainSeconds + " reconnectEvery=" + config.reconnectEvery
                + " expectEcho=" + config.expectEcho
                + " udpClosedTimeoutMs=" + UDP_CLOSED_TIMEOUT_MS
                + " udpSaturatingTimeoutMs=" + UDP_SATURATING_TIMEOUT_MS
                + " fireAndCountPacingNsPerPacket="
                + FIRE_AND_COUNT_PACING_NS_PER_PACKET);
        ArrayList<L4StressFlow> flows = new ArrayList<>();
        ExecutorService executor = null;
        boolean executorTimedOut = false;
        synchronized (l4StressLock) {
            l4StressStopRequested = false;
            activeL4Flows = flows;
            activeL4Executor = null;
        }
        try {
            L4StressPhase phase = new L4StressPhase();
            phase.setupStartNanos = System.nanoTime();
            InetAddress remote = InetAddress.getByName(config.host);
            CyclicBarrier barrier = new CyclicBarrier(config.flows, () -> {
                phase.warmupStartNanos = System.nanoTime();
                phase.steadyStartNanos = phase.warmupStartNanos
                        + TimeUnit.SECONDS.toNanos(config.warmupSeconds);
                phase.steadyEndNanos = phase.steadyStartNanos
                        + TimeUnit.SECONDS.toNanos(config.steadySeconds);
                phase.drainEndNanos = phase.steadyEndNanos
                        + TimeUnit.SECONDS.toNanos(config.drainSeconds);
                appendProbeLog(logPath, "phase setup-start-nanos=" + phase.setupStartNanos
                        + " setup-end-nanos=" + phase.setupEndNanos
                        + " warmup-start-nanos=" + phase.warmupStartNanos
                        + " steady-start-nanos=" + phase.steadyStartNanos
                        + " steady-end-nanos=" + phase.steadyEndNanos
                        + " drain-end-nanos=" + phase.drainEndNanos);
            });
            for (int flow = 0; flow < config.flows; flow++) {
                flows.add(new L4StressFlow(config, remote, flow, barrier, phase));
            }
            phase.setupEndNanos = System.nanoTime();
            executor = Executors.newFixedThreadPool(config.flows);
            activeL4Executor = executor;
            for (L4StressFlow flow : flows) executor.execute(flow);
            executor.shutdown();
            if (!executor.awaitTermination(config.warmupSeconds + config.steadySeconds
                    + config.drainSeconds + 30L, TimeUnit.SECONDS)) {
                executor.shutdownNow();
                executor.awaitTermination(5L, TimeUnit.SECONDS);
                executorTimedOut = true;
                appendProbeLog(logPath, "fail runId=" + Long.toUnsignedString(config.runId)
                        + " reason=executor-timeout");
            }
            if (phase.teardownStartNanos == 0) {
                phase.markTeardownStart(System.nanoTime());
            }
            if (phase.teardownEndNanos == 0) {
                phase.markTeardownEnd(System.nanoTime());
            }
            long sent = 0;
            long received = 0;
            long errors = 0;
            long mismatches = 0;
            long unexpected = 0;
            long late = 0;
            long reordered = 0;
            long fatalFlows = 0;
            long tcpConnectedFlows = 0;
            long tcpFirstEchoFlows = 0;
            for (L4StressFlow flow : flows) {
                L4FlowStats stats = flow.stats();
                sent += stats.sent;
                received += stats.received;
                errors += stats.errors;
                mismatches += stats.mismatches;
                unexpected += stats.unexpected;
                late += stats.late;
                reordered += stats.reordered;
                if (stats.tcpConnected) tcpConnectedFlows++;
                if (stats.tcpFirstEcho) tcpFirstEchoFlows++;
                if (stats.fatal) fatalFlows++;
                appendProbeLog(logPath, "flow=" + stats.flow + " localPort=" + stats.localPort
                        + " runId=" + Long.toUnsignedString(config.runId)
                        + " sent=" + stats.sent + " received=" + stats.received
                        + " errors=" + stats.errors + " reconnects=" + stats.reconnects
                        + " reconnectErrors=" + stats.reconnectErrors
                        + " tcpConnected=" + stats.tcpConnected
                        + " tcpConnectUs=" + (stats.tcpConnectNanos < 0
                                ? -1 : stats.tcpConnectNanos / 1000L)
                        + " tcpFirstEcho=" + stats.tcpFirstEcho
                        + " tcpFirstEchoNanos=" + stats.tcpFirstEchoNanos
                        + " mismatches=" + stats.mismatches + " unexpected="
                        + stats.unexpected + " reordered=" + stats.reordered
                        + " late=" + stats.late
                        + " rttUsP50=" + percentileMicros(stats.rttNanos, 0.50)
                        + " rttUsP95=" + percentileMicros(stats.rttNanos, 0.95)
                        + " rttUsP99=" + percentileMicros(stats.rttNanos, 0.99)
                        + " fatal=" + stats.fatal
                        + " failure=" + (stats.failure.isEmpty() ? "none" : stats.failure));
            }
            long elapsed = System.currentTimeMillis() - startedMillis;
            long steadyNanos = phase.steadyEndNanos - phase.steadyStartNanos;
            long sentPpsMilli = steadyNanos > 0
                    ? (long) ((double) sent * 1000000000.0 * 1000.0 / steadyNanos) : 0;
            long receivedPpsMilli = steadyNanos > 0
                    ? (long) ((double) received * 1000000000.0 * 1000.0 / steadyNanos) : 0;
            long goodputBytesPerSec = steadyNanos > 0
                    ? (long) ((double) received * config.payloadBytes
                            * 1000000000.0 / steadyNanos) : 0;
            appendProbeLog(logPath, "done runId=" + Long.toUnsignedString(config.runId)
                    + " sent=" + sent + " received=" + received
                    + " errors=" + errors + " mismatches=" + mismatches
                    + " unexpected=" + unexpected + " late=" + late
                    + " reordered=" + reordered
                    + " fatalFlows=" + fatalFlows + " executorTimeout=" + executorTimedOut
                    + " tcpConnectedFlows=" + tcpConnectedFlows
                    + " tcpFirstEchoFlows=" + tcpFirstEchoFlows
                    + " tcpHandshakeReady="
                    + (!"tcp".equals(config.protocol)
                            || (tcpConnectedFlows == config.flows
                                && tcpFirstEchoFlows == config.flows))
                    + " steadySeconds=" + config.steadySeconds
                    + " sentPpsMilli=" + sentPpsMilli
                    + " receivedPpsMilli=" + receivedPpsMilli
                    + " goodputBytesPerSec=" + goodputBytesPerSec
                    + " udpClosedTimeoutMs=" + UDP_CLOSED_TIMEOUT_MS
                    + " udpSaturatingTimeoutMs=" + UDP_SATURATING_TIMEOUT_MS
                    + " setupStartNanos=" + phase.setupStartNanos
                    + " setupEndNanos=" + phase.setupEndNanos
                    + " teardownStartNanos=" + phase.teardownStartNanos
                    + " teardownEndNanos=" + phase.teardownEndNanos
                    + " elapsedMs=" + elapsed);
            Log.i(TAG, "app L4 stress done protocol=" + config.protocol + " flows="
                    + config.flows + " sent=" + sent + " received=" + received
                    + " errors=" + errors + " elapsedMs=" + elapsed);
        } catch (Exception error) {
            appendProbeLog(logPath, "fail runId=" + Long.toUnsignedString(config.runId)
                    + " elapsedMs="
                    + (System.currentTimeMillis() - startedMillis)
                    + " tcpHandshakeReady=false error=" + error);
            if (executor != null) executor.shutdownNow();
            for (L4StressFlow flow : flows) flow.closeSocket();
            Log.w(TAG, "app L4 stress failed protocol=" + config.protocol, error);
        } finally {
            synchronized (l4StressLock) {
                if (activeL4Flows == flows) {
                    activeL4Flows = null;
                    activeL4Executor = null;
                    l4StressStopRequested = false;
                }
            }
        }
    }

    private long percentileNanos(ArrayList<Long> values, double percentile) {
        if (values.isEmpty()) return -1L;
        Collections.sort(values);
        int index = (int) Math.ceil(percentile * values.size()) - 1;
        index = Math.max(0, Math.min(index, values.size() - 1));
        return values.get(index);
    }

    private long percentileMicros(ArrayList<Long> values, double percentile) {
        long nanos = percentileNanos(values, percentile);
        return nanos < 0 ? -1L : nanos / 1000L;
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
        cancelL4StressProbe();
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
