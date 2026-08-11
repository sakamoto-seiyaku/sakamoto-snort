package com.sakamoto.snort.androidruntime;

import android.net.VpnService;
import android.util.Log;

import java.io.File;

/** Owns the product HEV transport peer for the VPN/TUN Adapter. */
public final class VpnHevTransportSession implements AutoCloseable {
    public static final String LIBRARY_NAME = "sakamoto_vpn_transport";
    public static final String TRANSPORT_NAME = "hev-socks5";
    public static final int DEFAULT_SOCKS_PORT = 41080;
    private static final String TAG = "SakamotoVpnHev";

    static {
        System.loadLibrary(LIBRARY_NAME);
    }

    private final VpnService service;
    private boolean closed;

    private VpnHevTransportSession(VpnService service) {
        this.service = service;
    }

    public static StartResult start(VpnService service, String nativeLibraryDir, File logDir) {
        if (service == null) {
            return StartResult.error("vpn_service_missing",
                    "VpnService instance is unavailable for HEV protect");
        }
        if (nativeLibraryDir == null || nativeLibraryDir.trim().isEmpty()) {
            return StartResult.error("vpn_hev_native_dir_missing",
                    "native library directory is unavailable");
        }
        if (logDir == null) {
            return StartResult.error("vpn_hev_log_dir_missing",
                    "HEV log directory is unavailable");
        }

        int[] fds = nativeCreateTransportSocketPair();
        if (fds == null || fds.length != 2 || fds[0] < 0 || fds[1] < 0) {
            closeIfOpen(fds, 0);
            closeIfOpen(fds, 1);
            return StartResult.error("vpn_hev_socketpair_failed",
                    "HEV transport socketpair could not be created");
        }
        int runtimeFd = fds[0];
        int hevFd = fds[1];

        RuntimeControlFdClient.AttachResult attach =
                RuntimeControlFdClient.attachVpnTransport(runtimeFd);
        runtimeFd = -1; // attachVpnTransport consumes the local descriptor.
        if (!attach.ok) {
            nativeCloseFd(hevFd);
            return StartResult.error(attach.errorCode.isEmpty()
                            ? "vpn_transport_attach_failed" : attach.errorCode,
                    attach.errorMessage.isEmpty()
                            ? "VPN transport fd attach failed" : attach.errorMessage);
        }
        if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(attach.adapter)
                || !attach.transportFdAttached) {
            nativeCloseFd(hevFd);
            return StartResult.error("vpn_transport_attach_invalid_result",
                    "VPN transport attach did not prove the HEV adapter handoff");
        }

        VpnHevTransportSession session = new VpnHevTransportSession(service);
        int rc = nativeStartHevTransport(hevFd, nativeLibraryDir, logDir.getPath(), session);
        hevFd = -1; // nativeStartHevTransport consumes the descriptor.
        if (rc != 0) {
            session.close();
            return StartResult.error("vpn_hev_start_failed",
                    "HEV transport start failed rc=" + rc);
        }
        return StartResult.ready(session);
    }

    @SuppressWarnings("unused")
    public boolean protectSocketForNative(int fd) {
        boolean protectedSocket = service.protect(fd);
        Log.i(TAG, "VpnService.protect fd=" + fd + " result=" + protectedSocket);
        return protectedSocket;
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        nativeStopHevTransport();
    }

    private static void closeIfOpen(int[] fds, int index) {
        if (fds != null && fds.length > index && fds[index] >= 0) {
            nativeCloseFd(fds[index]);
        }
    }

    private static native int[] nativeCreateTransportSocketPair();

    private static native int nativeStartHevTransport(int transportFd, String nativeLibraryDir,
                                                      String logDir,
                                                      VpnHevTransportSession owner);

    private static native void nativeStopHevTransport();

    private static native void nativeCloseFd(int fd);

    public static final class StartResult {
        public final boolean ok;
        public final VpnHevTransportSession session;
        public final String errorCode;
        public final String errorMessage;

        private StartResult(boolean ok, VpnHevTransportSession session, String errorCode,
                            String errorMessage) {
            this.ok = ok;
            this.session = session;
            this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.errorMessage = BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }

        static StartResult ready(VpnHevTransportSession session) {
            return new StartResult(true, session, "", "");
        }

        static StartResult error(String code, String message) {
            return new StartResult(false, null, code, message);
        }
    }
}
