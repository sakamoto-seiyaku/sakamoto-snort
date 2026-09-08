package com.sakamoto.snort.androidruntime;

import android.net.VpnService;
import android.os.ParcelFileDescriptor;

import java.io.IOException;

/**
 * Owns the Android VpnService TUN fd establishment seam for the product VPN Adapter.
 *
 * <p>This module is deliberately only the platform session: it does not start VPP,
 * does not run HEV, and does not evaluate policy. A later VPN Adapter runtime takes
 * ownership through {@link #releaseFd()} after the shared native Adapter is ready.</p>
 */
public final class VpnTunPlatformSession implements AutoCloseable {
    public static final String ADAPTER_NAME = ProductPacketAdapterContract.VPN_ADAPTER;
    public static final String IPV4_ADDRESS = "10.111.0.2";
    public static final String IPV6_ADDRESS = "fd00:111:111::2";
    public static final int MTU = 1500;

    private int rawFd;
    public final boolean ipv6Enabled;

    private VpnTunPlatformSession(int rawFd, boolean ipv6Enabled) {
        this.rawFd = rawFd;
        this.ipv6Enabled = ipv6Enabled;
    }

    public static EstablishResult establish(VpnService service, boolean enableIpv6) {
        return establish(service, enableIpv6, false);
    }

    static EstablishResult establish(VpnService service, boolean enableIpv6, boolean graphValidation) {
        if (service == null) {
            return EstablishResult.error("vpn_service_missing",
                    "VpnService instance is unavailable");
        }

        ParcelFileDescriptor descriptor = null;
        try {
            VpnService.Builder builder = service.new Builder()
                    .setSession("Sakamoto VPN")
                    .setMtu(MTU)
                    .addAddress(IPV4_ADDRESS, 32)
                    .addRoute("0.0.0.0", 0);
            if (graphValidation) {
                builder.addAllowedApplication(service.getPackageName());
            }
            if (enableIpv6) {
                builder = builder.addAddress(IPV6_ADDRESS, 128)
                        .addRoute("::", 0);
            }
            descriptor = builder.establish();
            if (descriptor == null) {
                return EstablishResult.error("vpn_establish_returned_null",
                        "VpnService.Builder.establish returned null");
            }
            int fd = descriptor.detachFd();
            descriptor = null;
            return EstablishResult.ready(new VpnTunPlatformSession(fd, enableIpv6));
        } catch (Exception error) {
            return EstablishResult.error("vpn_establish_failed", messageOf(error));
        } finally {
            if (descriptor != null) {
                try {
                    descriptor.close();
                } catch (IOException ignored) {
                    // The returned error already records the establishment failure.
                }
            }
        }
    }

    public synchronized int releaseFd() {
        int fd = rawFd;
        rawFd = -1;
        return fd;
    }

    public synchronized int fdNumber() {
        return rawFd;
    }

    public synchronized String procFdPathForCurrentProcess() {
        if (rawFd < 0) {
            return "";
        }
        return "/proc/" + android.os.Process.myPid() + "/fd/" + rawFd;
    }

    public synchronized boolean isOpen() {
        return rawFd >= 0;
    }

    @Override
    public synchronized void close() throws IOException {
        if (rawFd < 0) {
            return;
        }
        try (ParcelFileDescriptor descriptor = ParcelFileDescriptor.adoptFd(rawFd)) {
            rawFd = -1;
        }
    }

    private static String messageOf(Exception error) {
        String message = error == null ? "" : error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            message = error == null ? "unknown error" : error.getClass().getSimpleName();
        }
        return BoundedText.value(message, RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    public static final class EstablishResult {
        public final boolean ok;
        public final VpnTunPlatformSession session;
        public final String errorCode;
        public final String errorMessage;

        private EstablishResult(boolean ok, VpnTunPlatformSession session,
                                String errorCode, String errorMessage) {
            this.ok = ok;
            this.session = session;
            this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.errorMessage = BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }

        static EstablishResult ready(VpnTunPlatformSession session) {
            return new EstablishResult(true, session, "", "");
        }

        static EstablishResult error(String code, String message) {
            return new EstablishResult(false, null, code, message);
        }
    }
}
