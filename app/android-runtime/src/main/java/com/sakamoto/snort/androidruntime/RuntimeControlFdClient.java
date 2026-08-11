package com.sakamoto.snort.androidruntime;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.SystemClock;
import android.os.ParcelFileDescriptor;

import org.json.JSONException;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileDescriptor;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** vNext control client for product-owned SCM_RIGHTS packet-adapter fd handoff. */
public final class RuntimeControlFdClient {
    public static final String CONTROL_SOCKET_NAME = "sucre-snort-control-vnext";
    public static final String HELLO = "HELLO";
    public static final String VPN_TUN_ATTACH = "VPN_TUN.ATTACH";
    public static final String VPN_TRANSPORT_ATTACH = "VPN_TRANSPORT.ATTACH";
    private static final int CONTROL_SOCKET_TIMEOUT_MILLIS = 2500;
    private static final int CONTROL_MAX_PAYLOAD_BYTES = 1024 * 1024;

    private RuntimeControlFdClient() {}

    public static AttachResult waitForVpnTunHandoffReady() {
        LocalSocket socket = null;
        try {
            socket = connectControlSocket();
            OutputStream output = socket.getOutputStream();
            byte[] frame = frameNetstring(requestPayload(0, HELLO, new JSONObject()));
            output.write(frame);
            output.flush();
            JSONObject response = new JSONObject(
                    new String(readNetstring(socket.getInputStream()), StandardCharsets.UTF_8));
            if (!response.optBoolean("ok", false)) {
                JSONObject error = response.optJSONObject("error");
                return AttachResult.error(
                        error == null ? "VPN_TUN_CONTROL_READY_FAILED"
                                : error.optString("code", "VPN_TUN_CONTROL_READY_FAILED"),
                        error == null ? "" : error.optString("message", ""));
            }
            JSONObject result = response.optJSONObject("result");
            JSONArray capabilities = result == null
                    ? new JSONArray()
                    : result.optJSONArray("capabilities");
            if (!hasCapability(capabilities, "vpn-tun-fd-handoff")) {
                return AttachResult.error("VPN_TUN_HANDOFF_UNAVAILABLE",
                        "native runtime did not advertise VPN TUN fd handoff");
            }
            if (!hasCapability(capabilities, "vpn-tun-transport-fd-handoff")) {
                return AttachResult.error("VPN_TRANSPORT_HANDOFF_UNAVAILABLE",
                        "native runtime did not advertise VPN transport fd handoff");
            }
            return AttachResult.accepted(new JSONObject()
                    .put("adapter", ProductPacketAdapterContract.VPN_ADAPTER)
                    .put("fdAttached", false)
                    .put("transportFdAttached", false)
                    .put("ipv6Enabled", false));
        } catch (Exception error) {
            return AttachResult.error("VPN_TUN_CONTROL_READY_FAILED", messageOf(error));
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // The readiness result above is the actionable failure.
                }
            }
        }
    }

    /**
     * Consumes {@code rawFd}: the local descriptor is closed after the complete netstring frame is
     * written, while the native runtime receives an SCM_RIGHTS duplicate.
     */
    public static AttachResult attachVpnTun(int rawFd, boolean enableIpv6) {
        JSONObject args = new JSONObject();
        try {
            args.put("enableIpv6", enableIpv6);
        } catch (JSONException error) {
            return AttachResult.error("VPN_TUN_ATTACH_INVALID_ARGUMENT", messageOf(error));
        }
        return callWithFd(1, VPN_TUN_ATTACH, args, rawFd);
    }

    /**
     * Consumes {@code rawFd}: the local descriptor is closed after the complete netstring frame is
     * written, while the native runtime receives an SCM_RIGHTS duplicate.
     */
    public static AttachResult attachVpnTransport(int rawFd) {
        return callWithFd(2, VPN_TRANSPORT_ATTACH, new JSONObject(), rawFd);
    }

    private static AttachResult callWithFd(int id, String command, JSONObject args, int rawFd) {
        if (rawFd < 0) {
            return AttachResult.error(command + "_INVALID_FD", "raw fd is invalid");
        }
        ParcelFileDescriptor descriptor = null;
        LocalSocket socket = null;
        try {
            descriptor = ParcelFileDescriptor.adoptFd(rawFd);
            socket = connectControlSocket();
            FileDescriptor fd = descriptor.getFileDescriptor();
            socket.setFileDescriptorsForSend(new FileDescriptor[]{fd});
            OutputStream output = socket.getOutputStream();
            byte[] frame = frameNetstring(requestPayload(id, command, args));
            output.write(frame);
            output.flush();
            socket.setFileDescriptorsForSend(null);
            descriptor.close();
            descriptor = null;

            JSONObject response = new JSONObject(
                    new String(readNetstring(socket.getInputStream()), StandardCharsets.UTF_8));
            if (!response.optBoolean("ok", false)) {
                JSONObject error = response.optJSONObject("error");
                return AttachResult.error(
                        error == null ? "RPC_FAILED" : error.optString("code", "RPC_FAILED"),
                        error == null ? "" : error.optString("message", ""));
            }
            JSONObject result = response.optJSONObject("result");
            return AttachResult.accepted(result == null ? new JSONObject() : result);
        } catch (Exception error) {
            return AttachResult.error(command + "_FAILED", messageOf(error));
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // The attach result above is the actionable failure.
                }
            }
            if (descriptor != null) {
                try {
                    descriptor.close();
                } catch (IOException ignored) {
                    // The attach result above is the actionable failure.
                }
            }
        }
    }

    private static LocalSocket connectControlSocket() throws IOException {
        IOException lastError = null;
        long deadline = SystemClock.elapsedRealtime() + CONTROL_SOCKET_TIMEOUT_MILLIS;
        while (true) {
            LocalSocket socket = new LocalSocket();
            try {
                socket.connect(new LocalSocketAddress(
                        CONTROL_SOCKET_NAME, LocalSocketAddress.Namespace.ABSTRACT));
                socket.setSoTimeout(CONTROL_SOCKET_TIMEOUT_MILLIS);
                return socket;
            } catch (IOException error) {
                lastError = error;
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // The connect failure is the actionable error.
                }
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                throw lastError == null
                        ? new IOException("control socket connect timed out")
                        : lastError;
            }
            try {
                Thread.sleep(50L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                IOException interrupted =
                        new IOException("interrupted while connecting control socket");
                interrupted.initCause(error);
                throw interrupted;
            }
        }
    }

    private static byte[] requestPayload(int id, String command, JSONObject args)
            throws JSONException {
        return new JSONObject()
                .put("id", id)
                .put("cmd", command)
                .put("args", args)
                .toString()
                .getBytes(StandardCharsets.UTF_8);
    }

    private static byte[] frameNetstring(byte[] payload) throws IOException {
        ByteArrayOutputStream frame = new ByteArrayOutputStream(payload.length + 16);
        frame.write(Integer.toString(payload.length).getBytes(StandardCharsets.US_ASCII));
        frame.write(':');
        frame.write(payload);
        frame.write(',');
        return frame.toByteArray();
    }

    private static byte[] readNetstring(InputStream input) throws IOException {
        int length = readLength(input);
        byte[] payload = new byte[length];
        int offset = 0;
        while (offset < length) {
            int n = input.read(payload, offset, length - offset);
            if (n < 0) {
                throw new IOException("control socket closed while reading payload");
            }
            offset += n;
        }
        int comma = input.read();
        if (comma != ',') {
            throw new IOException("invalid netstring terminator");
        }
        return payload;
    }

    private static boolean hasCapability(JSONArray capabilities, String expected) {
        if (capabilities == null) {
            return false;
        }
        for (int index = 0; index < capabilities.length(); ++index) {
            if (expected.equals(capabilities.optString(index))) {
                return true;
            }
        }
        return false;
    }

    private static int readLength(InputStream input) throws IOException {
        int value = 0;
        int digits = 0;
        while (true) {
            int ch = input.read();
            if (ch < 0) {
                throw new IOException("control socket closed while reading length");
            }
            if (ch == ':') {
                if (digits == 0) {
                    throw new IOException("empty netstring length");
                }
                return value;
            }
            if (ch < '0' || ch > '9') {
                throw new IOException("invalid netstring length");
            }
            if (digits == 0 && ch == '0') {
                int next = input.read();
                if (next != ':') {
                    throw new IOException("invalid leading zero netstring length");
                }
                return 0;
            }
            value = value * 10 + (ch - '0');
            digits++;
            if (value > CONTROL_MAX_PAYLOAD_BYTES || digits > 8) {
                throw new IOException("netstring payload too large");
            }
        }
    }

    private static String messageOf(Exception error) {
        String message = error == null ? "" : error.getMessage();
        if (message == null || message.trim().isEmpty()) {
            message = error == null ? "unknown error" : error.getClass().getSimpleName();
        }
        return BoundedText.value(message, RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    public static final class AttachResult {
        public final boolean ok;
        public final String errorCode;
        public final String errorMessage;
        public final String adapter;
        public final boolean fdAttached;
        public final boolean transportFdAttached;
        public final boolean ipv6Enabled;

        private AttachResult(boolean ok, String errorCode, String errorMessage, String adapter,
                             boolean fdAttached, boolean transportFdAttached,
                             boolean ipv6Enabled) {
            this.ok = ok;
            this.errorCode = BoundedText.value(errorCode, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.errorMessage = BoundedText.value(errorMessage, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.adapter = BoundedText.value(adapter, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.fdAttached = fdAttached;
            this.transportFdAttached = transportFdAttached;
            this.ipv6Enabled = ipv6Enabled;
        }

        static AttachResult accepted(JSONObject result) {
            return new AttachResult(true, "", "", result.optString("adapter", ""),
                    result.optBoolean("fdAttached", false),
                    result.optBoolean("transportFdAttached", false),
                    result.optBoolean("ipv6Enabled", false));
        }

        static AttachResult error(String code, String message) {
            return new AttachResult(false, code, message, "", false, false, false);
        }
    }
}
