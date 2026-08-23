package com.sakamoto.snort.vpnlite;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/**
 * POC-only durable proof of one VpnService builder session.
 *
 * <p>This writer is deliberately outside the native packet path.  A success
 * receipt is published only after the allowed-application calls, VPN
 * establishment, and TUN-fd detach have all succeeded.  Startup failures
 * therefore leave no success receipt (and cannot turn a stale receipt into a
 * new session claim).</p>
 */
final class VpnSessionProvenance {
    static final String SCHEMA = "vpn-session-provenance/v1";
    static final String RECEIPT_NAME = "vpn-session-provenance.json";
    static final String RECEIPT_TEMP_NAME = "vpn-session-provenance.json.tmp";
    static final String FAILURE_RECEIPT_NAME = "vpn-session-provenance-failure.json";

    private static final String LOG_DIRECTORY = "logs";

    private VpnSessionProvenance() {}

    static File receiptFile(File filesDir) {
        return new File(new File(filesDir, LOG_DIRECTORY), RECEIPT_NAME);
    }

    /**
     * Remove prior session receipts before a new session is attempted.
     *
     * @return {@code false} when any prior receipt/temp file could not be
     *         removed; callers must abort in that case so stale success data
     *         can never be attributed to the new session.
     */
    static boolean clear(File filesDir) {
        File receipt = receiptFile(filesDir);
        File temporary = new File(receipt.getParentFile(), RECEIPT_TEMP_NAME);
        File failure = new File(receipt.getParentFile(), FAILURE_RECEIPT_NAME);
        File failureTemporary = new File(receipt.getParentFile(),
                FAILURE_RECEIPT_NAME + ".tmp");
        boolean cleared = true;
        if (receipt.exists() && !receipt.delete()) {
            cleared = false;
        }
        if (temporary.exists() && !temporary.delete()) {
            cleared = false;
        }
        if (failure.exists() && !failure.delete()) {
            cleared = false;
        }
        if (failureTemporary.exists() && !failureTemporary.delete()) {
            cleared = false;
        }
        return cleared;
    }

    static String configDigest(String mode, int mtu, List<String> allowedPackages,
                               String disallowedPackage, List<String> ipv4Addresses,
                               List<String> ipv4Routes, List<String> ipv6Addresses,
                               List<String> ipv6Routes) throws Exception {
        StringBuilder canonical = new StringBuilder(512);
        appendCanonical(canonical, "mode", mode);
        appendCanonical(canonical, "mtu", Integer.toString(mtu));
        appendCanonicalList(canonical, "allowedPackages", allowedPackages);
        appendCanonical(canonical, "disallowedPackage", disallowedPackage);
        appendCanonicalList(canonical, "ipv4Addresses", ipv4Addresses);
        appendCanonicalList(canonical, "ipv4Routes", ipv4Routes);
        appendCanonicalList(canonical, "ipv6Addresses", ipv6Addresses);
        appendCanonicalList(canonical, "ipv6Routes", ipv6Routes);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] bytes = digest.digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format(java.util.Locale.US, "%02x", value & 0xff));
        }
        return hex.toString();
    }

    static boolean writeSuccess(File filesDir, String mode, List<String> allowedPackages,
                                List<Integer> allowedUids, List<String> ipv4Addresses,
                                List<String> ipv4Routes, List<String> ipv6Addresses,
                                List<String> ipv6Routes, String normalizedDisallowedPackage,
                                String configDigest,
                                long monotonicStartNs, long monotonicEstablishedNs,
                                String vpnLitePackage, int vpnLiteProcessUid, int vpnLitePid,
                                int mtu) {
        if (mode == null || normalizedDisallowedPackage == null
                || configDigest == null || configDigest.isEmpty()
                || monotonicEstablishedNs < monotonicStartNs
                || vpnLitePackage == null || vpnLitePackage.isEmpty()
                || vpnLiteProcessUid < 0 || vpnLitePid < 0) {
            return false;
        }
        StringBuilder json = new StringBuilder(1536);
        json.append("{\n")
                .append("  \"schema\":\"").append(escape(SCHEMA)).append("\",\n")
                .append("  \"receiptType\":\"success\",\n")
                .append("  \"sessionId\":\"")
                .append(Long.toUnsignedString(monotonicStartNs)).append("\",\n")
                .append("  \"mode\":\"").append(escape(mode)).append("\",\n")
                .append("  \"normalizedDisallowedPackage\":\"")
                .append(escape(normalizedDisallowedPackage)).append("\",\n")
                .append("  \"normalizedAllowedPackages\":");
        appendStringArray(json, allowedPackages);
        json.append(",\n  \"resolvedAllowedUids\":");
        appendIntArray(json, allowedUids);
        json.append(",\n  \"builderSuccess\":true")
                .append(",\n  \"addAllowedApplicationSuccess\":true")
                .append(",\n  \"establishSuccess\":true")
                .append(",\n  \"tunFdDetached\":true")
                .append(",\n  \"mtu\":").append(mtu)
                .append(",\n  \"addressRouteProfile\":{\n")
                .append("    \"ipv4\":{\"addresses\":");
        appendStringArray(json, ipv4Addresses);
        json.append(",\"routes\":");
        appendStringArray(json, ipv4Routes);
        json.append("},\n    \"ipv6\":{\"addresses\":");
        appendStringArray(json, ipv6Addresses);
        json.append(",\"routes\":");
        appendStringArray(json, ipv6Routes);
        json.append("}\n  },\n")
                .append("  \"configDigest\":\"").append(escape(configDigest)).append("\",\n")
                .append("  \"monotonicStartNs\":").append(monotonicStartNs).append(",\n")
                .append("  \"monotonicEstablishedNs\":").append(monotonicEstablishedNs)
                .append(",\n  \"elapsedMonotonicNs\":")
                .append(monotonicEstablishedNs - monotonicStartNs).append(",\n")
                .append("  \"wallClockEpochMs\":").append(System.currentTimeMillis())
                .append(",\n  \"vpnLitePackage\":\"")
                .append(escape(vpnLitePackage)).append("\",\n")
                .append("  \"vpnLiteProcessUid\":").append(vpnLiteProcessUid).append(",\n")
                .append("  \"vpnLitePid\":").append(vpnLitePid).append(",\n")
                .append("  \"failureReason\":\"\"\n")
                .append("}\n");
        return publish(receiptFile(filesDir), json.toString());
    }

    /**
     * Preserve an explicit non-success startup outcome without writing it to
     * the success receipt path.  The runner may copy this file for diagnosis;
     * the verifier never treats it as A2-0 provenance.
     */
    static boolean writeFailure(File filesDir, String mode, boolean builderSuccess,
                                boolean addAllowedApplicationSuccess,
                                boolean establishSuccess, String reason,
                                long monotonicStartNs, String vpnLitePackage,
                                int vpnLiteProcessUid, int vpnLitePid) {
        File failure = new File(receiptFile(filesDir).getParentFile(),
                FAILURE_RECEIPT_NAME);
        StringBuilder json = new StringBuilder(768);
        json.append("{\n")
                .append("  \"schema\":\"").append(escape(SCHEMA)).append("\",\n")
                .append("  \"receiptType\":\"failure\",\n")
                .append("  \"mode\":\"").append(escape(mode)).append("\",\n")
                .append("  \"builderSuccess\":").append(builderSuccess).append(",\n")
                .append("  \"addAllowedApplicationSuccess\":")
                .append(addAllowedApplicationSuccess)
                .append(",\n  \"establishSuccess\":").append(establishSuccess)
                .append(",\n  \"monotonicStartNs\":").append(monotonicStartNs).append(",\n")
                .append("  \"vpnLitePackage\":\"").append(escape(vpnLitePackage))
                .append("\",\n  \"vpnLiteProcessUid\":").append(vpnLiteProcessUid)
                .append(",\n  \"vpnLitePid\":").append(vpnLitePid)
                .append(",\n  \"failureReason\":\"").append(escape(reason))
                .append("\"\n}\n");
        return publish(failure, json.toString());
    }

    private static boolean publish(File target, String text) {
        File parent = target.getParentFile();
        if (parent != null && !parent.isDirectory() && !parent.mkdirs()
                && !parent.isDirectory()) {
            return false;
        }
        File temporary = new File(parent, target.getName() + ".tmp");
        try (FileOutputStream output = new FileOutputStream(temporary, false)) {
            output.write(text.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (IOException error) {
            return false;
        }
        if (temporary.renameTo(target)) {
            return true;
        }
        if (target.exists() && !target.delete()) {
            temporary.delete();
            return false;
        }
        boolean renamed = temporary.renameTo(target);
        if (!renamed) {
            temporary.delete();
        }
        return renamed;
    }

    private static void appendCanonical(StringBuilder out, String key, String value) {
        out.append(key).append('=').append(value == null ? "" : value).append('\n');
    }

    private static void appendCanonicalList(StringBuilder out, String key, List<String> values) {
        out.append(key).append('=');
        if (values != null) {
            for (int index = 0; index < values.size(); index++) {
                if (index > 0) out.append(',');
                out.append(values.get(index) == null ? "" : values.get(index));
            }
        }
        out.append('\n');
    }

    private static void appendStringArray(StringBuilder out, List<String> values) {
        out.append('[');
        if (values != null) {
            for (int index = 0; index < values.size(); index++) {
                if (index > 0) out.append(',');
                out.append('"').append(escape(values.get(index))).append('"');
            }
        }
        out.append(']');
    }

    private static void appendIntArray(StringBuilder out, List<Integer> values) {
        out.append('[');
        if (values != null) {
            for (int index = 0; index < values.size(); index++) {
                if (index > 0) out.append(',');
                out.append(values.get(index) == null ? -1 : values.get(index));
            }
        }
        out.append(']');
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }
}
