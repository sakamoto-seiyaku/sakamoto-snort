package com.sakamoto.snort.vpnlite;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Versioned, narrow health contract between RuntimeService and packaged VPP. */
public final class VppHealthHandshake {
    public static final String PROTOCOL = "vpp-runtime-health/v1";
    private static final Pattern VERSION = Pattern.compile(
            "(?im)(?:^|\\s)(?:version:\\s*|vpp\\s+)(v[0-9][^\\s\\r\\n]*)");

    private VppHealthHandshake() {}

    public static Result parse(String manifestProtocol, String expectedVersion,
                               String manifestAbi, String deviceAbi, int cliExitCode,
                               String cliOutput) {
        String version = extractVersion(cliOutput);
        String protocol = clean(manifestProtocol);
        String abi = clean(manifestAbi);
        String actualDeviceAbi = clean(deviceAbi);
        String abiEvidence = "manifest-" + abi + ",device-" + actualDeviceAbi;
        boolean protocolMatches = PROTOCOL.equals(protocol);
        boolean versionMatches = expectedVersion != null && !expectedVersion.isEmpty()
                && expectedVersion.equals(version);
        boolean abiMatches = !abi.isEmpty() && abi.equals(actualDeviceAbi);
        boolean cliSucceeded = cliExitCode == 0;
        boolean outputPresent = cliOutput != null && !cliOutput.trim().isEmpty();
        String errorCode = "";
        if (!protocolMatches) {
            errorCode = "health_protocol_mismatch";
        } else if (!abiMatches) {
            errorCode = "health_abi_mismatch";
        } else if (!cliSucceeded) {
            errorCode = "health_vppctl_failed";
        } else if (!outputPresent || !versionMatches) {
            errorCode = "health_version_mismatch";
        }
        return new Result(protocol, version, abi, abiEvidence,
                errorCode.isEmpty() ? "ok" : "error", errorCode);
    }

    public static String extractVersion(String cliOutput) {
        if (cliOutput == null) {
            return "";
        }
        Matcher matcher = VERSION.matcher(cliOutput);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    public static final class Result {
        public final String protocol;
        public final String version;
        public final String abi;
        public final String abiEvidence;
        public final String health;
        public final String errorCode;

        Result(String protocol, String version, String abi, String abiEvidence,
               String health, String errorCode) {
            this.protocol = protocol;
            this.version = version;
            this.abi = abi;
            this.abiEvidence = abiEvidence;
            this.health = health;
            this.errorCode = errorCode;
        }

        public boolean isReady() {
            return "ok".equals(health);
        }
    }
}
