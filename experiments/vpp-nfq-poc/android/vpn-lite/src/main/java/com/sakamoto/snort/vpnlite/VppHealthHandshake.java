package com.sakamoto.snort.vpnlite;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Versioned, narrow health contract between RuntimeService and packaged VPP. */
public final class VppHealthHandshake {
    public static final String PROTOCOL = "vpp-runtime-health/v1";
    private static final Pattern VERSION = Pattern.compile(
            "(?im)(?:^|\\s)(?:version:\\s*|vpp\\s+)(v[0-9][^\\s\\r\\n]*)");

    private VppHealthHandshake() {}

    public static Result parse(String cliOutput, String expectedVersion, String expectedAbi) {
        String version = extractVersion(cliOutput);
        String abi = expectedAbi == null ? "" : expectedAbi.trim();
        boolean versionMatches = expectedVersion != null && !expectedVersion.isEmpty()
                && expectedVersion.equals(version);
        boolean abiMatches = "arm64-v8a".equals(abi);
        boolean outputPresent = cliOutput != null && !cliOutput.trim().isEmpty();
        return new Result(PROTOCOL, version, abi,
                versionMatches && abiMatches && outputPresent ? "ok" : "error");
    }

    public static String extractVersion(String cliOutput) {
        if (cliOutput == null) {
            return "";
        }
        Matcher matcher = VERSION.matcher(cliOutput);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    public static final class Result {
        public final String protocol;
        public final String version;
        public final String abi;
        public final String health;

        Result(String protocol, String version, String abi, String health) {
            this.protocol = protocol;
            this.version = version;
            this.abi = abi;
            this.health = health;
        }

        public boolean isReady() {
            return "ok".equals(health);
        }
    }
}
