package com.sakamoto.snort.androidruntime;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runtime readiness contract. A VPP process is not product-ready until its
 * version, measured artifact identity, and selected profile adapter all agree.
 */
public final class VppHealthHandshake {
    public static final String PROTOCOL = "vpp-runtime-health/v1";
    private static final Pattern VERSION = Pattern.compile(
            "(?im)(?:^|\\s)(?:version:\\s*|vpp\\s+)(v[0-9][^\\s\\r\\n]*)");
    private static final Pattern ARTIFACT = Pattern.compile(
            "(?im)^artifact:\\s*([^\\s\\r\\n]+)\\s*$");

    private VppHealthHandshake() {}

    public static Result parse(RuntimeProfile profile, String manifestProtocol,
                               String expectedVersion, String deviceAbi,
                               String expectedArtifact, int cliExitCode, String cliOutput) {
        String output = bounded(cliOutput);
        String protocol = clean(manifestProtocol);
        String version = extractVersion(output);
        String artifact = extractArtifact(output);
        String abi = clean(deviceAbi);
        String expected = clean(expectedArtifact);
        String adapter = profile == null ? "" : profile.adapter;
        String errorCode = "";
        if (profile == null) {
            errorCode = "health_profile_missing";
        } else if (!PROTOCOL.equals(protocol)) {
            errorCode = "health_protocol_mismatch";
        } else if (expectedVersion == null || expectedVersion.trim().isEmpty()
                || !expectedVersion.trim().equals(version)) {
            errorCode = "health_version_mismatch";
        } else if (expected.isEmpty() || !expected.equals(artifact)) {
            errorCode = "health_artifact_mismatch";
        } else if (cliExitCode != 0) {
            errorCode = "health_vppctl_failed";
        } else if (!containsAdapterReady(profile, output)) {
            errorCode = "health_adapter_not_ready";
        }
        return new Result(protocol, version, artifact, abi, adapter,
                errorCode.isEmpty() ? "ok" : "error", errorCode);
    }

    /** Compatibility overload for host callers that only have a root adapter. */
    public static Result parse(String manifestProtocol, String expectedVersion,
                               String manifestAbi, String deviceAbi, int cliExitCode,
                               String cliOutput) {
        String protocol = clean(manifestProtocol);
        String version = extractVersion(cliOutput);
        String expected = clean(expectedVersion);
        String abi = clean(manifestAbi);
        String actualAbi = clean(deviceAbi);
        String errorCode = "";
        if (!PROTOCOL.equals(protocol)) {
            errorCode = "health_protocol_mismatch";
        } else if (!abi.equals(actualAbi)) {
            errorCode = "health_abi_mismatch";
        } else if (cliExitCode != 0) {
            errorCode = "health_vppctl_failed";
        } else if (!expected.equals(version)) {
            errorCode = "health_version_mismatch";
        }
        return new Result(protocol, version, "", actualAbi, RuntimeProfile.ROOT.adapter,
                errorCode.isEmpty() ? "ok" : "error", errorCode);
    }

    public static String extractVersion(String cliOutput) {
        if (cliOutput == null) {
            return "";
        }
        Matcher matcher = VERSION.matcher(cliOutput);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    public static String extractArtifact(String cliOutput) {
        if (cliOutput == null) {
            return "";
        }
        Matcher matcher = ARTIFACT.matcher(cliOutput);
        return matcher.find() ? matcher.group(1).trim() : "";
    }

    private static boolean containsAdapterReady(RuntimeProfile profile, String output) {
        String lower = output.toLowerCase(Locale.US);
        return lower.contains(profile.adapter + " adapter ready")
                || lower.contains("adapter=" + profile.adapter + ":ready")
                || lower.contains("adapter: " + profile.adapter + " ready");
    }

    private static String bounded(String value) {
        return value == null ? "" : value.length() <= 64 * 1024
                ? value : value.substring(0, 64 * 1024);
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    public static final class Result {
        public final String protocol;
        public final String version;
        public final String artifact;
        public final String abi;
        public final String adapter;
        public final String health;
        public final String errorCode;

        Result(String protocol, String version, String artifact, String abi, String adapter,
               String health, String errorCode) {
            this.protocol = protocol;
            this.version = version;
            this.artifact = artifact;
            this.abi = abi;
            this.adapter = adapter;
            this.health = health;
            this.errorCode = errorCode;
        }

        public boolean isReady() {
            return "ok".equals(health);
        }
    }
}
