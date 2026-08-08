package com.sakamoto.snort.androidruntime;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Core VPP readiness contract; Adapter readiness is intentionally separate. */
public final class VppHealthHandshake {
    public static final String PROTOCOL = "vpp-runtime-health/v1";
    private static final Pattern VERSION = Pattern.compile(
            "(?im)(?:^|\\s)(?:version:\\s*|vpp\\s+)(v[0-9][^\\s\\r\\n]*)");
    private static final Pattern ARTIFACT = Pattern.compile(
            "(?im)^artifact:\\s*([^\\s\\r\\n]+)\\s*$");

    private VppHealthHandshake() {}

    /** Evaluate a real native generated-VAPI response for the core runtime. */
    public static Result evaluate(RuntimeProfile profile, String manifestProtocol,
                                  String expectedVersion, String expectedAbi,
                                  String expectedArtifact, String expectedApiIdentity,
                                  RuntimeControlNative.Status status) {
        String protocol = clean(manifestProtocol);
        String expected = clean(expectedVersion);
        String artifact = clean(expectedArtifact);
        String apiIdentity = clean(expectedApiIdentity);
        String errorCode = "";
        if (profile == null) {
            errorCode = "health_profile_missing";
        } else if (!PROTOCOL.equals(protocol)) {
            errorCode = "health_protocol_mismatch";
        } else if (expected.isEmpty() || status == null || !sameVersion(expected, status.version)) {
            errorCode = "health_version_mismatch";
        } else if (status.controlAbiVersion != RuntimeControlNative.CONTROL_ABI_VERSION) {
            errorCode = "health_control_abi_mismatch";
        } else if (status.transportCode != 0 || status.vppRetval != 0) {
            errorCode = "health_vapi_failed";
        } else if (!apiIdentity.isEmpty() && !apiIdentity.equals(status.apiIdentity)) {
            errorCode = "health_api_identity_mismatch";
        } else if (!"vpp".equalsIgnoreCase(status.program)
                && !"vpe".equalsIgnoreCase(status.program)) {
            errorCode = "health_program_mismatch";
        }
        return new Result(protocol, status == null ? "" : status.version, artifact,
                clean(expectedAbi),
                errorCode.isEmpty() ? "ok" : "error", errorCode);
    }

    /**
     * Migration-only parser for old host evidence. It verifies core fields
     * and never promotes a plugin line into Adapter readiness.
     */
    public static Result parse(RuntimeProfile profile, String manifestProtocol,
                               String expectedVersion, String deviceAbi,
                               String expectedArtifact, int cliExitCode, String cliOutput) {
        String output = bounded(cliOutput);
        String protocol = clean(manifestProtocol);
        String version = extractVersion(output);
        String artifact = extractArtifact(output);
        String abi = clean(deviceAbi);
        String expected = clean(expectedArtifact);
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
        }
        return new Result(protocol, version, artifact, abi,
                errorCode.isEmpty() ? "ok" : "error", errorCode);
    }

    /** Compatibility overload for migration callers with no profile. */
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
        return new Result(protocol, version, "", actualAbi,
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

    private static String bounded(String value) {
        return value == null ? "" : value.length() <= 64 * 1024
                ? value : value.substring(0, 64 * 1024);
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }

    private static boolean sameVersion(String expected, String actual) {
        String left = clean(expected);
        String right = clean(actual);
        return left.equals(right)
                || (left.startsWith("v") && left.substring(1).equals(right))
                || (right.startsWith("v") && right.substring(1).equals(left));
    }

    public static final class Result {
        public final String protocol;
        public final String version;
        public final String artifact;
        public final String abi;
        public final String health;
        public final String errorCode;

        Result(String protocol, String version, String artifact, String abi, String health,
               String errorCode) {
            this.protocol = protocol;
            this.version = version;
            this.artifact = artifact;
            this.abi = abi;
            this.health = health;
            this.errorCode = errorCode;
        }

        public boolean isReady() {
            return "ok".equals(health);
        }
    }
}
