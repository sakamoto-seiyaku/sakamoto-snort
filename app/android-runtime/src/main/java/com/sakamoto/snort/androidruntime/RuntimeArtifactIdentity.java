package com.sakamoto.snort.androidruntime;

import java.util.Properties;
import java.util.regex.Pattern;

/** Validated identity for the packaged core runtime and its generated VAPI. */
final class RuntimeArtifactIdentity {
    private static final Pattern ARTIFACT = Pattern.compile("sha256:[0-9a-fA-F]{64}");
    private static final Pattern API_IDENTITY = Pattern.compile("show_version_[0-9a-fA-F]{8}");

    final String protocol;
    final String version;
    final String abi;
    final String artifact;
    final String apiIdentity;

    private RuntimeArtifactIdentity(String protocol, String version, String abi,
                                    String artifact, String apiIdentity) {
        this.protocol = clean(protocol);
        this.version = clean(version);
        this.abi = clean(abi);
        this.artifact = clean(artifact);
        this.apiIdentity = clean(apiIdentity);
    }

    static RuntimeArtifactIdentity from(Properties values) {
        if (values == null) {
            return new RuntimeArtifactIdentity("", "", "", "", "");
        }
        return new RuntimeArtifactIdentity(values.getProperty("protocol", ""),
                values.getProperty("version", ""), values.getProperty("abi", ""),
                values.getProperty("artifact", ""), values.getProperty("apiIdentity", ""));
    }

    /** Empty means valid for this device; otherwise returns a stable error code. */
    String validationError(String deviceAbi) {
        if (!VppHealthHandshake.PROTOCOL.equals(protocol)) {
            return "runtime_manifest_invalid";
        }
        if (version.isEmpty() || abi.isEmpty() || artifact.isEmpty() || apiIdentity.isEmpty()) {
            return "runtime_manifest_invalid";
        }
        if (!ARTIFACT.matcher(artifact).matches()) {
            return "runtime_manifest_invalid";
        }
        if (!API_IDENTITY.matcher(apiIdentity).matches()) {
            return "runtime_manifest_invalid";
        }
        if (deviceAbi == null || !abi.equals(deviceAbi.trim())) {
            return "runtime_abi_mismatch";
        }
        return "";
    }

    String validationMessage(String deviceAbi) {
        String error = validationError(deviceAbi);
        if ("runtime_abi_mismatch".equals(error)) {
            return "manifest=" + abi + ",device=" + clean(deviceAbi);
        }
        return "protocol, version, abi, artifact and API identity are required and valid";
    }

    private static String clean(String value) {
        return value == null ? "" : value.trim();
    }
}
