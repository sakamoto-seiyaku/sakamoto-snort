package com.sakamoto.snort.vpnlite;

/**
 * Product-facing projection of the Android runtime boundary.
 *
 * <p>The state names are deliberately part of the v1 product contract.  The
 * Activity can be destroyed and recreated without losing this projection
 * because the service persists it through {@link RuntimeStateStore}.</p>
 */
public final class RuntimeSnapshot {
    public static final int SCHEMA_VERSION = 2;

    public static final String STATE_STARTING = "starting";
    public static final String STATE_RUNNING = "running";
    public static final String STATE_STOPPING = "stopping";
    public static final String STATE_STOPPED = "stopped";
    public static final String STATE_ERROR = "error";

    public static final String PROFILE_ROOT = "root";
    public static final String PROFILE_VPN = "vpn";

    public final String state;
    public final String profile;
    public final String protocol;
    public final String version;
    public final String abi;
    public final String abiEvidence;
    public final String health;
    public final String errorCode;
    public final String errorMessage;
    public final boolean mayBeActive;
    public final long pid;
    public final long updatedAtMillis;

    public RuntimeSnapshot(String state, String profile, String protocol, String version,
                           String abi, String abiEvidence, String health, String errorCode,
                           String errorMessage, boolean mayBeActive, long pid,
                           long updatedAtMillis) {
        this.state = requireState(state);
        this.profile = profile == null || profile.isEmpty() ? PROFILE_ROOT : profile;
        this.protocol = valueOrEmpty(protocol);
        this.version = valueOrEmpty(version);
        this.abi = valueOrEmpty(abi);
        this.abiEvidence = valueOrEmpty(abiEvidence);
        this.health = valueOrEmpty(health);
        this.errorCode = valueOrEmpty(errorCode);
        this.errorMessage = valueOrEmpty(errorMessage);
        this.mayBeActive = mayBeActive;
        this.pid = Math.max(-1L, pid);
        this.updatedAtMillis = Math.max(0L, updatedAtMillis);
    }

    public static RuntimeSnapshot stopped() {
        return new RuntimeSnapshot(STATE_STOPPED, PROFILE_ROOT, "", "", "", "",
                "unknown", "", "", false, -1L, System.currentTimeMillis());
    }

    public static RuntimeSnapshot starting(String profile, String protocol, String version,
                                           String abi, String abiEvidence) {
        return new RuntimeSnapshot(STATE_STARTING, profile, protocol, version, abi,
                abiEvidence, "checking", "", "", true, -1L, System.currentTimeMillis());
    }

    public static RuntimeSnapshot running(String profile, String protocol, String version,
                                          String abi, String abiEvidence, String health,
                                          long pid) {
        return new RuntimeSnapshot(STATE_RUNNING, profile, protocol, version, abi,
                abiEvidence, health, "", "", true, pid, System.currentTimeMillis());
    }

    public static RuntimeSnapshot stopping(RuntimeSnapshot current) {
        return new RuntimeSnapshot(STATE_STOPPING, current.profile, current.protocol,
                current.version, current.abi, current.abiEvidence, "stopping", "", "",
                true, current.pid, System.currentTimeMillis());
    }

    public static RuntimeSnapshot error(String profile, String protocol, String version,
                                        String abi, String abiEvidence, String errorCode,
                                        String errorMessage, boolean mayBeActive, long pid) {
        return new RuntimeSnapshot(STATE_ERROR, profile, protocol, version, abi,
                abiEvidence, "error", errorCode, errorMessage, mayBeActive, pid,
                System.currentTimeMillis());
    }

    public boolean isActive() {
        return STATE_STARTING.equals(state) || STATE_RUNNING.equals(state)
                || STATE_STOPPING.equals(state) || mayBeActive;
    }

    public String displayText() {
        StringBuilder result = new StringBuilder();
        result.append("Runtime: ").append(state)
                .append("\nProfile: ").append(profile)
                .append("\nProtocol: ").append(protocol.isEmpty() ? "unknown" : protocol)
                .append("\nVersion: ").append(version.isEmpty() ? "unknown" : version)
                .append("\nABI: ").append(abi.isEmpty() ? "unknown" : abi)
                .append("\nABI evidence: ")
                .append(abiEvidence.isEmpty() ? "unknown" : abiEvidence)
                .append("\nHealth: ").append(health.isEmpty() ? "unknown" : health);
        if (mayBeActive && STATE_ERROR.equals(state)) {
            result.append("\nRuntime may still be active");
        }
        if (!errorCode.isEmpty()) {
            result.append("\nError: ").append(errorCode);
            if (!errorMessage.isEmpty()) {
                result.append(" — ").append(errorMessage);
            }
        }
        return result.toString();
    }

    private static String requireState(String value) {
        if (STATE_STARTING.equals(value) || STATE_RUNNING.equals(value)
                || STATE_STOPPING.equals(value) || STATE_STOPPED.equals(value)
                || STATE_ERROR.equals(value)) {
            return value;
        }
        throw new IllegalArgumentException("unknown runtime state: " + value);
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
