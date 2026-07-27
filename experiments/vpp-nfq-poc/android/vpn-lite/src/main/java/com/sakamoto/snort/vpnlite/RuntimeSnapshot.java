package com.sakamoto.snort.vpnlite;

/**
 * Product-facing projection of the Android runtime boundary.
 *
 * <p>The state names are deliberately part of the v1 product contract.  The
 * Activity can be destroyed and recreated without losing this projection
 * because the service persists it through {@link RuntimeStateStore}.</p>
 */
public final class RuntimeSnapshot {
    public static final int SCHEMA_VERSION = 1;

    public static final String STATE_STARTING = "starting";
    public static final String STATE_RUNNING = "running";
    public static final String STATE_STOPPED = "stopped";
    public static final String STATE_STARTUP_ERROR = "startup_error";

    public static final String PROFILE_ROOT = "root";
    public static final String PROFILE_VPN = "vpn";

    public final String state;
    public final String profile;
    public final String version;
    public final String abi;
    public final String health;
    public final String errorCode;
    public final String errorMessage;
    public final long pid;
    public final long updatedAtMillis;

    public RuntimeSnapshot(String state, String profile, String version, String abi,
                           String health, String errorCode, String errorMessage,
                           long pid, long updatedAtMillis) {
        this.state = requireState(state);
        this.profile = profile == null || profile.isEmpty() ? PROFILE_ROOT : profile;
        this.version = valueOrEmpty(version);
        this.abi = valueOrEmpty(abi);
        this.health = valueOrEmpty(health);
        this.errorCode = valueOrEmpty(errorCode);
        this.errorMessage = valueOrEmpty(errorMessage);
        this.pid = Math.max(-1L, pid);
        this.updatedAtMillis = Math.max(0L, updatedAtMillis);
    }

    public static RuntimeSnapshot stopped() {
        return new RuntimeSnapshot(STATE_STOPPED, PROFILE_ROOT, "", "", "unknown",
                "", "", -1L, System.currentTimeMillis());
    }

    public static RuntimeSnapshot starting(String profile, String version, String abi) {
        return new RuntimeSnapshot(STATE_STARTING, profile, version, abi, "checking",
                "", "", -1L, System.currentTimeMillis());
    }

    public static RuntimeSnapshot running(String profile, String version, String abi,
                                          String health, long pid) {
        return new RuntimeSnapshot(STATE_RUNNING, profile, version, abi, health, "", "", pid,
                System.currentTimeMillis());
    }

    public static RuntimeSnapshot startupError(String profile, String version, String abi,
                                               String errorCode, String errorMessage) {
        return new RuntimeSnapshot(STATE_STARTUP_ERROR, profile, version, abi, "error",
                errorCode, errorMessage, -1L, System.currentTimeMillis());
    }

    public boolean isActive() {
        return STATE_STARTING.equals(state) || STATE_RUNNING.equals(state);
    }

    public String displayText() {
        StringBuilder result = new StringBuilder();
        result.append("Runtime: ").append(state)
                .append("\nProfile: ").append(profile)
                .append("\nVersion: ").append(version.isEmpty() ? "unknown" : version)
                .append("\nABI: ").append(abi.isEmpty() ? "unknown" : abi)
                .append("\nHealth: ").append(health.isEmpty() ? "unknown" : health);
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
                || STATE_STOPPED.equals(value) || STATE_STARTUP_ERROR.equals(value)) {
            return value;
        }
        throw new IllegalArgumentException("unknown runtime state: " + value);
    }

    private static String valueOrEmpty(String value) {
        return value == null ? "" : value.trim();
    }
}
