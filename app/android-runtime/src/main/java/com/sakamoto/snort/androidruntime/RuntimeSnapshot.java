package com.sakamoto.snort.androidruntime;

import java.util.LinkedHashMap;
import java.util.Map;

/** Bounded product-facing projection of one supervised VPP core runtime. */
public final class RuntimeSnapshot {
    public static final int SCHEMA_VERSION = 2;
    public static final int MAX_TEXT_LENGTH = BoundedText.MAX_LENGTH;

    public static final String STATE_STARTING = "starting";
    public static final String STATE_RUNNING = "running";
    public static final String STATE_STOPPING = "stopping";
    public static final String STATE_STOPPED = "stopped";
    public static final String STATE_ERROR = "error";
    public static final String PROFILE_ROOT = "root";
    public static final String PROFILE_VPN = "vpn";

    /** SAKAMOTO-67 does not own a packet Adapter yet. */
    public static final String ADAPTER_UNAVAILABLE = "unavailable";
    public static final String ADAPTER_NOT_READY = "not_ready";

    public final String state;
    public final RuntimeProfile profile;
    public final String protocol;
    public final String version;
    public final String artifact;
    /** Legacy name for the artifact identity while callers migrate. */
    public final String abiEvidence;
    public final String abi;
    /** Health proved by the core VPP control handshake. */
    public final String coreHealth;
    /** Explicit bounded Adapter state; never inferred from plugin presence. */
    public final String adapterReadiness;
    /** Compatibility aliases; values always mirror the separated fields. */
    @Deprecated public final String adapter;
    @Deprecated public final String health;
    public final String errorCode;
    public final String errorMessage;
    public final boolean mayBeActive;
    public final long pid;
    public final long generation;
    public final long updatedAtMillis;

    public RuntimeSnapshot(String state, RuntimeProfile profile, String protocol, String version,
                           String artifact, String abi, String adapter, String health,
                           String errorCode, String errorMessage, boolean mayBeActive, long pid,
                           long generation, long updatedAtMillis) {
        this.state = requireState(state);
        this.profile = profile == null ? RuntimeProfile.ROOT : profile;
        this.protocol = text(protocol);
        this.version = text(version);
        this.artifact = text(artifact);
        this.abiEvidence = this.artifact;
        this.abi = text(abi);
        this.coreHealth = text(health);
        // Adapter readiness is deliberately not an input to this projection.
        // In particular, plugin names from migration experiments can never
        // become product state by being passed to a constructor.
        this.adapterReadiness = ADAPTER_UNAVAILABLE;
        this.adapter = this.adapterReadiness;
        this.health = this.coreHealth;
        this.errorCode = text(errorCode);
        this.errorMessage = text(errorMessage);
        this.mayBeActive = mayBeActive;
        this.pid = Math.max(-1L, pid);
        this.generation = Math.max(0L, generation);
        this.updatedAtMillis = Math.max(0L, updatedAtMillis);
    }

    public RuntimeSnapshot(String state, String profile, String protocol, String version,
                           String artifact, String adapter, String health, String errorCode,
                           String errorMessage, boolean mayBeActive, long pid, long generation,
                           long updatedAtMillis) {
        this(state, RuntimeProfile.parse(profile), protocol, version, artifact, "", adapter,
                health, errorCode, errorMessage, mayBeActive, pid, generation, updatedAtMillis);
    }

    public static RuntimeSnapshot stopped() {
        return stopped(RuntimeProfile.ROOT, 0L);
    }

    public static RuntimeSnapshot stopped(RuntimeProfile profile, long generation) {
        return new RuntimeSnapshot(STATE_STOPPED, profile, "", "", "", "", "",
                "unknown", "", "", false, -1L, generation, System.currentTimeMillis());
    }

    /** Terminal projection after cleanup, retaining the most recent failure. */
    public static RuntimeSnapshot stoppedAfter(RuntimeSnapshot previous) {
        if (previous == null || previous.errorCode.isEmpty()) {
            return previous == null ? stopped() : stopped(previous.profile, previous.generation);
        }
        return new RuntimeSnapshot(STATE_STOPPED, previous.profile, previous.protocol,
                previous.version, previous.artifact, previous.abi, "", "unknown",
                previous.errorCode, previous.errorMessage, false, -1L, previous.generation,
                System.currentTimeMillis());
    }

    public static RuntimeSnapshot starting(RuntimeProfile profile, String protocol,
                                           String version, String artifact, long generation) {
        return new RuntimeSnapshot(STATE_STARTING, profile, protocol, version, artifact, "",
                "", "checking", "", "", true, -1L, generation,
                System.currentTimeMillis());
    }

    public static RuntimeSnapshot starting(String profile, String protocol, String version,
                                           String abi, String abiEvidence) {
        return starting(RuntimeProfile.parse(profile), protocol, version, abiEvidence, 0L)
                .withAbi(abi);
    }

    public static RuntimeSnapshot running(RuntimeProfile profile, String protocol, String version,
                                          String artifact, String abi, String adapter,
                                          String health, long pid) {
        return running(profile, protocol, version, artifact, abi, adapter, health, pid, 0L);
    }

    public static RuntimeSnapshot running(String profile, String protocol, String version,
                                          String abi, String abiEvidence, String health,
                                          long pid) {
        return running(RuntimeProfile.parse(profile), protocol, version, abiEvidence, abi,
                "", health, pid);
    }

    public static RuntimeSnapshot running(RuntimeProfile profile, String protocol, String version,
                                          String artifact, String abi, String adapter,
                                          String health, long pid, long generation) {
        return new RuntimeSnapshot(STATE_RUNNING, profile, protocol, version, artifact, abi,
                "", health, "", "", true, pid, generation, System.currentTimeMillis());
    }

    public static RuntimeSnapshot stopping(RuntimeSnapshot current) {
        return new RuntimeSnapshot(STATE_STOPPING, current.profile, current.protocol,
                current.version, current.artifact, current.abi, "", "stopping", "", "", true,
                current.pid, current.generation, System.currentTimeMillis());
    }

    public static RuntimeSnapshot error(RuntimeProfile profile, String protocol, String version,
                                        String artifact, String abi, String adapter,
                                        String errorCode, String errorMessage, boolean mayBeActive,
                                        long pid) {
        return error(profile, protocol, version, artifact, abi, adapter, errorCode, errorMessage,
                mayBeActive, pid, 0L);
    }

    public static RuntimeSnapshot error(String profile, String protocol, String version,
                                        String abi, String abiEvidence, String errorCode,
                                        String errorMessage, boolean mayBeActive, long pid) {
        RuntimeProfile parsed = RuntimeProfile.parse(profile);
        return error(parsed, protocol, version, abiEvidence, abi, "", errorCode,
                errorMessage, mayBeActive, pid);
    }

    public static RuntimeSnapshot error(RuntimeProfile profile, String protocol, String version,
                                        String artifact, String abi, String adapter,
                                        String errorCode, String errorMessage, boolean mayBeActive,
                                        long pid, long generation) {
        return new RuntimeSnapshot(STATE_ERROR, profile, protocol, version, artifact, abi, "",
                "error", errorCode, errorMessage, mayBeActive, pid, generation,
                System.currentTimeMillis());
    }

    public boolean isActive() {
        return mayBeActive || STATE_STARTING.equals(state) || STATE_RUNNING.equals(state)
                || STATE_STOPPING.equals(state);
    }

    public Map<String, String> encode() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("schemaVersion", Integer.toString(SCHEMA_VERSION));
        values.put("state", state);
        values.put("profile", profile.wireName);
        values.put("protocol", protocol);
        values.put("version", version);
        values.put("artifact", artifact);
        values.put("abiEvidence", artifact);
        values.put("abi", abi);
        values.put("coreHealth", coreHealth);
        values.put("adapterReadiness", adapterReadiness);
        // Keep migration aliases in the wire projection for old readers.
        values.put("adapter", adapterReadiness);
        values.put("health", coreHealth);
        values.put("errorCode", errorCode);
        values.put("errorMessage", errorMessage);
        values.put("mayBeActive", Boolean.toString(mayBeActive));
        values.put("pid", Long.toString(pid));
        values.put("generation", Long.toString(generation));
        values.put("updatedAtMillis", Long.toString(updatedAtMillis));
        return values;
    }

    public String displayText() {
        StringBuilder result = new StringBuilder();
        result.append("Runtime: ").append(state)
                .append("\nProfile: ").append(profile.displayName)
                .append("\nCore health: ").append(coreHealth.isEmpty() ? "unknown" : coreHealth)
                .append("\nAdapter: ").append(adapterReadiness)
                .append("\nVersion: ").append(version.isEmpty() ? "unknown" : version)
                .append("\nABI: ").append(abi.isEmpty() ? "unknown" : abi)
                .append("\nArtifact: ").append(artifact.isEmpty() ? "unknown" : artifact);
        if (!errorCode.isEmpty()) {
            result.append("\nError: ").append(errorCode);
            if (!errorMessage.isEmpty()) {
                result.append(" — ").append(errorMessage);
            }
        }
        if (mayBeActive && STATE_ERROR.equals(state)) {
            result.append("\nRuntime may still be active; cleanup is pending");
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

    private static String text(String value) {
        return BoundedText.value(value, BoundedText.MAX_LENGTH);
    }

    private RuntimeSnapshot withAbi(String value) {
        return new RuntimeSnapshot(state, profile, protocol, version, artifact, value, "",
                coreHealth, errorCode, errorMessage, mayBeActive, pid, generation,
                updatedAtMillis);
    }
}
