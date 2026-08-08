package com.sakamoto.snort.androidruntime;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Product-control request at the Activity/RuntimeService boundary.
 *
 * <p>The wire shape is deliberately small and deterministic. Android Intents
 * carry the same fields, while this representation keeps host contract tests
 * independent of the Android SDK.</p>
 */
public final class RuntimeControlRequest {
    public static final String START = RuntimeControlProtocol.ACTION_START;
    public static final String QUERY = RuntimeControlProtocol.ACTION_QUERY;
    public static final String STOP = RuntimeControlProtocol.ACTION_STOP;

    public enum Action {
        START(RuntimeControlProtocol.ACTION_START),
        QUERY(RuntimeControlProtocol.ACTION_QUERY),
        STOP(RuntimeControlProtocol.ACTION_STOP);

        final String wireName;

        Action(String wireName) {
            this.wireName = wireName;
        }

        static Action parse(String value) {
            for (Action action : values()) {
                if (action.wireName.equals(value)) {
                    return action;
                }
            }
            throw new IllegalArgumentException("unknown runtime action: " + value);
        }
    }

    public final int protocolVersion;
    public final String requestId;
    public final Action action;
    public final RuntimeProfile profile;

    private RuntimeControlRequest(int protocolVersion, String requestId, Action action,
                                  RuntimeProfile profile) {
        if (protocolVersion != RuntimeControlProtocol.VERSION) {
            throw new IllegalArgumentException("unsupported runtime control version: "
                    + protocolVersion);
        }
        if (requestId == null || requestId.trim().isEmpty()) {
            throw new IllegalArgumentException("runtime request id is required");
        }
        if (action == null) {
            throw new IllegalArgumentException("runtime action is required");
        }
        if (action == Action.START && profile == null) {
            throw new IllegalArgumentException("start requires a runtime profile");
        }
        if (action != Action.START && profile != null) {
            throw new IllegalArgumentException("only start may select a runtime profile");
        }
        this.protocolVersion = protocolVersion;
        this.requestId = BoundedText.value(requestId, 80);
        this.action = action;
        this.profile = profile;
    }

    public static RuntimeControlRequest start(RuntimeProfile profile) {
        return start(profile, UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest start(RuntimeProfile profile, String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.START, profile);
    }

    public static RuntimeControlRequest query() {
        return query(UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest query(String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.QUERY, null);
    }

    public static RuntimeControlRequest stop() {
        return stop(UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest stop(String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.STOP, null);
    }

    public Map<String, String> encode() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("protocolVersion", Integer.toString(protocolVersion));
        values.put("requestId", requestId);
        values.put("action", action.wireName);
        if (profile != null) {
            values.put("profile", profile.wireName);
        }
        return values;
    }

    public static RuntimeControlRequest decode(Map<String, String> values) {
        if (values == null) {
            throw new IllegalArgumentException("runtime request is missing");
        }
        int version;
        try {
            version = Integer.parseInt(values.get("protocolVersion"));
        } catch (Exception error) {
            throw new IllegalArgumentException("runtime request version is invalid", error);
        }
        Action action = Action.parse(required(values, "action"));
        String profileValue = values.get("profile");
        RuntimeProfile profile = profileValue == null || profileValue.trim().isEmpty()
                ? null : RuntimeProfile.parse(profileValue);
        return new RuntimeControlRequest(version, required(values, "requestId"), action, profile);
    }

    @Override
    public boolean equals(Object other) {
        if (!(other instanceof RuntimeControlRequest)) {
            return false;
        }
        RuntimeControlRequest value = (RuntimeControlRequest) other;
        return protocolVersion == value.protocolVersion
                && action == value.action
                && profile == value.profile
                && requestId.equals(value.requestId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocolVersion, requestId, action, profile);
    }

    private static String required(Map<String, String> values, String name) {
        String value = values.get(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("runtime request field is missing: " + name);
        }
        return value;
    }
}
