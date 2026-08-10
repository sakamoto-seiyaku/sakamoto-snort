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
    public static final String PRODUCT_PROFILE_SELECT =
            RuntimeControlProtocol.ACTION_PRODUCT_PROFILE_SELECT;
    public static final String PRODUCT_BIND_APP = RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP;
    public static final String PRODUCT_UNBIND_APP =
            RuntimeControlProtocol.ACTION_PRODUCT_UNBIND_APP;

    public enum Action {
        START(RuntimeControlProtocol.ACTION_START),
        QUERY(RuntimeControlProtocol.ACTION_QUERY),
        STOP(RuntimeControlProtocol.ACTION_STOP),
        PRODUCT_PROFILE_SELECT(RuntimeControlProtocol.ACTION_PRODUCT_PROFILE_SELECT),
        PRODUCT_BIND_APP(RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP),
        PRODUCT_UNBIND_APP(RuntimeControlProtocol.ACTION_PRODUCT_UNBIND_APP);

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
    public final ApplicationSubjectId applicationSubjectId;

    private RuntimeControlRequest(int protocolVersion, String requestId, Action action,
                                  RuntimeProfile profile,
                                  ApplicationSubjectId applicationSubjectId) {
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
        if ((action == Action.START || action == Action.PRODUCT_PROFILE_SELECT)
                && profile == null) {
            throw new IllegalArgumentException(action.wireName + " requires a runtime profile");
        }
        if (action != Action.START && action != Action.PRODUCT_PROFILE_SELECT
                && profile != null) {
            throw new IllegalArgumentException(
                    "only start and product profile select may carry a runtime profile");
        }
        if ((action == Action.PRODUCT_BIND_APP || action == Action.PRODUCT_UNBIND_APP)
                && applicationSubjectId == null) {
            throw new IllegalArgumentException(action.wireName
                    + " requires an application subject");
        }
        if (action != Action.PRODUCT_BIND_APP && action != Action.PRODUCT_UNBIND_APP
                && applicationSubjectId != null) {
            throw new IllegalArgumentException(
                    "only product app bind/unbind may carry an application subject");
        }
        this.protocolVersion = protocolVersion;
        this.requestId = BoundedText.value(requestId, 80);
        this.action = action;
        this.profile = profile;
        this.applicationSubjectId = applicationSubjectId;
    }

    public static RuntimeControlRequest start(RuntimeProfile profile) {
        return start(profile, UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest start(RuntimeProfile profile, String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.START, profile, null);
    }

    public static RuntimeControlRequest query() {
        return query(UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest query(String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.QUERY, null, null);
    }

    public static RuntimeControlRequest stop() {
        return stop(UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest stop(String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.STOP, null, null);
    }

    public static RuntimeControlRequest selectProductProfile(RuntimeProfile profile) {
        return selectProductProfile(profile, UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest selectProductProfile(RuntimeProfile profile,
                                                            String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.PRODUCT_PROFILE_SELECT, profile, null);
    }

    public static RuntimeControlRequest bindProductApplication(ApplicationSubjectId subjectId) {
        return bindProductApplication(subjectId, UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest bindProductApplication(ApplicationSubjectId subjectId,
                                                              String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.PRODUCT_BIND_APP, null, subjectId);
    }

    public static RuntimeControlRequest unbindProductApplication(ApplicationSubjectId subjectId) {
        return unbindProductApplication(subjectId, UUID.randomUUID().toString());
    }

    public static RuntimeControlRequest unbindProductApplication(ApplicationSubjectId subjectId,
                                                                String requestId) {
        return new RuntimeControlRequest(RuntimeControlProtocol.VERSION, requestId,
                Action.PRODUCT_UNBIND_APP, null, subjectId);
    }

    public Map<String, String> encode() {
        Map<String, String> values = new LinkedHashMap<>();
        values.put("protocolVersion", Integer.toString(protocolVersion));
        values.put("requestId", requestId);
        values.put("action", action.wireName);
        if (profile != null) {
            values.put("profile", profile.wireName);
        }
        if (applicationSubjectId != null) {
            values.put("applicationSubjectId", applicationSubjectId.encode());
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
        String subjectValue = values.get("applicationSubjectId");
        ApplicationSubjectId subjectId = subjectValue == null || subjectValue.trim().isEmpty()
                ? null : ApplicationSubjectId.parse(subjectValue);
        return new RuntimeControlRequest(version, required(values, "requestId"), action, profile,
                subjectId);
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
                && Objects.equals(applicationSubjectId, value.applicationSubjectId)
                && requestId.equals(value.requestId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocolVersion, requestId, action, profile, applicationSubjectId);
    }

    private static String required(Map<String, String> values, String name) {
        String value = values.get(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("runtime request field is missing: " + name);
        }
        return value;
    }
}
