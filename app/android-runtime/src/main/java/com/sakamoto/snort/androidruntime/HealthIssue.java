package com.sakamoto.snort.androidruntime;

/** Product-facing actionable health issue. */
public final class HealthIssue {
    public static final String CATEGORY_NONE = "none";
    public static final String CATEGORY_PERMISSION = "permission";
    public static final String CATEGORY_RUNTIME_FAULT = "runtime_fault";
    public static final String CATEGORY_TRANSPORT_FAILURE = "transport_failure";
    public static final String CATEGORY_APPLY_FAILURE = "apply_failure";
    public static final String CATEGORY_PAUSED = "paused";
    public static final String CATEGORY_RECOVERY = "recovery";
    public static final String CATEGORY_START_REQUIRED = "start_required";

    public final String category;
    public final String code;
    public final String message;
    public final String action;
    public final boolean blocking;

    public HealthIssue(String category, String code, String message, String action,
                       boolean blocking) {
        this.category = bounded(category == null || category.trim().isEmpty()
                ? CATEGORY_NONE : category);
        this.code = bounded(code);
        this.message = bounded(message);
        this.action = bounded(action);
        this.blocking = blocking;
    }

    public static HealthIssue none() {
        return new HealthIssue(CATEGORY_NONE, "", "", "", false);
    }

    public static HealthIssue applyFailure(String code, String message) {
        return new HealthIssue(CATEGORY_APPLY_FAILURE,
                code == null || code.trim().isEmpty() ? "product_policy_apply_failed" : code,
                message, "Keep the previous snapshot and fix the policy change.", true);
    }

    public static HealthIssue fromRuntimeSnapshot(RuntimeSnapshot snapshot) {
        if (snapshot == null || snapshot.errorCode.isEmpty()) {
            return none();
        }
        String code = snapshot.errorCode;
        String message = snapshot.errorMessage;
        if ("rule_configuration_not_active".equals(code)) {
            return new HealthIssue(CATEGORY_APPLY_FAILURE, code, message,
                    "Correct the saved rules, then start protection.", true);
        }
        if ("capture_not_started".equals(code)) {
            return new HealthIssue(CATEGORY_START_REQUIRED, code, message,
                    "Start protection when you are ready.", true);
        }
        if (RuntimeSnapshot.ERROR_USER_PAUSE.equals(code)) {
            return new HealthIssue(CATEGORY_PAUSED, code, message,
                    "Resume protection when you are ready.", true);
        }
        if ("notification_permission_required".equals(code)
                || "root_authorization_required".equals(code)
                || "vpn_authorization_required".equals(code)) {
            return new HealthIssue(CATEGORY_PERMISSION, code, message,
                    "Grant the required Android permission and retry.", true);
        }
        if ("runtime_auto_recovery_pending".equals(code)
                || "runtime_recovery_intervention_required".equals(code)) {
            return new HealthIssue(CATEGORY_RECOVERY, code, message,
                    "Wait for recovery or restart the selected profile.", true);
        }
        if ("vpn_tun_control_attach_failed".equals(code)
                || "vpn_hev_transport_start_failed".equals(code)
                || code.indexOf("transport") >= 0) {
            return new HealthIssue(CATEGORY_TRANSPORT_FAILURE, code, message,
                    "Restart VPN profile after checking transport readiness.", true);
        }
        return new HealthIssue(CATEGORY_RUNTIME_FAULT, code, message,
                "Stop, clean up the runtime, and start again.", true);
    }

    public boolean present() {
        return !CATEGORY_NONE.equals(category);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
