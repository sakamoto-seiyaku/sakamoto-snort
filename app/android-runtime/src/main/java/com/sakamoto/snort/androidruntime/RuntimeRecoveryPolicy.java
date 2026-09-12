package com.sakamoto.snort.androidruntime;

/** Fixed bounded restart policy for supervised runtime failures. */
public final class RuntimeRecoveryPolicy {
    public static final int MAX_FAILURES = 3;
    private static final long[] BACKOFF_MILLIS = new long[] {1000L, 5000L, 15000L};

    public static final class Decision {
        public final boolean shouldRestart;
        public final boolean requiresUserIntervention;
        public final int attempt;
        public final int nextFailureCount;
        public final long backoffMillis;
        public final String statusCode;
        public final String message;

        private Decision(boolean shouldRestart, boolean requiresUserIntervention,
                         int attempt, int nextFailureCount, long backoffMillis,
                         String statusCode, String message) {
            this.shouldRestart = shouldRestart;
            this.requiresUserIntervention = requiresUserIntervention;
            this.attempt = attempt;
            this.nextFailureCount = nextFailureCount;
            this.backoffMillis = backoffMillis;
            this.statusCode = statusCode == null ? "" : statusCode;
            this.message = message == null ? "" : message;
        }
    }

    public Decision afterFailure(int previousFailureCount, String reason) {
        int count = Math.max(0, previousFailureCount);
        if (count >= MAX_FAILURES) {
            return new Decision(false, true, MAX_FAILURES, count, 0L,
                    "runtime_recovery_intervention_required",
                    "automatic recovery exhausted after " + MAX_FAILURES
                            + " failures; user intervention is required"
                            + detail(reason));
        }
        int attempt = count + 1;
        long backoff = BACKOFF_MILLIS[Math.min(attempt - 1, BACKOFF_MILLIS.length - 1)];
        return new Decision(true, false, attempt, attempt, backoff,
                "runtime_auto_recovery_pending",
                "automatic recovery attempt " + attempt + "/" + MAX_FAILURES
                        + " after " + backoff + "ms" + detail(reason));
    }

    /** ADR-0007: the VPN Flow Stack gets one fresh-generation retry, not
     * the older generic supervisor's three-retry policy. Success does not
     * replenish this budget; only an explicit user start does. */
    public Decision afterVpnFlowStackFailure(int previousFailureCount, String reason) {
        int count = Math.max(0, previousFailureCount);
        if (count >= 1) {
            return new Decision(false, true, 1, count, 0L,
                    "runtime_recovery_intervention_required",
                    "VPN protection stopped after one automatic restart"
                            + detail(reason));
        }
        return new Decision(true, false, 1, 1, 1000L,
                "runtime_auto_recovery_pending",
                "VPN protection interrupted; one automatic restart in 1000ms"
                        + detail(reason));
    }

    public boolean vpnFlowStackRecoverable(String code) {
        return recoverable(code)
                || "product_core_not_ready".equals(code)
                || "product_core_allocation_failed".equals(code)
                || "product_core_connect_failed".equals(code)
                || "product_core_query_failed".equals(code)
                || "product_core_disconnected".equals(code)
                || "product_core_stale_handle".equals(code)
                || "product_core_session_missing".equals(code)
                || "vpn_socket_broker_failed".equals(code)
                || "vpn_tun_abnormal_close".equals(code)
                || "platform_network_publish_failed".equals(code);
    }

    public boolean recoverable(String code) {
        if (code == null || code.trim().isEmpty()) {
            return true;
        }
        return "unexpected_exit".equals(code)
                || "health_handshake_failed".equals(code)
                || "health_process_exited".equals(code)
                || "runtime_pid_unverified".equals(code)
                || "vpn_tun_control_attach_failed".equals(code)
                || "vpn_hev_transport_start_failed".equals(code)
                || "runtime_start_failed".equals(code);
    }

    public int reset() {
        return 0;
    }

    private static String detail(String reason) {
        String value = BoundedText.value(reason, 160);
        return value.isEmpty() ? "" : ": " + value;
    }
}
