package com.sakamoto.snort.androidruntime;

/** Exact SAKAMOTO-172 core-only readiness predicate. */
public final class ProductCoreLifecycle {
    /** Android java.lang.Process does not expose a portable numeric PID. */
    public static final long UNKNOWN_PID = -1L;

    private ProductCoreLifecycle() {}

    /** An unstarted repair generation has no native TUN control listener to drain. */
    public static boolean requiresVpnDrain(boolean captureStarted,
                                            RuntimeControlNative.Status status) {
        return captureStarted || status == null || status.code != 0
                || !status.coreReady || !status.generationLive
                || status.policyActiveRevision != 0L || status.productGraphEnabled != 0
                || status.vpnTunFdAttached != 0;
    }

    /**
     * Validate one Product Core reply against the installed product manifest.
     * The returned value is empty only when the reply is ready.
     */
    public static String validate(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status,
                                  boolean expectedAdapterAvailable) {
        String management = validateManagement(generation, expectedArtifactId,
                expectedApiIdentity, expectedVppRevision, expectedAbiVersion,
                expectedApiVersion, status);
        if (!management.isEmpty()) return management;
        if (status.adapterAvailable != expectedAdapterAvailable
                || status.protectionRunning != expectedAdapterAvailable) {
            return "product_core_not_ready";
        }
        return "";
    }

    /** Control availability is independent of policy and packet capture readiness. */
    public static String validateManagement(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status) {
        if (generation <= 0L || status == null) {
            return "product_protocol_mismatch";
        }
        // A failed connect/query has no trustworthy identity payload. Keep
        // its transport/core outcome instead of inventing an identity fault.
        if (status.code != 0) {
            return failureCode(status);
        }
        if (status.abiVersion != expectedAbiVersion
                || status.apiVersion != expectedApiVersion) {
            return "product_protocol_mismatch";
        }
        if (status.generation != generation) {
            return "product_generation_mismatch";
        }
        String artifactId = expectedArtifactId == null ? "" : expectedArtifactId.trim();
        if (artifactId.isEmpty() || !artifactId.equals(status.artifactId)) {
            return "product_artifact_identity_mismatch";
        }
        String apiIdentity = expectedApiIdentity == null ? "" : expectedApiIdentity.trim();
        if (apiIdentity.isEmpty() || !apiIdentity.equals(status.apiIdentity)) {
            return "product_api_identity_mismatch";
        }
        String revision = expectedVppRevision == null ? "" : expectedVppRevision.trim();
        if (revision.isEmpty() || !revision.equals(status.vppRevision)) {
            return "product_vpp_revision_mismatch";
        }
        if (status.productGraphWorkerCount <= 0
                || status.productGraphWorkerCount != status.productGraphVppWorkerCount
                || status.productGraphWorkerLayoutReady == 0) {
            return "product_worker_layout_mismatch";
        }
        if (!status.coreReady
                || !status.pluginLoaded || !status.vapiHandleLive || !status.generationLive
                || status.artifactId.isEmpty() || status.apiIdentity.isEmpty()) {
            return "product_core_not_ready";
        }
        return "";
    }

    /** S172 core-only callers remain exact about adapter unavailability. */
    public static String validate(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status) {
        return validate(generation, expectedArtifactId, expectedApiIdentity,
                expectedVppRevision, expectedAbiVersion, expectedApiVersion, status, false);
    }

    /** Identity/protocol failures cannot become valid through connection retry. */
    public static boolean isIdentityFailure(String code) {
        return "product_protocol_mismatch".equals(code)
                || "product_generation_mismatch".equals(code)
                || "product_artifact_identity_mismatch".equals(code)
                || "product_api_identity_mismatch".equals(code)
                || "product_vpp_revision_mismatch".equals(code)
                || "product_worker_layout_mismatch".equals(code);
    }

    /** Preserve the fixed native Product Core status tag at the visible runtime seam. */
    public static String failureCode(RuntimeControlNative.Status status) {
        if (status == null) {
            return "product_core_unavailable";
        }
        switch (status.code) {
            case 0:
                return "product_core_not_ready";
            case 1:
                return "product_core_invalid_argument";
            case 2:
                return "product_core_allocation_failed";
            case 3:
                return "product_core_connect_failed";
            case 4:
                return "product_core_disconnected";
            case 5:
                return "product_core_stale_handle";
            case 6:
                return "product_core_api_unavailable";
            case 7:
                return "product_core_query_failed";
            case 8:
                return "product_core_protocol_mismatch";
            case 9:
                return "product_core_internal_error";
            case 10:
                return "product_core_unknown_tag";
            case 11:
                return "product_core_disconnect_failed";
            case 12:
                return "product_policy_store_failed";
            case 13:
                return "product_policy_apply_failed";
            case 14:
                return "product_policy_outcome_unknown";
            case 15:
                return "product_policy_mutation_fenced";
            default:
                return "product_core_unknown_failure";
        }
    }

    /** Only the startup absence/connect race is retried; typed faults stop now. */
    public static boolean isRetryableConnectionFailure(String code) {
        return "product_core_not_ready".equals(code)
                || "product_core_connect_failed".equals(code);
    }

    /**
     * Startup readiness can lag behind a live VAPI session. Keep polling the
     * same generation until the bounded lifecycle timeout proves the worker
     * layout never converged.
     */
    public static boolean isRetryableStartupReadinessFailure(String code) {
        return isRetryableConnectionFailure(code)
                || "product_worker_layout_mismatch".equals(code);
    }

    /**
     * Root startup can expose the API socket before chmod/connect is fully
     * usable from the app process. While the generation process is still
     * alive, treat an unavailable native connect as the same bounded startup
     * race; typed protocol/identity failures remain terminal.
     */
    public static boolean isRetryableStartupTransportFailure(String code) {
        return "product_core_unavailable".equals(code)
                || "product_core_unknown_failure".equals(code);
    }

    /**
     * A live Product Core session must not be closed just because adapter
     * readiness is still converging. Closing retires the generation in Rust,
     * so the retry loop must poll the same session until it becomes ready or a
     * terminal failure appears.
     */
    public static boolean shouldKeepSessionForReadinessRetry(String code,
                                                             boolean sessionConnected) {
        return sessionConnected && ("product_core_not_ready".equals(code)
                || "product_worker_layout_mismatch".equals(code));
    }

    public static boolean isReady(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status) {
        return validate(generation, expectedArtifactId, expectedApiIdentity, expectedVppRevision,
                expectedAbiVersion, expectedApiVersion, status).isEmpty();
    }

    public static boolean isReady(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status,
                                  boolean expectedAdapterAvailable) {
        return validate(generation, expectedArtifactId, expectedApiIdentity, expectedVppRevision,
                expectedAbiVersion, expectedApiVersion, status,
                expectedAdapterAvailable).isEmpty();
    }

    public static boolean canRetryConnection(boolean stopRequested, boolean processAlive,
                                             int attempt, int maxAttempts) {
        return !stopRequested && processAlive && attempt >= 0 && attempt < maxAttempts;
    }

    /**
     * Visible START may remove a stale Product Core profile only when this
     * service has no live process or session handle for that generation.
     * Ownership/audit helpers for the retired Root path are not involved.
     */
    public static boolean shouldClearStaleProfile(boolean profileExists,
                                                  boolean processAlive,
                                                  boolean sessionLive) {
        return profileExists && !processAlive && !sessionLive;
    }
}
