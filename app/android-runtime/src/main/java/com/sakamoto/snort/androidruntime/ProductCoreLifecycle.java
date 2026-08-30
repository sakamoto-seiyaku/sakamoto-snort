package com.sakamoto.snort.androidruntime;

/** Exact SAKAMOTO-172 core-only readiness predicate. */
public final class ProductCoreLifecycle {
    /** Android java.lang.Process does not expose a portable numeric PID. */
    public static final long UNKNOWN_PID = -1L;

    private ProductCoreLifecycle() {}

    /**
     * Validate one Product Core reply against the installed product manifest.
     * The returned value is empty only when the reply is ready.
     */
    public static String validate(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status) {
        if (generation <= 0L || status == null) {
            return "product_protocol_mismatch";
        }
        // A failed connect/query has no trustworthy identity payload. Keep
        // its transport/core outcome instead of inventing an identity fault.
        if (status.code != 0) {
            return "product_core_not_ready";
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
        if (!status.coreReady || status.adapterAvailable || status.protectionRunning
                || !status.pluginLoaded || !status.vapiHandleLive || !status.generationLive
                || status.artifactId.isEmpty() || status.apiIdentity.isEmpty()) {
            return "product_core_not_ready";
        }
        return "";
    }

    /** Identity/protocol failures cannot become valid through connection retry. */
    public static boolean isIdentityFailure(String code) {
        return "product_protocol_mismatch".equals(code)
                || "product_generation_mismatch".equals(code)
                || "product_artifact_identity_mismatch".equals(code)
                || "product_api_identity_mismatch".equals(code)
                || "product_vpp_revision_mismatch".equals(code);
    }

    public static boolean isReady(long generation, String expectedVppRevision,
                                  RuntimeControlNative.Status status) {
        return validate(generation, status == null ? "" : status.artifactId,
                status == null ? "" : status.apiIdentity, expectedVppRevision,
                1, 1, status).isEmpty();
    }

    public static boolean isReady(long generation, String expectedArtifactId,
                                  String expectedApiIdentity, String expectedVppRevision,
                                  int expectedAbiVersion, int expectedApiVersion,
                                  RuntimeControlNative.Status status) {
        return validate(generation, expectedArtifactId, expectedApiIdentity, expectedVppRevision,
                expectedAbiVersion, expectedApiVersion, status).isEmpty();
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
