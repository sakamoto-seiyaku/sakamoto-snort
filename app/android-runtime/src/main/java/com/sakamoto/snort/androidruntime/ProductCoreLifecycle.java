package com.sakamoto.snort.androidruntime;

/** Exact SAKAMOTO-172 core-only readiness predicate. */
public final class ProductCoreLifecycle {
    private ProductCoreLifecycle() {}

    public static boolean isReady(long generation, String expectedVppRevision,
                                  RuntimeControlNative.Status status) {
        String revision = expectedVppRevision == null ? "" : expectedVppRevision.trim();
        return generation > 0L
                && status != null
                && status.code == 0
                && status.abiVersion == 1
                && status.apiVersion == 1
                && status.generation == generation
                && status.coreReady
                && !status.adapterAvailable
                && !status.protectionRunning
                && status.pluginLoaded
                && status.vapiHandleLive
                && status.generationLive
                && !status.artifactId.isEmpty()
                && !status.apiIdentity.isEmpty()
                && !revision.isEmpty()
                && revision.equals(status.vppRevision);
    }

    public static boolean canRetryConnection(boolean stopRequested, boolean processAlive,
                                             int attempt, int maxAttempts) {
        return !stopRequested && processAlive && attempt >= 0 && attempt < maxAttempts;
    }
}
