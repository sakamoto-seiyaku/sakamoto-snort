package com.sakamoto.snort.androidruntime;

/** Exact SAKAMOTO-172 core-only readiness predicate. */
public final class ProductCoreLifecycle {
    /** Android java.lang.Process does not expose a portable numeric PID. */
    public static final long UNKNOWN_PID = -1L;

    /** Result of an app-owned probe of a generation's Product Core socket. */
    public enum ProbeResult {
        LIVE,
        STOPPED,
        UNKNOWN
    }

    /** Ordered visible-START preflight result. */
    public enum StartDecision {
        QUERY_EXISTING,
        LAUNCH_NEW,
        BLOCK_LIVE,
        BLOCK_UNKNOWN,
        BLOCK_INCONSISTENT,
        CLEANUP_FAILED
    }

    /** Ordered Product Core stop result. */
    public enum StopDecision {
        STOP_WITH_PROCESS,
        CLEAR_STOPPED,
        BLOCK_LIVE,
        BLOCK_UNKNOWN,
        BLOCK_INCONSISTENT,
        CLEANUP_FAILED
    }

    /** Small callback seam for exercising the serialized preflight order. */
    public interface HandleProbe {
        ProbeResult probe();
    }

    /** Small callback seam for the app-owned generation profile cleanup. */
    public interface ProfileCleaner {
        boolean clear();
    }

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

    /**
     * Run the visible START preflight in its required order. A profile that
     * remains after service recreation is never cleared from missing Java
     * handles alone: the app-owned socket probe must prove it stopped first.
     * An absent profile is already a stopped generation and needs no probe.
     */
    public static StartDecision preflightStart(boolean profileExists,
                                               boolean processAlive,
                                               boolean sessionLive,
                                               HandleProbe probe,
                                               ProfileCleaner cleaner) {
        if (processAlive && sessionLive) {
            return StartDecision.QUERY_EXISTING;
        }
        if (processAlive || sessionLive) {
            return StartDecision.BLOCK_INCONSISTENT;
        }
        ProbeResult observed = profileExists ? safeProbe(probe) : ProbeResult.STOPPED;
        if (observed == ProbeResult.LIVE) {
            return StartDecision.BLOCK_LIVE;
        }
        if (observed == ProbeResult.UNKNOWN) {
            return StartDecision.BLOCK_UNKNOWN;
        }
        if (profileExists && (cleaner == null || !cleaner.clear())) {
            return StartDecision.CLEANUP_FAILED;
        }
        return StartDecision.LAUNCH_NEW;
    }

    /**
     * Run the Product Core stop preflight. A process handle is sufficient for
     * app-owned termination. Without it, only a stopped socket probe permits
     * profile removal; live or uncertain state fails closed.
     */
    public static StopDecision preflightStop(boolean profileExists,
                                              boolean processAlive,
                                              boolean sessionLive,
                                              HandleProbe probe,
                                              ProfileCleaner cleaner) {
        if (processAlive) {
            return StopDecision.STOP_WITH_PROCESS;
        }
        if (sessionLive) {
            return StopDecision.BLOCK_INCONSISTENT;
        }
        ProbeResult observed = profileExists ? safeProbe(probe) : ProbeResult.STOPPED;
        if (observed == ProbeResult.LIVE) {
            return StopDecision.BLOCK_LIVE;
        }
        if (observed == ProbeResult.UNKNOWN) {
            return StopDecision.BLOCK_UNKNOWN;
        }
        if (profileExists && (cleaner == null || !cleaner.clear())) {
            return StopDecision.CLEANUP_FAILED;
        }
        return StopDecision.CLEAR_STOPPED;
    }

    private static ProbeResult safeProbe(HandleProbe probe) {
        if (probe == null) {
            return ProbeResult.UNKNOWN;
        }
        try {
            ProbeResult result = probe.probe();
            return result == null ? ProbeResult.UNKNOWN : result;
        } catch (RuntimeException ignored) {
            return ProbeResult.UNKNOWN;
        }
    }
}
