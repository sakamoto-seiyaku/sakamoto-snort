package com.sakamoto.snort.androidruntime;

/**
 * Serial ordering for lifecycle requests that may be delivered out of order.
 *
 * <p>Activity instances can be replaced while Android still has an older
 * intent queued for the service.  A request with an older elapsed-realtime
 * stamp (or an un-stamped request after a stamped one) is not actionable: it
 * must not undo a newer STOP or select an older profile.  This small
 * Android-free seam keeps that fail-closed ordering policy host-testable.</p>
 */
public final class RuntimeControlOrdering {
    public enum Decision {
        ACCEPT,
        STALE
    }

    private long latestRequestTimeMillis;
    private int latestRequestStartId;

    /**
     * Observe one START/STOP request and record it only when its ordering can
     * be proved newer than the last accepted lifecycle request.
     */
    public synchronized Decision observe(long requestTimeMillis, int startId) {
        if (requestTimeMillis <= 0L) {
            // Once a stamped request exists, an unstamped request cannot prove
            // that it was authored later.  Reject it rather than allowing a
            // delayed START to clear a newer STOP.
            if (latestRequestTimeMillis > 0L) {
                return Decision.STALE;
            }
            if (startId < latestRequestStartId) {
                return Decision.STALE;
            }
            latestRequestStartId = Math.max(latestRequestStartId, startId);
            return Decision.ACCEPT;
        }
        if (latestRequestTimeMillis > 0L
                && (requestTimeMillis < latestRequestTimeMillis
                || requestTimeMillis == latestRequestTimeMillis
                && startId < latestRequestStartId)) {
            return Decision.STALE;
        }
        latestRequestTimeMillis = requestTimeMillis;
        latestRequestStartId = Math.max(latestRequestStartId, startId);
        return Decision.ACCEPT;
    }

    public synchronized long latestRequestTimeMillis() {
        return latestRequestTimeMillis;
    }

    public synchronized int latestRequestStartId() {
        return latestRequestStartId;
    }
}
