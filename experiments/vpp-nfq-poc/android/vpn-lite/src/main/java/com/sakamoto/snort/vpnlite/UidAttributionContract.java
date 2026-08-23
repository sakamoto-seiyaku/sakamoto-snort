package com.sakamoto.snort.vpnlite;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.net.ConnectivityManager;
import android.os.Process;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Throwaway A2 Android bridge for the A1 UID-attribution contract.
 *
 * <p>The native resolver calls {@link #lookup} from its dedicated resolver
 * bridge.  The Android API call itself runs on a bounded executor; lookup
 * returns a sentinel on a miss and the next packet observes the completion in
 * the cache.  UID is deliberately absent from the canonical key and every
 * request/cache record carries generation + network/app scope.</p>
 */
final class UidAttributionContract {
    static final String SCHEMA = "uid-attribution-contract/v1";
    static final String MISS_SUBMITTED = "MISS_SUBMITTED";
    static final String MISS_COALESCED = "MISS_COALESCED";
    static final String CACHE_HIT = "CACHE_HIT";
    static final String LOOKUP_UNAVAILABLE = "LOOKUP_UNAVAILABLE";
    static final String LOOKUP_QUEUE_FULL = "LOOKUP_QUEUE_FULL";
    static final String LOOKUP_STOPPED = "LOOKUP_STOPPED";
    static final String COMPLETION_ACCEPTED = "COMPLETION_ACCEPTED";
    static final String COMPLETION_WRONG_OWNER = "COMPLETION_WRONG_OWNER";
    static final String COMPLETION_WRONG_GENERATION = "COMPLETION_WRONG_GENERATION";
    static final String COMPLETION_DUPLICATE = "COMPLETION_DUPLICATE";
    static final String COMPLETION_STALE = "COMPLETION_STALE";
    static final String COMPLETION_WRONG_SCOPE = "COMPLETION_WRONG_SCOPE";
    static final String COMPLETION_WRONG_UID = "COMPLETION_WRONG_UID";
    static final String CROSS_APP_CACHE_HIT_REJECTED = "CROSS_APP_CACHE_HIT_REJECTED";
    static final String FLOW_OWNER_KEY_MUTATION_REJECTED =
            "FLOW_OWNER_KEY_MUTATION_REJECTED";
    static final String STAGE_BEGIN = "STAGE_BEGIN";

    private static final int PENDING_CAPACITY = 4;
    private static final int CACHE_CAPACITY = 4;
    private static final int FLOW_CAPACITY = PENDING_CAPACITY + CACHE_CAPACITY;
    private static final long CACHE_TTL_MILLIS = 10_000L;

    private final Context context;
    private final ConnectivityManager connectivityManager;
    private final Object lock = new Object();
    private final LinkedHashMap<String, CacheEntry> cache =
            new LinkedHashMap<String, CacheEntry>(8, 0.75f, true);
    private final Map<String, Request> pending = new HashMap<>();
    private final Map<String, Long> flowIds = new HashMap<>();
    private final LinkedHashMap<Long, String> settledTokens =
            new LinkedHashMap<Long, String>(32, 0.75f, true);
    private final Set<Integer> allowedUids = new HashSet<>();
    private final ExecutorService executor;
    private final File logFile;
    private long nextToken = 1;
    private long nextFlowId = 1;
    private long generation = 1;
    private long networkEpoch = 1;
    private long appEpoch = 1;
    private boolean active;
    private boolean providerAvailable = true;
    private boolean enforceAllowedUids;
    private long maxPending;
    private long maxCache;
    private long maxFlowIds;
    private Request lastRequest;
    private String allowedPackageCsv = "";
    private String stageCellId = "A2-4";
    private String stageId = "startup";
    private long stageSequence;
    private long completionDelayMillis;

    UidAttributionContract(Context owner) {
        context = owner.getApplicationContext();
        connectivityManager = (ConnectivityManager) context.getSystemService(
                Context.CONNECTIVITY_SERVICE);
        logFile = new File(context.getFilesDir(), "logs/uid-attribution-contract.jsonl");
        executor = new ThreadPoolExecutor(
                1, 1, 0L, TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(PENDING_CAPACITY),
                runnable -> {
                    Thread thread = new Thread(runnable, "uid-attribution-lookup");
                    thread.setDaemon(true);
                    return thread;
                }, new ThreadPoolExecutor.AbortPolicy());
        active = true;
        appendEvent("CONTRACT_START", null, Process.INVALID_UID,
                "pending-capacity=" + PENDING_CAPACITY + ";cache-capacity=" + CACHE_CAPACITY);
    }

    /**
     * Limit accepted Android owner facts to the packages in the active VPN
     * allow-list.  This is policy scope, not the canonical FlowOwner key: the
     * tuple key remains direction-independent and UID-free.
     */
    void setAllowedPackages(String packageCsv) {
        Set<Integer> resolved = new HashSet<>();
        boolean enforce = packageCsv != null && !packageCsv.trim().isEmpty();
        if (enforce) {
            for (String raw : packageCsv.split(",")) {
                String packageName = raw.trim();
                if (packageName.isEmpty()) {
                    continue;
                }
                try {
                    ApplicationInfo info = context.getPackageManager()
                            .getApplicationInfo(packageName, 0);
                    resolved.add(info.uid);
                } catch (Exception error) {
                    appendEvent("ALLOWED_UID_RESOLUTION_ERROR", null,
                            Process.INVALID_UID, "package=" + packageName
                                    + ";error=" + error.getClass().getSimpleName());
                }
            }
        }
        synchronized (lock) {
            allowedPackageCsv = packageCsv == null ? "" : packageCsv;
            allowedUids.clear();
            allowedUids.addAll(resolved);
            enforceAllowedUids = enforce && !allowedUids.isEmpty();
            appendEventLocked("ALLOWED_UID_SCOPE", null, Process.INVALID_UID, "-",
                    "enforced=" + enforceAllowedUids + ";uids=" + allowedUids);
        }
    }

    /** Publish a bounded lifecycle marker used to join Java and native ledgers. */
    void beginStage(String cellId, String nextStageId, String reason) {
        String normalizedCell = cellId == null || cellId.trim().isEmpty()
                ? "A2-4" : cellId.trim();
        String normalizedStage = nextStageId == null || nextStageId.trim().isEmpty()
                ? "unknown" : nextStageId.trim();
        synchronized (lock) {
            stageCellId = normalizedCell;
            stageId = normalizedStage;
            stageSequence++;
            appendEventLocked(STAGE_BEGIN, null, Process.INVALID_UID, "-",
                    "stage=" + normalizedStage + ";reason=" + reason);
        }
    }

    /** Keep the attribution executor bounded while a late-completion cell is armed. */
    void setCompletionDelayMillis(long delayMillis, String reason) {
        long bounded = Math.max(0L, Math.min(3000L, delayMillis));
        synchronized (lock) {
            completionDelayMillis = bounded;
            appendEventLocked("COMPLETION_DELAY", null, Process.INVALID_UID, "-",
                    "delay-ms=" + bounded + ";reason=" + reason);
        }
    }

    String allowedPackageCsv() {
        synchronized (lock) {
            return allowedPackageCsv;
        }
    }

    /** Return a UID only on a scoped cache hit; miss work is submitted and returns INVALID_UID. */
    int lookup(int protocol, String localAddress, int localPort,
               String remoteAddress, int remotePort) {
        final String family = localAddress.indexOf(':') >= 0 ? "ip6" : "ip4";
        final String protocolText = protocol == 6 ? "TCP" : "UDP";
        final String key = canonicalKey(family, protocolText,
                localAddress, localPort, remoteAddress, remotePort);
        final long now = System.currentTimeMillis();
        synchronized (lock) {
            if (!active) {
                appendEventLocked(LOOKUP_STOPPED, null, Process.INVALID_UID, key,
                        "runtime-inactive");
                return Process.INVALID_UID;
            }
            CacheEntry cached = cache.get(key);
            if (cached != null) {
                if (cached.request.generation == generation
                        && cached.request.networkEpoch == networkEpoch
                        && cached.request.appEpoch == appEpoch
                        && cached.expiresAt > now) {
                    // The cached owner identity belongs to the original
                    // request, but the observation belongs to the current
                    // lifecycle stage.  Keep token/flow/scope immutable while
                    // rebinding only the durable stage context so the native
                    // and Java ledgers can join the hit stage explicitly.
                    appendEventLocked(CACHE_HIT,
                            cached.request.withStage(stageCellId, stageId),
                            cached.uid, key,
                            "cache-hit");
                    return cached.uid;
                }
                cache.remove(key);
                removeFlowIdIfUnreferencedLocked(key);
                appendEventLocked("CACHE_EXPIRED", cached.request, cached.uid, key,
                        "scope-or-ttl");
            }
            Request waiting = pending.get(key);
            if (waiting != null) {
                appendEventLocked(MISS_COALESCED, waiting, Process.INVALID_UID, key,
                        "same-flow-pending");
                return Process.INVALID_UID;
            }
            if (!providerAvailable) {
                appendEventLocked(LOOKUP_UNAVAILABLE, null, Process.INVALID_UID, key,
                        "provider-unavailable");
                return Process.INVALID_UID;
            }
            if (pending.size() >= PENDING_CAPACITY) {
                appendEventLocked(LOOKUP_QUEUE_FULL, null, Process.INVALID_UID, key,
                        "pending-capacity");
                return Process.INVALID_UID;
            }
            long flowId = flowIds.containsKey(key) ? flowIds.get(key) : nextFlowId++;
            flowIds.put(key, flowId);
            maxFlowIds = Math.max(maxFlowIds, flowIds.size());
            if (flowIds.size() > FLOW_CAPACITY) {
                // Every live flow id must be represented by either pending or
                // cache state.  This guard keeps the evidence harness bounded
                // even if a future completion path forgets to release one.
                evictUnreferencedFlowIdsLocked();
            }
            int owner = ownerForKey(key);
            Request request = new Request(nextToken++, flowId, key, owner,
                    generation, networkEpoch, appEpoch, protocol,
                    localAddress, localPort, remoteAddress, remotePort,
                    stageCellId, stageId, completionDelayMillis);
            pending.put(key, request);
            lastRequest = request;
            maxPending = Math.max(maxPending, pending.size());
            appendEventLocked(MISS_SUBMITTED, request, Process.INVALID_UID, key,
                    "owner-sentinel-progress");
            try {
                executor.execute(() -> resolve(request));
            } catch (RejectedExecutionException rejected) {
                pending.remove(key);
                removeFlowIdIfUnreferencedLocked(key);
                appendEventLocked(LOOKUP_QUEUE_FULL, request, Process.INVALID_UID, key,
                        "executor-rejected");
            }
            return Process.INVALID_UID;
        }
    }

    private void resolve(Request request) {
        int uid = Process.INVALID_UID;
        String reason = "connectivity-manager-unavailable";
        try {
            if (connectivityManager != null) {
                java.net.InetSocketAddress local = new java.net.InetSocketAddress(
                        java.net.InetAddress.getByName(request.localAddress), request.localPort);
                java.net.InetSocketAddress remote = new java.net.InetSocketAddress(
                        java.net.InetAddress.getByName(request.remoteAddress), request.remotePort);
                uid = connectivityManager.getConnectionOwnerUid(request.protocol, local, remote);
                reason = uid >= 0 ? "android-api-completion" : "android-api-invalid-uid";
            }
        } catch (Exception error) {
            reason = "android-api-error=" + error.getClass().getSimpleName();
        }
        if (request.completionDelayMillis > 0L) {
            try {
                Thread.sleep(request.completionDelayMillis);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                reason = reason + ";completion-delay-interrupted";
            }
        }
        complete(request, uid, reason);
    }

    private void complete(Request request, int uid, String reason) {
        synchronized (lock) {
            completeLocked(request, uid, reason);
        }
    }

    /** Apply a completion against live state; callers hold {@link #lock}. */
    private String completeLocked(Request request, int uid, String reason) {
        String settled = settledTokens.get(request.token);
        if (settled != null) {
            String outcome = "COMPLETED".equals(settled)
                    ? COMPLETION_DUPLICATE : COMPLETION_STALE;
            appendEventLocked(outcome, request, uid, request.key,
                    "settled-token=" + settled + ";" + reason);
            return outcome;
        }

        Request current = pending.get(request.key);
        if (current == null) {
            appendEventLocked(COMPLETION_STALE, request, uid, request.key,
                    "not-live-pending;" + reason);
            return COMPLETION_STALE;
        }
        if (request.owner != current.owner) {
            appendEventLocked(COMPLETION_WRONG_OWNER, request, uid, request.key,
                    "expected-owner=" + current.owner + ";" + reason);
            return COMPLETION_WRONG_OWNER;
        }
        if (request.token != current.token || request.flowId != current.flowId
                || !request.key.equals(current.key)) {
            appendEventLocked(COMPLETION_STALE, request, uid, request.key,
                    "flow-or-token-mismatch;" + reason);
            return COMPLETION_STALE;
        }
        if (request.networkEpoch != current.networkEpoch
                || request.appEpoch != current.appEpoch
                || request.networkEpoch != networkEpoch
                || request.appEpoch != appEpoch) {
            appendEventLocked(COMPLETION_WRONG_SCOPE, request, uid, request.key,
                    "scope-mismatch;" + reason);
            return COMPLETION_WRONG_SCOPE;
        }
        if (!active || request.generation != current.generation
                || request.generation != generation) {
            appendEventLocked(COMPLETION_WRONG_GENERATION, request, uid, request.key,
                    "generation-mismatch;" + reason);
            return COMPLETION_WRONG_GENERATION;
        }

        pending.remove(request.key);
        if (uid < 0) {
            removeFlowIdIfUnreferencedLocked(request.key);
            rememberSettledLocked(request.token, "REJECTED");
            appendEventLocked(LOOKUP_UNAVAILABLE, request, uid, request.key, reason);
            return LOOKUP_UNAVAILABLE;
        }
        if (enforceAllowedUids && !allowedUids.contains(uid)) {
            removeFlowIdIfUnreferencedLocked(request.key);
            rememberSettledLocked(request.token, "REJECTED");
            appendEventLocked(COMPLETION_WRONG_UID, request, uid, request.key,
                    "allowed-uids=" + allowedUids + ";" + reason);
            return COMPLETION_WRONG_UID;
        }
        CacheEntry entry = new CacheEntry(request, uid,
                System.currentTimeMillis() + CACHE_TTL_MILLIS);
        cache.put(request.key, entry);
        while (cache.size() > CACHE_CAPACITY) {
            String evicted = cache.keySet().iterator().next();
            CacheEntry old = cache.remove(evicted);
            removeFlowIdIfUnreferencedLocked(evicted);
            appendEventLocked("CACHE_EVICTED", old.request, old.uid, evicted,
                    "cache-capacity");
        }
        maxCache = Math.max(maxCache, cache.size());
        rememberSettledLocked(request.token, "COMPLETED");
        appendEventLocked(COMPLETION_ACCEPTED, request, uid, request.key, reason);
        return COMPLETION_ACCEPTED;
    }

    private void rememberSettledLocked(long token, String state) {
        settledTokens.put(token, state);
        while (settledTokens.size() > 32) {
            settledTokens.remove(settledTokens.keySet().iterator().next());
        }
    }

    void refreshNetwork(String reason) {
        synchronized (lock) {
            networkEpoch++;
            invalidateScopeLocked("network-refresh=" + reason);
        }
    }

    void refreshApp(String reason) {
        String packageCsv;
        synchronized (lock) {
            appEpoch++;
            invalidateScopeLocked("app-refresh=" + reason);
            packageCsv = allowedPackageCsv;
        }
        if (!packageCsv.isEmpty()) {
            // Re-resolve the active allow-list after an app replace/reinstall;
            // the epoch refresh must not retain a stale package->UID mapping.
            setAllowedPackages(packageCsv);
        }
    }

    void restartGeneration(String reason) {
        synchronized (lock) {
            generation++;
            invalidateScopeLocked("runtime-generation=" + reason);
        }
    }

    private void invalidateScopeLocked(String reason) {
        cache.clear();
        pending.clear();
        flowIds.clear();
        appendEventLocked("SCOPE_REFRESH", null, Process.INVALID_UID, "-", reason);
    }

    private void removeFlowIdIfUnreferencedLocked(String key) {
        if (!pending.containsKey(key) && !cache.containsKey(key)) {
            flowIds.remove(key);
        }
    }

    private void evictUnreferencedFlowIdsLocked() {
        java.util.Iterator<String> iterator = flowIds.keySet().iterator();
        while (flowIds.size() > FLOW_CAPACITY && iterator.hasNext()) {
            String key = iterator.next();
            if (!pending.containsKey(key) && !cache.containsKey(key)) {
                iterator.remove();
            }
        }
    }

    void setProviderAvailable(boolean available, String reason) {
        synchronized (lock) {
            providerAvailable = available;
            appendEventLocked(available ? "LOOKUP_PROVIDER_AVAILABLE" : LOOKUP_UNAVAILABLE,
                    null, Process.INVALID_UID, "-", reason);
        }
    }

    void replayFaultMatrix() {
        synchronized (lock) {
            /* The replay must use an UID accepted by the active package scope
             * for its valid-completion branch.  The old fixture hard-coded
             * 10180, which made the same APK fail as soon as the deterministic
             * AppA package received a different install UID. */
            int acceptedUid = Process.myUid();
            if (!allowedUids.isEmpty()) {
                acceptedUid = allowedUids.iterator().next();
            }
            int wrongUid = acceptedUid == Integer.MAX_VALUE
                    ? acceptedUid - 1 : acceptedUid + 1;
            while (allowedUids.contains(wrongUid) && wrongUid < Integer.MAX_VALUE) {
                wrongUid++;
            }
            Request wrongOwner = createReplayRequestLocked();
            replayCompletionLocked("wrong-owner", wrongOwner.withOwner(wrongOwner.owner ^ 1),
                    acceptedUid, "replay-owner-mutation");
            Request wrongUidRequest = createReplayRequestLocked();
            replayCompletionLocked("wrong-uid", wrongUidRequest, wrongUid,
                    "replay-wrong-uid");
            Request wrongGeneration = createReplayRequestLocked();
            replayCompletionLocked("wrong-generation",
                    wrongGeneration.withScope(wrongGeneration.generation + 1,
                            wrongGeneration.networkEpoch, wrongGeneration.appEpoch),
                    acceptedUid, "replay-generation");
            Request wrongScope = createReplayRequestLocked();
            replayCompletionLocked("wrong-scope", wrongScope.withScope(wrongScope.generation,
                    wrongScope.networkEpoch + 1, wrongScope.appEpoch), acceptedUid,
                    "replay-network-scope");
            Request request = createReplayRequestLocked();
            replayCompletionLocked("accepted", request, acceptedUid,
                    "replay-valid-completion");
            replayCompletionLocked("duplicate", request, acceptedUid, "replay-duplicate");

            CacheEntry cached = cache.get(request.key);
            if (cached != null && cached.uid != wrongUid) {
                appendEventLocked(CROSS_APP_CACHE_HIT_REJECTED, request, wrongUid, request.key,
                        "replay-live;cached-uid=" + cached.uid + ";requested-uid=" + wrongUid
                                + ";pending=" + pending.size() + ";cache=" + cache.size());
            }
            appendEventLocked(FLOW_OWNER_KEY_MUTATION_REJECTED, request, acceptedUid, request.key,
                    "replay-live;uid-excluded-from-key;pending=" + pending.size()
                            + ";cache=" + cache.size());

            Request stale = createReplayRequestLocked();
            appEpoch++;
            invalidateScopeLocked("replay-app-refresh");
            replayCompletionLocked("stale-after-refresh", stale, acceptedUid,
                    "replay-stale-identity");
        }
    }

    private Request createReplayRequestLocked() {
        String key = canonicalKey("ip4", "TCP", "198.18.0.2", 40001,
                "198.18.0.3", 443);
        if (pending.remove(key) != null) {
            removeFlowIdIfUnreferencedLocked(key);
        }
        long flowId = nextFlowId++;
        Request request = new Request(nextToken++, flowId, key, ownerForKey(key),
                generation, networkEpoch, appEpoch, 6,
                "198.18.0.2", 40001, "198.18.0.3", 443,
                stageCellId, stageId, completionDelayMillis);
        flowIds.put(key, flowId);
        pending.put(key, request);
        lastRequest = request;
        maxPending = Math.max(maxPending, pending.size());
        maxFlowIds = Math.max(maxFlowIds, flowIds.size());
        return request;
    }

    private void replayCompletionLocked(String caseName, Request request, int uid,
                                         String reason) {
        int pendingBefore = pending.size();
        int cacheBefore = cache.size();
        String outcome = completeLocked(request, uid, reason);
        int pendingAfter = pending.size();
        int cacheAfter = cache.size();
        appendEventLocked("REPLAY_ASSERTION", request, uid, request.key,
                "case=" + caseName + ";outcome=" + outcome
                        + ";pending-before=" + pendingBefore + ";pending-after=" + pendingAfter
                        + ";cache-before=" + cacheBefore + ";cache-after=" + cacheAfter
                        + ";unchanged=" + (pendingBefore == pendingAfter
                        && cacheBefore == cacheAfter));
    }

    void stopRuntime(String reason) {
        synchronized (lock) {
            active = false;
            generation++;
            invalidateScopeLocked("runtime-stop=" + reason);
            appendEventLocked("CLEANUP", null, Process.INVALID_UID, "-",
                    "pending=0;cache=0;max-pending=" + maxPending
                            + ";max-cache=" + maxCache + ";flow-ids=" + flowIds.size()
                            + ";max-flow-ids=" + maxFlowIds);
        }
    }

    void startRuntime(String reason) {
        synchronized (lock) {
            active = true;
            generation++;
            invalidateScopeLocked("runtime-start=" + reason);
            appendEventLocked("RUNTIME_REFRESH", null, Process.INVALID_UID, "-",
                    "generation=" + generation);
        }
    }

    void close() {
        synchronized (lock) {
            active = false;
            pending.clear();
            cache.clear();
            appendEventLocked("CLEANUP", null, Process.INVALID_UID, "-",
                    "pending=0;cache=0;max-pending=" + maxPending
                            + ";max-cache=" + maxCache + ";flow-ids=" + flowIds.size()
                            + ";max-flow-ids=" + maxFlowIds);
        }
        executor.shutdownNow();
    }

    private static String canonicalKey(String family, String protocol,
                                       String sourceAddress, int sourcePort,
                                       String destinationAddress, int destinationPort) {
        String source = sourceAddress + ":" + sourcePort;
        String destination = destinationAddress + ":" + destinationPort;
        String a = source.compareTo(destination) <= 0 ? source : destination;
        String b = source.compareTo(destination) <= 0 ? destination : source;
        return family + "/" + protocol + "/" + a + "-" + b;
    }

    private static int ownerForKey(String key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(("a1|" + key).getBytes(StandardCharsets.UTF_8));
            long value = 0;
            for (int i = 0; i < 8; i++) value = (value << 8) | (digest[i] & 0xffL);
            return (int) (Math.floorMod(value, 2));
        } catch (Exception ignored) {
            return Math.floorMod(key.hashCode(), 2);
        }
    }

    private void appendEvent(String outcome, Request request, int uid, String reason) {
        synchronized (lock) {
            appendEventLocked(outcome, request, request == null ? "-" : request.key, uid,
                    reason);
        }
    }

    private void appendEventLocked(String outcome, Request request, int uid,
                                   String key, String reason) {
        appendEventLocked(outcome, request, key, uid, reason);
    }

    private void appendEventLocked(String outcome, Request request, String key,
                                   int uid, String reason) {
        File parent = logFile.getParentFile();
        if (parent != null && !parent.isDirectory()) parent.mkdirs();
        StringBuilder line = new StringBuilder(512);
        StageContext context = request == null
                ? new StageContext(stageCellId, stageId)
                : new StageContext(request.cellId, request.stageId);
        line.append("{\"schema\":\"").append(SCHEMA).append("\"")
                .append(",\"outcome\":\"").append(escape(outcome)).append("\"")
                .append(",\"cell_id\":\"").append(escape(context.cellId)).append("\"")
                .append(",\"stage_id\":\"").append(escape(context.stageId)).append("\"")
                .append(",\"sequence\":").append(++stageSequence)
                .append(",\"monotonic_ns\":").append(System.nanoTime())
                .append(",\"key\":\"").append(escape(key)).append("\"")
                .append(",\"uid\":").append(uid)
                .append(",\"owner\":").append(request == null ? -1 : request.owner)
                .append(",\"generation\":").append(request == null ? generation : request.generation)
                .append(",\"network_epoch\":").append(
                        request == null ? networkEpoch : request.networkEpoch)
                .append(",\"app_epoch\":").append(request == null ? appEpoch : request.appEpoch)
                .append(",\"token\":").append(request == null ? -1 : request.token)
                .append(",\"flow_id\":").append(request == null ? -1 : request.flowId)
                .append(",\"pending\":").append(pending.size())
                .append(",\"cache\":").append(cache.size())
                .append(",\"provider_available\":").append(providerAvailable)
                .append(",\"reason\":\"").append(escape(reason)).append("\"}\n");
        try (FileOutputStream output = new FileOutputStream(logFile, true)) {
            output.write(line.toString().getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        } catch (Exception ignored) {
            // Evidence logging is best effort; the bounded lookup contract is not.
        }
    }

    private static String escape(String value) {
        if (value == null) return "";
        return value.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", "\\n").replace("\r", "\\r");
    }

    private static final class Request {
        final long token;
        final long flowId;
        final String key;
        final int owner;
        final long generation;
        final long networkEpoch;
        final long appEpoch;
        final int protocol;
        final String localAddress;
        final int localPort;
        final String remoteAddress;
        final int remotePort;
        final String cellId;
        final String stageId;
        final long completionDelayMillis;

        Request(long token, long flowId, String key, int owner, long generation,
                long networkEpoch, long appEpoch, int protocol, String localAddress,
                int localPort, String remoteAddress, int remotePort,
                String cellId, String stageId, long completionDelayMillis) {
            this.token = token;
            this.flowId = flowId;
            this.key = key;
            this.owner = owner;
            this.generation = generation;
            this.networkEpoch = networkEpoch;
            this.appEpoch = appEpoch;
            this.protocol = protocol;
            this.localAddress = localAddress;
            this.localPort = localPort;
            this.remoteAddress = remoteAddress;
            this.remotePort = remotePort;
            this.cellId = cellId;
            this.stageId = stageId;
            this.completionDelayMillis = completionDelayMillis;
        }

        int uid() {
            return Process.INVALID_UID;
        }

        Request withOwner(int newOwner) {
            return new Request(token, flowId, key, newOwner, generation,
                    networkEpoch, appEpoch, protocol, localAddress, localPort,
                    remoteAddress, remotePort, cellId, stageId, completionDelayMillis);
        }

        Request withScope(long newGeneration, long newNetworkEpoch, long newAppEpoch) {
            return new Request(token, flowId, key, owner, newGeneration,
                    newNetworkEpoch, newAppEpoch, protocol, localAddress, localPort,
                    remoteAddress, remotePort, cellId, stageId, completionDelayMillis);
        }

        Request withStage(String newCellId, String newStageId) {
            return new Request(token, flowId, key, owner, generation,
                    networkEpoch, appEpoch, protocol, localAddress, localPort,
                    remoteAddress, remotePort, newCellId, newStageId,
                    completionDelayMillis);
        }
    }

    private static final class StageContext {
        final String cellId;
        final String stageId;

        StageContext(String cellId, String stageId) {
            this.cellId = cellId == null ? "A2-4" : cellId;
            this.stageId = stageId == null ? "unknown" : stageId;
        }
    }

    private static final class CacheEntry {
        final Request request;
        final int uid;
        final long expiresAt;

        CacheEntry(Request request, int uid, long expiresAt) {
            this.request = request;
            this.uid = uid;
            this.expiresAt = expiresAt;
        }
    }
}
