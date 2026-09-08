package com.sakamoto.snort.androidruntime;

/** JNI facade for the Rust-owned Product Core control session. */
public final class RuntimeControlNative {
    public static final int CONTROL_ABI_VERSION = 1;
    public static final int POLICY_MUTATION_FAULT_NONE = 0;
    public static final int POLICY_MUTATION_FAULT_OMIT_CALLBACK = 1;
    public static final int POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT = 2;
    // Preserve the S191 prefix name while making the S192 tail explicit.
    private static final int STATUS_VALUE_COUNT = 135;
    private static final int STATUS_VIEW_VALUE_COUNT = 7;
    private static final int STATUS_ASSOCIATION_VALUE_COUNT = 3;
    private static final int STATUS_WIRE_VALUE_COUNT =
            STATUS_VALUE_COUNT + STATUS_VIEW_VALUE_COUNT
                    + STATUS_ASSOCIATION_VALUE_COUNT;
    private static final int CONNECT_VALUE_COUNT = STATUS_WIRE_VALUE_COUNT + 1;
    private static final boolean LOADED;

    static {
        boolean loaded;
        try {
            System.loadLibrary("sakamoto_runtime_control");
            loaded = true;
        } catch (UnsatisfiedLinkError error) {
            loaded = false;
        }
        LOADED = loaded;
    }

    private RuntimeControlNative() {}

    /**
     * Connect one generation and retain the Rust-owned session for subsequent
     * calls to {@link Session#query()}.
     */
    public static Session connect(String apiSocket, long generation) {
        if (!LOADED || apiSocket == null || apiSocket.trim().isEmpty() || generation <= 0L) {
            return Session.unavailable(generation);
        }
        try {
            String[] values = nativeConnect(apiSocket, generation);
            if (values == null || values.length < CONNECT_VALUE_COUNT) {
                return Session.unavailable(generation);
            }
            long handle = parseLong(values[0], 0L);
            return new Session(handle, generation, parseStatus(values, 1));
        } catch (RuntimeException error) {
            return Session.unavailable(generation);
        }
    }

    /**
     * Compatibility entry point for old supervisor call sites. It never
     * invokes native code without an explicit generation; the next lifecycle
     * slice migrates those call sites to connect(apiSocket, generation).
     */
    @Deprecated
    public static Status query(String apiSocket) {
        return Status.unavailable();
    }

    private static Status parseStatus(String[] values, int offset) {
        // S191 callers may still hand this parser the stable prefix while a
        // new native session always enforces STATUS_WIRE_VALUE_COUNT above.
        if (values == null || values.length < offset + STATUS_VALUE_COUNT) {
            return Status.unavailable();
        }
        try {
            return new Status(
                    parseInt(values[offset + 12], -1),
                    parseInt(values[offset + 13], -1),
                    parseInt(values[offset + 0], -1),
                    parseInt(values[offset + 0], -1),
                    parseLong(values[offset + 1], -1L),
                    parseBoolean(values[offset + 2]),
                    parseBoolean(values[offset + 3]),
                    parseBoolean(values[offset + 4]),
                    parseBoolean(values[offset + 5]),
                    parseBoolean(values[offset + 6]),
                    parseBoolean(values[offset + 7]),
                    values[offset + 8],
                    values[offset + 9],
                    values[offset + 10],
                    values[offset + 11],
                    "", "",
                    parseLongAt(values, offset + 142, 0L),
                    parseLongAt(values, offset + 143, 0L),
                    parseLongAt(values, offset + 144, 0L),
                    parseInt(values[offset + 14], 0),
                    parseInt(values[offset + 15], 0),
                    parseInt(values[offset + 16], 0),
                    parseInt(values[offset + 17], 0),
                    parseLong(values[offset + 18], 0L),
                    parseLong(values[offset + 19], 0L),
                    parseLong(values[offset + 20], 0L),
                    parseLong(values[offset + 21], 0L),
                    parseLong(values[offset + 22], 0L),
                    parseLong(values[offset + 23], 0L),
                    parseLong(values[offset + 24], 0L),
                    parseLong(values[offset + 25], 0L),
                    parseLong(values[offset + 26], 0L),
                    parseLong(values[offset + 27], 0L),
                    parseLong(values[offset + 28], 0L),
                    parseLong(values[offset + 29], 0L),
                    parseLong(values[offset + 30], 0L),
                    parseLong(values[offset + 31], 0L),
                    parseLong(values[offset + 32], 0L),
                    parseLong(values[offset + 33], 0L),
                    parseInt(values[offset + 34], 0),
                    parseInt(values[offset + 35], 0),
                    parseInt(values[offset + 36], 0),
                    parseInt(values[offset + 37], 0),
                    parseInt(values[offset + 38], 0),
                    parseInt(values[offset + 39], 0),
                    parseInt(values[offset + 40], 0),
                    parseLong(values[offset + 41], 0L),
                    parseLong(values[offset + 42], 0L),
                    parseLong(values[offset + 43], 0L),
                    parseLong(values[offset + 44], 0L),
                    parseLong(values[offset + 45], 0L),
                    parseLong(values[offset + 46], 0L),
                    parseLong(values[offset + 47], 0L),
                    parseLong(values[offset + 48], 0L),
                    parseLong(values[offset + 49], 0L),
                    parseLong(values[offset + 50], 0L),
                    parseLong(values[offset + 51], 0L),
                    parseLong(values[offset + 52], 0L),
                    parseLong(values[offset + 53], 0L),
                    parseLong(values[offset + 54], 0L),
                    parseLong(values[offset + 55], 0L),
                    parseLong(values[offset + 56], 0L),
                    parseLong(values[offset + 57], 0L),
                    parseLong(values[offset + 58], 0L),
                    parseLong(values[offset + 59], 0L),
                    parseLong(values[offset + 60], 0L),
                    parseLong(values[offset + 61], 0L),
                    parseLong(values[offset + 62], 0L),
                    parseInt(values[offset + 63], 0),
                    parseLong(values[offset + 64], 0L),
                    parseInt(values[offset + 65], 0),
                    parseInt(values[offset + 66], 0),
                    parseInt(values[offset + 67], -1),
                    parseInt(values[offset + 68], -1),
                    parseInt(values[offset + 69], -1),
                    parseInt(values[offset + 70], -1),
                    parseInt(values[offset + 71], -1),
                    parseInt(values[offset + 72], 0),
                    parseInt(values[offset + 73], 0),
                    parseInt(values[offset + 74], 0),
                    parseLong(values[offset + 75], 0L),
                    parseLong(values[offset + 76], 0L),
                    parseLong(values[offset + 77], 0L),
                    parseLong(values[offset + 78], 0L),
                    parseLong(values[offset + 79], 0L),
                    parseLong(values[offset + 80], 0L),
                    parseLong(values[offset + 81], 0L),
                    parseLong(values[offset + 82], 0L),
                    parseLong(values[offset + 83], 0L),
                    parseBoolean(values[offset + 84]),
                    parseBoolean(values[offset + 85]),
                    parseInt(values[offset + 86], 0),
                    parseInt(values[offset + 87], 0),
                    parseInt(values[offset + 88], 0),
                    parseBoolean(values[offset + 89]),
                    parseBoolean(values[offset + 90]),
                    parseBoolean(values[offset + 91]),
                    values[offset + 92],
                    parseInt(values[offset + 93], 0),
                    parseInt(values[offset + 94], 0),
                    parseBoolean(values[offset + 95]),
                    parseInt(values[offset + 96], 0),
                    parseLong(values[offset + 97], 0L),
                    parseLong(values[offset + 98], 0L),
                    parseLong(values[offset + 99], 0L),
                    parseLong(values[offset + 100], 0L),
                    parseLong(values[offset + 101], 0L),
                    parseInt(values[offset + 102], 0),
                    parseInt(values[offset + 103], 0),
                    parseInt(values[offset + 104], 0),
                    parseInt(values[offset + 105], 0),
                    parseInt(values[offset + 106], 0),
                    parseBoolean(values[offset + 107]),
                    parseInt(values[offset + 108], 0),
                    parseLong(values[offset + 109], 0L),
                    parseLong(values[offset + 110], 0L),
                    parseLong(values[offset + 111], 0L),
                    parseLong(values[offset + 112], 0L),
                    parseLong(values[offset + 113], 0L),
                    parseLong(values[offset + 114], 0L),
                    parseInt(values[offset + 115], 0),
                    parseInt(values[offset + 116], 0),
                    parseInt(values[offset + 117], 0),
                    parseInt(values[offset + 118], 0),
                    parseInt(values[offset + 119], 0),
                    parseInt(values[offset + 120], 0),
                    parseInt(values[offset + 121], 0),
                    parseInt(values[offset + 122], 0),
                    parseInt(values[offset + 123], 0),
                    parseInt(values[offset + 124], 0),
                    parseInt(values[offset + 125], 0),
                    parseInt(values[offset + 126], 0),
                    parseInt(values[offset + 127], 0),
                    parseInt(values[offset + 128], 0),
                    parseInt(values[offset + 129], 0),
                    parseInt(values[offset + 130], 0),
                    parseInt(values[offset + 131], 0),
                    parseInt(values[offset + 132], 0),
                    parseInt(values[offset + 133], 0),
                    parseInt(values[offset + 134], 0),
                    parseIntAt(values, offset + 135, 0),
                    parseIntAt(values, offset + 136, 0),
                    parseIntAt(values, offset + 137, 0),
                    parseIntAt(values, offset + 138, 0),
                    parseIntAt(values, offset + 139, 0),
                    parseIntAt(values, offset + 140, 0),
                    parseIntAt(values, offset + 141, 0));
        } catch (RuntimeException error) {
            return Status.unavailable();
        }
    }

    private static int parseInt(String value, int fallback) {
        try {
            long parsed = Long.parseLong(value);
            if (parsed < Integer.MIN_VALUE || parsed > 0xffffffffL) {
                return fallback;
            }
            return (int) parsed;
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static int parseIntAt(String[] values, int index, int fallback) {
        return values != null && index >= 0 && index < values.length
                ? parseInt(values[index], fallback) : fallback;
    }

    private static long parseLongAt(String[] values, int index, long fallback) {
        return values != null && index >= 0 && index < values.length
                ? parseLong(values[index], fallback) : fallback;
    }

    private static long parseLong(String value, long fallback) {
        try {
            return Long.parseLong(value);
        } catch (Exception ignored) {
            try {
                return Long.parseUnsignedLong(value);
            } catch (Exception ignoredAgain) {
                return fallback;
            }
        }
    }

    private static boolean parseBoolean(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static native String[] nativeConnect(String apiSocket, long generation);

    private static native String[] nativeQuery(long handle, long generation);

    private static native String[] nativeApplyEmptyPolicy(long handle, long generation,
                                                          String filesDir);

    private static native String[] nativeApplyEmptyPolicyRevision(
            long handle, long generation, String filesDir, long revision);

    private static native String[] nativeApplyNetworkGatePolicy(long handle, long generation,
                                                                String filesDir, int subjectUid,
                                                                int networkContext,
                                                                boolean blocked, long ruleId,
                                                                int reasonId);

    private static native String[] nativeApplyNetworkGatePolicyRevision(
            long handle, long generation, String filesDir, long revision, int subjectUid,
            int networkContext, boolean blocked, long ruleId, int reasonId);

    private static native String[] nativeApplyL4Policy(
            long handle, long generation, String filesDir, int subjectUid, int networkContext,
            int ipFamily, int ipProtocol, int direction, int action, String sourceCidr,
            String destinationCidr, int sourcePortFirst, int sourcePortLast,
            int destinationPortFirst, int destinationPortLast, int priority, int order,
            long ruleId, int reasonId);

    private static native String[] nativeApplyL4PolicyRevision(
            long handle, long generation, String filesDir, long revision, int subjectUid,
            int networkContext, int ipFamily, int ipProtocol, int direction, int action,
            String sourceCidr, String destinationCidr, int sourcePortFirst, int sourcePortLast,
            int destinationPortFirst, int destinationPortLast, int priority, int order,
            long ruleId, int reasonId);

    /** Apply one complete fixed-capacity Gate + L4 successor in one native call. */
    private static native String[] nativeApplyPolicyBundle(
            long handle, long generation, String filesDir, byte[] bundlePayload);

    /** Arm one debug-only, one-shot fault at the typed bundle reply boundary. */
    private static native String[] nativeSetPolicyMutationFault(
            long handle, long generation, int faultMode);

    private static native String[] nativeReconcilePolicy(long handle, long generation,
                                                         String filesDir);

    private static native String[] nativeReconcileEmptyPolicy(long handle, long generation,
                                                              String filesDir);

    private static native int nativeDisconnect(long handle);

    private static native int nativeDestroy(long handle);

    public static final class Session implements AutoCloseable {
        private long nativeHandle;
        private final long generation;
        private Status lastStatus;

        private Session(long nativeHandle, long generation, Status initialStatus) {
            this.nativeHandle = nativeHandle;
            this.generation = generation;
            this.lastStatus = initialStatus == null ? Status.unavailable() : initialStatus;
        }

        private static Session unavailable(long generation) {
            return new Session(0L, generation, Status.unavailable(generation));
        }

        public long generation() {
            return generation;
        }

        public synchronized boolean isConnected() {
            return nativeHandle != 0L;
        }

        public synchronized Status lastStatus() {
            return lastStatus;
        }

        /** Query the same native session and generation used by connect(). */
        public synchronized Status query() {
            if (!LOADED || nativeHandle == 0L) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeQuery(nativeHandle, generation), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish a fresh empty default-pass policy snapshot. */
        public synchronized Status applyEmptyPolicy(String filesDir) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty()) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyEmptyPolicy(
                        nativeHandle, generation, filesDir), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish an empty policy at an authoring revision. */
        public synchronized Status applyEmptyPolicyRevision(String filesDir, long revision) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty() || revision <= 0L) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyEmptyPolicyRevision(
                        nativeHandle, generation, filesDir, revision), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish one Root Network Gate policy snapshot. */
        public synchronized Status applyNetworkGatePolicy(
                String filesDir, int subjectUid, int networkContext, boolean blocked,
                long ruleId, int reasonId) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty() || subjectUid < 0 || networkContext <= 0
                    || ruleId <= 0L || reasonId <= 0) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyNetworkGatePolicy(
                        nativeHandle, generation, filesDir, subjectUid, networkContext,
                        blocked, ruleId, reasonId), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish one Root Network Gate policy at an authoring revision. */
        public synchronized Status applyNetworkGatePolicyRevision(
                String filesDir, long revision, int subjectUid, int networkContext,
                boolean blocked, long ruleId, int reasonId) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty() || revision <= 0L || subjectUid < 0
                    || networkContext <= 0 || ruleId <= 0L || reasonId <= 0) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyNetworkGatePolicyRevision(
                        nativeHandle, generation, filesDir, revision, subjectUid,
                        networkContext, blocked, ruleId, reasonId), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish one stateless Root IPv4/TCP L4 policy snapshot. */
        public synchronized Status applyL4Policy(
                String filesDir, int subjectUid, int networkContext, int ipFamily,
                int ipProtocol, int direction, int action, String sourceCidr,
                String destinationCidr, int sourcePortFirst, int sourcePortLast,
                int destinationPortFirst, int destinationPortLast, int priority, int order,
                long ruleId, int reasonId) {
            if (!validL4Apply(filesDir, subjectUid, networkContext, ipFamily, ipProtocol,
                    direction, action, sourceCidr, destinationCidr, sourcePortFirst,
                    sourcePortLast, destinationPortFirst, destinationPortLast,
                    priority, order, ruleId,
                    reasonId)) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyL4Policy(
                        nativeHandle, generation, filesDir, subjectUid, networkContext,
                        ipFamily, ipProtocol, direction, action, sourceCidr, destinationCidr,
                        sourcePortFirst, sourcePortLast, destinationPortFirst,
                        destinationPortLast, priority, order, ruleId, reasonId), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Persist and publish one stateless Root IPv4/TCP L4 policy at an authoring revision. */
        public synchronized Status applyL4PolicyRevision(
                String filesDir, long revision, int subjectUid, int networkContext,
                int ipFamily, int ipProtocol, int direction, int action, String sourceCidr,
                String destinationCidr, int sourcePortFirst, int sourcePortLast,
                int destinationPortFirst, int destinationPortLast, int priority, int order,
                long ruleId, int reasonId) {
            if (revision <= 0L || !validL4Apply(filesDir, subjectUid, networkContext,
                    ipFamily, ipProtocol, direction, action, sourceCidr, destinationCidr,
                    sourcePortFirst, sourcePortLast, destinationPortFirst,
                    destinationPortLast, priority, order, ruleId, reasonId)) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyL4PolicyRevision(
                        nativeHandle, generation, filesDir, revision, subjectUid,
                        networkContext, ipFamily, ipProtocol, direction, action, sourceCidr,
                        destinationCidr, sourcePortFirst, sourcePortLast, destinationPortFirst,
                        destinationPortLast, priority, order, ruleId, reasonId), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /**
         * Persist and publish one complete typed policy bundle.  The payload
         * contains both Gate and L4 entries; callers must not split it into
         * legacy per-rule applies.
         */
        public synchronized Status applyPolicyBundle(String filesDir, byte[] bundlePayload) {
            if (!validPolicyBundleApply(filesDir, bundlePayload)) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeApplyPolicyBundle(
                        nativeHandle, generation, filesDir, bundlePayload), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /**
         * Arm or clear one debug-only, one-shot typed policy mutation fault.
         * The VAPI session consumes the arm on the next complete bundle apply.
         */
        public synchronized Status setPolicyMutationFaultMode(String mode) {
            int faultMode;
            if (mode == null || mode.trim().isEmpty() || "none".equals(mode.trim())) {
                faultMode = POLICY_MUTATION_FAULT_NONE;
            } else if ("bundle_callback_omission".equals(mode.trim())) {
                faultMode = POLICY_MUTATION_FAULT_OMIT_CALLBACK;
            } else if ("bundle_pre_submit_not_sent".equals(mode.trim())) {
                faultMode = POLICY_MUTATION_FAULT_PRE_SUBMIT_NOT_SENT;
            } else {
                return lastStatus;
            }
            if (!LOADED || nativeHandle == 0L) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeSetPolicyMutationFault(
                        nativeHandle, generation, faultMode), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        private boolean validPolicyBundleApply(String filesDir, byte[] bundlePayload) {
            return LOADED && nativeHandle != 0L && filesDir != null
                    && !filesDir.trim().isEmpty()
                    && bundlePayload != null
                    && bundlePayload.length == AuthoringPolicyBundle.BUNDLE_BYTES;
        }

        private boolean validL4Apply(String filesDir, int subjectUid, int networkContext,
                                     int ipFamily, int ipProtocol, int direction, int action,
                                     String sourceCidr, String destinationCidr,
                                     int sourcePortFirst, int sourcePortLast,
                                     int destinationPortFirst, int destinationPortLast,
                                     int priority, int order, long ruleId, int reasonId) {
            return LOADED && nativeHandle != 0L && filesDir != null
                    && !filesDir.trim().isEmpty()
                    && subjectUid >= 0 && networkContext > 0
                    && ipFamily == 4 && ipProtocol == 6
                    && (direction == 1 || direction == 3)
                    && (action == 1 || action == 2)
                    && sourceCidr != null && !sourceCidr.trim().isEmpty()
                    && destinationCidr != null && !destinationCidr.trim().isEmpty()
                    && sourcePortFirst >= 0 && sourcePortLast >= sourcePortFirst
                    && sourcePortLast <= 65535
                    && destinationPortFirst >= 0
                    && destinationPortLast >= destinationPortFirst
                    && destinationPortLast <= 65535
                    && priority >= 0 && order >= 0
                    && ruleId > 0L && reasonId > 0;
        }

        /**
         * Reconcile persisted policy state.  An unknown mutation is handled
         * by Product Core through fresh-generation active-state readback; this
         * method never replays the fenced candidate.
         */
        public synchronized Status reconcilePolicy(String filesDir) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty()) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeReconcilePolicy(
                        nativeHandle, generation, filesDir), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        /** Re-apply the persisted empty policy intent if one exists. */
        public synchronized Status reconcileEmptyPolicy(String filesDir) {
            if (!LOADED || nativeHandle == 0L || filesDir == null
                    || filesDir.trim().isEmpty()) {
                return lastStatus;
            }
            try {
                Status status = parseStatus(nativeReconcileEmptyPolicy(
                        nativeHandle, generation, filesDir), 0);
                lastStatus = status;
                return status;
            } catch (RuntimeException error) {
                lastStatus = Status.unavailable(generation);
                return lastStatus;
            }
        }

        @Override
        public synchronized void close() {
            closeAndGetStatus();
        }

        /** Close the native session and retain a typed disconnect result. */
        public synchronized Status closeAndGetStatus() {
            if (nativeHandle == 0L) {
                return lastStatus;
            }
            long handle = nativeHandle;
            nativeHandle = 0L;
            int disconnectCode = 0;
            int destroyCode = 0;
            try {
                disconnectCode = nativeDisconnect(handle);
            } finally {
                destroyCode = nativeDestroy(handle);
            }
            if (disconnectCode != 0) {
                lastStatus = Status.nativeFailure(lastStatus, disconnectCode,
                        "Product Core VAPI disconnect failed");
            } else if (destroyCode != 0) {
                lastStatus = Status.nativeFailure(lastStatus, destroyCode,
                        "Product Core native session destroy failed");
            } else {
                // A previous query failure must not be mistaken for a
                // disconnect failure after the native handle closes cleanly.
                lastStatus = Status.nativeFailure(lastStatus, 0, "");
            }
            return lastStatus;
        }
    }

    public static final class Status {
        public final int abiVersion;
        public final int apiVersion;
        public final int code;
        public final long generation;
        public final boolean coreReady;
        public final boolean adapterAvailable;
        public final boolean protectionRunning;
        public final boolean pluginLoaded;
        public final boolean vapiHandleLive;
        public final boolean generationLive;
        public final String artifactId;
        public final String apiIdentity;
        public final String vppRevision;
        public final String errorDetail;
        public final int rootNfqueueQueueId;
        public final int rootNfqueueQueueLast;
        public final int rootNfqueueLaneCount;
        public final int rootNfqueueReadyLaneMask;
        public final long rootNfqueueGeneration;
        public final long rootNfqueueVerdictAttempts;
        public final long rootNfqueueInternalSettlements;
        public final long rootNfqueueBufferReturns;
        public final long rootNfqueueOriginLocalCompletions;
        public final long rootNfqueueOriginRemoteCompletions;
        public final long rootNfqueueLane0VerdictAttempts;
        public final long rootNfqueueLane1VerdictAttempts;
        public final long rootNfqueueInputPackets;
        public final long rootNfqueueOutputPackets;
        public final long rootNfqueueIpv4Packets;
        public final long rootNfqueueIpv6Packets;
        public final long rootNfqueueTcpPackets;
        public final long rootNfqueueUdpPackets;
        public final long rootNfqueueUidKnownPackets;
        public final long rootNfqueueUidUnknownPackets;
        public final int rootNfqueueLastIpFamily;
        public final int rootNfqueueLastProtocol;
        public final int rootNfqueueLastHook;
        public final int rootNfqueueLastUidKnown;
        public final int rootNfqueueLastUid;
        public final int rootNfqueueLastQueueId;
        public final int rootNfqueueLastPacketId;
        public final long rootNfqueueVerdictSucceeded;
        public final long rootNfqueueVerdictFailedDefinite;
        public final long rootNfqueueVerdictOutcomeUnknown;
        public final long rootNfqueueIngressIdentityMissing;
        public final long rootNfqueueGraphSubmitFailOpens;
        public final long rootNfqueueNonOwnerBypasses;
        public final long rootNfqueueDuplicateCompletionDrops;
        public final long rootNfqueueStaleCompletionDrops;
        public final long vpnTunFdAttached;
        public final long vpnDirectUdp4SocketAttached;
        public final long vpnDirectUdp4ProtectSucceeded;
        public final long vpnDirectUdp4BindSucceeded;
        public final long vpnTunIngressPackets;
        public final long vpnTunUdp4TunOriginPackets;
        public final long vpnFlowStackAdmissions;
        public final long vpnDirectUdp4SendSucceeded;
        public final long vpnDirectUdp4TransportFailed;
        public final long vpnFlowStackReturnPackets;
        public final long vpnFlowStackReturnProvenancePackets;
        public final long vpnTunWriteCompletions;
        public final long vpnInfrastructureFaults;
        public final long vpnDuplicateOrStaleDrops;
        public final int productGraphWorkerCount;
        public final long productGraphHashSeed;
        public final int productGraphHandoffCredits;
        public final int productGraphVppWorkerCount;
        public final int productGraphVppMainCore;
        public final int productGraphVppWorker0ThreadIndex;
        public final int productGraphVppWorker0Core;
        public final int productGraphVppWorker1ThreadIndex;
        public final int productGraphVppWorker1Core;
        public final int productGraphEnabled;
        public final int productGraphAccepting;
        public final int productGraphWorkerLayoutReady;
        public final long productGraphObligationDebt;
        public final long productGraphBufferDebt;
        public final long productGraphHandoffDebt;
        public final long policyRequestedRevision;
        public final long policyActiveRevision;
        public final long policyGeneration;
        public final long policySnapshotHash;
        public final long policyWorker0Revision;
        public final long policyWorker1Revision;
        public final boolean policySnapshotEmpty;
        public final boolean policyDefaultPass;
        public final int policyGateClaimCount;
        public final int policyL4RuleCount;
        public final int policyLastApplyStatusCode;
        public final boolean policyMixedRevision;
        public final boolean policyArtifactMatch;
        public final boolean policyGenerationMatch;
        public final String policySnapshotIdentity;
        public final int policyGateSubjectUid;
        public final int policyGateNetworkContext;
        public final boolean policyGateBlocked;
        public final int policyGateReasonId;
        public final long policyGateRuleId;
        public final long policyDropRecords;
        public final long policyLastDropRevision;
        public final long policyLastDropRuleId;
        public final long policyLastDropCompletionAttempts;
        public final int policyLastDropUid;
        public final int policyLastDropNetworkContext;
        public final int policyLastDropReasonId;
        public final int policyLastDropVerdict;
        public final int policyLastDropWinner;
        public final boolean policyLastDropUidKnown;
        public final int policyLastDropDeviceDirection;
        public final long policyL4ActiveRevision;
        public final long policyL4RuleId;
        public final long policyL4MatchRecords;
        public final long policyL4NoMatchRecords;
        public final long policyL4LastMatchRevision;
        public final long policyL4LastMatchRuleId;
        public final int policyL4SubjectUid;
        public final int policyL4NetworkContext;
        public final int policyL4IpFamily;
        public final int policyL4IpProtocol;
        public final int policyL4Direction;
        public final int policyL4Action;
        public final int policyL4Priority;
        public final int policyL4Order;
        public final int policyL4ReasonId;
        public final int policyL4LastMatchUid;
        public final int policyL4LastMatchNetworkContext;
        public final int policyL4LastMatchReasonId;
        public final int policyL4LastMatchVerdict;
        public final int policyL4LastMatchWinner;
        public final int policyL4LastMatchUidKnown;
        public final int policyL4LastMatchDeviceDirection;
        public final int policyL4LastMatchAction;
        public final int policyL4LastEvaluationResult;
        public final int policyL4LastEvaluationVerdict;
        public final int policyL4LastEvaluationDeviceDirection;
        public final int policyL4ViewActive;
        public final int policyL4ViewRuleCount;
        public final int policyL4ViewMaxProbes;
        public final int policyL4ViewLastMatchWinnerRank;
        public final int policyL4ViewLastMatchProbes;
        public final int policyL4ViewLastMatchCandidateCount;
        public final int policyL4ViewLastNoMatchReason;
        public final long policyL4TypedMatchPolicyKey;
        public final long policyL4TypedMatchProbeKey;
        public final long policyL4LastEvaluationProbeKey;

        /*
         * These aliases keep the old health evaluator source-compatible until
         * the lifecycle tracer adopts the Product Core fields above. They are
         * never populated by the retired version-query native path.
         */
        public final int controlAbiVersion;
        public final int transportCode;
        public final int vppRetval;
        public final String program;
        public final String version;
        public final String buildDate;
        public final String buildDirectory;

        public Status(int abiVersion, int apiVersion, int code, int legacyVppRetval,
                       long generation, boolean coreReady, boolean adapterAvailable,
                       boolean protectionRunning, boolean pluginLoaded,
                       boolean vapiHandleLive, boolean generationLive,
                       String artifactId, String apiIdentity, String vppRevision,
                       String errorDetail, String program, String version) {
            this(abiVersion, apiVersion, code, legacyVppRetval, generation,
                    coreReady, adapterAvailable, protectionRunning, pluginLoaded,
                    vapiHandleLive, generationLive, artifactId, apiIdentity,
                    vppRevision, errorDetail, program, version, 0L, 0L, 0L,
                    0, 0, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0, 0, 0, 0, 0, 0, 0,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L,
                    0, 0L, 0, 0, -1, -1, -1, -1, -1,
                    0, 0, 0, 0L, 0L, 0L,
                    0L, 0L, 0L, 0L, 0L, 0L,
                    false, false, 0, 0, 0, false, false, false, "",
                    0, 0, false, 0, 0L, 0L, 0L, 0L, 0L,
                    0, 0, 0, 0, 0, false, 0,
                    0L, 0L, 0L, 0L, 0L, 0L,
                    0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
        }

        public Status(int abiVersion, int apiVersion, int code, int legacyVppRetval,
                       long generation, boolean coreReady, boolean adapterAvailable,
                       boolean protectionRunning, boolean pluginLoaded,
                       boolean vapiHandleLive, boolean generationLive,
                       String artifactId, String apiIdentity, String vppRevision,
                       String errorDetail, String program, String version,
                       long policyL4TypedMatchPolicyKey,
                       long policyL4TypedMatchProbeKey,
                       long policyL4LastEvaluationProbeKey,
                       int rootNfqueueQueueId, int rootNfqueueQueueLast,
                       int rootNfqueueLaneCount, int rootNfqueueReadyLaneMask,
                       long rootNfqueueGeneration,
                       long rootNfqueueVerdictAttempts,
                       long rootNfqueueInternalSettlements,
                       long rootNfqueueBufferReturns,
                       long rootNfqueueOriginLocalCompletions,
                       long rootNfqueueOriginRemoteCompletions,
                       long rootNfqueueLane0VerdictAttempts,
                       long rootNfqueueLane1VerdictAttempts,
                       long rootNfqueueInputPackets,
                       long rootNfqueueOutputPackets,
                       long rootNfqueueIpv4Packets,
                       long rootNfqueueIpv6Packets,
                       long rootNfqueueTcpPackets,
                       long rootNfqueueUdpPackets,
                       long rootNfqueueUidKnownPackets,
                       long rootNfqueueUidUnknownPackets,
                       int rootNfqueueLastIpFamily,
                       int rootNfqueueLastProtocol,
                       int rootNfqueueLastHook,
                       int rootNfqueueLastUidKnown,
                       int rootNfqueueLastUid,
                       int rootNfqueueLastQueueId,
                       int rootNfqueueLastPacketId,
                       long rootNfqueueVerdictSucceeded,
                       long rootNfqueueVerdictFailedDefinite,
                       long rootNfqueueVerdictOutcomeUnknown,
                       long rootNfqueueIngressIdentityMissing,
                       long rootNfqueueGraphSubmitFailOpens,
                       long rootNfqueueNonOwnerBypasses,
                       long rootNfqueueDuplicateCompletionDrops,
                       long rootNfqueueStaleCompletionDrops,
                       long vpnTunFdAttached,
                       long vpnDirectUdp4SocketAttached,
                       long vpnDirectUdp4ProtectSucceeded,
                       long vpnDirectUdp4BindSucceeded,
                       long vpnTunIngressPackets,
                       long vpnTunUdp4TunOriginPackets,
                       long vpnFlowStackAdmissions,
                       long vpnDirectUdp4SendSucceeded,
                       long vpnDirectUdp4TransportFailed,
                       long vpnFlowStackReturnPackets,
                       long vpnFlowStackReturnProvenancePackets,
                       long vpnTunWriteCompletions,
                       long vpnInfrastructureFaults,
                       long vpnDuplicateOrStaleDrops,
                       int productGraphWorkerCount,
                       long productGraphHashSeed,
                       int productGraphHandoffCredits,
                       int productGraphVppWorkerCount,
                       int productGraphVppMainCore,
                       int productGraphVppWorker0ThreadIndex,
                       int productGraphVppWorker0Core,
                       int productGraphVppWorker1ThreadIndex,
                       int productGraphVppWorker1Core,
                       int productGraphEnabled,
                       int productGraphAccepting,
                       int productGraphWorkerLayoutReady,
                       long productGraphObligationDebt,
                       long productGraphBufferDebt,
                       long productGraphHandoffDebt,
                       long policyRequestedRevision,
                       long policyActiveRevision,
                       long policyGeneration,
                       long policySnapshotHash,
                       long policyWorker0Revision,
                       long policyWorker1Revision,
                       boolean policySnapshotEmpty,
                       boolean policyDefaultPass,
                       int policyGateClaimCount,
                       int policyL4RuleCount,
                       int policyLastApplyStatusCode,
                       boolean policyMixedRevision,
                       boolean policyArtifactMatch,
                       boolean policyGenerationMatch,
                       String policySnapshotIdentity,
                       int policyGateSubjectUid,
                       int policyGateNetworkContext,
                       boolean policyGateBlocked,
                       int policyGateReasonId,
                       long policyGateRuleId,
                       long policyDropRecords,
                       long policyLastDropRevision,
                       long policyLastDropRuleId,
                       long policyLastDropCompletionAttempts,
                       int policyLastDropUid,
                       int policyLastDropNetworkContext,
                       int policyLastDropReasonId,
                       int policyLastDropVerdict,
                       int policyLastDropWinner,
                       boolean policyLastDropUidKnown,
                       int policyLastDropDeviceDirection,
                       long policyL4ActiveRevision,
                       long policyL4RuleId,
                       long policyL4MatchRecords,
                       long policyL4NoMatchRecords,
                       long policyL4LastMatchRevision,
                       long policyL4LastMatchRuleId,
                       int policyL4SubjectUid,
                       int policyL4NetworkContext,
                       int policyL4IpFamily,
                       int policyL4IpProtocol,
                       int policyL4Direction,
                       int policyL4Action,
                       int policyL4Priority,
                       int policyL4Order,
                       int policyL4ReasonId,
                       int policyL4LastMatchUid,
                       int policyL4LastMatchNetworkContext,
                       int policyL4LastMatchReasonId,
                       int policyL4LastMatchVerdict,
                       int policyL4LastMatchWinner,
                       int policyL4LastMatchUidKnown,
                       int policyL4LastMatchDeviceDirection,
                       int policyL4LastMatchAction,
                       int policyL4LastEvaluationResult,
                       int policyL4LastEvaluationVerdict,
                       int policyL4LastEvaluationDeviceDirection,
                       int... policyL4View) {
            this.abiVersion = abiVersion;
            this.apiVersion = apiVersion;
            this.code = code;
            this.generation = generation;
            this.coreReady = coreReady;
            this.adapterAvailable = adapterAvailable;
            this.protectionRunning = protectionRunning;
            this.pluginLoaded = pluginLoaded;
            this.vapiHandleLive = vapiHandleLive;
            this.generationLive = generationLive;
            this.artifactId = bounded(artifactId);
            this.apiIdentity = bounded(apiIdentity);
            this.vppRevision = bounded(vppRevision);
            this.errorDetail = bounded(errorDetail);
            this.rootNfqueueQueueId = rootNfqueueQueueId;
            this.rootNfqueueQueueLast = rootNfqueueQueueLast;
            this.rootNfqueueLaneCount = rootNfqueueLaneCount;
            this.rootNfqueueReadyLaneMask = rootNfqueueReadyLaneMask;
            this.rootNfqueueGeneration = rootNfqueueGeneration;
            this.rootNfqueueVerdictAttempts = rootNfqueueVerdictAttempts;
            this.rootNfqueueInternalSettlements = rootNfqueueInternalSettlements;
            this.rootNfqueueBufferReturns = rootNfqueueBufferReturns;
            this.rootNfqueueOriginLocalCompletions = rootNfqueueOriginLocalCompletions;
            this.rootNfqueueOriginRemoteCompletions = rootNfqueueOriginRemoteCompletions;
            this.rootNfqueueLane0VerdictAttempts = rootNfqueueLane0VerdictAttempts;
            this.rootNfqueueLane1VerdictAttempts = rootNfqueueLane1VerdictAttempts;
            this.rootNfqueueInputPackets = rootNfqueueInputPackets;
            this.rootNfqueueOutputPackets = rootNfqueueOutputPackets;
            this.rootNfqueueIpv4Packets = rootNfqueueIpv4Packets;
            this.rootNfqueueIpv6Packets = rootNfqueueIpv6Packets;
            this.rootNfqueueTcpPackets = rootNfqueueTcpPackets;
            this.rootNfqueueUdpPackets = rootNfqueueUdpPackets;
            this.rootNfqueueUidKnownPackets = rootNfqueueUidKnownPackets;
            this.rootNfqueueUidUnknownPackets = rootNfqueueUidUnknownPackets;
            this.rootNfqueueLastIpFamily = rootNfqueueLastIpFamily;
            this.rootNfqueueLastProtocol = rootNfqueueLastProtocol;
            this.rootNfqueueLastHook = rootNfqueueLastHook;
            this.rootNfqueueLastUidKnown = rootNfqueueLastUidKnown;
            this.rootNfqueueLastUid = rootNfqueueLastUid;
            this.rootNfqueueLastQueueId = rootNfqueueLastQueueId;
            this.rootNfqueueLastPacketId = rootNfqueueLastPacketId;
            this.rootNfqueueVerdictSucceeded = rootNfqueueVerdictSucceeded;
            this.rootNfqueueVerdictFailedDefinite = rootNfqueueVerdictFailedDefinite;
            this.rootNfqueueVerdictOutcomeUnknown = rootNfqueueVerdictOutcomeUnknown;
            this.rootNfqueueIngressIdentityMissing = rootNfqueueIngressIdentityMissing;
            this.rootNfqueueGraphSubmitFailOpens = rootNfqueueGraphSubmitFailOpens;
            this.rootNfqueueNonOwnerBypasses = rootNfqueueNonOwnerBypasses;
            this.rootNfqueueDuplicateCompletionDrops = rootNfqueueDuplicateCompletionDrops;
            this.rootNfqueueStaleCompletionDrops = rootNfqueueStaleCompletionDrops;
            this.vpnTunFdAttached = vpnTunFdAttached;
            this.vpnDirectUdp4SocketAttached = vpnDirectUdp4SocketAttached;
            this.vpnDirectUdp4ProtectSucceeded = vpnDirectUdp4ProtectSucceeded;
            this.vpnDirectUdp4BindSucceeded = vpnDirectUdp4BindSucceeded;
            this.vpnTunIngressPackets = vpnTunIngressPackets;
            this.vpnTunUdp4TunOriginPackets = vpnTunUdp4TunOriginPackets;
            this.vpnFlowStackAdmissions = vpnFlowStackAdmissions;
            this.vpnDirectUdp4SendSucceeded = vpnDirectUdp4SendSucceeded;
            this.vpnDirectUdp4TransportFailed = vpnDirectUdp4TransportFailed;
            this.vpnFlowStackReturnPackets = vpnFlowStackReturnPackets;
            this.vpnFlowStackReturnProvenancePackets =
                    vpnFlowStackReturnProvenancePackets;
            this.vpnTunWriteCompletions = vpnTunWriteCompletions;
            this.vpnInfrastructureFaults = vpnInfrastructureFaults;
            this.vpnDuplicateOrStaleDrops = vpnDuplicateOrStaleDrops;
            this.productGraphWorkerCount = productGraphWorkerCount;
            this.productGraphHashSeed = productGraphHashSeed;
            this.productGraphHandoffCredits = productGraphHandoffCredits;
            this.productGraphVppWorkerCount = productGraphVppWorkerCount;
            this.productGraphVppMainCore = productGraphVppMainCore;
            this.productGraphVppWorker0ThreadIndex = productGraphVppWorker0ThreadIndex;
            this.productGraphVppWorker0Core = productGraphVppWorker0Core;
            this.productGraphVppWorker1ThreadIndex = productGraphVppWorker1ThreadIndex;
            this.productGraphVppWorker1Core = productGraphVppWorker1Core;
            this.productGraphEnabled = productGraphEnabled;
            this.productGraphAccepting = productGraphAccepting;
            this.productGraphWorkerLayoutReady = productGraphWorkerLayoutReady;
            this.productGraphObligationDebt = productGraphObligationDebt;
            this.productGraphBufferDebt = productGraphBufferDebt;
            this.productGraphHandoffDebt = productGraphHandoffDebt;
            this.policyRequestedRevision = policyRequestedRevision;
            this.policyActiveRevision = policyActiveRevision;
            this.policyGeneration = policyGeneration;
            this.policySnapshotHash = policySnapshotHash;
            this.policyWorker0Revision = policyWorker0Revision;
            this.policyWorker1Revision = policyWorker1Revision;
            this.policySnapshotEmpty = policySnapshotEmpty;
            this.policyDefaultPass = policyDefaultPass;
            this.policyGateClaimCount = policyGateClaimCount;
            this.policyL4RuleCount = policyL4RuleCount;
            this.policyLastApplyStatusCode = policyLastApplyStatusCode;
            this.policyMixedRevision = policyMixedRevision;
            this.policyArtifactMatch = policyArtifactMatch;
            this.policyGenerationMatch = policyGenerationMatch;
            this.policySnapshotIdentity = bounded(policySnapshotIdentity);
            this.policyGateSubjectUid = policyGateSubjectUid;
            this.policyGateNetworkContext = policyGateNetworkContext;
            this.policyGateBlocked = policyGateBlocked;
            this.policyGateReasonId = policyGateReasonId;
            this.policyGateRuleId = policyGateRuleId;
            this.policyDropRecords = policyDropRecords;
            this.policyLastDropRevision = policyLastDropRevision;
            this.policyLastDropRuleId = policyLastDropRuleId;
            this.policyLastDropCompletionAttempts = policyLastDropCompletionAttempts;
            this.policyLastDropUid = policyLastDropUid;
            this.policyLastDropNetworkContext = policyLastDropNetworkContext;
            this.policyLastDropReasonId = policyLastDropReasonId;
            this.policyLastDropVerdict = policyLastDropVerdict;
            this.policyLastDropWinner = policyLastDropWinner;
            this.policyLastDropUidKnown = policyLastDropUidKnown;
            this.policyLastDropDeviceDirection = policyLastDropDeviceDirection;
            this.policyL4ActiveRevision = policyL4ActiveRevision;
            this.policyL4RuleId = policyL4RuleId;
            this.policyL4MatchRecords = policyL4MatchRecords;
            this.policyL4NoMatchRecords = policyL4NoMatchRecords;
            this.policyL4LastMatchRevision = policyL4LastMatchRevision;
            this.policyL4LastMatchRuleId = policyL4LastMatchRuleId;
            this.policyL4SubjectUid = policyL4SubjectUid;
            this.policyL4NetworkContext = policyL4NetworkContext;
            this.policyL4IpFamily = policyL4IpFamily;
            this.policyL4IpProtocol = policyL4IpProtocol;
            this.policyL4Direction = policyL4Direction;
            this.policyL4Action = policyL4Action;
            this.policyL4Priority = policyL4Priority;
            this.policyL4Order = policyL4Order;
            this.policyL4ReasonId = policyL4ReasonId;
            this.policyL4LastMatchUid = policyL4LastMatchUid;
            this.policyL4LastMatchNetworkContext = policyL4LastMatchNetworkContext;
            this.policyL4LastMatchReasonId = policyL4LastMatchReasonId;
            this.policyL4LastMatchVerdict = policyL4LastMatchVerdict;
            this.policyL4LastMatchWinner = policyL4LastMatchWinner;
            this.policyL4LastMatchUidKnown = policyL4LastMatchUidKnown;
            this.policyL4LastMatchDeviceDirection = policyL4LastMatchDeviceDirection;
            this.policyL4LastMatchAction = policyL4LastMatchAction;
            this.policyL4LastEvaluationResult = policyL4LastEvaluationResult;
            this.policyL4LastEvaluationVerdict = policyL4LastEvaluationVerdict;
            this.policyL4LastEvaluationDeviceDirection = policyL4LastEvaluationDeviceDirection;
            this.policyL4TypedMatchPolicyKey = policyL4TypedMatchPolicyKey;
            this.policyL4TypedMatchProbeKey = policyL4TypedMatchProbeKey;
            this.policyL4LastEvaluationProbeKey = policyL4LastEvaluationProbeKey;
            this.policyL4ViewActive = viewValue(policyL4View, 0);
            this.policyL4ViewRuleCount = viewValue(policyL4View, 1);
            this.policyL4ViewMaxProbes = viewValue(policyL4View, 2);
            this.policyL4ViewLastMatchWinnerRank = viewValue(policyL4View, 3);
            this.policyL4ViewLastMatchProbes = viewValue(policyL4View, 4);
            this.policyL4ViewLastMatchCandidateCount = viewValue(policyL4View, 5);
            this.policyL4ViewLastNoMatchReason = viewValue(policyL4View, 6);
            this.controlAbiVersion = abiVersion;
            this.transportCode = code;
            this.vppRetval = legacyVppRetval;
            this.program = bounded(program);
            this.version = bounded(version);
            this.buildDate = "";
            this.buildDirectory = "";
        }

        /**
         * Source-compatible constructor for migration-only health tests.
         * Product JNI status is constructed from the fixed Product Core ABI.
         */
        public Status(int controlAbiVersion, int transportCode, int vppRetval,
                      String apiIdentity, String program, String version,
                      String buildDate, String buildDirectory) {
            this(controlAbiVersion, controlAbiVersion, transportCode, vppRetval, 0L,
                    false, false, false, false, false, false, "", apiIdentity,
                    version, "", program, version);
        }

        static Status unavailable() {
            return unavailable(-1L);
        }

        private static Status unavailable(long generation) {
            return new Status(-1, -1, -1, -1, generation, false, false, false,
                    false, false, false, "", "", "", "", "", "");
        }

        private static Status nativeFailure(Status previous, int code, String detail) {
            Status base = previous == null ? unavailable() : previous;
            return new Status(base.abiVersion, base.apiVersion, code, code, base.generation,
                    base.coreReady, base.adapterAvailable, base.protectionRunning,
                    base.pluginLoaded, base.vapiHandleLive, base.generationLive,
                    base.artifactId, base.apiIdentity, base.vppRevision, detail,
                    base.program, base.version,
                    base.policyL4TypedMatchPolicyKey,
                    base.policyL4TypedMatchProbeKey,
                    base.policyL4LastEvaluationProbeKey,
                    base.rootNfqueueQueueId,
                    base.rootNfqueueQueueLast, base.rootNfqueueLaneCount,
                    base.rootNfqueueReadyLaneMask, base.rootNfqueueGeneration,
                    base.rootNfqueueVerdictAttempts,
                    base.rootNfqueueInternalSettlements,
                    base.rootNfqueueBufferReturns,
                    base.rootNfqueueOriginLocalCompletions,
                    base.rootNfqueueOriginRemoteCompletions,
                    base.rootNfqueueLane0VerdictAttempts,
                    base.rootNfqueueLane1VerdictAttempts,
                    base.rootNfqueueInputPackets,
                    base.rootNfqueueOutputPackets,
                    base.rootNfqueueIpv4Packets,
                    base.rootNfqueueIpv6Packets,
                    base.rootNfqueueTcpPackets,
                    base.rootNfqueueUdpPackets,
                    base.rootNfqueueUidKnownPackets,
                    base.rootNfqueueUidUnknownPackets,
                    base.rootNfqueueLastIpFamily,
                    base.rootNfqueueLastProtocol,
                    base.rootNfqueueLastHook,
                    base.rootNfqueueLastUidKnown,
                    base.rootNfqueueLastUid,
                    base.rootNfqueueLastQueueId,
                    base.rootNfqueueLastPacketId,
                    base.rootNfqueueVerdictSucceeded,
                    base.rootNfqueueVerdictFailedDefinite,
                    base.rootNfqueueVerdictOutcomeUnknown,
                    base.rootNfqueueIngressIdentityMissing,
                    base.rootNfqueueGraphSubmitFailOpens,
                    base.rootNfqueueNonOwnerBypasses,
                    base.rootNfqueueDuplicateCompletionDrops,
                    base.rootNfqueueStaleCompletionDrops,
                    base.vpnTunFdAttached,
                    base.vpnDirectUdp4SocketAttached,
                    base.vpnDirectUdp4ProtectSucceeded,
                    base.vpnDirectUdp4BindSucceeded,
                    base.vpnTunIngressPackets,
                    base.vpnTunUdp4TunOriginPackets,
                    base.vpnFlowStackAdmissions,
                    base.vpnDirectUdp4SendSucceeded,
                    base.vpnDirectUdp4TransportFailed,
                    base.vpnFlowStackReturnPackets,
                    base.vpnFlowStackReturnProvenancePackets,
                    base.vpnTunWriteCompletions,
                    base.vpnInfrastructureFaults,
                    base.vpnDuplicateOrStaleDrops,
                    base.productGraphWorkerCount,
                    base.productGraphHashSeed,
                    base.productGraphHandoffCredits,
                    base.productGraphVppWorkerCount,
                    base.productGraphVppMainCore,
                    base.productGraphVppWorker0ThreadIndex,
                    base.productGraphVppWorker0Core,
                    base.productGraphVppWorker1ThreadIndex,
                    base.productGraphVppWorker1Core,
                    base.productGraphEnabled,
                    base.productGraphAccepting,
                    base.productGraphWorkerLayoutReady,
                    base.productGraphObligationDebt,
                    base.productGraphBufferDebt,
                    base.productGraphHandoffDebt,
                    base.policyRequestedRevision,
                    base.policyActiveRevision,
                    base.policyGeneration,
                    base.policySnapshotHash,
                    base.policyWorker0Revision,
                    base.policyWorker1Revision,
                    base.policySnapshotEmpty,
                    base.policyDefaultPass,
                    base.policyGateClaimCount,
                    base.policyL4RuleCount,
                    base.policyLastApplyStatusCode,
                    base.policyMixedRevision,
                    base.policyArtifactMatch,
                    base.policyGenerationMatch,
                    base.policySnapshotIdentity,
                    base.policyGateSubjectUid,
                    base.policyGateNetworkContext,
                    base.policyGateBlocked,
                    base.policyGateReasonId,
                    base.policyGateRuleId,
                    base.policyDropRecords,
                    base.policyLastDropRevision,
                    base.policyLastDropRuleId,
                    base.policyLastDropCompletionAttempts,
                    base.policyLastDropUid,
                    base.policyLastDropNetworkContext,
                    base.policyLastDropReasonId,
                    base.policyLastDropVerdict,
                    base.policyLastDropWinner,
                    base.policyLastDropUidKnown,
                    base.policyLastDropDeviceDirection,
                    base.policyL4ActiveRevision,
                    base.policyL4RuleId,
                    base.policyL4MatchRecords,
                    base.policyL4NoMatchRecords,
                    base.policyL4LastMatchRevision,
                    base.policyL4LastMatchRuleId,
                    base.policyL4SubjectUid,
                    base.policyL4NetworkContext,
                    base.policyL4IpFamily,
                    base.policyL4IpProtocol,
                    base.policyL4Direction,
                    base.policyL4Action,
                    base.policyL4Priority,
                    base.policyL4Order,
                    base.policyL4ReasonId,
                    base.policyL4LastMatchUid,
                    base.policyL4LastMatchNetworkContext,
                    base.policyL4LastMatchReasonId,
                    base.policyL4LastMatchVerdict,
                    base.policyL4LastMatchWinner,
                    base.policyL4LastMatchUidKnown,
                    base.policyL4LastMatchDeviceDirection,
                    base.policyL4LastMatchAction,
                    base.policyL4LastEvaluationResult,
                    base.policyL4LastEvaluationVerdict,
                    base.policyL4LastEvaluationDeviceDirection,
                    base.policyL4ViewActive,
                    base.policyL4ViewRuleCount,
                    base.policyL4ViewMaxProbes,
                    base.policyL4ViewLastMatchWinnerRank,
                    base.policyL4ViewLastMatchProbes,
                    base.policyL4ViewLastMatchCandidateCount,
                    base.policyL4ViewLastNoMatchReason);
        }

        private static int viewValue(int[] values, int index) {
            return values != null && values.length > index ? values[index] : 0;
        }

        private static String bounded(String value) {
            return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }
    }
}
