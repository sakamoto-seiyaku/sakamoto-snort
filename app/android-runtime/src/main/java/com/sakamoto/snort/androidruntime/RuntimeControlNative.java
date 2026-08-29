package com.sakamoto.snort.androidruntime;

/** JNI facade for the Rust-owned Product Core control session. */
public final class RuntimeControlNative {
    public static final int CONTROL_ABI_VERSION = 1;
    private static final int STATUS_VALUE_COUNT = 14;
    private static final int CONNECT_VALUE_COUNT = STATUS_VALUE_COUNT + 1;
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
                    "", "");
        } catch (RuntimeException error) {
            return Status.unavailable();
        }
    }

    private static int parseInt(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static long parseLong(String value, long fallback) {
        try {
            return Long.parseLong(value);
        } catch (Exception ignored) {
            return fallback;
        }
    }

    private static boolean parseBoolean(String value) {
        return "1".equals(value) || "true".equalsIgnoreCase(value);
    }

    private static native String[] nativeConnect(String apiSocket, long generation);

    private static native String[] nativeQuery(long handle, long generation);

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

        @Override
        public synchronized void close() {
            if (nativeHandle == 0L) {
                return;
            }
            long handle = nativeHandle;
            nativeHandle = 0L;
            try {
                nativeDisconnect(handle);
            } finally {
                nativeDestroy(handle);
            }
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

        private Status(int abiVersion, int apiVersion, int code, int legacyVppRetval,
                       long generation, boolean coreReady, boolean adapterAvailable,
                       boolean protectionRunning, boolean pluginLoaded,
                       boolean vapiHandleLive, boolean generationLive,
                       String artifactId, String apiIdentity, String vppRevision,
                       String errorDetail, String program, String version) {
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

        private static String bounded(String value) {
            return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }
    }
}
