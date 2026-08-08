package com.sakamoto.snort.androidruntime;

import java.util.concurrent.Callable;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** JNI facade for the versioned generated-VAPI core control shim. */
public final class RuntimeControlNative {
    public static final int CONTROL_ABI_VERSION = 1;
    private static final long QUERY_TIMEOUT_MILLIS = 2500L;
    private static final boolean LOADED;
    /**
     * The generated VAPI call is blocking native work. Keep at most one call
     * in flight and one caller waiting behind it; Activity refreshes are
     * intentionally back-pressured instead of growing an unbounded queue.
     */
    private static final ExecutorService QUERY_EXECUTOR = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(1),
            runnable -> {
                Thread thread = new Thread(runnable, "sakamoto-vapi-query");
                thread.setDaemon(true);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());

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

    public static Status query(String apiSocket) {
        if (!LOADED || apiSocket == null || apiSocket.trim().isEmpty()) {
            return Status.unavailable();
        }
        final Future<Status> request;
        try {
            request = QUERY_EXECUTOR.submit(new Callable<Status>() {
                @Override
                public Status call() {
                    return queryNative(apiSocket);
                }
            });
        } catch (RejectedExecutionException error) {
            return Status.unavailable();
        }
        try {
            return request.get(QUERY_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException error) {
            request.cancel(true);
            return Status.unavailable();
        } catch (Exception error) {
            return Status.unavailable();
        }
    }

    private static Status queryNative(String apiSocket) {
        if (!LOADED || apiSocket == null || apiSocket.trim().isEmpty()) {
            return Status.unavailable();
        }
        try {
            String[] values = nativeQuery(apiSocket);
            if (values == null || values.length < 8) {
                return Status.unavailable();
            }
            return new Status(parse(values[0], -1), parse(values[6], -1), parse(values[7], -1),
                    values[1], values[2], values[3], values[4], values[5]);
        } catch (RuntimeException error) {
            return Status.unavailable();
        }
    }

    private static native String[] nativeQuery(String apiSocket);

    private static int parse(String value, int fallback) {
        try {
            return Integer.parseInt(value);
        } catch (Exception ignored) {
            return fallback;
        }
    }

    public static final class Status {
        public final int controlAbiVersion;
        public final int transportCode;
        public final int vppRetval;
        public final String apiIdentity;
        public final String program;
        public final String version;
        public final String buildDate;
        public final String buildDirectory;

        public Status(int controlAbiVersion, int transportCode, int vppRetval, String apiIdentity,
                      String program, String version, String buildDate, String buildDirectory) {
            this.controlAbiVersion = controlAbiVersion;
            this.transportCode = transportCode;
            this.vppRetval = vppRetval;
            this.apiIdentity = bounded(apiIdentity);
            this.program = bounded(program);
            this.version = bounded(version);
            this.buildDate = bounded(buildDate);
            this.buildDirectory = bounded(buildDirectory);
        }

        static Status unavailable() {
            return new Status(-1, -1, -1, "", "", "", "", "");
        }

        private static String bounded(String value) {
            return BoundedText.value(value, RuntimeSnapshot.MAX_TEXT_LENGTH);
        }
    }
}
