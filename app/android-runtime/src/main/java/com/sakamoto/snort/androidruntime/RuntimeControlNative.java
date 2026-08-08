package com.sakamoto.snort.androidruntime;

/** JNI facade for the versioned generated-VAPI core control shim. */
public final class RuntimeControlNative {
    public static final int CONTROL_ABI_VERSION = 1;
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

    public static Status query(String apiSocket) {
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
