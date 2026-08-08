package com.sakamoto.snort.androidruntime;

/** Stable, versioned product-control vocabulary shared by the Activity and service. */
public final class RuntimeControlProtocol {
    public static final int VERSION = 1;
    public static final String NAME = "android-runtime-control/v1";

    public static final String ACTION_START = "start";
    public static final String ACTION_QUERY = "query";
    public static final String ACTION_STOP = "stop";

    public static final String EXTRA_PROTOCOL_VERSION = "runtimeControlProtocolVersion";
    public static final String EXTRA_ACTION = "runtimeControlAction";
    public static final String EXTRA_PROFILE = "runtimeProfile";
    public static final String EXTRA_REQUEST_ID = "runtimeRequestId";
    /** Monotonic elapsed ordering lets the service discard delayed stale stop intents. */
    public static final String EXTRA_REQUEST_TIME_MILLIS = "runtimeRequestTimeMillis";
    /** Debug-only fault seam; ignored unless the app is debuggable. */
    public static final String EXTRA_CLEANUP_FAULT = "runtimeCleanupFault";

    private RuntimeControlProtocol() {}
}
