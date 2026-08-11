package com.sakamoto.snort.androidruntime;

/** Stable, versioned product-control vocabulary shared by the Activity and service. */
public final class RuntimeControlProtocol {
    public static final int VERSION = 1;
    public static final String NAME = "android-runtime-control/v1";

    public static final String ACTION_START = "start";
    public static final String ACTION_QUERY = "query";
    public static final String ACTION_STOP = "stop";
    public static final String ACTION_PRODUCT_PROFILE_SELECT = "product_profile_select";
    public static final String ACTION_PRODUCT_BIND_APP = "product_bind_app";
    public static final String ACTION_PRODUCT_UNBIND_APP = "product_unbind_app";
    public static final String ACTION_PRODUCT_SET_NETWORK_GATE =
            "product_set_network_gate";

    public static final String EXTRA_PROTOCOL_VERSION = "runtimeControlProtocolVersion";
    public static final String EXTRA_ACTION = "runtimeControlAction";
    public static final String EXTRA_PROFILE = "runtimeProfile";
    public static final String EXTRA_APPLICATION_SUBJECT = "applicationSubjectId";
    public static final String EXTRA_NETWORK_CONTEXT = "networkContext";
    public static final String EXTRA_NETWORK_GATE_BLOCKED = "networkGateBlocked";
    public static final String EXTRA_REQUEST_ID = "runtimeRequestId";
    /** Monotonic elapsed ordering lets the service discard delayed stale stop intents. */
    public static final String EXTRA_REQUEST_TIME_MILLIS = "runtimeRequestTimeMillis";
    /** Debug-only fault seam; ignored unless the app is debuggable. */
    public static final String EXTRA_CLEANUP_FAULT = "runtimeCleanupFault";

    private RuntimeControlProtocol() {}
}
