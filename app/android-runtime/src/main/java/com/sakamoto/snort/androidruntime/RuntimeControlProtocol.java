package com.sakamoto.snort.androidruntime;

/** Stable, versioned product-control vocabulary shared by the Activity and service. */
public final class RuntimeControlProtocol {
    public static final int VERSION = 1;
    public static final String NAME = "android-runtime-control/v1";

    public static final String ACTION_START = "start";
    public static final String ACTION_QUERY = "query";
    public static final String ACTION_STOP = "stop";
    public static final String ACTION_PROTECTION_PAUSE = "protection_pause";
    public static final String ACTION_PROTECTION_RESUME = "protection_resume";
    public static final String ACTION_PRODUCT_PROFILE_SELECT = "product_profile_select";
    public static final String ACTION_PRODUCT_BIND_APP = "product_bind_app";
    public static final String ACTION_PRODUCT_UNBIND_APP = "product_unbind_app";
    public static final String ACTION_PRODUCT_SET_NETWORK_GATE =
            "product_set_network_gate";
    public static final String ACTION_PRODUCT_SET_L4_RULE =
            "product_set_l4_rule";
    public static final String ACTION_PRODUCT_APPLY_EMPTY_POLICY =
            "product_apply_empty_policy";

    public static final String EXTRA_PROTOCOL_VERSION = "runtimeControlProtocolVersion";
    public static final String EXTRA_ACTION = "runtimeControlAction";
    public static final String EXTRA_PROFILE = "runtimeProfile";
    public static final String EXTRA_APPLICATION_SUBJECT = "applicationSubjectId";
    public static final String EXTRA_NETWORK_CONTEXT = "networkContext";
    public static final String EXTRA_NETWORK_GATE_BLOCKED = "networkGateBlocked";
    public static final String EXTRA_L4_FAMILY = "l4Family";
    public static final String EXTRA_L4_SOURCE_CIDR = "l4SourceCidr";
    public static final String EXTRA_L4_DESTINATION_CIDR = "l4DestinationCidr";
    public static final String EXTRA_L4_SOURCE_PORT_FIRST = "l4SourcePortFirst";
    public static final String EXTRA_L4_SOURCE_PORT_LAST = "l4SourcePortLast";
    public static final String EXTRA_L4_DESTINATION_PORT_FIRST = "l4DestinationPortFirst";
    public static final String EXTRA_L4_DESTINATION_PORT_LAST = "l4DestinationPortLast";
    public static final String EXTRA_L4_IP_PROTOCOL = "l4IpProtocol";
    public static final String EXTRA_L4_PACKET_DIRECTION = "l4PacketDirection";
    public static final String EXTRA_L4_ACTION = "l4Action";
    public static final String EXTRA_L4_PRIORITY = "l4Priority";
    public static final String EXTRA_L4_ORDER = "l4Order";
    public static final String EXTRA_REQUEST_ID = "runtimeRequestId";
    /** Monotonic elapsed ordering lets the service discard delayed stale stop intents. */
    public static final String EXTRA_REQUEST_TIME_MILLIS = "runtimeRequestTimeMillis";
    /** Debug-only fault seam; ignored unless the app is debuggable. */
    public static final String EXTRA_CLEANUP_FAULT = "runtimeCleanupFault";
    /** Debug-only Root NFQUEUE fault mode; ignored unless the app is debuggable. */
    public static final String EXTRA_ROOT_NFQUEUE_FAULT_MODE =
            "runtimeRootNfqueueFaultMode";
    /** Debug-only VPN fault mode; ignored unless the app is debuggable. */
    public static final String EXTRA_VPN_FAULT_MODE =
            "runtimeVpnFaultMode";
    /** Debug-only VPN lifecycle/fd event; ignored unless the app is debuggable. */
    public static final String EXTRA_VPN_FAULT_EVENT =
            "runtimeVpnFaultEvent";
    /** Debug-only one-shot typed policy mutation fault; ignored unless debuggable. */
    public static final String EXTRA_POLICY_MUTATION_FAULT_MODE =
            "runtimePolicyMutationFaultMode";

    private RuntimeControlProtocol() {}
}
