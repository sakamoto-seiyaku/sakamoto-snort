package com.sakamoto.snort.androidruntime;

/**
 * Product Packet Adapter contract at the RuntimeService seam.
 *
 * <p>The selected Runtime Profile is only an identity. Adapter launch
 * readiness, platform I/O shape, completion ownership, transport attribution,
 * and UID-miss handling live here so callers cannot infer VPN readiness from
 * {@code VpnService} inheritance or plugin/artifact presence.</p>
 */
public final class ProductPacketAdapterContract {
    public static final String UID_MISS_UNKNOWN_APPLICATION_NO_HOLD =
            "unknown-application-no-hold";
    public static final String TRANSPORT_OUTCOME_SEPARATE =
            "transport-outcome-separate";
    public static final String ROOT_ADAPTER = "root-nfqueue";
    public static final String VPN_ADAPTER = "vpn-flow-stack";

    public final RuntimeProfile profile;
    public final String adapterName;
    public final String platformInterface;
    public final String completionModel;
    public final String transportOutcomeModel;
    public final String uidMissHandling;
    public final boolean requiresVpnPlatformSession;
    /** Root NFQUEUE must be authorised before the Product VPP is launched. */
    public final boolean requiresRootAuthorization;
    /** Exact VAPI expectation after one successful Product VPP launch. */
    public final boolean adapterReadyOnStart;
    /** Exact VAPI expectation after the profile-specific Android fd handoff. */
    public final boolean adapterReadyAfterHandoff;
    public final boolean enableIpv6;
    public final boolean productLaunchAllowed;
    public final String unavailableErrorCode;
    public final String unavailableMessage;

    private ProductPacketAdapterContract(RuntimeProfile profile, String adapterName,
                                         String platformInterface, String completionModel,
                                         String transportOutcomeModel, String uidMissHandling,
                                         boolean requiresVpnPlatformSession,
                                         boolean requiresRootAuthorization,
                                         boolean adapterReadyOnStart,
                                         boolean adapterReadyAfterHandoff,
                                         boolean enableIpv6,
                                         boolean productLaunchAllowed,
                                         String unavailableErrorCode,
                                         String unavailableMessage) {
        this.profile = profile == null ? RuntimeProfile.ROOT : profile;
        this.adapterName = text(adapterName);
        this.platformInterface = text(platformInterface);
        this.completionModel = text(completionModel);
        this.transportOutcomeModel = text(transportOutcomeModel);
        this.uidMissHandling = text(uidMissHandling);
        this.requiresVpnPlatformSession = requiresVpnPlatformSession;
        this.requiresRootAuthorization = requiresRootAuthorization;
        this.adapterReadyOnStart = adapterReadyOnStart;
        this.adapterReadyAfterHandoff = adapterReadyAfterHandoff;
        this.enableIpv6 = enableIpv6;
        this.productLaunchAllowed = productLaunchAllowed;
        this.unavailableErrorCode = text(unavailableErrorCode);
        this.unavailableMessage = text(unavailableMessage);
    }

    public static ProductPacketAdapterContract forProfile(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        if (selected == RuntimeProfile.VPN) {
            return new ProductPacketAdapterContract(selected, VPN_ADAPTER,
                    "VpnService TUN with owner-local HEV/lwIP (not implemented)",
                    "single-writer TUN completion",
                    TRANSPORT_OUTCOME_SEPARATE,
                    UID_MISS_UNKNOWN_APPLICATION_NO_HOLD,
                    true,
                    false,
                    false,
                    false,
                    true,
                    false,
                    "vpn_flow_stack_not_ready",
                    "VPN protection is not available in this build.");
        }
        return new ProductPacketAdapterContract(selected, ROOT_ADAPTER,
                "Root NFQUEUE lanes",
                "origin-lane NFQUEUE verdict completion",
                "kernel verdict outcome",
                UID_MISS_UNKNOWN_APPLICATION_NO_HOLD,
                false,
                true,
                true,
                true,
                false,
                true,
                "",
                "");
    }

    public boolean separatesTransportOutcome() {
        return TRANSPORT_OUTCOME_SEPARATE.equals(transportOutcomeModel);
    }

    private static String text(String value) {
        return BoundedText.value(value, BoundedText.MAX_LENGTH);
    }
}
