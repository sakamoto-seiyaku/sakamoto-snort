package com.sakamoto.snort.androidruntime;

/** Stable product-facing capability flags. UI code must not infer these from VPP internals. */
public final class CapabilitySet {
    public final boolean rootProfile;
    public final boolean vpnProfile;
    public final boolean profileSwitching;
    public final boolean networkGate;
    public final boolean l4Rules;
    public final boolean activity;
    public final boolean protocolRules;

    public CapabilitySet(boolean rootProfile, boolean vpnProfile, boolean profileSwitching,
                         boolean networkGate, boolean l4Rules, boolean activity,
                         boolean protocolRules) {
        this.rootProfile = rootProfile;
        this.vpnProfile = vpnProfile;
        this.profileSwitching = profileSwitching;
        this.networkGate = networkGate;
        this.l4Rules = l4Rules;
        this.activity = activity;
        this.protocolRules = protocolRules;
    }

    public static CapabilitySet androidL4(boolean rootProfile, boolean vpnProfile) {
        return new CapabilitySet(rootProfile, vpnProfile,
                rootProfile && vpnProfile, true, true, true, false);
    }

    public boolean supports(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        return selected == RuntimeProfile.VPN ? vpnProfile : rootProfile;
    }
}
