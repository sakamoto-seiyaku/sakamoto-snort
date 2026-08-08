package com.sakamoto.snort.androidruntime;

/** Mutually-exclusive packet-capture profiles owned by one RuntimeService. */
public enum RuntimeProfile {
    ROOT("root", "nfqueue", "libnfqueue_poc_plugin.so", "Root/NFQUEUE"),
    VPN("vpn", "tun", "libtun_poc_plugin.so", "VPN/TUN");

    public final String wireName;
    public final String adapter;
    public final String adapterArtifact;
    public final String displayName;

    RuntimeProfile(String wireName, String adapter, String adapterArtifact, String displayName) {
        this.wireName = wireName;
        this.adapter = adapter;
        this.adapterArtifact = adapterArtifact;
        this.displayName = displayName;
    }

    public static RuntimeProfile parse(String value) {
        if (value != null) {
            for (RuntimeProfile profile : values()) {
                if (profile.wireName.equalsIgnoreCase(value.trim())) {
                    return profile;
                }
            }
        }
        throw new IllegalArgumentException("unknown runtime profile: " + value);
    }

    @Override
    public String toString() {
        return wireName;
    }
}
