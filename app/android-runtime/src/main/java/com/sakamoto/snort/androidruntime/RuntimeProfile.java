package com.sakamoto.snort.androidruntime;

/** Mutually-exclusive core-runtime profiles owned by one RuntimeService. */
public enum RuntimeProfile {
    ROOT("root", "Root"),
    VPN("vpn", "VPN");

    public final String wireName;
    public final String displayName;

    RuntimeProfile(String wireName, String displayName) {
        this.wireName = wireName;
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

    public boolean hasProductPacketAdapter() {
        return this == ROOT;
    }

    public String adapterUnavailableErrorCode() {
        return this == VPN ? "vpn_adapter_unavailable" : "";
    }

    public String adapterUnavailableMessage() {
        return this == VPN
                ? "VPN/TUN product packet adapter is not integrated yet"
                : "";
    }

    @Override
    public String toString() {
        return wireName;
    }
}
