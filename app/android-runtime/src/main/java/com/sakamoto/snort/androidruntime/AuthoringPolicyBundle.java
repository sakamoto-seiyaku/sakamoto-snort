package com.sakamoto.snort.androidruntime;

/** Minimal S50 bundle shell: empty stage-owned rule families under one revision. */
public final class AuthoringPolicyBundle {
    public static final int SCHEMA_VERSION = 1;

    public final int schemaVersion;
    public final long revision;
    public final String source;
    public final int gateEntryCount;
    public final int l4RuleCount;
    public final int protocolRuleCount;

    private AuthoringPolicyBundle(int schemaVersion, long revision, String source, int gateEntryCount,
                                  int l4RuleCount, int protocolRuleCount) {
        this.schemaVersion = schemaVersion;
        this.revision = revision;
        this.source = source == null ? "" : source;
        this.gateEntryCount = gateEntryCount;
        this.l4RuleCount = l4RuleCount;
        this.protocolRuleCount = protocolRuleCount;
    }

    public static AuthoringPolicyBundle empty() {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, 0L, "", 0, 0, 0);
    }

    public boolean isEmpty() {
        return gateEntryCount == 0 && l4RuleCount == 0 && protocolRuleCount == 0;
    }
}
