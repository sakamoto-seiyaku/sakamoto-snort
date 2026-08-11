package com.sakamoto.snort.androidruntime;

/** Product-facing app row. Identity is the complete Android Linux UID subject. */
public final class AppSummary {
    public final ApplicationSubjectId subjectId;
    public final String packageName;
    public final String label;
    public final String profileLabel;
    public final int userId;
    public final int fullUid;
    public final boolean available;
    public final boolean bound;
    public final boolean wifiGateBlocked;
    public final boolean mobileGateBlocked;
    public final boolean vpnGateBlocked;
    public final int l4RuleCount;

    public AppSummary(ApplicationSubjectId subjectId, String packageName, String label,
                      String profileLabel, int userId, int fullUid, boolean available,
                      boolean bound, boolean wifiGateBlocked, boolean mobileGateBlocked,
                      boolean vpnGateBlocked, int l4RuleCount) {
        if (subjectId == null) {
            throw new IllegalArgumentException("subjectId is required");
        }
        this.subjectId = subjectId;
        this.packageName = bounded(packageName == null || packageName.trim().isEmpty()
                ? "(unknown package)" : packageName);
        this.label = bounded(label == null || label.trim().isEmpty()
                ? this.packageName : label);
        this.profileLabel = bounded(profileLabel);
        this.userId = userId;
        this.fullUid = fullUid;
        this.available = available;
        this.bound = bound;
        this.wifiGateBlocked = wifiGateBlocked;
        this.mobileGateBlocked = mobileGateBlocked;
        this.vpnGateBlocked = vpnGateBlocked;
        this.l4RuleCount = Math.max(0, l4RuleCount);
    }

    public static AppSummary fromCatalogRow(ProductCatalogFormatter.EntryRow row) {
        if (row == null) {
            throw new IllegalArgumentException("row is required");
        }
        return new AppSummary(row.subjectId, row.packageName, row.label, row.profileLabel,
                row.userId, row.fullUid, "available".equals(row.availability), row.bound,
                row.wifiGateBlocked, row.mobileGateBlocked, row.vpnGateBlocked,
                row.l4RuleCount);
    }

    public boolean gateBlocked(AuthoringPolicyBundle.NetworkContextId context) {
        if (context == AuthoringPolicyBundle.NetworkContextId.WIFI) {
            return wifiGateBlocked;
        }
        if (context == AuthoringPolicyBundle.NetworkContextId.MOBILE) {
            return mobileGateBlocked;
        }
        return vpnGateBlocked;
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
