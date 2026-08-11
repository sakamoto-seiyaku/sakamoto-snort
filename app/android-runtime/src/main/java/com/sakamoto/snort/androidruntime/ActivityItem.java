package com.sakamoto.snort.androidruntime;

/** Product-facing Activity row for verdict evidence and L4 rule prefill. */
public final class ActivityItem {
    public final ApplicationSubjectId subjectId;
    public final String appLabel;
    public final String packageName;
    public final long timestampMillis;
    public final String remoteIp;
    public final String protocol;
    public final int remotePort;
    public final String devicePacketDirection;
    public final String flowDirection;
    public final long packets;
    public final long bytes;
    public final String verdict;
    public final String winner;
    public final long policyRevision;
    public final long ruleId;
    public final int reasonId;
    public final String evidenceSource;
    public final boolean detailLossy;

    public ActivityItem(ApplicationSubjectId subjectId, String appLabel, String packageName,
                        long timestampMillis, String remoteIp, String protocol, int remotePort,
                        String devicePacketDirection, String flowDirection, long packets,
                        long bytes, String verdict, String winner, long policyRevision,
                        long ruleId, int reasonId, String evidenceSource, boolean detailLossy) {
        if (subjectId == null) {
            throw new IllegalArgumentException("subjectId is required");
        }
        if (remotePort < 0 || remotePort > 65535) {
            throw new IllegalArgumentException("remotePort must be u16 or zero when unknown");
        }
        this.subjectId = subjectId;
        this.appLabel = bounded(appLabel);
        this.packageName = bounded(packageName);
        this.timestampMillis = Math.max(0L, timestampMillis);
        this.remoteIp = bounded(remoteIp);
        this.protocol = bounded(protocol);
        this.remotePort = remotePort;
        this.devicePacketDirection = bounded(devicePacketDirection);
        this.flowDirection = bounded(flowDirection);
        this.packets = Math.max(0L, packets);
        this.bytes = Math.max(0L, bytes);
        this.verdict = bounded(verdict);
        this.winner = bounded(winner);
        this.policyRevision = Math.max(0L, policyRevision);
        this.ruleId = Math.max(0L, ruleId);
        this.reasonId = Math.max(0, reasonId);
        this.evidenceSource = bounded(evidenceSource);
        this.detailLossy = detailLossy;
    }

    public static ActivityItem policyDrop(ApplicationSubjectId subjectId, String appLabel,
                                          String packageName, long timestampMillis,
                                          String remoteIp, String protocol, int remotePort,
                                          String devicePacketDirection, long policyRevision,
                                          String winner, long ruleId, int reasonId) {
        return new ActivityItem(subjectId, appLabel, packageName, timestampMillis, remoteIp,
                protocol, remotePort, devicePacketDirection, "none", 1L, 0L,
                "drop", winner, policyRevision, ruleId, reasonId,
                "bounded_activity_accumulator", true);
    }

    public static ActivityItem allowedFlow(ApplicationSubjectId subjectId, String appLabel,
                                           String packageName, long timestampMillis,
                                           String remoteIp, String protocol, int remotePort,
                                           String devicePacketDirection, String flowDirection,
                                           long packets, long bytes, long policyRevision,
                                           String winner) {
        return new ActivityItem(subjectId, appLabel, packageName, timestampMillis, remoteIp,
                protocol, remotePort, devicePacketDirection, flowDirection, packets, bytes,
                "pass_next", winner, policyRevision, 0L, 0,
                "flow_entry", false);
    }

    public boolean canPrefillL4Rule() {
        return "drop".equals(verdict) && remotePort > 0 && !remoteIp.isEmpty();
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
