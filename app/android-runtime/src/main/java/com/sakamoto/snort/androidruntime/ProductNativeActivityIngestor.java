package com.sakamoto.snort.androidruntime;

/** Maps native runtime activity facts into product ActivityItem rows. */
public final class ProductNativeActivityIngestor {
    private ProductNativeActivityIngestor() {}

    public static final class NativePolicyDropRecord {
        public final long totalRecords;
        public final boolean hasLastRecord;
        public final int linuxUid;
        public final boolean uidKnown;
        public final int networkContext;
        public final String stage;
        public final int reasonId;
        public final long ruleId;
        public final long revision;

        public NativePolicyDropRecord(long totalRecords, boolean hasLastRecord, int linuxUid,
                                      boolean uidKnown, int networkContext, String stage,
                                      int reasonId, long ruleId, long revision) {
            this.totalRecords = Math.max(0L, totalRecords);
            this.hasLastRecord = hasLastRecord;
            this.linuxUid = Math.max(0, linuxUid);
            this.uidKnown = uidKnown;
            this.networkContext = Math.max(0, networkContext);
            this.stage = BoundedText.value(stage == null ? "" : stage,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.reasonId = Math.max(0, reasonId);
            this.ruleId = Math.max(0L, ruleId);
            this.revision = Math.max(0L, revision);
        }
    }

    public static boolean shouldIngest(NativePolicyDropRecord record, RuntimeProfile profile,
                                       RuntimeProfile previousProfile, long previousGeneration,
                                       long currentGeneration, long previousTotalRecords) {
        if (record == null || !record.hasLastRecord || record.totalRecords <= 0L) {
            return false;
        }
        if (profile != previousProfile || currentGeneration != previousGeneration) {
            return true;
        }
        return record.totalRecords > previousTotalRecords;
    }

    public static ActivityItem toActivityItem(NativePolicyDropRecord record,
                                              RuntimeProfile profile, long timestampMillis) {
        if (record == null || !record.hasLastRecord) {
            return null;
        }
        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(record.linuxUid);
        String label = record.uidKnown ? subject.encode() : "Unknown Application";
        String packageName = record.uidKnown ? "(native attributed app)" : "(unknown package)";
        return new ActivityItem(subject, label, packageName, timestampMillis,
                "", "", 0, devicePacketDirection(profile), "none", 1L, 0L,
                "drop", record.stage, record.revision, record.ruleId, record.reasonId,
                "native_policy_drop_activity", true);
    }

    private static String devicePacketDirection(RuntimeProfile profile) {
        return profile == RuntimeProfile.VPN ? "vpn_outbound_or_return" : "root_nfqueue";
    }
}
