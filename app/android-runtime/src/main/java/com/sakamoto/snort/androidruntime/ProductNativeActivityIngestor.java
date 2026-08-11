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

    public static final class NativeAllowedFlowRecord {
        public final long totalRecords;
        public final boolean hasLastRecord;
        public final int linuxUid;
        public final boolean uidKnown;
        public final int networkContext;
        public final String sourceAddress;
        public final String destinationAddress;
        public final int ipProtocol;
        public final int sourcePort;
        public final int destinationPort;
        public final boolean portsAvailable;
        public final String deviceDirection;
        public final String flowDirection;
        public final long policyRevision;
        public final long packets;
        public final long bytes;
        public final String protocolRecognitionState;
        public final String applicationProtocolKey;
        public final String applicationProtocolCategory;
        public final ProtocolRecognitionSequence recognitionSequence;
        public final String protocolRecognitionSequence;
        public final int protocolPayloadPackets;

        public NativeAllowedFlowRecord(long totalRecords, boolean hasLastRecord,
                                       int linuxUid, boolean uidKnown, int networkContext,
                                       String sourceAddress, String destinationAddress,
                                       int ipProtocol, int sourcePort, int destinationPort,
                                       boolean portsAvailable, String deviceDirection,
                                       String flowDirection, long policyRevision,
                                       long packets, long bytes,
                                       String protocolRecognitionState,
                                       String applicationProtocolKey,
                                       String applicationProtocolCategory,
                                       String protocolRecognitionSequence,
                                       int protocolPayloadPackets) {
            this.totalRecords = Math.max(0L, totalRecords);
            this.hasLastRecord = hasLastRecord;
            this.linuxUid = Math.max(0, linuxUid);
            this.uidKnown = uidKnown;
            this.networkContext = Math.max(0, networkContext);
            this.sourceAddress = BoundedText.value(sourceAddress == null ? "" : sourceAddress,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.destinationAddress = BoundedText.value(
                    destinationAddress == null ? "" : destinationAddress,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.ipProtocol = Math.max(0, ipProtocol);
            this.sourcePort = clampPort(sourcePort);
            this.destinationPort = clampPort(destinationPort);
            this.portsAvailable = portsAvailable;
            this.deviceDirection = BoundedText.value(deviceDirection == null ? ""
                    : deviceDirection, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.flowDirection = BoundedText.value(flowDirection == null ? ""
                    : flowDirection, RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.policyRevision = Math.max(0L, policyRevision);
            this.packets = Math.max(0L, packets);
            this.bytes = Math.max(0L, bytes);
            this.protocolRecognitionState = BoundedText.value(
                    protocolRecognitionState == null ? "" : protocolRecognitionState,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.applicationProtocolKey = BoundedText.value(
                    applicationProtocolKey == null ? "" : applicationProtocolKey,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.applicationProtocolCategory = BoundedText.value(
                    applicationProtocolCategory == null ? "" : applicationProtocolCategory,
                    RuntimeSnapshot.MAX_TEXT_LENGTH);
            this.recognitionSequence =
                    ProtocolRecognitionSequence.parse(protocolRecognitionSequence);
            this.protocolRecognitionSequence = this.recognitionSequence.wire();
            this.protocolPayloadPackets = Math.max(0, protocolPayloadPackets);
        }

        public ProtocolRecognitionProjection protocolRecognition() {
            return ProtocolRecognitionProjection.of(protocolRecognitionState,
                    applicationProtocolKey, applicationProtocolCategory,
                    recognitionSequence, protocolPayloadPackets);
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

    public static boolean shouldIngest(NativeAllowedFlowRecord record, RuntimeProfile profile,
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

    public static ActivityItem toActivityItem(NativeAllowedFlowRecord record,
                                              RuntimeProfile profile, long timestampMillis) {
        if (record == null || !record.hasLastRecord) {
            return null;
        }
        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(record.linuxUid);
        String label = record.uidKnown ? subject.encode() : "Unknown Application";
        String packageName = record.uidKnown ? "(native attributed app)" : "(unknown package)";
        if (!record.protocolRecognitionState.isEmpty()) {
            ProtocolRecognitionProjection recognition = record.protocolRecognition();
            return ActivityItem.protocolRecognition(subject, label, packageName,
                    timestampMillis, remoteAddress(record), protocolName(record.ipProtocol),
                    remotePort(record), devicePacketDirection(profile, record.deviceDirection),
                    record.flowDirection, record.packets, record.bytes,
                    record.policyRevision, recognition);
        }
        return ActivityItem.allowedFlow(subject, label, packageName, timestampMillis,
                remoteAddress(record), protocolName(record.ipProtocol),
                remotePort(record), devicePacketDirection(profile, record.deviceDirection),
                record.flowDirection, record.packets, record.bytes,
                record.policyRevision, "None");
    }

    private static String devicePacketDirection(RuntimeProfile profile) {
        return profile == RuntimeProfile.VPN ? "vpn_outbound_or_return" : "root_nfqueue";
    }

    private static String devicePacketDirection(RuntimeProfile profile, String nativeDirection) {
        if (nativeDirection == null || nativeDirection.isEmpty()) {
            return devicePacketDirection(profile);
        }
        return profile == RuntimeProfile.VPN ? "vpn_" + nativeDirection : nativeDirection;
    }

    private static String remoteAddress(NativeAllowedFlowRecord record) {
        if ("input".equals(record.deviceDirection)) {
            return record.sourceAddress;
        }
        return record.destinationAddress;
    }

    private static int remotePort(NativeAllowedFlowRecord record) {
        if (!record.portsAvailable) {
            return 0;
        }
        return "input".equals(record.deviceDirection)
                ? record.sourcePort : record.destinationPort;
    }

    private static String protocolName(int ipProtocol) {
        if (ipProtocol == 6) {
            return "tcp";
        }
        if (ipProtocol == 17) {
            return "udp";
        }
        return ipProtocol <= 0 ? "" : "ip-" + ipProtocol;
    }

    private static int clampPort(int value) {
        if (value < 0) {
            return 0;
        }
        return Math.min(value, 65535);
    }
}
