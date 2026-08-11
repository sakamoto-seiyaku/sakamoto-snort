package com.sakamoto.snort.androidruntime;

/** Product-facing Activity row for verdict evidence and L4 rule prefill. */
public final class ActivityItem {
    public static final String PROTOCOL_RECOGNITION_NONE = "";
    public static final String PROTOCOL_RECOGNITION_DETECTING = "detecting";
    public static final String PROTOCOL_RECOGNITION_IDENTIFIED = "identified";
    public static final String PROTOCOL_RECOGNITION_UNIDENTIFIED = "unidentified";

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
    public final String protocolRecognitionState;
    public final String applicationProtocolKey;
    public final String applicationProtocolCategory;
    public final String protocolRecognitionSequence;
    public final int protocolPayloadPackets;

    public ActivityItem(ApplicationSubjectId subjectId, String appLabel, String packageName,
                        long timestampMillis, String remoteIp, String protocol, int remotePort,
                        String devicePacketDirection, String flowDirection, long packets,
                        long bytes, String verdict, String winner, long policyRevision,
                        long ruleId, int reasonId, String evidenceSource, boolean detailLossy) {
        this(subjectId, appLabel, packageName, timestampMillis, remoteIp, protocol, remotePort,
                devicePacketDirection, flowDirection, packets, bytes, verdict, winner,
                policyRevision, ruleId, reasonId, evidenceSource, detailLossy,
                PROTOCOL_RECOGNITION_NONE, "", "", "", 0);
    }

    public ActivityItem(ApplicationSubjectId subjectId, String appLabel, String packageName,
                        long timestampMillis, String remoteIp, String protocol, int remotePort,
                        String devicePacketDirection, String flowDirection, long packets,
                        long bytes, String verdict, String winner, long policyRevision,
                        long ruleId, int reasonId, String evidenceSource, boolean detailLossy,
                        String protocolRecognitionState, String applicationProtocolKey,
                        String applicationProtocolCategory, String protocolRecognitionSequence,
                        int protocolPayloadPackets) {
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
        this.protocolRecognitionState = normalizeProtocolRecognitionState(
                protocolRecognitionState);
        this.applicationProtocolKey = bounded(applicationProtocolKey);
        this.applicationProtocolCategory = bounded(applicationProtocolCategory);
        this.protocolRecognitionSequence = bounded(protocolRecognitionSequence);
        this.protocolPayloadPackets = Math.max(0, protocolPayloadPackets);
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

    public static ActivityItem protocolRecognition(ApplicationSubjectId subjectId,
                                                   String appLabel, String packageName,
                                                   long timestampMillis, String remoteIp,
                                                   String transportProtocol,
                                                   int remotePort,
                                                   String devicePacketDirection,
                                                   String flowDirection, long packets,
                                                   long bytes, long policyRevision,
                                                   String recognitionState,
                                                   String latestProtocolKey,
                                                   String category,
                                                   String recognitionSequence,
                                                   int payloadPackets) {
        String state = normalizeProtocolRecognitionState(recognitionState);
        String winner = latestProtocolKey == null || latestProtocolKey.isEmpty()
                ? "ProtocolRecognition:" + state
                : "ProtocolRecognition:" + latestProtocolKey;
        return new ActivityItem(subjectId, appLabel, packageName, timestampMillis, remoteIp,
                transportProtocol, remotePort, devicePacketDirection, flowDirection,
                packets, bytes, "pass_next", winner, policyRevision, 0L, 0,
                "flow_entry_lpi_recognition", false, state, latestProtocolKey,
                category, recognitionSequence, payloadPackets);
    }

    public boolean canPrefillL4Rule() {
        return "drop".equals(verdict) && remotePort > 0 && !remoteIp.isEmpty();
    }

    private static String normalizeProtocolRecognitionState(String value) {
        String state = bounded(value);
        if (PROTOCOL_RECOGNITION_DETECTING.equals(state)
                || PROTOCOL_RECOGNITION_IDENTIFIED.equals(state)
                || PROTOCOL_RECOGNITION_UNIDENTIFIED.equals(state)
                || PROTOCOL_RECOGNITION_NONE.equals(state)) {
            return state;
        }
        throw new IllegalArgumentException("unsupported protocol recognition state: " + value);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
