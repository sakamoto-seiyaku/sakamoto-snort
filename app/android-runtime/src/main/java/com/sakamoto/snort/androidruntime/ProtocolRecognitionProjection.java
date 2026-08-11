package com.sakamoto.snort.androidruntime;

/** Product-facing protocol recognition projection carried as one cohesive value. */
public final class ProtocolRecognitionProjection {
    public static final String STATE_NONE = "";
    public static final String STATE_DETECTING = "detecting";
    public static final String STATE_IDENTIFIED = "identified";
    public static final String STATE_UNIDENTIFIED = "unidentified";

    public final String state;
    public final String key;
    public final String category;
    public final String sequence;
    public final int payloadPackets;

    private ProtocolRecognitionProjection(String state, String key, String category,
                                          String sequence, int payloadPackets) {
        this.state = normalizeState(state);
        this.key = bounded(key);
        this.category = bounded(category);
        this.sequence = bounded(sequence);
        this.payloadPackets = Math.max(0, payloadPackets);
    }

    public static ProtocolRecognitionProjection none() {
        return new ProtocolRecognitionProjection(STATE_NONE, "", "", "", 0);
    }

    public static ProtocolRecognitionProjection of(String state, String key, String category,
                                                   String sequence, int payloadPackets) {
        return new ProtocolRecognitionProjection(state, key, category, sequence,
                payloadPackets);
    }

    public boolean present() {
        return !state.isEmpty();
    }

    public String winner() {
        return key.isEmpty() ? "ProtocolRecognition:" + state
                : "ProtocolRecognition:" + key;
    }

    private static String normalizeState(String value) {
        String state = bounded(value);
        if (STATE_DETECTING.equals(state)
                || STATE_IDENTIFIED.equals(state)
                || STATE_UNIDENTIFIED.equals(state)
                || STATE_NONE.equals(state)) {
            return state;
        }
        throw new IllegalArgumentException("unsupported protocol recognition state: " + value);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
