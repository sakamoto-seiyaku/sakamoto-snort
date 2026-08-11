package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Typed internal view over the durable protocol recognition sequence wire string. */
public final class ProtocolRecognitionSequence {
    public final List<Entry> entries;

    private final String wire;

    private ProtocolRecognitionSequence(String wire, List<Entry> entries) {
        this.wire = bounded(wire);
        this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
    }

    public static ProtocolRecognitionSequence empty() {
        return new ProtocolRecognitionSequence("", Collections.<Entry>emptyList());
    }

    public static ProtocolRecognitionSequence parse(String wire) {
        String boundedWire = bounded(wire);
        if (boundedWire.isEmpty()) {
            return empty();
        }
        ArrayList<Entry> entries = new ArrayList<>();
        String[] tokens = boundedWire.split(",");
        for (String token : tokens) {
            Entry entry = parseEntry(token);
            if (entry != null) {
                entries.add(entry);
            }
        }
        return new ProtocolRecognitionSequence(boundedWire, entries);
    }

    public String wire() {
        return wire;
    }

    private static Entry parseEntry(String token) {
        if (token == null) {
            return null;
        }
        String[] parts = token.trim().split(":", -1);
        if (parts.length != 3) {
            return null;
        }
        try {
            long payloadPacketSequence = Long.parseLong(parts[0].trim());
            if (payloadPacketSequence < 0L) {
                return null;
            }
            String protocolKey = bounded(parts[1]);
            String flowDirection = bounded(parts[2]);
            if (protocolKey.isEmpty() || flowDirection.isEmpty()) {
                return null;
            }
            return new Entry(payloadPacketSequence, protocolKey, flowDirection);
        } catch (NumberFormatException error) {
            return null;
        }
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    /** One parsed protocol recognition event from the durable sequence wire. */
    public static final class Entry {
        public final long payloadPacketSequence;
        public final String protocolKey;
        public final String flowDirection;

        private Entry(long payloadPacketSequence, String protocolKey,
                      String flowDirection) {
            this.payloadPacketSequence = payloadPacketSequence;
            this.protocolKey = protocolKey;
            this.flowDirection = flowDirection;
        }
    }
}
