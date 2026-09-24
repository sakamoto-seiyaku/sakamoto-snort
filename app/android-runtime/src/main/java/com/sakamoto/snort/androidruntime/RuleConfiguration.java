package com.sakamoto.snort.androidruntime;

/** Bounded online VPP source request/status. No local policy persistence. */
public final class RuleConfiguration {
    private RuleConfiguration() {}

    public static int ipv4(String text) {
        if (text == null) throw new IllegalArgumentException("IPv4 address required");
        String[] pieces = text.split("\\.", -1);
        if (pieces.length != 4) throw new IllegalArgumentException("exact IPv4 address required");
        int value = 0;
        for (String piece : pieces) {
            if (!piece.matches("0|[1-9][0-9]{0,2}"))
                throw new IllegalArgumentException("canonical IPv4 address required");
            int octet = Integer.parseInt(piece);
            if (octet > 255) throw new IllegalArgumentException("invalid IPv4 address");
            value = (value << 8) | octet;
        }
        return value;
    }

    public static Rule udp(int uid, String source, String destination,
                            int sourcePort, int destinationPort, int action) {
        if (uid < 0 || sourcePort < 0 || sourcePort > 65535
                || destinationPort < 0 || destinationPort > 65535
                || (action != 1 && action != 2))
            throw new IllegalArgumentException("invalid direct UDP rule");
        return new Rule(1, uid, 17, 3, action, sourcePort, destinationPort,
                ipv4(source), ipv4(destination));
    }

    public static final class Rule {
        public final int present, uid, protocol, direction, action;
        public final int sourcePort, destinationPort, sourceAddress, destinationAddress;
        private Rule(int present, int uid, int protocol, int direction, int action,
                     int sourcePort, int destinationPort, int sourceAddress, int destinationAddress) {
            this.present = present; this.uid = uid; this.protocol = protocol;
            this.direction = direction; this.action = action;
            this.sourcePort = sourcePort; this.destinationPort = destinationPort;
            this.sourceAddress = sourceAddress; this.destinationAddress = destinationAddress;
        }
        public static Rule empty() { return new Rule(0, 0, 0, 0, 0, 0, 0, 0, 0); }
        // The sole Java array codec, shared by the Intent and JNI boundaries.
        int[] toWire() {
            return new int[]{present, uid, protocol, direction, action,
                    sourcePort, destinationPort, sourceAddress, destinationAddress};
        }
        static Rule fromWire(int[] wire) {
            if (wire == null || wire.length != 9)
                throw new IllegalArgumentException("invalid rule payload");
            return new Rule(wire[0], wire[1], wire[2], wire[3], wire[4], wire[5], wire[6], wire[7], wire[8]);
        }
    }

    public static final class Status {
        public final long transportCode, generation, savedRevision, activeRevision;
        public final long savedRuleVersion, activeRuleVersion, result, saveError, compileError;
        public final Rule rule;
        public Status(long[] values) {
            if (values == null || values.length != 18)
                throw new IllegalArgumentException("invalid rule configuration reply");
            transportCode = values[0]; generation = values[1];
            savedRevision = values[2]; activeRevision = values[3];
            savedRuleVersion = values[4]; activeRuleVersion = values[5];
            result = values[6]; saveError = values[7]; compileError = values[8];
            int[] fields = new int[9];
            for (int i = 0; i < 9; ++i) fields[i] = (int) values[9+i];
            rule = Rule.fromWire(fields);
        }
        public boolean applied() {
            return transportCode == 0 && result == 0 && saveError == 0 && compileError == 0
                    && savedRevision != 0 && activeRevision == savedRevision;
        }
        public String properties() {
            return "transportCode=" + transportCode + "\ngeneration=" + generation
                    + "\nsavedRevision=" + Long.toUnsignedString(savedRevision)
                    + "\nactiveRevision=" + Long.toUnsignedString(activeRevision)
                    + "\nsavedRuleVersion=" + Long.toUnsignedString(savedRuleVersion)
                    + "\nactiveRuleVersion=" + Long.toUnsignedString(activeRuleVersion)
                    + "\nresult=" + result + "\nsaveError=" + saveError
                    + "\ncompileError=" + compileError + "\npresent=" + rule.present
                    + "\nuid=" + rule.uid + "\naction=" + rule.action + "\n";
        }
    }
}
