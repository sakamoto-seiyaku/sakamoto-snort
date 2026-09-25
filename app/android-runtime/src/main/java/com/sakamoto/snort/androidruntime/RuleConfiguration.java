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

    public static final int COMPLETE_RULE_WORDS = 26;
    public static final int MAX_RULES = 256;
    public static final int MAX_ACTIVE_RULES = 128;
    private static final int COMPLETE_REPLY_HEADER_WORDS = 13;
    private static final int SOURCE_WORD = 18, DESTINATION_WORD = 22;

    /** Request-only numeric text. No hostname lookup and no second saved model. */
    public static long[] completeWire(String text) {
        if (text == null) throw new IllegalArgumentException("complete rules required");
        StringBuilder rules = new StringBuilder();
        java.util.ArrayList<Long> groups = new java.util.ArrayList<>();
        java.util.ArrayList<Long> edges = new java.util.ArrayList<>();
        java.util.ArrayList<Long> bindings = new java.util.ArrayList<>();
        for (String line : text.split("[\\r\\n]+")) {
            String[] f = line.trim().split("\\s+");
            java.util.ArrayList<Long> target;
            int fields, limit;
            if (f[0].equals("group")) { target = groups; fields = 1; limit = 64; }
            else if (f[0].equals("edge")) { target = edges; fields = 3; limit = 512; }
            else if (f[0].equals("bind")) { target = bindings; fields = 5; limit = 128; }
            else { rules.append(line).append('\n'); continue; }
            if (f.length != fields + 1 || target.size() / fields == limit)
                throw new IllegalArgumentException("invalid graph fields or capacity");
            for (int i = 1; i < f.length; ++i) target.add(unsigned32(f[i]));
        }
        long[] direct = directWire(rules.toString());
        if (groups.isEmpty() && edges.isEmpty() && bindings.isEmpty()) return direct;
        long[] wire = new long[5 + direct.length + groups.size() + edges.size() + bindings.size()];
        wire[0] = -1; wire[1] = direct.length / COMPLETE_RULE_WORDS;
        wire[2] = groups.size(); wire[3] = edges.size()/3; wire[4] = bindings.size()/5;
        System.arraycopy(direct, 0, wire, 5, direct.length);
        int at = 5 + direct.length;
        for (long n : groups) wire[at++] = n;
        for (long n : edges) wire[at++] = n;
        for (long n : bindings) wire[at++] = n;
        return wire;
    }
    private static long[] directWire(String text) {
        if (text == null) throw new IllegalArgumentException("complete rules required");
        String trimmed = text.trim();
        if (trimmed.isEmpty()) return new long[0];
        String[] lines = trimmed.split("[\\r\\n]+");
        if (lines.length > MAX_RULES) throw new IllegalArgumentException("too many source rules");
        long[] wire = new long[lines.length * COMPLETE_RULE_WORDS];
        for (int i = 0; i < lines.length; ++i) {
            String[] f = lines[i].trim().split("\\s+");
            if (f.length != 16) throw new IllegalArgumentException("expected 16 direct-rule fields at " + i);
            int at = i * COMPLETE_RULE_WORDS;
            wire[at] = Long.parseUnsignedLong(f[0]);
            wire[at+1] = Long.parseUnsignedLong(f[1]);
            // UID, network, interface, priority, order; then family/protocol/direction/action.
            for (int n = 2; n <= 6; ++n) wire[at+n] = unsigned32(f[n]);
            for (int n = 7; n <= 9; ++n) wire[at+n+1] = unsigned32(f[n]);
            int sourceFamily = cidr(f[10], wire, at+11, at+SOURCE_WORD);
            int destinationFamily = cidr(f[11], wire, at+12, at+DESTINATION_WORD);
            if (sourceFamily != destinationFamily) throw new IllegalArgumentException("CIDR families differ");
            wire[at+7] = sourceFamily;
            for (int n = 12; n <= 15; ++n) wire[at+n+1] = unsigned32(f[n]);
        }
        return wire;
    }
    private static long unsigned32(String text) {
        long value = Long.parseLong(text);
        if (value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("invalid unsigned field");
        return value;
    }
    private static int cidr(String text, long[] wire, int prefixAt, int addressAt) {
        String[] f = text.split("/", -1);
        if (f.length != 2) throw new IllegalArgumentException("numeric CIDR required");
        byte[] bytes;
        int family;
        if (f[0].contains(":")) {
            bytes = ipv6(f[0]);
            family = 6;
        } else {
            int address = ipv4(f[0]); bytes = new byte[16];
            for (int n = 0; n < 4; ++n) bytes[n] = (byte) (address >>> (24 - n*8));
            family = 4;
        }
        long prefix = unsigned32(f[1]);
        if (prefix > (family == 4 ? 32 : 128)) throw new IllegalArgumentException("invalid prefix");
        wire[prefixAt] = prefix;
        for (int n = 0; n < 16; ++n) wire[addressAt+n/4] |= (bytes[n] & 255L) << (24 - (n%4)*8);
        return family;
    }
    private static byte[] ipv6(String text) {
        // Preserve the explicit IPv6 family for mapped addresses; InetAddress's
        // text factory intentionally collapses those into IPv4 objects.
        if (!text.matches("[0-9a-fA-F:.]+")) throw new IllegalArgumentException("numeric IPv6 required");
        if (text.contains(".")) {
            int last = text.lastIndexOf(':');
            int address = ipv4(text.substring(last+1));
            text = text.substring(0, last+1) + Integer.toHexString(address >>> 16) + ":" + Integer.toHexString(address & 65535);
        }
        String[] halves = text.split("::", -1);
        if (halves.length > 2) throw new IllegalArgumentException("invalid IPv6 compression");
        String[] left = halves[0].isEmpty() ? new String[0] : halves[0].split(":", -1);
        String[] right = halves.length == 1 || halves[1].isEmpty() ? new String[0] : halves[1].split(":", -1);
        int used = left.length + right.length;
        if ((halves.length == 1 && used != 8) || (halves.length == 2 && used >= 8))
            throw new IllegalArgumentException("invalid IPv6 length");
        byte[] bytes = new byte[16];
        for (int i = 0; i < used; ++i) {
            String group = i < left.length ? left[i] : right[i-left.length];
            if (!group.matches("[0-9a-fA-F]{1,4}")) throw new IllegalArgumentException("invalid IPv6 group");
            int value = Integer.parseInt(group, 16);
            int at = i < left.length ? i : 8-right.length+i-left.length;
            bytes[at*2] = (byte) (value >>> 8); bytes[at*2+1] = (byte) value;
        }
        return bytes;
    }

    public static final class CompleteStatus {
        public final long transportCode, generation, savedRevision, activeRevision, result, saveError, compileError;
        public final int count, activeCount;
        public final int groupCount, edgeCount, bindingCount;
        private final long[] values;
        public CompleteStatus(long[] reply) {
            if (reply == null || reply.length < COMPLETE_REPLY_HEADER_WORDS) throw new IllegalArgumentException("invalid complete reply");
            count = (int) reply[9]; activeCount = (int) reply[10];
            if (count < 0 || count > MAX_RULES || activeCount < 0 || activeCount > MAX_RULES
                    || reply.length < COMPLETE_REPLY_HEADER_WORDS + count * COMPLETE_RULE_WORDS + activeCount)
                throw new IllegalArgumentException("invalid complete reply size");
            int graphAt = COMPLETE_REPLY_HEADER_WORDS + count * COMPLETE_RULE_WORDS + activeCount;
            boolean graph = reply.length != graphAt;
            if (graph && reply.length < graphAt + 3) throw new IllegalArgumentException("invalid graph reply");
            long groups = graph ? reply[graphAt] : 0, edges = graph ? reply[graphAt+1] : 0,
                    bindings = graph ? reply[graphAt+2] : 0;
            if (groups < 0 || groups > 64 || edges < 0 || edges > 512 || bindings < 0 || bindings > 128
                    || (graph && reply.length != graphAt + 3 + groups + 3*edges + 5*bindings))
                throw new IllegalArgumentException("invalid graph reply size");
            groupCount = (int) groups; edgeCount = (int) edges; bindingCount = (int) bindings;
            values = reply.clone(); transportCode = reply[0]; generation = reply[1];
            savedRevision = reply[2]; activeRevision = reply[3]; result = reply[6];
            saveError = reply[7]; compileError = reply[8];
        }
        public String properties() {
            String[] names = {"transportCode", "generation", "savedRevision", "activeRevision",
                "savedRuleVersion", "activeRuleVersion", "result", "saveError", "compileError",
                "count", "activeCount", "errorIndex", "compilerStatus"};
            StringBuilder out = new StringBuilder();
            for (int i = 0; i < names.length; ++i) out.append(names[i]).append('=').append(Long.toUnsignedString(values[i])).append('\n');
            for (int i = 0; i < count; ++i) {
                int at = COMPLETE_REPLY_HEADER_WORDS + i * COMPLETE_RULE_WORDS;
                out.append("rule.").append(i).append(".version=").append(Long.toUnsignedString(values[at])).append('\n');
                out.append("rule.").append(i).append(".uid=").append(values[at+2]).append('\n');
                out.append("rule.").append(i).append(".family=").append(values[at+7]).append('\n');
                out.append("rule.").append(i).append(".protocol=").append(values[at+8]).append('\n');
                out.append("rule.").append(i).append(".action=").append(values[at+10]).append('\n');
                out.append("rule.").append(i).append(".wire=");
                for (int j = 0; j < COMPLETE_RULE_WORDS; ++j) {
                    if (j != 0) out.append(','); out.append(Long.toUnsignedString(values[at+j]));
                }
                out.append('\n');
            }
            for (int i = 0; i < activeCount; ++i) out.append("activeVersion.").append(i).append('=')
                    .append(Long.toUnsignedString(values[COMPLETE_REPLY_HEADER_WORDS + count * COMPLETE_RULE_WORDS + i])).append('\n');
            out.append("groupCount=").append(groupCount).append('\n');
            out.append("edgeCount=").append(edgeCount).append('\n');
            out.append("bindingCount=").append(bindingCount).append('\n');
            int at = COMPLETE_REPLY_HEADER_WORDS + count * COMPLETE_RULE_WORDS + activeCount + 3;
            for (int i = 0; i < groupCount; ++i) out.append("group.").append(i).append('=').append(values[at++]).append('\n');
            for (int i = 0; i < edgeCount; ++i) {
                out.append("edge.").append(i).append('=');
                for (int j = 0; j < 3; ++j) { if (j != 0) out.append(','); out.append(values[at++]); }
                out.append('\n');
            }
            for (int i = 0; i < bindingCount; ++i) {
                out.append("binding.").append(i).append('=');
                for (int j = 0; j < 5; ++j) { if (j != 0) out.append(','); out.append(values[at++]); }
                out.append('\n');
            }
            return out.toString();
        }
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
