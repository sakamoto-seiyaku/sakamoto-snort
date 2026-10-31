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

    public static long[] networkDisable(int uid, int network, boolean blocked) {
        if (uid < 0 || network <= 0) throw new IllegalArgumentException("network scope required");
        long[] rule = new long[COMPLETE_RULE_WORDS];
        rule[2] = uid;
        // The legacy UI enum uses 3 for VPN; platform facts use context 4.
        rule[3] = network == 3 ? 4 : network; rule[4] = 0xffffffffL;
        rule[10] = blocked ? 2 : 1;
        rule[14] = rule[16] = 65535;
        return rule;
    }

    /** Read-only projection of ordinary source rules used by the existing toggle. */
    public static boolean networkDisabled(java.util.Properties source, int uid, int network) {
        long[] scope = networkDisable(uid, network, true);
        int count = Integer.parseInt(source.getProperty("count"));
        if (count < 0 || count > MAX_RULES) throw new IllegalArgumentException("invalid source count");
        for (int i = 0; i < count; ++i) {
            String[] fields = source.getProperty("rule." + i + ".wire", "").split(",", -1);
            if (fields.length != COMPLETE_RULE_WORDS) throw new IllegalArgumentException("invalid rule projection");
            boolean equal = true;
            for (int j = 2; j < COMPLETE_RULE_WORDS; ++j)
                equal &= Long.parseUnsignedLong(fields[j]) == scope[j];
            if (equal) return true;
        }
        return false;
    }

    public static final int COMPLETE_RULE_WORDS = 43;
    public static final int MAX_RULES = 256;
    public static final int DOMAIN_ENTRY_WORDS = 67;
    public static final int MAX_ACTIVE_RULES = 128;
    private static final int COMPLETE_REPLY_HEADER_WORDS = 13;
    private static final int SOURCE_WORD = 18, DESTINATION_WORD = 22;
    public static final int DNS_ENDPOINT_WORDS = 72, DNS_ROUTE_WORDS = 10, DNS_EXCEPTION_WORDS = 68;
    public static final int DNS_MAX_ENDPOINTS = 8, DNS_MAX_ROUTES = 8, DNS_MAX_EXCEPTIONS = 32;
    public static final int DNS_CONFIG_WORDS = 12 + 8*DNS_ENDPOINT_WORDS + 8*DNS_ROUTE_WORDS + 32*DNS_EXCEPTION_WORDS;

    /** Explicit numeric ordinary upstream; the existing VPP source transaction
     * remains the only saved setting. Address discovery runs only in the native upstream transport. */
    public static long[] dnsWire(String text) {
        if (text == null) throw new IllegalArgumentException("DNS upstream required");
        if (text.trim().startsWith("upstream ")) return dnsRoutesWire(text);
        long[] wire = new long[8]; wire[0] = -3;
        String[] fields = text.trim().split("\\s+");
        if (fields.length == 1 && fields[0].equals("off")) return wire;
        if ((fields.length != 2 && fields.length != 3) || !fields[0].equals("udp"))
            throw new IllegalArgumentException("use udp <numeric IP> [port], or off");
        byte[] address = new byte[16];
        if (fields[1].contains(":")) { wire[2]=6; address=ipv6(fields[1]); }
        else {
            wire[2]=4; int value=ipv4(fields[1]);
            for (int i=0;i<4;++i) address[i]=(byte)(value >>> (24-i*8));
        }
        wire[1]=1; wire[3]=fields.length == 3 ? unsigned32(fields[2]) : 53;
        if (wire[3]==0 || wire[3]>65535) throw new IllegalArgumentException("invalid DNS port");
        for (int i=0;i<16;++i) wire[4+i/4]|=(address[i]&255L)<<(24-(i%4)*8);
        return wire;
    }

    /** Same VPP source transaction: identity is independent of connection IP.
     * A DoT domain with '-' explicitly requests original-network bootstrap. */
    private static long[] dnsRoutesWire(String text) {
        java.util.ArrayList<long[]> endpoints = new java.util.ArrayList<>();
        java.util.ArrayList<long[]> routes = new java.util.ArrayList<>();
        java.util.ArrayList<long[]> exceptions = new java.util.ArrayList<>();
        java.util.HashSet<String> scopes = new java.util.HashSet<>();
        for (String line : text.split("[\\r\\n]+")) {
            String[] f = line.trim().split("\\s+");
            if (f[0].equals("upstream")) {
                if (f.length != 6 || endpoints.size() >= DNS_MAX_ENDPOINTS
                        || unsigned32(f[1]) != endpoints.size()
                        || !(f[2].equals("udp") || f[2].equals("tcp") || f[2].equals("dot")))
                    throw new IllegalArgumentException("upstream <index> <udp|tcp|dot> <identity> <connection IP> <port>");
                long[] endpoint = new long[DNS_ENDPOINT_WORDS];
                endpoint[0] = f[2].equals("udp") ? 1 : f[2].equals("tcp") ? 2 : 3;
                String identity;
                if (f[3].contains(":")) { ipv6(f[3]); identity = f[3].toLowerCase(java.util.Locale.ROOT); }
                else if (f[3].matches("[0-9.]+")) { ipv4(f[3]); identity = f[3]; }
                else identity = dnsName(f[3]);
                dnsString(endpoint, 8, identity);
                String connection = f[4];
                if (connection.equals("-")) {
                    if (endpoint[0] != 3) throw new IllegalArgumentException("bootstrap requires DoT");
                    if (identity.contains(":") || identity.matches("[0-9.]+")) connection = identity;
                    else {
                        endpoint[2] = unsigned32(f[5]);
                        if (endpoint[2] == 0 || endpoint[2] > 65535)
                            throw new IllegalArgumentException("invalid DNS port");
                    }
                }
                if (!connection.equals("-")) {
                    long[] single = dnsWire("udp " + connection + " " + f[5]);
                    endpoint[1] = single[2]; endpoint[2] = single[3];
                    System.arraycopy(single, 4, endpoint, 4, 4);
                }
                endpoints.add(endpoint);
            } else if (f[0].equals("route")) {
                if (f.length < 3 || f.length > 10 || routes.size() >= DNS_MAX_ROUTES
                        || unsigned32(f[1]) != routes.size())
                    throw new IllegalArgumentException("route <index> <ordered upstream indices>");
                long[] route = new long[DNS_ROUTE_WORDS]; route[0] = f.length - 2;
                java.util.HashSet<Long> seen = new java.util.HashSet<>();
                for (int i = 2; i < f.length; ++i) {
                    long index = unsigned32(f[i]);
                    if (index >= endpoints.size() || !seen.add(index))
                        throw new IllegalArgumentException("unknown or duplicate DNS upstream");
                    route[i] = index;
                }
                routes.add(route);
            } else if (f[0].equals("exception")) {
                if (exceptions.size() >= DNS_MAX_EXCEPTIONS || (f.length != 4 && f.length != 5))
                    throw new IllegalArgumentException("exception <exact|descendants> <name> <original|route index>");
                String name = dnsName(f[2]);
                int match = f[1].equals("exact") ? 0 : f[1].equals("descendants") ? 1 : -1;
                if (match < 0 || !scopes.add(match + ":" + name))
                    throw new IllegalArgumentException("duplicate DNS exception scope");
                long[] exception = new long[DNS_EXCEPTION_WORDS];
                exception[0] = match; exception[3] = name.length();
                if (f.length == 4 && f[3].equals("original")) exception[1] = 0;
                else if (f.length == 5 && f[3].equals("route") && unsigned32(f[4]) < routes.size()) {
                    exception[1] = 1; exception[2] = unsigned32(f[4]);
                } else throw new IllegalArgumentException("unknown DNS exception route");
                dnsString(exception, 4, name); exceptions.add(exception);
            } else throw new IllegalArgumentException("unknown DNS configuration line");
        }
        if (endpoints.isEmpty() || routes.isEmpty()) throw new IllegalArgumentException("DNS default route required");
        long[] wire = new long[5 + DNS_ENDPOINT_WORDS*endpoints.size()
                + DNS_ROUTE_WORDS*routes.size() + DNS_EXCEPTION_WORDS*exceptions.size()];
        wire[0] = -4; wire[1] = 1; wire[2] = endpoints.size(); wire[3] = routes.size(); wire[4] = exceptions.size();
        int at = 5;
        for (java.util.ArrayList<long[]> entries : java.util.Arrays.asList(endpoints, routes, exceptions))
            for (long[] entry : entries) { System.arraycopy(entry, 0, wire, at, entry.length); at += entry.length; }
        return wire;
    }

    private static void dnsString(long[] wire, int at, String text) {
        for (int i = 0; i < text.length(); ++i) wire[at+i/4] |= (long)text.charAt(i) << (24-(i%4)*8);
    }

    private static String dnsName(String text) {
        String name = text.toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".")) name = name.substring(0, name.length()-1);
        if (name.isEmpty() || name.length() > 253) throw new IllegalArgumentException("DNS name length");
        for (String label : name.split("\\.", -1))
            if (label.isEmpty() || label.length() > 63 || !label.matches("[a-z0-9_-]+"))
                throw new IllegalArgumentException("use DNS ASCII labels");
        return name;
    }

    /** Request-only numeric text. No hostname lookup and no second saved model. */
    public static long[] completeWire(String text) {
        if (text == null) throw new IllegalArgumentException("complete rules required");
        StringBuilder rules = new StringBuilder();
        java.util.ArrayList<Long> groups = new java.util.ArrayList<>();
        java.util.ArrayList<Long> edges = new java.util.ArrayList<>();
        java.util.ArrayList<Long> bindings = new java.util.ArrayList<>();
        java.util.ArrayList<long[]> domains = new java.util.ArrayList<>();
        int listCount = 0;
        boolean listsDeclared = false;
        for (String line : text.split("[\\r\\n]+")) {
            String[] f = line.trim().split("\\s+");
            java.util.ArrayList<Long> target;
            int fields, limit;
            if (f[0].equals("lists")) {
                if (f.length != 2 || listsDeclared) throw new IllegalArgumentException("invalid list declaration");
                long n = unsigned32(f[1]);
                if (n > 64) throw new IllegalArgumentException("too many domain lists");
                listCount = (int)n; listsDeclared = true; continue;
            }
            if (f[0].equals("domain")) {
                if (f.length != 4 || domains.size() >= 256) throw new IllegalArgumentException("invalid domain fields/count");
                long list = unsigned32(f[1]);
                int mode = f[2].equals("exact") ? 0 : f[2].equals("descendants") ? 1 : -1;
                if (list >= listCount || mode < 0 || f[3].isEmpty() || f[3].length() > 254)
                    throw new IllegalArgumentException("invalid domain list/mode/name");
                long[] entry = new long[DOMAIN_ENTRY_WORDS];
                entry[0] = list; entry[1] = mode; entry[2] = f[3].length();
                for (int i = 0; i < f[3].length(); ++i) {
                    char c = f[3].charAt(i);
                    if (c > 127) throw new IllegalArgumentException("use ASCII A-labels");
                    entry[3+i/4] |= (long)c << (24-(i%4)*8);
                }
                domains.add(entry); continue;
            }
            if (f[0].equals("group")) { target = groups; fields = 1; limit = 64; }
            else if (f[0].equals("edge")) { target = edges; fields = 3; limit = 512; }
            else if (f[0].equals("bind")) { target = bindings; fields = 5; limit = 128; }
            else { rules.append(line).append('\n'); continue; }
            if (f.length != fields + 1 || target.size() / fields == limit)
                throw new IllegalArgumentException("invalid graph fields or capacity");
            for (int i = 1; i < f.length; ++i) target.add(unsigned32(f[i]));
        }
        long[] direct = directWire(rules.toString());
        if (groups.isEmpty() && edges.isEmpty() && bindings.isEmpty() && !listsDeclared) return direct;
        int headerWords = listsDeclared ? 7 : 5;
        long[] wire = new long[headerWords + direct.length + groups.size() + edges.size() + bindings.size() + DOMAIN_ENTRY_WORDS*domains.size()];
        wire[0] = listsDeclared ? -2 : -1; wire[1] = direct.length / COMPLETE_RULE_WORDS;
        wire[2] = groups.size(); wire[3] = edges.size()/3; wire[4] = bindings.size()/5;
        if (listsDeclared) { wire[5] = listCount; wire[6] = domains.size(); }
        System.arraycopy(direct, 0, wire, headerWords, direct.length);
        int at = headerWords + direct.length;
        for (long n : groups) wire[at++] = n;
        for (long n : edges) wire[at++] = n;
        for (long n : bindings) wire[at++] = n;
        for (long[] entry : domains) { System.arraycopy(entry, 0, wire, at, DOMAIN_ENTRY_WORDS); at += DOMAIN_ENTRY_WORDS; }
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
            if (f.length != 16 && f.length != 17) throw new IllegalArgumentException("expected 16 direct-rule fields at " + i);
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
            if (f.length == 17) {
                String hex = f[16];
                if (!hex.matches("(?:[0-9a-fA-F]{2}){1,64}"))
                    throw new IllegalArgumentException("expression must be 1..64 hex bytes");
                wire[at+26] = hex.length()/2;
                for (int n = 0; n < hex.length()/2; ++n)
                    wire[at+27+n/4] |= Long.parseLong(hex.substring(n*2, n*2+2), 16) << (24-(n%4)*8);
            }
        }
        return wire;
    }
    private static long unsigned32(String text) {
        long value = Long.parseLong(text);
        if (value < 0 || value > 0xffffffffL) throw new IllegalArgumentException("invalid unsigned field");
        return value;
    }
    private static int cidr(String text, long[] wire, int prefixAt, int addressAt) {
        if (text.equals("*")) return 0;
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
        public final int domainListCount, domainEntryCount;
        private final long[] values;
        private final int dnsAt, dnsStride;
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
                    || (graph && reply.length < graphAt + 3 + groups + 3*edges + 5*bindings))
                throw new IllegalArgumentException("invalid graph reply size");
            groupCount = (int) groups; edgeCount = (int) edges; bindingCount = (int) bindings;
            int domainAt = graph ? graphAt + 3 + (int)groups + 3*(int)edges + 5*(int)bindings : graphAt;
            long lists = 0, entries = 0;
            int sourceEnd = domainAt;
            if (reply.length != domainAt) {
                if (reply.length < domainAt + 2) throw new IllegalArgumentException("invalid domain reply");
                lists = reply[domainAt]; entries = reply[domainAt+1];
                if (lists < 0 || lists > 64 || entries < 0 || entries > 256 ||
                    (reply.length != domainAt + 2 + DOMAIN_ENTRY_WORDS*entries &&
                     reply.length != domainAt + 2 + DOMAIN_ENTRY_WORDS*entries + 16 &&
                     reply.length != domainAt + 2 + DOMAIN_ENTRY_WORDS*entries + 2*DNS_CONFIG_WORDS))
                    throw new IllegalArgumentException("invalid domain reply size");
                sourceEnd=domainAt+2+DOMAIN_ENTRY_WORDS*(int)entries;
                for (int i = 0; i < entries; ++i) {
                    int at = domainAt + 2 + i*DOMAIN_ENTRY_WORDS;
                    if (reply[at] < 0 || reply[at] >= lists || reply[at+1] < 0 || reply[at+1] > 1 ||
                        reply[at+2] <= 0 || reply[at+2] > 253) throw new IllegalArgumentException("invalid domain reply entry");
                    for (int j = 3; j < DOMAIN_ENTRY_WORDS; ++j)
                        if (reply[at+j] < 0 || reply[at+j] > 0xffffffffL) throw new IllegalArgumentException("invalid name word");
                }
            }
            dnsStride=reply.length == sourceEnd+2*DNS_CONFIG_WORDS ? DNS_CONFIG_WORDS : 8;
            dnsAt=(reply.length == sourceEnd+16 || dnsStride==DNS_CONFIG_WORDS) ? sourceEnd : -1;
            if (dnsAt>=0) for (int i=0;i<2;++i) {
                int at=dnsAt+i*dnsStride;
                for (int j=0;j<dnsStride;++j)
                    if (reply[at+j]<0 || reply[at+j]>0xffffffffL) throw new IllegalArgumentException("invalid DNS status word");
                if (reply[at]>1 || (reply[at+1]!=0 && reply[at+1]!=4 && reply[at+1]!=6)
                        || reply[at+2]>65535 || reply[at+3]!=0)
                    throw new IllegalArgumentException("invalid DNS status");
                if(dnsStride==DNS_CONFIG_WORDS && (reply[at+8]>8 || reply[at+9]>8 || reply[at+10]>32 || reply[at+11]!=0))
                    throw new IllegalArgumentException("invalid DNS configuration status counts");
            }
            domainListCount = (int)lists; domainEntryCount = (int)entries;
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
            out.append("domainListCount=").append(domainListCount).append('\n');
            out.append("domainEntryCount=").append(domainEntryCount).append('\n');
            at += 2;
            for (int i = 0; i < domainEntryCount; ++i) {
                out.append("domain.").append(i).append(".list=").append(values[at]).append('\n');
                out.append("domain.").append(i).append(".mode=").append(values[at+1]).append('\n');
                out.append("domain.").append(i).append(".name=");
                for (int j = 0; j < values[at+2]; ++j)
                    out.append((char)((values[at+3+j/4] >> (24-(j%4)*8)) & 255));
                out.append('\n'); at += DOMAIN_ENTRY_WORDS;
            }
            String[] dnsNames={"dns", "dns.active"};
            for (int i=0;i<2;++i) {
                int offset=dnsAt<0 ? -1 : dnsAt+i*dnsStride;
                out.append(dnsNames[i]).append(".enabled=").append(offset<0 ? 0 : values[offset]).append('\n');
                out.append(dnsNames[i]).append(".family=").append(offset<0 ? 0 : values[offset+1]).append('\n');
                out.append(dnsNames[i]).append(".port=").append(offset<0 ? 0 : values[offset+2]).append('\n');
                out.append(dnsNames[i]).append(".address=");
                for (int j=0;j<4;++j) out.append(String.format(java.util.Locale.ROOT,"%08x",offset<0 ? 0 : values[offset+4+j]));
                out.append('\n');
                if(offset>=0 && dnsStride==DNS_CONFIG_WORDS) dnsProperties(out,dnsNames[i],values,offset);
            }
            return out.toString();
        }
    }

    private static String dnsText(long[] words,int at,int bytes) {
        StringBuilder text=new StringBuilder();
        for(int i=0;i<bytes;++i) {
            char c=(char)((words[at+i/4] >>> (24-(i%4)*8)) & 255);
            if(c==0) break;
            if(c<33 || c>126) throw new IllegalArgumentException("invalid DNS status text");
            text.append(c);
        }
        return text.toString();
    }
    private static void dnsProperties(StringBuilder out,String name,long[] words,int base) {
        int endpoints=(int)words[base+8],routes=(int)words[base+9],exceptions=(int)words[base+10];
        out.append(name).append(".endpointCount=").append(endpoints).append('\n');
        out.append(name).append(".routeCount=").append(routes).append('\n');
        out.append(name).append(".exceptionCount=").append(exceptions).append('\n');
        for(int i=0;i<endpoints;++i) {
            int at=base+12+i*DNS_ENDPOINT_WORDS;
            String prefix=name+".endpoint."+i;
            out.append(prefix).append(".transport=").append(words[at]).append('\n');
            out.append(prefix).append(".family=").append(words[at+1]).append('\n');
            out.append(prefix).append(".port=").append(words[at+2]).append('\n');
            out.append(prefix).append(".address=");
            for(int j=0;j<4;++j) out.append(String.format(java.util.Locale.ROOT,"%08x",words[at+4+j]));
            out.append('\n').append(prefix).append(".identity=").append(dnsText(words,at+8,256)).append('\n');
        }
        int routeBase=base+12+8*DNS_ENDPOINT_WORDS;
        for(int i=0;i<routes;++i) {
            int at=routeBase+i*DNS_ROUTE_WORDS;
            if(words[at]<1 || words[at]>8) throw new IllegalArgumentException("invalid DNS route status count");
            out.append(name).append(".route.").append(i).append(".candidates=");
            for(int j=0;j<words[at];++j) {
                if(words[at+2+j]>=endpoints) throw new IllegalArgumentException("invalid DNS candidate status");
                if(j!=0) out.append(','); out.append(words[at+2+j]);
            }
            out.append('\n');
        }
        int exceptionBase=routeBase+8*DNS_ROUTE_WORDS;
        for(int i=0;i<exceptions;++i) {
            int at=exceptionBase+i*DNS_EXCEPTION_WORDS;
            String prefix=name+".exception."+i;
            out.append(prefix).append(".match=").append(words[at]).append('\n');
            out.append(prefix).append(".target=").append(words[at+1]).append('\n');
            out.append(prefix).append(".route=").append(words[at+2]).append('\n');
            out.append(prefix).append(".name=").append(dnsText(words,at+4,256)).append('\n');
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
