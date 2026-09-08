package com.sakamoto.snort.androidruntime;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Local product authoring bundle: stage-owned typed rule families under one revision. */
public final class AuthoringPolicyBundle {
    public static final int SCHEMA_VERSION = 1;
    public static final String LOCAL_PRODUCT_BACKEND_SOURCE = "local-product-backend";

    /* Keep these values in lockstep with sakamoto_product_abi.h. */
    public static final int BUNDLE_ABI_VERSION = 1;
    public static final int MAX_GATE_ENTRIES = 64;
    public static final int MAX_L4_RULES = 64;
    public static final int MAX_L4_ENTRIES = MAX_L4_RULES;
    public static final int MAX_RULE_ENTRIES = MAX_GATE_ENTRIES + MAX_L4_RULES;
    public static final int RULE_ENTRY_BYTES = 120;
    public static final int BUNDLE_HEADER_BYTES = 136;
    public static final int BUNDLE_BYTES = BUNDLE_HEADER_BYTES
            + (MAX_RULE_ENTRIES * RULE_ENTRY_BYTES);
    public static final String BUNDLE_FORMAT = "sakamoto-policy-bundle/v1";

    private static final int RULE_KIND_GATE = 1;
    private static final int RULE_KIND_L4 = 2;
    private static final int IP_FAMILY_IPV4 = 4;
    private static final int IP_FAMILY_IPV6 = 6;
    private static final int IP_PROTOCOL_TCP = 6;
    private static final int IP_PROTOCOL_UDP = 17;
    private static final int DIRECTION_INPUT = 1;
    private static final int DIRECTION_OUTPUT = 3;
    private static final int ACTION_PASS_NEXT = 1;
    private static final int ACTION_DROP = 2;
    private static final int IFINDEX_ANY = -1;
    private static final int POLICY_IDENTITY_BYTES = 96;

    public enum NetworkContextId {
        WIFI(1, "wifi"),
        MOBILE(2, "mobile"),
        VPN(3, "vpn");

        public final int wireId;
        public final String wireName;

        NetworkContextId(int wireId, String wireName) {
            this.wireId = wireId;
            this.wireName = wireName;
        }

        public static NetworkContextId parse(String value) {
            for (NetworkContextId candidate : values()) {
                if (candidate.wireName.equals(value)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unsupported network context: " + value);
        }
    }

    public enum IpFamily {
        IPV4("ipv4"),
        IPV6("ipv6");

        public final String wireName;

        IpFamily(String wireName) {
            this.wireName = wireName;
        }

        public static IpFamily parse(String value) {
            for (IpFamily candidate : values()) {
                if (candidate.wireName.equals(value)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unsupported L4 family: " + value);
        }
    }

    public enum PacketDirection {
        INPUT("input"),
        OUTPUT("output");

        public final String wireName;

        PacketDirection(String wireName) {
            this.wireName = wireName;
        }

        public static PacketDirection parse(String value) {
            for (PacketDirection candidate : values()) {
                if (candidate.wireName.equals(value)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unsupported packet direction: " + value);
        }
    }

    public enum L4Action {
        ALLOW("allow"),
        DROP("drop");

        public final String wireName;

        L4Action(String wireName) {
            this.wireName = wireName;
        }

        public static L4Action parse(String value) {
            for (L4Action candidate : values()) {
                if (candidate.wireName.equals(value)) {
                    return candidate;
                }
            }
            throw new IllegalArgumentException("unsupported L4 action: " + value);
        }
    }

    public static final class PortRange {
        public final int first;
        public final int last;

        private PortRange(int first, int last) {
            if (first < 0 || first > 65535 || last < 0 || last > 65535 || first > last) {
                throw new IllegalArgumentException("L4 port range must be valid u16 first..last");
            }
            this.first = first;
            this.last = last;
        }

        public static PortRange exact(int port) {
            return new PortRange(port, port);
        }

        public static PortRange inclusive(int first, int last) {
            return new PortRange(first, last);
        }
    }

    public static final class L4Rule implements Comparable<L4Rule> {
        public final ApplicationSubjectId subjectId;
        public final IpFamily family;
        public final String sourceCidr;
        public final String destinationCidr;
        public final PortRange sourcePorts;
        public final PortRange destinationPorts;
        public final int ipProtocol;
        public final PacketDirection direction;
        public final NetworkContextId networkContext;
        public final L4Action action;
        public final int ifIndex;
        public final boolean enabled;
        public final int priority;
        public final int order;
        public final long ruleId;
        public final int reasonId;

        public L4Rule(ApplicationSubjectId subjectId, IpFamily family, String sourceCidr,
                      String destinationCidr, PortRange sourcePorts, PortRange destinationPorts,
                      int ipProtocol, PacketDirection direction, NetworkContextId networkContext,
                      L4Action action, int priority, int order, long ruleId, int reasonId) {
            this(subjectId, family, sourceCidr, destinationCidr, sourcePorts, destinationPorts,
                    ipProtocol, direction, networkContext, action, priority, order, ruleId,
                    reasonId, 0, true);
        }

        public L4Rule(ApplicationSubjectId subjectId, IpFamily family, String sourceCidr,
                      String destinationCidr, PortRange sourcePorts, PortRange destinationPorts,
                      int ipProtocol, PacketDirection direction, NetworkContextId networkContext,
                      L4Action action, int priority, int order, long ruleId, int reasonId,
                      int ifIndex, boolean enabled) {
            if (subjectId == null) {
                throw new IllegalArgumentException("L4 subject is required");
            }
            if (family == null) {
                throw new IllegalArgumentException("L4 family is required");
            }
            if (direction == null) {
                throw new IllegalArgumentException("L4 packet direction is required");
            }
            if (action == null) {
                throw new IllegalArgumentException("L4 action is required");
            }
            if (ipProtocol < 0 || ipProtocol > 255) {
                throw new IllegalArgumentException("L4 ipProtocol must be u8");
            }
            if (ruleId <= 0L) {
                throw new IllegalArgumentException("L4 ruleId must be stable positive");
            }
            if (reasonId <= 0) {
                throw new IllegalArgumentException("L4 reasonId must be stable positive");
            }
            if (priority < 0 || order < 0) {
                throw new IllegalArgumentException("L4 priority/order must be non-negative");
            }
            if (ifIndex < 0) {
                throw new IllegalArgumentException("L4 ifIndex must be non-negative");
            }
            this.subjectId = subjectId;
            this.family = family;
            this.sourceCidr = normalizeOptional(sourceCidr);
            this.destinationCidr = normalizeOptional(destinationCidr);
            this.sourcePorts = sourcePorts;
            this.destinationPorts = destinationPorts;
            this.ipProtocol = ipProtocol;
            this.direction = direction;
            this.networkContext = networkContext;
            this.action = action;
            this.ifIndex = ifIndex;
            this.enabled = enabled;
            this.priority = priority;
            this.order = order;
            this.ruleId = ruleId;
            this.reasonId = reasonId;
        }

        public static L4Rule create(ApplicationSubjectId subjectId, IpFamily family,
                                    String sourceCidr, String destinationCidr,
                                    PortRange sourcePorts, PortRange destinationPorts,
                                    int ipProtocol, PacketDirection direction,
                                    NetworkContextId networkContext, L4Action action,
                                    int priority, int order) {
            String normalizedSource = normalizeOptional(sourceCidr);
            String normalizedDestination = normalizeOptional(destinationCidr);
            long ruleId = stableRuleId(subjectId, family, normalizedSource,
                    normalizedDestination, sourcePorts, destinationPorts, ipProtocol,
                    direction, networkContext, action, priority, order);
            return new L4Rule(subjectId, family, sourceCidr, destinationCidr, sourcePorts,
                    destinationPorts, ipProtocol, direction, networkContext, action, priority,
                    order, ruleId, stableReasonId(subjectId, ipProtocol, order), 0, true);
        }

        public static L4Rule create(ApplicationSubjectId subjectId, IpFamily family,
                                    String sourceCidr, String destinationCidr,
                                    PortRange sourcePorts, PortRange destinationPorts,
                                    int ipProtocol, PacketDirection direction,
                                    NetworkContextId networkContext, L4Action action,
                                    int priority, int order, int ifIndex, boolean enabled) {
            String normalizedSource = normalizeOptional(sourceCidr);
            String normalizedDestination = normalizeOptional(destinationCidr);
            long ruleId = stableRuleId(subjectId, family, normalizedSource,
                    normalizedDestination, sourcePorts, destinationPorts, ipProtocol,
                    direction, networkContext, action, priority, order);
            return new L4Rule(subjectId, family, sourceCidr, destinationCidr, sourcePorts,
                    destinationPorts, ipProtocol, direction, networkContext, action, priority,
                    order, ruleId, stableReasonId(subjectId, ipProtocol, order), ifIndex,
                    enabled);
        }

        @Override
        public int compareTo(L4Rule other) {
            int bySubject = subjectId.compareTo(other.subjectId);
            if (bySubject != 0) {
                return bySubject;
            }
            if (priority != other.priority) {
                return Integer.compare(priority, other.priority);
            }
            if (order != other.order) {
                return Integer.compare(order, other.order);
            }
            return Long.compareUnsigned(ruleId, other.ruleId);
        }

        private static String normalizeOptional(String value) {
            return value == null ? "" : value.trim();
        }

        private static long stableRuleId(ApplicationSubjectId subjectId, IpFamily family,
                                         String sourceCidr, String destinationCidr,
                                         PortRange sourcePorts, PortRange destinationPorts,
                                         int ipProtocol, PacketDirection direction,
                                         NetworkContextId networkContext, L4Action action,
                                         int priority, int order) {
            long hash = 0xcbf29ce484222325L;
            hash = mixStableRuleHash(hash, subjectId.uid);
            hash = mixStableRuleHash(hash, family.ordinal());
            hash = mixStableRuleHash(hash, sourceCidr);
            hash = mixStableRuleHash(hash, destinationCidr);
            hash = mixStableRuleHash(hash, sourcePorts == null ? -1 : sourcePorts.first);
            hash = mixStableRuleHash(hash, sourcePorts == null ? -1 : sourcePorts.last);
            hash = mixStableRuleHash(hash,
                    destinationPorts == null ? -1 : destinationPorts.first);
            hash = mixStableRuleHash(hash,
                    destinationPorts == null ? -1 : destinationPorts.last);
            hash = mixStableRuleHash(hash, ipProtocol);
            hash = mixStableRuleHash(hash, direction.ordinal());
            hash = mixStableRuleHash(hash, networkContext == null ? -1 : networkContext.wireId);
            hash = mixStableRuleHash(hash, priority);
            hash = mixStableRuleHash(hash, order);
            return 0x5200000000000000L | (hash & 0x00ffffffffffffffL);
        }

        private static int stableReasonId(ApplicationSubjectId subjectId, int ipProtocol,
                                          int order) {
            return 0x52000000 | ((subjectId.uid & 0x00ffff) << 8)
                    | ((ipProtocol & 0xff) ^ (order & 0xff));
        }

        private static long mixStableRuleHash(long hash, int value) {
            long next = hash;
            for (int shift = 0; shift < 32; shift += 8) {
                next ^= (value >>> shift) & 0xffL;
                next *= 0x100000001b3L;
            }
            return next;
        }

        private static long mixStableRuleHash(long hash, String value) {
            long next = mixStableRuleHash(hash, value.length());
            for (int index = 0; index < value.length(); ++index) {
                next ^= value.charAt(index) & 0xffL;
                next *= 0x100000001b3L;
            }
            return next;
        }
    }

    public static final class NetworkGateRule implements Comparable<NetworkGateRule> {
        public final ApplicationSubjectId subjectId;
        public final NetworkContextId networkContext;
        public final boolean blocked;
        public final int ifIndex;
        public final boolean enabled;
        public final long ruleId;
        public final int reasonId;

        public NetworkGateRule(ApplicationSubjectId subjectId, NetworkContextId networkContext,
                               boolean blocked, long ruleId, int reasonId) {
            this(subjectId, networkContext, blocked, ruleId, reasonId, 0, true);
        }

        public NetworkGateRule(ApplicationSubjectId subjectId, NetworkContextId networkContext,
                               boolean blocked, long ruleId, int reasonId,
                               int ifIndex, boolean enabled) {
            if (subjectId == null) {
                throw new IllegalArgumentException("network gate subject is required");
            }
            if (networkContext == null) {
                throw new IllegalArgumentException("network gate context is required");
            }
            if (ruleId <= 0L) {
                throw new IllegalArgumentException("network gate ruleId must be stable positive");
            }
            if (reasonId <= 0) {
                throw new IllegalArgumentException("network gate reasonId must be stable positive");
            }
            if (ifIndex < 0) {
                throw new IllegalArgumentException("network gate ifIndex must be non-negative");
            }
            this.subjectId = subjectId;
            this.networkContext = networkContext;
            this.blocked = blocked;
            this.ifIndex = ifIndex;
            this.enabled = enabled;
            this.ruleId = ruleId;
            this.reasonId = reasonId;
        }

        public static NetworkGateRule create(ApplicationSubjectId subjectId,
                                             NetworkContextId networkContext, boolean blocked) {
            long ruleId = stableRuleId(subjectId, networkContext);
            return new NetworkGateRule(subjectId, networkContext, blocked, ruleId,
                    stableReasonId(subjectId, networkContext), 0, true);
        }

        public static NetworkGateRule create(ApplicationSubjectId subjectId,
                                             NetworkContextId networkContext, boolean blocked,
                                             int ifIndex, boolean enabled) {
            long ruleId = stableRuleId(subjectId, networkContext);
            return new NetworkGateRule(subjectId, networkContext, blocked, ruleId,
                    stableReasonId(subjectId, networkContext), ifIndex, enabled);
        }

        public NetworkGateRule withBlocked(boolean nextBlocked) {
            return new NetworkGateRule(subjectId, networkContext, nextBlocked, ruleId, reasonId,
                    ifIndex, enabled);
        }

        @Override
        public int compareTo(NetworkGateRule other) {
            int bySubject = subjectId.compareTo(other.subjectId);
            if (bySubject != 0) {
                return bySubject;
            }
            return Integer.compare(networkContext.wireId, other.networkContext.wireId);
        }

        private static long stableRuleId(ApplicationSubjectId subjectId,
                                         NetworkContextId networkContext) {
            return 0x5100000000000000L
                    | (((long) subjectId.uid & 0xffffffffL) << 8)
                    | (long) networkContext.wireId;
        }

        private static int stableReasonId(ApplicationSubjectId subjectId,
                                          NetworkContextId networkContext) {
            return 0x51000000 | ((subjectId.uid & 0x00ffff) << 4) | networkContext.wireId;
        }
    }

    public final int schemaVersion;
    public final long revision;
    public final String source;
    public final List<NetworkGateRule> gateMatrix;
    public final List<L4Rule> l4Rules;
    public final int gateEntryCount;
    public final int l4RuleCount;
    public final int protocolRuleCount;

    private AuthoringPolicyBundle(int schemaVersion, long revision, String source,
                                  List<NetworkGateRule> gateMatrix, List<L4Rule> l4Rules,
                                  int declaredL4RuleCount, int protocolRuleCount) {
        this.schemaVersion = schemaVersion;
        this.revision = revision;
        this.source = source == null ? "" : source;
        ArrayList<NetworkGateRule> ordered = new ArrayList<>();
        if (gateMatrix != null) {
            ordered.addAll(gateMatrix);
            Collections.sort(ordered);
        }
        for (int index = 1; index < ordered.size(); index++) {
            NetworkGateRule previous = ordered.get(index - 1);
            NetworkGateRule current = ordered.get(index);
            if (previous.subjectId.equals(current.subjectId)
                    && previous.networkContext == current.networkContext) {
                throw new IllegalArgumentException(
                        "GateMatrix subject/context entries must be unique");
            }
        }
        this.gateMatrix = Collections.unmodifiableList(ordered);
        this.gateEntryCount = ordered.size();
        ArrayList<L4Rule> orderedL4 = new ArrayList<>();
        if (l4Rules != null) {
            orderedL4.addAll(l4Rules);
            Collections.sort(orderedL4);
        }
        for (int index = 1; index < orderedL4.size(); index++) {
            L4Rule previous = orderedL4.get(index - 1);
            L4Rule current = orderedL4.get(index);
            if (previous.subjectId.equals(current.subjectId)
                    && previous.ruleId == current.ruleId) {
                throw new IllegalArgumentException("L4RuleList subject/ruleId entries must be unique");
            }
        }
        this.l4Rules = Collections.unmodifiableList(orderedL4);
        this.l4RuleCount = declaredL4RuleCount >= 0 ? declaredL4RuleCount : orderedL4.size();
        this.protocolRuleCount = protocolRuleCount;
    }

    public static AuthoringPolicyBundle empty() {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, 0L, "", Collections.emptyList(),
                Collections.emptyList(), -1, 0);
    }

    public static AuthoringPolicyBundle restore(long revision, String source,
                                                List<NetworkGateRule> gateMatrix,
                                                int l4RuleCount, int protocolRuleCount) {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, revision, source, gateMatrix,
                Collections.emptyList(), l4RuleCount, protocolRuleCount);
    }

    public static AuthoringPolicyBundle restore(long revision, String source,
                                                List<NetworkGateRule> gateMatrix,
                                                List<L4Rule> l4Rules, int protocolRuleCount) {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, revision, source, gateMatrix,
                l4Rules, -1, protocolRuleCount);
    }

    public boolean isEmpty() {
        return gateEntryCount == 0 && l4RuleCount == 0 && protocolRuleCount == 0;
    }

    public AuthoringPolicyBundle withNetworkGate(ApplicationSubjectId subjectId,
                                                NetworkContextId networkContext,
                                                boolean blocked) {
        ArrayList<NetworkGateRule> next = new ArrayList<>();
        boolean replaced = false;
        for (NetworkGateRule rule : gateMatrix) {
            if (rule.subjectId.equals(subjectId) && rule.networkContext == networkContext) {
                next.add(rule.withBlocked(blocked));
                replaced = true;
            } else {
                next.add(rule);
            }
        }
        if (!replaced) {
            next.add(NetworkGateRule.create(subjectId, networkContext, blocked));
        }
        return new AuthoringPolicyBundle(SCHEMA_VERSION, revision + 1L,
                LOCAL_PRODUCT_BACKEND_SOURCE, next, l4Rules, -1, protocolRuleCount);
    }

    public AuthoringPolicyBundle withL4Rule(L4Rule nextRule) {
        ArrayList<L4Rule> next = new ArrayList<>();
        boolean replaced = false;
        for (L4Rule rule : l4Rules) {
            if (rule.subjectId.equals(nextRule.subjectId) && rule.ruleId == nextRule.ruleId) {
                next.add(nextRule);
                replaced = true;
            } else {
                next.add(rule);
            }
        }
        if (!replaced) {
            next.add(nextRule);
        }
        return new AuthoringPolicyBundle(SCHEMA_VERSION, revision + 1L,
                LOCAL_PRODUCT_BACKEND_SOURCE, gateMatrix, next, -1, protocolRuleCount);
    }

    /** Validate the complete fixed-capacity native successor before one-shot apply. */
    public void validateForNativeBundle() {
        if (schemaVersion != SCHEMA_VERSION) {
            throw new IllegalArgumentException("unsupported authoring policy schema");
        }
        if (revision <= 0L) {
            throw new IllegalArgumentException("native policy bundle revision must be positive");
        }
        if (protocolRuleCount != 0) {
            throw new IllegalArgumentException("unsupported protocol rules in native bundle");
        }
        if (gateEntryCount != gateMatrix.size() || l4RuleCount != l4Rules.size()) {
            throw new IllegalArgumentException("native bundle rule counts do not match entries");
        }
        if (gateEntryCount > MAX_GATE_ENTRIES || l4RuleCount > MAX_L4_RULES
                || gateEntryCount + l4RuleCount > MAX_RULE_ENTRIES) {
            throw new IllegalArgumentException("native policy bundle exceeds fixed capacity");
        }
        Set<Long> ruleIds = new HashSet<>();
        for (NetworkGateRule rule : gateMatrix) {
            if (rule == null || rule.subjectId == null || rule.networkContext == null
                    || rule.networkContext.wireId <= 0 || rule.ifIndex < 0
                    || rule.ruleId <= 0L || rule.reasonId <= 0
                    || !ruleIds.add(rule.ruleId)) {
                throw new IllegalArgumentException("invalid or duplicate native Gate entry");
            }
        }
        for (L4Rule rule : l4Rules) {
            if (rule == null || rule.subjectId == null
                    || (rule.networkContext != null && rule.networkContext.wireId <= 0)
                    || rule.ifIndex < 0
                    || rule.family == null || rule.direction == null || rule.action == null
                    || rule.ruleId <= 0L || rule.reasonId <= 0
                    || !ruleIds.add(rule.ruleId)) {
                throw new IllegalArgumentException("invalid or duplicate native L4 entry");
            }
            if (rule.family == IpFamily.IPV4 && rule.ipProtocol != IP_PROTOCOL_TCP
                    && rule.ipProtocol != IP_PROTOCOL_UDP) {
                throw new IllegalArgumentException("native IPv4 L4 protocol must be TCP/UDP");
            }
            if (rule.family == IpFamily.IPV6 && rule.ipProtocol != IP_PROTOCOL_TCP
                    && rule.ipProtocol != IP_PROTOCOL_UDP) {
                throw new IllegalArgumentException("native IPv6 L4 protocol must be TCP/UDP");
            }
            if (rule.priority < 0 || rule.order < 0) {
                throw new IllegalArgumentException("native L4 priority/order must be non-negative");
            }
            validateCidr(rule.sourceCidr, rule.family, "source");
            validateCidr(rule.destinationCidr, rule.family, "destination");
        }
    }

    /** Encode one complete successor into the fixed Product Core wire layout. */
    public byte[] toNativeBundlePayload() {
        return toNativeBundlePayload(nativeSnapshotHash(), BUNDLE_FORMAT);
    }

    /** Encode one complete successor with the caller's persisted identity/hash. */
    public byte[] toNativeBundlePayload(long snapshotHash, String snapshotIdentity) {
        validateForNativeBundle();
        if (snapshotHash == 0L || snapshotIdentity == null || snapshotIdentity.isEmpty()) {
            throw new IllegalArgumentException("native policy bundle identity/hash is required");
        }
        byte[] identity = snapshotIdentity.getBytes(StandardCharsets.US_ASCII);
        for (int index = 0; index < snapshotIdentity.length(); ++index) {
            char ch = snapshotIdentity.charAt(index);
            if (ch == 0 || ch > 0x7f) {
                throw new IllegalArgumentException("native policy bundle identity is not ASCII");
            }
        }
        if (identity.length >= POLICY_IDENTITY_BYTES || containsPropertyDelimiter(identity)) {
            throw new IllegalArgumentException("native policy bundle identity is not bounded");
        }
        ByteBuffer wire = ByteBuffer.allocate(BUNDLE_BYTES).order(ByteOrder.LITTLE_ENDIAN);
        wire.putInt(BUNDLE_ABI_VERSION);
        wire.putInt(BUNDLE_BYTES);
        wire.putLong(revision);
        wire.putLong(snapshotHash);
        wire.putInt(gateEntryCount);
        wire.putInt(l4RuleCount);
        wire.putInt(1);
        wire.putInt(0);
        wire.put(identity);
        wire.position(BUNDLE_HEADER_BYTES);
        for (int index = 0; index < MAX_GATE_ENTRIES; ++index) {
            if (index < gateEntryCount) {
                putGateEntry(wire, gateMatrix.get(index));
            } else {
                wire.position(wire.position() + RULE_ENTRY_BYTES);
            }
        }
        for (int index = 0; index < MAX_L4_RULES; ++index) {
            if (index < l4RuleCount) {
                putL4Entry(wire, l4Rules.get(index));
            } else {
                wire.position(wire.position() + RULE_ENTRY_BYTES);
            }
        }
        return wire.array();
    }

    private static void putGateEntry(ByteBuffer wire, NetworkGateRule rule) {
        wire.putInt(rule.subjectId.uid);
        wire.putInt(rule.networkContext.wireId);
        wire.putInt(wireIfIndex(rule.ifIndex));
        wire.putInt(RULE_KIND_GATE);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(rule.blocked ? ACTION_DROP : ACTION_PASS_NEXT);
        wire.putInt(rule.enabled ? 1 : 0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(0);
        wire.putInt(rule.reasonId);
        wire.putInt(0);
        wire.putInt(0); // C ABI alignment padding before the u64 rule ID.
        wire.putLong(rule.ruleId);
        wire.position(wire.position() + 32);
    }

    private static void putL4Entry(ByteBuffer wire, L4Rule rule) {
        wire.putInt(rule.subjectId.uid);
        wire.putInt(rule.networkContext == null ? -1 : rule.networkContext.wireId);
        wire.putInt(wireIfIndex(rule.ifIndex));
        wire.putInt(RULE_KIND_L4);
        wire.putInt(rule.family == IpFamily.IPV4 ? IP_FAMILY_IPV4 : IP_FAMILY_IPV6);
        wire.putInt(rule.ipProtocol);
        wire.putInt(rule.direction == PacketDirection.INPUT ? DIRECTION_INPUT : DIRECTION_OUTPUT);
        wire.putInt(rule.action == L4Action.ALLOW ? ACTION_PASS_NEXT : ACTION_DROP);
        wire.putInt(rule.enabled ? 1 : 0);
        Cidr source = parseCidr(rule.sourceCidr, rule.family, "source");
        Cidr destination = parseCidr(rule.destinationCidr, rule.family, "destination");
        wire.putInt(source.prefixLength);
        wire.putInt(destination.prefixLength);
        putRange(wire, rule.sourcePorts);
        putRange(wire, rule.destinationPorts);
        wire.putInt(rule.priority);
        wire.putInt(rule.order);
        wire.putInt(rule.reasonId);
        wire.putInt(0);
        wire.putInt(0); // C ABI alignment padding before the u64 rule ID.
        wire.putLong(rule.ruleId);
        wire.put(source.address);
        wire.put(destination.address);
    }

    private static void putRange(ByteBuffer wire, PortRange range) {
        wire.putInt(range == null ? 0 : range.first);
        wire.putInt(range == null ? 65535 : range.last);
    }

    private static int wireIfIndex(int ifIndex) {
        // Existing authoring constructors use zero for an unspecified
        // interface; the matcher ABI reserves UINT32_MAX for that wildcard.
        return ifIndex == 0 ? IFINDEX_ANY : ifIndex;
    }

    private static Cidr parseCidr(String value, IpFamily family, String label) {
        String normalized = value == null ? "" : value.trim();
        int bits = family == IpFamily.IPV4 ? 32 : 128;
        if (normalized.isEmpty()) {
            return new Cidr(new byte[16], 0);
        }
        String[] parts = normalized.split("/", -1);
        if (parts.length > 2 || parts[0].isEmpty() || !isAddressLiteral(parts[0])) {
            throw new IllegalArgumentException("invalid " + label + " CIDR");
        }
        int prefix = bits;
        if (parts.length == 2) {
            try {
                prefix = Integer.parseInt(parts[1]);
            } catch (NumberFormatException error) {
                throw new IllegalArgumentException("invalid " + label + " CIDR prefix", error);
            }
        }
        if (prefix < 0 || prefix > bits) {
            throw new IllegalArgumentException("invalid " + label + " CIDR prefix");
        }
        final byte[] raw;
        try {
            raw = InetAddress.getByName(parts[0]).getAddress();
        } catch (UnknownHostException error) {
            throw new IllegalArgumentException("invalid " + label + " CIDR address", error);
        }
        if ((family == IpFamily.IPV4 && raw.length != 4)
                || (family == IpFamily.IPV6 && raw.length != 16)) {
            throw new IllegalArgumentException("" + label + " CIDR family does not match rule");
        }
        byte[] address = new byte[16];
        if (raw.length == 4) {
            // The new bundle follows PacketFacts' canonical endpoint shape.
            // S191's scalar snapshot has a separate, legacy tail placement.
            System.arraycopy(raw, 0, address, 0, raw.length);
        } else {
            System.arraycopy(raw, 0, address, 0, raw.length);
        }
        return new Cidr(address, prefix);
    }

    private static void validateCidr(String value, IpFamily family, String label) {
        parseCidr(value, family, label);
    }

    private static boolean isAddressLiteral(String value) {
        for (int index = 0; index < value.length(); ++index) {
            char ch = value.charAt(index);
            if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f')
                    || (ch >= 'A' && ch <= 'F') || ch == '.' || ch == ':')) {
                return false;
            }
        }
        return true;
    }

    private static boolean containsPropertyDelimiter(byte[] value) {
        for (byte ch : value) {
            if (ch == '\n' || ch == '\r' || ch == '=') {
                return true;
            }
        }
        return false;
    }

    long nativeSnapshotHash() {
        long hash = 0xcbf29ce484222325L;
        hash = mixStableRuleHash(hash, (int) revision);
        hash = mixStableRuleHash(hash, (int) (revision >>> 32));
        hash = mixStableRuleHash(hash, gateEntryCount);
        hash = mixStableRuleHash(hash, l4RuleCount);
        for (NetworkGateRule rule : gateMatrix) {
            hash = mixStableRuleHash(hash, rule.subjectId.uid);
            hash = mixStableRuleHash(hash, rule.networkContext.wireId);
            hash = mixStableRuleHash(hash, wireIfIndex(rule.ifIndex));
            hash = mixStableRuleHash(hash, rule.blocked ? 1 : 0);
            hash = mixStableRuleHash(hash, rule.enabled ? 1 : 0);
            hash = mixStableRuleHash(hash, rule.reasonId);
            hash = mixStableRuleHash(hash, (int) rule.ruleId);
            hash = mixStableRuleHash(hash, (int) (rule.ruleId >>> 32));
        }
        for (L4Rule rule : l4Rules) {
            hash = mixStableRuleHash(hash, rule.subjectId.uid);
            hash = mixStableRuleHash(hash,
                    rule.networkContext == null ? -1 : rule.networkContext.wireId);
            hash = mixStableRuleHash(hash, wireIfIndex(rule.ifIndex));
            hash = mixStableRuleHash(hash, rule.family == IpFamily.IPV4 ? IP_FAMILY_IPV4
                    : IP_FAMILY_IPV6);
            hash = mixStableRuleHash(hash, rule.ipProtocol);
            hash = mixStableRuleHash(hash, rule.direction == PacketDirection.INPUT
                    ? DIRECTION_INPUT : DIRECTION_OUTPUT);
            hash = mixStableRuleHash(hash, rule.action == L4Action.ALLOW
                    ? ACTION_PASS_NEXT : ACTION_DROP);
            hash = mixStableRuleHash(hash, rule.enabled ? 1 : 0);
            hash = mixStableRuleHash(hash, rule.sourceCidr);
            hash = mixStableRuleHash(hash, rule.destinationCidr);
            hash = mixStableRuleHash(hash, rule.sourcePorts == null ? -1 : rule.sourcePorts.first);
            hash = mixStableRuleHash(hash, rule.sourcePorts == null ? -1 : rule.sourcePorts.last);
            hash = mixStableRuleHash(hash,
                    rule.destinationPorts == null ? -1 : rule.destinationPorts.first);
            hash = mixStableRuleHash(hash,
                    rule.destinationPorts == null ? -1 : rule.destinationPorts.last);
            hash = mixStableRuleHash(hash, rule.priority);
            hash = mixStableRuleHash(hash, rule.order);
            hash = mixStableRuleHash(hash, rule.reasonId);
            hash = mixStableRuleHash(hash, (int) rule.ruleId);
            hash = mixStableRuleHash(hash, (int) (rule.ruleId >>> 32));
        }
        return hash == 0L ? 1L : hash;
    }

    private static long mixStableRuleHash(long hash, int value) {
        long next = hash;
        for (int shift = 0; shift < 32; shift += 8) {
            next ^= (value >>> shift) & 0xffL;
            next *= 0x100000001b3L;
        }
        return next;
    }

    private static long mixStableRuleHash(long hash, String value) {
        long next = mixStableRuleHash(hash, value.length());
        for (int index = 0; index < value.length(); ++index) {
            next ^= value.charAt(index) & 0xffL;
            next *= 0x100000001b3L;
        }
        return next;
    }

    private static final class Cidr {
        final byte[] address;
        final int prefixLength;

        Cidr(byte[] address, int prefixLength) {
            this.address = address;
            this.prefixLength = prefixLength;
        }
    }
}
