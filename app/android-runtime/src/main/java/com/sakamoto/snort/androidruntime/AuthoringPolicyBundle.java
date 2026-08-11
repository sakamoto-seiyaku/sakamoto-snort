package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Local product authoring bundle: stage-owned typed rule families under one revision. */
public final class AuthoringPolicyBundle {
    public static final int SCHEMA_VERSION = 1;
    public static final String LOCAL_PRODUCT_BACKEND_SOURCE = "local-product-backend";

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
        public final int priority;
        public final int order;
        public final long ruleId;
        public final int reasonId;

        public L4Rule(ApplicationSubjectId subjectId, IpFamily family, String sourceCidr,
                      String destinationCidr, PortRange sourcePorts, PortRange destinationPorts,
                      int ipProtocol, PacketDirection direction, NetworkContextId networkContext,
                      L4Action action, int priority, int order, long ruleId, int reasonId) {
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
            long ruleId = stableRuleId(subjectId, family, ipProtocol, priority, order);
            return new L4Rule(subjectId, family, sourceCidr, destinationCidr, sourcePorts,
                    destinationPorts, ipProtocol, direction, networkContext, action, priority,
                    order, ruleId, stableReasonId(subjectId, ipProtocol, order));
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
                                         int ipProtocol, int priority, int order) {
            return 0x5200000000000000L
                    | (((long) subjectId.uid & 0xffffffffL) << 16)
                    | (((long) family.ordinal() & 0x1L) << 15)
                    | (((long) ipProtocol & 0xffL) << 7)
                    | ((long) (priority + 32768) & 0x7fL)
                    | ((long) order & 0x7fL);
        }

        private static int stableReasonId(ApplicationSubjectId subjectId, int ipProtocol,
                                          int order) {
            return 0x52000000 | ((subjectId.uid & 0x00ffff) << 8)
                    | ((ipProtocol & 0xff) ^ (order & 0xff));
        }
    }

    public static final class NetworkGateRule implements Comparable<NetworkGateRule> {
        public final ApplicationSubjectId subjectId;
        public final NetworkContextId networkContext;
        public final boolean blocked;
        public final long ruleId;
        public final int reasonId;

        public NetworkGateRule(ApplicationSubjectId subjectId, NetworkContextId networkContext,
                               boolean blocked, long ruleId, int reasonId) {
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
            this.subjectId = subjectId;
            this.networkContext = networkContext;
            this.blocked = blocked;
            this.ruleId = ruleId;
            this.reasonId = reasonId;
        }

        public static NetworkGateRule create(ApplicationSubjectId subjectId,
                                             NetworkContextId networkContext, boolean blocked) {
            long ruleId = stableRuleId(subjectId, networkContext);
            return new NetworkGateRule(subjectId, networkContext, blocked, ruleId,
                    stableReasonId(subjectId, networkContext));
        }

        public NetworkGateRule withBlocked(boolean nextBlocked) {
            return new NetworkGateRule(subjectId, networkContext, nextBlocked, ruleId, reasonId);
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
}
