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
    public final int gateEntryCount;
    public final int l4RuleCount;
    public final int protocolRuleCount;

    private AuthoringPolicyBundle(int schemaVersion, long revision, String source,
                                  List<NetworkGateRule> gateMatrix, int l4RuleCount,
                                  int protocolRuleCount) {
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
        this.l4RuleCount = l4RuleCount;
        this.protocolRuleCount = protocolRuleCount;
    }

    public static AuthoringPolicyBundle empty() {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, 0L, "", Collections.emptyList(), 0, 0);
    }

    public static AuthoringPolicyBundle restore(long revision, String source,
                                                List<NetworkGateRule> gateMatrix,
                                                int l4RuleCount, int protocolRuleCount) {
        return new AuthoringPolicyBundle(SCHEMA_VERSION, revision, source, gateMatrix,
                l4RuleCount, protocolRuleCount);
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
                LOCAL_PRODUCT_BACKEND_SOURCE, next, l4RuleCount, protocolRuleCount);
    }
}
