package com.sakamoto.snort.androidruntime;

/** Product-facing L4 rule draft derived from bounded Activity evidence. */
public final class ActivityL4RuleDraft {
    public static final int TCP_PROTOCOL = 6;
    public static final int DEFAULT_PRIORITY = 10;
    public static final int DEFAULT_ORDER = 0;

    public final ApplicationSubjectId subjectId;
    public final AuthoringPolicyBundle.IpFamily family;
    public final String destinationCidr;
    public final AuthoringPolicyBundle.PortRange destinationPorts;
    public final int ipProtocol;
    public final AuthoringPolicyBundle.PacketDirection direction;
    public final AuthoringPolicyBundle.NetworkContextId networkContext;
    public final AuthoringPolicyBundle.L4Action action;

    private ActivityL4RuleDraft(ApplicationSubjectId subjectId,
                                AuthoringPolicyBundle.IpFamily family,
                                String destinationCidr,
                                AuthoringPolicyBundle.PortRange destinationPorts,
                                int ipProtocol,
                                AuthoringPolicyBundle.PacketDirection direction,
                                AuthoringPolicyBundle.NetworkContextId networkContext,
                                AuthoringPolicyBundle.L4Action action) {
        this.subjectId = subjectId;
        this.family = family;
        this.destinationCidr = destinationCidr;
        this.destinationPorts = destinationPorts;
        this.ipProtocol = ipProtocol;
        this.direction = direction;
        this.networkContext = networkContext;
        this.action = action;
    }

    public static ActivityL4RuleDraft fromTcpPolicyDropActivity(
            String host, int port, int linuxUid, boolean uidKnown, int networkContext,
            String stage) {
        if (!uidKnown || linuxUid < 0 || port <= 0 || port > 65535
                || host == null || host.trim().isEmpty() || !"L4".equals(stage)) {
            return null;
        }
        String trimmedHost = host.trim();
        AuthoringPolicyBundle.IpFamily family = trimmedHost.indexOf(':') >= 0
                ? AuthoringPolicyBundle.IpFamily.IPV6 : AuthoringPolicyBundle.IpFamily.IPV4;
        String cidr = trimmedHost + (family == AuthoringPolicyBundle.IpFamily.IPV6
                ? "/128" : "/32");
        return new ActivityL4RuleDraft(ApplicationSubjectId.fromUid(linuxUid), family,
                cidr, AuthoringPolicyBundle.PortRange.exact(port), TCP_PROTOCOL,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                networkContextFromWireId(networkContext),
                AuthoringPolicyBundle.L4Action.DROP);
    }

    public AuthoringPolicyBundle.L4Rule toRule() {
        return AuthoringPolicyBundle.L4Rule.create(subjectId, family,
                null, destinationCidr, null, destinationPorts, ipProtocol,
                direction, networkContext, action, DEFAULT_PRIORITY, DEFAULT_ORDER);
    }

    public String summary() {
        return "L4 prefill: subject=" + subjectId.encode()
                + " family=" + family.wireName
                + " destinationCidr=" + destinationCidr
                + " destinationPort=" + destinationPorts.first
                + " ipProtocol=" + ipProtocol
                + " direction=" + direction.wireName
                + " networkContext=" + (networkContext == null
                ? "(none)" : networkContext.wireName)
                + " action=" + action.wireName
                + " priority=" + DEFAULT_PRIORITY
                + " order=" + DEFAULT_ORDER;
    }

    private static AuthoringPolicyBundle.NetworkContextId networkContextFromWireId(int wireId) {
        for (AuthoringPolicyBundle.NetworkContextId candidate
                : AuthoringPolicyBundle.NetworkContextId.values()) {
            if (candidate.wireId == wireId) {
                return candidate;
            }
        }
        return null;
    }
}
