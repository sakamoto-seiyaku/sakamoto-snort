package com.sakamoto.snort.androidruntime;

/** Product-facing authoring draft, including Activity-derived L4 prefill. */
public final class RuleDraft {
    public final ApplicationSubjectId subjectId;
    public final AuthoringPolicyBundle.IpFamily family;
    public final String destinationCidr;
    public final int destinationPort;
    public final int ipProtocol;
    public final AuthoringPolicyBundle.PacketDirection direction;
    public final AuthoringPolicyBundle.NetworkContextId networkContext;
    public final AuthoringPolicyBundle.L4Action action;
    public final String source;

    public RuleDraft(ApplicationSubjectId subjectId, AuthoringPolicyBundle.IpFamily family,
                     String destinationCidr, int destinationPort, int ipProtocol,
                     AuthoringPolicyBundle.PacketDirection direction,
                     AuthoringPolicyBundle.NetworkContextId networkContext,
                     AuthoringPolicyBundle.L4Action action, String source) {
        if (subjectId == null) {
            throw new IllegalArgumentException("subjectId is required");
        }
        if (family == null || direction == null || action == null) {
            throw new IllegalArgumentException("family, direction, and action are required");
        }
        if (destinationPort <= 0 || destinationPort > 65535) {
            throw new IllegalArgumentException("destinationPort must be 1..65535");
        }
        if (ipProtocol < 0 || ipProtocol > 255) {
            throw new IllegalArgumentException("ipProtocol must be u8");
        }
        this.subjectId = subjectId;
        this.family = family;
        this.destinationCidr = bounded(destinationCidr);
        this.destinationPort = destinationPort;
        this.ipProtocol = ipProtocol;
        this.direction = direction;
        this.networkContext = networkContext;
        this.action = action;
        this.source = bounded(source == null || source.trim().isEmpty()
                ? "manual" : source);
    }

    public static RuleDraft fromActivityL4RuleDraft(ActivityL4RuleDraft draft) {
        if (draft == null) {
            return null;
        }
        return new RuleDraft(draft.subjectId, draft.family, draft.destinationCidr,
                draft.destinationPorts.first, draft.ipProtocol, draft.direction,
                draft.networkContext, draft.action, "activity");
    }

    public AuthoringPolicyBundle.L4Rule toL4Rule() {
        return AuthoringPolicyBundle.L4Rule.create(subjectId, family,
                null, destinationCidr, null,
                AuthoringPolicyBundle.PortRange.exact(destinationPort),
                ipProtocol, direction, networkContext, action,
                ActivityL4RuleDraft.DEFAULT_PRIORITY, ActivityL4RuleDraft.DEFAULT_ORDER);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
