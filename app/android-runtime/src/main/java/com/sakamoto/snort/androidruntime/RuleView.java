package com.sakamoto.snort.androidruntime;

/** Product-facing committed rule view. */
public final class RuleView {
    public final long ruleId;
    public final String family;
    public final String label;
    public final String action;
    public final String status;
    public final long policyRevision;
    public final boolean winnerEligible;

    public RuleView(long ruleId, String family, String label, String action, String status,
                    long policyRevision, boolean winnerEligible) {
        if (ruleId <= 0L) {
            throw new IllegalArgumentException("ruleId must be positive");
        }
        this.ruleId = ruleId;
        this.family = bounded(family);
        this.label = bounded(label);
        this.action = bounded(action);
        this.status = bounded(status == null || status.trim().isEmpty()
                ? "enabled" : status);
        this.policyRevision = Math.max(0L, policyRevision);
        this.winnerEligible = winnerEligible;
    }

    public static RuleView networkGate(AuthoringPolicyBundle.NetworkGateRule rule,
                                       long policyRevision) {
        if (rule == null) {
            throw new IllegalArgumentException("rule is required");
        }
        return new RuleView(rule.ruleId, "network_gate",
                rule.networkContext.wireName + " gate for " + rule.subjectId.encode(),
                rule.blocked ? "drop" : "pass_next",
                rule.blocked ? "enabled" : "open", policyRevision, rule.blocked);
    }

    public static RuleView l4(AuthoringPolicyBundle.L4Rule rule, long policyRevision) {
        if (rule == null) {
            throw new IllegalArgumentException("rule is required");
        }
        return new RuleView(rule.ruleId, "l4",
                rule.family.wireName + " proto " + rule.ipProtocol + " "
                        + (rule.destinationCidr.isEmpty() ? "any" : rule.destinationCidr),
                rule.action.wireName, "enabled", policyRevision, true);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
