package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Map;
import java.util.TreeMap;

/** Compiles Local Product Backend authoring state into vNext packet-policy payloads. */
public final class AuthoringPolicyCompiler {
    private AuthoringPolicyCompiler() {}

    public static CompileResult compilePacketPolicyApply(AuthoringPolicyBundle bundle) {
        AuthoringPolicyBundle value = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
        if (value.schemaVersion != AuthoringPolicyBundle.SCHEMA_VERSION) {
            return CompileResult.failure("authoring_policy_bundle_unsupported_schema",
                    "authoring policy bundle schema is unsupported");
        }
        if (value.protocolRuleCount != 0) {
            return CompileResult.failure("authoring_policy_bundle_unsupported",
                    "Protocol authoring rule families are not compiled by this slice");
        }
        if (value.l4RuleCount != value.l4Rules.size()) {
            return CompileResult.failure("authoring_policy_bundle_invalid_l4_rules",
                    "L4RuleList count does not match its typed entries");
        }

        TreeMap<ApplicationSubjectId, SubjectPolicy> subjects = new TreeMap<>();
        for (AuthoringPolicyBundle.NetworkGateRule rule : value.gateMatrix) {
            if (rule == null) {
                return CompileResult.failure("authoring_policy_bundle_invalid_gate_matrix",
                        "GateMatrix contains an empty rule");
            }
            SubjectPolicy subject = subjects.get(rule.subjectId);
            if (subject == null) {
                subject = new SubjectPolicy(rule.subjectId);
                subjects.put(rule.subjectId, subject);
            }
            if (rule.blocked) {
                subject.blockedRules.add(rule);
            }
        }
        for (AuthoringPolicyBundle.L4Rule rule : value.l4Rules) {
            if (rule == null) {
                return CompileResult.failure("authoring_policy_bundle_invalid_l4_rules",
                        "L4RuleList contains an empty rule");
            }
            SubjectPolicy subject = subjects.get(rule.subjectId);
            if (subject == null) {
                subject = new SubjectPolicy(rule.subjectId);
                subjects.put(rule.subjectId, subject);
            }
            subject.l4Rules.add(rule);
        }

        StringBuilder out = new StringBuilder();
        out.append("{\"revision\":").append(value.revision).append(",\"subjects\":[");
        boolean firstSubject = true;
        for (Map.Entry<ApplicationSubjectId, SubjectPolicy> entry : subjects.entrySet()) {
            SubjectPolicy subject = entry.getValue();
            if (!firstSubject) {
                out.append(',');
            }
            out.append("{\"linuxUid\":").append(subject.subjectId.uid)
                    .append(",\"uidKnown\":true");
            if (!subject.blockedRules.isEmpty()) {
                out.append(",\"networkGate\":{\"rules\":[");
                for (int i = 0; i < subject.blockedRules.size(); ++i) {
                    if (i > 0) {
                        out.append(',');
                    }
                    AuthoringPolicyBundle.NetworkGateRule rule = subject.blockedRules.get(i);
                    out.append("{\"networkContext\":").append(rule.networkContext.wireId)
                            .append(",\"reasonId\":").append(rule.reasonId)
                            .append(",\"ruleId\":").append(Long.toUnsignedString(rule.ruleId))
                            .append('}');
                }
                out.append("]}");
            }
            out.append(",\"l4Rules\":[");
            for (int i = 0; i < subject.l4Rules.size(); ++i) {
                if (i > 0) {
                    out.append(',');
                }
                appendL4Rule(out, subject.l4Rules.get(i));
            }
            out.append(']');
            out.append('}');
            firstSubject = false;
        }
        out.append("]}");
        return CompileResult.success(out.toString(), value.revision);
    }

    private static void appendL4Rule(StringBuilder out, AuthoringPolicyBundle.L4Rule rule) {
        out.append("{\"ruleId\":").append(Long.toUnsignedString(rule.ruleId))
                .append(",\"reasonId\":").append(rule.reasonId)
                .append(",\"priority\":").append(rule.priority)
                .append(",\"order\":").append(rule.order)
                .append(",\"action\":\"").append(rule.action.wireName)
                .append("\",\"match\":{\"family\":\"").append(rule.family.wireName)
                .append("\",\"direction\":\"").append(rule.direction.wireName)
                .append("\",\"ipProtocol\":").append(rule.ipProtocol);
        if (!rule.sourceCidr.isEmpty()) {
            out.append(",\"sourceCidr\":\"").append(escape(rule.sourceCidr)).append('"');
        }
        if (!rule.destinationCidr.isEmpty()) {
            out.append(",\"destinationCidr\":\"").append(escape(rule.destinationCidr))
                    .append('"');
        }
        if (rule.networkContext != null) {
            out.append(",\"networkContexts\":[").append(rule.networkContext.wireId).append(']');
        }
        if (rule.sourcePorts != null) {
            appendPortRange(out, "sourcePorts", rule.sourcePorts);
        }
        if (rule.destinationPorts != null) {
            appendPortRange(out, "destinationPorts", rule.destinationPorts);
        }
        out.append("}}");
    }

    private static void appendPortRange(StringBuilder out, String key,
                                        AuthoringPolicyBundle.PortRange range) {
        out.append(",\"").append(key).append("\":{\"first\":").append(range.first)
                .append(",\"last\":").append(range.last).append('}');
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static final class SubjectPolicy {
        final ApplicationSubjectId subjectId;
        final ArrayList<AuthoringPolicyBundle.NetworkGateRule> blockedRules =
                new ArrayList<>();
        final ArrayList<AuthoringPolicyBundle.L4Rule> l4Rules = new ArrayList<>();

        SubjectPolicy(ApplicationSubjectId subjectId) {
            this.subjectId = subjectId;
        }
    }

    public static final class CompileResult {
        public final boolean ok;
        public final String applyPayload;
        public final long revision;
        public final String errorCode;
        public final String errorMessage;

        private CompileResult(boolean ok, String applyPayload, long revision, String errorCode,
                              String errorMessage) {
            this.ok = ok;
            this.applyPayload = applyPayload == null ? "" : applyPayload;
            this.revision = revision;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        static CompileResult success(String applyPayload, long revision) {
            return new CompileResult(true, applyPayload, revision, "", "");
        }

        static CompileResult failure(String errorCode, String errorMessage) {
            return new CompileResult(false, "", 0L, errorCode, errorMessage);
        }
    }
}
