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
        if (value.l4RuleCount != 0 || value.protocolRuleCount != 0) {
            return CompileResult.failure("authoring_policy_bundle_unsupported",
                    "L4 and Protocol authoring rule families are not compiled by this slice");
        }

        TreeMap<ApplicationSubjectId, SubjectGate> subjects = new TreeMap<>();
        for (AuthoringPolicyBundle.NetworkGateRule rule : value.gateMatrix) {
            if (rule == null) {
                return CompileResult.failure("authoring_policy_bundle_invalid_gate_matrix",
                        "GateMatrix contains an empty rule");
            }
            SubjectGate subject = subjects.get(rule.subjectId);
            if (subject == null) {
                subject = new SubjectGate(rule.subjectId);
                subjects.put(rule.subjectId, subject);
            }
            if (rule.blocked) {
                subject.blockedRules.add(rule);
            }
        }

        StringBuilder out = new StringBuilder();
        out.append("{\"revision\":").append(value.revision).append(",\"subjects\":[");
        boolean firstSubject = true;
        for (Map.Entry<ApplicationSubjectId, SubjectGate> entry : subjects.entrySet()) {
            SubjectGate subject = entry.getValue();
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
            out.append('}');
            firstSubject = false;
        }
        out.append("]}");
        return CompileResult.success(out.toString(), value.revision);
    }

    private static final class SubjectGate {
        final ApplicationSubjectId subjectId;
        final ArrayList<AuthoringPolicyBundle.NetworkGateRule> blockedRules =
                new ArrayList<>();

        SubjectGate(ApplicationSubjectId subjectId) {
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
