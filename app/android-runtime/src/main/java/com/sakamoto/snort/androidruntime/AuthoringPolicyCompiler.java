package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

/** Compiles Local Product Backend authoring state into vNext packet-policy payloads. */
public final class AuthoringPolicyCompiler {
    private AuthoringPolicyCompiler() {}

    public static CompileResult compilePacketPolicyApply(AuthoringPolicyBundle bundle) {
        return compilePacketPolicyApply(bundle, false);
    }

    private static CompileResult compilePacketPolicyApply(AuthoringPolicyBundle bundle,
                                                           boolean forceNativeBundle) {
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
            subject.networkGateRules.add(rule);
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
            if (!subject.networkGateRules.isEmpty()) {
                out.append(",\"networkGate\":{\"rules\":[");
                for (int i = 0; i < subject.networkGateRules.size(); ++i) {
                    if (i > 0) {
                        out.append(',');
                    }
                    AuthoringPolicyBundle.NetworkGateRule rule = subject.networkGateRules.get(i);
                    out.append("{\"networkContext\":").append(rule.networkContext.wireId)
                            .append(",\"blocked\":").append(rule.blocked)
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
        byte[] nativeBundlePayload = null;
        long nativeBundleHash = 0L;
        if (forceNativeBundle || requiresCompleteNativeBundle(value)) {
            try {
                nativeBundlePayload = value.toNativeBundlePayload();
                nativeBundleHash = value.nativeSnapshotHash();
            } catch (IllegalArgumentException error) {
                return CompileResult.failure("authoring_policy_bundle_invalid_native_bundle",
                        error.getMessage() == null ? "native policy bundle is invalid"
                                : error.getMessage());
            }
        }
        out.append(']');
        if (nativeBundlePayload != null) {
            out.append(",\"bundleAbiVersion\":")
                    .append(AuthoringPolicyBundle.BUNDLE_ABI_VERSION)
                    .append(",\"bundleSnapshotHash\":\"")
                    .append(Long.toUnsignedString(nativeBundleHash))
                    .append('"')
                    .append(",\"bundlePayload\":\"")
                    .append(Base64.getEncoder().encodeToString(nativeBundlePayload))
                    .append('"');
        } else {
            // Scalar applies are retained only as an explicitly tagged S191 fallback.
            out.append(",\"nativeApply\":\"s191-scalar\"");
        }
        out.append('}');
        return CompileResult.success(out.toString(), value.revision, nativeBundlePayload);
    }

    private static boolean requiresCompleteNativeBundle(AuthoringPolicyBundle value) {
        return (value.gateEntryCount > 0 && value.l4RuleCount > 0)
                || value.gateEntryCount > 1 || value.l4RuleCount > 1;
    }

    /**
     * Compile a complete Gate + L4 successor for the typed one-shot native
     * apply path.  The legacy JSON payload remains available to S191 callers;
     * this method additionally returns the fixed-size native wire payload.
     */
    public static CompileResult compilePolicyBundle(AuthoringPolicyBundle bundle) {
        AuthoringPolicyBundle value = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
        if (value.isEmpty() && value.revision <= 0L) {
            // The initial empty authoring state has no successor yet. Native apply still needs
            // a positive revision, so materialize the first complete empty successor here.
            value = AuthoringPolicyBundle.restore(1L, value.source, value.gateMatrix,
                    value.l4Rules, value.protocolRuleCount);
        }
        return compilePacketPolicyApply(value, true);
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
        final ArrayList<AuthoringPolicyBundle.NetworkGateRule> networkGateRules =
                new ArrayList<>();
        final ArrayList<AuthoringPolicyBundle.L4Rule> l4Rules = new ArrayList<>();

        SubjectPolicy(ApplicationSubjectId subjectId) {
            this.subjectId = subjectId;
        }
    }

    public static final class CompileResult {
        public final boolean ok;
        public final String applyPayload;
        public final byte[] nativeBundlePayload;
        public final long revision;
        public final String errorCode;
        public final String errorMessage;

        private CompileResult(boolean ok, String applyPayload, long revision, String errorCode,
                              String errorMessage, byte[] nativeBundlePayload) {
            this.ok = ok;
            this.applyPayload = applyPayload == null ? "" : applyPayload;
            this.nativeBundlePayload = nativeBundlePayload == null
                    ? new byte[0] : nativeBundlePayload.clone();
            this.revision = revision;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        static CompileResult success(String applyPayload, long revision) {
            return new CompileResult(true, applyPayload, revision, "", "", null);
        }

        static CompileResult success(String applyPayload, long revision,
                                     byte[] nativeBundlePayload) {
            return new CompileResult(true, applyPayload, revision, "", "",
                    nativeBundlePayload);
        }

        static CompileResult failure(String errorCode, String errorMessage) {
            return new CompileResult(false, "", 0L, errorCode, errorMessage, null);
        }

        public byte[] nativeBundle() {
            return nativeBundlePayload.clone();
        }
    }
}
