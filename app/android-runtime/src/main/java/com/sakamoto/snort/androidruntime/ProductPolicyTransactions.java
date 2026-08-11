package com.sakamoto.snort.androidruntime;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Draft/commit/apply/checkpoint transaction state for one Authoring Policy Bundle. */
public final class ProductPolicyTransactions {
    public static final int MAX_CHECKPOINTS = 5;
    public static final String EXPORT_HEADER = "sakamoto-authoring-policy/v1";

    public interface ApplyTransport {
        LocalProductBackend.PolicyApplyResult apply(String applyArgsJson);
    }

    public static final class Issue {
        public final String severity;
        public final String code;
        public final String message;

        private Issue(String severity, String code, String message) {
            this.severity = severity;
            this.code = code;
            this.message = message;
        }

        public static Issue warning(String code, String message) {
            return new Issue("warning", code, message);
        }

        public static Issue error(String code, String message) {
            return new Issue("error", code, message);
        }
    }

    public static final class Result {
        public final boolean ok;
        public final String errorCode;
        public final String errorMessage;
        public final List<Issue> issues;

        private Result(boolean ok, String errorCode, String errorMessage, List<Issue> issues) {
            this.ok = ok;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
            this.issues = Collections.unmodifiableList(new ArrayList<>(
                    issues == null ? Collections.emptyList() : issues));
        }

        public static Result ok(List<Issue> issues) {
            return new Result(true, "", "", issues);
        }

        public static Result error(String code, String message) {
            return new Result(false, code, message, Collections.emptyList());
        }
    }

    public static final class CommitValidationContext {
        public final ProductStateSnapshot productState;
        public final List<ApplicationCatalogEntry> catalog;

        private CommitValidationContext(ProductStateSnapshot productState,
                                        List<ApplicationCatalogEntry> catalog) {
            this.productState = productState == null ? ProductStateSnapshot.empty()
                    : productState;
            this.catalog = Collections.unmodifiableList(new ArrayList<>(
                    catalog == null ? Collections.emptyList() : catalog));
        }

        public static CommitValidationContext of(ProductStateSnapshot productState,
                                                 List<ApplicationCatalogEntry> catalog) {
            return new CommitValidationContext(productState, catalog);
        }
    }

    public static final class ImportResult {
        public final boolean ok;
        public final AuthoringPolicyBundle bundle;
        public final String errorCode;
        public final String errorMessage;

        private ImportResult(boolean ok, AuthoringPolicyBundle bundle,
                             String errorCode, String errorMessage) {
            this.ok = ok;
            this.bundle = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }
    }

    public static final class Checkpoint {
        public final long revision;
        public final AuthoringPolicyBundle bundle;
        public final String applyPayload;

        public Checkpoint(long revision, AuthoringPolicyBundle bundle, String applyPayload) {
            this.revision = revision;
            this.bundle = bundle;
            this.applyPayload = applyPayload;
        }
    }

    public static final class Status {
        public final long draftRevision;
        public final long committedRevision;
        public final long runtimeRevision;
        public final boolean draftDirty;
        public final int checkpointCount;
        public final long selectedCheckpointRevision;
        public final String runtimeSnapshotState;

        private Status(long draftRevision, long committedRevision, long runtimeRevision,
                       boolean draftDirty, int checkpointCount,
                       long selectedCheckpointRevision, String runtimeSnapshotState) {
            this.draftRevision = draftRevision;
            this.committedRevision = committedRevision;
            this.runtimeRevision = runtimeRevision;
            this.draftDirty = draftDirty;
            this.checkpointCount = checkpointCount;
            this.selectedCheckpointRevision = selectedCheckpointRevision;
            this.runtimeSnapshotState = runtimeSnapshotState;
        }
    }

    private AuthoringPolicyBundle draft;
    private AuthoringPolicyBundle committed;
    private boolean draftDirty;
    private long runtimeRevision;
    private long selectedCheckpointRevision;
    private String runtimeSnapshotState = "empty";
    private final ArrayList<Checkpoint> checkpoints = new ArrayList<>();

    public ProductPolicyTransactions(AuthoringPolicyBundle initial) {
        AuthoringPolicyBundle bundle = initial == null ? AuthoringPolicyBundle.empty() : initial;
        this.draft = bundle;
        this.committed = bundle;
    }

    public static ProductPolicyTransactions restore(
            AuthoringPolicyBundle draft, AuthoringPolicyBundle committed,
            boolean draftDirty, long runtimeRevision, long selectedCheckpointRevision,
            String runtimeSnapshotState, List<Checkpoint> checkpoints) {
        ProductPolicyTransactions restored = new ProductPolicyTransactions(committed);
        restored.draft = draft == null ? AuthoringPolicyBundle.empty() : draft;
        restored.committed = committed == null ? AuthoringPolicyBundle.empty() : committed;
        restored.draftDirty = draftDirty;
        restored.runtimeRevision = Math.max(0L, runtimeRevision);
        restored.selectedCheckpointRevision = Math.max(0L, selectedCheckpointRevision);
        restored.runtimeSnapshotState = runtimeSnapshotState == null
                || runtimeSnapshotState.trim().isEmpty() ? "empty" : runtimeSnapshotState;
        if (checkpoints != null) {
            restored.checkpoints.addAll(checkpoints);
            while (restored.checkpoints.size() > MAX_CHECKPOINTS) {
                restored.checkpoints.remove(0);
            }
        }
        return restored;
    }

    public synchronized Status status() {
        return new Status(draft.revision, committed.revision, runtimeRevision, draftDirty,
                checkpoints.size(), selectedCheckpointRevision, runtimeSnapshotState);
    }

    public synchronized AuthoringPolicyBundle draft() {
        return draft;
    }

    public synchronized AuthoringPolicyBundle committed() {
        return committed;
    }

    public synchronized List<Checkpoint> checkpoints() {
        return Collections.unmodifiableList(new ArrayList<>(checkpoints));
    }

    public synchronized Result replaceDraft(AuthoringPolicyBundle nextDraft) {
        if (nextDraft == null) {
            return Result.error("draft_missing", "draft bundle is required");
        }
        draft = nextDraft;
        draftDirty = draft.revision != committed.revision;
        return Result.ok(Collections.emptyList());
    }

    public synchronized Result commitDraft() {
        return commitDraft(null);
    }

    public synchronized Result commitDraft(CommitValidationContext context) {
        List<Issue> issues = validateDraft(draft, committed, context);
        for (Issue issue : issues) {
            if ("error".equals(issue.severity)) {
                return new Result(false, issue.code, issue.message, issues);
            }
        }
        committed = draft;
        draftDirty = false;
        return Result.ok(issues);
    }

    public synchronized Result applyCommitted(ApplyTransport transport) {
        if (draftDirty) {
            return Result.error("draft_has_uncommitted_changes",
                    "commit or discard draft changes before apply");
        }
        AuthoringPolicyCompiler.CompileResult compiled =
                AuthoringPolicyCompiler.compilePacketPolicyApply(committed);
        if (!compiled.ok) {
            return Result.error(compiled.errorCode, compiled.errorMessage);
        }
        LocalProductBackend.PolicyApplyResult applied = apply(transport, compiled.applyPayload);
        if (applied == null || !applied.ok) {
            return Result.error(applied == null || applied.errorCode.isEmpty()
                            ? "product_policy_apply_failed" : applied.errorCode,
                    applied == null || applied.errorMessage.isEmpty()
                            ? "runtime policy apply failed" : applied.errorMessage);
        }
        runtimeRevision = committed.revision;
        runtimeSnapshotState = "applied";
        selectedCheckpointRevision = committed.revision;
        checkpoints.add(new Checkpoint(committed.revision, committed, compiled.applyPayload));
        while (checkpoints.size() > MAX_CHECKPOINTS) {
            checkpoints.remove(0);
        }
        return Result.ok(Collections.emptyList());
    }

    public synchronized Result restoreCheckpoint(long revision, ApplyTransport transport) {
        if (draftDirty) {
            return Result.error("restore_requires_clean_draft",
                    "commit or discard draft changes before restoring a checkpoint");
        }
        Checkpoint selected = null;
        for (Checkpoint checkpoint : checkpoints) {
            if (checkpoint.revision == revision) {
                selected = checkpoint;
                break;
            }
        }
        if (selected == null) {
            return Result.error("checkpoint_not_found",
                    "selected checkpoint is not retained");
        }
        AuthoringPolicyCompiler.CompileResult compiled =
                AuthoringPolicyCompiler.compilePacketPolicyApply(selected.bundle);
        if (!compiled.ok) {
            return Result.error(compiled.errorCode, compiled.errorMessage);
        }
        LocalProductBackend.PolicyApplyResult applied = apply(transport, compiled.applyPayload);
        if (applied == null || !applied.ok) {
            return Result.error(applied == null || applied.errorCode.isEmpty()
                            ? "checkpoint_restore_apply_failed" : applied.errorCode,
                    applied == null || applied.errorMessage.isEmpty()
                            ? "runtime checkpoint restore failed" : applied.errorMessage);
        }
        draft = selected.bundle;
        committed = selected.bundle;
        draftDirty = false;
        runtimeRevision = selected.revision;
        runtimeSnapshotState = "applied";
        selectedCheckpointRevision = selected.revision;
        return Result.ok(Collections.emptyList());
    }

    public synchronized String exportCommitted() {
        return exportBundle(committed);
    }

    public synchronized Result importDraft(String encoded) {
        ImportResult imported = importBundle(encoded);
        if (!imported.ok) {
            return Result.error(imported.errorCode, imported.errorMessage);
        }
        draft = imported.bundle;
        draftDirty = draft.revision != committed.revision;
        return Result.ok(Collections.emptyList());
    }

    public static String exportBundle(AuthoringPolicyBundle bundle) {
        AuthoringPolicyBundle value = bundle == null ? AuthoringPolicyBundle.empty() : bundle;
        StringBuilder out = new StringBuilder();
        out.append(EXPORT_HEADER).append('\n');
        out.append("revision=").append(value.revision).append('\n');
        out.append("source=").append(b64(value.source)).append('\n');
        for (AuthoringPolicyBundle.NetworkGateRule rule : value.gateMatrix) {
            out.append("gate=").append(rule.subjectId.encode()).append('|')
                    .append(rule.networkContext.wireName).append('|')
                    .append(rule.blocked ? "blocked" : "open").append('|')
                    .append(Long.toUnsignedString(rule.ruleId)).append('|')
                    .append(rule.reasonId).append('\n');
        }
        for (AuthoringPolicyBundle.L4Rule rule : value.l4Rules) {
            out.append("l4=").append(rule.subjectId.encode()).append('|')
                    .append(Long.toUnsignedString(rule.ruleId)).append('|')
                    .append(rule.reasonId).append('|')
                    .append(rule.priority).append('|')
                    .append(rule.order).append('|')
                    .append(rule.action.wireName).append('|')
                    .append(rule.family.wireName).append('|')
                    .append(rule.direction.wireName).append('|')
                    .append(rule.ipProtocol).append('|')
                    .append(rule.networkContext == null ? "-" : rule.networkContext.wireName)
                    .append('|').append(b64(rule.sourceCidr))
                    .append('|').append(b64(rule.destinationCidr))
                    .append('|').append(portRange(rule.sourcePorts))
                    .append('|').append(portRange(rule.destinationPorts))
                    .append('\n');
        }
        return out.toString();
    }

    public static ImportResult importBundle(String encoded) {
        try {
            if (encoded == null || encoded.trim().isEmpty()) {
                return new ImportResult(false, null, "policy_import_empty",
                        "import payload is empty");
            }
            String[] lines = encoded.split("\\r?\\n");
            if (lines.length == 0 || !EXPORT_HEADER.equals(lines[0])) {
                return new ImportResult(false, null, "policy_import_unsupported_format",
                        "import payload is not " + EXPORT_HEADER);
            }
            long revision = 0L;
            String source = "";
            ArrayList<AuthoringPolicyBundle.NetworkGateRule> gates = new ArrayList<>();
            ArrayList<AuthoringPolicyBundle.L4Rule> l4Rules = new ArrayList<>();
            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (line == null || line.trim().isEmpty()) {
                    continue;
                }
                if (line.startsWith("revision=")) {
                    revision = Long.parseLong(line.substring("revision=".length()));
                } else if (line.startsWith("source=")) {
                    source = unb64(line.substring("source=".length()));
                } else if (line.startsWith("gate=")) {
                    gates.add(parseGate(line.substring("gate=".length())));
                } else if (line.startsWith("l4=")) {
                    l4Rules.add(parseL4(line.substring("l4=".length())));
                } else {
                    return new ImportResult(false, null, "policy_import_unknown_record",
                            "import payload contains an unknown record");
                }
            }
            return new ImportResult(true,
                    AuthoringPolicyBundle.restore(revision, source, gates, l4Rules, 0),
                    "", "");
        } catch (RuntimeException error) {
            return new ImportResult(false, null, "policy_import_invalid",
                    "import payload is invalid: " + error.getClass().getSimpleName());
        }
    }

    private static List<Issue> validateDraft(AuthoringPolicyBundle bundle,
                                             AuthoringPolicyBundle committed,
                                             CommitValidationContext context) {
        ArrayList<Issue> issues = new ArrayList<>();
        if (bundle == null) {
            issues.add(Issue.error("draft_missing", "draft bundle is required"));
            return issues;
        }
        if (committed != null && !bundle.source.isEmpty() && !committed.source.isEmpty()
                && !bundle.source.equals(committed.source)) {
            issues.add(Issue.error("source_conflict",
                    "draft source=" + bundle.source + " conflicts with committed source="
                            + committed.source));
        }
        if (context != null) {
            validateBindings(bundle, context, issues);
        }
        for (int i = 0; i < bundle.l4Rules.size(); i++) {
            AuthoringPolicyBundle.L4Rule left = bundle.l4Rules.get(i);
            for (int j = i + 1; j < bundle.l4Rules.size(); j++) {
                AuthoringPolicyBundle.L4Rule right = bundle.l4Rules.get(j);
                if (sameMatch(left, right)) {
                    issues.add(Issue.warning("duplicate_match_warning",
                            "subject=" + left.subjectId.encode()
                                    + " ruleIds=" + Long.toUnsignedString(left.ruleId)
                                    + "," + Long.toUnsignedString(right.ruleId)));
                }
            }
        }
        return issues;
    }

    private static void validateBindings(AuthoringPolicyBundle bundle,
                                         CommitValidationContext context,
                                         ArrayList<Issue> issues) {
        TreeSet<ApplicationSubjectId> catalogSubjects = new TreeSet<>();
        TreeSet<ApplicationSubjectId> unavailableSubjects = new TreeSet<>();
        for (ApplicationCatalogEntry entry : context.catalog) {
            if (entry.available) {
                catalogSubjects.add(entry.subjectId);
            } else {
                unavailableSubjects.add(entry.subjectId);
            }
        }
        for (ApplicationSubjectId bound : context.productState.boundApplications) {
            if (!catalogSubjects.contains(bound)) {
                String reason = unavailableSubjects.contains(bound) ? "unavailable" : "missing";
                issues.add(Issue.error("stale_binding",
                        "subject=" + bound.encode() + " binding is " + reason
                                + " in the current application catalog"));
            }
        }
        Set<ApplicationSubjectId> boundSubjects =
                new TreeSet<>(context.productState.boundApplications);
        for (ApplicationSubjectId subject : policySubjects(bundle)) {
            if (!boundSubjects.contains(subject)) {
                issues.add(Issue.error("binding_mode_conflict",
                        "subject=" + subject.encode()
                                + " has policy rules but is not explicitly bound"));
            }
        }
    }

    private static Set<ApplicationSubjectId> policySubjects(AuthoringPolicyBundle bundle) {
        TreeSet<ApplicationSubjectId> subjects = new TreeSet<>();
        for (AuthoringPolicyBundle.NetworkGateRule rule : bundle.gateMatrix) {
            subjects.add(rule.subjectId);
        }
        for (AuthoringPolicyBundle.L4Rule rule : bundle.l4Rules) {
            subjects.add(rule.subjectId);
        }
        return subjects;
    }

    private static boolean sameMatch(AuthoringPolicyBundle.L4Rule left,
                                     AuthoringPolicyBundle.L4Rule right) {
        return left.subjectId.equals(right.subjectId)
                && left.family == right.family
                && left.ipProtocol == right.ipProtocol
                && left.direction == right.direction
                && left.action == right.action
                && left.priority == right.priority
                && left.sourceCidr.equals(right.sourceCidr)
                && left.destinationCidr.equals(right.destinationCidr)
                && sameContext(left.networkContext, right.networkContext)
                && samePortRange(left.sourcePorts, right.sourcePorts)
                && samePortRange(left.destinationPorts, right.destinationPorts);
    }

    private static boolean sameContext(AuthoringPolicyBundle.NetworkContextId left,
                                       AuthoringPolicyBundle.NetworkContextId right) {
        return left == right;
    }

    private static boolean samePortRange(AuthoringPolicyBundle.PortRange left,
                                         AuthoringPolicyBundle.PortRange right) {
        if (left == null || right == null) {
            return left == right;
        }
        return left.first == right.first && left.last == right.last;
    }

    private static LocalProductBackend.PolicyApplyResult apply(
            ApplyTransport transport, String payload) {
        if (transport == null) {
            return LocalProductBackend.PolicyApplyResult.error(
                    "product_policy_runtime_unavailable",
                    "runtime policy apply transport is not configured");
        }
        return transport.apply(payload);
    }

    private static AuthoringPolicyBundle.NetworkGateRule parseGate(String encoded) {
        String[] fields = encoded.split("\\|", -1);
        if (fields.length != 5) {
            throw new IllegalArgumentException("invalid gate record");
        }
        return new AuthoringPolicyBundle.NetworkGateRule(
                ApplicationSubjectId.parse(fields[0]),
                AuthoringPolicyBundle.NetworkContextId.parse(fields[1]),
                "blocked".equals(fields[2]),
                Long.parseUnsignedLong(fields[3]),
                Integer.parseInt(fields[4]));
    }

    private static AuthoringPolicyBundle.L4Rule parseL4(String encoded) {
        String[] fields = encoded.split("\\|", -1);
        if (fields.length != 14) {
            throw new IllegalArgumentException("invalid l4 record");
        }
        return new AuthoringPolicyBundle.L4Rule(
                ApplicationSubjectId.parse(fields[0]),
                AuthoringPolicyBundle.IpFamily.parse(fields[6]),
                unb64(fields[10]),
                unb64(fields[11]),
                parsePortRange(fields[12]),
                parsePortRange(fields[13]),
                Integer.parseInt(fields[8]),
                AuthoringPolicyBundle.PacketDirection.parse(fields[7]),
                "-".equals(fields[9])
                        ? null : AuthoringPolicyBundle.NetworkContextId.parse(fields[9]),
                AuthoringPolicyBundle.L4Action.parse(fields[5]),
                Integer.parseInt(fields[3]),
                Integer.parseInt(fields[4]),
                Long.parseUnsignedLong(fields[1]),
                Integer.parseInt(fields[2]));
    }

    private static String portRange(AuthoringPolicyBundle.PortRange range) {
        return range == null ? "*" : range.first + "-" + range.last;
    }

    private static AuthoringPolicyBundle.PortRange parsePortRange(String encoded) {
        if ("*".equals(encoded)) {
            return null;
        }
        String[] parts = encoded.split("-", -1);
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid port range");
        }
        return AuthoringPolicyBundle.PortRange.inclusive(
                Integer.parseInt(parts[0]), Integer.parseInt(parts[1]));
    }

    private static String b64(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    private static String unb64(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }
        return new String(Base64.getUrlDecoder().decode(value), StandardCharsets.UTF_8);
    }
}
