package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.TreeSet;

/** Atomic policy/config product-state repository. Bounded Activity uses a different repository. */
public final class ProductStateStore {
    private static final String DIRECTORY = "product-state";
    private static final String FILE = "product.properties";
    private static final String TEMP_FILE = "product.properties.tmp";

    private ProductStateStore() {}

    @FunctionalInterface
    public interface Writer {
        void write(File filesDir, ProductStateSnapshot snapshot) throws IOException;
    }

    public static Writer defaultWriter() {
        return ProductStateStore::write;
    }

    public static ReadResult readResult(File filesDir) {
        File target = stateFile(filesDir);
        if (!target.isFile()) {
            return ReadResult.absent(ProductStateSnapshot.empty());
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(target)) {
            values.load(input);
            int schema = Integer.parseInt(values.getProperty("schemaVersion", "0"));
            if (schema != ProductStateSnapshot.SCHEMA_VERSION) {
                return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                        "product_state_unsupported_schema",
                        "product state schema " + schema
                                + " is unsupported; upgrade the app or reset product state");
            }
            RuntimeProfile profile = RuntimeProfile.parse(values.getProperty("selectedProfile",
                    RuntimeProfile.ROOT.wireName));
            Set<ApplicationSubjectId> bound = parseBoundApplications(
                    values.getProperty("boundApplications", ""));
            int bundleSchema = Integer.parseInt(values.getProperty("bundle.schemaVersion", "0"));
            long bundleRevision = Long.parseLong(values.getProperty("bundle.revision", "0"));
            String bundleSource = values.getProperty("bundle.source", "");
            int gateCount = Integer.parseInt(values.getProperty("bundle.gateEntryCount", "0"));
            int l4Count = Integer.parseInt(values.getProperty("bundle.l4RuleCount", "0"));
            int protocolCount = Integer.parseInt(values.getProperty(
                    "bundle.protocolRuleCount", "0"));
            if (bundleSchema != AuthoringPolicyBundle.SCHEMA_VERSION) {
                return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                        "authoring_policy_bundle_unsupported_schema",
                        "authoring policy bundle schema " + bundleSchema
                                + " is unsupported; upgrade the app or reset product state");
            }
            List<AuthoringPolicyBundle.NetworkGateRule> gateMatrix = parseGateMatrix(
                    values.getProperty("bundle.gateMatrix", ""));
            if (gateMatrix.size() != gateCount) {
                return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                        "authoring_policy_bundle_gate_matrix_mismatch",
                        "authoring policy bundle GateMatrix count does not match its entries");
            }
            List<AuthoringPolicyBundle.L4Rule> l4Rules = parseL4Rules(
                    values.getProperty("bundle.l4Rules", ""));
            if (l4Rules.size() != l4Count) {
                return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                        "authoring_policy_bundle_l4_rules_mismatch",
                        "authoring policy bundle L4RuleList count does not match its entries");
            }
            if (protocolCount != 0) {
                return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                        "authoring_policy_bundle_unsupported",
                        "Protocol authoring rule families are unsupported by this slice");
            }
            return ReadResult.valid(new ProductStateSnapshot(profile, bound,
                    AuthoringPolicyBundle.restore(bundleRevision, bundleSource, gateMatrix,
                            l4Rules, protocolCount)));
        } catch (Exception error) {
            return ReadResult.invalid(ProductStateSnapshot.empty(), true,
                    "product_state_corrupt",
                    "product state could not be read; export diagnostics and reset product state");
        }
    }

    public static ProductStateSnapshot read(File filesDir) {
        return readResult(filesDir).snapshot;
    }

    public static void write(File filesDir, ProductStateSnapshot snapshot) throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create product state directory: " + directory);
        }
        ProductStateSnapshot value = snapshot == null ? ProductStateSnapshot.empty() : snapshot;
        Properties values = new Properties();
        values.setProperty("schemaVersion", Integer.toString(value.schemaVersion));
        values.setProperty("selectedProfile", value.selectedProfile.wireName);
        values.setProperty("boundApplications", encodeBoundApplications(value.boundApplications));
        values.setProperty("bundle.schemaVersion",
                Integer.toString(value.authoringPolicyBundle.schemaVersion));
        values.setProperty("bundle.revision",
                Long.toString(value.authoringPolicyBundle.revision));
        values.setProperty("bundle.source", value.authoringPolicyBundle.source);
        values.setProperty("bundle.gateEntryCount",
                Integer.toString(value.authoringPolicyBundle.gateEntryCount));
        values.setProperty("bundle.l4RuleCount",
                Integer.toString(value.authoringPolicyBundle.l4RuleCount));
        values.setProperty("bundle.protocolRuleCount",
                Integer.toString(value.authoringPolicyBundle.protocolRuleCount));
        values.setProperty("bundle.gateMatrix",
                encodeGateMatrix(value.authoringPolicyBundle.gateMatrix));
        values.setProperty("bundle.l4Rules",
                encodeL4Rules(value.authoringPolicyBundle.l4Rules));

        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            values.store(output, "Sakamoto Android Local Product Backend state");
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("unable to replace product state: " + target);
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("unable to publish product state: " + target);
            }
        }
    }

    public static File stateFile(File filesDir) {
        return new File(new File(filesDir, DIRECTORY), FILE);
    }

    private static Set<ApplicationSubjectId> parseBoundApplications(String encoded) {
        TreeSet<ApplicationSubjectId> out = new TreeSet<>();
        if (encoded == null || encoded.trim().isEmpty()) {
            return out;
        }
        String[] pieces = encoded.split(",");
        for (String piece : pieces) {
            String token = piece.trim();
            if (!token.isEmpty()) {
                out.add(ApplicationSubjectId.parse(token));
            }
        }
        return out;
    }

    private static String encodeBoundApplications(Set<ApplicationSubjectId> values) {
        StringBuilder out = new StringBuilder();
        boolean first = true;
        for (ApplicationSubjectId value : new TreeSet<>(values)) {
            if (!first) {
                out.append(',');
            }
            out.append(value.encode());
            first = false;
        }
        return out.toString();
    }

    private static List<AuthoringPolicyBundle.NetworkGateRule> parseGateMatrix(String encoded) {
        ArrayList<AuthoringPolicyBundle.NetworkGateRule> out = new ArrayList<>();
        TreeSet<String> seen = new TreeSet<>();
        if (encoded == null || encoded.trim().isEmpty()) {
            return out;
        }
        String[] pieces = encoded.split(";");
        for (String piece : pieces) {
            String token = piece.trim();
            if (token.isEmpty()) {
                continue;
            }
            String[] fields = token.split(":");
            if (fields.length != 5) {
                throw new IllegalArgumentException("invalid GateMatrix entry");
            }
            ApplicationSubjectId subjectId = ApplicationSubjectId.fromUid(
                    Integer.parseInt(fields[0]));
            AuthoringPolicyBundle.NetworkContextId context =
                    AuthoringPolicyBundle.NetworkContextId.parse(fields[1]);
            boolean blocked;
            if ("blocked".equals(fields[2])) {
                blocked = true;
            } else if ("open".equals(fields[2])) {
                blocked = false;
            } else {
                throw new IllegalArgumentException("invalid GateMatrix action");
            }
            long ruleId = Long.parseUnsignedLong(fields[3]);
            int reasonId = Integer.parseInt(fields[4]);
            String key = subjectId.uid + ":" + context.wireName;
            if (!seen.add(key)) {
                throw new IllegalArgumentException("duplicate GateMatrix entry");
            }
            out.add(new AuthoringPolicyBundle.NetworkGateRule(subjectId, context, blocked,
                    ruleId, reasonId));
        }
        return out;
    }

    private static String encodeGateMatrix(
            List<AuthoringPolicyBundle.NetworkGateRule> gateMatrix) {
        StringBuilder out = new StringBuilder();
        boolean first = true;
        for (AuthoringPolicyBundle.NetworkGateRule rule : gateMatrix) {
            if (!first) {
                out.append(';');
            }
            out.append(rule.subjectId.uid).append(':')
                    .append(rule.networkContext.wireName).append(':')
                    .append(rule.blocked ? "blocked" : "open").append(':')
                    .append(Long.toUnsignedString(rule.ruleId)).append(':')
                    .append(rule.reasonId);
            first = false;
        }
        return out.toString();
    }

    private static List<AuthoringPolicyBundle.L4Rule> parseL4Rules(String encoded) {
        ArrayList<AuthoringPolicyBundle.L4Rule> out = new ArrayList<>();
        TreeSet<String> seen = new TreeSet<>();
        if (encoded == null || encoded.trim().isEmpty()) {
            return out;
        }
        String[] pieces = encoded.split(";");
        for (String piece : pieces) {
            String token = piece.trim();
            if (token.isEmpty()) {
                continue;
            }
            String[] fields = token.split("\\|", -1);
            if (fields.length != 14) {
                throw new IllegalArgumentException("invalid L4RuleList entry");
            }
            ApplicationSubjectId subjectId = ApplicationSubjectId.fromUid(
                    Integer.parseInt(fields[0]));
            long ruleId = Long.parseUnsignedLong(fields[1]);
            int reasonId = Integer.parseInt(fields[2]);
            int priority = Integer.parseInt(fields[3]);
            int order = Integer.parseInt(fields[4]);
            AuthoringPolicyBundle.L4Action action =
                    AuthoringPolicyBundle.L4Action.parse(fields[5]);
            AuthoringPolicyBundle.IpFamily family =
                    AuthoringPolicyBundle.IpFamily.parse(fields[6]);
            AuthoringPolicyBundle.PacketDirection direction =
                    AuthoringPolicyBundle.PacketDirection.parse(fields[7]);
            int ipProtocol = Integer.parseInt(fields[8]);
            AuthoringPolicyBundle.NetworkContextId context = "-".equals(fields[9])
                    ? null : AuthoringPolicyBundle.NetworkContextId.parse(fields[9]);
            String sourceCidr = decodeString(fields[10]);
            String destinationCidr = decodeString(fields[11]);
            AuthoringPolicyBundle.PortRange sourcePorts = parsePortRange(fields[12]);
            AuthoringPolicyBundle.PortRange destinationPorts = parsePortRange(fields[13]);
            String key = subjectId.uid + ":" + Long.toUnsignedString(ruleId);
            if (!seen.add(key)) {
                throw new IllegalArgumentException("duplicate L4RuleList entry");
            }
            out.add(new AuthoringPolicyBundle.L4Rule(subjectId, family, sourceCidr,
                    destinationCidr, sourcePorts, destinationPorts, ipProtocol, direction,
                    context, action, priority, order, ruleId, reasonId));
        }
        return out;
    }

    private static String encodeL4Rules(List<AuthoringPolicyBundle.L4Rule> l4Rules) {
        StringBuilder out = new StringBuilder();
        boolean first = true;
        for (AuthoringPolicyBundle.L4Rule rule : l4Rules) {
            if (!first) {
                out.append(';');
            }
            out.append(rule.subjectId.uid).append('|')
                    .append(Long.toUnsignedString(rule.ruleId)).append('|')
                    .append(rule.reasonId).append('|')
                    .append(rule.priority).append('|')
                    .append(rule.order).append('|')
                    .append(rule.action.wireName).append('|')
                    .append(rule.family.wireName).append('|')
                    .append(rule.direction.wireName).append('|')
                    .append(rule.ipProtocol).append('|')
                    .append(rule.networkContext == null ? "-" : rule.networkContext.wireName)
                    .append('|')
                    .append(encodeString(rule.sourceCidr)).append('|')
                    .append(encodeString(rule.destinationCidr)).append('|')
                    .append(encodePortRange(rule.sourcePorts)).append('|')
                    .append(encodePortRange(rule.destinationPorts));
            first = false;
        }
        return out.toString();
    }

    private static AuthoringPolicyBundle.PortRange parsePortRange(String encoded) {
        if ("*".equals(encoded)) {
            return null;
        }
        String[] fields = encoded.split("-", -1);
        if (fields.length != 2) {
            throw new IllegalArgumentException("invalid L4 port range");
        }
        return AuthoringPolicyBundle.PortRange.inclusive(
                Integer.parseInt(fields[0]), Integer.parseInt(fields[1]));
    }

    private static String encodePortRange(AuthoringPolicyBundle.PortRange range) {
        if (range == null) {
            return "*";
        }
        return range.first + "-" + range.last;
    }

    private static String encodeString(String value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(
                (value == null ? "" : value).getBytes(StandardCharsets.UTF_8));
    }

    private static String decodeString(String encoded) {
        if (encoded == null || encoded.isEmpty()) {
            return "";
        }
        return new String(Base64.getUrlDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    public static final class ReadResult {
        public final ProductStateSnapshot snapshot;
        public final boolean present;
        public final boolean valid;
        public final String errorCode;
        public final String errorMessage;

        private ReadResult(ProductStateSnapshot snapshot, boolean present, boolean valid,
                           String errorCode, String errorMessage) {
            this.snapshot = snapshot;
            this.present = present;
            this.valid = valid;
            this.errorCode = errorCode == null ? "" : errorCode;
            this.errorMessage = errorMessage == null ? "" : errorMessage;
        }

        private static ReadResult absent(ProductStateSnapshot snapshot) {
            return new ReadResult(snapshot, false, true, "", "");
        }

        private static ReadResult valid(ProductStateSnapshot snapshot) {
            return new ReadResult(snapshot, true, true, "", "");
        }

        public static ReadResult validSnapshot(ProductStateSnapshot snapshot) {
            return valid(snapshot == null ? ProductStateSnapshot.empty() : snapshot);
        }

        public ReadResult withSnapshot(ProductStateSnapshot snapshot) {
            return new ReadResult(snapshot == null ? ProductStateSnapshot.empty() : snapshot,
                    present, valid, errorCode, errorMessage);
        }

        private static ReadResult invalid(ProductStateSnapshot snapshot, String code,
                                          String message) {
            return invalid(snapshot, true, code, message);
        }

        private static ReadResult invalid(ProductStateSnapshot snapshot, boolean present,
                                          String code, String message) {
            return new ReadResult(snapshot, present, false, code, message);
        }
    }
}
