package com.sakamoto.snort.androidruntime;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/** Durable UI projection for one selected AppDetail. Not policy/config authority. */
public final class ProductActivityProjectionStore {
    private static final int SCHEMA_VERSION = 1;
    private static final int MAX_RULES = 128;
    private static final int MAX_ACTIVITY = 256;
    private static final String DIRECTORY = "product-activity-projection";
    private static final String FILE = "app-detail.properties";
    private static final String TEMP_FILE = "app-detail.properties.tmp";

    private ProductActivityProjectionStore() {}

    public static AppDetail read(File filesDir) {
        File target = projectionFile(filesDir);
        if (!target.isFile()) {
            return AppDetail.loading(RuntimeSummary.fromSnapshot(RuntimeSnapshot.stopped(),
                    CapabilitySet.androidL4(true, false)));
        }
        Properties values = new Properties();
        try (FileInputStream input = new FileInputStream(target)) {
            values.load(input);
            int schema = parseInt(values, "schemaVersion", 0);
            if (schema != SCHEMA_VERSION) {
                throw new IOException("unsupported product activity projection schema: "
                        + schema);
            }
            AppSummary app = readApp(values);
            RuntimeSummary runtime = readRuntime(values);
            HealthIssue issue = readHealth(values);
            List<RuleView> rules = readRules(values);
            List<ActivityItem> activity = readActivity(values);
            AppDetail inferred = AppDetail.normal(app, runtime, rules, activity);
            String state = values.getProperty("state", AppDetail.STATE_EMPTY);
            if (AppDetail.STATE_NORMAL.equals(state) && !issue.present()) {
                return inferred;
            }
            return new AppDetail(app, state, runtime, rules, activity, issue,
                    inferred.prefillDraft);
        } catch (Exception error) {
            return AppDetail.error(RuntimeSummary.fromSnapshot(RuntimeSnapshot.stopped(),
                    CapabilitySet.androidL4(true, false)),
                    new HealthIssue(HealthIssue.CATEGORY_RUNTIME_FAULT,
                            "product_activity_projection_corrupt",
                            "product activity projection could not be read; query RuntimeService",
                            "Refresh product state from RuntimeService.", true));
        }
    }

    public static void write(File filesDir, AppDetail detail) throws IOException {
        File directory = new File(filesDir, DIRECTORY);
        if (!directory.isDirectory() && !directory.mkdirs() && !directory.isDirectory()) {
            throw new IOException("unable to create product activity projection directory: "
                    + directory);
        }
        AppDetail value = detail == null ? AppDetail.loading(
                RuntimeSummary.fromSnapshot(RuntimeSnapshot.stopped(),
                        CapabilitySet.androidL4(true, false))) : detail;
        Properties values = new Properties();
        values.setProperty("schemaVersion", Integer.toString(SCHEMA_VERSION));
        values.setProperty("state", value.state);
        writeApp(values, value.app);
        writeRuntime(values, value.runtime);
        writeHealth(values, value.healthIssue);
        writeRules(values, value.rules);
        writeActivity(values, value.activity);

        File temporary = new File(directory, TEMP_FILE);
        File target = new File(directory, FILE);
        try (FileOutputStream output = new FileOutputStream(temporary)) {
            values.store(output, "Sakamoto Android Product activity UI projection");
            output.getFD().sync();
        }
        if (!temporary.renameTo(target)) {
            if (target.exists() && !target.delete()) {
                throw new IOException("unable to replace product activity projection: "
                        + target);
            }
            if (!temporary.renameTo(target)) {
                throw new IOException("unable to publish product activity projection: "
                        + target);
            }
        }
    }

    public static File projectionFile(File filesDir) {
        return new File(new File(filesDir, DIRECTORY), FILE);
    }

    private static void writeApp(Properties values, AppSummary app) {
        values.setProperty("app.present", Boolean.toString(app != null));
        if (app == null) {
            return;
        }
        values.setProperty("app.subjectId", app.subjectId.encode());
        values.setProperty("app.packageName", app.packageName);
        values.setProperty("app.label", app.label);
        values.setProperty("app.profileLabel", app.profileLabel);
        values.setProperty("app.userId", Integer.toString(app.userId));
        values.setProperty("app.fullUid", Integer.toString(app.fullUid));
        values.setProperty("app.available", Boolean.toString(app.available));
        values.setProperty("app.bound", Boolean.toString(app.bound));
        values.setProperty("app.wifiGateBlocked", Boolean.toString(app.wifiGateBlocked));
        values.setProperty("app.mobileGateBlocked", Boolean.toString(app.mobileGateBlocked));
        values.setProperty("app.vpnGateBlocked", Boolean.toString(app.vpnGateBlocked));
        values.setProperty("app.l4RuleCount", Integer.toString(app.l4RuleCount));
    }

    private static AppSummary readApp(Properties values) {
        if (!Boolean.parseBoolean(values.getProperty("app.present", "false"))) {
            return null;
        }
        ApplicationSubjectId subject = ApplicationSubjectId.parse(
                values.getProperty("app.subjectId", ""));
        return new AppSummary(subject, values.getProperty("app.packageName", ""),
                values.getProperty("app.label", ""),
                values.getProperty("app.profileLabel", ""),
                parseIntUnchecked(values, "app.userId", subject.userId),
                parseIntUnchecked(values, "app.fullUid", subject.uid),
                Boolean.parseBoolean(values.getProperty("app.available", "false")),
                Boolean.parseBoolean(values.getProperty("app.bound", "false")),
                Boolean.parseBoolean(values.getProperty("app.wifiGateBlocked", "false")),
                Boolean.parseBoolean(values.getProperty("app.mobileGateBlocked", "false")),
                Boolean.parseBoolean(values.getProperty("app.vpnGateBlocked", "false")),
                parseIntUnchecked(values, "app.l4RuleCount", 0));
    }

    private static void writeRuntime(Properties values, RuntimeSummary runtime) {
        RuntimeSummary value = runtime == null ? RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.stopped(), CapabilitySet.androidL4(true, false)) : runtime;
        values.setProperty("runtime.profile", value.selectedProfile.wireName);
        values.setProperty("runtime.state", value.state);
        values.setProperty("runtime.coreHealth", value.coreHealth);
        values.setProperty("runtime.adapterReadiness", value.adapterReadiness);
        values.setProperty("runtime.active", Boolean.toString(value.active));
        values.setProperty("runtime.loading", Boolean.toString(value.loading));
        values.setProperty("runtime.paused", Boolean.toString(value.paused));
        values.setProperty("runtime.recovering", Boolean.toString(value.recovering));
    }

    private static RuntimeSummary readRuntime(Properties values) {
        return new RuntimeSummary(RuntimeProfile.parse(values.getProperty(
                "runtime.profile", RuntimeProfile.ROOT.wireName)),
                values.getProperty("runtime.state", RuntimeSnapshot.STATE_STOPPED),
                values.getProperty("runtime.coreHealth", ""),
                values.getProperty("runtime.adapterReadiness", RuntimeSnapshot.ADAPTER_UNAVAILABLE),
                Boolean.parseBoolean(values.getProperty("runtime.active", "false")),
                Boolean.parseBoolean(values.getProperty("runtime.loading", "false")),
                Boolean.parseBoolean(values.getProperty("runtime.paused", "false")),
                Boolean.parseBoolean(values.getProperty("runtime.recovering", "false")),
                CapabilitySet.androidL4(true, true), readHealth(values));
    }

    private static void writeHealth(Properties values, HealthIssue issue) {
        HealthIssue value = issue == null ? HealthIssue.none() : issue;
        values.setProperty("health.category", value.category);
        values.setProperty("health.code", value.code);
        values.setProperty("health.message", value.message);
        values.setProperty("health.action", value.action);
        values.setProperty("health.blocking", Boolean.toString(value.blocking));
    }

    private static HealthIssue readHealth(Properties values) {
        return new HealthIssue(values.getProperty("health.category", HealthIssue.CATEGORY_NONE),
                values.getProperty("health.code", ""),
                values.getProperty("health.message", ""),
                values.getProperty("health.action", ""),
                Boolean.parseBoolean(values.getProperty("health.blocking", "false")));
    }

    private static void writeRules(Properties values, List<RuleView> rules) {
        List<RuleView> source = rules == null ? java.util.Collections.emptyList() : rules;
        int count = Math.min(source.size(), MAX_RULES);
        values.setProperty("rules.count", Integer.toString(count));
        for (int i = 0; i < count; i++) {
            RuleView rule = source.get(i);
            String key = "rules." + i + ".";
            values.setProperty(key + "ruleId", Long.toUnsignedString(rule.ruleId));
            values.setProperty(key + "family", rule.family);
            values.setProperty(key + "label", rule.label);
            values.setProperty(key + "action", rule.action);
            values.setProperty(key + "status", rule.status);
            values.setProperty(key + "policyRevision", Long.toString(rule.policyRevision));
            values.setProperty(key + "winnerEligible", Boolean.toString(rule.winnerEligible));
        }
    }

    private static List<RuleView> readRules(Properties values) throws IOException {
        int count = Math.min(parseInt(values, "rules.count", 0), MAX_RULES);
        ArrayList<RuleView> rules = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String key = "rules." + i + ".";
            rules.add(new RuleView(Long.parseUnsignedLong(
                    values.getProperty(key + "ruleId", "0")),
                    values.getProperty(key + "family", ""),
                    values.getProperty(key + "label", ""),
                    values.getProperty(key + "action", ""),
                    values.getProperty(key + "status", ""),
                    parseLong(values, key + "policyRevision", 0L),
                    Boolean.parseBoolean(values.getProperty(key + "winnerEligible", "false"))));
        }
        return rules;
    }

    private static void writeActivity(Properties values, List<ActivityItem> activity) {
        List<ActivityItem> source = activity == null
                ? java.util.Collections.emptyList() : activity;
        int count = Math.min(source.size(), MAX_ACTIVITY);
        values.setProperty("activity.count", Integer.toString(count));
        for (int i = 0; i < count; i++) {
            ActivityItem item = source.get(i);
            String key = "activity." + i + ".";
            values.setProperty(key + "subjectId", item.subjectId.encode());
            values.setProperty(key + "appLabel", item.appLabel);
            values.setProperty(key + "packageName", item.packageName);
            values.setProperty(key + "timestampMillis", Long.toString(item.timestampMillis));
            values.setProperty(key + "remoteIp", item.remoteIp);
            values.setProperty(key + "protocol", item.protocol);
            values.setProperty(key + "remotePort", Integer.toString(item.remotePort));
            values.setProperty(key + "devicePacketDirection", item.devicePacketDirection);
            values.setProperty(key + "flowDirection", item.flowDirection);
            values.setProperty(key + "packets", Long.toString(item.packets));
            values.setProperty(key + "bytes", Long.toString(item.bytes));
            values.setProperty(key + "verdict", item.verdict);
            values.setProperty(key + "winner", item.winner);
            values.setProperty(key + "policyRevision", Long.toString(item.policyRevision));
            values.setProperty(key + "ruleId", Long.toUnsignedString(item.ruleId));
            values.setProperty(key + "reasonId", Integer.toString(item.reasonId));
            values.setProperty(key + "evidenceSource", item.evidenceSource);
            values.setProperty(key + "detailLossy", Boolean.toString(item.detailLossy));
            ProtocolRecognitionProjection recognition = item.protocolRecognition;
            values.setProperty(key + "protocolRecognitionState", recognition.state);
            values.setProperty(key + "applicationProtocolKey", recognition.key);
            values.setProperty(key + "applicationProtocolCategory",
                    recognition.category);
            values.setProperty(key + "protocolRecognitionSequence",
                    recognition.recognitionSequence.wire());
            values.setProperty(key + "protocolPayloadPackets",
                    Integer.toString(recognition.payloadPackets));
        }
    }

    private static List<ActivityItem> readActivity(Properties values) throws IOException {
        int count = Math.min(parseInt(values, "activity.count", 0), MAX_ACTIVITY);
        ArrayList<ActivityItem> activity = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String key = "activity." + i + ".";
            activity.add(new ActivityItem(ApplicationSubjectId.parse(
                    values.getProperty(key + "subjectId", "")),
                    values.getProperty(key + "appLabel", ""),
                    values.getProperty(key + "packageName", ""),
                    parseLong(values, key + "timestampMillis", 0L),
                    values.getProperty(key + "remoteIp", ""),
                    values.getProperty(key + "protocol", ""),
                    parseInt(values, key + "remotePort", 0),
                    values.getProperty(key + "devicePacketDirection", ""),
                    values.getProperty(key + "flowDirection", ""),
                    parseLong(values, key + "packets", 0L),
                    parseLong(values, key + "bytes", 0L),
                    values.getProperty(key + "verdict", ""),
                    values.getProperty(key + "winner", ""),
                    parseLong(values, key + "policyRevision", 0L),
                    Long.parseUnsignedLong(values.getProperty(key + "ruleId", "0")),
                    parseInt(values, key + "reasonId", 0),
                    values.getProperty(key + "evidenceSource", ""),
                    Boolean.parseBoolean(values.getProperty(key + "detailLossy", "false")),
                    ProtocolRecognitionProjection.of(values.getProperty(
                                    key + "protocolRecognitionState",
                                    ProtocolRecognitionProjection.STATE_NONE),
                            values.getProperty(key + "applicationProtocolKey", ""),
                            values.getProperty(key + "applicationProtocolCategory", ""),
                            values.getProperty(key + "protocolRecognitionSequence", ""),
                            parseInt(values, key + "protocolPayloadPackets", 0))));
        }
        return activity;
    }

    private static int parseIntUnchecked(Properties values, String key, int fallback) {
        try {
            return parseInt(values, key, fallback);
        } catch (IOException error) {
            return fallback;
        }
    }

    private static int parseInt(Properties values, String key, int fallback) throws IOException {
        String value = values.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException error) {
            throw new IOException("invalid product activity projection " + key, error);
        }
    }

    private static long parseLong(Properties values, String key, long fallback)
            throws IOException {
        String value = values.getProperty(key);
        if (value == null || value.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Long.parseLong(value.trim());
        } catch (NumberFormatException error) {
            throw new IOException("invalid product activity projection " + key, error);
        }
    }
}
