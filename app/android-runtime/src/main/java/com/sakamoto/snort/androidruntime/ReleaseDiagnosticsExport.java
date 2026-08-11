package com.sakamoto.snort.androidruntime;

/** Desensitized Android L4 release diagnostic export formatter. */
public final class ReleaseDiagnosticsExport {
    public static final String SCHEMA = "sakamoto.android_l4.release_diagnostics.v1";
    public static final String PRIVACY = "desensitized_no_payload_no_keys";
    public static final String PAYLOAD_NOT_EXPORTED = "payload=not_exported";
    public static final String KEYS_NOT_EXPORTED = "keys=not_exported";
    public static final String FEEDBACK_BUG = "Bug report";
    public static final String FEEDBACK_COMPATIBILITY = "Compatibility report";
    public static final String FEEDBACK_FEATURE = "Feature request";
    public static final String FEEDBACK_HELP = "Help request";

    private ReleaseDiagnosticsExport() {}

    public static String format(RuntimeSnapshot runtime,
                                ProductCatalogFormatter.Projection catalog,
                                AppDetail detail,
                                ProductCatalogFormatter.EntryRow selectedRow,
                                long exportedAtMillis) {
        RuntimeSnapshot runtimeValue = runtime == null ? RuntimeSnapshot.stopped() : runtime;
        ProductCatalogFormatter.Projection catalogValue = catalog == null
                ? ProductCatalogFormatter.loading(ProductStateSnapshot.empty()) : catalog;
        AppDetail detailValue = detail == null ? AppDetail.loading(
                RuntimeSummary.fromSnapshot(runtimeValue, CapabilitySet.androidL4(true, true)))
                : detail;

        StringBuilder out = new StringBuilder();
        line(out, "schema", SCHEMA);
        line(out, "releaseGate", "SAKAMOTO-59");
        line(out, "scope", "android_l4_product_release");
        line(out, "privacy", PRIVACY);
        entry(out, PAYLOAD_NOT_EXPORTED);
        entry(out, KEYS_NOT_EXPORTED);
        line(out, "exportedAtMillis", Long.toString(Math.max(0L, exportedAtMillis)));

        line(out, "runtime.profile", runtimeValue.profile.wireName);
        line(out, "runtime.state", runtimeValue.state);
        line(out, "runtime.coreHealth", runtimeValue.coreHealth);
        line(out, "runtime.adapterReadiness", runtimeValue.adapterReadiness);
        line(out, "runtime.errorCode", runtimeValue.errorCode);
        line(out, "runtime.mayBeActive", Boolean.toString(runtimeValue.mayBeActive));
        line(out, "runtime.version", runtimeValue.version);
        line(out, "runtime.artifact", runtimeValue.artifact);
        line(out, "runtime.abi", runtimeValue.abi);

        line(out, "catalog.selectedProfile", catalogValue.selectedProfile.wireName);
        line(out, "catalog.status", catalogValue.catalogStatus);
        line(out, "catalog.errorCode", catalogValue.errorCode);
        line(out, "catalog.entries", Integer.toString(catalogValue.catalogEntryCount));
        line(out, "catalog.selectableEntries",
                Integer.toString(catalogValue.selectableRows.size()));
        line(out, "catalog.boundApplications",
                Integer.toString(catalogValue.boundApplicationCount));
        line(out, "productState.status", catalogValue.productStateStatus);
        line(out, "productState.errorCode", catalogValue.productStateErrorCode);

        if (selectedRow == null) {
            line(out, "selected.present", "false");
        } else {
            line(out, "selected.present", "true");
            line(out, "selected.subject", selectedRow.subjectId.encode());
            line(out, "selected.uid", Integer.toString(selectedRow.fullUid));
            line(out, "selected.package", selectedRow.packageName);
            line(out, "selected.label", selectedRow.label);
            line(out, "selected.bound", Boolean.toString(selectedRow.bound));
            line(out, "selected.l4Rules", Integer.toString(selectedRow.l4RuleCount));
            line(out, "selected.gate.wifi",
                    selectedRow.wifiGateBlocked ? "blocked" : "open");
            line(out, "selected.gate.mobile",
                    selectedRow.mobileGateBlocked ? "blocked" : "open");
            line(out, "selected.gate.vpn",
                    selectedRow.vpnGateBlocked ? "blocked" : "open");
        }

        line(out, "appDetail.state", detailValue.state);
        line(out, "appDetail.rules", Integer.toString(detailValue.rules.size()));
        line(out, "appDetail.activity", Integer.toString(detailValue.activity.size()));
        line(out, "appDetail.health.category", detailValue.healthIssue.category);
        line(out, "appDetail.health.code", detailValue.healthIssue.code);
        line(out, "appDetail.health.action", detailValue.healthIssue.action);
        line(out, "appDetail.l4PrefillAvailable",
                Boolean.toString(detailValue.prefillDraft != null));

        line(out, "feedback.bug", FEEDBACK_BUG);
        line(out, "feedback.compatibility", FEEDBACK_COMPATIBILITY);
        line(out, "feedback.feature", FEEDBACK_FEATURE);
        line(out, "feedback.help", FEEDBACK_HELP);
        return out.toString();
    }

    public static String feedbackSummary() {
        return FEEDBACK_BUG + ": include APK version, profile, health state, expected behavior,"
                + " observed behavior, and the desensitized diagnostics file.\n"
                + FEEDBACK_COMPATIBILITY + ": include device model, Android version, ABI,"
                + " Root availability, VPN authorization, IPv4/IPv6 availability, and failing"
                + " matrix step.\n"
                + FEEDBACK_FEATURE + ": describe the user task, profile, app, rule type, and"
                + " why existing Gate/L4 controls are insufficient.\n"
                + FEEDBACK_HELP + ": include the current onboarding/recovery step and visible"
                + " health action.";
    }

    private static void line(StringBuilder out, String key, String value) {
        out.append(key).append('=').append(propertyValue(value)).append('\n');
    }

    private static void entry(StringBuilder out, String propertyEntry) {
        out.append(propertyEntry == null ? "" : propertyEntry).append('\n');
    }

    private static String propertyValue(String value) {
        return value == null ? "" : value.replace("\r", "\\r").replace("\n", "\\n");
    }
}
