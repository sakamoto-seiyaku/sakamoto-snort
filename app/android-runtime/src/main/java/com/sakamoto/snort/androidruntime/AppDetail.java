package com.sakamoto.snort.androidruntime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Product-facing app detail view model. */
public final class AppDetail {
    public static final String STATE_NORMAL = "normal";
    public static final String STATE_EMPTY = "empty";
    public static final String STATE_LOADING = "loading";
    public static final String STATE_ERROR = "error";

    public final AppSummary app;
    public final String state;
    public final RuntimeSummary runtime;
    public final List<RuleView> rules;
    public final HealthIssue healthIssue;
    public final String displayText;

    public AppDetail(AppSummary app, String state, RuntimeSummary runtime,
                     List<RuleView> rules, HealthIssue healthIssue) {
        this.app = app;
        this.state = bounded(state == null || state.trim().isEmpty()
                ? STATE_EMPTY : state);
        this.runtime = runtime;
        this.rules = immutableRules(rules);
        this.healthIssue = healthIssue == null ? HealthIssue.none() : healthIssue;
        this.displayText = buildDisplayText();
    }

    public static AppDetail normal(AppSummary app, RuntimeSummary runtime,
                                   List<RuleView> rules) {
        HealthIssue issue = runtime == null ? HealthIssue.none() : runtime.healthIssue;
        return new AppDetail(app, stateFor(app, runtime, issue), runtime, rules, issue);
    }

    public static AppDetail loading(RuntimeSummary runtime) {
        return new AppDetail(null, STATE_LOADING, runtime, Collections.emptyList(), HealthIssue.none());
    }

    public static AppDetail error(RuntimeSummary runtime, HealthIssue issue) {
        return new AppDetail(null, STATE_ERROR, runtime, Collections.emptyList(), issue);
    }

    private static List<RuleView> immutableRules(List<RuleView> rules) {
        ArrayList<RuleView> values = new ArrayList<>();
        if (rules != null) {
            for (RuleView rule : rules) {
                if (rule != null) {
                    values.add(rule);
                }
            }
        }
        return Collections.unmodifiableList(values);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    private static String stateFor(AppSummary app, RuntimeSummary runtime, HealthIssue issue) {
        if (runtime != null && runtime.loading) {
            return STATE_LOADING;
        }
        if (issue != null && issue.present()) {
            return STATE_ERROR;
        }
        return app == null ? STATE_EMPTY : STATE_NORMAL;
    }

    private String buildDisplayText() {
        StringBuilder out = new StringBuilder();
        out.append("App detail: ").append(state);
        if (app != null) {
            out.append('\n').append("App: ").append(app.label)
                    .append(" | package ").append(app.packageName)
                    .append(" | subject ").append(app.subjectId.encode())
                    .append(" | full uid ").append(app.fullUid)
                    .append(" | bound ").append(app.bound ? "yes" : "no")
                    .append(" | gate wifi=").append(app.wifiGateBlocked ? "blocked" : "open")
                    .append(" mobile=").append(app.mobileGateBlocked ? "blocked" : "open")
                    .append(" vpn=").append(app.vpnGateBlocked ? "blocked" : "open");
        }
        if (runtime != null) {
            out.append('\n').append("Runtime: ").append(runtime.state)
                    .append(" | profile ").append(runtime.selectedProfile.wireName)
                    .append(" | health ").append(runtime.coreHealth)
                    .append(" | adapter ").append(runtime.adapterReadiness);
        }
        if (healthIssue.present()) {
            out.append('\n').append("Health: ").append(healthIssue.category)
                    .append(" ").append(healthIssue.code)
                    .append(" | action ").append(healthIssue.action);
        }
        out.append('\n').append("Rules: ").append(rules.size());
        for (RuleView rule : rules) {
            out.append('\n').append("- ")
                    .append(rule.family).append(" ")
                    .append(rule.action).append(" ")
                    .append(rule.label)
                    .append(" revision=").append(rule.policyRevision);
        }
        return out.toString();
    }
}
