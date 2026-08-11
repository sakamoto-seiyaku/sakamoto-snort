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
    public final List<ActivityItem> activity;
    public final HealthIssue healthIssue;
    public final RuleDraft prefillDraft;

    public AppDetail(AppSummary app, String state, RuntimeSummary runtime,
                     List<RuleView> rules, List<ActivityItem> activity,
                     HealthIssue healthIssue, RuleDraft prefillDraft) {
        this.app = app;
        this.state = bounded(state == null || state.trim().isEmpty()
                ? STATE_EMPTY : state);
        this.runtime = runtime;
        this.rules = immutableRules(rules);
        this.activity = immutableActivity(activity);
        this.healthIssue = healthIssue == null ? HealthIssue.none() : healthIssue;
        this.prefillDraft = prefillDraft;
    }

    public static AppDetail normal(AppSummary app, RuntimeSummary runtime,
                                   List<RuleView> rules, List<ActivityItem> activity) {
        RuleDraft prefill = null;
        if (activity != null) {
            for (ActivityItem item : activity) {
                if (item != null && item.canPrefillL4Rule()) {
                    prefill = new RuleDraft(item.subjectId,
                            item.remoteIp.indexOf(':') >= 0
                                    ? AuthoringPolicyBundle.IpFamily.IPV6
                                    : AuthoringPolicyBundle.IpFamily.IPV4,
                            item.remoteIp + (item.remoteIp.indexOf(':') >= 0
                                    ? "/128" : "/32"),
                            item.remotePort,
                            "udp".equalsIgnoreCase(item.protocol) ? 17 : 6,
                            AuthoringPolicyBundle.PacketDirection.OUTPUT,
                            null, AuthoringPolicyBundle.L4Action.DROP, "activity");
                    break;
                }
            }
        }
        return new AppDetail(app, app == null ? STATE_EMPTY : STATE_NORMAL,
                runtime, rules, activity, runtime == null ? HealthIssue.none()
                : runtime.healthIssue, prefill);
    }

    public static AppDetail loading(RuntimeSummary runtime) {
        return new AppDetail(null, STATE_LOADING, runtime, Collections.emptyList(),
                Collections.emptyList(), HealthIssue.none(), null);
    }

    public static AppDetail error(RuntimeSummary runtime, HealthIssue issue) {
        return new AppDetail(null, STATE_ERROR, runtime, Collections.emptyList(),
                Collections.emptyList(), issue, null);
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

    private static List<ActivityItem> immutableActivity(List<ActivityItem> activity) {
        ArrayList<ActivityItem> values = new ArrayList<>();
        if (activity != null) {
            for (ActivityItem item : activity) {
                if (item != null) {
                    values.add(item);
                }
            }
        }
        return Collections.unmodifiableList(values);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
