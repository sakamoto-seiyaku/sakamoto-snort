package com.sakamoto.snort.androidruntime;

/** Stable product summary for the current Runtime Profile and health state. */
public final class RuntimeSummary {
    public final RuntimeProfile selectedProfile;
    public final String state;
    public final String coreHealth;
    public final String adapterReadiness;
    public final boolean active;
    public final boolean loading;
    public final boolean paused;
    public final boolean recovering;
    public final CapabilitySet capabilities;
    public final HealthIssue healthIssue;

    public RuntimeSummary(RuntimeProfile selectedProfile, String state, String coreHealth,
                          String adapterReadiness, boolean active, boolean loading,
                          boolean paused, boolean recovering, CapabilitySet capabilities,
                          HealthIssue healthIssue) {
        this.selectedProfile = selectedProfile == null ? RuntimeProfile.ROOT : selectedProfile;
        this.state = bounded(state == null || state.trim().isEmpty()
                ? RuntimeSnapshot.STATE_STOPPED : state);
        this.coreHealth = bounded(coreHealth);
        this.adapterReadiness = bounded(adapterReadiness);
        this.active = active;
        this.loading = loading;
        this.paused = paused;
        this.recovering = recovering;
        this.capabilities = capabilities == null
                ? CapabilitySet.androidL4(true, false) : capabilities;
        this.healthIssue = healthIssue == null ? HealthIssue.none() : healthIssue;
    }

    public static RuntimeSummary fromSnapshot(RuntimeSnapshot snapshot,
                                              CapabilitySet capabilities) {
        RuntimeSnapshot value = snapshot == null ? RuntimeSnapshot.stopped() : snapshot;
        HealthIssue issue = HealthIssue.fromRuntimeSnapshot(value);
        boolean loading = RuntimeSnapshot.STATE_STARTING.equals(value.state)
                || RuntimeSnapshot.STATE_STOPPING.equals(value.state);
        boolean recovering = "runtime_auto_recovery_pending".equals(value.errorCode)
                || "runtime_recovery_intervention_required".equals(value.errorCode);
        return new RuntimeSummary(value.profile, value.state, value.coreHealth,
                value.adapterReadiness, value.isActive(), loading,
                RuntimeSnapshot.ERROR_USER_PAUSE.equals(value.errorCode), recovering,
                capabilities, issue);
    }

    public boolean healthyForPolicyApply() {
        return RuntimeSnapshot.STATE_RUNNING.equals(state)
                && !healthIssue.present()
                && !"unavailable".equals(adapterReadiness);
    }

    private static String bounded(String value) {
        return BoundedText.value(value == null ? "" : value,
                RuntimeSnapshot.MAX_TEXT_LENGTH);
    }
}
