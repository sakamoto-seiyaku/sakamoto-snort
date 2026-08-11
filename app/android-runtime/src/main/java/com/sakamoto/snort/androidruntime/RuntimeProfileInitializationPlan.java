package com.sakamoto.snort.androidruntime;

/**
 * Product-facing Runtime Profile initialization plan.
 *
 * <p>This is intentionally independent from Android UI classes: the UI can
 * render one current step/action while RuntimeService remains the only owner
 * that actually starts, stops, or switches VPP runtimes.</p>
 */
public final class RuntimeProfileInitializationPlan {
    public enum Step {
        CAPABILITY_DETECTION,
        PROFILE_CONFIRMATION,
        VISIBLE_NOTIFICATION,
        PROFILE_AUTHORIZATION,
        RUNTIME_READINESS,
        READY
    }

    public static final class Inputs {
        public final boolean rootSupported;
        public final boolean rootAuthorized;
        public final boolean vpnSupported;
        public final boolean vpnAuthorized;
        public final boolean notificationReady;
        public final boolean runtimeReady;
        public final RuntimeProfile selectedProfile;

        public Inputs(boolean rootSupported, boolean rootAuthorized,
                      boolean vpnSupported, boolean vpnAuthorized,
                      boolean notificationReady, boolean runtimeReady,
                      RuntimeProfile selectedProfile) {
            this.rootSupported = rootSupported;
            this.rootAuthorized = rootAuthorized;
            this.vpnSupported = vpnSupported;
            this.vpnAuthorized = vpnAuthorized;
            this.notificationReady = notificationReady;
            this.runtimeReady = runtimeReady;
            this.selectedProfile = selectedProfile;
        }

        public Inputs withSelectedProfile(RuntimeProfile profile) {
            return new Inputs(rootSupported, rootAuthorized, vpnSupported, vpnAuthorized,
                    notificationReady, runtimeReady, profile);
        }

        public Inputs withNotificationReady(boolean ready) {
            return new Inputs(rootSupported, rootAuthorized, vpnSupported, vpnAuthorized,
                    ready, runtimeReady, selectedProfile);
        }

        public Inputs withAuthorization(boolean rootReady, boolean vpnReady) {
            return new Inputs(rootSupported, rootReady, vpnSupported, vpnReady,
                    notificationReady, runtimeReady, selectedProfile);
        }

        public Inputs withRuntimeReady(boolean ready) {
            return new Inputs(rootSupported, rootAuthorized, vpnSupported, vpnAuthorized,
                    notificationReady, ready, selectedProfile);
        }
    }

    public final RuntimeProfile recommendedProfile;
    public final RuntimeProfile selectedProfile;
    public final Step currentStep;
    public final String currentAction;
    public final String impact;
    public final String recoveryAction;
    public final boolean requiresUserConfirmation;
    public final boolean shouldAutoAuthorize;
    public final boolean shouldAutoStart;
    public final boolean shouldAutoSwitchProfile;

    private RuntimeProfileInitializationPlan(RuntimeProfile recommendedProfile,
                                             RuntimeProfile selectedProfile,
                                             Step currentStep,
                                             String currentAction,
                                             String impact,
                                             String recoveryAction,
                                             boolean requiresUserConfirmation) {
        this.recommendedProfile = recommendedProfile;
        this.selectedProfile = selectedProfile;
        this.currentStep = currentStep;
        this.currentAction = currentAction;
        this.impact = impact;
        this.recoveryAction = recoveryAction;
        this.requiresUserConfirmation = requiresUserConfirmation;
        this.shouldAutoAuthorize = false;
        this.shouldAutoStart = false;
        this.shouldAutoSwitchProfile = false;
    }

    public static RuntimeProfileInitializationPlan from(Inputs inputs) {
        RuntimeProfile recommended = recommend(inputs);
        if (recommended == null) {
            return new RuntimeProfileInitializationPlan(null, null,
                    Step.CAPABILITY_DETECTION,
                    "Check Root and VPN runtime capabilities",
                    "Protection cannot start until at least one runtime profile is available.",
                    "Install a supported build or use a device that supports Root or VPN.",
                    false);
        }
        RuntimeProfile selected = inputs.selectedProfile;
        if (selected == null || !supported(inputs, selected)) {
            return new RuntimeProfileInitializationPlan(recommended, selected,
                    Step.PROFILE_CONFIRMATION,
                    "Confirm the " + recommended.displayName + " runtime profile",
                    "Only one VPP runtime can be active; switching never copies, migrates, or deletes the Authoring Policy Bundle.",
                    "Choose Root or VPN explicitly before any permission request or runtime start.",
                    true);
        }
        if (!inputs.notificationReady) {
            return new RuntimeProfileInitializationPlan(recommended, selected,
                    Step.VISIBLE_NOTIFICATION,
                    "Allow the visible runtime notification",
                    "The notification is the user-visible protection status gate before starting VPP.",
                    "Grant notification permission, then continue initialization.",
                    false);
        }
        if (!authorized(inputs, selected)) {
            return new RuntimeProfileInitializationPlan(recommended, selected,
                    Step.PROFILE_AUTHORIZATION,
                    selected == RuntimeProfile.ROOT
                            ? "Grant KernelSU authorization for Root runtime"
                            : "Authorize Android VPN for VPN runtime",
                    selected == RuntimeProfile.ROOT
                            ? "Root authorization is required before cleanup, ownership audit, or launch can proceed."
                            : "VPN authorization is required before creating the TUN packet adapter.",
                    selected == RuntimeProfile.ROOT
                            ? "Open the Root authorization prompt and retry after granting access."
                            : "Open the Android VPN consent prompt and retry after approval.",
                    false);
        }
        if (!inputs.runtimeReady) {
            return new RuntimeProfileInitializationPlan(recommended, selected,
                    Step.RUNTIME_READINESS,
                    "Start and verify " + selected.displayName + " runtime readiness",
                    "Initialization succeeds only after Adapter readiness, IPv4/IPv6 packet runtime, and VPP health are verified.",
                    "Clean up partial runtime residue, then retry the selected profile.",
                    false);
        }
        return new RuntimeProfileInitializationPlan(recommended, selected, Step.READY,
                "Initialization complete",
                selected.displayName + " runtime is active and ready.",
                "Use Protection Pause or switch profiles when needed.",
                false);
    }

    private static RuntimeProfile recommend(Inputs inputs) {
        if (inputs.rootSupported) {
            return RuntimeProfile.ROOT;
        }
        if (inputs.vpnSupported) {
            return RuntimeProfile.VPN;
        }
        return null;
    }

    private static boolean supported(Inputs inputs, RuntimeProfile profile) {
        return profile == RuntimeProfile.ROOT ? inputs.rootSupported : inputs.vpnSupported;
    }

    private static boolean authorized(Inputs inputs, RuntimeProfile profile) {
        return profile == RuntimeProfile.ROOT ? inputs.rootAuthorized : inputs.vpnAuthorized;
    }
}
