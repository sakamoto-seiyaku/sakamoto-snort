package com.sakamoto.snort.androidruntime;

/**
 * Pure decision seam for recovering the mutually-exclusive durable runtime.
 *
 * <p>The Android service supplies the evidence for each profile (live owner,
 * residue, no evidence, or an unverifiable inspection).  This class only
 * decides whether that evidence permits an adopt/cleanup action.  Keeping the
 * decision independent of Android process APIs makes the exact-one invariant
 * directly testable.</p>
 */
public final class RuntimeOwnershipReconciliation {
    public enum Evidence {
        NONE,
        LIVE,
        RESIDUE,
        UNKNOWN
    }

    public enum Action {
        CLEAN,
        ADOPT_ROOT,
        ADOPT_VPN,
        BLOCK
    }

    private RuntimeOwnershipReconciliation() {}

    /**
     * Select a safe action for the durable Root/VPN ownership evidence.
     *
     * <p>Any unknown evidence or more than one non-empty profile is
     * deliberately blocked.  A single live owner may be adopted; a single
     * residue profile may be cleaned; and an empty pair is safe to start from.
     * The conservative multiple-profile rule prevents a replacement start
     * from racing an unobserved owner.</p>
     */
    public static Action decide(Evidence root, Evidence vpn) {
        Evidence safeRoot = root == null ? Evidence.UNKNOWN : root;
        Evidence safeVpn = vpn == null ? Evidence.UNKNOWN : vpn;
        if (safeRoot == Evidence.UNKNOWN || safeVpn == Evidence.UNKNOWN) {
            return Action.BLOCK;
        }
        boolean rootPresent = safeRoot != Evidence.NONE;
        boolean vpnPresent = safeVpn != Evidence.NONE;
        if (rootPresent && vpnPresent) {
            return Action.BLOCK;
        }
        if (safeRoot == Evidence.LIVE) {
            return Action.ADOPT_ROOT;
        }
        if (safeVpn == Evidence.LIVE) {
            return Action.ADOPT_VPN;
        }
        return Action.CLEAN;
    }
}
