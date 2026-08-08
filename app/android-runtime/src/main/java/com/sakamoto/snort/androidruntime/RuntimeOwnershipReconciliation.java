package com.sakamoto.snort.androidruntime;

/**
 * Service-owned seam for inspecting and reconciling the durable Root/VPN
 * runtime owner.
 *
 * <p>The Android service remains the lifecycle authority: it starts and
 * stops commands, supervises processes, and removes profile trees. This
 * collaborator owns the evidence vocabulary, bounded shell inspection
 * commands, and fail-closed cleanup/adoption decisions. Its command runner
 * boundary keeps the policy independently testable on the host.</p>
 */
public final class RuntimeOwnershipReconciliation {
    private static final int OWNER_MATCH_STATUS = 10;
    private static final int OWNER_AMBIGUOUS_STATUS = 11;
    private static final int OWNER_UNCERTAIN_STATUS = 127;

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

    public enum PidIdentity {
        MISSING,
        MATCH,
        MISMATCH,
        UNKNOWN
    }

    public enum CleanupAction {
        REMOVE,
        BLOCK_ACTIVE_PID,
        BLOCK_PID_MISMATCH,
        BLOCK_PID_UNKNOWN,
        BLOCK_PROCESS_HANDLE,
        BLOCK_LIVE_OWNER,
        BLOCK_OWNER_UNKNOWN
    }

    /** Result returned by the service's bounded root/app command runner. */
    public static final class CommandResult {
        public final int status;
        public final String output;

        public CommandResult(int status, String output) {
            this.status = status;
            this.output = output == null ? "" : output;
        }
    }

    /** Android-free execution boundary for /proc and ownership inspection. */
    public interface CommandRunner {
        CommandResult run(RuntimeProfile profile, String command, long timeoutSeconds);
    }

    /** Immutable identity facts needed by the ownership shell inspection. */
    public static final class ProfileSpec {
        public final RuntimeProfile profile;
        public final String startupPath;
        public final String runtimePath;
        public final String executablePath;
        public final String executableHash;
        public final String ownerToken;
        public final String expectedUid;
        public final int unavailableStatus;
        public final String unavailableErrorCode;
        public final String unavailableDetail;

        public ProfileSpec(RuntimeProfile profile, String startupPath, String runtimePath,
                           String executablePath, String executableHash, String ownerToken,
                           String expectedUid, int unavailableStatus,
                           String unavailableErrorCode, String unavailableDetail) {
            this.profile = profile == null ? RuntimeProfile.ROOT : profile;
            this.startupPath = value(startupPath);
            this.runtimePath = value(runtimePath);
            this.executablePath = value(executablePath);
            this.executableHash = value(executableHash);
            this.ownerToken = value(ownerToken);
            this.expectedUid = value(expectedUid);
            this.unavailableStatus = unavailableStatus;
            this.unavailableErrorCode = value(unavailableErrorCode);
            this.unavailableDetail = value(unavailableDetail);
        }
    }

    /** Result of matching a profile's owner token and process identities. */
    public static final class OwnershipAudit {
        public enum Kind {
            NONE,
            LIVE,
            UNKNOWN
        }

        public final Kind kind;
        public final long pid;
        public final String detail;
        public final String errorCode;

        private OwnershipAudit(Kind kind, long pid, String detail, String errorCode) {
            this.kind = kind;
            this.pid = pid;
            this.detail = value(detail);
            this.errorCode = value(errorCode);
        }

        public static OwnershipAudit none() {
            return new OwnershipAudit(Kind.NONE, -1L, "no matching live owner", "");
        }

        public static OwnershipAudit live(long pid) {
            return pid > 0L
                    ? new OwnershipAudit(Kind.LIVE, pid, "matching live owner", "")
                    : unknown("matching owner PID was not returned");
        }

        public static OwnershipAudit unknown(String detail) {
            return unknown("cleanup_failed", detail);
        }

        public static OwnershipAudit unknown(String errorCode, String detail) {
            return new OwnershipAudit(Kind.UNKNOWN, -1L, detail, errorCode);
        }

        public boolean isVerifiedLive() {
            return kind == Kind.LIVE && pid > 0L;
        }

        public boolean isSafeToRemove() {
            return kind == Kind.NONE;
        }

        public boolean isUnknown() {
            return kind == Kind.UNKNOWN;
        }
    }

    /** Combined evidence for one durable profile directory. */
    public static final class ProfileAudit {
        public final RuntimeProfile profile;
        public final Evidence evidence;
        public final long pid;
        public final String detail;
        public final String errorCode;

        private ProfileAudit(RuntimeProfile profile, Evidence evidence, long pid, String detail,
                             String errorCode) {
            this.profile = profile == null ? RuntimeProfile.ROOT : profile;
            this.evidence = evidence == null ? Evidence.UNKNOWN : evidence;
            this.pid = pid;
            this.detail = value(detail);
            this.errorCode = value(errorCode);
        }

        public static ProfileAudit none(RuntimeProfile profile) {
            return new ProfileAudit(profile, Evidence.NONE, -1L,
                    "no durable profile or live owner", "");
        }

        public static ProfileAudit live(RuntimeProfile profile, long pid, String detail) {
            return new ProfileAudit(profile, Evidence.LIVE, pid, detail, "");
        }

        public static ProfileAudit residue(RuntimeProfile profile, long pid, String detail) {
            return new ProfileAudit(profile, Evidence.RESIDUE, pid, detail, "");
        }

        public static ProfileAudit unknown(RuntimeProfile profile, String detail) {
            return unknown(profile, "runtime_ownership_unverified", detail);
        }

        public static ProfileAudit unknown(RuntimeProfile profile, String errorCode,
                                           String detail) {
            return new ProfileAudit(profile, Evidence.UNKNOWN, -1L, detail, errorCode);
        }
    }

    /** Durable product projection facts used to validate a global owner. */
    public static final class Projection {
        public final boolean known;
        public final RuntimeProfile profile;
        public final boolean active;
        public final long pid;

        private Projection(boolean known, RuntimeProfile profile, boolean active, long pid) {
            this.known = known;
            this.profile = profile == null ? RuntimeProfile.ROOT : profile;
            this.active = active;
            this.pid = pid;
        }

        public static Projection unknown() {
            return new Projection(false, RuntimeProfile.ROOT, false, -1L);
        }

        public static Projection known(RuntimeProfile profile, boolean active, long pid) {
            return new Projection(true, profile, active, pid);
        }
    }

    /** One global ownership decision after both Root and VPN audits complete. */
    public static final class GlobalDecision {
        public final Action action;
        public final ProfileAudit root;
        public final ProfileAudit vpn;
        public final RuntimeProfile ownerProfile;
        public final long ownerPid;
        public final RuntimeProfile cleanupProfile;
        public final long cleanupPid;
        public final String errorCode;
        public final String detail;

        private GlobalDecision(Action action, ProfileAudit root, ProfileAudit vpn,
                               RuntimeProfile ownerProfile, long ownerPid,
                               RuntimeProfile cleanupProfile, long cleanupPid,
                               String errorCode, String detail) {
            this.action = action == null ? Action.BLOCK : action;
            this.root = root == null ? ProfileAudit.unknown(RuntimeProfile.ROOT,
                    "root ownership audit is unavailable") : root;
            this.vpn = vpn == null ? ProfileAudit.unknown(RuntimeProfile.VPN,
                    "VPN ownership audit is unavailable") : vpn;
            this.ownerProfile = ownerProfile;
            this.ownerPid = ownerPid;
            this.cleanupProfile = cleanupProfile;
            this.cleanupPid = cleanupPid;
            this.errorCode = value(errorCode);
            this.detail = value(detail);
        }

        public boolean isBlocked() {
            return action == Action.BLOCK;
        }
    }

    /**
     * A live projection can briefly race an owner exit or a proc snapshot.
     * Retry that narrow unverifiable case while retaining fail-closed
     * behavior for ambiguity and all inactive projections.
     */
    public static boolean shouldRetryOwnershipAudit(GlobalDecision decision,
                                                     boolean runtimeMayBeActive) {
        return runtimeMayBeActive
                && decision != null
                && decision.isBlocked()
                && "runtime_ownership_unverified".equals(decision.errorCode);
    }

    /** Result of the profile cleanup policy, before the service deletes files. */
    public static final class CleanupDecision {
        public final CleanupAction action;
        public final long pid;
        public final String errorCode;
        public final String detail;

        private CleanupDecision(CleanupAction action, long pid, String errorCode, String detail) {
            this.action = action;
            this.pid = pid;
            this.errorCode = value(errorCode);
            this.detail = value(detail);
        }

        public boolean canRemove() {
            return action == CleanupAction.REMOVE;
        }

        private static CleanupDecision remove() {
            return new CleanupDecision(CleanupAction.REMOVE, -1L, "", "");
        }

        private static CleanupDecision block(CleanupAction action, long pid,
                                             String errorCode, String detail) {
            return new CleanupDecision(action, pid, errorCode, detail);
        }
    }

    private RuntimeOwnershipReconciliation() {}

    /**
     * Select a safe action for the durable Root/VPN ownership evidence.
     * Unknown evidence or more than one non-empty profile is blocked.
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

    /**
     * Reconcile the complete Root/VPN ownership set against one durable
     * projection. This is the only global decision seam: callers must audit
     * both profiles first and then use this result before adopting, cleaning,
     * or launching either profile.
     */
    public static GlobalDecision decide(ProfileAudit root, ProfileAudit vpn,
                                        Projection projection) {
        ProfileAudit safeRoot = root == null
                ? ProfileAudit.unknown(RuntimeProfile.ROOT, "root ownership audit is unavailable")
                : root;
        ProfileAudit safeVpn = vpn == null
                ? ProfileAudit.unknown(RuntimeProfile.VPN, "VPN ownership audit is unavailable")
                : vpn;
        Projection safeProjection = projection == null ? Projection.unknown() : projection;
        Action action = decide(safeRoot.evidence, safeVpn.evidence);
        if (action == Action.BLOCK) {
            String errorCode = safeRoot.evidence == Evidence.UNKNOWN && !safeRoot.errorCode.isEmpty()
                    ? safeRoot.errorCode
                    : safeVpn.evidence == Evidence.UNKNOWN && !safeVpn.errorCode.isEmpty()
                            ? safeVpn.errorCode : "runtime_ownership_ambiguous";
            return new GlobalDecision(Action.BLOCK, safeRoot, safeVpn, null, -1L,
                    null, -1L, errorCode,
                    ownershipConflictDetail(safeRoot, safeVpn));
        }

        if (action == Action.ADOPT_ROOT || action == Action.ADOPT_VPN) {
            ProfileAudit owner = action == Action.ADOPT_ROOT ? safeRoot : safeVpn;
            if (owner.pid <= 0L) {
                return new GlobalDecision(Action.BLOCK, safeRoot, safeVpn, null, -1L,
                        null, -1L, "runtime_ownership_unverified",
                        "globally verified live owner did not provide a usable PID");
            }
            if (safeProjection.known) {
                if (!safeProjection.active) {
                    return new GlobalDecision(Action.BLOCK, safeRoot, safeVpn, null, -1L,
                            null, -1L, "runtime_ownership_ambiguous",
                            "a live durable owner conflicts with an inactive runtime projection");
                }
                if (safeProjection.profile != owner.profile) {
                    return new GlobalDecision(Action.BLOCK, safeRoot, safeVpn, null, -1L,
                            null, -1L, "runtime_ownership_ambiguous",
                            "live durable owner profile differs from the runtime projection");
                }
                // A valid active projection can be observed during the
                // launch-shell window before its PID has been durably
                // published. The exhaustive owner scan is authoritative in
                // that case; a non-missing recorded PID, however, must match
                // exactly and never be silently replaced.
                if (safeProjection.pid > 0L && safeProjection.pid != owner.pid) {
                    return new GlobalDecision(Action.BLOCK, safeRoot, safeVpn, null, -1L,
                            null, -1L, "runtime_ownership_ambiguous",
                            "live durable owner PID differs from the runtime projection");
                }
            }
            return new GlobalDecision(action, safeRoot, safeVpn, owner.profile, owner.pid,
                    null, -1L, "", owner.detail);
        }

        RuntimeProfile cleanupProfile = null;
        long cleanupPid = -1L;
        if (safeRoot.evidence == Evidence.RESIDUE) {
            cleanupProfile = RuntimeProfile.ROOT;
            cleanupPid = safeRoot.pid;
        } else if (safeVpn.evidence == Evidence.RESIDUE) {
            cleanupProfile = RuntimeProfile.VPN;
            cleanupPid = safeVpn.pid;
        }
        return new GlobalDecision(Action.CLEAN, safeRoot, safeVpn, null, -1L,
                cleanupProfile, cleanupPid, "", cleanupProfile == null
                        ? "no durable Root/VPN owner or residue" : "one safely audited profile residue");
    }

    private static String ownershipConflictDetail(ProfileAudit root, ProfileAudit vpn) {
        return "durable ownership audit blocked: root=" + root.detail + ", vpn=" + vpn.detail;
    }

    /**
     * Convert durable PID evidence and an exhaustive ownership inspection into
     * a profile audit. A durable PID is never sufficient by itself: a live
     * recorded PID must be the one and only verified owner in the full scan.
     * A verified PID-less candidate remains adoptable, while duplicate,
     * transitional, and otherwise unverifiable evidence stays fail-closed.
     */
    public static ProfileAudit classifyDurableProfile(
            RuntimeProfile profile, boolean present, long durablePid,
            PidIdentity durableIdentity, OwnershipAudit candidate) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        PidIdentity identity = durableIdentity == null ? PidIdentity.UNKNOWN : durableIdentity;
        if (identity == PidIdentity.UNKNOWN) {
            return ProfileAudit.unknown(selected, "runtime_ownership_unverified",
                    "durable PID identity could not be verified");
        }
        if (identity == PidIdentity.MISMATCH) {
            return ProfileAudit.unknown(selected, "runtime_ownership_unverified",
                    "durable PID belongs to a different process");
        }
        if (!present) {
            return ProfileAudit.none(selected);
        }
        if (candidate == null || candidate.isUnknown()) {
            String detail = candidate == null ? "cleanup_failed: ownership audit unavailable"
                    : candidate.errorCode + ": " + candidate.detail;
            String errorCode = candidate == null || candidate.errorCode.isEmpty()
                    ? "runtime_ownership_unverified" : candidate.errorCode;
            return ProfileAudit.unknown(selected, errorCode, detail);
        }
        if (candidate.isVerifiedLive()) {
            if (identity == PidIdentity.MATCH && candidate.pid != durablePid) {
                return ProfileAudit.unknown(selected, "runtime_ownership_ambiguous",
                        "runtime_ownership_ambiguous: durable PID differs from the sole audited owner");
            }
            return ProfileAudit.live(selected, candidate.pid,
                    identity == PidIdentity.MATCH
                            ? "durable PID and exhaustive ownership scan identify one owner"
                            : "PID-less ownership candidate matches");
        }
        if (identity == PidIdentity.MATCH) {
            return ProfileAudit.unknown(selected, "runtime_ownership_unverified",
                    "runtime_ownership_unverified: durable PID was not the sole audited owner");
        }
        return ProfileAudit.residue(selected, durablePid,
                "profile residue has no live owner");
    }

    /**
     * Decide whether profile files may be removed after the service has
     * stopped its in-process handle. The service still performs the actual
     * TERM/KILL and file deletion.
     */
    public static CleanupDecision decideCleanup(RuntimeProfile profile, PidIdentity identity,
                                                boolean processHandleAlive,
                                                OwnershipAudit residueAudit,
                                                boolean rootAvailable) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        PidIdentity safeIdentity = identity == null ? PidIdentity.UNKNOWN : identity;
        if (safeIdentity == PidIdentity.MATCH) {
            return CleanupDecision.block(CleanupAction.BLOCK_ACTIVE_PID, -1L,
                    "cleanup_failed", "VPP PID remains active");
        }
        if (safeIdentity == PidIdentity.MISMATCH) {
            return CleanupDecision.block(CleanupAction.BLOCK_PID_MISMATCH, -1L,
                    "cleanup_failed", "recorded PID identity changed; refusing to remove profile");
        }
        if (safeIdentity == PidIdentity.UNKNOWN) {
            boolean unavailable = selected == RuntimeProfile.ROOT && !rootAvailable;
            return CleanupDecision.block(CleanupAction.BLOCK_PID_UNKNOWN, -1L,
                    unavailable ? "root_authorization_required" : "cleanup_failed",
                    unavailable ? "recorded PID cannot be audited without root authorization"
                            : "recorded PID identity could not be verified; refusing cleanup");
        }
        if (processHandleAlive) {
            return CleanupDecision.block(CleanupAction.BLOCK_PROCESS_HANDLE, -1L,
                    "cleanup_failed", "VPP process handle remains active");
        }
        OwnershipAudit audit = residueAudit == null ? OwnershipAudit.none() : residueAudit;
        if (audit.isUnknown()) {
            return CleanupDecision.block(CleanupAction.BLOCK_OWNER_UNKNOWN, audit.pid,
                    audit.errorCode, "profile residue ownership audit failed: " + audit.detail);
        }
        if (audit.isVerifiedLive()) {
            return CleanupDecision.block(CleanupAction.BLOCK_LIVE_OWNER, audit.pid,
                    "cleanup_failed", "profile residue still belongs to a live VPP process");
        }
        return CleanupDecision.remove();
    }

    /**
     * Run the complete token/profile/executable/hash ownership inspection.
     * The shell seam reports LIVE only for exactly one verified process;
     * duplicate matches and candidate identity races remain UNKNOWN.
     */
    public static OwnershipAudit inspect(ProfileSpec spec, CommandRunner runner) {
        if (spec == null || runner == null) {
            return OwnershipAudit.unknown("ownership inspection is unavailable");
        }
        CommandResult result = runner.run(spec.profile, buildOwnershipScanCommand(spec), 3L);
        if (result == null) {
            return OwnershipAudit.unknown("ownership inspection returned no result");
        }
        if (result.status == 0) {
            return OwnershipAudit.none();
        }
        if (result.status == OWNER_MATCH_STATUS) {
            return OwnershipAudit.live(parseOwnerPid(result.output));
        }
        if (result.status == OWNER_AMBIGUOUS_STATUS) {
            return OwnershipAudit.unknown(
                    "runtime_ownership_ambiguous",
                    "ownership scan found multiple matching live owners"
                            + parseOwnerCountDetail(result.output));
        }
        if (result.status == OWNER_UNCERTAIN_STATUS) {
            if (result.output.contains("VPP_STRONG_IDENTITY_MISMATCH=1")) {
                return OwnershipAudit.unknown(
                        "runtime_ownership_ambiguous",
                        "ownership scan found a strong profile identity mismatch");
            }
            if (result.output.contains("VPP_STRONG_IDENTITY_UNVERIFIED=1")) {
                return OwnershipAudit.unknown(
                        "runtime_ownership_unverified",
                        "ownership scan could not read or validate the durable profile configuration");
            }
            return OwnershipAudit.unknown(
                    "runtime_ownership_unverified",
                    "ownership scan observed a candidate identity race or unreadable identity");
        }
        if (result.status == spec.unavailableStatus) {
            return OwnershipAudit.unknown(spec.unavailableErrorCode, spec.unavailableDetail);
        }
        return OwnershipAudit.unknown((spec.profile == RuntimeProfile.ROOT ? "root" : "app-UID")
                + " /proc ownership scan returned status " + result.status);
    }

    /** Validate one recorded PID against the complete profile identity. */
    public static PidIdentity validatePid(ProfileSpec spec, long pid, CommandRunner runner) {
        if (pid <= 0L) {
            return PidIdentity.MISSING;
        }
        if (spec == null || runner == null) {
            return PidIdentity.UNKNOWN;
        }
        CommandResult probe = runner.run(spec.profile, buildProbeCommand(spec, pid), 2L);
        if (probe == null || probe.status != 0 && probe.status != 1) {
            return PidIdentity.UNKNOWN;
        }
        if (probe.status == 1) {
            return PidIdentity.MISSING;
        }
        CommandResult identity = runner.run(spec.profile, buildPidIdentityCommand(spec, pid), 2L);
        if (identity == null) {
            return PidIdentity.UNKNOWN;
        }
        if (identity.status == 0) {
            return PidIdentity.MATCH;
        }
        return identity.status == 1 ? PidIdentity.MISMATCH : PidIdentity.UNKNOWN;
    }

    /** Public for host tests and for keeping shell construction in this seam. */
    public static String buildOwnershipScanCommand(ProfileSpec spec) {
        String expectedUid = shellQuote(spec.expectedUid);
        String startup = shellQuote(spec.startupPath);
        String executable = shellQuote(spec.executablePath);
        String ownerToken = shellQuote("SAKAMOTO_VPP_OWNER_TOKEN=" + spec.ownerToken);
        String runtimeEnv = shellQuote("SAKAMOTO_VPP_RUNTIME_DIR=" + spec.runtimePath);
        String profileEnv = shellQuote("SAKAMOTO_RUNTIME_PROFILE=" + spec.profile.wireName);
        String ownerKey = shellQuote("SAKAMOTO_VPP_OWNER_TOKEN=");
        String runtimeKey = shellQuote("SAKAMOTO_VPP_RUNTIME_DIR=");
        String profileKey = shellQuote("SAKAMOTO_RUNTIME_PROFILE=");
        String ownerValue = shellQuote(spec.ownerToken);
        String runtimeValue = shellQuote(spec.runtimePath);
        String profileValue = shellQuote(spec.profile.wireName);
        String runtimeDirLine = shellQuote("runtime-dir " + spec.runtimePath);
        String cliSocketLine = shellQuote("cli-listen " + spec.runtimePath + "/cli.sock");
        String apiSocketLine = shellQuote("socket-name " + spec.runtimePath + "/api.sock");
        String statsegSocketLine = shellQuote("socket-name " + spec.runtimePath + "/statseg.sock");
        // KernelSU launches the root shell in the Android shell SELinux
        // domain. That domain cannot read app-data /proc entries even when
        // the caller is UID 0; runcon restores the privileged reader context
        // for each bounded probe while keeping the scan itself shell-owned.
        String procReader = "0".equals(spec.expectedUid) ? "runcon u:r:ksu:s0 " : "";
        String procTest = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 test " : "test ";
        String cmdlineReader = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 sh -c \"tr '\\0' ' ' </proc/$pid/cmdline 2>/dev/null\""
                : "tr '\\0' ' ' </proc/$pid/cmdline 2>/dev/null";
        String environReader = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 sh -c \"tr '\\0' '\\n' </proc/$pid/environ 2>/dev/null\""
                : "tr '\\0' '\\n' </proc/$pid/environ 2>/dev/null";
        return "audit_pid=$$; "
                + "is_audit_lineage() { lineage_pid=\"$1\"; lineage_depth=0; "
                + "while test \"$lineage_depth\" -lt 8 && test -n \"$lineage_pid\"; do "
                + "[ \"$lineage_pid\" = \"$audit_pid\" ] && return 0; "
                + "lineage_parent=$(" + procReader
                + "awk '{print $4}' \"/proc/$lineage_pid/stat\" 2>/dev/null) "
                + "|| return 1; "
                + "case \"$lineage_parent\" in ''|*[!0-9]*) return 1 ;; esac; "
                + "[ \"$lineage_parent\" = \"$lineage_pid\" ] && return 1; "
                + "lineage_pid=\"$lineage_parent\"; "
                + "lineage_depth=$((lineage_depth + 1)); done; return 1; }; "
                + "scan_snapshot() { "
                + "profile_config=$(" + procReader + "cat " + startup
                + " 2>/dev/null); profile_config_status=$?; "
                + "profile_config_mismatch=0; profile_config_unverified=0; "
                + "if [ \"$profile_config_status\" -ne 0 ]; then "
                + "profile_config_unverified=1; "
                + "elif ! printf '%s\\n' \"$profile_config\" | grep -F -- " + runtimeDirLine
                + " >/dev/null || ! printf '%s\\n' \"$profile_config\" | grep -F -- "
                + cliSocketLine + " >/dev/null || ! printf '%s\\n' \"$profile_config\" | grep -F -- "
                + apiSocketLine + " >/dev/null || ! printf '%s\\n' \"$profile_config\" | grep -F -- "
                + statsegSocketLine + " >/dev/null; then "
                + "profile_config_mismatch=1; fi; "
                + "ps_output=$(ps -A -o PID,UID,args 2>/dev/null) || return 120; "
                + "match_count=0; transition_count=0; first_pid=; uncertain=0; strong_mismatch=0; "
                + "candidate_pids=$(printf '%s\\n' \"$ps_output\" | awk -v startup="
                + startup + " -v expected_uid=" + expectedUid
                + " '$1 ~ /^[0-9]+$/ && $2 == expected_uid"
                + " && index($0, startup) {print $1}') || return 120; "
                + "for pid in $candidate_pids; do "
                + "is_audit_lineage \"$pid\" && continue; "
                + "proc=/proc/$pid; "
                // A process can exit between the exhaustive ps snapshot and
                // its bounded /proc reads.  Its disappearance is not an
                // unreadable live owner; ignore that stale candidate and
                // decide from the remaining stable snapshot.
                + "if ! " + procTest + "-d \"$proc\"; then continue; fi; "
                + "if ! " + procTest + "-r \"$proc/status\"; then uncertain=1; continue; fi; "
                + "uid=$(" + procReader + "awk '$1 == \"Uid:\" {print $2; exit}' \"$proc/status\") "
                + "|| { uncertain=1; continue; }; "
                + "if test -z \"$uid\"; then uncertain=1; continue; fi; "
                + "[ \"$uid\" = " + expectedUid + " ] || continue; "
                + "if ! " + procTest + "-r \"$proc/exe\" || ! " + procTest
                + "-r \"$proc/cmdline\"; then "
                + "uncertain=1; continue; fi; "
                + "exe=$(" + procReader + "readlink \"$proc/exe\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "test -n \"$exe\" || { uncertain=1; continue; }; "
                + "cmd=$(" + cmdlineReader + ") "
                + "|| { uncertain=1; continue; }; "
                + "case \"$cmd\" in *" + startup + "*) ;; *) continue ;; esac; "
                + "if [ \"$exe\" = " + executable + " ]; then "
                + "if [ \"$profile_config_mismatch\" -ne 0 ]; then "
                + "strong_mismatch=1; continue; fi; "
                + "if [ \"$profile_config_unverified\" -ne 0 ]; then "
                + "uncertain=1; continue; fi; "
                + "env_status=0; env=; "
                + "if " + procTest + "-r \"$proc/environ\"; then "
                + "env=$(" + environReader + "); env_status=$?; "
                + "else env_status=125; fi; "
                + "if [ \"$env_status\" -eq 0 ]; then "
                + "printf '%s\\n' \"$env\" | grep -F -- " + ownerToken
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -eq 1 ]; then strong_mismatch=1; continue; fi; "
                + "[ \"$grep_status\" -eq 0 ] || { uncertain=1; continue; }; "
                + "printf '%s\\n' \"$env\" | grep -F -- " + runtimeEnv
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -eq 1 ]; then strong_mismatch=1; continue; fi; "
                + "[ \"$grep_status\" -eq 0 ] || { uncertain=1; continue; }; "
                + "printf '%s\\n' \"$env\" | grep -F -- " + profileEnv
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -eq 1 ]; then strong_mismatch=1; continue; fi; "
                + "[ \"$grep_status\" -eq 0 ] || { uncertain=1; continue; }; "
                + "elif [ " + expectedUid + " != '0' ] && [ \"$env_status\" -ne 0 ]; then "
                + "uncertain=1; continue; fi; "
                + "hash_line=$(" + procReader + "sha256sum \"$proc/exe\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "hash=$(printf '%s\\n' \"$hash_line\" | awk '{print $1}') "
                + "|| { uncertain=1; continue; }; "
                + "test -n \"$hash\" || { uncertain=1; continue; }; "
                + "[ \"$hash\" = " + shellQuote(spec.executableHash)
                + " ] || { strong_mismatch=1; continue; }; "
                + "match_count=$((match_count + 1)); "
                + "[ -n \"$first_pid\" ] || first_pid=\"$pid\"; "
                + "elif [ \"$exe\" = '/system/bin/sh' ]; then "
                + "case \"$cmd\" in *" + ownerKey + "*" + ownerValue + "*) ;; *) continue ;; esac; "
                + "case \"$cmd\" in *" + runtimeKey + "*" + runtimeValue + "*) ;; *) continue ;; esac; "
                + "case \"$cmd\" in *" + profileKey + "*" + profileValue + "*) ;; *) continue ;; esac; "
                + "case \"$cmd\" in *'export '*'exec '*" + executable + "*'plugin_path'*' -c '*"
                + startup + "*) transition_count=$((transition_count + 1));; esac; "
                + "fi; done; "
                + "printf 'VPP_OWNER_COUNT=%s\\nVPP_TRANSITION_COUNT=%s\\n' "
                + "\"$match_count\" \"$transition_count\"; "
                + "if [ \"$strong_mismatch\" -ne 0 ]; then "
                + "printf 'VPP_STRONG_IDENTITY_MISMATCH=1\\n'; return 127; fi; "
                + "if [ \"$uncertain\" -ne 0 ]; then return 127; fi; "
                + "if [ \"$match_count\" -gt 1 ]; then "
                + "printf 'VPP_OWNER_PID=%s\\n' \"$first_pid\"; return 11; fi; "
                + "if [ \"$transition_count\" -gt 0 ]; then return 12; fi; "
                + "if [ \"$match_count\" -eq 1 ]; then "
                + "printf 'VPP_OWNER_PID=%s\\n' \"$first_pid\"; return 10; fi; return 0; }; "
                + "snapshot_one=$(scan_snapshot); snapshot_status=$?; "
                + "printf '%s\\n' \"$snapshot_one\"; "
                + "case \"$snapshot_status\" in "
                + "0) exit 0 ;; 10) exit 10 ;; 11) exit 11 ;; 127) exit 127 ;; "
                + "12) sleep 0.05 || exit 127; "
                + "snapshot_two=$(scan_snapshot); snapshot_two_status=$?; "
                + "printf '%s\\n' \"$snapshot_two\"; "
                + "case \"$snapshot_two_status\" in 10) exit 10 ;; 11) exit 11 ;; *) exit 127 ;; esac ;; "
                + "*) exit 120 ;; esac";
    }

    private static String buildPidIdentityCommand(ProfileSpec spec, long pid) {
        String cmdline = shellQuote("/proc/" + pid + "/cmdline");
        String environ = shellQuote("/proc/" + pid + "/environ");
        String status = shellQuote("/proc/" + pid + "/status");
        String exe = shellQuote("/proc/" + pid + "/exe");
        String expectedUid = shellQuote(spec.expectedUid);
        String executable = shellQuote(spec.executablePath);
        String startup = shellQuote(spec.startupPath);
        String token = shellQuote("SAKAMOTO_VPP_OWNER_TOKEN=" + spec.ownerToken);
        String runtime = shellQuote("SAKAMOTO_VPP_RUNTIME_DIR=" + spec.runtimePath);
        String profile = shellQuote("SAKAMOTO_RUNTIME_PROFILE=" + spec.profile.wireName);
        String runtimeDirLine = shellQuote("runtime-dir " + spec.runtimePath);
        String cliSocketLine = shellQuote("cli-listen " + spec.runtimePath + "/cli.sock");
        String apiSocketLine = shellQuote("socket-name " + spec.runtimePath + "/api.sock");
        String statsegSocketLine = shellQuote("socket-name " + spec.runtimePath + "/statseg.sock");
        // KernelSU's root shell domain cannot directly read another process's
        // proc files on this device.  Use its privileged domain for root
        // profiles while retaining the normal reader for app-owned profiles.
        String procReader = "0".equals(spec.expectedUid) ? "runcon u:r:ksu:s0 " : "";
        String cmdlineReader = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 sh -c \"tr '\\0' ' ' </proc/" + pid + "/cmdline 2>/dev/null\""
                : "tr '\\0' ' ' </proc/" + pid + "/cmdline 2>/dev/null";
        String environReader = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 sh -c \"tr '\\0' '\\n' </proc/" + pid + "/environ 2>/dev/null\""
                : "tr '\\0' '\\n' </proc/" + pid + "/environ 2>/dev/null";
        String procTest = "0".equals(spec.expectedUid)
                ? "runcon u:r:ksu:s0 test " : "test ";
        return "profile_config=$(" + procReader + "cat " + startup + " 2>/dev/null)"
                + " || exit 125"
                + " && printf '%s\\n' \"$profile_config\" | grep -F -- " + runtimeDirLine
                + " >/dev/null"
                + " && printf '%s\\n' \"$profile_config\" | grep -F -- " + cliSocketLine
                + " >/dev/null"
                + " && printf '%s\\n' \"$profile_config\" | grep -F -- " + apiSocketLine
                + " >/dev/null"
                + " && printf '%s\\n' \"$profile_config\" | grep -F -- " + statsegSocketLine
                + " >/dev/null"
                + " && if ! " + procTest + "-r " + status + " || ! " + procTest + "-r " + cmdline
                + " || ! " + procTest + "-r " + environ + " || ! " + procTest + "-r " + exe
                + "; then exit 125; fi"
                + " && uid=$(" + procReader + "awk '$1 == \"Uid:\" {print $2; exit}' " + status + ")"
                + " && test \"$uid\" = " + expectedUid
                + " && exe=$(" + procReader + "readlink " + exe + ")"
                + " && test \"$exe\" = " + executable
                + " && " + cmdlineReader + " | grep -F -- " + startup + " >/dev/null"
                + " && " + environReader + " | grep -F -- " + token + " >/dev/null"
                + " && " + environReader + " | grep -F -- " + runtime + " >/dev/null"
                + " && " + environReader + " | grep -F -- " + profile + " >/dev/null";
    }

    /** Public shell seam for tests and for the service's bounded PID probe. */
    public static String buildProbeCommand(ProfileSpec spec, long pid) {
        String probe = "if kill -0 " + pid + " 2>/dev/null; then exit 0; "
                + "elif test -e /proc/" + pid + "; then exit 2; else exit 1; fi";
        if (spec != null && "0".equals(spec.expectedUid)) {
            // Both kill(2) and /proc existence are security-context-sensitive
            // on Android. Running only the `test` branch through runcon still
            // lets a shell-domain EPERM be misclassified as a missing PID.
            return "runcon u:r:ksu:s0 sh -c " + shellQuote(probe);
        }
        return probe;
    }

    private static long parseOwnerPid(String output) {
        if (output == null) {
            return -1L;
        }
        long parsedPid = -1L;
        for (String line : output.split("\\r?\\n")) {
            if (!line.startsWith("VPP_OWNER_PID=")) {
                continue;
            }
            try {
                long pid = Long.parseLong(line.substring("VPP_OWNER_PID=".length()).trim());
                if (pid > 0L) {
                    // A transition scan prints the first and stable-second
                    // snapshots together; the last verified PID belongs to
                    // the stable snapshot that justified adoption.
                    parsedPid = pid;
                }
            } catch (NumberFormatException ignored) {
                // Keep looking for a later, valid snapshot result.
            }
        }
        return parsedPid;
    }

    private static String parseOwnerCountDetail(String output) {
        if (output == null) {
            return "";
        }
        long maxCount = 0L;
        for (String line : output.split("\\r?\\n")) {
            if (!line.startsWith("VPP_OWNER_COUNT=")) {
                continue;
            }
            String count = line.substring("VPP_OWNER_COUNT=".length()).trim();
            try {
                long parsed = Long.parseLong(count);
                maxCount = Math.max(maxCount, parsed);
            } catch (NumberFormatException ignored) {
                // Keep the bounded generic ambiguity detail.
            }
        }
        if (maxCount > 1L) {
            return " (" + maxCount + " matches)";
        }
        return "";
    }

    private static String value(String value) {
        return value == null ? "" : value;
    }

    private static String shellQuote(String value) {
        return "'" + value(value).replace("'", "'\\''") + "'";
    }
}
