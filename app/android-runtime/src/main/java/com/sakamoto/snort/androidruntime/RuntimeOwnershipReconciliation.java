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

        private ProfileAudit(RuntimeProfile profile, Evidence evidence, long pid, String detail) {
            this.profile = profile == null ? RuntimeProfile.ROOT : profile;
            this.evidence = evidence == null ? Evidence.UNKNOWN : evidence;
            this.pid = pid;
            this.detail = value(detail);
        }

        public static ProfileAudit none(RuntimeProfile profile) {
            return new ProfileAudit(profile, Evidence.NONE, -1L,
                    "no durable profile or live owner");
        }

        public static ProfileAudit live(RuntimeProfile profile, long pid, String detail) {
            return new ProfileAudit(profile, Evidence.LIVE, pid, detail);
        }

        public static ProfileAudit residue(RuntimeProfile profile, long pid, String detail) {
            return new ProfileAudit(profile, Evidence.RESIDUE, pid, detail);
        }

        public static ProfileAudit unknown(RuntimeProfile profile, String detail) {
            return new ProfileAudit(profile, Evidence.UNKNOWN, -1L, detail);
        }
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
     * Convert durable PID evidence and a PID-less ownership inspection into a
     * profile audit. A verified live candidate is considered before the safe
     * residue path; this preserves adoption when the PID file is absent.
     */
    public static ProfileAudit classifyDurableProfile(
            RuntimeProfile profile, boolean present, long durablePid,
            PidIdentity durableIdentity, OwnershipAudit candidate) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        PidIdentity identity = durableIdentity == null ? PidIdentity.UNKNOWN : durableIdentity;
        if (identity == PidIdentity.MATCH) {
            return ProfileAudit.live(selected, durablePid, "durable PID identity matches");
        }
        if (identity == PidIdentity.UNKNOWN) {
            return ProfileAudit.unknown(selected,
                    "durable PID identity could not be verified");
        }
        if (identity == PidIdentity.MISMATCH) {
            return ProfileAudit.unknown(selected,
                    "durable PID belongs to a different process");
        }
        if (!present) {
            return ProfileAudit.none(selected);
        }
        if (candidate == null || candidate.isUnknown()) {
            String detail = candidate == null ? "cleanup_failed: ownership audit unavailable"
                    : candidate.errorCode + ": " + candidate.detail;
            return ProfileAudit.unknown(selected, detail);
        }
        if (candidate.isVerifiedLive()) {
            return ProfileAudit.live(selected, candidate.pid,
                    "PID-less ownership candidate matches");
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
        CommandResult probe = runner.run(spec.profile, buildProbeCommand(pid), 2L);
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
        String runtime = shellQuote(spec.runtimePath);
        String profileName = shellQuote(spec.profile.wireName);
        return "ps_output=$(ps -A -o PID,UID,args 2>/dev/null) || exit 120; "
                + "match_count=0; first_pid=; uncertain=0; "
                + "candidate_pids=$(printf '%s\\n' \"$ps_output\" | awk -v startup="
                + startup + " -v expected_uid=" + expectedUid
                + " '$1 ~ /^[0-9]+$/ && $2 == expected_uid"
                + " && index($0, startup) {print $1}') || exit 120; "
                + "for pid in $candidate_pids; do "
                + "proc=/proc/$pid; "
                + "if ! test -d \"$proc\"; then uncertain=1; continue; fi; "
                + "if ! test -r \"$proc/status\"; then "
                + "uncertain=1; continue; fi; "
                + "uid=$(awk '$1 == \"Uid:\" {print $2; exit}' \"$proc/status\") "
                + "|| { uncertain=1; continue; }; "
                + "if test -z \"$uid\"; then uncertain=1; continue; fi; "
                + "[ \"$uid\" = " + expectedUid + " ] || continue; "
                + "if ! test -r \"$proc/exe\"; then "
                + "uncertain=1; continue; fi; "
                + "exe=$(readlink \"$proc/exe\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "test -n \"$exe\" || { uncertain=1; continue; }; "
                + "[ \"$exe\" = " + executable + " ] || continue; "
                + "if ! test -r \"$proc/cmdline\"; then "
                + "uncertain=1; continue; fi; "
                + "cmd=$(tr '\\0' ' ' <\"$proc/cmdline\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "case \"$cmd\" in *" + startup + "*) ;; *) continue ;; esac; "
                + "if ! test -r \"$proc/environ\"; then "
                + "uncertain=1; continue; fi; "
                + "env=$(tr '\\0' '\\n' <\"$proc/environ\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "printf '%s\\n' \"$env\" | grep -F -- "
                + shellQuote("SAKAMOTO_VPP_OWNER_TOKEN=" + spec.ownerToken)
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -ne 0 ]; then "
                + "[ \"$grep_status\" -eq 1 ] || uncertain=1; continue; fi; "
                + "printf '%s\\n' \"$env\" | grep -F -- "
                + shellQuote("SAKAMOTO_VPP_RUNTIME_DIR=" + spec.runtimePath)
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -ne 0 ]; then "
                + "[ \"$grep_status\" -eq 1 ] || uncertain=1; continue; fi; "
                + "printf '%s\\n' \"$env\" | grep -F -- "
                + shellQuote("SAKAMOTO_RUNTIME_PROFILE=" + spec.profile.wireName)
                + " >/dev/null; grep_status=$?; "
                + "if [ \"$grep_status\" -ne 0 ]; then "
                + "[ \"$grep_status\" -eq 1 ] || uncertain=1; continue; fi; "
                + "hash_line=$(sha256sum \"$proc/exe\" 2>/dev/null) "
                + "|| { uncertain=1; continue; }; "
                + "hash=$(printf '%s\\n' \"$hash_line\" | awk '{print $1}') "
                + "|| { uncertain=1; continue; }; "
                + "test -n \"$hash\" || { uncertain=1; continue; }; "
                + "[ \"$hash\" = " + shellQuote(spec.executableHash)
                + " ] || continue; "
                + "match_count=$((match_count + 1)); "
                + "[ -n \"$first_pid\" ] || first_pid=\"$pid\"; "
                + "done; "
                + "if [ \"$uncertain\" -ne 0 ]; then "
                + "printf 'VPP_OWNER_COUNT=%s\\n' \"$match_count\"; exit 127; fi; "
                + "if [ \"$match_count\" -eq 0 ]; then exit 0; fi; "
                + "if [ \"$match_count\" -gt 1 ]; then "
                + "printf 'VPP_OWNER_COUNT=%s\\n' \"$match_count\"; "
                + "printf 'VPP_OWNER_PID=%s\\n' \"$first_pid\"; exit 11; fi; "
                + "printf 'VPP_OWNER_COUNT=1\\nVPP_OWNER_PID=%s\\n' \"$first_pid\"; exit 10";
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
        return "if ! test -r " + status + " || ! test -r " + cmdline
                + " || ! test -r " + environ + " || ! test -r " + exe + "; then exit 125; fi"
                + " && uid=$(awk '$1 == \"Uid:\" {print $2; exit}' " + status + ")"
                + " && test \"$uid\" = " + expectedUid
                + " && exe=$(readlink " + exe + ")"
                + " && test \"$exe\" = " + executable
                + " && tr '\\0' ' ' <" + cmdline + " | grep -F -- " + startup + " >/dev/null"
                + " && tr '\\0' '\\n' <" + environ + " | grep -F -- " + token + " >/dev/null"
                + " && tr '\\0' '\\n' <" + environ + " | grep -F -- " + runtime + " >/dev/null"
                + " && tr '\\0' '\\n' <" + environ + " | grep -F -- " + profile + " >/dev/null";
    }

    private static String buildProbeCommand(long pid) {
        return "if kill -0 " + pid + " 2>/dev/null; then exit 0; "
                + "elif test -e /proc/" + pid + "; then exit 2; else exit 1; fi";
    }

    private static long parseOwnerPid(String output) {
        if (output == null) {
            return -1L;
        }
        for (String line : output.split("\\r?\\n")) {
            if (!line.startsWith("VPP_OWNER_PID=")) {
                continue;
            }
            try {
                long pid = Long.parseLong(line.substring("VPP_OWNER_PID=".length()).trim());
                return pid > 0L ? pid : -1L;
            } catch (NumberFormatException ignored) {
                return -1L;
            }
        }
        return -1L;
    }

    private static String parseOwnerCountDetail(String output) {
        if (output == null) {
            return "";
        }
        for (String line : output.split("\\r?\\n")) {
            if (!line.startsWith("VPP_OWNER_COUNT=")) {
                continue;
            }
            String count = line.substring("VPP_OWNER_COUNT=".length()).trim();
            try {
                long parsed = Long.parseLong(count);
                if (parsed > 1L) {
                    return " (" + parsed + " matches)";
                }
            } catch (NumberFormatException ignored) {
                // Keep the bounded generic ambiguity detail.
            }
            break;
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
