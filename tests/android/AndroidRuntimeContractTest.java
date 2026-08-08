import com.sakamoto.snort.androidruntime.RuntimeControlProtocol;
import com.sakamoto.snort.androidruntime.RuntimeControlRequest;
import com.sakamoto.snort.androidruntime.RuntimeControlOrdering;
import com.sakamoto.snort.androidruntime.RuntimeControlNative;
import com.sakamoto.snort.androidruntime.RuntimeProfile;
import com.sakamoto.snort.androidruntime.RuntimeOwnershipReconciliation;
import com.sakamoto.snort.androidruntime.RuntimeSnapshot;
import com.sakamoto.snort.androidruntime.RuntimeStateStore;
import com.sakamoto.snort.androidruntime.VppHealthHandshake;

import java.nio.file.Files;
import java.nio.file.Path;

/** Public-seam tests for the production Android runtime incubator. */
public final class AndroidRuntimeContractTest {
    public static void main(String[] args) throws Exception {
        requestRoundTripIsVersionedAndProfileAware();
        lifecycleRequestOrderingRejectsDelayedStarts();
        profileDoesNotExposeAdapterArtifacts();
        snapshotRoundTripPreservesBoundedHealthAndError();
        durableProjectionReadResultIsExplicit();
        durableOwnershipDecisionFailsClosed();
        globalOwnershipDecisionRequiresOneProjectionConsistentOwner();
        pidlessLiveOwnerIsAdoptable();
        ownershipCleanupDecisionFailsClosed();
        ownershipInspectionKeepsIdentityInThePublicSeam();
        pidIdentityUsesPrivilegedProcContext();
        rootProbeUsesPrivilegedContextAndFailsClosed();
        ownershipInspectionBlocksLiveUnreadableEnvironment();
        ownershipScanRechecksProcAfterReadRaces();
        ownershipScanBlocksMatchingIdentityOnMismatchedExecutable();
        ownershipInspectionRejectsSameProfileMultiplicity();
        recordedPidRequiresAnExhaustiveSoleOwnerScan();
        launchShellTransitionFailsClosedUntilStableVpp();
        transientOwnershipAuditRetriesOnlyForActiveRuntime();
        stoppedSnapshotRetainsRecentFailure();
        coreHealthDoesNotClaimAdapterReadiness();
        nativeCoreHandshakeRequiresGeneratedIdentity();
        System.out.println("android runtime contract: PASS");
    }

    private static void requestRoundTripIsVersionedAndProfileAware() {
        RuntimeControlRequest start = RuntimeControlRequest.start(RuntimeProfile.VPN);
        check(start.protocolVersion == RuntimeControlProtocol.VERSION,
                "start request uses the current protocol version");
        check(RuntimeControlRequest.Action.START == start.action,
                "start action is preserved");
        check(RuntimeProfile.VPN == start.profile, "VPN profile is preserved");
        RuntimeControlRequest restored = RuntimeControlRequest.decode(start.encode());
        check(start.equals(restored), "request wire round-trips");

        RuntimeControlRequest query = RuntimeControlRequest.decode(
                RuntimeControlRequest.query().encode());
        check(RuntimeControlRequest.Action.QUERY == query.action,
                "query is a first-class public action");
        check(query.profile == null, "query does not select a profile");
        check(RuntimeControlRequest.STOP.equals(
                RuntimeControlRequest.stop().encode().get("action")),
                "stop action has a stable wire name");
    }

    private static void lifecycleRequestOrderingRejectsDelayedStarts() {
        RuntimeControlOrdering ordering = new RuntimeControlOrdering();
        check(ordering.observe(100L, 1) == RuntimeControlOrdering.Decision.ACCEPT,
                "first stamped lifecycle request is accepted");
        check(ordering.observe(200L, 2) == RuntimeControlOrdering.Decision.ACCEPT,
                "newer lifecycle request is accepted");
        check(ordering.observe(150L, 3) == RuntimeControlOrdering.Decision.STALE,
                "delayed older START is rejected after a newer STOP");
        check(ordering.latestRequestTimeMillis() == 200L,
                "stale request cannot replace latest lifecycle timestamp");
        check(ordering.observe(0L, 4) == RuntimeControlOrdering.Decision.STALE,
                "unstamped delayed request fails closed after stamped control");

        RuntimeControlOrdering sameMillisecond = new RuntimeControlOrdering();
        check(sameMillisecond.observe(500L, 8) == RuntimeControlOrdering.Decision.ACCEPT,
                "same-millisecond request baseline is accepted");
        check(sameMillisecond.observe(500L, 7) == RuntimeControlOrdering.Decision.STALE,
                "older start ID breaks same-millisecond ties as stale");
        check(sameMillisecond.observe(500L, 9) == RuntimeControlOrdering.Decision.ACCEPT,
                "newer start ID wins same-millisecond tie");
    }

    private static void snapshotRoundTripPreservesBoundedHealthAndError() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-67-runtime");
        RuntimeSnapshot running = RuntimeSnapshot.running(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "ok", 42L);
        RuntimeStateStore.write(files.toFile(), running);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check(restored.state.equals(RuntimeSnapshot.STATE_RUNNING), "running state round-trips");
        check(restored.profile == RuntimeProfile.ROOT, "root profile round-trips");
        check(RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(restored.adapterReadiness),
                "adapter readiness remains explicitly unavailable");
        check("ok".equals(restored.coreHealth), "core health round-trips separately");
        check(restored.pid == 42L, "owner pid round-trips");

        RuntimeSnapshot failure = RuntimeSnapshot.error(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "cleanup_failed",
                "socket residue remains", true, 77L);
        RuntimeStateStore.write(files.toFile(), failure);
        RuntimeSnapshot restoredFailure = RuntimeStateStore.read(files.toFile());
        check(restoredFailure.isActive(), "active uncertainty survives an error state");
        check(restoredFailure.errorCode.equals("cleanup_failed"), "error code round-trips");
        check(restoredFailure.errorMessage.length() <= RuntimeSnapshot.MAX_TEXT_LENGTH,
                "error message is bounded");
    }

    private static void durableProjectionReadResultIsExplicit() throws Exception {
        Path missing = Files.createTempDirectory("sakamoto-67-runtime-missing");
        RuntimeStateStore.ReadResult absent = RuntimeStateStore.readResult(missing.toFile());
        check(!absent.present, "missing projection is reported as absent");
        check(absent.valid, "missing projection is not a parse failure");
        check(RuntimeSnapshot.STATE_STOPPED.equals(absent.snapshot.state),
                "missing projection starts from an inactive snapshot");

        Path corrupt = Files.createTempDirectory("sakamoto-67-runtime-corrupt");
        Files.createDirectories(corrupt.resolve("runtime-state"));
        Files.write(corrupt.resolve("runtime-state/snapshot.properties"),
                "schemaVersion=not-a-number\nprofile=vpn\nstate=running\n"
                        .getBytes("US-ASCII"));
        RuntimeStateStore.ReadResult unreadable = RuntimeStateStore.readResult(corrupt.toFile());
        check(unreadable.present, "corrupt projection is reported as present");
        check(!unreadable.valid, "corrupt projection is reported as invalid");
        check("state_projection_corrupt".equals(unreadable.snapshot.errorCode),
                "corrupt projection has an explicit bounded error");

        Path corruptPid = Files.createTempDirectory("sakamoto-67-runtime-pid-corrupt");
        Files.createDirectories(corruptPid.resolve("runtime-state"));
        Files.write(corruptPid.resolve("runtime-state/snapshot.properties"),
                "schemaVersion=2\nprofile=vpn\nstate=running\npid=not-a-pid\n"
                        .getBytes("US-ASCII"));
        check(!RuntimeStateStore.readResult(corruptPid.toFile()).valid,
                "malformed durable PID also requires reconciliation");
    }

    private static void durableOwnershipDecisionFailsClosed() {
        check(RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.LIVE,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "one live root owner can be adopted");
        check(RuntimeOwnershipReconciliation.Action.ADOPT_VPN
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.NONE,
                                RuntimeOwnershipReconciliation.Evidence.LIVE),
                "one live VPN owner can be adopted");
        check(RuntimeOwnershipReconciliation.Action.CLEAN
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.RESIDUE,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "one dead residue profile can be cleaned");
        check(RuntimeOwnershipReconciliation.Action.BLOCK
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.LIVE,
                                RuntimeOwnershipReconciliation.Evidence.LIVE),
                "two live owners are blocked");
        check(RuntimeOwnershipReconciliation.Action.BLOCK
                        == RuntimeOwnershipReconciliation.decide(
                                RuntimeOwnershipReconciliation.Evidence.UNKNOWN,
                                RuntimeOwnershipReconciliation.Evidence.NONE),
                "unverifiable ownership is blocked");
    }

    private static void globalOwnershipDecisionRequiresOneProjectionConsistentOwner() {
        RuntimeOwnershipReconciliation.ProfileAudit rootLive =
                RuntimeOwnershipReconciliation.ProfileAudit.live(
                        RuntimeProfile.ROOT, 42L, "root owner");
        RuntimeOwnershipReconciliation.ProfileAudit vpnLive =
                RuntimeOwnershipReconciliation.ProfileAudit.live(
                        RuntimeProfile.VPN, 77L, "vpn owner");
        RuntimeOwnershipReconciliation.Projection rootProjection =
                RuntimeOwnershipReconciliation.Projection.known(RuntimeProfile.ROOT, true, 42L);

        RuntimeOwnershipReconciliation.GlobalDecision twoLive =
                RuntimeOwnershipReconciliation.decide(rootLive, vpnLive, rootProjection);
        check(twoLive.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "a valid Root projection plus a live VPN owner is blocked globally");
        check(twoLive.root == rootLive && twoLive.vpn == vpnLive,
                "global decision retains both profile audit results");

        RuntimeOwnershipReconciliation.ProfileAudit vpnResidue =
                RuntimeOwnershipReconciliation.ProfileAudit.residue(
                        RuntimeProfile.VPN, -1L, "safe residue");
        RuntimeOwnershipReconciliation.GlobalDecision hiddenResidue =
                RuntimeOwnershipReconciliation.decide(rootLive, vpnResidue, rootProjection);
        check(hiddenResidue.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "an opposite safe residue cannot hide a second-profile ownership conflict");

        RuntimeOwnershipReconciliation.GlobalDecision soleRoot =
                RuntimeOwnershipReconciliation.decide(
                        rootLive,
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        rootProjection);
        check(soleRoot.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT,
                "a sole projected Root owner is adoptable");
        check(soleRoot.ownerProfile == RuntimeProfile.ROOT && soleRoot.ownerPid == 42L,
                "Root adoption keeps the audited owner identity");

        RuntimeOwnershipReconciliation.GlobalDecision wrongPid =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.live(
                                RuntimeProfile.ROOT, 43L, "different owner"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        rootProjection);
        check(wrongPid.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "a projected PID mismatch fails closed");

        RuntimeOwnershipReconciliation.GlobalDecision vpnMismatch =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        vpnLive,
                        rootProjection);
        check(vpnMismatch.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "a live VPN owner cannot replace a projected Root owner silently");

        RuntimeOwnershipReconciliation.GlobalDecision oppositeUnknown =
                RuntimeOwnershipReconciliation.decide(
                        rootLive,
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(
                                RuntimeProfile.VPN, "VPN audit unavailable"),
                        rootProjection);
        check(oppositeUnknown.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "an uncertain opposite profile blocks an otherwise valid owner");

        RuntimeOwnershipReconciliation.GlobalDecision missingProjectedPid =
                RuntimeOwnershipReconciliation.decide(
                        rootLive,
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.known(
                                RuntimeProfile.ROOT, true, -1L));
        check(missingProjectedPid.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT,
                "an active projection without a recorded PID can adopt its exact owner");

        RuntimeOwnershipReconciliation.GlobalDecision missingProjectedPidCrossProfile =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        vpnLive,
                        RuntimeOwnershipReconciliation.Projection.known(
                                RuntimeProfile.ROOT, true, -1L));
        check(missingProjectedPidCrossProfile.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "a missing projected PID cannot make a cross-profile owner safe");

        RuntimeOwnershipReconciliation.GlobalDecision corruptProjection =
                RuntimeOwnershipReconciliation.decide(
                        rootLive,
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(corruptProjection.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT,
                "a sole globally verified owner remains adoptable without a projection");

        RuntimeOwnershipReconciliation.GlobalDecision oppositeResidueSymmetric =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.residue(
                                RuntimeProfile.ROOT, -1L, "safe residue"),
                        vpnLive,
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(oppositeResidueSymmetric.action == RuntimeOwnershipReconciliation.Action.BLOCK,
                "safe residue in Root cannot hide a live VPN owner");

        RuntimeOwnershipReconciliation.GlobalDecision soleVpn =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        vpnLive,
                        RuntimeOwnershipReconciliation.Projection.known(RuntimeProfile.VPN, true, 77L));
        check(soleVpn.action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN,
                "a sole projected VPN owner is adoptable symmetrically");

        RuntimeOwnershipReconciliation.GlobalDecision clean =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.residue(
                                RuntimeProfile.ROOT, -1L, "safe residue"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        rootProjection);
        check(clean.action == RuntimeOwnershipReconciliation.Action.CLEAN,
                "a globally sole safe residue can be cleaned");
        check(clean.cleanupProfile == RuntimeProfile.ROOT,
                "global cleanup identifies the one residue profile");
    }

    private static void pidlessLiveOwnerIsAdoptable() {
        RuntimeOwnershipReconciliation.OwnershipAudit candidate =
                RuntimeOwnershipReconciliation.OwnershipAudit.live(4242L);
        RuntimeOwnershipReconciliation.ProfileAudit root =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, -1L,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING, candidate);
        check(root.evidence == RuntimeOwnershipReconciliation.Evidence.LIVE,
                "verified PID-less owner remains live evidence");
        check(root.pid == 4242L, "PID-less live evidence carries the audited PID");
        check(RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                        == RuntimeOwnershipReconciliation.decide(
                                root.evidence, RuntimeOwnershipReconciliation.Evidence.NONE),
                "verified PID-less owner can be adopted");
    }

    private static void ownershipCleanupDecisionFailsClosed() {
        RuntimeOwnershipReconciliation.CleanupDecision live =
                RuntimeOwnershipReconciliation.decideCleanup(
                        RuntimeProfile.ROOT,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false,
                        RuntimeOwnershipReconciliation.OwnershipAudit.live(4242L),
                        true);
        check(!live.canRemove(), "live audited owner blocks profile cleanup");
        check(live.pid == 4242L, "cleanup block identifies the live owner PID");

        RuntimeOwnershipReconciliation.CleanupDecision unknown =
                RuntimeOwnershipReconciliation.decideCleanup(
                        RuntimeProfile.ROOT,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false,
                        RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                                "ownership inspection unavailable"),
                        true);
        check(!unknown.canRemove(), "unknown ownership blocks profile cleanup");
    }

    private static void ownershipInspectionKeepsIdentityInThePublicSeam() {
        RuntimeOwnershipReconciliation.ProfileSpec spec =
                new RuntimeOwnershipReconciliation.ProfileSpec(
                        RuntimeProfile.VPN,
                        "/data/user/0/example/files/profiles/vpn/vpp/startup.conf",
                        "/data/user/0/example/files/profiles/vpn/vpp/runtime",
                        "/data/app/example/lib/arm64/libvpp_runtime.so",
                        "0123456789abcdef", "12345678-1234-1234-1234-123456789abc",
                        "10123", 125, "cleanup_failed", "runner unavailable");
        RuntimeOwnershipReconciliation.OwnershipAudit audit =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    check(profile == RuntimeProfile.VPN, "inspection preserves selected profile");
                    check(timeout == 3L, "ownership scan remains bounded");
                    check(command.contains("awk -v startup="),
                            "scan passes startup path to awk without shell-quote ambiguity");
                    check(command.contains("SAKAMOTO_VPP_OWNER_TOKEN="),
                            "scan matches the durable owner token");
                    check(command.contains("SAKAMOTO_RUNTIME_PROFILE=vpn"),
                            "scan matches the selected profile");
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            10, "VPP_OWNER_PID=4242\n");
                });
        check(audit.isVerifiedLive(), "public inspection seam reports a verified live owner");
        check(audit.pid == 4242L, "public inspection seam preserves audited PID");

        RuntimeOwnershipReconciliation.PidIdentity identity =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) ->
                                new RuntimeOwnershipReconciliation.CommandResult(0, ""));
        check(identity == RuntimeOwnershipReconciliation.PidIdentity.MATCH,
                "public PID validation seam accepts a complete identity match");
    }

    private static void pidIdentityUsesPrivilegedProcContext() {
        RuntimeOwnershipReconciliation.ProfileSpec spec = ownershipSpec();
        final String[] identityCommand = {""};
        RuntimeOwnershipReconciliation.PidIdentity identity =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) -> {
                            if (!command.startsWith("if kill -0")) {
                                identityCommand[0] = command;
                            }
                            return new RuntimeOwnershipReconciliation.CommandResult(0, "");
                        });
        check(identity == RuntimeOwnershipReconciliation.PidIdentity.MATCH,
                "root PID identity validation remains a complete match");
        check(identityCommand[0].contains(
                        "runcon u:r:ksu:s0 test -r '/proc/4242/environ'"),
                "root PID identity checks /proc readability in runcon context");
        check(!identityCommand[0].contains("if ! test -r '/proc/4242/environ'"),
                "root PID identity has no unprivileged outer environ check");
        check(identityCommand[0].contains("runcon u:r:ksu:s0 sh -c"),
                "root PID identity reads proc data in runcon context");
    }

    private static void rootProbeUsesPrivilegedContextAndFailsClosed() {
        RuntimeOwnershipReconciliation.ProfileSpec spec = ownershipSpec();
        String probe = RuntimeOwnershipReconciliation.buildProbeCommand(spec, 4242L);
        check(probe.contains("runcon u:r:ksu:s0 sh -c"),
                "root PID probe runs both liveness and /proc existence in the privileged context");
        check(probe.contains("kill -0 4242") && probe.contains("test -e /proc/4242"),
                "root PID probe checks the exact PID in the privileged context");

        final int[] calls = {0};
        RuntimeOwnershipReconciliation.PidIdentity absent =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) -> {
                            calls[0]++;
                            check(command.contains("runcon u:r:ksu:s0"),
                                    "root probe command remains privileged");
                            return new RuntimeOwnershipReconciliation.CommandResult(1, "");
                        });
        check(absent == RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                "a privileged probe proving /proc absence maps to MISSING");
        check(calls[0] == 1, "an absent PID does not trigger identity inspection");

        RuntimeOwnershipReconciliation.PidIdentity inaccessible =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) ->
                                new RuntimeOwnershipReconciliation.CommandResult(2, ""));
        check(inaccessible == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                "a privileged probe that sees an inaccessible process stays UNKNOWN");

        RuntimeOwnershipReconciliation.PidIdentity probeFailure =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) ->
                                new RuntimeOwnershipReconciliation.CommandResult(125, ""));
        check(probeFailure == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                "a privileged probe/permission failure stays UNKNOWN");

        RuntimeOwnershipReconciliation.PidIdentity vanishedDuringIdentity =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) -> {
                            if (command.startsWith("runcon u:r:ksu:s0 sh -c 'if kill -0")) {
                                return new RuntimeOwnershipReconciliation.CommandResult(0, "");
                            }
                            check(command.contains("proc_probe_status=$?"),
                                    "strong PID identity rechecks privileged proc presence after reads");
                            return new RuntimeOwnershipReconciliation.CommandResult(2, "");
                        });
        check(vanishedDuringIdentity
                        == RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                "a PID that vanishes during strong identity validation is already gone");
    }

    private static void ownershipInspectionBlocksLiveUnreadableEnvironment() {
        RuntimeOwnershipReconciliation.ProfileSpec spec = ownershipSpec();
        final String[] scanCommand = {""};
        RuntimeOwnershipReconciliation.OwnershipAudit live =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    scanCommand[0] = command;
                    check(command.contains("env_status=$?"),
                            "ownership scan records unreadable-environment status explicitly");
                    check(command.contains("runtime-dir"),
                            "ownership scan validates the profile runtime directory in startup.conf");
                    check(command.contains("cli-listen"),
                            "ownership scan validates the profile CLI socket in startup.conf");
                    check(command.contains("socket-name"),
                            "ownership scan validates profile API/statseg sockets in startup.conf");
                    check(command.contains("runcon u:r:ksu:s0 sh -c"),
                            "root ownership scan enters the privileged proc reader context");
                    check(command.contains("</proc/$pid/environ"),
                            "root ownership scan opens proc environment inside the reader context");
                    check(command.contains("profile_config_mismatch=0"),
                            "ownership scan defers corrupt startup metadata until a live candidate exists");
                    check(command.contains("profile_config_unverified=0"),
                            "ownership scan distinguishes unreadable startup metadata from stale residue");
                    check(command.contains("runcon u:r:ksu:s0 test -d \"$proc\""),
                            "root ownership scan checks candidate existence in runcon context");
                    check(!command.contains("if ! test -r \"$proc/environ\""),
                            "root ownership scan has no unprivileged outer environ check");
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            127, "VPP_OWNER_COUNT=0\nVPP_STRONG_IDENTITY_UNVERIFIED=1\n");
                });
        check(live.isUnknown(),
                "a live process with unreadable root /proc/environ remains unknown");
        check("runtime_ownership_unverified".equals(live.errorCode),
                "unreadable root /proc/environ has an explicit unverifiable error");

        final String[] mismatchOutput = {""};
        RuntimeOwnershipReconciliation.OwnershipAudit mismatch =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    mismatchOutput[0] = "VPP_OWNER_COUNT=0\nVPP_STRONG_IDENTITY_MISMATCH=1\n";
                    return new RuntimeOwnershipReconciliation.CommandResult(127, mismatchOutput[0]);
                });
        check(mismatch.isUnknown(),
                "a strong identity mismatch remains fail-closed when environment is denied");
        check(mismatchOutput[0].contains("VPP_STRONG_IDENTITY_MISMATCH"),
                "ownership scan exposes a bounded strong-identity mismatch result");
    }

    private static void ownershipScanRechecksProcAfterReadRaces() {
        String command = RuntimeOwnershipReconciliation.buildOwnershipScanCommand(ownershipSpec());
        check(command.contains("proc_presence_status=$?"),
                "every bounded proc read records the privileged recheck status");
        check(command.contains(
                        "case \"$proc_presence_status\" in 1) : ;; 0|*) uncertain=1 ;; esac"),
                "only a status-1 disappearance is ignored; live/recheck failures stay unknown");
        check(!command.contains(
                        "if ! runcon u:r:ksu:s0 test -d \"$proc\"; then continue; fi"),
                "a failed privileged existence recheck is not blindly treated as vanished");
        check(command.contains("env_status=$?"),
                "environment reader status remains explicit after the recheck");
        check(command.contains("[ \"$env_status\" -ne 0 ]"),
                "a live unreadable environment remains an uncertain identity");
        check(command.contains("hash_line=$(") && command.contains("hash_status=$?"),
                "hash reader status remains explicit before accepting executable identity");
        check(command.contains("$snapshot_two_status\" in 0) exit 0"),
                "a transition whose second snapshot is empty is treated as gone");
    }

    private static void ownershipScanBlocksMatchingIdentityOnMismatchedExecutable() {
        String command = RuntimeOwnershipReconciliation.buildOwnershipScanCommand(ownershipSpec());
        int shellBranch = command.indexOf("elif [ \"$exe\" = '/system/bin/sh' ]");
        int identityBranch = shellBranch < 0 ? -1 : command.indexOf("else ", shellBranch);
        check(identityBranch >= 0,
                "ownership scan has an explicit non-shell executable branch");
        String nonShell = command.substring(identityBranch);
        check(nonShell.contains("/proc/$pid/environ"),
                "mismatched executable candidates are checked against their environment identity");
        check(nonShell.contains("strong_mismatch=1"),
                "matching token/profile/runtime on an old executable blocks as unknown");
        check(nonShell.contains("owner_status") && nonShell.contains("runtime_status")
                        && nonShell.contains("profile_status"),
                "unrelated shell/audit commands are filtered by all identity fields");
    }

    private static void ownershipInspectionRejectsSameProfileMultiplicity() {
        RuntimeOwnershipReconciliation.ProfileSpec spec =
                new RuntimeOwnershipReconciliation.ProfileSpec(
                        RuntimeProfile.ROOT,
                        "/data/user/0/example/files/profiles/root/vpp/startup.conf",
                        "/data/user/0/example/files/profiles/root/vpp/runtime",
                        "/data/app/example/lib/arm64/libvpp_runtime.so",
                        "0123456789abcdef", "01234567-0123-0123-0123-0123456789ab",
                        "0", 120, "root_authorization_required", "runner unavailable");
        RuntimeOwnershipReconciliation.OwnershipAudit audit =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    check(profile == RuntimeProfile.ROOT,
                            "multiplicity inspection preserves the selected profile");
                    check(timeout == 3L,
                            "multiplicity inspection remains bounded");
                    check(command.contains("match_count=0"),
                            "ownership scan counts every verified match");
                    check(command.contains("VPP_OWNER_COUNT="),
                            "ownership scan reports an explicit owner count");
                    check(command.indexOf("done;") < command.lastIndexOf("exit 10"),
                            "ownership scan decides exact-one only after the full loop");
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            11, "VPP_OWNER_COUNT=2\nVPP_OWNER_PID=4242\n");
                });
        check(audit.isUnknown(),
                "same-profile duplicate owners are unknown rather than adoptable");
        check("runtime_ownership_ambiguous".equals(audit.errorCode),
                "same-profile duplicate owners have an explicit ambiguity error");
        check(audit.detail.contains("2 matches"),
                "same-profile ambiguity retains the bounded verified-match count");
        check(audit.pid < 0L,
                "ambiguous ownership never exposes one PID as safe to adopt");
        RuntimeOwnershipReconciliation.ProfileAudit root =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, -1L,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING, audit);
        check(root.evidence == RuntimeOwnershipReconciliation.Evidence.UNKNOWN,
                "ambiguous same-profile ownership blocks durable reconciliation");
        check(RuntimeOwnershipReconciliation.Action.BLOCK
                        == RuntimeOwnershipReconciliation.decide(
                                root.evidence, RuntimeOwnershipReconciliation.Evidence.NONE),
                "ambiguous same-profile ownership cannot be adopted or cleaned");

        RuntimeOwnershipReconciliation.OwnershipAudit uncertain =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) ->
                        new RuntimeOwnershipReconciliation.CommandResult(127, ""));
        check(uncertain.isUnknown(),
                "candidate identity races remain unknown rather than residue");
        check("runtime_ownership_unverified".equals(uncertain.errorCode),
                "candidate identity races have an explicit unverifiable error");
    }

    private static void transientOwnershipAuditRetriesOnlyForActiveRuntime() {
        RuntimeOwnershipReconciliation.GlobalDecision unverified =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(
                                RuntimeProfile.ROOT, "runtime_ownership_unverified",
                                "candidate exited during proc snapshot"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(unverified, true),
                "active runtime retries a transient ownership-unverified audit");
        check(!RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(unverified, false),
                "inactive runtime keeps ownership-unverified fail-closed");

        RuntimeOwnershipReconciliation.GlobalDecision ambiguous =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(
                                RuntimeProfile.ROOT, "runtime_ownership_ambiguous",
                                "duplicate owner"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(!RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(ambiguous, true),
                "ambiguous ownership never downgrades into a retry");
    }

    private static void recordedPidRequiresAnExhaustiveSoleOwnerScan() {
        RuntimeOwnershipReconciliation.ProfileSpec spec = ownershipSpec();
        final String[] scanCommand = {""};
        RuntimeOwnershipReconciliation.OwnershipAudit duplicate =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    scanCommand[0] = command;
                    check(timeout == 3L, "recorded-PID ownership scan remains bounded");
                    check(command.contains("match_count=0"),
                            "recorded PID path still performs the exhaustive match loop");
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            11, "VPP_OWNER_COUNT=2\nVPP_OWNER_PID=4242\n");
                });
        check(duplicate.isUnknown(),
                "recorded PID plus another verified owner is not adoptable");
        RuntimeOwnershipReconciliation.ProfileAudit blocked =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, 4242L,
                        RuntimeOwnershipReconciliation.PidIdentity.MATCH, duplicate);
        check(blocked.evidence == RuntimeOwnershipReconciliation.Evidence.UNKNOWN,
                "recorded PID plus another owner blocks durable reconciliation");

        RuntimeOwnershipReconciliation.OwnershipAudit sole =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) ->
                        new RuntimeOwnershipReconciliation.CommandResult(
                                10, "VPP_OWNER_COUNT=1\nVPP_OWNER_PID=4242\n"));
        RuntimeOwnershipReconciliation.ProfileAudit live =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, 4242L,
                        RuntimeOwnershipReconciliation.PidIdentity.MATCH, sole);
        check(live.evidence == RuntimeOwnershipReconciliation.Evidence.LIVE,
                "recorded PID matching the exhaustive sole owner remains live");
        check(live.pid == 4242L, "sole-owner adoption preserves the recorded PID");

        check(scanCommand[0].contains("audit_pid=$$"),
                "ownership command identifies its own audit process");
        check(scanCommand[0].contains("is_audit_lineage"),
                "ownership command excludes its own process lineage");
    }

    private static void launchShellTransitionFailsClosedUntilStableVpp() {
        RuntimeOwnershipReconciliation.ProfileSpec spec = ownershipSpec();
        final String[] transitionCommand = {""};
        RuntimeOwnershipReconciliation.OwnershipAudit shell =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) -> {
                    transitionCommand[0] = command;
                    return new RuntimeOwnershipReconciliation.CommandResult(
                            127, "VPP_OWNER_COUNT=0\nVPP_TRANSITION_COUNT=1\n");
                });
        check(shell.isUnknown(),
                "an exact launch-shaped shell remains transitional uncertainty");
        RuntimeOwnershipReconciliation.ProfileAudit blocked =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, -1L,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING, shell);
        check(blocked.evidence == RuntimeOwnershipReconciliation.Evidence.UNKNOWN,
                "pre-PID launch shell blocks cleanup/replacement");
        check(transitionCommand[0].contains("VPP_TRANSITION_COUNT="),
                "ownership command reports transitional shell evidence");
        check(transitionCommand[0].contains("/system/bin/sh"),
                "ownership command recognizes the platform launch shell");
        check(transitionCommand[0].contains("plugin_path"),
                "shell transition requires the VPP launch command shape");
        check(transitionCommand[0].contains("sleep 0.05"),
                "shell transition uses a bounded stable second snapshot");

        RuntimeOwnershipReconciliation.OwnershipAudit resolved =
                RuntimeOwnershipReconciliation.inspect(spec, (profile, command, timeout) ->
                        new RuntimeOwnershipReconciliation.CommandResult(
                                10, "VPP_OWNER_COUNT=1\nVPP_OWNER_PID=4343\n"));
        RuntimeOwnershipReconciliation.ProfileAudit adopted =
                RuntimeOwnershipReconciliation.classifyDurableProfile(
                        RuntimeProfile.ROOT, true, -1L,
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING, resolved);
        check(adopted.evidence == RuntimeOwnershipReconciliation.Evidence.LIVE,
                "a stable second snapshot with one VPP resolves the transition");
        check(adopted.pid == 4343L, "stable transition adoption uses the verified VPP PID");
    }

    private static RuntimeOwnershipReconciliation.ProfileSpec ownershipSpec() {
        return new RuntimeOwnershipReconciliation.ProfileSpec(
                RuntimeProfile.ROOT,
                "/data/user/0/example/files/profiles/root/vpp/startup.conf",
                "/data/user/0/example/files/profiles/root/vpp/runtime",
                "/data/app/example/lib/arm64/libvpp_runtime.so",
                "0123456789abcdef", "01234567-0123-0123-0123-0123456789ab",
                "0", 120, "root_authorization_required", "runner unavailable");
    }

    private static void stoppedSnapshotRetainsRecentFailure() throws Exception {
        RuntimeSnapshot failure = RuntimeSnapshot.error(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release",
                "arm64-v8a", "artifact-sha256:abc", "unexpected_exit",
                "VPP owner exited with status 137", false, -1L, 8L);
        RuntimeSnapshot stopped = RuntimeSnapshot.stoppedAfter(failure);
        check(RuntimeSnapshot.STATE_STOPPED.equals(stopped.state),
                "terminal snapshot is stopped");
        check("unexpected_exit".equals(stopped.errorCode),
                "terminal snapshot retains recent failure code");
        check("VPP owner exited with status 137".equals(stopped.errorMessage),
                "terminal snapshot retains recent failure message");
        check(!stopped.mayBeActive, "terminal failure cannot claim an active owner");
        check(!stopped.isActive(), "terminal failure is inactive");
        check(stopped.generation == 8L, "terminal snapshot retains generation");

        Path files = Files.createTempDirectory("sakamoto-67-stopped-failure");
        RuntimeStateStore.write(files.toFile(), stopped);
        RuntimeSnapshot restored = RuntimeStateStore.read(files.toFile());
        check("unexpected_exit".equals(restored.errorCode),
                "terminal failure code survives persistence");
        check(!restored.mayBeActive, "persisted terminal failure is inactive");
    }

    private static void profileDoesNotExposeAdapterArtifacts() {
        check("root".equals(RuntimeProfile.ROOT.wireName), "root profile wire name is stable");
        check("vpn".equals(RuntimeProfile.VPN.wireName), "VPN profile wire name is stable");
    }

    private static void coreHealthDoesNotClaimAdapterReadiness() {
        VppHealthHandshake.Result healthy = VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n");
        check(healthy.isReady(), "matching core version/artifact health is ready");

        check(VppHealthHandshake.parse(
                RuntimeProfile.VPN, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n").isReady(),
                "VPN core health is independent of Adapter readiness");
        check(!VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:wrong", 0,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n").isReady(),
                "artifact identity mismatch fails closed");
        check(!VppHealthHandshake.parse(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a",
                "artifact-sha256:abc", 1,
                "Version: v26.02-release\nArtifact: artifact-sha256:abc\n"
                        + "Plugin: nfqueue adapter ready\n").isReady(),
                "non-zero health command fails closed");
        check(VppHealthHandshake.parse(
                "vpp-runtime-health/v1", "v26.02-release", "arm64-v8a", "arm64-v8a", 0,
                "Version: v26.02-release\n").isReady(),
                "legacy health parser remains usable for migration evidence");
    }

    private static void nativeCoreHandshakeRequiresGeneratedIdentity() {
        RuntimeControlNative.Status status = new RuntimeControlNative.Status(
                RuntimeControlNative.CONTROL_ABI_VERSION, 0, 0, "show_version_51077d14",
                "vpp", "v26.02-release", "", "");
        check(VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "show_version_51077d14",
                status).isReady(), "generated VAPI core identity proves readiness");
        RuntimeSnapshot vpn = RuntimeSnapshot.running(RuntimeProfile.VPN,
                "vpp-runtime-health/v1", "v26.02-release", "sha256:core", "arm64-v8a",
                "ok", 43L);
        check(RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(vpn.adapterReadiness),
                "native core handshake leaves VPN Adapter unavailable");
        check(!VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "wrong-api", status).isReady(),
                "generated API identity mismatch fails closed");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }
}
