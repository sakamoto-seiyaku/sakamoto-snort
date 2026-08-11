import com.sakamoto.snort.androidruntime.RuntimeControlProtocol;
import com.sakamoto.snort.androidruntime.RuntimeControlRequest;
import com.sakamoto.snort.androidruntime.RuntimeControlOrdering;
import com.sakamoto.snort.androidruntime.RuntimeControlNative;
import com.sakamoto.snort.androidruntime.RuntimeProfile;
import com.sakamoto.snort.androidruntime.RuntimeOwnershipReconciliation;
import com.sakamoto.snort.androidruntime.RuntimeSnapshot;
import com.sakamoto.snort.androidruntime.RuntimeStateStore;
import com.sakamoto.snort.androidruntime.VppHealthHandshake;
import com.sakamoto.snort.androidruntime.ApplicationSubjectId;
import com.sakamoto.snort.androidruntime.ApplicationCatalogEntry;
import com.sakamoto.snort.androidruntime.ApplicationCatalogProvider;
import com.sakamoto.snort.androidruntime.AuthoringPolicyBundle;
import com.sakamoto.snort.androidruntime.ProductStateSnapshot;
import com.sakamoto.snort.androidruntime.ProductStateStore;
import com.sakamoto.snort.androidruntime.ProductStore;
import com.sakamoto.snort.androidruntime.ProductPacketAdapterContract;
import com.sakamoto.snort.androidruntime.BoundedActivityStore;
import com.sakamoto.snort.androidruntime.LocalProductBackend;
import com.sakamoto.snort.androidruntime.ProductCatalogFormatter;
import com.sakamoto.snort.androidruntime.ProductCatalogProjectionStore;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Public-seam tests for the production Android runtime incubator. */
public final class AndroidRuntimeContractTest {
    public static void main(String[] args) throws Exception {
        requestRoundTripIsVersionedAndProfileAware();
        productMutationRequestsAreVersionedServiceRequests();
        lifecycleRequestOrderingRejectsDelayedStarts();
        profileDoesNotExposeAdapterArtifacts();
        productPacketAdapterContractIsExplicit();
        snapshotRoundTripPreservesBoundedHealthAndError();
        runtimeStateWriterCanInjectPersistenceFailure();
        persistenceFailureGateIsFailClosedUntilSafeRecovery();
        durableProjectionReadResultIsExplicit();
        durableOwnershipDecisionFailsClosed();
        globalOwnershipDecisionRequiresOneProjectionConsistentOwner();
        pidlessLiveOwnerIsAdoptable();
        ownershipCleanupDecisionFailsClosed();
        residueOwnershipAuditRetryIsNarrow();
        cleanStopDecisionRequiresGlobalProof();
        ownershipInspectionKeepsIdentityInThePublicSeam();
        pidIdentityUsesPrivilegedProcContext();
        rootProbeUsesPrivilegedContextAndFailsClosed();
        ownershipInspectionBlocksLiveUnreadableEnvironment();
        ownershipScanRechecksProcAfterReadRaces();
        ownershipScanIsValidShell();
        ownershipScanBlocksMatchingIdentityOnMismatchedExecutable();
        ownershipInspectionRejectsSameProfileMultiplicity();
        recordedPidRequiresAnExhaustiveSoleOwnerScan();
        launchShellTransitionFailsClosedUntilStableVpp();
        transientOwnershipAuditRetriesOnlyForActiveRuntime();
        stoppedSnapshotRetainsRecentFailure();
        coreHealthDoesNotClaimAdapterReadiness();
        nativeCoreHandshakeRequiresGeneratedIdentity();
        applicationSubjectIdentityIsCompleteUidOnly();
        productStorePersistsProfileBindingsAndEmptyBundle();
        productStorePersistsNetworkGateMatrixAsTypedRuleFamily();
        boundedActivityStoreIsSeparateFromProductState();
        productCatalogFormatterKeepsUidIdentitySeparateFromMetadata();
        selectableCatalogRowsKeepBindingIdentityOutOfMetadata();
        localProductBackendProjectsCatalogWithoutOwningMetadataIdentity();
        productCatalogProjectionStoreRoundTripsSamePackageTwoProfileRows();
        localProductBackendPublishesDurableProductCatalogProjection();
        backendProjectionInvalidProductStateDisablesBind();
        backendProjectionCatalogErrorRendersActionableStatus();
        corruptProductStateReadResultProjectsVisibleActionableError();
        invalidProductStateProjectionDisablesBindCandidate();
        productStateReloadPreservesLastValidSnapshotUntilValidRead();
        missingProductStateProjectionRemainsNormalEmpty();
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

    private static void productMutationRequestsAreVersionedServiceRequests() {
        RuntimeControlRequest profile = RuntimeControlRequest.decode(
                RuntimeControlRequest.selectProductProfile(RuntimeProfile.VPN,
                        "product-profile-request").encode());
        check(profile.protocolVersion == RuntimeControlProtocol.VERSION,
                "product profile mutation carries the current protocol version");
        check(profile.action == RuntimeControlRequest.Action.PRODUCT_PROFILE_SELECT,
                "product profile mutation has a stable service action");
        check(profile.profile == RuntimeProfile.VPN,
                "product profile mutation preserves the selected profile");
        check(profile.applicationSubjectId == null,
                "product profile mutation does not carry an app binding subject");

        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(1010001);
        RuntimeControlRequest bind = RuntimeControlRequest.decode(
                RuntimeControlRequest.bindProductApplication(subject, "bind-request").encode());
        check(bind.action == RuntimeControlRequest.Action.PRODUCT_BIND_APP,
                "product app bind is a first-class service request");
        check(subject.equals(bind.applicationSubjectId),
                "product app bind preserves the complete UID subject");
        check(bind.profile == null, "product app bind does not carry a runtime profile");

        RuntimeControlRequest unbind = RuntimeControlRequest.decode(
                RuntimeControlRequest.unbindProductApplication(subject,
                        "unbind-request").encode());
        check(unbind.action == RuntimeControlRequest.Action.PRODUCT_UNBIND_APP,
                "product app unbind is a first-class service request");
        check(subject.equals(unbind.applicationSubjectId),
                "product app unbind preserves the complete UID subject");
        check(RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP.equals(
                        RuntimeControlRequest.PRODUCT_BIND_APP),
                "product bind action has a stable protocol name");
        expectIllegalArgument("bind without subject is rejected",
                () -> RuntimeControlRequest.decode(map("protocolVersion",
                        Integer.toString(RuntimeControlProtocol.VERSION),
                        "requestId", "bad-bind",
                        "action", RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP)));
        expectIllegalArgument("bind cannot smuggle a runtime profile",
                () -> RuntimeControlRequest.decode(map("protocolVersion",
                        Integer.toString(RuntimeControlProtocol.VERSION),
                        "requestId", "bad-bind-profile",
                        "action", RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP,
                        "profile", RuntimeProfile.ROOT.wireName,
                        "applicationSubjectId", subject.encode())));
        expectIllegalArgument("product profile select requires profile",
                () -> RuntimeControlRequest.decode(map("protocolVersion",
                        Integer.toString(RuntimeControlProtocol.VERSION),
                        "requestId", "bad-profile",
                        "action", RuntimeControlProtocol.ACTION_PRODUCT_PROFILE_SELECT)));
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
        check(RuntimeSnapshot.ADAPTER_ROOT_NFQUEUE.equals(restored.adapterReadiness),
                "running root adapter readiness round-trips");
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

    private static void runtimeStateWriterCanInjectPersistenceFailure() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-67-runtime-writer");
        RuntimeSnapshot snapshot = RuntimeSnapshot.stopped();
        final boolean[] invoked = {false};
        RuntimeStateStore.Writer writer = (root, value) -> {
            invoked[0] = root.equals(files.toFile()) && value == snapshot;
            throw new IOException("injected persistence failure");
        };
        try {
            writer.write(files.toFile(), snapshot);
            throw new AssertionError("injected writer must fail");
        } catch (IOException expected) {
            check(invoked[0], "writer seam receives the target and snapshot");
        }
    }

    private static void persistenceFailureGateIsFailClosedUntilSafeRecovery() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-67-runtime-persistence-gate");
        RuntimeSnapshot initial = RuntimeSnapshot.stopped();
        final boolean[] failWrites = {true};
        RuntimeStateStore.Writer writer = (root, value) -> {
            if (failWrites[0]) {
                throw new IOException("injected persistence failure");
            }
            RuntimeStateStore.write(root, value);
        };
        RuntimeStateStore.PersistenceGate gate =
                new RuntimeStateStore.PersistenceGate(writer, initial);

        RuntimeStateStore.PersistenceGate.Result prelaunch = gate.publish(
                files.toFile(), RuntimeSnapshot.starting(RuntimeProfile.ROOT,
                        "protocol", "version", "artifact", 1L), false);
        check(!prelaunch.persisted, "pre-launch projection failure is reported");
        check(!prelaunch.launchAllowed, "pre-launch projection failure blocks launch");
        check(!prelaunch.cleanupRequired, "pre-launch failure has no owner to clean");
        check(gate.isPersistenceUnavailable(), "projection failure latches unavailable state");
        check("runtime_state_persistence_unavailable".equals(gate.snapshot().errorCode),
                "projection failure exposes a bounded local error snapshot");

        failWrites[0] = false;
        RuntimeStateStore.PersistenceGate.Result ordinary = gate.publish(
                files.toFile(), RuntimeSnapshot.stopped(RuntimeProfile.ROOT, 1L), false);
        check(ordinary.persisted, "an ordinary write can recover the filesystem boundary");
        check(gate.isPersistenceUnavailable(),
                "ordinary write success does not clear the failure latch");

        RuntimeStateStore.PersistenceGate.Result blockedStart = gate.publish(
                files.toFile(), RuntimeSnapshot.starting(RuntimeProfile.ROOT,
                        "protocol", "version", "artifact", 2L), false);
        check(!blockedStart.launchAllowed,
                "a new START remains blocked while recovery is not explicit");

        failWrites[0] = true;
        RuntimeStateStore.PersistenceGate.Result postlaunch = gate.publish(
                files.toFile(), RuntimeSnapshot.running(RuntimeProfile.ROOT,
                        "protocol", "version", "artifact", "abi", "ok", 77L, 2L), true);
        check(!postlaunch.persisted, "post-launch projection failure is reported");
        check(postlaunch.cleanupRequired,
                "post-launch projection failure requires bounded owner cleanup");
        check(gate.snapshot().mayBeActive,
                "post-launch persistence failure retains active uncertainty");

        RuntimeStateStore.PersistenceGate.Result stop = gate.publish(
                files.toFile(), RuntimeSnapshot.stopping(gate.snapshot()), true);
        check(stop.cleanupAllowed,
                "STOP cleanup remains allowed while persistence is unavailable");

        RuntimeStateStore.PersistenceGate.Result unsafeRecovery = gate.recover(
                files.toFile(), false);
        check(!unsafeRecovery.recovered,
                "recovery cannot clear persistence failure before ownership audit");
        failWrites[0] = false;
        RuntimeStateStore.PersistenceGate.Result recovery = gate.recover(files.toFile(), true);
        check(recovery.recovered, "safe ownership audit plus probe clears the latch");
        check(!gate.isPersistenceUnavailable(), "explicit durable recovery clears the latch");
        check(gate.publish(files.toFile(), RuntimeSnapshot.starting(RuntimeProfile.ROOT,
                "protocol", "version", "artifact", 3L), false).launchAllowed,
                "a later START is allowed after explicit durable recovery");
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

    private static void residueOwnershipAuditRetryIsNarrow() {
        RuntimeOwnershipReconciliation.OwnershipAudit transientAudit =
                RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                        "cleanup_failed",
                        "app-UID /proc ownership scan returned status 120");
        check(RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, transientAudit),
                "post-exit residue cleanup retries a bounded transient ownership scan race");
        check(!RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                        false, transientAudit),
                "unverifiable recorded PID cannot use the transient residue retry");
        check(!RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        true, transientAudit),
                "live process handle blocks the transient residue retry");
        check(!RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, RuntimeOwnershipReconciliation.OwnershipAudit.live(4242L)),
                "live audited owner is never retried as transient residue");
        check(!RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                                "cleanup_failed", "socket residue remains")),
                "ordinary cleanup failures do not enter the transient residue retry");
        check(!RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                                "root_authorization_required",
                                "privileged audit unavailable")),
                "authorization failures remain fail-closed");
    }

    private static void cleanStopDecisionRequiresGlobalProof() {
        RuntimeOwnershipReconciliation.GlobalDecision clean =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        String transientAudit = "profile residue ownership audit failed: "
                + "root /proc ownership scan returned status 120";
        check(RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, clean, false, false, "cleanup_failed", transientAudit),
                "status-120 audit race is clean only after global no-owner proof");
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                        false, clean, false, false, "cleanup_failed", transientAudit),
                "unverifiable PID never qualifies for clean stop");
        check(RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                        false, clean, false, true, "cleanup_failed", transientAudit),
                "successful strong-identity cleanup may clear a stale transient audit");
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.MISMATCH,
                        false, clean, false, true, "cleanup_failed", transientAudit),
                "successful cleanup cannot bless a mismatched identity witness");
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, clean, true, true, "cleanup_failed", transientAudit),
                "residual profile blocks clean stop finalization");
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, clean, false, true, "cleanup_failed", "socket residue remains"),
                "ordinary cleanup failures remain fail-closed");
        RuntimeOwnershipReconciliation.GlobalDecision live =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.live(RuntimeProfile.ROOT, 9L,
                                "owner"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.MISSING,
                        false, live, false, true, "cleanup_failed", transientAudit),
                "global live ownership blocks clean stop finalization");
        RuntimeOwnershipReconciliation.GlobalDecision unknown =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(RuntimeProfile.ROOT,
                                "scanner unavailable"),
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.VPN),
                        RuntimeOwnershipReconciliation.Projection.unknown());
        check(!RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                        RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                        false, unknown, false, true, "cleanup_failed", transientAudit),
                "global ownership uncertainty blocks stale error clearing");
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
                            return new RuntimeOwnershipReconciliation.CommandResult(42, "");
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

        RuntimeOwnershipReconciliation.PidIdentity runconFailure =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) ->
                                new RuntimeOwnershipReconciliation.CommandResult(1, ""));
        check(runconFailure == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN,
                "runcon launcher status 1 is not confused with an absent PID");

        RuntimeOwnershipReconciliation.PidIdentity vanishedDuringIdentity =
                RuntimeOwnershipReconciliation.validatePid(spec, 4242L,
                        (profile, command, timeout) -> {
                            if (command.startsWith("runcon u:r:ksu:s0 sh -c 'if kill -0")) {
                                return new RuntimeOwnershipReconciliation.CommandResult(0, "");
                            }
                            check(command.contains("proc_probe_status=$?"),
                                    "strong PID identity rechecks privileged proc presence after reads");
                            return new RuntimeOwnershipReconciliation.CommandResult(42, "");
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
                    check(command.contains("runcon u:r:ksu:s0 sh -c"),
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
                        "case \"$proc_presence_status\" in 42) : ;; 0|*) uncertain=1 ;; esac"),
                "only the encoded disappearance is ignored; runcon/live failures stay unknown");
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

    private static void ownershipScanIsValidShell() throws Exception {
        assertGeneratedScanSyntax(ownershipSpec(), "root");
        assertGeneratedScanSyntax(new RuntimeOwnershipReconciliation.ProfileSpec(
                RuntimeProfile.VPN,
                "/data/user/0/example/files/profiles/vpn/vpp/startup.conf",
                "/data/user/0/example/files/profiles/vpn/vpp/runtime",
                "/data/app/example/lib/arm64/libvpp_runtime.so",
                "0123456789abcdef", "01234567-0123-0123-0123-0123456789ab",
                "10123", 125, "cleanup_failed", "runner unavailable"), "app-UID");
    }

    private static void assertGeneratedScanSyntax(
            RuntimeOwnershipReconciliation.ProfileSpec spec, String label) throws Exception {
        String command = RuntimeOwnershipReconciliation.buildOwnershipScanCommand(spec);
        Path script = Files.createTempFile("sakamoto-ownership-scan", ".sh");
        try {
            Files.write(script, command.getBytes(StandardCharsets.UTF_8));
            Process syntaxCheck = new ProcessBuilder("sh", "-n", script.toString())
                    .redirectErrorStream(true)
                    .start();
            int status = syntaxCheck.waitFor();
            check(status == 0, "generated " + label + " ownership scan is valid POSIX shell");
        } finally {
            Files.deleteIfExists(script);
        }
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

        RuntimeOwnershipReconciliation.GlobalDecision transientScanFailure =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(
                                RuntimeProfile.VPN, "cleanup_failed",
                                "app-UID /proc ownership scan returned status 120"),
                        RuntimeOwnershipReconciliation.Projection.known(
                                RuntimeProfile.VPN, true, 7981L));
        check(RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(
                        transientScanFailure, true),
                "active runtime retries a bounded transient ownership scan failure");
        check(!RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(
                        transientScanFailure, false),
                "inactive runtime keeps transient ownership scan failure fail-closed");

        RuntimeOwnershipReconciliation.GlobalDecision ordinaryCleanupFailure =
                RuntimeOwnershipReconciliation.decide(
                        RuntimeOwnershipReconciliation.ProfileAudit.none(RuntimeProfile.ROOT),
                        RuntimeOwnershipReconciliation.ProfileAudit.unknown(
                                RuntimeProfile.VPN, "cleanup_failed", "socket residue remains"),
                        RuntimeOwnershipReconciliation.Projection.known(
                                RuntimeProfile.VPN, true, 7981L));
        check(!RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(
                        ordinaryCleanupFailure, true),
                "ordinary cleanup failures never downgrade into an audit retry");

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

    private static void productPacketAdapterContractIsExplicit() {
        ProductPacketAdapterContract root =
                ProductPacketAdapterContract.forProfile(RuntimeProfile.ROOT);
        check(root.productLaunchAllowed,
                "ROOT product Adapter launch is allowed by the Adapter contract");
        check(ProductPacketAdapterContract.ROOT_ADAPTER.equals(root.adapterName),
                "ROOT Adapter name is stable");
        check(ProductPacketAdapterContract.UID_MISS_UNKNOWN_APPLICATION_NO_HOLD
                        .equals(root.uidMissHandling),
                "ROOT UID miss uses Unknown Application without hold/cache/replay");
        check(!root.requiresVpnPlatformSession,
                "ROOT does not require Android VPN platform establishment");

        ProductPacketAdapterContract vpn =
                ProductPacketAdapterContract.forProfile(RuntimeProfile.VPN);
        check(vpn.productLaunchAllowed,
                "VPN product Adapter launch requires explicit TUN fd handoff");
        check(ProductPacketAdapterContract.VPN_ADAPTER.equals(vpn.adapterName),
                "VPN Adapter name is stable");
        check(vpn.platformInterface.contains("VpnService TUN fd"),
                "VPN contract names the platform TUN fd seam");
        check(vpn.separatesTransportOutcome(),
                "VPN contract separates transport outcome from policy verdict");
        check(vpn.requiresVpnPlatformSession && vpn.enableIpv6,
                "VPN contract preflights Android TUN with dual-stack enabled");
        check(ProductPacketAdapterContract.UID_MISS_UNKNOWN_APPLICATION_NO_HOLD
                        .equals(vpn.uidMissHandling),
                "VPN UID miss uses Unknown Application without hold/cache/replay");
        check("vpn_adapter_unavailable".equals(vpn.unavailableErrorCode),
                "VPN adapter unavailable has a stable error code");
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
        check(RuntimeSnapshot.ADAPTER_VPN_TUN_HEV.equals(vpn.adapterReadiness),
                "running VPN snapshot exposes VPN/TUN Adapter readiness");
        check(!VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "wrong-api", status).isReady(),
                "generated API identity mismatch fails closed");
    }

    private static void applicationSubjectIdentityIsCompleteUidOnly() {
        ApplicationSubjectId owner = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId workProfileOwner = ApplicationSubjectId.fromUid(1010001);
        check(owner.userId == 0, "primary user is derived from complete Linux UID");
        check(workProfileOwner.userId == 10, "work profile user is derived from UID");
        check(owner.appId == workProfileOwner.appId,
                "same package appId can exist under different users");
        check(!owner.equals(workProfileOwner),
                "same package across users has distinct ApplicationSubjectId");
        check("android.uid:10001".equals(owner.encode()),
                "subject identity encodes only the Android UID variant");
        check(!owner.encode().contains("com.example"),
                "package metadata is not part of hot-path policy identity");
        check(ApplicationSubjectId.fromUid(1000).appId == 1000,
                "complete Linux UID identity does not discard system package UIDs");
    }

    private static void productStorePersistsProfileBindingsAndEmptyBundle() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-product-store");
        ProductStore store = new ProductStore(files.toFile());
        check(store.snapshot().selectedProfile == RuntimeProfile.ROOT,
                "missing product state defaults to root profile");
        check(store.snapshot().authoringPolicyBundle.isEmpty(),
                "missing product state exposes an empty authoring bundle");

        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        check(store.selectRuntimeProfile(RuntimeProfile.VPN).persisted,
                "selected runtime profile is persisted by backend writer");
        check(store.bindApplication(work).persisted,
                "work-profile application binding is persisted");
        check(store.bindApplication(primary).persisted,
                "primary-user application binding is persisted");

        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.selectedProfile == RuntimeProfile.VPN,
                "selected profile restores after process recreation");
        check(restored.boundApplications.contains(primary)
                        && restored.boundApplications.contains(work),
                "application bindings restore with complete UIDs");
        check(restored.boundApplications.size() == 2,
                "same appId across users remains two bindings");
        check(restored.authoringPolicyBundle.schemaVersion
                        == AuthoringPolicyBundle.SCHEMA_VERSION,
                "authoring bundle schema is persisted");
        check(restored.authoringPolicyBundle.revision == 0L
                        && "".equals(restored.authoringPolicyBundle.source),
                "S50 persists an empty authoring policy revision and source");
        check(restored.authoringPolicyBundle.isEmpty(),
                "S50 persists an empty authoring policy bundle shell");

        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=not-a-number\nselectedProfile=vpn\n"
                        .getBytes(StandardCharsets.US_ASCII));
        ProductStateStore.ReadResult corrupt = ProductStateStore.readResult(files.toFile());
        check(corrupt.present && !corrupt.valid,
                "corrupt product state is reported explicitly");
        check("product_state_corrupt".equals(corrupt.errorCode),
                "corrupt product state returns an actionable product error code");

        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=999\nselectedProfile=vpn\n"
                        .getBytes(StandardCharsets.US_ASCII));
        ProductStateStore.ReadResult unsupported =
                ProductStateStore.readResult(files.toFile());
        check(unsupported.present && !unsupported.valid,
                "unsupported product state schema is reported explicitly");
        check("product_state_unsupported_schema".equals(unsupported.errorCode),
                "unsupported product state schema has a distinct actionable error");
        ProductStore blockedStore = new ProductStore(files.toFile());
        check(!blockedStore.readResult().valid,
                "ProductStore exposes unsupported initial read instead of hiding it");
        check(!blockedStore.selectRuntimeProfile(RuntimeProfile.ROOT).persisted,
                "ProductStore does not overwrite unsupported state as if it were empty");
    }

    private static void productStorePersistsNetworkGateMatrixAsTypedRuleFamily()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-51-gate-matrix");
        ProductStore store = new ProductStore(files.toFile());
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);

        ProductStore.MutationResult blocked = store.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.WIFI, true);
        check(blocked.persisted, "Network Gate mutation persists through ProductStore");
        check(blocked.snapshot.authoringPolicyBundle.revision == 1L,
                "Network Gate mutation publishes a new authoring bundle revision");
        check(blocked.snapshot.authoringPolicyBundle.gateEntryCount == 1,
                "GateMatrix is an independent typed rule family entry count");
        check(blocked.snapshot.authoringPolicyBundle.l4RuleCount == 0
                        && blocked.snapshot.authoringPolicyBundle.protocolRuleCount == 0,
                "GateMatrix mutation does not smuggle L4 or Protocol rules");

        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.authoringPolicyBundle.gateMatrix.size() == 1,
                "GateMatrix entries restore after process recreation");
        AuthoringPolicyBundle.NetworkGateRule rule =
                restored.authoringPolicyBundle.gateMatrix.get(0);
        check(rule.subjectId.equals(app), "GateMatrix stores complete UID subject identity");
        check(rule.networkContext == AuthoringPolicyBundle.NetworkContextId.WIFI,
                "GateMatrix stores typed Wi-Fi network context");
        check(rule.blocked, "GateMatrix stores blocked gate action");
        long stableRuleId = rule.ruleId;
        int stableReasonId = rule.reasonId;

        ProductStore reloaded = new ProductStore(files.toFile());
        ProductStore.MutationResult opened = reloaded.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.WIFI, false);
        check(opened.persisted, "Network Gate open mutation persists");
        check(opened.snapshot.authoringPolicyBundle.revision == 2L,
                "Network Gate open publishes the next revision");
        check(opened.snapshot.authoringPolicyBundle.gateMatrix.size() == 1,
                "same subject/context updates the stable GateMatrix rule instead of duplicating");
        AuthoringPolicyBundle.NetworkGateRule openedRule =
                opened.snapshot.authoringPolicyBundle.gateMatrix.get(0);
        check(!openedRule.blocked, "Network Gate open state restores access intent");
        check(openedRule.ruleId == stableRuleId && openedRule.reasonId == stableReasonId,
                "GateMatrix ruleId and reasonId stay stable across block/open edits");

        ProductStore.MutationResult mobile = reloaded.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.MOBILE, true);
        ProductStore.MutationResult vpn = reloaded.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.VPN, true);
        check(mobile.persisted && vpn.persisted,
                "GateMatrix persists Mobile and VPN network contexts");
        ProductStateSnapshot allContexts = ProductStateStore.read(files.toFile());
        check(allContexts.authoringPolicyBundle.gateMatrix.size() == 3,
                "GateMatrix keeps Wi-Fi, Mobile, and VPN as separate typed contexts");
        check(allContexts.authoringPolicyBundle.gateMatrix.get(0).networkContext
                        == AuthoringPolicyBundle.NetworkContextId.WIFI,
                "GateMatrix stores Wi-Fi context in stable order");
        check(allContexts.authoringPolicyBundle.gateMatrix.get(1).networkContext
                        == AuthoringPolicyBundle.NetworkContextId.MOBILE,
                "GateMatrix stores Mobile context in stable order");
        check(allContexts.authoringPolicyBundle.gateMatrix.get(2).networkContext
                        == AuthoringPolicyBundle.NetworkContextId.VPN,
                "GateMatrix stores VPN context in stable order");

        Files.write(files.resolve("product-state/product.properties"),
                ("schemaVersion=1\nselectedProfile=root\nboundApplications=\n"
                        + "bundle.schemaVersion=1\nbundle.revision=99\n"
                        + "bundle.source=local-product-backend\nbundle.gateEntryCount=2\n"
                        + "bundle.l4RuleCount=0\nbundle.protocolRuleCount=0\n"
                        + "bundle.gateMatrix=1010001:wifi:blocked:1:1;"
                        + "1010001:wifi:open:2:2\n")
                        .getBytes(StandardCharsets.US_ASCII));
        ProductStateStore.ReadResult duplicate = reloaded.reload();
        check(!duplicate.valid,
                "duplicate subject/context GateMatrix entries fail closed on reload");
        check(reloaded.snapshot().authoringPolicyBundle.revision
                        == allContexts.authoringPolicyBundle.revision,
                "invalid GateMatrix reload preserves the last valid ProductStore snapshot");
    }

    private static void boundedActivityStoreIsSeparateFromProductState() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-activity-store");
        ProductStore product = new ProductStore(files.toFile());
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(10001);
        product.bindApplication(app);

        BoundedActivityStore activity = new BoundedActivityStore(2);
        activity.append(new BoundedActivityStore.Record(1L, app, "allow", "default"));
        activity.append(new BoundedActivityStore.Record(2L, app, "drop", "gate"));
        activity.append(new BoundedActivityStore.Record(3L, app, "drop", "l4"));
        check(activity.records().size() == 2, "activity store is bounded");
        check(activity.evictedRecords() == 1L,
                "activity detail eviction is observable and lossy");

        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.boundApplications.contains(app),
                "bounded Activity eviction cannot change policy/config state");
        check(ProductStateStore.stateFile(files.toFile()).getPath().contains("product-state"),
                "policy/config state has its own repository path");
        check(!ProductStateStore.stateFile(files.toFile()).getPath()
                        .contains(BoundedActivityStore.REPOSITORY_DIRECTORY),
                "bounded Activity repository path is not policy/config state");
    }

    private static void productCatalogFormatterKeepsUidIdentitySeparateFromMetadata() {
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        java.util.TreeSet<ApplicationSubjectId> bound = new java.util.TreeSet<>();
        bound.add(work);
        ProductStateSnapshot state = new ProductStateSnapshot(RuntimeProfile.VPN, bound,
                AuthoringPolicyBundle.empty());
        List<ApplicationCatalogEntry> catalog = Arrays.asList(
                new ApplicationCatalogEntry(primary, "com.example.mail", "Mail",
                        "icon:mail/u0", 0, "Owner", true),
                new ApplicationCatalogEntry(work, "com.example.mail", "Mail",
                        "icon:mail/u10", 10, "Work", false));

        ProductCatalogFormatter.Projection loading = ProductCatalogFormatter.loading(state);
        check(loading.displayText.contains("Catalog: loading"),
                "Product UI projection has an explicit catalog loading state");

        ProductCatalogFormatter.Projection projection =
                ProductCatalogFormatter.result(state, catalog);
        check(projection.rows.size() == 2,
                "same package in two Android profiles renders as two product catalog rows");
        check(projection.rows.get(0).packageName.equals(projection.rows.get(1).packageName),
                "catalog rows may share package metadata");
        check(!projection.rows.get(0).subjectId.equals(projection.rows.get(1).subjectId),
                "catalog rows keep distinct ApplicationSubjectId identities");
        check("icon:mail/u0".equals(projection.rows.get(0).iconToken)
                        && "icon:mail/u10".equals(projection.rows.get(1).iconToken),
                "catalog rows preserve distinct provider icon tokens per profile instance");
        check(!projection.rows.get(0).iconToken.equals(projection.rows.get(1).iconToken),
                "same-package profile rows may carry distinct icon metadata");
        check(projection.rows.get(1).fullUid == 1010001,
                "catalog row renders full Linux UID identity");
        check(projection.boundApplicationCount == 1,
                "Product UI projection renders bound application count");
        check(projection.firstBoundSubjectId.equals(work),
                "unbind candidate is the bound ApplicationSubjectId");
        check(projection.firstAvailableSubjectId.equals(primary),
                "bind candidate is the first available ApplicationSubjectId, not packageName");
        ProductCatalogFormatter.Projection nextCandidate =
                ProductCatalogFormatter.result(new ProductStateSnapshot(RuntimeProfile.VPN,
                        new java.util.TreeSet<>(Arrays.asList(primary)),
                        AuthoringPolicyBundle.empty()), catalog);
        check(nextCandidate.firstAvailableSubjectId == null,
                "bind candidate skips already-bound available ApplicationSubjectId");
        check(projection.displayText.contains("Product Store selected profile: VPN (vpn)"),
                "Product UI projection renders selected profile from ProductStore state");
        check(projection.displayText.contains("Catalog: result: 2 application instances"),
                "Product UI projection has an explicit catalog result state");
        check(projection.displayText.contains("full uid 1010001"),
                "Product UI projection displays full UID for profile-specific app rows");
        check(projection.displayText.contains("icon icon:mail/u0")
                        && projection.displayText.contains("icon icon:mail/u10"),
                "Product UI projection displays provider icon identity per catalog row");
        check(!projection.rows.get(0).subjectId.encode().contains("icon:")
                        && !projection.rows.get(1).subjectId.encode().contains("icon:"),
                "ApplicationSubjectId encoding excludes icon metadata");

        ProductCatalogFormatter.Projection error =
                ProductCatalogFormatter.error(state, "catalog_load_failed",
                        "PackageManager unavailable");
        check(error.displayText.contains("Catalog: error catalog_load_failed"),
                "Product UI projection has an explicit catalog error state");
    }

    private static void localProductBackendProjectsCatalogWithoutOwningMetadataIdentity()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-local-backend");
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        ApplicationCatalogProvider provider = () -> Arrays.asList(
                new ApplicationCatalogEntry(primary, "com.example.mail", "Mail",
                        "icon:mail/u0", 0, "Owner", true),
                new ApplicationCatalogEntry(work, "com.example.mail", "Mail",
                        "icon:mail/u10", 10, "Work", true));
        LocalProductBackend backend = new LocalProductBackend(files.toFile(), provider);
        List<ApplicationCatalogEntry> apps = backend.applicationCatalog();
        check(apps.size() == 2, "catalog projects same package in two profiles");
        check(apps.get(0).subjectId.uid != apps.get(1).subjectId.uid,
                "catalog entries carry distinct complete Linux UIDs");
        check(apps.get(0).packageName.equals(apps.get(1).packageName),
                "catalog metadata may share package name");
        check(!apps.get(0).iconToken.equals(apps.get(1).iconToken),
                "catalog metadata may carry distinct icon tokens for each profile instance");
        check(!apps.get(1).subjectId.encode().contains(apps.get(1).iconToken),
                "catalog icon token is not part of binding identity");
        check(backend.bindApplication(apps.get(1).subjectId).persisted,
                "Local Product Backend writes selected app binding");
        check(backend.productState().boundApplications.contains(work),
                "backend product state uses ApplicationSubjectId, not package metadata");
    }

    private static void productCatalogProjectionStoreRoundTripsSamePackageTwoProfileRows()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-product-projection");
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.result(
                new ProductStateSnapshot(RuntimeProfile.VPN,
                        new java.util.TreeSet<>(Arrays.asList(work)),
                        AuthoringPolicyBundle.empty()),
                Arrays.asList(
                        new ApplicationCatalogEntry(primary, "com.example.mail", "Mail",
                                "icon:mail/u0", 0, "Owner", true),
                        new ApplicationCatalogEntry(work, "com.example.mail", "Mail",
                                "icon:mail/u10", 10, "Work", true)));

        ProductCatalogProjectionStore.write(files.toFile(), projection);
        ProductCatalogProjectionStore.ReadResult restored =
                ProductCatalogProjectionStore.readResult(files.toFile());

        check(restored.present && restored.valid,
                "product catalog projection store exposes a valid durable read result");
        check(restored.projection.selectedProfile == RuntimeProfile.VPN,
                "projection store round-trips the selected profile display state");
        check(restored.projection.selectableRows.size() == 2,
                "projection store round-trips same-package two-profile selector rows");
        check(restored.projection.selectableRows.get(0).packageName
                        .equals(restored.projection.selectableRows.get(1).packageName),
                "projection rows may share package metadata after durable handoff");
        check(!restored.projection.selectableRows.get(0).subjectId.equals(
                        restored.projection.selectableRows.get(1).subjectId),
                "projection handoff preserves distinct complete-UID identities");
        check("icon:mail/u0".equals(restored.projection.selectableRows.get(0).iconToken)
                        && "icon:mail/u10".equals(
                                restored.projection.selectableRows.get(1).iconToken),
                "projection handoff preserves per-profile icon tokens");
        check(restored.projection.selectableRows.get(0).canBind(),
                "projection handoff preserves bind-enabled selected row");
        check(restored.projection.selectableRows.get(1).canUnbind(),
                "projection handoff preserves unbind-enabled selected row");
        check(ProductCatalogProjectionStore.projectionFile(files.toFile()).getPath()
                        .contains("product-catalog-projection"),
                "product catalog projection uses its own UI/evidence repository path");
        check(!ProductCatalogProjectionStore.projectionFile(files.toFile()).getPath()
                        .contains("product-state"),
                "product catalog projection store is separate from policy/config state");
    }

    private static void localProductBackendPublishesDurableProductCatalogProjection()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-backend-projection");
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(
                        new ApplicationCatalogEntry(primary, "com.example.mail", "Mail",
                                "icon:mail/u0", 0, "Owner", true),
                        new ApplicationCatalogEntry(work, "com.example.mail", "Mail",
                                "icon:mail/u10", 10, "Work", true)));

        check(backend.selectRuntimeProfile(RuntimeProfile.VPN).persisted,
                "backend writes selected profile before publishing projection");
        check(backend.bindApplication(work).persisted,
                "backend writes selected binding before publishing projection");
        ProductCatalogFormatter.Projection projection =
                ProductCatalogProjectionStore.read(files.toFile());

        check(projection.selectedProfile == RuntimeProfile.VPN,
                "backend-published projection reflects ProductStore selected profile");
        check(projection.boundApplicationCount == 1,
                "backend-published projection reflects ProductStore bound count");
        check(projection.firstAvailableSubjectId.equals(primary),
                "backend-published projection computes bind candidate");
        check(projection.firstBoundSubjectId.equals(work),
                "backend-published projection computes unbind candidate");
        check(projection.displayText.contains("Catalog: result: 2 application instances"),
                "backend-published projection renders catalog result text");
    }

    private static void backendProjectionInvalidProductStateDisablesBind()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-invalid-backend-projection");
        Files.createDirectories(files.resolve("product-state"));
        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=not-a-number\nselectedProfile=vpn\n"
                        .getBytes(StandardCharsets.US_ASCII));
        ApplicationSubjectId available = ApplicationSubjectId.fromUid(10001);
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(available,
                        "com.example.mail", "Mail", "icon:mail/u0",
                        0, "Owner", true)));

        ProductCatalogFormatter.Projection projection =
                backend.refreshProductCatalogProjection();
        ProductCatalogFormatter.Projection restored =
                ProductCatalogProjectionStore.read(files.toFile());

        check("invalid".equals(projection.productStateStatus),
                "backend projection reports invalid ProductStore state");
        check("product_state_corrupt".equals(restored.productStateErrorCode),
                "durable backend projection preserves actionable product-state error");
        check(restored.selectableRows.size() == 1,
                "invalid product-state projection still shows catalog evidence rows");
        check(!restored.selectableRows.get(0).canBind(),
                "invalid product-state disables bind in the durable projection");
        check(restored.firstAvailableSubjectId == null,
                "invalid product-state removes the durable bind candidate");
        check(restored.displayText.contains("Product Store state: invalid product_state_corrupt"),
                "durable projection renders invalid product-state status");
    }

    private static void backendProjectionCatalogErrorRendersActionableStatus()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-catalog-error-projection");
        LocalProductBackend backend = new LocalProductBackend(files.toFile(), () -> {
            throw new RuntimeException("PackageManager unavailable");
        });

        ProductCatalogFormatter.Projection projection =
                backend.refreshProductCatalogProjection();
        ProductCatalogFormatter.Projection restored =
                ProductCatalogProjectionStore.read(files.toFile());

        check("error".equals(projection.catalogStatus),
                "backend projection reports catalog provider errors");
        check("catalog_load_failed".equals(restored.errorCode),
                "durable projection preserves actionable catalog error code");
        check(restored.selectableRows.isEmpty(),
                "catalog error projection has no bindable selector rows");
        check(restored.firstAvailableSubjectId == null,
                "catalog error projection disables bind candidate");
        check(restored.displayText.contains("Catalog: error catalog_load_failed"),
                "durable projection renders actionable catalog error status");
    }

    private static void selectableCatalogRowsKeepBindingIdentityOutOfMetadata() {
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        List<ApplicationCatalogEntry> catalog = Arrays.asList(
                new ApplicationCatalogEntry(primary, "com.example.mail", "Mail",
                        "icon:shared-mail", 0, "Owner", true),
                new ApplicationCatalogEntry(work, "com.example.mail", "Mail",
                        "icon:shared-mail", 10, "Work", true));
        ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.project(
                new ProductStateSnapshot(RuntimeProfile.ROOT,
                        new java.util.TreeSet<>(Arrays.asList(work)),
                        AuthoringPolicyBundle.empty()),
                catalog, "result", "", "", 1);

        check(projection.rows.size() == 1,
                "text preview may stay capped for debug readability");
        check(projection.selectableRows.size() == 2,
                "selector exposes every projected catalog app instance");
        check(projection.selectableRows.get(0).subjectId.equals(primary)
                        && projection.selectableRows.get(1).subjectId.equals(work),
                "selector preserves distinct complete-Linux-UID subjects");
        check(projection.selectableRows.get(0).packageName
                        .equals(projection.selectableRows.get(1).packageName),
                "selector rows can share package metadata without merging identity");
        check(projection.selectableRows.get(0).iconToken
                        .equals(projection.selectableRows.get(1).iconToken),
                "selector rows can share icon metadata without merging identity");
        check(projection.selectableRows.get(0).canBind(),
                "unbound selected available row is bindable");
        check(projection.selectableRows.get(1).canUnbind(),
                "bound selected row is unbindable");
        check(RuntimeControlRequest.bindProductApplication(
                        projection.selectableRows.get(0).subjectId)
                        .applicationSubjectId.equals(primary),
                "bind request carries the selected row ApplicationSubjectId");
        check(RuntimeControlRequest.unbindProductApplication(
                        projection.selectableRows.get(1).subjectId)
                        .applicationSubjectId.equals(work),
                "unbind request carries the selected row ApplicationSubjectId");
        check(!RuntimeControlRequest.bindProductApplication(
                        projection.selectableRows.get(0).subjectId)
                        .applicationSubjectId.encode().contains("icon:"),
                "selected bind identity excludes icon metadata");
    }

    private static void corruptProductStateReadResultProjectsVisibleActionableError()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-corrupt-projection");
        Files.createDirectories(files.resolve("product-state"));
        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=not-a-number\nselectedProfile=vpn\n"
                        .getBytes(StandardCharsets.US_ASCII));

        ProductStateStore.ReadResult corrupt = ProductStateStore.readResult(files.toFile());
        ProductCatalogFormatter.Projection projection =
                ProductCatalogFormatter.result(corrupt, Arrays.asList(
                        new ApplicationCatalogEntry(ApplicationSubjectId.fromUid(10001),
                                "com.example.mail", "Mail", "icon:mail/u0",
                                0, "Owner", true)));

        check("invalid".equals(projection.productStateStatus),
                "corrupt product-state projects as invalid instead of empty valid state");
        check("product_state_corrupt".equals(projection.productStateErrorCode),
                "corrupt product-state projection exposes an actionable error code");
        check(projection.displayText.contains("Product Store state: invalid product_state_corrupt"),
                "corrupt product-state projection renders a visible invalid status");
        check(projection.displayText.contains("product state could not be read"),
                "corrupt product-state projection renders an actionable error message");
    }

    private static void invalidProductStateProjectionDisablesBindCandidate()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-invalid-candidate");
        Files.createDirectories(files.resolve("product-state"));
        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=999\nselectedProfile=vpn\n"
                        .getBytes(StandardCharsets.US_ASCII));
        ApplicationSubjectId available = ApplicationSubjectId.fromUid(10001);
        ProductCatalogFormatter.Projection projection =
                ProductCatalogFormatter.result(ProductStateStore.readResult(files.toFile()),
                        Arrays.asList(new ApplicationCatalogEntry(available,
                                "com.example.mail", "Mail", "icon:mail/u0",
                                0, "Owner", true)));

        check("invalid".equals(projection.productStateStatus),
                "unsupported product-state projects as invalid");
        check(projection.firstAvailableSubjectId == null,
                "invalid product-state disables the bind candidate");
        check(projection.firstBoundSubjectId == null,
                "invalid product-state disables the unbind candidate");
        check(!projection.selectableRows.get(0).canBind(),
                "invalid product-state disables selected-row bind action");
        check(!projection.selectableRows.get(0).canUnbind(),
                "invalid product-state disables selected-row unbind action");
        check(projection.displayText.contains("product_state_unsupported_schema"),
                "invalid product-state keeps the actionable schema error visible");
    }

    private static void productStateReloadPreservesLastValidSnapshotUntilValidRead()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-reload");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app, "com.example.mail",
                        "Mail", "icon:mail/u10", 10, "Work", true)));
        check(backend.selectRuntimeProfile(RuntimeProfile.VPN).persisted,
                "backend persists an initial valid profile");
        check(backend.bindApplication(app).persisted,
                "backend persists an initial valid binding");

        Files.write(files.resolve("product-state/product.properties"),
                "schemaVersion=not-a-number\nselectedProfile=root\n"
                        .getBytes(StandardCharsets.US_ASCII));
        ProductStateStore.ReadResult corrupt = backend.reloadProductState();
        check(!corrupt.valid, "reload reports an invalid product-state read");
        check(corrupt.snapshot.selectedProfile == RuntimeProfile.VPN,
                "invalid reload read result carries the last valid profile snapshot");
        check(corrupt.snapshot.boundApplications.contains(app),
                "invalid reload read result carries the last valid binding snapshot");
        check(backend.productState().selectedProfile == RuntimeProfile.VPN,
                "reload preserves the last valid profile snapshot after an invalid read");
        check(backend.productState().boundApplications.contains(app),
                "reload preserves the last valid binding snapshot after an invalid read");
        check(!backend.selectRuntimeProfile(RuntimeProfile.ROOT).persisted,
                "invalid reload gates mutations until a valid read recovers");

        ProductStateStore.write(files.toFile(), ProductStateSnapshot.empty());
        ProductStateStore.ReadResult recovered = backend.reloadProductState();
        check(recovered.valid && recovered.present,
                "reload accepts a later valid product-state read");
        check(backend.productState().selectedProfile == RuntimeProfile.ROOT
                        && backend.productState().boundApplications.isEmpty(),
                "valid reload replaces the preserved snapshot");
    }

    private static void missingProductStateProjectionRemainsNormalEmpty() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-missing-projection");
        ApplicationSubjectId available = ApplicationSubjectId.fromUid(10001);
        ProductStateStore.ReadResult missing = ProductStateStore.readResult(files.toFile());
        ProductCatalogFormatter.Projection projection =
                ProductCatalogFormatter.result(missing, Arrays.asList(
                        new ApplicationCatalogEntry(available, "com.example.mail",
                                "Mail", "icon:mail/u0", 0, "Owner", true)));

        check(!missing.present && missing.valid,
                "missing product-state is a valid empty read result");
        check("missing".equals(projection.productStateStatus),
                "missing product-state projects a distinct missing status");
        check(projection.productStateErrorCode.isEmpty()
                        && projection.productStateErrorMessage.isEmpty(),
                "missing product-state does not project an error");
        check(projection.boundApplicationCount == 0,
                "missing product-state remains a normal empty Product Store state");
        check(projection.firstAvailableSubjectId.equals(available),
                "missing product-state still allows binding an available app");
        check(projection.selectableRows.get(0).canBind(),
                "missing product-state still allows selected-row bind action");
        check(projection.displayText.contains("Catalog: result: 1 application instance"),
                "missing product-state still renders the catalog result normally");
    }

    private static void check(boolean condition, String message) {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    private static void expectIllegalArgument(String message, ThrowingRunnable action) {
        try {
            action.run();
            throw new AssertionError(message);
        } catch (IllegalArgumentException expected) {
            // Expected fail-closed validation.
        } catch (Exception error) {
            throw new AssertionError(message + ": " + error);
        }
    }

    private static Map<String, String> map(String... values) {
        if (values.length % 2 != 0) {
            throw new IllegalArgumentException("map helper requires key/value pairs");
        }
        Map<String, String> out = new LinkedHashMap<>();
        for (int i = 0; i < values.length; i += 2) {
            out.put(values[i], values[i + 1]);
        }
        return out;
    }

    private interface ThrowingRunnable {
        void run() throws Exception;
    }
}
