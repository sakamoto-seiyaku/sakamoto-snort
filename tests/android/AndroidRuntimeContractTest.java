import com.sakamoto.snort.androidruntime.RuntimeControlProtocol;
import com.sakamoto.snort.androidruntime.RuntimeControlRequest;
import com.sakamoto.snort.androidruntime.RuntimeControlOrdering;
import com.sakamoto.snort.androidruntime.RuntimeControlNative;
import com.sakamoto.snort.androidruntime.RuntimeProfile;
import com.sakamoto.snort.androidruntime.RuntimeProfileInitializationPlan;
import com.sakamoto.snort.androidruntime.RuntimeRecoveryPolicy;
import com.sakamoto.snort.androidruntime.RuntimeOwnershipReconciliation;
import com.sakamoto.snort.androidruntime.RuntimeSnapshot;
import com.sakamoto.snort.androidruntime.RuntimeStateStore;
import com.sakamoto.snort.androidruntime.VppHealthHandshake;
import com.sakamoto.snort.androidruntime.ApplicationSubjectId;
import com.sakamoto.snort.androidruntime.ApplicationProtocolCatalog;
import com.sakamoto.snort.androidruntime.ApplicationCatalogEntry;
import com.sakamoto.snort.androidruntime.ApplicationCatalogProvider;
import com.sakamoto.snort.androidruntime.ActivityL4RuleDraft;
import com.sakamoto.snort.androidruntime.AuthoringPolicyBundle;
import com.sakamoto.snort.androidruntime.AuthoringPolicyCompiler;
import com.sakamoto.snort.androidruntime.ProductStateSnapshot;
import com.sakamoto.snort.androidruntime.ProductStateStore;
import com.sakamoto.snort.androidruntime.ProductStore;
import com.sakamoto.snort.androidruntime.ProductPacketAdapterContract;
import com.sakamoto.snort.androidruntime.ProductCoreLifecycle;
import com.sakamoto.snort.androidruntime.ProductCoreOwner;
import com.sakamoto.snort.androidruntime.BoundedActivityStore;
import com.sakamoto.snort.androidruntime.LocalProductBackend;
import com.sakamoto.snort.androidruntime.ProductCatalogFormatter;
import com.sakamoto.snort.androidruntime.ProductCatalogProjectionStore;
import com.sakamoto.snort.androidruntime.ProductActivityProjectionStore;
import com.sakamoto.snort.androidruntime.ProductNativeActivityIngestor;
import com.sakamoto.snort.androidruntime.ProductPolicyTransactions;
import com.sakamoto.snort.androidruntime.ProductPolicyTransactionStore;
import com.sakamoto.snort.androidruntime.CapabilitySet;
import com.sakamoto.snort.androidruntime.HealthIssue;
import com.sakamoto.snort.androidruntime.RuntimeSummary;
import com.sakamoto.snort.androidruntime.AppSummary;
import com.sakamoto.snort.androidruntime.AppDetail;
import com.sakamoto.snort.androidruntime.ReleaseDiagnosticsExport;
import com.sakamoto.snort.androidruntime.RuleDraft;
import com.sakamoto.snort.androidruntime.RuleView;
import com.sakamoto.snort.androidruntime.ActivityItem;
import com.sakamoto.snort.androidruntime.ProtocolRecognitionSequence;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.charset.StandardCharsets;
import java.io.IOException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Public-seam tests for the production Android runtime incubator. */
public final class AndroidRuntimeContractTest {
    public static void main(String[] args) throws Exception {
        requestRoundTripIsVersionedAndProfileAware();
        productMutationRequestsAreVersionedServiceRequests();
        lifecycleRequestOrderingRejectsDelayedStarts();
        runtimeProfileInitializationPlanIsExplicitAndRecoverable();
        profileDoesNotExposeAdapterArtifacts();
        productPacketAdapterContractIsExplicit();
        snapshotRoundTripPreservesBoundedHealthAndError();
        runtimeRecoveryPolicyIsBoundedAndActionable();
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
        productCoreNativeStatusFieldOrderIsStable();
        productCoreLifecycleRequiresTheExactLiveGeneration();
        productCoreIdentityValidatorFailsClosed();
        productCoreNativeFailureCodesRemainVisible();
        productCoreFailureRetryPolicyIsNarrow();
        productCoreOwnerDecisionIsFailClosed();
        applicationSubjectIdentityIsCompleteUidOnly();
        applicationProtocolCatalogOwnsStablePolicyIdentity();
        productStorePersistsProfileBindingsAndEmptyBundle();
        productStorePersistsNetworkGateMatrixAsTypedRuleFamily();
        productStorePersistsL4RuleListAsTypedRuleFamily();
        gateMatrixCompilesToPacketPolicyApplyPayload();
        l4RuleListCompilesToPacketPolicyApplyPayload();
        localProductBackendAppliesGatePolicyBeforePersistingBundle();
        localProductBackendAppliesL4PolicyBeforePersistingBundle();
        localProductBackendPersistsPolicyTransactionsAroundProductState();
        localProductBackendExposesPolicyImportExportAndRestore();
        boundedActivityStoreIsSeparateFromProductState();
        localProductBackendOwnsBoundedActivityStoreWriter();
        productActivityProjectionStoreRoundTripsAppDetail();
        productActivityProjectionStoresProtocolRecognitionState();
        productNativeActivityIngestorMapsRuntimeDropEvidence();
        activityL4RuleDraftPrefillsFromPolicyDropEvidence();
        productCatalogFormatterKeepsUidIdentitySeparateFromMetadata();
        selectableCatalogRowsKeepBindingIdentityOutOfMetadata();
        localProductBackendProjectsCatalogWithoutOwningMetadataIdentity();
        localProductBackendAppliesGateMatrixBeforePersistingProductState();
        productCatalogProjectionStoreRoundTripsSamePackageTwoProfileRows();
        localProductBackendPublishesDurableProductCatalogProjection();
        backendProjectionInvalidProductStateDisablesBind();
        backendProjectionCatalogErrorRendersActionableStatus();
        corruptProductStateReadResultProjectsVisibleActionableError();
        invalidProductStateProjectionDisablesBindCandidate();
        productStateReloadPreservesLastValidSnapshotUntilValidRead();
        missingProductStateProjectionRemainsNormalEmpty();
        productPolicyTransactionsSeparateDraftCommitApplyAndCheckpoint();
        productPolicyTransactionRestoreAndImportExportAreAtomic();
        productPolicyTransactionStorePersistsDraftCommitRuntimeAndCheckpoints();
        productPolicyCommitValidationRejectsConflictsAndStaleBindings();
        releaseDiagnosticsExportIsDesensitizedAndFeedbackReady();
        appFirstProductUiModelsExposeStableUserFacingSeams();
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
        RuntimeControlRequest pause = RuntimeControlRequest.decode(
                RuntimeControlRequest.pauseProtection("pause-request").encode());
        check(pause.action == RuntimeControlRequest.Action.PROTECTION_PAUSE
                        && RuntimeControlRequest.PROTECTION_PAUSE.equals(
                        pause.encode().get("action")),
                "Protection Pause is a stable explicit user action");
        RuntimeControlRequest resume = RuntimeControlRequest.decode(
                RuntimeControlRequest.resumeProtection("resume-request").encode());
        check(resume.action == RuntimeControlRequest.Action.PROTECTION_RESUME
                        && resume.profile == null,
                "Protection Resume restarts the retained selected profile");
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
        RuntimeControlRequest gate = RuntimeControlRequest.decode(
                RuntimeControlRequest.setNetworkGate(subject,
                        AuthoringPolicyBundle.NetworkContextId.MOBILE,
                        true, "gate-request").encode());
        check(gate.action == RuntimeControlRequest.Action.PRODUCT_SET_NETWORK_GATE,
                "product Network Gate mutation is a first-class service request");
        check(subject.equals(gate.applicationSubjectId),
                "product Network Gate mutation preserves the complete UID subject");
        check(gate.networkContext == AuthoringPolicyBundle.NetworkContextId.MOBILE,
                "product Network Gate mutation preserves typed NetworkContextId");
        check(gate.networkGateBlocked,
                "product Network Gate mutation preserves blocked/open action");
        check(gate.profile == null,
                "product Network Gate mutation does not carry a runtime profile");
        check(RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP.equals(
                        RuntimeControlRequest.PRODUCT_BIND_APP),
                "product bind action has a stable protocol name");
        check(RuntimeControlProtocol.ACTION_PRODUCT_SET_NETWORK_GATE.equals(
                        RuntimeControlRequest.PRODUCT_SET_NETWORK_GATE),
                "product Network Gate action has a stable protocol name");
        check("product_set_l4_rule".equals(RuntimeControlProtocol.ACTION_PRODUCT_SET_L4_RULE),
                "product L4 rule action has a stable protocol name");
        check("l4DestinationCidr".equals(RuntimeControlProtocol.EXTRA_L4_DESTINATION_CIDR),
                "product L4 rule destination CIDR extra has a stable protocol name");
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
        expectIllegalArgument("Network Gate without context is rejected",
                () -> RuntimeControlRequest.decode(map("protocolVersion",
                        Integer.toString(RuntimeControlProtocol.VERSION),
                        "requestId", "bad-gate",
                        "action", RuntimeControlProtocol.ACTION_PRODUCT_SET_NETWORK_GATE,
                        "applicationSubjectId", subject.encode())));
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

    private static void runtimeProfileInitializationPlanIsExplicitAndRecoverable() {
        RuntimeProfileInitializationPlan.Inputs initial =
                new RuntimeProfileInitializationPlan.Inputs(
                        true, false, true, false, false, false, null);
        RuntimeProfileInitializationPlan first =
                RuntimeProfileInitializationPlan.from(initial);
        check(first.recommendedProfile == RuntimeProfile.ROOT,
                "Root capability is recommended when present");
        check(first.currentStep
                        == RuntimeProfileInitializationPlan.Step.PROFILE_CONFIRMATION,
                "recommendation still requires explicit profile confirmation");
        check(first.requiresUserConfirmation,
                "recommended profile is not silently selected");
        check(!first.shouldAutoAuthorize && !first.shouldAutoStart
                        && !first.shouldAutoSwitchProfile,
                "initialization plan never grants permissions, starts, or switches runtime");
        check(first.impact.contains("Authoring Policy Bundle"),
                "profile confirmation explains policy preservation");

        RuntimeProfileInitializationPlan notification =
                RuntimeProfileInitializationPlan.from(initial.withSelectedProfile(
                        RuntimeProfile.ROOT));
        check(notification.currentStep
                        == RuntimeProfileInitializationPlan.Step.VISIBLE_NOTIFICATION,
                "visible notification is a gate before profile authorization and launch");

        RuntimeProfileInitializationPlan authorization =
                RuntimeProfileInitializationPlan.from(initial
                        .withSelectedProfile(RuntimeProfile.ROOT)
                        .withNotificationReady(true));
        check(authorization.currentStep
                        == RuntimeProfileInitializationPlan.Step.PROFILE_AUTHORIZATION,
                "Root authorization is a distinct current step");
        check(authorization.currentAction.contains("KernelSU"),
                "Root authorization action is concrete");

        RuntimeProfileInitializationPlan readiness =
                RuntimeProfileInitializationPlan.from(initial
                        .withSelectedProfile(RuntimeProfile.ROOT)
                        .withNotificationReady(true)
                        .withAuthorization(true, false));
        check(readiness.currentStep
                        == RuntimeProfileInitializationPlan.Step.RUNTIME_READINESS,
                "runtime readiness is verified after notification and authorization");
        check(readiness.impact.contains("IPv4/IPv6"),
                "readiness step covers dual-stack packet runtime");

        RuntimeProfileInitializationPlan ready =
                RuntimeProfileInitializationPlan.from(initial
                        .withSelectedProfile(RuntimeProfile.ROOT)
                        .withNotificationReady(true)
                        .withAuthorization(true, false)
                        .withRuntimeReady(true));
        check(ready.currentStep == RuntimeProfileInitializationPlan.Step.READY,
                "successful readiness completes initialization");

        RuntimeProfileInitializationPlan vpnFallback =
                RuntimeProfileInitializationPlan.from(new RuntimeProfileInitializationPlan.Inputs(
                        false, false, true, false, false, false, null));
        check(vpnFallback.recommendedProfile == RuntimeProfile.VPN,
                "VPN is recommended when Root capability is unavailable");
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

        RuntimeSnapshot product = RuntimeSnapshot.runningProduct(
                RuntimeProfile.ROOT, "vpp-runtime-health/v1", "v26.02-release",
                "artifact-sha256:def", "arm64-v8a",
                RuntimeSnapshot.ADAPTER_ROOT_NFQUEUE, true, 43L, 8L);
        RuntimeStateStore.write(files.toFile(), product);
        RuntimeSnapshot restoredProduct = RuntimeStateStore.read(files.toFile());
        check(restoredProduct.protectionRunning,
                "product protection running state round-trips");
        check(RuntimeSnapshot.ADAPTER_ROOT_NFQUEUE.equals(restoredProduct.adapterReadiness),
                "product adapter readiness round-trips without inference");

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

        RuntimeSnapshot paused = RuntimeSnapshot.paused(RuntimeProfile.ROOT, 7L);
        RuntimeStateStore.write(files.toFile(), paused);
        RuntimeSnapshot restoredPaused = RuntimeStateStore.read(files.toFile());
        check(RuntimeSnapshot.STATE_STOPPED.equals(restoredPaused.state)
                        && RuntimeSnapshot.ERROR_USER_PAUSE.equals(restoredPaused.errorCode)
                        && !restoredPaused.mayBeActive,
                "user pause is distinguishable from ordinary runtime down");
        check(restoredPaused.displayText().contains("paused by user"),
                "user pause renders as product status instead of runtime failure");
    }

    private static void runtimeRecoveryPolicyIsBoundedAndActionable() {
        RuntimeRecoveryPolicy policy = new RuntimeRecoveryPolicy();
        RuntimeRecoveryPolicy.Decision first =
                policy.afterFailure(0, "unexpected_exit");
        check(first.shouldRestart && first.attempt == 1 && first.backoffMillis == 1000L,
                "automatic recovery first retry uses fixed bounded backoff");
        RuntimeRecoveryPolicy.Decision third =
                policy.afterFailure(2, "health_handshake_failed");
        check(third.shouldRestart && third.attempt == 3 && third.backoffMillis == 15000L,
                "automatic recovery caps retry attempts with fixed final backoff");
        RuntimeRecoveryPolicy.Decision exhausted =
                policy.afterFailure(3, "runtime_start_failed");
        check(!exhausted.shouldRestart && exhausted.requiresUserIntervention
                        && "runtime_recovery_intervention_required".equals(
                        exhausted.statusCode),
                "repeated runtime failures stop automatic restart and request intervention");
        check(!policy.recoverable("root_authorization_required"),
                "permission failures are surfaced to the user instead of auto-restarted");
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
        check(RuntimeSnapshot.ADAPTER_VPN_TUN_FD_COMPAT.equals(vpn.adapterReadiness),
                "running VPN snapshot exposes VPN/TUN fd compatibility Adapter readiness");
        check(!VppHealthHandshake.evaluate(RuntimeProfile.ROOT, "vpp-runtime-health/v1",
                "v26.02-release", "arm64-v8a", "sha256:core", "wrong-api", status).isReady(),
                "generated API identity mismatch fails closed");
    }

    private static void productCoreNativeStatusFieldOrderIsStable() throws Exception {
        String[] nativeValues = {
                "7", "41", "1", "0", "1", "1", "1", "0",
                "artifact-41", "product_core.api/1.0.0@abcd1234", "v26.02-release",
                "query failed", "2", "3", "176", "177", "2", "3", "44",
                "5", "5", "5", "2", "3", "2", "3", "4", "5", "6", "7",
                "8", "9", "10", "11", "6", "17", "1", "0",
                "4294967295", "177", "99", "12", "13", "14", "15", "16",
                "17", "18", "19", "20", "21", "22", "23", "24", "25",
                "26", "27", "28", "29", "30", "31", "32", "33",
                "2", "7", "8032009842424885559", "32", "2", "0", "1", "1",
                "2", "2", "1", "1", "1", "34", "35", "36"
                , "88", "88", "41", "18446744073709551600", "88", "88",
                "0", "1", "1", "0", "0", "0", "1", "1",
                "network-gate/v1/revision-88/uid-1010001/context-1/blocked",
                "1010001", "1", "1", "136000017", "5836665117071779841",
                "3", "88", "5836665117071779841", "1", "1010001", "1",
                "136000017", "2", "1", "1", "3",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0"
        };
        Method parser = RuntimeControlNative.class.getDeclaredMethod(
                "parseStatus", String[].class, int.class);
        parser.setAccessible(true);
        RuntimeControlNative.Status status = (RuntimeControlNative.Status) parser.invoke(
                null, (Object) nativeValues, 0);
        check(status.code == 7, "native status code stays in the code field");
        check(status.abiVersion == 2, "native ABI version stays in the ABI field");
        check(status.apiVersion == 3, "native API version stays in the API field");
        check(status.generation == 41L, "native generation stays in the generation field");
        check(status.coreReady && !status.adapterAvailable,
                "native readiness flags preserve their order");
        check(status.pluginLoaded && status.vapiHandleLive && !status.generationLive,
                "native session flags preserve their order");
        check("artifact-41".equals(status.artifactId),
                "native artifact identity stays in the artifact field");
        check("product_core.api/1.0.0@abcd1234".equals(status.apiIdentity),
                "native API identity stays in the API identity field");
        check("v26.02-release".equals(status.vppRevision),
                "native VPP revision stays in the revision field");
        check("query failed".equals(status.errorDetail),
                "native error detail stays in the error field");
        check(status.rootNfqueueQueueId == 176,
                "native Root NFQUEUE queue id stays in the queue field");
        check(status.rootNfqueueQueueLast == 177
                        && status.rootNfqueueLaneCount == 2
                        && status.rootNfqueueReadyLaneMask == 3,
                "native Root NFQUEUE lane summary preserves its order");
        check(status.rootNfqueueGeneration == 44L,
                "native Root NFQUEUE generation stays in the generation field");
        check(status.rootNfqueueVerdictAttempts == 5L
                        && status.rootNfqueueInternalSettlements == 5L
                        && status.rootNfqueueBufferReturns == 5L
                        && status.rootNfqueueOriginLocalCompletions == 2L
                        && status.rootNfqueueOriginRemoteCompletions == 3L
                        && status.rootNfqueueLane0VerdictAttempts == 2L
                        && status.rootNfqueueLane1VerdictAttempts == 3L,
                "native Root NFQUEUE counters preserve their order");
        check(status.rootNfqueueInputPackets == 4L
                        && status.rootNfqueueOutputPackets == 5L
                        && status.rootNfqueueIpv4Packets == 6L
                        && status.rootNfqueueIpv6Packets == 7L
                        && status.rootNfqueueTcpPackets == 8L
                        && status.rootNfqueueUdpPackets == 9L
                        && status.rootNfqueueUidKnownPackets == 10L
                        && status.rootNfqueueUidUnknownPackets == 11L,
                "native Root NFQUEUE S178 aggregate counters preserve their order");
        check(status.rootNfqueueLastIpFamily == 6
                        && status.rootNfqueueLastProtocol == 17
                        && status.rootNfqueueLastHook == 1
                        && status.rootNfqueueLastUidKnown == 0
                        && status.rootNfqueueLastUid == -1
                        && status.rootNfqueueLastQueueId == 177
                        && status.rootNfqueueLastPacketId == 99,
                "native Root NFQUEUE S178 last-packet fields preserve their order");
        check(status.rootNfqueueVerdictSucceeded == 12L
                        && status.rootNfqueueVerdictFailedDefinite == 13L
                        && status.rootNfqueueVerdictOutcomeUnknown == 14L
                        && status.rootNfqueueIngressIdentityMissing == 15L
                        && status.rootNfqueueGraphSubmitFailOpens == 16L
                        && status.rootNfqueueNonOwnerBypasses == 17L
                        && status.rootNfqueueDuplicateCompletionDrops == 18L
                        && status.rootNfqueueStaleCompletionDrops == 19L,
                "native Root NFQUEUE S179 fault counters preserve their order");
        check(status.vpnTunFdAttached == 20L
                        && status.vpnDirectUdp4SocketAttached == 21L
                        && status.vpnDirectUdp4ProtectSucceeded == 22L
                        && status.vpnDirectUdp4BindSucceeded == 23L
                        && status.vpnTunIngressPackets == 24L
                        && status.vpnTunUdp4TunOriginPackets == 25L
                        && status.vpnFlowStackAdmissions == 26L
                        && status.vpnDirectUdp4SendSucceeded == 27L
                        && status.vpnDirectUdp4TransportFailed == 28L
                        && status.vpnFlowStackReturnPackets == 29L
                        && status.vpnFlowStackReturnProvenancePackets == 30L
                        && status.vpnTunWriteCompletions == 31L
                        && status.vpnInfrastructureFaults == 32L
                        && status.vpnDuplicateOrStaleDrops == 33L,
                "native VPN UDP4 Direct Egress counters preserve their order");
        check(status.productGraphWorkerCount == 2
                        && status.productGraphFlowDomain == 7
                        && status.productGraphHashSeed == 8032009842424885559L
                        && status.productGraphHandoffCredits == 32,
                "native Product graph worker layout fields preserve their order");
        check(status.productGraphVppWorkerCount == 2
                        && status.productGraphVppMainCore == 0
                        && status.productGraphVppWorker0ThreadIndex == 1
                        && status.productGraphVppWorker0Core == 1
                        && status.productGraphVppWorker1ThreadIndex == 2
                        && status.productGraphVppWorker1Core == 2,
                "native Product graph VPP worker/core placement preserves its order");
        check(status.productGraphEnabled == 1
                        && status.productGraphAccepting == 1
                        && status.productGraphWorkerLayoutReady == 1
                        && status.productGraphObligationDebt == 34L
                        && status.productGraphBufferDebt == 35L
                        && status.productGraphHandoffDebt == 36L,
                "native Product graph guardrail gauges preserve their order");
        check(status.policyRequestedRevision == 88L
                        && status.policyActiveRevision == 88L
                        && status.policyGeneration == 41L
                        && "18446744073709551600".equals(
                        Long.toUnsignedString(status.policySnapshotHash))
                        && status.policyWorker0Revision == 88L
                        && status.policyWorker1Revision == 88L,
                "native Product policy revision/hash fields preserve their order");
        check(!status.policySnapshotEmpty,
                "native Product policy snapshot empty flag preserves its order");
        check(status.policyDefaultPass,
                "native Product policy default-pass flag preserves its order");
        check(status.policyGateClaimCount == 1,
                "native Product policy Gate claim count preserves its order");
        check(status.policyL4RuleCount == 0,
                "native Product policy L4 count preserves its order");
        check(status.policyLastApplyStatusCode == 0,
                "native Product policy last apply status preserves its order");
        check(!status.policyMixedRevision,
                "native Product policy mixed-revision flag preserves its order");
        check(status.policyArtifactMatch,
                "native Product policy artifact-match flag preserves its order");
        check(status.policyGenerationMatch,
                "native Product policy generation-match flag preserves its order");
        check("network-gate/v1/revision-88/uid-1010001/context-1/blocked".equals(
                        status.policySnapshotIdentity),
                "native Product policy snapshot identity preserves its order");
        check(status.policyGateSubjectUid == 1010001
                        && status.policyGateNetworkContext == 1
                        && status.policyGateBlocked
                        && status.policyGateReasonId == 136000017
                        && status.policyGateRuleId == 5836665117071779841L,
                "native Product Gate fields preserve their order");
        check(status.policyDropRecords == 3L
                        && status.policyLastDropRevision == 88L
                        && status.policyLastDropRuleId == 5836665117071779841L
                        && status.policyLastDropCompletionAttempts == 1L
                        && status.policyLastDropUid == 1010001
                        && status.policyLastDropNetworkContext == 1
                        && status.policyLastDropReasonId == 136000017
                        && status.policyLastDropVerdict == 2
                        && status.policyLastDropWinner == 1
                        && status.policyLastDropUidKnown
                        && status.policyLastDropDeviceDirection == 3,
                "native Product Gate drop evidence fields preserve their order");
    }

    private static void productCoreLifecycleRequiresTheExactLiveGeneration() throws Exception {
        Method parser = RuntimeControlNative.class.getDeclaredMethod(
                "parseStatus", String[].class, int.class);
        parser.setAccessible(true);
        String[] readyValues = {
                "0", "42", "1", "0", "0", "1", "1", "1",
                "product-core", "product_core.api/1.0.0@abcd1234",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0", "", "1", "1",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "2", "7", "8032009842424885559", "32", "2", "0", "1", "1",
                "2", "2", "1", "1", "1", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "",
                "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
                "0", "0", "0", "0", "0", "0"
        };
        RuntimeControlNative.Status ready = (RuntimeControlNative.Status) parser.invoke(
                null, (Object) readyValues, 0);
        check(ProductCoreLifecycle.isReady(42L, "product-core",
                        "product_core.api/1.0.0@abcd1234",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, ready),
                "the exact live core-only Product Core generation is ready");

        readyValues[1] = "41";
        RuntimeControlNative.Status stale = (RuntimeControlNative.Status) parser.invoke(
                null, (Object) readyValues, 0);
        check(!ProductCoreLifecycle.isReady(42L, "product-core",
                        "product_core.api/1.0.0@abcd1234",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, stale),
                "a status from another generation is not ready");

        readyValues[1] = "42";
        readyValues[3] = "1";
        RuntimeControlNative.Status adapter = (RuntimeControlNative.Status) parser.invoke(
                null, (Object) readyValues, 0);
        check(!ProductCoreLifecycle.isReady(42L, "product-core",
                        "product_core.api/1.0.0@abcd1234",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, adapter),
                "SAKAMOTO-172 does not promote an Adapter generation to core-only ready");
        check(ProductCoreLifecycle.canRetryConnection(false, true, 0, 24),
                "a live sidecar gets a bounded retry after its first not-ready reply");
        check(ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                        "product_core_not_ready", true),
                "a connected Product Core session is polled while adapter readiness converges");
        check(ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                        "product_worker_layout_mismatch", true),
                "a connected Product Core session is polled while worker layout converges");
        check(!ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                        "product_core_not_ready", false),
                "an unavailable Product Core connection cannot be retained");
        check(!ProductCoreLifecycle.shouldKeepSessionForReadinessRetry(
                        "product_core_connect_failed", true),
                "a failed VAPI connect is retried by reconnecting, not by retaining a session");
        check(!ProductCoreLifecycle.canRetryConnection(true, true, 0, 24),
                "STOP cancels Product Core connection retries");
        check(!ProductCoreLifecycle.canRetryConnection(false, false, 0, 24),
                "an exited sidecar is never retried as a live generation");
        check(!ProductCoreLifecycle.canRetryConnection(false, true, 24, 24),
                "Product Core connection retries remain bounded");
        check(ProductCoreLifecycle.UNKNOWN_PID == -1L,
                "Product Core projection uses an explicit unknown PID");
        check(ProductCoreLifecycle.shouldClearStaleProfile(true, false, false),
                "a tokenless profile with no live Product Core handle is START-cleanable");
        check(!ProductCoreLifecycle.shouldClearStaleProfile(true, true, false),
                "START never removes a profile while its Product Core process is alive");
        check(!ProductCoreLifecycle.shouldClearStaleProfile(true, false, true),
                "START never removes a profile while its Product Core session remains live");
        RuntimeSnapshot running = RuntimeSnapshot.runningCoreOnly(RuntimeProfile.ROOT,
                "vpp-runtime-health/v1", ready.vppRevision, ready.artifactId,
                "arm64-v8a", ProductCoreLifecycle.UNKNOWN_PID, 42L);
        check(running.pid == ProductCoreLifecycle.UNKNOWN_PID,
                "core-only running projection retains unknown PID");
        check(running.isActive(),
                "unknown PID does not make a ready core-only projection inactive");
        check(RuntimeSnapshot.ADAPTER_UNAVAILABLE.equals(running.adapterReadiness),
                "core-only running state keeps the Adapter unavailable");
        check(running.displayText().contains("Protection: not running"),
                "visible runtime status says protection is not running");
    }

    private static void productCoreIdentityValidatorFailsClosed() throws Exception {
        RuntimeControlNative.Status ready = productStatus(1, 1, 0, 42L,
                "sakamoto-product-vpp-host-v1", "product_core.api/1.0.0@92abd1ba",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0");
        check(ProductCoreLifecycle.isReady(42L,
                        "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, ready),
                "matching Product Core identity is ready");

        RuntimeControlNative.Status wrongArtifact = productStatus(1, 1, 0, 42L,
                "wrong-artifact", "product_core.api/1.0.0@92abd1ba",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0");
        check("product_artifact_identity_mismatch".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongArtifact)),
                "wrong artifact identity has a stable failure code");
        check(!ProductCoreLifecycle.isReady(42L,
                        "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongArtifact),
                "wrong artifact identity cannot become ready");

        RuntimeControlNative.Status wrongApi = productStatus(1, 1, 0, 42L,
                "sakamoto-product-vpp-host-v1", "wrong-api",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0");
        check("product_api_identity_mismatch".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongApi)),
                "wrong generated API identity has a stable failure code");

        RuntimeControlNative.Status wrongRevision = productStatus(1, 1, 0, 42L,
                "sakamoto-product-vpp-host-v1", "product_core.api/1.0.0@92abd1ba",
                "wrong-revision");
        check("product_vpp_revision_mismatch".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongRevision)),
                "wrong VPP revision has a stable failure code");

        RuntimeControlNative.Status wrongAbi = productStatus(2, 1, 0, 42L,
                "sakamoto-product-vpp-host-v1", "product_core.api/1.0.0@92abd1ba",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0");
        check("product_protocol_mismatch".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongAbi)),
                "wrong numeric ABI has a stable protocol failure code");
        check(!ProductCoreLifecycle.isReady(42L,
                        "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1, wrongAbi),
                "wrong numeric ABI cannot become ready");

        RuntimeControlNative.Status wrongApiVersion = productStatus(1, 2, 0, 42L,
                "sakamoto-product-vpp-host-v1", "product_core.api/1.0.0@92abd1ba",
                "9258530f3804a152578ce11cc7c8a1e9eab88ed0");
        check("product_protocol_mismatch".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1,
                        wrongApiVersion)),
                "wrong numeric API has a stable protocol failure code");
        check(!ProductCoreLifecycle.isReady(42L,
                        "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1,
                        wrongApiVersion),
                "wrong numeric API cannot become ready");

        RuntimeControlNative.Status failedReply = productStatus(9, 9, 7, 42L,
                "", "", "");
        check("product_core_query_failed".equals(ProductCoreLifecycle.validate(
                        42L, "sakamoto-product-vpp-host-v1",
                        "product_core.api/1.0.0@92abd1ba",
                        "9258530f3804a152578ce11cc7c8a1e9eab88ed0", 1, 1,
                        failedReply)),
                "failed reply keeps its typed native failure rather than identity mismatch");
    }

    private static RuntimeControlNative.Status productStatus(int abiVersion, int apiVersion,
                                                              int code, long generation,
                                                              String artifactId,
                                                              String apiIdentity,
                                                              String vppRevision) {
        return new RuntimeControlNative.Status(abiVersion, apiVersion, code, code, generation,
                true, false, false, true, true, true, artifactId, apiIdentity, vppRevision,
                "", "", "",
                0L, 0L, 0L,
                0, 0, 0, 0, 0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, 0, 0,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L,
                0L, 0L, 0L, 0L, 0L, 0L,
                1, 0, 0L, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 0L, 0L, 0L,
                0L, 0L, generation, 0L, 0L, 0L,
                false, false, 0, 0, 0, false, false, false, "",
                0, 0, false, 0, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, false, 0,
                0L, 0L, 0L, 0L, 0L, 0L,
                0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    private static void productCoreNativeFailureCodesRemainVisible() {
        int[] nativeCodes = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
        String[] productCodes = {
                "product_core_invalid_argument",
                "product_core_allocation_failed",
                "product_core_connect_failed",
                "product_core_disconnected",
                "product_core_stale_handle",
                "product_core_api_unavailable",
                "product_core_query_failed",
                "product_core_protocol_mismatch",
                "product_core_internal_error",
                "product_core_unknown_tag",
                "product_core_disconnect_failed",
                "product_policy_store_failed",
                "product_policy_apply_failed"
        };
        for (int index = 0; index < nativeCodes.length; index++) {
            RuntimeControlNative.Status status = productStatus(1, 1, nativeCodes[index], 42L,
                    "", "", "");
            check(productCodes[index].equals(ProductCoreLifecycle.failureCode(status)),
                    "native Product Core code remains visible: " + nativeCodes[index]);
        }
        check("product_core_not_ready".equals(ProductCoreLifecycle.failureCode(
                        productStatus(1, 1, 0, 42L, "", "", ""))),
                "a zero native code without readiness remains not ready");
        check("product_core_unavailable".equals(ProductCoreLifecycle.failureCode(null)),
                "a missing native status remains explicitly unavailable");
        check("product_core_unknown_failure".equals(ProductCoreLifecycle.failureCode(
                        productStatus(1, 1, 0xfeed, 42L, "", "", ""))),
                "an unknown native code remains explicitly unknown");
    }

    private static void productCoreFailureRetryPolicyIsNarrow() {
        check(ProductCoreLifecycle.isRetryableConnectionFailure("product_core_not_ready"),
                "an absent readiness reply may be retried while the sidecar starts");
        check(ProductCoreLifecycle.isRetryableConnectionFailure("product_core_connect_failed"),
                "a VAPI connect race may be retried while the sidecar starts");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_allocation_failed"),
                "allocation failure is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_api_unavailable"),
                "missing VAPI API is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_query_failed"),
                "a failed VAPI request is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_stale_handle"),
                "a stale generation is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_protocol_mismatch"),
                "a protocol failure is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_core_unknown_failure"),
                "an unknown native failure is surfaced immediately");
        check(!ProductCoreLifecycle.isRetryableConnectionFailure(
                        "product_worker_layout_mismatch"),
                "worker layout is not a generic connect failure");
        check(ProductCoreLifecycle.isRetryableStartupReadinessFailure(
                        "product_worker_layout_mismatch"),
                "worker layout mismatch may converge during bounded startup readiness");
        check(ProductCoreLifecycle.isRetryableStartupTransportFailure(
                        "product_core_unknown_failure"),
                "an unavailable startup transport is retried only by the startup path");
    }

    private static void productCoreOwnerDecisionIsFailClosed() {
        String realPixelNativeLibraryPath =
                "/data/app/~~6RmWNDoq9QO8jzbNE3R7Hw==/"
                        + "com.sakamoto.snort.androidruntime-foN8T5ZUigkrNeO2lBtk8g==/"
                        + "lib/arm64/libvpp_runtime.so";
        ProductCoreOwner.OwnerRecord expected = ProductCoreOwner.OwnerRecord.create(
                42L, "01234567-0123-0123-0123-0123456789ab", RuntimeProfile.ROOT,
                "/data/user/0/example/files/profiles/root/vpp/runtime",
                "/data/user/0/example/files/profiles/root/vpp/runtime/api.sock",
                "product-core", "vpp-r1");
        check(expected.generation == 42L, "owner record retains generation");
        check(expected.diagnosticPid == ProductCoreOwner.UNKNOWN_PID,
                "owner record keeps PID diagnostic-only and unknown on Android");
        String encoded = expected.encode();
        check(encoded.contains("generation=42"), "owner record writes generation");
        check(encoded.contains("token=01234567-0123-0123-0123-0123456789ab"),
                "owner record writes the generation token");
        check(encoded.contains("apiSocket=/data/user/0/example/files/profiles/root/vpp/runtime/api.sock"),
                "owner record writes the exact API socket path");
        ProductCoreOwner.OwnerRecord restored = ProductCoreOwner.OwnerRecord.parse(encoded);
        check(expected.sameInstallation(restored),
                "owner record round-trips the exact installation identity");
        check(expected.token.equals(restored.token), "owner record round-trips its token");
        ProductCoreOwner.OwnerRecord canonicalPathOwner = ProductCoreOwner.OwnerRecord.create(
                43L, "01234567-0123-0123-0123-0123456789ac", RuntimeProfile.ROOT,
                "/data/app/~~6RmWNDoq9QO8jzbNE3R7Hw==/"
                        + "com.sakamoto.snort.androidruntime-foN8T5ZUigkrNeO2lBtk8g==/runtime",
                "/data/app/~~6RmWNDoq9QO8jzbNE3R7Hw==/"
                        + "com.sakamoto.snort.androidruntime-foN8T5ZUigkrNeO2lBtk8g==/runtime/api.sock",
                "product-core", "vpp-r1");
        ProductCoreOwner.OwnerRecord canonicalPathRestored =
                ProductCoreOwner.OwnerRecord.parse(canonicalPathOwner.encode());
        check(canonicalPathOwner.sameInstallation(canonicalPathRestored)
                        && canonicalPathOwner.token.equals(canonicalPathRestored.token),
                "canonical owner paths round-trip through the durable record");
        String canonicalGlobalCommand = ProductCoreOwner.buildGlobalProcessAuditCommand(
                realPixelNativeLibraryPath, "10123");
        check(canonicalGlobalCommand.contains("case \"$exe\" in '"
                        + realPixelNativeLibraryPath + "'|*/'libvpp_runtime.so'|*/'libvpp_runtime.so (deleted)'"),
                "global owner audit treats an upgraded/deleted same-name VPP executable as live");
        int canonicalGlobalCandidate = canonicalGlobalCommand.indexOf(
                "index(args, executable) > 0");
        int canonicalGlobalReadlink = canonicalGlobalCommand.indexOf("readlink");
        check(canonicalGlobalCandidate >= 0
                        && canonicalGlobalCandidate < canonicalGlobalReadlink,
                "global owner audit filters ps args to product executable candidates before proc exe reads");
        String canonicalOwnerCommand = ProductCoreOwner.buildProcessAuditCommand(
                canonicalPathOwner, realPixelNativeLibraryPath, "10123");
        check(canonicalOwnerCommand.contains("case \"$exe\" in '"
                        + realPixelNativeLibraryPath + "'|*/'libvpp_runtime.so'|*/'libvpp_runtime.so (deleted)'"),
                "owner audit keeps an upgraded/deleted same-name VPP executable tied to its owner");
        int canonicalOwnerCandidate = canonicalOwnerCommand.indexOf(
                "index(args, executable) > 0 || index(args, startup) > 0");
        int canonicalOwnerReadlink = canonicalOwnerCommand.indexOf("readlink");
        check(canonicalOwnerCandidate >= 0 && canonicalOwnerCandidate < canonicalOwnerReadlink,
                "owner audit filters ps args to product candidates before proc exe reads");
        check(canonicalOwnerCommand.contains("grep -F -x -- 'SAKAMOTO_VPP_RUNTIME_DIR="
                        + canonicalPathOwner.runtimePath + "'"),
                "owner audit preserves the canonical owner runtime path");
        expectIllegalArgument("owner record rejects duplicate fields",
                () -> ProductCoreOwner.OwnerRecord.parse(encoded + "generation=43\n"));
        expectIllegalArgument("owner record rejects missing fields",
                () -> ProductCoreOwner.OwnerRecord.parse(encoded.replace("revision=vpp-r1\n", "")));

        ProductCoreOwner.ProfileFact rootAbsent = ProductCoreOwner.ProfileFact.absent(
                RuntimeProfile.ROOT);
        ProductCoreOwner.ProfileFact vpnAbsent = ProductCoreOwner.ProfileFact.absent(
                RuntimeProfile.VPN);
        ProductCoreOwner.GlobalDecision globalFresh = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent, vpnAbsent, false,
                ProductCoreOwner.ProcessState.GONE);
        check(globalFresh.action == ProductCoreOwner.Action.FRESH_START,
                "both absent Product Core profiles permit a fresh start");
        ProductCoreOwner.GlobalDecision globalHandleLive = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent, vpnAbsent, true,
                ProductCoreOwner.ProcessState.GONE);
        check(globalHandleLive.action == ProductCoreOwner.Action.BLOCK_LIVE,
                "a live in-process Product Core handle blocks global replacement");
        ProductCoreOwner.GlobalDecision unregisteredLive = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent, vpnAbsent, false,
                ProductCoreOwner.ProcessState.LIVE);
        check(unregisteredLive.action == ProductCoreOwner.Action.BLOCK_LIVE,
                "an unregistered app-UID VPP blocks even with both profiles absent");
        ProductCoreOwner.GlobalDecision unregisteredUnknown = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent, vpnAbsent, false,
                ProductCoreOwner.ProcessState.UNKNOWN);
        check(unregisteredUnknown.action == ProductCoreOwner.Action.BLOCK_UNKNOWN,
                "an unregistered global scan failure blocks even with both profiles absent");
        ProductCoreOwner.ProfileFact rootGone = ProductCoreOwner.ProfileFact.exactGone(
                RuntimeProfile.ROOT, expected);
        ProductCoreOwner.ProfileFact vpnGone = ProductCoreOwner.ProfileFact.exactGone(
                RuntimeProfile.VPN, ProductCoreOwner.OwnerRecord.create(
                        50L, "01234567-0123-0123-0123-0123456789ac", RuntimeProfile.VPN,
                        "/data/user/0/example/files/profiles/vpn/vpp/runtime",
                        "/data/user/0/example/files/profiles/vpn/vpp/runtime/api.sock",
                        "product-core", "vpp-r1"));
        ProductCoreOwner.GlobalDecision globalGone = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootGone, vpnGone, false,
                ProductCoreOwner.ProcessState.GONE);
        check(globalGone.action == ProductCoreOwner.Action.CLEAN_THEN_START,
                "global Product Core audit permits cleanup only after both profiles are gone");
        check(globalGone.shouldClean(RuntimeProfile.ROOT)
                        && globalGone.shouldClean(RuntimeProfile.VPN),
                "global cleanup selects only exact gone ROOT and VPN owners");
        check(globalGone.highestGeneration() == 50L,
                "generation allocation observes the highest ROOT or VPN durable generation");
        ProductCoreOwner.GlobalDecision vpnLive = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootGone,
                ProductCoreOwner.ProfileFact.live(RuntimeProfile.VPN, vpnGone.owner), false,
                ProductCoreOwner.ProcessState.GONE);
        check(vpnLive.action == ProductCoreOwner.Action.BLOCK_LIVE,
                "a live opposite-profile owner blocks selected-profile replacement");
        ProductCoreOwner.GlobalDecision vpnUnknown = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent,
                ProductCoreOwner.ProfileFact.unknown(RuntimeProfile.VPN, "unreadable owner"),
                false, ProductCoreOwner.ProcessState.GONE);
        check(vpnUnknown.action == ProductCoreOwner.Action.BLOCK_UNKNOWN,
                "an unknown opposite-profile owner blocks selected-profile replacement");
        check(!vpnUnknown.shouldClean(RuntimeProfile.ROOT)
                        && !vpnUnknown.shouldClean(RuntimeProfile.VPN),
                "blocked global ownership audit selects no unproven profile for deletion");
        ProductCoreOwner.GlobalDecision repairedFresh = ProductCoreOwner.decideGlobalForStart(
                RuntimeProfile.ROOT, rootAbsent, vpnAbsent, false,
                ProductCoreOwner.ProcessState.GONE);
        check(repairedFresh.action == ProductCoreOwner.Action.FRESH_START,
                "after exact residue repair the next explicit start is fresh");

        try {
            Path ownerDirectory = Files.createTempDirectory("sakamoto-owner-atomic");
            java.io.File ownerFile = ownerDirectory.resolve(ProductCoreOwner.RECORD_FILE).toFile();
            expected.write(ownerFile);
            java.io.File candidate = ownerDirectory.resolve(
                    ".owner.properties.interrupted.tmp").toFile();
            Files.write(candidate.toPath(), "incomplete\n".getBytes(StandardCharsets.US_ASCII));
            check(expected.sameInstallation(ProductCoreOwner.OwnerRecord.read(ownerFile)),
                    "an interrupted owner candidate leaves the previous complete record readable");
            ProductCoreOwner.OwnerRecord replacement = ProductCoreOwner.OwnerRecord.create(
                    43L, "01234567-0123-0123-0123-0123456789ad", RuntimeProfile.ROOT,
                    expected.runtimePath, expected.apiSocket, expected.artifactId, "vpp-r2");
            Files.deleteIfExists(candidate.toPath());
            Files.deleteIfExists(ownerFile.toPath());
            java.io.File pending = ownerDirectory.resolve(
                    ".owner.properties.pending.tmp").toFile();
            Files.write(pending.toPath(), replacement.encode().getBytes(StandardCharsets.US_ASCII));
            check(ProductCoreOwner.isInterruptedPublicationOnly(ownerDirectory.toFile()),
                    "a candidate-only profile is explicitly repairable");
            check(replacement.sameInstallation(
                            ProductCoreOwner.OwnerRecord.readPending(ownerFile)),
                    "a complete owner candidate can be audited after a pre-rename interruption");
            java.io.File duplicatePending = ownerDirectory.resolve(
                    ".owner.properties.duplicate.tmp").toFile();
            Files.write(duplicatePending.toPath(), replacement.encode()
                    .getBytes(StandardCharsets.US_ASCII));
            boolean duplicateRejected = false;
            try {
                ProductCoreOwner.OwnerRecord.readPending(ownerFile);
            } catch (IOException expectedDuplicate) {
                duplicateRejected = true;
            }
            check(duplicateRejected, "duplicate owner candidates are rejected fail-closed");
            Files.deleteIfExists(duplicatePending.toPath());
            replacement.write(ownerFile);
            check(replacement.sameInstallation(ProductCoreOwner.OwnerRecord.read(ownerFile))
                            && replacement.revision.equals(
                            ProductCoreOwner.OwnerRecord.read(ownerFile).revision),
                    "atomic owner replacement publishes one complete new record");
            java.io.File startup = ownerDirectory.resolve("startup.conf").toFile();
            Files.write(startup.toPath(), "old-startup\n".getBytes(StandardCharsets.UTF_8));
            java.io.File startupCandidate = ownerDirectory.resolve(
                    ".startup.conf.interrupted.tmp").toFile();
            Files.write(startupCandidate.toPath(), "incomplete\n".getBytes(StandardCharsets.UTF_8));
            check("old-startup\n".equals(new String(Files.readAllBytes(startup.toPath()),
                    StandardCharsets.UTF_8)),
                    "an interrupted startup candidate leaves the previous complete file readable");
            ProductCoreOwner.writeAtomic(startup, "new-startup\n".getBytes(StandardCharsets.UTF_8));
            check("new-startup\n".equals(new String(Files.readAllBytes(startup.toPath()),
                    StandardCharsets.UTF_8)),
                    "startup configuration uses the same atomic file publication seam");
            Files.deleteIfExists(candidate.toPath());
            Files.deleteIfExists(pending.toPath());
            Files.deleteIfExists(duplicatePending.toPath());
            Files.deleteIfExists(startupCandidate.toPath());
            Files.deleteIfExists(ownerFile.toPath());
            Files.deleteIfExists(startup.toPath());
            Files.deleteIfExists(ownerDirectory);
        } catch (Exception error) {
            throw new AssertionError("atomic owner publication could not be checked", error);
        }

        String globalCommand = ProductCoreOwner.buildGlobalProcessAuditCommand(
                "/data/app/example/lib/arm64-v8a/libvpp_runtime.so", "10123");
        check(globalCommand.contains("expected_uid='10123'"),
                "global owner audit filters unregistered candidates to the app UID first");
        check(!globalCommand.contains("SAKAMOTO_VPP_OWNER_TOKEN="),
                "global owner audit does not require a registered owner token");
        check(globalCommand.contains("readlink")
                        && globalCommand.contains("libvpp_runtime.so"),
                "global owner audit checks the Product Core executable identity");
        check(globalCommand.contains("-v audit_pid=\"$$\"")
                        && globalCommand.contains("$1 != audit_pid")
                        && globalCommand.contains("$3 != \"ps\""),
                "global owner audit excludes its shell and known ps helper row");
        check(globalCommand.contains("-v executable='/data/app/example/lib/arm64-v8a/libvpp_runtime.so'"),
                "global owner audit carries the product executable into the ps prefilter");
        check(globalCommand.contains("index(args, executable) > 0"),
                "global owner audit skips unrelated UID processes before proc exe reads");
        check(globalCommand.contains("if [ ! -e \"$proc\" ]; then continue; fi;"),
                "global owner audit ignores a process that vanished before readlink");
        check(globalCommand.contains("*/'libvpp_runtime.so (deleted)'"),
                "global owner audit catches a still-live Product Core process after APK upgrade");
        try {
            Path globalScript = Files.createTempFile("sakamoto-product-global-owner-audit", ".sh");
            try {
                Files.write(globalScript, globalCommand.getBytes(StandardCharsets.UTF_8));
                Process syntax = new ProcessBuilder("sh", "-n", globalScript.toString())
                        .redirectErrorStream(true).start();
                check(syntax.waitFor() == 0,
                        "global Product Core executable audit command is valid POSIX shell");
            } finally {
                Files.deleteIfExists(globalScript);
            }
        } catch (Exception error) {
            throw new AssertionError("global Product Core audit syntax could not be checked", error);
        }
        check(ProductCoreOwner.ProcessState.LIVE
                        == ProductCoreOwner.processState(0, "PRODUCT_OWNER_COUNT=1\n"),
                "one unregistered exact executable is live");
        check(ProductCoreOwner.ProcessState.GONE
                        == ProductCoreOwner.processState(0, "PRODUCT_OWNER_COUNT=0\n"),
                "zero global executable matches permits fresh evaluation");
        check(ProductCoreOwner.ProcessState.UNKNOWN
                        == ProductCoreOwner.processState(125, "PRODUCT_OWNER_AUDIT_ERROR=ps\n"),
                "global executable scan failure is unknown rather than fresh");

        String command = ProductCoreOwner.buildProcessAuditCommand(expected,
                "/data/app/example/lib/arm64-v8a/libvpp_runtime.so", "10123");
        check(command.contains("SAKAMOTO_VPP_OWNER_TOKEN=" + expected.token),
                "owner audit checks the exact generation token");
        check(command.contains("SAKAMOTO_PRODUCT_GENERATION=42"),
                "owner audit checks the exact generation");
        check(command.contains("SAKAMOTO_VPP_RUNTIME_DIR=" + expected.runtimePath),
                "owner audit checks the exact runtime directory");
        check(command.contains("SAKAMOTO_RUNTIME_PROFILE=root"),
                "owner audit checks the exact runtime profile");
        check(command.contains("ps -A -o PID,UID,args"),
                "owner audit obtains the current-UID filter before proc reads");
        check(command.contains("expected_uid='10123'"),
                "owner audit filters candidates to the app UID first");
        check(command.contains("api.sock"),
                "owner audit carries the exact API socket identity");
        check(command.contains("-v audit_pid=\"$$\"")
                        && command.contains("$1 != audit_pid")
                        && command.contains("$3 != \"ps\""),
                "owner audit excludes its shell and known ps helper row");
        check(command.contains("-v executable='/data/app/example/lib/arm64-v8a/libvpp_runtime.so'")
                        && command.contains("-v startup='/data/user/0/example/files/profiles/root/vpp/startup.conf'"),
                "owner audit carries product executable and startup into the ps prefilter");
        check(command.contains("index(args, executable) > 0 || index(args, startup) > 0"),
                "owner audit skips unrelated UID processes before proc exe reads");
        check(command.contains("if [ ! -e \"$proc\" ]; then continue; fi;"),
                "owner audit ignores a process that vanished before readlink");
        check(command.contains("*/'libvpp_runtime.so (deleted)'"),
                "owner audit catches a still-live generation owner after APK upgrade");
        try {
            Path script = Files.createTempFile("sakamoto-product-owner-audit", ".sh");
            try {
                Files.write(script, command.getBytes(StandardCharsets.UTF_8));
                Process syntax = new ProcessBuilder("sh", "-n", script.toString())
                        .redirectErrorStream(true).start();
                check(syntax.waitFor() == 0,
                        "Product Core owner audit command is valid POSIX shell");
            } finally {
                Files.deleteIfExists(script);
            }
        } catch (Exception error) {
            throw new AssertionError("Product Core owner audit syntax could not be checked", error);
        }
        check(ProductCoreOwner.ProcessState.LIVE
                        == ProductCoreOwner.processState(0, "PRODUCT_OWNER_COUNT=1\n"),
                "one exact process audit match is live");
        check(ProductCoreOwner.ProcessState.GONE
                        == ProductCoreOwner.processState(0, "PRODUCT_OWNER_COUNT=0\n"),
                "zero process audit matches proves gone");
        check(ProductCoreOwner.ProcessState.UNKNOWN
                        == ProductCoreOwner.processState(125, ""),
                "audit command failure is unknown rather than gone");
        check(ProductCoreOwner.ProcessState.UNKNOWN
                        == ProductCoreOwner.processState(0, "PRODUCT_OWNER_COUNT=2\n"),
                "multiple process matches are unknown rather than adoptable");
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

    private static void applicationProtocolCatalogOwnsStablePolicyIdentity() {
        check(ApplicationProtocolCatalog.CATALOG_VERSION == 1,
                "catalog version is a build-time diagnostic version");
        check(ApplicationProtocolCatalog.ID_DNS == 1001
                        && ApplicationProtocolCatalog.ID_HTTP == 1002
                        && ApplicationProtocolCatalog.ID_TLS == 1003
                        && ApplicationProtocolCatalog.ID_QUIC == 1004,
                "catalog ids are project-owned and not qDPI/libprotoident ordinals");
        check(ApplicationProtocolCatalog.byKey("http").id == ApplicationProtocolCatalog.ID_HTTP,
                "lowercase ApplicationProtocolKey resolves to stable id");
        check(ApplicationProtocolCatalog.byMigrationAlias("ssl").id
                        == ApplicationProtocolCatalog.ID_TLS,
                "rename/migration alias resolves explicitly without changing the key mapping");
        check(ApplicationProtocolCatalog.byProviderAlias("lpi:http").id
                        == ApplicationProtocolCatalog.ID_HTTP,
                "provider alias maps recognition evidence without becoming policy identity");
        check(ApplicationProtocolCatalog.byKey("lpi:http") == null,
                "provider-prefixed names are not ApplicationProtocolKey values");
        check(ApplicationProtocolCatalog.byKey("reserved-1000") != null
                        && !ApplicationProtocolCatalog.byKey("reserved-1000").active(),
                "deleted ids stay as reserved/tombstone entries");
        List<Integer> web = ApplicationProtocolCatalog.expandCategory("web");
        check(web.size() == 3
                        && web.contains(Integer.valueOf(ApplicationProtocolCatalog.ID_HTTP))
                        && web.contains(Integer.valueOf(ApplicationProtocolCatalog.ID_TLS))
                        && web.contains(Integer.valueOf(ApplicationProtocolCatalog.ID_QUIC)),
                "category selector expands to exact active protocol ids at Apply");
        check(ApplicationProtocolCatalog.expandCategory("reserved-1000").isEmpty(),
                "category is not a protocol result or hierarchy");
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

    private static void gateMatrixCompilesToPacketPolicyApplyPayload() {
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle blocked = AuthoringPolicyBundle.empty()
                .withNetworkGate(app, AuthoringPolicyBundle.NetworkContextId.WIFI, false)
                .withNetworkGate(app, AuthoringPolicyBundle.NetworkContextId.MOBILE, true)
                .withNetworkGate(app, AuthoringPolicyBundle.NetworkContextId.VPN, true);
        AuthoringPolicyCompiler.CompileResult result =
                AuthoringPolicyCompiler.compilePacketPolicyApply(blocked);
        check(result.ok, "GateMatrix compiles to a packet policy apply payload");
        check(result.revision == blocked.revision, "compiled payload carries bundle revision");
        check(result.applyPayload.contains("\"revision\":3"),
                "compiled payload encodes revision");
        check(result.applyPayload.contains("\"linuxUid\":1010001"),
                "compiled payload encodes complete Linux UID");
        check(result.applyPayload.contains("\"uidKnown\":true"),
                "compiled payload encodes explicit known UID");
        check(result.applyPayload.contains("\"networkGate\":{\"rules\":["),
                "compiled payload uses per-context GateTable rules");
        check(result.applyPayload.contains("\"networkContext\":1")
                        && result.applyPayload.contains("\"blocked\":false"),
                "open Wi-Fi Gate compiles as a revisioned open rule");
        check(result.applyPayload.contains("\"networkContext\":2")
                        && result.applyPayload.contains("\"networkContext\":3"),
                "compiled payload maps Mobile and VPN NetworkContextId values");
        check(!result.applyPayload.contains("blockedNetworkContexts"),
                "compiled payload does not collapse GateMatrix into lossy legacy context list");
        check(result.applyPayload.contains("\"reasonId\":"),
                "compiled payload carries stable reason attribution");
        check(result.applyPayload.contains("\"ruleId\":"),
                "compiled payload carries stable rule attribution");

        AuthoringPolicyBundle opened = blocked.withNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.MOBILE, false)
                .withNetworkGate(app, AuthoringPolicyBundle.NetworkContextId.VPN, false);
        AuthoringPolicyCompiler.CompileResult openResult =
                AuthoringPolicyCompiler.compilePacketPolicyApply(opened);
        check(openResult.ok, "open GateMatrix compiles");
        check(openResult.applyPayload.contains("\"revision\":5"),
                "open GateMatrix compiles as a new revision");
        check(openResult.applyPayload.contains("\"rules\"")
                        && openResult.applyPayload.contains("\"blocked\":false")
                        && !openResult.applyPayload.contains("\"blocked\":true"),
                "open Gate compiles a successor open snapshot without a blocking claim");

        AuthoringPolicyBundle unsupported = AuthoringPolicyBundle.restore(9L, "test",
                blocked.gateMatrix, blocked.l4Rules, 1);
        AuthoringPolicyCompiler.CompileResult failure =
                AuthoringPolicyCompiler.compilePacketPolicyApply(unsupported);
        check(!failure.ok, "unsupported rule families fail compile before runtime apply");
        check("authoring_policy_bundle_unsupported".equals(failure.errorCode),
                "compile failure reports actionable unsupported bundle code");
    }

    private static void productStorePersistsL4RuleListAsTypedRuleFamily() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-52-l4-store");
        ProductStore product = new ProductStore(files.toFile());
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle.L4Rule dropHttps = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 10, 2);
        AuthoringPolicyBundle.L4Rule allowDns = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV6, "2001:db8::/32", "2001:4860::/32",
                AuthoringPolicyBundle.PortRange.inclusive(49152, 65535),
                AuthoringPolicyBundle.PortRange.exact(53), 17,
                AuthoringPolicyBundle.PacketDirection.INPUT, null,
                AuthoringPolicyBundle.L4Action.ALLOW, 20, 1);
        ProductStore.MutationResult published = product.replaceAuthoringPolicyBundle(
                AuthoringPolicyBundle.empty().withL4Rule(dropHttps).withL4Rule(allowDns));
        check(published.persisted, "ProductStore persists typed L4RuleList");

        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.authoringPolicyBundle.l4RuleCount == 2,
                "ProductStateStore restores L4RuleList count");
        check(restored.authoringPolicyBundle.l4Rules.get(0).subjectId.equals(app),
                "L4RuleList preserves complete ApplicationSubjectId");
        check("10.0.0.0/8".equals(restored.authoringPolicyBundle.l4Rules.get(0).sourceCidr)
                        && "192.0.2.0/24".equals(
                        restored.authoringPolicyBundle.l4Rules.get(0).destinationCidr),
                "L4RuleList preserves source/destination CIDR");
        check(restored.authoringPolicyBundle.l4Rules.get(0).destinationPorts.first == 443
                        && restored.authoringPolicyBundle.l4Rules.get(0).destinationPorts.last == 443,
                "L4RuleList preserves destination port range");
        check(restored.authoringPolicyBundle.l4Rules.get(0).networkContext
                        == AuthoringPolicyBundle.NetworkContextId.WIFI,
                "L4RuleList preserves optional interface context");
        check(restored.authoringPolicyBundle.l4Rules.get(1).family
                        == AuthoringPolicyBundle.IpFamily.IPV6,
                "L4RuleList preserves explicit IPv6 family");
        AuthoringPolicyBundle.L4Rule samePriorityDifferentOrder =
                AuthoringPolicyBundle.L4Rule.create(app,
                        AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8",
                        "198.51.100.0/24", null,
                        AuthoringPolicyBundle.PortRange.exact(443), 6,
                        AuthoringPolicyBundle.PacketDirection.OUTPUT,
                        AuthoringPolicyBundle.NetworkContextId.WIFI,
                        AuthoringPolicyBundle.L4Action.DROP, 10, 3);
        check(dropHttps.ruleId != samePriorityDifferentOrder.ruleId,
                "L4 stable rule IDs distinguish explicit order values");
        AuthoringPolicyBundle.L4Rule allowHttps = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.ALLOW, 10, 2);
        AuthoringPolicyBundle toggled = AuthoringPolicyBundle.empty()
                .withL4Rule(dropHttps)
                .withL4Rule(allowHttps);
        check(dropHttps.ruleId == allowHttps.ruleId
                        && toggled.l4RuleCount == 1
                        && toggled.l4Rules.get(0).action
                        == AuthoringPolicyBundle.L4Action.ALLOW,
                "L4 successor action replaces the same tuple instead of adding a second rule");
    }

    private static void l4RuleListCompilesToPacketPolicyApplyPayload() {
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle.L4Rule lateAllow = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.ALLOW, 20, 0);
        AuthoringPolicyBundle.L4Rule earlyDrop = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 10, 0);
        AuthoringPolicyBundle bundle = AuthoringPolicyBundle.empty()
                .withL4Rule(lateAllow)
                .withL4Rule(earlyDrop);

        AuthoringPolicyCompiler.CompileResult result =
                AuthoringPolicyCompiler.compilePacketPolicyApply(bundle);
        check(result.ok, "L4RuleList compiles to packet policy apply payload");
        check(result.applyPayload.contains("\"l4Rules\":["),
                "compiled payload emits L4RuleList");
        check(result.applyPayload.contains("\"family\":\"ipv4\"")
                        && result.applyPayload.contains("\"sourceCidr\":\"10.0.0.0/8\"")
                        && result.applyPayload.contains("\"destinationCidr\":\"192.0.2.0/24\""),
                "compiled L4 payload carries explicit family and CIDR predicates");
        check(result.applyPayload.contains("\"direction\":\"output\"")
                        && result.applyPayload.contains("\"ipProtocol\":6")
                        && result.applyPayload.contains("\"destinationPorts\":{\"first\":443,\"last\":443}"),
                "compiled L4 payload carries direction/protocol/port predicates");
        check(result.applyPayload.contains("\"networkContexts\":[1]"),
                "compiled L4 payload carries optional NetworkContextId");
        int dropIndex = result.applyPayload.indexOf("\"action\":\"drop\"");
        int allowIndex = result.applyPayload.indexOf("\"action\":\"allow\"");
        check(dropIndex >= 0 && allowIndex > dropIndex,
                "compiled L4 payload is ordered by priority before later allow");
    }

    private static void localProductBackendAppliesGatePolicyBeforePersistingBundle()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-51-backend-apply");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        final String[] appliedPayload = {""};
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app, "com.example.mail",
                        "Mail", "icon:mail/u10", 10, "Work", true)),
                payload -> {
                    appliedPayload[0] = payload;
                    return LocalProductBackend.PolicyApplyResult.ok();
                });

        ProductStore.MutationResult blocked = backend.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.WIFI, true);
        check(blocked.persisted, "backend persists GateMatrix after runtime apply success");
        check(appliedPayload[0].contains("\"cmd\"") == false,
                "backend transport receives POLICY.APPLY args, not a wrapped RPC frame");
        check(appliedPayload[0].contains("\"revision\":1"),
                "backend applies the same revision it persists");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.revision == 1L,
                "successful backend apply publishes durable authoring revision");

        LocalProductBackend failingBackend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app, "com.example.mail",
                        "Mail", "icon:mail/u10", 10, "Work", true)),
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "injected_runtime_apply_failure", "runtime rejected policy"));
        ProductStore.MutationResult failed = failingBackend.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.WIFI, false);
        check(!failed.persisted, "backend rejects GateMatrix mutation on runtime apply failure");
        check("injected_runtime_apply_failure".equals(failed.errorCode),
                "backend returns the runtime apply failure code");
        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.authoringPolicyBundle.revision == 1L,
                "failed runtime apply does not publish a new durable revision");
        check(restored.authoringPolicyBundle.gateMatrix.get(0).blocked,
                "failed runtime apply keeps old GateMatrix action");
    }

    private static void localProductBackendAppliesL4PolicyBeforePersistingBundle()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-52-backend-apply");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        final String[] appliedPayload = {""};
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app, "com.example.mail",
                        "Mail", "icon:mail/u10", 10, "Work", true)),
                payload -> {
                    appliedPayload[0] = payload;
                    return LocalProductBackend.PolicyApplyResult.ok();
                });
        AuthoringPolicyBundle.L4Rule rule = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.DROP, 10, 0);

        ProductStore.MutationResult persisted = backend.setL4Rule(rule);
        check(persisted.persisted, "backend persists L4RuleList after runtime apply success");
        check(appliedPayload[0].contains("\"l4Rules\":["),
                "backend applies L4RuleList through POLICY.APPLY args");
        check(appliedPayload[0].contains("\"sourceCidr\":\"10.0.0.0/8\"")
                        && appliedPayload[0].contains("\"destinationCidr\":\"192.0.2.0/24\""),
                "backend runtime apply payload carries L4 CIDR predicates");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 1,
                "successful backend L4 apply publishes durable authoring revision");

        LocalProductBackend failingBackend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app, "com.example.mail",
                        "Mail", "icon:mail/u10", 10, "Work", true)),
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "injected_l4_apply_failure", "runtime rejected L4 policy"));
        AuthoringPolicyBundle.L4Rule allow = AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "10.0.0.0/8", "192.0.2.0/24",
                null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                AuthoringPolicyBundle.L4Action.ALLOW, 5, 0);
        ProductStore.MutationResult failed = failingBackend.setL4Rule(allow);
        check(!failed.persisted, "backend rejects L4 mutation on runtime apply failure");
        check("injected_l4_apply_failure".equals(failed.errorCode),
                "backend returns the L4 runtime apply failure code");
        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.authoringPolicyBundle.l4RuleCount == 1
                        && restored.authoringPolicyBundle.l4Rules.get(0).action
                        == AuthoringPolicyBundle.L4Action.DROP,
                "failed runtime L4 apply keeps old durable L4 rule");
    }

    private static void localProductBackendPersistsPolicyTransactionsAroundProductState()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-53-backend-transactions");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        final StringBuilder appliedPayloads = new StringBuilder();
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                payload -> {
                    appliedPayloads.append(payload).append('\n');
                    return LocalProductBackend.PolicyApplyResult.ok();
                });
        AuthoringPolicyBundle.L4Rule drop = l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                AuthoringPolicyBundle.L4Action.DROP);

        ProductStore.MutationResult persisted = backend.setL4Rule(drop);
        check(persisted.persisted, "backend L4 mutation persists through transaction path");
        ProductPolicyTransactionStore.ReadResult transactionRead =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(transactionRead.present && transactionRead.valid,
                "backend publishes durable policy transaction state");
        check(transactionRead.transactions.status().committedRevision == 1L
                        && transactionRead.transactions.status().runtimeRevision == 1L
                        && transactionRead.transactions.status().checkpointCount == 1
                        && "applied".equals(
                        transactionRead.transactions.status().runtimeSnapshotState),
                "backend transaction state records committed runtime snapshot and checkpoint");
        ProductStateSnapshot productState = ProductStateStore.read(files.toFile());
        check(productState.boundApplications.contains(app)
                        && productState.authoringPolicyBundle.l4RuleCount == 1,
                "backend binds the policy subject and publishes ProductState after transaction");
        check(appliedPayloads.toString().contains("\"revision\":1"),
                "backend transaction applies the same revision it checkpoints");

        LocalProductBackend failingBackend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "injected_transaction_apply_failure", "runtime rejected transaction"));
        ProductStore.MutationResult failed = failingBackend.setL4Rule(
                l4Rule(app, "8.8.8.8/32", 6, 20, 1,
                        AuthoringPolicyBundle.L4Action.ALLOW));
        check(!failed.persisted
                        && "injected_transaction_apply_failure".equals(failed.errorCode),
                "backend transaction surfaces runtime apply failure");
        ProductPolicyTransactionStore.ReadResult afterFailure =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(afterFailure.transactions.status().committedRevision == 1L
                        && afterFailure.transactions.status().runtimeRevision == 1L
                        && afterFailure.transactions.status().checkpointCount == 1,
                "failed backend transaction leaves durable transaction head unchanged");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 1,
                "failed backend transaction leaves durable ProductState unchanged");

        Path writerFailureFiles = Files.createTempDirectory(
                "sakamoto-53-backend-transaction-writer-fail");
        final StringBuilder writerFailurePayloads = new StringBuilder();
        LocalProductBackend writerFailingBackend = new LocalProductBackend(
                writerFailureFiles.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                payload -> {
                    writerFailurePayloads.append(payload).append('\n');
                    return LocalProductBackend.PolicyApplyResult.ok();
                },
                (dir, transactions) -> {
                    throw new IOException("injected transaction persistence failure");
                });
        ProductStore.MutationResult writerFailed =
                writerFailingBackend.setNetworkGate(app,
                        AuthoringPolicyBundle.NetworkContextId.WIFI, true);
        check(!writerFailed.persisted
                        && "policy_transactions_persistence_failed".equals(
                        writerFailed.errorCode),
                "backend does not publish ProductState when transaction persistence fails");
        check(!ProductStateStore.readResult(writerFailureFiles.toFile()).present,
                "transaction persistence failure leaves ProductState unpublished");
        check(!ProductPolicyTransactionStore.readResult(writerFailureFiles.toFile()).present,
                "transaction persistence failure leaves no durable checkpoint");
        String rollbackPayloads = writerFailurePayloads.toString();
        int firstTypedApply = rollbackPayloads.indexOf("\"bundlePayload\":\"");
        int rollbackTypedApply = firstTypedApply < 0 ? -1
                : rollbackPayloads.indexOf("\"bundlePayload\":\"", firstTypedApply + 1);
        check(rollbackPayloads.contains("\"revision\":1")
                        && firstTypedApply >= 0 && rollbackTypedApply > firstTypedApply
                        && !rollbackPayloads.contains("\"nativeApply\":\"s191-scalar\""),
                "transaction persistence failure rolls runtime back through the typed snapshot path");
    }

    private static void localProductBackendExposesPolicyImportExportAndRestore()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-53-backend-import-restore");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        final StringBuilder appliedPayloads = new StringBuilder();
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                payload -> {
                    appliedPayloads.append(payload).append('\n');
                    return LocalProductBackend.PolicyApplyResult.ok();
                });
        check(backend.bindApplication(app).persisted,
                "backend policy commit validation can use explicit Product binding");

        AuthoringPolicyBundle first = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        ProductStore.MutationResult imported =
                backend.importPolicyDraft(ProductPolicyTransactions.exportBundle(first));
        check(imported.persisted && backend.policyTransactionStatus().draftDirty,
                "backend import stores a dirty Draft without applying runtime");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.isEmpty(),
                "backend import Draft does not publish ProductState before commit");
        ProductStore.MutationResult badImport = backend.importPolicyDraft("bad");
        check(!badImport.persisted
                        && "policy_import_unsupported_format".equals(badImport.errorCode),
                "backend bad import returns actionable failure");
        check(backend.policyTransactionStatus().draftRevision == first.revision,
                "backend bad import leaves previous Draft intact");

        ProductStore.MutationResult committed = backend.commitPolicyDraft();
        check(committed.persisted
                        && backend.policyTransactionStatus().committedRevision == first.revision
                        && backend.policyTransactionStatus().runtimeRevision == 0L,
                "backend commit advances committed head without applying runtime");
        LocalProductBackend.PolicyTextResult exported = backend.exportCommittedPolicy();
        check(exported.ok && exported.payload.startsWith(
                        ProductPolicyTransactions.EXPORT_HEADER)
                        && exported.payload.contains("l4=android.uid:1010001|"),
                "backend export exposes committed policy with tagged subjects");
        ProductStore.MutationResult applied = backend.applyCommittedPolicy();
        check(applied.persisted
                        && backend.policyTransactionStatus().runtimeRevision == first.revision
                        && backend.policyTransactionStatus().checkpointCount == 1,
                "backend apply creates runtime snapshot and checkpoint");
        check(appliedPayloads.toString().contains("\"revision\":1"),
                "backend explicit apply sends the committed revision to runtime");

        AuthoringPolicyBundle second = first.withL4Rule(
                l4Rule(app, "8.8.8.8/32", 6, 20, 1,
                        AuthoringPolicyBundle.L4Action.ALLOW));
        check(backend.importPolicyDraft(ProductPolicyTransactions.exportBundle(second))
                        .persisted,
                "backend can import a second Draft");
        check(backend.commitPolicyDraft().persisted
                        && backend.applyCommittedPolicy().persisted,
                "backend can commit and apply second imported policy");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 2
                        && backend.policyTransactionStatus().checkpointCount == 2,
                "backend second apply publishes ProductState and retains checkpoints");

        AuthoringPolicyBundle dirty = second.withL4Rule(
                l4Rule(app, "203.0.113.8/32", 17, 30, 2,
                        AuthoringPolicyBundle.L4Action.DROP));
        check(backend.importPolicyDraft(ProductPolicyTransactions.exportBundle(dirty))
                        .persisted,
                "backend can stage dirty Draft before restore");
        ProductStore.MutationResult dirtyRestore =
                backend.restorePolicyCheckpoint(first.revision);
        check(!dirtyRestore.persisted
                        && "restore_requires_clean_draft".equals(dirtyRestore.errorCode),
                "backend restore requires clean Draft");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 2
                        && backend.policyTransactionStatus().runtimeRevision == second.revision,
                "failed dirty backend restore leaves ProductState and runtime head unchanged");

        check(backend.importPolicyDraft(backend.exportCommittedPolicy().payload).persisted,
                "backend can clean Draft by importing current committed export");
        ProductStore.MutationResult restored =
                backend.restorePolicyCheckpoint(first.revision);
        check(restored.persisted
                        && backend.policyTransactionStatus().committedRevision == first.revision
                        && backend.policyTransactionStatus().runtimeRevision == first.revision
                        && backend.policyTransactionStatus().selectedCheckpointRevision
                        == first.revision,
                "backend restore atomically restores committed head and runtime status");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 1,
                "backend restore publishes restored bundle to ProductState");

        LocalProductBackend failingRestoreBackend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "injected_checkpoint_restore_failure",
                        "runtime rejected checkpoint restore"));
        ProductStore.MutationResult failedRestore =
                failingRestoreBackend.restorePolicyCheckpoint(second.revision);
        check(!failedRestore.persisted
                        && "injected_checkpoint_restore_failure".equals(
                        failedRestore.errorCode),
                "backend restore surfaces runtime restore failure");
        ProductPolicyTransactions.Status failedRestoreStatus =
                ProductPolicyTransactionStore.readResult(files.toFile())
                        .transactions.status();
        check(failedRestoreStatus.committedRevision == first.revision
                        && failedRestoreStatus.runtimeRevision == first.revision
                        && failedRestoreStatus.selectedCheckpointRevision == first.revision,
                "failed backend restore leaves durable transaction head unchanged");
        check(ProductStateStore.read(files.toFile()).authoringPolicyBundle.l4RuleCount == 1,
                "failed backend restore leaves durable ProductState unchanged");
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
        check(activity.activityItems().size() == 2,
                "activity store keeps ActivityItem projections bounded");
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

    private static void localProductBackendOwnsBoundedActivityStoreWriter() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-58-activity-writer");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                json -> LocalProductBackend.PolicyApplyResult.ok());
        backend.bindApplication(app);
        backend.setNetworkGate(app, AuthoringPolicyBundle.NetworkContextId.WIFI, true);

        ActivityItem drop = ActivityItem.policyDrop(app, "Mail", "com.example.mail",
                1000L, "1.1.1.1", "tcp", 443, "output", 7L,
                "NetworkGate", 0x5100000000000001L, 0x51000001);
        ActivityItem allowed = ActivityItem.allowedFlow(app, "Mail", "com.example.mail",
                1001L, "1.1.1.1", "tcp", 443, "output", "orig",
                5L, 2048L, 8L, "None");
        backend.ingestActivity(drop);
        backend.ingestActivity(allowed);

        check(backend.activityStore().capacity() == BoundedActivityStore.DEFAULT_CAPACITY,
                "LocalProductBackend owns the bounded Activity Store capacity");
        check(backend.recentActivity(app, 10).size() == 2,
                "LocalProductBackend is the Activity Store append/query seam");
        AppDetail detail = backend.appDetail(app,
                RuntimeSummary.fromSnapshot(RuntimeSnapshot.running(RuntimeProfile.ROOT,
                        "control-vnext", "1", "runtime", "arm64", "ok", 9L),
                        CapabilitySet.androidL4(true, true)), 10);
        check(detail.app != null && detail.app.subjectId.equals(app),
                "AppDetail reads app identity from backend catalog projection");
        check(detail.activity.size() == 2 && detail.rules.size() >= 1,
                "AppDetail combines backend-owned activity and rules");
        check(detail.prefillDraft != null,
                "backend app detail keeps Activity-derived L4 prefill available");

        ProductStateSnapshot restored = ProductStateStore.read(files.toFile());
        check(restored.boundApplications.contains(app),
                "Activity ingestion cannot mutate product binding state");
        check(restored.authoringPolicyBundle.gateEntryCount == 1,
                "Activity ingestion cannot mutate authoring policy state");
    }

    private static void productActivityProjectionStoreRoundTripsAppDetail() throws Exception {
        Path files = Files.createTempDirectory("sakamoto-58-activity-projection");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        app.userId, "Work", true)),
                json -> LocalProductBackend.PolicyApplyResult.ok());
        backend.bindApplication(app);
        backend.setL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                AuthoringPolicyBundle.L4Action.DROP));
        backend.ingestActivity(ActivityItem.policyDrop(app, "Mail", "com.example.mail",
                1000L, "1.1.1.1", "tcp", 443, "output", 7L,
                "L4", 0x5200000000000001L, 0x52000001));
        RuntimeSummary runtime = RuntimeSummary.fromSnapshot(RuntimeSnapshot.running(
                RuntimeProfile.ROOT, "control-vnext", "1", "runtime", "arm64",
                "ok", 9L), CapabilitySet.androidL4(true, true));
        AppDetail published = backend.refreshProductActivityProjection(app, runtime, 10);
        AppDetail restored = ProductActivityProjectionStore.read(files.toFile());

        check(ProductActivityProjectionStore.projectionFile(files.toFile()).getPath()
                        .contains("product-activity-projection"),
                "Activity projection uses its own UI/evidence repository");
        check(published.activity.size() == 1 && restored.activity.size() == 1,
                "Activity projection round-trips recent ActivityItem rows");
        check(restored.rules.size() == 1
                        && restored.rules.get(0).policyRevision
                        == published.rules.get(0).policyRevision,
                "Activity projection round-trips RuleView revision");
        check(restored.displayText.contains("Activity: 1")
                        && restored.displayText.contains("L4 prefill: available"),
                "Activity projection is directly renderable by the UI");
        check(backend.productActivityProjection().activity.size() == 1,
                "LocalProductBackend exposes the durable Activity projection read seam");
        check(!ProductActivityProjectionStore.projectionFile(files.toFile()).getPath()
                        .contains("product-state"),
                "Activity projection is separate from policy/config state");
    }

    private static void productActivityProjectionStoresProtocolRecognitionState()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-61-protocol-activity");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        ActivityItem detecting = ActivityItem.protocolRecognition(app, "Mail",
                "com.example.mail", 2000L, "93.184.216.34", "tcp", 443,
                "output", "orig", 2L, 256L, 7L,
                ActivityItem.PROTOCOL_RECOGNITION_DETECTING, "", "",
                "", 2);
        ActivityItem identified = ActivityItem.protocolRecognition(app, "Mail",
                "com.example.mail", 2500L, "93.184.216.34", "tcp", 443,
                "output", "reply", 4L, 1024L, 7L,
                ActivityItem.PROTOCOL_RECOGNITION_IDENTIFIED, "quic", "web",
                "1:http:orig,3:quic:reply", 3);
        ActivityItem unidentified = ActivityItem.protocolRecognition(app, "Mail",
                "com.example.mail", 3000L, "192.0.2.44", "udp", 5353,
                "output", "orig", 1L, 80L, 7L,
                ActivityItem.PROTOCOL_RECOGNITION_UNIDENTIFIED, "", "",
                "", 20);
        ActivityItem malformedSequence = ActivityItem.protocolRecognition(app, "Mail",
                "com.example.mail", 3500L, "192.0.2.55", "tcp", 443,
                "output", "orig", 3L, 384L, 7L,
                ActivityItem.PROTOCOL_RECOGNITION_IDENTIFIED, "tls", "web",
                "bad-token,5:tls:orig,nope:quic:reply", 5);
        RuntimeSummary runtime = RuntimeSummary.fromSnapshot(RuntimeSnapshot.running(
                RuntimeProfile.VPN, "control-vnext", "1", "runtime", "arm64",
                "ok", 9L), CapabilitySet.androidL4(true, true));
        AppDetail detail = AppDetail.normal(new AppSummary(app, "com.example.mail",
                "Mail", "Work", app.userId, app.uid, true, true,
                false, false, false, 0), runtime,
                Collections.emptyList(), Arrays.asList(detecting, identified, unidentified,
                        malformedSequence));
        ProductActivityProjectionStore.write(files.toFile(), detail);
        AppDetail restored = ProductActivityProjectionStore.read(files.toFile());

        check(restored.activity.size() == 4,
                "Activity projection preserves protocol recognition rows");
        ActivityItem restoredIdentified = restored.activity.get(1);
        ProtocolRecognitionSequence identifiedSequence =
                restoredIdentified.protocolRecognition.recognitionSequence;
        check(ActivityItem.PROTOCOL_RECOGNITION_IDENTIFIED.equals(
                        restoredIdentified.protocolRecognitionState)
                        && "quic".equals(restoredIdentified.applicationProtocolKey)
                        && "web".equals(restoredIdentified.applicationProtocolCategory)
                        && "1:http:orig,3:quic:reply".equals(
                        restoredIdentified.protocolRecognitionSequence)
                        && restoredIdentified.protocolPayloadPackets == 3,
                "identified Activity row round-trips latest exact result and full sequence");
        check(identifiedSequence.entries.size() == 2,
                "identified Activity row exposes typed protocol recognition sequence entries");
        ProtocolRecognitionSequence.Entry firstIdentifiedEntry =
                identifiedSequence.entries.get(0);
        ProtocolRecognitionSequence.Entry secondIdentifiedEntry =
                identifiedSequence.entries.get(1);
        check(firstIdentifiedEntry.payloadPacketSequence == 1L
                        && "http".equals(firstIdentifiedEntry.protocolKey)
                        && "orig".equals(firstIdentifiedEntry.flowDirection)
                        && secondIdentifiedEntry.payloadPacketSequence == 3L
                        && "quic".equals(secondIdentifiedEntry.protocolKey)
                        && "reply".equals(secondIdentifiedEntry.flowDirection),
                "identified Activity row exposes typed protocol recognition sequence fields");
        ActivityItem restoredDetecting = restored.activity.get(0);
        check(ActivityItem.PROTOCOL_RECOGNITION_DETECTING.equals(
                        restoredDetecting.protocolRecognitionState)
                        && restoredDetecting.protocolRecognition.recognitionSequence
                        .entries.isEmpty()
                        && ActivityItem.PROTOCOL_RECOGNITION_UNIDENTIFIED.equals(
                        restored.activity.get(2).protocolRecognitionState),
                "Activity rows can represent detecting, empty sequence and unidentified states");
        ActivityItem restoredMalformed = restored.activity.get(3);
        ProtocolRecognitionSequence malformedTypedSequence =
                restoredMalformed.protocolRecognition.recognitionSequence;
        check("bad-token,5:tls:orig,nope:quic:reply".equals(
                        restoredMalformed.protocolRecognitionSequence)
                        && malformedTypedSequence.entries.size() == 1,
                "malformed protocol recognition sequence preserves wire and skips bad entries");
        ProtocolRecognitionSequence.Entry malformedEntry =
                malformedTypedSequence.entries.get(0);
        check(malformedEntry.payloadPacketSequence == 5L
                        && "tls".equals(malformedEntry.protocolKey)
                        && "orig".equals(malformedEntry.flowDirection),
                "malformed protocol recognition sequence keeps parseable typed fields");
        check(restored.displayText.contains("recognition=identified")
                        && restored.displayText.contains("appProtocol=quic")
                        && restored.displayText.contains("category=web")
                        && restored.displayText.contains("lpiSequence=1:http:orig,3:quic:reply")
                        && restored.displayText.contains("payloadPackets=3"),
                "AppDetail renders protocol recognition state, latest protocol, category and sequence");
    }

    private static void productNativeActivityIngestorMapsRuntimeDropEvidence() {
        ProductNativeActivityIngestor.NativePolicyDropRecord rootDrop =
                new ProductNativeActivityIngestor.NativePolicyDropRecord(
                        3L, true, 1010001, true, 7,
                        "10.0.0.1", "192.0.2.1", 6, 40000, 443,
                        true, "output", "NetworkGate", 91, 7001L, 69L);
        check(ProductNativeActivityIngestor.shouldIngest(rootDrop, RuntimeProfile.ROOT,
                        null, -1L, 4L, 0L),
                "first native policy drop activity is ingested");
        check(!ProductNativeActivityIngestor.shouldIngest(rootDrop, RuntimeProfile.ROOT,
                        RuntimeProfile.ROOT, 4L, 4L, 3L),
                "same native policy drop total is not duplicated");
        check(ProductNativeActivityIngestor.shouldIngest(rootDrop, RuntimeProfile.VPN,
                        RuntimeProfile.ROOT, 4L, 4L, 3L),
                "profile switch resets native activity de-duplication");
        ActivityItem item = ProductNativeActivityIngestor.toActivityItem(rootDrop,
                RuntimeProfile.ROOT, 1234L);
        check(item.subjectId.equals(ApplicationSubjectId.fromUid(1010001))
                        && "drop".equals(item.verdict)
                        && "NetworkGate".equals(item.winner)
                        && "192.0.2.1".equals(item.remoteIp)
                        && "tcp".equals(item.protocol)
                        && item.remotePort == 443
                        && item.policyRevision == 69L
                        && item.ruleId == 7001L
                        && "native_policy_drop_activity".equals(item.evidenceSource)
                        && item.detailLossy,
                "native policyDropActivity maps to a product ActivityItem");

        ProductNativeActivityIngestor.NativePolicyDropRecord unknown =
                new ProductNativeActivityIngestor.NativePolicyDropRecord(
                        1L, true, 0, false, 0, "198.51.100.58", "10.111.0.2",
                        17, 53, 45658, true, "input", "L4", 17, 42L, 7L);
        ActivityItem unknownItem = ProductNativeActivityIngestor.toActivityItem(unknown,
                RuntimeProfile.VPN, 1235L);
        check("Unknown Application".equals(unknownItem.appLabel)
                        && "vpn_input".equals(
                        unknownItem.devicePacketDirection)
                        && "udp".equals(unknownItem.protocol)
                        && "198.51.100.58".equals(unknownItem.remoteIp)
                        && unknownItem.remotePort == 53,
                "unknown native attribution remains explicit in ActivityItem");

        ProductNativeActivityIngestor.NativeAllowedFlowRecord allowed =
                new ProductNativeActivityIngestor.NativeAllowedFlowRecord(
                        4L, true, 1010001, true, 7,
                        "10.0.0.1", "192.0.2.1", 6,
                        40000, 443, true, "output", "orig",
                        70L, 3L, 4500L, "", "", "", "", 0);
        check(ProductNativeActivityIngestor.shouldIngest(allowed, RuntimeProfile.ROOT,
                        RuntimeProfile.ROOT, 4L, 4L, 3L),
                "new native allowed FlowEntry total is ingested");
        ActivityItem allowedItem = ProductNativeActivityIngestor.toActivityItem(
                allowed, RuntimeProfile.ROOT, 1236L);
        check(allowedItem.subjectId.equals(ApplicationSubjectId.fromUid(1010001))
                        && "pass_next".equals(allowedItem.verdict)
                        && "flow_entry".equals(allowedItem.evidenceSource)
                        && !allowedItem.detailLossy
                        && "192.0.2.1".equals(allowedItem.remoteIp)
                        && allowedItem.remotePort == 443
                        && "tcp".equals(allowedItem.protocol)
                        && "output".equals(allowedItem.devicePacketDirection)
                        && "orig".equals(allowedItem.flowDirection)
                        && allowedItem.policyRevision == 70L
                        && allowedItem.packets == 3L
                        && allowedItem.bytes == 4500L,
                "native allowed FlowEntry maps to a product ActivityItem");

        ProductNativeActivityIngestor.NativeAllowedFlowRecord recognized =
                new ProductNativeActivityIngestor.NativeAllowedFlowRecord(
                        5L, true, 1010001, true, 7,
                        "10.0.0.1", "192.0.2.1", 17,
                        53000, 443, true, "output", "reply",
                        71L, 4L, 5200L,
                        ActivityItem.PROTOCOL_RECOGNITION_IDENTIFIED,
                        "quic", "web", "1:http:orig,4:quic:reply", 4);
        ActivityItem recognizedItem = ProductNativeActivityIngestor.toActivityItem(
                recognized, RuntimeProfile.VPN, 1237L);
        check(recognizedItem.subjectId.equals(ApplicationSubjectId.fromUid(1010001))
                        && "pass_next".equals(recognizedItem.verdict)
                        && "flow_entry_lpi_recognition".equals(
                        recognizedItem.evidenceSource)
                        && ActivityItem.PROTOCOL_RECOGNITION_IDENTIFIED.equals(
                        recognizedItem.protocolRecognitionState)
                        && "quic".equals(recognizedItem.applicationProtocolKey)
                        && "web".equals(recognizedItem.applicationProtocolCategory)
                        && "1:http:orig,4:quic:reply".equals(
                        recognizedItem.protocolRecognitionSequence)
                        && recognizedItem.protocolPayloadPackets == 4
                        && "udp".equals(recognizedItem.protocol)
                        && "vpn_output".equals(recognizedItem.devicePacketDirection)
                        && "reply".equals(recognizedItem.flowDirection),
                "native allowed FlowEntry recognition state maps to protocol ActivityItem");
    }

    private static void activityL4RuleDraftPrefillsFromPolicyDropEvidence() {
        ActivityL4RuleDraft draft = ActivityL4RuleDraft.fromPolicyDropActivity(
                "1.1.1.1", 443, ActivityL4RuleDraft.TCP_PROTOCOL, 1010001, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4");
        check(draft != null, "L4 policy drop Activity can create an L4 prefill draft");
        check(draft.subjectId.equals(ApplicationSubjectId.fromUid(1010001)),
                "L4 prefill draft preserves complete UID subject");
        check(draft.family == AuthoringPolicyBundle.IpFamily.IPV4
                        && "1.1.1.1/32".equals(draft.destinationCidr),
                "L4 prefill draft derives IPv4 destination CIDR from probe host");
        check(draft.destinationPorts.first == 443 && draft.destinationPorts.last == 443,
                "L4 prefill draft derives exact destination port from probe");
        check(draft.ipProtocol == ActivityL4RuleDraft.TCP_PROTOCOL
                        && draft.direction == AuthoringPolicyBundle.PacketDirection.OUTPUT
                        && draft.action == AuthoringPolicyBundle.L4Action.DROP,
                "L4 prefill draft sets TCP/output/drop defaults from the probe context");
        check(draft.networkContext == AuthoringPolicyBundle.NetworkContextId.WIFI,
                "L4 prefill draft maps Activity network context to Product context");
        AuthoringPolicyBundle.L4Rule rule = draft.toRule();
        check(rule.subjectId.equals(draft.subjectId)
                        && "1.1.1.1/32".equals(rule.destinationCidr)
                        && rule.destinationPorts.first == 443,
                "L4 prefill draft materializes as a Product L4Rule");
        check(draft.summary().contains("L4 prefill: subject=android.uid:1010001")
                        && draft.summary().contains("destinationPort=443"),
                "L4 prefill draft renders an actionable UI summary");

        ActivityL4RuleDraft udp = ActivityL4RuleDraft.fromPolicyDropActivity(
                "1.1.1.1", 53, ActivityL4RuleDraft.UDP_PROTOCOL, 1010001, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4");
        check(udp != null && udp.ipProtocol == ActivityL4RuleDraft.UDP_PROTOCOL
                        && udp.destinationPorts.first == 53
                        && udp.summary().contains("ipProtocol=17"),
                "L4 prefill draft supports UDP policy drop Activity evidence");

        ActivityL4RuleDraft v6 = ActivityL4RuleDraft.fromTcpPolicyDropActivity(
                "2606:4700:4700::1111", 80, 1010001, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4");
        check(v6 != null && v6.family == AuthoringPolicyBundle.IpFamily.IPV6
                        && "2606:4700:4700::1111/128".equals(v6.destinationCidr),
                "L4 prefill draft derives IPv6 destination CIDR from probe host");
        check(ActivityL4RuleDraft.fromTcpPolicyDropActivity(
                "1.1.1.1", 443, 1010001, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "NetworkGate") == null,
                "NetworkGate Activity does not masquerade as an L4 prefill");
        check(ActivityL4RuleDraft.fromTcpPolicyDropActivity(
                "1.1.1.1", 443, 1010001, false,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4") == null,
                "unknown UID Activity cannot create an application-scoped L4 prefill");
        check(ActivityL4RuleDraft.fromPolicyDropActivity(
                "1.1.1.1", 443, 1, 1010001, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4") == null,
                "unsupported protocol Activity cannot create an L4 prefill");
    }

    private static void productCatalogFormatterKeepsUidIdentitySeparateFromMetadata() {
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        java.util.TreeSet<ApplicationSubjectId> bound = new java.util.TreeSet<>();
        bound.add(work);
        AuthoringPolicyBundle gates = AuthoringPolicyBundle.empty()
                .withNetworkGate(primary, AuthoringPolicyBundle.NetworkContextId.WIFI, true)
                .withNetworkGate(primary, AuthoringPolicyBundle.NetworkContextId.MOBILE, false)
                .withNetworkGate(work, AuthoringPolicyBundle.NetworkContextId.VPN, true)
                .withL4Rule(AuthoringPolicyBundle.L4Rule.create(work,
                        AuthoringPolicyBundle.IpFamily.IPV4, "", "1.1.1.1/32",
                        null, AuthoringPolicyBundle.PortRange.exact(443), 6,
                        AuthoringPolicyBundle.PacketDirection.OUTPUT,
                        AuthoringPolicyBundle.NetworkContextId.WIFI,
                        AuthoringPolicyBundle.L4Action.DROP, 10, 0));
        ProductStateSnapshot state = new ProductStateSnapshot(RuntimeProfile.VPN, bound,
                gates);
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
        check(projection.rows.get(0).l4RuleCount == 0
                        && projection.rows.get(1).l4RuleCount == 1,
                "Product UI projection renders per-row L4 rule count");
        check(projection.boundApplicationCount == 1,
                "Product UI projection renders bound application count");
        check(projection.rows.get(0).wifiGateBlocked
                        && !projection.rows.get(0).mobileGateBlocked
                        && !projection.rows.get(0).vpnGateBlocked,
                "Product UI projection renders per-row Wi-Fi/Mobile/VPN Gate state");
        check("Open wifi".equals(projection.rows.get(0).networkGateButtonLabel(
                        AuthoringPolicyBundle.NetworkContextId.WIFI))
                        && "Block mobile".equals(projection.rows.get(0).networkGateButtonLabel(
                        AuthoringPolicyBundle.NetworkContextId.MOBILE)),
                "Product UI projection exposes app-row Gate toggle labels");
        check(!projection.rows.get(0).canToggleGate(),
                "Product UI disables Gate toggle for available but unbound application rows");
        check(projection.displayText.contains("gate wifi=blocked mobile=open vpn=open"),
                "Product UI projection display text includes app-row Gate state");
        check(projection.displayText.contains("l4Rules=1"),
                "Product UI projection display text includes app-row L4 rule state");
        check(projection.firstBoundSubjectId.equals(work),
                "unbind candidate is the bound ApplicationSubjectId");
        check(projection.firstAvailableSubjectId.equals(primary),
                "bind candidate is the first available ApplicationSubjectId, not packageName");
        ProductCatalogFormatter.Projection nextCandidate =
                ProductCatalogFormatter.result(new ProductStateSnapshot(RuntimeProfile.VPN,
                        new java.util.TreeSet<>(Arrays.asList(primary)),
                        gates), catalog);
        check(nextCandidate.firstAvailableSubjectId == null,
                "bind candidate skips already-bound available ApplicationSubjectId");
        check(nextCandidate.rows.get(0).canToggleGate(),
                "Product UI enables Gate toggle for bound available application rows");
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

    private static void localProductBackendAppliesGateMatrixBeforePersistingProductState()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-51-backend-apply");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(10001);
        final StringBuilder appliedPayload = new StringBuilder();
        LocalProductBackend backend = new LocalProductBackend(files.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u0",
                        0, "Owner", true)),
                payload -> {
                    appliedPayload.append(payload);
                    return LocalProductBackend.PolicyApplyResult.ok();
                });

        ProductStore.MutationResult blocked = backend.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.MOBILE, true);
        check(blocked.persisted,
                "Local Product Backend persists Network Gate only after runtime apply succeeds");
        check(appliedPayload.toString().contains("\"cmd\"") == false,
                "policy transport receives POLICY.APPLY args, not a framed request");
        check(appliedPayload.toString().contains("\"networkContext\":2"),
                "runtime apply payload carries the blocked Mobile NetworkContextId");
        ProductStateSnapshot persisted = ProductStateStore.read(files.toFile());
        check(persisted.authoringPolicyBundle.gateEntryCount == 1,
                "successful runtime apply publishes Product GateMatrix state");

        Path failedFiles = Files.createTempDirectory("sakamoto-51-backend-apply-fail");
        final StringBuilder failedPayload = new StringBuilder();
        LocalProductBackend failingBackend = new LocalProductBackend(failedFiles.toFile(),
                () -> Arrays.asList(new ApplicationCatalogEntry(app,
                        "com.example.mail", "Mail", "icon:mail/u0",
                        0, "Owner", true)),
                payload -> {
                    failedPayload.append(payload);
                    return LocalProductBackend.PolicyApplyResult.error(
                            "POLICY_APPLY_REJECTED", "synthetic apply failure");
                });
        ProductStore.MutationResult rejected = failingBackend.setNetworkGate(app,
                AuthoringPolicyBundle.NetworkContextId.VPN, true);
        check(!rejected.persisted,
                "Local Product Backend does not persist Network Gate after runtime apply failure");
        check("POLICY_APPLY_REJECTED".equals(rejected.errorCode),
                "runtime apply failure is surfaced as the product mutation error");
        ProductStateStore.ReadResult absent =
                ProductStateStore.readResult(failedFiles.toFile());
        check(!absent.present && absent.snapshot.authoringPolicyBundle.isEmpty(),
                "failed runtime apply leaves durable product state unchanged");
        check(failedPayload.toString().contains("\"networkContext\":3"),
                "failed runtime apply still used the candidate VPN GateMatrix payload");
    }

    private static void productCatalogProjectionStoreRoundTripsSamePackageTwoProfileRows()
            throws Exception {
        Path files = Files.createTempDirectory("sakamoto-50-product-projection");
        ApplicationSubjectId primary = ApplicationSubjectId.fromUid(10001);
        ApplicationSubjectId work = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle gates = AuthoringPolicyBundle.empty()
                .withNetworkGate(primary, AuthoringPolicyBundle.NetworkContextId.WIFI, true)
                .withNetworkGate(work, AuthoringPolicyBundle.NetworkContextId.VPN, true);
        ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.result(
                new ProductStateSnapshot(RuntimeProfile.VPN,
                        new java.util.TreeSet<>(Arrays.asList(work)),
                        gates),
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
        check(restored.projection.selectableRows.get(0).wifiGateBlocked
                        && restored.projection.selectableRows.get(1).vpnGateBlocked,
                "projection store round-trips per-row Network Gate state");
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

    private static void productPolicyTransactionsSeparateDraftCommitApplyAndCheckpoint() {
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        ProductPolicyTransactions tx = new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        check(!tx.status().draftDirty && tx.status().runtimeRevision == 0L
                        && "empty".equals(tx.status().runtimeSnapshotState),
                "S53 transaction status exposes clean Draft, committed head and empty runtime");

        AuthoringPolicyBundle first = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        check(tx.replaceDraft(first).ok, "S53 can edit Draft without applying runtime");
        check(tx.status().draftDirty && tx.status().draftRevision == 1L
                        && tx.status().committedRevision == 0L,
                "Draft edit does not move committed policy revision");
        check(!tx.applyCommitted(payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "Apply refuses uncommitted Draft changes");

        ProductPolicyTransactions.Result committed = tx.commitDraft();
        check(committed.ok && !tx.status().draftDirty
                        && tx.status().committedRevision == 1L,
                "Commit publishes committed revision and makes Draft clean");
        final String[] appliedPayload = {""};
        check(tx.applyCommitted(payload -> {
            appliedPayload[0] = payload;
            return LocalProductBackend.PolicyApplyResult.ok();
        }).ok, "Apply compiles committed bundle before publishing runtime");
        check(appliedPayload[0].contains("\"revision\":1")
                        && tx.status().runtimeRevision == 1L
                        && tx.status().checkpointCount == 1,
                "successful Apply publishes runtime revision and creates one checkpoint");

        AuthoringPolicyBundle second = first.withL4Rule(l4Rule(app, "8.8.8.8/32", 6, 20, 1,
                AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(second);
        tx.commitDraft();
        ProductPolicyTransactions.Result failedApply = tx.applyCommitted(
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "injected_apply_failure", "runtime rejected policy"));
        check(!failedApply.ok && "injected_apply_failure".equals(failedApply.errorCode),
                "failed Apply returns actionable runtime failure");
        check(tx.status().committedRevision == 2L
                        && tx.status().runtimeRevision == 1L
                        && tx.status().checkpointCount == 1,
                "failed Apply does not create checkpoint or replace old runtime snapshot");

        for (int order = 2; order < 8; order++) {
            AuthoringPolicyBundle next = tx.committed().withL4Rule(
                    l4Rule(app, "198.51.100." + order + "/32", 6, 30 + order, order,
                            AuthoringPolicyBundle.L4Action.DROP));
            tx.replaceDraft(next);
            tx.commitDraft();
            check(tx.applyCommitted(payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                    "successful Apply keeps advancing checkpoint ring");
        }
        check(tx.status().checkpointCount == ProductPolicyTransactions.MAX_CHECKPOINTS,
                "S53 retains only the latest five full checkpoints");
        check(tx.checkpoints().get(0).revision == 4L,
                "checkpoint retention evicts the oldest full snapshot after capacity");
    }

    private static void productPolicyTransactionRestoreAndImportExportAreAtomic() {
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        ProductPolicyTransactions tx = new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        AuthoringPolicyBundle first = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(first);
        tx.commitDraft();
        check(tx.applyCommitted(payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "first committed bundle can be applied");
        long firstRuntime = tx.status().runtimeRevision;

        AuthoringPolicyBundle dirty = tx.committed().withL4Rule(
                l4Rule(app, "8.8.8.8/32", 6, 20, 1,
                        AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(dirty);
        check(!tx.restoreCheckpoint(firstRuntime,
                        payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "Checkpoint Restore requires a clean Draft");
        check(tx.status().draftDirty && tx.status().runtimeRevision == firstRuntime,
                "failed dirty restore preserves Draft and runtime state");
        tx.commitDraft();
        ProductPolicyTransactions.Result failedRestore = tx.restoreCheckpoint(firstRuntime,
                payload -> LocalProductBackend.PolicyApplyResult.error(
                        "restore_runtime_failed", "runtime rejected checkpoint"));
        check(!failedRestore.ok && tx.status().committedRevision == dirty.revision
                        && tx.status().runtimeRevision == firstRuntime,
                "failed Checkpoint Restore keeps committed head and runtime unchanged");
        check(tx.restoreCheckpoint(firstRuntime,
                        payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "clean Checkpoint Restore can atomically restore bundle and runtime");
        check(tx.status().committedRevision == firstRuntime
                        && tx.status().runtimeRevision == firstRuntime
                        && tx.status().selectedCheckpointRevision == firstRuntime
                        && !tx.status().draftDirty,
                "successful Checkpoint Restore restores clean Draft, committed head and runtime");

        String exported = tx.exportCommitted();
        check(exported.startsWith(ProductPolicyTransactions.EXPORT_HEADER)
                        && exported.contains("l4=android.uid:1010001|"),
                "policy export preserves tagged ApplicationSubjectId and typed L4 family");
        ProductPolicyTransactions.ImportResult imported =
                ProductPolicyTransactions.importBundle(exported);
        check(imported.ok && imported.bundle.l4RuleCount == 1
                        && imported.bundle.l4Rules.get(0).ruleId
                        == tx.committed().l4Rules.get(0).ruleId
                        && "1.1.1.1/32".equals(imported.bundle.l4Rules.get(0).destinationCidr),
                "policy import preserves stable IDs and user-authored CIDR intent");
        check(!ProductPolicyTransactions.importBundle("bad").ok,
                "illegal policy import returns actionable failure instead of partial state");
        ProductPolicyTransactions.Result importedDraft = tx.importDraft(exported);
        check(importedDraft.ok && !tx.status().draftDirty,
                "importing current committed export keeps Draft clean");
        ProductPolicyTransactions.Result badImport = tx.importDraft("bad");
        check(!badImport.ok && !tx.status().draftDirty
                        && tx.status().committedRevision == firstRuntime,
                "failed import keeps Draft and committed head unchanged");

        AuthoringPolicyBundle duplicate = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "203.0.113.7/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP))
                .withL4Rule(l4Rule(app, "203.0.113.7/32", 6, 10, 1,
                        AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(duplicate);
        ProductPolicyTransactions.Result duplicateCommit = tx.commitDraft();
        check(duplicateCommit.ok && !duplicateCommit.issues.isEmpty()
                        && "duplicate_match_warning".equals(
                        duplicateCommit.issues.get(0).code),
                "duplicate match validation is a non-blocking warning with source attribution");
    }

    private static void productPolicyTransactionStorePersistsDraftCommitRuntimeAndCheckpoints()
            throws IOException {
        Path files = Files.createTempDirectory("sakamoto-53-policy-transactions");
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        ProductPolicyTransactionStore.ReadResult absent =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(!absent.present && absent.valid
                        && absent.transactions.status().runtimeRevision == 0L,
                "missing policy transaction store is a valid empty transaction state");

        ProductPolicyTransactions tx =
                new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        AuthoringPolicyBundle first = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(first);
        tx.commitDraft();
        check(tx.applyCommitted(payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "first persisted transaction checkpoint can apply");
        AuthoringPolicyBundle second = tx.committed().withL4Rule(
                l4Rule(app, "8.8.8.8/32", 6, 20, 1,
                        AuthoringPolicyBundle.L4Action.ALLOW));
        tx.replaceDraft(second);
        tx.commitDraft();
        check(tx.applyCommitted(payload -> LocalProductBackend.PolicyApplyResult.ok()).ok,
                "second persisted transaction checkpoint can apply");
        AuthoringPolicyBundle dirtyDraft = tx.committed().withL4Rule(
                l4Rule(app, "203.0.113.8/32", 17, 30, 2,
                        AuthoringPolicyBundle.L4Action.DROP));
        tx.replaceDraft(dirtyDraft);

        ProductPolicyTransactionStore.write(files.toFile(), tx);
        ProductPolicyTransactionStore.ReadResult read =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(read.present && read.valid, "policy transaction store reads persisted state");
        ProductPolicyTransactions restored = read.transactions;
        check(restored.status().draftDirty
                        && restored.status().draftRevision == dirtyDraft.revision
                        && restored.status().committedRevision == second.revision
                        && restored.status().runtimeRevision == second.revision
                        && restored.status().selectedCheckpointRevision == second.revision
                        && "applied".equals(restored.status().runtimeSnapshotState),
                "policy transaction store preserves Draft, committed, runtime and snapshot status");
        check(restored.checkpoints().size() == 2
                        && restored.checkpoints().get(1).revision == second.revision
                        && restored.checkpoints().get(1).applyPayload.contains("\"revision\":2"),
                "policy transaction store preserves full checkpoint bundles and apply payloads");
        check(restored.committed().l4RuleCount == 2
                        && restored.committed().l4Rules.get(0).ruleId
                        == second.l4Rules.get(0).ruleId
                        && restored.draft().l4RuleCount == 3,
                "policy transaction store preserves stable L4 rule IDs and dirty Draft intent");

        Files.write(ProductPolicyTransactionStore.stateFile(files.toFile()).toPath(),
                "schemaVersion=99\n".getBytes(StandardCharsets.US_ASCII));
        ProductPolicyTransactionStore.ReadResult unsupported =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(!unsupported.valid && unsupported.present
                        && "policy_transactions_unsupported_schema".equals(
                        unsupported.errorCode),
                "unsupported policy transaction schema returns actionable failure");

        Files.write(ProductPolicyTransactionStore.stateFile(files.toFile()).toPath(),
                "schemaVersion=1\ncheckpointCount=9\n".getBytes(StandardCharsets.US_ASCII));
        ProductPolicyTransactionStore.ReadResult corrupt =
                ProductPolicyTransactionStore.readResult(files.toFile());
        check(!corrupt.valid && "policy_transactions_corrupt".equals(corrupt.errorCode),
                "corrupt policy transaction store returns actionable failure");
    }

    private static void productPolicyCommitValidationRejectsConflictsAndStaleBindings() {
        ApplicationSubjectId app = ApplicationSubjectId.fromUid(1010001);
        ApplicationSubjectId stale = ApplicationSubjectId.fromUid(1010002);
        AuthoringPolicyBundle localCommitted = AuthoringPolicyBundle.empty()
                .withL4Rule(l4Rule(app, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        ProductPolicyTransactions tx = new ProductPolicyTransactions(localCommitted);
        tx.replaceDraft(AuthoringPolicyBundle.restore(localCommitted.revision,
                "imported-policy-file", localCommitted.gateMatrix, localCommitted.l4Rules, 0));
        ProductPolicyTransactions.Result sourceConflict = tx.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(
                        new ProductStateSnapshot(RuntimeProfile.ROOT,
                                new java.util.TreeSet<>(Arrays.asList(app)),
                                localCommitted),
                        Arrays.asList(new ApplicationCatalogEntry(app,
                                "com.example.mail", "Mail", "icon:mail/u10",
                                app.userId, "Work", true))));
        check(!sourceConflict.ok
                        && "source_conflict".equals(sourceConflict.errorCode)
                        && sourceConflict.errorMessage.contains("source=imported-policy-file"),
                "commit validation rejects source conflicts with stable attribution");

        ProductPolicyTransactions unboundTx =
                new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        unboundTx.replaceDraft(localCommitted);
        ProductPolicyTransactions.Result bindingConflict = unboundTx.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(
                        ProductStateSnapshot.empty(),
                        Arrays.asList(new ApplicationCatalogEntry(app,
                                "com.example.mail", "Mail", "icon:mail/u10",
                                app.userId, "Work", true))));
        check(!bindingConflict.ok
                        && "binding_mode_conflict".equals(bindingConflict.errorCode)
                        && bindingConflict.errorMessage.contains("android.uid:1010001"),
                "commit validation rejects policy subjects that are not explicitly bound");

        ProductPolicyTransactions staleTx =
                new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        staleTx.replaceDraft(localCommitted);
        java.util.TreeSet<ApplicationSubjectId> bound = new java.util.TreeSet<>();
        bound.add(app);
        bound.add(stale);
        ProductPolicyTransactions.Result staleBinding = staleTx.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(
                        new ProductStateSnapshot(RuntimeProfile.ROOT, bound, localCommitted),
                        Arrays.asList(
                                new ApplicationCatalogEntry(app,
                                        "com.example.mail", "Mail", "icon:mail/u10",
                                        app.userId, "Work", true),
                                new ApplicationCatalogEntry(stale,
                                        "com.example.old", "Old", "icon:old/u10",
                                        stale.userId, "Work", false))));
        check(!staleBinding.ok
                        && "stale_binding".equals(staleBinding.errorCode)
                        && staleBinding.errorMessage.contains("android.uid:1010002"),
                "commit validation rejects stale bound applications before publishing");

        ProductPolicyTransactions validTx =
                new ProductPolicyTransactions(AuthoringPolicyBundle.empty());
        validTx.replaceDraft(localCommitted);
        ProductPolicyTransactions.Result valid = validTx.commitDraft(
                ProductPolicyTransactions.CommitValidationContext.of(
                        new ProductStateSnapshot(RuntimeProfile.ROOT,
                                new java.util.TreeSet<>(Arrays.asList(app)),
                                localCommitted),
                        Arrays.asList(new ApplicationCatalogEntry(app,
                                "com.example.mail", "Mail", "icon:mail/u10",
                                app.userId, "Work", true))));
        check(valid.ok && validTx.status().committedRevision == localCommitted.revision,
                "commit validation accepts bound current catalog subjects");
    }

    private static void appFirstProductUiModelsExposeStableUserFacingSeams() {
        CapabilitySet capabilities = CapabilitySet.androidL4(true, true);
        check(capabilities.rootProfile && capabilities.vpnProfile
                        && capabilities.profileSwitching && capabilities.networkGate
                        && capabilities.l4Rules && capabilities.activity
                        && !capabilities.protocolRules,
                "Android L4 capability set is explicit and protocol rules remain future work");

        RuntimeSnapshot running = RuntimeSnapshot.running(RuntimeProfile.VPN,
                "control-vnext", "1", "runtime", "arm64", "ok", 4242L, 9L);
        RuntimeSummary summary = RuntimeSummary.fromSnapshot(running, capabilities);
        check(summary.selectedProfile == RuntimeProfile.VPN
                        && RuntimeSnapshot.STATE_RUNNING.equals(summary.state)
                        && summary.healthyForPolicyApply()
                        && !summary.healthIssue.present(),
                "RuntimeSummary projects running profile without exposing runtime internals");

        RuntimeSummary paused = RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.paused(RuntimeProfile.ROOT, 10L), capabilities);
        check(paused.paused
                        && HealthIssue.CATEGORY_PAUSED.equals(paused.healthIssue.category)
                        && paused.healthIssue.action.contains("Resume protection"),
                "HealthIssue maps user pause to an actionable product state");
        RuntimeSummary permission = RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.error(RuntimeProfile.ROOT, "", "", "", "",
                        "root_authorization_required", "Root permission missing",
                        false, -1L), capabilities);
        check(HealthIssue.CATEGORY_PERMISSION.equals(permission.healthIssue.category),
                "HealthIssue maps permission failure without calling it a runtime crash");
        RuntimeSummary transport = RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.error(RuntimeProfile.VPN, "", "", "", "",
                        "vpn_hev_transport_start_failed", "HEV failed",
                        false, -1L), capabilities);
        check(HealthIssue.CATEGORY_TRANSPORT_FAILURE.equals(transport.healthIssue.category),
                "HealthIssue keeps VPN transport failures separate from policy verdicts");
        RuntimeSummary runtimeFault = RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.error(RuntimeProfile.ROOT, "", "", "", "",
                        "cleanup_failed", "profile residue remains",
                        true, 4242L), capabilities);
        check(HealthIssue.CATEGORY_RUNTIME_FAULT.equals(runtimeFault.healthIssue.category),
                "HealthIssue maps cleanup failures to runtime fault state");
        RuntimeSummary recovery = RuntimeSummary.fromSnapshot(
                RuntimeSnapshot.error(RuntimeProfile.ROOT, "", "", "", "",
                        "runtime_auto_recovery_pending", "recovering",
                        true, 4242L), capabilities);
        check(recovery.recovering
                        && HealthIssue.CATEGORY_RECOVERY.equals(recovery.healthIssue.category),
                "HealthIssue maps recovery into a distinct recovery state");
        HealthIssue applyFailure = HealthIssue.applyFailure(
                "product_policy_runtime_unavailable", "runtime is unavailable");
        check(HealthIssue.CATEGORY_APPLY_FAILURE.equals(applyFailure.category)
                        && applyFailure.action.contains("previous snapshot"),
                "apply failure keeps the previous snapshot visible");

        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle bundle = AuthoringPolicyBundle.empty()
                .withNetworkGate(subject, AuthoringPolicyBundle.NetworkContextId.WIFI, true)
                .withL4Rule(l4Rule(subject, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        ProductCatalogFormatter.EntryRow row = ProductCatalogFormatter.project(
                new ProductStateSnapshot(RuntimeProfile.ROOT,
                        new java.util.TreeSet<>(Arrays.asList(subject)), bundle),
                Arrays.asList(new ApplicationCatalogEntry(subject,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        subject.userId, "Work", true)),
                "result", "", "", 5).selectableRows.get(0);
        AppSummary app = AppSummary.fromCatalogRow(row);
        check(app.subjectId.equals(subject) && app.bound && app.wifiGateBlocked
                        && app.l4RuleCount == 1,
                "AppSummary preserves complete UID identity and product controls");

        AuthoringPolicyBundle.NetworkGateRule gateRule = bundle.gateMatrix.get(0);
        RuleView gate = RuleView.networkGate(gateRule, bundle.revision);
        RuleView l4 = RuleView.l4(bundle.l4Rules.get(0), bundle.revision);
        check("network_gate".equals(gate.family) && "drop".equals(gate.action)
                        && gate.policyRevision == bundle.revision
                        && "l4".equals(l4.family),
                "RuleView exposes stable family/action/revision instead of compiler details");

        ActivityItem drop = ActivityItem.policyDrop(subject, "Mail",
                "com.example.mail", 1234L, "1.1.1.1", "tcp", 443,
                "output", bundle.revision, "L4", l4.ruleId, 42);
        ActivityItem allowed = ActivityItem.allowedFlow(subject, "Mail",
                "com.example.mail", 1235L, "1.1.1.1", "tcp", 443,
                "output", "orig", 7L, 4096L, bundle.revision, "None");
        check(drop.detailLossy
                        && "bounded_activity_accumulator".equals(drop.evidenceSource)
                        && drop.canPrefillL4Rule()
                        && !allowed.detailLossy
                        && "flow_entry".equals(allowed.evidenceSource)
                        && allowed.packets == 7L && allowed.bytes == 4096L,
                "ActivityItem separates bounded DROP detail from allowed FlowEntry evidence");

        ActivityL4RuleDraft activityDraft = ActivityL4RuleDraft.fromPolicyDropActivity(
                "1.1.1.1", 443, ActivityL4RuleDraft.TCP_PROTOCOL, subject.uid, true,
                AuthoringPolicyBundle.NetworkContextId.WIFI.wireId, "L4");
        RuleDraft draft = RuleDraft.fromActivityL4RuleDraft(activityDraft);
        check(draft != null && draft.subjectId.equals(subject)
                        && "activity".equals(draft.source)
                        && draft.toL4Rule().subjectId.equals(subject),
                "RuleDraft can prefill an L4 rule from Activity evidence");

        AppDetail detail = AppDetail.normal(app, summary,
                Arrays.asList(gate, l4), Arrays.asList(drop, allowed));
        check(AppDetail.STATE_NORMAL.equals(detail.state)
                        && detail.rules.size() == 2
                        && detail.activity.size() == 2
                        && detail.prefillDraft != null,
                "AppDetail combines app, rules, activity, health, and prefill state");
        check(AppDetail.loading(summary).rules.isEmpty()
                        && AppDetail.error(summary, applyFailure).healthIssue.blocking,
                "AppDetail covers loading and actionable error states");
        RuntimeSummary loadingSummary = new RuntimeSummary(RuntimeProfile.ROOT,
                RuntimeSnapshot.STATE_STARTING, "starting", "unavailable",
                false, true, false, false, capabilities, HealthIssue.none());
        check(AppDetail.STATE_EMPTY.equals(AppDetail.normal(null, summary,
                        Collections.emptyList(), Collections.emptyList()).state)
                        && AppDetail.STATE_LOADING.equals(AppDetail.normal(app,
                        loadingSummary, Collections.emptyList(),
                        Collections.emptyList()).state),
                "AppDetail distinguishes empty and loading product states");
        for (RuntimeSummary issueSummary : Arrays.asList(permission, transport,
                runtimeFault, recovery, paused)) {
            AppDetail issueDetail = AppDetail.normal(app, issueSummary,
                    Collections.emptyList(), Collections.emptyList());
            check(AppDetail.STATE_ERROR.equals(issueDetail.state)
                            && issueDetail.healthIssue.present()
                            && issueDetail.displayText.contains(
                            issueDetail.healthIssue.category),
                    "AppDetail renders permission/fault/transport/pause/recovery states");
        }
        AppDetail applyFailureDetail = AppDetail.error(summary, applyFailure);
        check(AppDetail.STATE_ERROR.equals(applyFailureDetail.state)
                        && applyFailureDetail.displayText.contains(
                        HealthIssue.CATEGORY_APPLY_FAILURE),
                "AppDetail renders apply failure with old snapshot guidance");
    }

    private static void releaseDiagnosticsExportIsDesensitizedAndFeedbackReady() {
        ApplicationSubjectId subject = ApplicationSubjectId.fromUid(1010001);
        AuthoringPolicyBundle bundle = AuthoringPolicyBundle.empty()
                .withNetworkGate(subject, AuthoringPolicyBundle.NetworkContextId.WIFI, true)
                .withL4Rule(l4Rule(subject, "1.1.1.1/32", 6, 10, 0,
                        AuthoringPolicyBundle.L4Action.DROP));
        ProductCatalogFormatter.Projection projection = ProductCatalogFormatter.project(
                new ProductStateSnapshot(RuntimeProfile.VPN,
                        new java.util.TreeSet<>(Arrays.asList(subject)), bundle),
                Arrays.asList(new ApplicationCatalogEntry(subject,
                        "com.example.mail", "Mail", "icon:mail/u10",
                        subject.userId, "Work", true)),
                "result", "", "", 5);
        ProductCatalogFormatter.EntryRow row = projection.selectableRows.get(0);
        RuntimeSnapshot runtime = RuntimeSnapshot.running(RuntimeProfile.VPN,
                "control-vnext", "1", "runtime-arm64", "arm64", "ok", 4242L, 9L);
        RuntimeSummary summary = RuntimeSummary.fromSnapshot(runtime,
                CapabilitySet.androidL4(true, true));
        AppDetail detail = AppDetail.normal(AppSummary.fromCatalogRow(row), summary,
                Arrays.asList(RuleView.l4(bundle.l4Rules.get(0), bundle.revision)),
                Arrays.asList(ActivityItem.policyDrop(subject, "Mail",
                        "com.example.mail", 1234L, "1.1.1.1", "tcp", 443,
                        "output", bundle.revision, "L4",
                        bundle.l4Rules.get(0).ruleId, 42)));

        String export = ReleaseDiagnosticsExport.format(runtime, projection, detail, row,
                123456789L);
        check(export.contains("schema=sakamoto.android_l4.release_diagnostics.v1"),
                "release diagnostics schema is stable");
        check(export.contains("privacy=desensitized_no_payload_no_keys")
                        && export.contains("payload=not_exported")
                        && export.contains("keys=not_exported"),
                "release diagnostics declares desensitized no-payload/no-key policy");
        check(export.contains("runtime.profile=vpn")
                        && export.contains("runtime.coreHealth=ok")
                        && export.contains("runtime.abi=arm64")
                        && export.contains("selected.subject=" + subject.encode())
                        && export.contains("appDetail.activity=1"),
                "release diagnostics includes bounded troubleshooting facts");
        check(export.contains("feedback.bug=Bug report")
                        && export.contains("feedback.compatibility=Compatibility report")
                        && export.contains("feedback.feature=Feature request")
                        && export.contains("feedback.help=Help request"),
                "release diagnostics exposes all S59 feedback routes");
        check(!export.contains("payload bytes") && !export.contains("apiKey")
                        && !export.contains("signingKey"),
                "release diagnostics does not expose raw payloads or secret labels");
        check(ReleaseDiagnosticsExport.feedbackSummary().contains("Bug report")
                        && ReleaseDiagnosticsExport.feedbackSummary().contains(
                        "Compatibility report"),
                "feedback summary is user-findable from the UI action");
    }

    private static AuthoringPolicyBundle.L4Rule l4Rule(
            ApplicationSubjectId app, String destinationCidr, int ipProtocol,
            int priority, int order, AuthoringPolicyBundle.L4Action action) {
        return AuthoringPolicyBundle.L4Rule.create(app,
                AuthoringPolicyBundle.IpFamily.IPV4, "", destinationCidr,
                null, AuthoringPolicyBundle.PortRange.exact(443),
                ipProtocol, AuthoringPolicyBundle.PacketDirection.OUTPUT,
                AuthoringPolicyBundle.NetworkContextId.WIFI,
                action, priority, order);
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
