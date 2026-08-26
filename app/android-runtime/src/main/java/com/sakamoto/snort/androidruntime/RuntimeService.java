package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ApplicationInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/**
 * Sole Android lifecycle authority for one profile-owned VPP runtime.
 *
 * <p>The Activity sends only versioned product requests. This service owns
 * profile selection, foreground visibility, core-runtime health, process
 * supervision, and cleanup. It intentionally remains alive when the Activity
 * is closed or recreated.</p>
 */
public final class RuntimeService extends VpnService {
    public static final String ACTION_START = RuntimeControlProtocol.ACTION_START;
    public static final String ACTION_QUERY = RuntimeControlProtocol.ACTION_QUERY;
    public static final String ACTION_STOP = RuntimeControlProtocol.ACTION_STOP;
    public static final String ACTION_PROTECTION_PAUSE =
            RuntimeControlProtocol.ACTION_PROTECTION_PAUSE;
    public static final String ACTION_PROTECTION_RESUME =
            RuntimeControlProtocol.ACTION_PROTECTION_RESUME;
    public static final String ACTION_PRODUCT_PROFILE_SELECT =
            RuntimeControlProtocol.ACTION_PRODUCT_PROFILE_SELECT;
    public static final String ACTION_PRODUCT_BIND_APP =
            RuntimeControlProtocol.ACTION_PRODUCT_BIND_APP;
    public static final String ACTION_PRODUCT_UNBIND_APP =
            RuntimeControlProtocol.ACTION_PRODUCT_UNBIND_APP;
    public static final String ACTION_PRODUCT_SET_NETWORK_GATE =
            RuntimeControlProtocol.ACTION_PRODUCT_SET_NETWORK_GATE;
    public static final String ACTION_PRODUCT_SET_L4_RULE =
            RuntimeControlProtocol.ACTION_PRODUCT_SET_L4_RULE;

    private static final String TAG = "SakamotoRuntimeService";
    private static final String SU_PATH = "/system/bin/su";
    private static final String VPP_BINARY = "libvpp_runtime.so";
    private static final String ROOT_BINARY = "libsucre_snortd.so";
    private static final String VPN_BINARY = "libsucre_snortd.so";
    private static final String MANIFEST_ASSET = "vpp-runtime.properties";
    private static final String HASH_ASSET = "vpp-runtime.sha256";
    private static final String DAEMON_HASH_ASSET = "sucre-snortd.sha256";
    private static final String CHANNEL_ID = "sakamoto-runtime";
    private static final int NOTIFICATION_ID = 6701;
    private static final int HEALTH_ATTEMPTS = 24;
    private static final long HEALTH_RETRY_MILLIS = 250L;
    private static final long STOP_TERM_MILLIS = 1500L;
    private static final long STOP_KILL_MILLIS = 1500L;
    private static final long OWNERSHIP_RETRY_MILLIS = 50L;
    private static final int OWNERSHIP_RETRY_ATTEMPTS = 2;
    private static final int ROOT_COMMAND_UNAVAILABLE = -125;

    /** Android instantiates the production service through the no-arg path. */
    public RuntimeService() {
        this(RuntimeStateStore.defaultWriter());
    }

    /**
     * Host/instrumentation seam for deterministic durable-projection failure
     * injection. The lifecycle still owns all Android side effects; only the
     * filesystem publication boundary is replaceable.
     */
    public RuntimeService(RuntimeStateStore.Writer stateWriter) {
        this.persistenceGate = new RuntimeStateStore.PersistenceGate(stateWriter,
                RuntimeSnapshot.stopped());
    }

    private enum WaitResult {
        GONE,
        TIMED_OUT,
        MISMATCH,
        UNKNOWN
    }

    private final Object stateLock = new Object();
    private final ExecutorService lifecycle = new ThreadPoolExecutor(
            1, 1, 0L, TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(8), runnable -> {
                Thread thread = new Thread(runnable, "sakamoto-runtime-lifecycle");
                thread.setDaemon(false);
                return thread;
            }, new ThreadPoolExecutor.AbortPolicy());
    /** Coalesce Activity polling while one bounded generated-VAPI query runs. */
    private final AtomicBoolean healthQueryScheduled = new AtomicBoolean();
    /** Monotonic bounded evidence revision for explicit QUERY requests. */
    private final AtomicLong healthQueryRevision = new AtomicLong();
    /** Reject delayed START/STOP intents before they can mutate lifecycle state. */
    private final RuntimeControlOrdering controlOrdering = new RuntimeControlOrdering();
    private final RuntimeStateStore.PersistenceGate persistenceGate;
    private final RuntimeRecoveryPolicy recoveryPolicy = new RuntimeRecoveryPolicy();

    private volatile boolean stopRequested;
    private volatile boolean foregroundStarted;
    private volatile boolean destroying;
    private volatile boolean cleanupFaultInjected;
    /** Missing/corrupt projections require a two-profile ownership audit. */
    private volatile boolean durableProjectionRequiresAudit;
    /** Set when that audit found ambiguity or unverifiable ownership. */
    private volatile boolean durableRecoveryBlocked;
    private volatile int latestStartId;
    private volatile long monitoredPid = -1L;
    private volatile int recoveryFailureCount;
    private RuntimeSnapshot snapshot;
    private LocalProductBackend productBackend;
    private Process vppProcess;
    private VpnTunPlatformSession vpnTunSession;
    private VpnHevTransportSession vpnHevSession;
    private RuntimeProfile activeProfile;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;
    private long generation;
    private RuntimeProfile lastNativePolicyDropActivityProfile;
    private long lastNativePolicyDropActivityGeneration = -1L;
    private long lastNativePolicyDropActivityTotalRecords;
    private RuntimeProfile lastNativeAllowedFlowActivityProfile;
    private long lastNativeAllowedFlowActivityGeneration = -1L;
    private long lastNativeAllowedFlowActivityTotalRecords;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        RuntimeStateStore.ReadResult durable = RuntimeStateStore.readResult(getFilesDir());
        productBackend = new LocalProductBackend(getFilesDir(),
                new PackageManagerApplicationCatalogProvider(this),
                new RuntimePolicyApplyTransport());
        snapshot = durable.snapshot;
        persistenceGate.setSnapshot(snapshot);
        durableProjectionRequiresAudit = !durable.present || !durable.valid;
        generation = snapshot.generation;
        activeProfile = snapshot.profile;
        initializeProfilePaths(activeProfile);
        enqueueLifecycle(() -> refreshProductCatalogProjection("service_create"));
        enqueueLifecycle(this::reconcileDurableRuntime);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        latestStartId = Math.max(latestStartId, startId);
        String action = intent == null ? ACTION_QUERY : intent.getAction();
        if (action == null) {
            action = ACTION_QUERY;
        }
        if (!isSupportedAction(action)) {
            final String rejectedAction = action;
            enqueueLifecycle(() -> publishError("unsupported_runtime_action",
                    "unknown runtime action: " + rejectedAction,
                    currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_ACTION)
                && !action.equals(intent.getStringExtra(RuntimeControlProtocol.EXTRA_ACTION))) {
            enqueueLifecycle(() -> publishError("runtime_action_mismatch",
                    "intent action and versioned action disagree", currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        int protocolVersion = intent == null ? RuntimeControlProtocol.VERSION
                : intent.getIntExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION, -1);
        if (protocolVersion != RuntimeControlProtocol.VERSION) {
            enqueueLifecycle(() -> publishError("unsupported_control_protocol",
                    "expected " + RuntimeControlProtocol.NAME, currentMayBeActive(), currentPid()));
            return START_STICKY;
        }

        long requestTimeMillis = intent == null ? 0L
                : intent.getLongExtra(RuntimeControlProtocol.EXTRA_REQUEST_TIME_MILLIS, 0L);
        if (ACTION_START.equals(action) || ACTION_STOP.equals(action)
                || ACTION_PROTECTION_PAUSE.equals(action)
                || ACTION_PROTECTION_RESUME.equals(action)) {
            RuntimeControlOrdering.Decision ordering = controlOrdering.observe(
                    requestTimeMillis, startId);
            if (ordering == RuntimeControlOrdering.Decision.STALE) {
                appendLog("ignored stale " + action + " request=" + requestTimeMillis
                        + " latest=" + controlOrdering.latestRequestTimeMillis()
                        + " latestStartId=" + controlOrdering.latestRequestStartId());
                return START_NOT_STICKY;
            }
        }
        RuntimeProfile requested = null;
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_PROFILE)) {
            try {
                requested = RuntimeProfile.parse(
                        intent.getStringExtra(RuntimeControlProtocol.EXTRA_PROFILE));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_runtime_profile", error.getMessage(),
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        ApplicationSubjectId requestedSubject = null;
        if (intent != null
                && intent.hasExtra(RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT)) {
            try {
                requestedSubject = ApplicationSubjectId.parse(intent.getStringExtra(
                        RuntimeControlProtocol.EXTRA_APPLICATION_SUBJECT));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_application_subject",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        AuthoringPolicyBundle.NetworkContextId requestedNetworkContext = null;
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT)) {
            try {
                requestedNetworkContext = AuthoringPolicyBundle.NetworkContextId.parse(
                        intent.getStringExtra(RuntimeControlProtocol.EXTRA_NETWORK_CONTEXT));
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_network_context",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }
        final boolean requestedNetworkGateBlocked = intent != null
                && intent.getBooleanExtra(RuntimeControlProtocol.EXTRA_NETWORK_GATE_BLOCKED,
                        false);

        if (ACTION_START.equals(action) || ACTION_PROTECTION_RESUME.equals(action)) {
            // A user retry is an explicit new lifecycle transaction. Clear a
            // stale active error synchronously so queued health polls cannot
            // make a still-pending retry look permanently failed. The
            // serialized start/reconciliation audit remains authoritative and
            // will immediately republish a fail-closed error if ownership is
            // still ambiguous or cleanup still fails.
            markExplicitStartPending();
            // A valid start request is authoritative over any delayed stop
            // from an Activity instance that has already been replaced.
            stopRequested = false;
            recoveryFailureCount = recoveryPolicy.reset();
        }

        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_CLEANUP_FAULT)) {
            final boolean enabled = intent.getBooleanExtra(
                    RuntimeControlProtocol.EXTRA_CLEANUP_FAULT, false);
            enqueueLifecycle(() -> setCleanupFault(enabled));
        }

        if (ACTION_STOP.equals(action)) {
            stopRequested = true;
            enqueueLifecycle(this::stopRuntime);
            return START_NOT_STICKY;
        }
        if (ACTION_PROTECTION_PAUSE.equals(action)) {
            stopRequested = true;
            enqueueLifecycle(this::pauseProtection);
            return START_NOT_STICKY;
        }
        if (ACTION_PRODUCT_PROFILE_SELECT.equals(action)) {
            if (requested == null) {
                enqueueLifecycle(() -> publishError("invalid_product_profile_request",
                        "product profile selection requires a runtime profile",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final RuntimeProfile profile = requested;
            enqueueLifecycle(() -> selectProductProfile(profile));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_BIND_APP.equals(action)) {
            if (requestedSubject == null) {
                enqueueLifecycle(() -> publishError("invalid_product_bind_request",
                        "product app bind requires an application subject",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            enqueueLifecycle(() -> bindProductApplication(subject));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_UNBIND_APP.equals(action)) {
            if (requestedSubject == null) {
                enqueueLifecycle(() -> publishError("invalid_product_unbind_request",
                        "product app unbind requires an application subject",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            enqueueLifecycle(() -> unbindProductApplication(subject));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_SET_NETWORK_GATE.equals(action)) {
            if (requestedSubject == null || requestedNetworkContext == null) {
                enqueueLifecycle(() -> publishError("invalid_product_network_gate_request",
                        "Network Gate mutation requires an application subject and network context",
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            final ApplicationSubjectId subject = requestedSubject;
            final AuthoringPolicyBundle.NetworkContextId context = requestedNetworkContext;
            enqueueLifecycle(() -> setProductNetworkGate(
                    subject, context, requestedNetworkGateBlocked));
            return START_STICKY;
        }
        if (ACTION_PRODUCT_SET_L4_RULE.equals(action)) {
            final AuthoringPolicyBundle.L4Rule rule;
            try {
                rule = parseL4RuleIntent(intent, requestedSubject, requestedNetworkContext);
            } catch (IllegalArgumentException error) {
                enqueueLifecycle(() -> publishError("invalid_product_l4_rule_request",
                        error.getMessage(), currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> setProductL4Rule(rule));
            return START_STICKY;
        }
        if (ACTION_START.equals(action)) {
            final RuntimeProfile profile = requested == null ? activeProfile : requested;
            if (!ensureForeground(profile)) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> startRuntime(profile));
            return START_STICKY;
        }
        if (ACTION_PROTECTION_RESUME.equals(action)) {
            final RuntimeProfile profile = activeProfile == null ? RuntimeProfile.ROOT
                    : activeProfile;
            if (!ensureForeground(profile)) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            enqueueLifecycle(() -> startRuntime(profile));
            return START_STICKY;
        }
        // QUERY is a public health request. It must reconcile the durable
        // owner and issue a bounded generated-VAPI show_version call even
        // when this service already monitors the same PID.
        if (currentMayBeActive() && !ensureForeground(activeProfile)) {
            return START_NOT_STICKY;
        }
        queueHealthQuery(startId);
        return START_STICKY;
    }

    private static boolean isSupportedAction(String action) {
        return ACTION_START.equals(action)
                || ACTION_QUERY.equals(action)
                || ACTION_STOP.equals(action)
                || ACTION_PROTECTION_PAUSE.equals(action)
                || ACTION_PROTECTION_RESUME.equals(action)
                || ACTION_PRODUCT_PROFILE_SELECT.equals(action)
                || ACTION_PRODUCT_BIND_APP.equals(action)
                || ACTION_PRODUCT_UNBIND_APP.equals(action)
                || ACTION_PRODUCT_SET_NETWORK_GATE.equals(action)
                || ACTION_PRODUCT_SET_L4_RULE.equals(action);
    }

    private static AuthoringPolicyBundle.L4Rule parseL4RuleIntent(
            Intent intent, ApplicationSubjectId subjectId,
            AuthoringPolicyBundle.NetworkContextId context) {
        if (intent == null || subjectId == null) {
            throw new IllegalArgumentException("L4 rule mutation requires an application subject");
        }
        AuthoringPolicyBundle.IpFamily family = AuthoringPolicyBundle.IpFamily.parse(
                requiredStringExtra(intent, RuntimeControlProtocol.EXTRA_L4_FAMILY));
        String sourceCidr = intent.getStringExtra(RuntimeControlProtocol.EXTRA_L4_SOURCE_CIDR);
        String destinationCidr = intent.getStringExtra(
                RuntimeControlProtocol.EXTRA_L4_DESTINATION_CIDR);
        int ipProtocol = intent.getIntExtra(
                RuntimeControlProtocol.EXTRA_L4_IP_PROTOCOL, -1);
        AuthoringPolicyBundle.PacketDirection direction =
                AuthoringPolicyBundle.PacketDirection.parse(requiredStringExtra(
                        intent, RuntimeControlProtocol.EXTRA_L4_PACKET_DIRECTION));
        AuthoringPolicyBundle.L4Action action = AuthoringPolicyBundle.L4Action.parse(
                requiredStringExtra(intent, RuntimeControlProtocol.EXTRA_L4_ACTION));
        int priority = intent.getIntExtra(RuntimeControlProtocol.EXTRA_L4_PRIORITY, 0);
        int order = intent.getIntExtra(RuntimeControlProtocol.EXTRA_L4_ORDER, 0);
        return AuthoringPolicyBundle.L4Rule.create(subjectId, family, sourceCidr,
                destinationCidr, portRangeExtra(intent,
                        RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_FIRST,
                        RuntimeControlProtocol.EXTRA_L4_SOURCE_PORT_LAST),
                portRangeExtra(intent,
                        RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_FIRST,
                        RuntimeControlProtocol.EXTRA_L4_DESTINATION_PORT_LAST),
                ipProtocol, direction, context, action, priority, order);
    }

    private static String requiredStringExtra(Intent intent, String name) {
        String value = intent.getStringExtra(name);
        if (value == null || value.trim().isEmpty()) {
            throw new IllegalArgumentException("missing " + name);
        }
        return value;
    }

    private static AuthoringPolicyBundle.PortRange portRangeExtra(
            Intent intent, String firstName, String lastName) {
        boolean hasFirst = intent.hasExtra(firstName);
        boolean hasLast = intent.hasExtra(lastName);
        if (!hasFirst && !hasLast) {
            return null;
        }
        if (!hasFirst || !hasLast) {
            throw new IllegalArgumentException(firstName + "/" + lastName
                    + " must be supplied together");
        }
        return AuthoringPolicyBundle.PortRange.inclusive(
                intent.getIntExtra(firstName, -1), intent.getIntExtra(lastName, -1));
    }

    private void queueHealthQuery(int requestStartId) {
        long revision = healthQueryRevision.incrementAndGet();
        appendLog("health_query=request revision=" + revision + " startId=" + requestStartId);
        if (!healthQueryScheduled.compareAndSet(false, true)) {
            appendLog("health_query=coalesced revision=" + revision);
            return;
        }
        if (!enqueueLifecycle(() -> {
            try {
                reconcileDurableRuntime(true, revision);
                refreshProductCatalogProjection("query");
                refreshProductActivityProjection("query", null);
                appendLog("health_query=result revision=" + revision);
                stopIfInactive(requestStartId);
            } finally {
                healthQueryScheduled.set(false);
            }
        })) {
            healthQueryScheduled.set(false);
        }
    }

    private boolean enqueueLifecycle(Runnable task) {
        try {
            lifecycle.execute(task);
            return true;
        } catch (RejectedExecutionException error) {
            appendLog("lifecycle_backpressure=rejected");
            return false;
        }
    }

    private void markExplicitStartPending() {
        if (persistenceGate.isPersistenceUnavailable()) {
            appendLog("runtime_state_persistence=start_blocked pending_recovery");
            return;
        }
        RuntimeSnapshot current = snapshot;
        if (current == null || !RuntimeSnapshot.STATE_ERROR.equals(current.state)
                || !current.mayBeActive) {
            return;
        }
        publish(RuntimeSnapshot.starting(current.profile, current.protocol, current.version,
                current.artifact, current.generation));
    }

    public static boolean notificationsReady(Context context) {
        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        return manager != null && manager.areNotificationsEnabled();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Sakamoto protection", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Ongoing status for the supervised VPP runtime");
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    private synchronized boolean ensureForeground(RuntimeProfile profile) {
        if (foregroundStarted) {
            return true;
        }
        RuntimeSnapshot pending = RuntimeSnapshot.starting(profile, VppHealthHandshake.PROTOCOL,
                "", "", generation);
        try {
            startForeground(NOTIFICATION_ID, buildNotification(pending),
                    Build.VERSION.SDK_INT >= 29 ?
                            android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0);
            foregroundStarted = true;
            if (!notificationsReady(this)) {
                publishError("notification_permission_required",
                        "allow the ongoing protection notification before starting", false, -1L);
                stopForeground(true);
                foregroundStarted = false;
                return false;
            }
            return true;
        } catch (RuntimeException error) {
            publishError("foreground_service_start_failed", messageOf(error), false, -1L);
            foregroundStarted = false;
            return false;
        }
    }

    private void startRuntime(RuntimeProfile requestedProfile) {
        if (destroying) {
            return;
        }
        // A missing/corrupt projection is not evidence that ROOT is stopped.
        // The serial onCreate reconciliation must audit both profiles before
        // any new process can be launched. Keep this guard as a second seam
        // against a reordered lifecycle request.
        if (durableProjectionRequiresAudit) {
            publishError("runtime_ownership_unverified",
                    "Root/VPN durable ownership has not been safely reconciled",
                    true, currentPid());
            return;
        }
        if (requestedProfile == null) {
            requestedProfile = RuntimeProfile.ROOT;
        }
        // A successful ordinary publish is not enough to clear this latch:
        // the durable projection may still describe an older owner. An
        // explicit START first performs a bounded ownership audit and writes
        // the current in-memory projection as a recovery probe. Only that
        // sequence may make a new launch eligible again.
        if (persistenceGate.isPersistenceUnavailable() && !recoverDurableProjectionBeforeStart()) {
            return;
        }
        RuntimeOwnershipReconciliation.GlobalDecision ownership =
                auditGlobalOwnership(true);
        if (ownership.isBlocked()) {
            publishGlobalOwnershipFailure(ownership);
            return;
        }
        if (ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                || ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN) {
            RuntimeProfile previousProfile = ownership.ownerProfile;
            activeProfile = previousProfile;
            initializeProfilePaths(activeProfile);
            if (requestedProfile == previousProfile) {
                adoptRuntime(ownership.ownerPid);
                appendLog("start ignored: exactly one runtime is already active");
                return;
            }
            stopRequested = true;
            // Keep this service and its foreground notification alive while
            // replacing profiles. A normal stop calls stopSelf(), which can
            // race the queued replacement start and tear down the new core.
            if (!stopRuntime(false)) {
                // The previous profile remains authoritative. Never launch a
                // second VPP while ownership or residue is uncertain.
                stopRequested = false;
                return;
            }
        } else if (!cleanGlobalResidue(ownership, "pre-start residue: ")) {
            return;
        }
        activeProfile = requestedProfile;
        initializeProfilePaths(activeProfile);
        stopRequested = false;
        generation++;
        if (!persistSelectedProductProfile(activeProfile)) {
            stopIfInactive();
            return;
        }
        ProductPacketAdapterContract adapter =
                ProductPacketAdapterContract.forProfile(activeProfile);
        VpnTunPlatformSession pendingVpnTunSession = establishPacketAdapterSession(adapter);
        if (adapter.requiresVpnPlatformSession && pendingVpnTunSession == null) {
            return;
        }
        if (!adapter.productLaunchAllowed) {
            closeVpnTunSessionQuietly(pendingVpnTunSession);
            failSelectedProfileWithoutRuntime(adapter.unavailableErrorCode,
                    adapter.unavailableMessage);
            return;
        }

        Properties manifest;
        try {
            manifest = readManifest();
        } catch (IOException error) {
            failWithoutRuntime("runtime_manifest_unreadable", messageOf(error));
            return;
        }
        RuntimeArtifactIdentity identity = RuntimeArtifactIdentity.from(manifest);
        String protocol = identity.protocol;
        String version = identity.version;
        String abi = identity.abi;
        String expectedArtifact = identity.artifact;
        String expectedApiIdentity = identity.apiIdentity;
        String deviceAbi = deviceAbi();
        String identityError = identity.validationError(deviceAbi);
        if (!identityError.isEmpty()) {
            failWithoutRuntime(identityError, identity.validationMessage(deviceAbi));
            return;
        }
        if (activeProfile == RuntimeProfile.ROOT) {
            try {
                expectedArtifact = "sha256:"
                        + readExpectedHash(DAEMON_HASH_ASSET, "sucre-snortd");
            } catch (IOException error) {
                failWithoutRuntime("runtime_manifest_unreadable", messageOf(error));
                return;
            }
        }

        if (activeProfile == RuntimeProfile.ROOT && !rootCommandAvailable()) {
            publishError("root_authorization_required",
                    "KernelSU/root execution is unavailable to this app process",
                    profileRoot.exists(), currentPid());
            if (!profileRoot.exists()) {
                stopIfInactive();
            }
            return;
        }

        if (!publish(RuntimeSnapshot.starting(activeProfile, protocol, version, expectedArtifact,
                generation))) {
            // No process has been launched yet. Keep the service fail-closed
            // and leave the durable projection untouched rather than
            // starting an owner that a restarted supervisor could not prove.
            return;
        }
        CleanupResult preflight = removeAndVerifyProfile(profileRoot, currentPid(), null);
        if (!preflight.ok) {
            publishCleanupFailure("pre-start residue: ", preflight, true);
            return;
        }

        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File vpp = runtimeExecutable(nativeDir, activeProfile);
        try {
            if (!vpp.isFile()) {
                throw new IOException("runtime artifact is not packaged: "
                        + runtimeBinaryName(activeProfile));
            }
            String actualArtifact = "sha256:" + sha256(vpp);
            if (activeProfile == RuntimeProfile.ROOT) {
                String expectedHash = readExpectedHash(DAEMON_HASH_ASSET, "sucre-snortd");
                if (!expectedArtifact.equalsIgnoreCase("sha256:" + expectedHash)) {
                    failWithoutRuntime("runtime_manifest_hash_mismatch",
                            "artifact and SHA-256 assets disagree");
                    return;
                }
                if (!expectedArtifact.equalsIgnoreCase(actualArtifact)) {
                    failWithoutRuntime("runtime_artifact_hash_mismatch",
                            "daemon artifact does not match packaged runtime");
                    return;
                }
            } else {
                expectedArtifact = actualArtifact;
            }
            if (!vpp.canExecute() && !vpp.setExecutable(true, false)) {
                throw new IOException("runtime artifact is not executable");
            }
            prepareProfile(profileRoot, activeProfile);
            Process process = launchVpp(vpp, nativeDir, profileRoot, activeProfile,
                    pendingVpnTunSession);
            vppProcess = process;
            vpnTunSession = pendingVpnTunSession;
            pendingVpnTunSession = null;
            appendLog("vpp_process=started profile=" + activeProfile.wireName
                    + " artifact=" + expectedArtifact);
            VppHealthHandshake.Result health = activeProfile == RuntimeProfile.VPN
                    ? vpnNativeOwnerHealth(protocol, version, deviceAbi, expectedArtifact,
                            process)
                    : waitForRootDaemonHealth(protocol, version, deviceAbi, expectedArtifact,
                            process);
            if (stopRequested) {
                stopRuntime();
                return;
            }
            if (!health.isReady()) {
                failWithCleanup(health.errorCode.isEmpty() ? "health_handshake_failed"
                        : health.errorCode, "VPP health did not prove profile readiness");
                return;
            }
            if (!attachVpnTunSessionAfterHealth(activeProfile, vpnTunSession)) {
                failWithCleanup("vpn_tun_control_attach_failed",
                        "VPN TUN fd handoff over vNext control failed");
                return;
            }
            if (!startVpnHevTransportAfterTun(activeProfile, nativeDir, profileRoot)) {
                failWithCleanup("vpn_hev_transport_start_failed",
                        "VPN HEV transport did not reach the native Adapter");
                return;
            }
            closeVpnTunSessionAfterNativeHandoff();
            long pid = readPid(pidFile);
            if (pid <= 0L || !isPidAlive(pid)) {
                failWithCleanup("runtime_pid_unverified",
                        "health passed but the VPP owner PID was not active");
                return;
            }
            if (!publish(RuntimeSnapshot.running(activeProfile, protocol, health.version,
                    expectedArtifact, deviceAbi, health.health, pid, generation))) {
                // The owner is already live, but the supervisor could not
                // publish its identity. Reuse the bounded strong-identity
                // TERM/KILL path before returning to the caller.
                failWithCleanup("runtime_state_persistence_unavailable",
                        "runtime state could not be persisted after launch");
                return;
            }
            appendLog("runtime_state=running profile=" + activeProfile.wireName
                    + " version=" + version + " core_health=" + health.health
                    + " adapter=" + (activeProfile == RuntimeProfile.VPN
                    ? RuntimeSnapshot.ADAPTER_VPN_TUN_FD_COMPAT
                    : RuntimeSnapshot.ADAPTER_ROOT_NFQUEUE));
            monitorExit(process);
        } catch (Exception error) {
            Log.e(TAG, "VPP runtime startup failed", error);
            closeVpnTunSessionQuietly(pendingVpnTunSession);
            closeVpnTunSessionAfterNativeHandoff();
            failWithCleanup("runtime_start_failed", messageOf(error));
        }
    }

    private void reconcileDurableRuntime() {
        reconcileDurableRuntime(false);
    }

    private void reconcileDurableRuntime(boolean forceHealthQuery) {
        reconcileDurableRuntime(forceHealthQuery, 0L);
    }

    private void reconcileDurableRuntime(boolean forceHealthQuery, long queryRevision) {
        RuntimeOwnershipReconciliation.GlobalDecision ownership =
                auditGlobalOwnership(!durableProjectionRequiresAudit);
        if (ownership.isBlocked()) {
            publishGlobalOwnershipFailure(ownership);
            return;
        }
        // A cleanup failure is a deliberate fail-closed state. Do not let a
        // periodic QUERY re-adopt the still-live owner as "running" and
        // thereby erase the replacement block before an explicit retry.
        if (snapshot != null && RuntimeSnapshot.STATE_ERROR.equals(snapshot.state)
                && "cleanup_failed".equals(snapshot.errorCode) && snapshot.mayBeActive
                && (ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                || ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN)) {
            durableRecoveryBlocked = true;
            publishError(snapshot.errorCode, snapshot.errorMessage, true, snapshot.pid);
            return;
        }
        if (ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                || ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN) {
            activeProfile = ownership.ownerProfile;
            initializeProfilePaths(activeProfile);
            durableProjectionRequiresAudit = false;
            durableRecoveryBlocked = false;
            adoptRuntime(ownership.ownerPid, forceHealthQuery, queryRevision);
            return;
        }
        if (!cleanGlobalResidue(ownership, "durable recovery: ")) {
            return;
        }
        activeProfile = snapshot == null || snapshot.profile == null
                ? RuntimeProfile.ROOT : snapshot.profile;
        initializeProfilePaths(activeProfile);
        durableProjectionRequiresAudit = false;
        durableRecoveryBlocked = false;
        if (snapshot != null && snapshot.isActive()) {
            publishError("runtime_recovered", "previous VPP owner was no longer active",
                    false, -1L);
            publish(RuntimeSnapshot.stoppedAfter(snapshot));
        } else if (snapshot == null) {
            publish(RuntimeSnapshot.stopped(activeProfile, generation));
        }
    }

    private RuntimeOwnershipReconciliation.ProfileAudit auditDurableProfile(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        File profileRoot = profileDirectory(selected);
        boolean present = profileRoot.exists();
        File durablePid = new File(new File(profileRoot, "runtime"), "vpp.pid");
        long pid = readPid(durablePid);
        if (!present) {
            return RuntimeOwnershipReconciliation.ProfileAudit.none(selected);
        }
        RuntimeOwnershipReconciliation.PidIdentity identity = validatePid(selected, pid);
        // A durable PID is only one identity witness. Always run the bounded
        // exhaustive profile scan while the profile is non-empty so a second
        // same-token/profile/executable owner cannot bypass reconciliation.
        RuntimeOwnershipReconciliation.OwnershipAudit candidate =
                auditOwnedProcess(selected, profileRoot);
        return RuntimeOwnershipReconciliation.classifyDurableProfile(
                selected, present, pid, identity, candidate);
    }

    private File profileDirectory(RuntimeProfile profile) {
        RuntimeProfile selected = profile == null ? RuntimeProfile.ROOT : profile;
        return new File(getFilesDir(), "profiles/" + selected.wireName + "/vpp");
    }

    private static String boundedOwnershipFailure(
            RuntimeOwnershipReconciliation.ProfileAudit root,
            RuntimeOwnershipReconciliation.ProfileAudit vpn) {
        String detail = "durable ownership audit blocked: root=" + root.detail
                + ", vpn=" + vpn.detail;
        return BoundedText.value(detail, RuntimeSnapshot.MAX_TEXT_LENGTH);
    }

    /**
     * Audit both mutually-exclusive profile directories before any lifecycle
     * path may adopt, clean, or launch a VPP process. A valid snapshot is a
     * projection witness only; missing/corrupt projections deliberately pass
     * an unknown projection so a sole globally verified owner can still be
     * recovered.
     */
    private RuntimeOwnershipReconciliation.GlobalDecision auditGlobalOwnership(
            boolean projectionKnown) {
        RuntimeOwnershipReconciliation.GlobalDecision decision =
                auditGlobalOwnershipOnce(projectionKnown);
        boolean runtimeMayBeActive = snapshot != null && snapshot.isActive();
        for (int attempt = 0;
                attempt < OWNERSHIP_RETRY_ATTEMPTS
                        && RuntimeOwnershipReconciliation.shouldRetryOwnershipAudit(
                                decision, runtimeMayBeActive);
                attempt++) {
            try {
                Thread.sleep(OWNERSHIP_RETRY_MILLIS);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                break;
            }
            decision = auditGlobalOwnershipOnce(projectionKnown);
        }
        return decision;
    }

    private RuntimeOwnershipReconciliation.GlobalDecision auditGlobalOwnershipOnce(
            boolean projectionKnown) {
        RuntimeOwnershipReconciliation.ProfileAudit root =
                auditDurableProfile(RuntimeProfile.ROOT);
        RuntimeOwnershipReconciliation.ProfileAudit vpn =
                auditDurableProfile(RuntimeProfile.VPN);
        RuntimeOwnershipReconciliation.Projection projection = projectionKnown && snapshot != null
                ? RuntimeOwnershipReconciliation.Projection.known(
                        snapshot.profile, snapshot.isActive(), snapshot.pid)
                : RuntimeOwnershipReconciliation.Projection.unknown();
        return RuntimeOwnershipReconciliation.decide(root, vpn, projection);
    }

    /**
     * Recover a failed durable projection only as an explicit pre-start
     * transaction. A live owner is deliberately not adopted or replaced
     * while the projection remains unavailable; the user must stop it first
     * so this probe cannot bless an uncertain replacement.
     */
    private boolean recoverDurableProjectionBeforeStart() {
        RuntimeOwnershipReconciliation.GlobalDecision ownership =
                auditGlobalOwnership(false);
        if (ownership.isBlocked()) {
            publishGlobalOwnershipFailure(ownership);
            appendLog("runtime_state_persistence=recovery_blocked ownership="
                    + ownership.errorCode);
            return false;
        }
        if (ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                || ownership.action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN) {
            appendLog("runtime_state_persistence=recovery_blocked live_owner="
                    + ownership.ownerProfile.wireName + " pid=" + ownership.ownerPid);
            return false;
        }
        if (!cleanGlobalResidue(ownership, "persistence recovery: ")) {
            return false;
        }
        RuntimeStateStore.PersistenceGate.Result recovery = persistenceGate.recover(
                getFilesDir(), true);
        snapshot = recovery.snapshot;
        if (!recovery.recovered) {
            exposePersistenceFailure(recovery, "recovery_probe");
            return false;
        }
        appendLog("runtime_state_persistence=recovered");
        return true;
    }

    /**
     * Remove only the one residue named by a completed global CLEAN decision.
     * The opposite profile was audited as NONE by the same decision and is
     * never implicitly removed or treated as harmless here.
     */
    private boolean cleanGlobalResidue(
            RuntimeOwnershipReconciliation.GlobalDecision ownership, String prefix) {
        if (ownership == null || ownership.action != RuntimeOwnershipReconciliation.Action.CLEAN) {
            return false;
        }
        if (ownership.cleanupProfile == null) {
            return true;
        }
        activeProfile = ownership.cleanupProfile;
        initializeProfilePaths(activeProfile);
        CleanupResult cleanup = removeAndVerifyProfile(
                profileRoot, ownership.cleanupPid, null);
        if (!cleanup.ok) {
            durableRecoveryBlocked = true;
            publishCleanupFailure(prefix == null ? "" : prefix, cleanup, true);
            return false;
        }
        return true;
    }

    /** Publish one bounded, fail-closed error for any global ownership block. */
    private void publishGlobalOwnershipFailure(
            RuntimeOwnershipReconciliation.GlobalDecision ownership) {
        durableRecoveryBlocked = true;
        RuntimeProfile selected = snapshot == null || snapshot.profile == null
                ? RuntimeProfile.ROOT : snapshot.profile;
        activeProfile = selected;
        initializeProfilePaths(activeProfile);
        String code = ownership == null || ownership.errorCode.isEmpty()
                ? "runtime_ownership_ambiguous" : ownership.errorCode;
        String detail = ownership == null
                ? "Root/VPN durable ownership decision is unavailable"
                : boundedOwnershipFailure(ownership.root, ownership.vpn);
        long pid = -1L;
        boolean liveRoot = ownership != null
                && ownership.root.evidence == RuntimeOwnershipReconciliation.Evidence.LIVE;
        boolean liveVpn = ownership != null
                && ownership.vpn.evidence == RuntimeOwnershipReconciliation.Evidence.LIVE;
        if (liveRoot && !liveVpn && ownership.root.pid > 0L) {
            pid = ownership.root.pid;
        } else if (liveVpn && !liveRoot && ownership.vpn.pid > 0L) {
            pid = ownership.vpn.pid;
        } else if (snapshot != null && snapshot.isActive() && snapshot.pid > 0L) {
            pid = snapshot.pid;
        }
        boolean mayBeActive = snapshot != null && snapshot.isActive() || liveRoot || liveVpn;
        publishError(code, detail, mayBeActive, pid);
    }

    private void adoptRuntime(long pid) {
        adoptRuntime(pid, false, 0L);
    }

    private void adoptRuntime(long pid, boolean forceHealthQuery) {
        adoptRuntime(pid, forceHealthQuery, 0L);
    }

    private void adoptRuntime(long pid, boolean forceHealthQuery, long queryRevision) {
        if (!forceHealthQuery && monitoredPid == pid && snapshot != null
                && RuntimeSnapshot.STATE_RUNNING.equals(snapshot.state)) {
            return;
        }
        try {
            Properties manifest = readManifest();
            RuntimeArtifactIdentity identity = RuntimeArtifactIdentity.from(manifest);
            String protocol = identity.protocol;
            String version = identity.version;
            String abi = identity.abi;
            String artifact = identity.artifact;
            String apiIdentity = identity.apiIdentity;
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            String actualAbi = deviceAbi();
            String identityError = identity.validationError(actualAbi);
            if (!identityError.isEmpty()) {
                publishError(identityError, identity.validationMessage(actualAbi), true, pid);
                monitorPid(pid);
                return;
            }
            File vpp = runtimeExecutable(nativeDir, activeProfile);
            if (!vpp.isFile()) {
                publishError("runtime_artifact_missing",
                        "runtime artifact is not packaged: "
                                + runtimeBinaryName(activeProfile), true, pid);
                monitorPid(pid);
                return;
            }
            if (activeProfile == RuntimeProfile.ROOT) {
                String expectedHash = readExpectedHash(DAEMON_HASH_ASSET, "sucre-snortd");
                artifact = "sha256:" + expectedHash;
                if (!artifact.equalsIgnoreCase("sha256:" + expectedHash)) {
                    publishError("runtime_manifest_hash_mismatch",
                            "artifact and SHA-256 assets disagree", true, pid);
                    monitorPid(pid);
                    return;
                }
                if (!artifact.equalsIgnoreCase("sha256:" + sha256(vpp))) {
                    publishError("runtime_artifact_hash_mismatch",
                            "daemon artifact does not match packaged runtime", true, pid);
                    monitorPid(pid);
                    return;
                }
            } else {
                artifact = "sha256:" + sha256(vpp);
            }
            File socket = new File(profileRoot, "runtime/api.sock");
            if (activeProfile == RuntimeProfile.ROOT && socket.exists()) {
                runRootCommand("chmod 0666 " + shellQuote(socket.getPath()), 2L);
            }
            RuntimeControlNative.Status nativeStatus;
            if (socket.exists()) {
                if (forceHealthQuery && queryRevision > 0L) {
                    appendLog("health_query=vapi_start revision=" + queryRevision
                            + " profile=" + activeProfile.wireName + " pid=" + pid);
                }
                nativeStatus = RuntimeControlNative.query(socket.getPath());
                if (forceHealthQuery && queryRevision > 0L) {
                    appendLog("health_query=vapi_result revision=" + queryRevision
                            + " generated_vapi=true rc=" + nativeStatus.transportCode
                            + " api=" + nativeStatus.apiIdentity);
                }
            } else {
                nativeStatus = RuntimeControlNative.Status.unavailable();
                if (forceHealthQuery && queryRevision > 0L) {
                    appendLog("health_query=vapi_result revision=" + queryRevision
                            + " generated_vapi=false rc=" + nativeStatus.transportCode);
                }
            }
            VppHealthHandshake.Result health = activeProfile == RuntimeProfile.VPN
                    ? vpnNativeOwnerHealth(protocol, version, abi, artifact, null)
                    : rootDaemonHealth(protocol, version, abi, artifact, null);
            if (!health.isReady()) {
                publishHealthError(health, "adopted runtime health failed", true, pid);
            } else {
                publish(RuntimeSnapshot.running(activeProfile, protocol, health.version, artifact,
                        abi, health.health, pid, generation));
            }
        } catch (Exception error) {
            publishError("runtime_recovery_failed", messageOf(error), true, pid);
        }
        monitorPid(pid);
    }

    private Process launchVpp(File vpp, File nativeDir, File currentProfile,
                              RuntimeProfile profile,
                              VpnTunPlatformSession pendingTunSession) throws IOException {
        File runtime = new File(currentProfile, "runtime");
        File logs = new File(currentProfile, "logs");
        File shm = new File(currentProfile, "shm");
        String token = readOwnerToken();
        if (token.isEmpty()) {
            throw new IOException("VPP owner token is absent from profile");
        }
        if (profile == RuntimeProfile.VPN) {
            if (pendingTunSession == null || !pendingTunSession.isOpen()) {
                throw new IOException("VPN TUN fd is absent before native launch");
            }
        }
        String command = "umask 022; echo $$ > " + shellQuote(pidFile.getPath())
                + "; export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                + " SAKAMOTO_ANDROID_SHM_DIR=" + shellQuote(shm.getPath())
                + " SAKAMOTO_VPP_RUNTIME_DIR=" + shellQuote(runtime.getPath())
                + " SAKAMOTO_VPP_OWNER_TOKEN=" + shellQuote(token)
                + " SAKAMOTO_RUNTIME_PROFILE=" + shellQuote(profile.wireName)
                + " SAKAMOTO_VPN_FLOW_STACK_BACKEND="
                + shellQuote(RuntimeSnapshot.ADAPTER_VPN_TUN_FD_COMPAT)
                + "; exec " + shellQuote(vpp.getPath()) + " plugin_path "
                + shellQuote(nativeDir.getPath()) + " -c "
                + shellQuote(new File(currentProfile, "startup.conf").getPath())
                + " >" + shellQuote(new File(logs, "vpp-stdout.log").getPath()) + " 2>&1";
        if (profile == RuntimeProfile.ROOT) {
            return new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
        }
        return new ProcessBuilder("/system/bin/sh", "-c", command).start();
    }

    private static String runtimeBinaryName(RuntimeProfile profile) {
        return profile == RuntimeProfile.ROOT ? ROOT_BINARY : VPN_BINARY;
    }

    private File runtimeExecutable(File nativeDir, RuntimeProfile profile) {
        return new File(nativeDir, runtimeBinaryName(profile));
    }

    private VppHealthHandshake.Result vpnNativeOwnerHealth(
            String protocol, String version, String abi, String artifact, Process process) {
        if (process != null && !process.isAlive()) {
            return new VppHealthHandshake.Result(protocol, version, artifact, abi,
                    "error", "health_process_exited");
        }
        return new VppHealthHandshake.Result(protocol, version, artifact, abi, "ok", "");
    }

    private VppHealthHandshake.Result rootDaemonHealth(
            String protocol, String version, String abi, String artifact, Process process) {
        if (process != null && !process.isAlive()) {
            return new VppHealthHandshake.Result(protocol, version, artifact, abi,
                    "error", "health_process_exited");
        }
        RuntimeControlFdClient.AttachResult hello =
                RuntimeControlFdClient.callJson(0, RuntimeControlFdClient.HELLO,
                        new JSONObject());
        if (hello.ok) {
            return new VppHealthHandshake.Result(protocol, version, artifact, abi, "ok", "");
        }
        return new VppHealthHandshake.Result(protocol, version, artifact, abi,
                hello.errorCode.isEmpty() ? "HELLO_FAILED" : hello.errorCode,
                hello.errorMessage);
    }

    private VppHealthHandshake.Result waitForRootDaemonHealth(
            String protocol, String version, String abi, String artifact, Process process)
            throws InterruptedException {
        VppHealthHandshake.Result last = rootDaemonHealth(
                protocol, version, abi, artifact, process);
        for (int attempt = 0; attempt < HEALTH_ATTEMPTS; attempt++) {
            if (stopRequested || !process.isAlive() || last.isReady()) {
                return last;
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
            last = rootDaemonHealth(protocol, version, abi, artifact, process);
        }
        return last;
    }

    private VppHealthHandshake.Result waitForHealth(File nativeDir, File profile,
                                                    String protocol, String version, String abi,
                                                    String artifact, String apiIdentity,
                                                    RuntimeProfile selected, Process process)
            throws Exception {
        File socket = new File(profile, "runtime/api.sock");
        VppHealthHandshake.Result last = VppHealthHandshake.evaluate(selected, protocol, version,
                abi, artifact, apiIdentity, RuntimeControlNative.Status.unavailable());
        for (int attempt = 0; attempt < HEALTH_ATTEMPTS; attempt++) {
            if (stopRequested || !process.isAlive()) {
                return last;
            }
            if (socket.exists()) {
                if (selected == RuntimeProfile.ROOT) {
                    // Root VPP creates the private socksvr as root. The app
                    // control shim is read-only and needs a bounded handoff
                    // to query the same instance; no Adapter state is shared.
                    runRootCommand("chmod 0666 " + shellQuote(socket.getPath()), 2L);
                }
                RuntimeControlNative.Status nativeStatus =
                        RuntimeControlNative.query(socket.getPath());
                appendLog("core_control rc=" + nativeStatus.transportCode
                        + " retval=" + nativeStatus.vppRetval
                        + " abi=" + nativeStatus.controlAbiVersion
                        + " api=" + nativeStatus.apiIdentity
                        + " program=" + nativeStatus.program
                        + " version=" + nativeStatus.version);
                last = VppHealthHandshake.evaluate(selected, protocol, version, abi, artifact,
                        apiIdentity, nativeStatus);
                if (last.isReady()) {
                    return last;
                }
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        return last;
    }

    private void monitorExit(Process process) {
        Thread monitor = new Thread(() -> {
            int exitCode;
            try {
                exitCode = process.waitFor();
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return;
            }
            enqueueLifecycle(() -> handleProcessExit(process, exitCode));
        }, "sakamoto-vpp-exit-monitor");
        monitor.start();
    }

    private void monitorPid(long pid) {
        synchronized (stateLock) {
            if (monitoredPid == pid) {
                return;
            }
            monitoredPid = pid;
        }
        Thread monitor = new Thread(() -> {
            try {
                while (!destroying && isPidAlive(pid)) {
                    Thread.sleep(250L);
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } finally {
                if (!destroying) {
                    enqueueLifecycle(() -> handleAdoptedProcessExit(pid));
                }
            }
        }, "sakamoto-adopted-vpp-monitor");
        monitor.setDaemon(true);
        monitor.start();
    }

    private void handleAdoptedProcessExit(long pid) {
        if (monitoredPid == pid) {
            monitoredPid = -1L;
        }
        if (currentPid() != pid || destroying || stopRequested) {
            return;
        }
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishCleanupFailure("VPP exited; ", cleanup, true);
            return;
        }
        clearProfileHandles();
        recoverAfterRuntimeFailure("unexpected_exit", "VPP owner exited unexpectedly");
    }

    private void handleProcessExit(Process process, int exitCode) {
        if (process != vppProcess) {
            return;
        }
        vppProcess = null;
        if (stopRequested || (snapshot != null
                && RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state))) {
            return;
        }
        CleanupResult cleanup = terminateAndClean(profileRoot, currentPid(), process);
        if (!cleanup.ok) {
            publishCleanupFailure("VPP exited with status " + exitCode + "; ", cleanup, true);
            return;
        }
        clearProfileHandles();
        recoverAfterRuntimeFailure("unexpected_exit", "VPP exited with status " + exitCode);
    }

    private boolean stopRuntime() {
        return stopRuntime(true);
    }

    private boolean stopRuntime(boolean stopService) {
        initializeProfilePaths(activeProfile);
        long pid = currentPid();
        boolean residue = profileRoot.exists() || pid > 0L || processAlive(vppProcess);
        if (!residue && snapshot != null && RuntimeSnapshot.STATE_STOPPED.equals(snapshot.state)) {
            stopRequested = false;
            if (persistenceGate.isPersistenceUnavailable()) {
                // Keep this service alive as the temporary in-memory error
                // authority. A new service instance would not inherit the
                // unavailable latch from the stale durable projection.
                appendLog("runtime_state_persistence=stop_blocked pending_recovery");
                return false;
            }
            stopIfInactive();
            return true;
        }
        RuntimeSnapshot current = snapshot == null ? RuntimeSnapshot.stopped(activeProfile, generation)
                : snapshot;
        boolean stoppingPublished = publish(RuntimeSnapshot.stopping(current));
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, vppProcess);
        boolean cleanStopFinalized = false;
        if (!cleanup.ok) {
            if (canFinalizeTransientStopIfGloballyClean(
                    cleanup, current, pid, vppProcess, false)) {
                cleanup = CleanupResult.success();
                cleanStopFinalized = true;
            } else {
                publishCleanupFailure("", cleanup, true);
                stopRequested = false;
                return false;
            }
        } else if (canFinalizeTransientStopIfGloballyClean(
                cleanup, current, pid, vppProcess, true)) {
            // A concurrent durable audit can publish a transient ownership
            // error immediately before STOP. Successful bounded cleanup is
            // already the strong identity witness; clear only that stale
            // error after a fresh global no-owner/no-residue proof.
            cleanStopFinalized = true;
        }
        vppProcess = null;
        clearProfileHandles();
        RuntimeSnapshot stopped = cleanStopFinalized
                ? RuntimeSnapshot.stopped(current.profile, current.generation)
                : RuntimeSnapshot.stoppedAfter(current);
        boolean stoppedPublished = publish(stopped);
        stopRequested = false;
        if (stopService && foregroundStarted && !persistenceGate.isPersistenceUnavailable()) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (stopService && !destroying && !persistenceGate.isPersistenceUnavailable()) {
            stopSelf();
        }
        // Cleanup is allowed to complete even when either projection write
        // failed, but a replacement/new START must observe the unavailable
        // latch and run the explicit recovery probe first.
        return stoppingPublished && stoppedPublished
                && !persistenceGate.isPersistenceUnavailable();
    }

    private void pauseProtection() {
        RuntimeProfile pausedProfile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        boolean stopped = stopRuntime(false);
        if (!stopped && persistenceGate.isPersistenceUnavailable()) {
            return;
        }
        stopRequested = true;
        publish(RuntimeSnapshot.paused(pausedProfile, generation));
        if (foregroundStarted && !persistenceGate.isPersistenceUnavailable()) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying && !persistenceGate.isPersistenceUnavailable()) {
            stopSelf();
        }
    }

    /**
     * A post-stop ownership scan can lose a disappearing profile between the
     * strong PID probe and its exhaustive scan. Retry only that bounded race;
     * a fresh global NONE/NONE audit plus absent profile trees is the proof
     * required to clear the transient error. All other cleanup failures stay
     * fail-closed.
     */
    private boolean canFinalizeTransientStopIfGloballyClean(
            CleanupResult cleanup, RuntimeSnapshot current, long pid, Process process,
            boolean cleanupCompleted) {
        if (cleanup == null) {
            return false;
        }
        String errorCode = cleanupCompleted
                ? current == null ? "" : current.errorCode : cleanup.errorCode;
        String detail = cleanupCompleted
                ? current == null ? "" : current.errorMessage : cleanup.detail;
        if (!RuntimeOwnershipReconciliation.isTransientOwnershipAuditFailure(
                errorCode, detail)) {
            return false;
        }
        // A failed cleanup retry needs a fresh MISSING PID witness. A
        // successful terminateAndClean already proved the owner identity and
        // removed the token, so post-cleanup validation may legitimately be
        // UNKNOWN without weakening the proof.
        RuntimeOwnershipReconciliation.PidIdentity identity = cleanupCompleted
                ? RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN : validatePid(pid);
        boolean processHandleAlive = processAlive(process);
        RuntimeOwnershipReconciliation.GlobalDecision ownership =
                auditGlobalOwnership(false);
        boolean profileResiduePresent = profileDirectory(RuntimeProfile.ROOT).exists()
                || profileDirectory(RuntimeProfile.VPN).exists();
        boolean finalized = RuntimeOwnershipReconciliation.canFinalizeCleanStop(
                identity, processHandleAlive, ownership, profileResiduePresent,
                cleanupCompleted, errorCode, detail);
        if (finalized) {
            appendLog(cleanupCompleted
                    ? "cleanup_audit_error=cleared_after_successful_stop"
                    : "cleanup_audit_race=finalized_clean_stop");
        }
        return finalized;
    }

    private CleanupResult terminateAndClean(File profile, long pid, Process process) {
        if (cleanupFaultInjected) {
            return CleanupResult.failure(pid, "debug cleanup fault injected");
        }
        RuntimeOwnershipReconciliation.PidIdentity identity = validatePid(pid);
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISMATCH) {
            return CleanupResult.failure(pid,
                    "recorded PID identity changed; refusing to kill it");
        }
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN) {
            return cleanupIdentityFailure(pid,
                    "recorded PID identity could not be verified before TERM");
        }
        // RuntimeService is the process supervisor. Product stop never sends
        // a CLI `quit`; TERM/KILL are the only lifecycle signals.
        // A missing PID is already gone. Never send TERM to a stale/reused
        // numeric PID merely because the in-process handle or state file
        // still remembers it.
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MATCH && pid > 0L) {
            runPlatformCommand("kill -TERM " + pid, 2L);
        }
        if (process != null && process.isAlive()) {
            process.destroy();
        }
        WaitResult termResult = waitUntilGone(process, pid, STOP_TERM_MILLIS);
        if (termResult == WaitResult.UNKNOWN) {
            return cleanupIdentityFailure(pid,
                    "recorded PID identity became unverifiable while waiting after TERM");
        }
        if (termResult == WaitResult.MISMATCH) {
            return CleanupResult.failure(pid,
                    "recorded PID identity changed while waiting after TERM; refusing KILL");
        }
        if (termResult == WaitResult.TIMED_OUT) {
            // Re-run the complete privileged identity probe immediately
            // before KILL. Missing means gone; only an exact MATCH may be
            // signalled, preventing stale PID reuse from receiving KILL.
            identity = validatePid(pid);
            if (identity == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN) {
                return cleanupIdentityFailure(pid,
                        "recorded PID identity could not be verified before KILL");
            }
            if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISMATCH) {
                return CleanupResult.failure(pid,
                        "recorded PID identity changed before KILL; refusing to kill it");
            }
            if (identity == RuntimeOwnershipReconciliation.PidIdentity.MATCH && pid > 0L) {
                runPlatformCommand("kill -KILL " + pid, 2L);
            }
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
        WaitResult killResult = termResult == WaitResult.GONE
                ? WaitResult.GONE : waitUntilGone(process, pid, STOP_KILL_MILLIS);
        if (killResult == WaitResult.UNKNOWN) {
            return cleanupIdentityFailure(pid,
                    "recorded PID identity became unverifiable after KILL");
        }
        if (killResult == WaitResult.MISMATCH) {
            return CleanupResult.failure(pid,
                    "recorded PID identity changed after KILL; refusing cleanup");
        }
        if (killResult != WaitResult.GONE) {
            return CleanupResult.failure(pid, "VPP process remained active after bounded stop");
        }
        return removeAndVerifyProfile(profile, pid, process);
    }

    private CleanupResult cleanupIdentityFailure(long pid, String detail) {
        boolean unavailable = activeProfile == RuntimeProfile.ROOT && !rootCommandAvailable();
        return CleanupResult.failure(pid, unavailable ? "root_authorization_required"
                        : "cleanup_failed",
                unavailable ? "recorded PID cannot be audited without root authorization" : detail);
    }

    private CleanupResult removeAndVerifyProfile(File profile, long pid, Process process) {
        RuntimeOwnershipReconciliation.PidIdentity identity = validatePid(pid);
        RuntimeOwnershipReconciliation.OwnershipAudit audit =
                RuntimeOwnershipReconciliation.OwnershipAudit.none();
        // A launch can create the app-UID profile before the shell has
        // published its PID. Audit candidates whenever no in-process handle
        // remains, including a stale durable PID, before deleting residue.
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISSING
                && !processAlive(process) && profile != null && profile.exists()) {
            audit = auditOwnedProcess(profile);
            for (int attempt = 0;
                    attempt < OWNERSHIP_RETRY_ATTEMPTS
                            && RuntimeOwnershipReconciliation.shouldRetryResidueOwnershipAudit(
                                    identity, processAlive(process), audit);
                    attempt++) {
                try {
                    Thread.sleep(OWNERSHIP_RETRY_MILLIS);
                } catch (InterruptedException error) {
                    Thread.currentThread().interrupt();
                    break;
                }
                audit = auditOwnedProcess(profile);
            }
        }
        RuntimeOwnershipReconciliation.CleanupDecision decision =
                RuntimeOwnershipReconciliation.decideCleanup(
                        activeProfile, identity, processAlive(process), audit,
                        rootCommandAvailable());
        if (!decision.canRemove()) {
            return CleanupResult.failure(decision.pid, decision.errorCode, decision.detail);
        }
        if (profile != null && profile.exists()) {
            if (activeProfile == RuntimeProfile.ROOT) {
                int removalStatus = runRootCommandStatus(
                        "rm -rf -- " + shellQuote(profile.getPath()), 5L);
                if (removalStatus != 0) {
                    return CleanupResult.failure(pid,
                            removalStatus == ROOT_COMMAND_UNAVAILABLE
                                    ? "root_authorization_required" : "cleanup_failed",
                            removalStatus == ROOT_COMMAND_UNAVAILABLE
                                    ? "privileged profile removal is unavailable to this app process"
                                    : "privileged profile removal command failed");
                }
            }
            if (profile.exists() && !deleteTree(profile)) {
                return CleanupResult.failure(pid, "profile tree could not be removed");
            }
        }
        if (profile != null && profile.exists()) {
            return CleanupResult.failure(pid, "profile-owned runtime residue remains");
        }
        return CleanupResult.success();
    }

    /**
     * Prove that no live VPP process owns a root profile before removing
     * orphaned residue. The audit matches every ownership identity component
     * written by launchVpp: root UID, exact startup path, executable path and
     * hash, runtime directory, owner token, and selected profile. A live match
     * blocks cleanup; an inspection error also blocks cleanup.
     */
    private RuntimeOwnershipReconciliation.OwnershipAudit auditOwnedProcess(File profile) {
        return auditOwnedProcess(activeProfile, profile);
    }

    private RuntimeOwnershipReconciliation.OwnershipAudit auditOwnedProcess(
            RuntimeProfile selected, File profile) {
        RuntimeProfile profileType = selected == null ? RuntimeProfile.ROOT : selected;
        if (profile == null || !profile.exists()) {
            return RuntimeOwnershipReconciliation.OwnershipAudit.none();
        }
        if (profileType == RuntimeProfile.ROOT && !rootCommandAvailable()) {
            return RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                    "root_authorization_required",
                    "privileged /proc ownership audit is unavailable to this app process");
        }
        String token = readOwnerToken(profile);
        if (token.isEmpty()) {
            return RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                    "profile owner token is absent or invalid");
        }
        File executableFile = runtimeExecutable(
                new File(getApplicationInfo().nativeLibraryDir), profileType);
        String executable = executableFile.getPath();
        final String executableHash;
        try {
            executableHash = sha256(executableFile);
        } catch (Exception error) {
            return RuntimeOwnershipReconciliation.OwnershipAudit.unknown(
                    "packaged VPP executable identity is unavailable");
        }
        String expectedUid = profileType == RuntimeProfile.ROOT
                ? "0" : Integer.toString(android.os.Process.myUid());
        RuntimeOwnershipReconciliation.ProfileSpec spec =
                new RuntimeOwnershipReconciliation.ProfileSpec(
                        profileType,
                        new File(profile, "startup.conf").getPath(),
                        new File(profile, "runtime").getPath(),
                        executable, executableHash, token, expectedUid,
                        profileType == RuntimeProfile.ROOT ? ROOT_COMMAND_UNAVAILABLE : 125,
                        profileType == RuntimeProfile.ROOT
                                ? "root_authorization_required" : "cleanup_failed",
                        profileType == RuntimeProfile.ROOT
                                ? "privileged /proc ownership audit is unavailable to this app process"
                                : "app-UID /proc ownership audit is unavailable to this app process");
        return RuntimeOwnershipReconciliation.inspect(spec, ownershipCommandRunner());
    }

    private WaitResult waitUntilGone(Process process, long pid, long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        do {
            RuntimeOwnershipReconciliation.PidIdentity identity = processGone(pid);
            if (identity == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN) {
                return WaitResult.UNKNOWN;
            }
            if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISMATCH) {
                return WaitResult.MISMATCH;
            }
            if (!processAlive(process) && identity
                    == RuntimeOwnershipReconciliation.PidIdentity.MISSING) {
                return WaitResult.GONE;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return WaitResult.TIMED_OUT;
            }
        } while (System.currentTimeMillis() < deadline);
        RuntimeOwnershipReconciliation.PidIdentity identity = processGone(pid);
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN) {
            return WaitResult.UNKNOWN;
        }
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISMATCH) {
            return WaitResult.MISMATCH;
        }
        return !processAlive(process)
                && identity == RuntimeOwnershipReconciliation.PidIdentity.MISSING
                ? WaitResult.GONE : WaitResult.TIMED_OUT;
    }

    private boolean runtimeExists() {
        if (processAlive(vppProcess)) {
            return true;
        }
        long pid = currentPid();
        if (pid <= 0L || !isPidAlive(pid)) {
            return false;
        }
        adoptRuntime(pid);
        return true;
    }

    private boolean profileHasResidue(RuntimeProfile profile) {
        if (profile == null) {
            return false;
        }
        File root = new File(getFilesDir(), "profiles/" + profile.wireName + "/vpp");
        return root.exists();
    }

    private RuntimeOwnershipReconciliation.PidIdentity processGone(long pid) {
        if (pid <= 0L) {
            return RuntimeOwnershipReconciliation.PidIdentity.MISSING;
        }
        // Reuse the complete privileged ownership probe. A bare kill -0 or
        // /proc existence test cannot distinguish an inaccessible live owner
        // from an absent PID and would make cleanup unsafe.
        return validatePid(pid);
    }

    private boolean isPidAlive(long pid) {
        return validatePid(pid) == RuntimeOwnershipReconciliation.PidIdentity.MATCH;
    }

    private RuntimeOwnershipReconciliation.PidIdentity validatePid(long pid) {
        return validatePid(activeProfile, pid);
    }

    private RuntimeOwnershipReconciliation.PidIdentity validatePid(
            RuntimeProfile selected, long pid) {
        RuntimeProfile profileType = selected == null ? RuntimeProfile.ROOT : selected;
        if (pid <= 0L) {
            return RuntimeOwnershipReconciliation.PidIdentity.MISSING;
        }
        File selectedRoot = profileDirectory(profileType);
        String token = readOwnerToken(selectedRoot);
        if (token.isEmpty()) {
            return RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN;
        }
        File executableFile = runtimeExecutable(
                new File(getApplicationInfo().nativeLibraryDir), profileType);
        String executable = executableFile.getPath();
        final String executableHash;
        try {
            executableHash = sha256(executableFile);
        } catch (Exception error) {
            return RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN;
        }
        String expectedUid = profileType == RuntimeProfile.ROOT
                ? "0" : Integer.toString(android.os.Process.myUid());
        RuntimeOwnershipReconciliation.ProfileSpec spec =
                new RuntimeOwnershipReconciliation.ProfileSpec(
                        profileType,
                        new File(selectedRoot, "startup.conf").getPath(),
                        new File(selectedRoot, "runtime").getPath(),
                        executable, executableHash, token, expectedUid,
                        profileType == RuntimeProfile.ROOT ? ROOT_COMMAND_UNAVAILABLE : 125,
                        profileType == RuntimeProfile.ROOT
                                ? "root_authorization_required" : "cleanup_failed",
                        profileType == RuntimeProfile.ROOT
                                ? "privileged /proc ownership audit is unavailable to this app process"
                                : "app-UID /proc ownership audit is unavailable to this app process");
        return RuntimeOwnershipReconciliation.validatePid(
                spec, pid, ownershipCommandRunner());
    }

    private boolean runPlatformCommand(String command, long timeoutSeconds) {
        return runPlatformCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runPlatformCommandStatus(String command, long timeoutSeconds) {
        return runPlatformCommandStatus(activeProfile, command, timeoutSeconds);
    }

    private int runPlatformCommandStatus(RuntimeProfile selected, String command,
                                         long timeoutSeconds) {
        RuntimeProfile profileType = selected == null ? RuntimeProfile.ROOT : selected;
        return profileType == RuntimeProfile.ROOT
                ? runRootCommandStatus(command, timeoutSeconds)
                : runAppCommandStatus(command, timeoutSeconds);
    }

    private RuntimeOwnershipReconciliation.CommandRunner ownershipCommandRunner() {
        return (profile, command, timeoutSeconds) ->
                runProfileCommandResult(profile, command, timeoutSeconds);
    }

    /** Run a bounded ownership scan and retain its exact-match evidence. */
    private RuntimeOwnershipReconciliation.CommandResult runProfileCommandResult(
            RuntimeProfile selected, String command, long timeoutSeconds) {
        RuntimeProfile profileType = selected == null ? RuntimeProfile.ROOT : selected;
        Process process = null;
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            process = profileType == RuntimeProfile.ROOT
                    ? new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start()
                    : new ProcessBuilder("/system/bin/sh", "-c", command).start();
            final InputStream input = process.getInputStream();
            Thread reader = new Thread(() -> {
                byte[] buffer = new byte[256];
                try {
                    int count;
                    while ((count = input.read(buffer)) >= 0) {
                        if (count > 0 && output.size() < 4096) {
                            output.write(buffer, 0, Math.min(count, 4096 - output.size()));
                        }
                    }
                } catch (IOException ignored) {
                    // The process status remains the authoritative result.
                }
            }, "sakamoto-runtime-owner-audit-reader");
            reader.setDaemon(true);
            reader.start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new RuntimeOwnershipReconciliation.CommandResult(
                        124, output.toString(StandardCharsets.UTF_8.name()));
            }
            reader.join(250L);
            return new RuntimeOwnershipReconciliation.CommandResult(process.exitValue(),
                    output.toString(StandardCharsets.UTF_8.name()));
        } catch (Exception error) {
            if (process != null) {
                process.destroyForcibly();
            }
            return new RuntimeOwnershipReconciliation.CommandResult(profileType == RuntimeProfile.ROOT
                    ? ROOT_COMMAND_UNAVAILABLE : 125, output.toString());
        }
    }

    private void failWithoutRuntime(String code, String message) {
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void failSelectedProfileWithoutRuntime(String code, String message) {
        RuntimeProfile selected = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        publish(RuntimeSnapshot.error(selected, VppHealthHandshake.PROTOCOL, "", "", "",
                code, message, false, -1L, generation));
        stopIfInactive();
    }

    private VpnTunPlatformSession establishPacketAdapterSession(
            ProductPacketAdapterContract adapter) {
        if (adapter == null || !adapter.requiresVpnPlatformSession) {
            return null;
        }
        VpnTunPlatformSession.EstablishResult result =
                VpnTunPlatformSession.establish(this, adapter.enableIpv6);
        if (!result.ok) {
            failSelectedProfileWithoutRuntime(result.errorCode, result.errorMessage);
            return null;
        }
        return result.session;
    }

    private boolean attachVpnTunSessionAfterHealth(RuntimeProfile profile,
                                                   VpnTunPlatformSession session) {
        if (profile != RuntimeProfile.VPN) {
            return true;
        }
        if (session == null || !session.isOpen()) {
            appendLog("vpn_tun_control_attach=missing_session");
            return false;
        }
        RuntimeControlFdClient.AttachResult readiness =
                RuntimeControlFdClient.waitForVpnTunHandoffReady();
        if (!readiness.ok) {
            appendLog("vpn_tun_control_ready=failed code=" + readiness.errorCode
                    + " message=" + readiness.errorMessage);
            return false;
        }
        appendLog("vpn_tun_control_ready=ok");
        int rawFd = session.releaseFd();
        RuntimeControlFdClient.AttachResult result =
                RuntimeControlFdClient.attachVpnTun(rawFd, session.ipv6Enabled);
        if (!result.ok) {
            appendLog("vpn_tun_control_attach=failed code=" + result.errorCode
                    + " message=" + result.errorMessage);
            return false;
        }
        if (!ProductPacketAdapterContract.VPN_ADAPTER.equals(result.adapter)
                || !result.fdAttached || result.ipv6Enabled != session.ipv6Enabled) {
            appendLog("vpn_tun_control_attach=invalid_result adapter=" + result.adapter
                    + " fdAttached=" + result.fdAttached
                    + " ipv6Enabled=" + result.ipv6Enabled);
            return false;
        }
        appendLog("vpn_tun_control_attach=ok adapter=" + result.adapter
                + " ipv6Enabled=" + result.ipv6Enabled);
        return true;
    }

    private boolean startVpnHevTransportAfterTun(RuntimeProfile profile, File nativeDir,
                                                 File currentProfile) {
        if (profile != RuntimeProfile.VPN) {
            return true;
        }
        VpnHevTransportSession.StartResult result =
                VpnHevTransportSession.start(this, nativeDir.getPath(),
                        new File(currentProfile, "logs"));
        if (!result.ok) {
            appendLog("vpn_hev_transport=failed code=" + result.errorCode
                    + " message=" + result.errorMessage);
            return false;
        }
        vpnHevSession = result.session;
        appendLog("vpn_hev_transport=ok name=" + VpnHevTransportSession.TRANSPORT_NAME
                + " socksPort=" + VpnHevTransportSession.DEFAULT_SOCKS_PORT);
        return true;
    }

    private void closeVpnTunSessionAfterNativeHandoff() {
        VpnTunPlatformSession session = vpnTunSession;
        vpnTunSession = null;
        closeVpnTunSessionQuietly(session);
    }

    private void closeVpnTunSessionQuietly(VpnTunPlatformSession session) {
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (IOException error) {
            appendLog("vpn_tun_cleanup_failed=" + messageOf(error));
        }
    }

    private void closeVpnHevSessionQuietly() {
        VpnHevTransportSession session = vpnHevSession;
        vpnHevSession = null;
        if (session == null) {
            return;
        }
        try {
            session.close();
        } catch (RuntimeException error) {
            appendLog("vpn_hev_cleanup_failed=" + messageOf(error));
        }
    }

    private void failWithCleanup(String code, String message) {
        CleanupResult cleanup = terminateAndClean(profileRoot, currentPid(), vppProcess);
        if (!cleanup.ok) {
            publishCleanupFailure(code + ": " + message + "; ", cleanup, true);
            return;
        }
        vppProcess = null;
        clearProfileHandles();
        if (!stopRequested && recoveryPolicy.recoverable(code)) {
            recoverAfterRuntimeFailure(code, message);
            return;
        }
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void recoverAfterRuntimeFailure(String code, String message) {
        if (destroying || stopRequested || !recoveryPolicy.recoverable(code)) {
            publishError(code, message, false, -1L);
            stopIfInactive();
            return;
        }
        RuntimeProfile recoverProfile = activeProfile == null ? RuntimeProfile.ROOT : activeProfile;
        RuntimeRecoveryPolicy.Decision decision = recoveryPolicy.afterFailure(
                recoveryFailureCount, code + ": " + message);
        recoveryFailureCount = decision.nextFailureCount;
        if (decision.requiresUserIntervention) {
            publishError(decision.statusCode, decision.message, false, -1L);
            stopIfInactive();
            return;
        }
        publishError(decision.statusCode, decision.message, false, -1L);
        try {
            Thread.sleep(decision.backoffMillis);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            publishError("runtime_recovery_interrupted",
                    "automatic recovery was interrupted", false, -1L);
            stopIfInactive();
            return;
        }
        if (!destroying && !stopRequested) {
            startRuntime(recoverProfile);
        }
    }

    private void publishError(String code, String message, boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null
                ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, current.version,
                current.artifact, current.abi, code, message, mayBeActive, pid,
                current.generation));
    }

    private void publishCleanupFailure(String prefix, CleanupResult cleanup,
                                       boolean mayBeActive) {
        String code = cleanup == null || cleanup.errorCode.isEmpty()
                ? "cleanup_failed" : cleanup.errorCode;
        String detail = cleanup == null ? "cleanup result is unavailable"
                : prefix + cleanup.detail;
        long pid = cleanup == null ? -1L : cleanup.pid;
        publishError(code, detail, mayBeActive, pid);
    }

    private void publishHealthError(VppHealthHandshake.Result health, String message,
                                    boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null
                ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
        String version = health == null || health.version.isEmpty()
                ? current.version : health.version;
        String code = health == null || health.errorCode.isEmpty()
                ? "health_handshake_failed" : health.errorCode;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, version, current.artifact,
                current.abi, code, message, mayBeActive, pid, current.generation));
    }

    private boolean publish(RuntimeSnapshot next) {
        synchronized (stateLock) {
            RuntimeStateStore.PersistenceGate.Result result = persistenceGate.publish(
                    getFilesDir(), next, processAlive(vppProcess));
            snapshot = result.snapshot;
            if (!result.persisted) {
                exposePersistenceFailure(result, "publish");
                return false;
            }
            if (!result.launchAllowed) {
                exposePersistenceFailure(result, "launch_blocked");
                return false;
            }
            if (foregroundStarted) {
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) {
                    manager.notify(NOTIFICATION_ID, buildNotification(next));
                }
            }
        }
        appendLog("runtime_state=" + next.state + " profile=" + next.profile.wireName
                + " health=" + next.health + (next.errorCode.isEmpty() ? ""
                : " error=" + next.errorCode));
        return true;
    }

    private boolean persistSelectedProductProfile(RuntimeProfile profile) {
        if (productBackend == null) {
            return true;
        }
        ProductStore.MutationResult result = productBackend.selectRuntimeProfile(profile);
        if (result.persisted) {
            appendLog("product_state=profile_selected profile=" + profile.wireName);
            return true;
        }
        publishError(result.errorCode.isEmpty() ? "product_state_persistence_failed"
                        : result.errorCode,
                result.errorMessage.isEmpty()
                        ? "selected runtime profile could not be persisted"
                        : result.errorMessage,
                currentMayBeActive(), currentPid());
        return false;
    }

    private void selectProductProfile(RuntimeProfile profile) {
        if (persistSelectedProductProfile(profile)) {
            appendLog("product_control=profile_select profile=" + profile.wireName);
        }
        refreshProductCatalogProjection("profile_select");
        stopIfInactive();
    }

    private void bindProductApplication(ApplicationSubjectId subjectId) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.bindApplication(subjectId);
        if (result.persisted) {
            appendLog("product_control=bind_app subject=" + subjectId.encode());
        } else {
            publishProductMutationFailure("product_bind_failed", result,
                    "application binding could not be persisted");
        }
        refreshProductCatalogProjection("bind_app");
        stopIfInactive();
    }

    private void unbindProductApplication(ApplicationSubjectId subjectId) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.unbindApplication(subjectId);
        if (result.persisted) {
            appendLog("product_control=unbind_app subject=" + subjectId.encode());
        } else {
            publishProductMutationFailure("product_unbind_failed", result,
                    "application unbinding could not be persisted");
        }
        refreshProductCatalogProjection("unbind_app");
        stopIfInactive();
    }

    private void setProductNetworkGate(ApplicationSubjectId subjectId,
                                       AuthoringPolicyBundle.NetworkContextId context,
                                       boolean blocked) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result =
                productBackend.setNetworkGate(subjectId, context, blocked);
        if (result.persisted) {
            appendLog("product_control=network_gate subject=" + subjectId.encode()
                    + " context=" + context.wireName
                    + " blocked=" + blocked);
        } else {
            publishProductMutationFailure("product_network_gate_failed", result,
                    "Network Gate mutation could not be applied");
        }
        refreshProductCatalogProjection("network_gate");
        refreshProductActivityProjection("network_gate", subjectId);
        stopIfInactive();
    }

    private void setProductL4Rule(AuthoringPolicyBundle.L4Rule rule) {
        if (productBackend == null) {
            stopIfInactive();
            return;
        }
        ProductStore.MutationResult result = productBackend.setL4Rule(rule);
        if (result.persisted) {
            appendLog("product_control=l4_rule subject=" + rule.subjectId.encode()
                    + " family=" + rule.family.wireName
                    + " direction=" + rule.direction.wireName
                    + " ipProtocol=" + rule.ipProtocol
                    + " action=" + rule.action.wireName
                    + " ruleId=" + Long.toUnsignedString(rule.ruleId));
        } else {
            publishProductMutationFailure("product_l4_rule_failed", result,
                    "L4 rule mutation could not be applied");
        }
        refreshProductCatalogProjection("l4_rule");
        refreshProductActivityProjection("l4_rule", rule.subjectId);
        stopIfInactive();
    }

    private void refreshProductCatalogProjection(String reason) {
        if (productBackend == null) {
            return;
        }
        ProductCatalogFormatter.Projection projection =
                productBackend.refreshProductCatalogProjection();
        appendLog("product_catalog_projection=" + projection.catalogStatus
                + " reason=" + reason
                + " entries=" + projection.catalogEntryCount
                + (projection.errorCode.isEmpty() ? "" : " error=" + projection.errorCode)
                + ("valid".equals(projection.productStateStatus)
                        || "missing".equals(projection.productStateStatus) ? ""
                        : " product_state=" + projection.productStateStatus
                                + " product_error=" + projection.productStateErrorCode));
    }

    private void refreshProductActivityProjection(String reason,
                                                  ApplicationSubjectId preferredSubject) {
        if (productBackend == null) {
            return;
        }
        ingestLatestNativeActivity(reason);
        ApplicationSubjectId subject = preferredSubject;
        if (subject == null) {
            ProductStateSnapshot state = productBackend.productState();
            subject = state.boundApplications.isEmpty()
                    ? null : state.boundApplications.iterator().next();
        }
        RuntimeSummary runtime = RuntimeSummary.fromSnapshot(
                snapshot == null ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot,
                CapabilitySet.androidL4(true, true));
        AppDetail detail = productBackend.refreshProductActivityProjection(subject, runtime, 32);
        appendLog("product_activity_projection=published reason=" + reason
                + " subject=" + (subject == null ? "(none)" : subject.encode())
                + " activity=" + detail.activity.size()
                + " rules=" + detail.rules.size()
                + " state=" + detail.state);
    }

    private void ingestLatestNativeActivity(String reason) {
        RuntimeSnapshot current = snapshot;
        if (current == null || !current.isActive()) {
            return;
        }
        RuntimeProfile profile = current.profile == null ? RuntimeProfile.ROOT : current.profile;
        RuntimeControlFdClient.AttachResult status = RuntimeControlFdClient.callJson(58,
                profile == RuntimeProfile.VPN ? "VPN_TUN.STATUS" : "NFQUEUE.STATUS",
                new JSONObject());
        if (!status.ok) {
            appendLog("product_activity_native_status=unavailable reason=" + reason
                    + " profile=" + profile.wireName
                    + " code=" + status.errorCode);
            return;
        }
        JSONObject activity = status.result.optJSONObject("policyDropActivity");
        ProductNativeActivityIngestor.NativePolicyDropRecord record =
                nativePolicyDropRecord(activity);
        if (!ProductNativeActivityIngestor.shouldIngest(record, profile,
                lastNativePolicyDropActivityProfile, lastNativePolicyDropActivityGeneration,
                current.generation, lastNativePolicyDropActivityTotalRecords)) {
            record = null;
        }
        ActivityItem item = ProductNativeActivityIngestor.toActivityItem(record, profile,
                System.currentTimeMillis());
        if (item != null) {
            productBackend.ingestActivity(item);
            lastNativePolicyDropActivityProfile = profile;
            lastNativePolicyDropActivityGeneration = current.generation;
            lastNativePolicyDropActivityTotalRecords = record.totalRecords;
            appendLog("product_activity_native_ingest=ok reason=" + reason
                    + " profile=" + profile.wireName
                    + " kind=policy_drop"
                    + " totalRecords=" + record.totalRecords
                    + " subject=" + item.subjectId.encode()
                    + " winner=" + item.winner
                    + " revision=" + item.policyRevision);
        }

        JSONObject allowedActivity = status.result.optJSONObject("allowedFlowActivity");
        ProductNativeActivityIngestor.NativeAllowedFlowRecord allowedRecord =
                nativeAllowedFlowRecord(allowedActivity);
        if (!ProductNativeActivityIngestor.shouldIngest(allowedRecord, profile,
                lastNativeAllowedFlowActivityProfile, lastNativeAllowedFlowActivityGeneration,
                current.generation, lastNativeAllowedFlowActivityTotalRecords)) {
            return;
        }
        ActivityItem allowed = ProductNativeActivityIngestor.toActivityItem(
                allowedRecord, profile, System.currentTimeMillis());
        if (allowed == null) {
            return;
        }
        productBackend.ingestActivity(allowed);
        lastNativeAllowedFlowActivityProfile = profile;
        lastNativeAllowedFlowActivityGeneration = current.generation;
        lastNativeAllowedFlowActivityTotalRecords = allowedRecord.totalRecords;
        appendLog("product_activity_native_ingest=ok reason=" + reason
                + " profile=" + profile.wireName
                + " kind=allowed_flow"
                + " totalRecords=" + allowedRecord.totalRecords
                + " subject=" + allowed.subjectId.encode()
                + " remote=" + allowed.remoteIp + ":" + allowed.remotePort
                + " revision=" + allowed.policyRevision);
    }

    private static ProductNativeActivityIngestor.NativePolicyDropRecord nativePolicyDropRecord(
            JSONObject activity) {
        if (activity == null) {
            return null;
        }
        return new ProductNativeActivityIngestor.NativePolicyDropRecord(
                activity.optLong("totalRecords", 0L),
                activity.optBoolean("hasLastRecord", false),
                (int) activity.optLong("lastLinuxUid", 0L),
                activity.optBoolean("lastUidKnown", false),
                (int) activity.optLong("lastNetworkContext", 0L),
                activity.optString("lastSourceAddress", ""),
                activity.optString("lastDestinationAddress", ""),
                (int) activity.optLong("lastIpProtocol", 0L),
                (int) activity.optLong("lastSourcePort", 0L),
                (int) activity.optLong("lastDestinationPort", 0L),
                activity.optBoolean("lastPortsAvailable", false),
                activity.optString("lastDeviceDirection", ""),
                activity.optString("lastStage", ""),
                (int) activity.optLong("lastReasonId", 0L),
                activity.optLong("lastRuleId", 0L),
                activity.optLong("lastRevision", 0L));
    }

    private static ProductNativeActivityIngestor.NativeAllowedFlowRecord nativeAllowedFlowRecord(
            JSONObject activity) {
        if (activity == null) {
            return null;
        }
        return new ProductNativeActivityIngestor.NativeAllowedFlowRecord(
                activity.optLong("totalRecords", 0L),
                activity.optBoolean("hasLastRecord", false),
                (int) activity.optLong("lastLinuxUid", 0L),
                activity.optBoolean("lastUidKnown", false),
                (int) activity.optLong("lastNetworkContext", 0L),
                activity.optString("lastSourceAddress", ""),
                activity.optString("lastDestinationAddress", ""),
                (int) activity.optLong("lastIpProtocol", 0L),
                (int) activity.optLong("lastSourcePort", 0L),
                (int) activity.optLong("lastDestinationPort", 0L),
                activity.optBoolean("lastPortsAvailable", false),
                activity.optString("lastDeviceDirection", ""),
                activity.optString("lastFlowDirection", ""),
                activity.optLong("lastPolicyRevision", 0L),
                activity.optLong("lastPackets", 0L),
                activity.optLong("lastBytes", 0L),
                activity.optString("lastProtocolRecognitionState", ""),
                activity.optString("lastApplicationProtocolKey", ""),
                activity.optString("lastApplicationProtocolCategory", ""),
                activity.optString("lastProtocolRecognitionSequence", ""),
                (int) activity.optLong("lastProtocolPayloadPackets", 0L));
    }

    private void publishProductMutationFailure(String fallbackCode,
                                               ProductStore.MutationResult result,
                                               String fallbackMessage) {
        publishError(result == null || result.errorCode.isEmpty()
                        ? fallbackCode : result.errorCode,
                result == null || result.errorMessage.isEmpty()
                        ? fallbackMessage : result.errorMessage,
                currentMayBeActive(), currentPid());
    }

    /**
     * Keep a bounded local error projection when the durable write itself is
     * unavailable. This deliberately does not call publish again: doing so
     * would recurse through the same failing writer and hide the original
     * lifecycle transition. The latch is cleared only by the explicit
     * ownership-audited recovery probe above.
     */
    private void exposePersistenceFailure(RuntimeStateStore.PersistenceGate.Result result,
                                          String phase) {
        synchronized (stateLock) {
            RuntimeSnapshot local = result == null || result.snapshot == null
                    ? (snapshot == null
                            ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot)
                    : result.snapshot;
            snapshot = local;
            Log.e(TAG, "failed to persist runtime state: "
                    + (result == null ? "missing persistence result" : result.detail));
            if (foregroundStarted) {
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) {
                    manager.notify(NOTIFICATION_ID, buildNotification(local));
                }
            }
            appendLog("runtime_state_persistence=unavailable phase=" + phase
                    + " state=" + local.state + " mayBeActive=" + local.mayBeActive
                    + (local.pid > 0L ? " pid=" + local.pid : ""));
        }
    }

    private Notification buildNotification(RuntimeSnapshot value) {
        String text = "Protection " + value.state;
        if (!value.errorCode.isEmpty()) {
            text += ": " + value.errorCode;
        }
        Notification.Builder builder = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
                ? new Notification.Builder(this, CHANNEL_ID) : new Notification.Builder(this);
        return builder.setContentTitle("Sakamoto protection").setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(value.isActive()).setCategory(Notification.CATEGORY_SERVICE).build();
    }

    private void stopIfInactive() {
        stopIfInactive(latestStartId);
    }

    private void stopIfInactive(int startId) {
        if (persistenceGate.isPersistenceUnavailable()) {
            appendLog("runtime_state_persistence=service_retained pending_recovery");
            return;
        }
        if (snapshot != null && snapshot.mayBeActive) {
            return;
        }
        if (startId <= 0) {
            // onCreate's durable reconciliation has no startId. Do not stop
            // the service here: a START intent may be queued immediately
            // afterward and must not race an onDestroy/stopRequested flag.
            return;
        }
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying) {
            stopSelf(startId);
        }
    }

    private void setCleanupFault(boolean enabled) {
        if ((getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) == 0) {
            appendLog("ignored cleanup fault seam in non-debug build");
            return;
        }
        cleanupFaultInjected = enabled;
        appendLog("debug cleanup fault=" + enabled);
    }

    private Properties readManifest() throws IOException {
        Properties properties = new Properties();
        try (InputStream input = getAssets().open(MANIFEST_ASSET)) {
            properties.load(input);
        }
        return properties;
    }

    private String readExpectedHash(String asset, String label) throws IOException {
        try (InputStream input = getAssets().open(asset)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[128];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    bytes.write(buffer, 0, count);
                }
            }
            String hash = bytes.toString(StandardCharsets.US_ASCII.name()).trim();
            if (!hash.matches("[0-9a-fA-F]{64}")) {
                throw new IOException("invalid " + label + " SHA-256 asset");
            }
            return hash;
        }
    }

    private void prepareProfile(File profile, RuntimeProfile selected) throws IOException {
        File runtime = new File(profile, "runtime");
        File logs = new File(profile, "logs");
        File shm = new File(profile, "shm");
        if ((!runtime.isDirectory() && !runtime.mkdirs())
                || (!logs.isDirectory() && !logs.mkdirs())
                || (!shm.isDirectory() && !shm.mkdirs())) {
            throw new IOException("unable to create profile directories");
        }
        ensureOwnerToken(runtime);
        String config = "unix {\n  nodaemon\n  nobanner\n  runtime-dir "
                + runtime.getPath() + "\n  log " + new File(logs, "vpp.log").getPath()
                + "\n  cli-listen " + new File(runtime, "cli.sock").getPath()
                + "\n  cli-no-pager\n}\n\n"
                + "socksvr {\n  socket-name " + new File(runtime, "api.sock").getPath()
                + "\n}\n\napi-segment {\n  prefix sakamoto-vpp-"
                + selected.wireName + "-v1\n}\n\nstatseg {\n  socket-name "
                + new File(runtime, "statseg.sock").getPath() + "\n}\n";
        try (FileOutputStream output = new FileOutputStream(new File(profile, "startup.conf"))) {
            output.write(config.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
    }

    private void initializeProfilePaths(RuntimeProfile profile) {
        if (profile == null) {
            profile = RuntimeProfile.ROOT;
        }
        File expectedRoot = new File(getFilesDir(), "profiles/" + profile.wireName + "/vpp");
        if (activeProfile != profile || profileRoot == null
                || !expectedRoot.equals(profileRoot)) {
            activeProfile = profile;
            profileRoot = expectedRoot;
            pidFile = new File(profileRoot, "runtime/vpp.pid");
        }
    }

    private void ensureOwnerToken(File runtime) throws IOException {
        File token = new File(runtime, "owner.token");
        if (token.isFile() && !readOwnerToken().isEmpty()) {
            return;
        }
        String value = UUID.randomUUID().toString();
        try (FileOutputStream output = new FileOutputStream(token)) {
            output.write((value + "\n").getBytes(StandardCharsets.US_ASCII));
            output.getFD().sync();
        }
    }

    private String readOwnerToken() {
        initializeProfilePaths(activeProfile);
        return readOwnerToken(profileRoot);
    }

    private String readOwnerToken(File profile) {
        File token = new File(new File(profile, "runtime"), "owner.token");
        try (FileInputStream input = new FileInputStream(token)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[64];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    bytes.write(buffer, 0, count);
                }
            }
            String value = bytes.toString(StandardCharsets.US_ASCII.name()).trim();
            return value.matches("[0-9a-fA-F-]{36}") ? value : "";
        } catch (Exception ignored) {
            return "";
        }
    }

    private void clearProfileHandles() {
        closeVpnHevSessionQuietly();
        closeVpnTunSessionAfterNativeHandoff();
        profileRoot = null;
        pidFile = null;
    }

    private long currentPid() {
        if (snapshot != null && snapshot.pid > 0L) {
            return snapshot.pid;
        }
        initializeProfilePaths(activeProfile);
        return readPid(pidFile);
    }

    private boolean currentMayBeActive() {
        return snapshot != null && snapshot.mayBeActive;
    }

    private static boolean processAlive(Process process) {
        return process != null && process.isAlive();
    }

    private static long readPid(File file) {
        try (FileInputStream input = new FileInputStream(file)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[32];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    bytes.write(buffer, 0, count);
                }
            }
            return Long.parseLong(bytes.toString(StandardCharsets.US_ASCII.name()).trim());
        } catch (Exception ignored) {
            return -1L;
        }
    }

    private static String sha256(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[32 * 1024];
        try (InputStream input = new FileInputStream(file)) {
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) {
                    digest.update(buffer, 0, count);
                }
            }
        }
        StringBuilder value = new StringBuilder(64);
        for (byte item : digest.digest()) {
            value.append(String.format(Locale.US, "%02x", item & 0xff));
        }
        return value.toString();
    }

    private boolean rootCommandAvailable() {
        File su = new File(SU_PATH);
        return su.isFile() && su.canExecute();
    }

    private boolean runRootCommand(String command, long timeoutSeconds) {
        return runRootCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runRootCommandStatus(String command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return 124;
            }
            return process.exitValue();
        } catch (Exception error) {
            Log.w(TAG, "root command failed", error);
            return ROOT_COMMAND_UNAVAILABLE;
        }
    }

    private boolean runAppCommand(String command, long timeoutSeconds) {
        return runAppCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runAppCommandStatus(String command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder("/system/bin/sh", "-c", command).start();
            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return 124;
            }
            return process.exitValue();
        } catch (Exception error) {
            Log.w(TAG, "app command failed", error);
            return 125;
        }
    }

    private static boolean deleteTree(File file) {
        if (!file.exists()) {
            return true;
        }
        File[] children = file.listFiles();
        if (children != null) {
            for (File child : children) {
                if (!deleteTree(child)) {
                    return false;
                }
            }
        }
        return file.delete();
    }

    private static String deviceAbi() {
        return Build.SUPPORTED_ABIS.length == 0 ? "" : Build.SUPPORTED_ABIS[0];
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String messageOf(Exception error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    @Override
    public void onDestroy() {
        destroying = true;
        stopRequested = true;
        if (snapshot != null && snapshot.isActive()
                && !RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)) {
            publish(RuntimeSnapshot.stopping(snapshot));
        }
        // Main-thread destruction never waits. The serial worker drains an
        // in-flight start and performs bounded stop/cleanup before shutdown.
        Runnable teardown = () -> {
            try {
                stopRuntime();
            } finally {
                lifecycle.shutdown();
            }
        };
        // Destruction supersedes queued queries/starts. Drop those stale
        // requests so a bounded lifecycle queue always retains room for the
        // teardown barrier; an in-flight task remains serialized ahead of it.
        if (lifecycle instanceof ThreadPoolExecutor) {
            ((ThreadPoolExecutor) lifecycle).getQueue().clear();
        }
        if (!enqueueLifecycle(teardown)) {
            appendLog("lifecycle_teardown_rejected");
        }
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void appendLog(String line) {
        File log = runtimeLog;
        if (log == null) {
            File logs = new File(getFilesDir(), "logs");
            if (!logs.isDirectory()) {
                logs.mkdirs();
            }
            log = new File(logs, "runtime-service.log");
            runtimeLog = log;
        }
        try (FileOutputStream output = new FileOutputStream(log, true)) {
            output.write((System.currentTimeMillis() + " " + line + "\n")
                    .getBytes(StandardCharsets.UTF_8));
            if (log.length() > 256L * 1024L) {
                // Keep diagnostics bounded; the durable snapshot remains the
                // source of truth for current state and error identity.
                log.delete();
            }
        } catch (IOException error) {
            Log.e(TAG, "runtime log write failed", error);
        }
    }

    private static final class CleanupResult {
        final boolean ok;
        final long pid;
        final String detail;
        final String errorCode;

        private CleanupResult(boolean ok, long pid, String detail, String errorCode) {
            this.ok = ok;
            this.pid = pid;
            this.detail = detail;
            this.errorCode = errorCode;
        }

        static CleanupResult success() {
            return new CleanupResult(true, -1L, "", "");
        }

        static CleanupResult failure(long pid, String detail) {
            return failure(pid, "cleanup_failed", detail);
        }

        static CleanupResult failure(long pid, String errorCode, String detail) {
            return new CleanupResult(false, pid, detail, errorCode);
        }
    }

}
