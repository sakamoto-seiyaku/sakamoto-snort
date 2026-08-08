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

    private static final String TAG = "SakamotoRuntimeService";
    private static final String SU_PATH = "/system/bin/su";
    private static final String VPP_BINARY = "libvpp_runtime.so";
    private static final String MANIFEST_ASSET = "vpp-runtime.properties";
    private static final String HASH_ASSET = "vpp-runtime.sha256";
    private static final String CHANNEL_ID = "sakamoto-runtime";
    private static final int NOTIFICATION_ID = 6701;
    private static final int HEALTH_ATTEMPTS = 24;
    private static final long HEALTH_RETRY_MILLIS = 250L;
    private static final long STOP_TERM_MILLIS = 1500L;
    private static final long STOP_KILL_MILLIS = 1500L;
    private static final int ROOT_COMMAND_UNAVAILABLE = -125;

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

    private volatile boolean stopRequested;
    private volatile boolean foregroundStarted;
    private volatile boolean destroying;
    private volatile boolean cleanupFaultInjected;
    /** Missing/corrupt projections require a two-profile ownership audit. */
    private volatile boolean durableProjectionRequiresAudit;
    /** Set when that audit found ambiguity or unverifiable ownership. */
    private volatile boolean durableRecoveryBlocked;
    private volatile long latestStartRequestMillis;
    private volatile int latestStartId;
    private volatile long monitoredPid = -1L;
    private RuntimeSnapshot snapshot;
    private Process vppProcess;
    private RuntimeProfile activeProfile;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;
    private long generation;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        RuntimeStateStore.ReadResult durable = RuntimeStateStore.readResult(getFilesDir());
        snapshot = durable.snapshot;
        durableProjectionRequiresAudit = !durable.present || !durable.valid;
        generation = snapshot.generation;
        activeProfile = snapshot.profile;
        initializeProfilePaths(activeProfile);
        enqueueLifecycle(this::reconcileDurableRuntime);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        latestStartId = Math.max(latestStartId, startId);
        String action = intent == null ? ACTION_QUERY : intent.getAction();
        if (action == null) {
            action = ACTION_QUERY;
        }
        if (!ACTION_START.equals(action) && !ACTION_QUERY.equals(action)
                && !ACTION_STOP.equals(action)) {
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

        if (ACTION_START.equals(action)) {
            if (requestTimeMillis > latestStartRequestMillis) {
                latestStartRequestMillis = requestTimeMillis;
            }
            // A valid start request is authoritative over any delayed stop
            // from an Activity instance that has already been replaced.
            stopRequested = false;
        }

        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_CLEANUP_FAULT)) {
            final boolean enabled = intent.getBooleanExtra(
                    RuntimeControlProtocol.EXTRA_CLEANUP_FAULT, false);
            enqueueLifecycle(() -> setCleanupFault(enabled));
        }

        if (ACTION_STOP.equals(action)) {
            if (requestTimeMillis > 0L && latestStartRequestMillis > requestTimeMillis) {
                appendLog("ignored stale stop request=" + requestTimeMillis
                        + " latestStart=" + latestStartRequestMillis);
                return START_NOT_STICKY;
            }
            stopRequested = true;
            enqueueLifecycle(this::stopRuntime);
            return START_NOT_STICKY;
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
        // QUERY is a public health request. It must reconcile the durable
        // owner and issue a bounded generated-VAPI show_version call even
        // when this service already monitors the same PID.
        if (currentMayBeActive() && !ensureForeground(activeProfile)) {
            return START_NOT_STICKY;
        }
        queueHealthQuery(startId);
        return START_STICKY;
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
        if (durableProjectionRequiresAudit || durableRecoveryBlocked) {
            publishError("runtime_ownership_unverified",
                    "Root/VPN durable ownership has not been safely reconciled",
                    true, currentPid());
            return;
        }
        if (requestedProfile == null) {
            requestedProfile = RuntimeProfile.ROOT;
        }
        RuntimeProfile previousProfile = activeProfile;
        boolean previousRuntime = runtimeExists() || profileHasResidue(previousProfile)
                || (snapshot != null && snapshot.isActive());
        if (previousRuntime) {
            if (requestedProfile == previousProfile && runtimeExists()) {
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
        }
        activeProfile = requestedProfile;
        initializeProfilePaths(activeProfile);
        stopRequested = false;
        generation++;

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

        if (activeProfile == RuntimeProfile.ROOT && !rootCommandAvailable()) {
            publishError("root_authorization_required",
                    "KernelSU/root execution is unavailable to this app process",
                    profileRoot.exists(), currentPid());
            if (!profileRoot.exists()) {
                stopIfInactive();
            }
            return;
        }

        publish(RuntimeSnapshot.starting(activeProfile, protocol, version, expectedArtifact,
                generation));
        CleanupResult preflight = removeAndVerifyProfile(profileRoot, currentPid(), null);
        if (!preflight.ok) {
            publishCleanupFailure("pre-start residue: ", preflight, true);
            return;
        }

        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File vpp = new File(nativeDir, VPP_BINARY);
        try {
            if (!vpp.isFile()) {
                throw new IOException("VPP artifact is not packaged: " + VPP_BINARY);
            }
            String expectedHash = readExpectedHash();
            if (!expectedArtifact.equalsIgnoreCase("sha256:" + expectedHash)) {
                failWithoutRuntime("runtime_manifest_hash_mismatch",
                        "artifact and SHA-256 assets disagree");
                return;
            }
            String actualArtifact = "sha256:" + sha256(vpp);
            if (!expectedArtifact.equalsIgnoreCase(actualArtifact)) {
                failWithoutRuntime("runtime_artifact_hash_mismatch",
                        "manifest artifact does not match packaged VPP");
                return;
            }
            if (!vpp.canExecute() && !vpp.setExecutable(true, false)) {
                throw new IOException("VPP artifact is not executable");
            }
            prepareProfile(profileRoot, activeProfile);
            Process process = launchVpp(vpp, nativeDir, profileRoot, activeProfile);
            vppProcess = process;
            appendLog("vpp_process=started profile=" + activeProfile.wireName
                    + " artifact=" + expectedArtifact);
            VppHealthHandshake.Result health = waitForHealth(nativeDir, profileRoot, protocol,
                    version, deviceAbi, expectedArtifact, expectedApiIdentity, activeProfile,
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
            long pid = readPid(pidFile);
            if (pid <= 0L || !isPidAlive(pid)) {
                failWithCleanup("runtime_pid_unverified",
                        "health passed but the VPP owner PID was not active");
                return;
            }
            publish(RuntimeSnapshot.running(activeProfile, protocol, health.version,
                    expectedArtifact, deviceAbi, health.health, pid, generation));
            appendLog("runtime_state=running profile=" + activeProfile.wireName
                    + " version=" + version + " core_health=" + health.health
                    + " adapter=" + RuntimeSnapshot.ADAPTER_UNAVAILABLE);
            monitorExit(process);
        } catch (Exception error) {
            Log.e(TAG, "VPP runtime startup failed", error);
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
        if (durableProjectionRequiresAudit
                && !reconcileMissingOrCorruptProjection(forceHealthQuery, queryRevision)) {
            return;
        }
        initializeProfilePaths(activeProfile);
        // A cleanup failure is a deliberate fail-closed state. Do not let a
        // periodic QUERY re-adopt the still-live owner as "running" and
        // thereby erase the replacement block before an explicit retry.
        if (snapshot != null && RuntimeSnapshot.STATE_ERROR.equals(snapshot.state)
                && "cleanup_failed".equals(snapshot.errorCode) && snapshot.mayBeActive) {
            return;
        }
        if (snapshot != null && snapshot.isActive() && !foregroundStarted
                && !ensureForeground(activeProfile)) {
            return;
        }
        long pid = currentPid();
        RuntimeOwnershipReconciliation.PidIdentity identity = validatePid(pid);
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MATCH) {
            adoptRuntime(pid, forceHealthQuery, queryRevision);
            return;
        }
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISMATCH
                || identity == RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN) {
            publishError("runtime_pid_unverified",
                    "durable VPP owner PID could not be safely adopted; refusing cleanup",
                    true, pid);
            return;
        }
        boolean residue = profileRoot.exists() || (snapshot != null && snapshot.isActive());
        if (!residue) {
            return;
        }
        // A process death can leave root-owned profile files behind after the
        // PID file has been lost. removeAndVerifyProfile performs a
        // fail-closed ownership audit before it considers that residue safe.
        CleanupResult cleanup = removeAndVerifyProfile(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishCleanupFailure("durable recovery: ", cleanup, true);
            return;
        }
        publishError("runtime_recovered", "previous VPP owner was no longer active", false, -1L);
        publish(RuntimeSnapshot.stoppedAfter(snapshot));
    }

    /**
     * Recover when the product projection is absent or unreadable.  The
     * projection is only a UI-facing cache; Root and VPN profile directories,
     * PID identities, and process ownership evidence are the durable runtime
     * authority.  Both profiles are audited before this service may launch a
     * replacement process.
     */
    private boolean reconcileMissingOrCorruptProjection(boolean forceHealthQuery,
                                                        long queryRevision) {
        RuntimeOwnershipReconciliation.ProfileAudit root =
                auditDurableProfile(RuntimeProfile.ROOT);
        RuntimeOwnershipReconciliation.ProfileAudit vpn =
                auditDurableProfile(RuntimeProfile.VPN);
        RuntimeOwnershipReconciliation.Action action =
                RuntimeOwnershipReconciliation.decide(root.evidence, vpn.evidence);
        if (action == RuntimeOwnershipReconciliation.Action.BLOCK) {
            durableRecoveryBlocked = true;
            activeProfile = RuntimeProfile.ROOT;
            initializeProfilePaths(activeProfile);
            publishError("runtime_ownership_ambiguous",
                    boundedOwnershipFailure(root, vpn), true, -1L);
            return false;
        }

        RuntimeOwnershipReconciliation.ProfileAudit owner =
                action == RuntimeOwnershipReconciliation.Action.ADOPT_ROOT
                ? root : action == RuntimeOwnershipReconciliation.Action.ADOPT_VPN ? vpn : null;
        if (owner != null) {
            if (owner.pid <= 0L) {
                durableRecoveryBlocked = true;
                publishError("runtime_ownership_unverified",
                        "live durable owner did not provide a usable PID", true, -1L);
                return false;
            }
            activeProfile = owner.profile;
            initializeProfilePaths(activeProfile);
            durableProjectionRequiresAudit = false;
            durableRecoveryBlocked = false;
            adoptRuntime(owner.pid, forceHealthQuery, queryRevision);
            return true;
        }

        // CLEAN covers an empty pair and exactly one safely-audited residue
        // profile.  Never remove a profile before the decision seam has
        // proved that the other profile is empty.
        RuntimeOwnershipReconciliation.ProfileAudit residue =
                root.evidence == RuntimeOwnershipReconciliation.Evidence.RESIDUE
                ? root : vpn.evidence == RuntimeOwnershipReconciliation.Evidence.RESIDUE ? vpn : null;
        if (residue != null) {
            activeProfile = residue.profile;
            initializeProfilePaths(activeProfile);
            CleanupResult cleanup = removeAndVerifyProfile(profileRoot, residue.pid, null);
            if (!cleanup.ok) {
                durableRecoveryBlocked = true;
                publishCleanupFailure("durable reconciliation: ", cleanup, true);
                return false;
            }
        }
        activeProfile = snapshot == null || snapshot.profile == null
                ? RuntimeProfile.ROOT : snapshot.profile;
        initializeProfilePaths(activeProfile);
        durableProjectionRequiresAudit = false;
        durableRecoveryBlocked = false;
        publish(RuntimeSnapshot.stopped(activeProfile, generation));
        return true;
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
        RuntimeOwnershipReconciliation.OwnershipAudit candidate =
                identity == RuntimeOwnershipReconciliation.PidIdentity.MISSING
                        ? auditOwnedProcess(selected, profileRoot) : null;
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
            File vpp = new File(nativeDir, VPP_BINARY);
            if (!vpp.isFile()) {
                publishError("runtime_artifact_missing",
                        "VPP artifact is not packaged: " + VPP_BINARY, true, pid);
                monitorPid(pid);
                return;
            }
            String expectedHash = readExpectedHash();
            if (!artifact.equalsIgnoreCase("sha256:" + expectedHash)) {
                publishError("runtime_manifest_hash_mismatch",
                        "artifact and SHA-256 assets disagree", true, pid);
                monitorPid(pid);
                return;
            }
            if (!artifact.equalsIgnoreCase("sha256:" + sha256(vpp))) {
                publishError("runtime_artifact_hash_mismatch",
                        "manifest artifact does not match packaged VPP", true, pid);
                monitorPid(pid);
                return;
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
            VppHealthHandshake.Result health = VppHealthHandshake.evaluate(activeProfile,
                    protocol, version, abi, artifact, apiIdentity, nativeStatus);
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
                              RuntimeProfile profile) throws IOException {
        File runtime = new File(currentProfile, "runtime");
        File logs = new File(currentProfile, "logs");
        File shm = new File(currentProfile, "shm");
        String token = readOwnerToken();
        if (token.isEmpty()) {
            throw new IOException("VPP owner token is absent from profile");
        }
        String command = "umask 022; echo $$ > " + shellQuote(pidFile.getPath())
                + "; export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                + " SAKAMOTO_ANDROID_SHM_DIR=" + shellQuote(shm.getPath())
                + " SAKAMOTO_VPP_RUNTIME_DIR=" + shellQuote(runtime.getPath())
                + " SAKAMOTO_VPP_OWNER_TOKEN=" + shellQuote(token)
                + " SAKAMOTO_RUNTIME_PROFILE=" + shellQuote(profile.wireName)
                + "; exec " + shellQuote(vpp.getPath()) + " plugin_path "
                + shellQuote(nativeDir.getPath()) + " -c "
                + shellQuote(new File(currentProfile, "startup.conf").getPath())
                + " >" + shellQuote(new File(logs, "vpp-stdout.log").getPath()) + " 2>&1";
        if (profile == RuntimeProfile.ROOT) {
            return new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
        }
        return new ProcessBuilder("/system/bin/sh", "-c", command).start();
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
        publishError("unexpected_exit", "VPP owner exited unexpectedly", false, -1L);
        stopIfInactive();
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
        publishError("unexpected_exit", "VPP exited with status " + exitCode, false, -1L);
        stopIfInactive();
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
            stopIfInactive();
            return true;
        }
        RuntimeSnapshot current = snapshot == null ? RuntimeSnapshot.stopped(activeProfile, generation)
                : snapshot;
        publish(RuntimeSnapshot.stopping(current));
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, vppProcess);
        if (!cleanup.ok) {
            publishCleanupFailure("", cleanup, true);
            stopRequested = false;
            return false;
        }
        vppProcess = null;
        clearProfileHandles();
        publish(RuntimeSnapshot.stoppedAfter(current));
        stopRequested = false;
        if (stopService && foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (stopService && !destroying) {
            stopSelf();
        }
        return true;
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
            return CleanupResult.failure(pid,
                    activeProfile == RuntimeProfile.ROOT && !rootCommandAvailable()
                            ? "root_authorization_required" : "cleanup_failed",
                    activeProfile == RuntimeProfile.ROOT && !rootCommandAvailable()
                            ? "recorded PID cannot be audited without root authorization"
                            : "recorded PID identity could not be verified; refusing cleanup");
        }
        // RuntimeService is the process supervisor. Product stop never sends
        // a CLI `quit`; TERM/KILL are the only lifecycle signals.
        if (pid > 0L) {
            runPlatformCommand("kill -TERM " + pid, 2L);
        }
        if (process != null && process.isAlive()) {
            process.destroy();
        }
        if (!waitUntilGone(process, pid, STOP_TERM_MILLIS)) {
            if (pid > 0L) {
                runPlatformCommand("kill -KILL " + pid, 2L);
            }
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
        if (!waitUntilGone(process, pid, STOP_KILL_MILLIS)) {
            return CleanupResult.failure(pid, "VPP process remained active after bounded stop");
        }
        return removeAndVerifyProfile(profile, pid, process);
    }

    private CleanupResult removeAndVerifyProfile(File profile, long pid, Process process) {
        RuntimeOwnershipReconciliation.PidIdentity identity = validatePid(pid);
        RuntimeOwnershipReconciliation.OwnershipAudit audit =
                RuntimeOwnershipReconciliation.OwnershipAudit.none();
        // A launch can create the app-UID profile before the shell has
        // published its PID. Audit candidates whenever no in-process handle
        // remains, including a stale durable PID, before deleting residue.
        if (identity == RuntimeOwnershipReconciliation.PidIdentity.MISSING
                && process == null && profile != null && profile.exists()) {
            audit = auditOwnedProcess(profile);
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
        File executableFile = new File(getApplicationInfo().nativeLibraryDir, VPP_BINARY);
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

    private boolean waitUntilGone(Process process, long pid, long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        do {
            if (!processAlive(process) && (pid <= 0L || processGone(pid))) {
                return true;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return false;
            }
        } while (System.currentTimeMillis() < deadline);
        return !processAlive(process) && (pid <= 0L || processGone(pid));
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

    private boolean processExists(long pid) {
        return pid > 0L && probeProcess(pid) == 0;
    }

    private boolean processGone(long pid) {
        if (pid <= 0L) {
            return true;
        }
        // A command failure is deliberately treated as "not gone".  The
        // cleanup path must not remove durable ownership state merely because
        // /proc or kill(2) was temporarily unavailable.
        return probeProcess(pid) == 1;
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
        // Preserve the dead-PID fast path: a missing packaged executable
        // cannot turn an already-gone owner into an unverifiable live one.
        int exists = probeProcess(profileType, pid);
        if (exists == 1) {
            return RuntimeOwnershipReconciliation.PidIdentity.MISSING;
        }
        if (exists != 0) {
            return RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN;
        }
        File selectedRoot = profileDirectory(profileType);
        String token = readOwnerToken(selectedRoot);
        if (token.isEmpty()) {
            return RuntimeOwnershipReconciliation.PidIdentity.UNKNOWN;
        }
        File executableFile = new File(getApplicationInfo().nativeLibraryDir, VPP_BINARY);
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

    /**
     * Distinguish an absent PID from a live-but-inaccessible one. A bare
     * `kill -0` maps both ESRCH and EPERM to shell status 1, which would make
     * a fail-closed cleanup path mistake an unauthorized live owner for a
     * dead one.
     */
    private int probeProcess(long pid) {
        return probeProcess(activeProfile, pid);
    }

    private int probeProcess(RuntimeProfile selected, long pid) {
        if (pid <= 0L) {
            return 1;
        }
        String command = "if kill -0 " + pid + " 2>/dev/null; then exit 0; "
                + "elif test -e /proc/" + pid + "; then exit 2; else exit 1; fi";
        return runPlatformCommandStatus(selected, command, 2L);
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

    private void failWithCleanup(String code, String message) {
        CleanupResult cleanup = terminateAndClean(profileRoot, currentPid(), vppProcess);
        if (!cleanup.ok) {
            publishCleanupFailure(code + ": " + message + "; ", cleanup, true);
            return;
        }
        vppProcess = null;
        clearProfileHandles();
        publishError(code, message, false, -1L);
        stopIfInactive();
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

    private void publish(RuntimeSnapshot next) {
        synchronized (stateLock) {
            try {
                RuntimeStateStore.write(getFilesDir(), next);
                snapshot = next;
            } catch (IOException error) {
                Log.e(TAG, "failed to persist runtime state", error);
                return;
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

    private String readExpectedHash() throws IOException {
        try (InputStream input = getAssets().open(HASH_ASSET)) {
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
                throw new IOException("invalid VPP runtime SHA-256 asset");
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
