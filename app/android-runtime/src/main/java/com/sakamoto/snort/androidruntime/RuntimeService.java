package com.sakamoto.snort.androidruntime;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * Sole Android lifecycle authority for one profile-owned VPP runtime.
 *
 * <p>The Activity sends only versioned product requests. This service owns
 * profile selection, foreground visibility, artifact/adapter health, process
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
    private static final String VPPCTL_BINARY = "libvppctl.so";
    private static final String MANIFEST_ASSET = "vpp-runtime.properties";
    private static final String HASH_ASSET = "vpp-runtime.sha256";
    private static final String CHANNEL_ID = "sakamoto-runtime";
    private static final int NOTIFICATION_ID = 6701;
    private static final int HEALTH_ATTEMPTS = 24;
    private static final long HEALTH_RETRY_MILLIS = 250L;
    private static final long STOP_GRACE_MILLIS = 2500L;
    private static final long STOP_TERM_MILLIS = 1500L;
    private static final long STOP_KILL_MILLIS = 1500L;

    private final Object stateLock = new Object();
    private final ExecutorService lifecycle = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "sakamoto-runtime-lifecycle");
        thread.setDaemon(false);
        return thread;
    });

    private volatile boolean stopRequested;
    private volatile boolean foregroundStarted;
    private volatile boolean destroying;
    private volatile long monitoredPid = -1L;
    private RuntimeSnapshot snapshot;
    private Process vppProcess;
    private ParcelFileDescriptor vpnFd;
    private RuntimeProfile activeProfile;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;
    private long generation;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        snapshot = RuntimeStateStore.read(getFilesDir());
        generation = snapshot.generation;
        activeProfile = snapshot.profile;
        initializeProfilePaths(activeProfile);
        lifecycle.execute(this::reconcileDurableRuntime);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_QUERY : intent.getAction();
        if (action == null) {
            action = ACTION_QUERY;
        }
        if (!ACTION_START.equals(action) && !ACTION_QUERY.equals(action)
                && !ACTION_STOP.equals(action)) {
            final String rejectedAction = action;
            lifecycle.execute(() -> publishError("unsupported_runtime_action",
                    "unknown runtime action: " + rejectedAction,
                    currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_ACTION)
                && !action.equals(intent.getStringExtra(RuntimeControlProtocol.EXTRA_ACTION))) {
            lifecycle.execute(() -> publishError("runtime_action_mismatch",
                    "intent action and versioned action disagree", currentMayBeActive(), currentPid()));
            return START_NOT_STICKY;
        }
        int protocolVersion = intent == null ? RuntimeControlProtocol.VERSION
                : intent.getIntExtra(RuntimeControlProtocol.EXTRA_PROTOCOL_VERSION, -1);
        if (protocolVersion != RuntimeControlProtocol.VERSION) {
            lifecycle.execute(() -> publishError("unsupported_control_protocol",
                    "expected " + RuntimeControlProtocol.NAME, currentMayBeActive(), currentPid()));
            return START_STICKY;
        }

        RuntimeProfile requested = null;
        if (intent != null && intent.hasExtra(RuntimeControlProtocol.EXTRA_PROFILE)) {
            try {
                requested = RuntimeProfile.parse(
                        intent.getStringExtra(RuntimeControlProtocol.EXTRA_PROFILE));
            } catch (IllegalArgumentException error) {
                lifecycle.execute(() -> publishError("invalid_runtime_profile", error.getMessage(),
                        currentMayBeActive(), currentPid()));
                return START_NOT_STICKY;
            }
        }

        if (ACTION_STOP.equals(action)) {
            stopRequested = true;
            lifecycle.execute(this::stopRuntime);
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action)) {
            final RuntimeProfile profile = requested == null ? activeProfile : requested;
            if (!ensureForeground(profile)) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            lifecycle.execute(() -> startRuntime(profile));
            return START_STICKY;
        }
        // QUERY is intentionally side-effect free; the Activity reads the
        // durable snapshot and may issue this request to wake a recreated
        // service for durable-runtime reconciliation.
        if (currentMayBeActive() && !ensureForeground(activeProfile)) {
            return START_NOT_STICKY;
        }
        lifecycle.execute(this::reconcileDurableRuntime);
        return START_STICKY;
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
        if (requestedProfile == null) {
            requestedProfile = RuntimeProfile.ROOT;
        }
        if (runtimeExists()) {
            if (requestedProfile == activeProfile) {
                appendLog("start ignored: exactly one runtime is already active");
                return;
            }
            stopRequested = true;
            stopRuntime();
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
        String protocol = manifest.getProperty("protocol", "").trim();
        String version = manifest.getProperty("version", "").trim();
        String abi = manifest.getProperty("abi", "").trim();
        String expectedArtifact = manifest.getProperty("artifact", "").trim();
        String expectedAdapter;
        try {
            expectedAdapter = manifestAdapterArtifact(manifest, activeProfile);
        } catch (IOException error) {
            failWithoutRuntime("runtime_manifest_invalid", messageOf(error));
            return;
        }
        String deviceAbi = deviceAbi();
        if (!VppHealthHandshake.PROTOCOL.equals(protocol) || version.isEmpty()
                || abi.isEmpty() || expectedArtifact.isEmpty()) {
            failWithoutRuntime("runtime_manifest_invalid",
                    "protocol, version, abi and artifact identity are required");
            return;
        }
        if (!abi.equals(deviceAbi)) {
            failWithoutRuntime("runtime_abi_mismatch", "manifest=" + abi + ",device=" + deviceAbi);
            return;
        }

        publish(RuntimeSnapshot.starting(activeProfile, protocol, version, expectedArtifact,
                generation));
        CleanupResult preflight = removeAndVerifyProfile(profileRoot, currentPid(), null);
        if (!preflight.ok) {
            publishError("cleanup_failed", "pre-start residue: " + preflight.detail,
                    true, preflight.pid);
            return;
        }

        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File vpp = new File(nativeDir, VPP_BINARY);
        File adapter = new File(nativeDir, expectedAdapter);
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
            if (!adapter.isFile()) {
                throw new IOException("profile adapter is not packaged: " + adapter.getName());
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
            if (activeProfile == RuntimeProfile.VPN) {
                if (!establishVpnAdapter()) {
                    failWithoutRuntime("vpn_adapter_unavailable",
                            "VPN authorization or TUN establishment failed");
                    return;
                }
            }
            prepareProfile(profileRoot, nativeDir, activeProfile, adapter.getName());
            Process process = launchVpp(vpp, nativeDir, profileRoot, activeProfile);
            vppProcess = process;
            appendLog("vpp_process=started profile=" + activeProfile.wireName
                    + " artifact=" + expectedArtifact);
            VppHealthHandshake.Result health = waitForHealth(nativeDir, profileRoot, protocol,
                    version, deviceAbi, expectedArtifact, activeProfile, process);
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
            publish(RuntimeSnapshot.running(activeProfile, protocol, version, expectedArtifact,
                    deviceAbi, health.adapter, health.health, pid, generation));
            appendLog("runtime_state=running profile=" + activeProfile.wireName
                    + " version=" + version + " adapter=" + health.adapter);
            monitorExit(process);
        } catch (Exception error) {
            Log.e(TAG, "VPP runtime startup failed", error);
            failWithCleanup("runtime_start_failed", messageOf(error));
        }
    }

    private boolean establishVpnAdapter() {
        if (vpnFd != null) {
            return true;
        }
        try {
            VpnService.Builder builder = new VpnService.Builder()
                    .setSession("Sakamoto VPP")
                    .setMtu(1500)
                    .addAddress("10.111.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addAddress("fd00:111:111::2", 128)
                    .addRoute("::", 0);
            vpnFd = builder.establish();
            return vpnFd != null;
        } catch (RuntimeException error) {
            appendLog("vpn_establish_failed=" + messageOf(error));
            return false;
        }
    }

    private void reconcileDurableRuntime() {
        initializeProfilePaths(activeProfile);
        if (snapshot != null && snapshot.isActive() && !foregroundStarted
                && !ensureForeground(activeProfile)) {
            return;
        }
        long pid = currentPid();
        PidIdentity identity = validatePid(pid);
        if (identity == PidIdentity.MATCH) {
            adoptRuntime(pid);
            return;
        }
        if (identity == PidIdentity.MISMATCH || identity == PidIdentity.UNKNOWN) {
            publishError("runtime_pid_unverified",
                    "durable VPP owner PID could not be safely adopted; refusing cleanup",
                    true, pid);
            return;
        }
        boolean residue = profileRoot.exists() || (snapshot != null && snapshot.isActive());
        if (!residue) {
            return;
        }
        if (pid <= 0L && snapshot != null && snapshot.isActive() && profileRoot.exists()) {
            publishError("runtime_pid_unverified",
                    "durable runtime has profile residue but no owner PID; refusing cleanup",
                    true, -1L);
            return;
        }
        CleanupResult cleanup = removeAndVerifyProfile(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishError("cleanup_failed", "durable recovery: " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        closeVpnAdapter();
        publishError("runtime_recovered", "previous VPP owner was no longer active", false, -1L);
        publish(RuntimeSnapshot.stoppedAfter(snapshot));
    }

    private void adoptRuntime(long pid) {
        if (monitoredPid == pid && snapshot != null
                && RuntimeSnapshot.STATE_RUNNING.equals(snapshot.state)) {
            return;
        }
        try {
            Properties manifest = readManifest();
            String protocol = manifest.getProperty("protocol", "").trim();
            String version = manifest.getProperty("version", "").trim();
            String abi = manifest.getProperty("abi", "").trim();
            String artifact = manifest.getProperty("artifact", "").trim();
            String expectedAdapter;
            try {
                expectedAdapter = manifestAdapterArtifact(manifest, activeProfile);
            } catch (IOException error) {
                publishError("runtime_manifest_invalid", messageOf(error), true, pid);
                monitorPid(pid);
                return;
            }
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            if (!VppHealthHandshake.PROTOCOL.equals(protocol) || version.isEmpty()
                    || abi.isEmpty() || artifact.isEmpty()) {
                publishError("runtime_manifest_invalid",
                        "protocol, version, abi and artifact identity are required", true, pid);
                monitorPid(pid);
                return;
            }
            String actualAbi = deviceAbi();
            if (!abi.equals(actualAbi)) {
                publishError("runtime_abi_mismatch",
                        "manifest=" + abi + ",device=" + actualAbi, true, pid);
                monitorPid(pid);
                return;
            }
            File vpp = new File(nativeDir, VPP_BINARY);
            File adapter = new File(nativeDir, expectedAdapter);
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
            if (!adapter.isFile()) {
                publishError("runtime_adapter_missing",
                        "profile adapter is not packaged: " + adapter.getName(), true, pid);
                monitorPid(pid);
                return;
            }
            if (activeProfile == RuntimeProfile.VPN && !establishVpnAdapter()) {
                publishError("vpn_adapter_unavailable",
                        "VPN authorization or TUN establishment failed", true, pid);
                monitorPid(pid);
                return;
            }
            File socket = new File(profileRoot, "runtime/cli.sock");
            CommandResult command = socket.exists()
                    ? runHealthProbe(nativeDir, socket)
                    : new CommandResult(125, "runtime CLI socket is absent");
            String output = "Artifact: " + artifact + "\n" + command.output;
            if (pluginIdentityPresent(command.output, activeProfile)) {
                output += "\nPlugin: " + activeProfile.adapter + " adapter ready\n";
            }
            VppHealthHandshake.Result health = VppHealthHandshake.parse(activeProfile, protocol,
                    version, abi, artifact, command.exitCode, output);
            if (!health.isReady()) {
                publishError(health.errorCode, "adopted runtime health failed", true, pid);
            } else {
                publish(RuntimeSnapshot.running(activeProfile, protocol, version, artifact, abi,
                        health.adapter, health.health, pid, generation));
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
                + " SAKAMOTO_VPP_OWNER_TOKEN=" + shellQuote(token)
                + " SAKAMOTO_RUNTIME_PROFILE=" + shellQuote(profile.wireName)
                + " SAKAMOTO_RUNTIME_ADAPTER=" + shellQuote(profile.adapter)
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
                                                    String artifact, RuntimeProfile selected,
                                                    Process process) throws Exception {
        File socket = new File(profile, "runtime/cli.sock");
        VppHealthHandshake.Result last = VppHealthHandshake.parse(selected, protocol, version,
                abi, artifact, -1, "");
        for (int attempt = 0; attempt < HEALTH_ATTEMPTS; attempt++) {
            if (stopRequested || !process.isAlive()) {
                return last;
            }
            if (socket.exists()) {
                CommandResult command = runHealthProbe(nativeDir, socket);
                String output = "Artifact: " + artifact + "\n" + command.output;
                if (pluginIdentityPresent(command.output, selected)) {
                    output += "\nPlugin: " + selected.adapter + " adapter ready\n";
                }
                last = VppHealthHandshake.parse(selected, protocol, version, abi, artifact,
                        command.exitCode, output);
                if (last.isReady()) {
                    return last;
                }
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        return last;
    }

    private CommandResult runHealthProbe(File nativeDir, File socket) throws Exception {
        CommandResult version = runVppctl(nativeDir, socket, "show version");
        if (version.exitCode != 0) {
            return version;
        }
        CommandResult plugins = runVppctl(nativeDir, socket, "show plugins");
        return new CommandResult(plugins.exitCode, version.output + "\n" + plugins.output);
    }

    private CommandResult runVppctl(File nativeDir, File socket, String command) throws Exception {
        File vppctl = new File(nativeDir, VPPCTL_BINARY);
        if (!vppctl.isFile()) {
            return new CommandResult(127, "vppctl artifact is not packaged");
        }
        // Pass the complete command as one argv element.  vppctl joins its
        // arguments before sending them to the VPP CLI; letting a shell parse
        // a multiline query would split it into separate shell commands.
        ProcessBuilder builder;
        if (activeProfile == RuntimeProfile.ROOT) {
            String shell = "export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                    + "; exec " + shellQuote(vppctl.getPath()) + " -s "
                    + shellQuote(socket.getPath()) + " " + shellQuote(command);
            builder = new ProcessBuilder(SU_PATH, "0", "sh", "-c", shell);
        } else {
            builder = new ProcessBuilder(vppctl.getPath(), "-s", socket.getPath(), command);
            builder.environment().put("LD_LIBRARY_PATH", nativeDir.getPath());
        }
        Process process = builder.redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> copyBounded(process.getInputStream(), output),
                "sakamoto-vppctl-reader");
        reader.start();
        if (!process.waitFor(2, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            reader.join(500L);
            return new CommandResult(124, "vppctl health query timed out");
        }
        reader.join(500L);
        return new CommandResult(process.exitValue(),
                output.toString(StandardCharsets.UTF_8.name()));
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
            lifecycle.execute(() -> handleProcessExit(process, exitCode));
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
                    lifecycle.execute(() -> handleAdoptedProcessExit(pid));
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
            publishError("cleanup_failed", "VPP exited; " + cleanup.detail, true, cleanup.pid);
            return;
        }
        closeVpnAdapter();
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
            publishError("cleanup_failed", "VPP exited with status " + exitCode + "; "
                    + cleanup.detail, true, cleanup.pid);
            return;
        }
        closeVpnAdapter();
        clearProfileHandles();
        publishError("unexpected_exit", "VPP exited with status " + exitCode, false, -1L);
        stopIfInactive();
    }

    private void stopRuntime() {
        initializeProfilePaths(activeProfile);
        long pid = currentPid();
        boolean residue = profileRoot.exists() || pid > 0L || processAlive(vppProcess)
                || vpnFd != null;
        if (!residue && snapshot != null && RuntimeSnapshot.STATE_STOPPED.equals(snapshot.state)) {
            stopRequested = false;
            stopIfInactive();
            return;
        }
        RuntimeSnapshot current = snapshot == null ? RuntimeSnapshot.stopped(activeProfile, generation)
                : snapshot;
        publish(RuntimeSnapshot.stopping(current));
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, vppProcess);
        if (!cleanup.ok) {
            publishError("cleanup_failed", cleanup.detail, true, cleanup.pid);
            stopRequested = false;
            return;
        }
        vppProcess = null;
        closeVpnAdapter();
        clearProfileHandles();
        publish(RuntimeSnapshot.stoppedAfter(current));
        stopRequested = false;
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying) {
            stopSelf();
        }
    }

    private CleanupResult terminateAndClean(File profile, long pid, Process process) {
        PidIdentity identity = validatePid(pid);
        if (identity == PidIdentity.MISMATCH) {
            return CleanupResult.failure(pid,
                    "recorded PID identity changed; refusing to kill it");
        }
        if (identity == PidIdentity.UNKNOWN) {
            return CleanupResult.failure(pid,
                    "recorded PID identity could not be verified; refusing cleanup");
        }
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File socket = profile == null ? null : new File(profile, "runtime/cli.sock");
        if (socket != null && socket.exists()) {
            try {
                runVppctl(nativeDir, socket, "quit");
            } catch (Exception error) {
                appendLog("vppctl_quit_failed=" + messageOf(error));
            }
        }
        if (!waitUntilGone(process, pid, STOP_GRACE_MILLIS)) {
            if (pid > 0L) {
                runPlatformCommand("kill -TERM " + pid, 2L);
            }
            if (process != null && process.isAlive()) {
                process.destroy();
            }
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
        PidIdentity identity = validatePid(pid);
        if (identity == PidIdentity.MATCH) {
            return CleanupResult.failure(pid, "VPP PID remains active");
        }
        if (identity == PidIdentity.MISMATCH) {
            return CleanupResult.failure(pid,
                    "recorded PID identity changed; refusing to remove profile");
        }
        if (identity == PidIdentity.UNKNOWN) {
            return CleanupResult.failure(pid,
                    "recorded PID identity could not be verified; refusing cleanup");
        }
        if (processAlive(process)) {
            return CleanupResult.failure(pid, "VPP process handle remains active");
        }
        if (pid <= 0L && process == null && profile != null && profile.exists()) {
            return CleanupResult.failure(pid,
                    "profile residue has no durable owner PID; refusing cleanup");
        }
        if (profile != null && profile.exists()) {
            if (activeProfile == RuntimeProfile.ROOT) {
                runRootCommand("rm -rf -- " + shellQuote(profile.getPath()), 5L);
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

    private boolean processExists(long pid) {
        return pid > 0L && runPlatformCommandStatus("kill -0 " + pid, 2L) == 0;
    }

    private boolean processGone(long pid) {
        if (pid <= 0L) {
            return true;
        }
        // A command failure is deliberately treated as "not gone".  The
        // cleanup path must not remove durable ownership state merely because
        // /proc or kill(2) was temporarily unavailable.
        return runPlatformCommandStatus("kill -0 " + pid, 2L) == 1;
    }

    private boolean isPidAlive(long pid) {
        return validatePid(pid) == PidIdentity.MATCH;
    }

    private PidIdentity validatePid(long pid) {
        if (pid <= 0L) {
            return PidIdentity.MISSING;
        }
        int exists = runPlatformCommandStatus("kill -0 " + pid, 2L);
        if (exists == 1) {
            return PidIdentity.MISSING;
        }
        if (exists != 0) {
            return PidIdentity.UNKNOWN;
        }
        initializeProfilePaths(activeProfile);
        String token = readOwnerToken();
        if (token.isEmpty()) {
            return PidIdentity.UNKNOWN;
        }
        String startup = new File(profileRoot, "startup.conf").getPath();
        String cmdline = "/proc/" + pid + "/cmdline";
        String environ = "/proc/" + pid + "/environ";
        String command = "if ! test -r " + shellQuote(cmdline) + " || ! test -r "
                + shellQuote(environ) + "; then exit 125; fi"
                + " && tr '\\0' ' ' <" + shellQuote(cmdline) + " | grep -F -- "
                + shellQuote(startup) + " >/dev/null"
                + " && tr '\\0' '\\n' <" + shellQuote(environ) + " | grep -F -- "
                + shellQuote("SAKAMOTO_VPP_OWNER_TOKEN=" + token) + " >/dev/null"
                + " && tr '\\0' '\\n' <" + shellQuote(environ) + " | grep -F -- "
                + shellQuote("SAKAMOTO_RUNTIME_PROFILE=" + activeProfile.wireName)
                + " >/dev/null"
                + " && tr '\\0' '\\n' <" + shellQuote(environ) + " | grep -F -- "
                + shellQuote("SAKAMOTO_RUNTIME_ADAPTER=" + activeProfile.adapter)
                + " >/dev/null";
        int status = runPlatformCommandStatus(command, 2L);
        if (status == 0) {
            return PidIdentity.MATCH;
        }
        return status == 1 ? PidIdentity.MISMATCH : PidIdentity.UNKNOWN;
    }

    private boolean runPlatformCommand(String command, long timeoutSeconds) {
        return runPlatformCommandStatus(command, timeoutSeconds) == 0;
    }

    private int runPlatformCommandStatus(String command, long timeoutSeconds) {
        return activeProfile == RuntimeProfile.ROOT
                ? runRootCommandStatus(command, timeoutSeconds)
                : runAppCommandStatus(command, timeoutSeconds);
    }

    private void failWithoutRuntime(String code, String message) {
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void failWithCleanup(String code, String message) {
        CleanupResult cleanup = terminateAndClean(profileRoot, currentPid(), vppProcess);
        if (!cleanup.ok) {
            publishError("cleanup_failed", code + ": " + message + "; " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        vppProcess = null;
        closeVpnAdapter();
        clearProfileHandles();
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void publishError(String code, String message, boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null
                ? RuntimeSnapshot.stopped(activeProfile, generation) : snapshot;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, current.version,
                current.artifact, current.abi, current.adapter, code, message, mayBeActive, pid,
                current.generation));
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
        if (snapshot != null && snapshot.mayBeActive) {
            return;
        }
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying) {
            stopSelf();
        }
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

    private void prepareProfile(File profile, File nativeDir, RuntimeProfile selected,
                                String adapterName) throws IOException {
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
                + "\n  cli-no-pager\n}\n\napi-segment {\n  prefix sakamoto-vpp-"
                + selected.wireName + "-v1\n}\n\nstatseg {\n  socket-name "
                + new File(runtime, "statseg.sock").getPath() + "\n}\n\nplugins {\n  path "
                + nativeDir.getPath() + "\n  plugin " + adapterName + " { enable }\n}\n";
        try (FileOutputStream output = new FileOutputStream(new File(profile, "startup.conf"))) {
            output.write(config.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
    }

    private void initializeProfilePaths(RuntimeProfile profile) {
        if (profile == null) {
            profile = RuntimeProfile.ROOT;
        }
        if (activeProfile != profile || profileRoot == null) {
            activeProfile = profile;
            profileRoot = new File(getFilesDir(), "profiles/" + profile.wireName + "/vpp");
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
        File token = new File(new File(profileRoot, "runtime"), "owner.token");
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

    private static void copyBounded(InputStream input, ByteArrayOutputStream output) {
        try (InputStream source = input) {
            byte[] buffer = new byte[1024];
            int count;
            while ((count = source.read(buffer)) >= 0) {
                if (count > 0 && output.size() < 64 * 1024) {
                    output.write(buffer, 0, Math.min(count, 64 * 1024 - output.size()));
                }
            }
        } catch (IOException ignored) {
            // Exit code remains authoritative.
        }
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
            return 125;
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

    private void closeVpnAdapter() {
        ParcelFileDescriptor descriptor = vpnFd;
        vpnFd = null;
        if (descriptor != null) {
            try {
                descriptor.close();
            } catch (IOException error) {
                appendLog("vpn_fd_close_failed=" + messageOf(error));
            }
        }
    }

    private static String adapterArtifact(RuntimeProfile profile) {
        return profile.adapterArtifact;
    }

    private static String manifestAdapterArtifact(Properties manifest, RuntimeProfile profile)
            throws IOException {
        String key = "adapter." + profile.wireName;
        String expected = manifest.getProperty(key, "").trim();
        String canonical = adapterArtifact(profile);
        if (!canonical.equals(expected)) {
            throw new IOException(key + " must identify " + canonical);
        }
        return expected;
    }

    private static boolean pluginIdentityPresent(String output, RuntimeProfile profile) {
        if (output == null || profile == null) {
            return false;
        }
        String lower = output.toLowerCase(Locale.US);
        String artifact = adapterArtifact(profile).toLowerCase(Locale.US);
        String stem = artifact.startsWith("lib") ? artifact.substring(3) : artifact;
        if (stem.endsWith(".so")) {
            stem = stem.substring(0, stem.length() - 3);
        }
        return lower.contains(artifact) || lower.contains(stem);
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
        lifecycle.execute(() -> {
            try {
                stopRuntime();
            } finally {
                lifecycle.shutdown();
            }
        });
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

    private static final class CommandResult {
        final int exitCode;
        final String output;

        CommandResult(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }

    private enum PidIdentity {
        MISSING,
        MATCH,
        MISMATCH,
        UNKNOWN
    }

    private static final class CleanupResult {
        final boolean ok;
        final long pid;
        final String detail;

        private CleanupResult(boolean ok, long pid, String detail) {
            this.ok = ok;
            this.pid = pid;
            this.detail = detail;
        }

        static CleanupResult success() {
            return new CleanupResult(true, -1L, "");
        }

        static CleanupResult failure(long pid, String detail) {
            return new CleanupResult(false, pid, detail);
        }
    }
}
