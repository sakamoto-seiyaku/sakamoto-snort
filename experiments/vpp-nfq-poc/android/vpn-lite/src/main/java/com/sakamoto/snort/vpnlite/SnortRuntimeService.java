package com.sakamoto.snort.vpnlite;

import android.Manifest;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Android lifecycle authority for exactly one packaged VPP runtime. */
public final class SnortRuntimeService extends Service {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.RUNTIME_START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.RUNTIME_STOP";
    public static final String EXTRA_CONTROL_PROTOCOL_VERSION = "controlProtocolVersion";

    private static final String TAG = "SnortRuntimeService";
    private static final String SU_PATH = "/system/bin/su";
    private static final String VPP_BINARY = "libvpp_runtime.so";
    private static final String VPPCTL_BINARY = "libvppctl.so";
    private static final String MANIFEST_ASSET = "vpp-runtime.properties";
    private static final String HASH_ASSET = "vpp-runtime.sha256";
    private static final String CHANNEL_ID = "snort-runtime";
    private static final int NOTIFICATION_ID = 1001;
    private static final int CONTROL_PROTOCOL_VERSION = 1;
    private static final int HEALTH_ATTEMPTS = 24;
    private static final long HEALTH_RETRY_MILLIS = 250L;
    private static final long GRACEFUL_STOP_MILLIS = 3000L;
    private static final long TERM_STOP_MILLIS = 2000L;
    private static final long KILL_STOP_MILLIS = 2000L;

    private final Object stateLock = new Object();
    private final ExecutorService lifecycle = Executors.newSingleThreadExecutor(runnable -> {
        Thread thread = new Thread(runnable, "snort-runtime-lifecycle");
        thread.setDaemon(false);
        return thread;
    });

    private volatile boolean stopRequested;
    private volatile boolean foregroundStarted;
    private volatile boolean destroying;
    private volatile long monitoredPid = -1L;
    private RuntimeSnapshot snapshot;
    private Process vppProcess;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        snapshot = RuntimeStateStore.read(getFilesDir());
        initializeProfilePaths();
        lifecycle.execute(this::reconcileDurableRuntime);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        int protocolVersion = intent == null ? CONTROL_PROTOCOL_VERSION
                : intent.getIntExtra(EXTRA_CONTROL_PROTOCOL_VERSION, CONTROL_PROTOCOL_VERSION);
        if (protocolVersion != CONTROL_PROTOCOL_VERSION) {
            lifecycle.execute(() -> {
                publishError("unsupported_control_protocol", "expected version 1",
                        currentMayBeActive(), currentPid());
                stopIfInactive();
            });
            return START_STICKY;
        }

        if (ACTION_STOP.equals(action)) {
            stopRequested = true;
            lifecycle.execute(this::stopRuntime);
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action) || action == null) {
            if (!ensureForeground()) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            lifecycle.execute(this::startRuntime);
        }
        return START_STICKY;
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            return;
        }
        NotificationChannel channel = new NotificationChannel(
                CHANNEL_ID, "Sakamoto protection", NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("Ongoing status for the Sakamoto VPP runtime");
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    public static boolean notificationsReady(Context context) {
        if (Build.VERSION.SDK_INT >= 33
                && context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            return false;
        }
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        return manager == null || manager.areNotificationsEnabled();
    }

    private synchronized boolean ensureForeground() {
        if (foregroundStarted) {
            return true;
        }
        RuntimeSnapshot pending = RuntimeSnapshot.starting(
                RuntimeSnapshot.PROFILE_ROOT, VppHealthHandshake.PROTOCOL, "",
                deviceAbi(), "device-" + deviceAbi());
        try {
            startForeground(NOTIFICATION_ID, buildNotification(pending),
                    Build.VERSION.SDK_INT >= 29
                            ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0);
            foregroundStarted = true;
            if (!notificationsReady(this)) {
                publishError("notification_permission_required",
                        "allow the ongoing protection notification before starting",
                        false, -1L);
                stopForeground(true);
                foregroundStarted = false;
                return false;
            }
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null && snapshot != null) {
                manager.notify(NOTIFICATION_ID, buildNotification(snapshot));
            }
            appendLog("foreground_service=ready notification_id=" + NOTIFICATION_ID);
            return true;
        } catch (RuntimeException error) {
            publishError("foreground_service_start_failed", messageOf(error), false, -1L);
            Log.e(TAG, "unable to enter foreground", error);
            foregroundStarted = false;
            return false;
        }
    }

    private void startRuntime() {
        initializeProfilePaths();
        if (destroying) {
            stopRequested = true;
            stopRuntime();
            return;
        }
        if (runtimeExists()) {
            appendLog("start ignored: exactly one runtime is already active");
            return;
        }
        stopRequested = false;

        Properties manifest;
        try {
            manifest = readManifest();
        } catch (IOException error) {
            failWithoutRuntime("runtime_manifest_unreadable", messageOf(error));
            return;
        }
        String expectedProtocol = manifest.getProperty("protocol", "").trim();
        String expectedVersion = manifest.getProperty("version", "").trim();
        String expectedAbi = manifest.getProperty("abi", "").trim();
        String actualDeviceAbi = deviceAbi();
        String abiEvidence = "manifest-" + expectedAbi + ",device-" + actualDeviceAbi;
        if (!VppHealthHandshake.PROTOCOL.equals(expectedProtocol)
                || expectedVersion.isEmpty() || expectedAbi.isEmpty()) {
            failWithoutRuntime("runtime_manifest_invalid",
                    "protocol, version and abi must match the runtime contract");
            return;
        }
        if (!expectedAbi.equals(actualDeviceAbi)) {
            failWithoutRuntime("runtime_abi_mismatch", abiEvidence);
            return;
        }

        publish(RuntimeSnapshot.starting(RuntimeSnapshot.PROFILE_ROOT, expectedProtocol,
                expectedVersion, expectedAbi, abiEvidence));

        CleanupResult preflight = removeAndVerifyProfile(profileRoot, -1L, null);
        if (!preflight.ok) {
            publishError("cleanup_failed", "pre-start residue: " + preflight.detail,
                    true, preflight.pid);
            return;
        }
        if (stopRequested) {
            stopRuntime();
            return;
        }

        try {
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File vpp = new File(nativeDir, VPP_BINARY);
            if (!vpp.isFile()) {
                failWithoutRuntime("vpp_artifact_missing", VPP_BINARY + " is not packaged");
                return;
            }
            if (!vpp.canExecute() && !vpp.setExecutable(true, false)) {
                failWithoutRuntime("vpp_artifact_not_executable", vpp.getPath());
                return;
            }
            String expectedHash = readExpectedHash();
            String actualHash = sha256(vpp);
            if (!expectedHash.equalsIgnoreCase(actualHash)) {
                failWithoutRuntime("vpp_artifact_hash_mismatch",
                        "packaged VPP SHA-256 did not match");
                return;
            }

            prepareProfile(profileRoot, nativeDir);
            Process process = launchVpp(vpp, nativeDir, profileRoot);
            vppProcess = process;
            appendLog("vpp_process=started artifact=" + vpp.getName());

            VppHealthHandshake.Result health = waitForHealth(nativeDir, profileRoot,
                    expectedProtocol, expectedVersion, expectedAbi, actualDeviceAbi, process);
            if (stopRequested) {
                stopRuntime();
                return;
            }
            if (!health.isReady()) {
                failWithCleanup(health.errorCode.isEmpty()
                                ? "health_handshake_failed" : health.errorCode,
                        "protocol=" + health.protocol + " version=" + health.version
                                + " " + health.abiEvidence);
                return;
            }

            long pid = readPid(pidFile);
            if (pid <= 0L || !isPidAlive(pid)) {
                failWithCleanup("runtime_pid_unverified",
                        "health passed but the VPP owner PID was not active");
                return;
            }
            publish(RuntimeSnapshot.running(RuntimeSnapshot.PROFILE_ROOT, health.protocol,
                    health.version, health.abi, health.abiEvidence, health.health, pid));
            appendLog("runtime_state=running protocol=" + health.protocol
                    + " version=" + health.version + " " + health.abiEvidence
                    + " pid=" + pid);
            monitorExit(process);
        } catch (Exception error) {
            Log.e(TAG, "VPP runtime startup failed", error);
            if (stopRequested) {
                stopRuntime();
            } else {
                failWithCleanup("runtime_start_failed", messageOf(error));
            }
        }
    }

    /** Reconcile durable state before accepting a new lifecycle command. */
    private void reconcileDurableRuntime() {
        initializeProfilePaths();
        long pid = currentPid();
        if (pid > 0L && processExists(pid)) {
            if (!isPidAlive(pid)) {
                publishError("runtime_pid_identity_mismatch",
                        "recorded PID does not identify the packaged VPP; refusing to kill it",
                        true, pid);
                return;
            }
            adoptRuntime(pid);
            return;
        }

        boolean durableResidue = profileRoot.exists()
                || (snapshot != null && snapshot.isActive());
        if (!durableResidue) {
            return;
        }

        CleanupResult cleanup = removeAndVerifyProfile(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishError("cleanup_failed", "durable runtime recovery: " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        clearProfileHandles();
        publishError("runtime_recovered", "previous VPP owner was no longer active",
                false, -1L);
    }

    /** Adopt an already-running product VPP after Android recreated this service. */
    private void adoptRuntime(long pid) {
        initializeProfilePaths();
        if (monitoredPid == pid && snapshot != null
                && RuntimeSnapshot.STATE_RUNNING.equals(snapshot.state)) {
            return;
        }
        try {
            Properties manifest = readManifest();
            String protocol = manifest.getProperty("protocol", "").trim();
            String version = manifest.getProperty("version", "").trim();
            String abi = manifest.getProperty("abi", "").trim();
            String device = deviceAbi();
            if (!VppHealthHandshake.PROTOCOL.equals(protocol)
                    || version.isEmpty() || !abi.equals(device)) {
                publishError("runtime_manifest_invalid",
                        "durable VPP could not be adopted: manifest mismatch", true, pid);
                monitorPid(pid);
                return;
            }

            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File cliSocket = new File(profileRoot, "runtime/cli.sock");
            CommandResult command = cliSocket.exists()
                    ? runVppctl(nativeDir, cliSocket, "show version")
                    : new CommandResult(125, "runtime CLI socket is absent");
            VppHealthHandshake.Result health = VppHealthHandshake.parse(
                    protocol, version, abi, device, command.exitCode, command.output);
            if (!health.isReady()) {
                publishError(health.errorCode.isEmpty()
                                ? "runtime_recovery_health_failed" : health.errorCode,
                        "adopted VPP health check failed: " + command.output.trim(),
                        true, pid);
            } else {
                publish(RuntimeSnapshot.running(RuntimeSnapshot.PROFILE_ROOT,
                        health.protocol, health.version, health.abi, health.abiEvidence,
                        health.health, pid));
            }
        } catch (Exception error) {
            publishError("runtime_recovery_failed", messageOf(error), true, pid);
        }
        monitorPid(pid);
    }

    private Process launchVpp(File vpp, File nativeDir, File currentProfile)
            throws IOException {
        File runtimeDirectory = new File(currentProfile, "runtime");
        File logDirectory = new File(currentProfile, "logs");
        File shmDirectory = new File(currentProfile, "shm");
        String command = "umask 022; echo $$ > " + shellQuote(pidFile.getPath())
                + "; export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                + " SAKAMOTO_ANDROID_SHM_DIR=" + shellQuote(shmDirectory.getPath())
                + "; exec " + shellQuote(vpp.getPath())
                + " plugin_path " + shellQuote(nativeDir.getPath())
                + " -c " + shellQuote(new File(currentProfile, "startup.conf").getPath())
                + " >" + shellQuote(new File(logDirectory, "vpp-stdout.log").getPath())
                + " 2>&1";
        return new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
    }

    private VppHealthHandshake.Result waitForHealth(
            File nativeDir, File profile, String expectedProtocol, String expectedVersion,
            String expectedAbi, String actualDeviceAbi, Process process) throws Exception {
        File cliSocket = new File(profile, "runtime/cli.sock");
        VppHealthHandshake.Result last = VppHealthHandshake.parse(
                expectedProtocol, expectedVersion, expectedAbi, actualDeviceAbi,
                -1, "");
        for (int attempt = 1; attempt <= HEALTH_ATTEMPTS; attempt++) {
            if (stopRequested || !process.isAlive()) {
                return last;
            }
            if (cliSocket.exists()) {
                CommandResult command = runVppctl(nativeDir, cliSocket, "show version");
                last = VppHealthHandshake.parse(expectedProtocol, expectedVersion,
                        expectedAbi, actualDeviceAbi, command.exitCode, command.output);
                if (last.isReady()) {
                    return last;
                }
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        return last;
    }

    private CommandResult runVppctl(File nativeDir, File cliSocket, String command)
            throws Exception {
        File vppctl = new File(nativeDir, VPPCTL_BINARY);
        if (!vppctl.isFile()) {
            return new CommandResult(127, VPPCTL_BINARY + " is not packaged");
        }
        String shell = "export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                + "; exec " + shellQuote(vppctl.getPath()) + " -s "
                + shellQuote(cliSocket.getPath()) + " " + command;
        Process commandProcess = new ProcessBuilder(SU_PATH, "0", "sh", "-c", shell)
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> copyBounded(commandProcess.getInputStream(), output),
                "snort-vppctl-reader");
        reader.start();
        if (!commandProcess.waitFor(2, TimeUnit.SECONDS)) {
            commandProcess.destroyForcibly();
            reader.join(500L);
            return new CommandResult(124, "vppctl health query timed out");
        }
        reader.join(500L);
        return new CommandResult(commandProcess.exitValue(),
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
        }, "snort-vpp-exit-monitor");
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
            boolean stillAlive = true;
            try {
                while (!destroying && isPidAlive(pid)) {
                    Thread.sleep(250L);
                }
                stillAlive = processExists(pid);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
            } finally {
                final boolean observedAlive = stillAlive;
                if (!destroying) {
                    lifecycle.execute(() -> handleAdoptedProcessExit(pid, observedAlive));
                }
            }
        }, "snort-adopted-vpp-monitor");
        monitor.setDaemon(true);
        monitor.start();
    }

    private void handleAdoptedProcessExit(long pid, boolean stillAlive) {
        if (monitoredPid == pid) {
            monitoredPid = -1L;
        }
        if (currentPid() != pid || destroying
                || stopRequested || (snapshot != null
                && RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state))) {
            return;
        }
        if (stillAlive && !isPidAlive(pid)) {
            publishError("runtime_pid_identity_mismatch",
                    "adopted PID changed identity; refusing to kill it", true, pid);
            return;
        }
        CleanupResult cleanup = removeAndVerifyProfile(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishError("cleanup_failed", "adopted VPP exited; " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        clearProfileHandles();
        publishError("unexpected_exit", "adopted VPP exited unexpectedly", false, -1L);
        stopIfInactive();
    }

    private void handleProcessExit(Process process, int exitCode) {
        if (process != vppProcess) {
            return;
        }
        vppProcess = null;
        if (stopRequested || RuntimeSnapshot.STATE_STOPPING.equals(snapshot.state)) {
            return;
        }
        long pid = currentPid();
        CleanupResult cleanup = removeAndVerifyProfile(profileRoot, pid, null);
        if (!cleanup.ok) {
            publishError("cleanup_failed",
                    "VPP exited with status " + exitCode + "; " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        publishError("unexpected_exit", "VPP exited with status " + exitCode,
                false, -1L);
        clearProfileHandles();
        stopIfInactive();
    }

    private void stopRuntime() {
        initializeProfilePaths();
        long pid = currentPid();
        boolean residue = profileRoot.exists() || pid > 0L || processAlive(vppProcess);
        if (!residue && RuntimeSnapshot.STATE_STOPPED.equals(snapshot.state)) {
            stopRequested = false;
            stopIfInactive();
            return;
        }

        publish(RuntimeSnapshot.stopping(snapshot));
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, vppProcess);
        if (!cleanup.ok) {
            publishError("cleanup_failed", cleanup.detail, true, cleanup.pid);
            stopRequested = false;
            return;
        }

        vppProcess = null;
        clearProfileHandles();
        publish(RuntimeSnapshot.stopped());
        stopRequested = false;
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        if (!destroying) {
            stopSelf();
        }
    }

    private CleanupResult terminateAndClean(File currentProfile, long pid, Process process) {
        if (pid > 0L && processExists(pid) && !isPidAlive(pid)) {
            return CleanupResult.failure(pid,
                    "recorded PID no longer identifies the packaged VPP; refusing to kill it");
        }
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File cliSocket = new File(currentProfile, "runtime/cli.sock");
        if (cliSocket.exists()) {
            try {
                runVppctl(nativeDir, cliSocket, "quit");
            } catch (Exception error) {
                appendLog("vppctl_quit_failed=" + messageOf(error));
            }
        }
        if (!waitUntilGone(process, pid, GRACEFUL_STOP_MILLIS)) {
            if (pid > 0L) {
                runRootCommand("kill -TERM " + pid, 2L);
            }
            if (process != null && process.isAlive()) {
                process.destroy();
            }
        }
        if (!waitUntilGone(process, pid, TERM_STOP_MILLIS)) {
            if (pid > 0L) {
                runRootCommand("kill -KILL " + pid, 2L);
            }
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
        if (!waitUntilGone(process, pid, KILL_STOP_MILLIS)) {
            return CleanupResult.failure(pid, "VPP PID/process remained active after KILL");
        }
        return removeAndVerifyProfile(currentProfile, pid, process);
    }

    private CleanupResult removeAndVerifyProfile(File currentProfile, long pid, Process process) {
        if (pid > 0L && isPidAlive(pid)) {
            return CleanupResult.failure(pid, "VPP PID " + pid + " is still active");
        }
        if (processAlive(process)) {
            return CleanupResult.failure(pid, "VPP process handle is still active");
        }
        if (!packagedRuntimeAbsent()) {
            return CleanupResult.failure(pid,
                    "a packaged VPP process remains active without the recorded owner PID");
        }
        if (currentProfile != null && currentProfile.exists()) {
            boolean rootClean = runRootCommand(
                    "rm -rf -- " + shellQuote(currentProfile.getPath()), 5L);
            if (currentProfile.exists() && !deleteTree(currentProfile)) {
                return CleanupResult.failure(pid, "profile tree could not be removed");
            }
            if (!rootClean && currentProfile.exists()) {
                return CleanupResult.failure(pid, "root profile cleanup failed");
            }
        }
        if (currentProfile != null && !verifyProfileAbsent(currentProfile)) {
            return CleanupResult.failure(pid,
                    "profile directory, socket, or temporary runtime residue remains");
        }
        return CleanupResult.success();
    }

    private boolean verifyProfileAbsent(File currentProfile) {
        File runtime = new File(currentProfile, "runtime");
        File cli = new File(runtime, "cli.sock");
        File statseg = new File(runtime, "statseg.sock");
        File shm = new File(currentProfile, "shm");
        boolean localAbsent = !currentProfile.exists() && !runtime.exists()
                && !cli.exists() && !statseg.exists() && !shm.exists();
        String command = "test ! -e " + shellQuote(currentProfile.getPath())
                + " && test ! -e " + shellQuote(cli.getPath())
                + " && test ! -e " + shellQuote(statseg.getPath())
                + " && test ! -e " + shellQuote(shm.getPath());
        return localAbsent && runRootCommand(command, 2L);
    }

    private boolean packagedRuntimeAbsent() {
        return runRootCommand("! pgrep -f '[l]ibvpp_runtime.so' >/dev/null", 2L);
    }

    private boolean waitUntilGone(Process process, long pid, long timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        do {
            if (!processAlive(process) && (pid <= 0L || !isPidAlive(pid))) {
                return true;
            }
            try {
                Thread.sleep(100L);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                return false;
            }
        } while (System.currentTimeMillis() < deadline);
        return !processAlive(process) && (pid <= 0L || !isPidAlive(pid));
    }

    private boolean runtimeExists() {
        if (processAlive(vppProcess)) {
            return true;
        }
        long pid = currentPid();
        if (pid <= 0L || !processExists(pid)) {
            return false;
        }
        if (!isPidAlive(pid)) {
            publishError("runtime_pid_identity_mismatch",
                    "recorded PID does not identify the packaged VPP; refusing to start another",
                    true, pid);
            return true;
        }
        adoptRuntime(pid);
        return true;
    }

    private boolean processExists(long pid) {
        return pid > 0L && runRootCommand("kill -0 " + pid, 2L);
    }

    /** True only when the PID is alive and still identifies this packaged VPP. */
    private boolean isPidAlive(long pid) {
        if (!processExists(pid)) {
            return false;
        }
        File expected = new File(new File(getApplicationInfo().nativeLibraryDir), VPP_BINARY);
        String processDirectory = "/proc/" + pid;
        String command = "test -r " + processDirectory + "/cmdline && ("
                + "tr '\\0' ' ' <" + processDirectory + "/cmdline | grep -F -- "
                + shellQuote(expected.getPath()) + " >/dev/null || "
                + "readlink " + processDirectory + "/exe | grep -F -- "
                + shellQuote(expected.getPath()) + " >/dev/null)";
        return runRootCommand(command, 2L);
    }

    private void failWithoutRuntime(String code, String message) {
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void failWithCleanup(String code, String message) {
        long pid = currentPid();
        CleanupResult cleanup = terminateAndClean(profileRoot, pid, vppProcess);
        if (!cleanup.ok) {
            publishError("cleanup_failed", code + ": " + message + "; " + cleanup.detail,
                    true, cleanup.pid);
            return;
        }
        vppProcess = null;
        clearProfileHandles();
        publishError(code, message, false, -1L);
        stopIfInactive();
    }

    private void publishError(String code, String message, boolean mayBeActive, long pid) {
        RuntimeSnapshot current = snapshot == null ? RuntimeSnapshot.stopped() : snapshot;
        publish(RuntimeSnapshot.error(current.profile, current.protocol, current.version,
                current.abi, current.abiEvidence, code, message, mayBeActive, pid));
    }

    private void publish(RuntimeSnapshot next) {
        synchronized (stateLock) {
            try {
                RuntimeStateStore.write(getFilesDir(), next);
            } catch (IOException error) {
                Log.e(TAG, "failed to persist runtime state", error);
                return;
            }
            snapshot = next;
            if (foregroundStarted) {
                NotificationManager manager = getSystemService(NotificationManager.class);
                if (manager != null) {
                    manager.notify(NOTIFICATION_ID, buildNotification(next));
                }
            }
        }
        appendLog("runtime_state=" + next.state + " health=" + next.health
                + " mayBeActive=" + next.mayBeActive
                + (next.errorCode.isEmpty() ? "" : " error=" + next.errorCode));
    }

    private Notification buildNotification(RuntimeSnapshot value) {
        String text = "Protection " + value.state;
        if (!value.errorCode.isEmpty()) {
            text += ": " + value.errorCode;
        }
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Sakamoto protection")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(value.isActive())
                .setCategory(Notification.CATEGORY_SERVICE)
                .build();
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

    private void prepareProfile(File currentProfile, File nativeDir) throws IOException {
        File runtime = new File(currentProfile, "runtime");
        File logs = new File(currentProfile, "logs");
        File shm = new File(currentProfile, "shm");
        if ((!runtime.isDirectory() && !runtime.mkdirs())
                || (!logs.isDirectory() && !logs.mkdirs())
                || (!shm.isDirectory() && !shm.mkdirs())) {
            throw new IOException("unable to create VPP profile directories");
        }
        String config = "unix {\n"
                + "  nodaemon\n  nobanner\n"
                + "  runtime-dir " + runtime.getPath() + "\n"
                + "  log " + new File(logs, "vpp.log").getPath() + "\n"
                + "  cli-listen " + new File(runtime, "cli.sock").getPath() + "\n"
                + "  cli-no-pager\n}\n\n"
                + "api-segment {\n  prefix sakamoto-vpp-runtime-v1\n}\n\n"
                + "statseg {\n  socket-name " + new File(runtime, "statseg.sock").getPath()
                + "\n}\n\n"
                + "plugins {\n  path " + nativeDir.getPath() + "\n"
                + "  plugin default { disable }\n}\n";
        File configuration = new File(currentProfile, "startup.conf");
        try (FileOutputStream output = new FileOutputStream(configuration)) {
            output.write(config.getBytes(StandardCharsets.UTF_8));
            output.getFD().sync();
        }
    }

    private boolean runRootCommand(String command, long timeoutSeconds) {
        try {
            Process process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
            boolean exited = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!exited) {
                process.destroyForcibly();
                process.waitFor(500L, TimeUnit.MILLISECONDS);
                return false;
            }
            return process.exitValue() == 0;
        } catch (Exception error) {
            Log.w(TAG, "root command failed", error);
            return false;
        }
    }

    private void initializeProfilePaths() {
        if (profileRoot == null) {
            profileRoot = new File(getFilesDir(), "profiles/root/vpp");
        }
        if (pidFile == null) {
            pidFile = new File(profileRoot, "runtime/vpp.pid");
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
        initializeProfilePaths();
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
        byte[] hash = digest.digest();
        StringBuilder output = new StringBuilder(hash.length * 2);
        for (byte value : hash) {
            output.append(String.format(Locale.US, "%02x", value & 0xff));
        }
        return output.toString();
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
            // The command exit code remains authoritative.
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
        if (hasDurableRuntime()) {
            stopRequested = true;
            Future<?> cleanup = lifecycle.submit(this::stopRuntime);
            try {
                cleanup.get(15L, TimeUnit.SECONDS);
            } catch (TimeoutException error) {
                publishError("cleanup_failed", "service destroyed before runtime cleanup completed",
                        true, currentPid());
                cleanup.cancel(true);
            } catch (Exception error) {
                publishError("cleanup_failed", "service destruction cleanup failed: "
                        + messageOf(error), true, currentPid());
            }
        }
        lifecycle.shutdownNow();
        super.onDestroy();
    }

    private boolean hasDurableRuntime() {
        initializeProfilePaths();
        return processAlive(vppProcess) || profileRoot.exists()
                || currentPid() > 0L || (snapshot != null && snapshot.isActive());
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
        } catch (IOException error) {
            Log.e(TAG, "failed to write runtime log", error);
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
