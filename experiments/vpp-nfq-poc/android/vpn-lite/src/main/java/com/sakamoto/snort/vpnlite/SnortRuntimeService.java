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
import java.util.concurrent.TimeUnit;

/** Android lifecycle owner for exactly one packaged VPP runtime. */
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

    private final Object runtimeLock = new Object();
    private volatile Process vppProcess;
    private volatile boolean stopRequested;
    private volatile boolean stopInProgress;
    private volatile boolean foregroundStarted;
    private RuntimeSnapshot snapshot;
    private File profileRoot;
    private File pidFile;
    private File runtimeLog;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        snapshot = RuntimeStateStore.read(getFilesDir());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        int protocolVersion = intent == null ? CONTROL_PROTOCOL_VERSION
                : intent.getIntExtra(EXTRA_CONTROL_PROTOCOL_VERSION, CONTROL_PROTOCOL_VERSION);
        if (protocolVersion != CONTROL_PROTOCOL_VERSION) {
            publishError("unsupported_control_protocol", "expected version 1");
            stopSelf(startId);
            return START_NOT_STICKY;
        }

        if (ACTION_STOP.equals(action)) {
            requestStop();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action) || action == null) {
            if (!ensureForeground()) {
                stopSelf(startId);
                return START_NOT_STICKY;
            }
            startRuntime();
        }
        return START_NOT_STICKY;
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

    private boolean ensureForeground() {
        RuntimeSnapshot current = RuntimeSnapshot.starting(
                RuntimeSnapshot.PROFILE_ROOT, "", BuildConfigAbi.value());
        try {
            startForeground(NOTIFICATION_ID, buildNotification(current),
                    Build.VERSION.SDK_INT >= 29
                            ? ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE : 0);
            foregroundStarted = true;
            if (!notificationsReady(this)) {
                publishError("notification_permission_required",
                        "allow the ongoing protection notification before starting");
                stopForeground(true);
                foregroundStarted = false;
                return false;
            }
            appendLog("foreground_service=ready notification_id=" + NOTIFICATION_ID);
            return true;
        } catch (RuntimeException error) {
            publishError("foreground_service_start_failed", messageOf(error));
            Log.e(TAG, "unable to enter foreground", error);
            foregroundStarted = false;
            return false;
        }
    }

    private void startRuntime() {
        synchronized (runtimeLock) {
            if ((snapshot != null && snapshot.isActive())
                    || (vppProcess != null && vppProcess.isAlive())) {
                appendLog("start ignored: runtime already active");
                return;
            }
            stopRequested = false;
            stopInProgress = false;
            profileRoot = new File(getFilesDir(), "profiles/root/vpp");
            pidFile = new File(profileRoot, "runtime/vpp.pid");
            publishLocked(RuntimeSnapshot.starting(
                    RuntimeSnapshot.PROFILE_ROOT, "", BuildConfigAbi.value()));
        }

        Thread starter = new Thread(this::startAndMonitorRuntime, "snort-vpp-runtime");
        starter.start();
    }

    private void startAndMonitorRuntime() {
        File currentProfile = profileRoot;
        try {
            cleanupProfileArtifacts(currentProfile);
            if (stopRequested) {
                finishStopped(currentProfile);
                return;
            }

            Properties manifest = readManifest();
            String expectedVersion = manifest.getProperty("version", "").trim();
            String expectedAbi = manifest.getProperty("abi", "").trim();
            if (expectedVersion.isEmpty() || expectedAbi.isEmpty()) {
                failStartup("runtime_manifest_invalid", "version and abi are required");
                return;
            }
            if (!BuildConfigAbi.value().equals(expectedAbi)) {
                failStartup("runtime_abi_mismatch", "device ABI is " + BuildConfigAbi.value());
                return;
            }

            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File vpp = new File(nativeDir, VPP_BINARY);
            if (!vpp.isFile()) {
                failStartup("vpp_artifact_missing", VPP_BINARY + " is not packaged");
                return;
            }
            if (!vpp.canExecute()) {
                vpp.setExecutable(true, false);
            }
            String expectedHash = readExpectedHash();
            String actualHash = sha256(vpp);
            if (!expectedHash.equalsIgnoreCase(actualHash)) {
                failStartup("vpp_artifact_hash_mismatch", "packaged VPP hash did not match");
                return;
            }

            writeVppConfiguration(currentProfile, nativeDir);
            File runtimeDirectory = new File(currentProfile, "runtime");
            File logDirectory = new File(currentProfile, "logs");
            File shmDirectory = new File(currentProfile, "shm");
            if ((!runtimeDirectory.isDirectory() && !runtimeDirectory.mkdirs())
                    || (!logDirectory.isDirectory() && !logDirectory.mkdirs())
                    || (!shmDirectory.isDirectory() && !shmDirectory.mkdirs())) {
                failStartup("profile_artifact_prepare_failed", "unable to create VPP profile directories");
                return;
            }

            runtimeLog = new File(getFilesDir(), "logs/runtime-service.log");
            String command = "umask 022; mkdir -p " + shellQuote(runtimeDirectory.getPath())
                    + " " + shellQuote(logDirectory.getPath()) + " "
                    + shellQuote(shmDirectory.getPath())
                    + "; echo $$ > " + shellQuote(pidFile.getPath())
                    + "; export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                    + " SAKAMOTO_ANDROID_SHM_DIR=" + shellQuote(shmDirectory.getPath())
                    + "; exec " + shellQuote(vpp.getPath())
                    + " plugin_path " + shellQuote(nativeDir.getPath())
                    + " -c " + shellQuote(new File(currentProfile, "startup.conf").getPath())
                    + " >" + shellQuote(new File(logDirectory, "vpp-stdout.log").getPath())
                    + " 2>&1";

            Process process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
            synchronized (runtimeLock) {
                vppProcess = process;
            }
            appendLog("vpp_process=started artifact=" + vpp.getName());

            VppHealthHandshake.Result health = waitForHealth(nativeDir, currentProfile,
                    expectedVersion, expectedAbi, process);
            if (!health.isReady()) {
                failStartup("health_handshake_failed",
                        "expected " + expectedVersion + " / " + expectedAbi);
                return;
            }

            long pid = readPid(pidFile);
            publish(RuntimeSnapshot.running(RuntimeSnapshot.PROFILE_ROOT, health.version,
                    health.abi, health.health, pid));
            appendLog("runtime_state=running protocol=" + health.protocol
                    + " version=" + health.version + " abi=" + health.abi);

            int exitCode = process.waitFor();
            synchronized (runtimeLock) {
                vppProcess = null;
            }
            if (stopRequested) {
                finishStopped(currentProfile);
            } else {
                cleanupProfileArtifacts(currentProfile);
                publishError("vpp_process_exit", "VPP exited with status " + exitCode);
                leaveForegroundAfterFailure();
            }
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
            if (stopRequested) {
                finishStopped(currentProfile);
            } else {
                failStartup("runtime_start_interrupted", "runtime worker was interrupted");
            }
        } catch (Exception error) {
            Log.e(TAG, "VPP runtime startup failed", error);
            if (stopRequested) {
                finishStopped(currentProfile);
            } else {
                failStartup("runtime_start_failed", messageOf(error));
            }
        }
    }

    private VppHealthHandshake.Result waitForHealth(File nativeDir, File profile,
                                                    String expectedVersion, String expectedAbi,
                                                    Process process) throws Exception {
        File cliSocket = new File(profile, "runtime/cli.sock");
        VppHealthHandshake.Result last = new VppHealthHandshake.Result(
                VppHealthHandshake.PROTOCOL, "", expectedAbi, "error");
        for (int attempt = 1; attempt <= HEALTH_ATTEMPTS; attempt++) {
            if (stopRequested || !process.isAlive()) {
                return last;
            }
            if (cliSocket.exists()) {
                String output = runVppctl(nativeDir, cliSocket, "show version");
                last = VppHealthHandshake.parse(output, expectedVersion, expectedAbi);
                if (last.isReady()) {
                    return last;
                }
            }
            Thread.sleep(HEALTH_RETRY_MILLIS);
        }
        return last;
    }

    private String runVppctl(File nativeDir, File cliSocket, String command) throws Exception {
        File vppctl = new File(nativeDir, VPPCTL_BINARY);
        if (!vppctl.isFile()) {
            throw new IOException(VPPCTL_BINARY + " is not packaged");
        }
        File logSocket = new File(profileRoot, "runtime/cli.sock");
        String shell = "export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                + "; exec " + shellQuote(vppctl.getPath()) + " -s "
                + shellQuote(logSocket.getPath()) + " " + command;
        Process commandProcess = new ProcessBuilder(SU_PATH, "0", "sh", "-c", shell)
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        Thread reader = new Thread(() -> {
            try (InputStream input = commandProcess.getInputStream()) {
                byte[] buffer = new byte[1024];
                int count;
                while ((count = input.read(buffer)) >= 0) {
                    if (count > 0 && output.size() < 64 * 1024) {
                        output.write(buffer, 0, Math.min(count, 64 * 1024 - output.size()));
                    }
                }
            } catch (IOException ignored) {
                // The exit code is the authoritative result for a failed CLI probe.
            }
        }, "snort-vppctl-reader");
        reader.start();
        if (!commandProcess.waitFor(2, TimeUnit.SECONDS)) {
            commandProcess.destroyForcibly();
            throw new IOException("vppctl health query timed out");
        }
        reader.join(500L);
        return output.toString(StandardCharsets.UTF_8.name());
    }

    private void requestStop() {
        synchronized (runtimeLock) {
            if (stopInProgress) {
                return;
            }
            stopRequested = true;
            stopInProgress = true;
        }
        Thread stopper = new Thread(() -> {
            File currentProfile = profileRoot;
            Process process = vppProcess;
            if (process != null && process.isAlive()) {
                try {
                    process.destroy();
                } catch (RuntimeException ignored) {
                    // Root PID cleanup below is authoritative.
                }
            }
            terminateVpp(currentProfile);
            if (process != null) {
                try {
                    if (!process.waitFor(3, TimeUnit.SECONDS)) {
                        process.destroyForcibly();
                    }
                } catch (Exception ignored) {
                    // Continue with profile cleanup and persisted stopped state.
                }
            }
            finishStopped(currentProfile);
        }, "snort-vpp-stop");
        stopper.start();
    }

    private void terminateVpp(File currentProfile) {
        if (currentProfile == null) {
            return;
        }
        File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
        File cliSocket = new File(currentProfile, "runtime/cli.sock");
        File vppctl = new File(nativeDir, VPPCTL_BINARY);
        if (vppctl.isFile() && cliSocket.exists()) {
            String command = "export LD_LIBRARY_PATH=" + shellQuote(nativeDir.getPath())
                    + "; " + shellQuote(vppctl.getPath()) + " -s "
                    + shellQuote(cliSocket.getPath()) + " quit >/dev/null 2>&1 || true";
            runRootCommand(command, 2L);
        }
        File pid = new File(currentProfile, "runtime/vpp.pid");
        String command = "pid=$(cat " + shellQuote(pid.getPath()) + " 2>/dev/null || true); "
                + "case \"$pid\" in ''|*[!0-9]*) ;; *) kill -TERM \"$pid\" 2>/dev/null || true; "
                + "sleep 1; kill -0 \"$pid\" 2>/dev/null && kill -KILL \"$pid\" 2>/dev/null || true;; esac";
        runRootCommand(command, 5L);
    }

    private boolean cleanupProfileArtifacts(File currentProfile) {
        if (currentProfile == null) {
            return true;
        }
        String command = "rm -rf " + shellQuote(currentProfile.getPath());
        boolean rootClean = runRootCommand(command, 5L);
        if (!currentProfile.exists()) {
            return rootClean;
        }
        return deleteTree(currentProfile) && rootClean;
    }

    private void finishStopped(File currentProfile) {
        cleanupProfileArtifacts(currentProfile);
        synchronized (runtimeLock) {
            vppProcess = null;
            profileRoot = null;
            pidFile = null;
            stopInProgress = false;
            publishLocked(RuntimeSnapshot.stopped());
        }
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        stopSelf();
    }

    private void failStartup(String code, String message) {
        File currentProfile = profileRoot;
        terminateVpp(currentProfile);
        cleanupProfileArtifacts(currentProfile);
        if (stopRequested) {
            finishStopped(currentProfile);
            return;
        }
        publishError(code, message);
        leaveForegroundAfterFailure();
    }

    private void leaveForegroundAfterFailure() {
        if (foregroundStarted) {
            stopForeground(true);
            foregroundStarted = false;
        }
        stopSelf();
    }

    private void publishError(String code, String message) {
        RuntimeSnapshot current = snapshot == null ? RuntimeSnapshot.stopped() : snapshot;
        publish(RuntimeSnapshot.startupError(current.profile, current.version, current.abi,
                code, message));
    }

    private void publish(RuntimeSnapshot next) {
        synchronized (runtimeLock) {
            publishLocked(next);
        }
    }

    private void publishLocked(RuntimeSnapshot next) {
        snapshot = next;
        try {
            RuntimeStateStore.write(getFilesDir(), next);
        } catch (IOException error) {
            Log.e(TAG, "failed to persist runtime state", error);
        }
        if (foregroundStarted) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) {
                manager.notify(NOTIFICATION_ID, buildNotification(next));
            }
        }
        appendLog("runtime_state=" + next.state + " health=" + next.health
                + (next.errorCode.isEmpty() ? "" : " error=" + next.errorCode));
    }

    private Notification buildNotification(RuntimeSnapshot value) {
        String text = "Protection " + value.state;
        return new Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("Sakamoto protection")
                .setContentText(text)
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(value.isActive())
                .setCategory(Notification.CATEGORY_SERVICE)
                .build();
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

    private void writeVppConfiguration(File currentProfile, File nativeDir) throws IOException {
        if (!currentProfile.isDirectory() && !currentProfile.mkdirs()) {
            throw new IOException("unable to create profile directory: " + currentProfile);
        }
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
        try (FileOutputStream output = new FileOutputStream(new File(currentProfile, "startup.conf"))) {
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
            }
            return exited && process.exitValue() == 0;
        } catch (Exception error) {
            Log.w(TAG, "root command failed", error);
            return false;
        }
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

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static String messageOf(Exception error) {
        String message = error.getMessage();
        return error.getClass().getSimpleName() + (message == null ? "" : ": " + message);
    }

    @Override
    public void onDestroy() {
        if (vppProcess != null || (snapshot != null && snapshot.isActive())) {
            requestStop();
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
        } catch (IOException error) {
            Log.e(TAG, "failed to write runtime log", error);
        }
    }

    /** Keeps the Android ABI string in one testable, build-independent place. */
    private static final class BuildConfigAbi {
        static String value() {
            return "arm64-v8a";
        }
    }
}
