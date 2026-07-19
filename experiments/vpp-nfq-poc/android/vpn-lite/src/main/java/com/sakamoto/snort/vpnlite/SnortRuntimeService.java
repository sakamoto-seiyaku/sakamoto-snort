package com.sakamoto.snort.vpnlite;

import android.app.Service;
import android.content.Intent;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.IBinder;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

/** Minimal RuntimeService POC: root-launch the packaged daemon and gate on HELLO. */
public final class SnortRuntimeService extends Service {
    public static final String ACTION_START = "com.sakamoto.snort.vpnlite.RUNTIME_START";
    public static final String ACTION_STOP = "com.sakamoto.snort.vpnlite.RUNTIME_STOP";

    private static final String TAG = "SnortRuntimeService";
    private static final String SU_PATH = "/system/bin/su";
    private static final String CONTROL_SOCKET = "sucre-snort-control-vnext";
    private static final int HELLO_ATTEMPTS = 20;
    private static final long HELLO_RETRY_MS = 250L;

    private final Object processLock = new Object();
    private Process daemonProcess;
    private File runtimeLog;
    private File daemonPidFile;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent == null ? ACTION_START : intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopRuntime();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action) || action == null) {
            startRuntime();
        }
        return START_NOT_STICKY;
    }

    private void startRuntime() {
        synchronized (processLock) {
            if (daemonProcess != null && daemonProcess.isAlive()) {
                appendLog("start skipped: daemon already running");
                return;
            }
        }

        Thread worker = new Thread(() -> {
            File nativeDir = new File(getApplicationInfo().nativeLibraryDir);
            File daemon = new File(nativeDir, "libsucre_snortd.so");
            File logsDir = new File(getFilesDir(), "logs");
            if (!logsDir.isDirectory() && !logsDir.mkdirs()) {
                Log.w(TAG, "failed to create logs directory: " + logsDir);
            }
            runtimeLog = new File(logsDir, "runtime-service.log");
            File runtimeDir = new File(getFilesDir(), "runtime");
            if (!runtimeDir.isDirectory() && !runtimeDir.mkdirs()) {
                Log.w(TAG, "failed to create runtime directory: " + runtimeDir);
            }
            daemonPidFile = new File(runtimeDir, "daemon.pid");
            appendLog("native_library_dir=" + nativeDir.getAbsolutePath());
            appendLog("daemon_path=" + daemon.getAbsolutePath());
            appendLog("daemon_exists=" + daemon.isFile() + " executable=" + daemon.canExecute());
            if (!daemon.isFile() || !daemon.canExecute()) {
                appendLog("runtime_start_result=fail reason=daemon_artifact_unavailable");
                return;
            }

            String command = "echo $$ > " + shellQuote(daemonPidFile.getAbsolutePath())
                    + "; exec " + shellQuote(daemon.getAbsolutePath())
                    + " >> " + shellQuote(runtimeLog.getAbsolutePath()) + " 2>&1";
            try {
                Process process = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
                synchronized (processLock) {
                    daemonProcess = process;
                }
                appendLog("root_launch=started");
                if (waitForHello()) {
                    appendLog("runtime_start_result=pass");
                    try {
                        process.waitFor();
                        appendLog("root_process_exit=observed");
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        appendLog("root_process_exit=interrupted");
                    }
                } else {
                    appendLog("runtime_start_result=fail reason=hello_gate_timeout");
                    stopRuntime();
                }
            } catch (Exception e) {
                appendLog("runtime_start_result=fail reason=" + e.getClass().getSimpleName()
                        + " message=" + String.valueOf(e.getMessage()));
                Log.e(TAG, "root launch failed", e);
            }
        }, "snort-runtime-start");
        worker.start();
    }

    private boolean waitForHello() {
        for (int attempt = 1; attempt <= HELLO_ATTEMPTS; attempt++) {
            try {
                Hello hello = requestHello();
                appendLog("hello_protocol=" + hello.protocol);
                appendLog("hello_artifact_abi=" + hello.artifactAbi);
                appendLog("hello_daemon_build_id=" + hello.daemonBuildId);
                appendLog("hello_capability_snort10_base=" + hello.hasSnort10Base);
                appendLog("hello_capability_nfqueue_pass_through=" + hello.hasNfqueuePassThrough);
                if ("control-vnext".equals(hello.protocol)
                        && "arm64-v8a".equals(hello.artifactAbi)
                        && !hello.daemonBuildId.isEmpty()
                        && hello.hasSnort10Base) {
                    appendLog("hello_result=pass attempt=" + attempt);
                    return true;
                }
                appendLog("hello_result=fail reason=contract_mismatch attempt=" + attempt);
            } catch (Exception e) {
                if (attempt == HELLO_ATTEMPTS) {
                    appendLog("hello_result=fail reason=" + e.getClass().getSimpleName()
                            + " message=" + String.valueOf(e.getMessage()));
                }
            }
            try {
                Thread.sleep(HELLO_RETRY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    private Hello requestHello() throws Exception {
        LocalSocket socket = new LocalSocket();
        try {
            socket.connect(new LocalSocketAddress(CONTROL_SOCKET,
                    LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(1000);
            JSONObject request = new JSONObject();
            request.put("id", 1);
            request.put("cmd", "HELLO");
            request.put("args", new JSONObject());
            byte[] payload = request.toString().getBytes(StandardCharsets.UTF_8);
            OutputStream output = socket.getOutputStream();
            output.write((Integer.toString(payload.length) + ":").getBytes(StandardCharsets.US_ASCII));
            output.write(payload);
            output.write(',');
            output.flush();

            InputStream input = socket.getInputStream();
            StringBuilder header = new StringBuilder();
            int next;
            while ((next = input.read()) >= 0 && next != ':') {
                if (header.length() >= 12 || next < '0' || next > '9') {
                    throw new IOException("invalid HELLO netstring header");
                }
                header.append((char) next);
            }
            if (next != ':' || header.length() == 0) {
                throw new IOException("missing HELLO netstring header");
            }
            int length = Integer.parseInt(header.toString());
            byte[] responseBytes = readFully(input, length);
            if (input.read() != ',') {
                throw new IOException("missing HELLO netstring comma");
            }
            JSONObject response = new JSONObject(new String(responseBytes, StandardCharsets.UTF_8));
            if (!response.optBoolean("ok", false)) {
                throw new IOException("HELLO returned ok=false");
            }
            JSONObject result = response.getJSONObject("result");
            JSONArray capabilities = result.optJSONArray("capabilities");
            boolean hasSnort10Base = false;
            boolean hasNfqueuePassThrough = false;
            if (capabilities != null) {
                for (int i = 0; i < capabilities.length(); i++) {
                    String capability = capabilities.optString(i, "");
                    hasSnort10Base |= "snort10-base".equals(capability);
                    hasNfqueuePassThrough |= "nfqueue-pass-through".equals(capability);
                }
            }
            return new Hello(result.optString("protocol", ""),
                    result.optString("artifactAbi", ""),
                    result.optString("daemonBuildId", ""), hasSnort10Base,
                    hasNfqueuePassThrough);
        } finally {
            socket.close();
        }
    }

    private static byte[] readFully(InputStream input, int length) throws IOException {
        if (length < 0 || length > 1024 * 1024) {
            throw new IOException("invalid HELLO response length: " + length);
        }
        byte[] output = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(output, offset, length - offset);
            if (count < 0) {
                throw new IOException("unexpected HELLO EOF");
            }
            offset += count;
        }
        return output;
    }

    private void stopRuntime() {
        Process process;
        File pidFile;
        synchronized (processLock) {
            process = daemonProcess;
            daemonProcess = null;
            pidFile = daemonPidFile;
            daemonPidFile = null;
        }
        if (process == null && pidFile == null) {
            appendLog("runtime_stop_result=not_running");
            return;
        }

        if (process != null) {
            process.destroy();
        }
        boolean rootStop = terminateRootDaemon(pidFile);
        try {
            if (process != null && !process.waitFor(2, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                process.waitFor(2, TimeUnit.SECONDS);
            }
            appendLog(rootStop ? "runtime_stop_result=pass" :
                    "runtime_stop_result=fail reason=root_stop_failed");
        } catch (Exception e) {
            appendLog("runtime_stop_result=fail reason=" + e.getClass().getSimpleName()
                    + " message=" + String.valueOf(e.getMessage()));
        }
    }

    private boolean terminateRootDaemon(File pidFile) {
        if (pidFile == null) {
            return true;
        }
        String pidPath = shellQuote(pidFile.getAbsolutePath());
        String command = "pid=$(cat " + pidPath + " 2>/dev/null || true); "
                + "case \"$pid\" in ''|*[!0-9]*) ;; *) "
                + "kill -TERM \"$pid\" 2>/dev/null || true; sleep 1; "
                + "kill -0 \"$pid\" 2>/dev/null && kill -KILL \"$pid\" 2>/dev/null || true; "
                + "esac; rm -f " + pidPath;
        try {
            Process killer = new ProcessBuilder(SU_PATH, "0", "sh", "-c", command).start();
            boolean exited = killer.waitFor(5, TimeUnit.SECONDS);
            if (!exited) {
                killer.destroyForcibly();
            }
            return exited;
        } catch (Exception e) {
            Log.e(TAG, "root daemon stop failed", e);
            return false;
        }
    }

    @Override
    public void onDestroy() {
        stopRuntime();
        super.onDestroy();
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    private void appendLog(String line) {
        File log = runtimeLog;
        if (log == null) {
            File logsDir = new File(getFilesDir(), "logs");
            if (!logsDir.isDirectory()) {
                logsDir.mkdirs();
            }
            log = new File(logsDir, "runtime-service.log");
            runtimeLog = log;
        }
        String entry = System.currentTimeMillis() + " " + line + "\n";
        try (FileOutputStream output = new FileOutputStream(log, true)) {
            output.write(entry.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            Log.e(TAG, "failed to write runtime log", e);
        }
    }

    private static String shellQuote(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static final class Hello {
        final String protocol;
        final String artifactAbi;
        final String daemonBuildId;
        final boolean hasSnort10Base;
        final boolean hasNfqueuePassThrough;

        Hello(String protocol, String artifactAbi, String daemonBuildId,
              boolean hasSnort10Base, boolean hasNfqueuePassThrough) {
            this.protocol = protocol;
            this.artifactAbi = artifactAbi;
            this.daemonBuildId = daemonBuildId;
            this.hasSnort10Base = hasSnort10Base;
            this.hasNfqueuePassThrough = hasNfqueuePassThrough;
        }
    }
}
