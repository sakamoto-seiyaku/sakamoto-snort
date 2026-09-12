package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.os.SystemClock;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.json.JSONArray;
import org.json.JSONObject;

/** Debug-only real application TCP sockets. No packet construction, forwarding,
 * owner selection, protection or underlay socket access belongs to this probe. */
final class FlowStackTcpProbe {
    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private static void write(Context app, String name, JSONObject value) throws Exception {
        File destination = new File(app.getFilesDir(), "product-state/" + name + ".json");
        destination.getParentFile().mkdirs();
        File pending = new File(destination.getParentFile(), name + ".pending");
        try (FileOutputStream output = new FileOutputStream(pending)) {
            output.write(value.toString().getBytes(StandardCharsets.UTF_8));
        }
        if (!pending.renameTo(destination)) throw new java.io.IOException("probe report rename failed");
    }

    private static void phase(Context app, String nonce, int index, JSONObject result,
            String phase) throws Exception {
        result.put("phase", phase).put("phaseMs", SystemClock.elapsedRealtime());
        write(app, "s240-" + nonce + "-" + index, result);
    }

    static void start(Context context, String nonce, String planText) {
        if (nonce == null || !nonce.matches("[a-zA-Z0-9_-]{1,80}") || planText == null) return;
        final JSONArray plan;
        try {
            plan = new JSONArray(planText);
            if (plan.length() < 1 || plan.length() > 4) return;
            for (int i = 0; i < plan.length(); ++i) {
                JSONObject f = plan.getJSONObject(i);
                String address = f.getString("address"), mode = f.getString("mode");
                if (!(address.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")
                        || (address.contains(":") && address.matches("[0-9a-fA-F:]+")))) return;
                int port = f.getInt("port"), source = f.getInt("source"), size = f.optInt("bytes", 4096);
                int connectMs = f.optInt("connectTimeoutMs", 15000), chunk = f.optInt("writeChunkBytes", 0);
                int holdMs = f.optInt("holdTimeoutMs", 20000);
                if (port < 1 || port > 65535 || source < 1024 || source > 65535
                        || size < 256 || size > 32768
                        || connectMs < 100 || connectMs > 15000 || chunk < 0 || chunk > size
                        || holdMs < 1000 || holdMs > 60000
                        || !Arrays.asList("fin", "rst", "refusal", "failure", "policy", "hold").contains(mode)) return;
            }
        } catch (Exception invalid) { return; }
        if (!RUNNING.compareAndSet(false, true)) return;
        Context app = context.getApplicationContext();
        new Thread(() -> {
            JSONObject report = new JSONObject();
            JSONObject[] results = new JSONObject[plan.length()];
            Thread[] threads = new Thread[plan.length()];
            AtomicReferenceArray<Socket> sockets = new AtomicReferenceArray<>(plan.length());
            CountDownLatch ready = new CountDownLatch(plan.length()), go = new CountDownLatch(1);
            try {
                report.put("nonce", nonce).put("uid", android.os.Process.myUid()).put("plan", plan);
                for (int i = 0; i < plan.length(); ++i) {
                    final int index = i;
                    final JSONObject config = plan.getJSONObject(i);
                    threads[i] = new Thread(() -> {
                        JSONObject result = new JSONObject();
                        boolean announced = false;
                        try {
                            String mode = config.getString("mode");
                            result.put("nonce", nonce).put("index", index).put("mode", mode)
                                    .put("source", config.getInt("source")).put("echoes", 0).put("timeouts", 0);
                            InetAddress endpoint = InetAddress.getByName(config.getString("address"));
                            if (endpoint.isLoopbackAddress() || endpoint.isAnyLocalAddress()
                                    || endpoint.isLinkLocalAddress() || endpoint.isMulticastAddress())
                                throw new IllegalArgumentException("unicast underlay required");
                            Socket socket = new Socket();
                            sockets.set(index, socket);
                            socket.setReuseAddress(true);
                            socket.setTcpNoDelay(true);
                            socket.bind(new InetSocketAddress(InetAddress.getByName(endpoint.getAddress().length == 4
                                    ? VpnTunPlatformSession.IPV4_ADDRESS : VpnTunPlatformSession.IPV6_ADDRESS),
                                    config.getInt("source")));
                            result.put("local", socket.getLocalSocketAddress().toString());
                            ready.countDown(); announced = true;
                            if (!go.await(6, TimeUnit.SECONDS)) throw new IllegalStateException("start deadline");
                            if (config.optBoolean("waitToConnect")) {
                                phase(app, nonce, index, result, "waiting_to_connect");
                                File gate = new File(app.getFilesDir(),
                                        "product-state/s240-connect-" + nonce + "-" + index);
                                long deadline = SystemClock.elapsedRealtime() + 20000;
                                while (!gate.exists() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(20);
                                if (!gate.exists()) throw new IllegalStateException("connect release deadline");
                            }
                            long started = SystemClock.elapsedRealtime();
                            result.put("startMs", started);
                            phase(app, nonce, index, result, "connecting");
                            try {
                                socket.connect(new InetSocketAddress(endpoint, config.getInt("port")),
                                        config.optInt("connectTimeoutMs", 15000));
                                result.put("connectedMs", SystemClock.elapsedRealtime());
                                phase(app, nonce, index, result, "connected");
                                if (mode.equals("refusal") || mode.equals("failure")) {
                                    socket.setSoTimeout(mode.equals("failure") ? 3000 : 10000);
                                    socket.getOutputStream().write(42);
                                    int value = socket.getInputStream().read();
                                    if (value != -1) throw new IllegalStateException("refusal unexpectedly returned data");
                                    result.put("outcome", mode.equals("failure") ? "failed_eof" : "refused_eof");
                                } else {
                                    InputStream input = socket.getInputStream();
                                    socket.setSoTimeout(1200);
                                    for (int round = 0; round < 3; ++round) {
                                        if (round == 1 && (mode.equals("policy") || mode.equals("hold"))) {
                                            phase(app, nonce, index, result, mode.equals("hold") ? "holding" : "first_echo");
                                            File gate = new File(app.getFilesDir(),
                                                    "product-state/s240-release-" + nonce + "-" + index);
                                            long deadline = SystemClock.elapsedRealtime() + config.optInt("holdTimeoutMs", 20000);
                                            while (!gate.exists() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(20);
                                            if (!gate.exists()) throw new IllegalStateException("probe release deadline");
                                            if (mode.equals("hold")) break;
                                        }
                                        byte[] request = new byte[config.optInt("bytes", 4096)];
                                        Arrays.fill(request, (byte)('a' + index));
                                        byte[] prefix = (nonce + "_" + index + ":" + round + ":").getBytes(StandardCharsets.UTF_8);
                                        System.arraycopy(prefix, 0, request, 0, prefix.length);
                                        int chunk = round == 1 ? config.optInt("writeChunkBytes", 0) : 0;
                                        if (chunk == 0) socket.getOutputStream().write(request);
                                        else {
                                            for (int offset = 0; offset < request.length; offset += chunk) {
                                                socket.getOutputStream().write(request, offset,
                                                        Math.min(chunk, request.length - offset));
                                                Thread.sleep(2); // Generate small real TCP packets for bounded pressure tests.
                                            }
                                        }
                                        byte[] response = new byte[request.length];
                                        int received = 0;
                                        long deadline = SystemClock.elapsedRealtime() + 20000;
                                        while (received < response.length && SystemClock.elapsedRealtime() < deadline) {
                                            try {
                                                int count = input.read(response, received, response.length - received);
                                                if (count < 0) throw new java.io.EOFException("echo ended early");
                                                received += count;
                                            } catch (SocketTimeoutException timeout) {
                                                result.put("timeouts", result.getInt("timeouts") + 1);
                                                phase(app, nonce, index, result, "return_timeout");
                                            }
                                        }
                                        if (received != request.length || !Arrays.equals(request, response))
                                            throw new IllegalStateException("echo incomplete or changed");
                                        result.put("echoes", round + 1).put("echoBytes", (round + 1) * request.length);
                                        phase(app, nonce, index, result, "echo_" + round);
                                    }
                                    if (mode.equals("rst")) socket.setSoLinger(true, 0);
                                    else if (!mode.equals("hold")) {
                                        socket.shutdownOutput();
                                        socket.setSoTimeout(10000);
                                        if (input.read() != -1) throw new IllegalStateException("unexpected trailing bytes");
                                        result.put("remoteEof", true);
                                    }
                                    result.put("outcome", mode.equals("hold") ? "held_closed" : "echo_closed");
                                }
                            } catch (java.io.IOException error) {
                                if (mode.equals("failure"))
                                    result.put("outcome", error instanceof SocketTimeoutException
                                            ? "failed_timeout" : "failed_error").put("failureError", error.toString());
                                else {
                                    if (!mode.equals("refusal") || error instanceof SocketTimeoutException) throw error;
                                    result.put("outcome", "refused_error").put("refusalError", error.toString());
                                }
                            }
                        } catch (Exception error) {
                            try { result.put("error", error.toString()); } catch (Exception ignored) { }
                        } finally {
                            if (!announced) ready.countDown();
                            Socket socket = sockets.get(index);
                            if (socket != null) try { socket.close(); } catch (Exception ignored) { }
                            try { result.put("endMs", SystemClock.elapsedRealtime()); phase(app, nonce, index, result, "finished"); }
                            catch (Exception ignored) { }
                            results[index] = result;
                        }
                    }, "s240-app-tcp-" + i);
                    threads[i].start();
                }
                if (!ready.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("probe bind deadline");
                go.countDown();
                long deadline = SystemClock.elapsedRealtime() + 70000;
                for (Thread thread : threads) thread.join(Math.max(1, deadline - SystemClock.elapsedRealtime()));
                JSONArray flows = new JSONArray();
                for (int i = 0; i < threads.length; ++i) {
                    if (threads[i].isAlive()) throw new IllegalStateException("probe completion deadline");
                    flows.put(results[i]);
                }
                report.put("flows", flows);
            } catch (Exception error) {
                try { report.put("error", error.toString()); } catch (Exception ignored) { }
            } finally {
                go.countDown();
                for (int i = 0; i < sockets.length(); ++i) {
                    Socket socket = sockets.get(i);
                    if (socket != null) try { socket.close(); } catch (Exception ignored) { }
                }
                boolean finished = true;
                for (Thread thread : threads) if (thread != null) {
                    thread.interrupt();
                    try { thread.join(2000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                    finished &= !thread.isAlive();
                }
                try { write(app, "s240-probe", report); }
                catch (Exception error) { android.util.Log.e("SakamotoTcpProbe", "record failed", error); }
                if (finished) RUNNING.set(false);
            }
        }, "s240-app-probe").start();
    }
}
