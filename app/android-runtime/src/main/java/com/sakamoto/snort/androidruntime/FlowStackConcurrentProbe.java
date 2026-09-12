package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.os.SystemClock;
import java.io.File;
import java.io.FileOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.BitSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReferenceArray;
import org.json.JSONArray;
import org.json.JSONObject;

/** Debug-only app traffic. No flow ownership, socket protection or packet
 * forwarding logic: ordinary UDP sockets exercise the actual VPN path. */
final class FlowStackConcurrentProbe {
    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private static void writePhase(Context app, String nonce, int index, JSONObject value) throws Exception {
        File destination = new File(app.getFilesDir(), "product-state/s243-udp-" + nonce + "-" + index + ".json");
        destination.getParentFile().mkdirs();
        File pending = new File(destination.getParentFile(), destination.getName() + ".pending");
        try (FileOutputStream output = new FileOutputStream(pending)) {
            output.write(value.toString().getBytes(StandardCharsets.UTF_8));
        }
        if (!pending.renameTo(destination)) throw new java.io.IOException("UDP phase rename failed");
    }

    static void start(Context context, String nonce, String planText) {
        if (nonce == null || !nonce.matches("[a-zA-Z0-9_-]{1,80}") || planText == null) return;
        final JSONArray plan;
        try {
            plan = new JSONArray(planText);
            if (plan.length() < 1 || plan.length() > 4) return;
            for (int i = 0; i < plan.length(); ++i) {
                JSONObject f = plan.getJSONObject(i);
                String address = f.getString("address");
                if (!(address.matches("[0-9]{1,3}(\\.[0-9]{1,3}){3}")
                        || (address.contains(":") && address.matches("[0-9a-fA-F:]+")))) return;
                int port = f.getInt("port"), source = f.getInt("source"), count = f.getInt("packets");
                int interval = f.optInt("intervalMs", 100);
                if (port < 1 || port > 65535 || source < 1024 || source > 65535
                        || count < 1 || count > 1000 || interval < 0 || interval > 1000
                        || (f.optBoolean("burst") && count > 256)) return;
            }
        } catch (Exception invalid) { return; }
        if (!RUNNING.compareAndSet(false, true)) return;
        Context app = context.getApplicationContext();
        new Thread(() -> {
            JSONObject report = new JSONObject();
            JSONObject[] results = new JSONObject[plan.length()];
            Thread[] threads = new Thread[plan.length()];
            AtomicReferenceArray<DatagramSocket> sockets = new AtomicReferenceArray<>(plan.length());
            CountDownLatch ready = new CountDownLatch(plan.length()), go = new CountDownLatch(1);
            try {
                report.put("nonce", nonce).put("uid", android.os.Process.myUid());
                for (int i = 0; i < plan.length(); ++i) {
                    final int index = i;
                    final JSONObject config = plan.getJSONObject(i);
                    threads[i] = new Thread(() -> {
                        JSONObject result = new JSONObject();
                        boolean announced = false;
                        try {
                            InetAddress endpoint = InetAddress.getByName(config.getString("address"));
                            if (endpoint.isLoopbackAddress() || endpoint.isAnyLocalAddress()
                                    || endpoint.isLinkLocalAddress() || endpoint.isMulticastAddress())
                                throw new IllegalArgumentException("unicast underlay required");
                            DatagramSocket socket = new DatagramSocket(config.getInt("source"),
                                    InetAddress.getByName(endpoint.getAddress().length == 4
                                            ? VpnTunPlatformSession.IPV4_ADDRESS : VpnTunPlatformSession.IPV6_ADDRESS));
                            sockets.set(index, socket);
                            socket.connect(endpoint, config.getInt("port"));
                            ready.countDown(); announced = true;
                            if (!go.await(6, TimeUnit.SECONDS)) throw new IllegalStateException("start deadline");
                            long started = SystemClock.elapsedRealtime(), deadline = started + 90000;
                            int count = config.getInt("packets"), sentCount = 0, duplicates = 0, wrong = 0;
                            boolean burst = config.optBoolean("burst");
                            BitSet received = new BitSet(count);
                            JSONArray outcomes = new JSONArray();
                            long lastEcho = 0;
                            String prefix = nonce + "_" + index + ":";
                            result.put("startMs", started).put("source", config.getInt("source"));
                            for (int packet = 0; packet < count && SystemClock.elapsedRealtime() < deadline; ++packet) {
                                byte[] bytes = (prefix + packet).getBytes(StandardCharsets.UTF_8);
                                socket.send(new DatagramPacket(bytes, bytes.length));
                                ++sentCount;
                                if (burst && packet + 1 < count && config.optInt("intervalMs", 0) > 0)
                                    Thread.sleep(config.getInt("intervalMs"));
                                if (!burst) {
                                    socket.setSoTimeout(1500);
                                    String outcome;
                                    try {
                                        byte[] storage = new byte[256];
                                        DatagramPacket reply = new DatagramPacket(storage, storage.length);
                                        socket.receive(reply);
                                        String value = new String(storage, 0, reply.getLength(), StandardCharsets.UTF_8);
                                        if (value.equals(prefix + packet)) {
                                            received.set(packet); lastEcho = SystemClock.elapsedRealtime(); outcome = "echo";
                                        } else { ++wrong; outcome = "wrong_reply"; }
                                    } catch (SocketTimeoutException timeout) { outcome = "timeout"; }
                                    outcomes.put(outcome);
                                    boolean underlaySequence = config.optBoolean("underlaySequence");
                                    if ((packet == 0 && config.optBoolean("holdAfterFirst"))
                                            || (underlaySequence && packet < (config.optBoolean("underlayDrop") ? 3 : 2))) {
                                        result.put("nonce", nonce).put("index", index).put("phase", "holding")
                                                .put("echoes", received.cardinality()).put("sent", sentCount)
                                                .put("packet", packet).put("outcomes", outcomes)
                                                .put("phaseMs", SystemClock.elapsedRealtime());
                                        writePhase(app, nonce, index, result);
                                        File gate = new File(app.getFilesDir(),
                                                "product-state/s243-udp-release-" + nonce + "-" + index
                                                + (packet == 0 ? "" : "-" + packet));
                                        long holdDeadline = SystemClock.elapsedRealtime() + (underlaySequence ? 30000 : 20000);
                                        while (!gate.exists() && SystemClock.elapsedRealtime() < holdDeadline)
                                            Thread.sleep(20);
                                        if (!gate.exists()) throw new IllegalStateException("UDP hold release deadline");
                                        if (!underlaySequence) break; // Lifecycle-only: no post-generation packet.
                                    }
                                    int interval = config.optInt("intervalMs", 100);
                                    if (interval > 0 && packet + 1 < count) Thread.sleep(interval);
                                }
                            }
                            if (burst) {
                                long receiveDeadline = Math.min(deadline, SystemClock.elapsedRealtime() + 10000);
                                while (received.cardinality() < sentCount && SystemClock.elapsedRealtime() < receiveDeadline) {
                                    socket.setSoTimeout((int)Math.max(1, Math.min(500, receiveDeadline - SystemClock.elapsedRealtime())));
                                    try {
                                        byte[] storage = new byte[256];
                                        DatagramPacket reply = new DatagramPacket(storage, storage.length);
                                        socket.receive(reply);
                                        String value = new String(storage, 0, reply.getLength(), StandardCharsets.UTF_8);
                                        int packet = value.startsWith(prefix) ? Integer.parseInt(value.substring(prefix.length())) : -1;
                                        if (packet < 0 || packet >= sentCount) ++wrong;
                                        else if (received.get(packet)) ++duplicates;
                                        else { received.set(packet); lastEcho = SystemClock.elapsedRealtime(); }
                                    } catch (SocketTimeoutException timeout) { /* bounded receive deadline */ }
                                }
                                for (int packet = 0; packet < sentCount; ++packet)
                                    outcomes.put(received.get(packet) ? "echo" : "timeout");
                            }
                            result.put("sent", sentCount).put("echoes", received.cardinality())
                                    .put("wrong", wrong).put("duplicates", duplicates)
                                    .put("lastEchoMs", lastEcho).put("outcomes", outcomes)
                                    .put("endMs", SystemClock.elapsedRealtime());
                        } catch (Exception error) {
                            try { result.put("error", error.toString()); } catch (Exception ignored) { }
                        } finally {
                            if (!announced) ready.countDown();
                            DatagramSocket socket = sockets.get(index);
                            if (socket != null) socket.close();
                            results[index] = result;
                        }
                    }, "s239-app-udp-" + i);
                    threads[i].start();
                }
                if (!ready.await(5, TimeUnit.SECONDS)) throw new IllegalStateException("probe bind deadline");
                go.countDown();
                long joinDeadline = SystemClock.elapsedRealtime() + 95000;
                for (Thread thread : threads) thread.join(Math.max(1, joinDeadline - SystemClock.elapsedRealtime()));
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
                    DatagramSocket socket = sockets.get(i);
                    if (socket != null) socket.close();
                }
                boolean finished = true;
                for (Thread thread : threads) if (thread != null) {
                    thread.interrupt();
                    try { thread.join(2000); } catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                    finished &= !thread.isAlive();
                }
                File result = new File(app.getFilesDir(), "product-state/s239-probe.json");
                try {
                    result.getParentFile().mkdirs();
                    File pending = new File(result.getParentFile(), "s239-probe.pending");
                    try (FileOutputStream output = new FileOutputStream(pending)) {
                        output.write(report.toString().getBytes(StandardCharsets.UTF_8));
                    }
                    if (!pending.renameTo(result)) throw new java.io.IOException("probe report rename failed");
                } catch (Exception error) { android.util.Log.e("SakamotoW2Probe", "record failed", error); }
                if (finished) RUNNING.set(false);
            }
        }, "s239-app-probe").start();
    }
}
