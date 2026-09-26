package com.sakamoto.snort.androidruntime;

import android.content.Context;
import android.os.SystemClock;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import org.json.JSONObject;

/** Debug-only ordinary app sockets for bounded protocol-fact acceptance.
 * No native Flow mutation, packet injection, socket protection or policy API. */
final class ProtocolFactsProbe {
    private static final AtomicBoolean RUNNING = new AtomicBoolean();

    private static byte[] hex(String value) {
        if (value.length() > 65536 || (value.length() & 1) != 0
                || !value.matches("[0-9a-fA-F]*")) throw new IllegalArgumentException("hex payload");
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; ++i)
            bytes[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }
    private static String toHex(byte[] bytes) {
        StringBuilder value = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            value.append(Character.forDigit((b & 255) >>> 4, 16));
            value.append(Character.forDigit(b & 15, 16));
        }
        return value.toString();
    }
    private static void report(Context app, String nonce, JSONObject value, String phase) throws Exception {
        value.put("phase", phase).put("phaseMs", SystemClock.elapsedRealtime());
        File destination = new File(app.getFilesDir(), "product-state/t12-" + nonce + ".json");
        destination.getParentFile().mkdirs();
        File pending = new File(destination.getParentFile(), "t12-" + nonce + ".pending");
        try (FileOutputStream output = new FileOutputStream(pending)) {
            output.write(value.toString().getBytes(StandardCharsets.UTF_8));
        }
        if (!pending.renameTo(destination)) throw new java.io.IOException("probe report rename");
    }
    private static void gate(Context app, String nonce, JSONObject value, String phase) throws Exception {
        report(app, nonce, value, phase);
        File release = new File(app.getFilesDir(), "product-state/t12-release-" + nonce + "-" + phase);
        long deadline = SystemClock.elapsedRealtime() + 60000;
        while (!release.exists() && SystemClock.elapsedRealtime() < deadline) Thread.sleep(20);
        if (!release.exists()) throw new IllegalStateException("release deadline " + phase);
    }
    private static byte[] read(InputStream input, int length) throws Exception {
        byte[] bytes = new byte[length];
        int at = 0;
        while (at < length) {
            int count = input.read(bytes, at, length - at);
            if (count < 0) throw new java.io.EOFException("short echo");
            at += count;
        }
        return bytes;
    }
    private static String readLine(InputStream input) throws Exception {
        StringBuilder line = new StringBuilder();
        while (line.length() < 1024) {
            int value = input.read();
            if (value < 0) throw new java.io.EOFException("protocol response");
            line.append((char) value);
            if (line.toString().endsWith("\r\n")) return line.toString();
        }
        throw new IllegalStateException("protocol response limit");
    }
    private static void tcp(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        try (Socket socket = new Socket()) {
            socket.setReuseAddress(true); socket.setTcpNoDelay(true);
            socket.bind(new InetSocketAddress(local, source));
            socket.connect(new InetSocketAddress(endpoint, port), 10000); socket.setSoTimeout(10000);
            result.put("local", socket.getLocalSocketAddress().toString());
            boolean ftp = plan.optBoolean("ftp");
            if (plan.optBoolean("t13Direct")) {
                // TLS is the first application message, without upgrade negotiation.
            } else if (ftp) {
                String banner = readLine(socket.getInputStream());
                if (!banner.startsWith("220 ") || !banner.contains(" FTPd "))
                    throw new IllegalStateException("FTP banner");
                result.put("ftpBanner", banner);
                gate(app, nonce, result, "ftp_ready");
                socket.getOutputStream().write("AUTH TLS\r\n".getBytes(StandardCharsets.US_ASCII));
                String response = readLine(socket.getInputStream());
                if (!response.equals("234 Ready for TLS\r\n"))
                    throw new IllegalStateException("FTP AUTH TLS");
                result.put("ftpUpgrade", response);
            } else {
                byte[] request = ("GET /" + nonce + " HTTP/1.1\r\nHost: example.test\r\n"
                        + "Connection: Upgrade\r\nUpgrade: TLS/1.2\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
                socket.getOutputStream().write(request);
                StringBuilder header = new StringBuilder();
                while (header.length() < 1024 && !header.toString().endsWith("\r\n\r\n")) {
                    int value = socket.getInputStream().read();
                    if (value < 0) throw new java.io.EOFException("HTTP response");
                    header.append((char) value);
                }
                if (!header.toString().startsWith("HTTP/1.1 101")) throw new IllegalStateException("HTTP upgrade");
                result.put("httpResponse", header.toString());
                gate(app, nonce, result, "http_ready");
            }
            final byte[] expected = hex(plan.getString("certificateSha256"));
            if (expected.length != 32) throw new IllegalArgumentException("certificate pin");
            X509TrustManager pin = new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                public void checkClientTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    throw new CertificateException("client trust unused");
                }
                public void checkServerTrusted(X509Certificate[] chain, String auth) throws CertificateException {
                    try {
                        if (chain.length == 0 || !Arrays.equals(expected,
                                MessageDigest.getInstance("SHA-256").digest(chain[0].getEncoded())))
                            throw new CertificateException("test endpoint certificate pin mismatch");
                    } catch (CertificateException error) { throw error; }
                    catch (Exception error) { throw new CertificateException(error); }
                }
            };
            SSLContext context = SSLContext.getInstance("TLS");
            context.init(null, new TrustManager[] {pin}, null);
            try (SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(socket,
                    plan.optBoolean("t13Absent") ? endpoint.getHostAddress() : "example.test", port, false)) {
                if (plan.optBoolean("t13Absent")) {
                    javax.net.ssl.SSLParameters parameters = tls.getSSLParameters();
                    parameters.setServerNames(java.util.Collections.emptyList());
                    tls.setSSLParameters(parameters);
                }
                tls.setEnabledProtocols(new String[] {"TLSv1.2"}); tls.setSoTimeout(15000); tls.startHandshake();
                result.put("tlsProtocol", tls.getSession().getProtocol()).put("cipher", tls.getSession().getCipherSuite());
                gate(app, nonce, result, "tls_ready");
                if (plan.optBoolean("domainChecks")) {
                    byte[] changed = (nonce + ":domain-change\n").getBytes(StandardCharsets.US_ASCII);
                    tls.getOutputStream().write(changed);
                    if (!Arrays.equals(changed, read(tls.getInputStream(), changed.length)))
                        throw new IllegalStateException("domain update TLS receipt");
                    gate(app, nonce, result, "domain_changed");
                }
                byte[] payload = (ftp ? "NOOP " + nonce + ":blocked\r\n" : nonce + ":blocked\n")
                        .getBytes(StandardCharsets.US_ASCII);
                byte[] expectedReply = (ftp ? "200 " + nonce + ":blocked\r\n" : nonce + ":blocked\n")
                        .getBytes(StandardCharsets.US_ASCII);
                tls.setSoTimeout(1200); tls.getOutputStream().write(payload);
                try { tls.getInputStream().read(); throw new IllegalStateException("expected policy timeout"); }
                catch (SocketTimeoutException expectedTimeout) { result.put("blockedTimeout", true); }
                gate(app, nonce, result, "blocked");
                tls.setSoTimeout(15000);
                if (!Arrays.equals(expectedReply, read(tls.getInputStream(), expectedReply.length)))
                    throw new IllegalStateException("recovered TLS echo");
                for (int i = 0; i < 24; ++i) {
                    byte[] message = (ftp ? "NOOP " + nonce + ":" + i + "\r\n" : nonce + ":" + i + "\n")
                            .getBytes(StandardCharsets.US_ASCII);
                    byte[] wanted = (ftp ? "200 " + nonce + ":" + i + "\r\n" : nonce + ":" + i + "\n")
                            .getBytes(StandardCharsets.US_ASCII);
                    tls.getOutputStream().write(message);
                    if (!Arrays.equals(wanted, read(tls.getInputStream(), wanted.length)))
                        throw new IllegalStateException("TLS echo");
                    Thread.sleep(30);
                }
                result.put("echoes", 25);
                gate(app, nonce, result, "budget_done");
            }
        }
    }
    private static void sniRaw(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        try (Socket socket = new Socket()) {
            socket.setTcpNoDelay(true); socket.bind(new InetSocketAddress(local, source));
            socket.connect(new InetSocketAddress(endpoint, port), 10000); socket.setSoTimeout(10000);
            byte[] hello = hex(plan.getString("t13RawHex"));
            socket.getOutputStream().write(hello);
            if (socket.getInputStream().read() != 65) throw new IllegalStateException("raw endpoint receipt");
            result.put("sentBytes", hello.length).put("endpointReceipt", true);
            gate(app, nonce, result, "raw_ready");
        }
    }

    private static void tcpReassembly(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        byte[] hello = hex(plan.getString("t14WireHex"));
        int count = plan.optInt("t14Count", 1), prefix = plan.optInt("t14Prefix", 20);
        int delay = plan.optInt("t14DelayMs", 80);
        if (count < 1 || count > 48 || hello.length > 4097 || prefix < 1
                || prefix >= hello.length || delay < 0 || delay > 2000)
            throw new IllegalArgumentException("bounded TCP reassembly probe");
        ArrayList<Socket> sockets = new ArrayList<>();
        try {
            for (int i = 0; i < count; ++i) {
                Socket socket = new Socket(); sockets.add(socket);
                socket.setTcpNoDelay(true); socket.bind(new InetSocketAddress(local, source + i));
                socket.connect(new InetSocketAddress(endpoint, port), 10000); socket.setSoTimeout(15000);
            }
            result.put("connections", count);
            gate(app, nonce, result, "connected_ready");
            for (Socket socket : sockets) socket.getOutputStream().write(hello, 0, prefix);
            result.put("prefixBytes", prefix);
            if (plan.optBoolean("t14HoldPrefix", false)) gate(app, nonce, result, "prefix_ready");
            else Thread.sleep(delay);
            for (Socket socket : sockets) socket.getOutputStream().write(hello, prefix, hello.length - prefix);
            for (Socket socket : sockets)
                if (socket.getInputStream().read() != 65) throw new IllegalStateException("TCP endpoint receipt");
            result.put("sentBytesPerConnection", hello.length).put("endpointReceipts", count);
            gate(app, nonce, result, "raw_ready");
        } finally {
            for (Socket socket : sockets) try { socket.close(); } catch (Exception ignored) { }
        }
    }

    private static void udp(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true); socket.bind(new InetSocketAddress(local, source));
            socket.connect(endpoint, port); socket.setSoTimeout(3000);
            result.put("local", socket.getLocalSocketAddress().toString());
            byte[] dns = hex(plan.getString("dnsHex"));
            socket.send(new DatagramPacket(dns, dns.length));
            DatagramPacket reply = new DatagramPacket(new byte[4096], 4096); socket.receive(reply);
            if (reply.getLength() < 12 || reply.getData()[0] != dns[0] || reply.getData()[1] != dns[1]
                    || (reply.getData()[2] & 0x80) == 0) throw new IllegalStateException("DNS response");
            result.put("dnsReplyBytes", reply.getLength());
            // UDP can duplicate a response. Drain the preceding exchange before
            // the gated protocol transition, without treating it as QUIC data.
            socket.setSoTimeout(250);
            try { for (int i = 0; i < 8; ++i) { reply.setLength(4096); socket.receive(reply); } }
            catch (SocketTimeoutException drained) { }
            gate(app, nonce, result, "dns_ready");
            socket.setSoTimeout(3000);
            byte[] initial = hex(plan.getString("quicHex"));
            if (initial.length < 1200) throw new IllegalArgumentException("QUIC Initial datagram");
            socket.send(new DatagramPacket(initial, initial.length));
            reply.setLength(4096); socket.receive(reply);
            if ((reply.getData()[0] & 0xc0) != 0xc0) throw new IllegalStateException("QUIC long-header response");
            result.put("quicReplyBytes", reply.getLength());
            // Drain the rest of the Initial/Handshake flight before the drop probe.
            socket.setSoTimeout(250);
            try { for (int i = 0; i < 8; ++i) { reply.setLength(4096); socket.receive(reply); } }
            catch (SocketTimeoutException drained) { }
            gate(app, nonce, result, "quic_ready");
            byte[] unknown = ("T12-opaque-" + nonce).getBytes(StandardCharsets.US_ASCII);
            socket.setSoTimeout(1200); socket.send(new DatagramPacket(unknown, unknown.length));
            try { reply.setLength(4096); socket.receive(reply); throw new IllegalStateException("expected policy timeout"); }
            catch (SocketTimeoutException expectedTimeout) { result.put("blockedTimeout", true); }
            gate(app, nonce, result, "blocked");
            socket.setSoTimeout(3000);
            for (int i = 0; i < 24; ++i) {
                socket.send(new DatagramPacket(unknown, unknown.length));
                reply.setLength(4096); socket.receive(reply);
                if (reply.getLength() != unknown.length
                        || !Arrays.equals(unknown, Arrays.copyOf(reply.getData(), reply.getLength())))
                    throw new IllegalStateException("UDP echo");
            }
            result.put("echoes", 24); gate(app, nonce, result, "budget_done");
        }
    }
    private static void proxy(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        try (Socket socket = new Socket()) {
            socket.setReuseAddress(true); socket.setTcpNoDelay(true);
            socket.bind(new InetSocketAddress(local, source));
            socket.connect(new InetSocketAddress(endpoint, port), 10000); socket.setSoTimeout(10000);
            result.put("local", socket.getLocalSocketAddress().toString());
            gate(app, nonce, result, "connected_ready");
            socket.getOutputStream().write(new byte[] {5, 2, 0, (byte) 128});
            if (!Arrays.equals(read(socket.getInputStream(), 2), new byte[] {5, 0}))
                throw new IllegalStateException("SOCKS5 method selection");
            byte[] address = endpoint.getAddress();
            if (address.length != 4) throw new IllegalArgumentException("probe IPv4 target");
            int target = plan.getInt("targetPort");
            if (target < 1 || target > 65535) throw new IllegalArgumentException("proxy target port");
            byte[] request = new byte[] {5, 1, 0, 1, address[0], address[1], address[2], address[3],
                    (byte) (target >>> 8), (byte) target};
            socket.getOutputStream().write(request);
            byte[] response = read(socket.getInputStream(), 10);
            request[1] = 0;
            if (!Arrays.equals(request, response)) throw new IllegalStateException("SOCKS5 CONNECT");
            result.put("proxyConnected", true);
            byte[] first = (nonce + ":0\n").getBytes(StandardCharsets.US_ASCII);
            socket.getOutputStream().write(first);
            if (!Arrays.equals(first, read(socket.getInputStream(), first.length)))
                throw new IllegalStateException("proxy initial delivery");
            gate(app, nonce, result, "tunnel_ready");
            byte[] blocked = (nonce + ":1\n").getBytes(StandardCharsets.US_ASCII);
            socket.setSoTimeout(1200); socket.getOutputStream().write(blocked);
            try { socket.getInputStream().read(); throw new IllegalStateException("expected proxy policy timeout"); }
            catch (SocketTimeoutException expected) { result.put("blockedTimeout", true); }
            gate(app, nonce, result, "blocked");
            socket.setSoTimeout(15000);
            if (!Arrays.equals(blocked, read(socket.getInputStream(), blocked.length)))
                throw new IllegalStateException("proxy recovery delivery");
            for (int i = 2; i < 26; ++i) {
                byte[] message = (nonce + ":" + i + "\n").getBytes(StandardCharsets.US_ASCII);
                socket.getOutputStream().write(message);
                if (!Arrays.equals(message, read(socket.getInputStream(), message.length)))
                    throw new IllegalStateException("proxy relayed delivery");
                Thread.sleep(30);
            }
            result.put("echoes", 25); gate(app, nonce, result, "budget_done");
        }
    }
    private static void receiveDatagram(DatagramSocket socket, byte[] expected) throws Exception {
        DatagramPacket response = new DatagramPacket(new byte[4096], 4096);
        socket.receive(response);
        if (!Arrays.equals(expected, Arrays.copyOf(response.getData(), response.getLength())))
            throw new IllegalStateException("protocol peer response mismatch");
    }
    private static void wireguard(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        JSONObject fixture = plan.getJSONObject("wireguard");
        org.json.JSONArray pairs = fixture.getJSONArray("pairs");
        if (pairs.length() != 26 || !fixture.getString("label").equals(nonce))
            throw new IllegalArgumentException("WireGuard session fixture");
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true); socket.bind(new InetSocketAddress(local, source));
            socket.connect(endpoint, port); socket.setSoTimeout(5000);
            result.put("local", socket.getLocalSocketAddress().toString());
            gate(app, nonce, result, "connected_ready");
            byte[] initial = hex(fixture.getString("initial"));
            if (initial.length != 148) throw new IllegalArgumentException("WireGuard initiation");
            socket.send(new DatagramPacket(initial, initial.length));
            receiveDatagram(socket, hex(fixture.getString("response")));
            result.put("handshakeResponse", true);
            byte[] first = hex(pairs.getJSONObject(0).getString("request"));
            socket.send(new DatagramPacket(first, first.length));
            receiveDatagram(socket, hex(pairs.getJSONObject(0).getString("reply")));
            gate(app, nonce, result, "tunnel_ready");
            byte[] blocked = hex(pairs.getJSONObject(1).getString("request"));
            socket.setSoTimeout(1200); socket.send(new DatagramPacket(blocked, blocked.length));
            try { socket.receive(new DatagramPacket(new byte[4096], 4096));
                throw new IllegalStateException("expected WireGuard policy timeout"); }
            catch (SocketTimeoutException expected) { result.put("blockedTimeout", true); }
            gate(app, nonce, result, "blocked");
            socket.setSoTimeout(5000);
            for (int i = 1; i < 26; ++i) {
                byte[] message = hex(pairs.getJSONObject(i).getString("request"));
                socket.send(new DatagramPacket(message, message.length));
                receiveDatagram(socket, hex(pairs.getJSONObject(i).getString("reply")));
                Thread.sleep(30);
            }
            result.put("echoes", 25); gate(app, nonce, result, "budget_done");
        }
    }
    private static void realtime(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        JSONObject fixture = plan.getJSONObject("realtime");
        org.json.JSONArray requests = fixture.getJSONArray("requests");
        org.json.JSONArray replies = fixture.getJSONArray("replies");
        if (requests.length() != 30 || replies.length() != 30)
            throw new IllegalArgumentException("realtime workload size");
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true); socket.bind(new InetSocketAddress(local, source));
            socket.connect(endpoint, port); socket.setSoTimeout(5000);
            result.put("local", socket.getLocalSocketAddress().toString());
            byte[] binding = hex(fixture.getString("first"));
            socket.send(new DatagramPacket(binding, binding.length));
            receiveDatagram(socket, hex(fixture.getString("firstReply")));
            result.put("bindingResponse", true);
            gate(app, nonce, result, "connected_ready");
            for (int i = 0; i < 3; ++i) {
                byte[] message = hex(requests.getString(i));
                if (message.length != 172) throw new IllegalArgumentException("RTP PCMU packet");
                socket.send(new DatagramPacket(message, message.length));
                receiveDatagram(socket, hex(replies.getString(i)));
            }
            result.put("mediaResponses", 3);
            gate(app, nonce, result, "realtime_ready");
            byte[] blocked = hex(requests.getString(3));
            socket.setSoTimeout(1200); socket.send(new DatagramPacket(blocked, blocked.length));
            try { socket.receive(new DatagramPacket(new byte[4096], 4096));
                throw new IllegalStateException("expected realtime policy timeout"); }
            catch (SocketTimeoutException expected) { result.put("blockedTimeout", true); }
            gate(app, nonce, result, "blocked");
            socket.setSoTimeout(5000);
            for (int i = 3; i < 28; ++i) {
                byte[] message = hex(requests.getString(i));
                socket.send(new DatagramPacket(message, message.length));
                receiveDatagram(socket, hex(replies.getString(i)));
                Thread.sleep(30);
            }
            result.put("echoes", 25); gate(app, nonce, result, "budget_done");
        }
    }
    private static void quicInitial(Context app, JSONObject plan, JSONObject result, String nonce,
            InetAddress endpoint, InetAddress local, int source, int port) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(null)) {
            socket.setReuseAddress(true); socket.bind(new InetSocketAddress(local, source));
            socket.connect(endpoint, port); socket.setSoTimeout(5000);
            result.put("local", socket.getLocalSocketAddress().toString());
            byte[] prelude = hex(plan.getString("preludeHex"));
            byte[] preludeReply = hex(plan.getString("preludeReplyHex"));
            for (int i = 0; i < 2; ++i) {
                socket.send(new DatagramPacket(prelude, prelude.length));
                receiveDatagram(socket, preludeReply);
            }
            if (plan.has("t16Sequence")) {
                org.json.JSONArray sequence = plan.getJSONArray("t16Sequence");
                if (sequence.length() < 1 || sequence.length() > 20)
                    throw new IllegalArgumentException("QUIC sequence count");
                org.json.JSONArray replies = new org.json.JSONArray();
                for (int i = 0; i < sequence.length(); ++i) {
                    byte[] packet = hex(sequence.getString(i));
                    if (packet.length < 1200 || packet.length > 4096)
                        throw new IllegalArgumentException("Initial size");
                    socket.send(new DatagramPacket(packet, packet.length));
                    if (plan.optBoolean("rawInitial")) {
                        socket.setSoTimeout(5000); receiveDatagram(socket, packet);
                    } else {
                        socket.setSoTimeout(50);
                        try {
                            for (int j = 0; j < 8; ++j) {
                                DatagramPacket reply = new DatagramPacket(new byte[4096], 4096);
                                socket.receive(reply);
                                replies.put(toHex(Arrays.copyOf(reply.getData(), reply.getLength())));
                            }
                        } catch (SocketTimeoutException drained) { }
                    }
                }
                result.put("sequenceReplies", replies);
                if (plan.optBoolean("assemblyTimeout")) {
                    long began = android.os.SystemClock.elapsedRealtimeNanos();
                    Thread.sleep(5100);
                    result.put("timeoutWaitNs", android.os.SystemClock.elapsedRealtimeNanos() - began);
                }
            } else {
            byte[] initial = hex(plan.getString("t15InitialHex"));
            socket.send(new DatagramPacket(initial, initial.length));
            boolean initialBlocked = plan.optBoolean("initialBlocked");
            if (initialBlocked) {
                socket.setSoTimeout(1200);
                try { socket.receive(new DatagramPacket(new byte[4096], 4096));
                    throw new IllegalStateException("expected Initial policy timeout"); }
                catch (SocketTimeoutException expected) { result.put("initialTimeout", true); }
            } else if (plan.optBoolean("rawInitial")) {
                receiveDatagram(socket, initial);
                result.put("rawInitialReceived", true);
            } else {
                DatagramPacket reply = new DatagramPacket(new byte[4096], 4096);
                socket.receive(reply);
                if (reply.getLength() < 20 || (reply.getData()[0] & 0xc0) != 0xc0)
                    throw new IllegalStateException("QUIC Initial response");
                result.put("initialReplyHex", toHex(Arrays.copyOf(reply.getData(), reply.getLength())));
                socket.setSoTimeout(250);
                try { for (int i = 0; i < 8; ++i) { reply.setLength(4096); socket.receive(reply); } }
                catch (SocketTimeoutException drained) { }
            }
            }
            gate(app, nonce, result, "quic_ready");
            if (plan.optBoolean("domainChecks")) {
                byte[] changed = ("T15-" + nonce + ":domain-change").getBytes(StandardCharsets.US_ASCII);
                socket.setSoTimeout(5000); socket.send(new DatagramPacket(changed, changed.length));
                receiveDatagram(socket, changed);
                gate(app, nonce, result, "domain_changed");
            }
            if (plan.optBoolean("policyBlocked") && !plan.optBoolean("initialBlocked")) {
                byte[] blocked = ("T15-" + nonce + ":blocked").getBytes(StandardCharsets.US_ASCII);
                socket.setSoTimeout(1200); socket.send(new DatagramPacket(blocked, blocked.length));
                try { socket.receive(new DatagramPacket(new byte[4096], 4096));
                    throw new IllegalStateException("expected QUIC policy timeout"); }
                catch (SocketTimeoutException expected) { result.put("blockedTimeout", true); }
                gate(app, nonce, result, "blocked");
            }
            socket.setSoTimeout(5000);
            for (int i = 0; i < 25; ++i) {
                byte[] message = ("T15-" + nonce + ":" + i).getBytes(StandardCharsets.US_ASCII);
                socket.send(new DatagramPacket(message, message.length));
                receiveDatagram(socket, message);
            }
            result.put("echoes", 25); gate(app, nonce, result, "budget_done");
        }
    }
    static void start(Context context, String text) {
        final JSONObject plan;
        final String nonce;
        try {
            plan = new JSONObject(text); nonce = plan.getString("nonce");
            if (!nonce.matches("[a-zA-Z0-9_-]{1,80}")) return;
        } catch (Exception invalid) { return; }
        if (!RUNNING.compareAndSet(false, true)) return;
        Context app = context.getApplicationContext();
        new Thread(() -> {
            JSONObject result = new JSONObject();
            try {
                result.put("nonce", nonce).put("uid", android.os.Process.myUid()).put("plan", plan);
                InetAddress endpoint = InetAddress.getByName(plan.getString("endpoint"));
                if (endpoint.isAnyLocalAddress() || endpoint.isLoopbackAddress()
                        || endpoint.isLinkLocalAddress() || endpoint.isMulticastAddress())
                    throw new IllegalArgumentException("unicast underlay required");
                InetAddress local = plan.optBoolean("bindDefault") ? null : InetAddress.getByName(VpnTunPlatformSession.IPV4_ADDRESS);
                int source = plan.getInt("source"), port = plan.getInt("port");
                if (source < 1024 || source > 65535 || port < 1 || port > 65535) throw new IllegalArgumentException("port");
                if (plan.has("t15InitialHex") || plan.has("t16Sequence")) quicInitial(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.has("t14WireHex")) tcpReassembly(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.has("t13RawHex")) sniRaw(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.optString("r4Protocol").equals("rtp_udp")) realtime(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.optString("r3Protocol").equals("socks5")) proxy(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.optString("r3Protocol").equals("wireguard")) wireguard(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.getString("mode").equals("tcp")) tcp(app, plan, result, nonce, endpoint, local, source, port);
                else if (plan.getString("mode").equals("udp")) udp(app, plan, result, nonce, endpoint, local, source, port);
                else throw new IllegalArgumentException("mode");
            } catch (Exception error) {
                try { result.put("error", error.toString()); } catch (Exception ignored) { }
            } finally {
                try { report(app, nonce, result, "finished"); } catch (Exception ignored) { }
                RUNNING.set(false);
            }
        }, "t12-app-protocol").start();
    }
}
