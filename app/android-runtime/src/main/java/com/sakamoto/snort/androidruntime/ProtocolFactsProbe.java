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
            if (ftp) {
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
            try (SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(socket, "example.test", port, false)) {
                tls.setEnabledProtocols(new String[] {"TLSv1.2"}); tls.setSoTimeout(15000); tls.startHandshake();
                result.put("tlsProtocol", tls.getSession().getProtocol()).put("cipher", tls.getSession().getCipherSuite());
                gate(app, nonce, result, "tls_ready");
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
                if (plan.getString("mode").equals("tcp")) tcp(app, plan, result, nonce, endpoint, local, source, port);
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
